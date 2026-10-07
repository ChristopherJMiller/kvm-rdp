use crate::support::{T, es3_sim, login, sim_with, target};
use futures_util::{SinkExt, StreamExt};
use kvm_proto::hid::HidFrame;
use kvm_sim::{KvmSim, Pacing, SimEvent};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

async fn ws(
    sim: &KvmSim,
    token: &str,
    limit: Option<usize>,
) -> Result<
    tokio_tungstenite::WebSocketStream<kvm_probe::kvm::BoxedIo>,
    tokio_tungstenite::tungstenite::Error,
> {
    let io = kvm_probe::kvm::connect_to(&target(sim), sim.ports().control, Some(sim.spki_sha256()))
        .await
        .unwrap();
    let mut req = format!("wss://127.0.0.1:{}/websocket", sim.ports().control)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Cookie", format!("token={token}").parse().unwrap());
    let cfg = WebSocketConfig {
        max_message_size: limit,
        max_frame_size: limit,
        ..WebSocketConfig::default()
    };
    tokio_tungstenite::client_async_with_config(req, io, Some(cfg))
        .await
        .map(|(w, _)| w)
}

#[tokio::test]
async fn hid_frames_are_recorded_verbatim() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, None).await.unwrap();
    let frames = [
        HidFrame::SetMode { hid_type: 0 },
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        },
        HidFrame::abs_mouse(0, 100, 200),
    ];
    for f in frames {
        w.send(Message::Binary(f.to_vec())).await.unwrap();
    }
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::Hid { .. }))
                .count()
                == 3
        })
        .await
        .unwrap();
    let got: Vec<HidFrame> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::Hid { bytes, .. } => HidFrame::decode(bytes).ok(),
            _ => None,
        })
        .collect();
    assert_eq!(got, frames);
    assert_eq!(sim.stats().ws_open, 1);
}

#[tokio::test]
async fn upgrade_needs_a_live_token() {
    let sim = es3_sim(Pacing::Manual).await;
    assert!(ws(&sim, "0.1", None).await.is_err());
    sim.wait_for(T, |e| e.contains(&SimEvent::WsRefused { status: 403 }))
        .await
        .unwrap();
}

#[tokio::test]
async fn closing_and_oversize_faults_reach_the_client() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, Some(4096)).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsOpen { .. }))
    })
    .await
    .unwrap();
    sim.send_ws_oversize(64 << 20);
    let r = tokio::time::timeout(T, w.next()).await.unwrap();
    assert!(matches!(r, Some(Err(_))), "{r:?}");
    let mut w2 = ws(&sim, &token, None).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::WsOpen { .. }))
            .count()
            == 2
    })
    .await
    .unwrap();
    // P4: `ws_max_open` is pinned by the API table but never asserted; two
    // concurrent websockets (`w` is still counted open, having errored on
    // read but not yet closed) make it 2 here.
    assert_eq!(sim.stats().ws_max_open, 2);
    sim.close_websockets();
    let r = tokio::time::timeout(T, w2.next()).await.unwrap();
    assert!(matches!(r, Some(Ok(Message::Close(_))) | None), "{r:?}");
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::WsClose { .. }))
            .count()
            == 2
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_policy_status_refuses_the_upgrade() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.ws_status = Some(503));
    assert!(ws(&sim, &token, None).await.is_err());
    sim.wait_for(T, |e| e.contains(&SimEvent::WsRefused { status: 503 }))
        .await
        .unwrap();
}

#[tokio::test]
async fn paused_reads_back_up_the_clients_writes_until_resumed() {
    // §11.3's blocked websocket write: kvm-sim stops reading and its control
    // sockets have a 4 KiB receive buffer, so 16 MB of writes (past any
    // loopback send buffer) cannot drain until reads resume.
    const N: usize = 256;
    let sim = sim_with(|c| {
        c.pacing = Pacing::Manual;
        c.control_recv_buffer = Some(4096);
    })
    .await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, None).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsOpen { .. }))
    })
    .await
    .unwrap();
    sim.set_policy(|p| p.pause_ws_reads = true);
    let mut flood = tokio::spawn(async move {
        for _ in 0..N {
            w.send(Message::Binary(vec![0x5A; 64_000])).await.unwrap();
        }
        w
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut flood)
            .await
            .is_err(),
        "the writes back up while kvm-sim is not reading"
    );
    sim.set_policy(|p| p.pause_ws_reads = false);
    let _w = tokio::time::timeout(T, flood).await.unwrap().unwrap();
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::Hid { .. }))
            .count()
            == N
    })
    .await
    .unwrap();
}

/// PB17 fix round 1, I1: mirrors `flv.rs`'s
/// `logout_is_global_but_open_streams_survive`. Neither the brief nor the
/// spec names the control websocket here — §3.2 and `census.md`'s "Live
/// streams on another session's logout: survive" measured only `av.flv`
/// (a/b captures) — so this pins kvm-sim's own choice instead: the upgrade
/// callback (`ws.rs`) checks the token once, at the handshake, and nothing
/// re-checks it on an already-open connection, so an open control
/// websocket survives another session's logout exactly the way an open
/// FLV does.
#[tokio::test]
async fn logout_is_global_but_an_already_open_websocket_survives() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let b = login(&sim).await;
    let mut w = ws(&sim, &a, None).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsOpen { .. }))
    })
    .await
    .unwrap();
    kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &b)
        .await
        .unwrap();
    // (a) every token died, including the one that did not log out: a new
    // upgrade with it is refused.
    assert!(ws(&sim, &a, None).await.is_err());
    sim.wait_for(T, |e| e.contains(&SimEvent::WsRefused { status: 403 }))
        .await
        .unwrap();
    // (b) … but the websocket opened before the logout keeps working — no
    // re-check happens on an open connection, so a HID frame sent on it
    // now still arrives, and the logout never closed it.
    w.send(Message::Binary(HidFrame::SetMode { hid_type: 0 }.to_vec()))
        .await
        .unwrap();
    sim.wait_for(T, |e| e.iter().any(|e| matches!(e, SimEvent::Hid { .. })))
        .await
        .unwrap();
    assert_eq!(sim.stats().ws_open, 1, "A's websocket is still open");
    assert_eq!(sim.stats().logouts, 1);
}

/// PB17 fix round 1, M3: `ws.rs` never calls `HidFrame::decode` itself —
/// decoding is the bridge's job, not kvm-sim's — so a malformed frame
/// cannot panic kvm-sim by construction. Pinned by test, not just by
/// inspection: garbage bytes are still recorded verbatim, and the
/// connection stays open and usable right after.
#[tokio::test]
async fn garbage_bytes_are_recorded_verbatim_and_the_connection_stays_sane() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, None).await.unwrap();
    let garbage = vec![0xFF, 0x00, 0x13, 0x37];
    w.send(Message::Binary(garbage.clone())).await.unwrap();
    // A well-formed frame right after, to prove the connection stayed
    // sane (not wedged, not silently dropped) past the garbage.
    let good = HidFrame::SetMode { hid_type: 0 };
    w.send(Message::Binary(good.to_vec())).await.unwrap();
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::Hid { .. }))
                .count()
                == 2
        })
        .await
        .unwrap();
    let got: Vec<Vec<u8>> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::Hid { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(got, [garbage.clone(), good.to_vec()]);
    assert!(
        HidFrame::decode(&garbage).is_err(),
        "not coincidentally a valid frame"
    );
    assert_eq!(sim.stats().ws_open, 1, "the connection stayed open");
}
