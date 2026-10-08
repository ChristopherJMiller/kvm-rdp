//! §7.3's writer through the bridge (DC7: driven via `HidControl`). Every
//! push waits for `Env::hid_ready()` — the writer is past `drive()`'s
//! `discard_queued()` once the session-start pair is on the wire (P47) —
//! and a case that pushes after a reopen calls it only once the reopen
//! shows up (it waits on the latest websocket).
use crate::client::{Opts, pictures, terminated};
use crate::harness::{
    KBD_ZERO, SET_MODE, T, env, es3, hid_on, ms, sized, streaming, until, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_sim::SimEvent;

/// Reports reach kvm-sim byte-exact, in order, after the session-start
/// sequence; a websocket reopen's session-start carries the pointer at the
/// last position sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_reach_the_kvm_and_a_reopen_restores_the_pointer() {
    let (env, _c) = streaming(|_| {}).await;
    let hid = env.bridge().hid().clone();
    let ws = env.hid_ready().await;
    let frames = [
        HidFrame::abs_mouse(0, 1000, 2000),
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0x04, 0, 0, 0, 0],
        },
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        },
    ];
    for f in frames {
        let _ = hid.push(f, false);
    }
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).len() >= 5)
        .await
        .unwrap();
    let mut want = vec![SET_MODE.to_vec(), KBD_ZERO.to_vec()];
    want.extend(frames.iter().map(HidFrame::to_vec));
    assert_eq!(
        hid_on(&log, ws),
        want,
        "exactly the session start, then the reports"
    );
    env.sim.close_websockets();
    let log = env
        .sim
        .wait_for(T, |l| {
            ws_opens(l).len() >= 2 && hid_on(l, ws_opens(l)[1]).len() >= 3
        })
        .await
        .unwrap();
    let ws2 = ws_opens(&log)[1];
    assert_eq!(
        hid_on(&log, ws2),
        [
            SET_MODE.to_vec(),
            KBD_ZERO.to_vec(),
            HidFrame::abs_mouse(0, 1000, 2000).to_vec()
        ]
    );
}

/// §7.3: a full queue resyncs to the correct final state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_resyncs_to_the_final_state() {
    let (env, _c) = streaming(|c| c.input.queue = 4).await;
    let hid = env.bridge().hid().clone();
    let ws = env.hid_ready().await;
    for i in 0..64u8 {
        let _ = hid.push(
            HidFrame::Keyboard {
                modifiers: 0,
                keys: [0x04 + i % 20, 0, 0, 0, 0],
            },
            false,
        );
    }
    let last = HidFrame::Keyboard {
        modifiers: 0x02,
        keys: [0x1D, 0, 0, 0, 0],
    };
    let _ = hid.push(last, false);
    env.sim
        .wait_for(T, |l| hid_on(l, ws).last() == Some(&last.to_vec()))
        .await
        .unwrap();
    assert!(env.metrics().hid_resyncs.get() >= 1);
}

/// §6.9 websocket: a write blocked past `hid_write_timeout` reconnects, and
/// the new websocket starts with the session-start sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_websocket_write_reconnects() {
    let wt = ms(300);
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, move |c| {
        sized(c);
        c.input.hid_write_timeout = wt;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    env.hid_ready().await;
    let before = ws_opens(&env.sim.events()).len();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    let hid = env.bridge().hid().clone();
    let mut x = 0u16;
    let reconnected = until(T, || {
        for _ in 0..200 {
            x = x % 29_999 + 1; // 1..=29 999: the test itself never sends (0, 0)
            let _ = hid.push(HidFrame::abs_mouse(0, x, x), false);
        }
        ws_opens(&env.sim.events()).len() > before
    })
    .await;
    assert!(reconnected, "no reconnect after a blocked write");
    assert!(env.metrics().upstream_reconnects.get("websocket_write") >= 1);
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    // The reopen has shown up: `hid_ready` now waits on it.
    let new = env.hid_ready().await;
    let log = env.sim.events();
    // The new websocket starts with the session start; the pointer report
    // after it is at the last position the old one wrote — never (0, 0).
    let on_new = hid_on(&log, new);
    assert_eq!(on_new[..2], [SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
    assert!(
        !on_new.contains(&HidFrame::abs_mouse(0, 0, 0).to_vec()),
        "the pointer was parked at (0, 0)"
    );
    assert!(
        terminated(&c.events()).is_none(),
        "a websocket fault never disconnects the client"
    );
}

/// Plan A's assumption for L4, on kvm-sim: another session's logout (every
/// token invalidated) leaves the control websocket up, and reports keep
/// flowing on it. kvm-sim was built on that assumption, so this checks the
/// bridge's side only; the real ES3 is one of DC18's L4 checks (Plan D).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_websocket_survives_another_sessions_logout() {
    let (env, _c) = streaming(|_| {}).await;
    let hid = env.bridge().hid().clone();
    let ws = env.hid_ready().await;
    env.sim.expire_tokens();
    tokio::time::sleep(ms(300)).await;
    let k = HidFrame::Keyboard {
        modifiers: 0,
        keys: [0x05, 0, 0, 0, 0],
    };
    let _ = hid.push(k, false);
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).contains(&k.to_vec()))
        .await
        .unwrap();
    assert!(!log.contains(&SimEvent::WsClose { conn: ws }));
    assert_eq!(ws_opens(&log).len(), 1);
}
