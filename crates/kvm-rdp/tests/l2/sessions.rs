//! §11.3 Auth and pre-auth, Preemption, Generations.
use crate::client::{CONNECT_BOUND, Ev, Opts, confirmed, pictures, takeover, terminated, timeline};
use crate::harness::{
    ES3_FIXTURE, KBD_ZERO, SET_MODE, T, assert_run, barcodes, env, es3, flv_opens, hid_on,
    index_of, ms, sent_on, sized, until, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_sim::{SimEvent, SimStats};
use std::time::Instant;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn accepts(s: &SimStats) -> u64 {
    s.accepts_web + s.accepts_video + s.accepts_control
}

/// §5.1: with a live session, a wrong-password client, a client without
/// CredSSP and a raw TCP connect sending garbage all fail; the live session
/// keeps receiving frames; kvm-sim records no new TCP accept on any port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_and_pre_auth_attempts_cost_no_kvm_traffic() {
    let env = env(es3(), sized).await;
    let live = env.client(Opts::new(2));
    live.wait_for(T, |e| pictures(e).len() >= 5).await;
    let before = accepts(&env.sim.stats());
    let wrong = env.client(Opts::new(3).password("not-the-password-at-all-0"));
    let plain = env.client(Opts::new(4).no_credssp());
    assert!(!wrong.refused().await.is_empty());
    assert!(!plain.refused().await.is_empty());
    let mut raw = tokio::net::TcpStream::connect(env.rdp).await.unwrap();
    raw.write_all(b"\x03\x00\x00\x13garbage, not an X.224 request")
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(T, raw.read_to_end(&mut sink)).await;
    let n = pictures(&live.events()).len();
    live.wait_for(T, |e| {
        pictures(e).len() >= n + 10 && terminated(e).is_none()
    })
    .await;
    assert_eq!(
        accepts(&env.sim.stats()),
        before,
        "§5.1: no KVM traffic before auth"
    );
    assert_eq!(env.metrics().sessions.get(), 1);
}

/// §11.3 Preemption: release-all → websocket close → FLV close → login →
/// websocket open → session-start, whose pointer report is at the evicted
/// session's last position (DC7: pushed through `HidControl`, the input
/// handler's entry point) — exactly `[SET_MODE, KBD_ZERO, pointer]`, never a
/// pointer at (0, 0); no logout, never two websockets; the evicted client
/// gets 0x5; a retake from its address within 5 s is refused and the new
/// session is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_releases_closes_and_starts_clean_without_a_logout() {
    let env = env(es3(), sized).await;
    let a = env.client(Opts::new(2));
    a.wait_for(T, |e| pictures(e).len() >= 3).await;
    // Past the writer's `discard_queued()` (P47): a push now is written.
    let ws1 = env.hid_ready().await;
    let pointer = HidFrame::abs_mouse(0, 1000, 2000);
    let _ = env.bridge().hid().push(pointer, false);
    env.sim
        .wait_for(T, |l| hid_on(l, ws1).contains(&pointer.to_vec()))
        .await
        .unwrap();
    let log0 = env.sim.events();
    let flv1 = flv_opens(&log0)[0];
    // The KVM is slow to read the websocket, so the close order shows in
    // kvm-sim's log: the FLV must stay open (kvm-sim keeps writing to it)
    // until the websocket's close is answered. Unpaused, both closes land
    // within ~100 µs and kvm-sim's log order is a race either way.
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    let released = env.metrics().release_all.total();
    let t0 = Instant::now();
    let b = env.client(Opts::new(3));
    let (took, ()) = tokio::join!(
        async {
            b.connected().await;
            t0.elapsed()
        },
        async {
            let evs = a.wait_for(T, |e| terminated(e).is_some()).await;
            assert_eq!(terminated(&evs).unwrap(), takeover());
            // `on_disconnected` (or the winner's `on_connection_info`)
            // released all: the KVM side is closing the evicted session.
            assert!(until(T, || env.metrics().release_all.total() > released).await);
            // Two frames later (≥ 33 ms; the bridge's close waits 400 ms
            // for the KVM's answer) a FLV closed first has closed.
            let n = sent_on(&env.sim.events(), flv1).len();
            env.sim
                .wait_for(T, |l| {
                    sent_on(l, flv1).len() >= n + 2
                        || l.contains(&SimEvent::FlvClose { conn: flv1 })
                })
                .await
                .unwrap();
            env.sim.set_policy(|p| p.pause_ws_reads = false);
        }
    );
    // PC16 carry: a takeover's connect (TCP, TLS, CredSSP, the eviction,
    // activation) is far inside the client's connect bound (≈ 90 ms).
    assert!(
        took < CONNECT_BOUND / 3,
        "a takeover connect took {took:?} of the {CONNECT_BOUND:?} bound"
    );
    b.wait_for(T, |e| pictures(e).len() >= 3).await;
    let n0 = log0.len();
    let log = env
        .sim
        .wait_for(T, |l| {
            ws_opens(&l[n0..])
                .first()
                .is_some_and(|w| hid_on(&l[n0..], *w).len() >= 3)
        })
        .await
        .unwrap();
    let after = &log[n0..];
    let pos = |what: &str, pred: &dyn Fn(&SimEvent) -> bool| {
        after
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("no {what} in {after:?}"))
    };
    let release = pos(
        "release",
        &|e| matches!(e, SimEvent::Hid { conn, bytes } if *conn == ws1 && bytes[..] == KBD_ZERO),
    );
    let ws_close = pos("websocket close", &|e| {
        *e == SimEvent::WsClose { conn: ws1 }
    });
    let flv_close = pos("FLV close", &|e| *e == SimEvent::FlvClose { conn: flv1 });
    let login = pos("login", &|e| matches!(e, SimEvent::Login { ok: true }));
    let ws2 = *ws_opens(after).first().unwrap();
    let ws_open = pos("websocket open", &|e| *e == SimEvent::WsOpen { conn: ws2 });
    assert!(
        release < ws_close && ws_close < flv_close && flv_close < login && login < ws_open,
        "{after:?}"
    );
    assert_eq!(
        hid_on(after, ws2),
        [SET_MODE.to_vec(), KBD_ZERO.to_vec(), pointer.to_vec()]
    );
    let s = env.sim.stats();
    assert_eq!((s.ws_max_open, s.logouts), (1, 0));
    let retake = env.client(Opts::new(2));
    assert!(
        !retake.refused().await.is_empty(),
        "a retake inside the cooldown was let in"
    );
    let n = pictures(&b.events()).len();
    b.wait_for(T, |e| {
        pictures(e).len() >= n + 10 && terminated(e).is_none()
    })
    .await;
    assert_eq!(env.metrics().sessions.get(), 2);
}

/// §4.3 generations: end the first session with work in flight — a
/// re-advertise's IDR request, deferred inside the setup window — and
/// reconnect at once. The second session sees no frame, timer, request or
/// `Disconnect` from the first: no side FLV opens after its login, and its
/// pictures are exactly its own main FLV's AUs (the barcode oracle, which
/// would catch a first-generation AU reaching it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quick_reconnect_sees_nothing_of_the_previous_generation() {
    let wd = ms(300);
    let env = env(es3(), move |c| {
        sized(c);
        c.video.disconnect_watchdog = wd;
    })
    .await;
    let a = env.client(Opts::new(2));
    a.wait_for(T, |e| pictures(e).len() >= 10).await;
    // A Setup cause: an IDR request, deferred inside the setup window. The
    // re-advertise's confirm, then its Setup's MapSurfaceToOutput, show the
    // pump ran that Setup — so the request is in flight — before the close
    // (I3: without the wait, IronRDP read the re-advertise after the
    // teardown in 28 of 30 runs, and the shell skips it since 9b8b1f3).
    let n = a.with_log(<[Ev]>::len);
    a.readvertise();
    a.wait_for(T, |e| {
        confirmed(e, n).is_some_and(|k| timeline(&e[k..]).iter().any(|l| l == "map"))
    })
    .await;
    a.close();
    let b = env.client(Opts::new(3));
    let evs = b.wait_for(T, |e| pictures(e).len() >= 30).await;
    let t = timeline(&evs);
    assert_eq!(
        t[..5],
        ["confirm", "reset 640x360", "surface 640x360", "map", "idr"],
        "{t:?}"
    );
    b.never(wd * 5, |e| terminated(e).is_some()).await;
    assert_eq!(env.metrics().disconnects.total(), 0);
    assert_eq!(env.metrics().sessions.get(), 2);
    let log = env.sim.events();
    let second_login = log
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, SimEvent::Login { ok: true }))
        .nth(1)
        .unwrap()
        .0;
    let opens = flv_opens(&log[second_login..]);
    assert_eq!(
        opens.len(),
        1,
        "an IDR request leaked into the second generation: {opens:?}"
    );
    let main2 = opens[0];
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pictures(&b.events())
        .iter()
        .map(|p| index_of(&map, &p.annex_b))
        .collect();
    let log = env
        .sim
        .wait_for(T, |l| sent_on(l, main2).len() >= got.len())
        .await
        .unwrap();
    assert_run(&got, &sent_on(&log, main2), "the second generation");
}

/// §9.1: the account name compares exactly (case-sensitive) and the domain
/// is not part of the compare — `KVM` is refused, `ROWLETT\kvm` (the form
/// FreeRDP sends through rdpgw) is let in. ironrdp-acceptor's
/// `auth_data_by_user` compares `account_name()` only, and sspi computes
/// NTLMv2 from what the client sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_username_compare_is_exact_and_ignores_the_domain() {
    let env = env(es3(), sized).await;
    let upper = env.client(Opts::new(2).user("KVM"));
    assert!(!upper.refused().await.is_empty(), "`KVM` was let in");
    assert_eq!(env.metrics().sessions.get(), 0);
    let domain = env.client(Opts::new(3).domain("ROWLETT"));
    domain.wait_for(T, |e| pictures(e).len() >= 3).await;
    assert_eq!(env.metrics().sessions.get(), 1);
    assert_eq!(env.logins(), 1);
}
