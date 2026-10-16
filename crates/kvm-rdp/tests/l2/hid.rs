//! §7.3's writer through the bridge (DC7: driven via `HidControl`). Every
//! push waits for `Env::hid_ready()` — the writer is past `drive()`'s
//! `discard_queued()` once the session-start pair is on the wire (P47) —
//! and a case that pushes after a reopen calls it only once the reopen
//! shows up (it waits on the latest websocket).
use crate::client::{Opts, pictures, terminated};
use crate::harness::{
    KBD_ZERO, SET_MODE, T, abs, env, es3, hid_on, hid_stamped, ms, sized, streaming, until,
    until_mark, within, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_sim::SimEvent;
use std::time::Duration;

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
///
/// Final review I1: the control socket's send buffer is capped
/// (`kvm::endpoint::CONTROL_SNDBUF`), so a KVM that stops reading blocks a
/// write within a bounded number of reports — about a thousand here, where
/// the autotuned buffer (2.6 MB on loopback) swallowed ~45 000 first. The
/// case pushes a batch only once every report pushed so far is written, so
/// none is lost to a queue resync and the count is the writer's: load
/// cannot inflate it. PC18 m3: the old connection is reset, not closed with
/// a FIN — of its unread reports, at most `STALE_MAX` reach kvm-sim after
/// the new websocket opens (what kvm-sim had already taken in; a FIN
/// delivers the whole send buffer after it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_websocket_write_reconnects() {
    /// Several times what fills the capped buffers; far below what an
    /// uncapped one takes.
    const PUSH_BUDGET: u64 = 4_000;
    const BATCH: u64 = 100;
    const STALE_MAX: usize = 400;
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
    let old = env.hid_ready().await;
    let before = ws_opens(&env.sim.events()).len();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    let hid = env.bridge().hid().clone();
    let sent0 = env.metrics().hid_reports_sent.get();
    let (mut pushed, mut x) = (0u64, 0u16);
    let reconnected = until(T, || {
        if ws_opens(&env.sim.events()).len() > before {
            return true;
        }
        let written = env.metrics().hid_reports_sent.get().saturating_sub(sent0);
        if written >= pushed && pushed < PUSH_BUDGET {
            for _ in 0..BATCH {
                x = x % 29_999 + 1; // 1..=29 999: the test itself never sends (0, 0)
                let _ = hid.push(HidFrame::abs_mouse(0, x, x), false);
            }
            pushed += BATCH;
        }
        false
    })
    .await;
    assert!(
        reconnected,
        "no reconnect after {pushed} reports (budget {PUSH_BUDGET}): no write blocked"
    );
    assert!(env.metrics().upstream_reconnects.get("websocket_write") >= 1);
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    // The reopen has shown up: `hid_ready` now waits on it.
    let new = env.hid_ready().await;
    // Once kvm-sim has seen the old websocket end, every report it will
    // ever take from it is in the log.
    let log = env
        .sim
        .wait_for(T, |l| l.contains(&SimEvent::WsClose { conn: old }))
        .await
        .unwrap_or_else(|_| panic!("the old websocket never closed"));
    let opened = log
        .iter()
        .position(|e| *e == SimEvent::WsOpen { conn: new })
        .unwrap();
    let stale = log[opened..]
        .iter()
        .filter(|e| matches!(e, SimEvent::Hid { conn, .. } if *conn == old))
        .count();
    assert!(
        stale <= STALE_MAX,
        "{stale} of the old websocket's reports reached kvm-sim after the new one \
         opened (at most {STALE_MAX}): its backlog was delivered, not reset"
    );
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

/// PC9 fix 2 / DD8 (Task 4.2): after a websocket reconnect, the fresh
/// websocket's session start is followed, `reassert_after` later (§11.1's
/// one-sided bound), by the current full state once more — so a stale
/// press the KVM read from its own receive buffer is overwritten.
///
/// PD10 m4: a key is held across the reconnect. The reconnect's epoch
/// released it, so the state re-asserted holds nothing — the re-assert
/// carries `KBD_ZERO` — and the pointer stays where the client left it.
/// The key stays released by the bridge: its client release sends nothing,
/// and the core's first step since the reconnect pushes only its released
/// state (the epoch zero, `input.rs`'s module doc) — never the key again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_reasserts_the_full_state() {
    /// Set-1 make code of the key held across the reconnect (usage 0x04).
    const A: u8 = 0x1E;
    /// The zero report the core's first step after a release pushes.
    const EPOCH_ZERO: [u8; 12] = KBD_ZERO;
    let after = ms(300);
    // `sized()` sets a 600 s re-assert so the exact-frame cases never see
    // one (Task 4.2, D10a); this case scales it back down (`streaming`'s
    // edit runs after `sized`). The key-repeat timer is moved out of the
    // way, so only the reconnect releases the held key.
    let (env, c) = streaming(move |c| {
        c.input.reassert_after = after;
        c.input.key_repeat_timeout = Duration::from_secs(60);
    })
    .await;
    let ws = env.hid_ready().await;
    // The first websocket's own re-assert, of a state nothing has set yet,
    // writes nothing; it is done before the case sends.
    assert!(
        until(T, || env.metrics().hid_reasserts.get() == 1).await,
        "the first websocket never re-asserted"
    );
    let pointer = abs(0, 320, 180); // the centre of the 640×360 surface
    c.key(A, true); // held across the reconnect
    c.mouse_move(320, 180);
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).len() >= 5)
        .await
        .unwrap();
    assert_eq!(
        hid_on(&log, ws),
        [
            SET_MODE.to_vec(),
            KBD_ZERO.to_vec(),
            EPOCH_ZERO.to_vec(),
            HidFrame::Keyboard {
                modifiers: 0,
                keys: [0x04, 0, 0, 0, 0]
            }
            .to_vec(),
            pointer.clone()
        ]
    );
    env.sim.close_websockets();
    let ws2 = env.hid_ready_after(1).await;
    assert!(
        until(T, || env.metrics().hid_reasserts.get() == 2).await,
        "the reopen never re-asserted"
    );
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws2).len() >= 5)
        .await
        .unwrap();
    // The reopen's session start (SET_MODE, KBD_ZERO, the pointer at its
    // last position), then the re-assert: no key held, the same pointer.
    assert_eq!(
        hid_on(&log, ws2),
        [
            SET_MODE.to_vec(),
            KBD_ZERO.to_vec(),
            pointer.clone(),
            KBD_ZERO.to_vec(),
            pointer.clone()
        ],
        "the re-assert after the reconnect"
    );
    let stamped = hid_stamped(&env.sim, ws2);
    within(stamped[3].0.duration_since(stamped[2].0), after);
    // The client releases the key the bridge already released, then marks.
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws2).await,
        [
            pointer.clone(),
            KBD_ZERO.to_vec(),
            pointer,
            EPOCH_ZERO.to_vec()
        ],
        "the held key was pressed again after the reconnect"
    );
    assert_eq!(env.metrics().hid_reasserts.get(), 2, "once per websocket");
    assert_eq!(env.metrics().release_all.get("websocket_reconnect"), 1);
    assert!(terminated(&c.events()).is_none());
}
