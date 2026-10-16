//! §7.3's writer through the bridge (DC7: driven via `HidControl`). Every
//! push waits for `Env::hid_ready()` — the writer is past `drive()`'s
//! `discard_queued()` once the session-start pair is on the wire (P47) —
//! and a case that pushes after a reopen calls it only once the reopen
//! shows up (it waits on the latest websocket).
use crate::client::{Opts, pictures, takeover, terminated};
use crate::harness::{
    KBD_ZERO, SET_MODE, T, abs, env, es3, hid_on, hid_stamped, ms, sized, streaming, until,
    until_mark, within, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_rdp::hid::writer::REASSERT_AFTER;
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

// ---- I2 (Plan D final review): the release websocket, end to end.

/// What the KVM holds if it keeps the last report it read (kvm-sim's model,
/// and Leg D step 8's open question for the ES3): the last keyboard report's
/// modifiers and keys and the last button mask kvm-sim read, on any
/// websocket, in its order.
fn kvm_holds(log: &[SimEvent]) -> (u8, [u8; 5], u8) {
    let mut held = (0, [0; 5], 0);
    for e in log {
        if let SimEvent::Hid { bytes, .. } = e {
            match HidFrame::decode(bytes) {
                Ok(HidFrame::Keyboard { modifiers, keys }) => (held.0, held.1) = (modifiers, keys),
                Ok(HidFrame::AbsMouse { buttons, .. } | HidFrame::Wheel { buttons, .. }) => {
                    held.2 = buttons;
                }
                Ok(HidFrame::SetMode { .. }) => {}
                Err(_) => panic!("kvm-sim read an undecodable frame: {bytes:02x?}"),
            }
        }
    }
    held
}

const NOTHING: (u8, [u8; 5], u8) = (0, [0; 5], 0);
const CMD: (u8, [u8; 5], u8) = (0x08, [0; 5], 0);
/// Set-1 `E0 5B`: the left GUI key, Cmd on the Mac.
const LGUI: u8 = 0x5B;

fn refusals(log: &[SimEvent]) -> usize {
    log.iter()
        .filter(|e| matches!(e, SimEvent::WsRefused { .. }))
        .count()
}

/// A client streaming on a sized ES3 whose websocket carries Cmd held.
async fn holding_cmd(env: &crate::harness::Env) -> crate::client::Client {
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 3).await;
    env.hid_ready().await;
    c.key_extended(LGUI, true);
    env.sim
        .wait_for(T, |l| kvm_holds(l) == CMD)
        .await
        .expect("Cmd never reached the KVM");
    c
}

/// Count of `release_websockets{outcome}` reaching `n` within `limit`.
async fn released(env: &crate::harness::Env, outcome: &str, n: u64, limit: Duration) {
    let m = env.metrics();
    assert!(
        until(limit, || m.release_websockets.get(outcome) >= n).await,
        "release_websockets{{{outcome}}} never reached {n} (all: {})",
        m.release_websockets.total()
    );
}

/// I2: the session ends while the KVM is not reading — Cmd held, kvm-sim's
/// 4 KiB control buffer and the 16 KiB send cap full of a flood, its reads
/// paused — so the release never lands on the session's own websocket (its
/// write blocks, and it is reset). The end opens a release websocket, which
/// kvm-sim takes while paused; once it reads again — the abandoned
/// websocket's stale reports included — the last state it read is released,
/// counted `confirmed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_end_during_a_kvm_stall_is_released_once_it_reads_again() {
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, |c| {
        sized(c);
        c.input.reassert_after = ms(200);
    })
    .await;
    let c = holding_cmd(&env).await;
    let ws = *ws_opens(&env.sim.events()).last().unwrap();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    let flood: Vec<(u8, bool)> = (0..2000)
        .flat_map(|i| {
            let k = [0x1E, 0x30, 0x2E][i % 3];
            [(k, true), (k, false)]
        })
        .collect();
    c.keys(&flood);
    tokio::time::sleep(ms(300)).await;
    c.close();
    // kvm-sim takes the release websocket's upgrade with its reads paused.
    env.sim
        .wait_for(T, |l| ws_opens(l).len() == 2)
        .await
        .expect("no release websocket after the session end");
    tokio::time::sleep(ms(300)).await;
    assert_ne!(
        kvm_holds(&env.sim.events()),
        NOTHING,
        "released before kvm-sim read again"
    );
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    released(&env, "confirmed", 1, T).await;
    let log = env
        .sim
        .wait_for(T, |l| l.contains(&SimEvent::WsClose { conn: ws }))
        .await
        .expect("the stalled websocket never ended");
    assert_eq!(
        kvm_holds(&log),
        NOTHING,
        "the KVM still holds what it read last"
    );
    assert_eq!(env.metrics().release_websockets.total(), 1);
}

/// I2: the session ends while its websocket is down — kvm-sim refusing
/// every reopen — so nothing released the Cmd the KVM read last. The
/// release websocket the end opens delivers the release once kvm-sim takes
/// a websocket again: one websocket at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_end_with_the_websocket_down_is_released_by_a_release_websocket() {
    let env = env(es3(), sized).await;
    let c = holding_cmd(&env).await;
    env.sim.set_policy(|p| p.ws_status = Some(503));
    env.sim.close_websockets();
    env.sim
        .wait_for(T, |l| refusals(l) >= 1)
        .await
        .expect("no reopen was refused");
    let ended = env.metrics().release_all.get("session_end");
    c.close();
    assert!(until(T, || env.metrics().release_all.get("session_end") > ended).await);
    tokio::time::sleep(ms(300)).await;
    assert_eq!(kvm_holds(&env.sim.events()), CMD, "released while down");
    env.sim.set_policy(|p| p.ws_status = None);
    released(&env, "confirmed", 1, T).await;
    let log = env.sim.events();
    assert_eq!(kvm_holds(&log), NOTHING);
    assert_eq!(ws_opens(&log).len(), 2);
    assert_eq!(env.sim.stats().ws_max_open, 1);
}

/// I2, bounded: with kvm-sim refusing every websocket after the session
/// end, the release websocket makes `ATTEMPTS` opens and gives up inside
/// its 10 s budget, counted `failed`, and opens nothing after; never a
/// logout (`Env`'s drop checks it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_websocket_gives_up_inside_its_budget() {
    use kvm_rdp::hid::release::{ATTEMPTS, BUDGET, RETRY_GAP};
    let env = env(es3(), sized).await;
    let c = holding_cmd(&env).await;
    env.sim.set_policy(|p| p.ws_status = Some(503));
    env.sim.close_websockets();
    env.sim
        .wait_for(T, |l| refusals(l) >= 1)
        .await
        .expect("no reopen was refused");
    let ended = env.metrics().release_all.get("session_end");
    c.close();
    assert!(until(T, || env.metrics().release_all.get("session_end") > ended).await);
    let (t0, before) = (std::time::Instant::now(), refusals(&env.sim.events()));
    released(&env, "failed", 1, BUDGET + ms(2000)).await;
    let took = t0.elapsed();
    assert!(took >= RETRY_GAP && took <= BUDGET, "{took:?}");
    let after = refusals(&env.sim.events());
    // The writer's last reopen may still have been in flight at the end.
    assert!(
        after - before <= usize::try_from(ATTEMPTS).unwrap() + 1,
        "{} refused opens after the session end",
        after - before
    );
    tokio::time::sleep(RETRY_GAP * 2).await;
    assert_eq!(
        refusals(&env.sim.events()),
        after,
        "an open after giving up"
    );
    assert_eq!(kvm_holds(&env.sim.events()), CMD);
    assert_eq!(env.metrics().release_websockets.total(), 1);
}

// ---- R-I2 (re-review of the final fix wave): an open during a KVM stall.

/// How long kvm-sim stays stalled past the new websocket's open: three
/// times the production `input.reassert_after`, so the open's timed
/// re-assert fires inside the stall.
const STALL_PAST_OPEN: Duration = Duration::from_secs(3);

/// A sized ES3 with kvm-sim's control buffer at 4 KiB and the production
/// `input.reassert_after` (1 s).
async fn stall_env() -> crate::harness::Env {
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    env(sim, |c| {
        sized(c);
        c.input.reassert_after = REASSERT_AFTER;
    })
    .await
}

/// `pairs` distinct press-release pairs (a, b, c).
fn flood(pairs: usize) -> Vec<(u8, bool)> {
    (0..pairs)
        .flat_map(|i| {
            let k = [0x1E, 0x30, 0x2E][i % 3];
            [(k, true), (k, false)]
        })
        .collect()
}

/// A websocket opened after the first `opens` while kvm-sim stalls with
/// stale Cmd reports in the older websockets' buffers. kvm-sim reads again
/// `STALL_PAST_OPEN` after that open, and reads the older websockets'
/// leftovers and the new one's frames in no set order. The newest
/// websocket re-asserts once more after kvm-sim reads again — `reassert_after`
/// past the pong to its open's ping — so what it reads last is the state:
/// nothing held.
async fn read_again_and_settle(env: &crate::harness::Env, opens: usize) {
    env.sim
        .wait_for(T, |l| ws_opens(l).len() > opens)
        .await
        .expect("no websocket opened during the stall");
    let opened = std::time::Instant::now();
    tokio::time::sleep_until((opened + STALL_PAST_OPEN).into()).await;
    let all = ws_opens(&env.sim.events());
    let older = all[..all.len() - 1].to_vec();
    assert_ne!(
        kvm_holds(&env.sim.events()),
        NOTHING,
        "released before kvm-sim read again"
    );
    let reasserts = env.metrics().hid_reasserts.get();
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    // Once every older websocket has ended, all it will ever deliver is in
    // the log.
    env.sim
        .wait_for(T, |l| {
            older
                .iter()
                .all(|w| l.contains(&SimEvent::WsClose { conn: *w }))
        })
        .await
        .expect("a stalled websocket never ended");
    assert!(
        until(T, || env.metrics().hid_reasserts.get() > reasserts).await,
        "no re-assert once kvm-sim read again: the open's re-assert fired \
         inside the stall, behind the stale reports"
    );
    assert!(
        until(T, || kvm_holds(&env.sim.events()) == NOTHING).await,
        "the KVM still holds {:02x?}: a stale report landed last",
        kvm_holds(&env.sim.events())
    );
    tokio::time::sleep(REASSERT_AFTER).await;
    assert_eq!(
        kvm_holds(&env.sim.events()),
        NOTHING,
        "a stale report landed late"
    );
}

/// R-I2: a takeover while kvm-sim stalls with Cmd held. The old session's
/// release never lands — its writes block, and its websocket is reset —
/// and the takeover's `Start` supersedes the release websocket its end
/// would open, so the new session's open is the release. That open's
/// session start and timed re-assert wait in kvm-sim's buffer while the
/// stall lasts; once it reads again the KVM ends holding nothing, the old
/// websocket's stale Cmd reports included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_during_a_kvm_stall_ends_released() {
    let env = stall_env().await;
    let a = holding_cmd(&env).await;
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    a.keys(&flood(2000));
    tokio::time::sleep(ms(300)).await;
    let opens = ws_opens(&env.sim.events()).len();
    let b = env.client(Opts::new(3)); // the takeover
    read_again_and_settle(&env, opens).await;
    let a_events = a.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&a_events).unwrap(), takeover());
    assert!(terminated(&b.events()).is_none());
    // r-m1: the takeover counted the release websocket it superseded.
    let rw = &env.metrics().release_websockets;
    assert_eq!((rw.get("superseded"), rw.total()), (1, 1));
}

/// R-I2: a websocket lost mid-session while kvm-sim stalls with Cmd held:
/// a write blocks past `hid_write_timeout`, and with input held the reopen
/// skips the backoff, so it opens inside the stall. The reconnect released
/// Cmd — the client still holds it, released by the bridge — so once
/// kvm-sim reads again the KVM must hold nothing, the old websocket's
/// stale Cmd reports included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_during_a_kvm_stall_ends_released() {
    let env = stall_env().await;
    let c = holding_cmd(&env).await;
    let opens = ws_opens(&env.sim.events()).len();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    // Distinct presses, Cmd held, until a write blocks and the websocket
    // reopens.
    let t0 = std::time::Instant::now();
    while ws_opens(&env.sim.events()).len() <= opens {
        assert!(t0.elapsed() < T, "no write blocked");
        c.keys(&flood(400));
        tokio::time::sleep(ms(50)).await;
    }
    assert!(env.metrics().upstream_reconnects.get("websocket_write") >= 1);
    read_again_and_settle(&env, opens).await;
    assert!(terminated(&c.events()).is_none());
}
