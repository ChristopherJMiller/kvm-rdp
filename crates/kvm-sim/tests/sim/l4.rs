//! kvm-probe's L4 checks (Plan D, spec §11.6) against kvm-sim, before they
//! run on the ES3: each produces its report; none logs out. The non-HID
//! checks send no HID frame except `logout-watch`'s one all-zero release;
//! every HID one ends released (`hid::guarded`).
use crate::support::{T, login, sim_with, target};
use kvm_probe::l4::NEVER_ISSUED;
use kvm_probe::l4::flv::{self, ConcurrentPlan, FlvOpen, Side};
use kvm_probe::l4::hid::{self, End, HidWs};
use kvm_probe::l4::session::{self, CapReport, Outcome};
use kvm_probe::l4::ws::{self, Reply, TcpEnd, Upgrade};
use kvm_probe::l4::{hold, page, snapshot, web};
use kvm_proto::hid::HidFrame;
use kvm_sim::{KvmSim, SimEvent};
use std::io::{BufRead as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn no_hid(sim: &KvmSim) {
    assert!(
        !sim.events()
            .iter()
            .any(|e| matches!(e, SimEvent::Hid { .. })),
        "an L4 check sent a HID frame"
    );
    assert_eq!(sim.stats().logouts, 0, "an L4 check logged out");
}

fn no_logout(sim: &KvmSim) {
    assert_eq!(sim.stats().logouts, 0);
}

/// Bounded connections (the checks must be safe on the ES3): every FLV and
/// websocket a check opened is closed once it returns.
async fn all_closed(sim: &KvmSim) {
    let open = sim
        .wait_for(T, |_| {
            let s = sim.stats();
            s.flv_open == 0 && s.ws_open == 0
        })
        .await;
    assert!(
        open.is_ok(),
        "a check left a connection open: {:?}",
        sim.stats()
    );
}

fn plan(trials: u32) -> ConcurrentPlan {
    ConcurrentPlan {
        trials,
        gop: 60,
        timeout: Duration::from_secs(3),
        pause: Duration::from_millis(100),
    }
}

/// kvm-sim's shared encoder forces an IDR into the main FLV whenever a
/// side FLV opens (the ES3's measured behaviour): every trial is served
/// and forced, and the replay count stays far under the ring of 64.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_flv_measures_one_forced_idr_per_side_open() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut lines = 0;
    let trials = flv::concurrent_flv(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &plan(3),
        |_, _| lines += 1,
    )
    .await
    .unwrap();
    assert_eq!((trials.len(), lines), (3, 3));
    for tr in &trials {
        assert!(
            matches!(
                tr.side,
                Side::Served {
                    first_idr_ms: Some(_),
                    ..
                }
            ),
            "{tr:?}"
        );
        assert!(tr.forced, "{tr:?}");
        assert!(tr.main_idr_ms.is_some_and(|ms| ms < 1000), "{tr:?}");
        assert!(tr.replay_aus.is_some_and(|n| n < 30), "{tr:?}");
        assert!(tr.lag_ms.is_some(), "{tr:?}");
    }
    assert!(
        flv::summary(&trials).contains("served=3 refused=0"),
        "{}",
        flv::summary(&trials)
    );
    assert_eq!(sim.stats().logins_ok, 1, "one token for every trial");
    all_closed(&sim).await;
    no_hid(&sim);
}

/// The same-token refusal carry: a side FLV the KVM refuses is recorded
/// with its form, and the run goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_side_flv_is_recorded_with_its_form() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.refuse_concurrent_flv = 1);
    let trials = flv::concurrent_flv(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &plan(2),
        |_, _| {},
    )
    .await
    .unwrap();
    assert!(
        matches!(&trials[0].side, Side::Refused(f) if f.status == 503),
        "{:?}",
        trials[0]
    );
    assert!(!trials[0].forced, "{:?}", trials[0]);
    assert!(
        matches!(trials[1].side, Side::Served { .. }),
        "{:?}",
        trials[1]
    );
    all_closed(&sim).await;
    no_hid(&sim);
}

/// DD1's tokens: a never-issued token and no token, on both services —
/// status, Content-Type and body, escaped — against a valid token's
/// baseline.
#[tokio::test]
async fn refusal_forms_name_status_type_and_body() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let Ok(FlvOpen::Refused(f)) = flv::open(&t, pin, Some(NEVER_ISSUED), T).await else {
        panic!("a never-issued token was served an FLV")
    };
    assert_eq!(
        (f.status, f.content_type.as_str(), f.body.as_str()),
        (403, "application/json", "{\\\"result\\\":403}")
    );
    let Ok(FlvOpen::Refused(f)) = flv::open(&t, pin, None, T).await else {
        panic!("no token was served an FLV")
    };
    assert_eq!(f.status, 403);
    for token in [Some(NEVER_ISSUED), None] {
        let Ok(Upgrade::Refused(f)) = ws::upgrade(&t, pin, token, T).await else {
            panic!("{token:?} upgraded the websocket")
        };
        assert_eq!(f.status, 403, "{token:?}");
    }
    let token = login(&sim).await;
    assert!(matches!(
        flv::open(&t, pin, Some(&token), T).await,
        Ok(FlvOpen::Stream(_))
    ));
    assert!(matches!(
        ws::upgrade(&t, pin, Some(&token), T).await,
        Ok(Upgrade::Accepted(_))
    ));
    all_closed(&sim).await;
    no_hid(&sim);
}

/// The close-form carry: the report says how the KVM answered a close
/// frame and how its TCP connection ended, within the wait; nothing but a
/// close frame was sent.
#[tokio::test]
async fn ws_close_reports_the_answer_and_the_tcp_end() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let Ok(Upgrade::Accepted(w)) =
        ws::upgrade(&target(&sim), Some(sim.spki_sha256()), Some(&token), T).await
    else {
        panic!("not upgraded")
    };
    let r = ws::close_form(*w, Duration::from_millis(200), Duration::from_secs(2)).await;
    assert!(!r.idle.closed_by_kvm, "{r:?}");
    assert!(!matches!(r.reply, Reply::Timeout), "{r:?}");
    assert!(!matches!(r.tcp, TcpEnd::Timeout), "{r:?}");
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsClose { .. }))
    })
    .await
    .unwrap();
    all_closed(&sim).await;
    no_hid(&sim);
}

/// DC18's token question: each token is probed once, at its age, with a
/// bare websocket upgrade; one that lapsed meanwhile (here: expired by the
/// sim) is refused with its form. The expiry is gated on the 500 ms
/// probe's report, not on a clock that the logins before `t0` could
/// outrun on a loaded host (D15). Each probe comes no earlier than its
/// age: `t0` follows the logins, so it follows `start` too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_life_probes_each_token_once_at_its_age() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let ages = [
        Duration::ZERO,
        Duration::from_millis(500),
        Duration::from_millis(1500),
    ];
    let mut seen = Vec::new();
    let start = std::time::Instant::now();
    let gate = tokio::sync::Notify::new();
    let expire = async {
        gate.notified().await;
        sim.expire_tokens();
    };
    let (probes, ()) = tokio::join!(
        session::token_life(&t, pin, pin, sim.password(), &ages, T, |p| {
            seen.push((p.age, start.elapsed()));
            if p.age == Duration::from_millis(500) {
                gate.notify_one();
            }
        }),
        expire
    );
    let probes = probes.unwrap();
    let accepted: Vec<bool> = probes
        .iter()
        .map(|p| p.outcome == Outcome::Accepted)
        .collect();
    assert_eq!(accepted, [true, true, false], "{probes:?}");
    assert!(
        matches!(&probes[2].outcome, Outcome::Refused(f) if f.status == 403),
        "{probes:?}"
    );
    assert_eq!(seen.iter().map(|(age, _)| *age).collect::<Vec<_>>(), ages);
    assert!(seen.iter().all(|(age, at)| at >= age), "{seen:?}");
    assert_eq!(sim.stats().logins_ok, 3);
    all_closed(&sim).await;
    no_hid(&sim);
}

/// DC18's session-cap question: logins up to the bound, each checked by a
/// bare upgrade of the first and the newest token; a refused first login
/// is the error.
#[tokio::test]
async fn session_cap_counts_logins_while_every_token_works() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let r = session::session_cap(&t, pin, pin, sim.password(), 5, T, |_, _| {})
        .await
        .unwrap();
    assert_eq!(
        r,
        CapReport {
            logins: 5,
            stopped: None
        }
    );
    sim.set_policy(|p| p.reject_logins = true);
    assert!(
        session::session_cap(&t, pin, pin, sim.password(), 5, T, |_, _| {})
            .await
            .is_err()
    );
    all_closed(&sim).await;
    no_hid(&sim);
}

/// Controller ruling 1 (`logout-watch`): the probe never logs out; the
/// "owner" here is a second session that logs out (`support::logout`,
/// kvm-sim's global logout) once the probe says READY. The probe sees its
/// token refused, records both refusal forms, and reports that the
/// websocket and FLV it opened before the logout survived it (kvm-sim's
/// model, §11.5) — on the ES3 that is the fact Task 1.6 step 16 records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_watch_records_the_forms_after_someone_elses_logout() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let owner = login(&sim).await;
    let ready = tokio::sync::Notify::new();
    let owner_logs_out = async {
        ready.notified().await;
        crate::support::logout(&sim, &owner).await;
    };
    let (r, ()) = tokio::join!(
        session::logout_watch(
            &t,
            pin,
            pin,
            pin,
            sim.password(),
            session::WatchPlan {
                max: Duration::from_secs(10),
                poll: Duration::from_millis(100),
            },
            || ready.notify_one(),
        ),
        owner_logs_out
    );
    let r = r.unwrap();
    assert!(r.logged_out_after.is_some(), "{r:?}");
    assert!(matches!(&r.flv_form, Some(f) if f.status == 403), "{r:?}");
    assert!(matches!(&r.ws_form, Some(f) if f.status == 403), "{r:?}");
    assert!(r.ws_survived && r.ws_write_ok && r.flv_survived, "{r:?}");
    // Exactly one logout — the owner's; the probe sent none.
    assert_eq!(sim.stats().logouts, 1);
    // The probe's only HID frame is its one all-zero report.
    let hid: Vec<_> = sim
        .events()
        .into_iter()
        .filter_map(|e| {
            if let SimEvent::Hid { bytes, .. } = e {
                Some(bytes)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(hid, [vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
    all_closed(&sim).await;
}

fn hid_on_ws(sim: &KvmSim, nth: usize) -> Vec<Vec<u8>> {
    let log = sim.events();
    let conn = log
        .iter()
        .filter_map(|e| {
            if let SimEvent::WsOpen { conn } = e {
                Some(*conn)
            } else {
                None
            }
        })
        .nth(nth)
        .unwrap_or_else(|| panic!("no websocket {nth}: {log:?}"));
    log.iter()
        .filter_map(|e| match e {
            SimEvent::Hid { conn: c, bytes } if *c == conn => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn ws_opens(sim: &KvmSim) -> usize {
    sim.events()
        .iter()
        .filter(|e| matches!(e, SimEvent::WsOpen { .. }))
        .count()
}

async fn hid_count(sim: &KvmSim, nth: usize, n: usize) -> Vec<Vec<u8>> {
    sim.wait_for(T, |_| ws_opens(sim) > nth && hid_on_ws(sim, nth).len() >= n)
        .await
        .unwrap();
    hid_on_ws(sim, nth)
}

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    HidFrame::Keyboard {
        modifiers,
        keys: [k, 0, 0, 0, 0],
    }
    .to_vec()
}

fn session_start() -> [Vec<u8>; 2] {
    [HidFrame::SetMode { hid_type: 0 }.to_vec(), kbd(0, 0)]
}

/// The test page's reset (PD3 R-I1): a Right Ctrl tap — a modifier-only
/// report, then an all-zero one. Never Esc.
fn reset_tap() -> [Vec<u8>; 2] {
    [kbd(0x10, 0), kbd(0, 0)]
}

/// PD3 R-I1: nothing the probe types can be a shell key sequence or a
/// shortcut. In zsh a lone ESC is a prefix with no timeout, so ESC then a
/// character is a command whatever the gap (ESC-a, accept-and-hold, runs
/// the command line); Alt/Option then a character is the same sequence in
/// a terminal set to send Meta as ESC. So across every keyboard report of
/// a stream: no Esc (usage 0x29) anywhere; no Alt/Option or Cmd bit ever;
/// Ctrl only in the reset tap — with no key, and released by the very
/// next report; a key only with no modifier or Left Shift.
fn assert_safe_typing(frames: &[Vec<u8>]) {
    const ALT_GUI: u8 = 0x04 | 0x40 | 0x08 | 0x80;
    const CTRL: u8 = 0x01 | 0x10;
    let kb: Vec<(u8, [u8; 5])> = frames
        .iter()
        .filter_map(|f| match HidFrame::decode(f) {
            Ok(HidFrame::Keyboard { modifiers, keys }) => Some((modifiers, keys)),
            _ => None,
        })
        .collect();
    assert!(!kb.is_empty(), "no keyboard report to check");
    for (i, &(m, keys)) in kb.iter().enumerate() {
        assert!(!keys.contains(&0x29), "Esc in report {i}: {kb:?}");
        assert_eq!(m & ALT_GUI, 0, "Alt/Option or Cmd in report {i}");
        let key = keys.iter().any(|&k| k != 0);
        if m & CTRL != 0 {
            assert!(!key, "Ctrl with a key in report {i}");
            assert_eq!(
                kb.get(i + 1),
                Some(&(0, [0; 5])),
                "the Ctrl tap in report {i} is not released by the next report"
            );
        }
        if key {
            assert_eq!(m & !0x02, 0, "a key with modifiers {m:#04x} in report {i}");
        }
    }
}

/// §3.3's session start, the Right Ctrl tap that resets the test page,
/// then one press and one all-zero release per character, Shift in the
/// press for a shifted one (§8's report sequence). `reports` counts the
/// text only. Never an Esc, never an Alt/Option prefix (PD3 R-I1).
#[tokio::test]
async fn a_hid_websocket_starts_the_session_and_types_press_release_pairs() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut w = HidWs::open(&target(&sim), Some(sim.spki_sha256()), &token, T)
        .await
        .unwrap();
    let report = hid::type_text(&mut w, "aB1", Duration::ZERO).await.unwrap();
    assert_eq!(
        (report.chars, report.reports, report.expected_len),
        (3, 6, 3)
    );
    assert_eq!(report.expected_hash, page::fnv1a32("aB1"));
    let got = hid_count(&sim, 0, 10).await;
    assert_eq!(
        got,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            kbd(0x10, 0),
            kbd(0, 0),
            kbd(0, 0x04),
            kbd(0, 0),
            kbd(0x02, 0x05),
            kbd(0, 0),
            kbd(0, 0x1E),
            kbd(0, 0),
        ]
    );
    assert_safe_typing(&got);
    w.end(End::CloseFrame).await;
    no_logout(&sim);
}

/// A key is never left held: a websocket reset with a key down is followed
/// by a fresh websocket whose session start releases it, with the pointer
/// at the given position (never (0, 0)).
#[tokio::test]
async fn ensure_released_opens_a_fresh_websocket_that_releases() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut w = HidWs::open(&t, pin, &token, T).await.unwrap();
    w.send(HidFrame::Keyboard {
        modifiers: 0,
        keys: [0x04, 0, 0, 0, 0],
    })
    .await
    .unwrap();
    hid_count(&sim, 0, 3).await;
    w.end(End::Reset).await;
    hid::ensure_released(&t, pin, &token, Some((100, 200)))
        .await
        .unwrap();
    assert_eq!(
        hid_count(&sim, 1, 3).await,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            HidFrame::abs_mouse(0, 100, 200).to_vec(),
        ]
    );
    no_logout(&sim);
}

/// When no websocket can be opened, `ensure_released` gives up after its
/// window and says a key may be held — loud, never silent.
#[tokio::test]
async fn ensure_released_says_a_key_may_be_held_when_it_cannot_reach_the_kvm() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.ws_status = Some(503));
    let e = hid::ensure_released_within(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        None,
        Duration::from_millis(600),
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("KEY MAY BE HELD"), "{e:?}");
}

/// `guarded` releases after its body, whether the body succeeded or not.
#[tokio::test]
async fn guarded_releases_after_a_failing_body() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let r: Result<(), _> = hid::guarded(&t, pin, &token, None, &mut irq, async {
        let mut w = HidWs::open(&t, pin, &token, T).await?;
        w.send(HidFrame::Keyboard {
            modifiers: 0x08,
            keys: [0; 5],
        })
        .await?;
        w.end(End::Fin).await;
        Err(kvm_probe::kvm::KvmError::Io("the body failed".to_owned()))
    })
    .await;
    assert!(r.is_err());
    assert_eq!(hid_count(&sim, 1, 2).await, session_start());
    // PD3 I1: a body that ran and did not end Ok is released twice, the
    // second time `SECOND_RELEASE_AFTER` later.
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(ws_opens(&sim), 3);
}

/// ...and after a body that succeeded with a key still down (the release
/// is not the body's job), with the result passed through.
#[tokio::test]
async fn guarded_releases_after_a_successful_body() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let r = hid::guarded(&t, pin, &token, Some((7, 9)), &mut irq, async {
        let mut w = HidWs::open(&t, pin, &token, T).await?;
        w.send(HidFrame::Keyboard {
            modifiers: 0,
            keys: [0x04, 0, 0, 0, 0],
        })
        .await?;
        w.end(End::Fin).await;
        Ok(42)
    })
    .await;
    assert_eq!(r.unwrap(), 42);
    assert_eq!(
        hid_count(&sim, 1, 3).await,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            HidFrame::abs_mouse(0, 7, 9).to_vec(),
        ]
    );
    no_logout(&sim);
}

/// ...and after a body that panicked with a key down: the panic is caught,
/// the release runs, and the panic is the error (D6: every exit path).
#[tokio::test]
async fn guarded_releases_after_a_panicking_body() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let r: Result<(), _> = hid::guarded(&t, pin, &token, None, &mut irq, async {
        let mut w = HidWs::open(&t, pin, &token, T).await?;
        w.send(HidFrame::Keyboard {
            modifiers: 0x08,
            keys: [0x19, 0, 0, 0, 0],
        })
        .await?;
        hid_count(&sim, 0, 3).await;
        panic!("the body panicked with Cmd-V down");
    })
    .await;
    let e = r.unwrap_err();
    assert!(format!("{e:?}").contains("panicked"), "{e:?}");
    assert_eq!(hid_count(&sim, 1, 2).await, session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(ws_opens(&sim), 3);
    no_logout(&sim);
}

const PRESS_A: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0x04, 0, 0, 0, 0],
};

/// Every HID frame kvm-sim read, in order.
fn all_hid(sim: &KvmSim) -> Vec<Vec<u8>> {
    sim.events()
        .into_iter()
        .filter_map(|e| match e {
            SimEvent::Hid { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect()
}

/// When each websocket opened, as kvm-sim stamped it.
fn ws_open_times(sim: &KvmSim) -> Vec<std::time::Instant> {
    sim.stamped_events()
        .into_iter()
        .filter_map(|(at, e)| matches!(e, SimEvent::WsOpen { .. }).then_some(at))
        .collect()
}

/// PD3 I1 (a): a websocket dropped without `end` — a body abandoned on an
/// error, a panic or a signal — is reset (`SO_LINGER` 0), so what is
/// still queued for it is discarded, never delivered after the release.
/// With kvm-sim's reads paused the writes back up until one times out;
/// once reads resume, kvm-sim gets fewer frames than were written — never
/// the whole backlog, as an ordinary close (a FIN) would deliver it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_websocket_is_reset_so_its_queued_tail_is_never_delivered() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut w = HidWs::open(&target(&sim), Some(sim.spki_sha256()), &token, T)
        .await
        .unwrap();
    hid_count(&sim, 0, 2).await;
    sim.set_policy(|p| p.pause_ws_reads = true);
    let mut written = 2usize;
    while w.send(PRESS_A).await.is_ok() {
        written += 1;
        assert!(written < 1_000_000, "the writes never backed up");
    }
    drop(w);
    sim.set_policy(|p| p.pause_ws_reads = false);
    all_closed(&sim).await;
    let got = hid_on_ws(&sim, 0).len();
    assert!(
        got < written,
        "the whole backlog was delivered: {got} of {written}"
    );
    no_logout(&sim);
}

/// PD3 I1 (b): what the KVM had already received from an abandoned body
/// may still be read after the release (kvm-sim reads it once reads
/// resume), so a body that ran and did not end Ok is released a second
/// time `SECOND_RELEASE_AFTER` (5 s) after the first: the last frame the
/// KVM reads is a zero report, never the body's press. Here the first
/// release goes unanswered (reads paused), reads resume before the
/// second, and the backlog of presses lands between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guarded_releases_twice_after_a_failed_body_so_its_tail_never_lands_last() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let resume = async {
        sim.wait_for(Duration::from_secs(20), |_| ws_opens(&sim) >= 2)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        sim.set_policy(|p| p.pause_ws_reads = false);
    };
    let body = async {
        let mut w = HidWs::open(&t, pin, &token, T).await?;
        hid_count(&sim, 0, 2).await;
        sim.set_policy(|p| p.pause_ws_reads = true);
        loop {
            w.send(PRESS_A).await?;
        }
    };
    let (r, ()) = tokio::join!(
        hid::guarded::<()>(&t, pin, &token, None, &mut irq, body),
        resume
    );
    // PD3 R-m1: kvm-sim answers neither release's close frame, so after a
    // failed body the result is KEY MAY BE HELD, the body's error inside it.
    let e = format!("{:?}", r.unwrap_err());
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    assert!(e.contains("longer than"), "{e}");
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 3, "{:?}", sim.stats());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    let opens = ws_open_times(&sim);
    let apart = opens[2].saturating_duration_since(opens[1]);
    assert!(apart >= Duration::from_millis(4500), "{apart:?}");
    no_logout(&sim);
}

/// PD3 I1 (c): a release is confirmed only by the KVM's answer to its
/// close frame. kvm-sim never answers one (it drops the connection), and
/// with its reads paused it does not even do that: both are unconfirmed,
/// never "released". (The confirmed case is proven against a stub that
/// answers, in kvm-probe's `stubs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_the_kvm_never_answers_is_unconfirmed() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let r = hid::release(&t, pin, &token, None, T).await.unwrap();
    assert!(matches!(r, hid::Released::Unconfirmed(_)), "{r:?}");
    sim.set_policy(|p| p.pause_ws_reads = true);
    let r = hid::release(&t, pin, &token, None, T).await.unwrap();
    assert_eq!(r, hid::Released::Unconfirmed("no answer within 2 s"));
    sim.set_policy(|p| p.pause_ws_reads = false);
    all_closed(&sim).await;
    assert_eq!(hid_on_ws(&sim, 0), session_start());
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    no_logout(&sim);
}

fn refusals(sim: &KvmSim) -> usize {
    sim.events()
        .iter()
        .filter(|e| matches!(e, SimEvent::WsRefused { .. }))
        .count()
}

/// PD3 m1: `hid-type` stops at a failed run. Its typing websocket is
/// refused; the error is the result, the run's section releases (twice,
/// since its body ran and failed), and no later run types — though the
/// KVM would take one by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn type_runs_stops_after_a_failed_run() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut irq = hid::Interrupts::new().unwrap();
    sim.set_policy(|p| p.ws_status = Some(503));
    let clear = async {
        sim.wait_for(T, |_| refusals(&sim) >= 1).await.unwrap();
        sim.set_policy(|p| p.ws_status = None);
    };
    let plan = hid::TypePlan::new(3, &[0], 3);
    let mut lines = Vec::new();
    let t = target(&sim);
    let (r, ()) = tokio::join!(
        hid::type_runs(&t, Some(sim.spki_sha256()), &token, &plan, &mut irq, |l| {
            lines.push(l)
        }),
        clear
    );
    let e = r.unwrap_err();
    assert!(e.contains("refused"), "{e}");
    assert!(lines.is_empty(), "{lines:?}");
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 2, "a later run started: {:?}", sim.stats());
    assert_eq!(hid_on_ws(&sim, 0), session_start());
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    no_logout(&sim);
}

/// PD3 m1: ...and at a failed release: the run typed, its release cannot
/// get through within the window, so the result is KEY MAY BE HELD and no
/// later run types — even once the KVM would take one again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn type_runs_stops_after_a_failed_release() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut irq = hid::Interrupts::new().unwrap();
    let plan = hid::TypePlan {
        release_window: Duration::from_millis(600),
        ..hid::TypePlan::new(3, &[0], 3)
    };
    let block = async {
        sim.wait_for(T, |_| ws_opens(&sim) >= 1).await.unwrap();
        sim.set_policy(|p| p.ws_status = Some(503));
        sim.wait_for(T, |_| refusals(&sim) >= 2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        sim.set_policy(|p| p.ws_status = None);
        tokio::time::sleep(Duration::from_millis(1500)).await;
    };
    let mut lines = Vec::new();
    let t = target(&sim);
    let (r, ()) = tokio::join!(
        hid::type_runs(&t, Some(sim.spki_sha256()), &token, &plan, &mut irq, |l| {
            lines.push(l)
        }),
        block
    );
    let e = r.unwrap_err();
    assert!(e.contains("KEY MAY BE HELD"), "{e}");
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(ws_opens(&sim), 1, "a later run started: {:?}", sim.stats());
    assert!(refusals(&sim) <= 4, "{}", refusals(&sim));
    no_logout(&sim);
}

/// PD3 m3/m4 (and the burst bounds): `type_runs` refuses more than
/// `MAX_RUNS` runs, more than `MAX_PACES` paces, a pace given twice, more
/// than `MAX_CHARS` characters and a pace past `MAX_PACE` — before it
/// connects or types anything.
#[tokio::test]
async fn type_runs_refuses_its_bounds_before_anything_types() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut irq = hid::Interrupts::new().unwrap();
    let nine: Vec<u64> = (0..9).collect();
    for (plan, why) in [
        (hid::TypePlan::new(3, &[0], hid::MAX_RUNS + 1), "--runs"),
        (hid::TypePlan::new(3, &[0], 0), "--runs"),
        (hid::TypePlan::new(3, &nine, 1), "--paces"),
        (hid::TypePlan::new(3, &[0, 5, 0], 1), "twice"),
        (hid::TypePlan::new(hid::MAX_CHARS + 1, &[0], 1), "--chars"),
        (hid::TypePlan::new(3, &[101], 1), "--paces"),
    ] {
        let e = hid::type_runs(
            &target(&sim),
            Some(sim.spki_sha256()),
            &token,
            &plan,
            &mut irq,
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains(why), "{why}: {e}");
    }
    assert_eq!(ws_opens(&sim), 0);
    assert_eq!(sim.stats().accepts_control, 0);
}

/// PD3 m7: a release refused for a token that lapsed mid-command logs in
/// again — once — and releases with the fresh token; that does not
/// count as a failed run. Once the one fresh login is spent, a release
/// that is still refused ends in KEY MAY BE HELD, with no further login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_refused_for_a_lapsed_token_logs_in_again_once() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let relogin = || hid::Relogin {
        web_pin: pin,
        password: sim.password(),
    };
    let plan = hid::TypePlan {
        relogin: Some(relogin()),
        ..hid::TypePlan::new(3, &[0], 1)
    };
    let lapse = async {
        sim.wait_for(T, |_| ws_opens(&sim) >= 1).await.unwrap();
        sim.expire_tokens();
    };
    let mut lines = Vec::new();
    // Bounded, so a release path that never stops logging in fails fast.
    let (r, ()) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(
            hid::type_runs(&t, pin, &token, &plan, &mut irq, |l| lines.push(l)),
            lapse
        )
    })
    .await
    .expect("type_runs never returned");
    r.unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(sim.stats().logins_ok, 2);
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 2);
    assert_eq!(hid_on_ws(&sim, 1), session_start());

    // Every upgrade refused: one fresh login, then KEY MAY BE HELD.
    let token = login(&sim).await;
    let logins = sim.stats().logins_ok;
    let plan = hid::TypePlan {
        relogin: Some(relogin()),
        release_window: Duration::from_millis(600),
        ..hid::TypePlan::new(3, &[0], 1)
    };
    let refuse = async {
        sim.wait_for(T, |_| ws_opens(&sim) >= 3).await.unwrap();
        sim.set_policy(|p| p.ws_status = Some(403));
    };
    let (r, ()) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(
            hid::type_runs(&t, pin, &token, &plan, &mut irq, |_| {}),
            refuse
        )
    })
    .await
    .expect("type_runs never returned");
    let e = r.unwrap_err();
    assert!(e.contains("KEY MAY BE HELD"), "{e}");
    assert_eq!(sim.stats().logins_ok, logins + 1);
    no_logout(&sim);
}

/// No burst is unbounded: `type_text` refuses more than `MAX_CHARS`
/// characters, or a pace past `MAX_PACE` (a key is held for one pace),
/// before it sends anything; at the bounds it types.
#[tokio::test]
async fn type_text_refuses_an_unbounded_burst_before_sending_anything() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut w = HidWs::open(&target(&sim), Some(sim.spki_sha256()), &token, T)
        .await
        .unwrap();
    let over = page::pattern(hid::MAX_CHARS + 1);
    let e = hid::type_text(&mut w, &over, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(format!("{e:?}").contains("at most 500"), "{e:?}");
    let slow = hid::MAX_PACE + Duration::from_millis(1);
    let e = hid::type_text(&mut w, "a", slow).await.unwrap_err();
    assert!(format!("{e:?}").contains("pace"), "{e:?}");
    let at = page::pattern(hid::MAX_CHARS);
    let r = hid::type_text(&mut w, &at, Duration::ZERO).await.unwrap();
    assert_eq!(
        (r.chars, r.reports),
        (hid::MAX_CHARS, 2 * hid::MAX_CHARS as u64)
    );
    w.end(End::CloseFrame).await;
    all_closed(&sim).await;
    let want = 4 + 2 * hid::MAX_CHARS;
    let got = hid_on_ws(&sim, 0);
    // The refused calls sent nothing: the session start, then the one reset
    // tap of the call that typed.
    assert_eq!(got.len(), want);
    assert_eq!(got[..4], [session_start(), reset_tap()].concat());
    assert_eq!(got[4], kbd(0, 0x04));
    assert_safe_typing(&got);
    no_logout(&sim);
}

/// `hid-type`'s loop: each pace × run on its own websocket, each followed
/// by a release websocket, one line per run; nothing but the pattern is
/// typed.
#[tokio::test]
async fn hid_type_runs_type_each_run_on_its_own_websocket_and_release_after_each() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut irq = hid::Interrupts::new().unwrap();
    // 30 characters: lower case, then upper case (Shift) from the 27th.
    let plan = hid::TypePlan::new(30, &[0, 1], 2);
    let text = page::pattern(30);
    let mut lines = Vec::new();
    hid::type_runs(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &plan,
        &mut irq,
        |l| lines.push(l),
    )
    .await
    .unwrap();
    assert_eq!(lines.len(), 4, "{lines:?}");
    for (line, want) in lines.iter().zip([
        "pace 0 ms, run 1/2",
        "pace 0 ms, run 2/2",
        "pace 1 ms, run 1/2",
        "pace 1 ms, run 2/2",
    ]) {
        assert!(line.starts_with(want), "{line}");
        assert!(
            line.contains(&format!("expect page: text 30 {:x}", page::fnv1a32(&text))),
            "{line}"
        );
    }
    // The US layout's strokes, built here (not with `hid::press`): Shift
    // (0x02) and nothing else with a shifted character.
    let strokes: Vec<Vec<u8>> = text
        .chars()
        .flat_map(|c| {
            let s = kvm_proto::keymap::us_stroke(c).unwrap();
            [kbd(if s.shift { 0x02 } else { 0 }, s.usage), kbd(0, 0)]
        })
        .collect();
    let typed: Vec<Vec<u8>> = [session_start().to_vec(), reset_tap().to_vec(), strokes].concat();
    all_closed(&sim).await;
    for run in 0..4 {
        assert_eq!(hid_on_ws(&sim, 2 * run), typed, "run {run}");
        assert_eq!(
            hid_on_ws(&sim, 2 * run + 1),
            session_start(),
            "release {run}"
        );
    }
    assert_eq!(ws_opens(&sim), 8);
    // PD3 R-I1: no stream hid-type sends — runs and releases — holds an Esc
    // or an Alt/Option prefix.
    assert_safe_typing(&all_hid(&sim));
    assert_eq!(sim.stats().logins_ok, 1);
    no_logout(&sim);
}

/// `snapshot`'s capture: the stream up to and including its first IDR,
/// which demuxes to the sequence header and that IDR.
#[tokio::test]
async fn write_first_idr_captures_through_the_first_idr() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.flv");
    let mut f = std::fs::File::create(&path).unwrap();
    let n = snapshot::write_first_idr(&target(&sim), Some(sim.spki_sha256()), &token, &mut f, T)
        .await
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(u64::try_from(bytes.len()).unwrap(), n);
    let mut d = kvm_proto::flv::FlvDemuxer::new(kvm_proto::flv::FlvLimits::default());
    d.push(&bytes);
    let mut idr = false;
    while let Some(tag) = d.next_tag().unwrap() {
        idr |= flv::is_coded(&tag) && flv::is_idr(&tag);
    }
    assert!(idr, "no IDR in the snapshot capture");
    no_hid(&sim);
}

/// The whole snapshot against kvm-sim: the capture and the PNG land in the
/// 0700 captures dir, decoded by the real bwrap sandbox.
#[tokio::test]
#[ignore = "live: needs bwrap and ffmpeg from the devshell, and unprivileged user namespaces"]
async fn snapshot_decodes_one_idr_to_a_png_in_the_sandbox() {
    use std::os::unix::fs::PermissionsExt as _;
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("captures");
    let dir = kvm_probe::captures::CaptureDir::create(&root).unwrap();
    let ffmpeg = kvm_probe::sandbox::resolve_ffmpeg().unwrap();
    let png = snapshot::snapshot(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &dir,
        "snap",
        &ffmpeg,
    )
    .await
    .unwrap();
    assert_eq!(png, root.join("snap.flv.png"));
    assert!(
        std::fs::read(&png)
            .unwrap()
            .starts_with(b"\x89PNG\r\n\x1a\n")
    );
    let mode = std::fs::metadata(&root).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    no_hid(&sim);
}

// --- Task 1.5: hid-hold, hid-stale, web-get.

/// A key held when the websocket is reset: kvm-sim records the session
/// start and the held press, and nothing after it on that socket. (On the
/// real ES3 the agent reads the page by snapshot; here, the mechanics.)
/// The press is '1' alone: no modifier, no Esc (PD3 R-I1).
#[tokio::test]
async fn hid_hold_holds_one_key_and_ends_the_way_it_was_told() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let r = hold::hold_then_kill(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        hold::HOLD_USAGE,
        End::Reset,
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    assert_eq!(r.end, End::Reset);
    let got = hid_count(&sim, 0, 3).await;
    assert_eq!(
        got,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            kbd(0, 0x1E)
        ]
    );
    all_closed(&sim).await;
    assert_eq!(hid_on_ws(&sim, 0), got, "a frame after the held press");
    assert_eq!(ws_opens(&sim), 1);
    assert_safe_typing(&all_hid(&sim));
    no_logout(&sim);
}

/// `hid-hold` holds `HOLD_USAGE` and nothing else: any other usage (Esc,
/// a letter, a modifier's usage), or a hold past `MAX_OBSERVE`, is refused
/// before anything connects.
#[tokio::test]
async fn hid_hold_refuses_any_other_key_or_an_unbounded_hold_before_connecting() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    for (usage, observe) in [
        (0x29, Duration::from_millis(10)),
        (0x04, Duration::from_millis(10)),
        (0xE3, Duration::from_millis(10)),
        (0x00, Duration::from_millis(10)),
        (
            hold::HOLD_USAGE,
            hold::MAX_OBSERVE + Duration::from_millis(1),
        ),
    ] {
        let e = hold::hold_then_kill(&t, pin, &token, usage, End::Fin, observe)
            .await
            .unwrap_err();
        assert!(format!("{e:?}").contains("hid-hold"), "{usage:#04x}: {e:?}");
    }
    assert_eq!(ws_opens(&sim), 0);
    assert_eq!(sim.stats().accepts_control, 0);
    no_logout(&sim);
}

/// What one `hid-hold` / `hid-stale` snapshot hook saw: the suffix it was
/// called with and how many websockets kvm-sim had opened by then.
type Shots = std::sync::Mutex<Vec<(String, usize)>>;

/// A snapshot hook that records into `shots` and succeeds.
macro_rules! record_into {
    ($shots:expr, $sim:expr) => {
        async |suffix: &str, _token: &str| {
            $shots
                .lock()
                .unwrap()
                .push((suffix.to_owned(), ws_opens($sim)));
            Ok(())
        }
    };
}

/// `hid-hold`'s whole run (Task 1.6 step 8): the held press, the `_held`
/// snapshot while nothing has released it, then two releases
/// `SECOND_RELEASE_AFTER` apart — its body left '1' last on a dead
/// websocket, so it always releases twice (PD4 I2) — then the `_released`
/// snapshot. kvm-sim answers neither release's close frame, so the result
/// is KEY MAY BE HELD with the remedy (PD3 R-m1), and `_released` is still
/// taken: it is how `held -` is checked. The last frame kvm-sim read is a
/// zero report.
#[tokio::test]
async fn hid_hold_snapshots_the_held_key_then_ends_released() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let shots = Shots::default();
    let e = hold::hid_hold(
        &t,
        pin,
        &token,
        &hold::HoldPlan::new(End::Fin, Duration::from_millis(200)),
        &mut irq,
        record_into!(shots, &sim),
    )
    .await
    .unwrap_err();
    let e = format!("{e:?}");
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    assert_eq!(
        *shots.lock().unwrap(),
        [("_held".to_owned(), 1), ("_released".to_owned(), 3)]
    );
    assert_eq!(hold::SHOTS, ["_held", "_released"]);
    all_closed(&sim).await;
    assert_eq!(
        hid_on_ws(&sim, 0),
        [session_start().to_vec(), vec![kbd(0, 0x1E)]].concat()
    );
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(ws_opens(&sim), 3);
    let opens = ws_open_times(&sim);
    let apart = opens[2].saturating_duration_since(opens[1]);
    assert!(apart >= Duration::from_millis(4500), "{apart:?}");
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    assert_safe_typing(&all_hid(&sim));
    no_logout(&sim);
}

/// ...and when its `_held` snapshot fails (with '1' still held), the
/// release runs twice, `SECOND_RELEASE_AFTER` apart; the result is KEY MAY
/// BE HELD, the snapshot's error inside, and `_released` is still taken
/// after both releases.
#[tokio::test]
async fn hid_hold_releases_twice_when_its_held_snapshot_fails() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let shots = Shots::default();
    let e = hold::hid_hold(
        &t,
        pin,
        &token,
        &hold::HoldPlan::new(End::Reset, Duration::from_millis(200)),
        &mut irq,
        async |suffix: &str, _token: &str| {
            shots
                .lock()
                .unwrap()
                .push((suffix.to_owned(), ws_opens(&sim)));
            if suffix == "_held" {
                Err(kvm_probe::kvm::KvmError::Io(
                    "the snapshot failed".to_owned(),
                ))
            } else {
                Ok(())
            }
        },
    )
    .await
    .unwrap_err();
    let e = format!("{e:?}");
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    assert!(e.contains("the snapshot failed"), "{e}");
    assert_eq!(
        *shots.lock().unwrap(),
        [("_held".to_owned(), 1), ("_released".to_owned(), 3)]
    );
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 3);
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    let opens = ws_open_times(&sim);
    let apart = opens[2].saturating_duration_since(opens[1]);
    assert!(apart >= Duration::from_millis(4500), "{apart:?}");
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    assert_safe_typing(&all_hid(&sim));
    no_logout(&sim);
}

/// PD4 I2, the review's reproduction: kvm-sim's reads are paused before
/// `hid-hold` and resumed after it returns (`--observe-ms 0`, no
/// snapshot), so the held '1' and both releases are all read late, in any
/// order. A successful run releases twice, and with neither release
/// confirmed it is never Ok: KEY MAY BE HELD with the remedy, every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hid_hold_whose_releases_are_stalled_is_never_ok() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    sim.set_policy(|p| p.pause_ws_reads = true);
    let r = hold::hid_hold(
        &t,
        pin,
        &token,
        &hold::HoldPlan::new(End::Reset, Duration::ZERO),
        &mut irq,
        async |_: &str, _: &str| Ok(()),
    )
    .await;
    sim.set_policy(|p| p.pause_ws_reads = false);
    let e = format!("{:?}", r.unwrap_err());
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 3, "{:?}", sim.stats());
    // Drained before the reset (I1): the press reached kvm-sim whole.
    assert_eq!(
        hid_on_ws(&sim, 0),
        [session_start().to_vec(), vec![kbd(0, 0x1E)]].concat()
    );
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    no_logout(&sim);
}

/// PD4 m1: '1' is held for a bounded time, snapshot included. A `_held`
/// snapshot that hangs is cut off at the plan's `shot_window`, the
/// section releases (twice: it failed), and the run is loud. The default
/// window is `hid::SHOT_WINDOW` (10 s), so `hold::MAX_HELD` — observe,
/// drain, end and the `_held` snapshot, each bounded — is 24 s.
#[tokio::test]
async fn a_hung_held_snapshot_is_cut_off_and_the_key_released() {
    assert_eq!(hid::SHOT_WINDOW, Duration::from_secs(10));
    assert_eq!(hold::MAX_HELD, Duration::from_secs(24));
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let plan = hold::HoldPlan {
        shot_window: Duration::from_millis(300),
        ..hold::HoldPlan::new(End::Fin, Duration::from_millis(100))
    };
    let opened = std::sync::Mutex::new(None);
    let started = std::time::Instant::now();
    let e = hold::hid_hold(
        &t,
        pin,
        &token,
        &plan,
        &mut irq,
        async |suffix: &str, _: &str| {
            if suffix == "_held" {
                *opened.lock().unwrap() = Some(ws_opens(&sim));
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(())
        },
    )
    .await
    .unwrap_err();
    let e = format!("{e:?}");
    assert!(e.contains("KEY MAY BE HELD"), "{e}");
    assert!(e.contains("snapshot took longer"), "{e}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(*opened.lock().unwrap(), Some(1));
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 3);
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    no_logout(&sim);
}

/// PD4 m5: a `hid-hold` release refused for a token that lapsed
/// mid-command logs in again — once — and both releases go out on the
/// fresh token, as does the `_released` snapshot (PD3 m7's rule).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hid_hold_release_refused_for_its_token_logs_in_again_once() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let plan = hold::HoldPlan {
        relogin: Some(hid::Relogin {
            web_pin: pin,
            password: sim.password(),
        }),
        ..hold::HoldPlan::new(End::Fin, Duration::from_millis(300))
    };
    let tokens = std::sync::Mutex::new(Vec::new());
    let lapse = async {
        sim.wait_for(T, |_| ws_opens(&sim) >= 1).await.unwrap();
        sim.expire_tokens();
    };
    let (r, ()) = tokio::join!(
        hold::hid_hold(
            &t,
            pin,
            &token,
            &plan,
            &mut irq,
            async |s: &str, tok: &str| {
                tokens.lock().unwrap().push((s.to_owned(), tok.to_owned()));
                Ok(())
            }
        ),
        lapse
    );
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.contains("KEY MAY BE HELD"), "{e}");
    assert_eq!(sim.stats().logins_ok, 2);
    assert!(refusals(&sim) >= 1);
    let tokens = tokens.lock().unwrap().clone();
    assert_eq!(tokens.len(), 2, "{tokens:?}");
    assert_eq!(tokens[0], ("_held".to_owned(), token.clone()));
    assert_eq!(tokens[1].0, "_released");
    assert_ne!(tokens[1].1, token, "the snapshot used the lapsed token");
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 3);
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    no_logout(&sim);
}

/// PD4 m5: ...and so does a `hid-stale` release.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hid_stale_release_refused_for_its_token_logs_in_again_once() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let plan = hid::StalePlan {
        relogin: Some(hid::Relogin {
            web_pin: pin,
            password: sim.password(),
        }),
        ..hid::StalePlan::new(Duration::from_millis(300))
    };
    let lapse = async {
        sim.wait_for(T, |_| ws_opens(&sim) >= 2).await.unwrap();
        sim.expire_tokens();
    };
    let (r, ()) = tokio::join!(
        hid::hid_stale(
            &t,
            pin,
            &token,
            &plan,
            &mut irq,
            async |_: &str, _: &str| Ok(()),
            |_| {}
        ),
        lapse
    );
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.contains("KEY MAY BE HELD"), "{e}");
    assert_eq!(sim.stats().logins_ok, 2);
    assert!(refusals(&sim) >= 1);
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 4);
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(hid_on_ws(&sim, 3), session_start());
    no_logout(&sim);
}

/// The burst's frames, built here from D5's rule (not with
/// `hid::stale_frame`): 'a'..'t' on even `i`, the all-zero release on odd.
fn burst_frame(i: usize) -> Vec<u8> {
    if i % 2 == 1 {
        kbd(0, 0)
    } else {
        kbd(0, 0x04 + u8::try_from((i / 2) % 20).unwrap())
    }
}

/// The re-assert carry (PC9 fix 2), bounded (D5): exactly STALE_BURST
/// reports, alternating press and release and ending on a release, all of
/// them delivered (drained before the reset, PD4 I1), then a reset; the
/// fresh websocket starts with the session start and the Right Ctrl tap
/// that resets the test page (never Esc, PD3 R-I1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_sends_a_bounded_alternating_burst_then_a_fresh_session_start() {
    let sim = sim_with(|c| c.control_recv_buffer = Some(4096)).await;
    let token = login(&sim).await;
    let r = hid::stale_after_reset(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    assert_eq!(r.pushed, 128);
    assert_eq!(hid::STALE_BURST, 128);
    let fresh = hid_count(&sim, 1, 4).await;
    assert_eq!(
        fresh.get(..4).unwrap(),
        [session_start(), reset_tap()].concat()
    );
    all_closed(&sim).await;
    assert_eq!(hid_on_ws(&sim, 1), [session_start(), reset_tap()].concat());
    let old = hid_on_ws(&sim, 0);
    assert_eq!(old.get(..2).unwrap(), session_start());
    assert_eq!(old.len(), 130, "the burst was cut or overran its cap");
    for (i, f) in old.iter().skip(2).enumerate() {
        assert_eq!(
            *f,
            hid::stale_frame(u64::try_from(i).unwrap()).to_vec(),
            "burst frame {i}"
        );
        assert_eq!(*f, burst_frame(i), "burst frame {i}");
    }
    assert_eq!(
        old.last().unwrap(),
        &kbd(0, 0),
        "a complete burst ends released"
    );
    assert_eq!(ws_opens(&sim), 2);
    assert_safe_typing(&old);
    assert_safe_typing(&all_hid(&sim));
    no_logout(&sim);
}

/// `hid-stale` refuses a settle past `MAX_SETTLE` (a stale press could be
/// down through it) before anything connects.
#[tokio::test]
async fn hid_stale_refuses_an_unbounded_settle_before_connecting() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let e = hid::stale_after_reset(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        hid::MAX_SETTLE + Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("hid-stale"), "{e:?}");
    let mut irq = hid::Interrupts::new().unwrap();
    let e = hid::hid_stale(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &hid::StalePlan::new(hid::MAX_SETTLE + Duration::from_millis(1)),
        &mut irq,
        async |_: &str, _: &str| Ok(()),
        |_| {},
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("hid-stale"), "{e:?}");
    assert_eq!(ws_opens(&sim), 0);
    assert_eq!(sim.stats().accepts_control, 0);
}

/// `hid-stale`'s whole run (Task 1.6 step 9): the burst, the fresh
/// session start and reset tap, the settle and the snapshot — all before
/// any release, and the report line before the snapshot (PD4 m4) — then
/// two releases `SECOND_RELEASE_AFTER` apart, on every path where the
/// burst was sent (D5: a backlog can drain late). kvm-sim answers neither
/// release's close frame, so even this run, whose body succeeded, ends KEY
/// MAY BE HELD with the remedy (PD3 R-m1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_releases_twice_and_is_loud_when_neither_release_is_confirmed() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let shots = Shots::default();
    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let lines_at_shot = std::sync::Mutex::new(None);
    let e = hid::hid_stale(
        &t,
        pin,
        &token,
        &hid::StalePlan::new(Duration::from_millis(300)),
        &mut irq,
        async |suffix: &str, _: &str| {
            *lines_at_shot.lock().unwrap() = Some(lines.lock().unwrap().len());
            shots
                .lock()
                .unwrap()
                .push((suffix.to_owned(), ws_opens(&sim)));
            Ok(())
        },
        |l| lines.lock().unwrap().push(l),
    )
    .await
    .unwrap_err();
    let e = format!("{e:?}");
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("pushed: 128"), "{lines:?}");
    assert_eq!(
        *lines_at_shot.lock().unwrap(),
        Some(1),
        "the report came after the snapshot"
    );
    // The one snapshot comes after the fresh websocket, before a release.
    assert_eq!(*shots.lock().unwrap(), [(String::new(), 2)]);
    assert_eq!(hid::STALE_SHOTS, [""]);
    all_closed(&sim).await;
    assert_eq!(ws_opens(&sim), 4, "{:?}", sim.stats());
    assert_eq!(hid_on_ws(&sim, 1), [session_start(), reset_tap()].concat());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert_eq!(hid_on_ws(&sim, 3), session_start());
    let opens = ws_open_times(&sim);
    let apart = opens[3].saturating_duration_since(opens[2]);
    assert!(apart >= Duration::from_millis(4500), "{apart:?}");
    assert_eq!(hid_on_ws(&sim, 0).len(), 130);
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    assert_safe_typing(&all_hid(&sim));
    no_logout(&sim);
}

/// `web-get` reads `/`: status, the `Server` header (absent on the ES3,
/// census) and the body's start, bounded. kvm-sim answers 404.
#[tokio::test]
async fn web_get_reads_the_root_page() {
    let sim = sim_with(|_| {}).await;
    let p = web::get(&target(&sim), Some(sim.spki_sha256()), "/")
        .await
        .unwrap();
    assert!(p.status == 404 || p.status == 200, "{p:?}");
    assert_eq!(
        (p.status, p.server.as_deref(), p.snippet.as_str()),
        (404, None, "not found")
    );
    no_logout(&sim);
    no_hid(&sim);
}

/// `web-get` can never log out or type: a path into `cgi-bin` or to a
/// `.lua` script, with a query, a fragment, a percent-escape, a `..`
/// segment, or not absolute is refused before anything connects — kvm-sim
/// would otherwise take `/cgi-bin/login.lua?logout` as the global logout.
#[tokio::test]
async fn web_get_never_requests_a_path_that_could_log_out_or_type() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    for path in [
        "/cgi-bin/login.lua?logout",
        "/cgi-bin/login.lua",
        "/CGI-BIN/x",
        "/hid.lua",
        "/x?logout",
        "/x#y",
        "/%63gi-bin/login.lua",
        "/../cgi-bin",
        "//evil/",
        "x",
        "",
        "/logout",
    ] {
        let e = web::get(&t, pin, path).await.unwrap_err();
        assert!(format!("{e:?}").contains("web-get"), "{path:?}: {e:?}");
    }
    assert_eq!(sim.stats().accepts_web, 0);
    no_logout(&sim);
    no_hid(&sim);
}

// --- Child processes (D6, D34; PD3 I2). A signal reaches a whole
// process, and a closed stderr is a process's own, so each such case runs
// in a child: this test binary re-run for that one test, with `CHILD_ENV`
// naming the case. A signal case's child prints READY once its HID
// section is under way; the parent sends the signal (and then SENT on the
// child's stdin). The child asserts against its own kvm-sim and prints
// CHILD-OK. Every signal's child runs at once, each in its own process.

const CHILD_ENV: &str = "KVM_PROBE_L4_SIGNAL_CHILD";

/// Every signal `Interrupts` catches, as `kill -s` names it.
const SIGNALS: [&str; 4] = ["TERM", "HUP", "INT", "QUIT"];

/// The name `Interrupts` gives each signal `kill -s` sends.
fn irq_name(sig: &str) -> &'static str {
    match sig {
        "INT" => "Ctrl-C",
        "TERM" => "SIGTERM",
        "HUP" => "SIGHUP",
        "QUIT" => "SIGQUIT",
        other => panic!("no such signal {other}"),
    }
}

/// Run `test` in a child with `CHILD_ENV=<mode>` and assert it ended with
/// CHILD-OK — every wait bounded. With `signal`, send it once the child
/// prints READY, then write SENT to its stdin. With `close_stderr`, the
/// child's stderr is a pipe whose read end is already closed: every write
/// to it fails (EPIPE), as after a closed terminal or an agent's pipe.
fn run_child(test: &str, mode: &str, signal: Option<&str>, close_stderr: bool) {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = if close_stderr {
        drop(stderr);
        None
    } else {
        Some(std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut s);
            s
        }))
    };
    let mut seen = Vec::new();
    let mut ready = signal.is_none();
    if let Some(sig) = signal {
        ready = loop {
            match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(l) if l.ends_with("READY") => break true,
                Ok(l) => seen.push(l),
                Err(_) => break false,
            }
        };
        if ready {
            let sent = Command::new("kill")
                .args(["-s", sig, &child.id().to_string()])
                .status()
                .unwrap();
            assert!(sent.success(), "kill -s {sig} failed");
            let mut stdin = child.stdin.take().unwrap();
            let _ = writeln!(stdin, "SENT");
        }
    }
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if started.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    out.join().unwrap();
    seen.extend(rx.try_iter());
    let stderr = err.map(|e| e.join().unwrap()).unwrap_or_default();
    assert!(
        ready && status.is_some_and(|s| s.success()) && seen.iter().any(|l| l.contains("CHILD-OK")),
        "{mode}: ready={ready} status={status:?}\nstdout:\n{}\nstderr:\n{stderr}",
        seen.join("\n")
    );
}

/// `test`'s child once per signal, all at once.
fn each_signal(test: &'static str) {
    let children: Vec<_> = SIGNALS
        .into_iter()
        .map(|sig| std::thread::spawn(move || run_child(test, sig, Some(sig), false)))
        .collect();
    for c in children {
        c.join().unwrap();
    }
}

/// The child half: a runtime of its own, as `kvm-probe` has.
fn child_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Ctrl-C, SIGTERM (an agent's tool timeout), SIGHUP (a closed terminal)
/// and SIGQUIT (Ctrl-\) mid-typing, with a key possibly down: `hid-type`'s
/// loop stops at once; a fresh websocket releases everything, and since
/// the run's body was cut off, a second one does 5 s later (PD3 I1); no
/// later run starts; the error names the signal.
#[test]
fn a_signal_mid_typing_still_ends_released() {
    if let Ok(sig) = std::env::var(CHILD_ENV) {
        return child_runtime().block_on(mid_typing_child(irq_name(&sig)));
    }
    each_signal("l4::a_signal_mid_typing_still_ends_released");
}

async fn mid_typing_child(name: &str) {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    // 50 characters at 100 ms a report: one run takes 10 s, so the signal
    // lands in the first run's typing.
    let plan = hid::TypePlan::new(50, &[100], 3);
    let ready = async {
        // The session start, the reset tap and the first press are out.
        hid_count(&sim, 0, 5).await;
        println!("READY");
    };
    let mut lines = Vec::new();
    let (r, ()) = tokio::join!(
        hid::type_runs(&t, pin, &token, &plan, &mut irq, |l| lines.push(l)),
        ready
    );
    let e = r.unwrap_err();
    assert!(e.contains(&format!("interrupted ({name})")), "{e}");
    assert!(lines.is_empty(), "a run completed: {lines:?}");
    all_closed(&sim).await;
    assert_eq!(hid_on_ws(&sim, 1), session_start());
    assert_eq!(hid_on_ws(&sim, 2), session_start());
    assert!(hid_on_ws(&sim, 0).len() < 102, "the run went on typing");
    assert_eq!(all_hid(&sim).last(), Some(&kbd(0, 0)));
    assert_safe_typing(&all_hid(&sim));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ws_opens(&sim), 3, "a run started after the signal");
    no_logout(&sim);
    println!("CHILD-OK");
}

/// A signal that arrives between `guarded` sections (D34: the settle, a
/// snapshot) is never lost: `check` sees it, and the next section skips
/// its body but still releases, and so does every section after it. A
/// skipped body never ran, so it left nothing to land late: one release.
#[test]
fn a_signal_between_sections_is_never_lost() {
    if let Ok(sig) = std::env::var(CHILD_ENV) {
        return child_runtime().block_on(between_child(irq_name(&sig)));
    }
    each_signal("l4::a_signal_between_sections_is_never_lost");
}

async fn between_child(name: &str) {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    // A second set, which only `check` ever looks at: it alone must see
    // the signal that arrived while nothing was waiting on it.
    let mut by_check = hid::Interrupts::new().unwrap();
    println!("READY");
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
    })
    .await
    .unwrap();
    // Nothing is waiting on either set while the signal is handled.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let e = by_check.check().unwrap_err();
    assert!(
        format!("{e:?}").contains(&format!("interrupted ({name})")),
        "{e:?}"
    );
    for nth in 0..2 {
        let ran = AtomicBool::new(false);
        let r: Result<(), _> = hid::guarded(&t, pin, &token, None, &mut irq, async {
            ran.store(true, Ordering::SeqCst);
            let mut w = HidWs::open(&t, pin, &token, T).await?;
            w.send(PRESS_A).await?;
            Ok(())
        })
        .await;
        let e = r.unwrap_err();
        assert!(
            format!("{e:?}").contains(&format!("interrupted ({name})")),
            "{e:?}"
        );
        assert!(!ran.load(Ordering::SeqCst), "section {nth} ran its body");
        assert_eq!(
            hid_count(&sim, nth, 2).await,
            session_start(),
            "section {nth}"
        );
    }
    assert!(irq.check().is_err());
    assert!(irq.sleep(Duration::from_secs(30)).await.is_err());
    assert_eq!(ws_opens(&sim), 2);
    no_logout(&sim);
    println!("CHILD-OK");
}

/// PD3 I2: a closed stderr (SIGHUP's closed terminal, an agent's closed
/// pipe) never stops the release. Every print on the release path cannot
/// fail loudly: the first attempts are refused, their retry lines go
/// nowhere, and the retries go on until one releases.
#[test]
fn a_closed_stderr_never_stops_the_release_retries() {
    if std::env::var(CHILD_ENV).is_ok() {
        return child_runtime().block_on(closed_stderr_child());
    }
    run_child(
        "l4::a_closed_stderr_never_stops_the_release_retries",
        "closed-stderr",
        None,
        true,
    );
}

async fn closed_stderr_child() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.ws_status = Some(503));
    let open = async {
        sim.wait_for(T, |_| refusals(&sim) >= 2).await.unwrap();
        sim.set_policy(|p| p.ws_status = None);
    };
    let t = target(&sim);
    let (r, ()) = tokio::join!(
        hid::ensure_released_within(
            &t,
            Some(sim.spki_sha256()),
            &token,
            None,
            Duration::from_secs(20)
        ),
        open
    );
    r.unwrap();
    assert_eq!(hid_count(&sim, 0, 2).await, session_start());
    no_logout(&sim);
    println!("CHILD-OK");
}
