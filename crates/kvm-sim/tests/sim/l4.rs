//! kvm-probe's L4 checks (Plan D, spec §11.6) against kvm-sim, before they
//! run on the ES3: each produces its report; none sends a HID frame except
//! `logout-watch`'s one all-zero release, and none logs out.
use crate::support::{T, login, sim_with, target};
use kvm_probe::l4::NEVER_ISSUED;
use kvm_probe::l4::flv::{self, ConcurrentPlan, FlvOpen, Side};
use kvm_probe::l4::session::{self, CapReport, Outcome};
use kvm_probe::l4::ws::{self, Reply, TcpEnd, Upgrade};
use kvm_sim::{KvmSim, SimEvent};
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
