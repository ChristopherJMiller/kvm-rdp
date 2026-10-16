//! §11.3 Faults, each against its §6.9 class and ErrorInfo. Every fatal
//! case also checks the cause's label: ErrorInfo 0x7 is shared by six
//! causes and 0x9 by two (P45).
use crate::client::{Opts, description, pictures, terminated};
use crate::harness::{
    KBD_ZERO, SET_MODE, T, env, es3, flv_opens, hid_on, ms, sized, streaming, until, within,
    ws_opens,
};
use kvm_rdp::msg::Cause;
use kvm_sim::{Fault, SimEvent};
use std::time::Instant;

/// Framing violations (§6.2): each one is transient — a reconnect, the
/// picture resumes, the session lives — and three within 60 s are
/// `stream_corrupt` (0x7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framing_violations_reconnect_and_three_are_stream_corrupt() {
    for fault in [
        Fault::OversizeTag,
        Fault::BadPrevTagSize,
        Fault::EncryptedTag,
        Fault::StartCodeInNal,
        Fault::TwoPictures,
    ] {
        let (env, c) = streaming(|_| {}).await;
        for round in 1..=2 {
            let opens = flv_opens(&env.sim.events()).len();
            env.sim.inject(fault);
            assert!(
                until(T, || flv_opens(&env.sim.events()).len() > opens).await,
                "{fault:?} {round}: no reconnect"
            );
            let n = pictures(&c.events()).len();
            c.wait_for(T, |e| pictures(e).len() > n).await;
            assert!(
                terminated(&c.events()).is_none(),
                "{fault:?} {round}: disconnected"
            );
        }
        env.sim.inject(fault);
        let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
        assert_eq!(
            terminated(&evs).unwrap(),
            description(Cause::StreamCorrupt),
            "{fault:?}"
        );
        assert_eq!(env.metrics().parse_errors.total(), 3, "{fault:?}");
        assert_eq!(
            env.metrics().disconnects.get("stream_corrupt"),
            1,
            "{fault:?}"
        );
    }
}

/// A NALU before any sequence header, on every reopen: three framing
/// violations → `stream_corrupt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nalus_before_the_sequence_header_are_stream_corrupt() {
    let (env, c) = streaming(|_| {}).await;
    env.sim.set_policy(|p| p.skip_sequence_header = true);
    env.sim.inject(Fault::Close);
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::StreamCorrupt));
    assert_eq!(env.metrics().parse_errors.total(), 3);
    assert_eq!(env.metrics().disconnects.get("stream_corrupt"), 1);
}

/// Stream-incompatible (§6.9): fatal at once with 0x7, never a reconnect;
/// the ES3's constant 16 ms `CompositionTime` is admitted until it changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_incompatible_faults_are_fatal_at_once() {
    for fault in [
        Fault::HevcCodecId,
        Fault::CompositionTime(20),
        Fault::BSlice,
    ] {
        let (env, c) = streaming(|_| {}).await;
        assert_eq!(
            env.metrics().disconnects.total(),
            0,
            "the constant 16 ms CompositionTime was refused"
        );
        env.sim.inject(fault);
        let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
        assert_eq!(
            terminated(&evs).unwrap(),
            description(Cause::StreamIncompatible),
            "{fault:?}"
        );
        assert_eq!(
            env.metrics().disconnects.get("stream_incompatible"),
            1,
            "{fault:?}"
        );
        assert_eq!(
            flv_opens(&env.sim.events()).len(),
            1,
            "{fault:?}: fatal is never a reconnect"
        );
    }
}

/// Transient (§6.9): end of sequence, an FLV drop, and an FLV silent past
/// `flv_idle_timeout` each reconnect with no disconnect and no new login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_of_sequence_drop_and_silence_reconnect_without_a_disconnect() {
    let idle = ms(500);
    let (env, c) = streaming(move |c| c.video.flv_idle_timeout = idle).await;
    for fault in [Fault::EndOfSequence, Fault::Close, Fault::Silence] {
        let opens = flv_opens(&env.sim.events()).len();
        let t0 = Instant::now();
        env.sim.inject(fault);
        assert!(
            until(T, || flv_opens(&env.sim.events()).len() > opens).await,
            "{fault:?}"
        );
        if fault == Fault::Silence {
            within(t0.elapsed(), idle);
        }
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() > n).await;
    }
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().disconnects.total(), 0);
    assert_eq!(env.logins(), 1);
}

/// Auth (§6.9): token expiry twice in one session, with a successful
/// re-login between — the open FLV keeps streaming meanwhile (as after
/// another session's logout, §3.2), the next reopen re-logs in once, and
/// nothing disconnects. The second expiry, after a re-login whose token the
/// KVM accepted, is a first refusal again (rev 6.2), not the fatal second.
/// The session's first re-login is immediate; every later one waits on
/// `login_backoff` — reset by the accepted token, so `kvm.backoff.initial`
/// (±20 %) — and per §11.1 does not come before half of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_expiry_twice_relogs_in_each_time() {
    let initial = ms(100);
    let (env, c) = streaming(move |c| c.kvm.backoff.initial = initial).await;
    for round in 1..=2u64 {
        env.sim.expire_tokens();
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() >= n + 5).await;
        assert_eq!(env.logins(), round, "a re-login while nothing reopened");
        let mark = env.sim.events().len();
        env.sim.inject(Fault::Close);
        assert!(
            until(T, || env.logins() == round + 1).await,
            "round {round}: no re-login"
        );
        if round == 2 {
            let log = env.sim.stamped_events();
            let at = |pred: &dyn Fn(&SimEvent) -> bool| {
                log[mark..]
                    .iter()
                    .find(|(_, e)| pred(e))
                    .unwrap_or_else(|| panic!("{:?}", &log[mark..]))
                    .0
            };
            let refused = at(&|e| matches!(e, SimEvent::FlvRefused { status: 403 }));
            let relogin = at(&|e| matches!(e, SimEvent::Login { ok: true }));
            let waited = relogin.saturating_duration_since(refused);
            assert!(
                waited >= initial / 2,
                "the second re-login came {waited:?} after its refusal: not on login_backoff"
            );
        }
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() > n).await;
    }
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().relogins.get(), 2);
    assert_eq!(env.metrics().disconnects.total(), 0);
}

/// Auth (§6.9): a second consecutive auth failure, with no successful
/// re-login between, is fatal — `kvm_auth_failed` (0x9) — and never
/// retried. Both forms: the re-login itself refused (a refused reopen
/// re-logs in once, and that login is refused); and a KVM that answers
/// every login but refuses every fresh token (rev 6.2: a re-login succeeds
/// only once the KVM accepts its token) — fatal at the new token's first
/// refusal, after exactly two logins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_consecutive_auth_failure_is_fatal() {
    for refuse_every_token in [false, true] {
        let form = if refuse_every_token {
            "every token refused"
        } else {
            "the re-login refused"
        };
        let (env, c) = streaming(|_| {}).await;
        if refuse_every_token {
            env.sim.set_policy(|p| p.flv_status = Some(403));
        } else {
            env.sim.set_policy(|p| p.reject_logins = true);
            env.sim.expire_tokens();
        }
        env.sim.inject(Fault::Close);
        let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
        assert_eq!(
            terminated(&evs).unwrap(),
            description(Cause::KvmAuthFailed),
            "{form}"
        );
        assert_eq!(
            env.metrics().disconnects.get("kvm_auth_failed"),
            1,
            "{form}"
        );
        let s = env.sim.stats();
        let refusals = env
            .sim
            .events()
            .iter()
            .filter(|e| matches!(e, SimEvent::FlvRefused { status: 403 }))
            .count();
        if refuse_every_token {
            assert_eq!(
                (s.logins_ok, s.logins_failed, refusals),
                (2, 0, 2),
                "{form}: re-login once, fatal at the new token's refusal"
            );
        } else {
            assert_eq!(
                (s.logins_ok, s.logins_failed, refusals),
                (1, 1, 1),
                "{form}: re-login once, never again"
            );
        }
    }
}

/// Websocket (§6.9): a drop and a 64 MiB message each reconnect with the
/// session-start sequence and no NeedIdr — the oversize one closed at the
/// frame limit (a bridge that waited for the whole message would never
/// reconnect: kvm-sim declares 64 MiB and sends 4 KiB of it; Task 3.3
/// checks the error at the 4 KiB limit itself).
///
/// DC24 (P46): §11.3's "RSS bounded" for this message is shown by
/// construction rather than measurement — Task 3.3's unit test proves the
/// error at the 4 KiB frame limit with nothing buffered, and this case
/// proves the reconnect. The in-process bridge shares this process's RSS
/// with up to three concurrent L2 cases (≈ 37 MiB each), so a measured
/// bound would be noise. Neither side holds the message: kvm-sim writes a
/// header and 4 KiB, and this test buffers nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_drop_and_oversize_reconnect_with_the_session_start() {
    let (env, c) = streaming(|_| {}).await;
    let awaiting = env.metrics().frames_dropped.get("awaiting_idr");
    for oversize in [false, true] {
        let before = ws_opens(&env.sim.events()).len();
        if oversize {
            env.sim.send_ws_oversize(64 << 20);
        } else {
            env.sim.close_websockets();
        }
        let log = env
            .sim
            .wait_for(T, |l| ws_opens(l).len() > before)
            .await
            .unwrap();
        let new = *ws_opens(&log).last().unwrap();
        let log = env
            .sim
            .wait_for(T, |l| hid_on(l, new).len() >= 2)
            .await
            .unwrap();
        // Exactly these two: no pointer was ever sent, none parked at (0, 0).
        assert_eq!(
            hid_on(&log, new),
            [SET_MODE.to_vec(), KBD_ZERO.to_vec()],
            "oversize: {oversize}"
        );
    }
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
    assert_eq!(
        env.metrics().frames_dropped.get("awaiting_idr"),
        awaiting,
        "a websocket reconnect is no NeedIdr"
    );
    assert_eq!(flv_opens(&env.sim.events()).len(), 1);
    assert_eq!(env.sim.stats().ws_max_open, 1);
    assert!(terminated(&c.events()).is_none());
}

/// Deadline (§6.9): a KVM that accepts and then says nothing → disconnect
/// with `kvm_unreachable` (0x7) at `upstream_deadline`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_kvm_disconnects_at_the_deadline() {
    let deadline = ms(1500);
    let env = env(es3(), move |c| {
        sized(c);
        c.kvm.upstream_deadline = deadline;
    })
    .await;
    env.sim.set_policy(|p| p.blackhole = true);
    let c = env.client(Opts::new(2));
    c.connected().await;
    let t0 = Instant::now();
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    within(t0.elapsed(), deadline);
    assert_eq!(
        terminated(&evs).unwrap(),
        description(Cause::KvmUnreachable)
    );
    assert_eq!(env.metrics().disconnects.get("kvm_unreachable"), 1);
    assert_eq!(env.logins(), 0);
}

/// Certificate (§6.9): an SPKI mismatch is fatal at once, and no login
/// request is ever sent — `kvm_cert_mismatch` (0x9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_kvm_certificate_sends_no_login() {
    let env = env(es3(), |c| {
        sized(c);
        c.kvm.spki_sha256 = "00".repeat(32);
    })
    .await;
    let c = env.client(Opts::new(2));
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(
        terminated(&evs).unwrap(),
        description(Cause::KvmCertMismatch)
    );
    assert_eq!(env.metrics().disconnects.get("kvm_cert_mismatch"), 1);
    let s = env.sim.stats();
    assert_eq!(s.logins_ok + s.logins_failed, 0);
}

/// PC7 W10 (ledger carry): the KVM's certificate changes mid-session, and
/// the websocket's next reconnect meets it. The bridge pins the SPKI
/// (§3.2), so the new certificate fails the pin: fatal at once,
/// `kvm_cert_mismatch` (0x9, shared with `kvm_auth_failed`, so the label is
/// checked too), with no re-login and no logout, and its writer idling
/// rather than reconnecting (rev 6.3). The mismatch is the websocket's: one
/// more control connection, which never upgraded, and no FLV reopened (the
/// open one keeps the certificate it was served).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_change_mid_session_is_fatal_at_once() {
    let (env, c) = streaming(|_| {}).await;
    env.hid_ready().await;
    let before = env.sim.stats();
    env.sim.rotate_certificate().unwrap();
    // Force a websocket reconnect: its reopen now hits the new certificate.
    env.sim.close_websockets();
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(
        terminated(&evs).unwrap(),
        description(Cause::KvmCertMismatch)
    );
    assert_eq!(env.metrics().disconnects.get("kvm_cert_mismatch"), 1);
    assert_eq!(env.metrics().disconnects.total(), 1);
    // The writer idles: no control connection after the one that met the
    // new certificate, however long the backoff (`kvm.backoff.max` 400 ms).
    let again = env
        .sim
        .wait_for(ms(1000), |_| {
            env.sim.stats().accepts_control > before.accepts_control + 1
        })
        .await;
    assert!(
        again.is_err(),
        "the websocket reconnected after the mismatch"
    );
    let s = env.sim.stats();
    assert_eq!(
        s.accepts_control,
        before.accepts_control + 1,
        "the reopen never reached the KVM"
    );
    assert_eq!(
        ws_opens(&env.sim.events()).len(),
        1,
        "a websocket upgraded over the new certificate"
    );
    assert_eq!(
        (s.accepts_video, flv_opens(&env.sim.events()).len()),
        (before.accepts_video, 1),
        "an FLV reopened: the mismatch was not the websocket's"
    );
    assert_eq!(
        (s.logins_ok, s.logins_failed),
        (before.logins_ok, before.logins_failed),
        "a re-login after the mismatch"
    );
    assert_eq!(s.logouts, 0, "§3.2: the bridge never logs out");
}
