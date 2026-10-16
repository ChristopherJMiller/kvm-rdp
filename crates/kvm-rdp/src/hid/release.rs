//! The release websocket (I2, Plan D final review; spec §7.4, §9.3). A
//! session that ends while the KVM is not reading — stalled, or its
//! websocket down in a backoff — leaves its release unread: the close path
//! gives a blocked or unanswered websocket up with a reset, so what the KVM
//! had not read is gone, and no websocket opens again until the next
//! session. A KVM that keeps the last report it read (kvm-sim does; whether
//! the ES3 does is Leg D step 8's question) then holds whatever it read
//! last — Cmd, on the work Mac — until a new session.
//!
//! So once a session has ended and the KVM has not proved it holds nothing
//! of ours (`HidControl::kvm_may_hold`), the KVM actor runs `run`: one more
//! websocket, bounded, and only for the release.
//!
//! - It opens over the same pinned TLS (`open_ws`) with the session's
//!   token, or after one fresh login when there is none or it is refused —
//!   none at all when the session's password was refused. Never a logout.
//! - It writes the session-start sequence (absolute mode, the all-zero
//!   keyboard report, the zero-button pointer report at the last position
//!   sent, §3.3) and a ping, and waits for the pong that proves the KVM
//!   read them. A KVM reading again may still read what the abandoned
//!   websocket left in its receive buffer, after our zeros; so, as every
//!   open does (DD8), it writes the release once more `settle`
//!   (`input.reassert_after`) after that pong, then closes.
//! - At most `ATTEMPTS` opens, all inside `BUDGET` (10 s): every network
//!   step is bounded by what is left of it, and the attempts are
//!   `RETRY_GAP` apart.
//! - It ends with a FIN, never a reset: it wrote only zero reports, and one
//!   delivered late is still a release.
//!
//! The bridge never holds two websockets at once: the session's own was
//! reset before this one opens, and a new session's `Start` supersedes it
//! (aborts it and waits for it to drop) — that session's own open is the
//! release. A KVM that has not yet read the reset may still see both for a
//! while (kvm-sim with its reads paused does).
//!
//! Each run counts one `release_websockets{outcome}`: `confirmed` (a pong
//! after the release), `unconfirmed` (written, never proved), `failed` (no
//! open carried it), `superseded` (dropped first: a new session, or the
//! process's exit).
use crate::config::Secret;
use crate::hid::HidControl;
use crate::hid::writer::RELEASE_PING;
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::FailClass;
use crate::kvm::login::login;
use crate::kvm::ws::{KvmWs, open_ws};
use crate::metrics::Metrics;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use kvm_proto::Token;
use kvm_proto::hid::HidFrame;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// Everything a release websocket does, from the session's end.
pub const BUDGET: Duration = Duration::from_secs(10);
/// The most websocket opens (each with its own fresh login, at most one
/// in all).
pub const ATTEMPTS: u32 = 3;
/// Between two attempts.
pub const RETRY_GAP: Duration = Duration::from_secs(1);
/// The close at the end: the time it may take, and the reserve the
/// re-assert leaves for it inside the budget.
const CLOSE_WAIT: Duration = Duration::from_millis(400);

/// What a release websocket needs; the KVM actor builds it as a session
/// ends (`kvm::session`).
pub struct ReleaseJob {
    pub ep: Arc<KvmEndpoint>,
    /// The session's token, if it had one.
    pub token: Option<Token>,
    /// `None`: never log in (the session's password was refused).
    pub password: Option<Secret>,
    pub connect_timeout: Duration,
    pub login_timeout: Duration,
    /// `input.hid_write_timeout`, for each write.
    pub write_timeout: Duration,
    /// `input.reassert_after`: from the KVM's pong to the second release.
    pub settle: Duration,
    /// `BUDGET`, but for a test.
    pub budget: Duration,
    pub hid: Arc<HidControl>,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The KVM answered the ping written after the release.
    Confirmed,
    /// The release was written; the KVM never proved it read it.
    Unconfirmed,
    /// No attempt wrote it.
    Failed,
    /// Dropped before it ended: a new session's `Start`, or the exit.
    Superseded,
}

impl Outcome {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Confirmed => "confirmed",
            Outcome::Unconfirmed => "unconfirmed",
            Outcome::Failed => "failed",
            Outcome::Superseded => "superseded",
        }
    }
}

/// Counts `superseded` for a run dropped before it ends (an abort, or the
/// runtime's teardown).
struct Counted {
    metrics: Arc<Metrics>,
    done: bool,
}

impl Drop for Counted {
    fn drop(&mut self) {
        if !self.done {
            self.metrics
                .release_websockets
                .inc(Outcome::Superseded.label());
        }
    }
}

/// One release websocket, bounded by `job.budget`; its outcome, counted
/// and logged (an outcome word and a count only). The `superseded` guard
/// exists before the future is first polled (r-m1, the re-review of the
/// final fix wave): a run aborted before it ever ran — a takeover's
/// `Start` sits right behind its `Stop` — still counts one.
pub fn run(job: ReleaseJob) -> impl std::future::Future<Output = Outcome> + Send + 'static {
    let counted = Counted {
        metrics: job.metrics.clone(),
        done: false,
    };
    async move {
        // The whole guard, moved in (a field assignment alone would
        // capture only the field, and drop the guard here and now).
        let mut counted = counted;
        let (outcome, attempts) = release(&job).await;
        counted.done = true;
        job.metrics.release_websockets.inc(outcome.label());
        match outcome {
            Outcome::Confirmed => {
                tracing::info!(outcome = outcome.label(), attempts, "release websocket");
            }
            Outcome::Unconfirmed | Outcome::Failed => tracing::warn!(
                outcome = outcome.label(),
                attempts,
                "release websocket: the KVM may still hold a key"
            ),
            Outcome::Superseded => {}
        }
        outcome
    }
}

/// How one open went.
enum Served {
    Confirmed,
    /// The release was written and the budget ran out unproved.
    Unproved,
    /// The websocket ended or a write failed: another attempt may follow.
    Lost,
}

async fn release(job: &ReleaseJob) -> (Outcome, u32) {
    let deadline = Instant::now() + job.budget;
    let mut token = job.token.clone();
    let mut may_login = job.password.is_some();
    let mut wrote = false;
    let mut attempts = 0u32;
    while attempts < ATTEMPTS {
        if attempts > 0 {
            tokio::time::sleep_until(deadline.min(Instant::now() + RETRY_GAP)).await;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        attempts = attempts.saturating_add(1);
        let tok = match token.clone() {
            Some(t) => t,
            None => {
                let Some(password) = job.password.as_ref().filter(|_| may_login) else {
                    break;
                };
                may_login = false;
                let fresh = tokio::time::timeout_at(
                    deadline,
                    login(
                        &job.ep,
                        password,
                        job.connect_timeout.min(left),
                        job.login_timeout.min(left),
                    ),
                )
                .await;
                match fresh {
                    Ok(Ok(t)) => {
                        job.metrics.logins.inc();
                        token = Some(t.clone());
                        t
                    }
                    Ok(Err(e)) if e.class() == FailClass::Cert => break,
                    // A refused password, a timeout: no more logins, and
                    // no token to open with.
                    Ok(Err(_)) | Err(_) => continue,
                }
            }
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let opened = tokio::time::timeout_at(
            deadline,
            open_ws(&job.ep, &tok, job.connect_timeout.min(left)),
        )
        .await;
        match opened {
            // Dropped at the end of this arm: a FIN (never `reset_on_close`).
            Ok(Ok((ws, _sock))) => {
                let (served, written) = serve(job, ws, deadline).await;
                wrote |= written;
                match served {
                    Served::Confirmed => return (Outcome::Confirmed, attempts),
                    Served::Unproved => break,
                    Served::Lost => {}
                }
            }
            Ok(Err(e)) => match e.class() {
                // A dead token: the next attempt logs in, if it may.
                FailClass::Auth => token = None,
                // Not the pinned KVM: nothing more to say to it.
                FailClass::Cert => break,
                FailClass::Transient => {}
            },
            Err(_) => {}
        }
    }
    let outcome = if wrote {
        Outcome::Unconfirmed
    } else {
        Outcome::Failed
    };
    (outcome, attempts)
}

/// Release on one open websocket; whether the all-zero keyboard report was
/// written.
async fn serve(job: &ReleaseJob, ws: KvmWs, deadline: Instant) -> (Served, bool) {
    let (mut sink, mut stream) = ws.split();
    let mut wrote = false;
    if !write_all(
        job,
        &mut sink,
        job.hid.session_start_frames(),
        deadline,
        &mut wrote,
    )
    .await
    {
        return (Served::Lost, wrote);
    }
    match pong(&mut stream, deadline).await {
        Some(true) => {}
        // The KVM ended the websocket before it answered.
        Some(false) => return (Served::Lost, wrote),
        None => {
            close(&mut sink).await;
            return (Served::Unproved, wrote);
        }
    }
    let _ = job.hid.confirm_read();
    // The KVM reads again. Once `settle` has let it read what the
    // abandoned websocket left, the release once more — inside the budget,
    // with the close's reserve left.
    let latest = deadline.checked_sub(CLOSE_WAIT).unwrap_or(deadline);
    let at = Instant::now()
        .checked_add(job.settle)
        .map_or(latest, |at| at.min(latest));
    let live = tokio::time::timeout_at(at, async {
        while let Some(Ok(m)) = stream.next().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
    })
    .await
    .is_err();
    if live
        && write_all(
            job,
            &mut sink,
            job.hid.release_frames(),
            deadline,
            &mut wrote,
        )
        .await
    {
        let answer = deadline.min(Instant::now() + CLOSE_WAIT);
        if pong(&mut stream, answer).await == Some(true) {
            let _ = job.hid.confirm_read();
        }
    }
    close(&mut sink).await;
    (Served::Confirmed, wrote)
}

/// Write `frames` and then the ping, each bounded by `write_timeout` and
/// the deadline; false at the first failure.
async fn write_all<S: Sink<Message, Error = WsError> + Unpin>(
    job: &ReleaseJob,
    sink: &mut S,
    frames: Vec<HidFrame>,
    deadline: Instant,
    wrote: &mut bool,
) -> bool {
    for f in frames {
        if !send(job, sink, Message::Binary(f.to_vec()), deadline).await {
            return false;
        }
        job.hid.note_sent(&f);
        if matches!(f, HidFrame::Keyboard { .. }) {
            *wrote = true;
        }
    }
    send(job, sink, Message::Ping(RELEASE_PING.to_vec()), deadline).await
}

async fn send<S: Sink<Message, Error = WsError> + Unpin>(
    job: &ReleaseJob,
    sink: &mut S,
    m: Message,
    deadline: Instant,
) -> bool {
    let by = deadline.min(Instant::now() + job.write_timeout);
    matches!(tokio::time::timeout_at(by, sink.send(m)).await, Ok(Ok(())))
}

/// The pong to `RELEASE_PING` by `by`: `Some(true)`; the websocket ended
/// first: `Some(false)`; `None` past `by`. Anything else is read and
/// discarded (§3.2).
async fn pong<St: Stream<Item = Result<Message, WsError>> + Unpin>(
    stream: &mut St,
    by: Instant,
) -> Option<bool> {
    tokio::time::timeout_at(by, async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Pong(p))) if p == RELEASE_PING => return true,
                Some(Ok(Message::Close(_)) | Err(_)) | None => return false,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .ok()
}

/// A close frame, bounded; the socket ends with a FIN when it drops.
async fn close<S: Sink<Message, Error = WsError> + Unpin>(sink: &mut S) {
    let _ = tokio::time::timeout(CLOSE_WAIT, sink.close()).await;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::config::Scheme;
    use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
    use std::time::Instant as StdInstant;

    const T: Duration = Duration::from_secs(15);
    const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
    const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    async fn sim_with(set: impl FnOnce(&mut SimConfig)) -> KvmSim {
        let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
        set(&mut cfg);
        KvmSim::start(cfg).await.unwrap()
    }

    fn endpoint(sim: &KvmSim) -> Arc<KvmEndpoint> {
        let p = sim.ports();
        Arc::new(KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            sim.spki_sha256(),
        ))
    }

    async fn token(sim: &KvmSim, ep: &KvmEndpoint) -> Token {
        login(
            ep,
            &Secret::new(sim.password()),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap()
    }

    /// A `HidControl` that wrote Cmd held, a button down at (100, 200).
    fn holding() -> Arc<HidControl> {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        hid.note_sent(&HidFrame::abs_mouse(1, 100, 200));
        hid.note_sent(&HidFrame::Keyboard {
            modifiers: 0x08,
            keys: [0; 5],
        });
        assert!(hid.kvm_may_hold());
        hid
    }

    fn job(
        sim: &KvmSim,
        ep: Arc<KvmEndpoint>,
        token: Option<Token>,
        hid: &Arc<HidControl>,
    ) -> ReleaseJob {
        ReleaseJob {
            ep,
            token,
            password: Some(Secret::new(sim.password())),
            connect_timeout: Duration::from_secs(1),
            login_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(1),
            settle: Duration::from_millis(100),
            budget: BUDGET,
            hid: hid.clone(),
            metrics: hid.metrics.clone(),
        }
    }

    fn ws_opens(log: &[SimEvent]) -> Vec<u64> {
        log.iter()
            .filter_map(|e| match e {
                SimEvent::WsOpen { conn } => Some(*conn),
                _ => None,
            })
            .collect()
    }

    fn hid_on(log: &[SimEvent], ws: u64) -> Vec<Vec<u8>> {
        log.iter()
            .filter_map(|e| match e {
                SimEvent::Hid { conn, bytes } if *conn == ws => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    fn refusals(sim: &KvmSim) -> usize {
        sim.events()
            .iter()
            .filter(|e| matches!(e, SimEvent::WsRefused { .. }))
            .count()
    }

    /// The session start, then — once the KVM's pong proved it read it —
    /// the release once more (DD8's re-assert), on one websocket, with the
    /// session's token: no login, no logout; the KVM now holds nothing of
    /// ours, and the run counts `confirmed`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_websocket_writes_the_release_twice_and_proves_it() {
        let sim = sim_with(|_| {}).await;
        let ep = endpoint(&sim);
        let tok = token(&sim, &ep).await;
        let hid = holding();
        let out = tokio::time::timeout(T, run(job(&sim, ep, Some(tok), &hid)))
            .await
            .unwrap();
        assert_eq!(out, Outcome::Confirmed);
        let pointer = HidFrame::abs_mouse(0, 100, 200).to_vec();
        let log = sim
            .wait_for(T, |l| {
                ws_opens(l).len() == 1 && hid_on(l, ws_opens(l)[0]).len() >= 5
            })
            .await
            .unwrap();
        assert_eq!(
            hid_on(&log, ws_opens(&log)[0]),
            [
                SET_MODE.to_vec(),
                KBD_ZERO.to_vec(),
                pointer.clone(),
                KBD_ZERO.to_vec(),
                pointer
            ]
        );
        assert!(!hid.kvm_may_hold());
        assert_eq!(hid.metrics.release_websockets.get("confirmed"), 1);
        assert_eq!(hid.metrics.release_websockets.total(), 1);
        let s = sim.stats();
        assert_eq!(
            (s.logins_ok, s.logouts),
            (1, 0),
            "a login beyond the test's own"
        );
        sim.wait_for(T, |_| sim.stats().ws_open == 0).await.unwrap();
    }

    /// A refused token gets one fresh login, over the same pin, and the
    /// release then lands; with the session's password refused (no
    /// password), nothing logs in and the run fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_token_is_replaced_by_one_fresh_login() {
        let sim = sim_with(|_| {}).await;
        let ep = endpoint(&sim);
        let dead = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
        let hid = holding();
        let out = tokio::time::timeout(T, run(job(&sim, ep.clone(), Some(dead.clone()), &hid)))
            .await
            .unwrap();
        assert_eq!(out, Outcome::Confirmed);
        assert_eq!((refusals(&sim), sim.stats().logins_ok), (1, 1));
        assert_eq!(hid.metrics.logins.get(), 1);
        let hid = holding();
        let mut j = job(&sim, ep, Some(dead), &hid);
        j.password = None;
        let out = tokio::time::timeout(T, run(j)).await.unwrap();
        assert_eq!(out, Outcome::Failed);
        assert_eq!((refusals(&sim), sim.stats().logins_ok), (2, 1));
        assert!(hid.kvm_may_hold());
        assert_eq!(hid.metrics.release_websockets.get("failed"), 1);
        assert_eq!(sim.stats().logouts, 0);
    }

    /// Bounded: a KVM refusing every websocket gets `ATTEMPTS` opens,
    /// `RETRY_GAP` apart, and the run fails inside `BUDGET`; one whose
    /// connections never answer (no TLS) is given up at the budget, however
    /// long `connect_timeout` is. Never a logout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_websocket_never_runs_past_its_budget() {
        let sim = sim_with(|_| {}).await;
        let ep = endpoint(&sim);
        let tok = token(&sim, &ep).await;
        sim.set_policy(|p| p.ws_status = Some(503));
        let hid = holding();
        let t0 = StdInstant::now();
        let out = tokio::time::timeout(T, run(job(&sim, ep.clone(), Some(tok.clone()), &hid)))
            .await
            .expect("the release websocket ran past its budget");
        let took = t0.elapsed();
        assert_eq!(out, Outcome::Failed);
        assert_eq!(refusals(&sim), usize::try_from(ATTEMPTS).unwrap());
        assert!(
            took >= RETRY_GAP * (ATTEMPTS - 1) && took < BUDGET,
            "{took:?}"
        );
        sim.set_policy(|p| {
            p.ws_status = None;
            p.blackhole = true;
        });
        let hid = holding();
        let mut j = job(&sim, ep, Some(tok), &hid);
        j.connect_timeout = Duration::from_secs(30);
        j.budget = Duration::from_millis(1500);
        let t0 = StdInstant::now();
        let out = tokio::time::timeout(T, run(j)).await.unwrap();
        let took = t0.elapsed();
        assert_eq!(out, Outcome::Failed);
        assert!(
            took >= Duration::from_millis(1500) && took < Duration::from_millis(2500),
            "{took:?}"
        );
        assert_eq!(hid.metrics.release_websockets.get("failed"), 1);
        assert_eq!(sim.stats().logouts, 0);
    }

    /// A KVM that is not reading takes the release into its buffer and
    /// never answers: the run is `unconfirmed` at its budget, the KVM still
    /// may hold, and the zeros it holds unread are delivered when it reads
    /// (a FIN, never a reset).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_the_kvm_never_reads_is_unconfirmed_and_still_delivered() {
        let sim = sim_with(|_| {}).await;
        let ep = endpoint(&sim);
        let tok = token(&sim, &ep).await;
        sim.set_policy(|p| p.pause_ws_reads = true);
        let hid = holding();
        let mut j = job(&sim, ep, Some(tok), &hid);
        j.budget = Duration::from_millis(1500);
        let out = tokio::time::timeout(T, run(j)).await.unwrap();
        assert_eq!(out, Outcome::Unconfirmed);
        assert!(hid.kvm_may_hold());
        assert_eq!(hid.metrics.release_websockets.get("unconfirmed"), 1);
        sim.set_policy(|p| p.pause_ws_reads = false);
        let log = sim
            .wait_for(T, |l| {
                ws_opens(l)
                    .first()
                    .is_some_and(|ws| hid_on(l, *ws).len() >= 3)
            })
            .await
            .unwrap();
        assert_eq!(
            hid_on(&log, ws_opens(&log)[0])[..2],
            [SET_MODE.to_vec(), KBD_ZERO.to_vec()]
        );
    }

    /// A run dropped before it ends — a new session's `Start` aborts it —
    /// counts `superseded`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_websocket_dropped_first_counts_superseded() {
        let sim = sim_with(|_| {}).await;
        sim.set_policy(|p| p.blackhole = true);
        let ep = endpoint(&sim);
        let hid = holding();
        let tok = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
        let h = tokio::spawn(run(job(&sim, ep, Some(tok), &hid)));
        tokio::time::sleep(Duration::from_millis(200)).await;
        h.abort();
        assert!(tokio::time::timeout(T, h).await.unwrap().is_err());
        assert_eq!(hid.metrics.release_websockets.get("superseded"), 1);
        assert_eq!(hid.metrics.release_websockets.total(), 1);
    }
}
