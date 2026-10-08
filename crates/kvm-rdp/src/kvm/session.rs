//! The KVM actor (§4.3): one task for the process, one `Session` per
//! generation, commands processed strictly in order. `Start{generation}` logs in
//! and opens the websocket (§5.1, the session-start sequence); `OpenFlv`
//! (the first Setup) opens the FLV; `Stop{generation}` completes — release flushed,
//! websocket, FLV and side FLV closed, **never a logout** (§3.2) — before
//! the next command is read. The token lives from Start to Stop and is
//! reused for every reopen; re-login happens only after an auth failure.
//!
//! Failures by §6.9 class: the main FLV's and the websocket's go through
//! `FailClass` (auth → the re-login-once `AuthGate`, cert → fatal); a side
//! FLV's are matched by kind on their own path (§6.5) — counted, never
//! retried, never fed to the `AuthGate` — except a certificate mismatch,
//! which §6.9's cert row makes fatal on every connection. Once a session
//! has a fatal cause nothing opens an FLV or starts a login: `Video::reconnect`
//! and `want` would reopen a closed `Video`, so the commands are dropped
//! here (PC8 n2), and a later auth refusal is ignored (P24).
//!
//! A re-login is "successful" only once the KVM accepts its token — the
//! websocket upgrades with it, or an FLV opened with it reaches its first
//! tag (§6.9, rev 6.2; `AuthGate::proven`). The first re-login of a session
//! is immediate (a global logout costs no extra wait); every later one
//! waits on `login_backoff`, which only a proven token resets — so a KVM
//! that accepts a token on one path and refuses it on the other is logged
//! into at most once per backoff, never as fast as it answers (I1).
use crate::config::{BackoffConfig, Config, Secret};
use crate::hid::HidControl;
use crate::hid::writer::{WsCtl, WsEvent, WsTask};
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::{FailClass, KvmError};
use crate::kvm::login::login;
use crate::kvm::side;
use crate::kvm::upstream::{AuthGate, AuthStep, Backoff, Deadline, Jitter};
use crate::kvm::video::{FlvSettings, Outcome, Video};
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, KvmCommand, KvmEvent};
use futures_util::future::BoxFuture;
use kvm_proto::Token;
use kvm_proto::video::AdmissionConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

/// Housekeeping cadence: retries, the idle timeout, the deadline.
const TICK: Duration = Duration::from_millis(100);
/// A Stop waits this long for the websocket to flush and close (§5.2).
const CLOSE_WAIT: Duration = Duration::from_millis(500);
/// After an abort, how long a Stop waits for the websocket task to be
/// dropped (its socket closed), so the next session's websocket never
/// overlaps it (census: never two control websockets).
const ABORT_WAIT: Duration = Duration::from_millis(100);

pub struct SessionConfig {
    pub password: Secret,
    pub connect_timeout: Duration,
    pub login_timeout: Duration,
    pub backoff: BackoffConfig,
    pub upstream_deadline: Duration,
    pub flv_idle_timeout: Duration,
    pub idr_side_timeout: Duration,
    pub hid_write_timeout: Duration,
    pub admission: AdmissionConfig,
}

impl SessionConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> SessionConfig {
        SessionConfig {
            password: c.kvm.password.clone(),
            connect_timeout: c.kvm.connect_timeout,
            login_timeout: c.kvm.login_timeout,
            backoff: c.kvm.backoff,
            upstream_deadline: c.kvm.upstream_deadline,
            flv_idle_timeout: c.video.flv_idle_timeout,
            idr_side_timeout: c.video.idr_side_timeout,
            hid_write_timeout: c.input.hid_write_timeout,
            admission: c.video.admission(),
        }
    }
}

pub struct KvmDeps {
    pub ep: Arc<KvmEndpoint>,
    pub cfg: Arc<SessionConfig>,
    pub to_pump: mpsc::Sender<KvmEvent>,
    pub hid: Arc<HidControl>,
    pub metrics: Arc<Metrics>,
}

fn ack(done: Option<oneshot::Sender<()>>) {
    if let Some(d) = done {
        let _ = d.send(());
    }
}

pub async fn run_actor(mut rx: mpsc::UnboundedReceiver<KvmCommand>, deps: KvmDeps) {
    let mut next: Option<KvmCommand> = None;
    loop {
        let cmd = match next.take() {
            Some(c) => c,
            None => match rx.recv().await {
                Some(c) => c,
                None => return,
            },
        };
        match cmd {
            KvmCommand::Start { generation } => {
                next = Session::new(generation, &deps).run(&mut rx).await;
            }
            KvmCommand::Stop { done, .. } => ack(done),
            KvmCommand::FlushHid { done } => {
                let _ = done.send(());
            }
            KvmCommand::Shutdown { done } => {
                let _ = done.send(());
                return;
            }
            KvmCommand::OpenFlv { .. }
            | KvmCommand::RequestIdr { .. }
            | KvmCommand::ReconnectFlv { .. } => {}
        }
    }
}

async fn login_slot(
    slot: &mut Option<BoxFuture<'static, Result<Token, KvmError>>>,
) -> Result<Token, KvmError> {
    match slot {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, JoinError> {
    match slot {
        Some(h) => h.await,
        None => std::future::pending().await,
    }
}

struct Session<'d> {
    generation: Gen,
    deps: &'d KvmDeps,
    auth: AuthGate,
    login_backoff: Backoff,
    login: Option<BoxFuture<'static, Result<Token, KvmError>>>,
    login_retry_at: Option<Instant>,
    /// A re-login has run: every later one waits on `login_backoff` (I1).
    relogged: bool,
    token: watch::Sender<Option<(u64, Token)>>,
    deadline: Deadline,
    ws_ctl: mpsc::UnboundedSender<WsCtl>,
    ws_events: mpsc::UnboundedReceiver<WsEvent>,
    ws_alive: bool,
    ws_task: JoinHandle<()>,
    video: Video,
    side: Option<JoinHandle<Result<(), KvmError>>>,
    fatal: bool,
}

impl<'d> Session<'d> {
    fn new(generation: Gen, deps: &'d KvmDeps) -> Session<'d> {
        let cfg = &deps.cfg;
        let (token_tx, token_rx) = watch::channel(None);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let ws_task = tokio::spawn(
            WsTask {
                ep: deps.ep.clone(),
                token: token_rx,
                ctl: ctl_rx,
                events: ev_tx,
                hid: deps.hid.clone(),
                backoff: Backoff::new(cfg.backoff, Jitter::from_clock()),
                connect_timeout: cfg.connect_timeout,
                write_timeout: cfg.hid_write_timeout,
                metrics: deps.metrics.clone(),
            }
            .run(),
        );
        let video = Video::new(
            generation,
            deps.ep.clone(),
            deps.to_pump.clone(),
            deps.metrics.clone(),
            FlvSettings {
                connect_timeout: cfg.connect_timeout,
                idle_timeout: cfg.flv_idle_timeout,
                deadline: cfg.upstream_deadline,
                admission: cfg.admission.clone(),
            },
            Backoff::new(cfg.backoff, Jitter::from_clock()),
        );
        Session {
            generation,
            deps,
            auth: AuthGate::default(),
            login_backoff: Backoff::new(cfg.backoff, Jitter::from_clock()),
            login: None,
            login_retry_at: None,
            relogged: false,
            token: token_tx,
            deadline: Deadline::new(cfg.upstream_deadline),
            ws_ctl: ctl_tx,
            ws_events: ev_rx,
            ws_alive: true,
            ws_task,
            video,
            side: None,
            fatal: false,
        }
    }

    /// Serve this generation; returns a command that must be handled by
    /// the actor next (a `Start` or `Shutdown` that ended it), if any.
    async fn run(mut self, rx: &mut mpsc::UnboundedReceiver<KvmCommand>) -> Option<KvmCommand> {
        self.deadline.started(Instant::now());
        self.start_login();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        self.close().await;
                        return None;
                    };
                    if let Some(exit) = self.command(cmd).await {
                        return exit;
                    }
                }
                ev = self.ws_events.recv(), if self.ws_alive => self.ws_event(ev).await,
                r = login_slot(&mut self.login) => {
                    self.login = None;
                    self.login_done(r).await;
                }
                // `on_ready` runs to completion in the arm's body (it is not
                // cancel-safe), and every `Ready` reaches it.
                r = self.video.ready() => {
                    let o = self.video.on_ready(r, Instant::now()).await;
                    if let Some(seq) = self.video.take_proven() {
                        self.proven(seq);
                    }
                    if let Some(o) = o {
                        self.outcome(o).await;
                    }
                }
                r = join_slot(&mut self.side) => {
                    self.side = None;
                    self.side_done(r).await;
                }
                _ = tick.tick() => self.tick().await,
            }
        }
    }

    /// `Some(exit)` ends the session.
    async fn command(&mut self, cmd: KvmCommand) -> Option<Option<KvmCommand>> {
        match cmd {
            KvmCommand::Stop { generation, done } if generation == self.generation => {
                self.close().await;
                ack(done);
                Some(None)
            }
            KvmCommand::Stop { done, .. } => {
                ack(done);
                None
            }
            KvmCommand::Start { generation } => {
                self.close().await;
                Some(Some(KvmCommand::Start { generation }))
            }
            KvmCommand::Shutdown { done } => {
                self.close().await;
                Some(Some(KvmCommand::Shutdown { done }))
            }
            KvmCommand::FlushHid { done } => {
                // If the task is gone, `done` is dropped and the waiter sees it.
                let _ = self.ws_ctl.send(WsCtl::Flush { done });
                None
            }
            // After a fatal cause, none of these may run: each would open
            // an FLV (PC8 n2).
            KvmCommand::OpenFlv { generation } if generation == self.generation && !self.fatal => {
                let token = self.token.borrow().clone();
                self.video.want(Instant::now(), token.as_ref());
                None
            }
            KvmCommand::ReconnectFlv { generation }
                if generation == self.generation && !self.fatal =>
            {
                let token = self.token.borrow().clone();
                self.video.reconnect(Instant::now(), token.as_ref());
                None
            }
            KvmCommand::RequestIdr { generation }
                if generation == self.generation && !self.fatal =>
            {
                self.request_idr();
                None
            }
            KvmCommand::OpenFlv { .. }
            | KvmCommand::ReconnectFlv { .. }
            | KvmCommand::RequestIdr { .. } => None,
        }
    }

    fn start_login(&mut self) {
        let (ep, cfg) = (self.deps.ep.clone(), self.deps.cfg.clone());
        self.login = Some(Box::pin(async move {
            login(&ep, &cfg.password, cfg.connect_timeout, cfg.login_timeout).await
        }));
        self.login_retry_at = None;
    }

    async fn login_done(&mut self, r: Result<Token, KvmError>) {
        match r {
            Ok(token) => {
                if self.auth.seq() > 0 {
                    self.deps.metrics.relogins.inc();
                }
                self.deps.metrics.logins.inc();
                self.auth.login_ok();
                self.deadline.logged_in();
                let current = (self.auth.seq(), token);
                self.video.token_ready(&current);
                self.token.send_replace(Some(current));
            }
            Err(e) => match e.class() {
                FailClass::Auth => match self.auth.login_rejected() {
                    AuthStep::Fatal => self.fatal(Cause::KvmAuthFailed).await,
                    AuthStep::Relogin | AuthStep::Wait => self.start_login(),
                },
                FailClass::Cert => self.fatal(Cause::KvmCertMismatch).await,
                FailClass::Transient => {
                    self.login_retry_at = Some(Instant::now() + self.login_backoff.next_delay());
                }
            },
        }
    }

    async fn ws_event(&mut self, ev: Option<WsEvent>) {
        match ev {
            Some(WsEvent::AuthRefused { seq }) => self.refused(seq).await,
            Some(WsEvent::CertMismatch) => self.fatal(Cause::KvmCertMismatch).await,
            Some(WsEvent::Up { seq }) => self.proven(seq),
            Some(WsEvent::Down) => {}
            None => self.ws_alive = false,
        }
    }

    /// A main-path request (the FLV or the websocket) made with token `seq`
    /// was refused for it (§6.9 auth). Never a side FLV's (§6.5).
    async fn refused(&mut self, seq: u64) {
        // P24: after a fatal cause, no refusal starts a login.
        if self.fatal {
            return;
        }
        match self.auth.refused(seq) {
            AuthStep::Relogin => self.relogin(),
            AuthStep::Wait => {
                // A token newer than the refused one may already be here:
                // hand it to the FLV (never the refused one again).
                let current = self.token.borrow().clone();
                if let Some(t) = current
                    && t.0 > seq
                {
                    self.video.token_ready(&t);
                }
            }
            AuthStep::Fatal => self.fatal(Cause::KvmAuthFailed).await,
        }
    }

    /// The gate's `Relogin` (I1, option B): the session's first re-login
    /// runs at once; every later one waits `login_backoff`, which only a
    /// proven token resets. One login at a time, and none while one is
    /// already scheduled.
    fn relogin(&mut self) {
        if self.login.is_some() || self.login_retry_at.is_some() {
            return;
        }
        if self.relogged {
            self.login_retry_at = Some(Instant::now() + self.login_backoff.next_delay());
        } else {
            self.relogged = true;
            self.start_login();
        }
    }

    /// The KVM accepted token `seq`: the websocket upgraded with it, or an
    /// FLV opened with it reached its first tag (§6.9, rev 6.2).
    fn proven(&mut self, seq: u64) {
        if self.auth.proven(seq) {
            self.login_backoff.reset();
        }
    }

    async fn outcome(&mut self, o: Outcome) {
        match o {
            Outcome::Refused { seq } => self.refused(seq).await,
            Outcome::Fatal(cause) => self.fatal(cause).await,
        }
    }

    fn request_idr(&mut self) {
        self.deps.metrics.idr_requests.inc("side");
        if self.side.is_some() {
            self.deps.metrics.idr_side_failures.inc("busy");
            return;
        }
        let Some((_, token)) = self.token.borrow().clone() else {
            self.deps.metrics.idr_side_failures.inc("no_token");
            return;
        };
        let cfg = &self.deps.cfg;
        self.side = Some(tokio::spawn(side::request_idr(
            self.deps.ep.clone(),
            token,
            cfg.connect_timeout,
            cfg.idr_side_timeout,
        )));
    }

    /// A side FLV finished (§6.5). Matched by kind, on purpose not through
    /// `FailClass`: a side FLV is excluded from §6.9's auth class, so a
    /// refusal for its token is only counted — never the `AuthGate`, never
    /// a re-login, never retried (PC8 m7). §6.9's certificate row has no
    /// such exclusion: a pin mismatch on a side FLV is fatal at once.
    async fn side_done(&mut self, r: Result<Result<(), KvmError>, JoinError>) {
        match r {
            Ok(Ok(())) => {}
            Ok(Err(KvmError::CertMismatch)) => {
                self.deps.metrics.idr_side_failures.inc("cert");
                self.fatal(Cause::KvmCertMismatch).await;
            }
            Ok(Err(
                e @ (KvmError::Auth
                | KvmError::Timeout(_)
                | KvmError::Connect(_)
                | KvmError::Tls
                | KvmError::Http(_)
                | KvmError::Protocol(_)
                | KvmError::Closed),
            )) => self.deps.metrics.idr_side_failures.inc(e.kind()),
            Err(_) => self.deps.metrics.idr_side_failures.inc("task"),
        }
    }

    async fn tick(&mut self) {
        if self.fatal {
            return;
        }
        let now = Instant::now();
        if self.deadline.expired(now) {
            self.fatal(Cause::KvmUnreachable).await;
            return;
        }
        if self.login.is_none() && self.login_retry_at.is_some_and(|t| now >= t) {
            self.start_login();
        }
        let token = self.token.borrow().clone();
        if let Some(o) = self.video.tick(now, token.as_ref()) {
            self.outcome(o).await;
        }
    }

    /// One fatal cause per session (§6.9): stop the KVM-side video (the
    /// main FLV and any side FLV) and tell the pump; the websocket stays up
    /// so Closing's release-all reaches the KVM; the pump's disconnect ends
    /// the session with a `Stop`.
    async fn fatal(&mut self, cause: Cause) {
        if self.fatal {
            return;
        }
        self.fatal = true;
        self.video.close();
        if let Some(side) = self.side.take() {
            side.abort();
        }
        self.login = None;
        self.login_retry_at = None;
        tracing::warn!(cause = cause.label(), "kvm session failed");
        let _ = self
            .deps
            .to_pump
            .send(KvmEvent::UpstreamFatal {
                generation: self.generation,
                cause,
            })
            .await;
    }

    async fn close(&mut self) {
        self.login = None;
        if let Some(side) = self.side.take() {
            side.abort();
        }
        // §11.3's order: release-all and the websocket close first (the
        // writer sends any pending release before closing), then the FLV.
        let (done, rx) = oneshot::channel();
        if self.ws_ctl.send(WsCtl::Close { done }).is_ok() {
            let _ = tokio::time::timeout(CLOSE_WAIT, rx).await;
        }
        self.ws_task.abort();
        // An aborted task is dropped asynchronously: wait (bounded) until
        // its socket is closed, so the next Start never has two websockets.
        let _ = tokio::time::timeout(ABORT_WAIT, &mut self.ws_task).await;
        self.video.close();
        // Never a logout (§3.2): the token lapses on the KVM.
    }
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
    use crate::hid::ReleaseTrigger;
    use crate::msg::FlvOrigin;
    use kvm_proto::hid::HidFrame;
    use kvm_sim::{Fault, KvmSim, SimConfig, SimEvent, Source};
    use std::future::Future as _;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::task::{Context, Wake, Waker};

    const T: Duration = Duration::from_secs(3);
    const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
    const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    struct Rig {
        sim: KvmSim,
        tx: mpsc::UnboundedSender<KvmCommand>,
        rx: mpsc::Receiver<KvmEvent>,
        hid: Arc<HidControl>,
        metrics: Arc<Metrics>,
        actor: tokio::task::JoinHandle<()>,
    }

    async fn start_sim() -> KvmSim {
        KvmSim::start(SimConfig::es3(
            Source::fixture("360p30_es3like_poc0.h264").unwrap(),
        ))
        .await
        .unwrap()
    }

    async fn rig(pin: Option<&str>, set: impl FnOnce(&mut SessionConfig)) -> Rig {
        let sim = start_sim().await;
        let p = sim.ports();
        let pin = pin.unwrap_or(sim.spki_sha256()).to_owned();
        rig_on(sim, (p.web, p.video, p.control), &pin, set)
    }

    /// The actor against `sim`, reaching it at `ports` (a test may put a
    /// proxy in front of one) and pinning `pin`.
    fn rig_on(
        sim: KvmSim,
        ports: (u16, u16, u16),
        pin: &str,
        set: impl FnOnce(&mut SessionConfig),
    ) -> Rig {
        let ep = Arc::new(KvmEndpoint::new(Scheme::Https, sim.host(), ports, pin));
        let mut cfg = SessionConfig {
            password: Secret::new(sim.password()),
            connect_timeout: Duration::from_secs(1),
            login_timeout: Duration::from_secs(2),
            backoff: BackoffConfig {
                initial: Duration::from_millis(50),
                factor: 2,
                max: Duration::from_millis(400),
                jitter_percent: 0,
            },
            upstream_deadline: Duration::from_secs(4),
            flv_idle_timeout: Duration::from_secs(2),
            idr_side_timeout: Duration::from_secs(1),
            hid_write_timeout: Duration::from_secs(1),
            admission: AdmissionConfig::default(),
        };
        set(&mut cfg);
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(256, metrics.clone()));
        let (tx, crx) = mpsc::unbounded_channel();
        let (ptx, rx) = mpsc::channel(68);
        let deps = KvmDeps {
            ep,
            cfg: Arc::new(cfg),
            to_pump: ptx,
            hid: hid.clone(),
            metrics: metrics.clone(),
        };
        let actor = tokio::spawn(run_actor(crx, deps));
        Rig {
            sim,
            tx,
            rx,
            hid,
            metrics,
            actor,
        }
    }

    impl Rig {
        async fn stop(&self, generation: Gen) {
            let (done, r) = oneshot::channel();
            self.tx
                .send(KvmCommand::Stop {
                    generation,
                    done: Some(done),
                })
                .unwrap();
            tokio::time::timeout(T, r).await.unwrap().unwrap();
        }
        /// The next event matching `pred`, skipping AUs and the rest.
        async fn wait(&mut self, pred: impl Fn(&KvmEvent) -> bool) -> KvmEvent {
            tokio::time::timeout(T, async {
                loop {
                    let ev = self.rx.recv().await.unwrap();
                    if pred(&ev) {
                        return ev;
                    }
                }
            })
            .await
            .unwrap()
        }
        async fn fatal(&mut self) -> Cause {
            match self
                .wait(|e| matches!(e, KvmEvent::UpstreamFatal { .. }))
                .await
            {
                KvmEvent::UpstreamFatal { cause, .. } => cause,
                _ => unreachable!(),
            }
        }
        fn hid_bytes(&self) -> Vec<Vec<u8>> {
            self.sim
                .events()
                .into_iter()
                .filter_map(|e| {
                    if let SimEvent::Hid { bytes, .. } = e {
                        Some(bytes)
                    } else {
                        None
                    }
                })
                .collect()
        }
        /// No `UpstreamFatal` is queued for the pump.
        fn no_fatal_queued(&mut self) {
            while let Ok(ev) = self.rx.try_recv() {
                assert!(!matches!(ev, KvmEvent::UpstreamFatal { .. }), "{ev:?}");
            }
        }
        /// The session-start sequence has reached kvm-sim, so the writer is
        /// past `drive`'s `discard_queued` and a push is written, not
        /// discarded as made while the websocket was down (§7.3). kvm-sim
        /// counts `ws_open` before the bridge's side of the handshake ends.
        async fn input_ready(&self) {
            self.sim
                .wait_for(T, |e| {
                    e.iter()
                        .filter(|e| matches!(e, SimEvent::Hid { .. }))
                        .count()
                        >= 2
                })
                .await
                .unwrap();
        }
        /// Start a session with its FLV open and its websocket up.
        async fn streaming(&mut self, generation: Gen) {
            self.tx.send(KvmCommand::Start { generation }).unwrap();
            self.tx.send(KvmCommand::OpenFlv { generation }).unwrap();
            self.wait(|e| opened(e, FlvOrigin::First)).await;
            self.sim
                .wait_for(T, |_| self.sim.stats().ws_open == 1)
                .await
                .unwrap();
        }
    }

    fn opened(e: &KvmEvent, want: FlvOrigin) -> bool {
        matches!(e, KvmEvent::FlvOpened { origin, .. } if *origin == want)
    }

    fn flv_opens(log: &[SimEvent]) -> usize {
        log.iter()
            .filter(|e| matches!(e, SimEvent::FlvOpen { .. }))
            .count()
    }

    /// §5.1: Start logs in once and opens the websocket with the
    /// session-start sequence; no FLV until `OpenFlv` (the first Setup).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_logs_in_once_and_sends_the_session_start_sequence() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.sim
            .wait_for(T, |e| {
                e.iter()
                    .filter(|e| matches!(e, SimEvent::Hid { .. }))
                    .count()
                    >= 2
            })
            .await
            .unwrap();
        // Exactly these two: no pointer report was ever sent, so none is
        // parked at (0, 0) (§3.3, rev 5.1).
        assert_eq!(r.hid_bytes(), [SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
        let s = r.sim.stats();
        assert_eq!((s.logins_ok, s.ws_open, s.flv_open), (1, 1, 0));
        r.stop(1).await;
    }

    /// §7.3/§3.2: Stop flushes the release before the websocket closes, and
    /// never logs out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_flushes_the_release_and_never_logs_out() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.input_ready().await;
        r.hid.push(
            HidFrame::Keyboard {
                modifiers: 0x08,
                keys: [4, 0, 0, 0, 0],
            },
            false,
        );
        r.sim
            .wait_for(T, |e| {
                e.iter()
                    .filter(|e| matches!(e, SimEvent::Hid { .. }))
                    .count()
                    >= 3
            })
            .await
            .unwrap();
        r.hid.release_all(ReleaseTrigger::SessionEnd);
        r.stop(1).await;
        r.sim
            .wait_for(T, |_| r.sim.stats().ws_open == 0)
            .await
            .unwrap();
        assert_eq!(r.hid_bytes().last().unwrap(), &KBD_ZERO.to_vec());
        assert_eq!(r.sim.stats().logouts, 0);
    }

    /// Review Focus 1: Start/Stop storms — including a Stop while the login
    /// is still in flight — leave nothing open, never two websockets, no
    /// logout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_stop_storm_leaves_nothing_open() {
        // A login that would hang for 30 s: a Stop that waited for it
        // could not meet the bound below.
        let r = rig(None, |c| {
            c.connect_timeout = Duration::from_secs(30);
            c.login_timeout = Duration::from_secs(30);
        })
        .await;
        r.sim.set_policy(|p| p.blackhole = true);
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = std::time::Instant::now();
        r.stop(1).await;
        assert!(
            t0.elapsed() < CLOSE_WAIT * 5,
            "Stop waited for the hung login: {:?}",
            t0.elapsed()
        );
        r.sim.set_policy(|p| p.blackhole = false);
        for generation in 2..12 {
            r.tx.send(KvmCommand::Start { generation }).unwrap();
            r.tx.send(KvmCommand::OpenFlv { generation }).unwrap();
            if generation % 2 == 0 {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            r.stop(generation).await;
        }
        r.tx.send(KvmCommand::Start { generation: 20 }).unwrap();
        r.sim
            .wait_for(T, |_| r.sim.stats().ws_open == 1)
            .await
            .unwrap();
        r.stop(20).await;
        r.sim
            .wait_for(T, |_| {
                let s = r.sim.stats();
                s.ws_open == 0 && s.flv_open == 0
            })
            .await
            .unwrap();
        let s = r.sim.stats();
        assert_eq!(s.ws_max_open, 1, "two websockets at once");
        assert_eq!(s.logouts, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_login_rejected_twice_is_kvm_auth_failed() {
        let mut r = rig(None, |_| {}).await;
        r.sim.set_policy(|p| p.reject_logins = true);
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        assert_eq!(r.sim.stats().logins_failed, 2);
        r.stop(1).await;
    }

    /// §6.9: a pin mismatch is fatal at once, no login request is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrong_pin_is_kvm_cert_mismatch_with_no_login() {
        let pin = "1".repeat(64);
        let mut r = rig(Some(&pin), |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmCertMismatch);
        let s = r.sim.stats();
        assert_eq!((s.logins_ok, s.logins_failed), (0, 0));
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_login_by_the_deadline_is_kvm_unreachable() {
        let deadline = Duration::from_millis(800);
        let mut r = rig(None, |c| c.upstream_deadline = deadline).await;
        r.sim.set_policy(|p| p.blackhole = true);
        let t0 = std::time::Instant::now();
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmUnreachable);
        assert!(
            t0.elapsed() >= deadline / 2 && t0.elapsed() < deadline * 5,
            "{:?}",
            t0.elapsed()
        );
        r.stop(1).await;
    }

    /// §6.9 auth, §11.3 "token expiry": the FLV and the websocket both hit
    /// the dead token, the bridge re-logs in exactly once, and the stream
    /// continues with no disconnect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_token_relogs_in_exactly_once_and_the_stream_continues() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.sim
            .wait_for(T, |_| r.sim.stats().ws_open == 1)
            .await
            .unwrap();
        r.sim.expire_tokens();
        r.sim.close_websockets();
        r.sim.inject(Fault::Close);
        r.wait(|e| opened(e, FlvOrigin::Transient)).await;
        r.sim
            .wait_for(T, |_| r.sim.stats().ws_open == 1)
            .await
            .unwrap();
        assert_eq!(r.sim.stats().logins_ok, 2);
        assert_eq!(r.metrics.relogins.get(), 1);
        r.no_fatal_queued();
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_consecutive_auth_failure_is_fatal() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.sim.expire_tokens();
        r.sim.set_policy(|p| p.reject_logins = true);
        r.sim.inject(Fault::Close);
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        r.stop(1).await;
    }

    /// No login past `logins_ok == n` within 1 s (a loop shows in ms).
    async fn no_more_logins(r: &Rig, n: u64) {
        let more = r
            .sim
            .wait_for(Duration::from_secs(1), |_| {
                let s = r.sim.stats();
                s.logins_ok + s.logins_failed > n
            })
            .await;
        assert!(more.is_err(), "logged in again: {:?}", r.sim.stats());
    }

    /// I1 (PC9 fix round 1, XP1): a KVM that accepts logins but refuses
    /// every fresh token on the websocket. A token that never worked does
    /// not make its re-login "successful" (§6.9, rev 6.2): the second
    /// refusal is fatal — two logins, not hundreds a second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_websocket_refusing_every_fresh_token_fails_after_two_logins() {
        let mut r = rig(None, |_| {}).await;
        r.streaming(1).await;
        r.sim.set_policy(|p| p.ws_status = Some(403));
        r.sim.close_websockets();
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        no_more_logins(&r, 2).await;
        assert_eq!(r.sim.stats().logins_ok, 2);
        r.stop(1).await;
    }

    /// I1: a token the FLV proves (its reopen reached a first tag) makes
    /// the re-login successful, so a second expiry re-logs in again rather
    /// than being fatal — with the websocket still up on the first token,
    /// the FLV's proof is the only one (§11.3 "token expiry", twice).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_flv_proven_token_allows_the_next_relogin() {
        let mut r = rig(None, |_| {}).await;
        r.streaming(1).await;
        for round in 1..=2u64 {
            r.sim.expire_tokens();
            r.sim.inject(Fault::Close);
            r.wait(|e| opened(e, FlvOrigin::Transient)).await;
            // The reopen's first tag, on the new token.
            r.wait(|e| matches!(e, KvmEvent::Au { .. })).await;
            assert_eq!(r.sim.stats().logins_ok, round + 1, "round {round}");
        }
        assert_eq!(r.metrics.relogins.get(), 2);
        assert_eq!(r.sim.stats().ws_open, 1);
        r.no_fatal_queued();
        r.stop(1).await;
    }

    /// I1 (XP2): the same with the FLV refusing every token — the websocket
    /// stays up on the first token, so no fresh token is ever accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_flv_refusing_every_fresh_token_fails_after_two_logins() {
        let mut r = rig(None, |c| c.upstream_deadline = Duration::from_secs(20)).await;
        r.sim.set_policy(|p| p.flv_status = Some(403));
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        no_more_logins(&r, 2).await;
        assert_eq!(r.sim.stats().logins_ok, 2);
        r.stop(1).await;
    }

    /// I1 residual (option B): the websocket accepts every fresh token —
    /// it is dropped after each login, so it reopens with the new one and
    /// proves it — while the FLV refuses every token. The gate never sees
    /// two unproven refusals in a row, so only `login_backoff` bounds the
    /// re-logins: the first is immediate, every later one starts at least
    /// the backoff after the refusal that caused it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn re_logins_while_only_the_flv_refuses_are_paced_by_the_backoff() {
        let backoff = Duration::from_millis(200);
        let sim = start_sim().await;
        sim.set_policy(|p| p.flv_status = Some(403));
        let p = sim.ports();
        // Each FLV refusal comes 500 ms after its open, well after the
        // websocket (reopened 200 ms after a drop) proved the token.
        let video = proxy_delayed(p.video, Duration::from_millis(500)).await;
        let pin = sim.spki_sha256().to_owned();
        let mut r = rig_on(sim, (p.web, video.port, p.control), &pin, |c| {
            c.backoff = BackoffConfig {
                initial: backoff,
                factor: 2,
                max: backoff * 4,
                jitter_percent: 0,
            };
            c.upstream_deadline = Duration::from_secs(20);
        });
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        let t0 = std::time::Instant::now();
        let mut seen = 0;
        while t0.elapsed() < Duration::from_secs(3) {
            let n = r.sim.stats().logins_ok;
            if n > seen {
                seen = n;
                r.sim.close_websockets();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        r.no_fatal_queued();
        let log = r.sim.stamped_events();
        let at = |f: fn(&SimEvent) -> bool| -> Vec<std::time::Instant> {
            log.iter().filter(|(_, e)| f(e)).map(|(t, _)| *t).collect()
        };
        let logins = at(|e| matches!(e, SimEvent::Login { ok: true }));
        let refusals = at(|e| matches!(e, SimEvent::FlvRefused { .. }));
        assert!(
            logins.len() >= 3,
            "the loop never ran: {} logins",
            logins.len()
        );
        for (k, login) in logins.iter().enumerate().skip(1) {
            let cause = refusals.iter().filter(|t| *t < login).max().unwrap();
            let gap = login.saturating_duration_since(*cause);
            if k == 1 {
                assert!(gap < backoff / 2, "the first re-login waited {gap:?}");
            } else {
                assert!(
                    gap >= backoff / 2,
                    "re-login {k} came {gap:?} after the refusal that caused it"
                );
            }
        }
        r.stop(1).await;
    }

    /// §6.5: `RequestIdr` → one side FLV; a refused one is counted and
    /// neither retried nor answered with a re-login.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn request_idr_runs_one_side_flv_and_counts_a_refusal() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        r.sim
            .wait_for(T, |e| {
                e.iter()
                    .filter(|e| matches!(e, SimEvent::FlvClose { .. }))
                    .count()
                    == 1
            })
            .await
            .unwrap();
        assert_eq!(r.metrics.idr_requests.get("side"), 1);
        let count =
            |r: &Rig, f: fn(&SimEvent) -> bool| r.sim.events().iter().filter(|e| f(e)).count();
        let opens_before = count(&r, |e| matches!(e, SimEvent::FlvOpen { .. }));
        r.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        tokio::time::timeout(T, async {
            while r.metrics.idr_side_failures.get("http") == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        // `refuse_concurrent_flv` is spent: a retry would now open a side
        // FLV. Wait past `idr_side_timeout` (1 s) and look for one.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            count(&r, |e| matches!(e, SimEvent::FlvRefused { .. })),
            1,
            "one refusal"
        );
        assert_eq!(
            count(&r, |e| matches!(e, SimEvent::FlvOpen { .. })),
            opens_before,
            "a refused side FLV was retried"
        );
        assert_eq!(
            r.sim.stats().logins_ok,
            1,
            "a refusal is never answered with a re-login"
        );
        r.stop(1).await;
    }

    /// §6.5/§6.9 (PC8 m7): side FLVs are excluded from the auth class. A
    /// side FLV refused for its dead token is counted under `auth` and is
    /// never fed to the `AuthGate`: no re-login, no fatal — the main FLV and
    /// the websocket, which still hold their connections, carry on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_flv_refused_for_its_token_is_counted_never_auth_gated() {
        let mut r = rig(None, |_| {}).await;
        r.streaming(1).await;
        r.sim.expire_tokens();
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        tokio::time::timeout(T, async {
            while r.metrics.idr_side_failures.get("auth") == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the side FLV's refusal was not counted under auth");
        // A re-login (the gate's answer) takes a few ms against kvm-sim.
        let relogin = r
            .sim
            .wait_for(Duration::from_secs(1), |_| {
                let s = r.sim.stats();
                s.logins_ok + s.logins_failed > 1
            })
            .await;
        assert!(relogin.is_err(), "a side refusal started a login");
        assert_eq!(r.metrics.idr_side_failures.get("auth"), 1);
        assert_eq!(r.metrics.relogins.get(), 0);
        let s = r.sim.stats();
        assert_eq!((s.logins_ok, s.logins_failed, s.logouts), (1, 0, 0));
        r.no_fatal_queued();
        r.stop(1).await;
    }

    /// A loopback TCP forwarder: each new connection goes to the port in
    /// `to` at the time it is accepted, so a test can serve one connection
    /// kind from a second kvm-sim.
    struct Proxy {
        port: u16,
        to: Arc<AtomicU16>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn proxy(to: u16) -> Proxy {
        proxy_delayed(to, Duration::ZERO).await
    }

    /// A proxy that holds each new connection for `delay` before it
    /// connects upstream: every answer on it comes at least that late.
    async fn proxy_delayed(to: u16, delay: Duration) -> Proxy {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let to = Arc::new(AtomicU16::new(to));
        let target = to.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut a, _)) = l.accept().await {
                let up = target.load(Ordering::SeqCst);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Ok(mut b) = tokio::net::TcpStream::connect(("127.0.0.1", up)).await {
                        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                    }
                });
            }
        });
        Proxy { port, to, task }
    }

    /// §6.9's certificate row has no exclusion (only the auth row excludes
    /// side FLVs; PC8 m7): a side FLV served a certificate that is not the
    /// pinned one is `kvm_cert_mismatch` at once. The video port is a
    /// proxy: the main FLV reaches the pinned kvm-sim, then the proxy is
    /// switched to a second kvm-sim (its own certificate), so only the
    /// side FLV meets the wrong one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_flv_with_the_wrong_certificate_is_fatal() {
        let sim = start_sim().await;
        let other = start_sim().await;
        assert_ne!(sim.spki_sha256(), other.spki_sha256());
        let p = sim.ports();
        let video = proxy(p.video).await;
        let pin = sim.spki_sha256().to_owned();
        let mut r = rig_on(sim, (p.web, video.port, p.control), &pin, |_| {});
        r.streaming(1).await;
        video.to.store(other.ports().video, Ordering::SeqCst);
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmCertMismatch);
        // It was the side FLV's: the one connection that reached the other
        // certificate, counted on the side path; the main FLV never
        // reopened.
        assert_eq!(r.metrics.idr_side_failures.get("cert"), 1);
        assert_eq!(other.stats().accepts_video, 1);
        assert_eq!(flv_opens(&other.events()), 0);
        assert_eq!(flv_opens(&r.sim.events()), 1);
        r.stop(1).await;
    }

    /// P24: an auth refusal that arrives after a fatal cause starts no
    /// login. The websocket stays up after a fatal (Closing's release-all
    /// must reach the KVM), so here it is dropped with every token expired,
    /// and its reopen is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_auth_refusal_after_a_fatal_cause_starts_no_login() {
        let mut r = rig(None, |_| {}).await;
        r.streaming(1).await;
        r.sim.inject(Fault::BSlice);
        assert_eq!(r.fatal().await, Cause::StreamIncompatible);
        r.sim.expire_tokens();
        r.sim.close_websockets();
        r.sim
            .wait_for(T, |e| {
                e.iter().any(|e| matches!(e, SimEvent::WsRefused { .. }))
            })
            .await
            .expect("the websocket's reopen was never refused");
        let login = r
            .sim
            .wait_for(Duration::from_secs(1), |_| {
                let s = r.sim.stats();
                s.logins_ok + s.logins_failed > 1
            })
            .await;
        assert!(
            login.is_err(),
            "a refusal after the fatal cause started a login"
        );
        assert_eq!(r.metrics.relogins.get(), 0);
        r.stop(1).await;
    }

    /// PC8 n2: after a fatal cause nothing opens an FLV — `Video::reconnect`
    /// (and `want`) would open a new one on a closed `Video`, and a side
    /// request would open one too — so the session drops `OpenFlv`,
    /// `ReconnectFlv` and `RequestIdr` once fatal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nothing_opens_an_flv_after_a_fatal_cause() {
        let mut r = rig(None, |_| {}).await;
        r.streaming(1).await;
        r.sim.inject(Fault::BSlice);
        assert_eq!(r.fatal().await, Cause::StreamIncompatible);
        let before = flv_opens(&r.sim.events());
        for cmd in [
            KvmCommand::ReconnectFlv { generation: 1 },
            KvmCommand::OpenFlv { generation: 1 },
            KvmCommand::RequestIdr { generation: 1 },
        ] {
            r.tx.send(cmd).unwrap();
        }
        let opened = r
            .sim
            .wait_for(Duration::from_secs(1), |e| flv_opens(e) > before)
            .await;
        assert!(opened.is_err(), "an FLV opened after the fatal cause");
        assert_eq!(r.metrics.idr_requests.get("side"), 0);
        assert_eq!(r.metrics.idr_requests.get("reconnect"), 0);
        assert!(
            !std::iter::from_fn(|| r.rx.try_recv().ok())
                .any(|e| matches!(e, KvmEvent::FlvOpened { .. })),
            "an FlvOpened after the fatal cause"
        );
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_flv_is_make_before_break() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.tx.send(KvmCommand::ReconnectFlv { generation: 1 })
            .unwrap();
        r.wait(|e| opened(e, FlvOrigin::Commanded)).await;
        r.sim
            .wait_for(T, |_| r.sim.stats().flv_open == 1)
            .await
            .unwrap();
        r.stop(1).await;
    }

    /// Reads `hid_reports_sent` at the instant the ack is sent: the oneshot
    /// sender wakes this waker synchronously inside `done.send(())`, on the
    /// writer's own thread, before the writer runs another line.
    struct AckProbe {
        metrics: Arc<Metrics>,
        at_ack: OnceLock<u64>,
        task: Mutex<Option<Waker>>,
    }

    impl Wake for AckProbe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let _ = self.at_ack.set(self.metrics.hid_reports_sent.get());
            let task = self.task.lock().unwrap().take();
            if let Some(w) = task {
                w.wake();
            }
        }
    }

    /// Await the ack on `rx`; the frames written when it was sent.
    async fn sent_at_ack(rx: oneshot::Receiver<()>, metrics: Arc<Metrics>) -> u64 {
        let probe = Arc::new(AckProbe {
            metrics,
            at_ack: OnceLock::new(),
            task: Mutex::new(None),
        });
        let waker = Waker::from(probe.clone());
        let mut rx = std::pin::pin!(rx);
        // Unconstrained: an exhausted coop budget would wake the probe
        // early, before any ack.
        tokio::task::unconstrained(std::future::poll_fn(|cx| {
            *probe.task.lock().unwrap() = Some(cx.waker().clone());
            rx.as_mut().poll(&mut Context::from_waker(&waker))
        }))
        .await
        .expect("the Flush was dropped, not acked");
        *probe.at_ack.get().unwrap()
    }

    /// §5.2 (PC7 W5): FlushHid writes a pending release while the websocket
    /// stays up, and its ack comes only once that release is written.
    ///
    /// Current-thread on purpose: nothing else runs until this task awaits.
    /// `FlushHid` is sent before `release_all`, so the actor (woken first)
    /// puts the Flush in the writer's control channel before the writer
    /// (woken second) runs — and the writer, whose select polls control
    /// first, finds the Flush with the release still pending: the Flush arm
    /// itself must write it before acking, not the loop top after.
    #[tokio::test]
    async fn flush_hid_acks_after_the_release_is_written() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.input_ready().await;
        r.hid.push(
            HidFrame::Keyboard {
                modifiers: 0,
                keys: [5, 0, 0, 0, 0],
            },
            false,
        );
        // SET_MODE, KBD_ZERO, the key: written, and the writer idle again.
        tokio::time::timeout(T, async {
            while r.metrics.hid_reports_sent.get() < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let before = r.metrics.hid_reports_sent.get();
        assert_eq!(before, 3);
        let (done, ack) = oneshot::channel();
        r.tx.send(KvmCommand::FlushHid { done }).unwrap();
        r.hid.release_all(ReleaseTrigger::Shutdown);
        let at_ack = tokio::time::timeout(T, sent_at_ack(ack, r.metrics.clone()))
            .await
            .unwrap();
        assert_eq!(
            at_ack,
            before + 1,
            "the Flush was acked before the pending release was written"
        );
        r.sim
            .wait_for(T, |e| {
                e.iter()
                    .filter(|e| matches!(e, SimEvent::Hid { .. }))
                    .count()
                    >= 4
            })
            .await
            .unwrap();
        assert_eq!(r.hid_bytes().last().unwrap(), &KBD_ZERO.to_vec());
        assert_eq!(r.sim.stats().ws_open, 1);
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_closes_everything_and_ends_the_actor() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        let (done, rx) = oneshot::channel();
        r.tx.send(KvmCommand::Shutdown { done }).unwrap();
        tokio::time::timeout(T, rx).await.unwrap().unwrap();
        tokio::time::timeout(T, r.actor).await.unwrap().unwrap();
        r.sim
            .wait_for(T, |_| {
                let s = r.sim.stats();
                s.ws_open == 0 && s.flv_open == 0
            })
            .await
            .unwrap();
        assert_eq!(r.sim.stats().logouts, 0);
    }
}
