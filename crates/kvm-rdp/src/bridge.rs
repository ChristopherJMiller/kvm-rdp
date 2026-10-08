//! The assembly (§4.3, §5.2). The RDP runtime — current-thread under a
//! `LocalSet`, on its own thread — runs IronRDP's `!Send` server, the
//! heartbeat and the pump's shell; the one-worker KVM runtime runs the KVM
//! actor, the admin listener and the certificate watcher. `shutdown` is
//! §5.2 in order, inside 5 s (DC13).
use crate::admin::{self, Health};
use crate::config::Config;
use crate::hid::{HidControl, ReleaseTrigger};
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::session::{self, KvmDeps, SessionConfig};
use crate::metrics::Metrics;
use crate::msg::{Generations, KvmCommand, KvmEvent, RdpInput, kvm_stream_capacity};
use crate::pump::PumpConfig;
use crate::pump::shell::{PumpShell, ShellDeps};
use crate::rdp::accept::{AcceptRate, HANDSHAKE_GRACE, Handshakes};
use crate::rdp::display::{BridgeDisplay, DisplayShared};
use crate::rdp::gfx::{GfxFactory, GfxSlot};
use crate::rdp::handler::Lifecycle;
use crate::rdp::input::InputStub;
use crate::rdp::server::{self, ServerParts};
use crate::rdp::tls::{self, TlsError};
use ironrdp_server::ServerEvent;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::signal::unix::{Signal, SignalKind};
use tokio::sync::{mpsc, oneshot, watch};

/// How long `spawn` waits for the RDP listener.
pub const STARTUP_WAIT: Duration = Duration::from_secs(5);
/// §5.2's steps (DC13): 4.7 s in all with both `Quit`s, inside the 5 s exit.
pub const FLUSH_WAIT: Duration = Duration::from_millis(500);
/// The shell's 2 s disconnect watchdog plus one 50 ms tick, and slack.
pub const DISCONNECT_WAIT: Duration = Duration::from_millis(2200);
/// Covers the KVM actor's slowest `Stop`/`Shutdown` (`session::STOP_BOUND`,
/// 600 ms): one may still be running from the disconnect when this step's
/// `Shutdown` is queued behind it.
pub const KVM_CLOSE_WAIT: Duration = Duration::from_secs(1);
pub const QUIT_WAIT: Duration = Duration::from_millis(500);
/// What `run_until_signal` gives the KVM runtime's tasks after §5.2:
/// 4.7 s + 0.2 s, inside the 5 s exit.
pub const RUNTIME_TEARDOWN: Duration = Duration::from_millis(200);

#[derive(Debug)]
pub enum BridgeError {
    Tls(TlsError),
    AdminBind(std::io::ErrorKind),
    RdpBind(String),
    Runtime(std::io::ErrorKind),
    Timeout,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Tls(e) => write!(f, "TLS identity: {e}"),
            BridgeError::AdminBind(k) => write!(f, "admin listener: {k}"),
            BridgeError::RdpBind(e) => write!(f, "RDP listener: {e}"),
            BridgeError::Runtime(k) => write!(f, "runtime: {k}"),
            BridgeError::Timeout => {
                write!(f, "the RDP listener did not start within {STARTUP_WAIT:?}")
            }
        }
    }
}

impl std::error::Error for BridgeError {}

/// Why the bridge stopped (the binary's exit code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Signal,
    CertificateChanged,
    ServerStopped,
}

impl Exit {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Exit::Signal => "signal",
            Exit::CertificateChanged => "certificate_changed",
            Exit::ServerStopped => "server_stopped",
        }
    }

    /// The binary's exit code: 0 after a signal or a certificate change (the
    /// orchestrator restarts it, on the new pair for the latter), 1 when the
    /// RDP server stopped on its own.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Exit::Signal | Exit::CertificateChanged => 0,
            Exit::ServerStopped => 1,
        }
    }
}

/// What the shutdown sequence touches.
struct Control {
    accepting: Arc<AtomicBool>,
    hid: Arc<HidControl>,
    to_kvm: mpsc::UnboundedSender<KvmCommand>,
    to_pump: mpsc::UnboundedSender<RdpInput>,
    events: mpsc::UnboundedSender<ServerEvent>,
    rdp_done: watch::Receiver<bool>,
}

pub struct BridgeHandle {
    pub rdp_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    metrics: Arc<Metrics>,
    hid: Arc<HidControl>,
    ctl: Arc<Control>,
    exit: watch::Receiver<bool>,
    kvm_rt: Option<Runtime>,
    // Detached on shutdown: it ends once `RdpServer::run` returns.
    _rdp_thread: std::thread::JoinHandle<()>,
}

/// The shell's dependencies that cross to the RDP thread.
struct ShellParts {
    cfg: PumpConfig,
    metrics: Arc<Metrics>,
    gens: Arc<Generations>,
    hid: Arc<HidControl>,
    display: Arc<DisplayShared>,
    suppressed: Arc<AtomicBool>,
    rtt: Arc<AtomicU32>,
    to_kvm: mpsc::UnboundedSender<KvmCommand>,
}

struct RdpParts {
    server: ServerParts,
    shell: ShellParts,
    rdp_inputs: mpsc::UnboundedReceiver<RdpInput>,
    kvm_events: mpsc::Receiver<KvmEvent>,
    health: Arc<Health>,
    beat: Duration,
    /// The KVM runtime's essential tasks (m5); the shell joins them.
    essential: Essential,
}

/// The tasks the bridge cannot work without (PC15 review m5), by name.
type Essential = Vec<(&'static str, tokio::task::JoinHandle<()>)>;

type Ready = Result<(SocketAddr, mpsc::UnboundedSender<ServerEvent>), BridgeError>;

/// A runtime shut down in the background when dropped: a blocking drop
/// panics inside another runtime (a cancelled `shutdown` future).
struct Background(Option<Runtime>);

impl Drop for Background {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

/// Start the bridge; returns once the RDP listener is bound (blocking).
pub fn spawn(cfg: Config) -> Result<BridgeHandle, BridgeError> {
    tls::install_crypto_provider();
    // P7: the certificate watcher's baseline, taken before the pair is read
    // — so a renewal racing the load counts as a change, and none between
    // here and the watcher's first poll goes unseen.
    let first_print = tls::fingerprint(&cfg.rdp.tls_cert_file, &cfg.rdp.tls_key_file);
    let identity =
        tls::load(&cfg.rdp.tls_cert_file, &cfg.rdp.tls_key_file).map_err(BridgeError::Tls)?;
    // PC13 m10: named, never judged (§9.1 leaves RSA vs ECDSA to acceptance).
    tracing::info!(
        key_type = identity.key.label(),
        key_bits = identity.key.bits(),
        "TLS identity loaded"
    );
    let metrics = Arc::new(Metrics::default());
    let health = Arc::new(Health::new(cfg.admin.liveness_timeout));
    health.set_tls_loaded();
    let gens = Arc::new(Generations::default());
    let handshakes = Arc::new(Handshakes::new(HANDSHAKE_GRACE));
    let hid = Arc::new(HidControl::new(cfg.input.queue, metrics.clone()));
    let display = DisplayShared::new(cfg.video.default_size);
    let accepting = Arc::new(AtomicBool::new(true));
    let suppressed = Arc::new(AtomicBool::new(false));
    let rtt = Arc::new(AtomicU32::new(u32::MAX));
    let gfx_slot = GfxSlot::default();
    let pump_cfg = PumpConfig::from_config(&cfg);
    let (to_kvm, kvm_cmds) = mpsc::unbounded_channel();
    let (kvm_tx, kvm_events) = mpsc::channel(kvm_stream_capacity(pump_cfg.hard_cap));
    let (to_pump, rdp_inputs) = mpsc::unbounded_channel();
    let (exit_tx, exit) = watch::channel(false);
    let (done_tx, rdp_done) = watch::channel(false);

    let admin_std = std::net::TcpListener::bind(cfg.admin.listen)
        .map_err(|e| BridgeError::AdminBind(e.kind()))?;
    admin_std
        .set_nonblocking(true)
        .map_err(|e| BridgeError::AdminBind(e.kind()))?;
    let admin_addr = admin_std
        .local_addr()
        .map_err(|e| BridgeError::AdminBind(e.kind()))?;

    let kvm_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("kvm-rdp-kvm")
        .enable_all()
        .build()
        .map_err(|e| BridgeError::Runtime(e.kind()))?;
    let admin_listener = {
        let _rt = kvm_rt.enter();
        tokio::net::TcpListener::from_std(admin_std)
    };
    let admin_listener = match admin_listener {
        Ok(l) => l,
        Err(e) => {
            kvm_rt.shutdown_background();
            return Err(BridgeError::AdminBind(e.kind()));
        }
    };
    let admin_task = kvm_rt.spawn(admin::serve(
        admin_listener,
        health.clone(),
        metrics.clone(),
    ));
    let actor_task = kvm_rt.spawn(session::run_actor(
        kvm_cmds,
        KvmDeps {
            ep: Arc::new(KvmEndpoint::from_config(&cfg.kvm)),
            cfg: Arc::new(SessionConfig::from_config(&cfg)),
            to_pump: kvm_tx,
            hid: hid.clone(),
            metrics: metrics.clone(),
        },
    ));
    let watcher_task = kvm_rt.spawn(watch_certificate(
        cfg.rdp.tls_cert_file.clone(),
        cfg.rdp.tls_key_file.clone(),
        first_print,
        cfg.rdp.cert_poll_interval,
        gens.clone(),
        handshakes.clone(),
        exit_tx,
    ));

    let parts = RdpParts {
        server: ServerParts {
            listen: cfg.rdp.listen,
            tls: identity,
            username: cfg.rdp.username.clone(),
            password: cfg.rdp.nla_password.clone(),
            input: InputStub::new(metrics.clone()),
            display: BridgeDisplay::new(display.clone(), to_pump.clone()),
            gfx: GfxFactory::new(
                gfx_slot.clone(),
                to_pump.clone(),
                pump_cfg.hard_cap,
                metrics.clone(),
            ),
            lifecycle: Lifecycle {
                gens: gens.clone(),
                accepting: accepting.clone(),
                rate: AcceptRate::new(cfg.security.accept_rate, cfg.security.accept_window),
                gfx: gfx_slot,
                hid: hid.clone(),
                metrics: metrics.clone(),
                to_pump: to_pump.clone(),
                to_kvm: to_kvm.clone(),
                handshakes,
            },
            suppressed: suppressed.clone(),
            rtt: rtt.clone(),
        },
        shell: ShellParts {
            cfg: pump_cfg,
            metrics: metrics.clone(),
            gens,
            hid: hid.clone(),
            display,
            suppressed,
            rtt,
            to_kvm: to_kvm.clone(),
        },
        rdp_inputs,
        kvm_events,
        health: health.clone(),
        essential: vec![
            ("KVM actor", actor_task),
            ("admin listener", admin_task),
            ("certificate watcher", watcher_task),
        ],
        beat: (cfg.admin.liveness_timeout / 4)
            .clamp(Duration::from_millis(10), Duration::from_secs(1)),
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Ready>();
    let rdp_thread = match std::thread::Builder::new()
        .name("kvm-rdp-rdp".to_owned())
        .spawn(move || rdp_main(parts, ready_tx, done_tx))
    {
        Ok(t) => t,
        Err(e) => {
            kvm_rt.shutdown_background();
            return Err(BridgeError::Runtime(e.kind()));
        }
    };
    let (rdp_addr, events) = match ready_rx.recv_timeout(STARTUP_WAIT) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            kvm_rt.shutdown_background();
            return Err(e);
        }
        Err(_) => {
            kvm_rt.shutdown_background();
            return Err(BridgeError::Timeout);
        }
    };
    health.set_rdp_bound();
    // "kvm-rdp ready" is `run_until_signal`'s, after its signal handlers (P37).
    tracing::debug!(rdp = %rdp_addr, admin = %admin_addr, "bridge started");
    let ctl = Arc::new(Control {
        accepting,
        hid: hid.clone(),
        to_kvm,
        to_pump,
        events,
        rdp_done,
    });
    Ok(BridgeHandle {
        rdp_addr,
        admin_addr,
        metrics,
        hid,
        ctl,
        exit,
        kvm_rt: Some(kvm_rt),
        _rdp_thread: rdp_thread,
    })
}

/// The RDP runtime's thread.
fn rdp_main(p: RdpParts, ready: std::sync::mpsc::Sender<Ready>, done: watch::Sender<bool>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(BridgeError::Runtime(e.kind())));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let RdpParts {
            server: parts,
            shell,
            rdp_inputs,
            kvm_events,
            health,
            beat,
            mut essential,
        } = p;
        let mut server = server::build(parts);
        let events = server.event_sender().clone();
        let deps = ShellDeps {
            cfg: shell.cfg,
            metrics: shell.metrics,
            gens: shell.gens,
            hid: shell.hid,
            display: shell.display,
            events: events.clone(),
            suppressed: shell.suppressed,
            rtt: shell.rtt,
            to_kvm: shell.to_kvm,
        };
        let shell = tokio::task::spawn_local(PumpShell::new(deps).run(rdp_inputs, kvm_events));
        essential.push(("pump shell", shell));
        tokio::task::spawn_local(heartbeat(health, beat));
        let mut run =
            tokio::task::spawn_local(
                async move { server.run().await.map_err(|e| format!("{e:#}")) },
            );
        let (tx, rx) = oneshot::channel();
        let _ = events.send(ServerEvent::GetLocalAddr(tx));
        match tokio::time::timeout(STARTUP_WAIT, rx).await {
            Ok(Ok(Some(addr))) => {
                if ready.send(Ok((addr, events.clone()))).is_err() {
                    // `spawn` gave up: stop the server again.
                    let _ = events.send(ServerEvent::Quit("startup abandoned".to_owned()));
                }
            }
            _ => {
                // `run()` failed to bind (the queued `GetLocalAddr` died with it).
                let why = match tokio::time::timeout(Duration::from_millis(500), run).await {
                    Ok(Ok(Err(e))) => e,
                    _ => "the RDP listener did not start".to_owned(),
                };
                let _ = ready.send(Err(BridgeError::RdpBind(why)));
                return;
            }
        }
        // m5: a panicked essential task stops the server in every build —
        // release's `panic = "abort"` exits on its own, a debug build would
        // otherwise keep serving NLA with no pump or no KVM side behind it.
        let ended = tokio::select! {
            r = &mut run => Some(r),
            task = first_panic(essential) => {
                tracing::error!(task, "a task the bridge needs panicked; stopping the RDP server");
                None
            }
        };
        match ended {
            Some(Ok(Ok(()))) => tracing::info!("RDP server stopped"),
            Some(Ok(Err(e))) => tracing::error!(error = %e, "RDP server failed"),
            Some(Err(_)) => tracing::error!("RDP server task failed"),
            None => {
                // Dropped before `done`: the listener is closed by then.
                run.abort();
                let _ = run.await;
            }
        }
        done.send_replace(true);
    });
}

/// Resolves with the name of the first essential task that panicked. A
/// normal end is not a death — the KVM actor returns at §5.2 step 4, the
/// certificate watcher after asking for an exit — nor is a cancellation
/// (its runtime shutting down): those are waited past, and with none left
/// this never resolves.
async fn first_panic(tasks: Essential) -> &'static str {
    let (tx, mut rx) = mpsc::unbounded_channel();
    for (name, task) in tasks {
        let tx = tx.clone();
        tokio::spawn(async move {
            if task.await.is_err_and(|e| e.is_panic()) {
                let _ = tx.send(name);
            }
        });
    }
    drop(tx);
    match rx.recv().await {
        Some(name) => name,
        None => std::future::pending().await,
    }
}

/// §4.5: the RDP runtime's heartbeat for `/livez`.
async fn heartbeat(health: Arc<Health>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        health.beat();
    }
}

/// §4.4 (rev 6.2): a renewed certificate restarts the bridge — exit 0, then
/// the orchestrator starts it again with the new pair — but never under a
/// live session: once the change is seen, the exit waits until no client is
/// connected (the companion deployment spec's decision 8: an LE renewal
/// must not cut the operator off). "Connected" is a live generation or a
/// connection between `on_accept` and its session's start — a fresh
/// client's TLS and CredSSP, a Preempt winner after the old session's end
/// (`Handshakes`, PC15 review m4; one never reported finished stops
/// counting after `HANDSHAKE_GRACE`). Polled at most every second
/// meanwhile; a client admitted in the gap before §5.2 stops accepting is
/// ended with cause `shutdown` like any other. `first` is the fingerprint
/// `spawn` took before loading the pair (P7), never one taken here.
async fn watch_certificate(
    cert: PathBuf,
    key: PathBuf,
    first: Option<tls::Fingerprint>,
    every: Duration,
    gens: Arc<Generations>,
    handshakes: Arc<Handshakes>,
    exit: watch::Sender<bool>,
) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tick.tick().await;
        if tls::fingerprint(&cert, &key) != first {
            break;
        }
    }
    tracing::info!("the TLS certificate changed; restarting once no client is connected");
    let mut idle = tokio::time::interval(every.min(Duration::from_secs(1)));
    loop {
        idle.tick().await;
        // Handshakes first: `on_connection_info` begins the generation
        // before it finishes the handshake, so read in this order a client
        // is always in one or the other (m4).
        if handshakes.in_flight(Instant::now()) == 0 && gens.current().is_none() {
            tracing::info!("no client connected; exiting to load the new certificate");
            exit.send_replace(true);
            return;
        }
    }
}

/// §5.2 in order (DC13), each step bounded; never a logout. Returns how
/// many `Quit`s stopping the server took (2 when a live connection consumed
/// the first). `disconnect` false skips step 3 — a test hook only, so that
/// a connected client is still being served when the first `Quit` goes out.
async fn shutdown_sequence(c: Arc<Control>, disconnect: bool) -> u32 {
    let t0 = Instant::now();
    // 1. Stop accepting: `on_accept` refuses from here on.
    c.accepting.store(false, Ordering::SeqCst);
    // 2. Release-all and wait for the websocket flush.
    c.hid.release_all(ReleaseTrigger::Shutdown);
    let (done, rx) = oneshot::channel();
    if c.to_kvm.send(KvmCommand::FlushHid { done }).is_ok() {
        let _ = tokio::time::timeout(FLUSH_WAIT, rx).await;
    }
    // 3. Disconnect the client with cause `shutdown` (2 s watchdog).
    if disconnect {
        let (done, rx) = oneshot::channel();
        if c.to_pump.send(RdpInput::Shutdown { done }).is_ok() {
            let _ = tokio::time::timeout(DISCONNECT_WAIT, rx).await;
        }
    }
    // 4. Close the FLV and websocket; the actor ends (no logout, §3.2).
    let (done, rx) = oneshot::channel();
    if c.to_kvm.send(KvmCommand::Shutdown { done }).is_ok() {
        let _ = tokio::time::timeout(KVM_CLOSE_WAIT, rx).await;
    }
    // 5. `Quit`, and a second one if a connection consumed the first (§5.2).
    // A live connection drops whatever shares a batch with the Quit it
    // consumes (ironrdp-server `recv_many` + `drain`): the second Quit must
    // come later — the `QUIT_WAIT` spacing is load-bearing (P35).
    let mut done = c.rdp_done.clone();
    let mut quits = 0u32;
    for _ in 0..2 {
        let _ = c.events.send(ServerEvent::Quit("shutdown".to_owned()));
        quits = quits.saturating_add(1);
        if tokio::time::timeout(QUIT_WAIT, done.wait_for(|v| *v))
            .await
            .is_ok()
        {
            break;
        }
    }
    tracing::info!(
        ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        quits,
        "shutdown complete"
    );
    quits
}

/// A signal handler, registered now; `None` (with a warning) if the OS
/// refuses, which then never fires.
fn register(kind: SignalKind, name: &'static str) -> Option<Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(signal = name, error = %e, "cannot handle the signal");
            None
        }
    }
}

/// Resolves on the next delivery of an already-registered signal.
async fn next(signal: Option<Signal>) {
    if let Some(mut s) = signal
        && s.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
}

/// Resolves when `rx` turns true; never, if its sender went away first.
async fn turned_true(mut rx: watch::Receiver<bool>) {
    if rx.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// P37: takes the handlers registered before "kvm-rdp ready" was logged.
async fn wait_for_exit(
    term: Option<Signal>,
    int: Option<Signal>,
    exit: watch::Receiver<bool>,
    mut done: watch::Receiver<bool>,
) -> Exit {
    tokio::select! {
        () = next(term) => Exit::Signal,
        () = next(int) => Exit::Signal,
        () = turned_true(exit) => Exit::CertificateChanged,
        // A dropped sender means the RDP thread ended: stopped too.
        _ = done.wait_for(|v| *v) => Exit::ServerStopped,
    }
}

impl BridgeHandle {
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// L2 drives the HID writer directly until Plan D's input handler (DC7).
    #[doc(hidden)]
    #[must_use]
    pub fn hid(&self) -> &Arc<HidControl> {
        &self.hid
    }

    /// Resolves once the bridge asks to exit (the certificate changed).
    pub async fn exit_requested(&mut self) {
        turned_true(self.exit.clone()).await;
    }

    /// §5.2's sequence; returns once the RDP server has stopped.
    pub async fn shutdown(mut self) {
        let _ = self.run_shutdown(true).await;
    }

    /// Test hook (L2, §5.2's second `Quit`): the sequence without step 3,
    /// so a connected client is still being served when the first `Quit`
    /// goes out; returns how many `Quit`s stopping the server took.
    #[doc(hidden)]
    pub async fn shutdown_skipping_disconnect(mut self) -> u32 {
        self.run_shutdown(false).await
    }

    async fn run_shutdown(&mut self, disconnect: bool) -> u32 {
        let Some(rt) = self.kvm_rt.take() else {
            return 0;
        };
        let sequence = rt.spawn(shutdown_sequence(self.ctl.clone(), disconnect));
        // Shut down in the background however this future ends.
        let _rt = Background(Some(rt));
        sequence.await.unwrap_or(0)
    }

    /// The binary's main loop: wait for SIGTERM, SIGINT, a certificate
    /// change or the RDP server stopping, then shut down (blocking).
    #[must_use]
    pub fn run_until_signal(mut self) -> Exit {
        let Some(rt) = self.kvm_rt.take() else {
            return Exit::ServerStopped;
        };
        let (ctl, exit, done) = (
            self.ctl.clone(),
            self.exit.clone(),
            self.ctl.rdp_done.clone(),
        );
        let (rdp, admin) = (self.rdp_addr, self.admin_addr);
        let why = rt.block_on(async move {
            // P37: both handlers exist before the ready line, so a SIGTERM
            // sent the moment it is seen runs §5.2 — never the default
            // disposition (death, no ErrorInfo 0x1, no exit 0).
            let term = register(SignalKind::terminate(), "SIGTERM");
            let int = register(SignalKind::interrupt(), "SIGINT");
            tracing::info!(rdp = %rdp, admin = %admin, "kvm-rdp ready");
            let why = wait_for_exit(term, int, exit, done).await;
            tracing::info!(reason = why.label(), "shutting down");
            let _ = shutdown_sequence(ctl, true).await;
            why
        });
        rt.shutdown_timeout(RUNTIME_TEARDOWN);
        why
    }

    /// Test hook (L2 `/livez`): block the RDP runtime's thread for `d`.
    #[doc(hidden)]
    pub fn block_rdp_runtime_for(&self, d: Duration) {
        let _ = self.ctl.to_pump.send(RdpInput::Stall(d));
    }
}

impl Drop for BridgeHandle {
    /// Best effort for a handle dropped without `shutdown` (a failing test).
    fn drop(&mut self) {
        if let Some(rt) = self.kvm_rt.take() {
            self.ctl.accepting.store(false, Ordering::SeqCst);
            let (done, _) = oneshot::channel();
            let _ = self.ctl.to_pump.send(RdpInput::Shutdown { done });
            let _ = self
                .ctl
                .events
                .send(ServerEvent::Quit("dropped".to_owned()));
            // A live connection drops whatever shares a batch with the Quit
            // it consumes (ironrdp-server `recv_many` + `drain`): the second
            // Quit must come later (P35).
            let events = self.ctl.events.clone();
            let _ = std::thread::Builder::new()
                .name("kvm-rdp-quit".to_owned())
                .spawn(move || {
                    std::thread::sleep(QUIT_WAIT);
                    let _ = events.send(ServerEvent::Quit("dropped".to_owned()));
                });
            rt.shutdown_background();
        }
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
    use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, RequestFlags, SecurityProtocol};
    use ironrdp_pdu::x224::X224;
    use kvm_sim::{KvmSim, SimConfig, Source};
    use std::path::Path;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// Every network wait in these tests is bounded by this.
    const T: Duration = Duration::from_secs(5);

    async fn sim() -> KvmSim {
        KvmSim::start(SimConfig::es3(
            Source::fixture("360p30_es3like_poc0.h264").unwrap(),
        ))
        .await
        .unwrap()
    }

    /// The real loader over the files a deployment has: loopback and
    /// ephemeral ports, a fresh TLS pair, the certificate polled every 200 ms.
    fn config_for(sim: &KvmSim, dir: &Path, edit: impl FnOnce(&mut Config)) -> Config {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
        std::fs::write(dir.join("nla.pass"), "bridge-unit-test-nla-password\n").unwrap();
        std::fs::write(dir.join("kvm.pass"), format!("{}\n", sim.password())).unwrap();
        let p = sim.ports();
        let toml = format!(
            "[rdp]\nlisten = \"127.0.0.1:0\"\nnla_password_file = \"nla.pass\"\ntls_cert_file = \"cert.pem\"\n\
             tls_key_file = \"key.pem\"\ncert_poll_interval = \"200ms\"\n[admin]\nlisten = \"127.0.0.1:0\"\n\
             [kvm]\nhost = \"{}\"\nspki_sha256 = \"{}\"\npassword_file = \"kvm.pass\"\n\
             web_port = {}\nvideo_port = {}\ncontrol_port = {}\n",
            sim.host(),
            sim.spki_sha256(),
            p.web,
            p.video,
            p.control
        );
        std::fs::write(dir.join("kvm-rdp.toml"), toml).unwrap();
        let mut c = Config::load(&dir.join("kvm-rdp.toml")).unwrap();
        edit(&mut c);
        c
    }

    /// `spawn` is blocking and bounded by `STARTUP_WAIT`.
    async fn start(cfg: Config) -> Result<BridgeHandle, BridgeError> {
        tokio::time::timeout(
            STARTUP_WAIT * 2,
            tokio::task::spawn_blocking(move || spawn(cfg)),
        )
        .await
        .expect("spawn outlived its STARTUP_WAIT")
        .unwrap()
    }

    /// §5.2's shutdown, bounded; how long it took.
    async fn stop(h: BridgeHandle) -> Duration {
        let t0 = Instant::now();
        tokio::time::timeout(T * 2, h.shutdown())
            .await
            .expect("shutdown is bounded by §5.2's 5 s");
        t0.elapsed()
    }

    /// The status code of one admin request; every step bounded (P36).
    async fn get(addr: SocketAddr, path: &str) -> u16 {
        let mut s = tokio::time::timeout(T, tokio::net::TcpStream::connect(addr))
            .await
            .expect("admin connect within 5 s")
            .unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(T, s.read_to_end(&mut buf))
            .await
            .expect("admin response within 5 s")
            .unwrap();
        String::from_utf8_lossy(&buf)
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Poll `f` every 20 ms for at most `limit`.
    async fn until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
        let t0 = Instant::now();
        while !f() {
            if t0.elapsed() > limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }

    /// §4.5, §5.1, §5.2: ready and live; a raw TCP connect costs no KVM
    /// traffic; shutdown without a session stops the server with the first
    /// `Quit` (no connection is there to consume it — Task 6.6 proves the
    /// second), inside §5.2's 5 s, and frees the listener; never a logout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_binds_reports_ready_and_shuts_down_promptly() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        let (rdp, admin) = (h.rdp_addr, h.admin_addr);
        assert_eq!(get(admin, "/readyz").await, 200);
        assert_eq!(get(admin, "/livez").await, 200);
        drop(
            tokio::time::timeout(T, tokio::net::TcpStream::connect(rdp))
                .await
                .unwrap()
                .unwrap(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let took = stop(h).await;
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(
            tokio::net::TcpStream::connect(rdp).await.is_err(),
            "the RDP listener is still open"
        );
        let s = sim.stats();
        assert_eq!(
            (s.accepts_web, s.accepts_video, s.accepts_control, s.logouts),
            (0, 0, 0, 0)
        );
    }

    /// §3.2, §5.2 step 4: a shutdown with the KVM side live — logged in,
    /// websocket and FLV open, as `on_connection_info` leaves it after NLA
    /// (Task 5.2) — closes the websocket and the FLV and never logs out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_closes_a_live_kvm_session_and_never_logs_out() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        h.ctl
            .to_kvm
            .send(KvmCommand::Start { generation: 1 })
            .unwrap();
        h.ctl
            .to_kvm
            .send(KvmCommand::OpenFlv { generation: 1 })
            .unwrap();
        assert!(
            until(T, || {
                let s = sim.stats();
                s.ws_open == 1 && s.flv_open == 1
            })
            .await,
            "the KVM side never came up: {:?}",
            sim.stats()
        );
        let took = stop(h).await;
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(
            until(T, || {
                let s = sim.stats();
                s.ws_open == 0 && s.flv_open == 0
            })
            .await,
            "the shutdown left the KVM side open: {:?}",
            sim.stats()
        );
        let s = sim.stats();
        assert_eq!((s.logins_ok, s.logouts), (1, 0), "{s:?}");
    }

    /// §4.4: with no client connected, a renewed certificate asks for an exit
    /// (to be restarted with it) within 5× the poll; no change, no exit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_changed_certificate_requests_an_exit() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let mut h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), h.exit_requested())
                .await
                .is_err()
        );
        let cert = d.path().join("cert.pem");
        let pem = std::fs::read(&cert).unwrap();
        std::fs::write(&cert, [pem.as_slice(), b"\n"].concat()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), h.exit_requested())
            .await
            .expect("no exit request within 5× the poll interval");
        stop(h).await;
    }

    /// A fresh pair in `dir`: (cert, key) paths.
    fn pair_in(dir: &Path) -> (PathBuf, PathBuf) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (cert, key)
    }

    /// A renewal: the certificate rewritten (one more byte).
    fn renew(cert: &Path) {
        let pem = std::fs::read(cert).unwrap();
        std::fs::write(cert, [pem.as_slice(), b"\n"].concat()).unwrap();
    }

    /// §4.4 (rev 6.2; the deployment spec's decision 8): a renewed
    /// certificate never ends a live session — the exit waits until no
    /// client is connected. Driven on the watcher itself, with the
    /// generation a connected client would hold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_change_waits_for_the_session_to_end() {
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = pair_in(d.path());
        let first = tls::fingerprint(&cert, &key);
        let gens = Arc::new(Generations::default());
        let generation = gens.begin(); // a client is connected
        let (tx, mut rx) = watch::channel(false);
        let poll = Duration::from_millis(100);
        tokio::spawn(watch_certificate(
            cert.clone(),
            key,
            first,
            poll,
            gens.clone(),
            idle_handshakes(),
            tx,
        ));
        renew(&cert);
        assert!(
            tokio::time::timeout(poll * 10, rx.wait_for(|v| *v))
                .await
                .is_err(),
            "the certificate change cut a live session"
        );
        assert_eq!(gens.end(), Some(generation)); // the client leaves
        let exited =
            tokio::time::timeout(poll * 5 + Duration::from_secs(1), rx.wait_for(|v| *v)).await;
        assert!(
            exited.is_ok_and(|r| r.is_ok()),
            "no exit once the session ended"
        );
    }

    fn idle_handshakes() -> Arc<Handshakes> {
        Arc::new(Handshakes::new(HANDSHAKE_GRACE))
    }

    /// DC21 (PC15 review m4): a client mid-handshake — TLS and CredSSP, or a
    /// Preempt winner between the old session's end and its own start — has
    /// no generation yet, but it is a client: the exit waits for it too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_change_waits_for_a_handshake_in_flight() {
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = pair_in(d.path());
        let first = tls::fingerprint(&cert, &key);
        let handshakes = idle_handshakes();
        handshakes.admit(Instant::now()); // a client is negotiating
        let (tx, mut rx) = watch::channel(false);
        let poll = Duration::from_millis(100);
        tokio::spawn(watch_certificate(
            cert.clone(),
            key,
            first,
            poll,
            Arc::new(Generations::default()),
            handshakes.clone(),
            tx,
        ));
        renew(&cert);
        assert!(
            tokio::time::timeout(poll * 10, rx.wait_for(|v| *v))
                .await
                .is_err(),
            "the certificate change cut a client mid-handshake"
        );
        handshakes.finish(); // it went (or its session began and ended)
        let exited =
            tokio::time::timeout(poll * 5 + Duration::from_secs(1), rx.wait_for(|v| *v)).await;
        assert!(
            exited.is_ok_and(|r| r.is_ok()),
            "no exit once the handshake ended"
        );
    }

    /// DC21 end to end on the real listener: a client that sent its X.224
    /// request and is mid-TLS (IronRDP waits for its ClientHello) holds a
    /// renewal's exit off; once it goes, the bridge asks to exit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewal_waits_for_a_client_mid_handshake() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let mut h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        let mut s = tokio::time::timeout(T, tokio::net::TcpStream::connect(h.rdp_addr))
            .await
            .unwrap()
            .unwrap();
        let request = ConnectionRequest {
            nego_data: None,
            flags: RequestFlags::empty(),
            protocol: SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX,
            correlation_info: None,
        };
        s.write_all(&ironrdp_core::encode_vec(&X224(request)).unwrap())
            .await
            .unwrap();
        let mut confirm = [0u8; 19];
        tokio::time::timeout(T, s.read_exact(&mut confirm))
            .await
            .expect("no Connection Confirm")
            .unwrap();
        renew(&d.path().join("cert.pem"));
        assert!(
            tokio::time::timeout(Duration::from_millis(1000), h.exit_requested())
                .await
                .is_err(),
            "the renewal cut a client mid-handshake (5x the 200 ms poll)"
        );
        drop(s); // the client goes: IronRDP's `on_disconnected`
        tokio::time::timeout(Duration::from_secs(2), h.exit_requested())
            .await
            .expect("no exit once the client went");
        stop(h).await;
    }

    /// P7: the baseline is the one `spawn` took before loading the pair, not
    /// one the watcher takes when it first runs — a renewal that lands in
    /// between (here: before the watcher task exists at all) is a change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewal_before_the_watcher_first_runs_is_seen() {
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = pair_in(d.path());
        let first = tls::fingerprint(&cert, &key);
        renew(&cert);
        let (tx, mut rx) = watch::channel(false);
        let poll = Duration::from_millis(100);
        tokio::spawn(watch_certificate(
            cert,
            key,
            first,
            poll,
            Arc::new(Generations::default()),
            idle_handshakes(),
            tx,
        ));
        let exited =
            tokio::time::timeout(poll * 5 + Duration::from_secs(1), rx.wait_for(|v| *v)).await;
        assert!(
            exited.is_ok_and(|r| r.is_ok()),
            "a renewal before the watcher's first poll was missed"
        );
    }

    /// P7 at `spawn` (PC15 review m1): the baseline is taken *before*
    /// `tls::load`, so a renewal racing the load counts as a change. The
    /// certificate is a FIFO: the load blocks on it until the "renewal"
    /// writes it, and the write moves the FIFO's mtime — so the state after
    /// the load differs from the baseline only if the baseline came first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewal_racing_the_load_is_seen() {
        use std::os::unix::ffi::OsStrExt as _;
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let cfg = config_for(&sim, d.path(), |_| {});
        let cert = d.path().join("cert.pem");
        let pem = std::fs::read(&cert).unwrap();
        std::fs::remove_file(&cert).unwrap();
        let path = std::ffi::CString::new(cert.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        std::thread::sleep(Duration::from_millis(20));
        let writer = std::thread::spawn(move || std::fs::write(&cert, pem).unwrap());
        let mut h = start(cfg).await.unwrap();
        writer.join().unwrap();
        tokio::time::timeout(Duration::from_secs(1), h.exit_requested())
            .await
            .expect("a renewal racing the load was missed");
        stop(h).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unbindable_rdp_listener_fails_spawn() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let r = start(config_for(&sim, d.path(), |c| c.rdp.listen = addr)).await;
        let Err(e) = r else {
            panic!("spawn bound a taken address")
        };
        assert!(matches!(e, BridgeError::RdpBind(_)), "{e:?}");
        // §9.2: no secret reaches an error.
        let shown = format!("{e:?} {e}");
        for secret in ["bridge-unit-test-nla-password", sim.password()] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    /// §4.4: a bad TLS identity fails before anything binds — with both
    /// listen addresses taken, the error is still the TLS one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bad_tls_identity_fails_before_anything_binds() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let rdp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = config_for(&sim, d.path(), |c| {
            c.rdp.listen = rdp.local_addr().unwrap();
            c.admin.listen = admin.local_addr().unwrap();
        });
        std::fs::write(d.path().join("key.pem"), "not a key\n").unwrap();
        let r = start(cfg).await;
        assert!(
            matches!(r, Err(BridgeError::Tls(TlsError::NoKey))),
            "{:?}",
            r.err()
        );
    }

    /// What the listener answers an X.224 Connection Request offering
    /// `offered`: the Connection Confirm, or `None` if it closed instead.
    async fn negotiate(addr: SocketAddr, offered: SecurityProtocol) -> Option<ConnectionConfirm> {
        let mut s = tokio::time::timeout(T, tokio::net::TcpStream::connect(addr))
            .await
            .expect("RDP connect within 5 s")
            .unwrap();
        let request = ConnectionRequest {
            nego_data: None,
            flags: RequestFlags::empty(),
            protocol: offered,
            correlation_info: None,
        };
        s.write_all(&ironrdp_core::encode_vec(&X224(request)).unwrap())
            .await
            .unwrap();
        let mut head = [0u8; 4];
        let read = tokio::time::timeout(T, s.read_exact(&mut head))
            .await
            .expect("an answer or a close within 5 s");
        if read.is_err() {
            return None; // closed (EOF or reset) without a confirm
        }
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        assert!((4..=512).contains(&len), "TPKT length {len}");
        let mut pdu = head.to_vec();
        pdu.resize(len, 0);
        tokio::time::timeout(T, s.read_exact(&mut pdu[4..]))
            .await
            .expect("the confirm's body within 5 s")
            .unwrap();
        Some(
            ironrdp_core::decode::<X224<ConnectionConfirm>>(&pdu)
                .unwrap()
                .0,
        )
    }

    /// §9.1 ("The release binary only ever calls `with_hybrid`"), PC13's
    /// "NLA required" from the outside: the listener `spawn` builds selects
    /// CredSSP for a client that offers it, and answers a client offering
    /// only TLS or only standard RDP security with no Connection Confirm
    /// Response at all — there is no TLS-only or plain-RDP path in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_rdp_listener_offers_nla_only() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        let all = SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX;
        let chosen = negotiate(h.rdp_addr, all).await;
        assert!(
            matches!(
                chosen,
                Some(ConnectionConfirm::Response { protocol, .. })
                    if protocol == SecurityProtocol::HYBRID_EX
            ),
            "{chosen:?}"
        );
        for offered in [SecurityProtocol::empty(), SecurityProtocol::SSL] {
            let answer = negotiate(h.rdp_addr, offered).await;
            assert!(
                !matches!(answer, Some(ConnectionConfirm::Response { .. })),
                "a client offering only {offered:?} was answered {answer:?}"
            );
        }
        stop(h).await;
        assert_eq!(sim.stats().accepts_web, 0, "a KVM login before NLA");
    }

    /// §9.1, §5.2 (DC13): the assembled listener consults the connection
    /// handler — without one IronRDP admits every connection, and neither
    /// `security.accept_rate` nor stop-accepting would hold. At a rate of
    /// one, the second connection is closed before negotiation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_listener_consults_the_connection_handler() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |c| c.security.accept_rate = 1))
            .await
            .unwrap();
        let hybrid = SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX;
        let first = negotiate(h.rdp_addr, hybrid).await;
        assert!(
            matches!(first, Some(ConnectionConfirm::Response { .. })),
            "{first:?}"
        );
        let second = negotiate(h.rdp_addr, hybrid).await;
        assert!(second.is_none(), "over the accept rate: {second:?}");
        assert_eq!(h.metrics().accept_refused.get(), 1);
        stop(h).await;
    }

    /// A `MakeWriter` that keeps every log line.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    impl Captured {
        fn lines(&self) -> Vec<serde_json::Value> {
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    /// PC13 m10 (PC15 review m7): startup names the TLS key's type and size
    /// at INFO, through the bridge's own subscriber; an ECDSA key is neither
    /// refused nor warned about (§9.1 leaves RSA vs ECDSA to the acceptance
    /// check). Run in a child with the subscriber process-wide, so every
    /// thread's lines are seen — the RDP and KVM runtimes', not only the
    /// caller's — from startup through §5.2's shutdown.
    #[test]
    fn startup_logs_the_tls_key_type_at_info() {
        if is_child() {
            startup_log_in_a_child();
            return;
        }
        passes_in_a_child("startup_logs_the_tls_key_type_at_info");
    }

    fn startup_log_in_a_child() {
        let out = Captured::default();
        let sub = crate::logging::subscriber("info", out.clone()).unwrap();
        tracing::subscriber::set_global_default(sub).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let sim = rt.block_on(sim());
        let d = tempfile::tempdir().unwrap();
        let h = spawn(config_for(&sim, d.path(), |_| {})).unwrap();
        rt.block_on(stop(h));
        let lines = out.lines();
        let loaded = lines
            .iter()
            .find(|v| v["fields"]["message"] == "TLS identity loaded")
            .unwrap_or_else(|| panic!("no key-type line in {lines:?}"));
        assert_eq!(loaded["level"], "INFO");
        assert_eq!(loaded["fields"]["key_type"], "ECDSA");
        assert_eq!(loaded["fields"]["key_bits"], 256);
        // The other threads were heard: the RDP thread's and the KVM
        // runtime's lines from the shutdown.
        for (message, thread) in [
            ("RDP server stopped", "the RDP thread"),
            ("shutdown complete", "the KVM runtime"),
        ] {
            assert!(
                lines.iter().any(|v| v["fields"]["message"] == message),
                "nothing from {thread} in {lines:?}"
            );
        }
        assert!(
            lines.iter().all(|v| v["level"] == "INFO"),
            "a line above INFO from some thread: {lines:?}"
        );
        drop(sim);
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    /// The channels `shutdown_sequence` talks to, with no bridge behind them.
    struct Fakes {
        kvm: mpsc::UnboundedReceiver<KvmCommand>,
        pump: mpsc::UnboundedReceiver<RdpInput>,
        events: mpsc::UnboundedReceiver<ServerEvent>,
        done: watch::Sender<bool>,
        metrics: Arc<Metrics>,
    }

    fn control() -> (Arc<Control>, Fakes) {
        let metrics = Arc::new(Metrics::default());
        let (to_kvm, kvm) = mpsc::unbounded_channel();
        let (to_pump, pump) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::unbounded_channel();
        let (done, rdp_done) = watch::channel(false);
        let ctl = Arc::new(Control {
            accepting: Arc::new(AtomicBool::new(true)),
            hid: Arc::new(HidControl::new(16, metrics.clone())),
            to_kvm,
            to_pump,
            events,
            rdp_done,
        });
        let fakes = Fakes {
            kvm,
            pump,
            events: events_rx,
            done,
            metrics,
        };
        (ctl, fakes)
    }

    type Log = Arc<Mutex<Vec<String>>>;

    /// §5.2's exit bound on the (paused) clock: a step that never times out
    /// fails here rather than hanging the test.
    async fn within_5s<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .expect("§5.2's sequence did not end within 5 s")
    }

    fn push(log: &Log, entry: String) {
        log.lock().unwrap().push(entry);
    }

    /// The KVM actor's and the pump's parts, answering at once; what each
    /// saw goes to `log` before it answers.
    fn answering(c: &Arc<Control>, f: Fakes, log: &Log) -> mpsc::UnboundedReceiver<ServerEvent> {
        let Fakes {
            mut kvm,
            mut pump,
            events,
            done,
            metrics,
        } = f;
        let (l, accepting) = (log.clone(), c.accepting.clone());
        tokio::spawn(async move {
            while let Some(cmd) = kvm.recv().await {
                match cmd {
                    KvmCommand::FlushHid { done } => {
                        push(
                            &l,
                            format!(
                                "flush_hid(accepting={}, released={})",
                                accepting.load(Ordering::SeqCst),
                                metrics.release_all.get("shutdown")
                            ),
                        );
                        let _ = done.send(());
                    }
                    KvmCommand::Shutdown { done } => {
                        push(&l, "kvm_shutdown".to_owned());
                        let _ = done.send(());
                    }
                    other => push(&l, format!("unexpected {other:?}")),
                }
            }
        });
        let l = log.clone();
        tokio::spawn(async move {
            while let Some(input) = pump.recv().await {
                match input {
                    RdpInput::Shutdown { done } => {
                        push(&l, "disconnect".to_owned());
                        let _ = done.send(());
                    }
                    other => push(&l, format!("unexpected {other:?}")),
                }
            }
        });
        // The server's part is the caller's; `done` lives as long as the
        // test's runtime.
        tokio::spawn(async move {
            let _done = done;
            std::future::pending::<()>().await;
        });
        events
    }

    /// §5.2 in order (DC13): stop accepting and release-all before the
    /// websocket flush; the disconnect (ErrorInfo 0x1, the shell's part)
    /// before the KVM side closes; `KvmCommand::Shutdown` — never a logout,
    /// and nothing else sent to the KVM — before the `Quit`; one `Quit`
    /// when no connection takes it.
    #[tokio::test(start_paused = true)]
    async fn shutdown_runs_section_5_2_in_order() {
        let (c, f) = control();
        let log = Log::default();
        let done = f.done.clone();
        let mut events = answering(&c, f, &log);
        let l = log.clone();
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                push(&l, format!("{ev:?}"));
                if matches!(ev, ServerEvent::Quit(_)) {
                    done.send_replace(true);
                }
            }
        });
        let quits = within_5s(shutdown_sequence(c, true)).await;
        assert_eq!(
            *log.lock().unwrap(),
            [
                "flush_hid(accepting=false, released=1)",
                "disconnect",
                "kvm_shutdown",
                "Quit(\"shutdown\")"
            ]
        );
        assert_eq!(quits, 1);
    }

    type QuitTimes = Arc<Mutex<Vec<tokio::time::Instant>>>;

    /// The first two `Quit`s' send times, once the fake server has read
    /// both (bounded; the clock is paused).
    async fn two_quits(at: &QuitTimes) -> [tokio::time::Instant; 2] {
        for _ in 0..100 {
            if let [a, b, ..] = at.lock().unwrap().as_slice() {
                return [*a, *b];
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("fewer than two Quits were sent");
    }

    /// §5.2: a `Quit` a live connection consumes ends only it; the second,
    /// `QUIT_WAIT` later — never in the same batch (P35) — stops the server.
    #[tokio::test(start_paused = true)]
    async fn a_quit_a_live_connection_takes_is_followed_by_a_second() {
        let (c, f) = control();
        let log = Log::default();
        let done = f.done.clone();
        let mut events = answering(&c, f, &log);
        let quits_at = QuitTimes::default();
        let q = quits_at.clone();
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                if matches!(ev, ServerEvent::Quit(_)) {
                    let n = {
                        let mut q = q.lock().unwrap();
                        q.push(tokio::time::Instant::now());
                        q.len()
                    };
                    // The first is taken by the live connection.
                    if n == 2 {
                        done.send_replace(true);
                    }
                }
            }
        });
        let quits = within_5s(shutdown_sequence(c, true)).await;
        assert_eq!(quits, 2);
        let at = two_quits(&quits_at).await;
        assert!(at[1] - at[0] >= QUIT_WAIT, "{:?}", at[1] - at[0]);
    }

    /// §5.2's bound with every part unresponsive — the KVM actor stuck, the
    /// pump never answering, the server never stopping: each step times out
    /// and the sequence still ends inside the 5 s exit, two spaced `Quit`s
    /// sent. The constants keep the KVM actor's slowest Stop/Shutdown
    /// (`STOP_BOUND`, ~600 ms) and the shell's watchdog inside their steps.
    #[tokio::test(start_paused = true)]
    async fn an_unresponsive_shutdown_still_ends_inside_five_seconds() {
        let (c, f) = control();
        let Fakes {
            mut kvm,
            mut pump,
            mut events,
            done,
            ..
        } = f;
        let held = Arc::new(Mutex::new(Vec::new()));
        let h = held.clone();
        tokio::spawn(async move {
            while let Some(cmd) = kvm.recv().await {
                h.lock().unwrap().push(format!("{cmd:?}"));
                std::mem::forget(cmd); // never answered, never dropped
            }
        });
        tokio::spawn(async move {
            while let Some(input) = pump.recv().await {
                std::mem::forget(input);
            }
        });
        let quits_at = QuitTimes::default();
        let q = quits_at.clone();
        tokio::spawn(async move {
            let _done = done; // never set
            while let Some(ev) = events.recv().await {
                if matches!(ev, ServerEvent::Quit(_)) {
                    q.lock().unwrap().push(tokio::time::Instant::now());
                }
            }
        });
        let t0 = tokio::time::Instant::now();
        let quits = within_5s(shutdown_sequence(c, true)).await;
        let took = t0.elapsed();
        assert_eq!(quits, 2);
        let steps = FLUSH_WAIT + DISCONNECT_WAIT + KVM_CLOSE_WAIT + QUIT_WAIT * 2;
        assert!(took >= steps, "{took:?}");
        assert!(
            took + RUNTIME_TEARDOWN < Duration::from_secs(5),
            "{took:?} + teardown is past §5.2's 5 s"
        );
        let at = two_quits(&quits_at).await;
        assert!(at[1] - at[0] >= QUIT_WAIT, "{:?}", at[1] - at[0]);
        assert_eq!(held.lock().unwrap().len(), 2, "FlushHid and Shutdown only");
        assert!(KVM_CLOSE_WAIT > crate::kvm::session::STOP_BOUND);
        assert!(DISCONNECT_WAIT > crate::pump::shell::SHUTDOWN_WATCHDOG + crate::pump::shell::TICK);
    }

    /// m5: of the essential tasks, only a panic is a death. The KVM actor
    /// returns normally at §5.2 step 4, the certificate watcher after asking
    /// for an exit, and a runtime shutting down cancels them — none of those
    /// may stop the server early.
    #[tokio::test(flavor = "current_thread")]
    async fn only_a_panicked_essential_task_is_a_death() {
        let ends = tokio::spawn(async {});
        let cancelled = tokio::spawn(std::future::pending::<()>());
        cancelled.abort();
        let quiet: Essential = vec![("ends", ends), ("cancelled", cancelled)];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), first_panic(quiet))
                .await
                .is_err(),
            "a normal end or a cancellation was read as a death"
        );
        let lives = tokio::spawn(std::future::pending::<()>());
        let dies = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            panic!("injected");
        });
        let tasks: Essential = vec![("lives", lives), ("dies", dies)];
        assert_eq!(
            tokio::time::timeout(T, first_panic(tasks)).await.unwrap(),
            "dies"
        );
    }

    /// PC15 review m5: a task the bridge cannot work without panicking —
    /// here the pump shell — stops the bridge in every build, not only under
    /// release's `panic = "abort"`: the RDP server stops and its listener
    /// closes rather than serving NLA with no pump behind it, and the
    /// binary's loop ends `ServerStopped`, exit 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicked_pump_shell_stops_the_bridge() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        h.ctl.to_pump.send(RdpInput::InjectedPanic).unwrap();
        let mut done = h.ctl.rdp_done.clone();
        tokio::time::timeout(T, done.wait_for(|v| *v))
            .await
            .expect("the bridge kept serving without its pump")
            .unwrap();
        assert!(
            tokio::net::TcpStream::connect(h.rdp_addr).await.is_err(),
            "the RDP listener is still open"
        );
        let why = tokio::time::timeout(
            T,
            wait_for_exit(None, None, h.exit.clone(), h.ctl.rdp_done.clone()),
        )
        .await
        .unwrap();
        assert_eq!((why, why.code()), (Exit::ServerStopped, 1));
        stop(h).await;
    }

    /// I2 (PC15 review): the binary's exits besides a signal. A certificate
    /// change resolves `wait_for_exit` to `CertificateChanged`, exit 0 — the
    /// orchestrator restarts the bridge on the new pair; the RDP server
    /// stopping, or its thread gone, to `ServerStopped`, exit 1. A watcher
    /// that went away without asking is no exit at all.
    #[tokio::test(start_paused = true)]
    async fn wait_for_exit_maps_a_renewal_and_a_stopped_server_to_their_exit_codes() {
        let wait = |exit, done| tokio::spawn(wait_for_exit(None, None, exit, done));
        let (exit_tx, exit) = watch::channel(false);
        let (_done_tx, done) = watch::channel(false);
        let w = wait(exit, done);
        exit_tx.send_replace(true);
        let why = within_5s(w).await.unwrap();
        assert_eq!((why, why.code()), (Exit::CertificateChanged, 0));

        let (_exit_tx, exit) = watch::channel(false);
        let (done_tx, done) = watch::channel(false);
        let w = wait(exit, done);
        done_tx.send_replace(true);
        let why = within_5s(w).await.unwrap();
        assert_eq!((why, why.code()), (Exit::ServerStopped, 1));

        let (_exit_tx, exit) = watch::channel(false);
        let (done_tx, done) = watch::channel(false);
        drop(done_tx); // the RDP thread ended
        assert_eq!(
            within_5s(wait(exit, done)).await.unwrap(),
            Exit::ServerStopped
        );

        let (exit_tx, exit) = watch::channel(false);
        let (_done_tx, done) = watch::channel(false);
        drop(exit_tx); // the watcher ended without asking
        assert!(
            tokio::time::timeout(Duration::from_secs(60), wait(exit, done))
                .await
                .is_err(),
            "a vanished watcher read as a certificate change"
        );
        assert_eq!(Exit::Signal.code(), 0);
    }

    /// A handle over `control()`'s channels, with no bridge behind it.
    fn handle_over(ctl: Arc<Control>, metrics: Arc<Metrics>) -> BridgeHandle {
        let (_, exit) = watch::channel(false);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        BridgeHandle {
            rdp_addr: "127.0.0.1:1".parse().unwrap(),
            admin_addr: "127.0.0.1:1".parse().unwrap(),
            metrics,
            hid: ctl.hid.clone(),
            ctl,
            exit,
            kvm_rt: Some(rt),
            _rdp_thread: std::thread::spawn(|| {}),
        }
    }

    /// P35: a handle dropped without `shutdown` (a failing test) stops
    /// accepting, asks the pump to disconnect, and sends one `Quit` at once
    /// and the second only `QUIT_WAIT` later — two in one batch would both
    /// be swallowed by a live connection (ironrdp-server `recv_many` +
    /// `drain`), leaking the server.
    #[test]
    fn a_dropped_handle_spaces_its_two_quits() {
        let (c, mut f) = control();
        let accepting = c.accepting.clone();
        let h = handle_over(c, f.metrics.clone());
        let t0 = Instant::now();
        drop(h);
        assert!(!accepting.load(Ordering::SeqCst));
        assert!(matches!(f.pump.try_recv(), Ok(RdpInput::Shutdown { .. })));
        assert!(
            matches!(f.events.try_recv(), Ok(ServerEvent::Quit(_))),
            "no Quit on drop"
        );
        let second = loop {
            match f.events.try_recv() {
                Ok(ServerEvent::Quit(_)) => break t0.elapsed(),
                Ok(other) => panic!("{other:?}"),
                Err(_) => {
                    assert!(t0.elapsed() < QUIT_WAIT * 5, "no second Quit");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        assert!(
            second >= QUIT_WAIT / 2,
            "the second Quit went out {second:?} after the first (P35)"
        );
    }

    /// Set in a copy of this test binary re-executed by `passes_in_a_child`:
    /// the test it runs takes its child branch.
    const CHILD: &str = "KVM_RDP_TEST_CHILD";

    fn is_child() -> bool {
        std::env::var_os(CHILD).is_some()
    }

    /// Run `bridge::tests::<name>` alone in a child process — this test
    /// binary re-executed with `CHILD` set — for what needs a process of its
    /// own (a signal, a process-wide subscriber), and require that it passed.
    /// The child is killed if it outlives 30 s.
    fn passes_in_a_child(name: &str) {
        let test = format!("bridge::tests::{name}");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        let Ok(out) = rx.recv_timeout(Duration::from_secs(30)) else {
            // SAFETY: kill(2) on our own child, not yet reaped (the waiting
            // thread is still blocked in waitpid).
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("{test}: the child did not finish within 30 s");
        };
        let out = out.unwrap();
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(out.status.success(), "{:?}\n{stdout}\n{stderr}", out.status);
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "{test}: the child ran no test:\n{stdout}"
        );
    }

    /// P37: a SIGTERM sent the moment "kvm-rdp ready" is logged is already
    /// the bridge's — §5.2's shutdown and `Exit::Signal` — never the default
    /// disposition. Run in a child process, which raises SIGTERM on the
    /// logging thread from inside the log call: with the handlers registered
    /// after the line, the child dies by the signal instead of passing.
    #[test]
    fn a_sigterm_right_after_the_ready_line_is_a_clean_exit() {
        if is_child() {
            sigterm_at_the_ready_line();
            return;
        }
        passes_in_a_child("a_sigterm_right_after_the_ready_line_is_a_clean_exit");
    }

    /// A layer that runs `f` inside the "kvm-rdp ready" event, on the thread
    /// that logs it (`run_until_signal`'s, after its handlers, P37).
    struct AtReady<F>(F);

    struct IsReady(bool);

    impl tracing::field::Visit for IsReady {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            if f.name() == "message" && format!("{v:?}") == "kvm-rdp ready" {
                self.0 = true;
            }
        }
    }

    impl<S, F> tracing_subscriber::Layer<S> for AtReady<F>
    where
        S: tracing::Subscriber,
        F: Fn() + 'static,
    {
        fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            let mut ready = IsReady(false);
            e.record(&mut ready);
            if ready.0 {
                (self.0)();
            }
        }
    }

    /// The bridge on kvm-sim in this (child) process, then
    /// `run_until_signal` with `at_ready` run inside the ready line; what it
    /// returned, within §5.2's 5 s of the line plus `limit`.
    fn run_binary_loop(at_ready: impl Fn(&Path) + Send + Sync + 'static, limit: Duration) -> Exit {
        use tracing_subscriber::layer::SubscriberExt as _;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let sim = rt.block_on(sim());
        let d = tempfile::tempdir().unwrap();
        let h = spawn(config_for(&sim, d.path(), |_| {})).unwrap();
        let dir = d.path().to_owned();
        let sub = tracing_subscriber::registry().with(AtReady(move || at_ready(&dir)));
        let t0 = Instant::now();
        let why = tracing::subscriber::with_default(sub, || h.run_until_signal());
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(5) + limit, "{took:?}");
        drop(sim);
        rt.shutdown_timeout(Duration::from_secs(1));
        why
    }

    /// P37's child: SIGTERM raised inside the "kvm-rdp ready" event.
    fn sigterm_at_the_ready_line() {
        let why = run_binary_loop(
            |_| {
                // SAFETY: raise(3) with a valid signal number; it returns
                // once the signal was handled on this thread.
                assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            },
            Duration::ZERO,
        );
        assert_eq!(why, Exit::Signal);
    }

    /// I2 (PC15 review), end to end: the binary's loop — `run_until_signal`
    /// with its signal handlers live — ends `CertificateChanged`, exit 0,
    /// when the certificate is renewed with no client connected, within 5×
    /// the 200 ms poll. Child-only: it registers SIGTERM and SIGINT.
    #[test]
    fn a_renewal_ends_the_binary_loop_for_a_restart() {
        if is_child() {
            let why = run_binary_loop(|dir| renew(&dir.join("cert.pem")), Duration::from_secs(1));
            assert_eq!((why, why.code()), (Exit::CertificateChanged, 0));
            return;
        }
        passes_in_a_child("a_renewal_ends_the_binary_loop_for_a_restart");
    }
}
