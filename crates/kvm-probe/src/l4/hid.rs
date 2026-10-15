//! The HID checks' websocket (Plan D L4). It opens the way the bridge does
//! — the token cookie, the §3.3 session start, the bridge's 16 KiB
//! `SO_SNDBUF` cap and 1 s write bound — and can end three ways (a close
//! frame, a FIN, a reset). A key is never left held: `guarded` runs every
//! HID subcommand's body and then `ensure_released`, whatever the body did
//! — returned, failed, panicked or was interrupted (Ctrl-C, SIGTERM,
//! SIGHUP). What is typed is only ever `page::pattern`, bounded in length
//! and pace (`MAX_CHARS`, `MAX_PACE`): no burst is unbounded.
use super::{escaped, ws};
use crate::captures::CaptureDir;
use crate::kvm::{self, BoxedIo, KvmError};
use crate::request::{KvmTarget, Scheme};
use futures_util::{FutureExt as _, SinkExt as _, StreamExt as _};
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{MOD_LSHIFT, Stroke, USAGE_ESC, us_stroke};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio_tungstenite::tungstenite::Message;

/// The bridge's websocket send buffer (Plan C's final fix wave), so the
/// probe sees the back-pressure the bridge would.
pub const SNDBUF: usize = 16 * 1024;
/// `input.hid_write_timeout`'s default.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// How long `ensure_released` keeps trying before it says a key may be held.
pub const RELEASE_WINDOW: Duration = Duration::from_secs(30);
/// The most characters one `type_text` types: at pace 0 that is a burst
/// of 2 × 500 + 2 reports, under DD8's ~1 800-report estimate of the
/// KVM's receive window, so no burst is unbounded. Task 1.6 types 200.
pub const MAX_CHARS: usize = 500;
/// The longest pace `type_text` waits after each report. A press is held
/// for one pace, so this bounds how long the Mac sees any key down while
/// typing — well under macOS's shortest delay until repeat (~225 ms), so
/// the page never auto-repeats. Task 1.6 uses 0–15 ms.
pub const MAX_PACE: Duration = Duration::from_millis(100);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `hid-type`'s websocket upgrade bound.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A release websocket's upgrade bound.
const RELEASE_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `End::CloseFrame` waits for the KVM's close frame.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

pub const KBD_ZERO: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0; 5],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// A close frame, then up to 2 s for the KVM's.
    CloseFrame,
    /// Drop the connection: a FIN (an RST if the KVM's data is unread).
    Fin,
    /// `SO_LINGER` 0, then drop: an RST — what the bridge does to a
    /// websocket whose writes did not complete (§3.2).
    Reset,
}

pub struct HidWs {
    ws: ws::Ws,
    /// A second descriptor of the same socket: its options (linger) are
    /// the connection's.
    sock: socket2::Socket,
    last_pos: Option<(u16, u16)>,
}

/// The bridge's order (Plan C's fix wave, endpoint.rs): the send buffer is
/// capped BEFORE connect, so the kernel never autotunes it (§7.3 rev 6.2).
async fn connect(t: &KvmTarget, pin: Option<&str>) -> Result<(BoxedIo, socket2::Socket), KvmError> {
    if matches!(t.scheme, Scheme::Https) && pin.is_none() {
        return Err(KvmError::Tls("pin required for https".into()));
    }
    let made = async {
        let c = |e: std::io::Error| KvmError::Connect(e.to_string());
        let addr = tokio::net::lookup_host((t.host.as_str(), t.control_port))
            .await
            .map_err(c)?
            .next()
            .ok_or_else(|| KvmError::Connect("the host resolved to no address".to_owned()))?;
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(c)?;
        sock.set_send_buffer_size(SNDBUF).map_err(c)?;
        sock.set_nonblocking(true).map_err(c)?;
        let tcp: TcpStream = TcpSocket::from_std_stream(sock.into())
            .connect(addr)
            .await
            .map_err(c)?;
        tcp.set_nodelay(true).map_err(c)?;
        let keep = socket2::SockRef::from(&tcp).try_clone().map_err(c)?;
        Ok::<_, KvmError>((kvm::over(t, tcp, pin).await?, keep))
    };
    tokio::time::timeout(CONNECT_TIMEOUT, made)
        .await
        .map_err(|_| KvmError::Connect(format!("connect timed out after {CONNECT_TIMEOUT:?}")))?
}

impl HidWs {
    /// Upgrade with `token` and send the §3.3 session start: absolute mode
    /// and an all-zero keyboard report (no pointer report: none was sent).
    pub async fn open(
        t: &KvmTarget,
        pin: Option<&str>,
        token: &str,
        timeout: Duration,
    ) -> Result<HidWs, KvmError> {
        let (io, sock) = connect(t, pin).await?;
        let ws = match ws::upgrade_on(io, t, Some(token), timeout).await? {
            ws::Upgrade::Accepted(w) => *w,
            ws::Upgrade::Refused(f) => {
                return Err(KvmError::Http(format!("websocket refused: {f}")));
            }
        };
        let mut h = HidWs {
            ws,
            sock,
            last_pos: None,
        };
        h.send(HidFrame::SetMode { hid_type: 0 }).await?;
        h.send(KBD_ZERO).await?;
        Ok(h)
    }

    /// One frame, bounded by `WRITE_TIMEOUT`; how long the write took.
    pub async fn send(&mut self, f: HidFrame) -> Result<Duration, KvmError> {
        let t0 = Instant::now();
        match tokio::time::timeout(WRITE_TIMEOUT, self.ws.send(Message::Binary(f.to_vec()))).await {
            Ok(Ok(())) => {
                if let HidFrame::AbsMouse { x, y, .. } = f {
                    self.last_pos = Some((x, y));
                }
                Ok(t0.elapsed())
            }
            Ok(Err(e)) => Err(KvmError::Http(escaped(e.to_string().as_bytes(), 120))),
            Err(_) => Err(KvmError::Http(format!(
                "a HID write took longer than {WRITE_TIMEOUT:?}"
            ))),
        }
    }

    #[must_use]
    pub fn last_pos(&self) -> Option<(u16, u16)> {
        self.last_pos
    }

    /// End the websocket `how`. Every step is bounded: the close frame's
    /// write by `WRITE_TIMEOUT` (a KVM that stopped reading cannot stall
    /// it), the wait for the KVM's close by 2 s.
    pub async fn end(mut self, how: End) {
        match how {
            End::CloseFrame => {
                let _ = tokio::time::timeout(WRITE_TIMEOUT, self.ws.close(None)).await;
                let _ = tokio::time::timeout(CLOSE_WAIT, async {
                    while let Some(Ok(m)) = self.ws.next().await {
                        if matches!(m, Message::Close(_)) {
                            break;
                        }
                    }
                })
                .await;
            }
            End::Fin => {}
            End::Reset => {
                let _ = self.sock.set_linger(Some(Duration::ZERO));
            }
        }
        drop(self.ws);
        drop(self.sock);
    }
}

/// §8's press report: the usage in slot 1, Shift in the modifier byte.
#[must_use]
pub fn press(s: Stroke) -> HidFrame {
    HidFrame::Keyboard {
        modifiers: if s.shift { MOD_LSHIFT } else { 0 },
        keys: [s.usage, 0, 0, 0, 0],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeReport {
    pub chars: usize,
    pub reports: u64,
    pub elapsed: Duration,
    /// At pace 0: the reports written before the first write that took
    /// 2 ms or more — what the kernel buffered before anything waited.
    /// A diagnostic only: 400 reports fit the send buffer and the KVM's
    /// receive window, so this is not the KVM's rate (the page's `rate`
    /// line is, D28).
    pub burst_capacity: u64,
    pub max_write: Duration,
    /// What the test page should show: `text <expected_len> <hash>`.
    pub expected_len: usize,
    pub expected_hash: u32,
}

impl std::fmt::Display for TypeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ms = super::ms(self.elapsed).max(1);
        write!(
            f,
            "chars={} reports={} elapsed_ms={} write_rate={} kernel_buffered={} max_write_ms={} expect page: text {} {:x}",
            self.chars,
            self.reports,
            super::ms(self.elapsed),
            self.reports
                .saturating_mul(1000)
                .checked_div(ms)
                .unwrap_or(0),
            self.burst_capacity,
            super::ms(self.max_write),
            self.expected_len,
            self.expected_hash
        )
    }
}

/// Type `text` (US layout; characters without a stroke are left out) as
/// press/release pairs, `pace` after every report (§8). First an Esc press
/// and release, which the test page reads as "start over" (D7a), and 200 ms
/// for it to redraw; those two reports are not counted or timed. More than
/// `MAX_CHARS` characters, or a pace past `MAX_PACE`, is refused before
/// anything is sent.
pub async fn type_text(w: &mut HidWs, text: &str, pace: Duration) -> Result<TypeReport, KvmError> {
    let typed: String = text.chars().filter(|c| us_stroke(*c).is_some()).collect();
    let strokes: Vec<Stroke> = typed.chars().filter_map(us_stroke).collect();
    if strokes.len() > MAX_CHARS {
        return Err(KvmError::Io(format!(
            "a HID run types at most {MAX_CHARS} characters (no burst is unbounded); this one has {}",
            strokes.len()
        )));
    }
    if pace > MAX_PACE {
        return Err(KvmError::Io(format!(
            "a HID run's pace is at most {MAX_PACE:?} (a key is held for one pace); got {pace:?}"
        )));
    }
    w.send(press(Stroke {
        usage: USAGE_ESC,
        shift: false,
    }))
    .await?;
    w.send(KBD_ZERO).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    let (mut reports, mut burst_capacity, mut max_write, mut bursting) =
        (0u64, 0u64, Duration::ZERO, true);
    for s in &strokes {
        for f in [press(*s), KBD_ZERO] {
            let took = w.send(f).await?;
            reports = reports.saturating_add(1);
            if bursting && took < Duration::from_millis(2) {
                burst_capacity = burst_capacity.saturating_add(1);
            } else {
                bursting = false;
            }
            max_write = max_write.max(took);
            if !pace.is_zero() {
                tokio::time::sleep(pace).await;
            }
        }
    }
    Ok(TypeReport {
        chars: strokes.len(),
        reports,
        elapsed: t0.elapsed(),
        burst_capacity,
        max_write,
        expected_len: typed.chars().count(),
        expected_hash: super::page::fnv1a32(&typed),
    })
}

async fn release_once(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
) -> Result<(), KvmError> {
    let mut w = HidWs::open(t, pin, token, RELEASE_OPEN_TIMEOUT).await?;
    if let Some((x, y)) = pointer {
        w.send(HidFrame::abs_mouse(0, x, y)).await?;
    }
    w.end(End::CloseFrame).await;
    Ok(())
}

/// A fresh websocket whose session start releases every key (§3.3), and a
/// zero-button pointer report at `pointer` if given (never (0, 0)).
pub async fn ensure_released(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
) -> Result<(), KvmError> {
    ensure_released_within(t, pin, token, pointer, RELEASE_WINDOW).await
}

/// `ensure_released`, retrying (250 ms, doubling to 4 s) for `window`;
/// past it, the error says a key may be held and what to do — first, so
/// a terminal's bounded error line always keeps it.
pub async fn ensure_released_within(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    window: Duration,
) -> Result<(), KvmError> {
    let started = Instant::now();
    let mut wait = Duration::from_millis(250);
    loop {
        match release_once(t, pin, token, pointer).await {
            Ok(()) => return Ok(()),
            Err(e) if started.elapsed() < window => {
                eprintln!(
                    "kvm-probe: release attempt failed, retrying: {}",
                    kvm::bounded_debug(&e)
                );
                tokio::time::sleep(wait.min(window.saturating_sub(started.elapsed()))).await;
                wait = wait.saturating_mul(2).min(Duration::from_secs(4));
            }
            Err(e) => {
                return Err(KvmError::Io(format!(
                    "KEY MAY BE HELD on the Mac: run `kvm-probe hid-release`, press and release the key on the Mac, or unplug the KVM's USB cable. No websocket could release it within {window:?}: {}",
                    escaped(kvm::bounded_debug(&e).as_bytes(), 80)
                )));
            }
        }
    }
}

fn interrupted(what: &str) -> KvmError {
    KvmError::Io(format!("interrupted ({what})"))
}

/// Ctrl-C (SIGINT), SIGTERM (an agent's tool timeout) and SIGHUP (a closed
/// terminal), created once per HID subcommand and passed to each `guarded`
/// section (D34). tokio keeps a signal's handler installed for the life of
/// the process once one is created, so per-section streams would swallow a
/// signal arriving between sections (a settle, a snapshot); one set, kept
/// for the whole command, buffers it for the next `check`, `sleep` or
/// `guarded`. Once one has arrived every later check fails, so nothing
/// after it types. A SIGKILL cannot be caught: `hid-release` is the
/// release after one (D6b).
pub struct Interrupts {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    seen: Option<&'static str>,
}

impl Interrupts {
    pub fn new() -> Result<Interrupts, KvmError> {
        use tokio::signal::unix::{SignalKind, signal};
        let s = |k| signal(k).map_err(|e| KvmError::Io(e.to_string()));
        Ok(Interrupts {
            int: s(SignalKind::interrupt())?,
            term: s(SignalKind::terminate())?,
            hup: s(SignalKind::hangup())?,
            seen: None,
        })
    }

    /// The next interrupt; its name. Cancel-safe (`Signal::recv` is).
    pub async fn recv(&mut self) -> &'static str {
        let name = tokio::select! {
            _ = self.int.recv() => "Ctrl-C",
            _ = self.term.recv() => "SIGTERM",
            _ = self.hup.recv() => "SIGHUP",
        };
        self.seen = Some(name);
        name
    }

    /// `Err` once any interrupt has arrived — including one buffered while
    /// nothing was waiting for it.
    pub fn check(&mut self) -> Result<(), KvmError> {
        if self.seen.is_none() {
            let _ = self.recv().now_or_never();
        }
        self.seen.map_or(Ok(()), |n| Err(interrupted(n)))
    }

    /// Sleep `d`, unless an interrupt comes first.
    pub async fn sleep(&mut self, d: Duration) -> Result<(), KvmError> {
        self.check()?;
        tokio::select! {
            () = tokio::time::sleep(d) => Ok(()),
            n = self.recv() => Err(interrupted(n)),
        }
    }
}

/// Run a HID subcommand's `body`, then release — after success, failure,
/// a panic (caught; the panic is the error) or an interrupt (`irq`). A
/// failed release is the error, whatever the body returned. An interrupt
/// that came before the section skips its body but never its release.
/// (A release build aborts on panic, like a SIGKILL: `hid-release`.)
pub async fn guarded<T>(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    irq: &mut Interrupts,
    body: impl std::future::Future<Output = Result<T, KvmError>>,
) -> Result<T, KvmError> {
    let out = match irq.check() {
        Err(e) => Err(e),
        // Biased, the interrupt first: one that has arrived always wins,
        // never a poll of the body.
        Ok(()) => tokio::select! {
            biased;
            n = irq.recv() => Err(interrupted(n)),
            r = std::panic::AssertUnwindSafe(body).catch_unwind() => r.unwrap_or_else(|_| {
                Err(KvmError::Io("the HID check panicked (the message is above)".to_owned()))
            }),
        },
    };
    ensure_released(t, pin, token, pointer).await?;
    out
}

/// `hid-type --snapshot`: after each run and `settle`, a snapshot named
/// `<prefix><pace>_<run>`.
pub struct Snapshots<'a> {
    pub prefix: &'a str,
    pub settle: Duration,
    pub dir: &'a CaptureDir,
    pub ffmpeg: &'a Path,
    /// The video port's pin.
    pub pin: Option<&'a str>,
}

/// `hid-type`'s runs: `runs` of `page::pattern(chars)` at each of
/// `paces_ms`.
pub struct TypePlan<'a> {
    pub chars: usize,
    pub paces_ms: &'a [u64],
    pub runs: u32,
    pub snapshots: Option<Snapshots<'a>>,
}

/// `hid-type` (Task 1.6 step 7) on one token: each pace × run types the
/// generated pattern — never any other text — on its own websocket, inside
/// `guarded`, so each run ends released; `out` gets a line per run (and
/// per snapshot). An interrupt stops it at once — mid-run (that run's
/// release still runs), in a settle, or between runs — and is the error.
/// Every bound and every snapshot name is checked before anything types.
pub async fn type_runs(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    plan: &TypePlan<'_>,
    irq: &mut Interrupts,
    mut out: impl FnMut(String),
) -> Result<(), String> {
    if plan.chars > MAX_CHARS {
        return Err(format!("--chars is at most {MAX_CHARS}"));
    }
    if let Some(p) = plan
        .paces_ms
        .iter()
        .find(|&&p| Duration::from_millis(p) > MAX_PACE)
    {
        return Err(format!(
            "--paces are at most {} ms (got {p})",
            super::ms(MAX_PACE)
        ));
    }
    let name = |pace: u64, run: u32| {
        plan.snapshots
            .as_ref()
            .map(|s| format!("{}{pace}_{run}", s.prefix))
    };
    if let Some(s) = &plan.snapshots {
        for &pace in plan.paces_ms {
            for run in 1..=plan.runs {
                let flv = format!("{}.flv", name(pace, run).unwrap_or_default());
                let path = s.dir.resolve(&flv).map_err(|e| format!("{e:?}"))?;
                if std::fs::symlink_metadata(&path).is_ok() {
                    return Err(format!(
                        "{} exists: pick another --snapshot prefix",
                        path.display()
                    ));
                }
            }
        }
    }
    let text = super::page::pattern(plan.chars);
    for &pace_ms in plan.paces_ms {
        for run in 1..=plan.runs {
            irq.check().map_err(|e| kvm::bounded_debug(&e))?;
            let r = guarded(t, pin, token, None, irq, async {
                let mut w = HidWs::open(t, pin, token, OPEN_TIMEOUT).await?;
                let r = type_text(&mut w, &text, Duration::from_millis(pace_ms)).await?;
                w.end(End::CloseFrame).await;
                Ok(r)
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))?;
            out(format!("pace {pace_ms} ms, run {run}/{}: {r}", plan.runs));
            if let (Some(s), Some(name)) = (&plan.snapshots, name(pace_ms, run)) {
                irq.sleep(s.settle)
                    .await
                    .map_err(|e| kvm::bounded_debug(&e))?;
                let png =
                    super::snapshot::snapshot(t, s.pin, token, s.dir, &name, s.ffmpeg).await?;
                out(format!("snapshot: {}", png.display()));
            }
        }
    }
    Ok(())
}
