//! The HID checks' websocket (Plan D L4). It opens the way the bridge does
//! — the token cookie, the §3.3 session start, the bridge's 16 KiB
//! `SO_SNDBUF` cap and 1 s write bound — and can end three ways (a close
//! frame, a FIN, a reset). One dropped without `end` (abandoned on an
//! error, a panic or a signal) is reset, so its queued tail is discarded,
//! never delivered late (PD3 I1).
//!
//! A key is never left held: `guarded` runs every HID subcommand's body and
//! then releases, whatever the body did — returned, failed, panicked or was
//! interrupted (Ctrl-C, SIGTERM, SIGHUP, SIGQUIT). A body that ran and did
//! not end Ok is released a second time `SECOND_RELEASE_AFTER` later: what
//! the KVM had already received from it may still be read after the first
//! release. A release is confirmed only by the KVM's answer to its close
//! frame; one without it is printed UNCONFIRMED, never "released". Nothing
//! on the release path can panic on a closed terminal or pipe (PD3 I2).
//!
//! What is typed is only ever `page::pattern`, bounded in length, pace,
//! runs and paces (`MAX_CHARS`, `MAX_PACE`, `MAX_RUNS`, `MAX_PACES`): no
//! burst is unbounded, and neither is one command's typing. Nothing typed
//! is ever Esc or carries Alt/Option or Cmd: the test page resets on a
//! Right Ctrl tap (`reset_page`, PD3 R-I1).
use super::{RefusalForm, escaped, ws};
use crate::captures::CaptureDir;
use crate::kvm::{self, BoxedIo, KvmError};
use crate::request::{KvmTarget, Scheme};
use futures_util::{FutureExt as _, SinkExt as _, StreamExt as _};
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{MOD_LSHIFT, MOD_RCTRL, Stroke, us_stroke};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio_tungstenite::tungstenite::{self, Message};

/// The bridge's websocket send buffer (Plan C's final fix wave), so the
/// probe sees the back-pressure the bridge would.
pub const SNDBUF: usize = 16 * 1024;
/// `input.hid_write_timeout`'s default.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// How long `ensure_released` keeps trying before it says a key may be held.
pub const RELEASE_WINDOW: Duration = Duration::from_secs(30);
/// How long after the first release a body that ran and did not end Ok is
/// released again (PD3 I1) — as Task 1.5's `hid-stale` does: what the KVM
/// had already received from the abandoned websocket may still be read
/// after the first release's zero report.
pub const SECOND_RELEASE_AFTER: Duration = Duration::from_secs(5);
/// The most characters one `type_text` types: at pace 0 that is a burst
/// of 2 × 500 + 2 reports, under DD8's ~1 800-report estimate of the
/// KVM's receive window, so no burst is unbounded. Task 1.6 types 200.
pub const MAX_CHARS: usize = 500;
/// The longest pace `type_text` waits after each report. A press is held
/// for one pace, so this bounds how long the Mac sees any key down while
/// typing — well under macOS's shortest delay until repeat (~225 ms), so
/// the page never auto-repeats. Task 1.6 uses 0–15 ms.
pub const MAX_PACE: Duration = Duration::from_millis(100);
/// The most runs per pace one `hid-type` makes (PD3 m3). Task 1.6: 3.
pub const MAX_RUNS: u32 = 10;
/// The most paces one `hid-type` takes (PD3 m3). Task 1.6: 4.
pub const MAX_PACES: usize = 8;
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

/// The test page's reset (PD3 R-I1): Right Ctrl alone — a modifier-only
/// report, released by `KBD_ZERO` at once. Never Esc: in zsh's emacs
/// keymap (macOS's default shell) a lone ESC is a prefix with no timeout,
/// so Esc and then the pattern's 'a', however far apart, is ESC-a —
/// accept-and-hold, which runs the command line if a terminal has focus.
/// Right Ctrl alone sends no byte to a terminal, has no macOS or Edge
/// action, and still fires the page's `ControlRight` keydown.
pub const RESET_TAP: HidFrame = HidFrame::Keyboard {
    modifiers: MOD_RCTRL,
    keys: [0; 5],
};
/// After the reset tap, before the first character: the page redraws (the
/// plan's original 200 ms).
const RESET_SETTLE: Duration = Duration::from_millis(200);

/// One line on stderr that can never panic (PD3 I2): after SIGHUP (a
/// closed terminal, EIO) or an agent's tool timeout (a closed pipe, EPIPE)
/// `eprintln!` would panic, end the release retries and say nothing. A
/// failed write is ignored instead.
fn note(line: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "kvm-probe: {line}");
}

/// The warning a HID command prints first in a build that aborts on panic
/// (PD3 m5): `guarded` cannot catch a panic there, so a panic mid-run is
/// like a SIGKILL — `hid-release` is the release after one. The runbook's
/// debug build unwinds, so this is `None` there (and in every test).
#[must_use]
pub fn abort_build_warning() -> Option<&'static str> {
    cfg!(panic = "abort").then_some(
        "this build aborts on panic, so a panic mid-run cannot be released here: \
         run `kvm-probe hid-release` after any crash",
    )
}

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

/// How a release ended: the KVM answered its close frame, or it did not
/// (and why) — then the session start was sent, but nothing says the KVM
/// read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    Confirmed,
    Unconfirmed(&'static str),
}

pub struct HidWs {
    ws: ws::Ws,
    /// A second descriptor of the same socket: its options (linger) are
    /// the connection's.
    sock: socket2::Socket,
    last_pos: Option<(u16, u16)>,
    /// `end` ran (`CloseFrame` or `Fin`): what was sent is the stream the
    /// caller meant, so closing delivers it. Unset, a drop resets.
    ended: bool,
}

/// PD3 I1: a websocket dropped without `end` — its body abandoned on an
/// error, a panic or an interrupt, possibly mid-write and with a press
/// last — closes with `SO_LINGER` 0 (an RST), the bridge's own rule for a
/// websocket whose writes did not complete (Plan C, §3.2): its queued tail
/// is discarded, never delivered after the release.
impl Drop for HidWs {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.sock.set_linger(Some(Duration::ZERO));
        }
    }
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
        match HidWs::open_or_refused(t, pin, token, timeout).await? {
            Ok(w) => Ok(w),
            Err(f) => Err(KvmError::Http(format!("websocket refused: {f}"))),
        }
    }

    /// `open`, with the KVM's refusal of the upgrade kept as its form (the
    /// release path logs in again after an auth refusal, PD3 m7).
    async fn open_or_refused(
        t: &KvmTarget,
        pin: Option<&str>,
        token: &str,
        timeout: Duration,
    ) -> Result<Result<HidWs, RefusalForm>, KvmError> {
        let (io, sock) = connect(t, pin).await?;
        let ws = match ws::upgrade_on(io, t, Some(token), timeout).await? {
            ws::Upgrade::Accepted(w) => *w,
            ws::Upgrade::Refused(f) => return Ok(Err(f)),
        };
        let mut h = HidWs {
            ws,
            sock,
            last_pos: None,
            ended: false,
        };
        h.send(HidFrame::SetMode { hid_type: 0 }).await?;
        h.send(KBD_ZERO).await?;
        Ok(Ok(h))
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
    /// it), the wait for the KVM's close by 2 s. `CloseFrame` and `Fin`
    /// close in order (a FIN delivers what was sent); `Reset` resets.
    pub async fn end(mut self, how: End) {
        match how {
            End::CloseFrame => {
                let _ = self.close_and_wait().await;
            }
            End::Fin => self.ended = true,
            // Not ended: the drop resets.
            End::Reset => {}
        }
    }

    /// A close frame, then the KVM's answer (bounded): `Confirmed` only if
    /// it answered with its own close frame.
    async fn close_and_wait(&mut self) -> Released {
        // Everything meant is sent: from here, even a cancelled wait closes
        // in order and delivers it.
        self.ended = true;
        match tokio::time::timeout(WRITE_TIMEOUT, self.ws.close(None)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Released::Unconfirmed("the close frame was not written"),
        }
        let answer = tokio::time::timeout(CLOSE_WAIT, async {
            loop {
                match self.ws.next().await {
                    Some(Ok(Message::Close(_))) => return Released::Confirmed,
                    Some(Ok(_)) => {}
                    Some(Err(tungstenite::Error::Io(e)))
                        if e.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        return Released::Unconfirmed("the KVM reset the connection");
                    }
                    Some(Err(_)) | None => {
                        return Released::Unconfirmed(
                            "the KVM closed the connection without answering the close frame",
                        );
                    }
                }
            }
        })
        .await;
        answer.unwrap_or(Released::Unconfirmed("no answer within 2 s"))
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

/// Reset the test page (D7a): the Right Ctrl tap — `RESET_TAP`, then
/// `KBD_ZERO` — and `RESET_SETTLE` for the page to redraw (PD3 R-I1: never
/// Esc). Task 1.5's `hid-stale` resets the same way.
pub async fn reset_page(w: &mut HidWs) -> Result<(), KvmError> {
    w.send(RESET_TAP).await?;
    w.send(KBD_ZERO).await?;
    tokio::time::sleep(RESET_SETTLE).await;
    Ok(())
}

/// Type `text` (US layout; characters without a stroke are left out) as
/// press/release pairs, `pace` after every report (§8). First `reset_page`
/// (the Right Ctrl tap the test page reads as "start over", D7a, PD3
/// R-I1); those two reports are not counted or timed. More than
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
    reset_page(w).await?;
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

/// Logging in afresh on the release path (PD3 m7): when a release
/// websocket is refused for its token (401/403: the token lapsed
/// mid-command), one fresh login per command, and the release retries with
/// that token. A refused token's session is already gone, so this replaces
/// it rather than adding one. Never printed (no `Debug`).
pub struct Relogin<'a> {
    pub web_pin: Option<&'a str>,
    pub password: &'a str,
}

/// The release path's state across a command's sections: the token (a
/// fresh one after a re-login), the fresh logins left, the retry window.
struct Releaser<'r> {
    token: String,
    relogin: Option<&'r Relogin<'r>>,
    relogins_left: u32,
    window: Duration,
}

impl<'r> Releaser<'r> {
    fn new(token: &str, relogin: Option<&'r Relogin<'r>>, window: Duration) -> Releaser<'r> {
        Releaser {
            token: token.to_owned(),
            relogin,
            relogins_left: u32::from(relogin.is_some()),
            window,
        }
    }
}

enum Failed {
    Refused(RefusalForm),
    Other(KvmError),
}

async fn release_once(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
) -> Result<Released, Failed> {
    let mut w = match HidWs::open_or_refused(t, pin, token, RELEASE_OPEN_TIMEOUT).await {
        Ok(Ok(w)) => w,
        Ok(Err(f)) => return Err(Failed::Refused(f)),
        Err(e) => return Err(Failed::Other(e)),
    };
    if let Some((x, y)) = pointer {
        w.send(HidFrame::abs_mouse(0, x, y))
            .await
            .map_err(Failed::Other)?;
    }
    Ok(w.close_and_wait().await)
}

/// Fresh websockets until one carries the session start, retrying
/// (250 ms, doubling to 4 s) for the window; after an auth refusal, one
/// fresh login if `r` has one left. Past the window, the error says a key
/// may be held and what to do — first, so a bounded error line keeps it.
/// Every line it prints goes through `note` (PD3 I2).
async fn release_loop(
    t: &KvmTarget,
    pin: Option<&str>,
    r: &mut Releaser<'_>,
    pointer: Option<(u16, u16)>,
) -> Result<Released, KvmError> {
    let started = Instant::now();
    let mut wait = Duration::from_millis(250);
    loop {
        let failed = match release_once(t, pin, &r.token, pointer).await {
            Ok(done) => return Ok(done),
            Err(f) => f,
        };
        if let (Failed::Refused(form), Some(re)) = (&failed, r.relogin)
            && matches!(form.status, 401 | 403)
            && r.relogins_left > 0
            && started.elapsed() < r.window
        {
            r.relogins_left = r.relogins_left.saturating_sub(1);
            note(format_args!(
                "the release websocket was refused ({form}): logging in again, once"
            ));
            match kvm::login(
                t,
                re.web_pin,
                re.password,
                super::now_unix(),
                kvm::PROBE_TIMEZONE,
            )
            .await
            {
                Ok(fresh) => {
                    r.token = fresh;
                    continue;
                }
                Err(e) => note(format_args!(
                    "the fresh login failed: {}",
                    kvm::bounded_debug(&e)
                )),
            }
        }
        let e = match failed {
            Failed::Refused(f) => KvmError::Http(format!("websocket refused: {f}")),
            Failed::Other(e) => e,
        };
        if started.elapsed() >= r.window {
            return Err(KvmError::Io(format!(
                "KEY MAY BE HELD on the Mac: run `kvm-probe hid-release`, press and release the key on the Mac, or unplug the KVM's USB cable. No websocket could release it within {:?}: {}",
                r.window,
                escaped(kvm::bounded_debug(&e).as_bytes(), 80)
            )));
        }
        note(format_args!(
            "release attempt failed, retrying: {}",
            kvm::bounded_debug(&e)
        ));
        tokio::time::sleep(wait.min(r.window.saturating_sub(started.elapsed()))).await;
        wait = wait.saturating_mul(2).min(Duration::from_secs(4));
    }
}

/// Print an unconfirmed release (PD3 I1 c): never as "released".
fn report(r: Released) {
    if let Released::Unconfirmed(why) = r {
        note(format_args!(
            "release UNCONFIRMED: the session start was sent, but {why}; a snapshot must show `held -`"
        ));
    }
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

/// `ensure_released`, retrying for `window`; an unconfirmed release is
/// printed UNCONFIRMED (PD3 I1 c) and is not an error.
pub async fn ensure_released_within(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    window: Duration,
) -> Result<(), KvmError> {
    let mut r = Releaser::new(token, None, window);
    report(release_loop(t, pin, &mut r, pointer).await?);
    Ok(())
}

/// `ensure_released_within`, saying how it ended and printing nothing of
/// it: `hid-release` prints "released" only for `Confirmed`.
pub async fn release(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    window: Duration,
) -> Result<Released, KvmError> {
    release_loop(t, pin, &mut Releaser::new(token, None, window), pointer).await
}

fn interrupted(what: &str) -> KvmError {
    KvmError::Io(format!("interrupted ({what})"))
}

/// Ctrl-C (SIGINT), SIGTERM (an agent's tool timeout), SIGHUP (a closed
/// terminal) and SIGQUIT (Ctrl-\, which would otherwise dump core with a
/// key held, PD3 m6), created once per HID subcommand and passed to each
/// `guarded` section (D34). tokio keeps a signal's handler installed for
/// the life of the process once one is created, so per-section streams
/// would swallow a signal arriving between sections (a settle, a
/// snapshot); one set, kept for the whole command, buffers it for the next
/// `check`, `sleep` or `guarded`. Once one has arrived every later check
/// fails, so nothing after it types. A SIGKILL cannot be caught:
/// `hid-release` is the release after one (D6b).
pub struct Interrupts {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
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
            quit: s(SignalKind::quit())?,
            seen: None,
        })
    }

    /// The next interrupt; its name. Cancel-safe (`Signal::recv` is).
    pub async fn recv(&mut self) -> &'static str {
        let name = tokio::select! {
            _ = self.int.recv() => "Ctrl-C",
            _ = self.term.recv() => "SIGTERM",
            _ = self.hup.recv() => "SIGHUP",
            _ = self.quit.recv() => "SIGQUIT",
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
/// body that ran and did not end Ok is released again
/// `SECOND_RELEASE_AFTER` later (PD3 I1); if the KVM confirmed neither
/// release, the error is KEY MAY BE HELD (PD3 R-m1). A failed release is the error,
/// whatever the body returned, and ends the section at once. An interrupt
/// that came before the section skips its body — which then left nothing
/// to land late — but never its release. (A release build aborts on panic,
/// like a SIGKILL: `hid-release`, `abort_build_warning`.)
pub async fn guarded<T>(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    irq: &mut Interrupts,
    body: impl std::future::Future<Output = Result<T, KvmError>>,
) -> Result<T, KvmError> {
    let mut r = Releaser::new(token, None, RELEASE_WINDOW);
    guarded_with(t, pin, &mut r, pointer, irq, Second::AfterFailure, body).await
}

/// When `guarded_with` releases a second time, `SECOND_RELEASE_AFTER`
/// after the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Second {
    /// After a body that ran and did not end Ok (PD3 I1): what the KVM had
    /// already received from it may still be read after the first release.
    AfterFailure,
    /// After any body that ran, Ok or not: it reset a websocket with a
    /// backlog on purpose (`hid_stale`, D5), so that backlog may drain
    /// after the first release whatever the body returned.
    Always,
}

async fn guarded_with<T>(
    t: &KvmTarget,
    pin: Option<&str>,
    r: &mut Releaser<'_>,
    pointer: Option<(u16, u16)>,
    irq: &mut Interrupts,
    second: Second,
    body: impl std::future::Future<Output = Result<T, KvmError>>,
) -> Result<T, KvmError> {
    let ran = std::cell::Cell::new(false);
    let body = async {
        ran.set(true);
        body.await
    };
    let out = match irq.check() {
        Err(e) => Err(e),
        // Biased, the interrupt first: one that has arrived always wins,
        // never a poll of the body.
        Ok(()) => tokio::select! {
            biased;
            n = irq.recv() => Err(interrupted(n)),
            done = std::panic::AssertUnwindSafe(body).catch_unwind() => done.unwrap_or_else(|_| {
                Err(KvmError::Io("the HID check panicked (the message is above)".to_owned()))
            }),
        },
    };
    let first = release_loop(t, pin, r, pointer).await?;
    report(first);
    if ran.get() && (out.is_err() || second == Second::Always) {
        tokio::time::sleep(SECOND_RELEASE_AFTER).await;
        let again = release_loop(t, pin, r, pointer).await?;
        report(again);
        // PD3 R-m1: the KVM confirmed neither release after a body that
        // failed mid-stream (or, `Always`, reset a websocket with a backlog
        // on purpose) — that backlog may still land after both (a stall
        // outlasting them). That is the one case no client-side order can
        // prevent, so it is loud: KEY MAY BE HELD, the body's error inside.
        if matches!(
            (first, again),
            (Released::Unconfirmed(_), Released::Unconfirmed(_))
        ) {
            let why = match &out {
                Err(e) => format!("The run failed: {}", escaped(what(e).as_bytes(), 80)),
                Ok(_) => "The run completed, but it reset a websocket whose backlog may land after both releases".to_owned(),
            };
            return Err(KvmError::Io(format!(
                "KEY MAY BE HELD on the Mac (neither release was confirmed): run `kvm-probe hid-release` and check `held -`. {why}"
            )));
        }
    }
    out
}

/// An error's own text, without its variant.
fn what(e: &KvmError) -> &str {
    match e {
        KvmError::Connect(s)
        | KvmError::Tls(s)
        | KvmError::Http(s)
        | KvmError::Login(s)
        | KvmError::Io(s) => s,
    }
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

/// Every snapshot a HID command will take, checked before anything types
/// (a name taken would fail mid-run): each `<name>.flv` must be a safe
/// name in `dir` that does not exist yet.
pub fn check_snapshot_names(
    dir: &CaptureDir,
    names: impl IntoIterator<Item = String>,
) -> Result<(), String> {
    for name in names {
        let path = dir
            .resolve(&format!("{name}.flv"))
            .map_err(|e| format!("{e:?}"))?;
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "{} exists: pick another --snapshot",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `hid-type`'s runs: `runs` of `page::pattern(chars)` at each of
/// `paces_ms`.
pub struct TypePlan<'a> {
    pub chars: usize,
    pub paces_ms: &'a [u64],
    pub runs: u32,
    pub snapshots: Option<Snapshots<'a>>,
    /// Each release's retry window: `RELEASE_WINDOW` (tests shorten it).
    pub release_window: Duration,
    /// A fresh login for a release refused for its token (PD3 m7).
    pub relogin: Option<Relogin<'a>>,
}

impl<'a> TypePlan<'a> {
    /// No snapshots, `RELEASE_WINDOW`, no fresh login.
    #[must_use]
    pub fn new(chars: usize, paces_ms: &'a [u64], runs: u32) -> TypePlan<'a> {
        TypePlan {
            chars,
            paces_ms,
            runs,
            snapshots: None,
            release_window: RELEASE_WINDOW,
            relogin: None,
        }
    }
}

/// Every bound of `plan`, before anything connects (the CLI checks them
/// too).
fn check_plan(plan: &TypePlan<'_>) -> Result<(), String> {
    if plan.chars > MAX_CHARS {
        return Err(format!("--chars is at most {MAX_CHARS}"));
    }
    if !(1..=MAX_RUNS).contains(&plan.runs) {
        return Err(format!("--runs is 1..={MAX_RUNS}"));
    }
    if !(1..=MAX_PACES).contains(&plan.paces_ms.len()) {
        return Err(format!("--paces takes 1 to {MAX_PACES} values"));
    }
    for (i, &p) in plan.paces_ms.iter().enumerate() {
        if Duration::from_millis(p) > MAX_PACE {
            return Err(format!(
                "--paces are at most {} ms (got {p})",
                super::ms(MAX_PACE)
            ));
        }
        if plan.paces_ms.iter().take(i).any(|&q| q == p) {
            return Err(format!("--paces gives {p} twice"));
        }
    }
    Ok(())
}

/// `hid-type` (Task 1.6 step 7) on one token: each pace × run types the
/// generated pattern — never any other text — on its own websocket, inside
/// a `guarded` section, so each run ends released; `out` gets a line per
/// run (and per snapshot). A failed run, a failed release or an interrupt
/// stops it at once — mid-run (that run's release still runs), in a
/// settle, or between runs — and is the error. Every bound and every
/// snapshot name is checked before anything types.
pub async fn type_runs(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    plan: &TypePlan<'_>,
    irq: &mut Interrupts,
    mut out: impl FnMut(String),
) -> Result<(), String> {
    check_plan(plan)?;
    let name = |pace: u64, run: u32| {
        plan.snapshots
            .as_ref()
            .map(|s| format!("{}{pace}_{run}", s.prefix))
    };
    if let Some(s) = &plan.snapshots {
        check_snapshot_names(
            s.dir,
            plan.paces_ms.iter().flat_map(|&pace| {
                (1..=plan.runs).map(move |run| name(pace, run).unwrap_or_default())
            }),
        )?;
    }
    let text = super::page::pattern(plan.chars);
    let mut releaser = Releaser::new(token, plan.relogin.as_ref(), plan.release_window);
    for &pace_ms in plan.paces_ms {
        for run in 1..=plan.runs {
            irq.check().map_err(|e| kvm::bounded_debug(&e))?;
            // The current token: a fresh one if a release logged in again.
            let tok = releaser.token.clone();
            let r = guarded_with(
                t,
                pin,
                &mut releaser,
                None,
                irq,
                Second::AfterFailure,
                async {
                    let mut w = HidWs::open(t, pin, &tok, OPEN_TIMEOUT).await?;
                    let r = type_text(&mut w, &text, Duration::from_millis(pace_ms)).await?;
                    w.end(End::CloseFrame).await;
                    Ok(r)
                },
            )
            .await
            .map_err(|e| kvm::bounded_debug(&e))?;
            out(format!("pace {pace_ms} ms, run {run}/{}: {r}", plan.runs));
            if let (Some(s), Some(name)) = (&plan.snapshots, name(pace_ms, run)) {
                irq.sleep(s.settle)
                    .await
                    .map_err(|e| kvm::bounded_debug(&e))?;
                let png =
                    super::snapshot::snapshot(t, s.pin, &releaser.token, s.dir, &name, s.ffmpeg)
                        .await?;
                out(format!("snapshot: {}", png.display()));
            }
        }
    }
    Ok(())
}

/// `hid-stale`'s burst length (D5): enough to see whether a reset
/// websocket's backlog is still read, small enough to type out harmlessly
/// as 64 letters into the test page if it is.
pub const STALE_BURST: u64 = 128;

/// The longest `hid-stale` waits for stale presses to land (`--settle-ms`;
/// Task 1.6 uses 5 s): a cut backlog can leave one press down through it,
/// so it is bounded like every hold.
pub const MAX_SETTLE: Duration = Duration::from_secs(30);

/// `hid_stale`'s one snapshot suffix: `<NAME>` itself, after the settle.
pub const STALE_SHOTS: [&str; 1] = [""];

/// The burst's `i`-th report: a press of `a`..`t` on even `i`, the
/// all-zero release on odd `i`. The burst ends on a release, so a backlog
/// read to its end leaves nothing held, and one cut anywhere leaves at most
/// one key down for the release after it to clear. No modifier, never Esc
/// (PD3 R-I1).
#[must_use]
pub fn stale_frame(i: u64) -> HidFrame {
    if i % 2 == 1 {
        return KBD_ZERO;
    }
    press(Stroke {
        usage: 0x04u8.saturating_add(u8::try_from((i / 2) % 20).unwrap_or(0)),
        shift: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleReport {
    /// Burst reports written before the reset (`STALE_BURST` unless a
    /// write failed).
    pub pushed: u64,
}

fn check_settle(settle: Duration) -> Result<(), KvmError> {
    if settle > MAX_SETTLE {
        return Err(KvmError::Io(format!(
            "hid-stale settles for at most {MAX_SETTLE:?}; got {settle:?}"
        )));
    }
    Ok(())
}

/// The re-assert measurement (PC9 fix 2): write the `STALE_BURST` burst at
/// pace 0 and reset the websocket (§3.2's rule for a stalled one), then
/// open a fresh one — its session start releases — and reset the test page
/// with `reset_page`'s Right Ctrl tap (never Esc, PD3 R-I1), which clears
/// its text and counts, so the page then shows only stale presses the KVM
/// read **after** the fresh session start. Wait `settle` (at most
/// `MAX_SETTLE`, else refused before anything connects) for them; the
/// caller snapshots the page before any release (`hid_stale`). Only the
/// device (or kvm-sim) sees what it read, so the report is just what was
/// written.
pub async fn stale_after_reset(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    settle: Duration,
) -> Result<StaleReport, KvmError> {
    check_settle(settle)?;
    let mut w = HidWs::open(t, pin, token, OPEN_TIMEOUT).await?;
    let mut pushed = 0u64;
    for i in 0..STALE_BURST {
        if w.send(stale_frame(i)).await.is_err() {
            break;
        }
        pushed = pushed.saturating_add(1);
    }
    w.end(End::Reset).await;
    let mut fresh = HidWs::open(t, pin, token, OPEN_TIMEOUT).await?;
    reset_page(&mut fresh).await?;
    fresh.end(End::CloseFrame).await;
    tokio::time::sleep(settle).await;
    Ok(StaleReport { pushed })
}

/// `hid-stale` (Task 1.6 step 9): `stale_after_reset`, its report through
/// `out` at once (so a later error never hides it), and `shot(STALE_SHOTS[0])`
/// — all before any release, in one section that releases twice on every
/// path where it ran, `SECOND_RELEASE_AFTER` apart (D5: the burst's
/// backlog may drain after the first; `Second::Always`). If the KVM
/// confirmed neither release the result is KEY MAY BE HELD, even after a
/// body that succeeded (PD3 R-m1). A settle past `MAX_SETTLE` is refused
/// before anything connects.
pub async fn hid_stale(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    settle: Duration,
    irq: &mut Interrupts,
    mut shot: impl AsyncFnMut(&str) -> Result<(), KvmError>,
    mut out: impl FnMut(String),
) -> Result<StaleReport, KvmError> {
    check_settle(settle)?;
    let [name] = STALE_SHOTS;
    let mut r = Releaser::new(token, None, RELEASE_WINDOW);
    let report = guarded_with(t, pin, &mut r, None, irq, Second::Always, async {
        let report = stale_after_reset(t, pin, token, settle).await?;
        out(format!("{report:?}"));
        shot(name).await?;
        Ok(report)
    })
    .await?;
    irq.check()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PD3 m5: tests (and the runbook's debug build) unwind, so `guarded`
    /// catches a panic and no warning is printed.
    #[test]
    fn an_unwinding_build_needs_no_abort_warning() {
        const { assert!(cfg!(panic = "unwind")) };
        assert_eq!(abort_build_warning(), None);
    }

    /// PD3 R-I1: the reports `type_text` builds — the reset tap and every
    /// character of the pattern — carry no Esc (0x29) and no modifier but
    /// Left Shift with a key; the tap is Right Ctrl alone.
    #[test]
    fn the_reset_tap_and_every_pattern_press_are_safe_reports() {
        assert_eq!(
            RESET_TAP,
            HidFrame::Keyboard {
                modifiers: kvm_proto::keymap::MOD_RCTRL,
                keys: [0; 5]
            }
        );
        for c in super::super::page::pattern(500).chars() {
            let Some(s) = us_stroke(c) else {
                panic!("{c:?} has no stroke")
            };
            let HidFrame::Keyboard { modifiers, keys } = press(s) else {
                panic!("not a keyboard report")
            };
            assert!(modifiers == 0 || modifiers == MOD_LSHIFT, "{c:?}");
            assert!(!keys.contains(&0x29), "{c:?} is Esc");
        }
    }

    /// D5, from literals: 128 reports, a press of 'a'..'t' (cycling) with
    /// no modifier on even `i` and the all-zero release on odd `i` — 64
    /// presses, never two keys down, and the last report a release.
    #[test]
    fn the_stale_burst_is_bounded_alternating_and_ends_released() {
        assert_eq!(STALE_BURST, 128);
        // 'a'..'t' from the US layout, cycling — not the burst's formula.
        let letters: Vec<u8> = ('a'..='t').filter_map(us_stroke).map(|s| s.usage).collect();
        assert_eq!(letters.len(), 20);
        let mut want = Vec::new();
        for &usage in letters.iter().cycle().take(64) {
            want.push(HidFrame::Keyboard {
                modifiers: 0,
                keys: [usage, 0, 0, 0, 0],
            });
            want.push(KBD_ZERO);
        }
        let burst: Vec<HidFrame> = (0..STALE_BURST).map(stale_frame).collect();
        assert_eq!(burst, want);
        assert_eq!(burst.last(), Some(&KBD_ZERO));
        assert!(!letters.contains(&kvm_proto::keymap::USAGE_ESC));
    }

    /// A HID command checks every snapshot name before anything types: an
    /// unsafe name, or one already taken, is refused.
    #[test]
    fn snapshot_names_are_checked_before_anything_types() {
        let base = tempfile::tempdir().unwrap();
        let dir = CaptureDir::create(&base.path().join("captures")).unwrap();
        let taken = dir.resolve("hold_held.flv").unwrap();
        std::fs::write(&taken, b"").unwrap();
        let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(check_snapshot_names(&dir, names(&["stale", "hold_released"])).is_ok());
        let e = check_snapshot_names(&dir, names(&["stale", "hold_held"])).unwrap_err();
        assert!(e.contains("exists"), "{e}");
        assert!(check_snapshot_names(&dir, names(&["../x"])).is_err());
    }
}
