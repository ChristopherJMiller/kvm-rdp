//! §11.3 Admin; Secrets hygiene (DC9) and Review Focus 5 on the real
//! binary, as a subprocess, under a real SIGTERM; the admin port under a
//! connection flood (P17's cap); the binary's peak RSS through a 64 MiB
//! websocket message (DC24).
use crate::client::{Client, Ev, Opts, description, pictures, terminated, timeline};
use crate::harness::{
    CANARY, CHORD_KEY, CHORD_MODS, NLA, SENTINEL, T, edit_toml, env, es3, hid_on, ms, paste_chord,
    scancode, sized, streaming, type_text, until, write_files, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{Chord, us_stroke};
use kvm_proto::paste::{PastePolicy, Typist, prepare};
use kvm_rdp::admin::{MAX_CONNECTIONS, REQUEST_TIMEOUT};
use kvm_rdp::hid::Report;
use kvm_rdp::input::keys::Keyboard;
use kvm_rdp::input::{Ctx, Event, InputCore, Out};
use kvm_rdp::msg::Cause;
use kvm_sim::{KvmSim, SimEvent};
use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// §4.5: `/livez` goes stale while the RDP runtime is blocked (not before
/// 0.5× the 1 s liveness timeout) and recovers; `/readyz` stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn livez_goes_stale_while_the_rdp_runtime_is_blocked() {
    let env = env(es3(), sized).await;
    assert_eq!(env.get("/livez").await.0, 200);
    let t0 = Instant::now();
    env.bridge().block_rdp_runtime_for(ms(3000));
    let mut stale = None;
    while t0.elapsed() < ms(2900) {
        if env.get("/livez").await.0 == 503 {
            stale = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(ms(50)).await;
    }
    let stale = stale.expect("/livez never went stale");
    assert!(stale >= ms(500), "stale after {stale:?}");
    assert_eq!(env.get("/readyz").await.0, 200);
    let t1 = Instant::now();
    let mut live = false;
    while !live && t1.elapsed() < T {
        live = env.get("/livez").await.0 == 200;
        tokio::time::sleep(ms(50)).await;
    }
    assert!(live, "/livez never recovered");
}

/// §4.5: `/readyz` never checks the KVM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_succeeds_without_a_kvm() {
    let env = env(es3(), sized).await;
    env.sim.set_policy(|p| p.blackhole = true);
    assert_eq!(env.get("/readyz").await.0, 200);
    let (code, body) = env.get("/metrics").await;
    assert_eq!(code, 200);
    assert!(body.contains("kvm_rdp_sessions_total"), "{body}");
    assert_eq!(env.sim.stats().accepts_web, 0);
}

const LIVEZ: &[u8] = b"GET /livez HTTP/1.1\r\nHost: l2\r\nConnection: close\r\n\r\n";

async fn admin_connect(addr: SocketAddr) -> TcpStream {
    tokio::time::timeout(T, TcpStream::connect(addr))
        .await
        .expect("admin connect within T")
        .unwrap()
}

/// One `GET /livez` on a fresh connection: its status, or `None` when the
/// connection was dropped unanswered (EOF or a reset, no status line).
async fn livez(addr: SocketAddr) -> Option<u16> {
    let mut s = admin_connect(addr).await;
    let _ = s.write_all(LIVEZ).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(T, s.read_to_end(&mut buf))
        .await
        .expect("an admin connection was neither answered nor closed within T");
    let text = String::from_utf8_lossy(&buf);
    text.strip_prefix("HTTP/1.1 ")?.get(..3)?.parse().ok()
}

/// P17 (PC4 M1, ruling 5): a flood on the admin port. `MAX_CONNECTIONS`
/// silent connections hold every permit; each connection past them is
/// dropped unanswered — although it sends a complete `/livez` request, so
/// a listener that served or queued it past the cap would answer 200 —
/// the session on the KVM runtime the listener shares keeps streaming, and
/// `/livez` answers again once the server has timed the silent ones out
/// (`REQUEST_TIMEOUT`), while the flood still holds them open: the cap
/// frees its own permits.
///
/// The judgement rests on FIFO accept order: the holders are accepted
/// before the extras, and hold their permits until `REQUEST_TIMEOUT`. A
/// runtime starved for longer than that between the two would let a holder
/// time out and an extra be served legitimately, so the extras must all
/// have answered within `REQUEST_TIMEOUT / 2` of the first holder's
/// connect; otherwise the round proves nothing and runs once more (PC19
/// review m8). Two such rounds fail the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_flood_past_the_cap_is_dropped_and_livez_recovers() {
    let (env, c) = streaming(|_| {}).await;
    let mut round = 1;
    let (t0, held) = loop {
        let t0 = Instant::now();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            held.push(admin_connect(env.admin).await);
        }
        let mut served = None;
        for i in 1..=16 {
            if livez(env.admin).await.is_some() && served.is_none() {
                served = Some(MAX_CONNECTIONS + i);
            }
        }
        let took = t0.elapsed();
        if took <= REQUEST_TIMEOUT / 2 {
            assert_eq!(
                served, None,
                "a connection past the cap of {MAX_CONNECTIONS} was served"
            );
            break (t0, held);
        }
        assert!(
            round < 2,
            "the extras took {took:?} (> REQUEST_TIMEOUT / 2) in two rounds, so FIFO \
             accept order cannot be relied on; connection {served:?} was served — the cap \
             queues instead of dropping, or the runtime was starved twice"
        );
        eprintln!("admin flood: round {round}'s extras took {took:?}; running it once more");
        drop(held);
        assert!(
            livez_within(env.admin, REQUEST_TIMEOUT + T).await.is_some(),
            "/livez never answered between the rounds"
        );
        round += 1;
    };
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
    let left = (REQUEST_TIMEOUT + T).saturating_sub(t0.elapsed());
    livez_within(env.admin, left)
        .await
        .expect("/livez never answered again: the flood's permits leaked");
    let answered = t0.elapsed();
    eprintln!("admin flood: /livez answered again {answered:?} after the flood began");
    assert!(terminated(&c.events()).is_none());
    drop(held);
}

/// Poll `/livez` every 50 ms until it answers 200 (`Some(when)`) or `limit`
/// passes (`None`).
async fn livez_within(addr: SocketAddr, limit: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    loop {
        if livez(addr).await == Some(200) {
            return Some(t0.elapsed());
        }
        if t0.elapsed() >= limit {
            return None;
        }
        tokio::time::sleep(ms(50)).await;
    }
}

/// The real binary on `dir`'s config; stdout and stderr captured by line.
struct Bin {
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    /// The two pipe readers (P10): `output` joins them.
    readers: Vec<std::thread::JoinHandle<()>>,
    ready: Option<std::sync::mpsc::Receiver<SocketAddr>>,
}

fn ready_addr(line: &str) -> Option<SocketAddr> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["fields"]["message"] != "kvm-rdp ready" {
        return None;
    }
    v["fields"]["rdp"].as_str()?.parse().ok()
}

fn message(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    v["fields"]["message"].as_str().map(str::to_owned)
}

impl Bin {
    /// The environment is cleared, then given `RUST_LOG=off` (P48: a binary
    /// that took its filter from `RUST_LOG` would log nothing, not even the
    /// ready line) and `envs`.
    fn spawn(dir: &Path, envs: &[(&str, &OsStr)]) -> Bin {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kvm-rdp"));
        cmd.arg("--config")
            .arg(dir.join("kvm-rdp.toml"))
            .env_clear()
            .env("RUST_LOG", "off");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (stdout, o) = (child.stdout.take().unwrap(), out.clone());
        let r1 = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(addr) = ready_addr(&line) {
                    let _ = tx.send(addr);
                }
                o.lock().unwrap().push(line);
            }
        });
        let (stderr, o) = (child.stderr.take().unwrap(), out.clone());
        let r2 = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                o.lock().unwrap().push(line);
            }
        });
        Bin {
            child,
            out,
            readers: vec![r1, r2],
            ready: Some(rx),
        }
    }

    /// The RDP address from the `kvm-rdp ready` line.
    async fn ready(&mut self) -> SocketAddr {
        let rx = self.ready.take().unwrap();
        tokio::task::spawn_blocking(move || rx.recv_timeout(T))
            .await
            .unwrap()
            .expect("the bridge never got ready")
    }

    fn sigterm(&self) {
        let pid = libc::pid_t::try_from(self.child.id()).unwrap();
        // SAFETY: kill(2) on our own child's pid, which it still is (not reaped).
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    }

    async fn wait(&mut self, limit: Duration) -> ExitStatus {
        let t0 = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(
                t0.elapsed() < limit,
                "the bridge did not exit within {limit:?}"
            );
            tokio::time::sleep(ms(20)).await;
        }
    }

    /// Everything the child wrote. Call it only after `wait` returned: the
    /// child's exit closes both pipes, so the joins return — and only after
    /// them is the log complete (P10: the shutdown's last lines, where a
    /// regression would leak, are the ones a reader may still be copying
    /// when `wait` returns).
    fn output(&mut self) -> Vec<String> {
        for r in self.readers.drain(..) {
            let _ = r.join();
        }
        self.out.lock().unwrap().clone()
    }

    /// `/proc/<pid>/status`'s `field` (`VmHWM`, `VmRSS`) in KiB.
    fn status_kib(&self, field: &str) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.child.id())).unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
            .and_then(|v| v.trim().strip_suffix("kB")?.trim().parse().ok())
            .unwrap_or_else(|| panic!("no {field} in /proc/<pid>/status"))
    }
}

impl Drop for Bin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The press frame the US layout types `c` with (no Shift).
fn press_frame(c: char) -> Vec<u8> {
    let s = us_stroke(c).unwrap();
    HidFrame::Keyboard {
        modifiers: if s.shift { 0x02 } else { 0 },
        keys: [s.usage, 0, 0, 0, 0],
    }
    .to_vec()
}

/// What may never reach a log or a `{:?}` for a typed `text` (DC9): the
/// text, and each of its keystrokes' 12-byte keyboard frames as lowercase
/// hex and as Rust prints the bytes.
fn forbidden_for(text: &str) -> Vec<String> {
    let mut v = vec![text.to_owned()];
    for c in text.chars() {
        let f = press_frame(c);
        v.push(f.iter().map(|b| format!("{b:02x}")).collect());
        v.push(format!("{f:?}"));
    }
    v
}

/// `frames` holds `text`'s presses in order (anything may lie between:
/// the release zeros, a re-assert).
fn typed_in_order(frames: &[Vec<u8>], text: &str) -> bool {
    let mut want = text.chars().map(press_frame).peekable();
    for f in frames {
        if want.peek() == Some(f) {
            let _ = want.next();
        }
    }
    want.peek().is_none()
}

/// `text` with each letter and digit moved one along (`z`→`a`, `9`→`0`):
/// the same keystrokes' shape — length, Shift, line breaks — with other keys.
fn decoy(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'z' => 'a',
            '9' => '0',
            'a'..='y' | '0'..='8' => char::from(u8::try_from(c).unwrap() + 1),
            other => other,
        })
        .collect()
}

/// Every `{:?}` the bridge's input path makes of a script, run through the
/// real `InputCore` (pace 0, all eight reports of room): `typed` as
/// scancode presses and releases, then `pasted` through the default chord
/// — each event, each out, each frame pushed and its queued `Report`, the
/// core after every step, each stroke, the keyboard and its key reports,
/// the prepared text and the Typist. Redacted (PD5 ruling, §4.5), none of
/// it can depend on which keys were typed or what was pasted.
fn debug_transcript(typed: &str, pasted: &str) -> Vec<String> {
    let ctx = Ctx {
        now: Instant::now(),
        epoch: 1,
        generation: 1,
        surface: (640, 360),
        mac_remap: false,
        key_repeat_timeout: Duration::from_secs(10),
        modifier_idle_timeout: Duration::from_secs(30),
        chord: Chord::parse("ctrl+option+shift+v").unwrap(),
        pace: Duration::ZERO,
        modifier_wait: Duration::from_secs(5),
        multiline_refuse: false,
        max_chars: 4096,
        queue_room: 8,
    };
    let step = |core: &mut InputCore, e: Event, lines: &mut Vec<String>| {
        lines.push(format!("{e:?}"));
        let mut out = Vec::new();
        core.step(&ctx, e, &mut out);
        for o in &out {
            lines.push(format!("{o:?}"));
            if let Out::Push {
                frame,
                motion_only,
                stamp,
            } = o
            {
                lines.push(format!("{frame:?}"));
                let r = Report {
                    epoch: *stamp,
                    frame: *frame,
                    motion_only: *motion_only,
                };
                lines.push(format!("{r:?}"));
            }
        }
        lines.push(format!("{core:?}"));
    };
    let mut core = InputCore::new();
    let mut lines = Vec::new();
    step(&mut core, Event::ClipboardAvailable(true), &mut lines);
    let mut keyboard = Keyboard::default();
    for ch in typed.chars() {
        let code = scancode(ch);
        lines.push(format!("{:?}", us_stroke(ch).unwrap()));
        lines.push(format!("{:?}", keyboard.press(code, false)));
        lines.push(format!("{keyboard:?}"));
        lines.push(format!("{:?}", keyboard.release(code, false)));
        let (pressed, released) = (
            Event::KeyPressed {
                code,
                extended: false,
            },
            Event::KeyReleased {
                code,
                extended: false,
            },
        );
        step(&mut core, pressed, &mut lines);
        step(&mut core, released, &mut lines);
    }
    let chord = CHORD_MODS
        .iter()
        .map(|m| (*m, true))
        .chain([(CHORD_KEY, true), (CHORD_KEY, false)])
        .chain(CHORD_MODS.iter().map(|m| (*m, false)));
    for (code, down) in chord {
        let e = if down {
            Event::KeyPressed {
                code,
                extended: false,
            }
        } else {
            Event::KeyReleased {
                code,
                extended: false,
            }
        };
        step(&mut core, e, &mut lines);
    }
    let mut bytes: Vec<u8> = pasted.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend([0, 0]);
    step(&mut core, Event::ClipboardText(bytes), &mut lines);
    for _ in 0..pasted.len() {
        step(&mut core, Event::Tick, &mut lines);
    }
    assert!(
        lines.iter().any(|l| l.starts_with("Paste(Done")),
        "the transcript's paste never finished"
    );
    let (prepared, skips) = prepare(
        pasted,
        &PastePolicy {
            multiline_refuse: false,
            max_chars: 4096,
        },
    );
    lines.push(format!("{prepared:?}"));
    lines.push(format!("{skips:?}"));
    let chars: Vec<char> = pasted.chars().collect();
    let mut typist = Typist::new(&chars);
    lines.push(format!("{typist:?}"));
    for f in typist.by_ref() {
        lines.push(format!("{f:?}"));
    }
    lines.push(format!("{typist:?}"));
    lines
}

/// DC9 (PD5 ruling): no `{:?}` the bridge's input path could emit carries
/// a keystroke or pasted text. Each is identical for the sentinel and the
/// canary and for decoys of the same shape — a `Debug` that showed a key,
/// a frame's bytes or a character would differ — and none holds either
/// string or a keystroke's frame bytes.
fn no_debug_shows_input() {
    let real = debug_transcript(SENTINEL, CANARY);
    let other = debug_transcript(&decoy(SENTINEL), &decoy(CANARY));
    assert_ne!(decoy(SENTINEL), SENTINEL);
    assert_eq!(real.len(), other.len());
    for (a, b) in real.iter().zip(&other) {
        assert_eq!(a, b, "a Debug shows what was typed or pasted");
    }
    let forbidden: Vec<String> = forbidden_for(SENTINEL)
        .into_iter()
        .chain(forbidden_for(CANARY))
        .collect();
    for line in &real {
        for f in &forbidden {
            assert!(!line.contains(f.as_str()), "{f:?} is in a Debug: {line}");
        }
    }
}

/// §11.3 secrets hygiene, both filters: an NLA session whose password is
/// the canary, a keystroke sentinel typed and a paste canary pasted through
/// it (DC9), then SIGTERM. Neither canary, the sentinel, their keystrokes'
/// frame bytes, the KVM password, NTLM (raw or base64) nor a token query
/// reaches stdout or stderr; no DEBUG or TRACE line from
/// `ironrdp_*`/`sspi`; at least one TRACE line from bridge code;
/// `SSLKEYLOGFILE` is never created. The shutdown's own lines are in the
/// log checked (P10). Nor does any `{:?}` the input path could emit show
/// the input (`no_debug_shows_input`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secrets_never_reach_the_logs() {
    no_debug_shows_input();
    for filter in [
        "trace",
        "kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace",
    ] {
        let sim = KvmSim::start(es3()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_files(&sim, dir.path());
        let toml = dir.path().join("kvm-rdp.toml");
        let mut text = std::fs::read_to_string(&toml).unwrap();
        text.push_str(&format!("[log]\nfilter = \"{filter}\"\n"));
        std::fs::write(&toml, text).unwrap();
        let keylog = dir.path().join("keylog.txt");
        let mut bin = Bin::spawn(dir.path(), &[("SSLKEYLOGFILE", keylog.as_os_str())]);
        let rdp = bin.ready().await;
        let c = Client::connect(rdp, Opts::new(2).clipboard(CANARY));
        c.wait_for(T, |e| {
            pictures(e).len() >= 5 && e.iter().any(|x| matches!(x, Ev::ClipReady))
        })
        .await;
        // DC9: type the sentinel, paste the canary; both reach kvm-sim.
        let ws = ws_started(&sim, 0).await;
        type_text(&c, SENTINEL);
        let log = sim
            .wait_for(T, |l| typed_in_order(&hid_on(l, ws), SENTINEL))
            .await
            .unwrap_or_else(|l| {
                panic!(
                    "{filter}: the sentinel was not typed: {:02x?}",
                    hid_on(&l, ws)
                )
            });
        let typed_before = hid_on(&log, ws).len();
        paste_chord(&c, true);
        sim.wait_for(T, |l| {
            typed_in_order(&hid_on(l, ws)[typed_before..], CANARY)
        })
        .await
        .unwrap_or_else(|l| {
            panic!(
                "{filter}: the canary was not pasted: {:02x?}",
                hid_on(&l, ws)
            )
        });
        bin.sigterm();
        assert!(bin.wait(T).await.success(), "{filter}");
        let out = bin.output();
        assert!(
            out.iter()
                .any(|l| message(l).as_deref() == Some("shutdown complete")),
            "{filter}: the shutdown's last lines are not in the log checked (P10)"
        );
        let all = out.join("\n");
        let fixed = [NLA, sim.password(), "NTLMSSP", "TlRMTVNTUA", "token="].map(str::to_owned);
        let input = forbidden_for(SENTINEL)
            .into_iter()
            .chain(forbidden_for(CANARY));
        for secret in fixed.into_iter().chain(input) {
            assert!(
                !all.contains(secret.as_str()),
                "{filter}: {secret:?} reached the logs"
            );
        }
        let mut bridge_trace = false;
        for line in &out {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|_| panic!("{filter}: not a JSON line: {line}"));
            let (level, target) = (
                v["level"].as_str().unwrap_or(""),
                v["target"].as_str().unwrap_or(""),
            );
            if target.starts_with("ironrdp") || target.starts_with("sspi") {
                assert!(!matches!(level, "DEBUG" | "TRACE"), "{filter}: {line}");
            }
            bridge_trace |= level == "TRACE" && target.starts_with("kvm_rdp");
        }
        assert!(
            bridge_trace,
            "{filter}: no TRACE line from bridge code — the filter did not take effect"
        );
        assert!(!keylog.exists(), "{filter}: SSLKEYLOGFILE was honoured");
        assert_eq!(sim.stats().logouts, 0);
    }
}

/// Review Focus 5: SIGTERM while a client is connected and the KVM is
/// unreachable (the actor stuck in a TLS handshake that never answers) →
/// the client still gets ErrorInfo 0x1, and the process exits 0 within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_completes_with_the_kvm_unreachable() {
    let sim = KvmSim::start(es3()).await.unwrap();
    sim.set_policy(|p| p.blackhole = true);
    let dir = tempfile::tempdir().unwrap();
    write_files(&sim, dir.path());
    edit_toml(
        dir.path(),
        "upstream_deadline = \"5s\"",
        "upstream_deadline = \"60s\"",
    );
    let mut bin = Bin::spawn(dir.path(), &[]);
    let rdp = bin.ready().await;
    let c = Client::connect(rdp, Opts::new(2));
    c.wait_for(T, |e| timeline(e).contains(&"map".to_owned()))
        .await;
    assert!(
        until(T, || sim.stats().accepts_web >= 1).await,
        "the actor never tried the KVM"
    );
    let t0 = Instant::now();
    bin.sigterm();
    let status = bin.wait(T).await;
    let took = t0.elapsed();
    assert!(status.success(), "{status:?}");
    assert!(took < Duration::from_secs(5), "exit took {took:?}");
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::Shutdown));
    assert_eq!(sim.stats().logouts, 0);
}

/// §5.2: a `Quit` that a live connection consumes ends only that connection;
/// stopping the server takes a second. The test hook runs §5.2 without step
/// 3 (the disconnect), so the client is still connected when the first
/// `Quit` goes out, and reports how many `Quit`s the sequence sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_connection_consumes_the_first_quit_and_a_second_stops_the_server() {
    let (mut env, c) = streaming(|_| {}).await;
    let rdp = env.rdp;
    let t0 = Instant::now();
    let quits = env.take_bridge().shutdown_skipping_disconnect().await;
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert_eq!(
        quits, 2,
        "the first Quit stopped the server although a client was connected"
    );
    c.wait_for(T, |e| {
        e.iter()
            .any(|x| matches!(x, Ev::Closed(_) | Ev::Terminated(_)))
    })
    .await;
    assert!(
        TcpStream::connect(rdp).await.is_err(),
        "the RDP listener is still open"
    );
}

/// The latest websocket's id, once its session-start frames are on the
/// wire (`Env::hid_ready` for a subprocess bridge).
async fn ws_started(sim: &KvmSim, after: usize) -> u64 {
    let ready = |l: &[SimEvent]| {
        let opens = ws_opens(l);
        opens.len() > after && opens.last().is_some_and(|ws| hid_on(l, *ws).len() >= 2)
    };
    let log = sim
        .wait_for(T, ready)
        .await
        .unwrap_or_else(|l| panic!("no websocket session start within {T:?}: {l:?}"));
    *ws_opens(&log).last().unwrap()
}

/// DC24 (P46, ruling 4): §11.3's "RSS bounded" for the 64 MiB websocket
/// message, measured on the real binary — its own process, so its RSS is
/// not shared with concurrent cases as the in-process bridge's is. kvm-sim
/// declares a 64 MiB binary frame and sends 4 KiB of it. What bounds the
/// bridge's memory is the 4 KiB websocket cap (Task 3.3's unit test); this
/// case's teeth are the reconnect: a bridge that waited for the declared
/// message would never reopen the websocket. The peak RSS (`VmHWM`) shows
/// less than it seems: pages a bridge allocates but never touches are not
/// resident (`Vec::with_capacity(64 MiB)` moves `VmHWM` by ~72 KiB), and 4
/// KiB of payload cannot fill a buffer, so a flat `VmHWM` shows only that
/// nothing sized from the declared length was touched — not that a fully
/// delivered 64 MiB message would go unbuffered (a kvm-sim knob that
/// streams the whole message would make it decisive).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_64_mib_websocket_message_leaves_the_binarys_peak_rss_flat() {
    let sim = KvmSim::start(es3()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_files(&sim, dir.path());
    let mut bin = Bin::spawn(dir.path(), &[]);
    let rdp = bin.ready().await;
    let c = Client::connect(rdp, Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    let first = ws_started(&sim, 0).await;
    let (hwm0, rss0) = (bin.status_kib("VmHWM"), bin.status_kib("VmRSS"));
    sim.send_ws_oversize(64 << 20);
    let second = ws_started(&sim, 1).await;
    assert_ne!(first, second);
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
    let (hwm1, rss1) = (bin.status_kib("VmHWM"), bin.status_kib("VmRSS"));
    eprintln!(
        "DC24: the real binary's VmHWM {hwm0} KiB → {hwm1} KiB, VmRSS {rss0} KiB → {rss1} KiB \
         through a 64 MiB websocket message"
    );
    assert!(
        hwm1.saturating_sub(hwm0) < 16 * 1024,
        "peak RSS grew {} KiB through the 64 MiB message",
        hwm1.saturating_sub(hwm0)
    );
    assert!(terminated(&c.events()).is_none());
    bin.sigterm();
    assert!(bin.wait(T).await.success());
    assert_eq!(sim.stats().logouts, 0);
}
