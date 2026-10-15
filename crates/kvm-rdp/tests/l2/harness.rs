//! The L2 environment (§11.1, §11.3): kvm-sim on this test's runtime, the
//! bridge in process from the files a deployment would write, scaled
//! timers, and the assertion every case shares: kvm-sim never sees a
//! logout (§3.2). Each case uses a subset of these helpers.
//!
//! L2 is its own test target: the library's `cfg(test)` seams do not exist
//! here. Cases reach the bridge through its public API and kvm-sim's
//! policies only.
#![allow(dead_code)]
use crate::client::{Client, Opts};
use kvm_proto::h264::split_annex_b;
use kvm_proto::hid::{HidFrame, scale_abs};
use kvm_proto::keymap::{us_stroke, usage_for_scancode};
use kvm_rdp::bridge::{self, BridgeHandle};
use kvm_rdp::config::Config;
use kvm_rdp::metrics::Metrics;
use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const USER: &str = "kvm";
/// The NLA password — and the secrets case's canary (§11.3).
pub const NLA: &str = "l2-canary-7f3a9c2e5b1d4a6f8e0c";
/// The secrets case's keystroke sentinel (DC9): typed as scancodes. Letters,
/// digits and `-` only — no Shift.
pub const SENTINEL: &str = "sentinel-6b1f0c9d2a";
/// The secrets case's paste canary (DC9): pasted over CLIPRDR. No Shift.
pub const CANARY: &str = "paste-canary-3e7a";
/// The upper bound on anything L2 waits for.
pub const T: Duration = Duration::from_secs(10);
pub const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
pub const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const ES3_FIXTURE: &str = "360p30_es3like_poc0.h264";
pub const P360: &str = "360p30_main_full.h264";
pub const P480: &str = "480p30_main_full.h264";
/// Main, 640×360, 330 frames, IDRs at 0 and 300: a new FLV restarts the
/// GOP at 300, the source wraps to its frame-0 IDR 30 frames (1 s) later,
/// and only then do 299 P frames (≈10 s) follow.
pub const LONGGOP: &str = "360p30_main_longgop.h264";

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// The default paste chord's make codes (`ctrl+option+shift+v`, §8).
pub const CHORD_MODS: [u8; 3] = [0x1D, 0x38, 0x2A]; // LCtrl, LAlt, LShift
pub const CHORD_KEY: u8 = 0x2F; // V

/// Press the chord's modifiers and V, release V, then — if `release_mods`
/// — the modifiers (they must release for the paste to type, §8).
pub fn paste_chord(c: &Client, release_mods: bool) {
    for m in CHORD_MODS {
        c.key(m, true);
    }
    c.key(CHORD_KEY, true);
    c.key(CHORD_KEY, false);
    if release_mods {
        for m in CHORD_MODS {
            c.key(m, false);
        }
    }
}

/// The set-1 make code that types `c` on the US layout without Shift.
pub fn scancode(c: char) -> u8 {
    let s = us_stroke(c).unwrap_or_else(|| panic!("{c:?} has no US-layout key"));
    assert!(!s.shift, "{c:?} needs Shift");
    (1..0x80u8)
        .find(|code| usage_for_scancode(*code, false) == Some(s.usage))
        .unwrap_or_else(|| panic!("no scancode types {c:?}"))
}

/// Type `text` (no Shift) as scancode presses and releases.
pub fn type_text(c: &Client, text: &str) {
    for ch in text.chars() {
        let code = scancode(ch);
        c.key(code, true);
        c.key(code, false);
    }
}

/// The §8 report list the US layout types `text` with (each character a
/// press, then the all-zero release), as kvm-sim records it.
pub fn typed(text: &str) -> Vec<Vec<u8>> {
    text.chars()
        .flat_map(|ch| {
            let s = us_stroke(ch).unwrap_or_else(|| panic!("{ch:?} has no US-layout key"));
            let modifiers = if s.shift { 0x02 } else { 0 };
            [
                HidFrame::Keyboard {
                    modifiers,
                    keys: [s.usage, 0, 0, 0, 0],
                }
                .to_vec(),
                KBD_ZERO.to_vec(),
            ]
        })
        .collect()
}

/// The surface `sized` gives every case: what §7.2 scales against.
pub const SURFACE: (u16, u16) = (640, 360);
/// A client position no script otherwise uses: the end-of-script mark.
pub const MARK: (u16, u16) = (7, 11);

/// An absolute-mouse frame for a client position on `SURFACE` (§7.2).
pub fn abs(buttons: u8, x: u16, y: u16) -> Vec<u8> {
    HidFrame::abs_mouse(buttons, scale_abs(x, SURFACE.0), scale_abs(y, SURFACE.1)).to_vec()
}

/// kvm-sim's frames on `ws` after its session start, once there are at
/// least `want` (everything recorded by then).
pub async fn after_start(env: &Env, ws: u64, want: usize) -> Vec<Vec<u8>> {
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).len() >= 2 + want)
        .await
        .unwrap_or_else(|l| {
            panic!(
                "fewer than {want} frames after the session start within {T:?}: {:02x?}",
                hid_on(&l, ws)
            )
        });
    let all = hid_on(&log, ws);
    assert_eq!(
        all[..2],
        [SET_MODE.to_vec(), KBD_ZERO.to_vec()],
        "the session start"
    );
    all[2..].to_vec()
}

/// End a script with a move to `MARK` (buttons up), and return kvm-sim's
/// frames on `ws` after its session start and before the mark's frame. One
/// client connection keeps every event in order, so a frame the script
/// should not have made shows up before the mark, not after the check.
pub async fn until_mark(env: &Env, c: &Client, ws: u64) -> Vec<Vec<u8>> {
    until_mark_at(env, c, ws, MARK).await
}

/// `until_mark` with a mark of the case's choosing: a websocket whose
/// session start already puts the pointer at `MARK` (a later session's,
/// after a case's earlier mark) needs another.
pub async fn until_mark_at(env: &Env, c: &Client, ws: u64, at: (u16, u16)) -> Vec<Vec<u8>> {
    c.mouse_move(at.0, at.1);
    let mark = abs(0, at.0, at.1);
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).contains(&mark))
        .await
        .unwrap_or_else(|l| panic!("the mark never came: {:02x?}", hid_on(&l, ws)));
    let all = hid_on(&log, ws);
    assert_eq!(
        all[..2],
        [SET_MODE.to_vec(), KBD_ZERO.to_vec()],
        "the session start"
    );
    let end = all.iter().position(|f| *f == mark).unwrap();
    all[2..end].to_vec()
}

/// The ES3-shaped POC-0 fixture (640×360, Baseline) at the ES3's pacing.
pub fn es3() -> SimConfig {
    SimConfig::es3(source(ES3_FIXTURE))
}

/// The Main 360p fixture: the resolution-change pair's first half.
pub fn main_360p() -> SimConfig {
    SimConfig::es3(source(P360))
}

pub fn source(name: &str) -> Source {
    Source::fixture(name).unwrap()
}

/// The fixtures' size as the default: no connect-time resize, no slate;
/// and no re-assert within a case (D10a): the exact-frame cases never see
/// one on a shared host. Task 5.3's re-assert case sets its own.
pub fn sized(c: &mut Config) {
    c.video.default_size = (640, 360);
    c.input.reassert_after = Duration::from_secs(600);
}

/// A loopback address no other `Env` binds — 127.128-191.x.y, from this
/// process's id and a counter — for one bridge's RDP and admin listeners.
/// On 127.0.0.1 a freed ephemeral port can be re-bound by a concurrent
/// case's `bind(0)` (kvm-sim binds three there per case), so a "listener
/// is closed" probe by connecting could reach a neighbour (PC15, 212a099:
/// about 1 in 45-80 runs). The lib's `testkit::private_loopback` mirrored —
/// `cfg(test)` items are invisible to this target — in its own range
/// (the lib uses 127.64-127), so lib tests and L2 never share an address.
pub fn private_loopback() -> IpAddr {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed) % 250;
    let [_, _, hi, lo] = std::process::id().to_be_bytes();
    Ipv4Addr::new(127, 128 | (hi & 0x3f), lo, u8::try_from(n + 2).unwrap()).into()
}

/// In `private_loopback`'s range.
pub fn is_private_loopback(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.octets()[0] == 127 && v.octets()[1] & 0xC0 == 0x80)
}

/// A deployment's files in `dir`: the secrets, a fresh TLS pair, and a
/// config for `sim` with ephemeral listeners on a fresh private loopback
/// address, scaled per §11.1.
pub fn write_files(sim: &KvmSim, dir: &Path) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    std::fs::write(dir.join("nla.pass"), format!("{NLA}\n")).unwrap();
    std::fs::write(dir.join("kvm.pass"), format!("{}\n", sim.password())).unwrap();
    let p = sim.ports();
    let ip = private_loopback();
    let toml = format!(
        "[rdp]\nlisten = \"{ip}:0\"\nusername = \"{USER}\"\nnla_password_file = \"nla.pass\"\n\
         tls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\n\
         [admin]\nlisten = \"{ip}:0\"\nliveness_timeout = \"1s\"\n\
         [kvm]\nhost = \"{host}\"\nspki_sha256 = \"{pin}\"\npassword_file = \"kvm.pass\"\n\
         web_port = {web}\nvideo_port = {video}\ncontrol_port = {control}\n\
         connect_timeout = \"1s\"\nlogin_timeout = \"2s\"\nupstream_deadline = \"5s\"\n\
         [kvm.backoff]\ninitial = \"50ms\"\nmax = \"400ms\"\n\
         [video]\navc420_timeout = \"2s\"\ndisconnect_watchdog = \"1s\"\nsuppress_debounce = \"300ms\"\n\
         [input]\nhid_write_timeout = \"300ms\"\n\
         [security]\naccept_rate = 1000\n",
        host = sim.host(),
        pin = sim.spki_sha256(),
        web = p.web,
        video = p.video,
        control = p.control,
    );
    std::fs::write(dir.join("kvm-rdp.toml"), toml).unwrap();
}

/// Replace one exact line fragment of the written config.
pub fn edit_toml(dir: &Path, from: &str, to: &str) {
    let path = dir.join("kvm-rdp.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{from:?} is not in the config");
    std::fs::write(&path, text.replace(from, to)).unwrap();
}

pub struct Env {
    pub sim: KvmSim,
    pub dir: tempfile::TempDir,
    pub rdp: SocketAddr,
    pub admin: SocketAddr,
    bridge: Option<BridgeHandle>,
    /// `Drop` waits for the bridge to stop unless a case took it.
    taken: bool,
}

/// kvm-sim, then the bridge over it, configured by the real loader and
/// then `edit`.
pub async fn env(sim: SimConfig, edit: impl FnOnce(&mut Config)) -> Env {
    let sim = KvmSim::start(sim).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_files(&sim, dir.path());
    let mut cfg = Config::load(&dir.path().join("kvm-rdp.toml")).unwrap();
    edit(&mut cfg);
    // `spawn` blocks until the RDP listener is bound (≤ STARTUP_WAIT).
    let bridge = tokio::time::timeout(T, tokio::task::spawn_blocking(move || bridge::spawn(cfg)))
        .await
        .expect("the bridge did not start")
        .unwrap()
        .unwrap();
    let (rdp, admin) = (bridge.rdp_addr, bridge.admin_addr);
    assert!(
        is_private_loopback(rdp.ip()) && admin.ip() == rdp.ip(),
        "the listeners are not on the Env's private loopback address: {rdp}, {admin}"
    );
    Env {
        rdp,
        admin,
        sim,
        dir,
        bridge: Some(bridge),
        taken: false,
    }
}

/// A sized ES3 session with `edit`, streaming (five pictures in).
pub async fn streaming(edit: impl FnOnce(&mut Config)) -> (Env, Client) {
    let env = env(es3(), |c| {
        sized(c);
        edit(c);
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| crate::client::pictures(e).len() >= 5)
        .await;
    (env, c)
}

impl Env {
    pub fn bridge(&self) -> &BridgeHandle {
        self.bridge.as_ref().unwrap()
    }

    pub fn metrics(&self) -> &Metrics {
        self.bridge().metrics()
    }

    pub fn client(&self, opts: Opts) -> Client {
        Client::connect(self.rdp, opts)
    }

    pub fn logins(&self) -> u64 {
        self.sim.stats().logins_ok
    }

    /// The current websocket, once its session-start frames (`SET_MODE`,
    /// `KBD_ZERO`) are on the wire. Push HID through `bridge().hid()` only
    /// after this: the writer discards whatever is queued when it starts
    /// a websocket (`drive()`'s `discard_queued()`), so an earlier push
    /// races it (P47).
    pub async fn hid_ready(&self) -> u64 {
        let ready = |l: &[SimEvent]| {
            ws_opens(l)
                .last()
                .is_some_and(|ws| hid_on(l, *ws).len() >= 2)
        };
        let log = self
            .sim
            .wait_for(T, ready)
            .await
            .unwrap_or_else(|l| panic!("no websocket session start within {T:?}: {l:?}"));
        *ws_opens(&log).last().unwrap()
    }

    /// `hid_ready` for a websocket opened after the first `opens` (a
    /// reopen, or a new session's): it waits for that one, never an older.
    pub async fn hid_ready_after(&self, opens: usize) -> u64 {
        let ready = |l: &[SimEvent]| {
            let o = ws_opens(l);
            o.len() > opens && o.last().is_some_and(|ws| hid_on(l, *ws).len() >= 2)
        };
        let log =
            self.sim.wait_for(T, ready).await.unwrap_or_else(|l| {
                panic!("no websocket after the first {opens} within {T:?}: {l:?}")
            });
        *ws_opens(&log).last().unwrap()
    }

    pub async fn shutdown(&mut self) {
        if let Some(b) = self.bridge.take() {
            tokio::time::timeout(T, b.shutdown())
                .await
                .expect("§5.2: shutdown is bounded");
        }
    }

    /// The bridge, for a case that shuts it down its own way.
    pub fn take_bridge(&mut self) -> BridgeHandle {
        self.taken = true;
        self.bridge.take().unwrap()
    }

    /// One admin request: (status, body).
    pub async fn get(&self, path: &str) -> (u16, String) {
        let mut s = tokio::time::timeout(T, tokio::net::TcpStream::connect(self.admin))
            .await
            .unwrap()
            .unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: l2\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(T, s.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        (status, body)
    }
}

impl Drop for Env {
    /// The bridge stops first. Dropping its handle shuts its KVM runtime
    /// down in the background, so wait until the admin listener — a task on
    /// that runtime — refuses: by then the runtime polls nothing more, so
    /// the KVM actor and the certificate watcher never see kvm-sim or the
    /// config directory vanish (both drop after this, as fields). §3.2's
    /// check comes last, so it covers the teardown too.
    fn drop(&mut self) {
        drop(self.bridge.take());
        let stopped = self.taken || refuses_within(self.admin, T);
        if std::thread::panicking() {
            return;
        }
        assert!(
            stopped,
            "the bridge's KVM runtime outlived its handle by {T:?}"
        );
        assert_eq!(
            self.sim.stats().logouts,
            0,
            "§3.2: the bridge never logs out"
        );
    }
}

/// Whether a TCP connect to `addr` is refused within `limit` (blocking; a
/// listener on a private loopback address, so no neighbour can hold it).
pub fn refuses_within(addr: SocketAddr, limit: Duration) -> bool {
    let t0 = Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(&addr, ms(100)).is_err() {
            return true;
        }
        if t0.elapsed() > limit {
            return false;
        }
        std::thread::sleep(ms(2));
    }
}

/// Poll `f` every 10 ms until it holds or `timeout` passes.
pub async fn until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    loop {
        if f() {
            return true;
        }
        if t0.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(ms(10)).await;
    }
}

/// §11.1's one-sided bound: within 5× the configured value, not before 0.5×.
pub fn within(took: Duration, configured: Duration) {
    assert!(
        took >= configured / 2 && took <= configured * 5,
        "took {took:?} for a configured {configured:?}"
    );
}

pub fn flv_opens(log: &[SimEvent]) -> Vec<u64> {
    log.iter()
        .filter_map(|e| {
            if let SimEvent::FlvOpen { conn } = e {
                Some(*conn)
            } else {
                None
            }
        })
        .collect()
}

pub fn ws_opens(log: &[SimEvent]) -> Vec<u64> {
    log.iter()
        .filter_map(|e| {
            if let SimEvent::WsOpen { conn } = e {
                Some(*conn)
            } else {
                None
            }
        })
        .collect()
}

/// Every HID frame kvm-sim received on websocket `conn`, in order.
pub fn hid_on(log: &[SimEvent], conn: u64) -> Vec<Vec<u8>> {
    log.iter()
        .filter_map(|e| match e {
            SimEvent::Hid { conn: c, bytes } if *c == conn => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// Every HID frame kvm-sim received on websocket `conn`, with the instant
/// it recorded it, in order.
pub fn hid_stamped(sim: &KvmSim, conn: u64) -> Vec<(Instant, Vec<u8>)> {
    sim.stamped_events()
        .into_iter()
        .filter_map(|(at, e)| match e {
            SimEvent::Hid { conn: c, bytes } if c == conn => Some((at, bytes)),
            _ => None,
        })
        .collect()
}

/// A slice NAL with any trailing zero bytes trimmed (§6.2 trims them).
fn key(nal: &[u8]) -> Vec<u8> {
    let end = nal.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    nal[..end].to_vec()
}

fn first_slice<'a>(nals: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    key(nals
        .into_iter()
        .find(|n| matches!(n[0] & 0x1F, 1 | 5))
        .unwrap())
}

/// The oracle (§11.1), independent of the bridge: a fixture's frames by
/// first slice NAL → barcode index. Every frame must be distinct.
pub fn barcodes(fixture: &str) -> HashMap<Vec<u8>, usize> {
    let src = source(fixture);
    let map: HashMap<_, _> = src
        .frames
        .iter()
        .map(|f| (first_slice(f.nals.iter().map(|n| &n[..])), f.index))
        .collect();
    assert_eq!(
        map.len(),
        src.frames.len(),
        "{fixture}: the frames are not distinct"
    );
    map
}

/// A received picture's barcode index.
pub fn index_of(map: &HashMap<Vec<u8>, usize>, annex_b: &[u8]) -> usize {
    map[&first_slice(split_annex_b(annex_b))]
}

/// The `source_index` of every AU kvm-sim sent on FLV `conn`, in order.
pub fn sent_on(log: &[SimEvent], conn: u64) -> Vec<usize> {
    log.iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu {
                conn: c,
                source_index,
                ..
            } if *c == conn => Some(*source_index),
            _ => None,
        })
        .collect()
}

/// `got` (the client's pictures as barcode indices) is one contiguous run
/// of `sent` (kvm-sim's AUs on one FLV), from `got[0]`'s first occurrence:
/// nothing dropped, reordered, duplicated or from another connection.
pub fn assert_run(got: &[usize], sent: &[usize], what: &str) {
    let start = sent
        .iter()
        .position(|i| *i == got[0])
        .unwrap_or_else(|| panic!("{what}: picture {} was never sent", got[0]));
    assert!(
        sent.len() >= start + got.len(),
        "{what}: more pictures than AUs sent ({} vs {})",
        got.len(),
        sent.len() - start
    );
    assert_eq!(got, &sent[start..start + got.len()], "{what}");
}
