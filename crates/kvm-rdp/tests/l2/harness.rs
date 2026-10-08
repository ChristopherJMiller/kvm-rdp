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
use kvm_rdp::bridge::{self, BridgeHandle};
use kvm_rdp::config::Config;
use kvm_rdp::metrics::Metrics;
use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const USER: &str = "kvm";
/// The NLA password — and the secrets case's canary (§11.3).
pub const NLA: &str = "l2-canary-7f3a9c2e5b1d4a6f8e0c";
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

/// The fixtures' size as the default: no connect-time resize, no slate.
pub fn sized(c: &mut Config) {
    c.video.default_size = (640, 360);
}

/// A deployment's files in `dir`: the secrets, a fresh TLS pair, and a
/// config for `sim` with ephemeral loopback listeners, scaled per §11.1.
pub fn write_files(sim: &KvmSim, dir: &Path) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    std::fs::write(dir.join("nla.pass"), format!("{NLA}\n")).unwrap();
    std::fs::write(dir.join("kvm.pass"), format!("{}\n", sim.password())).unwrap();
    let p = sim.ports();
    let toml = format!(
        "[rdp]\nlisten = \"127.0.0.1:0\"\nusername = \"{USER}\"\nnla_password_file = \"nla.pass\"\n\
         tls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\n\
         [admin]\nlisten = \"127.0.0.1:0\"\nliveness_timeout = \"1s\"\n\
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
    Env {
        rdp: bridge.rdp_addr,
        admin: bridge.admin_addr,
        sim,
        dir,
        bridge: Some(bridge),
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

    pub async fn shutdown(&mut self) {
        if let Some(b) = self.bridge.take() {
            tokio::time::timeout(T, b.shutdown())
                .await
                .expect("§5.2: shutdown is bounded");
        }
    }

    /// The bridge, for a case that shuts it down its own way.
    pub fn take_bridge(&mut self) -> BridgeHandle {
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
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert_eq!(
                self.sim.stats().logouts,
                0,
                "§3.2: the bridge never logs out"
            );
        }
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
