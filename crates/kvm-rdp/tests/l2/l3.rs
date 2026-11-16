//! L3 interop (spec §11.4; Plan E Tasks 3.1–3.2): the bridge binary and
//! FreeRDP 3 (the flake's, built with OpenH264) as subprocesses, kvm-sim in
//! process; FreeRDP under `xvfb-run` with `-fbdir`, so a case reads back
//! the picture FreeRDP decoded. `#[ignore]`d — they need the flake's tools:
//!   nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1
//! CI's `check` job puts `nix build .#l3-tools` on PATH (Task 3.2).
//! Oracles (§11.4): no H.264 error in FreeRDP's log at WARN; the
//! framebuffer's barcode advancing and equal to a frame kvm-sim sent; the
//! bridge's metrics.
use crate::admin::{Bin, http_get};
use crate::harness::{NLA, T, USER, edit_toml, es3, ms, write_files};
use crate::xwd::{Framebuffer, Group, barcode};
use kvm_sim::{KvmSim, SimEvent};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The ES3-shaped fixture's barcode: 16 blocks of 40×32 across the top
/// (scripts/gen-fixtures.sh `es3like`).
const BLOCK: (u32, u32) = (40, 32);
/// §11.4 oracle 1, matched case-insensitively.
const FORBIDDEN: [&str; 3] = ["avc420_decompress failure", "rdpgfx_decode failed", "h264"];
/// MS-RDPEGFX's CAPVERSION_81.
pub const V8_1: f64 = 524_549.0;
/// MS-RDPEGFX's CAPVERSION_107.
pub const V10_7: f64 = 657_153.0;

/// The first line `xfreerdp /version` prints: the ladder fixture's header
/// names the FreeRDP that recorded it.
fn freerdp_version() -> String {
    let out = Command::new("xfreerdp")
        .arg("/version")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// One L3 case's processes and files. Fields drop in declaration order:
/// FreeRDP's group (and the Xvfb under it) first, so a failing case never
/// leaves FreeRDP and Xvfb running for up to 2 s after the bridge, kvm-sim
/// and the directories holding their logs are gone.
pub struct L3 {
    freerdp: Option<Group>,
    pub sim: KvmSim,
    dir: tempfile::TempDir,
    fb: tempfile::TempDir,
    pub bin: Bin,
    pub rdp: SocketAddr,
}

/// §11.4's tools on PATH, or a message saying how to get them.
fn require_tools() {
    for tool in ["xvfb-run", "xfreerdp"] {
        let found = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()));
        assert!(
            found,
            "L3 needs {tool} on PATH: run it in `nix develop`, or put `nix build .#l3-tools`'s bin/ first"
        );
    }
}

impl L3 {
    /// kvm-sim (the ES3 profile over the ES3-shaped fixture, real time) and
    /// the bridge binary over it: a 640×360 desktop, the advertised-sets
    /// line on, and `video` TOML lines added to `[video]`.
    pub async fn start(video: &str) -> L3 {
        require_tools();
        let sim = KvmSim::start(es3()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_files(&sim, dir.path());
        edit_toml(
            dir.path(),
            "[video]\n",
            &format!("[video]\ndefault_size = \"640x360\"\n{video}"),
        );
        let toml = dir.path().join("kvm-rdp.toml");
        let text = std::fs::read_to_string(&toml).unwrap();
        std::fs::write(
            &toml,
            format!("{text}[log]\nfilter = \"info,kvm_rdp::rdp::gfx=debug\"\n"),
        )
        .unwrap();
        let mut bin = Bin::spawn(dir.path(), &[]);
        let rdp = bin.ready().await;
        L3 {
            freerdp: None,
            sim,
            dir,
            fb: tempfile::tempdir().unwrap(),
            bin,
            rdp,
        }
    }

    /// FreeRDP against the bridge, under Xvfb, in its own process group,
    /// stdout and stderr to `freerdp.log`, its config in a throwaway HOME.
    /// `xvfb-run -d` lets Xvfb pick a free display itself (`-displayfd`; the
    /// deprecated `-a` scans lock files and races a concurrent run), and the
    /// display is ready when xvfb-run resumes, so `-w 0` drops its 3 s
    /// sleep; Xvfb's own output goes to `xvfb.log` (`-e`). Nothing of the
    /// group's lands outside the case (PE8 review I2): `TMPDIR` is the case's
    /// directory (xvfb-run's Xauthority and pid files, anything FreeRDP
    /// makes), and `-clipboard` — L3 never pastes — spares FreeRDP's
    /// clipboard FUSE mount.
    pub fn freerdp(&mut self, args: &[&str]) {
        let log = std::fs::File::create(self.dir.path().join("freerdp.log")).unwrap();
        let home = self.dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let mut cmd = Command::new("xvfb-run");
        cmd.arg("-d")
            .arg("-e")
            .arg(self.dir.path().join("xvfb.log"))
            .args(["-w", "0"])
            .arg("-s")
            .arg(format!(
                "-screen 0 1280x720x24 -fbdir {}",
                self.fb.path().display()
            ))
            .arg("xfreerdp")
            .arg(format!("/v:{}:{}", self.rdp.ip(), self.rdp.port()))
            .arg(format!("/u:{USER}"))
            .arg(format!("/p:{NLA}"))
            .args(["/cert:ignore", "/log-level:WARN", "-clipboard"])
            .args(args)
            // A session's LD_LIBRARY_PATH can carry an alsa-lib FreeRDP
            // cannot load (spikes/legb-winapp/README.md).
            .env_remove("LD_LIBRARY_PATH")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("TMPDIR", self.dir.path())
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        self.freerdp = Some(Group::spawn(cmd).unwrap());
    }

    /// The bridge is sending FreeRDP pictures: `kvm_rdp_egfx_frames_sent_total`
    /// at least 1, polled every 200 ms within `limit` (the slate is not
    /// counted, only KVM frames). Every picture wait comes after it: before
    /// it, the framebuffer is Xvfb's root or FreeRDP's empty window. On a
    /// timeout, FreeRDP's, Xvfb's and the bridge's logs — a session the
    /// bridge ends (`no_avc420`, §6.7) shows in FreeRDP's only as
    /// ERRINFO_SERVER_DENIED_CONNECTION.
    pub async fn streaming(&self, limit: Duration) {
        let t0 = Instant::now();
        loop {
            let sent = sample(&self.metrics().await, "kvm_rdp_egfx_frames_sent_total");
            if sent.is_some_and(|n| n >= 1.0) {
                return;
            }
            assert!(
                t0.elapsed() <= limit,
                "the bridge sent FreeRDP no frame within {limit:?}; FreeRDP said:\n{}\nXvfb said:\n{}\nthe bridge said:\n{}",
                self.freerdp_log(),
                self.xvfb_log(),
                self.bin.lines().join("\n")
            );
            tokio::time::sleep(ms(200)).await;
        }
    }

    /// The framebuffer's barcode, once it reads clean and non-zero, within
    /// `limit`; on a timeout the framebuffer is kept beside FreeRDP's and
    /// Xvfb's logs for diagnosis. A reading of 0 is skipped: black is
    /// Xvfb's root, FreeRDP's empty window and frame 0 alike (`xwd.rs`'s
    /// barcode test), and frame 0 recurs every 4 s, so skipping it costs at
    /// most one frame. The `Instant` is taken just after the read, so any
    /// frame the picture shows was sent before it, however long the test
    /// thread waited between the two (PE8 review I1).
    pub async fn barcode_within(&self, limit: Duration) -> (u16, Instant) {
        let path = self.fb.path().join("Xvfb_screen0");
        let t0 = Instant::now();
        loop {
            let fb = Framebuffer::read(&path);
            let at = Instant::now();
            if let Some(b) = fb
                .and_then(|f| barcode(&f, 0, 0, BLOCK.0, BLOCK.1))
                .filter(|b| *b != 0)
            {
                return (b, at);
            }
            if t0.elapsed() > limit {
                let kept = std::env::temp_dir()
                    .join(format!("kvm-rdp-l3-framebuffer-{}.xwd", std::process::id()));
                let _ = std::fs::copy(&path, &kept);
                panic!(
                    "no clean non-zero barcode within {limit:?}; framebuffer kept at {}; FreeRDP said:\n{}\nXvfb said:\n{}",
                    kept.display(),
                    self.freerdp_log(),
                    self.xvfb_log()
                );
            }
            tokio::time::sleep(ms(200)).await;
        }
    }

    /// kvm-sim sent the frame whose barcode is `b` in the `window` before `at`.
    pub fn sim_sent(&self, b: u16, at: Instant, window: Duration) -> bool {
        self.sim.stamped_events().iter().any(|(t, e)| {
            matches!(e, SimEvent::FlvAu { source_index, .. } if *source_index == usize::from(b))
                && *t <= at
                && at.saturating_duration_since(*t) <= window
        })
    }

    pub async fn metrics(&self) -> String {
        http_get(self.bin.admin(), "/metrics").await
    }

    /// The sets the bridge last logged a client advertising (census notation).
    pub fn advertised(&self) -> Vec<String> {
        self.bin
            .lines()
            .iter()
            .rev()
            .find_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v["fields"]["message"] != "EGFX capabilities advertised" {
                    return None;
                }
                v["fields"]["sets"].as_str().map(str::to_owned)
            })
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    }

    pub fn freerdp_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("freerdp.log")).unwrap_or_default()
    }

    /// Xvfb's own output (`xvfb-run -e`): kept while xvfb-run runs;
    /// xvfb-run's cleanup truncates it when the command exits by itself —
    /// FreeRDP's log then names a display failure (`failed to open display`).
    pub fn xvfb_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("xvfb.log")).unwrap_or_default()
    }

    pub fn freerdp_running(&mut self) -> bool {
        self.freerdp.as_mut().is_some_and(Group::running)
    }

    /// FreeRDP's leader's own exit (a refused connection), within `limit`.
    pub fn freerdp_exit(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        self.freerdp.as_mut().and_then(|g| g.wait_exit(limit))
    }

    /// End FreeRDP's group, then §11.4 oracle 1 over everything it logged.
    pub fn stop_and_check_freerdp_log(&mut self) {
        self.freerdp = None;
        let log = self.freerdp_log().to_lowercase();
        for f in FORBIDDEN {
            assert!(!log.contains(f), "FreeRDP logged {f:?}:\n{log}");
        }
    }
}

/// A series' value in a `/metrics` body.
pub fn sample(body: &str, series: &str) -> Option<f64> {
    body.lines().find_map(|l| {
        l.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

/// §11.4 oracles 1–3 with `/gfx:AVC420`, and the advertise equal to
/// `census.md`'s FreeRDP pair (Legs B and C ran 3.31.1; the flake has
/// 3.32.1, DE9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_decodes_the_es3_stream_through_the_bridge() {
    let mut l3 = L3::start("").await;
    l3.freerdp(&["/sec:nla", "/gfx:AVC420"]);
    l3.streaming(Duration::from_secs(20)).await;
    let (b1, t1) = l3.barcode_within(T).await;
    let m1 = l3.metrics().await;
    tokio::time::sleep(ms(1100)).await;
    let (b2, t2) = l3.barcode_within(T).await;
    let m2 = l3.metrics().await;
    assert_ne!(b1, b2, "the picture did not advance in {:?}", t2 - t1);
    for (b, at) in [(b1, t1), (b2, t2)] {
        assert!(
            l3.sim_sent(b, at, ms(1500)),
            "barcode {b} is no frame kvm-sim sent in the 1.5 s before"
        );
    }
    assert_eq!(sample(&m2, "kvm_rdp_egfx_capability_version"), Some(V8_1));
    for series in [
        "kvm_rdp_egfx_frames_acked_total",
        "kvm_rdp_egfx_client_frames_decoded",
    ] {
        assert!(
            sample(&m2, series) > sample(&m1, series),
            "{series} did not advance"
        );
    }
    assert_eq!(l3.advertised(), ["00080004:02000000", "00080105:12000000"]);
    assert!(
        l3.freerdp_running(),
        "FreeRDP exited:\n{}",
        l3.freerdp_log()
    );
    l3.stop_and_check_freerdp_log();
    assert_eq!(l3.sim.stats().logouts, 0);
}

/// §11.4's second run: `/gfx:AVC420,frame-ack:off` suspends acks (§6.6) —
/// not §11.4's original `/gfx:frame-ack:off`, which FreeRDP 3.32.1 sends
/// with AVC420 off in every set, so the bridge ends it `no_avc420` (DE21,
/// spec rev 6.4). Frames keep flowing and the picture keeps moving, with
/// the stall timer scaled to 2 s, for three times that once acks are
/// suspended — a bridge that waited for acks would close the session as
/// client_stalled inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_suspending_acks_keeps_the_picture_moving() {
    let mut l3 = L3::start("stall_timeout = \"2s\"\n").await;
    l3.freerdp(&["/sec:nla", "/gfx:AVC420,frame-ack:off"]);
    l3.streaming(Duration::from_secs(20)).await;
    // The 6 s window starts once the suspension is in force, not before.
    let t0 = Instant::now();
    while sample(&l3.metrics().await, "kvm_rdp_egfx_ack_suspended") != Some(1.0) {
        assert!(
            t0.elapsed() < T,
            "acks never suspended:\n{}",
            l3.freerdp_log()
        );
        tokio::time::sleep(ms(200)).await;
    }
    let m1 = l3.metrics().await;
    let (b1, _) = l3.barcode_within(T).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (b2, t2) = l3.barcode_within(T).await;
    let m2 = l3.metrics().await;
    assert_eq!(
        sample(&m2, "kvm_rdp_egfx_ack_suspended"),
        Some(1.0),
        "acks never suspended"
    );
    // Nothing is recorded while acks are suspended: a bridge that kept
    // waiting on them reads the oldest unacked frame's age here (PE9 m1).
    assert_eq!(
        sample(&m2, "kvm_rdp_egfx_oldest_unacked_ms"),
        Some(0.0),
        "an unacked frame was recorded while acks were suspended"
    );
    // Frames keep flowing at rate: at least half of 6 s at 30 fps, where a
    // bridge throttled to IDR bursts sends a few dozen.
    let sent = |m: &str| sample(m, "kvm_rdp_egfx_frames_sent_total").unwrap_or(0.0);
    assert!(
        sent(&m2) - sent(&m1) >= 90.0,
        "{} frames sent in 6 s",
        sent(&m2) - sent(&m1)
    );
    assert_ne!(b1, b2, "the picture froze");
    assert!(l3.sim_sent(b2, t2, ms(1500)));
    assert!(
        l3.freerdp_running(),
        "the session ended:\n{}",
        l3.freerdp_log()
    );
    assert!(
        !m2.contains("kvm_rdp_disconnects_total{cause=\"client_stalled\"}"),
        "{m2}"
    );
    l3.stop_and_check_freerdp_log();
}

/// DC8: FreeRDP's full ladder — with no `/gfx` option (its default; census
/// Leg C's "direct run with no `/gfx`") it advertises eleven sets, V8 to
/// V10_7 — byte for byte the committed fixture, which the bridge confirms
/// at V10_7 and serves AVC420 under. Not a bare `/gfx`: FreeRDP 3.32.1
/// then advertises the same eleven versions with AVC420 off in every one
/// (V8_1 without AVC420_ENABLED, V10+ with AVC_DISABLED), a session the
/// bridge ends as `no_avc420` (§6.7). `KVM_RDP_L3_RECORD=1` writes the
/// fixture instead (a new FreeRDP in flake.lock: record, review the diff,
/// commit).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdps_full_ladder_is_the_committed_fixture() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/freerdp-gfx-ladder.txt");
    let mut l3 = L3::start("").await; // require_tools first: its message, not "os error 2"
    let version = format!("# {}", freerdp_version());
    l3.freerdp(&["/sec:nla"]);
    l3.streaming(Duration::from_secs(20)).await;
    l3.barcode_within(T).await;
    let sets = l3.advertised();
    assert_eq!(sets.len(), 11, "{sets:?}");
    if std::env::var_os("KVM_RDP_L3_RECORD").is_some() {
        // The first line names the recording FreeRDP (`xfreerdp /version`),
        // so a re-record after a flake.lock bump labels itself.
        let mut text = format!(
            "{version}\n\
             # The flake's FreeRDP with no `/gfx` option (its default): the 11-set\n\
             # capability ladder it advertises (census.md, Leg C; DC8), one set per\n\
             # line in census notation (version:data, hex). Recorded by L3's\n\
             # freerdps_full_ladder_is_the_committed_fixture with KVM_RDP_L3_RECORD=1.\n",
        );
        for s in &sets {
            text.push_str(s);
            text.push('\n');
        }
        std::fs::write(&fixture, text).unwrap();
    } else {
        let text = std::fs::read_to_string(&fixture).unwrap();
        assert_eq!(
            text.lines().next(),
            Some(version.as_str()),
            "FreeRDP changed: re-record (KVM_RDP_L3_RECORD=1) and review"
        );
        let want: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            sets, want,
            "FreeRDP's ladder changed: re-record (KVM_RDP_L3_RECORD=1) and review"
        );
    }
    let m = l3.metrics().await;
    assert_eq!(sample(&m, "kvm_rdp_egfx_capability_version"), Some(V10_7));
    l3.stop_and_check_freerdp_log();
}

/// §9.1 and §5.1 with a real client: FreeRDP offering TLS without NLA is
/// refused at negotiation, before any KVM traffic — kvm-sim sees no
/// connection at all — and the bridge keeps serving. IronRDP at the pinned
/// rev sends no RDP_NEG_FAILURE (it returns before the write), so FreeRDP
/// sees a plain close: the refusal's one trace is the bridge's own
/// "Connection error" line, which names the mismatch — asserted, so a
/// FreeRDP that failed for any other reason (no display, a bad flag, a
/// missing library) cannot pass for a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_without_nla_is_refused_before_any_kvm_traffic() {
    let mut l3 = L3::start("").await;
    l3.freerdp(&["/sec:tls", "/gfx:AVC420"]);
    let status = l3
        .freerdp_exit(Duration::from_secs(20))
        .expect("FreeRDP kept running");
    assert!(
        !status.success(),
        "FreeRDP connected without NLA:\n{}",
        l3.freerdp_log()
    );
    assert!(
        l3.bin
            .lines()
            .iter()
            .any(|l| l.contains("Connection error") && l.contains("security protocol mismatch")),
        "the bridge logged no refusal; FreeRDP said:\n{}\nXvfb said:\n{}",
        l3.freerdp_log(),
        l3.xvfb_log()
    );
    // FreeRDP 3.32.1 logs `[xf_setup_x11]: failed to open display: :N`,
    // then ERRCONNECT_PRE_CONNECT_FAILED, when it never got a display.
    let log = l3.freerdp_log();
    let lower = log.to_lowercase();
    for no_display in ["failed to open display", "errconnect_pre_connect_failed"] {
        assert!(
            !lower.contains(no_display),
            "FreeRDP never ran against the bridge:\n{log}"
        );
    }
    let s = l3.sim.stats();
    assert_eq!(
        (s.accepts_web, s.accepts_video, s.accepts_control),
        (0, 0, 0),
        "{s:?}"
    );
    http_get(l3.bin.admin(), "/readyz").await; // asserts the 200 itself
    l3.stop_and_check_freerdp_log();
}
