use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::captures::CaptureDir;

/// Build the `nice -n 19 bwrap … ffmpeg …` argv that decodes a capture's first
/// frame to a raw Y/UV plane in the decoder's native pix_fmt, with no scaler
/// (§12). `capture_name`/`out_name` must already be CaptureDir-validated
/// simple names.
pub fn build_ffmpeg_sandbox_argv(
    ffmpeg: &Path,
    cap_host_dir: &Path,
    capture_name: &str,
    out_name: &str,
) -> Vec<String> {
    let cap_in = format!("/cap/{capture_name}");
    let cap_out = format!("/cap/{out_name}");
    vec![
        "nice".to_string(),
        "-n".to_string(),
        "19".to_string(),
        "bwrap".to_string(),
        "--unshare-all".to_string(),
        "--die-with-parent".to_string(),
        "--clearenv".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "--ro-bind".to_string(),
        "/nix".to_string(),
        "/nix".to_string(),
        "--bind".to_string(),
        cap_host_dir.to_string_lossy().into_owned(),
        "/cap".to_string(),
        "--chdir".to_string(),
        "/cap".to_string(),
        "--".to_string(),
        ffmpeg.to_string_lossy().into_owned(),
        "-hide_banner".to_string(),
        "-nostdin".to_string(),
        "-y".to_string(),
        "-threads".to_string(),
        "4".to_string(),
        "-loglevel".to_string(),
        "verbose".to_string(),
        "-i".to_string(),
        cap_in,
        "-map".to_string(),
        "0:v:0".to_string(),
        "-frames:v".to_string(),
        "1".to_string(),
        "-f".to_string(),
        "rawvideo".to_string(),
        cap_out,
    ]
}

/// True if ffmpeg's verbose log shows swscale or an auto-inserted scale filter.
pub fn ffmpeg_inserted_scaler(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("swscaler") || s.contains("auto_scale")
}

/// Min/max of the Y plane (first `width*height` bytes) of a planar rawvideo frame.
/// Returns None if the buffer is too short or the plane is empty. Checked throughout:
/// this is semi-trusted sandbox output (decoded from hostile capture bytes), so no
/// indexing or arithmetic that can panic.
pub fn y_plane_range(frame: &[u8], width: usize, height: usize) -> Option<(u8, u8)> {
    let plane_len = width.checked_mul(height)?;
    if plane_len == 0 {
        return None;
    }
    let plane = frame.get(..plane_len)?;
    let mut min = u8::MAX;
    let mut max = u8::MIN;
    for &y in plane {
        if y < min {
            min = y;
        }
        if y > max {
            max = y;
        }
    }
    Some((min, max))
}

/// Outcome of one sandboxed decode-and-measure run (§12 Leg A sample range).
/// `ScalerInserted` is reported in preference to a range: a scaler changed
/// the pixels, so any min/max would describe ffmpeg's resampler, not the
/// device. `NoPlane` means the frame was too short to contain the Y plane.
#[derive(Debug)]
pub enum SampleOutcome {
    ScalerInserted,
    Decoded { y_min: u8, y_max: u8 },
    NoPlane,
}

/// A scaler in the log fails the measurement (§12); otherwise report min/max.
pub fn sample_range_outcome(
    ffmpeg_stderr: &str,
    y_frame: &[u8],
    width: usize,
    height: usize,
) -> SampleOutcome {
    if ffmpeg_inserted_scaler(ffmpeg_stderr) {
        return SampleOutcome::ScalerInserted;
    }
    match y_plane_range(y_frame, width, height) {
        Some((y_min, y_max)) => SampleOutcome::Decoded { y_min, y_max },
        None => SampleOutcome::NoPlane,
    }
}

/// Wall-clock bound on the sandboxed ffmpeg run (§12/§9.2): a hostile
/// capture or a wedged decoder must not hang the census forever. Exceeding
/// it kills the child and fails the run closed.
const FFMPEG_WALL_CLOCK_LIMIT: Duration = Duration::from_secs(120);

/// Cap on captured ffmpeg stderr (§9.2): never buffer an unbounded hostile
/// log.
const STDERR_CAP: usize = 1024 * 1024;

/// How often the wait loop polls the child for exit, while it waits for
/// either completion or the wall-clock limit.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The only process spawn in this module: argv[0] is the sandbox. A spawn
/// failure is returned as-is; there is no unsandboxed fallback. The child is
/// bounded by `FFMPEG_WALL_CLOCK_LIMIT` — exceeding it kills the child and
/// returns an error rather than waiting forever — and its stderr is read on
/// a separate thread, capped at `STDERR_CAP` bytes, so neither a slow exit
/// nor a chatty hostile decode can hang or unbound this call.
fn run_argv(argv: &[String]) -> std::io::Result<Output> {
    let (head, tail) = argv
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty argv"))?;
    let mut child = Command::new(head)
        .args(tail)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("no stderr pipe"))?;
    let cap = u64::try_from(STDERR_CAP).unwrap_or(u64::MAX);
    // Read stderr on its own thread so a child that fills the pipe while
    // the wait loop below is polling can't deadlock this call.
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut limited = stderr_pipe.take(cap);
        let _ = limited.read_to_end(&mut buf);
        buf
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= FFMPEG_WALL_CLOCK_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other(format!(
                "sandboxed ffmpeg exceeded the {FFMPEG_WALL_CLOCK_LIMIT:?} wall-clock limit; killed"
            )));
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let stderr = stderr_handle.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout: Vec::new(),
        stderr,
    })
}

/// Resolve `ffmpeg` on PATH to its canonical store path (the sandbox binds only /nix).
pub fn resolve_ffmpeg() -> std::io::Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or_else(|| std::io::Error::other("PATH unset"))?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("ffmpeg");
        if candidate.is_file() {
            let real = std::fs::canonicalize(&candidate)?;
            if real.starts_with("/nix/") {
                return Ok(real);
            }
            return Err(std::io::Error::other(format!(
                "ffmpeg at {} is outside /nix; run inside the devshell",
                real.display()
            )));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "ffmpeg not on PATH",
    ))
}

/// Remove whatever is at `path` — file or symlink — without following it
/// (`remove_file` unlinks the directory entry itself, never the symlink's
/// target), so a stale output or a link planted by a previous compromised
/// run can't be read back as this run's frame. Quiet if nothing is there.
fn remove_stale_output(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Open `path` host-side without ever following a symlink (`O_NOFOLLOW`
/// fails the open if `path` is itself a symlink — the rw-mounted captures
/// dir is where a compromised sandboxed ffmpeg could have planted one), and
/// read at most `max_len + 1` bytes: enough to know the data is at least
/// `max_len` bytes (what the Y-plane measurement needs) without ever
/// buffering an unbounded hostile file.
fn read_capped_no_symlink(path: &Path, max_len: usize) -> std::io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let cap = u64::try_from(max_len.saturating_add(1)).unwrap_or(u64::MAX);
    let mut limited = file.take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Spawn the sandbox, enforce no scaler, read the native Y-plane range. Live only.
///
/// `capture_name` and the derived output name are validated through
/// `CaptureDir::resolve` before anything is spawned — only the validated
/// `&str` names (never `resolve`'s host `PathBuf`) are handed to
/// `build_ffmpeg_sandbox_argv`, which maps them to fixed `/cap/<name>` paths
/// inside the sandbox.
pub fn run_sample_range(
    ffmpeg: &Path,
    dir: &CaptureDir,
    capture_name: &str,
    width: usize,
    height: usize,
) -> std::io::Result<SampleOutcome> {
    let cap_in_host = dir.resolve(capture_name)?;
    let out_name = format!("{capture_name}.y");
    let out_host = dir.resolve(&out_name)?;

    let cap_host_dir = cap_in_host
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("no capture dir"))?;

    remove_stale_output(&out_host)?;

    let argv = build_ffmpeg_sandbox_argv(ffmpeg, &cap_host_dir, capture_name, &out_name);
    let output = run_argv(&argv)?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "sandboxed ffmpeg failed: {stderr}"
        )));
    }

    let plane_len = width
        .checked_mul(height)
        .ok_or_else(|| std::io::Error::other("width*height overflow"))?;
    let frame = read_capped_no_symlink(&out_host, plane_len)?;
    Ok(sample_range_outcome(&stderr, &frame, width, height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn outcome_fails_closed_on_scaler_even_with_bytes() {
        let frame = [10u8, 240, 10, 240, 10, 240, 10, 240];
        assert!(matches!(
            sample_range_outcome("[swscaler @ 0x1] converting", &frame, 4, 2),
            SampleOutcome::ScalerInserted
        ));
    }

    #[test]
    fn outcome_reports_range_when_clean() {
        let frame = [16u8, 235, 16, 235, 16, 235, 16, 235];
        assert!(matches!(
            sample_range_outcome("clean verbose log", &frame, 4, 2),
            SampleOutcome::Decoded {
                y_min: 16,
                y_max: 235
            }
        ));
        assert!(matches!(
            sample_range_outcome("clean", &[0, 1], 4, 2),
            SampleOutcome::NoPlane
        ));
    }

    #[test]
    fn missing_sandbox_binary_fails_closed() {
        let argv = vec![
            "/nonexistent/bwrap".to_string(),
            "--".to_string(),
            "ffmpeg".to_string(),
        ];
        let err = run_argv(&argv).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_argv_is_an_error_not_a_panic() {
        assert!(run_argv(&[]).is_err());
    }

    /// A fresh, uniquely-named base dir for one test (never created on disk here).
    fn tmp_base(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kvm-probe-sandbox-{}-{label}", std::process::id()));
        p
    }

    #[test]
    fn read_capped_no_symlink_refuses_a_symlink() {
        let base = tmp_base("symlink");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let real = base.join("real.y");
        std::fs::write(&real, [1u8, 2, 3]).unwrap();
        let link = base.join("link.y");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let result = read_capped_no_symlink(&link, 10);
        assert!(result.is_err(), "a symlink must never be followed");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_capped_no_symlink_bounds_the_read() {
        let base = tmp_base("cap");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("big.y");
        std::fs::write(&path, vec![7u8; 1000]).unwrap();

        let bytes = read_capped_no_symlink(&path, 10).unwrap();
        assert_eq!(
            bytes.len(),
            11,
            "read must stop at max_len+1, never buffer the whole file"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_capped_no_symlink_reads_a_short_file_fully() {
        let base = tmp_base("short");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("small.y");
        std::fs::write(&path, [9u8, 8, 7]).unwrap();

        let bytes = read_capped_no_symlink(&path, 10).unwrap();
        assert_eq!(bytes, vec![9u8, 8, 7]);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn remove_stale_output_is_quiet_when_nothing_is_there() {
        let base = tmp_base("missing");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("nope.y");
        assert!(remove_stale_output(&path).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn remove_stale_output_removes_a_planted_symlink_without_following_it() {
        let base = tmp_base("stale-symlink");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let victim = base.join("victim");
        std::fs::write(&victim, b"do not touch").unwrap();
        let out = base.join("out.y");
        std::os::unix::fs::symlink(&victim, &out).unwrap();

        assert!(remove_stale_output(&out).is_ok());
        assert!(!out.exists(), "the stale link must be gone");
        assert!(
            victim.exists(),
            "unlinking the link must not touch its target"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[ignore = "live: needs bwrap+ffmpeg from the devshell and a real capture under captures/"]
    fn live_sample_range() {
        // Run (inside `nix develop`):
        //   cargo test -p kvm-probe --lib sandbox::tests::live_sample_range -- --ignored --nocapture
        // Precondition: captures/ramp.flv recorded by `kvm-probe capture` with the ramp on screen.
        let captures_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../captures"));
        let ffmpeg = resolve_ffmpeg().unwrap();
        let dir = CaptureDir::create(captures_dir).unwrap();
        let outcome = run_sample_range(&ffmpeg, &dir, "ramp.flv", 1920, 1080).unwrap();
        eprintln!("sample-range: {outcome:?}");
        assert!(!matches!(outcome, SampleOutcome::ScalerInserted));
    }

    #[test]
    fn argv_is_exact_and_has_no_scaler() {
        let argv = build_ffmpeg_sandbox_argv(
            Path::new("/nix/store/abc-ffmpeg/bin/ffmpeg"),
            Path::new("/home/chris/Repos/kvm-rdp/captures"),
            "ramp-1080p60.flv",
            "ramp-1080p60.y",
        );
        assert_eq!(
            argv,
            vec![
                "nice",
                "-n",
                "19",
                "bwrap",
                "--unshare-all",
                "--die-with-parent",
                "--clearenv",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--ro-bind",
                "/nix",
                "/nix",
                "--bind",
                "/home/chris/Repos/kvm-rdp/captures",
                "/cap",
                "--chdir",
                "/cap",
                "--",
                "/nix/store/abc-ffmpeg/bin/ffmpeg",
                "-hide_banner",
                "-nostdin",
                "-y",
                "-threads",
                "4",
                "-loglevel",
                "verbose",
                "-i",
                "/cap/ramp-1080p60.flv",
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-f",
                "rawvideo",
                "/cap/ramp-1080p60.y",
            ]
        );
        // No scaler, no explicit pixel format, no filtergraph.
        assert!(
            !argv
                .iter()
                .any(|a| a == "-vf" || a == "-pix_fmt" || a.contains("scale"))
        );
        // Network namespace is unshared.
        assert!(argv.contains(&"--unshare-all".to_string()));
    }

    #[test]
    fn scaler_detected_from_swscale_tags() {
        assert!(ffmpeg_inserted_scaler(
            "[swscaler @ 0x5563] deprecated pixel format used"
        ));
        assert!(ffmpeg_inserted_scaler(
            "Stream mapping:\n  auto_scale_0 (scale)"
        ));
        assert!(!ffmpeg_inserted_scaler(
            "Input #0, flv\nStream #0:0: Video: h264 (High), yuv420p\nframe=    1 fps=0.0"
        ));
    }

    #[test]
    fn y_plane_min_max_over_first_frame() {
        // width=4 height=2 -> 8 Y bytes, rest is chroma we ignore.
        let frame = [0u8, 255, 10, 20, 30, 40, 50, 16, 128, 128, 128, 128];
        assert_eq!(y_plane_range(&frame, 4, 2), Some((0, 255)));
        // too short -> None, never panics.
        assert_eq!(y_plane_range(&[0, 1, 2], 4, 2), None);
        // zero-size -> None.
        assert_eq!(y_plane_range(&frame, 0, 2), None);
    }
}
