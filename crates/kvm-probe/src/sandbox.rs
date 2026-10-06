use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::captures::{self, CaptureDir};

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
/// failure is returned as-is; there is no unsandboxed fallback. Delegates
/// to `run_argv_bounded` with the crate's real wall-clock limit and stderr
/// cap (`run_argv_bounded` exists as a seam so a test can use a short limit
/// and a tiny cap instead of the real ones, per I2).
fn run_argv(argv: &[String]) -> std::io::Result<Output> {
    run_argv_bounded(argv, FFMPEG_WALL_CLOCK_LIMIT, STDERR_CAP)
}

/// Spawn `argv`, bounded by `wall_clock_limit` and with stderr capped at
/// `stderr_cap` bytes (I2). The reader thread drains stderr all the way to
/// EOF — past the cap, into a sink — so the child is never SIGPIPE'd by a
/// pipe nobody is reading from any more; if that drain shows the log was
/// longer than the cap, if the read itself failed, or if the reader thread
/// could not be joined, the run fails closed rather than returning
/// whatever partial log it has. A truncated log could have hidden exactly
/// the one line (`ffmpeg_inserted_scaler`'s match) that fails the
/// measurement closed, so a run whose own log can't be fully vouched for
/// is itself a failure, never a silent "clean".
fn run_argv_bounded(
    argv: &[String],
    wall_clock_limit: Duration,
    stderr_cap: usize,
) -> std::io::Result<Output> {
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
    let cap = u64::try_from(stderr_cap).unwrap_or(u64::MAX);
    // Read stderr on its own thread so a child that fills the pipe while
    // the wait loop below is polling can't deadlock this call.
    let stderr_handle = std::thread::spawn(move || -> std::io::Result<(Vec<u8>, bool)> {
        let mut pipe = stderr_pipe;
        let mut buf = Vec::new();
        {
            let mut limited = (&mut pipe).take(cap);
            limited.read_to_end(&mut buf)?;
        }
        // Keep draining to EOF so the child is never SIGPIPE'd by a reader
        // that stopped at the cap; discard the bytes, but remember whether
        // there were any more — that's truncation.
        let mut truncated = false;
        let mut sink = [0u8; 8192];
        loop {
            let n = pipe.read(&mut sink)?;
            if n == 0 {
                break;
            }
            truncated = true;
        }
        Ok((buf, truncated))
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= wall_clock_limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other(format!(
                "sandboxed ffmpeg exceeded the {wall_clock_limit:?} wall-clock limit; killed"
            )));
        }
        std::thread::sleep(POLL_INTERVAL.min(wall_clock_limit));
    };

    let (stderr, truncated) = match stderr_handle.join() {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::other(
                "ffmpeg stderr reader thread panicked",
            ));
        }
    };
    if truncated {
        return Err(std::io::Error::other(format!(
            "ffmpeg stderr exceeded the {stderr_cap}-byte cap; cannot verify no scaler was inserted"
        )));
    }

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

/// How much of ffmpeg's stderr ever reaches the operator's terminal on
/// failure (I4, §9.2): a compromised ffmpeg's log is hostile input, so only
/// a short tail is kept.
const STDERR_TAIL_FOR_DISPLAY: usize = 4 * 1024;

/// Render (a tail of) ffmpeg's stderr for a human terminal: at most the
/// last `STDERR_TAIL_FOR_DISPLAY` bytes, lossily decoded, with every
/// control character other than `\n`/`\t` escaped (`char::is_control`
/// covers C0, DEL and C1 together). A compromised ffmpeg's log is hostile
/// input (§9.2) — without this, raw ESC/OSC bytes in it would reach the
/// operator's terminal verbatim (escape-sequence injection: title/clipboard
/// writes, emulator bugs), and up to a megabyte of it at that (`STDERR_CAP`).
fn sanitize_for_terminal(bytes: &[u8]) -> String {
    let tail_start = bytes.len().saturating_sub(STDERR_TAIL_FOR_DISPLAY);
    let tail = bytes.get(tail_start..).unwrap_or(&[]);
    let text = String::from_utf8_lossy(tail);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
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
    // `run_argv` already fails closed if this log was truncated (I2), so
    // it's complete (and bounded at `STDERR_CAP`) — safe to use whole for
    // the scaler check. Only the *displayed* error below gets the extra
    // tail+escape treatment (I4): that's about what reaches a terminal,
    // not about what the scaler check is allowed to see.
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "sandboxed ffmpeg failed: {}",
            sanitize_for_terminal(&output.stderr)
        )));
    }

    let plane_len = width
        .checked_mul(height)
        .ok_or_else(|| std::io::Error::other("width*height overflow"))?;
    let frame = captures::read_capped(dir, &out_name, plane_len)?;
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

    /// M1: the shipped argv[0] is `nice`, not `bwrap` directly — a missing
    /// `bwrap` surfaces as `nice` exiting 127 (its exec-failure code), which
    /// must land in the non-success branch, never a panic or a false
    /// "success".
    #[test]
    fn nice_wrapped_missing_bwrap_fails_closed_not_panics() {
        let argv = vec![
            "nice".to_string(),
            "-n".to_string(),
            "19".to_string(),
            "/nonexistent/bwrap".to_string(),
            "--".to_string(),
            "x".to_string(),
        ];
        let out = run_argv(&argv).unwrap();
        assert!(
            !out.status.success(),
            "nice exiting 127 for a missing bwrap must not look like success"
        );
    }

    /// I2: a child that outlives the wall-clock limit is killed and the
    /// run fails closed, within the bound — not a multi-second real wait,
    /// since the limit itself is a test-only short one via the
    /// `run_argv_bounded` seam.
    #[test]
    fn run_argv_bounded_kills_a_child_that_outlives_the_limit() {
        let argv = vec!["sleep".to_string(), "30".to_string()];
        let limit = Duration::from_millis(100);
        let started = Instant::now();
        let err = run_argv_bounded(&argv, limit, STDERR_CAP).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            format!("{err}").contains("wall-clock"),
            "expected a wall-clock-limit error, got {err}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "must not wait anywhere near the child's real 30s sleep: took {elapsed:?}"
        );
    }

    /// I2: stderr longer than the cap must fail closed rather than return
    /// a silently truncated ("clean") log — a truncated log could have
    /// hidden the one line that fails the scaler check.
    #[test]
    fn run_argv_bounded_fails_closed_on_truncated_stderr() {
        let base = tmp_base("big-stderr");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let bigfile = base.join("big.txt");
        std::fs::write(&bigfile, vec![b'a'; 200_000]).unwrap();

        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("cat {} >&2", bigfile.display()),
        ];
        let err = run_argv_bounded(&argv, Duration::from_secs(10), 1024).unwrap_err();
        assert!(
            format!("{err}").contains("cap"),
            "expected a stderr-cap error, got {err}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// I4: a hostile ffmpeg's stderr must never reach the operator's
    /// terminal with raw control bytes — this is the one channel a
    /// compromised sandboxed decoder would have into escape-sequence
    /// injection (title/clipboard writes, emulator bugs).
    #[test]
    fn sanitize_for_terminal_escapes_control_bytes_and_keeps_the_text() {
        let input = b"before\x1b]0;evil-title\x07after\n";
        let out = sanitize_for_terminal(input);
        assert!(out.starts_with("before"));
        assert!(out.ends_with("after\n"));
        assert!(
            !out.chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "a raw control byte survived sanitization: {out:?}"
        );
        // The escaped form is still visible (not silently dropped).
        assert!(out.contains("\\u{1b}") || out.contains("1b"), "{out:?}");
    }

    /// I4: only a bounded tail is ever kept, even if the input itself was
    /// within the (already-enforced-elsewhere) stderr cap.
    #[test]
    fn sanitize_for_terminal_keeps_only_a_bounded_tail() {
        let input = vec![b'a'; 3 * STDERR_TAIL_FOR_DISPLAY];
        let out = sanitize_for_terminal(&input);
        assert!(out.len() <= STDERR_TAIL_FOR_DISPLAY);
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
