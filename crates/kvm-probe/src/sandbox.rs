use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::captures::{self, CaptureDir};

/// Build the `nice -n 19 bwrap … ffmpeg …` argv that decodes a capture's first
/// frame to a raw Y/UV plane in the decoder's native pix_fmt, with no scaler
/// (§12). `capture_name`/`out_name` must already be CaptureDir-validated
/// simple names.
///
/// `--new-session` comes first (final review I1): bwrap `setsid`s the
/// sandboxed ffmpeg, so it has no controlling terminal. Without it, `--dev
/// /dev` still exposes `/dev/tty`, and a decoder compromised by a hostile
/// stream could open it and write escape sequences straight to the
/// operator's terminal (bypassing the stderr sanitising below) or, where
/// `dev.tty.legacy_tiocsti` is on, inject keystrokes with `TIOCSTI`
/// (CVE-2017-5226 — the bwrap man page tells callers to pass
/// `--new-session` for exactly this).
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
        "--new-session".to_string(),
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
///
/// `width`/`height` must each lie in `SAMPLE_DIMENSION_RANGE` (checked
/// before anything is resolved or spawned), and the decoded frame must be
/// exactly one 8-bit 4:2:0 frame of that size (`check_frame_layout`).
pub fn run_sample_range(
    ffmpeg: &Path,
    dir: &CaptureDir,
    capture_name: &str,
    width: usize,
    height: usize,
) -> std::io::Result<SampleOutcome> {
    if !SAMPLE_DIMENSION_RANGE.contains(&width) || !SAMPLE_DIMENSION_RANGE.contains(&height) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--width/--height must each be in {}..={} (got {width}x{height})",
                SAMPLE_DIMENSION_RANGE.start(),
                SAMPLE_DIMENSION_RANGE.end()
            ),
        ));
    }
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

    // A scaler is reported in preference to anything about the frame (it
    // changed the pixels, so the frame's size and contents describe
    // ffmpeg's resampler, not the device) — checked before the frame is
    // read, so a scaled frame's size can't turn this into a layout error.
    if ffmpeg_inserted_scaler(&stderr) {
        return Ok(SampleOutcome::ScalerInserted);
    }

    let frame = read_output_frame(dir, &out_name, width, height)?;
    Ok(sample_range_outcome(&stderr, &frame, width, height))
}

/// `sample-range`'s accepted `--width`/`--height`, each (final review m2):
/// never a zero-area or absurd frame, and never a read cap
/// (`FRAME_CAP_PLANE_MULTIPLE` × w × h) past a few hundred MiB.
pub const SAMPLE_DIMENSION_RANGE: std::ops::RangeInclusive<usize> = 16..=8192;

/// The planar layouts a native `rawvideo` frame from ffmpeg's H.264 decoder
/// can have (final review m2). `Bit16` covers every 9–16-bit depth, which
/// rawvideo stores in two bytes per sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanarLayout {
    Yuv420p8,
    Yuv422p8,
    Yuv444p8,
    Yuv420p16,
    Yuv422p16,
    Yuv444p16,
}

impl PlanarLayout {
    const ALL: [PlanarLayout; 6] = [
        PlanarLayout::Yuv420p8,
        PlanarLayout::Yuv422p8,
        PlanarLayout::Yuv444p8,
        PlanarLayout::Yuv420p16,
        PlanarLayout::Yuv422p16,
        PlanarLayout::Yuv444p16,
    ];

    fn name(self) -> &'static str {
        match self {
            PlanarLayout::Yuv420p8 => "8-bit 4:2:0",
            PlanarLayout::Yuv422p8 => "8-bit 4:2:2",
            PlanarLayout::Yuv444p8 => "8-bit 4:4:4",
            PlanarLayout::Yuv420p16 => "16-bit 4:2:0",
            PlanarLayout::Yuv422p16 => "16-bit 4:2:2",
            PlanarLayout::Yuv444p16 => "16-bit 4:4:4",
        }
    }

    /// Exact byte length of one `width`×`height` frame in this layout, as
    /// ffmpeg lays rawvideo out: a full-size Y plane plus two chroma
    /// planes of `ceil(w/2)`×`ceil(h/2)` (4:2:0), `ceil(w/2)`×`h` (4:2:2)
    /// or `w`×`h` (4:4:4), times two bytes per sample for `Bit16`.
    /// `None` only on overflow.
    fn frame_len(self, width: usize, height: usize) -> Option<usize> {
        let luma = width.checked_mul(height)?;
        let half_w = width.div_ceil(2);
        let half_h = height.div_ceil(2);
        let chroma_plane = match self {
            PlanarLayout::Yuv420p8 | PlanarLayout::Yuv420p16 => half_w.checked_mul(half_h)?,
            PlanarLayout::Yuv422p8 | PlanarLayout::Yuv422p16 => half_w.checked_mul(height)?,
            PlanarLayout::Yuv444p8 | PlanarLayout::Yuv444p16 => luma,
        };
        let samples = luma.checked_add(chroma_plane.checked_mul(2)?)?;
        match self {
            PlanarLayout::Yuv420p8 | PlanarLayout::Yuv422p8 | PlanarLayout::Yuv444p8 => {
                Some(samples)
            }
            PlanarLayout::Yuv420p16 | PlanarLayout::Yuv422p16 | PlanarLayout::Yuv444p16 => {
                samples.checked_mul(2)
            }
        }
    }
}

/// Require the decoded frame to be exactly one known planar frame of
/// `width`×`height` — and to be 8-bit 4:2:0, the one layout whose Y range
/// this tool measures (final review m2).
///
/// - A length that is no known layout's size means `--width`/`--height`
///   do not describe this frame: refused, instead of silently measuring
///   part of it (the old behaviour accepted anything up to 6× the plane).
/// - A length that is exactly a *different* known layout's size is named
///   in the error but not measured. That is stricter than measuring every
///   8-bit layout, for two reasons: such a stream is outside §6.1 anyway
///   (summarize's `check_sps_limits` verdict says so), and a size match
///   alone cannot tell layouts apart — a 1920×1080 4:2:0 frame is byte for
///   byte a 1440×1080 4:2:2 frame, and 3× the plane is both 8-bit 4:4:4
///   and 16-bit 4:2:0 — so measuring them could still report a wrong range
///   with no error. For 4:2:0 itself a same-length frame of another
///   `width`×`height` has the same area, so its Y plane is the same bytes
///   and the range is still right.
fn check_frame_layout(len: usize, width: usize, height: usize) -> std::io::Result<PlanarLayout> {
    let matches: Vec<PlanarLayout> = PlanarLayout::ALL
        .into_iter()
        .filter(|l| l.frame_len(width, height) == Some(len))
        .collect();
    if matches.as_slice() == [PlanarLayout::Yuv420p8] {
        return Ok(PlanarLayout::Yuv420p8);
    }
    if matches.is_empty() {
        let known: Vec<String> = PlanarLayout::ALL
            .into_iter()
            .map(|l| match l.frame_len(width, height) {
                Some(n) => format!("{} {n}", l.name()),
                None => format!("{} overflow", l.name()),
            })
            .collect();
        return Err(std::io::Error::other(format!(
            "decoded frame is {len} bytes, which is not a known planar size for \
             {width}x{height} ({}); pass the stream's own size as --width/--height \
             (summarize's SPS width/height)",
            known.join(", ")
        )));
    }
    let names: Vec<&str> = matches.into_iter().map(PlanarLayout::name).collect();
    Err(std::io::Error::other(format!(
        "decoded frame is {len} bytes: the size of a {width}x{height} frame in {}, \
         not 8-bit 4:2:0 — the only layout §6.1 admits and the only one \
         sample-range measures (check summarize's SPS chroma_format_idc/bit depth \
         and width/height)",
        names.join(" or ")
    )))
}

/// Upper bound on a sandbox output frame, as a multiple of the Y plane
/// (R1, a fix-round-1 regression): the sandbox's `rawvideo` output is the
/// *whole* frame in the decoder's native planar pix_fmt — Y plane plus
/// chroma — which for any real planar format is already bigger than the Y
/// plane alone (`plane_len * 3/2` for 4:2:0). Capping the read at exactly
/// `plane_len` (as a fix-round-1 change briefly did) made every real
/// sample-range run fail closed on a legitimate frame. `6` covers the
/// largest native planar pix_fmt in practice — 4:4:4 at 16 bits (3 full-size
/// samples * 2 bytes = 6x the Y plane) — while still refusing anything
/// bigger, never reading unboundedly.
const FRAME_CAP_PLANE_MULTIPLE: usize = 6;

/// Read the sandbox's `.y` output, bounded at
/// `FRAME_CAP_PLANE_MULTIPLE * plane_len` bytes rather than `plane_len`
/// itself (R1), then require it to be exactly one 8-bit 4:2:0 frame of
/// `width`×`height` (`check_frame_layout`, final review m2) —
/// `y_plane_range` (via `sample_range_outcome`) reads the frame's first
/// `plane_len` bytes, which is the whole Y plane only when that holds.
fn read_output_frame(
    dir: &CaptureDir,
    out_name: &str,
    width: usize,
    height: usize,
) -> std::io::Result<Vec<u8>> {
    let plane_len = width
        .checked_mul(height)
        .ok_or_else(|| std::io::Error::other("width*height overflow"))?;
    let frame_cap = plane_len.saturating_mul(FRAME_CAP_PLANE_MULTIPLE);
    let frame = captures::read_capped(dir, out_name, frame_cap)?;
    check_frame_layout(frame.len(), width, height)?;
    Ok(frame)
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

    /// R1 (fix-round-1 regression): the sandbox's `rawvideo` output is the
    /// *whole* frame — Y plane plus chroma — not just the Y plane. For
    /// 4:2:0 that's `plane_len * 3/2`. A real sample-range run must accept
    /// that and still measure the right Y min/max from the frame's first
    /// `plane_len` bytes.
    #[test]
    fn read_output_frame_accepts_a_full_yuv420p_frame_and_yields_decoded() {
        let base = tmp_base("full-frame");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();

        let (width, height) = (64usize, 64usize);
        let plane_len = width.checked_mul(height).unwrap();
        let chroma_len = plane_len.checked_div(2).unwrap(); // 4:2:0: (U+V) == plane/2
        let middle_len = plane_len.checked_sub(2).unwrap();

        let mut frame = Vec::new();
        frame.push(10u8); // Y-plane min, at the very first byte
        frame.extend(std::iter::repeat_n(200u8, middle_len));
        frame.push(240u8); // Y-plane max, at the last Y-plane byte
        frame.extend(std::iter::repeat_n(128u8, chroma_len)); // chroma: ignored by y_plane_range

        std::fs::write(root.join("t.flv.y"), &frame).unwrap();

        let bytes = read_output_frame(&dir, "t.flv.y", width, height).unwrap();
        assert_eq!(
            bytes.len(),
            frame.len(),
            "a real w*h*3/2 frame must be read in full, not truncated or refused"
        );
        let outcome = sample_range_outcome("clean", &bytes, width, height);
        assert!(
            matches!(
                outcome,
                SampleOutcome::Decoded {
                    y_min: 10,
                    y_max: 240
                }
            ),
            "{outcome:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// R1: a frame bigger than the 6x-plane upper bound (larger than any
    /// real planar pix_fmt, up to 4:4:4 at 16 bits) is still refused — the
    /// fix widens the cap, it does not remove it.
    #[test]
    fn read_output_frame_refuses_more_than_six_times_the_plane() {
        let base = tmp_base("oversize-frame");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();

        let (width, height) = (64usize, 64usize);
        let plane_len = width.checked_mul(height).unwrap();
        let frame_cap = plane_len.saturating_mul(6);
        let oversize_len = frame_cap.saturating_add(1);

        std::fs::write(root.join("t.flv.y"), vec![7u8; oversize_len]).unwrap();

        let result = read_output_frame(&dir, "t.flv.y", width, height);
        assert!(
            result.is_err(),
            "a file larger than 6x the Y plane must still be refused"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// m2 (final review): the failure the exact-size check exists for. An
    /// operator `--width`/`--height` smaller than the real frame used to be
    /// accepted (anything up to 6x the plane was) and silently measured only
    /// the top rows. A real 64x64 8-bit 4:2:0 frame (6144 bytes) read as
    /// 40x40 matches no known layout for 40x40 (2400/3200/4800 8-bit,
    /// 4800/6400/9600 16-bit), so it must be refused.
    #[test]
    fn read_output_frame_refuses_a_frame_that_is_not_exactly_a_known_size() {
        let base = tmp_base("wrong-dims");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();
        std::fs::write(root.join("t.flv.y"), vec![16u8; 6144]).unwrap();

        let result = read_output_frame(&dir, "t.flv.y", 40, 40);
        assert!(
            result.is_err(),
            "a 64x64 frame read as 40x40 must be refused, not part-measured"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// m2: an exact 8-bit 4:2:0 frame is accepted at even and odd sizes
    /// (odd: chroma planes are ceil(w/2) x ceil(h/2), as ffmpeg lays out
    /// yuv420p rawvideo).
    #[test]
    fn frame_layout_accepts_an_exact_8bit_420_frame_even_and_odd() {
        // 64x64: 4096 + 2 * 32 * 32.
        assert_eq!(
            check_frame_layout(6144, 64, 64).unwrap(),
            PlanarLayout::Yuv420p8
        );
        // 17x17: 289 + 2 * 9 * 9.
        assert_eq!(
            check_frame_layout(451, 17, 17).unwrap(),
            PlanarLayout::Yuv420p8
        );
        // The real thing: 1920x1080 yuv420p.
        assert_eq!(
            check_frame_layout(3_110_400, 1920, 1080).unwrap(),
            PlanarLayout::Yuv420p8
        );
    }

    /// m2: a length that is no known layout's size for w x h is refused —
    /// including one byte either side of an exact 4:2:0 frame, and empty.
    #[test]
    fn frame_layout_refuses_a_length_that_matches_no_known_layout() {
        let err = check_frame_layout(6144, 40, 40).unwrap_err();
        assert!(err.to_string().contains("not a known planar size"), "{err}");
        for len in [6143, 6145, 0] {
            assert!(check_frame_layout(len, 64, 64).is_err(), "{len}");
        }
    }

    /// m2: a length that is exactly another known layout's size is named
    /// in the error, never measured as if it were 8-bit 4:2:0. At 64x64:
    /// 8-bit 4:2:2 = 8192, 8-bit 4:4:4 = 12288 (= 16-bit 4:2:0), 16-bit
    /// 4:2:2 = 16384, 16-bit 4:4:4 = 24576.
    #[test]
    fn frame_layout_names_other_known_layouts_but_does_not_measure_them() {
        for (len, name) in [
            (8192, "8-bit 4:2:2"),
            (12288, "8-bit 4:4:4"),
            (12288, "16-bit 4:2:0"),
            (16384, "16-bit 4:2:2"),
            (24576, "16-bit 4:4:4"),
        ] {
            let err = check_frame_layout(len, 64, 64).unwrap_err();
            assert!(err.to_string().contains(name), "{len} {name}: {err}");
        }
    }

    /// m2: why other layouts are not measured — a size match alone is
    /// ambiguous. A real 1920x1080 4:2:0 frame (3,110,400 bytes) is exactly
    /// a 1440x1080 4:2:2 frame; measuring that would read only the top 810
    /// rows of the real Y plane with no error.
    #[test]
    fn a_1080p_420_frame_passed_as_1440x1080_is_refused_not_part_measured() {
        let err = check_frame_layout(3_110_400, 1440, 1080).unwrap_err();
        assert!(err.to_string().contains("8-bit 4:2:2"), "{err}");
    }

    /// m2: `--width`/`--height` outside 16..=8192 are refused before
    /// anything is spawned or touched (the ffmpeg path does not even exist,
    /// so this needs no bwrap/ffmpeg).
    #[test]
    fn run_sample_range_refuses_dimensions_outside_16_to_8192_before_spawning() {
        let base = tmp_base("dims");
        let _ = std::fs::remove_dir_all(&base);
        let dir = CaptureDir::create(&base.join("captures")).unwrap();
        for (w, h) in [(15, 1080), (1920, 15), (8193, 1080), (1920, 8193), (0, 0)] {
            let err = run_sample_range(Path::new("/nonexistent/ffmpeg"), &dir, "x.flv", w, h)
                .unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "{w}x{h}: {err}"
            );
            assert!(err.to_string().contains("16..=8192"), "{err}");
        }
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

    /// The host captures dir as the CLI anchors it (`main.rs`'s
    /// `CAPTURES_DIR`): build-tree-relative, never an owner's home path
    /// hard-coded into a public repository (final review m10).
    const TEST_CAPTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../captures");

    #[test]
    fn argv_is_exact_and_has_no_scaler() {
        let argv = build_ffmpeg_sandbox_argv(
            Path::new("/nix/store/abc-ffmpeg/bin/ffmpeg"),
            Path::new(TEST_CAPTURES_DIR),
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
                "--new-session",
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
                TEST_CAPTURES_DIR,
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
        // I1 (final review): bwrap must put ffmpeg in a new session
        // (setsid) straight away, so a compromised decoder has no
        // controlling terminal — no `/dev/tty` writes (escape-sequence
        // injection) and no TIOCSTI keystroke injection (CVE-2017-5226).
        assert_eq!(
            argv.iter().position(|a| a == "--new-session"),
            argv.iter()
                .position(|a| a == "bwrap")
                .and_then(|i| i.checked_add(1)),
            "--new-session must come right after bwrap"
        );
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
