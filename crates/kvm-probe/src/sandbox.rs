use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
