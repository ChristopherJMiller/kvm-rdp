//! `snapshot`: the screen as of now, through the KVM's own video. A fresh
//! `av.flv` (its open forces an IDR, §6.5) is written to captures/ up to
//! its first IDR, then decoded in the bwrap sandbox to a PNG (§12). The
//! Mac must be showing the HID test page or the lock screen.
use super::{deadline, flv};
use crate::captures::CaptureDir;
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use http_body_util::BodyExt as _;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long `snapshot` waits for the open and the first IDR.
const IDR_TIMEOUT: Duration = Duration::from_secs(5);

/// Write `av.flv` into `out` through the end of the chunk holding its first
/// IDR (bounded by `flv::MAX_BYTES` and `timeout`); the bytes written.
pub async fn write_first_idr(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    out: &mut std::fs::File,
    timeout: Duration,
) -> Result<u64, KvmError> {
    let until = deadline(timeout);
    let mut body = tokio::time::timeout_at(until, crate::capture::open_flv(t, pin, token))
        .await
        .map_err(|_| KvmError::Http(format!("av.flv open timed out after {timeout:?}")))??;
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut written: u64 = 0;
    loop {
        let frame = match tokio::time::timeout_at(until, body.frame()).await {
            Err(_) => return Err(KvmError::Http(format!("no IDR within {timeout:?}"))),
            Ok(None) => return Err(KvmError::Http("av.flv ended before an IDR".to_owned())),
            Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        written = written.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if written > flv::MAX_BYTES {
            return Err(KvmError::Http(
                "av.flv passed the cap before an IDR".to_owned(),
            ));
        }
        out.write_all(chunk)
            .map_err(|e| KvmError::Io(e.to_string()))?;
        demux.push(chunk);
        while let Some(tag) = demux
            .next_tag()
            .map_err(|e| KvmError::Http(format!("{e:?}")))?
        {
            if flv::is_coded(&tag) && flv::is_idr(&tag) {
                out.sync_all().map_err(|e| KvmError::Io(e.to_string()))?;
                return Ok(written);
            }
        }
    }
}

/// `captures/<name>.flv`, then `captures/<name>.flv.png` (returned). The
/// capture file is created new (0600, never through a link) in the 0700
/// captures dir, and only the sandbox decodes it.
pub async fn snapshot(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    dir: &CaptureDir,
    name: &str,
    ffmpeg: &Path,
) -> Result<PathBuf, String> {
    let flv_name = format!("{name}.flv");
    let path = dir.resolve(&flv_name).map_err(|e| format!("{e:?}"))?;
    let mut file = crate::capture::open_capture_file(&path).map_err(|e| kvm::bounded_debug(&e))?;
    write_first_idr(t, pin, token, &mut file, IDR_TIMEOUT)
        .await
        .map_err(|e| kvm::bounded_debug(&e))?;
    drop(file);
    let (ffmpeg, dir) = (ffmpeg.to_owned(), dir.clone());
    tokio::task::spawn_blocking(move || crate::sandbox::run_snapshot(&ffmpeg, &dir, &flv_name))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}
