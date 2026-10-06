//! First-IDR latency trial (§12 Leg A, Task 5.11): FLV-open to first-IDR
//! latency, used by the CLI's 20-trial census loop (Task 13).

use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use tokio::time::Instant as TokioInstant;

use crate::capture::{open_flv, record_for};
use crate::kvm::KvmError;
use crate::request::KvmTarget;

/// Hostile-input bound (§9.2): a peer that never sends an IDR must not be
/// used to exhaust memory. The trial stops at the first IDR; this is just
/// the backstop if one never arrives before `timeout` does.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Time from opening `av.flv` to the first FLV tag that carries an IDR NAL
/// (type 5). One deadline bounds the *whole* trial — the open (connect
/// through response headers) and every body read — so a peer that accepts
/// the connection and then stalls at any point gets a clean `KvmError`,
/// never a hang. Reads are capped at `MAX_BYTES` total.
pub async fn first_idr_latency(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    timeout: Duration,
) -> Result<Duration, KvmError> {
    let started = Instant::now();
    let now = TokioInstant::now();
    let deadline = now.checked_add(timeout).unwrap_or(now);

    let mut body = match tokio::time::timeout_at(deadline, open_flv(target, pin, token)).await {
        Err(_) => {
            return Err(KvmError::Http(format!(
                "av.flv open timed out after {timeout:?} without an IDR"
            )));
        }
        Ok(opened) => opened?,
    };

    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut total_bytes: u64 = 0;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                return Err(KvmError::Http(format!("no IDR within {timeout:?}")));
            }
            Ok(None) => return Err(KvmError::Http("av.flv stream ended before an IDR".into())),
            Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        total_bytes = total_bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if total_bytes > MAX_BYTES {
            return Err(KvmError::Http(format!(
                "av.flv exceeded the {MAX_BYTES}-byte cap before an IDR"
            )));
        }
        demux.push(chunk);
        while let Some(tag) = demux
            .next_tag()
            .map_err(|e| KvmError::Http(format!("{e:?}")))?
        {
            if record_for(&tag, 0).nal_types.contains(&5) {
                return Ok(started.elapsed());
            }
        }
    }
}
