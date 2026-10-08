//! The side FLV (§6.5 `side`): the ES3's one shared encoder forces an IDR
//! into every open stream whenever a new FLV connection opens, so the
//! bridge requests an IDR by opening a short second FLV on the session's
//! token, reading it through the §6.2 demuxer to its first tag, and closing
//! it. Nothing it reads reaches the pump; a failure is counted by the
//! caller, never retried and never answered with a re-login.
//!
//! Side FLVs are excluded from §6.9's auth class: a refusal for the token
//! comes back as `KvmError::Auth` only so the caller can count it under
//! `idr_side_failures{kind="auth"}` — it must never reach the session's
//! `AuthGate`. This function has no password and so cannot log in, and
//! (like everything under `kvm`) it cannot log out.
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use crate::kvm::flv::FlvConn;
use kvm_proto::Token;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use std::sync::Arc;
use std::time::Duration;

/// Open one side FLV, read it to its first tag and close it. The whole
/// request — connect, response and the read — is bounded by
/// `side_timeout` (`video.idr_side_timeout`); the open alone also by
/// `connect_timeout`. One connection per call: no retry.
pub async fn request_idr(
    ep: Arc<KvmEndpoint>,
    token: Token,
    connect_timeout: Duration,
    side_timeout: Duration,
) -> Result<(), KvmError> {
    let read_to_first_tag = async {
        let mut conn = FlvConn::open(&ep, &token, connect_timeout).await?;
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        loop {
            let Some(bytes) = conn.chunk().await? else {
                return Err(KvmError::Closed);
            };
            demux.push(&bytes);
            match demux.next_tag() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(_) => return Err(KvmError::Protocol("side flv framing")),
            }
        }
    };
    match tokio::time::timeout(side_timeout, read_to_first_tag).await {
        Ok(r) => r,
        Err(_) => Err(KvmError::Timeout("side flv")),
    }
}
