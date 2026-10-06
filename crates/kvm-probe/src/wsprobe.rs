//! Control-websocket open check (§3.2, Task 5.10). This confirms the KVM
//! control websocket opens on the configured control port the way the
//! bridge will open it — pinned TLS (or plain, per scheme), the token
//! cookie, the control port — and then closes **without ever sending a
//! data frame**: no HID traffic reaches the Mac from this probe.

use std::time::{Duration, Instant};

use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::kvm::{self, KvmError};
use crate::request::{self, KvmTarget};

/// Bound for the websocket upgrade itself, on top of `kvm::connect_to`'s own
/// connect/handshake timeout: a peer that completes TCP (and TLS) and then
/// never answers the HTTP upgrade must not hang the probe forever.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// Open the KVM control websocket exactly as the bridge will (§3.2):
/// `kvm::connect_to` for the pinned-TLS-or-plain transport (inheriting its
/// connect/handshake timeout and the R9 refusal of an unpinned `Https`
/// target), then the HTTP upgrade carrying `Cookie: token=…` on the control
/// port. Returns the upgrade latency. Closes immediately on success and
/// never sends a data frame.
pub async fn open_control_websocket(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
) -> Result<Duration, KvmError> {
    let io = kvm::connect_to(target, target.control_port, pin).await?;

    let mut req = request::websocket_url(target)
        .as_str()
        .into_client_request()
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let cookie = request::token_cookie_header(token)
        .parse()
        .map_err(|_| KvmError::Http("bad cookie header".into()))?;
    req.headers_mut().insert("Cookie", cookie);

    let started = Instant::now();
    let upgrade = tokio::time::timeout(
        UPGRADE_TIMEOUT,
        tokio_tungstenite::client_async_with_config(req, io, None),
    )
    .await;
    let (mut ws, _resp) = match upgrade {
        Err(_) => {
            return Err(KvmError::Http(format!(
                "websocket upgrade timed out after {UPGRADE_TIMEOUT:?}"
            )));
        }
        Ok(Err(e)) => return Err(KvmError::Http(e.to_string())),
        Ok(Ok(pair)) => pair,
    };
    let latency = started.elapsed();

    // Never send a data frame (no HID traffic reaches the Mac from this
    // probe): a close frame is the only thing this function ever writes.
    ws.close(None)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;

    Ok(latency)
}
