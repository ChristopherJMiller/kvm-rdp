//! The control websocket for the L4 checks: an upgrade that tells an
//! acceptance from a refusal, and `ws-close` — how the KVM answers a close
//! frame and how its TCP connection ends (the PC9 carry: §3.2 counts only
//! an answered close frame as a clean close).
use super::{RefusalForm, deadline, escaped, since};
use crate::kvm::{self, BoxedIo, KvmError};
use crate::request::{self, KvmTarget};
use futures_util::StreamExt as _;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;
use tokio_tungstenite::tungstenite::{
    self, Message, client::IntoClientRequest as _, protocol::WebSocketConfig,
};

pub type Ws = tokio_tungstenite::WebSocketStream<BoxedIo>;

/// `Accepted` is boxed: the stream is 296 bytes against `RefusalForm`'s 56
/// (`clippy::large_enum_variant`, D12).
pub enum Upgrade {
    Accepted(Box<Ws>),
    Refused(RefusalForm),
}

/// Upgrade `/websocket` on the control port, with `token`'s cookie or none.
pub async fn upgrade(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Upgrade, KvmError> {
    let io = kvm::connect_to(t, t.control_port, pin).await?;
    upgrade_on(io, t, token, timeout).await
}

/// The upgrade over a connection already made (the HID checks make theirs
/// resettable). The bridge's limits: 4 KiB messages and frames (§3.2).
pub async fn upgrade_on(
    io: BoxedIo,
    t: &KvmTarget,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Upgrade, KvmError> {
    let mut req = request::websocket_url(t)
        .as_str()
        .into_client_request()
        .map_err(|e| KvmError::Http(e.to_string()))?;
    if let Some(tok) = token {
        let cookie = request::token_cookie_header(tok)
            .parse()
            .map_err(|_| KvmError::Http("bad cookie header".to_owned()))?;
        req.headers_mut().insert("Cookie", cookie);
    }
    let cfg = WebSocketConfig {
        max_message_size: Some(4096),
        max_frame_size: Some(4096),
        ..WebSocketConfig::default()
    };
    match tokio::time::timeout(
        timeout,
        tokio_tungstenite::client_async_with_config(req, io, Some(cfg)),
    )
    .await
    {
        Err(_) => Err(KvmError::Http(format!(
            "websocket upgrade timed out after {timeout:?}"
        ))),
        Ok(Ok((ws, _))) => Ok(Upgrade::Accepted(Box::new(ws))),
        Ok(Err(tungstenite::Error::Http(resp))) => {
            let ct = resp.headers().get("content-type").map(|v| v.as_bytes());
            let body = resp.body().as_deref().unwrap_or_default();
            Ok(Upgrade::Refused(RefusalForm::new(
                resp.status().as_u16(),
                ct,
                body,
            )))
        }
        Ok(Err(e)) => Err(KvmError::Http(escaped(e.to_string().as_bytes(), 200))),
    }
}

/// What the KVM sent while the websocket sat idle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inbound {
    pub text: u32,
    pub binary: u32,
    pub ping: u32,
    pub pong: u32,
    /// The KVM closed (a close frame, an EOF or an error) before we did.
    pub closed_by_kvm: bool,
}

/// How the KVM answered our close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    CloseFrame { ms: u64 },
    Eof { ms: u64 },
    Error { ms: u64, what: String },
    Timeout,
}

/// How the TCP connection then ended, read below the websocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpEnd {
    Fin { ms: u64 },
    Reset { ms: u64 },
    Error { ms: u64, kind: String },
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReport {
    pub idle: Inbound,
    pub reply: Reply,
    pub tcp: TcpEnd,
}

/// `ws-close`: read for `idle` (sending nothing), send a close frame, then
/// wait up to `wait` for the answer and for the TCP end.
pub async fn close_form(mut ws: Ws, idle: Duration, wait: Duration) -> CloseReport {
    let mut inbound = Inbound::default();
    let idle_until = deadline(idle);
    loop {
        match tokio::time::timeout_at(idle_until, ws.next()).await {
            Err(_) => break,
            Ok(Some(Ok(m))) => match m {
                Message::Text(_) => inbound.text = inbound.text.saturating_add(1),
                Message::Binary(_) => inbound.binary = inbound.binary.saturating_add(1),
                Message::Ping(_) => inbound.ping = inbound.ping.saturating_add(1),
                Message::Pong(_) => inbound.pong = inbound.pong.saturating_add(1),
                Message::Close(_) => {
                    inbound.closed_by_kvm = true;
                    break;
                }
                Message::Frame(_) => {}
            },
            Ok(Some(Err(_)) | None) => {
                inbound.closed_by_kvm = true;
                break;
            }
        }
    }
    let t0 = Instant::now();
    if inbound.closed_by_kvm {
        let tcp = tcp_end(ws.get_mut(), t0, wait).await;
        return CloseReport {
            idle: inbound,
            reply: Reply::Timeout,
            tcp,
        };
    }
    let until = deadline(wait);
    // Bounded like every read: a KVM that never reads can stall the write.
    let _ = tokio::time::timeout_at(until, ws.close(None)).await;
    let reply = loop {
        match tokio::time::timeout_at(until, ws.next()).await {
            Err(_) => break Reply::Timeout,
            Ok(Some(Ok(Message::Close(_)))) => {
                break Reply::CloseFrame {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => {
                break Reply::Error {
                    ms: since(t0, Instant::now()),
                    what: escaped(e.to_string().as_bytes(), 120),
                };
            }
            Ok(None) => {
                break Reply::Eof {
                    ms: since(t0, Instant::now()),
                };
            }
        }
    };
    let tcp = tcp_end(ws.get_mut(), t0, wait).await;
    CloseReport {
        idle: inbound,
        reply,
        tcp,
    }
}

async fn tcp_end(io: &mut BoxedIo, t0: Instant, wait: Duration) -> TcpEnd {
    let until = deadline(wait);
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout_at(until, io.read(&mut buf)).await {
            Err(_) => return TcpEnd::Timeout,
            Ok(Ok(0)) => {
                return TcpEnd::Fin {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return TcpEnd::Reset {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Err(e)) => {
                return TcpEnd::Error {
                    ms: since(t0, Instant::now()),
                    kind: format!("{:?}", e.kind()),
                };
            }
        }
    }
}
