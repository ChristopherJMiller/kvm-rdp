//! The control websocket (`/websocket`, §3.1): the upgrade must carry a live
//! `Cookie: token=…`; every data message is recorded verbatim (§3.3 HID
//! frames). Tests can pause reads, close every websocket, or send the
//! client an oversize message.
use crate::http::cookie_token;
use crate::state::{Shared, SimEvent, WsCmd};
use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

// `result_large_err`: the handshake callback's `Err` type is fixed by
// tungstenite's `Callback` trait (a whole `http::Response`).
#[allow(clippy::result_large_err)]
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    conn: u64,
    shared: Arc<Shared>,
) {
    let refused = Arc::new(Mutex::new(None::<u16>));
    let (sh, rf) = (shared.clone(), refused.clone());
    let policy = shared.policy();
    let callback = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let token_ok = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(cookie_token)
            .is_some_and(|t| sh.token_valid(&t));
        let status = if req.uri().path() != "/websocket" {
            Some(404)
        } else if let Some(s) = policy.ws_status {
            Some(s)
        } else if !token_ok {
            Some(403)
        } else {
            None
        };
        match status {
            None => Ok(resp),
            Some(s) => {
                if let Ok(mut g) = rf.lock() {
                    *g = Some(s);
                }
                let mut r = ErrorResponse::new(None);
                *r.status_mut() = StatusCode::from_u16(s).unwrap_or(StatusCode::FORBIDDEN);
                Err(r)
            }
        }
    };
    let cfg = WebSocketConfig {
        max_message_size: Some(64 * 1024),
        max_frame_size: Some(64 * 1024),
        ..WebSocketConfig::default()
    };
    let mut ws =
        match tokio_tungstenite::accept_hdr_async_with_config(io, callback, Some(cfg)).await {
            Ok(ws) => ws,
            Err(_) => {
                let status = refused.lock().ok().and_then(|g| *g).unwrap_or(400);
                shared.record(SimEvent::WsRefused { status });
                return;
            }
        };
    shared.record(SimEvent::WsOpen { conn });
    let (tx, mut cmds) = mpsc::unbounded_channel();
    shared.add_ws(tx);
    loop {
        if shared.policy().pause_ws_reads {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(10)) => continue,
                cmd = cmds.recv() => if !handle(&mut ws, cmd).await { break },
            }
        }
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(b))) => shared.record(SimEvent::Hid { conn, bytes: b }),
                Some(Ok(Message::Text(t))) => shared.record(SimEvent::Hid { conn, bytes: t.into_bytes() }),
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            cmd = cmds.recv() => if !handle(&mut ws, cmd).await { break },
        }
    }
    shared.record(SimEvent::WsClose { conn });
}

/// Returns false when the websocket should end.
async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    cmd: Option<WsCmd>,
) -> bool {
    match cmd {
        Some(WsCmd::Close) | None => {
            let _ = ws.close(None).await;
            false
        }
        Some(WsCmd::Oversize(len)) => {
            // A binary frame header declaring `len` payload bytes, then 4 KiB
            // of it: the client must close at its limit without buffering.
            let mut raw = vec![0x82, 127];
            raw.extend_from_slice(&len.to_be_bytes());
            raw.extend_from_slice(&[0u8; 4096]);
            let io = ws.get_mut();
            io.write_all(&raw).await.is_ok() && io.flush().await.is_ok()
        }
    }
}
