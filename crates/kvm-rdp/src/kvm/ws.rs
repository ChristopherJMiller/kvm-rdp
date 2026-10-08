//! The control websocket (`/websocket` on the control port, §3.1, §3.2):
//! the token cookie, 4 KiB message and frame limits (an oversize message is
//! an error before it is buffered), no write buffering.
use crate::config::Scheme;
use crate::kvm::endpoint::{KvmEndpoint, KvmIo};
use crate::kvm::error::{KvmError, result_403};
use kvm_proto::Token;
use std::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub const WS_MAX_MESSAGE: usize = 4096;
pub type KvmWs = WebSocketStream<KvmIo>;

#[must_use]
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(WS_MAX_MESSAGE),
        max_frame_size: Some(WS_MAX_MESSAGE),
        write_buffer_size: 0,
        max_write_buffer_size: 64 * 1024,
        ..WebSocketConfig::default()
    }
}

pub async fn open_ws(
    ep: &KvmEndpoint,
    token: &Token,
    connect_timeout: Duration,
) -> Result<KvmWs, KvmError> {
    let io = ep.connect(ep.control_port, connect_timeout).await?;
    let scheme = match ep.scheme {
        Scheme::Https => "wss",
        Scheme::Http => "ws",
    };
    let mut req = format!("{scheme}://{}:{}/websocket", ep.host, ep.control_port)
        .into_client_request()
        .map_err(|_| KvmError::Protocol("ws request"))?;
    let cookie = HeaderValue::from_str(&format!("token={}", token.as_str()))
        .map_err(|_| KvmError::Protocol("ws cookie"))?;
    req.headers_mut().insert("Cookie", cookie);
    match tokio::time::timeout(
        connect_timeout,
        tokio_tungstenite::client_async_with_config(req, io, Some(ws_config())),
    )
    .await
    {
        Err(_) => Err(KvmError::Timeout("ws upgrade")),
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            let status = resp.status().as_u16();
            // §6.9/§7 (I3, fix round 1): a refusal can also arrive as a
            // non-101 body carrying `{"result":403}` rather than the
            // status line itself. The bytes are whatever tungstenite
            // already buffered while trying to parse the handshake head
            // (`handshake/client.rs`'s `stage_finished`), bounded by its
            // own `AttackCheck` (64 KiB / 512 packets) — no extra read.
            if matches!(status, 401 | 403) || resp.body().as_deref().is_some_and(result_403) {
                Err(KvmError::Auth)
            } else {
                Err(KvmError::Http(status))
            }
        }
        Ok(Err(_)) => Err(KvmError::Protocol("ws upgrade")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::config::{Scheme, Secret};
    use crate::kvm::login::login;
    use futures_util::StreamExt as _;
    use kvm_sim::{KvmSim, SimConfig, Source};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CT: Duration = Duration::from_secs(1);

    async fn sim_and_token() -> (KvmSim, KvmEndpoint, Token) {
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let sim = KvmSim::start(SimConfig::es3(src)).await.unwrap();
        let p = sim.ports();
        let ep = KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            sim.spki_sha256(),
        );
        let token = login(&ep, &Secret::new(sim.password()), CT, CT * 2)
            .await
            .unwrap();
        (sim, ep, token)
    }

    #[tokio::test]
    async fn the_websocket_opens_with_the_token_cookie() {
        let (sim, ep, token) = sim_and_token().await;
        let _ws = open_ws(&ep, &token, CT).await.unwrap();
        sim.wait_for(CT, |_| sim.stats().ws_open == 1)
            .await
            .unwrap();
        sim.expire_tokens();
        assert_eq!(
            open_ws(&ep, &token, CT).await.err().unwrap(),
            KvmError::Auth
        );
    }

    /// I2 (fix round 1): 8 KiB is over our 4 KiB cap but under
    /// tungstenite's 16 MiB default `max_frame_size`, so this only fails
    /// with our config applied — the original 64 MiB declaration was
    /// already refused by tungstenite's own built-in default and proved
    /// nothing about `open_ws` actually using `ws_config()`.
    #[tokio::test]
    async fn an_oversize_message_is_an_error_not_a_buffer() {
        let (sim, ep, token) = sim_and_token().await;
        let mut ws = open_ws(&ep, &token, CT).await.unwrap();
        sim.wait_for(CT, |_| sim.stats().ws_open == 1)
            .await
            .unwrap();
        sim.send_ws_oversize(8 * 1024);
        let next = tokio::time::timeout(CT, ws.next()).await.unwrap();
        assert!(matches!(next, Some(Err(_))), "{next:?}");
    }

    #[test]
    fn the_limits_are_the_spec_limits() {
        let c = ws_config();
        assert_eq!(
            (c.max_message_size, c.max_frame_size),
            (Some(4096), Some(4096))
        );
        assert_eq!(c.write_buffer_size, 0);
        assert_eq!(c.max_write_buffer_size, 64 * 1024);
    }

    /// I1 (fix round 1): the handshake-status arms via kvm-sim's existing
    /// `ws_status` policy, not just the already-covered token-expiry 403.
    #[tokio::test]
    async fn every_ws_status_classifies_by_section_6_9() {
        let (sim, ep, token) = sim_and_token().await;
        for (status, want) in [
            (401, KvmError::Auth),
            (403, KvmError::Auth),
            (503, KvmError::Http(503)),
        ] {
            sim.set_policy(|p| p.ws_status = Some(status));
            let e = open_ws(&ep, &token, CT).await.err().unwrap();
            assert_eq!(e, want, "status {status}");
        }
    }

    /// I3 (fix round 1): §6.9/§7 — a refusal answered `200 {"result":403}`
    /// (no 401/403 on the wire) is still `Auth`, not a transient
    /// `Http(200)`. kvm-sim's handshake callback cannot shape an arbitrary
    /// body, so this is a raw loopback stub, like `login`'s `hostile()`
    /// rig.
    #[tokio::test]
    async fn a_result_403_body_on_a_200_handshake_is_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut req = [0u8; 4096];
                let _ = s.read(&mut req).await;
                let body: &[u8] = b"{\"result\":403}";
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                resp.extend_from_slice(body);
                let _ = s.write_all(&resp).await;
            }
        });
        let ep = KvmEndpoint::new(
            Scheme::Http,
            "127.0.0.1",
            (port, port, port),
            &"0".repeat(64),
        );
        let token = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
        let e = open_ws(&ep, &token, CT).await.err().unwrap();
        assert_eq!(e, KvmError::Auth);
    }
}
