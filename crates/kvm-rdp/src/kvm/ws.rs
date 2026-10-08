//! The control websocket (`/websocket` on the control port, §3.1, §3.2):
//! the token cookie, 4 KiB message and frame limits (an oversize message is
//! an error before it is buffered), no write buffering.
use crate::config::Scheme;
use crate::kvm::endpoint::{KvmEndpoint, KvmIo};
use crate::kvm::error::KvmError;
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
            match resp.status().as_u16() {
                401 | 403 => Err(KvmError::Auth),
                s => Err(KvmError::Http(s)),
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

    /// §3.2: an oversize message closes the socket without buffering it —
    /// kvm-sim declares 64 MiB and sends 4 KiB of it.
    #[tokio::test]
    async fn an_oversize_message_is_an_error_not_a_buffer() {
        let (sim, ep, token) = sim_and_token().await;
        let mut ws = open_ws(&ep, &token, CT).await.unwrap();
        sim.wait_for(CT, |_| sim.stats().ws_open == 1)
            .await
            .unwrap();
        sim.send_ws_oversize(64 << 20);
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
    }
}
