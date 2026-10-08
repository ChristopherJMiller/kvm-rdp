//! `GET /av.flv?token=…` on the video port (§3.1, §3.2): the token as query
//! and cookie, as the web UI sends it. The body is read chunk by chunk;
//! `kvm_proto`'s demuxer checks every limit before buffering.
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use crate::kvm::login::{AbortOnDrop, MAX_RESPONSE_HEAD, read_capped};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kvm_proto::Token;
use std::time::Duration;

/// A refusal's JSON body is read up to this (it holds `{"result":403}`).
const MAX_REFUSAL_BODY: usize = 4096;

pub struct FlvConn {
    body: Incoming,
    _conn: AbortOnDrop,
}

impl FlvConn {
    pub async fn open(
        ep: &KvmEndpoint,
        token: &Token,
        connect_timeout: Duration,
    ) -> Result<FlvConn, KvmError> {
        let io = ep.connect(ep.video_port, connect_timeout).await?;
        match tokio::time::timeout(connect_timeout, request(ep, io, token)).await {
            Ok(r) => r,
            Err(_) => Err(KvmError::Timeout("flv response")),
        }
    }

    /// The next body chunk; `Ok(None)` when the KVM closes the stream.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, KvmError> {
        loop {
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(_)) => return Err(KvmError::Closed),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }
}

async fn request(
    ep: &KvmEndpoint,
    io: crate::kvm::endpoint::KvmIo,
    token: &Token,
) -> Result<FlvConn, KvmError> {
    let mut http = hyper::client::conn::http1::Builder::new();
    http.max_buf_size(MAX_RESPONSE_HEAD);
    let (mut sender, conn) = http
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| KvmError::Protocol("http handshake"))?;
    let conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("/av.flv?token={}", token.as_str()))
        .header("Host", &ep.host)
        .header("Cookie", format!("token={}", token.as_str()))
        .body(Empty::<Bytes>::new())
        .map_err(|_| KvmError::Protocol("request"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| KvmError::Protocol("response"))?;
    let status = resp.status().as_u16();
    let json = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("json"));
    match status {
        401 | 403 => Err(KvmError::Auth),
        200 if json => {
            let body = read_capped(resp.into_body(), MAX_REFUSAL_BODY).await?;
            if result_403(&body) {
                Err(KvmError::Auth)
            } else {
                Err(KvmError::Protocol("flv answered json"))
            }
        }
        200 => Ok(FlvConn {
            body: resp.into_body(),
            _conn: conn,
        }),
        s => Err(KvmError::Http(s)),
    }
}

/// `"result":403` anywhere in a refusal body (§6.9 auth), whitespace-blind.
pub(crate) fn result_403(body: &[u8]) -> bool {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let needle: &[u8] = b"\"result\":403";
    compact.windows(needle.len()).any(|w| w == needle)
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
    use kvm_proto::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
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
    async fn an_open_flv_starts_with_the_sequence_header() {
        let (_sim, ep, token) = sim_and_token().await;
        let mut flv = FlvConn::open(&ep, &token, CT).await.unwrap();
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        let tag = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(t) = demux.next_tag().unwrap() {
                    break t;
                }
                demux.push(&flv.chunk().await.unwrap().unwrap());
            }
        })
        .await
        .expect("no tag within 5 s");
        assert!(
            matches!(tag.body, TagBody::Video(VideoBody::SequenceHeader(_))),
            "{tag:?}"
        );
    }

    #[tokio::test]
    async fn an_expired_token_is_an_auth_failure() {
        let (sim, ep, token) = sim_and_token().await;
        sim.expire_tokens();
        let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
        assert_eq!(e, KvmError::Auth);
    }

    #[tokio::test]
    async fn a_5xx_is_transient() {
        let (sim, ep, token) = sim_and_token().await;
        sim.set_policy(|p| p.flv_status = Some(503));
        let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
        assert_eq!(
            (e.clone(), e.class()),
            (KvmError::Http(503), crate::kvm::FailClass::Transient)
        );
    }

    #[test]
    fn a_json_result_403_is_recognised() {
        assert!(result_403(br#"{"result":403}"#));
        assert!(result_403(b"{ \"result\" : 403 }"));
        assert!(!result_403(br#"{"result":0}"#));
    }
}
