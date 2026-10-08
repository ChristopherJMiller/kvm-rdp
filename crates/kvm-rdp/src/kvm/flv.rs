//! `GET /av.flv?token=…` on the video port (§3.1, §3.2): the token as query
//! and cookie, as the web UI sends it. The body is read chunk by chunk;
//! `kvm_proto`'s demuxer checks every limit before buffering.
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::{KvmError, result_403};
use crate::kvm::login::{AbortOnDrop, MAX_RESPONSE_HEAD};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kvm_proto::Token;
use std::time::Duration;

/// A refusal body is small (it holds `{"result":403}`); a 200 whose first
/// body byte is not the FLV signature but whose body (already bounded by
/// hyper's read buffer, [`MAX_RESPONSE_HEAD`]) still exceeds this is
/// `Protocol`, never scanned (m2, fix round 1).
const MAX_REFUSAL_BODY: usize = 4096;

/// The first byte of a real FLV stream's signature (`"FLV"`). A 200
/// response is a video stream only if its body starts with this; any
/// other first byte — or none at all before EOF — is a hiccup or a
/// refusal, classified by the bytes themselves rather than `Content-Type`
/// (m2, fix round 1: the ES3's header for this case is unmeasured, and a
/// 200 refusal with a non-`json` `Content-Type` used to be opened as a
/// stream).
const FLV_SIGNATURE_FIRST_BYTE: u8 = b'F';

pub struct FlvConn {
    body: Incoming,
    /// The first data frame, read while classifying a 200 response (m2):
    /// `chunk()` hands this out before it resumes reading `body`.
    lookahead: Option<Bytes>,
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
        if let Some(b) = self.lookahead.take() {
            return Ok(Some(b));
        }
        next_data_frame(&mut self.body).await
    }
}

/// The next non-empty data frame, or `Ok(None)` at EOF. Each read is
/// bounded by hyper's own read buffer (`MAX_RESPONSE_HEAD`, shared with
/// login); nothing here accumulates across frames.
async fn next_data_frame(body: &mut Incoming) -> Result<Option<Bytes>, KvmError> {
    loop {
        match body.frame().await {
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
    // Reaped: `Session::close` waits until a dropped FLV's socket is gone.
    let conn = AbortOnDrop::reaped(
        tokio::spawn(async move {
            let _ = conn.await;
        }),
        ep.reaper.clone(),
    );
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
    match resp.status().as_u16() {
        401 | 403 => Err(KvmError::Auth),
        200 => classify_200(resp.into_body(), conn).await,
        s => Err(KvmError::Http(s)),
    }
}

/// m2 (fix round 1): classify a 200 response by its body, not its
/// `Content-Type` — the ES3's header for a non-stream 200 is unmeasured,
/// and the old check silently opened a refusal as a (broken) stream
/// whenever a KVM answered with any content type other than `json`.
async fn classify_200(mut body: Incoming, conn: AbortOnDrop) -> Result<FlvConn, KvmError> {
    let first = next_data_frame(&mut body).await?;
    let looks_like_flv = first
        .as_deref()
        .and_then(<[u8]>::first)
        .is_some_and(|b| *b == FLV_SIGNATURE_FIRST_BYTE);
    if looks_like_flv {
        return Ok(FlvConn {
            body,
            lookahead: first,
            _conn: conn,
        });
    }
    let refusal = first.as_deref().unwrap_or(&[]);
    if refusal.len() > MAX_REFUSAL_BODY {
        return Err(KvmError::Protocol("flv answered json"));
    }
    if result_403(refusal) {
        Err(KvmError::Auth)
    } else {
        Err(KvmError::Protocol("flv answered json"))
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
    use kvm_proto::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
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

    /// I1 (fix round 1): every status the review found untested, driven
    /// by kvm-sim's existing `flv_status` policy. Catches, among others,
    /// `flv.rs`'s old `401 | 403` arm narrowed to `403` (401 would then
    /// fall through to `Http(401)`) and `classify_200`'s refusal arm
    /// flipped to `Auth` (the 200 case would then no longer be `Protocol`).
    #[tokio::test]
    async fn every_flv_status_classifies_by_section_6_9() {
        let (sim, ep, token) = sim_and_token().await;
        for (status, want) in [
            (401, KvmError::Auth),
            (403, KvmError::Auth),
            (200, KvmError::Protocol("flv answered json")),
            (404, KvmError::Http(404)),
        ] {
            sim.set_policy(|p| p.flv_status = Some(status));
            let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
            assert_eq!(e, want, "status {status}");
        }
    }

    /// m2 (fix round 1): a 200 refusal is recognised by its body, not its
    /// `Content-Type` — kvm-sim always answers `application/json`, so this
    /// needs a raw stub (like `login`'s `hostile()` rig) to prove the
    /// header is never consulted.
    #[tokio::test]
    async fn a_200_text_html_result_403_body_is_still_a_refusal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut req = [0u8; 4096];
                let _ = s.read(&mut req).await;
                let body: &[u8] = b"{\"result\":403}";
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
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
        let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
        assert_eq!(e, KvmError::Auth);
    }
}
