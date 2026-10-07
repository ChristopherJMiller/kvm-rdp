//! `POST /cgi-bin/login.lua` (§3.1). One login per session, a re-login only
//! after an auth failure (§5.1), bounded in time and size. No logout exists.
use crate::config::Secret;
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kvm_proto::{LoginError, Token, parse_login_token};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A login response body is read only up to this many bytes; the first
/// byte past it ends the read and refuses the login (§9.2, M2).
pub const MAX_LOGIN_BODY: usize = 64 * 1024;
/// hyper's read buffer for a KVM response head (login and FLV): a hostile
/// header is refused once this much is buffered — hyper's default is
/// ~400 KiB; 8 KiB is its minimum.
pub(crate) const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Aborts a hyper connection task when the request is done or dropped.
pub(crate) struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
struct LoginBody<'a> {
    pass: &'a str,
    timezone: &'a str,
    time: u64,
}

pub async fn login(
    ep: &KvmEndpoint,
    password: &Secret,
    connect_timeout: Duration,
    login_timeout: Duration,
) -> Result<Token, KvmError> {
    match tokio::time::timeout(login_timeout, login_inner(ep, password, connect_timeout)).await {
        Ok(r) => r,
        Err(_) => Err(KvmError::Timeout("login")),
    }
}

async fn login_inner(
    ep: &KvmEndpoint,
    password: &Secret,
    connect_timeout: Duration,
) -> Result<Token, KvmError> {
    let io = ep.connect(ep.web_port, connect_timeout).await?;
    let mut http = hyper::client::conn::http1::Builder::new();
    http.max_buf_size(MAX_RESPONSE_HEAD);
    let (mut sender, conn) = http
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| KvmError::Protocol("http handshake"))?;
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // The password reaches only this body; it is never logged (§9.2).
    let body = serde_json::to_vec(&LoginBody {
        pass: password.expose(),
        timezone: "UTC",
        time,
    })
    .map_err(|_| KvmError::Protocol("login body"))?;
    let req = Request::builder()
        .method("POST")
        .uri("/cgi-bin/login.lua")
        .header("Host", &ep.host)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| KvmError::Protocol("request"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| KvmError::Protocol("response"))?;
    match resp.status().as_u16() {
        200 => {}
        401 | 403 => return Err(KvmError::Auth),
        s => return Err(KvmError::Http(s)),
    }
    let bytes = read_capped(resp.into_body(), MAX_LOGIN_BODY).await?;
    parse_login_token(&bytes).map_err(|e| match e {
        LoginError::ResultNotOk => KvmError::Auth,
        LoginError::NoResult
        | LoginError::NotUtf8
        | LoginError::NoToken
        | LoginError::BadTokenFormat => KvmError::Protocol("login body"),
    })
}

/// Read a body, refusing it once it passes `cap` bytes.
pub(crate) async fn read_capped(mut body: Incoming, cap: usize) -> Result<Vec<u8>, KvmError> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| KvmError::Protocol("body"))?;
        if let Some(d) = frame.data_ref() {
            if buf.len().saturating_add(d.len()) > cap {
                return Err(KvmError::Protocol("body too large"));
            }
            buf.extend_from_slice(d);
        }
    }
    Ok(buf)
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
    use crate::config::Scheme;
    use crate::kvm::error::FailClass;
    use kvm_sim::{KvmSim, SimConfig, Source};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CT: Duration = Duration::from_secs(1);
    const LT: Duration = Duration::from_secs(2);

    async fn sim() -> KvmSim {
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        KvmSim::start(SimConfig::es3(src)).await.unwrap()
    }

    fn endpoint(sim: &KvmSim, pin: &str) -> KvmEndpoint {
        let p = sim.ports();
        KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), pin)
    }

    #[tokio::test]
    async fn login_with_the_pinned_certificate() {
        let sim = sim().await;
        let ep = endpoint(&sim, sim.spki_sha256());
        let token = login(&ep, &Secret::new(sim.password()), CT, LT)
            .await
            .unwrap();
        assert!(token.as_str().starts_with("0."));
        assert_eq!(sim.stats().logins_ok, 1);
        assert_eq!(sim.stats().logouts, 0);
    }

    #[tokio::test]
    async fn a_wrong_password_is_an_auth_failure() {
        let sim = sim().await;
        let ep = endpoint(&sim, sim.spki_sha256());
        let e = login(&ep, &Secret::new("nope"), CT, LT).await.unwrap_err();
        assert_eq!((e.clone(), e.class()), (KvmError::Auth, FailClass::Auth));
    }

    /// §6.9: a pin mismatch is fatal at once and no login is ever sent.
    #[tokio::test]
    async fn a_wrong_pin_refuses_before_any_request() {
        let sim = sim().await;
        let ep = endpoint(&sim, &"0".repeat(64));
        let e = login(&ep, &Secret::new(sim.password()), CT, LT)
            .await
            .unwrap_err();
        assert_eq!(
            (e.clone(), e.class()),
            (KvmError::CertMismatch, FailClass::Cert)
        );
        let s = sim.stats();
        assert_eq!((s.logins_ok, s.logins_failed), (0, 0));
    }

    #[tokio::test]
    async fn an_unreachable_kvm_times_out_as_transient() {
        let sim = sim().await;
        sim.set_policy(|p| p.blackhole = true);
        let ep = endpoint(&sim, sim.spki_sha256());
        let t = Instant::now();
        let e = login(&ep, &Secret::new(sim.password()), CT, LT)
            .await
            .unwrap_err();
        assert_eq!(e.class(), FailClass::Transient, "{e:?}");
        assert!(
            t.elapsed() >= CT / 2 && t.elapsed() < CT * 5,
            "{:?}",
            t.elapsed()
        );
    }

    #[derive(Clone, Copy)]
    enum Hostile {
        EndlessBody,
        HugeHeader,
        Silent,
        /// PC5 fix round 1, I1: `200` with an empty body — no `"result"`
        /// field at all, so this must not be classified as a rejected
        /// login.
        EmptyOk,
        /// PC5 fix round 1, I1: `200` with a non-JSON HTML body (a "busy"
        /// page, say) — same as `EmptyOk`, no `"result"` field.
        Html,
        /// PC5 fix round 1, I2: an arbitrary HTTP status with an empty
        /// body.
        Status(u16),
    }

    /// A plain-HTTP KVM (scheme `http`, §3.2's diagnosis option) that
    /// answers every request the hostile way.
    async fn hostile(mode: Hostile) -> KvmEndpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut req = [0u8; 4096];
                    let _ = s.read(&mut req).await;
                    match mode {
                        Hostile::EndlessBody => {
                            let _ = s
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
                                )
                                .await;
                            let chunk = vec![b'{'; 16 * 1024];
                            while s.write_all(&chunk).await.is_ok() {}
                        }
                        Hostile::HugeHeader => {
                            let mut h = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
                            h.extend(std::iter::repeat_n(b'a', 64 * 1024));
                            h.extend_from_slice(b"\r\n\r\n");
                            let _ = s.write_all(&h).await;
                        }
                        Hostile::Silent => tokio::time::sleep(Duration::from_secs(30)).await,
                        Hostile::EmptyOk => {
                            let _ = s
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
                                )
                                .await;
                        }
                        Hostile::Html => {
                            let body: &[u8] = b"<html>busy</html>";
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            );
                            let _ = s.write_all(head.as_bytes()).await;
                            let _ = s.write_all(body).await;
                        }
                        Hostile::Status(code) => {
                            let head = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
                            let _ = s.write_all(head.as_bytes()).await;
                        }
                    }
                });
            }
        });
        KvmEndpoint::new(
            Scheme::Http,
            "127.0.0.1",
            (port, port, port),
            &"0".repeat(64),
        )
    }

    /// Review Focus 3: whatever a hostile KVM answers, login ends within
    /// `login_timeout` and carries no device text; the 64 KiB header is
    /// refused at `MAX_RESPONSE_HEAD` (16 KiB; hyper's ~408 KiB default
    /// would accept it), the endless body at `MAX_LOGIN_BODY` (64 KiB).
    ///
    /// PC5 fix round 1: `EmptyOk`/`Html` (I1) are a CGI hiccup, not a
    /// rejected login — a present `"result"` is required for `Auth`, so
    /// both come back `Protocol("login body")`, class Transient, and are
    /// retried rather than ending the session fatally. `Status` (I2) pins
    /// the 401/403 → `Auth` arm (and a non-auth status's `Http` mapping) —
    /// deleting that arm now fails this test (see the report's "prove it
    /// bites" note).
    #[tokio::test]
    async fn hostile_login_responses_are_bounded() {
        for (mode, want) in [
            (Hostile::EndlessBody, KvmError::Protocol("body too large")),
            (Hostile::HugeHeader, KvmError::Protocol("response")),
            (Hostile::Silent, KvmError::Timeout("login")),
            (Hostile::EmptyOk, KvmError::Protocol("login body")),
            (Hostile::Html, KvmError::Protocol("login body")),
            (Hostile::Status(401), KvmError::Auth),
            (Hostile::Status(403), KvmError::Auth),
            (Hostile::Status(503), KvmError::Http(503)),
        ] {
            let ep = hostile(mode).await;
            let t = Instant::now();
            let e = login(&ep, &Secret::new("pw"), CT, LT).await.unwrap_err();
            assert_eq!(e, want);
            assert!(
                t.elapsed() < LT + Duration::from_millis(500),
                "{:?}",
                t.elapsed()
            );
        }
    }
}
