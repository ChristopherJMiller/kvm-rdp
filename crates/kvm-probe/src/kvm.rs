//! Pinned-TLS-or-plain connection to the KVM, and login (§3.2). The pin
//! verifier is the only certificate check: there is no accept-any mode
//! reachable from here (R9) — `fingerprint::observe` (a later task) is the
//! sole caller allowed to pass `pin: None` into `client_config`.

use std::sync::Arc;
use std::time::Duration;

use crate::pin::SpkiPinVerifier;
use crate::request::{self, KvmTarget, Scheme};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

/// Byte stream to the KVM, pinned-TLS or plain (§3.2). Blanket-implemented
/// for anything that is `AsyncRead + AsyncWrite + Unpin + Send`.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type BoxedIo = Box<dyn IoStream>;

/// §9.2: device-sourced text that lands here (status lines, body snippets,
/// header values) must be bounded and escaped so a hostile KVM cannot flood
/// or inject control characters into the operator's terminal. This module
/// satisfies that by construction: these variants only ever carry a numeric
/// status code, the `Debug` of a fixed-variant library enum
/// (`kvm_proto::login::LoginError`, `std::io::Error`, `hyper::Error`,
/// `rustls::Error`), or a static/locally-computed string (the pin
/// mismatch's SPKI hash) — never a raw echo of attacker-controlled bytes.
#[derive(Debug)]
pub enum KvmError {
    Connect(String),
    Tls(String),
    Http(String),
    Login(String),
    Io(String),
}

/// Response bodies read during login are size-capped: never buffer an
/// unbounded hostile body (spec §9.2).
const MAX_LOGIN_BODY: usize = 64 * 1024;

/// Bound for the TCP connect plus (for `Https`) the TLS handshake. The
/// device is hostile by assumption (§9.2): a peer that accepts the TCP
/// connection and then never speaks must not hang the probe forever.
/// `pub(crate)` so `fingerprint::observe` — the one other caller allowed to
/// open a connection (in no-pin record mode, R9) — is bound by the same
/// timeout rather than its own copy.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound for the whole login exchange: connect, handshake, request, and
/// the capped response-body read. Covers a peer that accepts the request
/// and then never answers.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Build the rustls `ClientConfig` that pins the server's SPKI. `pin: None`
/// is "accept whatever is presented" (record mode) and is deliberately not
/// reachable from `connect_to`/`login`/`capture` (R9) — only a later
/// `fingerprint::observe` is allowed to pass `None` here.
pub(crate) fn client_config(pin: Option<&str>) -> tokio_rustls::rustls::ClientConfig {
    let verifier = Arc::new(SpkiPinVerifier::new(pin.map(str::to_string)));
    tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Connect to `port` on the KVM: pinned TLS for `Https`, plain TCP for
/// `Http` (§3.2). `TCP_NODELAY` is set on every socket. An `Https` target
/// with no pin is refused before any network I/O (R9: there is no
/// accept-any path reachable from here). The TCP connect and (for `Https`)
/// the TLS handshake together are bounded by `CONNECT_TIMEOUT`: a silent
/// peer gets a clean `Connect`/`Tls` error, never a hang.
pub async fn connect_to(
    target: &KvmTarget,
    port: u16,
    pin_sha256_hex: Option<&str>,
) -> Result<BoxedIo, KvmError> {
    if matches!(target.scheme, Scheme::Https) && pin_sha256_hex.is_none() {
        return Err(KvmError::Tls("pin required for https".into()));
    }
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_and_handshake(target, port, pin_sha256_hex),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(match target.scheme {
            Scheme::Http => {
                KvmError::Connect(format!("connect timed out after {CONNECT_TIMEOUT:?}"))
            }
            Scheme::Https => KvmError::Tls(format!(
                "connect/handshake timed out after {CONNECT_TIMEOUT:?}"
            )),
        }),
    }
}

async fn connect_and_handshake(
    target: &KvmTarget,
    port: u16,
    pin_sha256_hex: Option<&str>,
) -> Result<BoxedIo, KvmError> {
    let tcp = TcpStream::connect((target.host.as_str(), port))
        .await
        .map_err(|e| KvmError::Connect(e.to_string()))?;
    tcp.set_nodelay(true)
        .map_err(|e| KvmError::Connect(e.to_string()))?;
    match target.scheme {
        Scheme::Http => Ok(Box::new(tcp)),
        Scheme::Https => {
            let connector = TlsConnector::from(Arc::new(client_config(pin_sha256_hex)));
            let name = ServerName::try_from(target.host.clone())
                .map_err(|_| KvmError::Tls("bad server name".into()))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .map_err(|e| KvmError::Tls(format!("{e}")))?;
            Ok(Box::new(tls))
        }
    }
}

/// Read a response body up to `MAX_LOGIN_BODY` bytes, refusing anything
/// larger rather than buffering an unbounded hostile body (spec §9.2).
async fn read_capped_body(mut body: hyper::body::Incoming) -> Result<Vec<u8>, KvmError> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| KvmError::Http(e.to_string()))?;
        if let Some(chunk) = frame.data_ref() {
            if buf.len().saturating_add(chunk.len()) > MAX_LOGIN_BODY {
                return Err(KvmError::Login(format!(
                    "login response body exceeds {MAX_LOGIN_BODY}-byte cap"
                )));
            }
            buf.extend_from_slice(chunk);
        }
    }
    Ok(buf)
}

/// `POST /cgi-bin/login.lua` and return the `0.<digits>` session token
/// (§3.1). The returned string is exactly the `Token` that
/// `kvm_proto::login::parse_login_token` produced — there is no second,
/// independent parse of the response body. The whole exchange (connect,
/// handshake, request, and the capped response read) is bounded by
/// `LOGIN_TIMEOUT`: a peer that accepts the request and never answers gets
/// a clean `Login` error, never a hang.
pub async fn login(
    target: &KvmTarget,
    pin: Option<&str>,
    password: &str,
    now_unix: i64,
    timezone: &str,
) -> Result<String, KvmError> {
    match tokio::time::timeout(
        LOGIN_TIMEOUT,
        login_inner(target, pin, password, now_unix, timezone),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(KvmError::Login(format!(
            "login timed out after {LOGIN_TIMEOUT:?}"
        ))),
    }
}

async fn login_inner(
    target: &KvmTarget,
    pin: Option<&str>,
    password: &str,
    now_unix: i64,
    timezone: &str,
) -> Result<String, KvmError> {
    let io = connect_to(target, target.login_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // `password` is only ever handed to `build_login_body`; it never
    // appears in a log line, panic message, or `KvmError` (spec §9.2).
    let body = request::build_login_body(password, timezone, now_unix);
    let req = Request::builder()
        .method("POST")
        .uri("/cgi-bin/login.lua")
        .header("Host", &target.host)
        .header("Content-Type", "application/json")
        .body(Full::new(hyper::body::Bytes::from(body)))
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status();
    if status != hyper::StatusCode::OK {
        return Err(KvmError::Login(format!("http status {}", status.as_u16())));
    }
    let bytes = read_capped_body(resp.into_body()).await?;
    let token = kvm_proto::login::parse_login_token(&bytes)
        .map_err(|e| KvmError::Login(format!("{e:?}")))?;
    Ok(token.into_string())
}
