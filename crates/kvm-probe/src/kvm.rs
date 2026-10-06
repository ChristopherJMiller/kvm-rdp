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

/// Bound for the whole logout exchange (final review m1; §3.2 "teardown
/// calls logout, best effort, bounded"): connect, handshake, request and
/// response head.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);

/// Log out of the KVM session `token` belongs to: `GET` the path of
/// `request::logout_url` (`/cgi-bin/login.lua?logout`) on the web port,
/// with the token cookie (§3.1, §3.2), bounded by `LOGOUT_TIMEOUT`. Any 2xx
/// or 3xx answer counts as logged out; anything else is an error naming
/// only the status code — the response body (device text) is never read
/// into it. Callers treat a failure as best effort: report it, carry on.
pub async fn logout(target: &KvmTarget, pin: Option<&str>, token: &str) -> Result<(), KvmError> {
    match tokio::time::timeout(LOGOUT_TIMEOUT, logout_inner(target, pin, token)).await {
        Ok(result) => result,
        Err(_) => Err(KvmError::Http(format!(
            "logout timed out after {LOGOUT_TIMEOUT:?}"
        ))),
    }
}

async fn logout_inner(target: &KvmTarget, pin: Option<&str>, token: &str) -> Result<(), KvmError> {
    // The request target is the origin-form path of the one logout URL
    // builder (`request::logout_url`), as `login` sends its own path.
    let url: hyper::Uri = request::logout_url(target)
        .parse()
        .map_err(|e| KvmError::Http(format!("logout url: {e}")))?;
    let path = url
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .ok_or_else(|| KvmError::Http("logout url has no path".into()))?;
    let io = connect_to(target, target.login_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", &target.host)
        .header("Cookie", request::token_cookie_header(token))
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status();
    if status.is_success() || status.is_redirection() {
        Ok(())
    } else {
        Err(KvmError::Http(format!(
            "logout http status {}",
            status.as_u16()
        )))
    }
}

/// The timezone every kvm-probe login reports (`login.lua`'s `timezone`
/// field): the probe has no reason to reveal the operator's.
pub const PROBE_TIMEZONE: &str = "UTC";

/// What a logged-in session produced: the work's output, and how its
/// logout went (final review m1).
#[derive(Debug)]
pub struct Session<T> {
    pub output: T,
    pub logout: Result<(), KvmError>,
}

/// Log in, run `work` with the token, then log out with it — always, even
/// when the work itself failed (final review m1): every kvm-probe run that
/// logs in releases its KVM session, so a census of many runs never piles up live
/// sessions against the device's session cap. A failed login is the error (there is no token,
/// so nothing to log out); a failed logout is reported in
/// `Session::logout`, never turned into the session's error.
pub async fn with_session<T>(
    target: &KvmTarget,
    pin: Option<&str>,
    password: &str,
    now_unix: i64,
    timezone: &str,
    work: impl AsyncFnOnce(&str) -> T,
) -> Result<Session<T>, KvmError> {
    let token = login(target, pin, password, now_unix, timezone).await?;
    let output = work(&token).await;
    let logout = logout(target, pin, &token).await;
    Ok(Session { output, logout })
}

/// §9.2's bound on device-influenced text reaching the terminal.
const MAX_ERROR_TEXT: usize = 200;

/// Render an error for the operator's terminal (final review m1/m7): its
/// `Debug` form, which escapes control characters, cut to at most
/// `MAX_ERROR_TEXT` bytes (on a char boundary, marked with `…`).
pub fn bounded_debug(e: &impl std::fmt::Debug) -> String {
    let text = format!("{e:?}");
    if text.len() <= MAX_ERROR_TEXT {
        return text;
    }
    let mut end = MAX_ERROR_TEXT;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut out = text.get(..end).unwrap_or_default().to_string();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// m1/m7: an error shown to the operator is escaped (no raw control
    /// bytes) and bounded at 200 bytes plus the `…` marker, even when it
    /// is long and multi-byte at the cut.
    #[test]
    fn bounded_debug_escapes_and_bounds() {
        let long = format!("\u{1b}]0;title\u{7}{}", "é".repeat(300));
        let out = bounded_debug(&KvmError::Http(long));
        assert!(out.len() <= MAX_ERROR_TEXT.saturating_add('…'.len_utf8()));
        assert!(out.ends_with('…'), "{out}");
        assert!(!out.chars().any(char::is_control), "{out:?}");
        assert!(out.starts_with("Http(\"\\u{1b}]0;title\\u{7}"), "{out}");

        let short = bounded_debug(&KvmError::Http("logout http status 500".into()));
        assert_eq!(short, "Http(\"logout http status 500\")");
    }
}
