//! `web-get` (§12): the KVM's web pages, for the firmware line the census
//! still lacks. Status, the `Server` header and a bounded, escaped snippet
//! — never the whole hostile page. No login, no token.
//!
//! It can never log out or type (owner rules, §3.2): the KVM's dynamic
//! endpoints — `/cgi-bin/login.lua?logout` is the global logout, and a
//! CGI script can type — are refused with every path that is not a plain
//! static one (`check_path`), before anything connects.
use super::escaped;
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use std::time::Duration;

const MAX_SNIPPET: usize = 512;
const MAX_SERVER: usize = 120;
const GET_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest `--path`.
pub const MAX_PATH: usize = 256;

#[derive(Debug, Clone)]
pub struct Page {
    pub status: u16,
    pub server: Option<String>,
    pub snippet: String,
}

/// A static page's path, or why not: absolute, at most `MAX_PATH` bytes of
/// `[A-Za-z0-9/._-]` (so no query, fragment, percent-escape or space), no
/// empty, `.` or `..` segment, and nothing naming a script, CGI, login or
/// logout (any case).
pub fn check_path(path: &str) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("web-get fetches only a static page's path: {why}"));
    if !path.starts_with('/') {
        return refuse("it must start with /");
    }
    if path.len() > MAX_PATH {
        return refuse("it is too long");
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return refuse("only letters, digits and / . _ - (no query, fragment or escape)");
    }
    // The leading '/' gives one empty first segment; a trailing one ("/x/")
    // is a directory index and is fine.
    let mut segments = path.split('/').skip(1).peekable();
    while let Some(s) = segments.next() {
        if matches!(s, "." | "..") || (s.is_empty() && segments.peek().is_some()) {
            return refuse("no empty, . or .. segment");
        }
    }
    let lower = path.to_ascii_lowercase();
    if ["cgi", ".lua", "login", "logout"]
        .iter()
        .any(|w| lower.contains(w))
    {
        return refuse("never a script, CGI, login or logout");
    }
    Ok(())
}

pub async fn get(t: &KvmTarget, pin: Option<&str>, path: &str) -> Result<Page, KvmError> {
    check_path(path).map_err(KvmError::Io)?;
    tokio::time::timeout(GET_TIMEOUT, get_inner(t, pin, path))
        .await
        .map_err(|_| KvmError::Http(format!("web-get: GET {path} timed out")))?
}

async fn get_inner(t: &KvmTarget, pin: Option<&str>, path: &str) -> Result<Page, KvmError> {
    let io = kvm::connect_to(t, t.login_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", &t.host)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    let server = resp
        .headers()
        .get("server")
        .map(|v| escaped(v.as_bytes(), MAX_SERVER));
    let mut body: Vec<u8> = Vec::new();
    let mut incoming = resp.into_body();
    while body.len() < MAX_SNIPPET {
        match incoming.frame().await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    let room = MAX_SNIPPET.saturating_sub(body.len());
                    body.extend_from_slice(d.get(..room.min(d.len())).unwrap_or_default());
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    Ok(Page {
        status,
        server,
        snippet: escaped(&body, MAX_SNIPPET),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Static pages pass; anything that could reach a script — the global
    /// logout first — or smuggle one past the check is refused.
    #[test]
    fn only_a_static_path_passes() {
        for ok in [
            "/",
            "/about.html",
            "/static/js/app.min.js",
            "/a_b-c/",
            "/version.txt",
        ] {
            assert_eq!(check_path(ok), Ok(()), "{ok}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH));
        for bad in [
            "/cgi-bin/login.lua?logout",
            "/cgi-bin/login.lua",
            "/cgi-bin/",
            "/CGI-BIN/x",
            "/hid.lua",
            "/x.LUA",
            "/logout",
            "/Login.html",
            "/x?logout",
            "/x#y",
            "/%63gi-bin/x",
            "/a b",
            "/a\\b",
            "/../x",
            "/a/./b",
            "/a/..",
            "//evil/",
            "/a//b",
            "x",
            "",
            "http://evil/",
            long.as_str(),
        ] {
            let e = check_path(bad).unwrap_err();
            assert!(e.starts_with("web-get"), "{bad:?}: {e}");
        }
    }
}
