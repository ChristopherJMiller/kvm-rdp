//! `web-get` (§12): the KVM's web pages, for the firmware line the census
//! still lacks. Status, the `Server` header and a bounded, escaped snippet
//! — never the whole hostile page. No login, no token.
//!
//! It can never log out or type (owner rules, §3.2): the KVM's dynamic
//! endpoints — `/cgi-bin/login.lua?logout` is the global logout, and a
//! CGI script can type — are refused, as is every path that is not on
//! `check_path`'s allowlist of static pages, before anything connects.
use super::escaped;
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use std::time::Duration;

const MAX_SNIPPET: usize = 512;
const MAX_SERVER: usize = 120;
/// The whole GET's bound: connect, request, headers and the snippet.
pub const GET_TIMEOUT: Duration = Duration::from_secs(10);
/// The most characters after the leading `/` (PD4 m3).
pub const MAX_PATH: usize = 128;

/// The static files `web-get` fetches, by extension (any case); the only
/// other path it fetches is `/` itself.
pub const STATIC_EXTENSIONS: [&str; 7] = [".html", ".htm", ".js", ".css", ".txt", ".json", ".xml"];

#[derive(Debug, Clone)]
pub struct Page {
    pub status: u16,
    pub server: Option<String>,
    pub snippet: String,
}

/// PD4 m3, r-m1: an allowlist. A path passes only if it is `/` itself, or
/// `/` followed by at most `MAX_PATH` characters of `[A-Za-z0-9._/-]` (so
/// no query, fragment, percent-escape, `;`, space or control byte) with no
/// `..`, `.lua`, `.cgi`, `cgi-bin`, `login` or `logout` anywhere (any
/// case), no empty segment and no segment starting with `.` (so no `.`,
/// `..` or dotfile), naming a static file (`STATIC_EXTENSIONS`). Everything
/// else is refused: a script, an extensionless name, a backup, and any
/// directory but `/` (its index can be a script).
pub fn check_path(path: &str) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("web-get fetches only a static page's path: {why}"));
    let Some(rest) = path.strip_prefix('/') else {
        return refuse("it must start with /");
    };
    if rest.is_empty() {
        return Ok(());
    }
    if rest.len() > MAX_PATH {
        return refuse("it is too long");
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return refuse("only letters, digits and / . _ - (no query, fragment or escape)");
    }
    let lower = rest.to_ascii_lowercase();
    if ["..", ".lua", ".cgi", "cgi-bin", "login", "logout"]
        .iter()
        .any(|w| lower.contains(w))
    {
        return refuse("never .., a script, CGI, login or logout");
    }
    if lower.split('/').any(|s| s.is_empty() || s.starts_with('.')) {
        return refuse("no empty segment (so no directory but /), . segment or dotfile");
    }
    if !STATIC_EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
        return refuse("only / or a .html .htm .js .css .txt .json .xml file");
    }
    Ok(())
}

/// GET `path` (a static page's, `check_path`, else refused before
/// anything connects), bounded by `GET_TIMEOUT`.
pub async fn get(t: &KvmTarget, pin: Option<&str>, path: &str) -> Result<Page, KvmError> {
    get_within(t, pin, path, GET_TIMEOUT).await
}

/// `get`, bounded by `within` instead (tests shorten it).
pub async fn get_within(
    t: &KvmTarget,
    pin: Option<&str>,
    path: &str,
    within: Duration,
) -> Result<Page, KvmError> {
    check_path(path).map_err(KvmError::Io)?;
    tokio::time::timeout(within, get_inner(t, pin, path))
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

    /// PD4 m3, r-m1: an allowlist — `/` itself, or a static file (`.html .htm
    /// .js .css .txt .json .xml`, any case) under at most 128 characters of
    /// `[A-Za-z0-9._/-]` — passes.
    #[test]
    fn only_a_static_path_passes() {
        // The ruling's 128, as literals: a bound derived from `MAX_PATH`
        // would move with it.
        assert_eq!(MAX_PATH, 128);
        let longest = format!("/{}.html", "a".repeat(123));
        assert_eq!(longest.len(), 1 + 128);
        for ok in [
            "/",
            "/about.html",
            "/About.HTM",
            "/static/js/app.min.js",
            "/css/site.css",
            "/a_b-c/d.html",
            "/version.txt",
            "/api/info.json",
            "/sitemap.xml",
            longest.as_str(),
        ] {
            assert_eq!(check_path(ok), Ok(()), "{ok}");
        }
    }

    /// PD4 m3: everything else is refused — each line a way to reach a
    /// script, a hidden file or another host past a check: the global
    /// logout and every ES3 `cgi-bin/*.lua` form, any case; a query,
    /// fragment, escape, `;`, space, backslash, control or non-ASCII byte;
    /// `.`/`..`/dot segments and dotfiles; an empty segment; a script or
    /// an extensionless name; a missing leading `/`; past 128 characters.
    #[test]
    fn everything_else_is_refused() {
        let past = format!("/{}.html", "a".repeat(124));
        assert_eq!(past.len(), 1 + 129);
        for bad in [
            "/cgi-bin/login.lua?logout",
            "/cgi-bin/login.lua",
            "/cgi-bin/",
            "/CGI-BIN/x.html",
            "/Cgi-Bin/index.html",
            "/cgi-bin.html",
            "/hid.lua",
            "/x.LUA",
            "/x.lua.html",
            "/x.cgi",
            "/x.Cgi.html",
            "/logout",
            "/logout.html",
            "/Login.html",
            "/x.html?logout",
            "/x?logout",
            "/x.html#y",
            "/%63gi-bin/x.html",
            "/x.html%00",
            "/x.html;logout",
            "/a b.html",
            "/a\\b.html",
            "/a\tb.html",
            "/a.html\r\nX: y",
            "/\u{e9}.html",
            "/x.html\u{200b}",
            "/../x.html",
            "/a/../b.html",
            "/a/..html",
            "/a..b.html",
            "/./x.html",
            "/a/./b.html",
            "/.git/config",
            "/.env",
            "/a/.hidden.html",
            "/.html",
            "//evil/x.html",
            "/a//b.html",
            "/x.sh",
            "/x.php",
            "/x.pl",
            "/reboot",
            "/signout",
            "/upload",
            "/x.html.bak",
            // r-m1: no directory but `/` itself — an index can be a script.
            "/x/",
            "/cgi/",
            "/upload/",
            "/static/",
            "/a_b-c/",
            "/about.html/",
            "/css/site.css/",
            "x.html",
            "",
            "http://evil/x.html",
            past.as_str(),
        ] {
            let e = check_path(bad).unwrap_err();
            assert!(e.starts_with("web-get"), "{bad:?}: {e}");
        }
    }
}
