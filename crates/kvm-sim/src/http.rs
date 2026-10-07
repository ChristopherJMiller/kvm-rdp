//! Just enough HTTP/1.1 for the ES3's three request shapes, parsed with
//! httparse (hyper's own parser). kvm-sim writes responses itself so every
//! FLV byte write is observable (`sim_tx`, back-pressure) and corruptible.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Request heads and bodies are small on the ES3; refuse anything bigger.
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 4 * 1024;

pub(crate) struct Request {
    pub method: String,
    /// Path and query, as sent.
    pub target: String,
    pub cookie_token: Option<String>,
    pub body: Vec<u8>,
}

impl Request {
    pub(crate) fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    pub(crate) fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    /// The `token` query parameter.
    pub(crate) fn query_token(&self) -> Option<&str> {
        self.query()
            .split('&')
            .find_map(|kv| kv.strip_prefix("token="))
    }
}

/// `token=<value>` from a `Cookie` header.
pub(crate) fn cookie_token(value: &str) -> Option<String> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("token="))
        .map(str::to_owned)
}

/// Read one request head (and a `Content-Length` body) from `io`.
pub(crate) async fn read_request<S: AsyncRead + Unpin>(io: &mut S) -> Option<Request> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = io.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let mut content_length = 0usize;
                let mut cookie = None;
                for h in req.headers.iter() {
                    let v = std::str::from_utf8(h.value).unwrap_or("");
                    if h.name.eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().ok()?;
                    } else if h.name.eq_ignore_ascii_case("cookie") {
                        cookie = cookie_token(v);
                    }
                }
                if content_length > MAX_BODY {
                    return None;
                }
                let method = req.method?.to_owned();
                let target = req.path?.to_owned();
                let mut body = buf.get(head_len..)?.to_vec();
                while body.len() < content_length {
                    let n = io.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    body.extend_from_slice(chunk.get(..n)?);
                }
                body.truncate(content_length);
                return Some(Request {
                    method,
                    target,
                    cookie_token: cookie,
                    body,
                });
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            _ => return None,
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A complete response with a `Content-Length` body; the connection closes.
pub(crate) async fn respond<S: AsyncWrite + Unpin>(
    io: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    io.write_all(head.as_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    io.shutdown().await
}

/// The head of a close-delimited streaming FLV response.
pub(crate) const FLV_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
