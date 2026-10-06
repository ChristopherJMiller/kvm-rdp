//! Loopback TLS stubs for the kvm-probe integration tests (Tasks 5.8–5.10).
//! No real KVM is reachable from tests, so every test drives one of these
//! instead.
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct Stub {
    pub port: u16,
    pub pin_hex: String,
    /// Every request head this stub received (request line + headers, lossy
    /// UTF-8), in arrival order — so a test can see e.g. that a logout was
    /// sent, and with which cookie.
    pub requests: Arc<Mutex<Vec<String>>>,
}

/// Read one request head (up to the blank line, or 4 KiB, or EOF).
async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < 4096 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A self-signed loopback TLS identity and the SHA-256(SPKI) hex pin of it.
pub fn tls_acceptor_and_pin() -> (TlsAcceptor, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert = tokio_rustls::rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der())
        .unwrap();
    let pin_hex = kvm_probe::fingerprint::spki_sha256_hex(&ck.key_pair.public_key_der());
    let cfg = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    (TlsAcceptor::from(Arc::new(cfg)), pin_hex)
}

/// Serve `response` verbatim (status line, headers, body) to every TLS
/// connection after reading (and recording) the request head, then close.
/// The head is recorded before the response is written, so once a client
/// has its response the request is already in `Stub::requests`.
pub async fn start_http_stub(response: Vec<u8>) -> Stub {
    let (acceptor, pin_hex) = tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = Arc::new(response);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let (acceptor, response, recorded) =
                (acceptor.clone(), response.clone(), recorded.clone());
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let head = read_head(&mut tls).await;
                recorded.lock().unwrap().push(head);
                let _ = tls.write_all(&response).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Stub {
        port,
        pin_hex,
        requests,
    }
}

pub fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

pub async fn start_login_stub() -> Stub {
    start_http_stub(http_response(
        "200 OK",
        "application/json",
        br#"{"result":0,"token":"0.987654","role":"admin"}"#,
    ))
    .await
}

pub fn flv_fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/360p30_main_full.flv"
    ))
    .unwrap()
}

/// Serve the committed fixture with a close-delimited body, exactly as a
/// streaming FLV endpoint does.
pub async fn start_flv_stub() -> Stub {
    let mut resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nConnection: close\r\n\r\n".to_vec();
    resp.extend_from_slice(&flv_fixture());
    start_http_stub(resp).await
}

pub struct WsStub {
    pub port: u16,
    pub pin_hex: String,
    pub saw_cookie: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub data_frames: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// A loopback TLS websocket stub (Task 5.10). Accepts exactly one
/// connection, records whether the upgrade request carried the token
/// cookie, then counts every data (text/binary) frame received until the
/// client closes — the control-websocket probe must send none.
///
/// `result_large_err`: the handshake callback's signature is fixed by
/// `tokio_tungstenite::accept_hdr_async`'s `Callback` trait (its `Err` is a
/// full `http::Response`); this is test-only stub code, not a library
/// return type we control.
#[allow(clippy::result_large_err)]
pub async fn start_ws_stub() -> WsStub {
    use futures_util::StreamExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    let (acceptor, pin_hex) = tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let saw_cookie = Arc::new(AtomicBool::new(false));
    let data_frames = Arc::new(AtomicUsize::new(0));
    let (sc, df) = (saw_cookie.clone(), data_frames.clone());
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let cb = |req: &Request, resp: Response| {
            let ok = req
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("token=0.987654"));
            sc.store(ok, Ordering::SeqCst);
            Ok(resp)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(tls, cb).await.unwrap();
        while let Some(Ok(msg)) = ws.next().await {
            if msg.is_binary() || msg.is_text() {
                df.fetch_add(1, Ordering::SeqCst);
            }
            if msg.is_close() {
                break;
            }
        }
    });
    WsStub {
        port,
        pin_hex,
        saw_cookie,
        data_frames,
    }
}
