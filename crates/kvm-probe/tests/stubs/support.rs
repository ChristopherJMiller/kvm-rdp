//! Loopback TLS stubs for the kvm-probe integration tests (Tasks 5.8–5.10).
//! No real KVM is reachable from tests, so every test drives one of these
//! instead.
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct Stub {
    pub port: u16,
    pub pin_hex: String,
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
/// connection after reading the request, then close.
pub async fn start_http_stub(response: Vec<u8>) -> Stub {
    let (acceptor, pin_hex) = tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = Arc::new(response);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let (acceptor, response) = (acceptor.clone(), response.clone());
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await; // consume the request head
                let _ = tls.write_all(&response).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Stub { port, pin_hex }
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
