//! Connections to the KVM (§3.2): `TCP_NODELAY` on every socket and, for
//! `https`, TLS whose only certificate check is the SPKI pin — one pin for
//! all three ports. There is no accept-any verifier.
//!
//! Same pin rule and SPKI hash as `kvm-probe fingerprint` (which records
//! `kvm.spki_sha256`); the two must stay byte-compatible (P18).
use crate::config::{KvmConfig, Scheme};
use crate::kvm::error::KvmError;
use crate::logging::redact_url;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type KvmIo = Box<dyn IoStream>;

pub struct KvmEndpoint {
    pub scheme: Scheme,
    pub host: String,
    pub web_port: u16,
    pub video_port: u16,
    pub control_port: u16,
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl KvmEndpoint {
    pub fn new(
        scheme: Scheme,
        host: impl Into<String>,
        ports: (u16, u16, u16),
        spki_sha256_hex: &str,
    ) -> KvmEndpoint {
        KvmEndpoint {
            scheme,
            host: host.into(),
            web_port: ports.0,
            video_port: ports.1,
            control_port: ports.2,
            pin: spki_sha256_hex.to_ascii_lowercase(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }

    #[must_use]
    pub fn from_config(c: &KvmConfig) -> KvmEndpoint {
        KvmEndpoint::new(
            c.scheme,
            c.host.clone(),
            (c.web_port, c.video_port, c.control_port),
            &c.spki_sha256,
        )
    }

    /// `scheme://host:port/path` for logs (§4.5).
    #[must_use]
    pub fn url_for_log(&self, port: u16, path: &str) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        redact_url(scheme, &self.host, port, path)
    }

    /// TCP (+ pinned TLS) to `port`, bounded by `timeout`.
    pub async fn connect(&self, port: u16, timeout: Duration) -> Result<KvmIo, KvmError> {
        match tokio::time::timeout(timeout, self.connect_inner(port)).await {
            Ok(r) => r,
            Err(_) => Err(KvmError::Timeout("connect")),
        }
    }

    async fn connect_inner(&self, port: u16) -> Result<KvmIo, KvmError> {
        let tcp = TcpStream::connect((self.host.as_str(), port))
            .await
            .map_err(|e| KvmError::Connect(e.kind()))?;
        tcp.set_nodelay(true)
            .map_err(|e| KvmError::Connect(e.kind()))?;
        match self.scheme {
            Scheme::Http => Ok(Box::new(tcp)),
            Scheme::Https => {
                let mismatch = Arc::new(AtomicBool::new(false));
                let verifier = Arc::new(PinVerifier {
                    expected: self.pin.clone(),
                    provider: self.provider.clone(),
                    mismatch: mismatch.clone(),
                });
                let cfg = ClientConfig::builder_with_provider(self.provider.clone())
                    .with_safe_default_protocol_versions()
                    .map_err(|_| KvmError::Tls)?
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();
                let name = ServerName::try_from(self.host.clone()).map_err(|_| KvmError::Tls)?;
                match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
                    Ok(tls) => Ok(Box::new(tls)),
                    Err(_) if mismatch.load(Ordering::SeqCst) => Err(KvmError::CertMismatch),
                    Err(_) => Err(KvmError::Tls),
                }
            }
        }
    }
}

/// Lowercase hex SHA-256 of a certificate's SubjectPublicKeyInfo.
#[must_use]
pub fn spki_sha256_hex(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(
        Sha256::digest(cert.public_key().raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

struct PinVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
    mismatch: Arc<AtomicBool>,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinVerifier")
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if spki_sha256_hex(end_entity.as_ref()).as_deref() == Some(self.expected.as_str()) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.store(true, Ordering::SeqCst);
            Err(TlsError::General("kvm_cert_mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
