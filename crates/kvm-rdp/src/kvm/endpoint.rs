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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
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
    /// The FLV connection tasks dropped and aborted, not yet waited for.
    pub(crate) reaper: Arc<Reaper>,
}

/// Connection tasks that were aborted but may not have been dropped yet
/// (PC17 I1). Each task owns its socket, so the socket closes only once
/// the runtime next polls the task. `Session::close` waits for these, so
/// an old FLV's close is on the wire before the next session's login.
#[derive(Default)]
pub struct Reaper(Mutex<Vec<JoinHandle<()>>>);

impl Reaper {
    /// Keep an aborted task (dropping the finished ones kept before).
    pub(crate) fn keep(&self, task: JoinHandle<()>) {
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        kept.retain(|t| !t.is_finished());
        kept.push(task);
    }

    /// Every task kept since the last call.
    pub(crate) fn take(&self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
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
            reaper: Arc::default(),
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
        match tokio::time::timeout(timeout, self.connect_inner(port, false)).await {
            Ok(r) => r.map(|(io, _)| io),
            Err(_) => Err(KvmError::Timeout("connect")),
        }
    }

    /// `connect`, plus a second handle on the connection's socket, so its
    /// owner can end it with a reset (`SocketHandle::reset_on_close`).
    pub async fn connect_resettable(
        &self,
        port: u16,
        timeout: Duration,
    ) -> Result<(KvmIo, SocketHandle), KvmError> {
        match tokio::time::timeout(timeout, self.connect_inner(port, true)).await {
            Ok(Ok((io, Some(h)))) => Ok((io, h)),
            Ok(Ok((_, None))) => Err(KvmError::Protocol("socket handle")),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(KvmError::Timeout("connect")),
        }
    }

    async fn connect_inner(
        &self,
        port: u16,
        handle: bool,
    ) -> Result<(KvmIo, Option<SocketHandle>), KvmError> {
        let tcp = TcpStream::connect((self.host.as_str(), port))
            .await
            .map_err(|e| KvmError::Connect(e.kind()))?;
        tcp.set_nodelay(true)
            .map_err(|e| KvmError::Connect(e.kind()))?;
        let handle = if handle {
            let dup = socket2::SockRef::from(&tcp)
                .try_clone()
                .map_err(|e| KvmError::Connect(e.kind()))?;
            Some(SocketHandle(dup))
        } else {
            None
        };
        let io = self.secure(tcp).await?;
        Ok((io, handle))
    }

    /// Pinned TLS over `tcp` for `https`; `tcp` itself for `http`.
    async fn secure(&self, tcp: TcpStream) -> Result<KvmIo, KvmError> {
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

/// A second handle on a connection's socket (a duplicated descriptor; I2,
/// PC9 fix round 1). Dropping it does nothing to the connection, but it
/// keeps the socket open while it lives: hold it no longer than the
/// connection.
pub struct SocketHandle(socket2::Socket);

impl SocketHandle {
    /// End the connection with a reset (`SO_LINGER` 0 → RST) once its last
    /// handle closes: whatever the kernel has not yet sent is discarded,
    /// never delivered late.
    pub fn reset_on_close(&self) {
        let _ = self.0.set_linger(Some(Duration::ZERO));
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
