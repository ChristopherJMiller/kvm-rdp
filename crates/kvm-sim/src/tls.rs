//! One self-signed certificate on all three ports, as on the ES3 (§3.2), and
//! the SHA-256 of its SPKI that a test config pins.
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub(crate) struct Identity {
    pub acceptor: TlsAcceptor,
    /// Lowercase hex SHA-256 of the certificate's SubjectPublicKeyInfo.
    pub spki_sha256: String,
}

pub(crate) fn identity() -> std::io::Result<Identity> {
    let err = |e: &dyn std::fmt::Display| std::io::Error::other(e.to_string());
    let ck =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
            .map_err(|e| err(&e))?;
    let spki_sha256 = Sha256::digest(ck.key_pair.public_key_der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).map_err(|e| err(&e))?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| err(&e))?;
    Ok(Identity {
        acceptor: TlsAcceptor::from(Arc::new(cfg)),
        spki_sha256,
    })
}
