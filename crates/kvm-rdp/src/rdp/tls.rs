//! The RDP listener's TLS identity (§9.1): our own rustls `ServerConfig` on
//! aws-lc-rs — never `TlsIdentityCtx` (DC2), never a key log — and the
//! certificate's subjectPublicKey, which CredSSP binds the NLA exchange to.
//! The key file's bytes never reach an error, a `Debug` or a log line: every
//! failure is one of `TlsError`'s fixed variants.
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio_rustls::TlsAcceptor;

/// Largest PEM file read (a chain of a few certificates fits easily).
pub const MAX_PEM: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Read {
        what: &'static str,
        kind: std::io::ErrorKind,
    },
    TooLarge(&'static str),
    NoCertificate,
    BadCertificate,
    NoKey,
    KeyMismatch,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Read { what, kind } => write!(f, "cannot read the {what} file: {kind}"),
            TlsError::TooLarge(what) => write!(f, "the {what} file is over {MAX_PEM} bytes"),
            TlsError::NoCertificate => f.write_str("no certificate in the certificate file"),
            TlsError::BadCertificate => f.write_str("the certificate does not parse"),
            TlsError::NoKey => f.write_str("no private key in the key file"),
            TlsError::KeyMismatch => f.write_str("the key does not match the certificate"),
        }
    }
}

impl std::error::Error for TlsError {}

/// No `Debug`: the acceptor holds the private key.
pub struct TlsIdentity {
    pub acceptor: TlsAcceptor,
    /// The leaf certificate's subjectPublicKey (BIT STRING contents).
    pub public_key: Vec<u8>,
}

/// §4.2: aws-lc-rs is the one provider, installed idempotently.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn load(cert_file: &Path, key_file: &Path) -> Result<TlsIdentity, TlsError> {
    let cert = read_capped(cert_file, "certificate")?;
    let key = read_capped(key_file, "key")?;
    from_pem(&cert, &key)
}

pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsIdentity, TlsError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::BadCertificate)?;
    let public_key = subject_public_key(certs.first().ok_or(TlsError::NoCertificate)?)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::NoKey)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // `key_log` stays rustls' default `NoKeyLog` (§9.1: no SSLKEYLOGFILE).
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::BadCertificate)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::KeyMismatch)?;
    Ok(TlsIdentity {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        public_key,
    })
}

fn subject_public_key(cert: &CertificateDer<'_>) -> Result<Vec<u8>, TlsError> {
    let (_, parsed) =
        x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| TlsError::BadCertificate)?;
    let spk = &parsed.public_key().subject_public_key;
    if spk.unused_bits != 0 {
        return Err(TlsError::BadCertificate);
    }
    Ok(spk.data.to_vec())
}

fn read_capped(path: &Path, what: &'static str) -> Result<Vec<u8>, TlsError> {
    let file = std::fs::File::open(path).map_err(|e| TlsError::Read {
        what,
        kind: e.kind(),
    })?;
    let mut buf = Vec::new();
    file.take(MAX_PEM + 1)
        .read_to_end(&mut buf)
        .map_err(|e| TlsError::Read {
            what,
            kind: e.kind(),
        })?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_PEM {
        return Err(TlsError::TooLarge(what));
    }
    Ok(buf)
}

/// Both files' modification time and length: what the certificate watcher
/// compares (§4.4: a renewed certificate restarts the bridge).
pub type Fingerprint = [(SystemTime, u64); 2];

#[must_use]
pub fn fingerprint(cert_file: &Path, key_file: &Path) -> Option<Fingerprint> {
    let one = |p: &Path| {
        let m = std::fs::metadata(p).ok()?;
        Some((m.modified().ok()?, m.len()))
    };
    Some([one(cert_file)?, one(key_file)?])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;

    /// A fresh self-signed pair: (cert PEM, key PEM, the raw public key).
    fn pair() -> (String, String, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["kvm-rdp.test".to_owned()]).unwrap();
        (
            ck.cert.pem(),
            ck.key_pair.serialize_pem(),
            ck.key_pair.public_key_raw().to_vec(),
        )
    }

    /// §9.1: CredSSP binds to the certificate's subjectPublicKey — the BIT
    /// STRING's contents, what `ironrdp-tls` extracts on the client — and
    /// our `ServerConfig` never logs keys, whatever `SSLKEYLOGFILE` says.
    #[test]
    fn a_generated_identity_loads_with_its_credssp_key_and_no_key_log() {
        install_crypto_provider();
        let (cert, key, raw) = pair();
        let id = from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(id.public_key, raw);
        assert!(!id.acceptor.config().key_log.will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn broken_or_mismatched_pairs_are_refused() {
        let (cert, key, _) = pair();
        let (_, other_key, _) = pair();
        assert_eq!(
            from_pem(cert.as_bytes(), other_key.as_bytes()).err(),
            Some(TlsError::KeyMismatch)
        );
        assert_eq!(
            from_pem(b"", key.as_bytes()).err(),
            Some(TlsError::NoCertificate)
        );
        assert_eq!(from_pem(cert.as_bytes(), b"").err(), Some(TlsError::NoKey));
        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(
            from_pem(garbage.as_bytes(), key.as_bytes()).err(),
            Some(TlsError::BadCertificate)
        );
    }

    /// Files are read capped (§4.4's secret-file rule, at PEM size), and the
    /// fingerprint the certificate watcher polls changes on a rewrite.
    #[test]
    fn files_are_read_capped_and_fingerprinted() {
        let d = tempfile::tempdir().unwrap();
        let (cert, key, _) = pair();
        let (c, k) = (d.path().join("cert.pem"), d.path().join("key.pem"));
        std::fs::write(&c, &cert).unwrap();
        std::fs::write(&k, &key).unwrap();
        assert!(load(&c, &k).is_ok());
        let before = fingerprint(&c, &k).unwrap();
        std::fs::write(&c, format!("{cert}\n")).unwrap();
        assert_ne!(
            fingerprint(&c, &k).unwrap(),
            before,
            "a renewal rewrites the file"
        );
        assert!(fingerprint(&d.path().join("absent.pem"), &k).is_none());
        assert!(matches!(
            load(&d.path().join("absent.pem"), &k),
            Err(TlsError::Read {
                what: "certificate",
                ..
            })
        ));
        std::fs::write(&c, vec![b'A'; 70_000]).unwrap();
        assert_eq!(load(&c, &k).err(), Some(TlsError::TooLarge("certificate")));
    }
}
