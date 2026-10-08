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
    /// A key aws-lc-rs will not sign with (RSA under 2048 bits; a curve other
    /// than P-256, P-384, P-521 or Ed25519) or a malformed key body (m9).
    UnsupportedKey,
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
            TlsError::UnsupportedKey => f.write_str(
                "the private key's type or size is not supported (RSA needs at least 2048 bits)",
            ),
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
    let config = server_config(certs, key)?;
    Ok(TlsIdentity {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        public_key,
    })
}

/// Our own `ServerConfig` on aws-lc-rs. `key_log` stays rustls' default
/// `NoKeyLog` (§9.1: no SSLKEYLOGFILE). rustls' errors become fixed
/// variants, so no key byte or rustls text reaches an error (m9).
fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        // Unreachable with aws-lc-rs' default provider (it has every version).
        .map_err(|_| TlsError::BadCertificate)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| match e {
            // The key is valid but is not the leaf certificate's.
            rustls::Error::InconsistentKeys(_) => TlsError::KeyMismatch,
            // webpki refused the leaf x509-parser accepted.
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                TlsError::BadCertificate
            }
            // The provider would not load the key (`Error::General`).
            _ => TlsError::UnsupportedKey,
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
        let renewed = fingerprint(&c, &k).unwrap();
        std::fs::write(&k, format!("{key}\n")).unwrap();
        assert_ne!(
            fingerprint(&c, &k).unwrap(),
            renewed,
            "a renewal that rewrites only the key file is seen too (m6)"
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

    /// m5: deployment loads a full chain (leaf, then its issuer). CredSSP
    /// binds to the leaf's key — the one the client's TLS sees — never an
    /// issuer's, which would fail NLA for every client.
    #[test]
    fn the_credssp_key_is_the_leafs_in_a_full_chain() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["kvm-rdp.test".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        let chain = format!("{}{}", leaf.pem(), ca.pem());
        let id = from_pem(chain.as_bytes(), leaf_key.serialize_pem().as_bytes()).unwrap();
        assert_eq!(id.public_key, leaf_key.public_key_raw());
        assert_ne!(id.public_key, ca_key.public_key_raw());
    }

    /// A SEC1 key on secp256k1, built here (the scalar is 1..=32, no
    /// secret): a curve aws-lc-rs does not sign with.
    fn secp256k1_key() -> PrivateKeyDer<'static> {
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x01, 0x04, 0x20];
        der.extend(1..=32u8);
        der.extend([0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]);
        PrivateKeyDer::Sec1(der.into())
    }

    /// m9: a key aws-lc-rs will not load — an unsupported curve or a
    /// malformed body (RSA under 2048 bits takes the same path) — is not
    /// called a mismatch, and the error carries none of the key's bytes.
    #[test]
    fn unsupported_keys_are_not_called_a_mismatch() {
        let (cert, _, _) = pair();
        let certs = CertificateDer::pem_slice_iter(cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            server_config(certs, secp256k1_key()).err(),
            Some(TlsError::UnsupportedKey)
        );
        let malformed = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let e = from_pem(cert.as_bytes(), malformed.as_bytes()).err();
        assert_eq!(e, Some(TlsError::UnsupportedKey));
        let shown = e.map(|e| format!("{e:?} {e}")).unwrap();
        assert!(!shown.contains("AAAA"), "{shown}");
    }
}
