use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
// `Certificate::from_der` is a trait method (der::Decode), not an inherent
// fn — x509-cert 0.3 doesn't re-export it into scope automatically.
use x509_cert::der::Decode as _;

pub struct TlsMaterial {
    pub acceptor: TlsAcceptor,
    /// Raw subjectPublicKey BIT STRING contents — what `with_hybrid` wants.
    pub spki_pub_key: Vec<u8>,
}

pub fn self_signed(san: &str) -> anyhow::Result<TlsMaterial> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![san.to_owned()]).context("gen self-signed cert")?;

    let cert_der_bytes = cert.der().to_vec();
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow!("convert key DER: {e}"))?;

    // Extract the inner public-key bytes (NOT the SPKI wrapper) for CredSSP.
    let parsed =
        x509_cert::Certificate::from_der(&cert_der_bytes).context("parse cert DER for SPKI")?;
    let spki_pub_key = parsed
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec();
    anyhow::ensure!(!spki_pub_key.is_empty(), "empty subjectPublicKey");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der_bytes)], key_der)
        .context("build rustls ServerConfig")?;

    Ok(TlsMaterial {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        spki_pub_key,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_signed_yields_nonempty_pubkey_and_acceptor() {
        let m = super::self_signed("kvm-bridge.spike").expect("tls material");
        assert!(
            !m.spki_pub_key.is_empty(),
            "pub key must be the raw BIT STRING, non-empty"
        );
    }
}
