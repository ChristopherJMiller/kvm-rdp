use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Errors from parsing a certificate to extract its SPKI (§3.2).
#[derive(Debug)]
pub enum PinError {
    Parse,
}

/// Extract the DER-encoded SubjectPublicKeyInfo from an X.509 certificate.
pub fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, PinError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|_| PinError::Parse)?;
    Ok(cert.public_key().raw.to_vec())
}

/// rustls `ServerCertVerifier` that pins the server's SPKI by SHA-256 hex
/// (§3.2). There is no accept-any mode except the explicit `None` pin used
/// for `--print-fingerprint` capture, where the caller has not yet seen a
/// pin to check against.
pub struct SpkiPinVerifier {
    expected_hex: Option<String>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for SpkiPinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpkiPinVerifier")
            .field("pinned", &self.expected_hex.is_some())
            .finish()
    }
}

impl SpkiPinVerifier {
    /// `expected_hex` is the lowercase-hex SHA-256 of the pinned SPKI, as
    /// produced by `fingerprint::spki_sha256_hex`. `None` means
    /// `--print-fingerprint` mode: accept whatever SPKI is presented so it
    /// can be recorded once.
    pub fn new(expected_hex: Option<String>) -> SpkiPinVerifier {
        SpkiPinVerifier {
            expected_hex: expected_hex.map(|h| h.to_ascii_lowercase()),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }

    /// True if this SPKI is accepted: either no pin configured (record
    /// mode) or its hash equals the configured pin exactly.
    pub fn spki_matches(&self, spki_der: &[u8]) -> bool {
        match &self.expected_hex {
            None => true,
            Some(want) => &crate::fingerprint::spki_sha256_hex(spki_der) == want,
        }
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let spki = extract_spki(end_entity.as_ref())
            .map_err(|_| TlsError::General("SPKI parse failed".into()))?;
        if self.spki_matches(&spki) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "kvm_cert_mismatch: observed spki_sha256={}",
                crate::fingerprint::spki_sha256_hex(&spki)
            )))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_spki_matches_rcgen_public_key_der() {
        let ck = rcgen::generate_simple_self_signed(vec!["kvm.test".to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let spki = extract_spki(&cert_der).unwrap();
        assert_eq!(spki, ck.key_pair.public_key_der());
    }

    #[test]
    fn pin_hex_round_trips_through_fingerprint() {
        let ck = rcgen::generate_simple_self_signed(vec!["kvm.test".to_string()]).unwrap();
        let spki = extract_spki(ck.cert.der()).unwrap();
        let pinned = crate::fingerprint::spki_sha256_hex(&spki);
        // A verifier built with the right pin considers this SPKI a match.
        let v = SpkiPinVerifier::new(Some(pinned.clone()));
        assert!(v.spki_matches(&spki));
        // A one-char-off pin does not.
        let mut wrong = pinned.clone();
        wrong.replace_range(0..1, if pinned.starts_with('a') { "b" } else { "a" });
        assert!(!SpkiPinVerifier::new(Some(wrong)).spki_matches(&spki));
        // print-fingerprint mode (no pin) accepts anything.
        assert!(SpkiPinVerifier::new(None).spki_matches(&spki));
    }
}
