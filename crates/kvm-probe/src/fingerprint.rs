use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::kvm::{self, KvmError};
use crate::pin::extract_spki;
use crate::request::KvmTarget;

/// Lowercase hex of the SHA-256 of a DER-encoded SubjectPublicKeyInfo (§3.2).
pub fn spki_sha256_hex(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    let mut out = String::with_capacity(64);
    for byte in digest {
        // {:02x} cannot overflow; no arithmetic on `byte`.
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Connect once without a pin and return the KVM certificate's SPKI
/// SHA-256 hex, for recording into config (`kvm.spki_sha256`, §3.2). This is
/// the *only* place in the crate allowed to build a no-pin (record-mode)
/// verifier (R9) — it does so explicitly via `kvm::client_config(None)`
/// rather than any ambient accept-any path, and is bounded by the same
/// connect+handshake timeout (`kvm::CONNECT_TIMEOUT`) every other KVM
/// connection uses, so a silent peer cannot hang this call forever.
pub async fn observe(target: &KvmTarget, port: u16) -> Result<String, KvmError> {
    match tokio::time::timeout(kvm::CONNECT_TIMEOUT, observe_inner(target, port)).await {
        Ok(result) => result,
        Err(_) => Err(KvmError::Tls(format!(
            "connect/handshake timed out after {:?}",
            kvm::CONNECT_TIMEOUT
        ))),
    }
}

async fn observe_inner(target: &KvmTarget, port: u16) -> Result<String, KvmError> {
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), port))
        .await
        .map_err(|e| KvmError::Connect(e.to_string()))?;
    let cfg = kvm::client_config(None);
    let name = ServerName::try_from(target.host.clone())
        .map_err(|_| KvmError::Tls("bad server name".into()))?;
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| KvmError::Tls(e.to_string()))?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| KvmError::Tls("no peer certificate".into()))?;
    let spki = extract_spki(cert.as_ref()).map_err(|e| KvmError::Tls(format!("{e:?}")))?;
    Ok(spki_sha256_hex(&spki))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abc_matches_known_sha256() {
        // SHA-256("abc") is a fixed, independently known value.
        assert_eq!(
            spki_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_is_64_hex_chars() {
        let s = spki_sha256_hex(b"");
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
