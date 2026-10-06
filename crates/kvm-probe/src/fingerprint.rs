use sha2::{Digest, Sha256};

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
