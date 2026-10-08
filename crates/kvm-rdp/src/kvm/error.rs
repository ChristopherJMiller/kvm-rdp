//! KVM-side failures by §6.9 class. Variants carry codes and static
//! strings only — never text the device sent.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// Reconnect with backoff.
    Transient,
    /// Re-login once (§6.9 auth).
    Auth,
    /// Fatal at once: `kvm_cert_mismatch`.
    Cert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvmError {
    /// The certificate's SPKI is not the pinned one (§3.2).
    CertMismatch,
    /// Login rejected, HTTP 401/403, or `result: 403`.
    Auth,
    Timeout(&'static str),
    Connect(std::io::ErrorKind),
    /// Any other TLS failure.
    Tls,
    /// An HTTP status other than 200/401/403.
    Http(u16),
    Protocol(&'static str),
    /// The connection ended.
    Closed,
}

impl KvmError {
    #[must_use]
    pub fn class(&self) -> FailClass {
        match self {
            KvmError::CertMismatch => FailClass::Cert,
            KvmError::Auth => FailClass::Auth,
            _ => FailClass::Transient,
        }
    }

    /// A metric label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            KvmError::CertMismatch => "cert",
            KvmError::Auth => "auth",
            KvmError::Timeout(_) => "timeout",
            KvmError::Connect(_) => "connect",
            KvmError::Tls => "tls",
            KvmError::Http(_) => "http",
            KvmError::Protocol(_) => "protocol",
            KvmError::Closed => "eof",
        }
    }
}

/// `"result":403` in a refusal body (§6.9 auth; fix round 1 m1/I3): the
/// exact key `"result"` — never a key merged by indiscriminate whitespace
/// stripping, such as `"res ult"` — optional whitespace around `:`, and a
/// `403` that is not the prefix of a longer number (`4030`/`4031` must not
/// match). Shared by `kvm::flv` (a 200 whose body is not FLV-shaped) and
/// `kvm::ws` (a non-101 handshake response).
pub(crate) fn result_403(body: &[u8]) -> bool {
    const KEY: &[u8] = b"\"result\"";
    let mut rest = body;
    loop {
        let Some(pos) = find(rest, KEY) else {
            return false;
        };
        let Some(after_key) = rest.get(pos.saturating_add(KEY.len())..) else {
            return false;
        };
        if matches_403(after_key) {
            return true;
        }
        // Not this occurrence: look for the next one past its first byte.
        let Some(next) = rest.get(pos.saturating_add(1)..) else {
            return false;
        };
        rest = next;
    }
}

/// `after_key` is whatever follows the closing quote of `"result"`:
/// optional whitespace, `:`, optional whitespace, then `403` immediately
/// followed by a non-digit (or the end of the body) — so `4030`/`4031`
/// are not mistaken for `403`.
fn matches_403(after_key: &[u8]) -> bool {
    let Some(after_colon) = skip_ws(after_key).strip_prefix(b":") else {
        return false;
    };
    let Some(after_403) = skip_ws(after_colon).strip_prefix(b"403") else {
        return false;
    };
    after_403.first().is_none_or(|b| !b.is_ascii_digit())
}

fn skip_ws(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|b| b.is_ascii_whitespace()).count();
    s.get(n..).unwrap_or(&[])
}

/// The first position of `needle` in `haystack`, or `None`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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

    /// m1 (fix round 1): `4031`/`4030` are not `403` (a prefix match used
    /// to let them through), and stripping whitespace must never merge a
    /// key split by it — `"res ult"` is a different key, not `"result"`.
    #[test]
    fn a_json_result_403_is_recognised() {
        assert!(result_403(br#"{"result":403}"#));
        assert!(result_403(b"{ \"result\" : 403 }"));
        assert!(!result_403(br#"{"result":0}"#));
        assert!(!result_403(br#"{"result":4031}"#));
        assert!(!result_403(br#"{"result":4030}"#));
        assert!(!result_403(br#"{"res ult":403}"#));
    }
}
