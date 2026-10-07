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
