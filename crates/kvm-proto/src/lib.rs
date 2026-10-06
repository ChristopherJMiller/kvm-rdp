//! `kvm-proto`: sans-IO parsers and encoders for the kvm-rdp bridge.
//!
//! This crate faces hostile input from the KVM (spec §2, §4.1) and must
//! never panic, index out of bounds, or overflow. The crate-root lints
//! below are denied crate-wide (the Milestone-0 hardening posture; full
//! fuzzing and the remaining byte-limits are Plan B). Test modules that
//! legitimately need `unwrap`/`panic` opt out locally with a scoped
//! `#![allow(...)]`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

pub mod login;
pub use login::{LoginError, Token, parse_login_token};

/// Crate name; the first link/smoke anchor until the parsers land.
#[must_use]
pub const fn name() -> &'static str {
    "kvm-proto"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn name_is_stable() {
        assert_eq!(name(), "kvm-proto");
    }

    #[test]
    fn bytes_dependency_links() {
        let buf = bytes::BytesMut::with_capacity(16);
        assert!(buf.is_empty());
    }
}
