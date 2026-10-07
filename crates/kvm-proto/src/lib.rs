//! `kvm-proto`: sans-IO parsers and encoders for the kvm-rdp bridge.
//!
//! This crate faces hostile input from the KVM (spec §2, §4.1) and must
//! never panic, index out of bounds, or overflow. The crate-root lints
//! below are denied crate-wide; test modules that legitimately need
//! `unwrap`/`panic` opt out locally with a scoped `#![allow(...)]`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

pub mod bits;
pub mod flv;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzzing;
pub mod h264;
pub mod hid;
pub mod login;
pub mod video;
pub use login::{LoginError, Token, parse_login_token};
