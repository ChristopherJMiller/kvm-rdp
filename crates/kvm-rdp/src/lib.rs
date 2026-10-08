//! `kvm-rdp`: the bridge from the ES3 IP-KVM to RDP (spec §4).
//!
//! Hostile input is parsed only in `kvm-proto`; this crate still never
//! panics on anything the KVM or a client sends. The await lints are §4.3's
//! (no lock held across an await); test modules opt out of the panic lints
//! locally.
#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions
)]

pub mod admin;
pub mod bridge;
pub mod cli;
pub mod config;
pub mod hid;
pub mod kvm;
pub mod logging;
pub mod metrics;
pub mod msg;
pub mod pump;
pub mod rdp;

#[cfg(test)]
mod pin_goldens;
#[cfg(test)]
mod testkit;
