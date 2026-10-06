//! The one kvm-probe integration-test binary (R8, spec §13). Lint-allow
//! for test-only code is set once here, at the crate root of this test
//! binary; it is inherited by every submodule below.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod support;

mod capture;
mod login;
mod ws;
