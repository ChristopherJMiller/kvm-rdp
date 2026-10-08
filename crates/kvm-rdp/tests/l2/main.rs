//! L2 (spec §11.3): the bridge in process, kvm-sim on loopback, and an
//! in-process IronRDP client with NLA. One integration-test binary (§13).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod client;
mod faults;
mod harness;
mod lifecycle;
mod resize;
mod sessions;
mod video;
