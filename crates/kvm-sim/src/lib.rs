//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

mod source;

pub use source::{Frame, Source, SourceError, fixtures_dir};
