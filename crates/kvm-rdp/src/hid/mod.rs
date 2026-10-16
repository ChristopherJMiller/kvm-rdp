//! The HID path (§7.3): a bounded queue of full-state reports, each stamped
//! with the release epoch, the websocket task that writes them, and the
//! release websocket a session end opens when the KVM did not prove it
//! released (I2, Plan D final review); and the KVM-runtime watch that
//! releases held input when the RDP runtime stops (m3, Plan E Task 1.5).
pub mod queue;
pub mod release;
pub mod stale;
pub mod writer;

pub use queue::{HidControl, HidQueue, Push, ReleaseTrigger, Report};
