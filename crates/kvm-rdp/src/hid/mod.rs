//! The HID path (§7.3): a bounded queue of full-state reports, each stamped
//! with the release epoch, and the websocket task that writes them.
pub mod queue;
pub mod writer;

pub use queue::{HidControl, HidQueue, Push, ReleaseTrigger, Report};
