//! The input path (§7): the keyboard and pointer state (`keys`, `pointer`),
//! the paste state (`paste`), and the sans-IO core that drives them with a
//! clock and the §7.4 triggers (`core`). No I/O; the shell (`rdp::input`)
//! carries the reports out through `HidControl` (DD2).
pub mod core;
pub mod keys;
pub mod paste;
pub mod pointer;

pub use core::{Ctx, Event, InputCore, Out};
pub use paste::{PasteOutcome, PasteRefusal};
