//! The EGFX pump (spec §4.3, §6.4–§6.6, §6.9): a sans-IO core (`core`) over
//! the flow, IDR and debounce cores, and an async shell (Task 5.3) that
//! only locks, steps and carries out commands.
pub mod core;
pub mod debounce;
pub mod flow;
pub mod idr;
#[cfg(test)]
pub(crate) mod rig;
pub mod slate;
pub mod types;

pub use core::Pump;
pub use types::{Command, DvcBatch, FlowConfig, IdrConfig, Input, PumpConfig, State};
