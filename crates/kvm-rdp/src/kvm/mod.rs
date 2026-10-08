//! The KVM side (spec §3): pinned TLS, login, the FLV and the control
//! websocket, the sans-IO upstream cores and the session actor. Nothing in
//! this module logs out — ES3 logout is global (§3.2) — and there is no
//! function that could.
pub mod endpoint;
pub mod error;
pub mod flv;
pub mod login;
pub mod upstream;
pub mod ws;

pub use endpoint::KvmEndpoint;
pub use error::{FailClass, KvmError};
