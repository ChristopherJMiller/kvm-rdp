//! The RDP side (spec §5, §9.1): the listener's TLS identity and accept
//! rate, IronRDP's callbacks, and the server's assembly. Callbacks run on
//! the RDP runtime and only push (§4.3).
pub mod accept;
pub mod display;
pub mod gfx;
pub mod handler;
pub mod input;
pub mod tls;
