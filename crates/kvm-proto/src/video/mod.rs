//! KVM-side video admission (§6.1, §6.2, §6.8): every demuxed FLV tag goes
//! through `VideoAdmission::admit`, which applies the NAL sanitiser, the SPS
//! rewriter, the SPS/PPS/slice checks and the one-picture rule, and returns
//! what the pump may see: a parameter-set change and/or one access unit.
//! Sans-IO: the caller passes the receive time. Nothing here allocates per
//! access unit — the AU reuses the demuxer's NAL `Vec`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod error;
// `VideoAdmission` (Task 4.6) is `ParamState`'s only caller; until then only
// its unit tests use it.
#[allow(dead_code)]
mod params;
mod violations;
pub use error::{AdmissionError, Framing, Incompatible};
pub use params::{ParamClass, ParamSets, ParamsChange};
pub use violations::{ViolationVerdict, ViolationWindow};
