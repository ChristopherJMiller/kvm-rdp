//! FLV demux for the ES3 KVM video stream (§6.2). Hand-rolled incremental
//! state machine over a `BytesMut`; no AMF0 parsing, no resync scanning.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod avc;
mod demux;
mod header;
mod reader;

pub use avc::{AvcConfig, FrameType, Nal, VideoBody};
pub use demux::{FlvDemuxer, FlvTag, TagBody};
pub use header::{FlvError, FlvHeader, FlvLimits};
