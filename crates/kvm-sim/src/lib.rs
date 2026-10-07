//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

// Wired into `KvmSim` by Tasks 8.3–8.6; until then only the unit tests use them.
#[allow(dead_code)]
mod encoder;
mod source;
#[allow(dead_code)]
mod state;

pub use source::{Frame, Source, SourceError, fixtures_dir};
pub use state::{Policy, PortKind, SimEvent, SimStats};

/// The stream's shape on the wire (`census.md`, Artifacts: kvm-sim profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Nominal frame rate: FLV timestamps and real-time pacing.
    pub fps: u32,
    /// AVCC NAL length size: 1, 2 or 4.
    pub length_size: u8,
    /// `CompositionTime` on every coded tag (0 on the sequence header).
    pub composition_time_ms: i32,
    /// A new FLV connection replays the GOP so far at once (a GOP-caching
    /// source; the ES3 does not).
    pub burst_on_connect: bool,
    /// Shared encoder: any new FLV connection forces an IDR into every open
    /// stream and restarts the GOP.
    pub idr_on_new_connection: bool,
    /// Keep in-band SPS/PPS in coded tags (the ES3 sends them only in the
    /// sequence header).
    pub inband_params: bool,
    /// Keep AUDs (the ES3 sends none).
    pub aud: bool,
    /// Keep SEI (the ES3 sends none).
    pub sei: bool,
    /// Append the ES3's trailing zero bytes to the sequence header's
    /// parameter sets — one after the SPS, two after the PPS — as the device
    /// does (`census.md` `sps_hex`, `pps_hex`).
    pub padded_param_sets: bool,
}

impl Profile {
    /// The ES3 as measured (`census.md`, Leg A — stream): 30 fps, length size
    /// 4, `CompositionTime` 16, no burst, shared encoder, tag = AU carrying
    /// only NAL types 1 and 5, and a sequence header whose SPS and PPS end in
    /// zero bytes.
    #[must_use]
    pub fn es3() -> Profile {
        Profile {
            fps: 30,
            length_size: 4,
            composition_time_ms: 16,
            burst_on_connect: false,
            idr_on_new_connection: true,
            inband_params: false,
            aud: false,
            sei: false,
            padded_param_sets: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// One frame every `1 / Profile::fps`, never catching up (the ES3 sends
    /// one tag every 33 ms whether the screen moves or not).
    RealTime,
    /// Frames only on [`KvmSim::advance`]: deterministic tests.
    Manual,
}

/// How a source switch reaches viewers (§6.4, §11.3 resolution change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeSignal {
    /// A new sequence header on every open FLV.
    SequenceHeader,
    /// The new SPS/PPS in-band in the next IDR's tag.
    InBandSps,
    /// Every open FLV closes (the ES3's observed preset change); new
    /// connections get the new source.
    CloseFlv,
}

/// One-shot faults, applied by every open FLV to its next tag (§6.9 cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OversizeTag,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    HevcCodecId,
    EnhancedHevc,
    /// The next coded tag's `CompositionTime`.
    CompositionTime(i32),
    /// The next two pictures in one tag.
    TwoPictures,
    BSlice,
    StartCodeInNal,
    ForbiddenBit,
    /// An `AVCPacketType 2` tag, now.
    EndOfSequence,
    /// 129 NALs in one tag.
    TooManyNals,
    /// Close every open FLV, now.
    Close,
    /// Stop writing on every open FLV, keeping it open.
    Silence,
}
