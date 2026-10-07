//! Admission refusals by §6.9 class, with their metric labels.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::flv::FlvError;
use crate::h264::SpsIncompatibleReason;
use crate::h264::picture::SliceRefusal;
use crate::h264::pps::PpsRefusal;
use crate::h264::rewrite::RewriteError;
use crate::h264::sanitize::NalRefusal;

/// §6.9 framing violations found after demux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framing {
    Flv(FlvError),
    /// A tag type other than 8, 9 or 18.
    UnknownTagType(u8),
    Nal(NalRefusal),
    /// A config record entry whose own header is not an SPS (resp. PPS).
    ConfigNalType(u8),
    /// The tag is not exactly one picture (§6.2): no slice, a second
    /// picture's slice, a first slice with `first_mb_in_slice != 0`, a second
    /// AUD, or an AUD after a slice.
    NotOnePicture,
    /// More distinct PPS ids than the §6.2 limit (16) at once.
    TooManyPps,
}

/// §6.9 stream-incompatible causes: fatal at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incompatible {
    /// FLV `CodecID` other than 7 (12 is HEVC).
    Codec(u8),
    /// An Enhanced-RTMP FourCC (`hvc1`, `av01`, …).
    Enhanced([u8; 4]),
    /// `CompositionTime` differs from the first coded tag's on this FLV.
    CompositionTime {
        first: i32,
        now: i32,
    },
    Rewrite(RewriteError),
    Sps(SpsIncompatibleReason),
    Pps(PpsRefusal),
    Slice(SliceRefusal),
}

/// Why a tag was refused, by §6.9 class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// Transient: reconnect the FLV and feed a `ViolationWindow` (three
    /// within 60 s is fatal `stream_corrupt`).
    Framing(Framing),
    /// Fatal `stream_incompatible`.
    Incompatible(Incompatible),
}

impl From<FlvError> for AdmissionError {
    fn from(e: FlvError) -> Self {
        AdmissionError::Framing(Framing::Flv(e))
    }
}

impl AdmissionError {
    /// The `parse_errors{kind}` label (framing) or the `stream_incompatible`
    /// detail (incompatible), for metrics and the disconnect log line.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            AdmissionError::Framing(f) => match f {
                Framing::Flv(e) => e.kind(),
                Framing::UnknownTagType(_) => "unknown_tag_type",
                Framing::Nal(NalRefusal::Empty) => "empty_nal",
                Framing::Nal(NalRefusal::ForbiddenBit) => "forbidden_bit",
                Framing::Nal(NalRefusal::StartCode) => "start_code_in_nal",
                Framing::ConfigNalType(_) => "config_nal_type",
                Framing::NotOnePicture => "not_one_picture",
                Framing::TooManyPps => "too_many_pps",
            },
            AdmissionError::Incompatible(i) => match i {
                Incompatible::Codec(_) => "codec",
                Incompatible::Enhanced(_) => "enhanced_rtmp",
                Incompatible::CompositionTime { .. } => "composition_time",
                Incompatible::Rewrite(_) => "sps_rewrite",
                Incompatible::Sps(_) => "sps",
                Incompatible::Pps(_) => "pps",
                Incompatible::Slice(_) => "slice",
            },
        }
    }
}

pub(crate) fn framing(f: Framing) -> AdmissionError {
    AdmissionError::Framing(f)
}

pub(crate) fn incompatible(i: Incompatible) -> AdmissionError {
    AdmissionError::Incompatible(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_label_is_distinct() {
        // Every `FlvError` variant (fix round 1, m1): the previous version
        // listed only `OversizeTag`, so renaming `Framing::TooManyPps`'s own
        // label to collide with `FlvError::TooManyNals`'s `"too_many_nals"`
        // passed. All 12 of `FlvError`'s current variants are listed so a
        // label collision anywhere in that delegated match fails here too.
        let all = [
            AdmissionError::from(FlvError::BadHeader),
            AdmissionError::from(FlvError::BadPrevTagSize),
            AdmissionError::from(FlvError::EncryptedTag),
            AdmissionError::from(FlvError::BadStreamId),
            AdmissionError::from(FlvError::OversizeTag),
            AdmissionError::from(FlvError::BadConfigRecord),
            AdmissionError::from(FlvError::BadLengthSize),
            AdmissionError::from(FlvError::NalBeforeSequenceHeader),
            AdmissionError::from(FlvError::MalformedVideoTag),
            AdmissionError::from(FlvError::TooManyNals),
            AdmissionError::from(FlvError::ParamSetCount),
            AdmissionError::from(FlvError::ParamSetSize),
            framing(Framing::UnknownTagType(3)),
            framing(Framing::Nal(NalRefusal::Empty)),
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
            framing(Framing::Nal(NalRefusal::StartCode)),
            framing(Framing::ConfigNalType(8)),
            framing(Framing::NotOnePicture),
            framing(Framing::TooManyPps),
            incompatible(Incompatible::Codec(12)),
            incompatible(Incompatible::Enhanced(*b"hvc1")),
            incompatible(Incompatible::CompositionTime { first: 16, now: 0 }),
            incompatible(Incompatible::Rewrite(RewriteError::SelfCheck)),
            incompatible(Incompatible::Sps(
                SpsIncompatibleReason::PinnedFieldChanged(crate::h264::PinnedField::ProfileIdc),
            )),
            incompatible(Incompatible::Pps(PpsRefusal::SliceGroups)),
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(1))),
        ];
        let mut kinds: Vec<&str> = all.iter().map(AdmissionError::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), all.len());
    }
}
