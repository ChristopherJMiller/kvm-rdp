//! Context-free slice-header prefix (spec §6.1 census fields). The first three
//! ue(v) fields of a coded slice header need no SPS/PPS context. Full slice
//! validation (PicSizeInMbs, POC order, validated pps_id) is Plan B/C.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use h264_reader::nal::{Nal, RefNal};
use h264_reader::rbsp::{BitRead, BitReaderError};

/// The leading, context-free fields of a coded slice header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceHeaderPrefix {
    pub first_mb_in_slice: u32,
    pub slice_type: u32,
    pub pic_parameter_set_id: u32,
}

/// Why a slice-header prefix could not be parsed.
#[derive(Debug)]
pub enum SliceParseError {
    /// The NAL was empty or its forbidden bit was set.
    BadNalHeader,
    /// The NAL was not a coded slice (type 1 or 5); carries the actual type.
    NotSlice(u8),
    /// The bit reader failed (truncated Exp-Golomb, etc.).
    Bits(BitReaderError),
}

/// Parse the first three ue(v) fields of a type-1/5 slice NAL.
pub fn parse_slice_header_prefix(nal: &[u8]) -> Result<SliceHeaderPrefix, SliceParseError> {
    // R4: `RefNal::new` panics on empty input (it indexes the first byte for
    // the header). Reject empty NALs before constructing it.
    if nal.is_empty() {
        return Err(SliceParseError::BadNalHeader);
    }
    let refnal = RefNal::new(nal, &[], true);
    let header = refnal.header().map_err(|_| SliceParseError::BadNalHeader)?;
    let unit_type = header.nal_unit_type().id();
    if !matches!(unit_type, 1 | 5) {
        return Err(SliceParseError::NotSlice(unit_type));
    }
    let mut r = refnal.rbsp_bits();
    let first_mb_in_slice = r
        .read_ue("first_mb_in_slice")
        .map_err(SliceParseError::Bits)?;
    let slice_type = r.read_ue("slice_type").map_err(SliceParseError::Bits)?;
    let pic_parameter_set_id = r
        .read_ue("pic_parameter_set_id")
        .map_err(SliceParseError::Bits)?;
    Ok(SliceHeaderPrefix {
        first_mb_in_slice,
        slice_type,
        pic_parameter_set_id,
    })
}

/// Spec §6.1 slice-type allowlist: P and I only (`{0,2,5,7}`); B/SP/SI refused.
#[must_use]
pub fn slice_type_allowed(slice_type: u32) -> bool {
    matches!(slice_type, 0 | 2 | 5 | 7)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::h264::test_support::build_slice_nal;

    #[test]
    fn non_idr_prefix_fields() {
        // header 0x41 = type 1; first_mb 0, slice_type 7 (I, all), pps_id 0
        let nal = build_slice_nal(0x41, 0, 7, 0);
        assert_eq!(
            parse_slice_header_prefix(&nal).unwrap(),
            SliceHeaderPrefix {
                first_mb_in_slice: 0,
                slice_type: 7,
                pic_parameter_set_id: 0
            }
        );
    }

    #[test]
    fn idr_prefix_fields_with_nonzero_values() {
        // header 0x65 = type 5 (IDR); first_mb 99, slice_type 2 (I), pps_id 1
        let nal = build_slice_nal(0x65, 99, 2, 1);
        assert_eq!(
            parse_slice_header_prefix(&nal).unwrap(),
            SliceHeaderPrefix {
                first_mb_in_slice: 99,
                slice_type: 2,
                pic_parameter_set_id: 1
            }
        );
    }

    #[test]
    fn non_slice_nal_rejected() {
        // SPS header byte 0x67 (type 7)
        assert!(matches!(
            parse_slice_header_prefix(&[0x67, 0x00]),
            Err(SliceParseError::NotSlice(7))
        ));
    }

    #[test]
    fn empty_nal_rejected() {
        assert!(matches!(
            parse_slice_header_prefix(&[]),
            Err(SliceParseError::BadNalHeader)
        ));
    }

    #[test]
    fn p_and_i_slice_types_allowed_only() {
        for t in [0u32, 2, 5, 7] {
            assert!(slice_type_allowed(t), "slice_type {t} (P/I) should pass");
        }
        for t in [1u32, 3, 4, 6, 8, 9] {
            assert!(
                !slice_type_allowed(t),
                "slice_type {t} (B/SP/SI) should fail"
            );
        }
    }
}
