//! NAL header parse and NAL-type helpers (spec §6.2). Hostile input.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// A parsed one-byte H.264 NAL unit header (forbidden bit already checked 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NalHeader {
    /// `nal_ref_idc` (0..=3).
    pub nal_ref_idc: u8,
    /// `nal_unit_type` (0..=31).
    pub nal_unit_type: u8,
}

/// Why a NAL header could not be accepted (a framing violation, spec §6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalHeaderError {
    /// `forbidden_zero_bit` was 1 (spec §6.2 refuses it).
    ForbiddenBitSet,
    /// The NAL was empty, so there is no header byte.
    Empty,
}

impl NalHeader {
    /// Parse the single NAL header byte.
    pub fn parse(byte: u8) -> Result<NalHeader, NalHeaderError> {
        if byte & 0b1000_0000 != 0 {
            return Err(NalHeaderError::ForbiddenBitSet);
        }
        Ok(NalHeader {
            nal_ref_idc: (byte & 0b0110_0000).wrapping_shr(5),
            nal_unit_type: byte & 0b0001_1111,
        })
    }

    /// Parse the header from the first byte of a NAL unit.
    pub fn from_nal(nal: &[u8]) -> Result<NalHeader, NalHeaderError> {
        let first = nal.first().copied().ok_or(NalHeaderError::Empty)?;
        Self::parse(first)
    }
}

/// The spec §6.2 allowlist: slices (1), IDR (5), SPS (7), PPS (8), AUD (9).
/// Everything else (SEI, filler, …) is dropped.
#[must_use]
pub fn nal_type_allowed(nal_unit_type: u8) -> bool {
    matches!(nal_unit_type, 1 | 5 | 7 | 8 | 9)
}

/// A VCL (slice) NAL: non-IDR coded slice (1) or IDR coded slice (5).
/// Spec §6.3: only AUs containing a VCL NAL are sent.
#[must_use]
pub fn is_vcl(nal_unit_type: u8) -> bool {
    matches!(nal_unit_type, 1 | 5)
}

/// An IDR coded slice (5).
#[must_use]
pub fn is_idr(nal_unit_type: u8) -> bool {
    nal_unit_type == 5
}

/// A parameter set: SPS (7) or PPS (8).
#[must_use]
pub fn is_parameter_set(nal_unit_type: u8) -> bool {
    matches!(nal_unit_type, 7 | 8)
}

/// An access unit delimiter (9).
#[must_use]
pub fn is_aud(nal_unit_type: u8) -> bool {
    nal_unit_type == 9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sps_header_byte() {
        // 0x67 = forbidden 0, nal_ref_idc 3, type 7
        assert_eq!(
            NalHeader::parse(0x67),
            Ok(NalHeader {
                nal_ref_idc: 3,
                nal_unit_type: 7
            })
        );
    }

    #[test]
    fn idr_slice_header_byte() {
        // 0x65 = forbidden 0, nal_ref_idc 3, type 5
        assert_eq!(
            NalHeader::parse(0x65),
            Ok(NalHeader {
                nal_ref_idc: 3,
                nal_unit_type: 5
            })
        );
    }

    #[test]
    fn non_ref_slice_header_byte() {
        // 0x01 = forbidden 0, nal_ref_idc 0, type 1
        assert_eq!(
            NalHeader::parse(0x01),
            Ok(NalHeader {
                nal_ref_idc: 0,
                nal_unit_type: 1
            })
        );
    }

    #[test]
    fn forbidden_bit_set_rejected() {
        // 0xE7 = forbidden bit set
        assert_eq!(NalHeader::parse(0xE7), Err(NalHeaderError::ForbiddenBitSet));
    }

    #[test]
    fn from_nal_reads_first_byte() {
        assert_eq!(
            NalHeader::from_nal(&[0x68, 0xaa, 0xbb]),
            Ok(NalHeader {
                nal_ref_idc: 3,
                nal_unit_type: 8
            })
        );
    }

    #[test]
    fn from_empty_nal_rejected() {
        assert_eq!(NalHeader::from_nal(&[]), Err(NalHeaderError::Empty));
    }

    #[test]
    fn allowlist_matches_spec_6_2() {
        for t in [1u8, 5, 7, 8, 9] {
            assert!(nal_type_allowed(t), "type {t} should be allowed");
        }
        // SEI(6), filler(12), end-of-seq(10), reserved/unspecified all dropped.
        for t in [0u8, 2, 3, 4, 6, 10, 11, 12, 20, 31] {
            assert!(!nal_type_allowed(t), "type {t} should be dropped");
        }
    }

    #[test]
    fn vcl_idr_pps_aud_classifiers() {
        assert!(is_vcl(1) && is_vcl(5));
        assert!(!is_vcl(7) && !is_vcl(8) && !is_vcl(9));
        assert!(is_idr(5) && !is_idr(1));
        assert!(is_parameter_set(7) && is_parameter_set(8) && !is_parameter_set(9));
        assert!(is_aud(9) && !is_aud(1));
    }
}
