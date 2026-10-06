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
}
