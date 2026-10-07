//! The per-NAL §6.2 checks every NAL from the KVM passes before anything
//! else looks at it.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::bits::contains_start_code;
use crate::h264::nal::{NalHeader, nal_type_allowed};
use bytes::Bytes;

/// Why a NAL was refused. Each is a framing violation (§6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalRefusal {
    /// Nothing left once trailing zero bytes are trimmed.
    Empty,
    /// `forbidden_zero_bit` is 1.
    ForbiddenBit,
    /// The NAL contains `00 00 00`, `00 00 01` or `00 00 02`.
    StartCode,
}

/// What to do with a NAL that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NalVerdict {
    /// On the allowlist `{1, 5, 7, 8, 9}`: keep these exact bytes.
    Keep(NalHeader, Bytes),
    /// Anything else (SEI, filler, …): drop it (§6.2).
    Drop(NalHeader),
}

/// §6.2 per-NAL checks. Trailing zero bytes are trimmed first: Annex B
/// cannot tell them from `trailing_zero_8bits`, a conforming NAL never ends
/// in `00` (7.4.1), and the ES3 appends them to its SPS and PPS
/// (`census.md` `sps_hex`, `pps_hex`). Then the forbidden bit is checked on
/// every NAL, the allowlist decides keep or drop, and a kept NAL must not
/// contain a start-code pattern — or the client's start-code scanner would
/// find NALs that were never checked. The returned `Bytes` shares `nal`'s
/// allocation.
pub fn check_nal(nal: &Bytes) -> Result<NalVerdict, NalRefusal> {
    let end = nal
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let trimmed = nal.slice(..end);
    let header = NalHeader::from_nal(&trimmed).map_err(|e| match e {
        crate::h264::NalHeaderError::Empty => NalRefusal::Empty,
        crate::h264::NalHeaderError::ForbiddenBitSet => NalRefusal::ForbiddenBit,
    })?;
    if !nal_type_allowed(header.nal_unit_type) {
        return Ok(NalVerdict::Drop(header));
    }
    if contains_start_code(&trimmed) {
        return Err(NalRefusal::StartCode);
    }
    Ok(NalVerdict::Keep(header, trimmed))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn b(v: &'static [u8]) -> Bytes {
        Bytes::from_static(v)
    }

    #[test]
    fn es3_pps_trailing_zeros_are_trimmed_not_refused() {
        // census.md pps_hex = 68ce31120000
        match check_nal(&b(&[0x68, 0xce, 0x31, 0x12, 0x00, 0x00])).unwrap() {
            NalVerdict::Keep(h, kept) => {
                assert_eq!(h.nal_unit_type, 8);
                assert_eq!(kept.as_ref(), &[0x68, 0xce, 0x31, 0x12]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_refusal_has_its_own_kind() {
        assert_eq!(check_nal(&b(&[0, 0])), Err(NalRefusal::Empty));
        assert_eq!(check_nal(&b(&[0xE5, 0x88])), Err(NalRefusal::ForbiddenBit));
        assert_eq!(
            check_nal(&b(&[0x65, 0x88, 0, 0, 1, 0x42])),
            Err(NalRefusal::StartCode)
        );
        assert_eq!(
            check_nal(&b(&[0x41, 0, 0, 0, 0x42])),
            Err(NalRefusal::StartCode)
        );
        assert_eq!(
            check_nal(&b(&[0x41, 0, 0, 2, 0x42])),
            Err(NalRefusal::StartCode)
        );
    }

    #[test]
    fn sei_and_filler_are_dropped_even_with_start_codes_inside() {
        assert!(matches!(
            check_nal(&b(&[0x06, 0, 0, 1, 0x80])),
            Ok(NalVerdict::Drop(_))
        ));
        assert!(matches!(
            check_nal(&b(&[0x0C, 0xFF, 0xFF])),
            Ok(NalVerdict::Drop(_))
        ));
    }

    #[test]
    fn emulation_prevented_bytes_are_fine() {
        assert!(matches!(
            check_nal(&b(&[0x65, 0, 0, 3, 0, 0, 3, 1])),
            Ok(NalVerdict::Keep(..))
        ));
    }
}
