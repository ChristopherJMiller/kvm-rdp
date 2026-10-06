//! AVCC (length-prefixed) → Annex-B conversion (spec §6.3 output contract).
//! Hostile input: no panics, checked access, saturating/checked arithmetic.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Why an AVCC buffer could not be converted. Maps to a framing violation
/// (spec §6.9) in the demuxer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvccError {
    /// `nal_length_size` was not 1, 2 or 4.
    BadLengthSize(usize),
    /// The buffer ended inside a length prefix.
    TruncatedPrefix,
    /// A NAL declared length 0 (spec §6.2: `0 < n`).
    NalLengthZero,
    /// A NAL length ran past the end of the buffer (spec §6.2: `n <= remaining`).
    NalExceedsBuffer { nal_len: usize, remaining: usize },
}

/// Convert one AVCC buffer into Annex-B with 4-byte start codes, **appending**
/// into `out` (the caller owns clearing/reuse — spec §6.2/§6.3 build an AU by
/// concatenating cached SPS/PPS and VCL NALs into one reused buffer).
///
/// `nal_length_size` is the NAL length-prefix width in bytes: 1, 2 or 4
/// (= `AVCDecoderConfigurationRecord.lengthSizeMinusOne + 1`; §6.2 admits
/// `lengthSizeMinusOne ∈ {0,1,3}`).
pub fn avcc_to_annex_b(
    data: &[u8],
    nal_length_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), AvccError> {
    if !matches!(nal_length_size, 1 | 2 | 4) {
        return Err(AvccError::BadLengthSize(nal_length_size));
    }
    let mut rest = data;
    while !rest.is_empty() {
        let (prefix, after_prefix) = rest
            .split_at_checked(nal_length_size)
            .ok_or(AvccError::TruncatedPrefix)?;
        let mut nal_len: usize = 0;
        for &b in prefix {
            // nal_length_size <= 4 so at most a 32-bit value; wrapping_shl
            // keeps us clear of clippy::arithmetic_side_effects.
            nal_len = nal_len.wrapping_shl(8) | usize::from(b);
        }
        if nal_len == 0 {
            return Err(AvccError::NalLengthZero);
        }
        let (nal, tail) =
            after_prefix
                .split_at_checked(nal_len)
                .ok_or(AvccError::NalExceedsBuffer {
                    nal_len,
                    remaining: after_prefix.len(),
                })?;
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nal);
        rest = tail;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;

    #[test]
    fn four_byte_prefix_two_nals() {
        // len=3 [67 42 00], len=2 [68 ce]
        let avcc = [0, 0, 0, 3, 0x67, 0x42, 0x00, 0, 0, 0, 2, 0x68, 0xce];
        let mut out = Vec::new();
        avcc_to_annex_b(&avcc, 4, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 1, 0x67, 0x42, 0x00, 0, 0, 0, 1, 0x68, 0xce]);
    }

    #[test]
    fn one_byte_prefix() {
        let avcc = [3, 0x65, 0x11, 0x22];
        let mut out = Vec::new();
        avcc_to_annex_b(&avcc, 1, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 1, 0x65, 0x11, 0x22]);
    }

    #[test]
    fn two_byte_prefix_appends_not_clears() {
        let avcc = [0, 1, 0xaa];
        let mut out = vec![0xff]; // pre-existing content is preserved
        avcc_to_annex_b(&avcc, 2, &mut out).unwrap();
        assert_eq!(out, [0xff, 0, 0, 0, 1, 0xaa]);
    }

    #[test]
    fn bad_length_size_rejected() {
        let mut out = Vec::new();
        assert_eq!(
            avcc_to_annex_b(&[0, 0, 0, 1, 0xaa], 3, &mut out),
            Err(AvccError::BadLengthSize(3))
        );
    }

    #[test]
    fn zero_length_nal_rejected() {
        let mut out = Vec::new();
        assert_eq!(
            avcc_to_annex_b(&[0, 0, 0, 0], 4, &mut out),
            Err(AvccError::NalLengthZero)
        );
    }

    #[test]
    fn nal_exceeds_buffer_rejected() {
        let mut out = Vec::new();
        // claims 5 bytes, only 2 remain
        assert_eq!(
            avcc_to_annex_b(&[0, 0, 0, 5, 0xaa, 0xbb], 4, &mut out),
            Err(AvccError::NalExceedsBuffer {
                nal_len: 5,
                remaining: 2
            })
        );
    }

    #[test]
    fn truncated_prefix_rejected() {
        let mut out = Vec::new();
        assert_eq!(
            avcc_to_annex_b(&[0, 0], 4, &mut out),
            Err(AvccError::TruncatedPrefix)
        );
    }
}
