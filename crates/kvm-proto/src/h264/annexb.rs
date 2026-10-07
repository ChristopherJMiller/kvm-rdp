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
/// Contract: on `Ok`, the converted NALs are appended to `out`. On `Err`,
/// `out` is left exactly as it was on entry — a rejected AU never leaves a
/// partial fragment behind for the next `avcc_to_annex_b` call to splice
/// onto (spec §6.3: `out` is reused across access units).
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
    let start_len = out.len();
    convert_all(data, nal_length_size, out).inspect_err(|_| out.truncate(start_len))
}

/// Does the actual appending; on error, `out` may hold a partial AU — the
/// caller (`avcc_to_annex_b`) truncates it back to the entry length.
fn convert_all(data: &[u8], nal_length_size: usize, out: &mut Vec<u8>) -> Result<(), AvccError> {
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

/// Iterator over the NAL units of an Annex-B byte stream (B.1): each NAL is
/// the bytes between one `00 00 01` start code (3- or 4-byte form) and the
/// next, with trailing zero bytes (`trailing_zero_8bits` and a 4-byte start
/// code's leading zero) removed. Bytes before the first start code are
/// skipped. Panic-free over any input.
#[derive(Debug, Clone)]
pub struct AnnexBNals<'a> {
    rest: &'a [u8],
}

/// Split an Annex-B stream into NAL units (see [`AnnexBNals`]).
#[must_use]
pub fn split_annex_b(data: &[u8]) -> AnnexBNals<'_> {
    let start = find_start_code(data).map_or(data.len(), |(_, after)| after);
    AnnexBNals {
        rest: data.get(start..).unwrap_or(&[]),
    }
}

/// `(index of the 00 00 01, index just past it)` of the first start code.
fn find_start_code(data: &[u8]) -> Option<(usize, usize)> {
    let at = data.windows(3).position(|w| w == [0, 0, 1])?;
    Some((at, at.checked_add(3)?))
}

impl<'a> Iterator for AnnexBNals<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            if self.rest.is_empty() {
                return None;
            }
            let (nal, rest) = match find_start_code(self.rest) {
                Some((at, after)) => (
                    self.rest.get(..at).unwrap_or(&[]),
                    self.rest.get(after..).unwrap_or(&[]),
                ),
                None => (self.rest, &[][..]),
            };
            self.rest = rest;
            let end = nal
                .iter()
                .rposition(|&b| b != 0)
                .map_or(0, |i| i.saturating_add(1));
            let nal = nal.get(..end).unwrap_or(&[]);
            if !nal.is_empty() {
                return Some(nal);
            }
        }
    }
}

/// §10.2 FrameId: FNV-1a 64 over the VCL NALs (types 1 and 5) of one access
/// unit, concatenated in order, header bytes included, without start codes
/// or length prefixes. kvm-sim records it on send and test clients on
/// receipt; the bridge never changes VCL bytes, so the two agree.
#[must_use]
pub fn frame_id<'a>(vcl: impl IntoIterator<Item = &'a [u8]>) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for nal in vcl {
        for &b in nal {
            h = (h ^ u64::from(b)).wrapping_mul(PRIME);
        }
    }
    h
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

    #[test]
    fn error_leaves_out_unchanged() {
        // One valid NAL [0x67, 0x42], then a second length prefix claiming 9
        // bytes with only 2 remaining -> NalExceedsBuffer. `out` must come
        // back exactly as it went in, not with the first NAL spliced on.
        let avcc = [
            0, 0, 0, 2, 0x67, 0x42, // valid NAL
            0, 0, 0, 9, 0xaa, 0xbb, // overrunning NAL
        ];
        let mut out = vec![0xde, 0xad, 0xbe, 0xef];
        let seeded = out.clone();
        assert_eq!(
            avcc_to_annex_b(&avcc, 4, &mut out),
            Err(AvccError::NalExceedsBuffer {
                nal_len: 9,
                remaining: 2
            })
        );
        assert_eq!(out, seeded);
    }
}

#[cfg(test)]
mod split_tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn splits_three_and_four_byte_start_codes_and_drops_trailing_zeros() {
        let s = [
            0xAA, 0xBB, // junk before the first start code
            0, 0, 0, 1, 0x67, 0x42, 0, 0, // SPS + trailing_zero_8bits
            0, 0, 1, 0x68, 0xCE, // 3-byte start code
            0, 0, 0, 1, 0x65, 0x88, 0x80,
        ];
        let nals: Vec<&[u8]> = split_annex_b(&s).collect();
        assert_eq!(
            nals,
            [&[0x67, 0x42][..], &[0x68, 0xCE], &[0x65, 0x88, 0x80]]
        );
    }

    #[test]
    fn empty_and_start_code_only_input_yield_nothing() {
        assert_eq!(split_annex_b(&[]).count(), 0);
        assert_eq!(split_annex_b(&[0, 0, 1]).count(), 0);
        assert_eq!(split_annex_b(&[0, 0, 0, 1, 0, 0, 0, 1]).count(), 0);
        assert_eq!(split_annex_b(&[1, 2, 3]).count(), 0);
    }

    #[test]
    fn re_splits_what_avcc_to_annex_b_writes() {
        let avcc = [0, 0, 0, 3, 0x67, 0x42, 0x10, 0, 0, 0, 2, 0x68, 0xCE];
        let mut out = Vec::new();
        avcc_to_annex_b(&avcc, 4, &mut out).unwrap_or_default();
        let nals: Vec<&[u8]> = split_annex_b(&out).collect();
        assert_eq!(nals, [&[0x67, 0x42, 0x10][..], &[0x68, 0xCE]]);
    }

    #[test]
    fn frame_id_is_fnv1a_64_over_the_concatenation() {
        // FNV-1a 64 reference values: "" and "a".
        assert_eq!(frame_id(std::iter::empty::<&[u8]>()), 0xcbf2_9ce4_8422_2325);
        assert_eq!(frame_id([&b"a"[..]]), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(
            frame_id([&[0x41, 0x9A][..], &[0x01, 0x02]]),
            frame_id([&[0x41, 0x9A, 0x01, 0x02][..]])
        );
    }
}
