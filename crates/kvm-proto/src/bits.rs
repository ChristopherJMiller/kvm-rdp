//! Bounded bit reader and writer over H.264 RBSP bytes (H.264 7.2), and
//! emulation prevention (7.4.1). The reader faces hostile input: every
//! read is bounds-checked and every Exp-Golomb code is length-capped, so
//! nothing here can panic, overflow or allocate without bound.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Why a bit-level read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitError {
    /// The read ran past the end of the RBSP.
    Eof,
    /// An Exp-Golomb code had more than 31 leading zero bits (its value
    /// would not fit in a `u32`).
    ExpGolombTooLong,
    /// `read_bits` was asked for more than 32 bits.
    TooManyBits,
    /// `finish` found data where `rbsp_trailing_bits()` belongs.
    TrailingData,
}

/// Forward-only MSB-first bit reader over an RBSP (emulation prevention
/// already removed, see [`unescape_rbsp`]).
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Position in bits from the start of `data`.
    pos: usize,
}

impl<'a> BitReader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bits consumed so far.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bits not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_mul(8).saturating_sub(self.pos)
    }

    pub fn read_bit(&mut self) -> Result<bool, BitError> {
        let byte = self
            .data
            .get(self.pos.wrapping_shr(3))
            .copied()
            .ok_or(BitError::Eof)?;
        let shift = 7_u32.saturating_sub(u32::try_from(self.pos & 7).unwrap_or(0));
        self.pos = self.pos.checked_add(1).ok_or(BitError::Eof)?;
        Ok(byte.wrapping_shr(shift) & 1 == 1)
    }

    /// `u(n)` for `n` in `0..=32`.
    pub fn read_bits(&mut self, n: u32) -> Result<u32, BitError> {
        if n > 32 {
            return Err(BitError::TooManyBits);
        }
        let mut v: u32 = 0;
        for _ in 0..n {
            v = v.wrapping_shl(1) | u32::from(self.read_bit()?);
        }
        Ok(v)
    }

    pub fn read_u8(&mut self) -> Result<u8, BitError> {
        u8::try_from(self.read_bits(8)?).map_err(|_| BitError::TooManyBits)
    }

    pub fn read_flag(&mut self) -> Result<bool, BitError> {
        self.read_bit()
    }

    /// `ue(v)`: unsigned Exp-Golomb, at most 31 leading zeros (0..=u32::MAX-1).
    pub fn read_ue(&mut self) -> Result<u32, BitError> {
        let mut zeros: u32 = 0;
        while !self.read_bit()? {
            zeros = zeros.checked_add(1).ok_or(BitError::ExpGolombTooLong)?;
            if zeros > 31 {
                return Err(BitError::ExpGolombTooLong);
            }
        }
        let suffix = self.read_bits(zeros)?;
        // (2^zeros - 1) + suffix, computed in u64 so zeros == 31 cannot overflow.
        let base = 1_u64.wrapping_shl(zeros).saturating_sub(1);
        u32::try_from(base.saturating_add(u64::from(suffix)))
            .map_err(|_| BitError::ExpGolombTooLong)
    }

    /// `se(v)`: signed Exp-Golomb (H.264 9.1.1).
    pub fn read_se(&mut self) -> Result<i32, BitError> {
        let k = i64::from(self.read_ue()?);
        let magnitude = k.saturating_add(1).wrapping_shr(1);
        let v = if k & 1 == 1 {
            magnitude
        } else {
            magnitude.saturating_neg()
        };
        i32::try_from(v).map_err(|_| BitError::ExpGolombTooLong)
    }

    /// `more_rbsp_data()` (7.2): true while anything other than the
    /// `rbsp_trailing_bits()` (a 1 then only zeros to the end) remains.
    #[must_use]
    pub fn more_rbsp_data(&self) -> bool {
        match self.last_one_bit() {
            Some(last) => self.pos < last,
            None => false,
        }
    }

    /// Checks that only `rbsp_trailing_bits()` remain: the next bit is the
    /// stop bit and every bit after it is zero. Trailing zero bytes after
    /// the stop bit (Annex B `trailing_zero_8bits`) are accepted.
    pub fn finish(self) -> Result<(), BitError> {
        match self.last_one_bit() {
            Some(last) if last == self.pos => Ok(()),
            _ => Err(BitError::TrailingData),
        }
    }

    /// Bit index of the last 1 bit in `data` — the `rbsp_stop_one_bit` of a
    /// well-formed RBSP — if any.
    #[must_use]
    pub fn stop_bit_position(&self) -> Option<usize> {
        self.last_one_bit()
    }

    fn last_one_bit(&self) -> Option<usize> {
        let (idx, byte) = self.data.iter().enumerate().rev().find(|(_, b)| **b != 0)?;
        let tz = usize::try_from(byte.trailing_zeros()).ok()?;
        idx.checked_mul(8)?.checked_add(7)?.checked_sub(tz)
    }
}

/// MSB-first bit writer that produces an RBSP. Infallible: it only appends
/// to its own buffer.
#[derive(Debug, Default, Clone)]
pub struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u32,
}

impl BitWriter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_bit(&mut self, bit: bool) {
        self.cur = self.cur.wrapping_shl(1) | u8::from(bit);
        self.nbits = self.nbits.saturating_add(1);
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// The low `n` bits of `value`, MSB first; `n` is clamped to 64.
    pub fn write_bits(&mut self, value: u64, n: u32) {
        for i in (0..n.min(64)).rev() {
            self.write_bit(value.wrapping_shr(i) & 1 == 1);
        }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.write_bits(u64::from(value), 8);
    }

    pub fn write_flag(&mut self, value: bool) {
        self.write_bit(value);
    }

    /// `ue(v)` for every `u32` (u32::MAX takes a 32-zero prefix).
    pub fn write_ue(&mut self, value: u32) {
        let code = u64::from(value).saturating_add(1);
        let len = 64_u32.saturating_sub(code.leading_zeros());
        for _ in 1..len {
            self.write_bit(false);
        }
        self.write_bits(code, len);
    }

    /// `se(v)` for every `i32`.
    pub fn write_se(&mut self, value: i32) {
        let v = i64::from(value);
        let code = if v > 0 {
            v.saturating_mul(2).saturating_sub(1)
        } else {
            v.saturating_mul(-2)
        };
        self.write_ue_u64(u64::try_from(code).unwrap_or(0));
    }

    fn write_ue_u64(&mut self, value: u64) {
        let code = value.saturating_add(1);
        let len = 64_u32.saturating_sub(code.leading_zeros());
        for _ in 1..len {
            self.write_bit(false);
        }
        self.write_bits(code, len);
    }

    /// `rbsp_trailing_bits()`: a stop bit, then zeros to a byte boundary.
    pub fn write_trailing_bits(&mut self) {
        self.write_bit(true);
        while self.nbits != 0 {
            self.write_bit(false);
        }
    }

    #[must_use]
    pub fn is_byte_aligned(&self) -> bool {
        self.nbits == 0
    }

    /// The RBSP written so far; a partial last byte is zero-padded.
    #[must_use]
    pub fn into_rbsp(mut self) -> Vec<u8> {
        if self.nbits != 0 {
            let pad = 8_u32.saturating_sub(self.nbits);
            self.bytes.push(self.cur.wrapping_shl(pad));
        }
        self.bytes
    }
}

/// NAL payload → RBSP: drop every `0x03` that follows `00 00` (7.4.1).
#[must_use]
pub fn unescape_rbsp(nal_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal_payload.len());
    let mut zeros: u8 = 0;
    for &b in nal_payload {
        if zeros >= 2 && b == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(b);
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
    }
    out
}

/// RBSP → NAL payload: insert `0x03` wherever `00 00` would be followed by a
/// byte ≤ `0x03` (7.4.1), so the payload never contains `00 00 00`,
/// `00 00 01` or `00 00 02`. Every RBSP this crate writes ends in a stop
/// bit, so 7.4.1's final-`0x03` rule (only for a trailing `cabac_zero_word`)
/// never applies.
pub fn escape_rbsp_into(rbsp: &[u8], out: &mut Vec<u8>) {
    let mut zeros: u8 = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
    }
}

/// True when `nal` contains `00 00 00`, `00 00 01` or `00 00 02` — a byte
/// pattern a decoder's start-code scanner would treat as a NAL boundary
/// (§6.2: such a NAL is refused).
#[must_use]
pub fn contains_start_code(nal: &[u8]) -> bool {
    nal.windows(3)
        .any(|w| matches!(w, [0, 0, 0] | [0, 0, 1] | [0, 0, 2]))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;
    use h264_reader::rbsp::BitRead as _;

    #[test]
    fn ue_and_se_round_trip_including_extremes() {
        let ues = [0u32, 1, 2, 3, 7, 8, 254, 255, 65_535, u32::MAX - 1];
        let ses = [0i32, 1, -1, 2, -2, 1000, -1000, i32::MAX, i32::MIN + 1];
        let mut w = BitWriter::new();
        for v in ues {
            w.write_ue(v);
        }
        for v in ses {
            w.write_se(v);
        }
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut r = BitReader::new(&rbsp);
        for v in ues {
            assert_eq!(r.read_ue().unwrap(), v);
        }
        for v in ses {
            assert_eq!(r.read_se().unwrap(), v);
        }
        r.finish().unwrap();
    }

    #[test]
    fn writer_agrees_with_h264_reader_bit_reader() {
        // Independent oracle: h264-reader's reader decodes what we wrote.
        let mut w = BitWriter::new();
        w.write_ue(300);
        w.write_se(-17);
        w.write_bits(0b101, 3);
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut r = h264_reader::rbsp::BitReader::new(&rbsp[..]);
        assert_eq!(r.read_ue("a").unwrap(), 300);
        assert_eq!(r.read_se("b").unwrap(), -17);
        assert_eq!(r.read::<3, u8>("c").unwrap(), 0b101);
        r.finish_rbsp().unwrap();
    }

    #[test]
    fn ue_with_32_leading_zeros_is_refused_not_wrapped() {
        // 32 zero bits then a 1: the value would be ≥ 2^32 - 1.
        let data = [0u8, 0, 0, 0, 0x80, 0, 0, 0, 0];
        assert_eq!(
            BitReader::new(&data).read_ue(),
            Err(BitError::ExpGolombTooLong)
        );
    }

    #[test]
    fn reads_past_the_end_are_eof() {
        let mut r = BitReader::new(&[0xFF]);
        assert_eq!(r.read_bits(8), Ok(0xFF));
        assert_eq!(r.read_bit(), Err(BitError::Eof));
        assert_eq!(BitReader::new(&[]).read_ue(), Err(BitError::Eof));
        assert_eq!(
            BitReader::new(&[0]).read_bits(33),
            Err(BitError::TooManyBits)
        );
    }

    #[test]
    fn finish_accepts_trailing_zero_bytes_and_refuses_data() {
        // stop bit at the top of 0x80, then two Annex B trailing zero bytes.
        BitReader::new(&[0x80, 0x00, 0x00]).finish().unwrap();
        let mut r = BitReader::new(&[0b1010_0000]);
        assert!(r.more_rbsp_data());
        r.read_bit().unwrap();
        assert!(r.more_rbsp_data());
        r.read_bit().unwrap();
        assert!(!r.more_rbsp_data());
        assert_eq!(
            BitReader::new(&[0b1100_0000]).finish(),
            Err(BitError::TrailingData)
        );
    }

    #[test]
    fn escape_matches_h264_reader_byte_writer_and_unescape_inverts_it() {
        use std::io::Write as _;
        let cases: [&[u8]; 6] = [
            &[0, 0, 0],
            &[0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 4],
            &[0x67, 0, 0, 0, 0, 0],
            &[1, 2, 3],
            &[0, 0],
            &[],
        ];
        for rbsp in cases {
            let mut ours = Vec::new();
            escape_rbsp_into(rbsp, &mut ours);
            let mut theirs = h264_reader::rbsp::ByteWriter::new(Vec::new());
            theirs.write_all(rbsp).unwrap();
            let theirs = theirs.into_writer();
            assert_eq!(ours, theirs, "escape of {rbsp:02x?}");
            assert!(!contains_start_code(&ours));
            assert_eq!(unescape_rbsp(&ours), rbsp, "round trip of {rbsp:02x?}");
        }
    }

    #[test]
    fn a_stop_bit_byte_after_two_zeros_is_escaped_and_still_found() {
        // An RBSP ending `00 00 01` (the stop bit alone in its byte) goes out
        // as `00 00 03 01`; reading it back still finds that stop bit.
        let rbsp = [0x42, 0x00, 0x00, 0x01];
        let mut nal = Vec::new();
        escape_rbsp_into(&rbsp, &mut nal);
        assert_eq!(nal, [0x42, 0x00, 0x00, 0x03, 0x01]);
        assert!(!contains_start_code(&nal));
        let back = unescape_rbsp(&nal);
        assert_eq!(back, rbsp);
        let mut r = BitReader::new(&back);
        assert_eq!(r.stop_bit_position(), Some(31));
        r.read_bits(31).unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn start_code_patterns_detected() {
        assert!(contains_start_code(&[0x65, 0, 0, 1, 0x88]));
        assert!(contains_start_code(&[0x65, 0, 0, 0]));
        assert!(contains_start_code(&[0x65, 0, 0, 2]));
        assert!(!contains_start_code(&[0x65, 0, 0, 3, 0]));
        assert!(!contains_start_code(&[0x68, 0xce, 0x31, 0x12, 0, 0]));
    }
}
