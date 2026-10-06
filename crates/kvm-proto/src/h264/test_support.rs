//! Test-only H.264 bit writer and SPS/slice NAL builders. Never compiled into
//! normal builds. Lets this component's tests hand-build bitstreams without a
//! fixture dependency (the fixtures component owns gen-fixtures, §11.5).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Big-endian bit writer with Exp-Golomb support.
#[derive(Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8, // bits currently buffered in `cur` (0..8)
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_bit(&mut self, bit: bool) {
        self.cur = (self.cur << 1) | u8::from(bit);
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    pub fn put_bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.put_bit((value >> i) & 1 == 1);
        }
    }

    /// ue(v), unsigned Exp-Golomb.
    pub fn put_ue(&mut self, value: u32) {
        let code = value + 1;
        let nbits = 32 - code.leading_zeros(); // >= 1
        for _ in 0..(nbits - 1) {
            self.put_bit(false);
        }
        self.put_bits(code, nbits);
    }

    /// se(v), signed Exp-Golomb.
    pub fn put_se(&mut self, value: i32) {
        let mapped = if value <= 0 {
            (-value as u32) * 2
        } else {
            (value as u32) * 2 - 1
        };
        self.put_ue(mapped);
    }

    /// rbsp_trailing_bits(): a stop-one bit then zero-pad to a byte boundary.
    pub fn rbsp_trailing_bits(&mut self) {
        self.put_bit(true);
        while self.nbits != 0 {
            self.put_bit(false);
        }
    }

    /// Flush and return the raw (un-escaped) RBSP bytes.
    pub fn into_rbsp(mut self) -> Vec<u8> {
        if self.nbits != 0 {
            self.cur <<= 8 - self.nbits;
            self.bytes.push(self.cur);
            self.nbits = 0;
        }
        self.bytes
    }
}

/// Emulation-prevention-encode an RBSP so `RefNal::rbsp_bits` reconstructs it
/// byte-for-byte: insert 0x03 after any `00 00` followed by a byte <= 0x03.
pub fn escape_rbsp(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len());
    let mut zeros = 0u32;
    for &b in rbsp {
        if zeros >= 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }
        out.push(b);
        if b == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
    }
    out
}

/// Prepend the 1-byte NAL header and emulation-encode the RBSP into a wire NAL.
pub fn wrap_nal(header_byte: u8, rbsp: &[u8]) -> Vec<u8> {
    let mut nal = Vec::with_capacity(rbsp.len() + 1);
    nal.push(header_byte);
    nal.extend_from_slice(&escape_rbsp(rbsp));
    nal
}

/// A hand-built SPS. Fields map 1:1 to H.264 SPS syntax; the chroma block is
/// emitted only for high profiles (profile_idc with chroma info).
pub struct SpsCfg {
    pub profile_idc: u8,
    pub level_idc: u8,
    pub seq_parameter_set_id: u32,
    pub chroma_format_idc: u32,       // emitted only for high profiles
    pub bit_depth_luma_minus8: u32,   // emitted only for high profiles
    pub bit_depth_chroma_minus8: u32, // emitted only for high profiles
    pub log2_max_frame_num_minus4: u32,
    pub pic_order_cnt_type: u32,
    pub log2_max_poc_lsb_minus4: u32, // used only for POC type 0
    pub max_num_ref_frames: u32,
    pub pic_width_in_mbs_minus1: u32,
    pub pic_height_in_map_units_minus1: u32,
    pub frame_mbs_only_flag: bool,
    pub crop: Option<(u32, u32, u32, u32)>, // left, right, top, bottom (crop units)
}

impl SpsCfg {
    /// Valid 1920x1080, Main profile, POC type 2, within §6.1 limits.
    /// Bottom crop of 4 (crop unit 2 for 4:2:0) trims 1088 -> 1080.
    pub fn main_1080p() -> Self {
        Self {
            profile_idc: 77,
            level_idc: 42,
            seq_parameter_set_id: 0,
            chroma_format_idc: 1,
            bit_depth_luma_minus8: 0,
            bit_depth_chroma_minus8: 0,
            log2_max_frame_num_minus4: 0,
            pic_order_cnt_type: 2,
            log2_max_poc_lsb_minus4: 0,
            max_num_ref_frames: 1,
            pic_width_in_mbs_minus1: 119,       // 120 * 16 = 1920
            pic_height_in_map_units_minus1: 67, // 68 * 16 = 1088
            frame_mbs_only_flag: true,
            crop: Some((0, 0, 0, 4)),
        }
    }

    fn has_chroma_block(&self) -> bool {
        matches!(
            self.profile_idc,
            100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 134 | 135 | 138 | 139
        )
    }

    /// Emit a complete wire SPS NAL (header 0x67 + emulation-encoded RBSP).
    pub fn build(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.put_bits(u32::from(self.profile_idc), 8);
        w.put_bits(0, 8); // constraint_set flags + reserved_zero_2bits
        w.put_bits(u32::from(self.level_idc), 8);
        w.put_ue(self.seq_parameter_set_id);
        if self.has_chroma_block() {
            w.put_ue(self.chroma_format_idc);
            if self.chroma_format_idc == 3 {
                w.put_bit(false); // separate_colour_plane_flag
            }
            w.put_ue(self.bit_depth_luma_minus8);
            w.put_ue(self.bit_depth_chroma_minus8);
            w.put_bit(false); // qpprime_y_zero_transform_bypass_flag
            w.put_bit(false); // seq_scaling_matrix_present_flag
        }
        w.put_ue(self.log2_max_frame_num_minus4);
        w.put_ue(self.pic_order_cnt_type);
        match self.pic_order_cnt_type {
            0 => w.put_ue(self.log2_max_poc_lsb_minus4),
            1 => {
                w.put_bit(false); // delta_pic_order_always_zero_flag
                w.put_se(0); // offset_for_non_ref_pic
                w.put_se(0); // offset_for_top_to_bottom_field
                w.put_ue(0); // num_ref_frames_in_pic_order_cnt_cycle
            }
            _ => {}
        }
        w.put_ue(self.max_num_ref_frames);
        w.put_bit(false); // gaps_in_frame_num_value_allowed_flag
        w.put_ue(self.pic_width_in_mbs_minus1);
        w.put_ue(self.pic_height_in_map_units_minus1);
        w.put_bit(self.frame_mbs_only_flag);
        if !self.frame_mbs_only_flag {
            w.put_bit(false); // mb_adaptive_frame_field_flag
        }
        w.put_bit(true); // direct_8x8_inference_flag
        match self.crop {
            Some((l, r, t, b)) => {
                w.put_bit(true); // frame_cropping_flag
                w.put_ue(l);
                w.put_ue(r);
                w.put_ue(t);
                w.put_ue(b);
            }
            None => w.put_bit(false),
        }
        w.put_bit(false); // vui_parameters_present_flag
        w.rbsp_trailing_bits();
        wrap_nal(0x67, &w.into_rbsp()) // SPS: forbidden 0, nal_ref_idc 3, type 7
    }
}

/// Build a wire slice NAL carrying only the three leading header fields
/// (first_mb_in_slice, slice_type, pic_parameter_set_id) + trailing bits.
/// `header_byte` e.g. 0x41 (type 1, non-IDR) or 0x65 (type 5, IDR).
pub fn build_slice_nal(
    header_byte: u8,
    first_mb_in_slice: u32,
    slice_type: u32,
    pps_id: u32,
) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.put_ue(first_mb_in_slice);
    w.put_ue(slice_type);
    w.put_ue(pps_id);
    w.rbsp_trailing_bits();
    wrap_nal(header_byte, &w.into_rbsp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use h264_reader::nal::sps::SeqParameterSet;
    use h264_reader::nal::{Nal, RefNal};

    fn parse(nal: &[u8]) -> SeqParameterSet {
        let refnal = RefNal::new(nal, &[], true);
        SeqParameterSet::from_bits(refnal.rbsp_bits()).unwrap()
    }

    #[test]
    fn ue_roundtrips_through_reader() {
        // Build a NAL whose RBSP is a single ue(v) and read it back via the
        // same reader h264-reader uses (rbsp_bits strips header + emulation).
        let mut w = BitWriter::new();
        w.put_ue(300);
        w.rbsp_trailing_bits();
        let nal = wrap_nal(0x68, &w.into_rbsp());
        let refnal = RefNal::new(&nal, &[], true);
        let mut r = refnal.rbsp_bits();
        use h264_reader::rbsp::BitRead;
        assert_eq!(r.read_ue("v").unwrap(), 300);
    }

    #[test]
    fn main_1080p_parses_to_expected_dimensions() {
        let sps = parse(&SpsCfg::main_1080p().build());
        assert_eq!(sps.pixel_dimensions().unwrap(), (1920, 1080));
        assert_eq!(u8::from(sps.profile_idc), 77);
    }

    #[test]
    fn escape_inserts_emulation_byte() {
        assert_eq!(escape_rbsp(&[0, 0, 0]), [0, 0, 3, 0]);
        assert_eq!(escape_rbsp(&[0, 0, 1]), [0, 0, 3, 1]);
        assert_eq!(escape_rbsp(&[0, 0, 4]), [0, 0, 4]); // >0x03: no insert
    }
}
