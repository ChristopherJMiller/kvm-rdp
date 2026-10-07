//! The full `seq_parameter_set_rbsp()` syntax (H.264 7.3.2.1.1 and E.1.1),
//! read with kvm-proto's own bounded bit reader and written back field by
//! field (§6.8). h264-reader refuses the ES3's SPS as sent (its level is
//! below its coded size), so the rewriter cannot start from h264-reader's
//! parse. Scaling matrices and HRD parameters are not read: §6.1 refuses
//! both, so such an SPS is `Unsupported`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::bits::{BitError, BitReader, BitWriter, escape_rbsp_into, unescape_rbsp};

/// Why an SPS could not be read into an [`SpsSyntax`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpsSyntaxError {
    /// Empty NAL, forbidden bit set, or not `nal_unit_type` 7.
    NotSps,
    /// The bitstream ended early, an Exp-Golomb code was too long, or data
    /// followed the syntax where `rbsp_trailing_bits()` belongs.
    Bits(BitError),
    /// A syntax element was outside its H.264 range.
    OutOfRange(&'static str),
    /// Syntax the rewriter does not read because §6.1 refuses it.
    Unsupported(&'static str),
}

impl From<BitError> for SpsSyntaxError {
    fn from(e: BitError) -> Self {
        SpsSyntaxError::Bits(e)
    }
}

/// `chroma_format_idc` .. `qpprime_y_zero_transform_bypass_flag`, present
/// only for the profiles listed in 7.3.2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromaSyntax {
    pub chroma_format_idc: u32,
    pub separate_colour_plane_flag: bool,
    pub bit_depth_luma_minus8: u32,
    pub bit_depth_chroma_minus8: u32,
    pub qpprime_y_zero_transform_bypass_flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocSyntax {
    Type0 {
        log2_max_pic_order_cnt_lsb_minus4: u32,
    },
    Type1 {
        delta_pic_order_always_zero_flag: bool,
        offset_for_non_ref_pic: i32,
        offset_for_top_to_bottom_field: i32,
        offset_for_ref_frame: Vec<i32>,
    },
    Type2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColourDescription {
    pub colour_primaries: u8,
    pub transfer_characteristics: u8,
    pub matrix_coefficients: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoSignalType {
    pub video_format: u8,
    pub video_full_range_flag: bool,
    pub colour_description: Option<ColourDescription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingInfo {
    pub num_units_in_tick: u32,
    pub time_scale: u32,
    pub fixed_frame_rate_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitstreamRestriction {
    pub motion_vectors_over_pic_boundaries_flag: bool,
    pub max_bytes_per_pic_denom: u32,
    pub max_bits_per_mb_denom: u32,
    pub log2_max_mv_length_horizontal: u32,
    pub log2_max_mv_length_vertical: u32,
    pub max_num_reorder_frames: u32,
    pub max_dec_frame_buffering: u32,
}

impl BitstreamRestriction {
    /// The structure's fields at the values H.264 infers when it is absent
    /// (E.2.1), with the two reordering fields set as §6.8 (c) requires.
    #[must_use]
    pub fn inferred(max_num_reorder_frames: u32, max_dec_frame_buffering: u32) -> Self {
        Self {
            motion_vectors_over_pic_boundaries_flag: true,
            max_bytes_per_pic_denom: 2,
            max_bits_per_mb_denom: 1,
            log2_max_mv_length_horizontal: 15,
            log2_max_mv_length_vertical: 15,
            max_num_reorder_frames,
            max_dec_frame_buffering,
        }
    }
}

/// `vui_parameters()` without HRD parameters (§6.1 refuses them).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VuiSyntax {
    /// `aspect_ratio_idc`, and `(sar_width, sar_height)` when it is 255.
    pub aspect_ratio: Option<(u8, Option<(u16, u16)>)>,
    /// `overscan_appropriate_flag` when `overscan_info_present_flag` is 1.
    pub overscan_appropriate: Option<bool>,
    pub video_signal_type: Option<VideoSignalType>,
    /// `(chroma_sample_loc_type_top_field, …_bottom_field)`.
    pub chroma_loc: Option<(u32, u32)>,
    pub timing: Option<TimingInfo>,
    pub pic_struct_present_flag: bool,
    pub bitstream_restriction: Option<BitstreamRestriction>,
}

/// Every syntax element of an SPS the rewriter admits, in syntax order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpsSyntax {
    /// `nal_ref_idc` of the NAL header (the header is rebuilt from it).
    pub nal_ref_idc: u8,
    pub profile_idc: u8,
    /// `constraint_set0_flag` .. `constraint_set5_flag` and
    /// `reserved_zero_2bits`, as one byte.
    pub constraint_flags: u8,
    pub level_idc: u8,
    pub seq_parameter_set_id: u32,
    pub chroma: Option<ChromaSyntax>,
    pub log2_max_frame_num_minus4: u32,
    pub poc: PocSyntax,
    pub max_num_ref_frames: u32,
    pub gaps_in_frame_num_value_allowed_flag: bool,
    pub pic_width_in_mbs_minus1: u32,
    pub pic_height_in_map_units_minus1: u32,
    pub frame_mbs_only_flag: bool,
    /// Present only when `frame_mbs_only_flag` is 0.
    pub mb_adaptive_frame_field_flag: bool,
    pub direct_8x8_inference_flag: bool,
    /// `frame_crop_{left,right,top,bottom}_offset`.
    pub frame_cropping: Option<[u32; 4]>,
    pub vui: Option<VuiSyntax>,
}

/// Profiles whose SPS carries the chroma block (7.3.2.1.1).
fn has_chroma_block(profile_idc: u8) -> bool {
    matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    )
}

fn ue_max(r: &mut BitReader<'_>, max: u32, name: &'static str) -> Result<u32, SpsSyntaxError> {
    let v = r.read_ue()?;
    if v > max {
        return Err(SpsSyntaxError::OutOfRange(name));
    }
    Ok(v)
}

impl SpsSyntax {
    /// Read a wire SPS NAL (header byte + emulation-prevented payload).
    pub fn parse(nal: &[u8]) -> Result<SpsSyntax, SpsSyntaxError> {
        let (&header, payload) = nal.split_first().ok_or(SpsSyntaxError::NotSps)?;
        if header & 0x80 != 0 || header & 0x1F != 7 {
            return Err(SpsSyntaxError::NotSps);
        }
        let rbsp = unescape_rbsp(payload);
        let mut r = BitReader::new(&rbsp);
        let profile_idc = r.read_u8()?;
        let constraint_flags = r.read_u8()?;
        let level_idc = r.read_u8()?;
        let seq_parameter_set_id = ue_max(&mut r, 31, "seq_parameter_set_id")?;
        let chroma = if has_chroma_block(profile_idc) {
            let chroma_format_idc = ue_max(&mut r, 3, "chroma_format_idc")?;
            let separate_colour_plane_flag = chroma_format_idc == 3 && r.read_flag()?;
            let bit_depth_luma_minus8 = ue_max(&mut r, 6, "bit_depth_luma_minus8")?;
            let bit_depth_chroma_minus8 = ue_max(&mut r, 6, "bit_depth_chroma_minus8")?;
            let qpprime_y_zero_transform_bypass_flag = r.read_flag()?;
            if r.read_flag()? {
                return Err(SpsSyntaxError::Unsupported(
                    "seq_scaling_matrix_present_flag",
                ));
            }
            Some(ChromaSyntax {
                chroma_format_idc,
                separate_colour_plane_flag,
                bit_depth_luma_minus8,
                bit_depth_chroma_minus8,
                qpprime_y_zero_transform_bypass_flag,
            })
        } else {
            None
        };
        let log2_max_frame_num_minus4 = ue_max(&mut r, 12, "log2_max_frame_num_minus4")?;
        let poc = match r.read_ue()? {
            0 => PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4: ue_max(
                    &mut r,
                    12,
                    "log2_max_pic_order_cnt_lsb_minus4",
                )?,
            },
            1 => {
                let delta_pic_order_always_zero_flag = r.read_flag()?;
                let offset_for_non_ref_pic = r.read_se()?;
                let offset_for_top_to_bottom_field = r.read_se()?;
                let n = ue_max(&mut r, 255, "num_ref_frames_in_pic_order_cnt_cycle")?;
                let mut offset_for_ref_frame = Vec::new();
                for _ in 0..n {
                    offset_for_ref_frame.push(r.read_se()?);
                }
                PocSyntax::Type1 {
                    delta_pic_order_always_zero_flag,
                    offset_for_non_ref_pic,
                    offset_for_top_to_bottom_field,
                    offset_for_ref_frame,
                }
            }
            2 => PocSyntax::Type2,
            _ => return Err(SpsSyntaxError::OutOfRange("pic_order_cnt_type")),
        };
        let max_num_ref_frames = ue_max(&mut r, 16, "max_num_ref_frames")?;
        let gaps_in_frame_num_value_allowed_flag = r.read_flag()?;
        let pic_width_in_mbs_minus1 = ue_max(&mut r, 1023, "pic_width_in_mbs_minus1")?;
        let pic_height_in_map_units_minus1 =
            ue_max(&mut r, 1023, "pic_height_in_map_units_minus1")?;
        let frame_mbs_only_flag = r.read_flag()?;
        let mb_adaptive_frame_field_flag = !frame_mbs_only_flag && r.read_flag()?;
        let direct_8x8_inference_flag = r.read_flag()?;
        let frame_cropping = if r.read_flag()? {
            Some([r.read_ue()?, r.read_ue()?, r.read_ue()?, r.read_ue()?])
        } else {
            None
        };
        let vui = if r.read_flag()? {
            Some(read_vui(&mut r)?)
        } else {
            None
        };
        r.finish()?;
        Ok(SpsSyntax {
            nal_ref_idc: header.wrapping_shr(5) & 0x03,
            profile_idc,
            constraint_flags,
            level_idc,
            seq_parameter_set_id,
            chroma,
            log2_max_frame_num_minus4,
            poc,
            max_num_ref_frames,
            gaps_in_frame_num_value_allowed_flag,
            pic_width_in_mbs_minus1,
            pic_height_in_map_units_minus1,
            frame_mbs_only_flag,
            mb_adaptive_frame_field_flag,
            direct_8x8_inference_flag,
            frame_cropping,
            vui,
        })
    }

    /// `PicWidthInMbs`.
    #[must_use]
    pub fn width_in_mbs(&self) -> u32 {
        self.pic_width_in_mbs_minus1.saturating_add(1)
    }

    /// `FrameHeightInMbs` = (2 − `frame_mbs_only_flag`) × `PicHeightInMapUnits`.
    #[must_use]
    pub fn frame_height_in_mbs(&self) -> u32 {
        let units = self.pic_height_in_map_units_minus1.saturating_add(1);
        if self.frame_mbs_only_flag {
            units
        } else {
            units.saturating_mul(2)
        }
    }

    /// The SPS as a wire NAL: header byte, then the escaped RBSP.
    #[must_use]
    pub fn to_nal(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_u8(self.profile_idc);
        w.write_u8(self.constraint_flags);
        w.write_u8(self.level_idc);
        w.write_ue(self.seq_parameter_set_id);
        if let Some(c) = &self.chroma {
            w.write_ue(c.chroma_format_idc);
            if c.chroma_format_idc == 3 {
                w.write_flag(c.separate_colour_plane_flag);
            }
            w.write_ue(c.bit_depth_luma_minus8);
            w.write_ue(c.bit_depth_chroma_minus8);
            w.write_flag(c.qpprime_y_zero_transform_bypass_flag);
            w.write_flag(false); // seq_scaling_matrix_present_flag
        }
        w.write_ue(self.log2_max_frame_num_minus4);
        match &self.poc {
            PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4,
            } => {
                w.write_ue(0);
                w.write_ue(*log2_max_pic_order_cnt_lsb_minus4);
            }
            PocSyntax::Type1 {
                delta_pic_order_always_zero_flag,
                offset_for_non_ref_pic,
                offset_for_top_to_bottom_field,
                offset_for_ref_frame,
            } => {
                w.write_ue(1);
                w.write_flag(*delta_pic_order_always_zero_flag);
                w.write_se(*offset_for_non_ref_pic);
                w.write_se(*offset_for_top_to_bottom_field);
                w.write_ue(u32::try_from(offset_for_ref_frame.len()).unwrap_or(u32::MAX));
                for o in offset_for_ref_frame {
                    w.write_se(*o);
                }
            }
            PocSyntax::Type2 => w.write_ue(2),
        }
        w.write_ue(self.max_num_ref_frames);
        w.write_flag(self.gaps_in_frame_num_value_allowed_flag);
        w.write_ue(self.pic_width_in_mbs_minus1);
        w.write_ue(self.pic_height_in_map_units_minus1);
        w.write_flag(self.frame_mbs_only_flag);
        if !self.frame_mbs_only_flag {
            w.write_flag(self.mb_adaptive_frame_field_flag);
        }
        w.write_flag(self.direct_8x8_inference_flag);
        match &self.frame_cropping {
            Some(c) => {
                w.write_flag(true);
                for v in c {
                    w.write_ue(*v);
                }
            }
            None => w.write_flag(false),
        }
        match &self.vui {
            Some(v) => {
                w.write_flag(true);
                write_vui(&mut w, v);
            }
            None => w.write_flag(false),
        }
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut nal = Vec::with_capacity(rbsp.len().saturating_add(8));
        nal.push(self.nal_ref_idc.wrapping_shl(5) & 0x60 | 7);
        escape_rbsp_into(&rbsp, &mut nal);
        nal
    }
}

fn read_vui(r: &mut BitReader<'_>) -> Result<VuiSyntax, SpsSyntaxError> {
    let aspect_ratio = if r.read_flag()? {
        let idc = r.read_u8()?;
        let sar = if idc == 255 {
            let w = u16::try_from(r.read_bits(16)?).map_err(|_| BitError::TooManyBits)?;
            let h = u16::try_from(r.read_bits(16)?).map_err(|_| BitError::TooManyBits)?;
            Some((w, h))
        } else {
            None
        };
        Some((idc, sar))
    } else {
        None
    };
    let overscan_appropriate = if r.read_flag()? {
        Some(r.read_flag()?)
    } else {
        None
    };
    let video_signal_type = if r.read_flag()? {
        let video_format = u8::try_from(r.read_bits(3)?).map_err(|_| BitError::TooManyBits)?;
        let video_full_range_flag = r.read_flag()?;
        let colour_description = if r.read_flag()? {
            Some(ColourDescription {
                colour_primaries: r.read_u8()?,
                transfer_characteristics: r.read_u8()?,
                matrix_coefficients: r.read_u8()?,
            })
        } else {
            None
        };
        Some(VideoSignalType {
            video_format,
            video_full_range_flag,
            colour_description,
        })
    } else {
        None
    };
    let chroma_loc = if r.read_flag()? {
        Some((
            ue_max(r, 5, "chroma_sample_loc_type_top_field")?,
            ue_max(r, 5, "chroma_sample_loc_type_bottom_field")?,
        ))
    } else {
        None
    };
    let timing = if r.read_flag()? {
        Some(TimingInfo {
            num_units_in_tick: r.read_bits(32)?,
            time_scale: r.read_bits(32)?,
            fixed_frame_rate_flag: r.read_flag()?,
        })
    } else {
        None
    };
    if r.read_flag()? {
        return Err(SpsSyntaxError::Unsupported(
            "nal_hrd_parameters_present_flag",
        ));
    }
    if r.read_flag()? {
        return Err(SpsSyntaxError::Unsupported(
            "vcl_hrd_parameters_present_flag",
        ));
    }
    let pic_struct_present_flag = r.read_flag()?;
    let bitstream_restriction = if r.read_flag()? {
        Some(BitstreamRestriction {
            motion_vectors_over_pic_boundaries_flag: r.read_flag()?,
            max_bytes_per_pic_denom: ue_max(r, 16, "max_bytes_per_pic_denom")?,
            max_bits_per_mb_denom: ue_max(r, 16, "max_bits_per_mb_denom")?,
            log2_max_mv_length_horizontal: ue_max(r, 16, "log2_max_mv_length_horizontal")?,
            log2_max_mv_length_vertical: ue_max(r, 16, "log2_max_mv_length_vertical")?,
            max_num_reorder_frames: ue_max(r, 16, "max_num_reorder_frames")?,
            max_dec_frame_buffering: ue_max(r, 16, "max_dec_frame_buffering")?,
        })
    } else {
        None
    };
    Ok(VuiSyntax {
        aspect_ratio,
        overscan_appropriate,
        video_signal_type,
        chroma_loc,
        timing,
        pic_struct_present_flag,
        bitstream_restriction,
    })
}

fn write_vui(w: &mut BitWriter, v: &VuiSyntax) {
    match v.aspect_ratio {
        Some((idc, sar)) => {
            w.write_flag(true);
            w.write_u8(idc);
            if idc == 255 {
                let (sw, sh) = sar.unwrap_or((0, 0));
                w.write_bits(u64::from(sw), 16);
                w.write_bits(u64::from(sh), 16);
            }
        }
        None => w.write_flag(false),
    }
    match v.overscan_appropriate {
        Some(f) => {
            w.write_flag(true);
            w.write_flag(f);
        }
        None => w.write_flag(false),
    }
    match v.video_signal_type {
        Some(s) => {
            w.write_flag(true);
            w.write_bits(u64::from(s.video_format), 3);
            w.write_flag(s.video_full_range_flag);
            match s.colour_description {
                Some(c) => {
                    w.write_flag(true);
                    w.write_u8(c.colour_primaries);
                    w.write_u8(c.transfer_characteristics);
                    w.write_u8(c.matrix_coefficients);
                }
                None => w.write_flag(false),
            }
        }
        None => w.write_flag(false),
    }
    match v.chroma_loc {
        Some((top, bottom)) => {
            w.write_flag(true);
            w.write_ue(top);
            w.write_ue(bottom);
        }
        None => w.write_flag(false),
    }
    match v.timing {
        Some(t) => {
            w.write_flag(true);
            w.write_bits(u64::from(t.num_units_in_tick), 32);
            w.write_bits(u64::from(t.time_scale), 32);
            w.write_flag(t.fixed_frame_rate_flag);
        }
        None => w.write_flag(false),
    }
    w.write_flag(false); // nal_hrd_parameters_present_flag
    w.write_flag(false); // vcl_hrd_parameters_present_flag
    w.write_flag(v.pic_struct_present_flag);
    match v.bitstream_restriction {
        Some(b) => {
            w.write_flag(true);
            w.write_flag(b.motion_vectors_over_pic_boundaries_flag);
            w.write_ue(b.max_bytes_per_pic_denom);
            w.write_ue(b.max_bits_per_mb_denom);
            w.write_ue(b.log2_max_mv_length_horizontal);
            w.write_ue(b.log2_max_mv_length_vertical);
            w.write_ue(b.max_num_reorder_frames);
            w.write_ue(b.max_dec_frame_buffering);
        }
        None => w.write_flag(false),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    /// `census.md` `sps_hex`: the ES3's SPS as sent (with a trailing zero byte).
    const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];

    #[test]
    fn reads_the_es3_sps_as_census_md_describes_it() {
        let s = SpsSyntax::parse(&ES3_SPS).unwrap();
        assert_eq!(
            (
                s.nal_ref_idc,
                s.profile_idc,
                s.constraint_flags,
                s.level_idc
            ),
            (3, 66, 0, 31)
        );
        assert_eq!(s.chroma, None); // Baseline: no chroma block
        assert_eq!(s.log2_max_frame_num_minus4, 4);
        assert_eq!(
            s.poc,
            PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4: 4
            }
        );
        assert_eq!(s.max_num_ref_frames, 1);
        assert_eq!((s.width_in_mbs(), s.frame_height_in_mbs()), (120, 68));
        assert!(s.frame_mbs_only_flag);
        assert_eq!(s.frame_cropping, Some([0, 0, 0, 4])); // 1088 → 1080
        let vui = s.vui.unwrap();
        assert_eq!(
            vui.video_signal_type,
            Some(VideoSignalType {
                video_format: 5,
                video_full_range_flag: true,
                colour_description: Some(ColourDescription {
                    colour_primaries: 5,
                    transfer_characteristics: 6,
                    matrix_coefficients: 5,
                }),
            })
        );
        assert_eq!((vui.timing, vui.bitstream_restriction), (None, None));
    }

    #[test]
    fn writes_back_the_same_bytes_without_the_trailing_zero() {
        let s = SpsSyntax::parse(&ES3_SPS).unwrap();
        assert_eq!(s.to_nal(), &ES3_SPS[..16]);
    }

    #[test]
    fn every_committed_fixture_sps_round_trips_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "h264") {
                continue;
            }
            let data = std::fs::read(&path).unwrap();
            for sps in crate::h264::split_annex_b(&data).filter(|n| n[0] & 0x1F == 7) {
                assert_eq!(SpsSyntax::parse(sps).unwrap().to_nal(), sps, "{path:?}");
                seen += 1;
            }
        }
        assert!(seen >= 10, "only {seen} SPSs found");
    }

    fn nal(w: BitWriter) -> Vec<u8> {
        let mut out = vec![0x67];
        escape_rbsp_into(&w.into_rbsp(), &mut out);
        out
    }

    #[test]
    fn refuses_what_section_6_1_refuses_and_what_is_malformed() {
        // High profile with seq_scaling_matrix_present_flag = 1.
        let mut w = BitWriter::new();
        w.write_u8(100);
        w.write_u8(0);
        w.write_u8(40);
        w.write_ue(0);
        w.write_ue(1); // chroma_format_idc
        w.write_ue(0);
        w.write_ue(0);
        w.write_flag(false);
        w.write_flag(true); // seq_scaling_matrix_present_flag
        w.write_trailing_bits();
        assert_eq!(
            SpsSyntax::parse(&nal(w)),
            Err(SpsSyntaxError::Unsupported(
                "seq_scaling_matrix_present_flag"
            ))
        );
        // Baseline with a VUI announcing NAL, then VCL, HRD parameters.
        let hrd = |nal_hrd: bool| {
            let mut w = BitWriter::new();
            w.write_u8(66);
            w.write_u8(0);
            w.write_u8(30);
            for v in [0, 0, 2, 1] {
                w.write_ue(v); // sps_id, log2_max_frame_num_minus4, poc type, refs
            }
            w.write_flag(false);
            w.write_ue(39);
            w.write_ue(22);
            w.write_flag(true);
            w.write_flag(true);
            w.write_flag(false);
            w.write_flag(true); // vui_parameters_present_flag
            for _ in 0..5 {
                w.write_flag(false);
            }
            w.write_flag(nal_hrd); // nal_hrd_parameters_present_flag
            w.write_flag(!nal_hrd); // vcl_hrd_parameters_present_flag
            w.write_trailing_bits();
            nal(w)
        };
        assert_eq!(
            SpsSyntax::parse(&hrd(true)),
            Err(SpsSyntaxError::Unsupported(
                "nal_hrd_parameters_present_flag"
            ))
        );
        assert_eq!(
            SpsSyntax::parse(&hrd(false)),
            Err(SpsSyntaxError::Unsupported(
                "vcl_hrd_parameters_present_flag"
            ))
        );
        // seq_parameter_set_id 32.
        let mut w = BitWriter::new();
        w.write_u8(66);
        w.write_u8(0);
        w.write_u8(30);
        w.write_ue(32);
        w.write_trailing_bits();
        assert_eq!(
            SpsSyntax::parse(&nal(w)),
            Err(SpsSyntaxError::OutOfRange("seq_parameter_set_id"))
        );
        // Truncated, trailing data, and not an SPS at all.
        assert_eq!(
            SpsSyntax::parse(&ES3_SPS[..8]),
            Err(SpsSyntaxError::Bits(BitError::Eof))
        );
        let mut extra = ES3_SPS[..16].to_vec();
        extra.push(0x80);
        assert_eq!(
            SpsSyntax::parse(&extra),
            Err(SpsSyntaxError::Bits(BitError::TrailingData))
        );
        assert_eq!(SpsSyntax::parse(&[0x68, 0xce]), Err(SpsSyntaxError::NotSps));
        assert_eq!(SpsSyntax::parse(&[0xE7, 0x42]), Err(SpsSyntaxError::NotSps));
        assert_eq!(SpsSyntax::parse(&[]), Err(SpsSyntaxError::NotSps));
    }
}
