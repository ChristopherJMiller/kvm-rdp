//! SPS inspection into a flat `SpsSummary` (spec §6.1). Uses h264-reader for
//! the bit-level parse; this layer is total and panic-free over its output.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use h264_reader::nal::sps::{
    ChromaFormat, FrameMbsFlags, PicOrderCntType, SeqParameterSet, SpsError,
};
use h264_reader::nal::{Nal, RefNal};

/// A flat, comparable summary of the SPS fields the bridge reasons about
/// (spec §6.1). `Eq` so change classification (Task 9) can compare summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpsSummary {
    pub profile_idc: u8,
    pub level_idc: u8,
    pub chroma_format_idc: u8, // 0 mono, 1 4:2:0, 2 4:2:2, 3 4:4:4
    pub bit_depth_luma_minus8: u8,
    pub bit_depth_chroma_minus8: u8,
    pub pic_order_cnt_type: u8, // 0, 1 or 2
    pub width: u32,
    pub height: u32,
    pub num_ref_frames: u32,
    pub frame_mbs_only_flag: bool,
    pub seq_scaling_matrix_present: bool,
    pub nal_hrd_present: bool,
    pub vcl_hrd_present: bool,
    pub video_full_range_flag: Option<bool>,
    pub colour_primaries: Option<u8>,
    pub matrix_coefficients: Option<u8>,
    pub max_num_reorder_frames: Option<u32>,
    pub max_dec_frame_buffering: Option<u32>,
    pub log2_max_frame_num: u8,
    pub sps_id: u8,
    pub frame_cropping: bool,
}

/// Why an `SpsSummary` could not be built from a parsed SPS.
#[derive(Debug)]
pub enum SpsSummaryError {
    /// `pixel_dimensions()` failed (cropping overflow, etc.).
    Dimensions(SpsError),
    /// The SPS declared an invalid chroma_format_idc.
    InvalidChroma(u32),
}

/// Why a wire NAL could not be parsed into an `SpsSummary`.
#[derive(Debug)]
pub enum SpsParseError {
    /// The NAL was empty or its forbidden bit was set.
    BadNalHeader,
    /// The NAL was not an SPS (carries the actual nal_unit_type).
    NotSps(u8),
    /// h264-reader rejected the SPS bitstream.
    Sps(SpsError),
    /// The SPS parsed but a summary field could not be derived.
    Summary(SpsSummaryError),
}

impl SpsSummary {
    /// Extract a summary from an already-parsed SPS.
    pub fn from_sps(sps: &SeqParameterSet) -> Result<SpsSummary, SpsSummaryError> {
        let chroma_format_idc: u8 = match sps.chroma_info.chroma_format {
            ChromaFormat::Monochrome => 0,
            ChromaFormat::YUV420 => 1,
            ChromaFormat::YUV422 => 2,
            ChromaFormat::YUV444 => 3,
            ChromaFormat::Invalid(n) => return Err(SpsSummaryError::InvalidChroma(n)),
        };
        // R3: h264-reader 0.9.0 names this field `pic_order_cnt`, not
        // `pic_order_cnt_type`.
        let pic_order_cnt_type: u8 = match sps.pic_order_cnt {
            PicOrderCntType::TypeZero { .. } => 0,
            PicOrderCntType::TypeOne { .. } => 1,
            PicOrderCntType::TypeTwo => 2,
        };
        let (width, height) = sps
            .pixel_dimensions()
            .map_err(SpsSummaryError::Dimensions)?;

        let vui = sps.vui_parameters.as_ref();
        let vst = vui.and_then(|v| v.video_signal_type.as_ref());
        let colour = vst.and_then(|v| v.colour_description.as_ref());
        let br = vui.and_then(|v| v.bitstream_restrictions.as_ref());

        Ok(SpsSummary {
            profile_idc: u8::from(sps.profile_idc),
            level_idc: sps.level_idc,
            chroma_format_idc,
            bit_depth_luma_minus8: sps.chroma_info.bit_depth_luma_minus8,
            bit_depth_chroma_minus8: sps.chroma_info.bit_depth_chroma_minus8,
            pic_order_cnt_type,
            width,
            height,
            // R3: h264-reader 0.9.0 names this field `max_num_ref_frames`, not
            // `num_ref_frames`.
            num_ref_frames: sps.max_num_ref_frames,
            frame_mbs_only_flag: matches!(sps.frame_mbs_flags, FrameMbsFlags::Frames),
            seq_scaling_matrix_present: sps.chroma_info.scaling_matrix.is_some(),
            nal_hrd_present: vui.map(|v| v.nal_hrd_parameters.is_some()).unwrap_or(false),
            vcl_hrd_present: vui.map(|v| v.vcl_hrd_parameters.is_some()).unwrap_or(false),
            video_full_range_flag: vst.map(|v| v.video_full_range_flag),
            colour_primaries: colour.map(|c| c.colour_primaries),
            matrix_coefficients: colour.map(|c| c.matrix_coefficients),
            max_num_reorder_frames: br.map(|b| b.max_num_reorder_frames),
            max_dec_frame_buffering: br.map(|b| b.max_dec_frame_buffering),
            log2_max_frame_num: sps.log2_max_frame_num_minus4.saturating_add(4),
            sps_id: sps.seq_parameter_set_id.id(),
            frame_cropping: sps.frame_cropping.is_some(),
        })
    }
}

/// Parse a wire SPS NAL (header byte + emulation-prevention bytes) into a
/// summary. `RefNal::rbsp_bits` skips the header and strips emulation bytes.
pub fn parse_sps(nal: &[u8]) -> Result<SpsSummary, SpsParseError> {
    // R4: `RefNal::new` panics on empty input (it indexes the first byte for
    // the header). Reject empty NALs before constructing it.
    if nal.is_empty() {
        return Err(SpsParseError::BadNalHeader);
    }
    let refnal = RefNal::new(nal, &[], true);
    let header = refnal.header().map_err(|_| SpsParseError::BadNalHeader)?;
    let unit_type = header.nal_unit_type().id();
    if unit_type != 7 {
        return Err(SpsParseError::NotSps(unit_type));
    }
    let sps = SeqParameterSet::from_bits(refnal.rbsp_bits()).map_err(SpsParseError::Sps)?;
    SpsSummary::from_sps(&sps).map_err(SpsParseError::Summary)
}

/// The §6.1 admission limits. Defaults are the spec ceilings; the census may
/// tighten `max_num_ref_frames` or (if the KVM uses them) relax the scaling
/// matrix / HRD requirements with pinned values.
#[derive(Debug, Clone)]
pub struct SpsLimits {
    pub allowed_profiles: &'static [u8],
    pub max_level_idc: u8,
    pub max_width: u32,
    pub max_height: u32,
    pub max_num_ref_frames: u32,
    pub require_no_scaling_matrix: bool,
    pub require_no_hrd: bool,
}

impl Default for SpsLimits {
    fn default() -> Self {
        Self {
            allowed_profiles: &[66, 77, 100],
            max_level_idc: 51, // level 5.1
            max_width: 4096,
            max_height: 2304,
            max_num_ref_frames: 16,
            require_no_scaling_matrix: true,
            require_no_hrd: true,
        }
    }
}

/// A specific §6.1 SPS limit that was exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpsLimitViolation {
    Profile(u8),
    ChromaNot420(u8),
    BitDepthNot8 { luma_minus8: u8, chroma_minus8: u8 },
    NotFrameMbsOnly,
    Level(u8),
    WidthTooLarge(u32),
    HeightTooLarge(u32),
    WidthNotEven(u32),
    HeightNotEven(u32),
    TooManyRefFrames(u32),
    ScalingMatrixPresent,
    HrdPresent,
}

/// Check an SPS summary against the §6.1 admission limits. The first failing
/// rule wins, in spec order.
pub fn check_sps_limits(s: &SpsSummary, limits: &SpsLimits) -> Result<(), SpsLimitViolation> {
    if !limits.allowed_profiles.contains(&s.profile_idc) {
        return Err(SpsLimitViolation::Profile(s.profile_idc));
    }
    if s.chroma_format_idc != 1 {
        return Err(SpsLimitViolation::ChromaNot420(s.chroma_format_idc));
    }
    if s.bit_depth_luma_minus8 != 0 || s.bit_depth_chroma_minus8 != 0 {
        return Err(SpsLimitViolation::BitDepthNot8 {
            luma_minus8: s.bit_depth_luma_minus8,
            chroma_minus8: s.bit_depth_chroma_minus8,
        });
    }
    if !s.frame_mbs_only_flag {
        return Err(SpsLimitViolation::NotFrameMbsOnly);
    }
    if s.level_idc > limits.max_level_idc {
        return Err(SpsLimitViolation::Level(s.level_idc));
    }
    if s.width > limits.max_width {
        return Err(SpsLimitViolation::WidthTooLarge(s.width));
    }
    if s.height > limits.max_height {
        return Err(SpsLimitViolation::HeightTooLarge(s.height));
    }
    // Bitwise `& 1` avoids clippy::arithmetic_side_effects on `%`.
    if s.width & 1 == 1 {
        return Err(SpsLimitViolation::WidthNotEven(s.width));
    }
    if s.height & 1 == 1 {
        return Err(SpsLimitViolation::HeightNotEven(s.height));
    }
    if s.num_ref_frames > limits.max_num_ref_frames {
        return Err(SpsLimitViolation::TooManyRefFrames(s.num_ref_frames));
    }
    if limits.require_no_scaling_matrix && s.seq_scaling_matrix_present {
        return Err(SpsLimitViolation::ScalingMatrixPresent);
    }
    if limits.require_no_hrd && (s.nal_hrd_present || s.vcl_hrd_present) {
        return Err(SpsLimitViolation::HrdPresent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::h264::test_support::SpsCfg;

    #[test]
    fn main_1080p_summary_fields() {
        let s = parse_sps(&SpsCfg::main_1080p().build()).unwrap();
        assert_eq!(s.profile_idc, 77);
        assert_eq!(s.level_idc, 42);
        assert_eq!(s.chroma_format_idc, 1);
        assert_eq!(s.bit_depth_luma_minus8, 0);
        assert_eq!(s.bit_depth_chroma_minus8, 0);
        assert_eq!(s.pic_order_cnt_type, 2);
        assert_eq!((s.width, s.height), (1920, 1080));
        assert_eq!(s.num_ref_frames, 1);
        assert!(s.frame_mbs_only_flag);
        assert!(!s.seq_scaling_matrix_present);
        assert!(!s.nal_hrd_present && !s.vcl_hrd_present);
        assert_eq!(s.log2_max_frame_num, 4);
        assert_eq!(s.sps_id, 0);
        assert!(s.frame_cropping);
        // No VUI in the builder => colour/reorder fields are None.
        assert_eq!(s.video_full_range_flag, None);
        assert_eq!(s.max_num_reorder_frames, None);
    }

    #[test]
    fn high_profile_10bit_422_extracted() {
        let mut cfg = SpsCfg::main_1080p();
        cfg.profile_idc = 100;
        cfg.chroma_format_idc = 2; // 4:2:2
        cfg.bit_depth_luma_minus8 = 2; // 10-bit
        cfg.bit_depth_chroma_minus8 = 2;
        cfg.crop = None; // avoid 4:2:2 crop-unit arithmetic in this check
        let s = parse_sps(&cfg.build()).unwrap();
        assert_eq!(s.profile_idc, 100);
        assert_eq!(s.chroma_format_idc, 2);
        assert_eq!(s.bit_depth_luma_minus8, 2);
        assert_eq!(s.bit_depth_chroma_minus8, 2);
    }

    #[test]
    fn parse_sps_rejects_non_sps_nal() {
        // PPS header byte 0x68 (type 8)
        assert!(matches!(
            parse_sps(&[0x68, 0x00]),
            Err(SpsParseError::NotSps(8))
        ));
    }

    #[test]
    fn parse_sps_rejects_empty() {
        assert!(matches!(parse_sps(&[]), Err(SpsParseError::BadNalHeader)));
    }

    // R5: `pub(super)` so Task 9's `classify_tests` module (a sibling under
    // `sps.rs`) can reach it via `super::tests::ok_summary`.
    pub(super) fn ok_summary() -> SpsSummary {
        SpsSummary {
            profile_idc: 77,
            level_idc: 42,
            chroma_format_idc: 1,
            bit_depth_luma_minus8: 0,
            bit_depth_chroma_minus8: 0,
            pic_order_cnt_type: 2,
            width: 1920,
            height: 1080,
            num_ref_frames: 1,
            frame_mbs_only_flag: true,
            seq_scaling_matrix_present: false,
            nal_hrd_present: false,
            vcl_hrd_present: false,
            video_full_range_flag: None,
            colour_primaries: None,
            matrix_coefficients: None,
            max_num_reorder_frames: None,
            max_dec_frame_buffering: None,
            log2_max_frame_num: 4,
            sps_id: 0,
            frame_cropping: true,
        }
    }

    #[test]
    fn within_limits_ok() {
        assert_eq!(
            check_sps_limits(&ok_summary(), &SpsLimits::default()),
            Ok(())
        );
    }

    #[test]
    fn each_rule_has_its_own_violation() {
        let lim = SpsLimits::default();
        let mut s = ok_summary();
        s.profile_idc = 244;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::Profile(244))
        );

        let mut s = ok_summary();
        s.chroma_format_idc = 2;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::ChromaNot420(2))
        );

        let mut s = ok_summary();
        s.bit_depth_luma_minus8 = 2;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::BitDepthNot8 {
                luma_minus8: 2,
                chroma_minus8: 0
            })
        );

        let mut s = ok_summary();
        s.frame_mbs_only_flag = false;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::NotFrameMbsOnly)
        );

        let mut s = ok_summary();
        s.level_idc = 52;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::Level(52))
        );

        let mut s = ok_summary();
        s.width = 4112;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::WidthTooLarge(4112))
        );

        let mut s = ok_summary();
        s.height = 2320;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::HeightTooLarge(2320))
        );

        let mut s = ok_summary();
        s.width = 1921;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::WidthNotEven(1921))
        );

        let mut s = ok_summary();
        s.height = 1081;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::HeightNotEven(1081))
        );

        let mut s = ok_summary();
        s.num_ref_frames = 17;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::TooManyRefFrames(17))
        );

        let mut s = ok_summary();
        s.seq_scaling_matrix_present = true;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::ScalingMatrixPresent)
        );

        let mut s = ok_summary();
        s.vcl_hrd_present = true;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::HrdPresent)
        );
    }
}
