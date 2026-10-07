//! The §6.8 SPS rewriter: raise `level_idc` to what the coded size needs,
//! make the VUI say what the ES3's pixels measure (limited-range BT.709),
//! and add `bitstream_restriction` so a decoder never holds frames. It runs
//! on every SPS before anything parses or checks it; its output is what is
//! admitted, classified, cached and sent (§6.1, §6.3).
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::sps_syntax::{
    BitstreamRestriction, ColourDescription, SpsSyntax, SpsSyntaxError, VideoSignalType, VuiSyntax,
};
use crate::h264::{SpsSummary, SpsSummaryError};
use h264_reader::nal::WritableNal as _;
use h264_reader::nal::sps::SeqParameterSet;

/// `video.sps_rewrite` plus `video.max_fps` (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteConfig {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
    pub max_fps: u32,
}

impl RewriteConfig {
    /// `["level", "vui", "restriction"]` at 30 fps — the ES3 default.
    pub const ES3: RewriteConfig = RewriteConfig {
        level: true,
        vui: true,
        restriction: true,
        max_fps: 30,
    };
}

/// Which rewrites changed the SPS (the `sps_rewrites{field}` metric).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewriteFields {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
}

/// Why an SPS could not be rewritten. Every variant is
/// `stream_incompatible` (§6.8, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteError {
    /// kvm-proto's reader could not read it (§6.8: it reads only what §6.1 admits).
    Unreadable(SpsSyntaxError),
    /// No level in H.264 Table A-1 admits the coded size at `max_fps`.
    NoLevel { width_mbs: u32, height_mbs: u32 },
    /// Reading the output back with kvm-proto's reader gave other fields.
    SelfCheck,
    /// h264-reader refused the output.
    H264Reader(String),
    /// h264-reader parsed the output but did not re-serialise it to the same
    /// bytes, so it read different fields than were written.
    Disagrees,
    /// The parsed output has no valid summary (chroma or cropping).
    Summary(String),
    /// `level_idc` is not level 1b, and either names no level in Table A-1
    /// at all, or names a level above 5.1 (§6.1 refuses above 5.1 anyway,
    /// so levels 6, 6.1 and 6.2 are refused here by policy even though they
    /// are real Table A-1 entries) (fix round 1, controller ruling; wording
    /// corrected in fix round 2): rather than pass an undefined or
    /// out-of-range level through unchanged, it is refused.
    UnknownLevel(u8),
}

/// A rewritten, verified SPS.
#[derive(Debug, Clone)]
pub struct RewrittenSps {
    /// The SPS NAL to admit, cache and send (header byte included).
    pub nal: Vec<u8>,
    pub syntax: SpsSyntax,
    /// h264-reader's parse of `nal`, for the PPS and slice checks.
    pub parsed: SeqParameterSet,
    pub summary: SpsSummary,
    pub changed: RewriteFields,
}

/// H.264 Table A-1: (`level_idc`, MaxMBPS, MaxFS), ascending. Level 1b is
/// left out: the lowest level that admits a size is never 1b.
const LEVELS: [(u8, u64, u64); 16] = [
    (10, 1_485, 99),
    (11, 3_000, 396),
    (12, 6_000, 396),
    (13, 11_880, 396),
    (20, 11_880, 396),
    (21, 19_800, 792),
    (22, 20_250, 1_620),
    (30, 40_500, 1_620),
    (31, 108_000, 3_600),
    (32, 216_000, 5_120),
    (40, 245_760, 8_192),
    (41, 245_760, 8_192),
    (42, 522_240, 8_704),
    (50, 589_824, 22_080),
    (51, 983_040, 36_864),
    (52, 2_073_600, 36_864),
];

/// The lowest `level_idc` whose MaxFS and MaxMBPS admit a
/// `width_mbs` × `height_mbs` frame at `fps` (A.3.1: FrameSizeInMbs ≤
/// MaxFS, PicWidthInMbs² and FrameHeightInMbs² ≤ 8 × MaxFS, and
/// FrameSizeInMbs × fps ≤ MaxMBPS — the side rule is beyond §6.8 (a)'s two
/// columns, deviation D9).
#[must_use]
pub fn required_level_idc(width_mbs: u32, height_mbs: u32, fps: u32) -> Option<u8> {
    let (w, h) = (u64::from(width_mbs), u64::from(height_mbs));
    let fs = w.saturating_mul(h);
    let mbps = fs.saturating_mul(u64::from(fps));
    LEVELS
        .iter()
        .find(|&&(_, max_mbps, max_fs)| {
            let side = max_fs.saturating_mul(8);
            fs <= max_fs
                && mbps <= max_mbps
                && w.saturating_mul(w) <= side
                && h.saturating_mul(h) <= side
        })
        .map(|&(idc, _, _)| idc)
}

/// True when `(profile_idc, level_idc, constraint_flags)` encodes level 1b
/// (Table A-1, note a): `level_idc` 11 with `constraint_set3_flag` set, for
/// the Baseline, Main and Extended profiles (66, 77, 88); `level_idc` 9, for
/// every other profile (fix round 1, I1).
#[must_use]
fn is_level_1b(profile_idc: u8, level_idc: u8, constraint_flags: u8) -> bool {
    match profile_idc {
        66 | 77 | 88 => level_idc == 11 && constraint_flags & 0x10 != 0,
        _ => level_idc == 9,
    }
}

/// A rank for `level_idc` that places level 1b strictly between level 1
/// (`level_idc` 10) and level 1.1 (`level_idc` 11): every `LEVELS`
/// `level_idc` doubled, so 1b's rank (21) falls between 1's (20) and 1.1's
/// (22). `None` when the level is neither 1b nor one of `LEVELS`'s entries
/// (up to 5.2 — not necessarily undefined in Table A-1 itself: levels 6,
/// 6.1 and 6.2 are real entries this rewriter does not rank, since §6.1
/// refuses above 5.1 regardless, fix round 2).
#[must_use]
fn level_rank(profile_idc: u8, level_idc: u8, constraint_flags: u8) -> Option<u16> {
    if is_level_1b(profile_idc, level_idc, constraint_flags) {
        return Some(21);
    }
    LEVELS
        .iter()
        .any(|&(idc, _, _)| idc == level_idc)
        .then(|| u16::from(level_idc).saturating_mul(2))
}

/// Apply the configured rewrites to a parsed SPS, in place; returns which
/// ones changed it.
pub fn apply_rewrites(
    s: &mut SpsSyntax,
    cfg: &RewriteConfig,
) -> Result<RewriteFields, RewriteError> {
    let mut changed = RewriteFields::default();
    if cfg.level {
        let (w, h) = (s.width_in_mbs(), s.frame_height_in_mbs());
        let need = required_level_idc(w, h, cfg.max_fps).ok_or(RewriteError::NoLevel {
            width_mbs: w,
            height_mbs: h,
        })?;
        let current = level_rank(s.profile_idc, s.level_idc, s.constraint_flags)
            .ok_or(RewriteError::UnknownLevel(s.level_idc))?;
        // `required_level_idc` never returns a 1b level (see its own doc),
        // so `need`'s rank is always a plain Table A-1 entry.
        let need_rank = u16::from(need).saturating_mul(2);
        if need_rank > current {
            if matches!(s.profile_idc, 66 | 77 | 88) {
                // cs3 is reserved-zero for 66/77/88 whenever level_idc != 11
                // (fix round 1) and must not survive a raise even when the
                // *input* was not itself 1b (fix round 2, N1): a stray cs3
                // at level_idc 10 raised to 11 would otherwise read back as
                // 1b, under-levelling the stream or wrongly refusing an
                // admissible one. `required_level_idc` never returns 9, so
                // this can only ever clear a bit that is reserved at the
                // output level.
                s.constraint_flags &= !0x10;
            }
            s.level_idc = need;
            changed.level = true;
        }
    }
    if cfg.vui {
        let vui = s.vui.get_or_insert_with(VuiSyntax::default);
        let video_format = vui.video_signal_type.map_or(5, |v| v.video_format);
        let want = Some(VideoSignalType {
            video_format,
            video_full_range_flag: false,
            colour_description: Some(ColourDescription {
                colour_primaries: 1,
                transfer_characteristics: 1,
                matrix_coefficients: 1,
            }),
        });
        if vui.video_signal_type != want {
            vui.video_signal_type = want;
            changed.vui = true;
        }
    }
    if cfg.restriction {
        let dpb = s.max_num_ref_frames.max(1);
        let vui = s.vui.get_or_insert_with(VuiSyntax::default);
        if vui.bitstream_restriction.is_none() {
            vui.bitstream_restriction = Some(BitstreamRestriction::inferred(0, dpb));
            changed.restriction = true;
        }
    }
    Ok(changed)
}

/// Rewrite and verify one wire SPS NAL (§6.8). The output is accepted only
/// if kvm-proto's reader reads back exactly the rewritten fields, and
/// h264-reader both parses it and re-serialises its parse to the same
/// bytes — an independent reader that saw every field as written.
pub fn rewrite_sps(nal: &[u8], cfg: &RewriteConfig) -> Result<RewrittenSps, RewriteError> {
    let mut syntax = SpsSyntax::parse(nal).map_err(RewriteError::Unreadable)?;
    let changed = apply_rewrites(&mut syntax, cfg)?;
    let out = syntax.to_nal();
    if SpsSyntax::parse(&out).as_ref() != Ok(&syntax) {
        return Err(RewriteError::SelfCheck);
    }
    let parsed = h264_reader_parse(&out)?;
    let header = h264_reader::nal::NalHeader::new(*out.first().ok_or(RewriteError::SelfCheck)?)
        .map_err(|e| RewriteError::H264Reader(format!("{e:?}")))?;
    let mut again = Vec::with_capacity(out.len());
    parsed
        .write_with_header(header, &mut again)
        .map_err(|e| RewriteError::H264Reader(e.to_string()))?;
    if again != out {
        return Err(RewriteError::Disagrees);
    }
    let summary = SpsSummary::from_sps(&parsed)
        .map_err(|e: SpsSummaryError| RewriteError::Summary(format!("{e:?}")))?;
    Ok(RewrittenSps {
        nal: out,
        syntax,
        parsed,
        summary,
        changed,
    })
}

fn h264_reader_parse(nal: &[u8]) -> Result<SeqParameterSet, RewriteError> {
    use h264_reader::nal::{Nal as _, RefNal};
    if nal.is_empty() {
        return Err(RewriteError::SelfCheck);
    }
    let refnal = RefNal::new(nal, &[], true);
    SeqParameterSet::from_bits(refnal.rbsp_bits())
        .map_err(|e| RewriteError::H264Reader(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::h264::sps_syntax::TimingInfo;
    use crate::h264::test_support::SpsCfg;

    /// `census.md` `sps_hex`: the ES3's SPS as sent.
    const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A minimal hand-built SPS for the level-1b tests: no chroma block
    /// unless `profile_idc` needs one, POC type 2, no VUI. `width_mbs` and
    /// `height_mbs` are MB counts directly (not pixels).
    fn sps_1b(
        profile_idc: u8,
        constraint_flags: u8,
        level_idc: u8,
        width_mbs: u32,
        height_mbs: u32,
        max_num_ref_frames: u32,
    ) -> Vec<u8> {
        let mut w = crate::bits::BitWriter::new();
        w.write_u8(profile_idc);
        w.write_u8(constraint_flags);
        w.write_u8(level_idc);
        w.write_ue(0); // seq_parameter_set_id
        if matches!(
            profile_idc,
            100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
        ) {
            w.write_ue(1); // chroma_format_idc: 4:2:0
            w.write_ue(0); // bit_depth_luma_minus8
            w.write_ue(0); // bit_depth_chroma_minus8
            w.write_flag(false); // qpprime_y_zero_transform_bypass_flag
            w.write_flag(false); // seq_scaling_matrix_present_flag
        }
        w.write_ue(0); // log2_max_frame_num_minus4
        w.write_ue(2); // pic_order_cnt_type = 2
        w.write_ue(max_num_ref_frames);
        w.write_flag(false); // gaps_in_frame_num_value_allowed_flag
        w.write_ue(width_mbs.saturating_sub(1));
        w.write_ue(height_mbs.saturating_sub(1));
        w.write_flag(true); // frame_mbs_only_flag
        w.write_flag(true); // direct_8x8_inference_flag
        w.write_flag(false); // frame_cropping_flag
        w.write_flag(false); // vui_parameters_present_flag
        w.write_trailing_bits();
        let mut nal = vec![0x67];
        crate::bits::escape_rbsp_into(&w.into_rbsp(), &mut nal);
        nal
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).unwrap())
            .collect()
    }

    fn contains_escape(n: &[u8]) -> bool {
        n.windows(3).any(|w| w == [0, 0, 3])
    }

    fn fixture_sps(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        let data = std::fs::read(p).unwrap();
        crate::h264::split_annex_b(&data)
            .find(|n| n[0] & 0x1F == 7)
            .unwrap()
            .to_vec()
    }

    /// The L0 golden (§11.2): level 31 → 40, VUI limited-range BT.709,
    /// bitstream_restriction 0/1 added — hand-checked bit by bit in Plan B;
    /// `scripts/gen-fixtures.sh es3like` (Task 6.1) re-reads this hex and the
    /// level+VUI one below with ffmpeg's trace_headers on every run.
    #[test]
    fn es3_sps_golden() {
        assert!(
            crate::h264::parse_sps(&ES3_SPS).is_err(),
            "h264-reader refuses it as sent"
        );
        let r = rewrite_sps(&ES3_SPS, &RewriteConfig::ES3).unwrap();
        assert_eq!(hex(&r.nal), "67420028965403c0112f2cd40404041b41008540");
        assert_eq!(
            r.changed,
            RewriteFields {
                level: true,
                vui: true,
                restriction: true
            }
        );
        let s = &r.summary;
        assert_eq!(
            (s.width, s.height, s.level_idc, s.profile_idc),
            (1920, 1080, 40, 66)
        );
        assert_eq!(s.video_full_range_flag, Some(false));
        assert_eq!(
            (s.colour_primaries, s.matrix_coefficients),
            (Some(1), Some(1))
        );
        assert_eq!(
            (s.max_num_reorder_frames, s.max_dec_frame_buffering),
            (Some(0), Some(1))
        );
        // Idempotence: rewriting an already-rewritten SPS is a no-op.
        let r2 = rewrite_sps(&r.nal, &RewriteConfig::ES3).unwrap();
        assert_eq!(r2.nal, r.nal);
        assert_eq!(r2.changed, RewriteFields::default());
    }

    #[test]
    fn es3_level_and_vui_only() {
        let cfg = RewriteConfig {
            restriction: false,
            ..RewriteConfig::ES3
        };
        let r = rewrite_sps(&ES3_SPS, &cfg).unwrap();
        assert_eq!(hex(&r.nal), "67420028965403c0112f2cd404040408");
        assert_eq!(r.summary.max_num_reorder_frames, None);
        // Idempotence under the same (non-ES3) config.
        let r2 = rewrite_sps(&r.nal, &cfg).unwrap();
        assert_eq!(r2.nal, r.nal);
        assert_eq!(r2.changed, RewriteFields::default());
    }

    #[test]
    fn level_table_a1() {
        assert_eq!(required_level_idc(120, 68, 30), Some(40)); // the ES3's 1080p30
        assert_eq!(required_level_idc(120, 68, 60), Some(42)); // 60 fps needs 4.2
        assert_eq!(required_level_idc(40, 23, 30), Some(30));
        assert_eq!(required_level_idc(11, 9, 15), Some(10));
        assert_eq!(required_level_idc(1024, 1024, 30), None);
        // A.3.1 (D9): a 4096×16 strip (256 × 1 MBs) fits MaxFS from level 1.1,
        // but PicWidthInMbs² ≤ 8 × MaxFS first holds at 4.0 (256² = 8 × 8192).
        assert_eq!(required_level_idc(256, 1, 30), Some(40));
    }

    #[test]
    fn level_1b_is_ranked_between_level_1_and_level_1_1() {
        // Case 1: Baseline 1b (level_idc 11, constraint_set3_flag set) at
        // 10×9 MBs @ 30 fps needs level 1.1 (2,700 MB/s > 1b's MaxMBPS of
        // 1,485): raised, with cs3 cleared, even though level_idc's *number*
        // (11) does not change — 1.1 and 1b share it.
        let case1 = sps_1b(66, 0x10, 11, 10, 9, 1);
        let r1 = rewrite_sps(&case1, &RewriteConfig::ES3).unwrap();
        assert_eq!(r1.syntax.level_idc, 11);
        assert_eq!(r1.syntax.constraint_flags & 0x10, 0, "cs3 must be cleared");
        assert!(
            r1.changed.level,
            "1b -> 1.1 is a level change even though level_idc's number is unchanged"
        );

        // Case 2: the same SPS at 11×10 MBs needs level 1.2: raised to
        // level_idc 12, with cs3 cleared (that bit is reserved for
        // 66/77/88 once level_idc != 11).
        let case2 = sps_1b(66, 0x10, 11, 11, 10, 1);
        let r2 = rewrite_sps(&case2, &RewriteConfig::ES3).unwrap();
        assert_eq!(r2.syntax.level_idc, 12);
        assert_eq!(r2.syntax.constraint_flags & 0x10, 0);
        assert!(r2.changed.level);

        // Case 3: a High-profile SPS at level_idc 9 (1b's other form; no
        // constraint-flag variant outside 66/77/88) at 5×5 MBs admits under
        // 1b's own MaxFS/MaxMBPS (99 MBs, 1,485 MB/s): must NOT be lowered
        // to level_idc 10 (level 1, which is weaker than 1b).
        let case3 = sps_1b(100, 0, 9, 5, 5, 1);
        let r3 = rewrite_sps(&case3, &RewriteConfig::ES3).unwrap();
        assert_eq!(r3.syntax.level_idc, 9, "1b must not be lowered to level 1");
        assert!(!r3.changed.level);
    }

    #[test]
    fn a_stray_cs3_below_level_1_1_is_cleared_on_every_raise() {
        // fix round 2 (N1): level_idc 10 is NOT 1b (1b needs level_idc 11
        // for 66/77/88), but a stray constraint_set3_flag there is reserved
        // and ignored by decoders. Raising it to 11 must produce true 1.1
        // (cs3 clear, 2,700 MB/s admitted), not an accidental 1b (MaxMBPS
        // 1,485, which the reviewer showed either under-levels or, at a
        // larger size, wrongly refuses an admissible stream).
        let case = sps_1b(66, 0x10, 10, 10, 9, 1);
        let r = rewrite_sps(&case, &RewriteConfig::ES3).unwrap();
        assert_eq!(r.syntax.level_idc, 11);
        assert_eq!(
            r.syntax.constraint_flags & 0x10,
            0,
            "a stray cs3 below 1.1 must be cleared on raise, not just one carried from 1b"
        );
        assert!(r.changed.level);
        // Idempotent.
        let r2 = rewrite_sps(&r.nal, &RewriteConfig::ES3).unwrap();
        assert_eq!(r2.nal, r.nal);
        assert_eq!(r2.changed, RewriteFields::default());
    }

    #[test]
    fn a_level_that_admits_the_size_is_never_lowered() {
        let mut c = SpsCfg::main_1080p();
        c.level_idc = 51;
        let r = rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap();
        assert_eq!(r.summary.level_idc, 51);
        assert!(!r.changed.level);
    }

    #[test]
    fn a_level_idc_outside_table_a1_is_refused() {
        // 45 is not in Table A-1 and is neither of level 1b's two forms —
        // undefined, so it must be refused rather than pass through
        // unchanged (controller ruling, fix round 1).
        let mut c = SpsCfg::main_1080p();
        c.level_idc = 45;
        assert_eq!(
            rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap_err(),
            RewriteError::UnknownLevel(45)
        );
    }

    #[test]
    fn a_missing_vui_is_created_with_the_inferred_restriction() {
        // Exercises §6.8 (c)'s max(num_ref_frames, 1): refs = 0 must still
        // give max_dec_frame_buffering = 1, not 0.
        let mut c = SpsCfg::main_1080p();
        c.max_num_ref_frames = 0;
        let r = rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap();
        assert_eq!(
            r.syntax.vui,
            Some(VuiSyntax {
                video_signal_type: Some(VideoSignalType {
                    video_format: 5,
                    video_full_range_flag: false,
                    colour_description: Some(ColourDescription {
                        colour_primaries: 1,
                        transfer_characteristics: 1,
                        matrix_coefficients: 1,
                    }),
                }),
                bitstream_restriction: Some(BitstreamRestriction::inferred(0, 1)),
                ..VuiSyntax::default()
            })
        );
        assert_eq!(
            r.changed,
            RewriteFields {
                level: false,
                vui: true,
                restriction: true,
            }
        );
    }

    #[test]
    fn an_already_correct_sps_is_byte_identical() {
        // x264's limited-range BT.709 fixture: level 31 admits 640×360 at
        // 30 fps and bitstream_restriction is present.
        let sps = fixture_sps("360p30_main_limited.h264");
        let r = rewrite_sps(&sps, &RewriteConfig::ES3).unwrap();
        assert_eq!(r.nal, sps);
        assert_eq!(r.changed, RewriteFields::default());
        // Idempotence on a real (non-ES3-shaped) fixture.
        let r2 = rewrite_sps(&r.nal, &RewriteConfig::ES3).unwrap();
        assert_eq!(r2.nal, r.nal);
        assert_eq!(r2.changed, RewriteFields::default());
    }

    #[test]
    fn an_existing_bitstream_restriction_is_kept() {
        let sps = fixture_sps("360p30_main_full.h264");
        let before = SpsSyntax::parse(&sps)
            .unwrap()
            .vui
            .unwrap()
            .bitstream_restriction;
        assert!(before.is_some());
        let r = rewrite_sps(&sps, &RewriteConfig::ES3).unwrap();
        assert_eq!(r.syntax.vui.unwrap().bitstream_restriction, before);
        assert!(r.changed.vui && !r.changed.restriction);
    }

    #[test]
    fn re_serialising_zeros_gains_emulation_prevention() {
        // num_units_in_tick = 1 puts `00 00 00 01` in the RBSP. With no
        // video_signal_type in the input, the VUI rewrite inserts 29 bits
        // ahead of that zero run, so its escapes land at new offsets.
        let mut s = SpsSyntax::parse(&ES3_SPS).unwrap();
        let vui = s.vui.as_mut().unwrap();
        vui.video_signal_type = None;
        vui.timing = Some(TimingInfo {
            num_units_in_tick: 1,
            time_scale: 60,
            fixed_frame_rate_flag: false,
        });
        let input = s.to_nal();
        let escapes = |n: &[u8]| -> Vec<usize> {
            n.windows(3)
                .enumerate()
                .filter(|(_, w)| *w == [0, 0, 3])
                .map(|(i, _)| i)
                .collect()
        };
        let r = rewrite_sps(&input, &RewriteConfig::ES3).unwrap();
        assert!(!escapes(&input).is_empty() && !escapes(&r.nal).is_empty());
        assert_ne!(escapes(&input), escapes(&r.nal), "the zero run moved");
        assert!(!crate::bits::contains_start_code(&r.nal));
        assert_eq!(SpsSyntax::parse(&r.nal).unwrap(), r.syntax);
        let t = r.parsed.vui_parameters.unwrap().timing_info.unwrap();
        assert_eq!((t.num_units_in_tick, t.time_scale), (1, 60));
    }

    #[test]
    fn what_cannot_be_read_or_levelled_is_refused() {
        assert_eq!(
            rewrite_sps(&[0x67], &RewriteConfig::ES3).unwrap_err(),
            RewriteError::Unreadable(SpsSyntaxError::Bits(crate::bits::BitError::Eof))
        );
        let mut huge = SpsCfg::main_1080p();
        huge.pic_width_in_mbs_minus1 = 1023;
        huge.pic_height_in_map_units_minus1 = 1023;
        huge.crop = None;
        assert_eq!(
            rewrite_sps(&huge.build(), &RewriteConfig::ES3).unwrap_err(),
            RewriteError::NoLevel {
                width_mbs: 1024,
                height_mbs: 1024
            }
        );
    }

    #[test]
    fn non_rewritten_vui_fields_including_video_format_survive() {
        // video_format (only full_range/colour_description are in
        // video.sps_rewrite) and every other VUI field the rewriter does
        // not touch must come through unchanged.
        let mut s = SpsSyntax::parse(&ES3_SPS).unwrap();
        let vui = s.vui.as_mut().unwrap();
        vui.aspect_ratio = Some((1, None));
        vui.overscan_appropriate = Some(true);
        vui.chroma_loc = Some((1, 2));
        vui.pic_struct_present_flag = true;
        vui.video_signal_type = vui.video_signal_type.map(|v| VideoSignalType {
            video_format: 2,
            ..v
        });
        let input = s.to_nal();
        let r = rewrite_sps(&input, &RewriteConfig::ES3).unwrap();
        let out = r.syntax.vui.unwrap();
        assert_eq!(out.aspect_ratio, Some((1, None)));
        assert_eq!(out.overscan_appropriate, Some(true));
        assert_eq!(out.chroma_loc, Some((1, 2)));
        assert!(out.pic_struct_present_flag);
        assert_eq!(out.video_signal_type.unwrap().video_format, 2);
    }

    #[test]
    fn an_unescaped_zero_run_gains_escaping_only_from_the_rewrite() {
        // No `00 00 03` anywhere in this input (unlike
        // `re_serialising_zeros_gains_emulation_prevention`, whose input is
        // already escaped): the VUI rewrite's inserted bits shift an
        // existing zero run (timing_info's low bytes) so it needs escaping
        // only in the output.
        let input = hex_decode("6742001f965403c0112f2c20000004000010000080");
        assert!(!contains_escape(&input), "input must start unescaped");
        let r = rewrite_sps(&input, &RewriteConfig::ES3).unwrap();
        assert!(
            contains_escape(&r.nal),
            "the rewrite must introduce an escape"
        );
        assert!(!crate::bits::contains_start_code(&r.nal));
        assert_eq!(SpsSyntax::parse(&r.nal).unwrap(), r.syntax);
        let t = r.parsed.vui_parameters.unwrap().timing_info.unwrap();
        assert_eq!((t.num_units_in_tick, t.time_scale), (32, 32768));
    }
}
