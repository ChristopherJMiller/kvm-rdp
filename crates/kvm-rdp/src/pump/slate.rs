//! The connecting slate (§6.4): a pre-encoded 1920×1080 "Connecting to
//! KVM…" IDR built by `gen-fixtures`, sent on the first Setup when the
//! surface has its size. Rebuilt once into §6.3's form — allowlisted NALs
//! only, 4-byte start codes. Not a KVM frame: it does not arm suppression
//! and does not count for delivery. Its SPS and PPS are byte for byte the
//! ones the client then gets for the ES3's stream on the same surface
//! (Baseline, CAVLC, POC type 0): Windows App on macOS appears not to
//! switch decoder mid-surface, and a Main/CABAC slate stranded the KVM's
//! picture behind it (2026-11-16; `gen-fixtures.sh` `slate()`).
use kvm_proto::h264::{is_vcl, nal_type_allowed, parse_sps, split_annex_b};

const SLATE: &[u8] = include_bytes!("../../../../fixtures/slate_1080p.h264");

pub struct Slate {
    pub annex_b: Vec<u8>,
    pub size: (u16, u16),
}

impl Slate {
    #[must_use]
    pub fn embedded() -> Option<Slate> {
        Slate::from_annex_b(SLATE)
    }

    #[must_use]
    pub fn from_annex_b(data: &[u8]) -> Option<Slate> {
        let mut annex_b = Vec::with_capacity(data.len());
        let mut size = None;
        let mut picture = false;
        for nal in split_annex_b(data) {
            let t = nal.first()? & 0x1F;
            if !nal_type_allowed(t) {
                continue;
            }
            if t == 7 {
                let s = parse_sps(nal).ok()?;
                size = Some((u16::try_from(s.width).ok()?, u16::try_from(s.height).ok()?));
            }
            picture |= is_vcl(t);
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(nal);
        }
        if !picture {
            return None;
        }
        Some(Slate {
            annex_b,
            size: size?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use kvm_proto::bits::{BitReader, unescape_rbsp};
    use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
    use kvm_proto::h264::sps_syntax::SpsSyntax;

    /// §6.4: the slate is a 1920×1080 IDR; only allowlisted NALs survive
    /// (x264's SEI does not), each behind a 4-byte start code (§6.3).
    #[test]
    fn the_embedded_slate_is_a_1080p_idr_with_allowlisted_nals_only() {
        let s = Slate::embedded().unwrap();
        assert_eq!(s.size, (1920, 1080));
        assert_eq!(s.annex_b[..4], [0, 0, 0, 1]);
        let types: Vec<u8> = split_annex_b(&s.annex_b).map(|n| n[0] & 0x1F).collect();
        assert!(
            types.contains(&5) && types.contains(&7) && types.contains(&8),
            "{types:?}"
        );
        assert!(
            types.iter().all(|t| matches!(t, 1 | 5 | 7 | 8 | 9)),
            "{types:?}"
        );
    }

    #[test]
    fn a_stream_without_a_picture_is_no_slate() {
        assert!(Slate::from_annex_b(&[0, 0, 0, 1, 0x09, 0x10]).is_none());
        assert!(Slate::from_annex_b(&[]).is_none());
    }

    /// §6.3/§6.4 (m3): the embedded slate's NAL sequence is pinned exactly
    /// (AUD, SPS, PPS, IDR — the SEI dropped), and removing its one VCL NAL
    /// — leaving every other allowlisted NAL intact — still has no slate.
    /// `a_stream_without_a_picture_is_no_slate` above only ever fails
    /// earlier, on the missing SPS; this reaches the picture check itself.
    #[test]
    fn removing_the_only_picture_nal_from_the_slate_leaves_no_slate() {
        let s = Slate::embedded().unwrap();
        let types: Vec<u8> = split_annex_b(&s.annex_b).map(|n| n[0] & 0x1F).collect();
        assert_eq!(types, [9, 7, 8, 5]);

        let mut without_idr = Vec::new();
        for nal in split_annex_b(&s.annex_b) {
            if nal.first().map(|b| b & 0x1F) == Some(5) {
                continue;
            }
            without_idr.extend_from_slice(&[0, 0, 0, 1]);
            without_idr.extend_from_slice(nal);
        }
        assert!(Slate::from_annex_b(&without_idr).is_none());
    }

    /// `census.md` `sps_hex` and `pps_hex` (trailing zero bytes included):
    /// the ES3's parameter sets as it sends them.
    const CENSUS_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];
    const CENSUS_PPS: [u8; 6] = [0x68, 0xce, 0x31, 0x12, 0x00, 0x00];

    /// The embedded slate's only NAL of `nal_type`.
    fn only_nal(nal_type: u8) -> Vec<u8> {
        let s = Slate::embedded().unwrap();
        let found: Vec<&[u8]> = split_annex_b(&s.annex_b)
            .filter(|n| n[0] & 0x1F == nal_type)
            .collect();
        let [nal] = found.as_slice() else {
            panic!("{} NALs of type {nal_type}", found.len());
        };
        nal.to_vec()
    }

    /// A PPS's (`entropy_coding_mode_flag`, `num_slice_groups_minus1`,
    /// `redundant_pic_cnt_present_flag`), read per H.264 7.3.2.2.
    fn pps_profile_fields(nal: &[u8]) -> (bool, u32, bool) {
        let rbsp = unescape_rbsp(&nal[1..]);
        let mut r = BitReader::new(&rbsp);
        r.read_ue().unwrap(); // pic_parameter_set_id
        r.read_ue().unwrap(); // seq_parameter_set_id
        let cabac = r.read_flag().unwrap();
        r.read_flag().unwrap(); // bottom_field_pic_order_in_frame_present_flag
        let slice_groups = r.read_ue().unwrap();
        assert_eq!(slice_groups, 0, "no slice-group map to skip");
        r.read_ue().unwrap(); // num_ref_idx_l0_default_active_minus1
        r.read_ue().unwrap(); // num_ref_idx_l1_default_active_minus1
        r.read_flag().unwrap(); // weighted_pred_flag
        r.read_bits(2).unwrap(); // weighted_bipred_idc
        r.read_se().unwrap(); // pic_init_qp_minus26
        r.read_se().unwrap(); // pic_init_qs_minus26
        r.read_se().unwrap(); // chroma_qp_index_offset
        r.read_flag().unwrap(); // deblocking_filter_control_present_flag
        r.read_flag().unwrap(); // constrained_intra_pred_flag
        (cabac, slice_groups, r.read_flag().unwrap())
    }

    /// §6.4 (2026-11-16): Windows App on macOS kept the Main/CABAC slate on
    /// screen while it acked the ES3's Baseline/CAVLC frames on the same
    /// surface, most likely because it does not switch decoder mid-surface.
    /// So the slate is Baseline (66) and CAVLC, keeps to the Constrained
    /// Baseline subset (one slice group, no redundant pictures; A.2.1.1) as
    /// the ES3 does, and leaves `constraint_set1_flag` 0 as the ES3 sends
    /// it: its SPS and PPS are byte for byte what the bridge sends for the
    /// ES3 — census.md's SPS through §6.8's rewrite at the default
    /// `video.sps_rewrite` and `max_fps` (`RewriteConfig::ES3`, pinned in
    /// config.rs), and census.md's PPS trimmed of its trailing zero bytes
    /// (§6.2).
    #[test]
    fn the_embedded_slate_is_baseline_cavlc_with_the_kvms_parameter_sets() {
        let (sps, pps) = (only_nal(7), only_nal(8));
        let syntax = SpsSyntax::parse(&sps).unwrap();
        assert_eq!(
            (syntax.profile_idc, syntax.constraint_flags),
            (66, 0x00),
            "Baseline, the ES3's constraint flags"
        );
        assert_eq!(
            pps_profile_fields(&pps),
            (false, 0, false),
            "CAVLC, one slice group, no redundant pictures"
        );

        let kvm = rewrite_sps(&CENSUS_SPS, &RewriteConfig::ES3).unwrap();
        assert_eq!(sps, kvm.nal, "the rewritten ES3 SPS, byte for byte");
        assert_eq!(pps, CENSUS_PPS[..4], "the ES3's PPS, byte for byte");
        // The fields that matter, spelled out (the equality above has them all).
        let s = parse_sps(&sps).unwrap();
        assert_eq!(s, kvm.summary);
        assert_eq!(
            (s.level_idc, s.pic_order_cnt_type, s.log2_max_frame_num),
            (40, 0, 8)
        );
        assert_eq!((s.num_ref_frames, s.frame_mbs_only_flag), (1, true));
        assert_eq!((s.width, s.height, s.frame_cropping), (1920, 1080, true));
        assert_eq!(s.video_full_range_flag, Some(false), "limited range");
        assert_eq!(
            (s.colour_primaries, s.matrix_coefficients),
            (Some(1), Some(1))
        );
        assert_eq!(
            (s.max_num_reorder_frames, s.max_dec_frame_buffering),
            (Some(0), Some(1))
        );
    }
}
