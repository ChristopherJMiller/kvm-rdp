//! Census summary (§12 Leg A): roll a capture's `TagRecord`s into IDR/P
//! counts, the codec/FourCC set, the size range, GOP length, and the three
//! counts that decide whether one FLV tag is one access unit.
//!
//! I6/M6: `idr`, `p_slices`, `gop_len`, `min_size` and `max_size` are all
//! counted over *coded AVC video picture tags only* — a video tag
//! (`tag_type == 9`) carrying an actual AVC NALU packet
//! (`codec_id == Some(7) && avc_packet_type == Some(1)`), never a
//! sequence-header/end-of-sequence tag, an audio or script tag, or an
//! Enhanced-RTMP/HEVC tag (which never sets `codec_id == Some(7)`).
//! Interleaved audio no longer inflates `gop_len`, and an HEVC
//! keyframe-flagged tag can never register as an AVC IDR. `idr` is "this
//! tag's NALs include type 5"; `p_slices` is "this tag has a VCL NAL (1–5)
//! but no type 5" — per tag, so they equal per-picture counts only when
//! tag = AU. `bad_header_nals` counts the framing-violation sentinel
//! (`u8::MAX`, §12 I2/record.rs) across *all* tags, not just picture tags —
//! the census must surface it wherever it occurs.
//!
//! **Tag = AU** (final review I2) holds only when all three of
//! `multi_picture_tags`, `continuation_tags` and `non_vcl_picture_tags` are
//! 0. A *slice NAL* is a VCL NAL (types 1–5), paired with its parallel
//! `first_mb` entry; a slice with `first_mb == Some(0)` starts a picture.
//! `gop_len` is counted in pictures, not tags: the picture index advances
//! once per picture start, so a picture split across tags, an AUD/SEI-only
//! tag or a two-picture tag cannot stretch or shrink it.

use crate::record::TagRecord;

#[derive(Debug, Default)]
pub struct TagSummary {
    pub total: usize,
    pub idr: usize,
    pub p_slices: usize,
    pub codecs: Vec<u8>,
    pub fourccs: Vec<String>,
    pub min_size: usize,
    pub max_size: usize,
    pub gop_len: Option<usize>,
    /// AVC NALU tags holding more than one picture start (> 1 slice NAL
    /// with `first_mb_in_slice == 0`): tag ≠ AU.
    pub multi_picture_tags: usize,
    /// Sentinel (`u8::MAX`) NAL-header entries across all tags: framing
    /// violations the census must surface (§12 I2), additive beyond the
    /// plan's original `TagSummary` (B13 review I6/M6).
    pub bad_header_nals: usize,
    /// AVC NALU tags whose first slice NAL does not start a picture
    /// (`first_mb != Some(0)`: the rest of a picture begun in an earlier
    /// tag, or a slice header that failed to parse): tag ≠ AU. Additive
    /// (final review I2).
    pub continuation_tags: usize,
    /// AVC NALU tags with no slice NAL at all (AUD, SEI or in-band SPS/PPS
    /// sent in a tag of their own): tag ≠ AU. Additive (final review I2).
    pub non_vcl_picture_tags: usize,
}

/// A video tag carrying an actual coded AVC picture (NALU packet type 1) —
/// never a sequence header/EOS tag, an audio/script tag, or an
/// Enhanced-RTMP/HEVC tag (which leaves `codec_id` `None`).
fn is_coded_avc_picture(r: &TagRecord) -> bool {
    r.tag_type == 9 && r.codec_id == Some(7) && r.avc_packet_type == Some(1)
}

/// A VCL NAL: a coded slice (1, 5) or slice data partition (2–4). Only
/// types 1 and 5 get a `first_mb` (`capture::push_nal`); a partition — not
/// in §6.2's allowlist anyway — reads as "not a picture start".
fn is_slice(nal_type: u8) -> bool {
    (1..=5).contains(&nal_type)
}

pub fn summarize(records: &[TagRecord]) -> TagSummary {
    let mut s = TagSummary {
        min_size: usize::MAX,
        ..TagSummary::default()
    };
    // Picture index (not `records`' own index, nor a tag count): it
    // advances once per picture start, so interleaved audio/script/
    // sequence-header tags (I6), continuation and non-VCL tags (I2) can
    // never stretch `gop_len`. Only the first two IDR positions are needed.
    let mut idr_positions: Vec<usize> = Vec::new();
    let mut picture_index: usize = 0;
    for r in records {
        s.total = s.total.saturating_add(1);
        if let Some(c) = r.codec_id
            && !s.codecs.contains(&c)
        {
            s.codecs.push(c);
        }
        if let Some(f) = &r.fourcc
            && !s.fourccs.contains(f)
        {
            s.fourccs.push(f.clone());
        }
        // `u8::MAX` is the framing-violation sentinel documented on
        // `TagRecord::nal_types` (record.rs) and produced by
        // `capture::push_nal` for a NAL whose header failed to parse.
        s.bad_header_nals = s
            .bad_header_nals
            .saturating_add(r.nal_types.iter().filter(|&&t| t == u8::MAX).count());

        if !is_coded_avc_picture(r) {
            continue;
        }
        s.min_size = s.min_size.min(r.size);
        s.max_size = s.max_size.max(r.size);
        let has_idr = r.nal_types.contains(&5);
        let has_vcl = r.nal_types.iter().any(|&t| is_slice(t));
        if has_idr {
            s.idr = s.idr.saturating_add(1);
        } else if has_vcl {
            s.p_slices = s.p_slices.saturating_add(1);
        }

        // Walk the slice NALs with their parallel `first_mb` entry. A
        // missing entry (only possible in a hand-edited or tampered JSONL;
        // `record_for` keeps the vectors parallel) reads as `None`.
        let mut first_slice_starts_picture: Option<bool> = None;
        let mut picture_starts: usize = 0;
        for (i, &t) in r.nal_types.iter().enumerate() {
            if !is_slice(t) {
                continue;
            }
            let starts_picture = r.first_mb.get(i).copied().flatten() == Some(0);
            first_slice_starts_picture.get_or_insert(starts_picture);
            if starts_picture {
                picture_starts = picture_starts.saturating_add(1);
                if t == 5 && idr_positions.len() < 2 {
                    idr_positions.push(picture_index);
                }
                picture_index = picture_index.saturating_add(1);
            }
        }
        match first_slice_starts_picture {
            None => s.non_vcl_picture_tags = s.non_vcl_picture_tags.saturating_add(1),
            Some(false) => s.continuation_tags = s.continuation_tags.saturating_add(1),
            Some(true) => {}
        }
        if picture_starts > 1 {
            s.multi_picture_tags = s.multi_picture_tags.saturating_add(1);
        }
    }
    if s.min_size == usize::MAX {
        s.min_size = 0;
    }
    s.codecs.sort_unstable();
    if let (Some(a), Some(b)) = (idr_positions.first(), idr_positions.get(1)) {
        s.gop_len = Some(b.saturating_sub(*a));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TagRecord;

    /// A coded AVC video picture tag: `tag_type == 9`, `codec_id ==
    /// Some(7)`, `avc_packet_type == Some(1)` — the only shape `summarize`
    /// counts for `idr`/`p_slices`/`gop_len`/`min_size`/`max_size` (I6).
    fn picture(nal_types: Vec<u8>, first_mb: Vec<Option<u32>>, size: usize) -> TagRecord {
        TagRecord {
            recv_ms: 0,
            tag_type: 9,
            timestamp_ms: 0,
            composition_time: 0,
            frame_type: None,
            codec_id: Some(7),
            avc_packet_type: Some(1),
            fourcc: None,
            nal_types,
            nal_ref_idc: vec![],
            slice_types: vec![],
            first_mb,
            size,
        }
    }

    /// An audio tag: `codec_id`/`avc_packet_type` are never set for
    /// non-video tags (`capture::record_for`), so this can never count as
    /// a picture.
    fn audio_tag() -> TagRecord {
        TagRecord {
            recv_ms: 0,
            tag_type: 8,
            timestamp_ms: 0,
            composition_time: 0,
            frame_type: None,
            codec_id: None,
            avc_packet_type: None,
            fourcc: None,
            nal_types: vec![],
            nal_ref_idc: vec![],
            slice_types: vec![],
            first_mb: vec![],
            size: 10,
        }
    }

    #[test]
    fn gop_len_counts_coded_pictures_only_skipping_interleaved_audio() {
        // V-IDR, A, V-P, A, V-IDR -> gop_len 2 (the true picture-to-picture
        // distance), not 4 (which the interleaved audio tags would give if
        // they were counted).
        let recs = vec![
            picture(vec![5], vec![Some(0)], 5000),
            audio_tag(),
            picture(vec![1], vec![Some(0)], 900),
            audio_tag(),
            picture(vec![5], vec![Some(0)], 4800),
        ];
        let s = summarize(&recs);
        assert_eq!(s.total, 5);
        assert_eq!(s.idr, 2);
        assert_eq!(s.p_slices, 1);
        assert_eq!(s.codecs, vec![7]);
        assert_eq!((s.min_size, s.max_size), (900, 5000));
        assert_eq!(s.gop_len, Some(2));
    }

    #[test]
    fn multi_picture_tags_still_detected_via_first_mb() {
        // Two slice NALs, each with its own parallel `first_mb` entry.
        let recs = vec![picture(vec![1, 1], vec![Some(0), Some(0)], 900)];
        let s = summarize(&recs);
        assert_eq!(s.multi_picture_tags, 1);
    }

    /// I6: an Enhanced-RTMP/HEVC tag never sets `codec_id == Some(7)`
    /// (`capture::record_for`'s `Enhanced` branch), so it can never
    /// register as an AVC IDR even if it is itself keyframe-flagged and
    /// happens to carry a NAL type 5 in its (HEVC) NAL list.
    #[test]
    fn enhanced_hevc_tag_never_counts_as_idr() {
        let mut r = picture(vec![5], vec![Some(0)], 1000);
        r.codec_id = None;
        r.fourcc = Some("hvc1".to_string());
        let s = summarize(&[r]);
        assert_eq!(s.idr, 0);
        assert_eq!(s.p_slices, 0);
        assert_eq!(s.total, 1);
        // Excluded from the picture-only size range too.
        assert_eq!((s.min_size, s.max_size), (0, 0));
    }

    /// A sequence-header tag (`avc_packet_type == Some(0)`) is not a coded
    /// picture and must not be counted as one, even though it shares
    /// `codec_id == Some(7)`.
    #[test]
    fn sequence_header_tag_is_not_a_coded_picture() {
        let mut r = picture(vec![7, 8], vec![], 40);
        r.avc_packet_type = Some(0);
        let s = summarize(&[r]);
        assert_eq!((s.idr, s.p_slices, s.min_size, s.max_size), (0, 0, 0, 0));
    }

    /// I6/M6: the sentinel NAL (a framing violation, §12 I2) is counted
    /// across all tags, and a picture that also carries a real IDR NAL is
    /// still correctly counted as an IDR.
    #[test]
    fn bad_header_nals_counts_sentinel_255_across_all_tags() {
        // `first_mb` is parallel to `nal_types`, as `record_for` writes it.
        let recs = vec![
            picture(vec![255, 5], vec![None, Some(0)], 1000),
            audio_tag(),
        ];
        let s = summarize(&recs);
        assert_eq!(s.bad_header_nals, 1);
        assert_eq!(s.idr, 1);
    }

    /// The three "tag ≠ AU" counts, in one tuple for the tests below:
    /// (multi_picture_tags, continuation_tags, non_vcl_picture_tags).
    fn not_au_counts(s: &TagSummary) -> (usize, usize, usize) {
        (
            s.multi_picture_tags,
            s.continuation_tags,
            s.non_vcl_picture_tags,
        )
    }

    /// I2 (final review): a picture split across tags — each picture's
    /// second slice arrives in its own tag with first_mb != 0. Every such
    /// tag is a continuation, and gop_len is counted in pictures (IDR, P,
    /// IDR = 2), not tags (which would give 1: the two IDR halves are
    /// adjacent tags).
    #[test]
    fn a_picture_split_across_two_tags_counts_continuations() {
        let recs = vec![
            picture(vec![9, 5], vec![None, Some(0)], 3000),
            picture(vec![5], vec![Some(120)], 3000),
            picture(vec![9, 1], vec![None, Some(0)], 400),
            picture(vec![1], vec![Some(120)], 400),
            picture(vec![9, 5], vec![None, Some(0)], 3000),
            picture(vec![5], vec![Some(120)], 3000),
        ];
        let s = summarize(&recs);
        assert_eq!(not_au_counts(&s), (0, 3, 0));
        assert_eq!(s.gop_len, Some(2));
    }

    /// I2: a slice whose header prefix failed to parse (`first_mb` None)
    /// cannot prove it starts a picture, so as a tag's first slice it is
    /// counted as a continuation — the conservative "tag ≠ AU" direction.
    #[test]
    fn an_unparsed_first_slice_counts_as_a_continuation() {
        let s = summarize(&[picture(vec![1], vec![None], 400)]);
        assert_eq!(not_au_counts(&s), (0, 1, 0));
    }

    /// I2 + B13 re-review minor: an AVC NALU tag with no slice at all (an
    /// AUD- or SEI-only tag, or in-band SPS/PPS in a tag of their own) is a
    /// non-VCL picture tag, and must not stretch gop_len (IDR, P, IDR = 2,
    /// not 5).
    #[test]
    fn aud_or_sei_only_tags_count_as_non_vcl_picture_tags() {
        let recs = vec![
            picture(vec![9, 5], vec![None, Some(0)], 3000),
            picture(vec![9], vec![None], 6),
            picture(vec![6], vec![None], 20),
            picture(vec![9, 1], vec![None, Some(0)], 400),
            picture(vec![7, 8], vec![None, None], 30),
            picture(vec![9, 5], vec![None, Some(0)], 3000),
        ];
        let s = summarize(&recs);
        assert_eq!(not_au_counts(&s), (0, 0, 3));
        assert_eq!(s.gop_len, Some(2));
    }

    /// I2: two pictures in one tag (two slices with first_mb == 0) is a
    /// multi-picture tag, and both pictures count toward gop_len (IDR, P+P,
    /// IDR = 3).
    #[test]
    fn two_pictures_in_one_tag_count_as_a_multi_picture_tag() {
        let recs = vec![
            picture(vec![5], vec![Some(0)], 3000),
            picture(vec![1, 1], vec![Some(0), Some(0)], 800),
            picture(vec![5], vec![Some(0)], 3000),
        ];
        let s = summarize(&recs);
        assert_eq!(not_au_counts(&s), (1, 0, 0));
        assert_eq!(s.gop_len, Some(3));
    }

    /// I2: a clean stream — one picture per AVC NALU tag, including a
    /// multi-slice picture whose slices all sit in its own tag, in-band
    /// SPS/PPS/AUD/SEI alongside a slice, plus sequence-header and audio
    /// tags — has all three "tag ≠ AU" counts at 0.
    #[test]
    fn a_clean_one_picture_per_tag_stream_has_all_three_counts_zero() {
        let mut seq = picture(vec![7, 8], vec![None, None], 40);
        seq.avc_packet_type = Some(0);
        let recs = vec![
            seq,
            picture(
                vec![9, 7, 8, 6, 5, 5],
                vec![None, None, None, None, Some(0), Some(60)],
                5000,
            ),
            audio_tag(),
            picture(vec![9, 1], vec![None, Some(0)], 900),
            picture(vec![9, 1, 1], vec![None, Some(0), Some(60)], 950),
            audio_tag(),
            picture(vec![9, 5], vec![None, Some(0)], 4800),
        ];
        let s = summarize(&recs);
        assert_eq!(not_au_counts(&s), (0, 0, 0));
        assert_eq!((s.idr, s.p_slices, s.gop_len), (2, 2, Some(3)));
    }

    #[test]
    fn empty_input_summarises_to_zeroes() {
        let s = summarize(&[]);
        assert_eq!(
            (s.total, s.min_size, s.max_size, s.gop_len),
            (0, 0, 0, None)
        );
    }
}
