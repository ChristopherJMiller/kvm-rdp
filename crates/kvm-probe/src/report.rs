//! Census summary (§12 Leg A): roll a capture's `TagRecord`s into IDR/P
//! counts, the codec/FourCC set, the size range, GOP length, and how many
//! tags hold more than one picture start (tag ≠ access unit).
//!
//! I6/M6: `idr`, `p_slices`, `gop_len`, `min_size` and `max_size` are all
//! counted over *coded AVC video pictures only* — a video tag
//! (`tag_type == 9`) carrying an actual AVC NALU packet
//! (`codec_id == Some(7) && avc_packet_type == Some(1)`), never a
//! sequence-header/end-of-sequence tag, an audio or script tag, or an
//! Enhanced-RTMP/HEVC tag (which never sets `codec_id == Some(7)`).
//! Interleaved audio no longer inflates `gop_len`, and an HEVC
//! keyframe-flagged tag can never register as an AVC IDR. `idr` is "this
//! picture's NALs include type 5"; `p_slices` is "this picture has a VCL
//! NAL (1–5) but no type 5". `bad_header_nals` counts the framing-violation
//! sentinel (`u8::MAX`, §12 I2/record.rs) across *all* tags, not just
//! picture tags — the census must surface it wherever it occurs.

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
    /// Tags holding more than one `first_mb_in_slice == 0` (more than one picture): tag ≠ AU.
    pub multi_picture_tags: usize,
    /// Sentinel (`u8::MAX`) NAL-header entries across all tags: framing
    /// violations the census must surface (§12 I2), additive beyond the
    /// plan's original `TagSummary` (B13 review I6/M6).
    pub bad_header_nals: usize,
}

/// A video tag carrying an actual coded AVC picture (NALU packet type 1) —
/// never a sequence header/EOS tag, an audio/script tag, or an
/// Enhanced-RTMP/HEVC tag (which leaves `codec_id` `None`).
fn is_coded_avc_picture(r: &TagRecord) -> bool {
    r.tag_type == 9 && r.codec_id == Some(7) && r.avc_packet_type == Some(1)
}

pub fn summarize(records: &[TagRecord]) -> TagSummary {
    let mut s = TagSummary {
        min_size: usize::MAX,
        ..TagSummary::default()
    };
    // Position among coded-picture tags only (not `records`' own index),
    // so an interleaved audio/script/sequence-header tag can never stretch
    // `gop_len` (I6).
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
        if r.first_mb.iter().filter(|m| **m == Some(0)).count() > 1 {
            s.multi_picture_tags = s.multi_picture_tags.saturating_add(1);
        }

        if !is_coded_avc_picture(r) {
            continue;
        }
        s.min_size = s.min_size.min(r.size);
        s.max_size = s.max_size.max(r.size);
        let has_idr = r.nal_types.contains(&5);
        let has_vcl = r.nal_types.iter().any(|&t| (1..=5).contains(&t));
        if has_idr {
            s.idr = s.idr.saturating_add(1);
            idr_positions.push(picture_index);
        } else if has_vcl {
            s.p_slices = s.p_slices.saturating_add(1);
        }
        picture_index = picture_index.saturating_add(1);
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
        let recs = vec![picture(vec![1], vec![Some(0), Some(0)], 900)];
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
        let recs = vec![picture(vec![255, 5], vec![Some(0)], 1000), audio_tag()];
        let s = summarize(&recs);
        assert_eq!(s.bad_header_nals, 1);
        assert_eq!(s.idr, 1);
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
