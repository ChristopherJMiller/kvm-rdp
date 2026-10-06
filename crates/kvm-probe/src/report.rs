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

use crate::record::{MAX_PARAM_SET_BYTES, TagRecord};
use kvm_proto::h264::{
    NalHeader, SpsChange, SpsLimitViolation, SpsLimits, SpsParseError, SpsSummary,
    check_sps_limits, classify_sps_change, parse_sps,
};

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
    /// Each distinct SPS in the capture (by bytes, first-seen order, at most
    /// `MAX_DISTINCT_PARAM_SETS`), run through kvm-proto's own parser and
    /// §6.1 checks. Additive (final review I3).
    pub sps: Vec<SpsReport>,
    /// Each distinct PPS's hex (first-seen order, at most
    /// `MAX_DISTINCT_PARAM_SETS`). kvm-proto has no PPS parser until Plan B,
    /// so these are reported, not decoded. Additive (final review I3).
    pub pps_hex: Vec<String>,
    /// Sum of every record's `param_sets_skipped`: SPS/PPS NALs the capture
    /// did not hex because they were past its per-tag or per-NAL bound — a
    /// fact about the device. Additive (final review I3).
    pub param_sets_skipped: usize,
    /// `param_sets_hex` entries this summary could not report: not
    /// lowercase hex of at most `MAX_PARAM_SET_BYTES`, not an SPS/PPS NAL
    /// (neither can come from `record_for`, so either means the JSONL was
    /// edited or tampered with), or a new distinct SPS/PPS past
    /// `MAX_DISTINCT_PARAM_SETS`. Additive (final review I3).
    pub param_sets_unreported: usize,
}

/// One distinct SPS seen in a capture (final review I3): kvm-proto's
/// `parse_sps` → `SpsSummary`, its §6.1 `check_sps_limits` verdict, and
/// `classify_sps_change` against the capture's first SPS that parsed (for
/// that first SPS itself: against none, so `Initial` when within limits).
/// `limits`/`change_vs_first` are `None` when the SPS did not parse.
#[derive(Debug)]
pub struct SpsReport {
    /// 1-based JSONL line on which this SPS was first seen.
    pub first_line: usize,
    /// First seen in-band (an AVC NALU tag), not in a sequence header.
    pub in_band: bool,
    /// Lowercase hex of the SPS NAL, header byte included.
    pub hex: String,
    pub summary: Result<SpsSummary, SpsParseError>,
    pub limits: Option<Result<(), SpsLimitViolation>>,
    pub change_vs_first: Option<SpsChange>,
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

/// At most this many distinct SPS, and separately PPS, are listed in a
/// summary (final review I3): far more than any real encoder uses, but a
/// hostile stream sending a new SPS every tag cannot turn `summarize`
/// into megabytes of output.
const MAX_DISTINCT_PARAM_SETS: usize = 32;

/// One hex digit as `record_for` writes it (lowercase only).
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Decode a `param_sets_hex` entry back into NAL bytes, accepting exactly
/// what `record_for` writes: non-empty lowercase hex of at most
/// `MAX_PARAM_SET_BYTES` bytes. The JSONL sits in a directory the ffmpeg
/// sandbox can write (final review m3, deferred), so anything else is
/// refused here rather than trusted.
fn decode_param_set_hex(hex: &str) -> Option<Vec<u8>> {
    let digits = hex.as_bytes();
    let max_digits = MAX_PARAM_SET_BYTES.checked_mul(2)?;
    if digits.is_empty() || digits.len() > max_digits || digits.len() & 1 == 1 {
        return None;
    }
    let mut out = Vec::new();
    for pair in digits.chunks_exact(2) {
        let hi = hex_nibble(*pair.first()?)?;
        let lo = hex_nibble(*pair.get(1)?)?;
        out.push(hi.wrapping_shl(4) | lo);
    }
    Some(out)
}

/// Fold one `param_sets_hex` entry into the summary (final review I3): a
/// new distinct SPS is parsed by kvm-proto, checked against the §6.1
/// limits and classified against the first SPS that parsed; a new distinct
/// PPS is listed. Repeats are skipped; anything undecodable, not an
/// SPS/PPS, or past `MAX_DISTINCT_PARAM_SETS` is counted in
/// `param_sets_unreported`.
fn add_param_set(
    s: &mut TagSummary,
    first_sps: &mut Option<SpsSummary>,
    hex: &str,
    line: usize,
    in_band: bool,
) {
    let decoded = decode_param_set_hex(hex)
        .and_then(|bytes| Some((NalHeader::from_nal(&bytes).ok()?.nal_unit_type, bytes)));
    match decoded {
        Some((7, bytes)) => {
            if s.sps.iter().any(|r| r.hex.as_str() == hex) {
                return;
            }
            if s.sps.len() >= MAX_DISTINCT_PARAM_SETS {
                s.param_sets_unreported = s.param_sets_unreported.saturating_add(1);
                return;
            }
            let limits = SpsLimits::default();
            let summary = parse_sps(&bytes);
            let (verdict, change) = match &summary {
                Ok(sum) => {
                    let change = classify_sps_change(first_sps.as_ref(), sum, &limits);
                    if first_sps.is_none() {
                        *first_sps = Some(sum.clone());
                    }
                    (Some(check_sps_limits(sum, &limits)), Some(change))
                }
                Err(_) => (None, None),
            };
            s.sps.push(SpsReport {
                first_line: line,
                in_band,
                hex: hex.to_string(),
                summary,
                limits: verdict,
                change_vs_first: change,
            });
        }
        Some((8, _)) => {
            if s.pps_hex.iter().any(|h| h.as_str() == hex) {
                return;
            }
            if s.pps_hex.len() >= MAX_DISTINCT_PARAM_SETS {
                s.param_sets_unreported = s.param_sets_unreported.saturating_add(1);
                return;
            }
            s.pps_hex.push(hex.to_string());
        }
        _ => s.param_sets_unreported = s.param_sets_unreported.saturating_add(1),
    }
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
    // The baseline `classify_sps_change` compares every later SPS against.
    let mut first_sps: Option<SpsSummary> = None;
    for (i, r) in records.iter().enumerate() {
        s.total = s.total.saturating_add(1);
        // Parameter sets ride on sequence-header tags and (in-band) on
        // NALU tags, so they are folded in before the picture-only filter.
        let line = i.saturating_add(1);
        let in_band = r.avc_packet_type == Some(1);
        for hex in &r.param_sets_hex {
            add_param_set(&mut s, &mut first_sps, hex, line, in_band);
        }
        s.param_sets_skipped = s.param_sets_skipped.saturating_add(r.param_sets_skipped);
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
    use kvm_proto::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
    use kvm_proto::h264::{PinnedField, SpsIncompatibleReason};

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
            param_sets_hex: vec![],
            param_sets_skipped: 0,
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
            param_sets_hex: vec![],
            param_sets_skipped: 0,
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

    /// The committed fixture FLV's sequence-header tag, through kvm-proto's
    /// real demuxer and `capture::record_for` — the same path a KVM's
    /// sequence header takes — so its `param_sets_hex` is x264's real SPS
    /// and PPS.
    fn fixture_sequence_header() -> TagRecord {
        let flv = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/360p30_main_full.flv"
        ))
        .unwrap();
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        demux.push(&flv);
        while let Some(tag) = demux.next_tag().unwrap() {
            if matches!(tag.body, TagBody::Video(VideoBody::SequenceHeader(_))) {
                return crate::capture::record_for(&tag, 0);
            }
        }
        panic!("the fixture FLV has no AVC sequence header");
    }

    /// ffmpeg's `trace_headers` view of that fixture (its committed manifest).
    fn fixture_manifest_u64(key: &str) -> u64 {
        let m: serde_json::Value = serde_json::from_slice(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/360p30_main_full.flv.manifest.json"
            ))
            .unwrap(),
        )
        .unwrap();
        m.get(key).and_then(serde_json::Value::as_u64).unwrap()
    }

    /// I3 (final review): the fixture's real SPS runs through kvm-proto's
    /// `parse_sps`, `check_sps_limits` and `classify_sps_change`, and the
    /// summary agrees with ffmpeg's independent view of it (the manifest).
    #[test]
    fn real_fixture_sps_is_parsed_checked_and_classified() {
        let seq = fixture_sequence_header();
        let s = summarize(std::slice::from_ref(&seq));
        let [rep] = s.sps.as_slice() else {
            panic!("expected exactly one SPS report: {:?}", s.sps);
        };
        assert_eq!((rep.first_line, rep.in_band), (1, false));
        assert_eq!(Some(&rep.hex), seq.param_sets_hex.first());
        assert!(rep.hex.starts_with("67"), "{}", rep.hex);
        let sum = rep.summary.as_ref().unwrap();
        assert_eq!(u64::from(sum.width), fixture_manifest_u64("width"));
        assert_eq!(u64::from(sum.height), fixture_manifest_u64("height"));
        assert_eq!(
            u64::from(sum.profile_idc),
            fixture_manifest_u64("profile_idc")
        );
        assert_eq!(u64::from(sum.level_idc), fixture_manifest_u64("level_idc"));
        assert_eq!(
            u64::from(sum.pic_order_cnt_type),
            fixture_manifest_u64("pic_order_cnt_type")
        );
        assert_eq!(
            sum.video_full_range_flag,
            Some(fixture_manifest_u64("video_full_range_flag") == 1)
        );
        assert_eq!(
            sum.colour_primaries.map(u64::from),
            Some(fixture_manifest_u64("colour_primaries"))
        );
        assert_eq!(
            sum.matrix_coefficients.map(u64::from),
            Some(fixture_manifest_u64("matrix_coefficients"))
        );
        assert_eq!(
            sum.max_num_reorder_frames.is_some(),
            fixture_manifest_u64("bitstream_restriction_flag") == 1
        );
        assert_eq!(rep.limits, Some(Ok(())));
        assert_eq!(rep.change_vs_first, Some(SpsChange::Initial));
        let [pps] = s.pps_hex.as_slice() else {
            panic!("expected exactly one PPS: {:?}", s.pps_hex);
        };
        assert!(pps.starts_with("68"), "{pps}");
        assert_eq!((s.param_sets_skipped, s.param_sets_unreported), (0, 0));
    }

    /// A 1920x1080 Main SPS (x264's own, from fixtures/slate_1080p.h264),
    /// standing in for what a KVM sends in-band on a resolution change.
    const SPS_1080P_MAIN: &str = "674d4028dc0780227e5c05b808080a000003000200000300781e3067";
    /// Its PPS.
    const PPS_1080P_MAIN: &str = "68ee0fc8";
    /// A 640x360 Baseline SPS (fixtures/360p30_baseline_full.h264):
    /// profile_idc 66, a pinned-field change against a Main first SPS.
    const SPS_360P_BASELINE: &str = "6742c01fda0280bfe5c05b808080a0000003002000000791e30654";

    /// An AVC NALU picture tag carrying in-band parameter-set hex.
    fn in_band(hexes: &[&str], skipped: usize) -> TagRecord {
        let mut r = picture(vec![9, 7, 8, 5], vec![None, None, None, Some(0)], 3000);
        r.param_sets_hex = hexes.iter().map(|h| (*h).to_string()).collect();
        r.param_sets_skipped = skipped;
        r
    }

    /// I3: synthetic in-band SPS after the real first one. A repeat of the
    /// first is not re-reported; a new resolution is `Resize`; a profile
    /// change is a pinned-field `Incompatible`; a truncated SPS is reported
    /// with its parse error and no verdicts. Every distinct PPS is listed,
    /// and capture-time skips are summed.
    #[test]
    fn in_band_sps_are_classified_against_the_first_sps() {
        let seq = fixture_sequence_header();
        let first_sps = seq.param_sets_hex.first().unwrap().clone();
        let recs = vec![
            seq,
            in_band(&[&first_sps], 0),
            in_band(&[SPS_1080P_MAIN, PPS_1080P_MAIN], 2),
            in_band(&[SPS_360P_BASELINE], 0),
            in_band(&["6700"], 0),
        ];
        let s = summarize(&recs);
        let [first, resize, profile, broken] = s.sps.as_slice() else {
            panic!("expected four distinct SPS reports: {:?}", s.sps);
        };
        assert_eq!(
            (first.first_line, first.in_band, &first.change_vs_first),
            (1, false, &Some(SpsChange::Initial))
        );

        assert_eq!((resize.first_line, resize.in_band), (3, true));
        assert_eq!(resize.hex, SPS_1080P_MAIN);
        let r = resize.summary.as_ref().unwrap();
        assert_eq!((r.width, r.height, r.profile_idc), (1920, 1080, 77));
        assert_eq!(resize.limits, Some(Ok(())));
        assert_eq!(resize.change_vs_first, Some(SpsChange::Resize));

        assert_eq!(profile.first_line, 4);
        assert_eq!(
            profile.change_vs_first,
            Some(SpsChange::Incompatible(
                SpsIncompatibleReason::PinnedFieldChanged(PinnedField::ProfileIdc)
            ))
        );

        assert_eq!(broken.hex, "6700");
        assert!(broken.summary.is_err(), "{:?}", broken.summary);
        assert!(broken.limits.is_none() && broken.change_vs_first.is_none());

        assert_eq!(s.pps_hex.len(), 2);
        assert_eq!(s.pps_hex.last().map(String::as_str), Some(PPS_1080P_MAIN));
        assert_eq!((s.param_sets_skipped, s.param_sets_unreported), (2, 0));
    }

    /// I3: an entry `record_for` could never have written — not lowercase
    /// hex, odd length, empty, over 1 KiB, not an SPS/PPS NAL (a slice, an
    /// AUD), or raw terminal escapes — is counted, never parsed or listed.
    /// (The JSONL lives in a directory the ffmpeg sandbox can write.)
    #[test]
    fn entries_that_are_not_bounded_sps_pps_hex_are_counted_not_reported() {
        let too_long = "67".repeat(1025);
        let recs = vec![in_band(
            &[
                "zz",
                "674D401F",
                "678",
                "",
                "658880",
                "0910",
                &too_long,
                "\u{1b}]0;x\u{7}",
            ],
            0,
        )];
        let s = summarize(&recs);
        assert!(s.sps.is_empty(), "{:?}", s.sps);
        assert!(s.pps_hex.is_empty(), "{:?}", s.pps_hex);
        assert_eq!(s.param_sets_unreported, 8);
    }

    /// I3: at most 32 distinct PPS (and SPS) are listed; a new one past
    /// that is counted, while a repeat of a listed one is not.
    #[test]
    fn distinct_param_sets_past_the_cap_are_counted_not_listed() {
        let hexes: Vec<String> = (0u8..33).map(|i| format!("68{i:02x}")).collect();
        let refs: Vec<&str> = hexes.iter().map(String::as_str).collect();
        let s = summarize(&[in_band(&refs, 0), in_band(&["6800"], 0)]);
        assert_eq!(s.pps_hex.len(), 32);
        assert_eq!(s.param_sets_unreported, 1);
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
