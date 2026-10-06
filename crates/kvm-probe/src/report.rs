//! Census summary (§12 Leg A): roll a capture's `TagRecord`s into IDR/P
//! counts, the codec/FourCC set, the size range, GOP length, and how many
//! tags hold more than one picture start (tag ≠ access unit).

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
}

pub fn summarize(records: &[TagRecord]) -> TagSummary {
    let mut s = TagSummary {
        min_size: usize::MAX,
        ..TagSummary::default()
    };
    let mut idr_positions: Vec<usize> = Vec::new();
    for (i, r) in records.iter().enumerate() {
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
        s.min_size = s.min_size.min(r.size);
        s.max_size = s.max_size.max(r.size);
        match r.frame_type {
            Some(1) => {
                s.idr = s.idr.saturating_add(1);
                idr_positions.push(i);
            }
            Some(2) => {
                s.p_slices = s.p_slices.saturating_add(1);
            }
            _ => {}
        }
        if r.first_mb.iter().filter(|m| **m == Some(0)).count() > 1 {
            s.multi_picture_tags = s.multi_picture_tags.saturating_add(1);
        }
    }
    if s.total == 0 {
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

    fn vid(
        frame_type: u8,
        slice: Option<u8>,
        first_mb: Vec<Option<u32>>,
        size: usize,
    ) -> TagRecord {
        TagRecord {
            recv_ms: 0,
            tag_type: 9,
            timestamp_ms: 0,
            composition_time: 0,
            frame_type: Some(frame_type),
            codec_id: Some(7),
            avc_packet_type: Some(1),
            fourcc: None,
            nal_types: vec![],
            nal_ref_idc: vec![],
            slice_types: vec![slice],
            first_mb,
            size,
        }
    }

    #[test]
    fn summary_counts_idrs_codecs_gop_and_multi_picture_tags() {
        // IDR, P, P, P, IDR -> 5 tags, 2 IDRs, GOP 4; one P tag holds two picture starts.
        let recs = vec![
            vid(1, Some(7), vec![Some(0)], 5000),
            vid(2, Some(5), vec![Some(0)], 900),
            vid(2, Some(5), vec![Some(0), Some(0)], 850),
            vid(2, Some(5), vec![Some(0)], 870),
            vid(1, Some(7), vec![Some(0)], 4800),
        ];
        let s = summarize(&recs);
        assert_eq!(s.total, 5);
        assert_eq!(s.idr, 2);
        assert_eq!(s.p_slices, 3);
        assert_eq!(s.codecs, vec![7]);
        assert_eq!((s.min_size, s.max_size), (850, 5000));
        assert_eq!(s.gop_len, Some(4));
        assert_eq!(s.multi_picture_tags, 1);
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
