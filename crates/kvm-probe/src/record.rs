use serde::Serialize;

/// At most this many SPS/PPS NALs are hexed into one tag's
/// `param_sets_hex` (final review I3); the rest are counted in
/// `param_sets_skipped`. Generous: §6.2 admits 4 SPS + 16 PPS per config.
pub(crate) const MAX_PARAM_SETS_PER_TAG: usize = 32;

/// A parameter-set NAL longer than this (header byte included) is not
/// hexed but counted in `param_sets_skipped` — §6.2's 1 KiB per SPS/PPS.
pub(crate) const MAX_PARAM_SET_BYTES: usize = 1024;

/// One census JSONL line (§12 Leg A). Field order below is the emitted order.
/// `Deserialize` lets `summarize` (`report.rs`) read a capture's `.jsonl`
/// back in.
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct TagRecord {
    pub recv_ms: u64,
    pub tag_type: u8,
    pub timestamp_ms: u32,
    pub composition_time: i32,
    pub frame_type: Option<u8>,
    pub codec_id: Option<u8>,
    pub avc_packet_type: Option<u8>,
    pub fourcc: Option<String>,
    /// One entry per NAL seen in this tag. A NAL whose header failed to
    /// parse (empty, or the forbidden bit set — a framing violation from a
    /// hostile device) is recorded as the sentinel `255` (`u8::MAX`, not a
    /// valid 5-bit `nal_unit_type`) rather than dropped, so the anomaly
    /// stays visible instead of looking like an empty access unit (I2).
    pub nal_types: Vec<u8>,
    /// Parallel to `nal_types`; `255` for the same sentinel case.
    pub nal_ref_idc: Vec<u8>,
    /// Parallel to `nal_types`; `None` for a non-slice NAL or a sentinel entry.
    pub slice_types: Vec<Option<u8>>,
    /// Parallel to `nal_types`; `None` for a non-slice NAL or a sentinel entry.
    pub first_mb: Vec<Option<u32>>,
    pub size: usize,
    /// Lowercase hex of each SPS (type 7) and PPS (type 8) NAL in this tag,
    /// in order: the AVCDecoderConfigurationRecord's on a sequence-header
    /// tag, in-band ones on a NALU tag. Header byte included and
    /// emulation-prevention bytes kept — exactly what
    /// `kvm_proto::h264::parse_sps` takes. **Parameter sets only**: a NAL is
    /// hexed only when its own header says type 7 or 8, never slice or any
    /// other NAL data (that is screen content). At most
    /// `MAX_PARAM_SETS_PER_TAG` per tag, each at most `MAX_PARAM_SET_BYTES`
    /// long. Additive (final review I3); `serde(default)` so a JSONL written
    /// before this field existed still summarizes.
    #[serde(default)]
    pub param_sets_hex: Vec<String>,
    /// SPS/PPS NALs in this tag that were *not* hexed because they were
    /// past either bound above. Additive (final review I3).
    #[serde(default)]
    pub param_sets_skipped: usize,
}

impl TagRecord {
    /// Serialize to a single JSON line (no trailing newline; the writer adds it).
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_idr_tag_serialises_exactly() {
        let r = TagRecord {
            recv_ms: 1234,
            tag_type: 9,
            timestamp_ms: 40,
            composition_time: 0,
            frame_type: Some(1),
            codec_id: Some(7),
            avc_packet_type: Some(1),
            fourcc: None,
            nal_types: vec![7, 8, 5],
            nal_ref_idc: vec![3, 3, 3],
            slice_types: vec![None, None, Some(7)],
            first_mb: vec![None, None, Some(0)],
            size: 4096,
            param_sets_hex: vec!["674d001f".to_string(), "68ce3c80".to_string()],
            param_sets_skipped: 0,
        };
        assert_eq!(
            r.to_jsonl().unwrap(),
            r#"{"recv_ms":1234,"tag_type":9,"timestamp_ms":40,"composition_time":0,"frame_type":1,"codec_id":7,"avc_packet_type":1,"fourcc":null,"nal_types":[7,8,5],"nal_ref_idc":[3,3,3],"slice_types":[null,null,7],"first_mb":[null,null,0],"size":4096,"param_sets_hex":["674d001f","68ce3c80"],"param_sets_skipped":0}"#
        );
    }

    /// I3: the parameter-set fields are additive — a line written before
    /// they existed still reads back, with them empty.
    #[test]
    fn a_line_without_the_param_set_fields_still_reads_back() {
        let line = r#"{"recv_ms":1,"tag_type":9,"timestamp_ms":0,"composition_time":0,"frame_type":1,"codec_id":7,"avc_packet_type":1,"fourcc":null,"nal_types":[5],"nal_ref_idc":[3],"slice_types":[7],"first_mb":[0],"size":10}"#;
        let r: TagRecord = serde_json::from_str(line).unwrap();
        assert!(r.param_sets_hex.is_empty());
        assert_eq!(r.param_sets_skipped, 0);
    }

    #[test]
    fn non_video_tag_has_null_video_fields() {
        let r = TagRecord {
            recv_ms: 5,
            tag_type: 18,
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
            size: 11,
            param_sets_hex: vec![],
            param_sets_skipped: 0,
        };
        let line = r.to_jsonl().unwrap();
        assert!(line.contains(r#""frame_type":null"#));
        assert!(!line.contains('\n'));
    }
}
