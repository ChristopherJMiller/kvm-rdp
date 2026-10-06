use serde::Serialize;

/// One census JSONL line (§12 Leg A). Field order below is the emitted order.
#[derive(Serialize, Clone, Debug)]
pub struct TagRecord {
    pub recv_ms: u64,
    pub tag_type: u8,
    pub timestamp_ms: u32,
    pub composition_time: i32,
    pub frame_type: Option<u8>,
    pub codec_id: Option<u8>,
    pub avc_packet_type: Option<u8>,
    pub fourcc: Option<String>,
    pub nal_types: Vec<u8>,
    pub nal_ref_idc: Vec<u8>,
    pub slice_types: Vec<Option<u8>>,
    pub first_mb: Vec<Option<u32>>,
    pub size: usize,
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
        };
        assert_eq!(
            r.to_jsonl().unwrap(),
            r#"{"recv_ms":1234,"tag_type":9,"timestamp_ms":40,"composition_time":0,"frame_type":1,"codec_id":7,"avc_packet_type":1,"fourcc":null,"nal_types":[7,8,5],"nal_ref_idc":[3,3,3],"slice_types":[null,null,7],"first_mb":[null,null,0],"size":4096}"#
        );
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
        };
        let line = r.to_jsonl().unwrap();
        assert!(line.contains(r#""frame_type":null"#));
        assert!(!line.contains('\n'));
    }
}
