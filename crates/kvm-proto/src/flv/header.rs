use crate::flv::reader::Cur;

pub(crate) const HEADER_LEN: usize = 9;
pub(crate) const TAG_HEADER_LEN: usize = 11;
pub(crate) const PREV_TAG_SIZE_LEN: usize = 4;

/// Per-stream framing limits (§6.2). Every one is checked before the data it
/// bounds is buffered or collected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlvLimits {
    /// `DataSize` cap: 4 MiB.
    pub max_tag_size: u32,
    /// NALs in one NALU tag (one access unit): 128.
    pub max_nals_per_tag: usize,
    /// SPSs in one `AVCDecoderConfigurationRecord`: 1..=4.
    pub max_sps: usize,
    /// PPSs in one `AVCDecoderConfigurationRecord`: 1..=16.
    pub max_pps: usize,
    /// Bytes in one SPS or PPS: 1 KiB.
    pub max_param_set_len: usize,
}
impl Default for FlvLimits {
    fn default() -> Self {
        Self {
            max_tag_size: 4_194_304,
            max_nals_per_tag: 128,
            max_sps: 4,
            max_pps: 16,
            max_param_set_len: 1024,
        }
    }
}

/// A framing violation found by the demuxer (§6.9: transient, an FLV
/// reconnect; `parse_errors{kind}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlvError {
    BadHeader,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    OversizeTag,
    BadConfigRecord,
    BadLengthSize,
    NalBeforeSequenceHeader,
    MalformedVideoTag,
    /// More than `FlvLimits::max_nals_per_tag` NALs in one tag.
    TooManyNals,
    /// A config record with 0 or more than `max_sps` SPSs, or 0 or more than
    /// `max_pps` PPSs.
    ParamSetCount,
    /// An SPS or PPS longer than `max_param_set_len`, or empty.
    ParamSetSize,
}

impl FlvError {
    /// The `parse_errors{kind}` label.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            FlvError::BadHeader => "bad_header",
            FlvError::BadPrevTagSize => "bad_prev_tag_size",
            FlvError::EncryptedTag => "encrypted_tag",
            FlvError::BadStreamId => "bad_stream_id",
            FlvError::OversizeTag => "oversize_tag",
            FlvError::BadConfigRecord => "bad_config_record",
            FlvError::BadLengthSize => "bad_length_size",
            FlvError::NalBeforeSequenceHeader => "nal_before_sequence_header",
            FlvError::MalformedVideoTag => "malformed_video_tag",
            FlvError::TooManyNals => "too_many_nals",
            FlvError::ParamSetCount => "param_set_count",
            FlvError::ParamSetSize => "param_set_size",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlvHeader {
    pub version: u8,
    pub has_audio: bool,
    pub has_video: bool,
    pub data_offset: u32,
}

/// Parse the 9-byte FLV header; `DataOffset` must be 9 (≤ 64 tolerated).
pub(crate) fn parse_flv_header(buf: &[u8]) -> Result<FlvHeader, FlvError> {
    let mut c = Cur::new(buf);
    if c.take(3).ok_or(FlvError::BadHeader)? != b"FLV" {
        return Err(FlvError::BadHeader);
    }
    let version = c.u8().ok_or(FlvError::BadHeader)?;
    let flags = c.u8().ok_or(FlvError::BadHeader)?;
    let data_offset = c.u32().ok_or(FlvError::BadHeader)?;
    if version != 1 || !(9..=64).contains(&data_offset) {
        return Err(FlvError::BadHeader);
    }
    Ok(FlvHeader {
        version,
        has_audio: flags & 0x04 != 0,
        has_video: flags & 0x01 != 0,
        data_offset,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TagHeader {
    pub(crate) tag_type: u8,
    pub(crate) data_size: u32,
    pub(crate) timestamp: u32,
    pub(crate) stream_id: u32,
}

/// Parse an 11-byte tag header. `data_size` is checked against the limit
/// here, before the body is buffered (§6.2).
pub(crate) fn parse_tag_header(buf: &[u8], limits: FlvLimits) -> Result<TagHeader, FlvError> {
    let mut c = Cur::new(buf);
    let type_byte = c.u8().ok_or(FlvError::BadHeader)?;
    let data_size = c.u24().ok_or(FlvError::BadHeader)?;
    let ts_low = c.u24().ok_or(FlvError::BadHeader)?;
    let ts_ext = c.u8().ok_or(FlvError::BadHeader)?;
    let stream_id = c.u24().ok_or(FlvError::BadHeader)?;
    if type_byte & 0x20 != 0 {
        return Err(FlvError::EncryptedTag);
    }
    if stream_id != 0 {
        return Err(FlvError::BadStreamId);
    }
    if data_size > limits.max_tag_size {
        return Err(FlvError::OversizeTag);
    }
    let timestamp = u32::from(ts_ext).wrapping_shl(24) | ts_low;
    Ok(TagHeader {
        tag_type: type_byte & 0x1F,
        data_size,
        timestamp,
        stream_id,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;

    #[test]
    fn parses_video_only_header() {
        let hdr = [b'F', b'L', b'V', 0x01, 0x01, 0x00, 0x00, 0x00, 0x09];
        let h = parse_flv_header(&hdr).unwrap();
        assert_eq!(h.version, 1);
        assert!(h.has_video && !h.has_audio);
        assert_eq!(h.data_offset, 9);
    }

    #[test]
    fn rejects_bad_signature_and_offset() {
        assert_eq!(
            parse_flv_header(&[b'X', b'L', b'V', 1, 1, 0, 0, 0, 9]),
            Err(FlvError::BadHeader)
        );
        assert_eq!(
            parse_flv_header(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 65]),
            Err(FlvError::BadHeader)
        );
    }

    #[test]
    fn parses_tag_header_and_timestamp() {
        let th = [
            0x09, 0x00, 0x00, 0x19, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00,
        ];
        let t = parse_tag_header(&th, FlvLimits::default()).unwrap();
        assert_eq!(t.tag_type, 9);
        assert_eq!(t.data_size, 25);
        assert_eq!(t.timestamp, 0x21);
        assert_eq!(t.stream_id, 0);
    }

    #[test]
    fn every_error_kind_is_a_distinct_snake_case_label() {
        let all = [
            FlvError::BadHeader,
            FlvError::BadPrevTagSize,
            FlvError::EncryptedTag,
            FlvError::BadStreamId,
            FlvError::OversizeTag,
            FlvError::BadConfigRecord,
            FlvError::BadLengthSize,
            FlvError::NalBeforeSequenceHeader,
            FlvError::MalformedVideoTag,
            FlvError::TooManyNals,
            FlvError::ParamSetCount,
            FlvError::ParamSetSize,
        ];
        let mut kinds: Vec<&str> = all.iter().map(|e| e.kind()).collect();
        assert!(
            kinds
                .iter()
                .all(|k| k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        );
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), all.len());
    }

    #[test]
    fn rejects_encrypted_streamid_and_oversize() {
        let enc = [0x29, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_tag_header(&enc, FlvLimits::default()),
            Err(FlvError::EncryptedTag)
        );
        let sid = [0x09, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            parse_tag_header(&sid, FlvLimits::default()),
            Err(FlvError::BadStreamId)
        );
        let big = [0x09, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_tag_header(&big, FlvLimits::default()),
            Err(FlvError::OversizeTag)
        );
    }
}
