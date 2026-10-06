use crate::flv::reader::Cur;

pub(crate) const HEADER_LEN: usize = 9;
pub(crate) const TAG_HEADER_LEN: usize = 11;
pub(crate) const PREV_TAG_SIZE_LEN: usize = 4;

/// Per-stream framing limits. `max_tag_size` is §6.2's 4 MiB tag cap; the
/// remaining size-limit hardening is Plan B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlvLimits {
    pub max_tag_size: u32,
}
impl Default for FlvLimits {
    fn default() -> Self {
        Self {
            max_tag_size: 4_194_304,
        }
    }
}

/// A framing violation (§6.9, `parse_errors{kind}`). The M0 subset surfaces
/// only the kinds reachable from demux; §6.1 admission kinds are Plan B.
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
