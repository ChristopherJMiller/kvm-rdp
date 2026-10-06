use crate::flv::header::{
    FlvError, FlvLimits, HEADER_LEN, PREV_TAG_SIZE_LEN, TAG_HEADER_LEN, parse_flv_header,
    parse_tag_header,
};
use crate::flv::reader::Cur;
use bytes::{Bytes, BytesMut};

/// A framed FLV tag with its body as a zero-copy `Bytes` slice of the
/// reassembly buffer (§6.2 ownership note).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawTag {
    pub(crate) tag_type: u8,
    pub(crate) data_size: u32,
    pub(crate) timestamp: u32,
    pub(crate) body: Bytes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    FirstPrev,
    Tag,
}

/// Incremental FLV demuxer over an internal `BytesMut`.
pub struct FlvDemuxer {
    buf: BytesMut,
    state: State,
    limits: FlvLimits,
    pub(crate) length_size: Option<u8>,
}

impl FlvDemuxer {
    pub fn new(limits: FlvLimits) -> Self {
        Self {
            buf: BytesMut::new(),
            state: State::Start,
            limits,
            length_size: None,
        }
    }

    /// Append received bytes. One copy into the reassembly buffer; NAL/SPS
    /// slices taken from a tag body are shared without further copying.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub(crate) fn next_raw_tag(&mut self) -> Result<Option<RawTag>, FlvError> {
        loop {
            match self.state {
                State::Start => {
                    let Some(head) = self.buf.as_ref().get(..HEADER_LEN) else {
                        return Ok(None);
                    };
                    let hdr = parse_flv_header(head)?;
                    let skip = usize::try_from(hdr.data_offset).unwrap_or(HEADER_LEN);
                    if self.buf.len() < skip {
                        return Ok(None);
                    }
                    let _ = self.buf.split_to(skip);
                    self.state = State::FirstPrev;
                }
                State::FirstPrev => {
                    let Some(pv) = self.buf.as_ref().get(..PREV_TAG_SIZE_LEN) else {
                        return Ok(None);
                    };
                    if Cur::new(pv).u32().ok_or(FlvError::BadPrevTagSize)? != 0 {
                        return Err(FlvError::BadPrevTagSize);
                    }
                    let _ = self.buf.split_to(PREV_TAG_SIZE_LEN);
                    self.state = State::Tag;
                }
                State::Tag => {
                    let Some(head) = self.buf.as_ref().get(..TAG_HEADER_LEN) else {
                        return Ok(None);
                    };
                    // data_size validated here, before buffering the body.
                    let th = parse_tag_header(head, self.limits)?;
                    let body_len = usize::try_from(th.data_size).unwrap_or(usize::MAX);
                    let total = TAG_HEADER_LEN
                        .checked_add(body_len)
                        .and_then(|n| n.checked_add(PREV_TAG_SIZE_LEN))
                        .ok_or(FlvError::OversizeTag)?;
                    if self.buf.len() < total {
                        return Ok(None);
                    }
                    let _ = self.buf.split_to(TAG_HEADER_LEN);
                    let body = self.buf.split_to(body_len).freeze();
                    let trailer = self.buf.split_to(PREV_TAG_SIZE_LEN);
                    let prev = Cur::new(trailer.as_ref())
                        .u32()
                        .ok_or(FlvError::BadPrevTagSize)?;
                    let expected =
                        u32::try_from(total.saturating_sub(PREV_TAG_SIZE_LEN)).unwrap_or(u32::MAX);
                    if prev != expected {
                        return Err(FlvError::BadPrevTagSize);
                    }
                    return Ok(Some(RawTag {
                        tag_type: th.tag_type,
                        data_size: th.data_size,
                        timestamp: th.timestamp,
                        body,
                    }));
                }
            }
        }
    }
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
    use crate::flv::header::FlvLimits;

    /// Hand-built FLV: header + a video sequence-header tag + a video NALU
    /// (IDR) tag. No real capture is used.
    fn build_flv() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[b'F', b'L', b'V', 0x01, 0x01, 0x00, 0x00, 0x00, 0x09]);
        v.extend_from_slice(&[0, 0, 0, 0]); // PrevTagSize0
        // Tag1: type 9, data_size 25, ts 0
        v.extend_from_slice(&[0x09, 0x00, 0x00, 0x19, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x17, 0x00, 0x00, 0x00, 0x00]); // key/AVC, seq header, CT 0
        v.extend_from_slice(&[
            0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05, 0x67, 0x42, 0x00, 0x1E, 0x88, 0x01,
            0x00, 0x04, 0x68, 0xCE, 0x3C, 0x80,
        ]); // AVCDecoderConfigurationRecord
        v.extend_from_slice(&[0, 0, 0, 36]); // PrevTagSize1 = 11 + 25
        // Tag2: type 9, data_size 13, ts 0x21
        v.extend_from_slice(&[0x09, 0x00, 0x00, 0x0D, 0, 0, 0x21, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x17, 0x01, 0x00, 0x00, 0x00]); // key/AVC, NALU, CT 0
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x65, 0x88, 0x80, 0x10]); // 4-byte len + IDR NAL
        v.extend_from_slice(&[0, 0, 0, 24]); // PrevTagSize2 = 11 + 13
        v
    }

    #[test]
    fn frames_two_video_tags() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&build_flv());
        let t1 = d.next_raw_tag().unwrap().unwrap();
        assert_eq!(
            (t1.tag_type, t1.data_size, t1.timestamp, t1.body.len()),
            (9, 25, 0, 25)
        );
        let t2 = d.next_raw_tag().unwrap().unwrap();
        assert_eq!(
            (t2.tag_type, t2.data_size, t2.timestamp, t2.body.len()),
            (9, 13, 0x21, 13)
        );
        assert!(d.next_raw_tag().unwrap().is_none());
    }

    #[test]
    fn is_incremental_across_pushes() {
        let flv = build_flv();
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&flv[..20]);
        assert!(d.next_raw_tag().unwrap().is_none()); // first tag not yet complete
        d.push(&flv[20..]);
        assert!(d.next_raw_tag().unwrap().is_some());
        assert!(d.next_raw_tag().unwrap().is_some());
    }

    #[test]
    fn rejects_bad_prev_tag_size() {
        let mut flv = build_flv();
        let n = flv.len();
        flv[n - 1] = 0xFF; // corrupt PrevTagSize2
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&flv);
        assert!(d.next_raw_tag().unwrap().is_some());
        assert_eq!(d.next_raw_tag(), Err(FlvError::BadPrevTagSize));
    }

    #[test]
    fn oversize_data_size_rejected_before_buffering() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        // header + PrevTagSize0 + tag header only, data_size = 0xFFFFFF
        d.push(&[
            b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0x09, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0,
            0, 0,
        ]);
        assert_eq!(d.next_raw_tag(), Err(FlvError::OversizeTag));
    }
}
