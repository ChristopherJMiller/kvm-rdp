use crate::flv::avc::{VideoBody, parse_video_body};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TagBody {
    Audio,
    ScriptData,
    Video(VideoBody),
    Other(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlvTag {
    pub tag_type: u8,
    pub data_size: u32,
    pub timestamp: u32,
    pub body: TagBody,
}

impl FlvDemuxer {
    /// Parsed next tag (§6.2). Video tags decode into `VideoBody` with
    /// zero-copy NAL/SPS/PPS slices; audio (8) and script-data (18) tags are
    /// framed and surfaced but their bodies are not parsed.
    pub fn next_tag(&mut self) -> Result<Option<FlvTag>, FlvError> {
        let Some(raw) = self.next_raw_tag()? else {
            return Ok(None);
        };
        let body = match raw.tag_type {
            8 => TagBody::Audio,
            18 => TagBody::ScriptData,
            9 => {
                let vb = parse_video_body(&raw.body, self.length_size)?;
                if let VideoBody::SequenceHeader(ref cfg) = vb {
                    self.length_size = Some(cfg.length_size_minus_one.wrapping_add(1));
                }
                TagBody::Video(vb)
            }
            other => TagBody::Other(other),
        };
        Ok(Some(FlvTag {
            tag_type: raw.tag_type,
            data_size: raw.data_size,
            timestamp: raw.timestamp,
            body,
        }))
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
    use crate::flv::{FrameType, TagBody, VideoBody};

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

    #[test]
    fn next_tag_parses_seqheader_then_idr() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&build_flv());
        let t1 = d.next_tag().unwrap().unwrap();
        match t1.body {
            TagBody::Video(VideoBody::SequenceHeader(cfg)) => {
                assert_eq!(cfg.length_size_minus_one, 3);
                assert_eq!(cfg.sps.len(), 1);
                assert_eq!(cfg.pps.len(), 1);
            }
            other => panic!("expected seq header, got {other:?}"),
        }
        let t2 = d.next_tag().unwrap().unwrap();
        match t2.body {
            TagBody::Video(VideoBody::Nalus {
                frame_type,
                composition_time,
                nals,
            }) => {
                assert_eq!(frame_type, FrameType::Key);
                assert_eq!(composition_time, 0);
                assert_eq!(nals.len(), 1);
                assert_eq!(nals[0].unit_type(), Some(5));
            }
            other => panic!("expected NALU AU, got {other:?}"),
        }
        assert!(d.next_tag().unwrap().is_none());
    }

    #[test]
    fn nalu_before_sequence_header_is_fatal() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0]);
        // a video NALU tag (data_size 13) with no prior seq header
        d.push(&[
            0x09, 0x00, 0x00, 0x0D, 0, 0, 0, 0, 0, 0, 0, 0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00,
            0x04, 0x65, 0x88, 0x80, 0x10, 0, 0, 0, 24,
        ]);
        assert_eq!(d.next_tag(), Err(FlvError::NalBeforeSequenceHeader));
    }

    #[test]
    fn audio_and_script_tags_surface_without_body_parse() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&[b'F', b'L', b'V', 1, 0x05, 0, 0, 0, 9, 0, 0, 0, 0]);
        // one audio tag (type 8, data_size 1), then one script tag (type 18, data_size 1)
        d.push(&[
            0x08, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0xAF, 0, 0, 0, 12,
        ]);
        d.push(&[
            0x12, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 12,
        ]);
        assert!(matches!(
            d.next_tag().unwrap().unwrap().body,
            TagBody::Audio
        ));
        assert!(matches!(
            d.next_tag().unwrap().unwrap().body,
            TagBody::ScriptData
        ));
    }

    #[test]
    fn enhanced_rtmp_hevc_tag_is_surfaced_not_misread_as_avc() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0]);
        // video tag, data_size 5: IsExHeader|FrameType=1(key)|PacketType=0, FourCC "hvc1"
        d.push(&[
            0x09, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0, 0x90, b'h', b'v', b'c', b'1', 0, 0, 0, 16,
        ]);
        match d.next_tag().unwrap().unwrap().body {
            TagBody::Video(VideoBody::Enhanced {
                packet_type,
                frame_type,
                fourcc,
            }) => {
                assert_eq!(packet_type, 0);
                assert_eq!(frame_type, FrameType::Key);
                assert_eq!(&fourcc, b"hvc1");
            }
            other => panic!("expected Enhanced, got {other:?}"),
        }
    }
}
