use crate::flv::header::FlvError;
use crate::flv::reader::Cur;
use bytes::Bytes;

/// A raw H.264 NAL unit (no start code, no length prefix), shared with the
/// FLV buffer without copying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nal {
    pub bytes: Bytes,
}

impl Nal {
    /// `nal_unit_type` (header byte & 0x1F).
    pub fn unit_type(&self) -> Option<u8> {
        self.bytes.first().map(|b| b & 0x1F)
    }
    /// `nal_ref_idc` ((header byte >> 5) & 0x3).
    pub fn ref_idc(&self) -> Option<u8> {
        self.bytes.first().map(|b| b.wrapping_shr(5) & 0x3)
    }
}

/// Parsed `AVCDecoderConfigurationRecord` (ISO 14496-15). SPS/PPS are
/// zero-copy slices of the tag body (§6.2). Count/size caps (1–4 SPS,
/// 1–16 PPS, ≤ 1 KiB each) are Plan B hardening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvcConfig {
    pub length_size_minus_one: u8,
    pub profile_idc: u8,
    pub level_idc: u8,
    pub sps: Vec<Bytes>,
    pub pps: Vec<Bytes>,
}

/// Parse the config record starting at `start` (past the 5-byte FLV AVC
/// header). `body` is the whole tag body so slices share its allocation.
pub(crate) fn parse_avc_config(body: &Bytes, start: usize) -> Result<AvcConfig, FlvError> {
    let region = body
        .as_ref()
        .get(start..)
        .ok_or(FlvError::BadConfigRecord)?;
    let mut c = Cur::new(region);
    if c.u8().ok_or(FlvError::BadConfigRecord)? != 1 {
        return Err(FlvError::BadConfigRecord);
    }
    let profile_idc = c.u8().ok_or(FlvError::BadConfigRecord)?;
    let _compat = c.u8().ok_or(FlvError::BadConfigRecord)?;
    let level_idc = c.u8().ok_or(FlvError::BadConfigRecord)?;
    let length_size_minus_one = c.u8().ok_or(FlvError::BadConfigRecord)? & 0x03;
    if length_size_minus_one == 2 {
        return Err(FlvError::BadLengthSize);
    }
    let num_sps = c.u8().ok_or(FlvError::BadConfigRecord)? & 0x1F;
    let sps = read_param_sets(body, &mut c, start, num_sps)?;
    let num_pps = c.u8().ok_or(FlvError::BadConfigRecord)?;
    let pps = read_param_sets(body, &mut c, start, num_pps)?;
    Ok(AvcConfig {
        length_size_minus_one,
        profile_idc,
        level_idc,
        sps,
        pps,
    })
}

fn read_param_sets(
    body: &Bytes,
    c: &mut Cur<'_>,
    start: usize,
    count: u8,
) -> Result<Vec<Bytes>, FlvError> {
    let mut out = Vec::new();
    for _ in 0..count {
        let len = usize::from(c.u16().ok_or(FlvError::BadConfigRecord)?);
        let at = start
            .checked_add(c.pos())
            .ok_or(FlvError::BadConfigRecord)?;
        let end = at.checked_add(len).ok_or(FlvError::BadConfigRecord)?;
        if body.as_ref().get(at..end).is_none() {
            return Err(FlvError::BadConfigRecord);
        }
        let _ = c.take(len).ok_or(FlvError::BadConfigRecord)?;
        out.push(body.slice(at..end));
    }
    Ok(out)
}

/// Split length-prefixed NALs out of an AVC NALU tag body (zero-copy).
/// `start` is past the 5-byte FLV AVC header; `length_size` is 1, 2 or 4.
pub(crate) fn parse_nalus(
    body: &Bytes,
    start: usize,
    length_size: u8,
) -> Result<Vec<Nal>, FlvError> {
    let mut nals = Vec::new();
    let mut at = start;
    let ls = usize::from(length_size);
    loop {
        if body.len().saturating_sub(at) == 0 {
            break;
        }
        let len_end = at.checked_add(ls).ok_or(FlvError::MalformedVideoTag)?;
        let len_bytes = body
            .as_ref()
            .get(at..len_end)
            .ok_or(FlvError::MalformedVideoTag)?;
        let nal_len = read_len(len_bytes);
        let nal_end = len_end
            .checked_add(nal_len)
            .ok_or(FlvError::MalformedVideoTag)?;
        if nal_len == 0 || body.as_ref().get(len_end..nal_end).is_none() {
            return Err(FlvError::MalformedVideoTag); // 0 < n ≤ remaining (§6.2)
        }
        nals.push(Nal {
            bytes: body.slice(len_end..nal_end),
        });
        at = nal_end;
    }
    Ok(nals)
}

/// Big-endian NAL length of 1–4 bytes.
fn read_len(bytes: &[u8]) -> usize {
    let mut v: usize = 0;
    for b in bytes {
        v = v.wrapping_shl(8).wrapping_add(usize::from(*b));
    }
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    Key,
    Inter,
    Other(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VideoBody {
    SequenceHeader(AvcConfig),
    Nalus {
        frame_type: FrameType,
        composition_time: i32,
        nals: Vec<Nal>,
    },
    EndOfSequence,
    NonAvc {
        codec_id: u8,
        frame_type: FrameType,
    },
    /// Enhanced-RTMP `IsExHeader` tag: bits 6..4 frame type, bits 3..0
    /// packet type, then a 4-byte FourCC (`hvc1`, `av01`, …).
    Enhanced {
        packet_type: u8,
        frame_type: FrameType,
        fourcc: [u8; 4],
    },
}

const AVC_HEADER_LEN: usize = 5;
const CODEC_AVC: u8 = 7;
const IS_EX_HEADER: u8 = 0x80;

/// Parse an FLV video tag body (§6.2). `length_size` is the current
/// `lengthSizeMinusOne + 1`, needed for NALU tags.
pub(crate) fn parse_video_body(
    body: &Bytes,
    length_size: Option<u8>,
) -> Result<VideoBody, FlvError> {
    let mut c = Cur::new(body.as_ref());
    let b0 = c.u8().ok_or(FlvError::MalformedVideoTag)?;
    if b0 & IS_EX_HEADER != 0 {
        let frame_type = match b0.wrapping_shr(4) & 0x07 {
            1 => FrameType::Key,
            2 => FrameType::Inter,
            other => FrameType::Other(other),
        };
        let fourcc = [
            c.u8().ok_or(FlvError::MalformedVideoTag)?,
            c.u8().ok_or(FlvError::MalformedVideoTag)?,
            c.u8().ok_or(FlvError::MalformedVideoTag)?,
            c.u8().ok_or(FlvError::MalformedVideoTag)?,
        ];
        return Ok(VideoBody::Enhanced {
            packet_type: b0 & 0x0F,
            frame_type,
            fourcc,
        });
    }
    let frame_type = match b0.wrapping_shr(4) {
        1 => FrameType::Key,
        2 => FrameType::Inter,
        other => FrameType::Other(other),
    };
    let codec_id = b0 & 0x0F;
    if codec_id != CODEC_AVC {
        return Ok(VideoBody::NonAvc {
            codec_id,
            frame_type,
        });
    }
    let packet_type = c.u8().ok_or(FlvError::MalformedVideoTag)?;
    let composition_time = c.i24().ok_or(FlvError::MalformedVideoTag)?;
    match packet_type {
        0 => Ok(VideoBody::SequenceHeader(parse_avc_config(
            body,
            AVC_HEADER_LEN,
        )?)),
        1 => {
            let ls = length_size.ok_or(FlvError::NalBeforeSequenceHeader)?;
            Ok(VideoBody::Nalus {
                frame_type,
                composition_time,
                nals: parse_nalus(body, AVC_HEADER_LEN, ls)?,
            })
        }
        2 => Ok(VideoBody::EndOfSequence),
        _ => Err(FlvError::MalformedVideoTag),
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
    use bytes::Bytes;

    #[test]
    fn nal_header_fields() {
        let n = Nal {
            bytes: Bytes::from_static(&[0x65, 0x88]),
        };
        assert_eq!(n.unit_type(), Some(5));
        assert_eq!(n.ref_idc(), Some(3));
        assert_eq!(
            Nal {
                bytes: Bytes::new()
            }
            .unit_type(),
            None
        );
    }

    #[test]
    fn parses_avcc_and_extracts_sps_pps() {
        let body = Bytes::from_static(&[
            0x17, 0x00, 0x00, 0x00, 0x00, // 5-byte FLV AVC header
            0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05, 0x67, 0x42, 0x00, 0x1E, 0x88, 0x01,
            0x00, 0x04, 0x68, 0xCE, 0x3C, 0x80,
        ]);
        let cfg = parse_avc_config(&body, 5).unwrap();
        assert_eq!(cfg.length_size_minus_one, 3);
        assert_eq!((cfg.profile_idc, cfg.level_idc), (0x42, 0x1E));
        assert_eq!(
            cfg.sps,
            vec![Bytes::from_static(&[0x67, 0x42, 0x00, 0x1E, 0x88])]
        );
        assert_eq!(cfg.pps, vec![Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])]);
    }

    #[test]
    fn rejects_bad_length_size_and_truncation() {
        // lengthSizeMinusOne = 2 (0xFE & 0x03)
        let bad_ls = Bytes::from_static(&[0x17, 0, 0, 0, 0, 0x01, 0x42, 0x00, 0x1E, 0xFE, 0xE0]);
        assert_eq!(parse_avc_config(&bad_ls, 5), Err(FlvError::BadLengthSize));
        // SPS length 0x0005 but only 1 byte present
        let short = Bytes::from_static(&[
            0x17, 0, 0, 0, 0, 0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05, 0x67,
        ]);
        assert_eq!(parse_avc_config(&short, 5), Err(FlvError::BadConfigRecord));
    }

    #[test]
    fn splits_four_byte_length_nal() {
        let body = Bytes::from_static(&[
            0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x04, 0x65, 0x88, 0x80, 0x10,
        ]);
        let nals = parse_nalus(&body, 5, 4).unwrap();
        assert_eq!(nals.len(), 1);
        assert_eq!(nals[0].bytes, Bytes::from_static(&[0x65, 0x88, 0x80, 0x10]));
        assert_eq!(nals[0].unit_type(), Some(5));
    }

    #[test]
    fn splits_two_one_byte_length_nals() {
        let body = Bytes::from_static(&[
            0x27, 0x01, 0, 0, 0, 0x02, 0x67, 0x88, 0x03, 0x68, 0xCE, 0x3C,
        ]);
        let nals = parse_nalus(&body, 5, 1).unwrap();
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0].bytes, Bytes::from_static(&[0x67, 0x88]));
        assert_eq!(nals[1].bytes, Bytes::from_static(&[0x68, 0xCE, 0x3C]));
    }

    #[test]
    fn rejects_overrun_and_zero_length() {
        let overrun =
            Bytes::from_static(&[0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x09, 0x65, 0x88]);
        assert_eq!(
            parse_nalus(&overrun, 5, 4),
            Err(FlvError::MalformedVideoTag)
        );
        let zero = Bytes::from_static(&[0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(parse_nalus(&zero, 5, 4), Err(FlvError::MalformedVideoTag));
    }
}
