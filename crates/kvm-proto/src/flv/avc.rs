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
}
