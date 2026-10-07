//! FLV muxer (§4.1): the inverse of the demuxer, for kvm-sim, the
//! mux→demux property tests and the differential fuzz target. Each writer
//! appends to a caller-owned `Vec` and checks every field fits before
//! writing anything; `write_raw_tag` takes every header field explicitly so
//! a test double can also write deliberately wrong ones.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// A value that does not fit the FLV field it was meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxError {
    /// A tag body longer than `DataSize`'s 24 bits.
    TagTooLarge,
    /// `length_size` other than 1, 2 or 4.
    BadLengthSize(u8),
    /// A NAL longer than its length prefix can express, or empty.
    NalLength,
    /// A parameter set longer than 65 535 bytes, or empty, or too many.
    ParamSet,
    /// `CompositionTime` outside the signed 24-bit range.
    CompositionTime,
}

/// FLV tag types.
pub const TAG_AUDIO: u8 = 8;
pub const TAG_VIDEO: u8 = 9;
pub const TAG_SCRIPT: u8 = 18;

/// Every field of an 11-byte tag header plus the trailing `PrevTagSize`.
/// `data_size`/`prev_tag_size` of `None` mean "the correct value".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTagHeader {
    /// The whole first byte: reserved bits, filter (`0x20`) and tag type.
    pub type_byte: u8,
    pub timestamp_ms: u32,
    pub stream_id: u32,
    pub data_size: Option<u32>,
    pub prev_tag_size: Option<u32>,
}

/// The 9-byte FLV header (`DataOffset` 9) and `PrevTagSize0`.
pub fn write_flv_header(out: &mut Vec<u8>, has_audio: bool, has_video: bool) {
    let flags = (if has_audio { 0x04 } else { 0 }) | u8::from(has_video);
    out.extend_from_slice(&[b'F', b'L', b'V', 1, flags, 0, 0, 0, 9, 0, 0, 0, 0]);
}

/// One correct tag of `tag_type` carrying `body`.
pub fn write_tag(
    out: &mut Vec<u8>,
    tag_type: u8,
    timestamp_ms: u32,
    body: &[u8],
) -> Result<(), MuxError> {
    write_raw_tag(
        out,
        &RawTagHeader {
            type_byte: tag_type & 0x1F,
            timestamp_ms,
            stream_id: 0,
            data_size: None,
            prev_tag_size: None,
        },
        body,
    )
}

/// One tag with explicit header fields (kvm-sim's fault injection).
pub fn write_raw_tag(out: &mut Vec<u8>, h: &RawTagHeader, body: &[u8]) -> Result<(), MuxError> {
    let real = u32::try_from(body.len()).map_err(|_| MuxError::TagTooLarge)?;
    if real > 0x00FF_FFFF {
        return Err(MuxError::TagTooLarge);
    }
    let data_size = h.data_size.unwrap_or(real) & 0x00FF_FFFF;
    let prev = h.prev_tag_size.unwrap_or(real.saturating_add(11));
    let ds = data_size.to_be_bytes();
    let ts = h.timestamp_ms.to_be_bytes();
    let sid = (h.stream_id & 0x00FF_FFFF).to_be_bytes();
    out.push(h.type_byte);
    out.extend_from_slice(ds.get(1..).unwrap_or(&[]));
    out.extend_from_slice(ts.get(1..).unwrap_or(&[])); // low 24 bits
    out.push(ts.first().copied().unwrap_or(0)); // TimestampExtended
    out.extend_from_slice(sid.get(1..).unwrap_or(&[]));
    out.extend_from_slice(body);
    out.extend_from_slice(&prev.to_be_bytes());
    Ok(())
}

/// First byte of a classic video tag body: frame type (1 key, 2 inter) and
/// `CodecID` (7 AVC, 12 HEVC).
#[must_use]
pub fn video_tag_byte(frame_type: u8, codec_id: u8) -> u8 {
    (frame_type & 0x0F).wrapping_shl(4) | (codec_id & 0x0F)
}

/// Body of an AVC sequence-header tag: the 5-byte AVC header (packet type 0,
/// `CompositionTime` 0) and an `AVCDecoderConfigurationRecord` (version 1,
/// profile/compat/level copied from the first SPS).
pub fn avc_sequence_header_body(
    sps: &[&[u8]],
    pps: &[&[u8]],
    length_size: u8,
) -> Result<Vec<u8>, MuxError> {
    let lsm1 = length_size_minus_one(length_size)?;
    let first = sps.first().ok_or(MuxError::ParamSet)?;
    let num_sps = u8::try_from(sps.len())
        .ok()
        .filter(|n| *n <= 31)
        .ok_or(MuxError::ParamSet)?;
    let num_pps = u8::try_from(pps.len()).map_err(|_| MuxError::ParamSet)?;
    let mut b = vec![video_tag_byte(1, 7), 0, 0, 0, 0, 1];
    b.push(first.get(1).copied().unwrap_or(0));
    b.push(first.get(2).copied().unwrap_or(0));
    b.push(first.get(3).copied().unwrap_or(0));
    b.push(0xFC | lsm1);
    b.push(0xE0 | num_sps);
    for s in sps {
        push_param_set(&mut b, s)?;
    }
    b.push(num_pps);
    for p in pps {
        push_param_set(&mut b, p)?;
    }
    Ok(b)
}

/// Body of an AVC NALU tag: the 5-byte AVC header then each NAL behind a
/// `length_size`-byte big-endian length.
pub fn avc_nalu_body(
    out: &mut Vec<u8>,
    key: bool,
    composition_time_ms: i32,
    nals: &[&[u8]],
    length_size: u8,
) -> Result<(), MuxError> {
    length_size_minus_one(length_size)?;
    if !(-0x0080_0000..=0x007F_FFFF).contains(&composition_time_ms) {
        return Err(MuxError::CompositionTime);
    }
    let start = out.len();
    out.push(video_tag_byte(if key { 1 } else { 2 }, 7));
    out.push(1);
    out.extend_from_slice(composition_time_ms.to_be_bytes().get(1..).unwrap_or(&[]));
    for nal in nals {
        if let Err(e) = push_length(out, nal.len(), length_size) {
            out.truncate(start);
            return Err(e);
        }
        out.extend_from_slice(nal);
    }
    Ok(())
}

/// Body of an AVC end-of-sequence tag (packet type 2).
#[must_use]
pub fn avc_end_of_sequence_body() -> [u8; 5] {
    [video_tag_byte(1, 7), 2, 0, 0, 0]
}

fn length_size_minus_one(length_size: u8) -> Result<u8, MuxError> {
    match length_size {
        1 => Ok(0),
        2 => Ok(1),
        4 => Ok(3),
        other => Err(MuxError::BadLengthSize(other)),
    }
}

fn push_length(out: &mut Vec<u8>, len: usize, length_size: u8) -> Result<(), MuxError> {
    let len = u32::try_from(len).map_err(|_| MuxError::NalLength)?;
    let fits = match length_size {
        1 => len <= 0xFF,
        2 => len <= 0xFFFF,
        _ => true,
    };
    if len == 0 || !fits {
        return Err(MuxError::NalLength);
    }
    let be = len.to_be_bytes();
    let skip = 4_usize.saturating_sub(usize::from(length_size));
    out.extend_from_slice(be.get(skip..).unwrap_or(&[]));
    Ok(())
}

fn push_param_set(b: &mut Vec<u8>, set: &[u8]) -> Result<(), MuxError> {
    let len = u16::try_from(set.len()).map_err(|_| MuxError::ParamSet)?;
    if len == 0 {
        return Err(MuxError::ParamSet);
    }
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(set);
    Ok(())
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
    use crate::flv::{FlvDemuxer, FlvLimits, FrameType, TagBody, VideoBody};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    #[test]
    fn header_and_one_tag_are_byte_exact() {
        let mut out = Vec::new();
        write_flv_header(&mut out, false, true);
        write_tag(&mut out, TAG_VIDEO, 0x0102_0304, &[0xAA, 0xBB]).unwrap();
        assert_eq!(
            out,
            [
                b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0, // header + PrevTagSize0
                9, 0, 0, 2, 0x02, 0x03, 0x04, 0x01, 0, 0, 0, // tag header, ts ext 0x01
                0xAA, 0xBB, 0, 0, 0, 13, // body + PrevTagSize = 11 + 2
            ]
        );
    }

    #[test]
    fn nalu_body_and_sequence_header_are_byte_exact() {
        let mut b = Vec::new();
        avc_nalu_body(&mut b, true, 16, &[&[0x65, 0x88], &[0x65, 0x99, 0x01]], 2).unwrap();
        assert_eq!(
            b,
            [0x17, 1, 0, 0, 16, 0, 2, 0x65, 0x88, 0, 3, 0x65, 0x99, 0x01]
        );
        let sh = avc_sequence_header_body(&[&[0x67, 0x42, 0x00, 0x1F, 0x96]], &[&[0x68, 0xCE]], 4)
            .unwrap();
        assert_eq!(
            sh,
            [
                0x17, 0, 0, 0, 0, 1, 0x42, 0x00, 0x1F, 0xFF, 0xE1, 0, 5, 0x67, 0x42, 0x00, 0x1F,
                0x96, 1, 0, 2, 0x68, 0xCE
            ]
        );
    }

    #[test]
    fn negative_composition_time_round_trips_and_out_of_range_is_refused() {
        let mut b = Vec::new();
        avc_nalu_body(&mut b, false, -1, &[&[0x41, 0x9A]], 4).unwrap();
        assert_eq!(&b[..5], &[0x27, 1, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            avc_nalu_body(&mut Vec::new(), false, 0x0080_0000, &[&[0x41]], 4),
            Err(MuxError::CompositionTime)
        );
    }

    #[test]
    fn nal_too_long_for_its_prefix_is_refused_and_leaves_out_unchanged() {
        let big = vec![0x41u8; 256];
        let mut b = vec![0xEE];
        assert_eq!(
            avc_nalu_body(&mut b, false, 0, &[&big], 1),
            Err(MuxError::NalLength)
        );
        assert_eq!(b, [0xEE]);
        assert_eq!(
            avc_nalu_body(&mut b, false, 0, &[&[0x41]], 3),
            Err(MuxError::BadLengthSize(3))
        );

        // Exactly at the boundary (not just one byte over) succeeds: 255
        // bytes is the largest NAL a 1-byte length prefix can express, 65535
        // the largest a 2-byte prefix can express.
        let max_for_1 = vec![0x41u8; 255];
        let mut ok1 = Vec::new();
        assert!(avc_nalu_body(&mut ok1, false, 0, &[&max_for_1], 1).is_ok());

        let max_for_2 = vec![0x41u8; 65535];
        let mut ok2 = Vec::new();
        assert!(avc_nalu_body(&mut ok2, false, 0, &[&max_for_2], 2).is_ok());
    }

    #[test]
    fn tag_too_large_fires_one_byte_over_the_24_bit_data_size_but_not_at_the_boundary() {
        // Cheap bodies: a Vec of zeros is fine, `write_tag` only looks at
        // length. 0x00FF_FFFF is the largest `DataSize` 24 bits can hold.
        let max_ok = vec![0u8; 0x00FF_FFFF];
        let mut out = Vec::new();
        assert!(write_tag(&mut out, TAG_VIDEO, 0, &max_ok).is_ok());

        let one_over = vec![0u8; 0x0100_0000];
        let mut out2 = Vec::new();
        assert_eq!(
            write_tag(&mut out2, TAG_VIDEO, 0, &one_over),
            Err(MuxError::TagTooLarge)
        );
        assert!(out2.is_empty());
    }

    /// One tag the property test muxes: a sequence header, a NALU tag or an
    /// end of sequence.
    #[derive(Debug, Clone)]
    enum Spec {
        Seq {
            sps: Vec<Vec<u8>>,
            pps: Vec<Vec<u8>>,
        },
        Nalus {
            key: bool,
            ct: i32,
            nals: Vec<Vec<u8>>,
        },
        Eos,
    }

    fn nal(header: u8) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(move |mut v| {
            v.insert(0, header);
            v
        })
    }

    fn spec() -> impl Strategy<Value = Spec> {
        prop_oneof![
            (
                proptest::collection::vec(nal(0x67), 1..=4),
                proptest::collection::vec(nal(0x68), 1..=16)
            )
                .prop_map(|(sps, pps)| Spec::Seq { sps, pps }),
            (
                any::<bool>(),
                -1000i32..1000,
                proptest::collection::vec(nal(0x41), 1..=8)
            )
                .prop_map(|(key, ct, nals)| Spec::Nalus { key, ct, nals }),
            Just(Spec::Eos),
        ]
    }

    proptest! {
        // A fixed seed, so a CI failure reproduces from its log (PROPTEST_RNG_SEED
        // still overrides it), and no regression files written into the tree.
        #![proptest_config(ProptestConfig {
            cases: 256,
            failure_persistence: None,
            rng_seed: match ProptestConfig::default().rng_seed {
                RngSeed::Random => RngSeed::Fixed(20_261_006),
                from_env => from_env,
            },
            ..ProptestConfig::default()
        })]

        /// mux → demux is the identity on every field the demuxer reports,
        /// whatever the length-prefix size and however the bytes are chunked.
        #[test]
        fn mux_then_demux_round_trips(
            ls in prop_oneof![Just(1u8), Just(2u8), Just(4u8)],
            body in proptest::collection::vec(spec(), 0..12),
            chunk in 1usize..64,
        ) {
            let mut flv = Vec::new();
            write_flv_header(&mut flv, false, true);
            let mut specs = vec![Spec::Seq { sps: vec![vec![0x67, 0x42]], pps: vec![vec![0x68, 0xCE]] }];
            specs.extend(body);
            for (i, s) in specs.iter().enumerate() {
                let ts = u32::try_from(i).unwrap() * 33;
                let b = match s {
                    Spec::Seq { sps, pps } => {
                        let sps: Vec<&[u8]> = sps.iter().map(Vec::as_slice).collect();
                        let pps: Vec<&[u8]> = pps.iter().map(Vec::as_slice).collect();
                        avc_sequence_header_body(&sps, &pps, ls).unwrap()
                    }
                    Spec::Nalus { key, ct, nals } => {
                        let nals: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
                        let mut b = Vec::new();
                        avc_nalu_body(&mut b, *key, *ct, &nals, ls).unwrap();
                        b
                    }
                    Spec::Eos => avc_end_of_sequence_body().to_vec(),
                };
                write_tag(&mut flv, TAG_VIDEO, ts, &b).unwrap();
            }
            let mut d = FlvDemuxer::new(FlvLimits::default());
            let mut got = Vec::new();
            for c in flv.chunks(chunk) {
                d.push(c);
                while let Some(t) = d.next_tag().unwrap() {
                    got.push(t);
                }
            }
            prop_assert_eq!(got.len(), specs.len());
            for (i, (t, s)) in got.iter().zip(&specs).enumerate() {
                prop_assert_eq!(t.timestamp, u32::try_from(i).unwrap() * 33);
                match (&t.body, s) {
                    (TagBody::Video(VideoBody::SequenceHeader(c)), Spec::Seq { sps, pps }) => {
                        prop_assert_eq!(c.length_size_minus_one + 1, ls);
                        prop_assert_eq!(c.sps.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), sps.clone());
                        prop_assert_eq!(c.pps.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), pps.clone());
                    }
                    (TagBody::Video(VideoBody::Nalus { frame_type, composition_time, nals: demuxed }), Spec::Nalus { key, ct, nals }) => {
                        prop_assert_eq!(*frame_type, if *key { FrameType::Key } else { FrameType::Inter });
                        prop_assert_eq!(composition_time, ct);
                        prop_assert_eq!(demuxed.iter().map(|n| n.bytes.to_vec()).collect::<Vec<_>>(), nals.clone());
                    }
                    (TagBody::Video(VideoBody::EndOfSequence), Spec::Eos) => {}
                    (other, s) => prop_assert!(false, "tag {i}: {other:?} for {s:?}"),
                }
            }
        }
    }
}
