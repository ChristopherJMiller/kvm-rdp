//! `av.flv` capture to the 0700 captures dir with per-tag JSONL (§12 Leg A).
//! The probe never decodes H.264: only framing, NAL-header and
//! slice-header-prefix fields are recorded.

use crate::captures::CaptureDir;
use crate::kvm::{self, KvmError};
use crate::record::{MAX_PARAM_SET_BYTES, MAX_PARAM_SETS_PER_TAG, TagRecord};
use crate::request::{self, KvmTarget};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, FrameType, TagBody, VideoBody};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Every capture is bounded (§13: captures are 15–60 MB and wiped) so a
/// forgotten run cannot fill the disk.
pub struct StopAt {
    pub max_bytes: u64,
    pub max_duration: Duration,
}
impl Default for StopAt {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_duration: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub tags: u64,
    pub bytes: u64,
    pub parse_errors: u64,
    pub first_error: Option<String>,
}

fn frame_type_code(f: FrameType) -> u8 {
    match f {
        FrameType::Key => 1,
        FrameType::Inter => 2,
        FrameType::Other(x) => x,
    }
}

/// Sentinel for a NAL whose header could not be parsed (I2): not a valid
/// 5-bit `nal_unit_type`/`nal_ref_idc`, so it cannot be confused with a
/// real value. Documented on `TagRecord` in `record.rs`.
const NAL_HEADER_SENTINEL: u8 = u8::MAX;

/// Record one NAL's header/slice-prefix fields (R19: the shared
/// `kvm_proto::h264::NalHeader` parser, never a hand-split header byte). A
/// NAL whose header cannot be parsed (empty, or the forbidden bit set — a
/// framing violation from a hostile device, §6.2/§6.9) is *not* dropped:
/// dropping it would make a framing violation indistinguishable from an
/// empty access unit. Instead it records the `NAL_HEADER_SENTINEL` in
/// `nal_types`/`nal_ref_idc` and `None` for its slice fields, keeping the
/// four parallel per-NAL vectors in `TagRecord` aligned and the anomaly
/// visible to census analysis (I2).
fn push_nal(r: &mut TagRecord, nal: &[u8]) {
    let Ok(header) = kvm_proto::h264::NalHeader::from_nal(nal) else {
        r.nal_types.push(NAL_HEADER_SENTINEL);
        r.nal_ref_idc.push(NAL_HEADER_SENTINEL);
        r.slice_types.push(None);
        r.first_mb.push(None);
        return;
    };
    let ty = header.nal_unit_type;
    r.nal_types.push(ty);
    r.nal_ref_idc.push(header.nal_ref_idc);
    let (slice_type, first_mb) = if ty == 1 || ty == 5 {
        match kvm_proto::h264::parse_slice_header_prefix(nal) {
            Ok(p) => (u8::try_from(p.slice_type).ok(), Some(p.first_mb_in_slice)),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };
    r.slice_types.push(slice_type);
    r.first_mb.push(first_mb);
    if ty == 7 || ty == 8 {
        push_param_set(r, nal);
    }
}

/// Hex one SPS/PPS NAL into `param_sets_hex` (final review I3), bounded:
/// past `MAX_PARAM_SETS_PER_TAG` entries in this tag, or longer than
/// `MAX_PARAM_SET_BYTES`, it is counted in `param_sets_skipped` instead.
/// Only `push_nal` calls this, and only for a NAL whose own parsed header
/// says type 7 or 8 — so slice data (screen content) can never land here,
/// whichever list or tag it arrived in.
fn push_param_set(r: &mut TagRecord, nal: &[u8]) {
    if r.param_sets_hex.len() >= MAX_PARAM_SETS_PER_TAG || nal.len() > MAX_PARAM_SET_BYTES {
        r.param_sets_skipped = r.param_sets_skipped.saturating_add(1);
        return;
    }
    r.param_sets_hex.push(hex_lower(nal));
}

/// Lowercase hex, two digits per byte.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Render a 4-byte Enhanced-RTMP FourCC for the census JSONL (M4). ASCII
/// FourCCs (`hvc1`, `av01`, …) are recorded as their natural string; a
/// non-ASCII-graphic FourCC — which could otherwise carry a raw control
/// character into the operator's terminal via `from_utf8_lossy` — is
/// recorded as `0x` plus 8 lowercase hex digits instead, so the exact
/// bytes the device sent are always visible and never garbled by lossy
/// UTF-8 substitution.
fn fourcc_to_string(fourcc: &[u8; 4]) -> String {
    if fourcc.iter().all(|b| b.is_ascii_graphic())
        && let Ok(s) = std::str::from_utf8(fourcc)
    {
        return s.to_string();
    }
    let mut s = String::with_capacity(10);
    s.push_str("0x");
    for b in fourcc {
        // {:02x} cannot overflow; no arithmetic on `b`.
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One census record for one FLV tag (§12 Leg A). Framing fields only.
pub fn record_for(tag: &FlvTag, recv_ms: u64) -> TagRecord {
    let mut r = TagRecord {
        recv_ms,
        tag_type: tag.tag_type,
        timestamp_ms: tag.timestamp,
        composition_time: 0,
        frame_type: None,
        codec_id: None,
        avc_packet_type: None,
        fourcc: None,
        nal_types: Vec::new(),
        nal_ref_idc: Vec::new(),
        slice_types: Vec::new(),
        first_mb: Vec::new(),
        size: usize::try_from(tag.data_size).unwrap_or(usize::MAX),
        param_sets_hex: Vec::new(),
        param_sets_skipped: 0,
    };
    if let TagBody::Video(v) = &tag.body {
        match v {
            VideoBody::SequenceHeader(cfg) => {
                r.codec_id = Some(7);
                r.avc_packet_type = Some(0);
                for ps in cfg.sps.iter().chain(cfg.pps.iter()) {
                    push_nal(&mut r, ps);
                }
            }
            VideoBody::Nalus {
                frame_type,
                composition_time,
                nals,
            } => {
                r.codec_id = Some(7);
                r.avc_packet_type = Some(1);
                r.frame_type = Some(frame_type_code(*frame_type));
                r.composition_time = *composition_time;
                for n in nals {
                    push_nal(&mut r, &n.bytes);
                }
            }
            VideoBody::EndOfSequence => {
                r.codec_id = Some(7);
                r.avc_packet_type = Some(2);
            }
            VideoBody::NonAvc {
                codec_id,
                frame_type,
            } => {
                r.codec_id = Some(*codec_id);
                r.frame_type = Some(frame_type_code(*frame_type));
            }
            VideoBody::Enhanced {
                packet_type,
                frame_type,
                fourcc,
            } => {
                r.avc_packet_type = Some(*packet_type);
                r.frame_type = Some(frame_type_code(*frame_type));
                r.fourcc = Some(fourcc_to_string(fourcc));
            }
        }
    }
    r
}

/// Open `GET /av.flv?token=…` on the KVM's video port with the token
/// cookie (§3.2) and return the response body stream. `pub(crate)` so a
/// later trial task can reuse the same open-and-check-status path (R19).
pub(crate) async fn open_flv(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
) -> Result<hyper::body::Incoming, KvmError> {
    let io = kvm::connect_to(target, target.video_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    // The browser sends the token as the ?token= query and as the cookie (§3.2).
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("/av.flv?token={token}")) // origin-form; Host header names the KVM
        .header("Host", &target.host)
        .header("Cookie", request::token_cookie_header(token))
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    if resp.status() != hyper::StatusCode::OK {
        return Err(KvmError::Http(format!(
            "av.flv http status {}",
            resp.status().as_u16()
        )));
    }
    Ok(resp.into_body())
}

/// Open the capture file at `path` for writing, refusing to follow or
/// replace anything already there (I3). The sandbox mounts the captures
/// dir read-write for ffmpeg (`sandbox.rs`); a sandboxed decoder
/// compromised by hostile video could otherwise plant a symlink at a
/// predictable capture name and have a later capture write KVM-controlled
/// bytes through it to an arbitrary host path. `create_new` (`O_EXCL`)
/// refuses to open if *anything* — a regular file or a symlink, dangling
/// or not — already exists at `path`, without ever following it; mode
/// `0o600` matches the 0700 captures dir's own access discipline.
fn open_capture_file(path: &Path) -> Result<std::fs::File, KvmError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| KvmError::Io(e.to_string()))
}

/// Capture `av.flv` into `dir/name`, writing one `TagRecord` JSONL line per
/// parsed FLV tag to `jsonl`, stamped with the real receive time. Bounded
/// by `stop.max_bytes` and `stop.max_duration` (§13) so a forgotten run
/// cannot fill the disk. A parse error stops *parsing* but not *saving* —
/// the raw bytes already on disk stay there for sandboxed analysis — and is
/// counted in `Stats::parse_errors`, never swallowed.
///
/// The duration clock starts before `open_flv` and `open_flv` itself is
/// bounded by `stop.max_duration` (I1): a peer that accepts the connection
/// (or the TLS handshake) and then never answers the `GET /av.flv` request
/// is bounded the same as a peer that stalls mid-stream, not left to hang
/// the whole census.
pub async fn run(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    dir: &CaptureDir,
    name: &str,
    jsonl: &mut impl Write,
    stop: StopAt,
) -> Result<Stats, KvmError> {
    let path = dir
        .resolve(name)
        .map_err(|e| KvmError::Io(format!("{e:?}")))?;

    let started = Instant::now();
    let mut body = match tokio::time::timeout(stop.max_duration, open_flv(target, pin, token)).await
    {
        Ok(opened) => opened?,
        Err(_) => {
            return Err(KvmError::Http(format!(
                "av.flv open timed out after {:?}",
                stop.max_duration
            )));
        }
    };

    let mut file = open_capture_file(&path)?;

    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut parsing = true;
    let mut stats = Stats::default();
    loop {
        let remaining = stop.max_duration.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let frame = match tokio::time::timeout(remaining, body.frame()).await {
            Err(_) | Ok(None) => break, // duration cap, or the KVM closed the stream
            Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        let recv_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        file.write_all(chunk)
            .map_err(|e| KvmError::Io(e.to_string()))?;
        stats.bytes = stats
            .bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if parsing {
            demux.push(chunk);
            loop {
                match demux.next_tag() {
                    Ok(Some(tag)) => {
                        let line = record_for(&tag, recv_ms)
                            .to_jsonl()
                            .map_err(|e| KvmError::Io(e.to_string()))?;
                        writeln!(jsonl, "{line}").map_err(|e| KvmError::Io(e.to_string()))?;
                        stats.tags = stats.tags.saturating_add(1);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        // Keep saving raw bytes for sandboxed analysis; stop parsing.
                        stats.parse_errors = stats.parse_errors.saturating_add(1);
                        stats.first_error.get_or_insert_with(|| format!("{e:?}"));
                        parsing = false;
                        break;
                    }
                }
            }
        }
        if stats.bytes >= stop.max_bytes {
            break;
        }
    }
    file.flush().map_err(|e| KvmError::Io(e.to_string()))?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use kvm_proto::flv::{FlvTag, FrameType, Nal, TagBody, VideoBody};

    fn tag(body: TagBody) -> FlvTag {
        FlvTag {
            tag_type: 9,
            data_size: 20,
            timestamp: 33,
            body,
        }
    }

    #[test]
    fn idr_nalus_map_types_ref_idc_slice_type_and_first_mb() {
        // 0x65 = ref_idc 3, type 5 (IDR). 0x88 0x80 = ue(0) first_mb, ue(7) I-slice, ue(0) pps.
        let t = tag(TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            composition_time: 0,
            nals: vec![
                Nal {
                    bytes: Bytes::from_static(&[0x09, 0x10]),
                }, // AUD
                Nal {
                    bytes: Bytes::from_static(&[0x65, 0x88, 0x80]),
                }, // IDR slice
            ],
        }));
        let r = super::record_for(&t, 1500);
        assert_eq!(
            (r.recv_ms, r.tag_type, r.timestamp_ms, r.size),
            (1500, 9, 33, 20)
        );
        assert_eq!(
            (r.codec_id, r.avc_packet_type, r.frame_type),
            (Some(7), Some(1), Some(1))
        );
        assert_eq!(r.nal_types, vec![9, 5]);
        assert_eq!(r.nal_ref_idc, vec![0, 3]);
        assert_eq!(r.slice_types, vec![None, Some(7)]);
        assert_eq!(r.first_mb, vec![None, Some(0)]);
        assert_eq!(r.fourcc, None);
    }

    #[test]
    fn sequence_header_lists_its_parameter_sets() {
        let cfg = kvm_proto::flv::AvcConfig {
            length_size_minus_one: 3,
            profile_idc: 77,
            level_idc: 31,
            sps: vec![Bytes::from_static(&[0x67, 0x4D, 0x00, 0x1F])],
            pps: vec![Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])],
        };
        let r = super::record_for(&tag(TagBody::Video(VideoBody::SequenceHeader(cfg))), 0);
        assert_eq!((r.codec_id, r.avc_packet_type), (Some(7), Some(0)));
        assert_eq!(r.nal_types, vec![7, 8]);
        // I3 (final review): the parameter sets themselves, as lowercase
        // hex, header byte included.
        assert_eq!(r.param_sets_hex, vec!["674d001f", "68ce3c80"]);
        assert_eq!(r.param_sets_skipped, 0);
    }

    fn nal(bytes: &[u8]) -> Nal {
        Nal {
            bytes: Bytes::copy_from_slice(bytes),
        }
    }

    fn nalus(nals: Vec<Nal>) -> FlvTag {
        tag(TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            composition_time: 0,
            nals,
        }))
    }

    /// I3: in-band SPS/PPS in a NALU tag are hexed; the AUD, SEI and slice
    /// next to them never are — slice data is screen content.
    #[test]
    fn in_band_parameter_sets_are_hexed_but_slices_never_are() {
        let r = super::record_for(
            &nalus(vec![
                nal(&[0x09, 0x10]),
                nal(&[0x67, 0x4D, 0x00, 0x1F]),
                nal(&[0x68, 0xCE, 0x3C, 0x80]),
                nal(&[0x06, 0x05, 0x01, 0x00]),
                nal(&[0x65, 0x88, 0x80]),
            ]),
            0,
        );
        assert_eq!(r.nal_types, vec![9, 7, 8, 6, 5]);
        assert_eq!(r.param_sets_hex, vec!["674d001f", "68ce3c80"]);
        assert_eq!(r.param_sets_skipped, 0);
    }

    /// I3: what gets hexed is decided by each NAL's own header, not by
    /// where it sits — a slice smuggled into the config record's SPS list
    /// (hostile device) is never hexed, and neither is a forbidden-bit
    /// "SPS" (0xE7: a framing violation, recorded as the sentinel).
    #[test]
    fn only_nals_whose_header_says_sps_or_pps_are_hexed() {
        let cfg = kvm_proto::flv::AvcConfig {
            length_size_minus_one: 3,
            profile_idc: 77,
            level_idc: 31,
            sps: vec![
                Bytes::from_static(&[0x65, 0x88, 0x80]),
                Bytes::from_static(&[0xE7, 0x4D, 0x00, 0x1F]),
            ],
            pps: vec![Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])],
        };
        let r = super::record_for(&tag(TagBody::Video(VideoBody::SequenceHeader(cfg))), 0);
        assert_eq!(r.nal_types, vec![5, 255, 8]);
        assert_eq!(r.param_sets_hex, vec!["68ce3c80"]);
        assert_eq!(r.param_sets_skipped, 0);
    }

    /// I3: hexing is bounded — at most 32 parameter sets per tag, each at
    /// most 1 KiB of NAL; anything past either bound is skipped and
    /// counted, never hexed.
    #[test]
    fn param_set_hex_is_bounded_per_tag_and_per_nal() {
        // 33 distinct PPS NALs: the 33rd is skipped.
        let r = super::record_for(&nalus((0u8..33).map(|i| nal(&[0x68, i])).collect()), 0);
        assert_eq!(r.param_sets_hex.len(), 32);
        assert_eq!(r.param_sets_hex.first().map(String::as_str), Some("6800"));
        assert_eq!(r.param_sets_hex.last().map(String::as_str), Some("681f"));
        assert_eq!(r.param_sets_skipped, 1);

        // A 1024-byte SPS NAL is hexed; a 1025-byte one is skipped.
        let mut at_cap = vec![0x67u8];
        at_cap.resize(1024, 0xAA);
        let mut over_cap = vec![0x67u8];
        over_cap.resize(1025, 0xAA);
        let r = super::record_for(&nalus(vec![nal(&at_cap), nal(&over_cap)]), 0);
        assert_eq!(r.param_sets_hex.len(), 1);
        assert_eq!(r.param_sets_hex.first().map(String::len), Some(2048));
        assert_eq!(r.param_sets_skipped, 1);
        assert_eq!(r.nal_types, vec![7, 7]);
    }

    #[test]
    fn enhanced_rtmp_records_fourcc_not_avc() {
        let r = super::record_for(
            &tag(TagBody::Video(VideoBody::Enhanced {
                packet_type: 1,
                frame_type: FrameType::Inter,
                fourcc: *b"hvc1",
            })),
            0,
        );
        assert_eq!(r.fourcc.as_deref(), Some("hvc1"));
        assert_eq!(r.codec_id, None);
        assert_eq!(r.frame_type, Some(2));
    }

    #[test]
    fn script_tag_has_no_video_fields() {
        let mut t = tag(TagBody::ScriptData);
        t.tag_type = 18;
        let r = super::record_for(&t, 0);
        assert_eq!((r.tag_type, r.codec_id, r.frame_type), (18, None, None));
        assert!(r.nal_types.is_empty());
    }

    /// I2: a forbidden-bit NAL is a framing violation, not an empty access
    /// unit — it must be visible in the census, not silently dropped.
    #[test]
    fn forbidden_bit_nal_is_recorded_as_sentinel_not_dropped() {
        // 0xE5 = forbidden bit set, nal_ref_idc 3, type 5 (would-be IDR).
        let t = tag(TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            composition_time: 0,
            nals: vec![Nal {
                bytes: Bytes::from_static(&[0xE5, 0x88, 0x80]),
            }],
        }));
        let r = super::record_for(&t, 0);
        assert_eq!(r.nal_types, vec![255]);
        assert_eq!(r.nal_ref_idc, vec![255]);
        assert_eq!(r.slice_types, vec![None]);
        assert_eq!(r.first_mb, vec![None]);
    }

    /// M4: a non-ASCII-graphic FourCC must not be lossily mangled into
    /// U+FFFD (which would also lose the actual bytes the device sent) —
    /// it is recorded as exact hex instead.
    #[test]
    fn non_ascii_fourcc_is_recorded_as_hex_not_lossy_utf8() {
        let r = super::record_for(
            &tag(TagBody::Video(VideoBody::Enhanced {
                packet_type: 1,
                frame_type: FrameType::Key,
                fourcc: [0xC2, 0x9B, 0x00, 0xFF],
            })),
            0,
        );
        assert_eq!(r.fourcc.as_deref(), Some("0xc29b00ff"));
    }

    /// M4: an ASCII-graphic FourCC is still recorded as its natural string.
    #[test]
    fn ascii_fourcc_is_recorded_as_its_string() {
        let r = super::record_for(
            &tag(TagBody::Video(VideoBody::Enhanced {
                packet_type: 0,
                frame_type: FrameType::Key,
                fourcc: *b"av01",
            })),
            0,
        );
        assert_eq!(r.fourcc.as_deref(), Some("av01"));
    }
}
