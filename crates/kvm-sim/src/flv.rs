//! `GET /av.flv?token=…` (§3.1): a close-delimited HTTP-FLV stream in the
//! profile's tag shape — one tag per access unit, `CompositionTime` per the
//! profile on coded tags (0 on the sequence header), the profile's NAL
//! length size, timestamps per `SimConfig::timestamps` — with one-shot
//! faults applied on the wire. Every write is timed (`max_flv_write_block`)
//! and each coded tag's is stamped (`FlvAu`'s instant is `sim_tx`).
use crate::encoder::{EncoderHandle, Item, OutFrame};
use crate::http::{FLV_HEAD, Request, respond};
use crate::source::nal_type;
use crate::state::{Shared, SimEvent};
use crate::{Fault, Profile, ResizeSignal, Timestamps};
use bytes::Bytes;
use kvm_proto::flv::mux::{
    RawTagHeader, TAG_VIDEO, avc_end_of_sequence_body, avc_nalu_body, avc_sequence_header_body,
    video_tag_byte, write_flv_header, write_raw_tag, write_tag,
};
use kvm_proto::h264::frame_id;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A slice NAL whose header prefix is `first_mb 0, slice_type 1 (B), pps 0`.
const B_SLICE: [u8; 2] = [0x41, 0xAC];
/// A tiny AUD, repeated to exceed §6.2's 128 NALs per tag.
const AUD: [u8; 2] = [0x09, 0xF0];

/// Bound on the final `shutdown()`, so closing an evicted-but-stalled
/// connection cannot itself hang (fix round 1, I1). A graceful TLS
/// `shutdown()` writes a close_notify, which can block on the same
/// congested socket a data write just did — short on purpose, since
/// `FlvClose` is recorded right after this regardless of whether the
/// write-side shutdown actually completed.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(50);

struct Writer<W> {
    out: W,
    profile: Profile,
    timestamps: Timestamps,
    /// When this FLV connection opened: `Timestamps::WallClock`'s zero.
    opened: Instant,
    conn: u64,
    shared: Arc<Shared>,
    frames_written: u64,
    seen_idr: bool,
    /// `Fault::Silence`: stop writing, keep the connection open.
    silenced: bool,
    /// A one-shot fault waiting for the next frame it can act on.
    pending: Option<Fault>,
    /// `Fault::TwoPictures`: the frame held back so it ships in the next
    /// frame's tag instead of its own.
    held: Option<Arc<OutFrame>>,
    inband_next: Option<(Bytes, Bytes)>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// The next tag's FLV timestamp (final review I2: see [`Timestamps`]).
    fn timestamp(&self) -> u32 {
        let ms = match self.timestamps {
            Timestamps::FrameCount => {
                self.frames_written * 1000 / u64::from(self.profile.fps.max(1))
            }
            Timestamps::WallClock => {
                u64::try_from(self.opened.elapsed().as_millis()).unwrap_or(u64::MAX)
            }
        };
        u32::try_from(ms).unwrap_or(u32::MAX)
    }

    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<Instant> {
        let start = Instant::now();
        self.out.write_all(bytes).await?;
        self.out.flush().await?;
        let done = Instant::now();
        self.shared.write_blocked(done - start);
        Ok(done)
    }

    async fn sequence_header(&mut self, sps: &[u8], pps: &[u8]) -> std::io::Result<()> {
        // The ES3 pads its config record's SPS with one zero byte and its PPS
        // with two (`census.md`); admission trims them (D2).
        let (sps, pps) = if self.profile.padded_param_sets {
            ([sps, &[0]].concat(), [pps, &[0, 0]].concat())
        } else {
            (sps.to_vec(), pps.to_vec())
        };
        let body = avc_sequence_header_body(&[&sps], &[&pps], self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut tag = Vec::new();
        write_tag(&mut tag, TAG_VIDEO, self.timestamp(), &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.write(&tag).await.map(|_| ())
    }

    /// Returns false when the connection should close.
    async fn item(&mut self, item: Item) -> std::io::Result<bool> {
        match item {
            Item::Fault(Fault::Close) => return Ok(false),
            Item::Fault(Fault::Silence) => self.silenced = true,
            Item::Fault(Fault::EndOfSequence) => {
                let mut tag = Vec::new();
                let _ = write_tag(
                    &mut tag,
                    TAG_VIDEO,
                    self.timestamp(),
                    &avc_end_of_sequence_body(),
                );
                self.write(&tag).await?;
            }
            Item::Fault(f) => self.pending = Some(f),
            Item::Params {
                signal: ResizeSignal::CloseFlv,
                ..
            } => return Ok(false),
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::SequenceHeader,
            } => {
                self.sequence_header(&sps, &pps).await?;
            }
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::InBandSps,
            } => {
                self.inband_next = Some((sps, pps));
            }
            Item::Frame(f) => self.frame(f).await?,
        }
        Ok(true)
    }

    async fn frame(&mut self, f: Arc<OutFrame>) -> std::io::Result<()> {
        if self.silenced || (!self.seen_idr && !f.idr) {
            return Ok(());
        }
        self.seen_idr = true;
        if matches!(self.pending, Some(Fault::TwoPictures)) && self.held.is_none() {
            self.held = Some(f);
            return Ok(());
        }
        let mut nals: Vec<Bytes> = Vec::new();
        let mut fault = None;
        if let Some(h) = self.held.take() {
            nals.extend(h.nals.iter().cloned());
            fault = self.pending.take();
        }
        if f.idr
            && let Some((sps, pps)) = self.inband_next.take()
        {
            nals.push(sps);
            nals.push(pps);
        }
        nals.extend(f.nals.iter().cloned());
        if fault.is_none() {
            fault = self.pending.take();
        }
        let mut ct = self.profile.composition_time_ms;
        match &fault {
            Some(Fault::CompositionTime(c)) => ct = *c,
            Some(Fault::BSlice) => nals = vec![Bytes::from_static(&B_SLICE)],
            Some(Fault::StartCodeInNal) => corrupt_first_vcl(&mut nals, |v| {
                v.splice(1..1, [0, 0, 1]);
            }),
            Some(Fault::ForbiddenBit) => corrupt_first_vcl(&mut nals, |v| {
                if let Some(b) = v.first_mut() {
                    *b |= 0x80;
                }
            }),
            Some(Fault::TooManyNals) => nals = vec![Bytes::from_static(&AUD); 129],
            _ => {}
        }
        let refs: Vec<&[u8]> = nals.iter().map(|n| n.as_ref()).collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, f.idr, ct, &refs, self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut header = RawTagHeader {
            type_byte: TAG_VIDEO,
            timestamp_ms: self.timestamp(),
            stream_id: 0,
            data_size: None,
            prev_tag_size: None,
        };
        match &fault {
            Some(Fault::OversizeTag) => header.data_size = Some(0x00FF_FFFF),
            Some(Fault::BadPrevTagSize) => {
                header.prev_tag_size = Some(u32::try_from(body.len() + 12).unwrap_or(0));
            }
            Some(Fault::EncryptedTag) => header.type_byte = 0x20 | TAG_VIDEO,
            Some(Fault::BadStreamId) => header.stream_id = 1,
            Some(Fault::HevcCodecId) => {
                if let Some(b) = body.first_mut() {
                    *b = video_tag_byte(if f.idr { 1 } else { 2 }, 12);
                }
            }
            Some(Fault::EnhancedHevc) => body = vec![0x80 | 0x10 | 1, b'h', b'v', b'c', b'1'],
            _ => {}
        }
        let mut tag = Vec::with_capacity(body.len() + 15);
        write_raw_tag(&mut tag, &header, &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let sim_tx = self.write(&tag).await?;
        self.frames_written += 1;
        if fault.is_none() {
            let vcl = nals
                .iter()
                .filter(|n| matches!(nal_type(n), 1 | 5))
                .map(|n| n.as_ref());
            self.shared.record_at(
                sim_tx,
                SimEvent::FlvAu {
                    conn: self.conn,
                    seq: f.seq,
                    source_index: f.source_index,
                    frame_id: frame_id(vcl),
                    idr: f.idr,
                },
            );
        }
        Ok(())
    }
}

fn corrupt_first_vcl(nals: &mut [Bytes], f: impl FnOnce(&mut Vec<u8>)) {
    if let Some(n) = nals.iter_mut().find(|n| matches!(nal_type(n), 1 | 5)) {
        let mut v = n.to_vec();
        f(&mut v);
        *n = Bytes::from(v);
    }
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    conn: u64,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    profile: Profile,
    timestamps: Timestamps,
) {
    let policy = shared.policy();
    let token_ok = match (req.query_token(), req.cookie_token.as_deref()) {
        (Some(q), Some(c)) => q == c && shared.token_valid(q),
        _ => false,
    };
    let status = if req.method != "GET" || req.path() != "/av.flv" {
        Some(404)
    } else if !token_ok {
        Some(403)
    } else if let Some(s) = policy.flv_status {
        Some(s)
    } else if shared.take_flv_refusal() {
        // m3 (fix round 1): tested and decremented under one lock in
        // `Shared`, so two concurrent opens can't both see "still
        // refusing" before either spends it.
        Some(503)
    } else {
        None
    };
    if let Some(status) = status {
        shared.record(SimEvent::FlvRefused { status });
        // §6.9 classes `result: 403` as an auth failure; only the 403 body
        // carries it, so a 404/401/503 refusal is never mistaken for one
        // (P2, fix round 1).
        let body: &[u8] = if status == 403 {
            b"{\"result\":403}"
        } else {
            b""
        };
        let _ = respond(&mut io, status, "application/json", body).await;
        return;
    }
    let Some(mut sub) = enc.subscribe().await else {
        return;
    };
    shared.record(SimEvent::FlvOpen { conn });
    let (mut rd, wr) = tokio::io::split(io);
    let mut w = Writer {
        out: wr,
        profile,
        timestamps,
        opened: Instant::now(),
        conn,
        shared: shared.clone(),
        frames_written: 0,
        seen_idr: false,
        silenced: false,
        pending: None,
        held: None,
        inband_next: None,
    };
    let mut head = FLV_HEAD.to_vec();
    write_flv_header(&mut head, false, true);
    let mut ok = w.write(&head).await.is_ok();
    if ok && !policy.skip_sequence_header {
        ok = w.sequence_header(&sub.sps, &sub.pps).await.is_ok();
    }
    let mut scratch = [0u8; 256];
    while ok {
        tokio::select! {
            item = sub.rx.recv() => match item {
                // Race the write itself against eviction (I1, fix round
                // 1): a full queue's `Fault`/`Params` drop in
                // `Encoder::broadcast` must end this connection promptly
                // even while its client isn't draining and this write is
                // stuck — not only once the client resumes and the
                // already-queued backlog drains naturally.
                Some(item) => {
                    ok = tokio::select! {
                        r = w.item(item) => r.unwrap_or(false),
                        _ = &mut sub.evicted => false,
                    };
                }
                None => ok = false,
            },
            n = rd.read(&mut scratch) => ok = matches!(n, Ok(n) if n > 0),
            _ = &mut sub.evicted => ok = false,
        }
    }
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, w.out.shutdown()).await;
    shared.record(SimEvent::FlvClose { conn });
}
