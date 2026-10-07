//! `GET /av.flv?token=…` (§3.1): a close-delimited HTTP-FLV stream in the
//! profile's tag shape — one tag per access unit, `CompositionTime` per the
//! profile on coded tags (0 on the sequence header), the profile's NAL
//! length size. Every write is timed (`max_flv_write_block`) and each coded
//! tag's is stamped (`FlvAu`'s instant is `sim_tx`).
use crate::encoder::{EncoderHandle, Item, OutFrame};
use crate::http::{FLV_HEAD, Request, respond};
use crate::source::nal_type;
use crate::state::{Shared, SimEvent};
use crate::{Profile, ResizeSignal};
use bytes::Bytes;
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::h264::frame_id;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Writer<W> {
    out: W,
    profile: Profile,
    conn: u64,
    shared: Arc<Shared>,
    frames_written: u64,
    seen_idr: bool,
    inband_next: Option<(Bytes, Bytes)>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn timestamp(&self) -> u32 {
        let ms = self.frames_written * 1000 / u64::from(self.profile.fps.max(1));
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
            // One-shot faults are Task 8.5's.
            Item::Fault(_) => {}
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
        if !self.seen_idr && !f.idr {
            return Ok(());
        }
        self.seen_idr = true;
        let mut nals: Vec<Bytes> = Vec::new();
        if f.idr
            && let Some((sps, pps)) = self.inband_next.take()
        {
            nals.push(sps);
            nals.push(pps);
        }
        nals.extend(f.nals.iter().cloned());
        let refs: Vec<&[u8]> = nals.iter().map(|n| n.as_ref()).collect();
        let mut body = Vec::new();
        let ct = self.profile.composition_time_ms;
        avc_nalu_body(&mut body, f.idr, ct, &refs, self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut tag = Vec::with_capacity(body.len() + 15);
        write_tag(&mut tag, TAG_VIDEO, self.timestamp(), &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let sim_tx = self.write(&tag).await?;
        self.frames_written += 1;
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
        Ok(())
    }
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    conn: u64,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    profile: Profile,
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
    } else if policy.refuse_concurrent_flv > 0 && shared.stats().flv_open > 0 {
        shared.set_policy(|p| p.refuse_concurrent_flv = p.refuse_concurrent_flv.saturating_sub(1));
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
        conn,
        shared: shared.clone(),
        frames_written: 0,
        seen_idr: false,
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
                Some(item) => ok = w.item(item).await.unwrap_or(false),
                None => ok = false,
            },
            n = rd.read(&mut scratch) => ok = matches!(n, Ok(n) if n > 0),
        }
    }
    let _ = w.out.shutdown().await;
    shared.record(SimEvent::FlvClose { conn });
}
