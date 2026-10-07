//! KVM-side video admission (§6.1, §6.2, §6.8): every demuxed FLV tag goes
//! through `VideoAdmission::admit`, which applies the NAL sanitiser, the SPS
//! rewriter, the SPS/PPS/slice checks and the one-picture rule, and returns
//! what the pump may see: a parameter-set change and/or one access unit.
//! Sans-IO: the caller passes the receive time. Nothing here allocates per
//! access unit — the AU reuses the demuxer's NAL `Vec`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod error;
mod params;
mod violations;
pub use error::{AdmissionError, Framing, Incompatible};
pub use params::{ParamClass, ParamSets, ParamsChange};
pub use violations::{ViolationVerdict, ViolationWindow};

use crate::flv::{AvcConfig, BurstMarker, FlvError, FlvLimits, FlvTag, Nal, TagBody, VideoBody};
use crate::h264::picture::{PocTracker, SliceInfo, parse_slice};
use crate::h264::rewrite::RewriteConfig;
use crate::h264::sanitize::{NalVerdict, check_nal};
use crate::h264::{SpsLimits, frame_id};
use bytes::Bytes;
use core::time::Duration;
use error::{framing, incompatible};
use params::{ParamState, strongest};
use std::time::Instant;

/// One admitted access unit: exactly one picture (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    pub flv_timestamp_ms: u32,
    pub idr: bool,
    /// Ran more than `burst_threshold` ahead of real time, measured from
    /// this FLV connection's first *coded* tag, not its sequence header
    /// (D11; fix round 1, P10/m5).
    pub burst: bool,
    /// The AUD, when the source sent one.
    pub aud: Option<Bytes>,
    /// The allowlisted VCL NALs (types 1 and 5), trimmed, in order.
    pub vcl: Vec<Nal>,
}

impl AccessUnit {
    /// §10.2 FrameId of this AU.
    #[must_use]
    pub fn frame_id(&self) -> u64 {
        frame_id(self.vcl.iter().map(|n| n.bytes.as_ref()))
    }

    /// Append this AU in §6.3's output form — 4-byte start codes; [AUD] +
    /// SPS and every PPS (IDR only) + the VCL NALs — to `out`, which the
    /// caller clears and reuses.
    pub fn write_annex_b(&self, params: &ParamSets, out: &mut Vec<u8>) {
        const SC: [u8; 4] = [0, 0, 0, 1];
        if let Some(aud) = &self.aud {
            out.extend_from_slice(&SC);
            out.extend_from_slice(aud);
        }
        if self.idr {
            out.extend_from_slice(&SC);
            out.extend_from_slice(&params.sps);
            for p in &params.pps {
                out.extend_from_slice(&SC);
                out.extend_from_slice(p);
            }
        }
        for n in &self.vcl {
            out.extend_from_slice(&SC);
            out.extend_from_slice(&n.bytes);
        }
    }
}

/// What one tag produced. When both are set the caller sends `params` (as
/// `SpsChanged`) before `au`, on the one ordered stream (§4.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admitted {
    pub params: Option<ParamsChange>,
    pub au: Option<AccessUnit>,
    /// `AVCPacketType 2`: reconnect the FLV (transient, §6.9).
    pub end_of_sequence: bool,
    /// NALs dropped by the allowlist (SEI, filler, …).
    pub dropped_nals: usize,
}

/// The `video.*` settings admission needs (§4.4).
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    pub limits: SpsLimits,
    pub rewrite: RewriteConfig,
    /// §6.2 burst threshold: 100 ms.
    pub burst_threshold: Duration,
    /// §6.2 SPS limit: 4 in-band SPSs per tag (D10).
    pub max_sps: usize,
    /// §6.2 PPS limit: 16 PPS ids at once, and 16 in-band PPSs per tag (D10).
    pub max_pps: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        AdmissionConfig {
            limits: SpsLimits::default(),
            rewrite: RewriteConfig::ES3,
            burst_threshold: Duration::from_millis(100),
            max_sps: FlvLimits::default().max_sps,
            max_pps: FlvLimits::default().max_pps,
        }
    }
}

/// Per-KVM-session admission (§6.1): created at `Start`, told about every
/// FLV open with [`VideoAdmission::flv_opened`].
pub struct VideoAdmission {
    params: ParamState,
    composition_time: Option<i32>,
    poc: PocTracker,
    burst: BurstMarker,
    max_sps: usize,
    max_pps: usize,
}

impl VideoAdmission {
    #[must_use]
    pub fn new(cfg: AdmissionConfig) -> Self {
        VideoAdmission {
            params: ParamState::new(cfg.limits, cfg.rewrite, cfg.max_pps),
            composition_time: None,
            poc: PocTracker::default(),
            burst: BurstMarker::new(cfg.burst_threshold),
            max_sps: cfg.max_sps,
            max_pps: cfg.max_pps,
        }
    }

    /// A new FLV connection (any origin) delivers the tags from now on: its
    /// first parameter sets are `Initial`, its first coded tag sets the
    /// `CompositionTime` and becomes the burst baseline (D11), and POC order
    /// starts afresh. The pins persist (§6.1).
    ///
    /// Callers must call this exactly once per FLV connection, before its
    /// first tag. `VideoAdmission` does not itself refuse a coded tag that
    /// arrives without a preceding sequence header on this connection (that
    /// protection is `FlvDemuxer::NalBeforeSequenceHeader`, which only holds
    /// with a fresh `FlvDemuxer` per connection, fix round 1, m3) — it would
    /// simply admit against whatever sets the previous connection left
    /// behind.
    pub fn flv_opened(&mut self) {
        self.params.flv_opened();
        self.composition_time = None;
        self.poc.reset();
        self.burst.reset();
    }

    /// Admit one demuxed tag received at `now`. On `Err`, the caller must
    /// reopen the FLV (`flv_opened`) before admitting another tag: any
    /// in-band parameter sets the failing tag adopted before the refusal
    /// stay adopted, with no `ParamsChange` delivered for them, until the
    /// next sequence header — which is `Initial` again after a reopen
    /// (fix round 1, m6).
    pub fn admit(&mut self, tag: FlvTag, now: Instant) -> Result<Admitted, AdmissionError> {
        match tag.body {
            TagBody::Audio | TagBody::ScriptData => Ok(Admitted::default()),
            TagBody::Other(t) => Err(framing(Framing::UnknownTagType(t))),
            TagBody::Video(VideoBody::NonAvc { codec_id, .. }) => {
                Err(incompatible(Incompatible::Codec(codec_id)))
            }
            TagBody::Video(VideoBody::Enhanced { fourcc, .. }) => {
                Err(incompatible(Incompatible::Enhanced(fourcc)))
            }
            TagBody::Video(VideoBody::EndOfSequence) => Ok(Admitted {
                end_of_sequence: true,
                ..Admitted::default()
            }),
            TagBody::Video(VideoBody::SequenceHeader(cfg)) => self.sequence_header(&cfg),
            TagBody::Video(VideoBody::Nalus {
                composition_time,
                nals,
                ..
            }) => self.coded(tag.timestamp, composition_time, nals, now),
        }
    }

    fn sequence_header(&mut self, cfg: &AvcConfig) -> Result<Admitted, AdmissionError> {
        let mut sps = Vec::with_capacity(cfg.sps.len());
        for nal in &cfg.sps {
            sps.push(config_nal(nal, 7)?);
        }
        let mut pps = Vec::with_capacity(cfg.pps.len());
        for nal in &cfg.pps {
            pps.push(config_nal(nal, 8)?);
        }
        let before = self.params.snapshot();
        self.params.clear_pps();
        let mut class = None;
        for nal in &sps {
            class = strongest(class, self.params.take_sps(nal)?);
        }
        for nal in &pps {
            self.params.take_pps(nal)?;
        }
        Ok(Admitted {
            params: self.params.change(class, before),
            ..Admitted::default()
        })
    }

    /// Classify and apply every NAL in one coded tag, then check the
    /// surviving VCL NALs as one picture.
    ///
    /// Deviation (fix round 1, m1): H.264 7.4.1.2.3 makes an SPS/PPS after
    /// a tag's first slice the start of the *next* access unit, not part of
    /// this one. This tag-at-a-time admission does not split a tag at a
    /// mid-tag parameter set: it adopts it immediately and validates every
    /// slice in the tag — including slices before it — against whatever is
    /// active once the whole tag is scanned. No unchecked bytes leak (every
    /// VCL NAL that reaches the AU was parsed against the sets active when
    /// `check_picture` ran), but a source that changes parameters mid-tag
    /// sees them applied to the wrong half of the tag. No observed source
    /// in scope does this (the ES3 and x264 send sets before any slice).
    fn coded(
        &mut self,
        timestamp: u32,
        composition_time: i32,
        mut nals: Vec<Nal>,
        now: Instant,
    ) -> Result<Admitted, AdmissionError> {
        match self.composition_time {
            None => self.composition_time = Some(composition_time),
            Some(first) if first != composition_time => {
                return Err(incompatible(Incompatible::CompositionTime {
                    first,
                    now: composition_time,
                }));
            }
            Some(_) => {}
        }
        let mut before = None;
        let mut class = None;
        let mut aud = None;
        let mut dropped = 0_usize;
        let mut seen_vcl = false;
        let (mut sps_seen, mut pps_seen) = (0_usize, 0_usize);
        for n in &mut nals {
            let kept = match check_nal(&n.bytes).map_err(|e| framing(Framing::Nal(e)))? {
                NalVerdict::Drop(_) => {
                    dropped = dropped.saturating_add(1);
                    None
                }
                NalVerdict::Keep(h, bytes) => match h.nal_unit_type {
                    7 | 8 => {
                        // §6.2: 4 SPS and 16 PPS per tag (D10), checked before
                        // each costs a rewrite or a parse.
                        let seen = if h.nal_unit_type == 7 {
                            &mut sps_seen
                        } else {
                            &mut pps_seen
                        };
                        *seen = seen.saturating_add(1);
                        if sps_seen > self.max_sps || pps_seen > self.max_pps {
                            return Err(AdmissionError::from(FlvError::ParamSetCount));
                        }
                        if before.is_none() {
                            before = Some(self.params.snapshot());
                        }
                        if h.nal_unit_type == 7 {
                            class = strongest(class, self.params.take_sps(&bytes)?);
                        } else {
                            self.params.take_pps(&bytes)?;
                        }
                        None
                    }
                    9 => {
                        if seen_vcl || aud.is_some() {
                            return Err(framing(Framing::NotOnePicture));
                        }
                        aud = Some(bytes);
                        None
                    }
                    _ => {
                        seen_vcl = true;
                        Some(bytes)
                    }
                },
            };
            n.bytes = kept.unwrap_or_default();
        }
        nals.retain(|n| !n.bytes.is_empty());
        let params = match before {
            Some(b) => self.params.change(class, b),
            None => None,
        };
        let first = self.check_picture(&nals)?;
        let sps = self
            .params
            .active_sps()
            .ok_or(framing(Framing::NotOnePicture))?;
        self.poc
            .next(sps, &first)
            .map_err(|e| incompatible(Incompatible::Slice(e)))?;
        Ok(Admitted {
            params,
            au: Some(AccessUnit {
                flv_timestamp_ms: timestamp,
                idr: first.idr,
                burst: self.burst.mark(timestamp, now),
                aud,
                vcl: nals,
            }),
            end_of_sequence: false,
            dropped_nals: dropped,
        })
    }

    /// §6.1's slice checks and §6.2's one-picture rule; returns the first
    /// slice's fields.
    fn check_picture(&self, vcl: &[Nal]) -> Result<SliceInfo, AdmissionError> {
        let mut first: Option<SliceInfo> = None;
        for n in vcl {
            let s = parse_slice(self.params.ctx(), &n.bytes)
                .map_err(|e| incompatible(Incompatible::Slice(e)))?;
            match &first {
                None if s.first_mb_in_slice == 0 => first = Some(s),
                Some(f) if s.first_mb_in_slice != 0 && f.same_picture(&s) => {}
                _ => return Err(framing(Framing::NotOnePicture)),
            }
        }
        first.ok_or(framing(Framing::NotOnePicture))
    }
}

/// A config-record entry: §6.2's per-NAL checks, and its own header must say
/// `want` (7 for the SPS list, 8 for the PPS list).
fn config_nal(nal: &Bytes, want: u8) -> Result<Bytes, AdmissionError> {
    match check_nal(nal) {
        Ok(NalVerdict::Keep(h, b)) if h.nal_unit_type == want => Ok(b),
        Ok(NalVerdict::Keep(h, _) | NalVerdict::Drop(h)) => {
            Err(framing(Framing::ConfigNalType(h.nal_unit_type)))
        }
        Err(e) => Err(framing(Framing::Nal(e))),
    }
}

#[cfg(test)]
mod tests;
