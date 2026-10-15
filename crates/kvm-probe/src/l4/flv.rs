//! `av.flv` for the L4 checks: an open that tells a stream from a refusal
//! (a 200 whose body is not FLV is a refusal, as the bridge's classifier
//! reads it, §6.9), and `concurrent-flv` (§6.5, §11.6).
use super::{FORM_BODY_MAX, RefusalForm, deadline, since};
use crate::capture::record_for;
use crate::kvm::{self, KvmError};
use crate::request::{self, KvmTarget};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, TagBody, VideoBody};
use std::time::{Duration, Instant};

/// Hostile-input bound (§9.2) on one stream.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// `concurrent-flv`'s queue of main-FLV AUs between its reader and the
/// trial loop: bounded (§9.2), and at 30 fps over two minutes of AUs, far
/// more than a pause and a trial queue up, so it never pushes back on the
/// reader in practice.
const MAIN_AU_QUEUE: usize = 4096;

pub enum FlvOpen {
    Stream(FlvStream),
    Refused(RefusalForm),
}

pub struct FlvStream {
    body: hyper::body::Incoming,
    demux: FlvDemuxer,
    bytes: u64,
    /// `MAX_BYTES` unless a check whose life is bounded by its own clock
    /// sizes it from that (`logout-watch`'s held FLV).
    max_bytes: u64,
}

/// `GET /av.flv` with `token` as query and cookie (§3.2), or with neither;
/// the open (through the first body bytes) bounded by `timeout`.
pub async fn open(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<FlvOpen, KvmError> {
    tokio::time::timeout(timeout, open_inner(t, pin, token))
        .await
        .map_err(|_| KvmError::Http(format!("av.flv open timed out after {timeout:?}")))?
}

async fn open_inner(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
) -> Result<FlvOpen, KvmError> {
    let io = kvm::connect_to(t, t.video_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .header("Host", &t.host);
    let req = match token {
        Some(tok) => req
            .uri(format!("/av.flv?token={tok}"))
            .header("Cookie", request::token_cookie_header(tok)),
        None => req.uri("/av.flv"),
    };
    let req = req
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.as_bytes().to_vec());
    let mut body = resp.into_body();
    // The first body bytes decide: FLV's signature, or a refusal.
    let mut first: Vec<u8> = Vec::new();
    while first.len() < 3 {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    first.extend_from_slice(d);
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    if status != 200 || !first.starts_with(b"FLV") {
        // A refusal: read on (still inside `open`'s timeout) until the form
        // holds FORM_BODY_MAX bytes or the body ends, so a body split over
        // frames is not cut at the first one (D14).
        while first.len() < FORM_BODY_MAX {
            match body.frame().await {
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        first.extend_from_slice(d);
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
        let shown = first
            .get(..first.len().min(FORM_BODY_MAX))
            .unwrap_or_default();
        return Ok(FlvOpen::Refused(RefusalForm::new(
            status,
            content_type.as_deref(),
            shown,
        )));
    }
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    demux.push(&first);
    Ok(FlvOpen::Stream(FlvStream {
        body,
        demux,
        bytes: u64::try_from(first.len()).unwrap_or(u64::MAX),
        max_bytes: MAX_BYTES,
    }))
}

impl FlvStream {
    /// Replace the stream's byte cap. Only for a stream whose life is
    /// already bounded by a clock: the cap stays finite, it is just sized
    /// for that life rather than cutting it short.
    pub(crate) fn set_max_bytes(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes;
    }

    /// The next tag and when it was demuxed; `None` at the end of the
    /// stream.
    pub async fn next_tag(&mut self) -> Result<Option<(Instant, FlvTag)>, KvmError> {
        loop {
            if let Some(tag) = self
                .demux
                .next_tag()
                .map_err(|e| KvmError::Http(format!("{e:?}")))?
            {
                return Ok(Some((Instant::now(), tag)));
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(KvmError::Http(e.to_string())),
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        self.bytes = self
                            .bytes
                            .saturating_add(u64::try_from(d.len()).unwrap_or(u64::MAX));
                        if self.bytes > self.max_bytes {
                            return Err(KvmError::Http(format!(
                                "av.flv passed the {}-byte cap",
                                self.max_bytes
                            )));
                        }
                        self.demux.push(d);
                    }
                }
            }
        }
    }
}

/// A coded (NALU) video tag: one access unit on the ES3 (§6.2).
#[must_use]
pub fn is_coded(tag: &FlvTag) -> bool {
    matches!(&tag.body, TagBody::Video(VideoBody::Nalus { .. }))
}

#[must_use]
pub fn is_idr(tag: &FlvTag) -> bool {
    record_for(tag, 0).nal_types.contains(&5)
}

#[derive(Debug, Clone)]
pub struct ConcurrentPlan {
    pub trials: u32,
    /// The main FLV's GOP length in frames (60 on the ES3, census Leg A).
    pub gop: u32,
    pub timeout: Duration,
    pub pause: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Served {
        first_tag_ms: u64,
        first_idr_ms: Option<u64>,
    },
    Refused(RefusalForm),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Trial {
    pub side: Side,
    /// Side open → the main FLV's next IDR.
    pub main_idr_ms: Option<u64>,
    /// That IDR came before the GOP's periodic slot: the side open forced it.
    pub forced: bool,
    /// The side's first IDR minus the main's forced IDR (a `ReconnectFlv`
    /// candidate's lag, §6.5).
    pub lag_ms: Option<i64>,
    /// Main AUs from its forced IDR up to the side's first IDR: what a
    /// swap's replay ring (64, §6.5) must hold.
    pub replay_aus: Option<u32>,
}

fn next_since(since: Option<u32>, idr: bool) -> Option<u32> {
    if idr {
        Some(0)
    } else {
        since.map(|s| s.saturating_add(1))
    }
}

fn signed_ms(from: Instant, to: Instant) -> i64 {
    let ahead = i64::try_from(since(from, to)).unwrap_or(i64::MAX);
    let behind = i64::try_from(since(to, from)).unwrap_or(i64::MAX);
    ahead.saturating_sub(behind)
}

async fn side_probe(
    t: KvmTarget,
    pin: Option<String>,
    token: String,
    timeout: Duration,
    t0: Instant,
) -> (Side, Option<Instant>) {
    let mut stream = match open(&t, pin.as_deref(), Some(&token), timeout).await {
        Ok(FlvOpen::Stream(s)) => s,
        Ok(FlvOpen::Refused(f)) => return (Side::Refused(f), None),
        Err(e) => return (Side::Failed(kvm::bounded_debug(&e)), None),
    };
    let until = deadline(timeout);
    let (mut first_tag, mut first_idr) = (None, None);
    while first_idr.is_none() {
        match tokio::time::timeout_at(until, stream.next_tag()).await {
            Ok(Ok(Some((at, tag)))) => {
                first_tag.get_or_insert(at);
                if is_coded(&tag) && is_idr(&tag) {
                    first_idr = Some(at);
                }
            }
            _ => break,
        }
    }
    // Dropping the stream closes the side FLV, as the bridge's does (§6.5).
    match first_tag {
        Some(ft) => (
            Side::Served {
                first_tag_ms: since(t0, ft),
                first_idr_ms: first_idr.map(|i| since(t0, i)),
            },
            first_idr,
        ),
        None => (Side::Failed("no tag before the timeout".to_owned()), None),
    }
}

/// `concurrent-flv`: one main FLV on `token`; per trial, wait until the
/// main is 10–20 frames into its GOP (so a forced IDR cannot be the
/// periodic one), open a side FLV on the same token, read it to its first
/// IDR and close it, and time the main's next IDR.
pub async fn concurrent_flv(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    plan: &ConcurrentPlan,
    mut on_trial: impl FnMut(u32, &Trial),
) -> Result<Vec<Trial>, KvmError> {
    let FlvOpen::Stream(mut main) = open(t, pin, Some(token), plan.timeout).await? else {
        return Err(KvmError::Http("the main av.flv was refused".to_owned()));
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Instant, bool)>(MAIN_AU_QUEUE);
    let reader = tokio::spawn(async move {
        while let Ok(Some((at, tag))) = main.next_tag().await {
            if is_coded(&tag) && tx.send((at, is_idr(&tag))).await.is_err() {
                break;
            }
        }
    });
    let mut trials = Vec::new();
    let mut since_idr: Option<u32> = None;
    for n in 1..=plan.trials {
        // D7b: the AUs that queued during the pause are history — count
        // them into `since_idr`, then wait for a live AU in the window, with
        // nothing still queued behind it, so `t0` is "now" in GOP terms.
        while let Ok((_, idr)) = rx.try_recv() {
            since_idr = next_since(since_idr, idr);
        }
        let window_until = deadline(plan.timeout.saturating_mul(3));
        let in_window = loop {
            match tokio::time::timeout_at(window_until, rx.recv()).await {
                Ok(Some((_, idr))) => {
                    since_idr = next_since(since_idr, idr);
                    if since_idr.is_some_and(|s| (10..=20).contains(&s)) && rx.is_empty() {
                        break true;
                    }
                }
                _ => break false,
            }
        };
        if !in_window {
            reader.abort();
            return Err(KvmError::Http(
                "the main av.flv stopped before a trial window".to_owned(),
            ));
        }
        let t0 = Instant::now();
        let side = tokio::spawn(side_probe(
            t.clone(),
            pin.map(str::to_owned),
            token.to_owned(),
            plan.timeout,
            t0,
        ));
        let mut main_aus: Vec<(Instant, bool)> = Vec::new();
        let mut main_idr: Option<(Instant, u32)> = None;
        let until = deadline(plan.timeout);
        while main_idr.is_none() {
            match tokio::time::timeout_at(until, rx.recv()).await {
                Ok(Some((at, idr))) => {
                    main_aus.push((at, idr));
                    // An AU received before `t0` can never be the IDR this
                    // side open forced (D7b).
                    if idr && at >= t0 {
                        let frames = since_idr.map_or(0, |s| s.saturating_add(1));
                        main_idr = Some((at, frames));
                    }
                    since_idr = next_since(since_idr, idr);
                }
                _ => break,
            }
        }
        let (side, side_idr) = side
            .await
            .unwrap_or_else(|e| (Side::Failed(format!("side task: {e}")), None));
        while let Ok((at, idr)) = rx.try_recv() {
            main_aus.push((at, idr));
            since_idr = next_since(since_idr, idr);
        }
        let paired = side_idr.zip(main_idr);
        let trial = Trial {
            main_idr_ms: main_idr.map(|(at, _)| since(t0, at)),
            forced: main_idr.is_some_and(|(_, frames)| frames < plan.gop.saturating_sub(2)),
            lag_ms: paired.map(|(s, (m, _))| signed_ms(m, s)),
            replay_aus: paired.map(|(s, (m, _))| {
                let n = main_aus
                    .iter()
                    .filter(|(at, _)| *at >= m && *at < s)
                    .count();
                u32::try_from(n).unwrap_or(u32::MAX)
            }),
            side,
        };
        on_trial(n, &trial);
        trials.push(trial);
        tokio::time::sleep(plan.pause).await;
    }
    reader.abort();
    Ok(trials)
}

/// One line for census.md: served/refused/failed, forced, the forced
/// trials' side → main IDR p50/p95, the lag's range and the most AUs a
/// replay would hold.
#[must_use]
pub fn summary(trials: &[Trial]) -> String {
    let count = |f: fn(&Side) -> bool| trials.iter().filter(|t| f(&t.side)).count();
    let served = count(|s| matches!(s, Side::Served { .. }));
    let refused = count(|s| matches!(s, Side::Refused(_)));
    let failed = count(|s| matches!(s, Side::Failed(_)));
    let forced: Vec<Duration> = trials
        .iter()
        .filter(|t| t.forced)
        .filter_map(|t| t.main_idr_ms.map(Duration::from_millis))
        .collect();
    let pct = |p| {
        crate::stats::percentile(&forced, p)
            .map_or("n/a".to_owned(), |d| format!("{} ms", d.as_millis()))
    };
    let lags: Vec<i64> = trials.iter().filter_map(|t| t.lag_ms).collect();
    let replay = trials.iter().filter_map(|t| t.replay_aus).max();
    format!(
        "trials={} served={served} refused={refused} failed={failed} forced={} side->main IDR p50={} p95={} lag_ms min={:?} max={:?} replay_aus max={:?}",
        trials.len(),
        forced.len(),
        pct(50),
        pct(95),
        lags.iter().min(),
        lags.iter().max(),
        replay
    )
}
