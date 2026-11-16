//! §10.2's scenarios. Each returns a `Report`; `run` picks one by name.
use crate::bridge::{Bridge, clk_tck};
use crate::client::{AckMode, BenchClient, Opts, Rx};
use crate::streams;
use kvm_bench::frames::{input_latencies, latencies, unique_loop};
use kvm_bench::prom::Scrape;
use kvm_bench::report::{Report, Thresholds};
use kvm_bench::stats::summarize;
use kvm_proto::h264::{frame_id, is_vcl};
use kvm_proto::keymap::usage_for_scancode;
use kvm_sim::{Fault, KvmSim, SimConfig, SimEvent, Source};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Ctx {
    pub bridge: PathBuf,
    pub thresholds: Thresholds,
    pub soak_duration: Duration,
    pub churn_every: Duration,
}

/// The per-PR set and every scenario but the soak (§10.2). Task 5.4 adds
/// its name.
pub const CI: &[&str] = &[
    "unshaped",
    "input-latency",
    "withhold",
    "suspended-reading",
    "panic-abort",
];
pub const ALL: &[&str] = &[
    "unshaped",
    "input-latency",
    "shaped-50ms-20mbit",
    "shaped-150ms-5mbit",
    "rtt-spike",
    "idle-motion",
    "withhold",
    "stop-reading",
    "suspended-not-reading",
    "suspended-reading",
    "panic-abort",
];

pub async fn run(name: &str, cx: &Ctx) -> Result<Report, String> {
    match name {
        "unshaped" => unshaped(cx).await,
        "input-latency" => input_latency(cx).await,
        "shaped-50ms-20mbit" => shaped(cx, "shaped-50ms-20mbit", 50, 20).await,
        "shaped-150ms-5mbit" => shaped(cx, "shaped-150ms-5mbit", 150, 5).await,
        "rtt-spike" => rtt_spike(cx).await,
        "idle-motion" => idle_motion(cx).await,
        "withhold" => stalled(cx, Stall::Withhold).await,
        "stop-reading" => stalled(cx, Stall::StopReading).await,
        "suspended-not-reading" => stalled(cx, Stall::SuspendedNotReading).await,
        "suspended-reading" => stalled(cx, Stall::SuspendedReading).await,
        "panic-abort" => panic_abort(cx).await,
        other => Err(format!("no scenario {other:?}")),
    }
}

/// A live session: kvm-sim over `cfg`, the bridge with `extra`, one client
/// with a picture.
pub struct Session {
    pub client: BenchClient,
    pub bridge: Bridge,
    pub sim: KvmSim,
}

pub async fn session(cx: &Ctx, cfg: SimConfig, extra: &str, opts: Opts) -> Result<Session, String> {
    // A KVM picture, not the "Connecting…" slate (an AVC420 frame too): a
    // frame whose FrameId is the source's, so a broken KVM leg fails here.
    let ids: std::collections::HashSet<u64> = source_ids(&cfg.source).into_iter().collect();
    let sim = KvmSim::start(cfg).await.map_err(|e| e.to_string())?;
    let bridge = Bridge::spawn(&cx.bridge, &sim, extra)?;
    let client = BenchClient::connect(bridge.rdp, opts);
    if !client
        .until(Duration::from_secs(15), |l| {
            l.rx.iter().any(|x| ids.contains(&x.frame_id))
        })
        .await
    {
        return Err(format!(
            "no KVM picture within 15 s: {:?}",
            client.with_log(|l| l.ended.clone())
        ));
    }
    Ok(Session {
        client,
        bridge,
        sim,
    })
}

/// A source's FrameIds over the VCL NALs kvm-sim sends (§10.2).
pub fn source_ids(src: &Source) -> Vec<u64> {
    src.frames
        .iter()
        .map(|f| {
            frame_id(
                f.nals
                    .iter()
                    .filter(|n| n.first().is_some_and(|b| is_vcl(b & 0x1F)))
                    .map(|n| n.as_ref()),
            )
        })
        .collect()
}

/// What kvm-sim sent, `(frame_id, sim_tx)`.
pub fn sim_sent(sim: &KvmSim) -> Vec<(u64, Instant)> {
    sim.stamped_events()
        .into_iter()
        .filter_map(|(t, e)| match e {
            SimEvent::FlvAu { frame_id, .. } => Some((frame_id, t)),
            _ => None,
        })
        .collect()
}

/// One point of a measured window.
pub struct Mark {
    pub m: Scrape,
    pub cpu: u64,
    pub at: Instant,
    pub rx: usize,
}

pub async fn mark(s: &Session) -> Result<Mark, String> {
    Ok(Mark {
        m: s.bridge.scrape().await?,
        cpu: s.bridge.cpu_ticks().ok_or("no /proc stat")?,
        at: Instant::now(),
        rx: s.client.with_log(|l| l.rx.len()),
    })
}

/// The checks every live window carries (§10.1, §10.2, PC17 m2).
pub fn window_checks(r: &mut Report, s: &Session, a: &Mark, b: &Mark) {
    // Counters and histograms always render, so a missing series is a
    // rename — which would read as 0, a silent pass or a misleading fail.
    for series in [
        "kvm_rdp_egfx_frames_sent_total",
        "kvm_rdp_egfx_frames_acked_total",
        "kvm_rdp_enqueue_latency_seconds_count",
        "kvm_rdp_kvm_frame_bytes_count",
    ] {
        r.holds(&format!("the bridge exports {series}"), b.m.has(series));
    }
    let secs = b.at.duration_since(a.at).as_secs_f64();
    let frames = b.m.delta(&a.m, "kvm_rdp_egfx_frames_sent_total");
    r.number("frames sent", frames);
    r.number("window s", secs);
    r.number(
        "channel_full drops per minute (PC17 m2)",
        b.m.delta(
            &a.m,
            "kvm_rdp_frames_dropped_total{reason=\"channel_full\"}",
        ) / secs
            * 60.0,
    );
    for (reason, n) in
        b.m.family_delta(&a.m, "kvm_rdp_frames_dropped_total", "reason")
    {
        r.number(&format!("dropped {reason}"), n);
    }
    let block = s.sim.stats().max_flv_write_block.as_secs_f64() * 1000.0;
    r.at_most(
        "max kvm-sim FLV write block, ms (§10.2: the KVM never sees back-pressure)",
        block,
        100.0,
    );
    r.holds(
        "the session is alive",
        s.client.with_log(|l| l.ended.is_none()),
    );
}

/// §10.1's unshaped targets on the 1080p30 8 Mbit/s bench stream: video
/// latency, CPU, allocations per frame, delivery, the forwarded bitrate,
/// FrameId uniqueness, and the end-to-end latency (for information).
async fn unshaped(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("unshaped", cx.thresholds);
    let src = streams::load("bench_1080p30.h264")?;
    let loop_ok = unique_loop(&source_ids(&src), 30, 10.0);
    r.holds(
        "FrameIds unique within a loop of ≥ 10 s (§10.2)",
        loop_ok.is_ok(),
    );
    if let Err(e) = loop_ok {
        r.note(e);
    }
    let s = session(cx, SimConfig::es3(src), "", Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(20)).await;
    let b = mark(&s).await?;
    // The source stops (the FLV stays open: 3 s is well under
    // flv_idle_timeout's 10 s), so 3 s on, every frame sent has been acked
    // or is lost: §10.1's "Delivery 1.0" reads as nothing left in flight.
    s.sim.inject(kvm_sim::Fault::Silence);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let c = s.bridge.scrape().await?;
    window_checks(&mut r, &s, &a, &b);
    let secs = b.at.duration_since(a.at).as_secs_f64();
    let frames = b.m.delta(&a.m, "kvm_rdp_egfx_frames_sent_total");
    // Bridge video latency p99 < 5 ms: the enqueue-latency histogram (§10.1).
    let le = if cx.thresholds == Thresholds::Strict {
        "0.005"
    } else {
        "0.05"
    };
    let under =
        b.m.fraction_le(&a.m, "kvm_rdp_enqueue_latency_seconds", le)
            .unwrap_or(0.0);
    r.at_least(
        &format!("enqueue latency: fraction ≤ {le} s (p99 < {le} s)"),
        under,
        0.99,
    );
    // CPU < 5 % of one core at 1080p30, 8 Mbit/s; and per Mbit/s.
    let cpu = (b.cpu - a.cpu) as f64 / clk_tck() / secs * 100.0;
    r.perf_at_most("CPU, % of one core", cpu, 5.0);
    // Whole-process allocations per frame (alloc-stats), §10.1's regression
    // metric. §10.1's 40 + bytes/1590 assumes one allocation per 1590-byte
    // DVC chunk; IronRDP's encode and SVC framing make about 6.2 per chunk
    // (third-party: bridge-owned code is 1.34 of 202 per frame, PE12
    // review), so the bound is the measured baseline, 70 + bytes/255, with
    // 10 % for the read side (hyper, rustls) on another machine — about 223
    // at the bench stream's mean frame. Task 6.1 restates §10.1's row.
    let bytes = b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_sum")
        / b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_count").max(1.0);
    r.number("mean KVM frame bytes", bytes);
    r.number(
        "§10.1's 40 + bytes/1590 per frame (reference)",
        40.0 + bytes / 1590.0,
    );
    if b.m.has("kvm_rdp_allocations_total") {
        let per_frame = b.m.delta(&a.m, "kvm_rdp_allocations_total") / frames.max(1.0);
        r.perf_at_most(
            "allocations per frame (whole process; baseline 1.1 × (70 + bytes/255))",
            per_frame,
            1.1 * (70.0 + bytes / 255.0),
        );
    } else {
        r.holds("the bridge is an alloc-stats build", false);
    }
    // Delivery 1.0: 3 s after the source stopped, no frame is in flight —
    // every frame the bridge sent was acked (the gauge refreshes after every
    // step). The ratio is information: the slate's ack is counted in acked,
    // never in sent.
    r.holds(
        "delivery 1.0: no frame in flight 3 s after the source stops",
        c.has("kvm_rdp_egfx_in_flight") && c.get("kvm_rdp_egfx_in_flight") == 0.0,
    );
    r.number(
        "frames acked / frames sent, window start to 3 s after the source stopped",
        c.delta(&a.m, "kvm_rdp_egfx_frames_acked_total")
            / c.delta(&a.m, "kvm_rdp_egfx_frames_sent_total").max(1.0),
    );
    // The forwarded VCL bitrate within ±10 % of 8 Mbit/s (§10.2).
    let (rx, vcl_bits) = s.client.with_log(|l| {
        let w: Vec<_> =
            l.rx.iter()
                .filter(|x| x.at >= a.at && x.at <= b.at)
                .copied()
                .collect();
        let bits: f64 = w.iter().map(|x| x.vcl_bytes as f64 * 8.0).sum();
        (w, bits)
    });
    r.within("forwarded VCL bit/s", vcl_bits / secs, 8e6, 0.10);
    r.number("CPU % per Mbit/s", cpu / (vcl_bits / secs / 1e6));
    // End to end, sim_tx → EndFrame parsed (information, §10.1).
    let got: Vec<(u64, Instant)> = rx.iter().map(|x| (x.frame_id, x.at)).collect();
    let (lat, unmatched) = latencies(&sim_sent(&s.sim), &got);
    r.at_most(
        "frames matching no kvm-sim send, fraction",
        unmatched as f64 / got.len().max(1) as f64,
        0.01,
    );
    if let Some(e) = summarize(&lat) {
        r.number("end-to-end p50 ms", e.p50);
        r.number("end-to-end p99 ms", e.p99);
    }
    Ok(r)
}

/// Set-1 make codes for a–z, cycled so consecutive presses differ.
const LETTERS: [u8; 26] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19,
    0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
];

/// §10.1: bridge input latency p99 < 5 ms — the client's input PDU written
/// → kvm-sim's HID frame read, on this process's one clock — while 1080p60
/// video with an IDR every second flows and a source burst replays every
/// 5 s (an FLV dropped under `burst_on_connect` replays the GOP so far).
async fn input_latency(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("input-latency", cx.thresholds);
    let mut cfg = SimConfig::es3(streams::load("bench_1080p60.h264")?);
    cfg.profile.fps = 60;
    cfg.profile.burst_on_connect = true;
    // No re-assert within the run (D10a). Re-check after Plan D's residual
    // fix lands (the re-assert pong-gated, the backoff skipped once until the
    // session start): 600 s must still mean "none within the run"
    // (pre-flight X3).
    let extra = "[video]\nmax_fps = 60\n[input]\nreassert_after = \"600s\"\n";
    let s = session(cx, cfg, extra, Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let a = mark(&s).await?;
    let t0 = Instant::now();
    let mut i = 0usize;
    while t0.elapsed() < Duration::from_secs(20) {
        let code = LETTERS[i % LETTERS.len()];
        s.client.key(code, true);
        tokio::time::sleep(Duration::from_millis(25)).await;
        s.client.key(code, false);
        tokio::time::sleep(Duration::from_millis(25)).await;
        if i % 100 == 99 {
            s.sim.inject(Fault::Close);
        }
        i += 1;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let presses: Vec<(u8, Instant)> = s.client.with_log(|l| {
        l.keys
            .iter()
            .filter_map(|(code, at)| Some((usage_for_scancode(*code, false)?, *at)))
            .collect()
    });
    let reports: Vec<(Instant, Vec<u8>)> = s
        .sim
        .stamped_events()
        .into_iter()
        .filter_map(|(t, e)| match e {
            SimEvent::Hid { bytes, .. } => Some((t, bytes)),
            _ => None,
        })
        .collect();
    let (lat, missed) = input_latencies(&presses, &reports);
    r.at_most("presses with no HID report", missed as f64, 0.0);
    match summarize(&lat) {
        Some(x) => {
            r.perf_at_most("input latency p99, ms", x.p99, 5.0);
            r.number("input latency p50 ms", x.p50);
            r.number("presses", x.n as f64);
        }
        None => r.holds("input latencies measured", false),
    }
    r.number(
        "burst frames",
        b.m.delta(&a.m, "kvm_rdp_burst_frames_total"),
    );
    Ok(r)
}

/// The longest gap between pictures in `[from, to]`, in ms.
fn longest_gap(rx: &[Rx], from: Instant, to: Instant) -> f64 {
    let (mut last, mut gap) = (from, 0.0f64);
    for x in rx.iter().filter(|x| x.at >= from && x.at <= to) {
        gap = gap.max(x.at.duration_since(last).as_secs_f64() * 1000.0);
        last = x.at;
    }
    gap.max(to.duration_since(last).as_secs_f64() * 1000.0)
}

/// §10.2's shaped links: acks delayed `delay_ms` and reads throttled to
/// `mbit` Mbit/s. Reported: NeedIdr entries per minute, drops by reason,
/// the longest picture gap. Checked: the session survives and kvm-sim never
/// sees back-pressure. (Task 6.1 records these numbers in rev 6.4; no
/// default changes from them — controller ruling b.)
async fn shaped(cx: &Ctx, name: &str, delay_ms: u64, mbit: u64) -> Result<Report, String> {
    let mut r = Report::new(name, cx.thresholds);
    let s = session(
        cx,
        SimConfig::es3(streams::load("bench_1080p30.h264")?),
        "",
        Opts::new(2),
    )
    .await?;
    s.client.shape(|sh| {
        sh.ack_delay = Duration::from_millis(delay_ms);
        sh.read_bps = Some(mbit * 1_000_000);
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let minutes = b.at.duration_since(a.at).as_secs_f64() / 60.0;
    r.number(
        "NeedIdr entries per minute",
        b.m.delta(&a.m, "kvm_rdp_need_idr_total") / minutes,
    );
    r.number(
        "longest picture gap, ms",
        s.client.with_log(|l| longest_gap(&l.rx, a.at, b.at)),
    );
    // What the link carried: under the source's 8 Mbit/s, the link or the
    // bridge's gates held the stream back.
    let bits: f64 = s.client.with_log(|l| {
        l.rx.iter()
            .filter(|x| x.at >= a.at && x.at <= b.at)
            .map(|x| x.vcl_bytes as f64 * 8.0)
            .sum()
    });
    r.number(
        "received VCL Mbit/s",
        bits / b.at.duration_since(a.at).as_secs_f64() / 1e6,
    );
    Ok(r)
}

/// §10.2's 2 s RTT spike: acks delayed 2 s for 3 s, then prompt again.
/// Reported: the time from the spike's end to the first picture kvm-sim
/// sent after it (time-to-picture), the longest picture gap after the
/// spike, NeedIdr entries and drops. Checked: the session survives.
async fn rtt_spike(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("rtt-spike", cx.thresholds);
    let s = session(
        cx,
        SimConfig::es3(streams::load("bench_1080p30.h264")?),
        "",
        Opts::new(2),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let a = mark(&s).await?;
    s.client.shape(|sh| sh.ack_delay = Duration::from_secs(2));
    tokio::time::sleep(Duration::from_secs(3)).await;
    s.client.shape(|sh| sh.ack_delay = Duration::ZERO);
    let spike_end = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let sent = sim_sent(&s.sim);
    let after: Vec<(u64, Instant)> = s.client.with_log(|l| {
        l.rx.iter()
            .filter(|x| x.at >= spike_end)
            .map(|x| (x.frame_id, x.at))
            .collect()
    });
    let ttp = after.iter().find_map(|(id, at)| {
        let (lat, _) = latencies(&sent, &[(*id, *at)]);
        let tx = *at - Duration::from_secs_f64(lat.first()? / 1000.0);
        (tx >= spike_end).then(|| at.duration_since(spike_end).as_secs_f64() * 1000.0)
    });
    match ttp {
        Some(ms) => r.number("time to picture after the spike, ms", ms),
        None => r.holds("a picture sent after the spike arrived", false),
    }
    // The recovery: the first picture after the spike can come while acks
    // queued in it still fall due (a FIFO link), and the gate close again.
    r.number(
        "longest picture gap after the spike, ms",
        s.client.with_log(|l| longest_gap(&l.rx, spike_end, b.at)),
    );
    r.number("NeedIdr entries", b.m.delta(&a.m, "kvm_rdp_need_idr_total"));
    Ok(r)
}

/// §10.2's idle → motion: the idle_motion stream's still 10 s, then 10 s of
/// noise, looped. The soft gate is an age gate (§14: not a frame count), so
/// the bitrate's jump must close nothing: no soft-gate drop and no NeedIdr
/// entry over two transitions.
async fn idle_motion(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("idle-motion", cx.thresholds);
    let s = session(
        cx,
        SimConfig::es3(streams::load("idle_motion_1080p30.h264")?),
        "",
        Opts::new(2),
    )
    .await?;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(22)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    r.at_most(
        "soft_gate drops across idle → motion",
        b.m.delta(&a.m, "kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"),
        0.0,
    );
    r.at_most(
        "NeedIdr entries across idle → motion",
        b.m.delta(&a.m, "kvm_rdp_need_idr_total"),
        0.0,
    );
    Ok(r)
}

/// The bridge's defaults these bounds are written in (§4.4).
const SOFT_GATE: f64 = 0.5;
const STALL_TIMEOUT: f64 = 10.0;
const WATCHDOG: f64 = 5.0;
const BACKLOG_LIMIT_MIB: f64 = 4.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stall {
    Withhold,
    StopReading,
    SuspendedNotReading,
    SuspendedReading,
}

/// When kvm-sim saw the session's websocket close after `from` — the KVM
/// side's `Stop`, which comes with the session's end (Closing's
/// `Disconnect`, or the watchdog's abort for a client that stopped reading).
fn ended_after(sim: &KvmSim, from: Instant) -> Option<Instant> {
    sim.stamped_events()
        .into_iter()
        .find_map(|(t, e)| (matches!(e, SimEvent::WsClose { .. }) && t >= from).then_some(t))
}

/// §10.1's stalled-client row, one way of stalling per run.
async fn stalled(cx: &Ctx, how: Stall) -> Result<Report, String> {
    let name = match how {
        Stall::Withhold => "withhold",
        Stall::StopReading => "stop-reading",
        Stall::SuspendedNotReading => "suspended-not-reading",
        Stall::SuspendedReading => "suspended-reading",
    };
    let mut r = Report::new(name, cx.thresholds);
    let s = session(
        cx,
        SimConfig::es3(streams::load("bench_1080p30.h264")?),
        "",
        Opts::new(2),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let m0 = s.bridge.scrape().await?;
    let t_m0 = Instant::now();
    let rss0 = s.bridge.rss_kib().ok_or("no VmRSS")?;
    let mut peak = rss0;
    // The reference instant each bound is measured from.
    let mut from = Instant::now();
    match how {
        Stall::Withhold => s.client.shape(|sh| sh.ack = AckMode::Withhold),
        Stall::StopReading => s.client.shape(|sh| sh.reading = false),
        Stall::SuspendedNotReading | Stall::SuspendedReading => {
            s.client.shape(|sh| sh.ack = AckMode::Suspend);
        }
    }
    if how == Stall::SuspendedNotReading {
        tokio::time::sleep(Duration::from_secs(2)).await;
        s.client.shape(|sh| sh.reading = false);
        // §10.1: from the backlog first reaching backlog_limit.
        let limit = BACKLOG_LIMIT_MIB * 1024.0 * 1024.0;
        let t0 = Instant::now();
        loop {
            // The instant before the scrape that shows the limit: taken
            // after it, the bound would lean toward passing by a scrape.
            let t = Instant::now();
            if s.bridge.scrape().await?.get("kvm_rdp_egfx_backlog_bytes") >= limit {
                from = t;
                break;
            }
            if t0.elapsed() > Duration::from_secs(30) {
                r.holds("the backlog reached backlog_limit", false);
                return Ok(r);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let (bound, horizon) = match how {
        Stall::Withhold | Stall::StopReading => (SOFT_GATE + STALL_TIMEOUT + WATCHDOG + 0.25, 40.0),
        Stall::SuspendedNotReading => (STALL_TIMEOUT + WATCHDOG + 0.25, 40.0),
        Stall::SuspendedReading => (f64::INFINITY, 2.0 * (STALL_TIMEOUT + WATCHDOG)),
    };
    let t0 = Instant::now();
    let mut ended = None;
    while t0.elapsed().as_secs_f64() < horizon {
        peak = peak.max(s.bridge.rss_kib().unwrap_or(peak));
        if let Some(t) = ended_after(&s.sim, from) {
            ended = Some(t);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    r.at_most(
        "RSS growth, MiB (≤ backlog_limit + 16 MiB)",
        (peak.saturating_sub(rss0)) as f64 / 1024.0,
        BACKLOG_LIMIT_MIB + 16.0,
    );
    let block = s.sim.stats().max_flv_write_block.as_secs_f64() * 1000.0;
    r.at_most("max kvm-sim FLV write block, ms", block, 100.0);
    if how == Stall::SuspendedReading {
        r.holds(
            "a client that suspends acks and keeps reading is never ended",
            ended.is_none(),
        );
        // §10.1's delivery row: "suspended runs are matched by FrameId".
        // Over the closed window [m0 + 0.5 s, m1 − 0.5 s] — a margin for a
        // frame in flight at either end — the bridge dropped no frame for
        // any reason, and every frame kvm-sim sent reached the client.
        let t_m1 = Instant::now();
        let m1 = s.bridge.scrape().await?;
        let drops = m1.family_delta(&m0, "kvm_rdp_frames_dropped_total", "reason");
        for (reason, n) in &drops {
            r.number(&format!("dropped {reason} while suspended"), *n);
        }
        r.holds(
            "no frame dropped while suspended, for any reason",
            drops.values().all(|n| *n == 0.0),
        );
        // The window stays under one 20 s loop of the bench stream, so a
        // FrameId names one frame: a lost frame cannot hide behind its copy
        // in another loop.
        let lo = t_m0 + Duration::from_millis(500);
        let hi = (t_m1 - Duration::from_millis(500)).min(lo + Duration::from_secs(15));
        let got: std::collections::HashSet<u64> = s.client.with_log(|l| {
            l.rx.iter()
                .filter(|x| x.at >= lo && x.at <= hi + Duration::from_secs(1))
                .map(|x| x.frame_id)
                .collect()
        });
        let missing = sim_sent(&s.sim)
            .iter()
            .filter(|(id, t)| *t >= lo && *t <= hi && !got.contains(id))
            .count();
        r.at_most(
            "kvm-sim frames in the window never received",
            missing as f64,
            0.0,
        );
        return Ok(r);
    }
    match ended {
        Some(t) => {
            r.timing_at_most(
                "ended after the stall began, s",
                t.duration_since(from).as_secs_f64(),
                bound,
            );
            let m1 = s.bridge.scrape().await?;
            r.at_least(
                "disconnects{client_stalled}",
                m1.delta(&m0, "kvm_rdp_disconnects_total{cause=\"client_stalled\"}"),
                1.0,
            );
        }
        None => r.holds(&format!("the session ended within {horizon} s"), false),
    }
    Ok(r)
}

/// `RLIMIT_CORE` of a live process, from `/proc/<pid>/limits` ("Max core
/// file size", soft and hard; "unlimited" reads as `u64::MAX`).
fn core_limit(pid: u32) -> Option<(u64, u64)> {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?;
    let line = limits
        .lines()
        .find_map(|l| l.strip_prefix("Max core file size"))?;
    let mut f = line.split_whitespace().map(|v| match v {
        "unlimited" => Some(u64::MAX),
        n => n.parse().ok(),
    });
    Some((f.next()??, f.next()??))
}

/// §5.2, DE7: a release build aborts on a panic. A test-hooks build's pump
/// shell panics on `[test] panic_after`, and the process dies by SIGABRT
/// with no orderly shutdown (in a debug build it would exit 1 — Task 1.1's
/// L2 case). It writes no core file: kvm-bench's `pre_exec` sets
/// `RLIMIT_CORE` 0, read back here while the bridge lives (systemd-coredump
/// still lists the crash, with no core stored). A crash never logs out of
/// the KVM (§3.2), so the bridge an orchestrator restarts logs in and
/// serves a picture against the same KVM.
async fn panic_abort(cx: &Ctx) -> Result<Report, String> {
    use std::os::unix::process::ExitStatusExt as _;
    let mut r = Report::new("panic-abort", cx.thresholds);
    let src = Source::fixture("360p30_es3like_poc0.h264").map_err(|e| format!("{e:?}"))?;
    let ids: std::collections::HashSet<u64> = source_ids(&src).into_iter().collect();
    let sim = KvmSim::start(SimConfig::es3(src))
        .await
        .map_err(|e| e.to_string())?;
    let mut b = Bridge::spawn(&cx.bridge, &sim, "[test]\npanic_after = \"1s\"\n")
        .map_err(|e| format!("{e} — is the bridge a release build with --features test-hooks?"))?;
    let core = core_limit(b.pid());
    r.holds(
        "the bridge runs with RLIMIT_CORE 0 (no core file)",
        core == Some((0, 0)),
    );
    r.number(
        "bridge pid (coredumpctl info PID: no core stored)",
        f64::from(b.pid()),
    );
    let status = b.wait(Duration::from_secs(10)).await;
    r.holds(
        "the release bridge died by SIGABRT (panic = \"abort\")",
        status.and_then(|s| s.signal()) == Some(libc::SIGABRT),
    );
    r.number(
        "WCOREDUMP (information: a core_pattern pipe sets it with no core stored)",
        if status.is_some_and(|s| s.core_dumped()) {
            1.0
        } else {
            0.0
        },
    );
    let lines = b.lines();
    r.holds(
        "the abort is the injected panic",
        lines
            .iter()
            .any(|l| l.contains("injected: the pump shell panics")),
    );
    r.holds(
        "no orderly shutdown ran",
        !lines.iter().any(|l| l.contains("\"shutting down\"")),
    );
    r.at_most("KVM logouts (§3.2)", sim.stats().logouts as f64, 0.0);
    // The restart: a bridge without the hook, on the same KVM, serves a
    // KVM picture to a client.
    drop(b);
    let again = Bridge::spawn(&cx.bridge, &sim, "")?;
    let client = BenchClient::connect(again.rdp, Opts::new(3));
    r.holds(
        "the restarted bridge serves a KVM picture within 15 s",
        client
            .until(Duration::from_secs(15), |l| {
                l.rx.iter().any(|x| ids.contains(&x.frame_id))
            })
            .await,
    );
    r.at_most(
        "KVM logouts after the restart (§3.2)",
        sim.stats().logouts as f64,
        0.0,
    );
    Ok(r)
}
