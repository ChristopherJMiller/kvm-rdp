//! §10.2's scenarios. Each returns a `Report`; `run` picks one by name.
use crate::bridge::{Bridge, clk_tck};
use crate::client::{BenchClient, Opts};
use crate::streams;
use kvm_bench::frames::{latencies, unique_loop};
use kvm_bench::prom::Scrape;
use kvm_bench::report::{Report, Thresholds};
use kvm_bench::stats::summarize;
use kvm_proto::h264::{frame_id, is_vcl};
use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Ctx {
    pub bridge: PathBuf,
    pub thresholds: Thresholds,
    pub soak_duration: Duration,
    pub churn_every: Duration,
}

/// The per-PR set and every scenario but the soak (§10.2). Tasks 5.2–5.4
/// add their names.
pub const CI: &[&str] = &["unshaped"];
pub const ALL: &[&str] = &["unshaped"];

pub async fn run(name: &str, cx: &Ctx) -> Result<Report, String> {
    match name {
        "unshaped" => unshaped(cx).await,
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
    // Whole-process allocations ≤ 40 + bytes/1590 per frame (alloc-stats).
    let bytes = b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_sum")
        / b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_count").max(1.0);
    if b.m.has("kvm_rdp_allocations_total") {
        let per_frame = b.m.delta(&a.m, "kvm_rdp_allocations_total") / frames.max(1.0);
        r.perf_at_most(
            "allocations per frame (whole process)",
            per_frame,
            40.0 + bytes / 1590.0,
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
