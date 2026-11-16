//! §10.1's memory soak (nightly; §13: the full hour in CI only). RSS every
//! 10 s under MALLOC_ARENA_MAX=2, on its own thread; every `churn_every` a
//! churn cycle — a preempting reconnect (from the other loopback address,
//! DE14), an FLV drop, a websocket drop, a re-advertise, a resize (1080p ↔
//! 720p) and a 1 KiB paste; over minutes 5 to the end, the RSS slope
//! < 2 MiB/h and max − min < 16 MiB. The steady RSS sizes the deployment's
//! memory limit.
use crate::bridge::{Bridge, rss_kib_of};
use crate::client::{BenchClient, Opts};
use crate::scenarios::{Ctx, source_ids};
use crate::streams;
use kvm_bench::prom::Scrape;
use kvm_bench::report::Report;
use kvm_bench::stats::soak_memory;
use kvm_sim::{Fault, KvmSim, ResizeSignal, SimConfig, SimEvent};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The paste chord's make codes (`ctrl+option+shift+v`, §8) and V.
const CHORD: [u8; 3] = [0x1D, 0x38, 0x2A];
const V: u8 = 0x2F;

/// One churn step's action.
type Act<'a> = Box<dyn Fn() + 'a>;

async fn picture(c: &BenchClient, since: usize) -> bool {
    c.until(Duration::from_secs(15), |l| l.rx.len() > since + 2)
        .await
}

/// A picture of the source a resize switched to: three of its frames (by
/// FrameId) since `since` — frames of the old source still in flight never
/// count.
async fn picture_of(c: &BenchClient, since: usize, ids: &HashSet<u64>) -> bool {
    c.until(Duration::from_secs(15), |l| {
        l.rx.iter()
            .skip(since)
            .filter(|x| ids.contains(&x.frame_id))
            .count()
            > 2
    })
    .await
}

/// What the churn did, read from the bridge's own counters between the
/// soak's start and its end: numbers beside the checks, which show each
/// step reached the bridge (a session per reconnect, an upstream reconnect
/// per drop, an IDR request per Setup, an SPS change per resize).
fn footprint(r: &mut Report, before: &Scrape, after: &Scrape) {
    r.number(
        "RDP sessions started",
        after.delta(before, "kvm_rdp_sessions_total"),
    );
    for (family, label) in [
        ("kvm_rdp_upstream_reconnects_total", "reason"),
        ("kvm_rdp_idr_requests_total", "kind"),
        ("kvm_rdp_sps_changes_total", "class"),
        ("kvm_rdp_release_all_total", "trigger"),
        ("kvm_rdp_disconnects_total", "cause"),
        ("kvm_rdp_frames_dropped_total", "reason"),
    ] {
        for (value, n) in after.family_delta(before, family, label) {
            r.number(&format!("{family}{{{label}=\"{value}\"}}"), n);
        }
    }
}

async fn connect(bridge: &Bridge, source: u8, text: &str) -> Result<BenchClient, String> {
    let mut o = Opts::new(source);
    o.clipboard = Some(text.to_owned());
    let c = BenchClient::connect(bridge.rdp, o);
    if !picture(&c, 0).await {
        return Err(format!(
            "no picture from 127.0.0.{source}: {:?}",
            c.with_log(|l| l.ended.clone())
        ));
    }
    Ok(c)
}

/// The longest a churn step took to recover, in seconds, per step: numbers
/// Task 6.1 reads beside the memory (each step's oracle is its own: a
/// picture, a reopened websocket, a new source's frames, a `done` paste).
fn took(slowest: &mut BTreeMap<&'static str, f64>, what: &'static str, from: Instant, to: Instant) {
    let s = to.saturating_duration_since(from).as_secs_f64();
    let e = slowest.entry(what).or_insert(0.0);
    *e = e.max(s);
}

fn hid_reports(sim: &KvmSim) -> usize {
    sim.stamped_events()
        .iter()
        .filter(|(_, e)| matches!(e, SimEvent::Hid { .. }))
        .count()
}

/// When kvm-sim saw a websocket open after a websocket close at or after
/// `since`: the HID path's recovery from a drop (§7.3: the bridge reopens
/// at once). The video never stops for it, so a picture is no evidence of
/// it.
fn ws_reopened(sim: &KvmSim, since: Instant) -> Option<Instant> {
    let ev = sim.stamped_events();
    let closed = ev
        .iter()
        .find_map(|(t, e)| (*t >= since && matches!(e, SimEvent::WsClose { .. })).then_some(*t))?;
    ev.iter()
        .find_map(|(t, e)| (*t >= closed && matches!(e, SimEvent::WsOpen { .. })).then_some(*t))
}

/// `ws_reopened`, polled for up to 15 s.
async fn reopened(sim: &KvmSim, since: Instant) -> Option<Instant> {
    let t = Instant::now();
    loop {
        if let Some(at) = ws_reopened(sim, since) {
            return Some(at);
        }
        if t.elapsed() > Duration::from_secs(15) {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// §10.1's "VmRSS sampled every 10 s", on its own thread: a churn cycle's
/// awaits (30–90 s of connects, picture waits and the paste) never pause
/// it, so the peaks the churn causes are in the samples. Stopped and
/// joined on `finish`, or on drop whatever path `soak` leaves by.
struct Sampler {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(f64, f64)>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start(pid: u32, t0: Instant) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let (s, v) = (stop.clone(), samples.clone());
        let thread = std::thread::spawn(move || {
            let mut next = t0;
            while !s.load(Ordering::Relaxed) {
                if Instant::now() >= next {
                    if let Some(kib) = rss_kib_of(pid) {
                        v.lock()
                            .unwrap()
                            .push((t0.elapsed().as_secs_f64() / 60.0, kib as f64 / 1024.0));
                    }
                    next += Duration::from_secs(10);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Sampler {
            stop,
            samples,
            thread: Some(thread),
        }
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Stop, join, and every sample: (minutes, MiB).
    fn finish(mut self) -> Vec<(f64, f64)> {
        self.halt();
        std::mem::take(&mut *self.samples.lock().unwrap())
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.halt();
    }
}

/// `paste_events{outcome}`'s rises between two scrapes: the `done` count,
/// and every abort reason's together (`aborted_*`, whatever
/// `PASTE_ABORTS` holds). Folded from 0.0: an empty `f64` sum is -0.0,
/// which a note prints as "-0".
fn paste_outcomes(before: &Scrape, after: &Scrape) -> (f64, f64) {
    let d = after.family_delta(before, "kvm_rdp_paste_events_total", "outcome");
    let done = d.get("done").copied().unwrap_or(0.0);
    let aborted = d
        .iter()
        .filter(|(k, _)| k.starts_with("aborted"))
        .fold(0.0, |a, (_, n)| a + n);
    (done, aborted)
}

pub async fn soak(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("soak", cx.thresholds);
    // Both resize sources up front: a load error ends the run before it
    // starts, never an hour in.
    let (big_src, small_src) = (
        streams::load("bench_1080p30.h264")?,
        streams::load("bench_720p30.h264")?,
    );
    let (big_ids, small_ids): (HashSet<u64>, HashSet<u64>) = (
        source_ids(&big_src).into_iter().collect(),
        source_ids(&small_src).into_iter().collect(),
    );
    let sim = KvmSim::start(SimConfig::es3(big_src.clone()))
        .await
        .map_err(|e| e.to_string())?;
    // No re-assert within the run. Re-check after Plan D's residual fix
    // lands (pong-gated re-assert; backoff skipped once until the session
    // start): 600 s must still mean "none within the run" (pre-flight X3).
    let bridge = Bridge::spawn(&cx.bridge, &sim, "[input]\nreassert_after = \"600s\"\n")?;
    // 1 KiB of typeable text, no line break (§8).
    let text: String = "abcdefghij".chars().cycle().take(1024).collect();
    let mut source = 2u8;
    let mut client = connect(&bridge, source, &text).await?;
    let s0 = bridge.scrape().await?;
    let (t0, mut big, mut failed_steps, mut cycles) = (Instant::now(), true, 0u32, 0u32);
    let sampler = Sampler::start(bridge.pid(), t0);
    let mut next_churn = t0 + cx.churn_every;
    let mut paste_reports: Vec<f64> = Vec::new();
    let mut slowest: BTreeMap<&'static str, f64> = BTreeMap::new();
    while t0.elapsed() < cx.soak_duration {
        if Instant::now() >= next_churn {
            cycles += 1;
            next_churn += cx.churn_every;
            // 1. A preempting reconnect from the other address (DE14).
            source = if source == 2 { 3 } else { 2 };
            let at = Instant::now();
            client = match connect(&bridge, source, &text).await {
                Ok(c) => c,
                Err(e) => {
                    r.note(format!("cycle {cycles}: reconnect: {e}"));
                    failed_steps += 1;
                    continue;
                }
            };
            took(&mut slowest, "reconnect", at, Instant::now());
            // 2–4. An FLV drop, a websocket drop, a re-advertise: a picture
            // after each, and after the websocket drop its reopen.
            let steps: [(&'static str, Act<'_>, bool); 3] = [
                ("FLV drop", Box::new(|| sim.inject(Fault::Close)), false),
                ("websocket drop", Box::new(|| sim.close_websockets()), true),
                ("re-advertise", Box::new(|| client.readvertise()), false),
            ];
            for (what, act, websocket) in steps {
                let n = client.with_log(|l| l.rx.len());
                let at = Instant::now();
                act();
                if picture(&client, n).await {
                    took(&mut slowest, what, at, Instant::now());
                } else {
                    r.note(format!("cycle {cycles}: no picture after the {what}"));
                    failed_steps += 1;
                }
                if websocket {
                    if let Some(back) = reopened(&sim, at).await {
                        took(&mut slowest, "websocket reopen", at, back);
                    } else {
                        r.note(format!(
                            "cycle {cycles}: the websocket never reopened after the {what}"
                        ));
                        failed_steps += 1;
                    }
                }
            }
            // 5. A resize, 1080p ↔ 720p, as a new sequence header (§6.4).
            big = !big;
            let (next, ids) = if big {
                (&big_src, &big_ids)
            } else {
                (&small_src, &small_ids)
            };
            let n = client.with_log(|l| l.rx.len());
            let at = Instant::now();
            sim.switch_source(next.clone(), ResizeSignal::SequenceHeader);
            if picture_of(&client, n, ids).await {
                took(&mut slowest, "resize", at, Instant::now());
            } else {
                r.note(format!("cycle {cycles}: no picture after the resize"));
                failed_steps += 1;
            }
            // 6. A 1 KiB paste (§8). Its oracle is the bridge's own outcome —
            // exactly one more `done` and no abort of any reason — not a
            // count of HID reports, which also holds the modifiers, the
            // re-asserts and the releases (kept as a number). A scrape that
            // fails is a failed step, never the end of an hour's report.
            let p0 = match bridge.scrape().await {
                Ok(s) => s,
                Err(e) => {
                    r.note(format!("cycle {cycles}: /metrics before the paste: {e}"));
                    failed_steps += 1;
                    continue;
                }
            };
            let hid0 = hid_reports(&sim);
            for m in CHORD {
                client.key(m, true);
            }
            client.key(V, true);
            client.key(V, false);
            for m in CHORD {
                client.key(m, false);
            }
            let t = Instant::now();
            let (mut done, mut aborted) = (0.0, 0.0);
            while t.elapsed() <= Duration::from_secs(60) {
                if let Ok(s) = bridge.scrape().await {
                    (done, aborted) = paste_outcomes(&p0, &s);
                }
                if done >= 1.0 || aborted > 0.0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            paste_reports.push((hid_reports(&sim) - hid0) as f64);
            if done == 1.0 && aborted == 0.0 {
                took(&mut slowest, "1 KiB paste", t, Instant::now());
            } else {
                r.note(format!(
                    "cycle {cycles}: the 1 KiB paste: {done} done, {aborted} aborted within 60 s (want 1, 0)"
                ));
                failed_steps += 1;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let samples = sampler.finish();
    match bridge.scrape().await {
        Ok(s1) => footprint(&mut r, &s0, &s1),
        Err(e) => r.note(format!("/metrics at the end: {e}")),
    }
    r.number("RSS samples", samples.len() as f64);
    // §10.1: minutes 5 to the end (a short local run: its last 11/12).
    match soak_memory(&samples, cx.soak_duration.as_secs_f64() / 60.0) {
        Some(m) => {
            r.number("steady window from minute", m.from);
            if cx.soak_duration < Duration::from_secs(30 * 60) {
                // Over a few minutes a 0.1 MiB drift is already 2 MiB/h, and
                // one churn cycle moves RSS by more: the bounds are the hour's.
                r.number("RSS slope, MiB/h (minutes 5 on)", m.per_hour);
                r.number("RSS max − min, MiB (minutes 5 on)", m.range);
                r.note(
                    "short soak: slope and range are reported, not checked (§10.1's hour is the nightly's)",
                );
            } else {
                r.at_most("RSS slope, MiB/h (minutes 5 on)", m.per_hour, 2.0);
                r.at_most("RSS max − min, MiB (minutes 5 on)", m.range, 16.0);
            }
            r.number("steady RSS MiB", m.steady);
            r.number("peak RSS MiB", m.peak);
            r.number("memory limit MiB (RSS + 4 + 16, + 50 %)", m.limit);
        }
        None => r.holds("two or more RSS samples in the steady window", false),
    }
    if let Some(n) = paste_reports.iter().copied().reduce(f64::max) {
        r.number("HID reports per 1 KiB paste, most", n);
    }
    for (what, s) in slowest {
        r.number(&format!("longest recovery, s: {what}"), s);
    }
    r.at_most(
        "churn steps that did not recover",
        f64::from(failed_steps),
        0.0,
    );
    r.holds(
        "the session is alive at the end",
        client.with_log(|l| l.ended.is_none()),
    );
    r.number("churn cycles", f64::from(cycles));
    Ok(r)
}
