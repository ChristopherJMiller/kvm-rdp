//! The bridge's metrics (spec §10.4), rendered as Prometheus text for
//! `/metrics` (§4.5). Label values are `&'static str` from bridge code —
//! never device or client text.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

pub struct Counter {
    name: &'static str,
    help: &'static str,
    v: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Counter {
        Counter {
            name,
            help,
            v: AtomicU64::new(0),
        }
    }
    pub fn inc(&self) {
        self.add(1);
    }
    pub fn add(&self, n: u64) {
        self.v.fetch_add(n, Ordering::Relaxed);
    }
    #[must_use]
    pub fn get(&self) -> u64 {
        self.v.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(
            out,
            "# HELP {0}_total {1}\n# TYPE {0}_total counter\n{0}_total {2}\n",
            self.name,
            self.help,
            self.get()
        );
    }
}

/// One counter whose value lives outside `Metrics` (a process-wide static):
/// rendered like `Counter`.
pub(crate) fn render_value_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = write!(
        out,
        "# HELP {name}_total {help}\n# TYPE {name}_total counter\n{name}_total {value}\n"
    );
}

pub struct Gauge {
    name: &'static str,
    help: &'static str,
    v: AtomicI64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Gauge {
        Gauge {
            name,
            help,
            v: AtomicI64::new(0),
        }
    }
    pub fn set(&self, v: i64) {
        self.v.store(v, Ordering::Relaxed);
    }
    #[must_use]
    pub fn get(&self) -> i64 {
        self.v.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(
            out,
            "# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n",
            self.name,
            self.help,
            self.get()
        );
    }
}

/// A counter with one label.
pub struct Family {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    v: Mutex<BTreeMap<&'static str, u64>>,
}

impl Family {
    const fn new(name: &'static str, help: &'static str, label: &'static str) -> Family {
        Family {
            name,
            help,
            label,
            v: Mutex::new(BTreeMap::new()),
        }
    }
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, u64>> {
        self.v
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn inc(&self, value: &'static str) {
        self.add(value, 1);
    }
    pub fn add(&self, value: &'static str, n: u64) {
        let mut m = self.map();
        let e = m.entry(value).or_insert(0);
        *e = e.saturating_add(n);
    }
    #[must_use]
    pub fn get(&self, value: &str) -> u64 {
        self.map().get(value).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn total(&self) -> u64 {
        self.map().values().fold(0, |a, b| a.saturating_add(*b))
    }
    fn render(&self, out: &mut String) {
        let _ = write!(
            out,
            "# HELP {0}_total {1}\n# TYPE {0}_total counter\n",
            self.name, self.help
        );
        for (k, v) in self.map().iter() {
            let _ = writeln!(out, "{}_total{{{}=\"{k}\"}} {v}", self.name, self.label);
        }
    }
}

/// Bucket bounds, in the histogram's unit.
const LATENCY: &[f64] = &[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.05, 0.25, 1.0];
const FRAME_BYTES: &[f64] = &[
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
];
const INTER_ARRIVAL: &[f64] = &[0.01, 0.02, 0.03, 0.035, 0.04, 0.05, 0.1, 0.25, 1.0];
const ACK_RTT: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];
const QOE_DECODE: &[f64] = &[0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25];

/// What a histogram measures: which `observe` it takes and its `_sum`'s unit.
#[derive(Clone, Copy)]
enum Unit {
    Seconds,
    Bytes,
}

pub struct Histogram {
    name: &'static str,
    help: &'static str,
    bounds: &'static [f64],
    unit: Unit,
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    /// Microseconds (`Seconds`) or bytes (`Bytes`).
    sum: AtomicU64,
}

impl Histogram {
    fn new(
        name: &'static str,
        help: &'static str,
        bounds: &'static [f64],
        unit: Unit,
    ) -> Histogram {
        Histogram {
            name,
            help,
            bounds,
            unit,
            buckets: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
        }
    }
    /// A duration (a seconds histogram).
    pub fn observe(&self, d: Duration) {
        self.record(
            d.as_secs_f64(),
            u64::try_from(d.as_micros()).unwrap_or(u64::MAX),
        );
    }
    /// A byte count (a bytes histogram).
    pub fn observe_bytes(&self, n: u64) {
        self.record(f64::from(u32::try_from(n).unwrap_or(u32::MAX)), n);
    }
    fn record(&self, v: f64, sum: u64) {
        if let Some(i) = self.bounds.iter().position(|&b| v <= b)
            && let Some(b) = self.buckets.get(i)
        {
            b.fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(sum, Ordering::Relaxed);
    }
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(
            out,
            "# HELP {0} {1}\n# TYPE {0} histogram\n",
            self.name, self.help
        );
        let mut cumulative = 0u64;
        for (bound, b) in self.bounds.iter().zip(self.buckets.iter()) {
            cumulative = cumulative.saturating_add(b.load(Ordering::Relaxed));
            let _ = writeln!(out, "{}_bucket{{le=\"{bound}\"}} {cumulative}", self.name);
        }
        let count = self.count();
        let raw = self.sum.load(Ordering::Relaxed);
        let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {count}", self.name);
        let _ = match self.unit {
            Unit::Seconds => writeln!(
                out,
                "{}_sum {}",
                self.name,
                Duration::from_micros(raw).as_secs_f64()
            ),
            Unit::Bytes => writeln!(out, "{}_sum {raw}", self.name),
        };
        let _ = writeln!(out, "{}_count {count}", self.name);
    }
}

/// §10.4 (Plan D final review m1): `paste_events`' abort labels, one per
/// reason the input core gives (`rdp::input::abort_label`).
pub const PASTE_ABORTS: [&str; 8] = [
    "aborted_esc",
    "aborted_key",
    "aborted_mouse",
    "aborted_release",
    "aborted_modifier_wait",
    "aborted_clipboard_failed",
    "aborted_clipboard_lost",
    "aborted_session",
];

pub struct Metrics {
    pub flv_bytes: Counter,
    pub flv_tags: Counter,
    pub frames: Family,
    pub frame_bytes: Histogram,
    pub inter_arrival: Histogram,
    pub kvm_fps: Gauge,
    pub parse_errors: Family,
    pub upstream_reconnects: Family,
    pub logins: Counter,
    pub relogins: Counter,
    pub idr_requests: Family,
    pub idr_side_failures: Family,
    pub idr_side_fallbacks: Counter,
    pub idr_cancelled: Counter,
    pub sps_rewrites: Family,
    pub sps_changes: Family,
    pub bursts: Counter,
    pub frames_sent: Counter,
    pub frames_acked: Counter,
    pub frames_dropped: Family,
    pub enqueue_latency: Histogram,
    pub ack_rtt: Histogram,
    pub qoe_decode: Histogram,
    pub egfx_in_flight: Gauge,
    pub egfx_backlog_bytes: Gauge,
    pub egfx_ack_suspended: Gauge,
    pub egfx_oldest_unacked_ms: Gauge,
    pub autodetect_rtt_ms: Gauge,
    pub standing_delay_ms: Gauge,
    pub egfx_capability_version: Gauge,
    pub hid_reports_sent: Counter,
    pub hid_reports_coalesced: Counter,
    pub hid_resyncs: Counter,
    pub hid_epoch_discards: Counter,
    /// PC9 fix 2: full-state re-asserts once a websocket (re)open settles.
    pub hid_reasserts: Counter,
    pub release_all: Family,
    pub sessions: Counter,
    pub disconnects: Family,
    pub accept_refused: Counter,
    pub input_events_ignored: Counter,
    /// §8: every paste's outcome (`started`, `done`, `no_text`,
    /// `caps_lock`, `multiline`, `oversize`, `backlog`, and an abort under
    /// its reason, `PASTE_ABORTS`; final review m1).
    pub paste_events: Family,
    pub paste_skipped_chars: Counter,
    /// PD9 carry 3: clipboard answers no paste took (`late`, `unasked`), or
    /// that the backend dropped while another was in flight (`in_flight`);
    /// and requests retired with no answer (`unanswered`, I2).
    pub clipboard_discarded: Family,
    /// I2 (Plan D final review): the release websocket a session end opens
    /// when the KVM did not prove it released (`confirmed`, `unconfirmed`,
    /// `failed`, `superseded`; `hid::release`).
    pub release_websockets: Family,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            flv_bytes: Counter::new(
                "kvm_rdp_flv_bytes",
                "FLV bytes read from the KVM (main stream)",
            ),
            flv_tags: Counter::new("kvm_rdp_flv_tags", "FLV tags demuxed (main stream)"),
            frames: Family::new(
                "kvm_rdp_kvm_frames",
                "Access units admitted, by type",
                "type",
            ),
            frame_bytes: Histogram::new(
                "kvm_rdp_kvm_frame_bytes",
                "VCL bytes per admitted access unit",
                FRAME_BYTES,
                Unit::Bytes,
            ),
            inter_arrival: Histogram::new(
                "kvm_rdp_kvm_inter_arrival_seconds",
                "Time between admitted access units on one FLV connection",
                INTER_ARRIVAL,
                Unit::Seconds,
            ),
            kvm_fps: Gauge::new(
                "kvm_rdp_kvm_fps",
                "Access units admitted per second, over the last whole second",
            ),
            parse_errors: Family::new("kvm_rdp_parse_errors", "Framing violations (§6.9)", "kind"),
            upstream_reconnects: Family::new(
                "kvm_rdp_upstream_reconnects",
                "KVM reconnects by reason",
                "reason",
            ),
            logins: Counter::new("kvm_rdp_kvm_logins", "Successful KVM logins"),
            relogins: Counter::new("kvm_rdp_kvm_relogins", "Re-logins after an auth failure"),
            idr_requests: Family::new("kvm_rdp_idr_requests", "IDR requests by mechanism", "kind"),
            idr_side_failures: Family::new(
                "kvm_rdp_idr_side_failures",
                "Side-FLV failures by kind",
                "kind",
            ),
            idr_side_fallbacks: Counter::new(
                "kvm_rdp_idr_side_fallbacks",
                "Side requests that fell back to a reconnect",
            ),
            idr_cancelled: Counter::new("kvm_rdp_idr_cancelled", "Deferred IDR requests cancelled"),
            sps_rewrites: Family::new(
                "kvm_rdp_sps_rewrites",
                "SPS rewrites by field (§6.8)",
                "field",
            ),
            sps_changes: Family::new("kvm_rdp_sps_changes", "SpsChanged by class", "class"),
            bursts: Counter::new("kvm_rdp_burst_frames", "Access units marked burst"),
            frames_sent: Counter::new("kvm_rdp_egfx_frames_sent", "KVM frames handed to IronRDP"),
            frames_acked: Counter::new("kvm_rdp_egfx_frames_acked", "EGFX frame acknowledgements"),
            frames_dropped: Family::new(
                "kvm_rdp_frames_dropped",
                "Frames dropped by reason (§10.4)",
                "reason",
            ),
            enqueue_latency: Histogram::new(
                "kvm_rdp_enqueue_latency_seconds",
                "Tag parsed to ServerEvent enqueued",
                LATENCY,
                Unit::Seconds,
            ),
            ack_rtt: Histogram::new(
                "kvm_rdp_egfx_ack_rtt_seconds",
                "Frame handed to IronRDP to its FrameAcknowledge",
                ACK_RTT,
                Unit::Seconds,
            ),
            qoe_decode: Histogram::new(
                "kvm_rdp_egfx_qoe_decode_seconds",
                "Client-reported decode and render time (QoE, V10+)",
                QOE_DECODE,
                Unit::Seconds,
            ),
            egfx_in_flight: Gauge::new(
                "kvm_rdp_egfx_in_flight",
                "EGFX frames awaiting acknowledgement",
            ),
            egfx_backlog_bytes: Gauge::new(
                "kvm_rdp_egfx_backlog_bytes",
                "Handed minus written EGFX bytes",
            ),
            egfx_ack_suspended: Gauge::new(
                "kvm_rdp_egfx_ack_suspended",
                "1 while the client suspends acks",
            ),
            egfx_oldest_unacked_ms: Gauge::new(
                "kvm_rdp_egfx_oldest_unacked_ms",
                "Age of the oldest unacked frame",
            ),
            autodetect_rtt_ms: Gauge::new(
                "kvm_rdp_autodetect_rtt_ms",
                "Last live auto-detect RTT sample",
            ),
            standing_delay_ms: Gauge::new(
                "kvm_rdp_standing_delay_ms",
                "Standing delay estimate (§6.6)",
            ),
            egfx_capability_version: Gauge::new(
                "kvm_rdp_egfx_capability_version",
                "Negotiated EGFX capability version",
            ),
            hid_reports_sent: Counter::new(
                "kvm_rdp_hid_reports_sent",
                "HID frames written to the websocket",
            ),
            hid_reports_coalesced: Counter::new(
                "kvm_rdp_hid_reports_coalesced",
                "Motion reports replaced in the queue",
            ),
            hid_resyncs: Counter::new("kvm_rdp_hid_resyncs", "Full-queue resyncs"),
            hid_epoch_discards: Counter::new(
                "kvm_rdp_hid_epoch_discards",
                "Reports discarded by a release epoch",
            ),
            hid_reasserts: Counter::new(
                "kvm_rdp_hid_reasserts",
                "Full-state re-asserts after a reconnect",
            ),
            release_all: Family::new(
                "kvm_rdp_release_all",
                "Release-all by trigger (§7.4)",
                "trigger",
            ),
            sessions: Counter::new("kvm_rdp_sessions", "Authenticated RDP sessions started"),
            disconnects: Family::new(
                "kvm_rdp_disconnects",
                "Bridge-initiated disconnects by cause",
                "cause",
            ),
            accept_refused: Counter::new(
                "kvm_rdp_accept_refused",
                "TCP connections refused by on_accept",
            ),
            input_events_ignored: Counter::new(
                "kvm_rdp_input_events_ignored",
                "Client input events dropped: unmapped, untypeable or past a bound (DD7, DD9)",
            ),
            paste_events: Family::new("kvm_rdp_paste_events", "Paste outcomes (§8)", "outcome"),
            paste_skipped_chars: Counter::new(
                "kvm_rdp_paste_skipped_chars",
                "Characters pastes skipped as untypeable (§8)",
            ),
            clipboard_discarded: Family::new(
                "kvm_rdp_clipboard_discarded",
                "Clipboard answers no paste took, by reason",
                "reason",
            ),
            release_websockets: Family::new(
                "kvm_rdp_release_websockets",
                "Release websockets after a session end the KVM did not prove released",
                "outcome",
            ),
        }
    }
}

impl Metrics {
    /// Every paste abort counted, whatever its reason (`PASTE_ABORTS`).
    #[must_use]
    pub fn paste_aborts(&self) -> u64 {
        PASTE_ABORTS
            .iter()
            .chain(&["aborted"])
            .fold(0, |n, l| n.saturating_add(self.paste_events.get(l)))
    }

    /// The Prometheus text exposition (version 0.0.4).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(12 * 1024);
        for c in [
            &self.flv_bytes,
            &self.flv_tags,
            &self.logins,
            &self.relogins,
            &self.idr_side_fallbacks,
            &self.idr_cancelled,
            &self.bursts,
            &self.frames_sent,
            &self.frames_acked,
            &self.hid_reports_sent,
            &self.hid_reports_coalesced,
            &self.hid_resyncs,
            &self.hid_epoch_discards,
            &self.hid_reasserts,
            &self.sessions,
            &self.accept_refused,
            &self.input_events_ignored,
            &self.paste_skipped_chars,
        ] {
            c.render(&mut out);
        }
        render_value_counter(
            &mut out,
            "kvm_rdp_log_lines_suppressed",
            "Third-party log lines past their callsite's limit (§4.5, rev 6.4)",
            crate::logging::suppressed(),
        );
        for f in [
            &self.frames,
            &self.parse_errors,
            &self.upstream_reconnects,
            &self.idr_requests,
            &self.idr_side_failures,
            &self.sps_rewrites,
            &self.sps_changes,
            &self.frames_dropped,
            &self.release_all,
            &self.disconnects,
            &self.paste_events,
            &self.clipboard_discarded,
            &self.release_websockets,
        ] {
            f.render(&mut out);
        }
        for g in [
            &self.kvm_fps,
            &self.egfx_in_flight,
            &self.egfx_backlog_bytes,
            &self.egfx_ack_suspended,
            &self.egfx_oldest_unacked_ms,
            &self.autodetect_rtt_ms,
            &self.standing_delay_ms,
            &self.egfx_capability_version,
        ] {
            g.render(&mut out);
        }
        for h in [
            &self.frame_bytes,
            &self.inter_arrival,
            &self.enqueue_latency,
            &self.ack_rtt,
            &self.qoe_decode,
        ] {
            h.render(&mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;

    #[test]
    fn counters_families_gauges_and_the_histograms_render() {
        let m = Metrics::default();
        m.sessions.inc();
        m.frames_dropped.inc("soft_gate");
        m.frames_dropped.inc("soft_gate");
        m.frames_dropped.inc("paused");
        m.egfx_in_flight.set(7);
        m.enqueue_latency.observe(Duration::from_micros(300));
        m.enqueue_latency.observe(Duration::from_millis(3));
        m.frame_bytes.observe_bytes(3000);
        let t = m.render();
        assert!(
            t.contains("# TYPE kvm_rdp_sessions_total counter\nkvm_rdp_sessions_total 1\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 2\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_frames_dropped_total{reason=\"paused\"} 1\n"),
            "{t}"
        );
        assert!(
            t.contains("# TYPE kvm_rdp_egfx_in_flight gauge\nkvm_rdp_egfx_in_flight 7\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.0005\"} 1\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 2\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"+Inf\"} 2\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_enqueue_latency_seconds_count 2\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_kvm_frame_bytes_bucket{le=\"1024\"} 0\n"),
            "{t}"
        );
        assert!(
            t.contains("kvm_rdp_kvm_frame_bytes_bucket{le=\"4096\"} 1\n"),
            "{t}"
        );
        assert!(t.contains("kvm_rdp_kvm_frame_bytes_sum 3000\n"), "{t}");
        assert_eq!(m.frames_dropped.get("soft_gate"), 2);
        assert_eq!(m.frames_dropped.total(), 3);
    }

    #[test]
    fn every_metric_name_is_unique_and_well_formed() {
        let t = Metrics::default().render();
        let names: Vec<&str> = t
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        assert_eq!(
            names.len(),
            45,
            "19 counters, 13 families, 8 gauges, 5 histograms"
        );
        assert!(t.contains("# TYPE kvm_rdp_log_lines_suppressed_total counter\n"));
        assert!(t.contains("# TYPE kvm_rdp_hid_reasserts_total counter\n"));
        assert!(t.contains("# TYPE kvm_rdp_release_websockets_total counter\n"));
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate metric name");
        for n in names {
            assert!(n.starts_with("kvm_rdp_"), "{n}");
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{n}"
            );
        }
    }
}
