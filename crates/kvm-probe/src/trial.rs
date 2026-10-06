//! First-IDR latency trial (§12 Leg A, Task 5.11): FLV-open to first-IDR
//! latency, used by the CLI's 20-trial census loop (Task 13).

use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use tokio::time::Instant as TokioInstant;

use crate::capture::{open_flv, record_for};
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use crate::stats;

/// Hostile-input bound (§9.2): a peer that never sends an IDR must not be
/// used to exhaust memory. The trial stops at the first IDR; this is just
/// the backstop if one never arrives before `timeout` does.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Time from opening `av.flv` to the first FLV tag that carries an IDR NAL
/// (type 5). One deadline bounds the *whole* trial — the open (connect
/// through response headers) and every body read — so a peer that accepts
/// the connection and then stalls at any point gets a clean `KvmError`,
/// never a hang. Reads are capped at `MAX_BYTES` total.
pub async fn first_idr_latency(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    timeout: Duration,
) -> Result<Duration, KvmError> {
    first_idr_latency_capped(target, pin, token, timeout, MAX_BYTES).await
}

/// Same as `first_idr_latency`, but with an explicit byte cap instead of
/// the crate's `MAX_BYTES` constant (B12 review, fix round 1, I1): a test
/// seam so the byte-cap boundedness can be exercised without actually
/// streaming 64 MiB. `pub` so the integration-test binary can reach it;
/// `first_idr_latency` is the crate's one real entry point for callers.
pub async fn first_idr_latency_capped(
    target: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    timeout: Duration,
    max_bytes: u64,
) -> Result<Duration, KvmError> {
    let started = Instant::now();
    let now = TokioInstant::now();
    let deadline = now.checked_add(timeout).unwrap_or(now);

    let mut body = match tokio::time::timeout_at(deadline, open_flv(target, pin, token)).await {
        Err(_) => {
            return Err(KvmError::Http(format!(
                "av.flv open timed out after {timeout:?} without an IDR"
            )));
        }
        Ok(opened) => opened?,
    };

    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut total_bytes: u64 = 0;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                return Err(KvmError::Http(format!("no IDR within {timeout:?}")));
            }
            Ok(None) => return Err(KvmError::Http("av.flv stream ended before an IDR".into())),
            Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        total_bytes = total_bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if total_bytes > max_bytes {
            return Err(KvmError::Http(format!(
                "av.flv exceeded the {max_bytes}-byte cap before an IDR"
            )));
        }
        demux.push(chunk);
        while let Some(tag) = demux
            .next_tag()
            .map_err(|e| KvmError::Http(format!("{e:?}")))?
        {
            if record_for(&tag, 0).nal_types.contains(&5) {
                return Ok(started.elapsed());
            }
        }
    }
}

/// The results of a `first-idr` run (final review m7). A failed trial —
/// a timeout, a refused FLV open, a failed login — is itself census data
/// (it bears on the p95 gate), so it is recorded and the run carries on;
/// percentiles are over the successful trials only.
#[derive(Debug, Default)]
pub struct TrialReport {
    /// Latency of each successful trial, in run order.
    pub successes: Vec<Duration>,
    /// One reason per failed trial, escaped and bounded for the terminal
    /// (`kvm::bounded_debug`).
    pub failures: Vec<String>,
}

impl TrialReport {
    /// Record one trial's outcome and return its line for the operator:
    /// `"<n> ms"`, or `"failed: <bounded, escaped reason>"`.
    pub fn record(&mut self, outcome: Result<Duration, KvmError>) -> String {
        match outcome {
            Ok(d) => {
                self.successes.push(d);
                format!("{} ms", d.as_millis())
            }
            Err(e) => {
                let reason = kvm::bounded_debug(&e);
                let line = format!("failed: {reason}");
                self.failures.push(reason);
                line
            }
        }
    }

    /// `ok=<n> failed=<n> p50=<d> p95=<d>`, percentiles over the successful
    /// trials only (`n/a` when there are none).
    pub fn summary(&self) -> String {
        let pct = |p| match stats::percentile(&self.successes, p) {
            Some(d) => format!("{d:?}"),
            None => "n/a".to_string(),
        };
        format!(
            "ok={} failed={} p50={} p95={} (percentiles over successful trials only)",
            self.successes.len(),
            self.failures.len(),
            pct(50),
            pct(95)
        )
    }

    /// True when no trial succeeded (every trial failed, or none ran) —
    /// the only case in which `first-idr` exits non-zero.
    pub fn all_failed(&self) -> bool {
        self.successes.is_empty()
    }
}

/// How a `first-idr` run is paced: how many trials, each bounded by
/// `timeout`, with `pause` between consecutive trials.
#[derive(Debug, Clone)]
pub struct TrialPlan {
    pub trials: u32,
    pub timeout: Duration,
    pub pause: Duration,
}

/// The whole `first-idr` run (final review m1, as corrected): log in
/// **once** on the web port, run every trial on that one token — each
/// trial reopens `av.flv` and times FLV open → first IDR, the bridge's
/// reconnect-on-the-same-session path (a fresh login per trial could
/// itself trigger an IDR and bias the measurement) — then, only when
/// `do_logout` is true, log out **once**, best effort, also when trials
/// failed (`kvm::with_session`). `do_logout` is off by default at the CLI
/// (R21: logout is global on this KVM and would end every other open
/// session, including the vendor web UI).
///
/// A failed trial — a timeout, a refused open, the KVM rejecting the
/// token — is recorded in the report like any other and the run goes on;
/// `on_trial(n, line)` is called after each trial with its printable line.
/// The only error is a failed login (no trial can run without a token).
#[allow(clippy::too_many_arguments)] // `do_logout` (R21) pushed this past 7; all 8 are load-bearing, not a cohesive sub-struct.
pub async fn first_idr_run(
    target: &KvmTarget,
    web_pin: Option<&str>,
    video_pin: Option<&str>,
    password: &str,
    now_unix: i64,
    plan: &TrialPlan,
    do_logout: bool,
    mut on_trial: impl FnMut(u32, &str),
) -> Result<kvm::Session<TrialReport>, KvmError> {
    kvm::with_session(
        target,
        web_pin,
        password,
        now_unix,
        kvm::PROBE_TIMEZONE,
        do_logout,
        async |token: &str| {
            let mut report = TrialReport::default();
            for n in 1..=plan.trials {
                let outcome = first_idr_latency(target, video_pin, token, plan.timeout).await;
                let line = report.record(outcome);
                on_trial(n, &line);
                if n < plan.trials {
                    tokio::time::sleep(plan.pause).await;
                }
            }
            report
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// m7 (final review): a failed trial is data, not the end of the run:
    /// it is counted with a bounded, escaped reason, and the percentiles
    /// are over the successful trials only.
    #[test]
    fn failed_trials_are_counted_with_bounded_reasons_and_left_out_of_percentiles() {
        let mut r = TrialReport::default();
        let long = format!("\u{1b}[2J{}", "x".repeat(500));
        let lines = [
            r.record(Ok(Duration::from_millis(100))),
            r.record(Err(KvmError::Http("no IDR within 10s".into()))),
            r.record(Ok(Duration::from_millis(300))),
            r.record(Err(KvmError::Http(long))),
        ];
        assert_eq!(r.successes.len(), 2);
        assert_eq!(r.failures.len(), 2);
        for reason in &r.failures {
            assert!(reason.len() <= 203, "{reason}");
            assert!(!reason.chars().any(char::is_control), "{reason:?}");
        }
        let [ok1, failed1, _, failed2] = &lines;
        assert_eq!(ok1, "100 ms");
        assert!(
            failed1.starts_with("failed: ") && failed1.contains("no IDR"),
            "{failed1}"
        );
        assert!(!failed2.chars().any(char::is_control), "{failed2:?}");
        assert!(!r.all_failed());
        let summary = r.summary();
        assert!(summary.contains("ok=2 failed=2"), "{summary}");
        assert!(summary.contains("p50=100ms p95=300ms"), "{summary}");
    }

    /// m7: the run fails (non-zero exit) only when no trial succeeded.
    #[test]
    fn all_failed_only_when_no_trial_succeeded() {
        let mut r = TrialReport::default();
        assert!(r.all_failed(), "no trials, no data");
        r.record(Err(KvmError::Http("no IDR within 10s".into())));
        assert!(r.all_failed());
        r.record(Ok(Duration::from_millis(250)));
        assert!(!r.all_failed());
        assert!(r.summary().contains("ok=1 failed=1"), "{}", r.summary());
    }
}
