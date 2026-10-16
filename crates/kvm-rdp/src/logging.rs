//! Logging (spec §4.5): `tracing` JSON lines on stdout. `log.filter` is one
//! `EnvFilter` (parsed from config, never from `RUST_LOG`); a second,
//! independent `Targets` filter holds the libraries that log credentials or
//! payloads at INFO (and those whose WARNs carry client-chosen data at
//! ERROR), combined with `FilterExt::and`, so nothing in config can raise
//! them. Third-party lines are also limited per callsite (rev 6.4, DE5).
//! Bridge code logs no keystrokes, HID frames, pasted text,
//! tokens or passwords, and no per-frame event above `trace`.
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::callsite::Identifier;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{EnvFilter, FilterExt as _, LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt as _};

/// Targets held at INFO whatever `log.filter` says: sspi and the acceptor
/// log NTLM tokens at debug, `ironrdp_server` traces every event, and the
/// websocket/HTTP/TLS stacks trace payloads (§4.5). Prefix matches, plus the
/// IronRDP crates spelled out.
pub const CAPPED_TARGETS: &[&str] = &[
    "ironrdp",
    "ironrdp_server",
    "ironrdp_acceptor",
    "ironrdp_connector",
    "ironrdp_egfx",
    "ironrdp_dvc",
    "ironrdp_svc",
    "ironrdp_pdu",
    "ironrdp_tokio",
    "ironrdp_async",
    "ironrdp_displaycontrol",
    "ironrdp_graphics",
    "sspi",
    "picky",
    "picky_krb",
    "tungstenite",
    "tokio_tungstenite",
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tokio_rustls",
];

/// Targets held at ERROR whatever `log.filter` says (PD8 review m4): their
/// WARNs carry client-chosen data — ironrdp-cliprdr's file-list sanitiser
/// logs the client's file names — and fire once per hostile PDU, so a
/// client could flood them. The more specific target wins over
/// `CAPPED_TARGETS`' `ironrdp` prefix.
pub const ERROR_CAPPED_TARGETS: &[&str] = &["ironrdp_cliprdr"];

/// Rev 6.4 (PD8 m4, DE5): a third-party callsite logs its first event, then
/// at most one per this interval; the rest are counted in
/// `kvm_rdp_log_lines_suppressed_total`. IronRDP warns once per PDU where
/// an authenticated client chooses the PDUs ("Unexpected channel
/// received"), so a level cap alone still lets a client flood the log.
pub const THIRD_PARTY_INTERVAL: Duration = Duration::from_secs(10);

/// Lines the per-callsite limit dropped, process-wide (`/metrics`).
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Third-party lines dropped so far by the per-callsite limit.
#[must_use]
pub fn suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// Bridge code is never limited: where a peer drives its lines they are
/// already bounded (DC15's refusal line, §4.5).
fn third_party(target: &str) -> bool {
    !(target == "kvm_rdp" || target.starts_with("kvm_rdp::"))
}

/// The limit: one `Instant` per third-party callsite that has logged — a
/// map bounded by the binary's callsites, not by what a peer sends.
struct PerCallsite {
    interval: Duration,
    last: Mutex<HashMap<Identifier, Instant>>,
    dropped: &'static AtomicU64,
}

/// `callsite_enabled` keeps its default, `sometimes`, on purpose: a filter
/// whose `event_enabled` can refuse needs `enabled` to run before every
/// event. With `always`, tracing-subscriber 0.3.23 skips `enabled`, so the
/// per-layer state a refusal leaves behind is never re-armed and the
/// thread's next event at an `always` callsite would be dropped unseen
/// (a debug assertion in `FilterState::event_enabled` catches it).
impl<S> Filter<S> for PerCallsite {
    /// Every callsite stays eligible; the level filters it is `and`ed
    /// after decide what reaches `event_enabled`.
    fn enabled(&self, _: &tracing::Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    /// No level opinion of its own: `And` takes the minimum of the hints,
    /// in which `None` wins, so `None` here would raise
    /// `LevelFilter::current()` to TRACE and make every skipped `trace!`
    /// pay an interest check.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    /// Called for an event the level filters let through, just before it
    /// is written: the per-callsite decision, and the count.
    fn event_enabled(&self, event: &tracing::Event<'_>, _: &Context<'_, S>) -> bool {
        let meta = event.metadata();
        if !third_party(meta.target()) {
            return true;
        }
        let now = Instant::now();
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match last.get(&meta.callsite()) {
            Some(t) if now.saturating_duration_since(*t) < self.interval => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            _ => {
                last.insert(meta.callsite(), now);
                true
            }
        }
    }
}

#[derive(Debug)]
pub struct LogError(pub String);

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "logging: {}", self.0)
    }
}

impl std::error::Error for LogError {}

/// The bridge's subscriber writing to `writer` (tests pass a buffer).
pub fn subscriber<W>(
    filter: &str,
    writer: W,
) -> Result<impl tracing::Subscriber + Send + Sync + 'static, LogError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    subscriber_limited(filter, writer, THIRD_PARTY_INTERVAL, &SUPPRESSED)
}

/// `subscriber` with the per-callsite limit's `interval` and the counter
/// its dropped lines go to (a test's own, so tests in one process never
/// see each other's counts).
fn subscriber_limited<W>(
    filter: &str,
    writer: W,
    interval: Duration,
    dropped: &'static AtomicU64,
) -> Result<impl tracing::Subscriber + Send + Sync + 'static, LogError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let user = EnvFilter::builder()
        .parse(filter)
        .map_err(|e| LogError(format!("log.filter: {e}")))?;
    let cap = CAPPED_TARGETS
        .iter()
        .map(|name| (*name, LevelFilter::INFO))
        .chain(
            ERROR_CAPPED_TARGETS
                .iter()
                .map(|name| (*name, LevelFilter::ERROR)),
        )
        .fold(
            Targets::new().with_default(LevelFilter::TRACE),
            |t, (name, level)| t.with_target(name, level),
        );
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(user.and(cap).and(PerCallsite {
            interval,
            last: Mutex::default(),
            dropped,
        }));
    Ok(tracing_subscriber::registry().with(layer))
}

/// Install the subscriber process-wide, writing to stdout.
pub fn init(filter: &str) -> Result<(), LogError> {
    let sub = subscriber(filter, std::io::stdout)?;
    tracing::subscriber::set_global_default(sub).map_err(|e| LogError(e.to_string()))
}

/// `scheme://host:port/path`, query removed (§4.5): a URL can carry the
/// KVM token (`av.flv?token=`).
#[must_use]
pub fn redact_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    format!("{scheme}://{host}:{port}{path}")
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
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A `MakeWriter` into a shared buffer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    struct BufWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for BufWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> BufWriter {
            BufWriter(self.0.clone())
        }
    }
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn emit_all() {
        tracing::debug!(target: "ironrdp_server::server", "ironrdp-debug");
        tracing::info!(target: "ironrdp_server::server", "ironrdp-info");
        tracing::debug!(target: "ironrdp_acceptor::credssp", "credssp-debug");
        tracing::trace!(target: "sspi::ntlm", "ntlm-trace");
        tracing::debug!(target: "tokio_tungstenite::compat", "ws-debug");
        tracing::trace!(target: "kvm_rdp::pump", "bridge-trace");
        tracing::info!(target: "kvm_rdp::bridge", "bridge-info");
    }

    fn run(filter: &str) -> String {
        let buf = Buf::default();
        let sub = subscriber(filter, buf.clone()).unwrap();
        tracing::subscriber::with_default(sub, emit_all);
        buf.text()
    }

    #[test]
    fn third_party_debug_is_capped_even_at_trace() {
        let out = run("trace");
        for hidden in ["ironrdp-debug", "credssp-debug", "ntlm-trace", "ws-debug"] {
            assert!(!out.contains(hidden), "{hidden} leaked: {out}");
        }
        for shown in ["ironrdp-info", "bridge-trace", "bridge-info"] {
            assert!(out.contains(shown), "{shown} missing: {out}");
        }
    }

    /// §11.3's second secrets-hygiene filter: naming a capped target in
    /// config cannot raise it.
    #[test]
    fn a_filter_naming_a_capped_target_cannot_raise_it() {
        let out = run("kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace");
        assert!(
            !out.contains("credssp-debug") && !out.contains("ntlm-trace"),
            "{out}"
        );
        assert!(out.contains("bridge-trace"), "{out}");
    }

    /// PD8 review m4: `ironrdp_cliprdr` is held at ERROR whatever
    /// `log.filter` says. Its WARNs carry client-chosen file names (the
    /// file-list sanitiser) and fire once per hostile PDU (unknown stream,
    /// unnegotiated file contents, a refused format list).
    #[test]
    fn ironrdp_cliprdr_is_capped_at_error_whatever_the_filter() {
        // Each keeps `trace` for everything else, so the control line
        // (another IronRDP crate at INFO) passes the user filter.
        for filter in [
            "trace",
            "trace,ironrdp_cliprdr=trace",
            "trace,ironrdp_cliprdr::pdu=trace",
        ] {
            let buf = Buf::default();
            let sub = subscriber(filter, buf.clone()).unwrap();
            tracing::subscriber::with_default(sub, || {
                tracing::info!(target: "ironrdp_cliprdr", "cliprdr-info");
                tracing::warn!(target: "ironrdp_cliprdr", "cliprdr-warn");
                tracing::warn!(target: "ironrdp_cliprdr::pdu", "cliprdr-pdu-warn");
                tracing::error!(target: "ironrdp_cliprdr", "cliprdr-error");
                tracing::info!(target: "ironrdp_server::server", "ironrdp-info");
            });
            let out = buf.text();
            for hidden in ["cliprdr-info", "cliprdr-warn", "cliprdr-pdu-warn"] {
                assert!(!out.contains(hidden), "{filter}: {hidden} leaked: {out}");
            }
            // ERROR still shows, and the other IronRDP crates keep INFO.
            for shown in ["cliprdr-error", "ironrdp-info"] {
                assert!(out.contains(shown), "{filter}: {shown} missing: {out}");
            }
        }
    }

    /// One third-party callsite (each macro call is its own).
    fn unexpected_channel() {
        tracing::warn!(target: "ironrdp_server::server", "unexpected-channel");
    }

    /// DE5 (PD8 m4): a third-party callsite logs its first event, then at
    /// most one per interval, and every dropped line is counted. Events the
    /// level filters already drop are never counted (they never reach the
    /// limit), other callsites keep their own allowance, and bridge lines
    /// are never limited.
    #[test]
    fn a_third_party_callsite_logs_once_per_interval_and_counts_the_rest() {
        let buf = Buf::default();
        let dropped: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));
        let sub =
            subscriber_limited("trace", buf.clone(), Duration::from_millis(300), dropped).unwrap();
        tracing::subscriber::with_default(sub, || {
            for _ in 0..1000 {
                unexpected_channel();
            }
            for _ in 0..1000 {
                tracing::debug!(target: "ironrdp_server::server", "capped-debug");
            }
            tracing::warn!(target: "ironrdp_server::other", "another-callsite");
            // Per callsite, not per target: the flooding callsite's target.
            tracing::warn!(target: "ironrdp_server::server", "same-target-callsite");
            for _ in 0..50 {
                tracing::info!(target: "kvm_rdp::bridge", "bridge-line");
            }
            std::thread::sleep(Duration::from_millis(400));
            unexpected_channel();
        });
        let out = buf.text();
        // Timing-robust (§13's loaded host): a deschedule past the 300 ms
        // interval inside the first loop lets one more line through, and
        // every line is either logged or counted.
        let logged = u64::try_from(out.matches("unexpected-channel").count()).unwrap();
        let dropped = dropped.load(std::sync::atomic::Ordering::Relaxed);
        assert!((2..=4).contains(&logged), "{logged} logged: {out}");
        assert_eq!(logged + dropped, 1001, "{logged} logged, {dropped} dropped");
        assert_eq!(out.matches("another-callsite").count(), 1, "{out}");
        assert_eq!(out.matches("same-target-callsite").count(), 1, "{out}");
        assert_eq!(out.matches("bridge-line").count(), 50, "{out}");
        assert_eq!(out.matches("capped-debug").count(), 0, "{out}");
    }

    /// The limit has no level opinion: the subscriber's hint stays the
    /// level filters' (`None` from the limit would win `And`'s minimum and
    /// raise `LevelFilter::current()` to TRACE).
    #[test]
    fn the_limit_keeps_the_level_hint() {
        for (filter, hint) in [("info", LevelFilter::INFO), ("warn", LevelFilter::WARN)] {
            let sub = subscriber(filter, Buf::default()).unwrap();
            assert_eq!(
                tracing::Subscriber::max_level_hint(&sub),
                Some(hint),
                "{filter}"
            );
        }
    }

    /// The production subscriber uses the 10 s interval and the
    /// process-wide counter `/metrics` reads.
    #[test]
    fn the_interval_is_ten_seconds() {
        assert_eq!(THIRD_PARTY_INTERVAL, Duration::from_secs(10));
        // `subscriber` itself: a callsite's second line inside the interval
        // is dropped into `suppressed()`, and `/metrics` renders that count.
        // Other tests in this process can only raise it, so the bounds hold.
        let buf = Buf::default();
        let sub = subscriber("trace", buf.clone()).unwrap();
        let before = suppressed();
        tracing::subscriber::with_default(sub, || {
            for _ in 0..2 {
                tracing::warn!(target: "ironrdp_server::server", "production-limit");
            }
        });
        let lo = suppressed();
        assert_eq!(buf.text().matches("production-limit").count(), 1);
        assert!(lo > before, "the dropped line was not counted");
        let shown = crate::metrics::Metrics::default().render();
        let hi = suppressed();
        let rendered: u64 = shown
            .lines()
            .find_map(|l| l.strip_prefix("kvm_rdp_log_lines_suppressed_total "))
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            (lo..=hi).contains(&rendered),
            "{rendered} not in {lo}..={hi}"
        );
    }

    #[test]
    fn the_user_filter_still_narrows() {
        let out = run("info");
        assert!(
            !out.contains("bridge-trace") && out.contains("bridge-info"),
            "{out}"
        );
    }

    #[test]
    fn every_line_is_json() {
        let out = run("trace");
        assert!(out.lines().count() >= 3);
        for line in out.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(
                v.get("level").is_some() && v.get("target").is_some(),
                "{line}"
            );
        }
    }

    #[test]
    fn a_bad_filter_is_an_error() {
        assert!(subscriber("kvm_rdp=loud", Buf::default()).is_err());
    }

    /// I1 sweep (PC15 review): a bad `log.filter` is refused without echoing
    /// it. `EnvFilter`'s errors are fixed text today (a level list, "error
    /// building NFA"); this pins that, since `LogError` passes them through.
    #[test]
    fn a_bad_filter_is_not_echoed() {
        const S: &str = "s3ntinel-Zq7vP2mX9kLr4TfW8";
        let mut refused = 0;
        for filter in [
            format!("kvm_rdp={S}"),
            format!("kvm_rdp[{{{S}=/(/}}]=info"),
            format!("[{{x={S}}}]=x{S}"),
            format!("{S}=info,,=\x00{S}"),
        ] {
            let Err(e) = subscriber(&filter, Buf::default()) else {
                continue; // accepted: nothing to echo
            };
            refused += 1;
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains(S), "{filter}: {shown}");
        }
        assert!(refused >= 2, "only {refused} filters were refused");
    }

    #[test]
    fn urls_are_logged_without_their_query() {
        assert_eq!(
            redact_url("https", "192.168.0.50", 8881, "/av.flv?token=0.123"),
            "https://192.168.0.50:8881/av.flv"
        );
        assert_eq!(
            redact_url("wss", "kvm", 8889, "/websocket"),
            "wss://kvm:8889/websocket"
        );
    }
}
