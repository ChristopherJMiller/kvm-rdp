//! Logging (spec §4.5): `tracing` JSON lines on stdout. `log.filter` is one
//! `EnvFilter` (parsed from config, never from `RUST_LOG`); a second,
//! independent `Targets` filter holds the libraries that log credentials or
//! payloads at INFO (and those whose WARNs carry client-chosen data at
//! ERROR), combined with `FilterExt::and`, so nothing in config can raise
//! them. Bridge code logs no keystrokes, HID frames, pasted text,
//! tokens or passwords, and no per-frame event above `trace`.
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{EnvFilter, FilterExt as _, LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

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
        .with_filter(user.and(cap));
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
    use std::sync::{Arc, Mutex};

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
