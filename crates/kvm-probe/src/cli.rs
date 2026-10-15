//! The `kvm-probe` clap CLI (§12 Leg A). The KVM password is read from a
//! file (`--password-file`); it is never accepted as an argument or from
//! the environment (§9.2) — `clap` enforces the "never `--password`" half
//! of that by simply not declaring such a flag, and
//! `password_is_never_an_argument` below pins that down as a regression
//! test.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum SchemeArg {
    Https,
    Http,
}

/// How `hid-hold` ends the websocket with the key held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum EndArg {
    Close,
    Fin,
    Reset,
}

impl From<EndArg> for crate::l4::hid::End {
    fn from(e: EndArg) -> Self {
        match e {
            EndArg::Close => Self::CloseFrame,
            EndArg::Fin => Self::Fin,
            EndArg::Reset => Self::Reset,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "kvm-probe",
    about = "Milestone-0 census tool for the ES3 KVM (spec §12). All capture output (.flv, .jsonl, .y) is written under this build's repo-root captures/ directory (gitignored), never the operator's current directory."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

impl Cli {
    /// I1: `required_if_eq("scheme", "https")` on `Endpoint::pin` only fires
    /// when `--scheme https` is given explicitly on argv — it does not see
    /// `scheme` falling back to its own default (also `Https`). Call this
    /// after a successful parse to catch that case too: `scheme == Https`
    /// (explicit or default) without `--pin` is a usage error, the same as
    /// if clap itself had refused it. R9's intent — refuse early — outranks
    /// its verbatim attribute (controller ruling). `fingerprint` takes no
    /// pin at all (record mode) and is exempt, as are the two subcommands
    /// that connect nowhere (`sample-range`, `summarize`).
    ///
    /// Final review I4: the check is on the *effective* pin
    /// (`Endpoint::pin_for`) of every port the subcommand touches — web (login) plus video for `capture`/`first-idr`, web plus control for
    /// `ws-open`.
    ///
    /// PD2 fix round 1: the checks that log in more than once (token-life,
    /// session-cap) are refused here without `--owner-consent`, before
    /// `main` reads the password file or opens a connection.
    pub fn validate(&self) -> Result<(), clap::Error> {
        let (at, ports): (&Endpoint, &[Port]) = match &self.cmd {
            Cmd::Capture { conn, .. } | Cmd::FirstIdr { conn, .. } => {
                (&conn.endpoint, &[Port::Web, Port::Video])
            }
            Cmd::WsOpen { conn } => (&conn.endpoint, &[Port::Web, Port::Control]),
            Cmd::ConcurrentFlv { conn, .. } => (&conn.endpoint, &[Port::Web, Port::Video]),
            // No login, so no web port.
            Cmd::RefusalForms { endpoint } => (endpoint, &[Port::Video, Port::Control]),
            Cmd::WsClose { conn, .. } => (&conn.endpoint, &[Port::Web, Port::Control]),
            Cmd::TokenLife {
                conn,
                owner_consent,
                ..
            }
            | Cmd::SessionCap {
                conn,
                owner_consent,
                ..
            } => {
                if !owner_consent {
                    let sub = if matches!(self.cmd, Cmd::TokenLife { .. }) {
                        "token-life"
                    } else {
                        "session-cap"
                    };
                    return Err(Cli::command().error(
                        clap::error::ErrorKind::MissingRequiredArgument,
                        format!(
                            "{sub} logs in more than once: on a KVM that evicts its oldest \
                             session at a cap, that can end the owner's web-UI session. Run it \
                             only with the owner's explicit consent, and pass --owner-consent \
                             to say so"
                        ),
                    ));
                }
                (&conn.endpoint, &[Port::Web, Port::Control])
            }
            Cmd::LogoutWatch { conn, .. } => {
                (&conn.endpoint, &[Port::Web, Port::Video, Port::Control])
            }
            Cmd::HidType { conn, paces, .. } => {
                // PD3 m3/m4: at most 8 paces, none twice (a repeated pace
                // would repeat a snapshot name, failing after its run).
                let max = crate::l4::hid::MAX_PACES;
                let twice = paces
                    .iter()
                    .enumerate()
                    .find(|&(i, p)| paces.iter().take(i).any(|q| q == p));
                if paces.len() > max || twice.is_some() {
                    return Err(Cli::command().error(
                        clap::error::ErrorKind::ValueValidation,
                        format!(
                            "--paces takes 1 to {max} values, none twice (got {})",
                            paces
                                .iter()
                                .map(u64::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    ));
                }
                (&conn.endpoint, &[Port::Web, Port::Control, Port::Video])
            }
            Cmd::HidRelease { conn, .. } => (&conn.endpoint, &[Port::Web, Port::Control]),
            Cmd::Snapshot { conn, .. } => (&conn.endpoint, &[Port::Web, Port::Video]),
            Cmd::HidHold { conn, .. } | Cmd::HidStale { conn, .. } => {
                (&conn.endpoint, &[Port::Web, Port::Control, Port::Video])
            }
            // No login: the web port alone.
            Cmd::WebGet { endpoint, .. } => (endpoint, &[Port::Web]),
            Cmd::Fingerprint { .. }
            | Cmd::SampleRange { .. }
            | Cmd::Summarize { .. }
            | Cmd::HidPageUrl => {
                return Ok(());
            }
        };
        if at.scheme != SchemeArg::Https {
            return Ok(());
        }
        for &port in ports {
            if at.pin_for(port).is_none() {
                let mut cmd = Cli::command();
                return Err(cmd.error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    port.missing_pin_help(),
                ));
            }
        }
        Ok(())
    }
}

/// `--owner-consent` on the checks that log in more than once (token-life,
/// session-cap): `validate` refuses them without it.
const OWNER_CONSENT_HELP: &str = "The owner has explicitly consented: this check logs in more than \
     once, and on a KVM that evicts its oldest session at a cap that can end the owner's \
     web-UI session";

/// `sample-range --width/--height` value parser (final review m2): a
/// decimal in `sandbox::SAMPLE_DIMENSION_RANGE` (16..=8192), else a clap
/// usage error. `run_sample_range` checks the same range again.
fn sample_dimension(s: &str) -> Result<usize, String> {
    let v: usize = s.parse().map_err(|e| format!("{e}"))?;
    let range = crate::sandbox::SAMPLE_DIMENSION_RANGE;
    if range.contains(&v) {
        Ok(v)
    } else {
        Err(format!("must be in {}..={}", range.start(), range.end()))
    }
}

/// `hid-type --chars` (no burst is unbounded): 1..=`l4::hid::MAX_CHARS`,
/// else a usage error. `type_text` checks the same bound again.
fn hid_chars(s: &str) -> Result<usize, String> {
    let v: usize = s.parse().map_err(|e| format!("{e}"))?;
    let max = crate::l4::hid::MAX_CHARS;
    if (1..=max).contains(&v) {
        Ok(v)
    } else {
        Err(format!("must be in 1..={max}"))
    }
}

/// `hid-type --runs` (PD3 m3): 1..=`l4::hid::MAX_RUNS`.
fn hid_runs(s: &str) -> Result<u32, String> {
    let v: u32 = s.parse().map_err(|e| format!("{e}"))?;
    let max = crate::l4::hid::MAX_RUNS;
    if (1..=max).contains(&v) {
        Ok(v)
    } else {
        Err(format!("must be in 1..={max}"))
    }
}

/// One `hid-type --paces` value in milliseconds: at most
/// `l4::hid::MAX_PACE` (a key is held for one pace).
fn hid_pace(s: &str) -> Result<u64, String> {
    let v: u64 = s.parse().map_err(|e| format!("{e}"))?;
    let max = crate::l4::ms(crate::l4::hid::MAX_PACE);
    if v <= max {
        Ok(v)
    } else {
        Err(format!("must be at most {max} (ms)"))
    }
}

/// Milliseconds, at most `max` (a hold or a settle is never unbounded).
fn ms_at_most(s: &str, max: std::time::Duration) -> Result<u64, String> {
    let v: u64 = s.parse().map_err(|e| format!("{e}"))?;
    let max = crate::l4::ms(max);
    if v <= max {
        Ok(v)
    } else {
        Err(format!("must be at most {max} (ms)"))
    }
}

/// `hid-hold --observe-ms`: at most `l4::hold::MAX_OBSERVE`.
fn hold_observe(s: &str) -> Result<u64, String> {
    ms_at_most(s, crate::l4::hold::MAX_OBSERVE)
}

/// `hid-stale --settle-ms`: at most `l4::hid::MAX_SETTLE`.
fn stale_settle(s: &str) -> Result<u64, String> {
    ms_at_most(s, crate::l4::hid::MAX_SETTLE)
}

/// `web-get --path`: a static page's path (`l4::web::check_path`), never
/// one that could log out or type.
fn web_path(s: &str) -> Result<String, String> {
    crate::l4::web::check_path(s).map(|()| s.to_owned())
}

/// `hid-release --x/--y`: an absolute coordinate, 0..=32767 (§3.3).
fn abs_coord(s: &str) -> Result<u16, String> {
    let v: u16 = s.parse().map_err(|e| format!("{e}"))?;
    let max = kvm_proto::hid::ABS_MAX;
    if v <= max {
        Ok(v)
    } else {
        Err(format!("must be in 0..={max}"))
    }
}

/// Where the KVM is and how its ports are pinned. Every subcommand that
/// connects takes this: `refusal-forms`, which never logs in, takes only
/// this; the rest take it inside `Conn`.
#[derive(clap::Args, Debug, Clone)]
pub struct Endpoint {
    #[arg(long)]
    pub host: String,
    #[arg(long, value_enum, default_value_t = SchemeArg::Https)]
    pub scheme: SchemeArg,
    /// SPKI SHA-256 hex from `fingerprint --port 443` (required for https):
    /// pins the web port (login), and the video and control ports
    /// unless --video-pin / --control-pin override it.
    #[arg(long, required_if_eq("scheme", "https"))]
    pub pin: Option<String>,
    /// Pin for the video port 8881 (av.flv), from `fingerprint --port 8881`;
    /// defaults to --pin.
    #[arg(long)]
    pub video_pin: Option<String>,
    /// Pin for the control port 8889 (websocket), from `fingerprint --port
    /// 8889`; defaults to --pin.
    #[arg(long)]
    pub control_pin: Option<String>,
}

/// An `Endpoint` and the password file: the subcommands that log in.
#[derive(clap::Args, Debug, Clone)]
pub struct Conn {
    #[command(flatten)]
    pub endpoint: Endpoint,
    /// File holding the KVM password (never pass it on the command line).
    #[arg(long)]
    pub password_file: PathBuf,
}

/// Which of the KVM's three services a connection goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Port {
    /// Web UI: login (https 443, http 80).
    Web,
    /// `av.flv` (https 8881, http 8880).
    Video,
    /// Control websocket (https 8889, http 8888).
    Control,
}

impl Endpoint {
    /// The SPKI pin for connections to `port` (final review I4): the web
    /// port always uses `--pin`; the video and control ports use their own
    /// `--video-pin` / `--control-pin` when given, else `--pin`. The ES3's
    /// web UI, video server and control server may be separate daemons
    /// with separate keys, and one pin for all three would then fail every
    /// https subcommand closed.
    pub fn pin_for(&self, port: Port) -> Option<&str> {
        match port {
            Port::Web => self.pin.as_deref(),
            Port::Video => self.video_pin.as_deref().or(self.pin.as_deref()),
            Port::Control => self.control_pin.as_deref().or(self.pin.as_deref()),
        }
    }
}

impl Conn {
    /// Its endpoint's `Endpoint::pin_for`.
    pub fn pin_for(&self, port: Port) -> Option<&str> {
        self.endpoint.pin_for(port)
    }
}

impl Port {
    /// What to pass when this port has no pin under https.
    fn missing_pin_help(self) -> &'static str {
        match self {
            Port::Web => {
                "--pin is required for https (the default scheme): it pins the web \
                 port 443 used for login. Run `fingerprint --port 443` \
                 and pass its output as --pin, or pass --scheme http"
            }
            Port::Video => {
                "the video port 8881 needs a pin for https: pass --video-pin (from \
                 `fingerprint --port 8881`) or --pin, or pass --scheme http"
            }
            Port::Control => {
                "the control port 8889 needs a pin for https: pass --control-pin \
                 (from `fingerprint --port 8889`) or --pin, or pass --scheme http"
            }
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Record the KVM certificate's SPKI SHA-256 (connects once without a pin).
    Fingerprint {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
    },
    /// Capture av.flv to captures/<name> plus captures/<name>.jsonl.
    ///
    /// Logs in, captures until --seconds or --max-mb, and leaves the session
    /// open: it never logs out (logout is global on this KVM). Each JSONL line also carries the hex of any SPS/PPS in the tag.
    Capture {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 64)]
        max_mb: u64,
    },
    /// FLV-open → first-IDR latency over N trials; prints ok/failed and p50/p95.
    ///
    /// Logs in once; every trial reopens av.flv with that one token (the
    /// bridge's reconnect-on-the-same-session path) and times FLV open →
    /// first IDR. It never logs out. A failed
    /// trial (a timeout, or the KVM refusing the token) is printed and
    /// counted, and the run goes on; p50/p95 are over the successful
    /// trials. Exits non-zero if the login fails or no trial succeeded.
    FirstIdr {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 20)]
        trials: u32,
    },
    /// Open the control websocket with the token cookie, then close (no frames sent).
    ///
    /// Logs in first, and never logs out.
    WsOpen {
        #[command(flatten)]
        conn: Conn,
    },
    /// L4 (§11.6): side FLVs on the main FLV's own token — served or
    /// refused (with the form), the main FLV's forced-IDR latency, and how
    /// many AUs a ReconnectFlv swap would replay. No HID, no logout.
    ConcurrentFlv {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 20)]
        trials: u32,
        /// The main FLV's GOP in frames (60 on the ES3, census Leg A).
        #[arg(long, default_value_t = 60)]
        gop: u32,
    },
    /// L4: how the KVM refuses an FLV and a websocket with a never-issued
    /// token and with none (status, Content-Type, body prefix). No login,
    /// so no --password-file.
    RefusalForms {
        #[command(flatten)]
        endpoint: Endpoint,
    },
    /// L4: open the control websocket, read for --idle-secs sending
    /// nothing, send a close frame, and report the KVM's answer and how its
    /// TCP connection ends. Never logs out.
    WsClose {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 10)]
        idle_secs: u64,
    },
    /// L4: log in once per --minutes value now, then probe each token once,
    /// at that age, with a bare websocket upgrade. Those logins can end the
    /// owner's web-UI session if the KVM evicts its oldest at a cap: it
    /// runs only with --owner-consent, after session-cap. Never logs out.
    TokenLife {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_delimiter = ',', default_value = "1,5,15,30,60")]
        minutes: Vec<u64>,
        #[arg(long, help = OWNER_CONSENT_HELP)]
        owner_consent: bool,
    },
    /// L4: log in up to --max times, checking after each that the first and
    /// the newest token still work. If the KVM evicts its oldest session at
    /// a cap, this can end the owner's web-UI session: it runs only with
    /// --owner-consent. Never logs out.
    SessionCap {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 16)]
        max: u32,
        #[arg(long, help = OWNER_CONSENT_HELP)]
        owner_consent: bool,
    },
    /// L4 [OWNER, optional]: log in, open the control websocket and an FLV,
    /// print READY, and watch while the OWNER logs out in the vendor web UI
    /// (controller ruling 1). The probe never sends a logout. Only after
    /// the owner confirms nobody else is using the KVM.
    LogoutWatch {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 300)]
        max_secs: u64,
    },
    /// L4 [OWNER]: print the HID test page's data: URL for the owner to
    /// open on the Mac. Sends nothing to the KVM.
    HidPageUrl,
    /// L4: on one login, type the generated pattern (never any other text)
    /// into the HID test page --runs times at each of --paces (ms); prints
    /// what the page should show after each run. Each run ends with a release.
    HidType {
        #[command(flatten)]
        conn: Conn,
        /// Characters per run, 1..=500 (no burst is unbounded).
        #[arg(long, default_value_t = 200, value_parser = hid_chars)]
        chars: usize,
        /// Milliseconds after each report: 1 to 8 values, none twice, each at
        /// most 100 (a key is held for one pace).
        #[arg(long, value_delimiter = ',', default_value = "0,5,10,15", value_parser = hid_pace)]
        paces: Vec<u64>,
        /// Runs per pace, 1..=10 (one command's typing is bounded too).
        #[arg(long, default_value_t = 3, value_parser = hid_runs)]
        runs: u32,
        /// After each run and --settle-ms, a snapshot named
        /// `<PREFIX><pace>_<run>` (e.g. `type0_1`).
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, default_value_t = 2000)]
        settle_ms: u64,
    },
    /// L4: release every key and button from a fresh process — a new HID
    /// websocket's session start, and a zero-button pointer report at
    /// (--x, --y) if both are given. Run it after any HID command that
    /// failed, was interrupted or was killed (D6b).
    HidRelease {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, requires = "y", value_parser = abs_coord)]
        x: Option<u16>,
        #[arg(long, requires = "x", value_parser = abs_coord)]
        y: Option<u16>,
    },
    /// L4: captures/<name>.flv up to its first IDR, decoded in the sandbox
    /// to captures/<name>.flv.png. Only while the Mac shows the HID test
    /// page or the lock screen.
    Snapshot {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        name: String,
    },
    /// L4 [OWNER present]: hold '1' (and only '1'), end the websocket by
    /// --end, wait --observe-ms with nothing released; with --snapshot N,
    /// snapshot `N_held` then and `N_released` after the releases. Ends with
    /// a release, and another 5 s later; '1' is held at most 24 s.
    HidHold {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_enum, default_value_t = EndArg::Reset)]
        end: EndArg,
        /// How long '1' stays held on the dead websocket before `N_held`, at
        /// most 10000 (with the drain, the end and the snapshot, at most 24 s).
        #[arg(long, default_value_t = 1500, value_parser = hold_observe)]
        observe_ms: u64,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// L4 [OWNER present]: the bounded stale burst (128 reports, alternating
    /// press and release), a reset, a fresh session start and the Right
    /// Ctrl tap that resets the test page, --settle-ms, then (with
    /// --snapshot N) snapshot `N`. Ends with a release, and another 5 s
    /// later.
    HidStale {
        #[command(flatten)]
        conn: Conn,
        /// How long stale presses may land before the snapshot, at most 30000.
        #[arg(long, default_value_t = 5000, value_parser = stale_settle)]
        settle_ms: u64,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// L4: GET a static page on the web port (no login); status, `Server`
    /// header, bounded escaped snippet. Never a script, CGI, login or
    /// logout path.
    WebGet {
        #[command(flatten)]
        endpoint: Endpoint,
        #[arg(long, default_value = "/", value_parser = web_path)]
        path: String,
    },
    /// Decode one frame of captures/<name> in the sandbox; report native Y min/max.
    ///
    /// The decoded frame must be exactly one 8-bit 4:2:0 frame of --width x
    /// --height (summarize's SPS width/height); anything else is refused.
    SampleRange {
        #[arg(long)]
        name: String,
        /// The stream's width in pixels (summarize's SPS width), 16..=8192.
        #[arg(long, value_parser = sample_dimension)]
        width: usize,
        /// The stream's height in pixels (summarize's SPS height), 16..=8192.
        #[arg(long, value_parser = sample_dimension)]
        height: usize,
    },
    /// Summarise captures/<name>.jsonl.
    ///
    /// Prints tag and picture counts, GOP length, the three tag != AU counts
    /// (multi_picture_tags, continuation_tags, non_vcl_picture_tags), and each
    /// distinct SPS run through kvm-proto (SpsSummary, the 6.1 limits verdict,
    /// the change against the first SPS) with its hex, plus each PPS's hex.
    Summarize {
        #[arg(long)]
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fingerprint_and_capture() {
        let c = Cli::try_parse_from(["kvm-probe", "fingerprint", "--host", "h"]).unwrap();
        assert!(matches!(c.cmd, Cmd::Fingerprint { port: 443, .. }));
        let c = Cli::try_parse_from([
            "kvm-probe",
            "capture",
            "--host",
            "h",
            "--pin",
            "ab",
            "--password-file",
            "/tmp/pw",
            "--name",
            "c.flv",
        ])
        .unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::Capture {
                seconds: 60,
                max_mb: 64,
                ..
            }
        ));
    }

    #[test]
    fn password_is_never_an_argument() {
        let err = Cli::try_parse_from([
            "kvm-probe",
            "ws-open",
            "--host",
            "h",
            "--pin",
            "ab",
            "--password",
            "x",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap_err();
        // Every other required value (--host, --pin, --password-file) is
        // present, so the *only* reason this fails is the unrecognized
        // `--password` flag — clap has no such argument to accept it.
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// I1: the default scheme is `Https`, and omitting `--pin` entirely
    /// (never mentioning `--scheme` at all) must still be caught — this is
    /// exactly the gap `required_if_eq` can't close on its own.
    #[test]
    fn https_default_without_pin_is_rejected_by_validate() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "ws-open",
            "--host",
            "h",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        assert!(c.validate().is_err());
    }

    /// Explicit `--scheme https` without `--pin` is caught by clap itself
    /// (`required_if_eq`) before `validate` ever runs — kept here as a
    /// reminder that both paths exist, not just the default-scheme one.
    #[test]
    fn https_explicit_without_pin_is_rejected_by_clap_itself() {
        assert!(
            Cli::try_parse_from([
                "kvm-probe",
                "ws-open",
                "--host",
                "h",
                "--scheme",
                "https",
                "--password-file",
                "/tmp/pw",
            ])
            .is_err()
        );
    }

    /// `http` needs no pin at all, whether selected explicitly or (once
    /// https's gap is fixed elsewhere) by some future default change.
    #[test]
    fn http_without_pin_validates_ok() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "first-idr",
            "--host",
            "h",
            "--scheme",
            "http",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        assert!(c.validate().is_ok());
    }

    /// `fingerprint` takes no pin at all (record mode) and must stay exempt
    /// from the post-parse check.
    #[test]
    fn fingerprint_is_exempt_from_pin_validation() {
        let c = Cli::try_parse_from(["kvm-probe", "fingerprint", "--host", "h"]).unwrap();
        assert!(c.validate().is_ok());
    }

    fn conn_of(c: &Cli) -> &Conn {
        match &c.cmd {
            Cmd::Capture { conn, .. } | Cmd::FirstIdr { conn, .. } | Cmd::WsOpen { conn } => conn,
            other => panic!("no Conn in {other:?}"),
        }
    }

    /// I4 (final review): with only `--pin`, every port uses it.
    #[test]
    fn video_and_control_pins_default_to_pin() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "capture",
            "--host",
            "h",
            "--pin",
            "web",
            "--password-file",
            "/tmp/pw",
            "--name",
            "c.flv",
        ])
        .unwrap();
        let conn = conn_of(&c);
        assert_eq!(conn.pin_for(Port::Web), Some("web"));
        assert_eq!(conn.pin_for(Port::Video), Some("web"));
        assert_eq!(conn.pin_for(Port::Control), Some("web"));
        assert!(c.validate().is_ok());
    }

    /// I4: `--video-pin`/`--control-pin` override `--pin` for their own
    /// port only (the ES3's web UI, video server and control server may be
    /// separate daemons with separate keys); login keeps `--pin`.
    #[test]
    fn video_and_control_pins_override_pin_for_their_port_only() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "ws-open",
            "--host",
            "h",
            "--pin",
            "web",
            "--video-pin",
            "video",
            "--control-pin",
            "control",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        let conn = conn_of(&c);
        assert_eq!(conn.pin_for(Port::Web), Some("web"));
        assert_eq!(conn.pin_for(Port::Video), Some("video"));
        assert_eq!(conn.pin_for(Port::Control), Some("control"));
        assert!(c.validate().is_ok());

        let c = Cli::try_parse_from([
            "kvm-probe",
            "first-idr",
            "--host",
            "h",
            "--pin",
            "web",
            "--video-pin",
            "video",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        let conn = conn_of(&c);
        assert_eq!(conn.pin_for(Port::Video), Some("video"));
        assert_eq!(conn.pin_for(Port::Control), Some("web"));
    }

    /// I4: the https-needs-a-pin check applies to the effective pin of
    /// every port the subcommand touches. Every logged-in subcommand
    /// touches the web port (login), so a per-port pin alone is
    /// not enough without `--pin`.
    #[test]
    fn https_still_needs_the_web_pin_when_only_port_pins_are_given() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "capture",
            "--host",
            "h",
            "--video-pin",
            "video",
            "--password-file",
            "/tmp/pw",
            "--name",
            "c.flv",
        ])
        .unwrap();
        let err = c.validate().unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--pin"), "{err}");
    }

    /// m2 (final review): `sample-range --width/--height` are each clamped
    /// to 16..=8192 at parse time — a usage error, not a later surprise.
    #[test]
    fn sample_range_dimensions_must_be_16_through_8192() {
        let parse = |w: &str, h: &str| {
            Cli::try_parse_from([
                "kvm-probe",
                "sample-range",
                "--name",
                "r.flv",
                "--width",
                w,
                "--height",
                h,
            ])
        };
        assert!(parse("16", "16").is_ok());
        assert!(parse("8192", "8192").is_ok());
        assert!(parse("1920", "1080").is_ok());
        for (w, h) in [
            ("15", "1080"),
            ("1920", "15"),
            ("8193", "1080"),
            ("1920", "8193"),
            ("0", "0"),
        ] {
            let err = parse(w, h).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{w}x{h}"
            );
        }
    }

    /// §3.2, owner: logout is global on the ES3, so no kvm-probe run may
    /// log out — there is no flag to ask for it on any subcommand.
    #[test]
    fn logout_is_never_an_argument() {
        for sub in [
            vec!["ws-open"],
            vec!["capture", "--name", "c.flv"],
            vec!["first-idr"],
            vec!["concurrent-flv"],
            vec!["refusal-forms"],
            vec!["ws-close"],
            vec!["token-life"],
            vec!["session-cap"],
            vec!["logout-watch"],
            vec!["hid-type"],
            vec!["hid-release"],
            vec!["snapshot", "--name", "s"],
        ] {
            let mut argv = vec!["kvm-probe"];
            argv.extend(&sub);
            argv.extend(["--host", "h", "--pin", "ab"]);
            // refusal-forms never logs in, so it takes no password file.
            if sub != ["refusal-forms"] {
                argv.extend(["--password-file", "/tmp/pw"]);
            }
            assert!(Cli::try_parse_from(&argv).is_ok(), "{sub:?}");
            argv.push("--logout");
            let err = Cli::try_parse_from(&argv).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{sub:?}"
            );
        }
    }

    /// The L4 subcommands' defaults (Task 1.6 runs them as written), and
    /// each one's https pin check covers the ports it touches.
    #[test]
    fn l4_subcommands_parse_with_their_defaults() {
        // token-life and session-cap also need the owner's consent (below).
        let parse = |sub: &str| {
            let mut argv = vec!["kvm-probe", sub, "--host", "h", "--pin", "ab"];
            // refusal-forms never logs in, so it takes no password file.
            if sub != "refusal-forms" {
                argv.extend(["--password-file", "/tmp/pw"]);
            }
            if matches!(sub, "token-life" | "session-cap") {
                argv.push("--owner-consent");
            }
            let c = Cli::try_parse_from(argv).unwrap();
            assert!(c.validate().is_ok(), "{sub}");
            c.cmd
        };
        assert!(matches!(
            parse("concurrent-flv"),
            Cmd::ConcurrentFlv {
                trials: 20,
                gop: 60,
                ..
            }
        ));
        assert!(matches!(parse("refusal-forms"), Cmd::RefusalForms { .. }));
        assert!(matches!(
            parse("ws-close"),
            Cmd::WsClose { idle_secs: 10, .. }
        ));
        assert!(matches!(
            parse("token-life"),
            Cmd::TokenLife { minutes, .. } if minutes == [1, 5, 15, 30, 60]
        ));
        assert!(matches!(
            parse("session-cap"),
            Cmd::SessionCap { max: 16, .. }
        ));
        assert!(matches!(
            parse("logout-watch"),
            Cmd::LogoutWatch { max_secs: 300, .. }
        ));
        let c = Cli::try_parse_from([
            "kvm-probe",
            "token-life",
            "--host",
            "h",
            "--pin",
            "ab",
            "--password-file",
            "/tmp/pw",
            "--minutes",
            "2,7",
            "--owner-consent",
        ])
        .unwrap();
        assert!(matches!(c.cmd, Cmd::TokenLife { minutes, .. } if minutes == [2, 7]));
        // `logout-watch` touches all three ports; without --pin, https fails.
        let c = Cli::try_parse_from([
            "kvm-probe",
            "logout-watch",
            "--host",
            "h",
            "--video-pin",
            "v",
            "--control-pin",
            "c",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        assert!(c.validate().is_err());
    }

    /// refusal-forms never logs in: it takes the host, the scheme and the
    /// pins of the two ports it touches (video, control), and no password
    /// file — not even an optional one.
    #[test]
    fn refusal_forms_takes_no_password_file() {
        let c = Cli::try_parse_from(["kvm-probe", "refusal-forms", "--host", "h", "--pin", "ab"])
            .unwrap();
        assert!(c.validate().is_ok());
        let err = Cli::try_parse_from([
            "kvm-probe",
            "refusal-forms",
            "--host",
            "h",
            "--pin",
            "ab",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        // No login, so no web-port pin: its own two ports' pins suffice...
        let c = Cli::try_parse_from([
            "kvm-probe",
            "refusal-forms",
            "--host",
            "h",
            "--video-pin",
            "v",
            "--control-pin",
            "c",
        ])
        .unwrap();
        assert!(c.validate().is_ok());
        // ...and each is still required under https.
        let c = Cli::try_parse_from([
            "kvm-probe",
            "refusal-forms",
            "--host",
            "h",
            "--video-pin",
            "v",
        ])
        .unwrap();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("--control-pin"), "{err}");
    }

    /// token-life and session-cap log in more than once: on a KVM that
    /// evicts its oldest session at a cap, either can end the owner's
    /// web-UI session. Each runs only with `--owner-consent`, and without
    /// it `validate` refuses and says why — before `main` reads the
    /// password file or touches the network.
    #[test]
    fn extra_login_checks_need_the_owners_consent() {
        let argv = |sub: &'static str| {
            vec![
                "kvm-probe",
                sub,
                "--host",
                "h",
                "--pin",
                "ab",
                "--password-file",
                "/tmp/pw",
            ]
        };
        for sub in ["token-life", "session-cap"] {
            let err = Cli::try_parse_from(argv(sub))
                .unwrap()
                .validate()
                .unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{sub}"
            );
            let text = err.to_string();
            assert!(
                text.contains(sub) && text.contains("--owner-consent") && text.contains("evict"),
                "{sub}: {text}"
            );
            let mut consented = argv(sub);
            consented.push("--owner-consent");
            assert!(
                Cli::try_parse_from(consented).unwrap().validate().is_ok(),
                "{sub}"
            );
        }
        // The other logged-in checks log in once and need no consent.
        for sub in ["concurrent-flv", "ws-close", "logout-watch"] {
            assert!(
                Cli::try_parse_from(argv(sub)).unwrap().validate().is_ok(),
                "{sub}"
            );
        }
    }

    #[test]
    fn http_scheme_is_selectable() {
        let c = Cli::try_parse_from([
            "kvm-probe",
            "first-idr",
            "--host",
            "h",
            "--scheme",
            "http",
            "--password-file",
            "/tmp/pw",
        ])
        .unwrap();
        match c.cmd {
            Cmd::FirstIdr { conn, trials } => {
                assert_eq!(conn.endpoint.scheme, SchemeArg::Http);
                assert_eq!(trials, 20);
            }
            other => panic!("{other:?}"),
        }
    }

    fn hid_argv<'a>(sub: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut argv = vec![
            "kvm-probe",
            sub,
            "--host",
            "h",
            "--pin",
            "ab",
            "--password-file",
            "/tmp/pw",
        ];
        argv.extend(extra);
        argv
    }

    /// The HID subcommands' defaults (Task 1.6 runs them as written);
    /// `hid-page-url` takes nothing and connects nowhere.
    #[test]
    fn hid_subcommands_parse_with_their_defaults() {
        let c = Cli::try_parse_from(["kvm-probe", "hid-page-url"]).unwrap();
        assert!(matches!(c.cmd, Cmd::HidPageUrl));
        assert!(c.validate().is_ok());
        let c = Cli::try_parse_from(hid_argv("hid-type", &[])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(
            c.cmd,
            Cmd::HidType { chars: 200, ref paces, runs: 3, snapshot: None, settle_ms: 2000, .. }
                if paces == &[0, 5, 10, 15]
        ));
        let c = Cli::try_parse_from(hid_argv("hid-release", &[])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(
            c.cmd,
            Cmd::HidRelease {
                x: None,
                y: None,
                ..
            }
        ));
        let c =
            Cli::try_parse_from(hid_argv("hid-release", &["--x", "100", "--y", "200"])).unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::HidRelease {
                x: Some(100),
                y: Some(200),
                ..
            }
        ));
        let c = Cli::try_parse_from(hid_argv("snapshot", &["--name", "pre_7"])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(c.cmd, Cmd::Snapshot { ref name, .. } if name == "pre_7"));
    }

    /// No burst is unbounded: `--chars` is 1..=500 and each `--paces`
    /// value at most 100 ms, refused at parse time.
    #[test]
    fn hid_type_bounds_its_burst() {
        for ok in [
            &["--chars", "1"][..],
            &["--chars", "500"],
            &["--paces", "0,100"],
        ] {
            assert!(
                Cli::try_parse_from(hid_argv("hid-type", ok)).is_ok(),
                "{ok:?}"
            );
        }
        for bad in [
            &["--chars", "501"][..],
            &["--chars", "0"],
            &["--chars", "1000000"],
            &["--paces", "101"],
            &["--paces", "0,5,1000"],
        ] {
            let err = Cli::try_parse_from(hid_argv("hid-type", bad)).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{bad:?}"
            );
        }
    }

    /// PD3 m3/m4: one command's total typing is bounded too — `--runs`
    /// 1..=10, at most 8 `--paces`, none given twice (a repeated pace would
    /// also repeat a snapshot name, which fails after its run has typed).
    #[test]
    fn hid_type_bounds_its_runs_and_paces() {
        let validate = |extra: &[&str]| Cli::try_parse_from(hid_argv("hid-type", extra));
        assert!(validate(&["--runs", "10"]).unwrap().validate().is_ok());
        assert!(
            validate(&["--paces", "0,1,2,3,4,5,6,7"])
                .unwrap()
                .validate()
                .is_ok()
        );
        for bad in [&["--runs", "11"][..], &["--runs", "0"]] {
            let err = validate(bad).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{bad:?}"
            );
        }
        for bad in [&["--paces", "0,1,2,3,4,5,6,7,8"][..], &["--paces", "0,5,0"]] {
            let err = validate(bad).unwrap().validate().unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{bad:?}"
            );
            assert!(err.to_string().contains("--paces"), "{bad:?}: {err}");
        }
    }

    /// `hid-type` types only the generated pattern: its arguments are
    /// exactly these — none names text or a file to type (the password
    /// file is only ever read to log in).
    #[test]
    fn hid_type_takes_no_text_to_type() {
        let cmd = Cli::command();
        let sub = cmd.find_subcommand("hid-type").unwrap();
        let mut args: Vec<&str> = sub.get_arguments().map(|a| a.get_id().as_str()).collect();
        args.sort_unstable();
        assert_eq!(
            args,
            [
                "chars",
                "control_pin",
                "host",
                "paces",
                "password_file",
                "pin",
                "runs",
                "scheme",
                "settle_ms",
                "snapshot",
                "video_pin"
            ]
        );
        for flag in ["--text", "--file", "--type", "--string"] {
            let err = Cli::try_parse_from(hid_argv("hid-type", &[flag, "x"])).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flag}"
            );
        }
    }

    /// `hid-release`'s pointer report needs both coordinates, each in
    /// 0..=32767 — never a silent (0, 0) or half a position.
    #[test]
    fn hid_release_takes_both_coordinates_or_neither() {
        for half in [&["--x", "1"][..], &["--y", "1"]] {
            let err = Cli::try_parse_from(hid_argv("hid-release", half)).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{half:?}"
            );
        }
        let err = Cli::try_parse_from(hid_argv("hid-release", &["--x", "32768", "--y", "1"]))
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(
            Cli::try_parse_from(hid_argv("hid-release", &["--x", "32767", "--y", "0"])).is_ok()
        );
    }

    /// Each HID subcommand's https pin check covers the ports it touches:
    /// `hid-type` all three (login, typing, snapshots), `hid-release` web
    /// and control, `snapshot` web and video.
    #[test]
    fn hid_subcommands_need_a_pin_for_each_port_they_touch() {
        let only = |sub: &'static str, extra: &[&'static str], port_pins: &[&'static str]| {
            let mut argv = vec![
                "kvm-probe",
                sub,
                "--host",
                "h",
                "--password-file",
                "/tmp/pw",
            ];
            argv.extend(extra);
            argv.extend(port_pins);
            Cli::try_parse_from(argv).unwrap().validate()
        };
        assert!(only("hid-type", &[], &["--video-pin", "v", "--control-pin", "c"]).is_err());
        assert!(only("hid-release", &[], &["--control-pin", "c"]).is_err());
        assert!(only("snapshot", &["--name", "s"], &["--video-pin", "v"]).is_err());
        let err = only("hid-type", &[], &["--pin", "w", "--control-pin", "c"]);
        assert!(err.is_ok(), "--pin covers video: {err:?}");
    }

    #[test]
    fn end_arg_maps_each_value_to_its_end() {
        use crate::l4::hid::End;
        assert_eq!(End::from(EndArg::Close), End::CloseFrame);
        assert_eq!(End::from(EndArg::Fin), End::Fin);
        assert_eq!(End::from(EndArg::Reset), End::Reset);
        let c = Cli::try_parse_from([
            "kvm-probe",
            "hid-hold",
            "--host",
            "h",
            "--pin",
            "ab",
            "--password-file",
            "/p",
            "--end",
            "fin",
        ])
        .unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::HidHold {
                end: EndArg::Fin,
                observe_ms: 1500,
                ..
            }
        ));
    }

    fn web_argv<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        let mut argv = vec!["kvm-probe", "web-get", "--host", "h", "--pin", "ab"];
        argv.extend(extra);
        argv
    }

    /// Task 1.6 steps 8, 9 and 14 run these as written.
    #[test]
    fn hid_hold_hid_stale_and_web_get_parse_with_their_defaults() {
        let c = Cli::try_parse_from(hid_argv("hid-hold", &[])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(
            c.cmd,
            Cmd::HidHold {
                end: EndArg::Reset,
                observe_ms: 1500,
                snapshot: None,
                ..
            }
        ));
        let c = Cli::try_parse_from(hid_argv(
            "hid-hold",
            &["--end", "close", "--snapshot", "hold_close"],
        ))
        .unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::HidHold { end: EndArg::Close, snapshot: Some(ref n), .. } if n == "hold_close"
        ));
        let c = Cli::try_parse_from(hid_argv("hid-stale", &[])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(
            c.cmd,
            Cmd::HidStale {
                settle_ms: 5000,
                snapshot: None,
                ..
            }
        ));
        let c = Cli::try_parse_from(web_argv(&[])).unwrap();
        assert!(c.validate().is_ok());
        assert!(matches!(c.cmd, Cmd::WebGet { ref path, .. } if path == "/"));
    }

    /// `hid-hold` holds only '1' and `hid-stale` sends only its burst:
    /// neither takes a key, a text or a file to type.
    #[test]
    fn hid_hold_and_hid_stale_take_no_key_or_text() {
        let cmd = Cli::command();
        for (sub, own) in [
            ("hid-hold", &["end", "observe_ms", "snapshot"][..]),
            ("hid-stale", &["settle_ms", "snapshot"]),
        ] {
            let mut args: Vec<&str> = cmd
                .find_subcommand(sub)
                .unwrap()
                .get_arguments()
                .map(|a| a.get_id().as_str())
                .collect();
            args.sort_unstable();
            let mut want = vec![
                "control_pin",
                "host",
                "password_file",
                "pin",
                "scheme",
                "video_pin",
            ];
            want.extend(own);
            want.sort_unstable();
            assert_eq!(args, want, "{sub}");
            for flag in ["--usage", "--key", "--text", "--file"] {
                let err = Cli::try_parse_from(hid_argv(sub, &[flag, "x"])).unwrap_err();
                assert_eq!(
                    err.kind(),
                    clap::error::ErrorKind::UnknownArgument,
                    "{sub} {flag}"
                );
            }
        }
    }

    /// Nothing is held or left to land without bound: `--observe-ms` (the
    /// key held on a dead websocket) is at most `hold::MAX_OBSERVE`,
    /// `--settle-ms` at most `hid::MAX_SETTLE`, refused at parse time.
    #[test]
    fn hid_hold_and_hid_stale_bound_their_waits() {
        for (sub, flag, at, past) in [
            ("hid-hold", "--observe-ms", "10000", "10001"),
            ("hid-stale", "--settle-ms", "30000", "30001"),
        ] {
            assert!(Cli::try_parse_from(hid_argv(sub, &[flag, at])).is_ok());
            let err = Cli::try_parse_from(hid_argv(sub, &[flag, past])).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation, "{sub}");
        }
        assert_eq!(
            crate::l4::ms(crate::l4::hold::MAX_OBSERVE),
            10_000,
            "the parser's bound"
        );
        assert_eq!(crate::l4::ms(crate::l4::hid::MAX_SETTLE), 30_000);
    }

    /// `web-get` never logs in (no `--password-file`) and never requests a
    /// path that could log out or type: `--path` is a static page's path,
    /// refused at parse time otherwise.
    #[test]
    fn web_get_takes_only_a_static_path_and_no_password() {
        assert!(Cli::try_parse_from(web_argv(&["--path", "/about.html"])).is_ok());
        for bad in ["/cgi-bin/login.lua?logout", "/x?y", "about", "/a/../b"] {
            let err = Cli::try_parse_from(web_argv(&["--path", bad])).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation, "{bad}");
        }
        let err = Cli::try_parse_from(web_argv(&["--password-file", "/tmp/pw"])).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `hid-hold` and `hid-stale` touch all three ports (login, the HID
    /// websocket, snapshots); `web-get` only the web port.
    #[test]
    fn hid_hold_hid_stale_and_web_get_need_a_pin_for_each_port_they_touch() {
        let run = |sub: &'static str, pins: &[&'static str]| {
            let mut argv = vec!["kvm-probe", sub, "--host", "h"];
            if sub != "web-get" {
                argv.extend(["--password-file", "/tmp/pw"]);
            }
            argv.extend(pins);
            Cli::try_parse_from(argv).unwrap().validate()
        };
        for sub in ["hid-hold", "hid-stale"] {
            assert!(run(sub, &["--video-pin", "v", "--control-pin", "c"]).is_err());
            assert!(run(sub, &["--pin", "w", "--control-pin", "c"]).is_ok());
            assert!(run(sub, &["--pin", "w", "--video-pin", "v"]).is_ok());
        }
        assert!(run("web-get", &["--video-pin", "v", "--control-pin", "c"]).is_err());
        assert!(run("web-get", &["--pin", "w"]).is_ok());
        assert!(run("web-get", &["--scheme", "http"]).is_ok());
    }
}
