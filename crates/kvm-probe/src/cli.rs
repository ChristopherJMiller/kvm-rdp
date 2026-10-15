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
    /// I1: `required_if_eq("scheme", "https")` on `Conn::pin` only fires
    /// when `--scheme https` is given explicitly on argv — it does not see
    /// `scheme` falling back to its own default (also `Https`). Call this
    /// after a successful parse to catch that case too: `scheme == Https`
    /// (explicit or default) without `--pin` is a usage error, the same as
    /// if clap itself had refused it. R9's intent — refuse early — outranks
    /// its verbatim attribute (controller ruling). `fingerprint` takes no
    /// pin at all (record mode) and is exempt, as are the two subcommands
    /// with no `Conn` (`sample-range`, `summarize`).
    ///
    /// Final review I4: the check is on the *effective* pin
    /// (`Conn::pin_for`) of every port the subcommand touches — web (login) plus video for `capture`/`first-idr`, web plus control for
    /// `ws-open`.
    ///
    /// PD2 fix round 1: the checks that log in more than once (token-life,
    /// session-cap) are refused here without `--owner-consent`, before
    /// `main` reads the password file or opens a connection.
    pub fn validate(&self) -> Result<(), clap::Error> {
        let (conn, ports): (&Conn, &[Port]) = match &self.cmd {
            Cmd::Capture { conn, .. } | Cmd::FirstIdr { conn, .. } => {
                (conn, &[Port::Web, Port::Video])
            }
            Cmd::WsOpen { conn } => (conn, &[Port::Web, Port::Control]),
            Cmd::ConcurrentFlv { conn, .. } => (conn, &[Port::Web, Port::Video]),
            Cmd::RefusalForms { conn } => (conn, &[Port::Video, Port::Control]),
            Cmd::WsClose { conn, .. } => (conn, &[Port::Web, Port::Control]),
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
                (conn, &[Port::Web, Port::Control])
            }
            Cmd::LogoutWatch { conn, .. } => (conn, &[Port::Web, Port::Video, Port::Control]),
            Cmd::Fingerprint { .. } | Cmd::SampleRange { .. } | Cmd::Summarize { .. } => {
                return Ok(());
            }
        };
        if conn.scheme != SchemeArg::Https {
            return Ok(());
        }
        for &port in ports {
            if conn.pin_for(port).is_none() {
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

#[derive(clap::Args, Debug, Clone)]
pub struct Conn {
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

impl Conn {
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
    /// token and with none (status, Content-Type, body prefix). No login.
    RefusalForms {
        #[command(flatten)]
        conn: Conn,
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
        ] {
            let mut argv = vec!["kvm-probe"];
            argv.extend(&sub);
            argv.extend(["--host", "h", "--pin", "ab", "--password-file", "/tmp/pw"]);
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
                assert_eq!(conn.scheme, SchemeArg::Http);
                assert_eq!(trials, 20);
            }
            other => panic!("{other:?}"),
        }
    }
}
