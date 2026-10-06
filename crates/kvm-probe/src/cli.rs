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
    pub fn validate(&self) -> Result<(), clap::Error> {
        let conn = match &self.cmd {
            Cmd::Capture { conn, .. } | Cmd::FirstIdr { conn, .. } | Cmd::WsOpen { conn } => conn,
            Cmd::Fingerprint { .. } | Cmd::SampleRange { .. } | Cmd::Summarize { .. } => {
                return Ok(());
            }
        };
        if conn.scheme == SchemeArg::Https && conn.pin.is_none() {
            let mut cmd = Cli::command();
            return Err(cmd.error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--pin is required for https (the default scheme); run `fingerprint` \
                 first and pass its output as --pin, or pass --scheme http",
            ));
        }
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct Conn {
    #[arg(long)]
    pub host: String,
    #[arg(long, value_enum, default_value_t = SchemeArg::Https)]
    pub scheme: SchemeArg,
    /// SPKI SHA-256 hex recorded by `fingerprint` (required for https).
    #[arg(long, required_if_eq("scheme", "https"))]
    pub pin: Option<String>,
    /// File holding the KVM password (never pass it on the command line).
    #[arg(long)]
    pub password_file: PathBuf,
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
    /// FLV-open → first-IDR latency over N trials; prints p50/p95.
    FirstIdr {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 20)]
        trials: u32,
    },
    /// Open the control websocket with the token cookie, then close (no frames sent).
    WsOpen {
        #[command(flatten)]
        conn: Conn,
    },
    /// Decode one frame of captures/<name> in the sandbox; report native Y min/max.
    SampleRange {
        #[arg(long)]
        name: String,
        #[arg(long)]
        width: usize,
        #[arg(long)]
        height: usize,
    },
    /// Summarise captures/<name>.jsonl.
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
