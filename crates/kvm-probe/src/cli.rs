//! The `kvm-probe` clap CLI (§12 Leg A). The KVM password is read from a
//! file (`--password-file`); it is never accepted as an argument or from
//! the environment (§9.2) — `clap` enforces the "never `--password`" half
//! of that by simply not declaring such a flag, and
//! `password_is_never_an_argument` below pins that down as a regression
//! test.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum SchemeArg {
    Https,
    Http,
}

#[derive(Parser, Debug)]
#[command(
    name = "kvm-probe",
    about = "Milestone-0 census tool for the ES3 KVM (spec §12)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
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
