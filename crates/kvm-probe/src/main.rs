//! `kvm-probe` CLI entry point (§12 Leg A). Installing the aws-lc-rs crypto
//! provider is the very first thing this binary does (R20) so every TLS
//! path below has a default provider to use.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;

use kvm_probe::captures::CaptureDir;
use kvm_probe::cli::{Cli, Cmd, Conn, SchemeArg};
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_probe::{capture, fingerprint, kvm, report, sandbox, stats, trial, wsprobe};

/// Local-file bound on the password file (§9.2): never buffer an
/// unbounded file, local or not. 4 KiB is generous for any real password.
const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

fn target(conn: &Conn) -> KvmTarget {
    match conn.scheme {
        SchemeArg::Https => KvmTarget {
            scheme: Scheme::Https,
            host: conn.host.clone(),
            login_port: 443,
            video_port: 8881,
            control_port: 8889,
        },
        SchemeArg::Http => KvmTarget {
            scheme: Scheme::Http,
            host: conn.host.clone(),
            login_port: 80,
            video_port: 8880,
            control_port: 8888,
        },
    }
}

/// Strip exactly one trailing newline (`\n` or `\r\n`), the way a text
/// editor or `echo` leaves one at end of file. Never strips more than one,
/// so a password that itself ends in a blank line is not silently mangled.
fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Read the KVM password from `path` — the only place a password may come
/// from; it is never accepted as a CLI argument or an environment variable
/// (§9.2). The read is bounded at `MAX_PASSWORD_FILE_BYTES` (refused, not
/// truncated, past that) and one trailing newline is stripped. Every error
/// here names only `path`, never the file's contents, and the password
/// itself is never logged, printed, or included in any error produced
/// anywhere in this binary.
fn read_password_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| format!("cannot read password file {}", path.display()))?;
    let cap = MAX_PASSWORD_FILE_BYTES.saturating_add(1);
    let mut limited = (&mut file).take(cap);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|_| format!("cannot read password file {}", path.display()))?;
    let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if len > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "password file {} exceeds the {MAX_PASSWORD_FILE_BYTES}-byte cap",
            path.display()
        ));
    }
    let text = String::from_utf8(buf)
        .map_err(|_| format!("password file {} is not valid UTF-8", path.display()))?;
    Ok(strip_one_trailing_newline(text))
}

async fn token(conn: &Conn) -> Result<String, String> {
    let pw = read_password_file(&conn.password_file)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let now = i64::try_from(now.as_secs()).map_err(|e| e.to_string())?;
    kvm::login(&target(conn), conn.pin.as_deref(), &pw, now, "UTC")
        .await
        .map_err(|e| format!("{e:?}"))
}

fn captures_dir() -> Result<CaptureDir, String> {
    CaptureDir::create(Path::new("captures")).map_err(|e| format!("{e:?}"))
}

/// Create `<dir>/<name>` for writing, via the same no-clobber,
/// no-symlink-follow, 0600 discipline as every other capture output
/// (`create_new` + `mode(0o600)`; never `File::create`).
fn create_output_file(dir: &CaptureDir, name: &str) -> Result<std::fs::File, String> {
    let path = dir.resolve(name).map_err(|e| format!("{e:?}"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Fingerprint { host, port } => {
            let t = KvmTarget {
                scheme: Scheme::Https,
                host,
                login_port: port,
                video_port: port,
                control_port: port,
            };
            println!(
                "{}",
                fingerprint::observe(&t, port)
                    .await
                    .map_err(|e| format!("{e:?}"))?
            );
        }
        Cmd::Capture {
            conn,
            name,
            seconds,
            max_mb,
        } => {
            let tok = token(&conn).await?;
            let dir = captures_dir()?;
            let jsonl_file = create_output_file(&dir, &format!("{name}.jsonl"))?;
            let mut jsonl = std::io::BufWriter::new(jsonl_file);
            let stop = capture::StopAt {
                max_bytes: max_mb.saturating_mul(1024 * 1024),
                max_duration: Duration::from_secs(seconds),
            };
            let s = capture::run(
                &target(&conn),
                conn.pin.as_deref(),
                &tok,
                &dir,
                &name,
                &mut jsonl,
                stop,
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
            println!(
                "tags={} bytes={} parse_errors={} first_error={:?}",
                s.tags, s.bytes, s.parse_errors, s.first_error
            );
        }
        Cmd::FirstIdr { conn, trials } => {
            let tok = token(&conn).await?;
            let t = target(&conn);
            let mut samples = Vec::new();
            for _ in 0..trials {
                let d = trial::first_idr_latency(
                    &t,
                    conn.pin.as_deref(),
                    &tok,
                    Duration::from_secs(10),
                )
                .await
                .map_err(|e| format!("{e:?}"))?;
                println!("trial: {} ms", d.as_millis());
                samples.push(d);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            println!(
                "p50={:?} p95={:?}",
                stats::percentile(&samples, 50),
                stats::percentile(&samples, 95)
            );
        }
        Cmd::WsOpen { conn } => {
            let tok = token(&conn).await?;
            let d = wsprobe::open_control_websocket(&target(&conn), conn.pin.as_deref(), &tok)
                .await
                .map_err(|e| format!("{e:?}"))?;
            println!("websocket upgrade: {} ms", d.as_millis());
        }
        Cmd::SampleRange {
            name,
            width,
            height,
        } => {
            let ffmpeg = sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?;
            let out = sandbox::run_sample_range(&ffmpeg, &captures_dir()?, &name, width, height)
                .map_err(|e| e.to_string())?;
            println!("{out:?}");
        }
        Cmd::Summarize { name } => {
            let path = captures_dir()?
                .resolve(&format!("{name}.jsonl"))
                .map_err(|e| format!("{e:?}"))?;
            let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let recs: Vec<kvm_probe::record::TagRecord> = text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            println!("{:#?}", report::summarize(&recs));
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("kvm-probe: {e}");
        std::process::exit(1);
    }
}
