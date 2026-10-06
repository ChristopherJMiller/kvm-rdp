//! `kvm-probe` CLI entry point (§12 Leg A). Installing the aws-lc-rs crypto
//! provider is the very first thing this binary does (R20) so every TLS
//! path below has a default provider to use.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;

use kvm_probe::captures::{self, CaptureDir};
use kvm_probe::cli::{Cli, Cmd, Conn, Port, SchemeArg};
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_probe::{capture, fingerprint, kvm, report, sandbox, secret, stats, trial, wsprobe};

/// The repo-root `/captures/` directory (gitignored, §11.5) — anchored at
/// build time via `CARGO_MANIFEST_DIR`, never relative to the operator's
/// current directory (I5): a run from any cwd must land captures in the
/// one place `.gitignore`'s anchored `/captures/` actually excludes,
/// exactly as `sandbox.rs`'s `live_sample_range` test is anchored (R12).
const CAPTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../captures");

/// Cap on `summarize`'s JSONL read (I3): large enough for any real
/// capture, but never unbounded.
const SUMMARIZE_MAX_BYTES: usize = 64 * 1024 * 1024;

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

async fn token(conn: &Conn) -> Result<String, String> {
    let pw = secret::read_password_file(&conn.password_file)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let now = i64::try_from(now.as_secs()).map_err(|e| e.to_string())?;
    kvm::login(&target(conn), conn.pin_for(Port::Web), &pw, now, "UTC")
        .await
        .map_err(|e| format!("{e:?}"))
}

fn captures_dir() -> Result<CaptureDir, String> {
    CaptureDir::create(Path::new(CAPTURES_DIR)).map_err(|e| format!("{e:?}"))
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

/// Write out and fsync the tag JSONL (final review m6). `into_inner`
/// flushes the buffer and returns its error instead of dropping it.
fn finish_jsonl(jsonl: std::io::BufWriter<std::fs::File>) -> Result<(), String> {
    let file = jsonl
        .into_inner()
        .map_err(|e| format!("writing the tag JSONL: {}", e.error()))?;
    file.sync_all()
        .map_err(|e| format!("syncing the tag JSONL: {e}"))
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
            let result = capture::run(
                &target(&conn),
                conn.pin_for(Port::Video),
                &tok,
                &dir,
                &name,
                &mut jsonl,
                stop,
            )
            .await
            .map_err(|e| format!("{e:?}"));
            // m6: write out and fsync the JSONL on every path, success or
            // not, and report a failure — never leave it to the
            // `BufWriter`'s drop, which swallows the error.
            let finished = finish_jsonl(jsonl);
            let s = match (result, finished) {
                (Ok(s), Ok(())) => s,
                (Err(e), Ok(())) | (Ok(_), Err(e)) => return Err(e),
                (Err(e), Err(f)) => return Err(format!("{e}; and {f}")),
            };
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
                    conn.pin_for(Port::Video),
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
            let d =
                wsprobe::open_control_websocket(&target(&conn), conn.pin_for(Port::Control), &tok)
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
            let dir = captures_dir()?;
            let jsonl_name = format!("{name}.jsonl");
            let path = dir.resolve(&jsonl_name).map_err(|e| format!("{e:?}"))?;
            // I3: never follow a symlink, never block on a FIFO, never
            // buffer past the cap — the captures dir is rw-mounted into
            // the ffmpeg sandbox, so a compromised decode could have
            // planted any entry type at this name.
            let bytes = captures::read_capped(&dir, &jsonl_name, SUMMARIZE_MAX_BYTES)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
            let mut recs = Vec::new();
            for (i, line) in text.lines().enumerate() {
                // M5: name the path and the 1-based line number, not just
                // serde's own ever-"line 1" (each line is parsed on its own).
                let n = i.saturating_add(1);
                let rec: kvm_probe::record::TagRecord = serde_json::from_str(line)
                    .map_err(|e| format!("{}: line {n}: {e}", path.display()))?;
                recs.push(rec);
            }
            println!("{:#?}", report::summarize(&recs));
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    // I1: catches `scheme == Https` (explicit or default) without `--pin`
    // — `required_if_eq` alone misses the default-scheme case. `exit()`
    // prints clap's usual usage-error text and exits with its usual code.
    if let Err(e) = cli.validate() {
        e.exit();
    }
    if let Err(e) = run(cli).await {
        eprintln!("kvm-probe: {e}");
        std::process::exit(1);
    }
}
