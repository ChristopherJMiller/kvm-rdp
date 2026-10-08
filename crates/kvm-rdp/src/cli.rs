//! The binary's body (spec §4.4, §5.2), in the library so tests can run it
//! as the binary does: `main.rs` only hands it the arguments and
//! `KVM_RDP_CONFIG` — the only environment variable read.
use crate::{bridge, config, logging};
use std::ffi::OsString;

/// Read the config, start the bridge, run until SIGTERM, SIGINT or a
/// certificate change, and shut down (§5.2). Returns the exit code: 0 after
/// a signal or a certificate change, 1 if startup failed or the RDP server
/// stopped on its own, 2 on a config or logging error.
#[must_use]
pub fn main(args: impl IntoIterator<Item = OsString>, env: Option<OsString>) -> u8 {
    // The error is a line that never carries the file's contents (§9.2).
    let cfg = match config::from_command_line(args, env) {
        Ok(c) => c,
        Err(line) => {
            eprintln!("{line}");
            return 2;
        }
    };
    if let Err(e) = logging::init(&cfg.log.filter) {
        eprintln!("kvm-rdp: {e}");
        return 2;
    }
    let handle = match bridge::spawn(cfg) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return 1;
        }
    };
    handle.run_until_signal().code()
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
    use crate::config::tests::{SENTINELS, leak_shapes};
    use crate::testkit::{is_child, passes_in_a_child};

    /// I1 (PC15 re-review): the binary's stderr. A child process — this
    /// test binary re-executed — runs the binary's body, `cli::main`, on
    /// every leak shape, so each error line goes to the process's real
    /// stderr; the parent reads it all and finds no sentinel in it.
    #[test]
    fn the_binarys_stderr_never_echoes_the_config_file() {
        let d = tempfile::tempdir().unwrap();
        let toml = d.path().join("kvm-rdp.toml");
        let shapes = leak_shapes(d.path());
        if is_child() {
            for (bytes, what) in &shapes {
                std::fs::write(&toml, bytes).unwrap();
                let args = ["--config".into(), toml.clone().into_os_string()];
                assert_eq!(main(args, None), 2, "{what}");
            }
            return;
        }
        let out = passes_in_a_child("cli::tests::the_binarys_stderr_never_echoes_the_config_file");
        let lines = out
            .stderr
            .lines()
            .filter(|l| l.starts_with("kvm-rdp: "))
            .count();
        assert_eq!(
            lines,
            shapes.len(),
            "one error line per shape:\n{}",
            out.stderr
        );
        let leaks: Vec<&str> = out
            .stderr
            .lines()
            .chain(out.stdout.lines())
            .filter(|l| SENTINELS.iter().any(|s| l.contains(s)))
            .collect();
        assert!(
            leaks.is_empty(),
            "{}/{} shapes leaked to stderr:\n{}",
            leaks.len(),
            shapes.len(),
            leaks.join("\n")
        );
    }
}
