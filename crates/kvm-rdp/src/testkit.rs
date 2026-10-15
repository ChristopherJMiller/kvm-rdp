//! Test support shared across modules (compiled for tests only).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::Duration;

/// PD5 ruling (§4.5, §9.2): no rendering of any of `values` — decimal,
/// hex in either case, `0x`-prefixed or two-digit — appears in `s` (a
/// `Debug` of key or pointer state). Renderings shorter than two characters
/// are skipped (a count may show them); the tests' value-invariance checks
/// cover those.
pub(crate) fn assert_no_value(s: &str, values: &[u64]) {
    for v in values {
        for r in [
            format!("{v}"),
            format!("{v:x}"),
            format!("{v:X}"),
            format!("{v:#x}"),
            format!("{v:02x}"),
            format!("{v:02X}"),
        ] {
            assert!(r.len() < 2 || !s.contains(&r), "{r} appears in {s}");
        }
    }
}

/// `{:?}` and `{:#?}` of `a` and `b` — the same shape holding different
/// keys, buttons or positions — print alike, and show none of `values`.
pub(crate) fn assert_debug_redacted<T: std::fmt::Debug>(a: &T, b: &T, values: &[u64]) {
    for (fa, fb) in [
        (format!("{a:?}"), format!("{b:?}")),
        (format!("{a:#?}"), format!("{b:#?}")),
    ] {
        assert_eq!(fa, fb, "Debug shows what it holds");
        assert_no_value(&fa, values);
    }
}

/// Set in a copy of the test binary re-executed by `passes_in_a_child`: the
/// test it runs takes its child branch.
const CHILD: &str = "KVM_RDP_TEST_CHILD";

pub(crate) fn is_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// What a child run printed.
pub(crate) struct ChildOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Run the test at `path` (`module::tests::name`) alone in a child process
/// — this test binary re-executed with `CHILD` set — for what needs a
/// process of its own (a signal, a process-wide subscriber, the process's
/// own stderr); require that it passed and return what it printed. The
/// child is killed with SIGKILL if it outlives 30 s.
pub(crate) fn passes_in_a_child(path: &str) -> ChildOutput {
    passes_in_a_child_with(path, &[])
}

/// `passes_in_a_child`, with `env` also set in the child (how a parent
/// tells one child which case to run).
pub(crate) fn passes_in_a_child_with(path: &str, env: &[(&str, &str)]) -> ChildOutput {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([path, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .envs(env.iter().copied())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let Ok(out) = rx.recv_timeout(Duration::from_secs(30)) else {
        // SAFETY: kill(2) on our own child, not yet reaped (the waiting
        // thread is still blocked in waitpid).
        unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("{path}: the child did not finish within 30 s");
    };
    let out = out.unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(out.status.success(), "{:?}\n{stdout}\n{stderr}", out.status);
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "{path}: the child ran no test:\n{stdout}"
    );
    ChildOutput { stdout, stderr }
}

/// A loopback address no other test binds — 127.64-127.x.y, from this
/// process's id and a counter — for a listener whose closing a test checks
/// by connecting. On 127.0.0.1 a freed ephemeral port can be rebound by a
/// concurrent test's `bind(0)` (seen once in 80 runs of the bridge suite),
/// so a successful connect there does not prove the listener still open.
pub(crate) fn private_loopback() -> std::net::IpAddr {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed) % 250;
    let [_, _, hi, lo] = std::process::id().to_be_bytes();
    std::net::Ipv4Addr::new(127, 64 | (hi & 0x3f), lo, u8::try_from(n + 2).unwrap()).into()
}
