//! Test support shared across modules (compiled for tests only).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::Duration;

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
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([path, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
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
