//! The bridge under test as a subprocess (§10.2): its config and secrets in
//! a temp dir pointed at kvm-sim; its ready line, `/metrics` and
//! `/proc/<pid>`. Its environment is cleared but for MALLOC_ARENA_MAX=2 —
//! §10.1's soak condition, and the image's.
use kvm_bench::prom::Scrape;
use kvm_sim::KvmSim;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const USER: &str = "kvm";
pub const NLA_PASSWORD: &str = "kvm-bench-nla-password-0123456789";

pub struct Bridge {
    child: Child,
    _dir: tempfile::TempDir,
    pub rdp: SocketAddr,
    pub admin: SocketAddr,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Bridge {
    /// `extra` is TOML appended to the config (whole tables: `[video]`, …).
    pub fn spawn(bin: &Path, sim: &KvmSim, extra: &str) -> Result<Bridge, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(|e| e.to_string())?;
        let write = |name: &str, text: String| {
            std::fs::write(dir.path().join(name), text).map_err(|e| e.to_string())
        };
        write("cert.pem", ck.cert.pem())?;
        write("key.pem", ck.key_pair.serialize_pem())?;
        write("nla.pass", format!("{NLA_PASSWORD}\n"))?;
        write("kvm.pass", format!("{}\n", sim.password()))?;
        let p = sim.ports();
        write(
            "kvm-rdp.toml",
            format!(
                "[rdp]\nlisten = \"127.0.0.1:0\"\nusername = \"{USER}\"\nnla_password_file = \"nla.pass\"\n\
                 tls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\n[admin]\nlisten = \"127.0.0.1:0\"\n\
                 [kvm]\nhost = \"{}\"\nspki_sha256 = \"{}\"\npassword_file = \"kvm.pass\"\n\
                 web_port = {}\nvideo_port = {}\ncontrol_port = {}\n{extra}",
                sim.host(),
                sim.spki_sha256(),
                p.web,
                p.video,
                p.control
            ),
        )?;
        let mut cmd = Command::new(bin);
        cmd.arg("--config")
            .arg(dir.path().join("kvm-rdp.toml"))
            .env_clear()
            .env("MALLOC_ARENA_MAX", "2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure runs in the forked child before exec and calls
        // only prctl(2) and setrlimit(2), both async-signal-safe; it touches
        // nothing of the parent's but its own stack.
        unsafe {
            cmd.pre_exec(|| {
                // kvm-bench is release, `panic = "abort"`: a panic never runs
                // `Drop for Bridge`. The bridge gets SIGTERM when the thread
                // that spawned it dies (a runtime worker or the main thread
                // — never call this from a blocking-pool thread), so none is
                // left running at nice 0 on the shared host.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // No core dump of Task 5.3's deliberate SIGABRT on a root
                // filesystem that has filled before (systemd-coredump).
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", bin.display()))?;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (out, l) = (child.stdout.take().ok_or("no stdout")?, lines.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(a) = ready_addrs(&line) {
                    let _ = tx.send(a);
                }
                l.lock().unwrap().push(line);
            }
        });
        let (err, l) = (child.stderr.take().ok_or("no stderr")?, lines.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                l.lock().unwrap().push(line);
            }
        });
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok((rdp, admin)) => Ok(Bridge {
                child,
                _dir: dir,
                rdp,
                admin,
                lines,
            }),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(format!(
                    "the bridge never got ready: {:?}",
                    lines.lock().unwrap()
                ))
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// utime + stime of the process, in clock ticks (`/proc/<pid>/stat`).
    pub fn cpu_ticks(&self) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid())).ok()?;
        let after = stat.rsplit_once(')')?.1;
        let f: Vec<&str> = after.split_whitespace().collect();
        // Fields 14 and 15 of proc(5); `after` starts at field 3.
        Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
    }

    /// `VmRSS` in KiB.
    pub fn rss_kib(&self) -> Option<u64> {
        rss_kib_of(self.pid())
    }

    pub async fn scrape(&self) -> Result<Scrape, String> {
        let admin = self.admin;
        let get = async move {
            let mut s = tokio::net::TcpStream::connect(admin)
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(b"GET /metrics HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            let (_, body) = text.split_once("\r\n\r\n").ok_or("no /metrics body")?;
            Ok::<_, String>(Scrape::parse(body))
        };
        tokio::time::timeout(Duration::from_secs(3), get)
            .await
            .map_err(|_| "/metrics timed out".to_owned())?
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    pub fn sigterm(&self) {
        if let Ok(pid) = libc::pid_t::try_from(self.pid()) {
            // SAFETY: kill(2) on our own child.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }

    /// The child's exit, if it comes within `limit` (polled; never blocks
    /// the runtime).
    pub async fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
        let t0 = Instant::now();
        loop {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            if t0.elapsed() > limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `VmRSS` of `pid` in KiB (`/proc/<pid>/status`): a free function, so
/// Task 5.5's sampler thread can read it without the `Bridge`.
pub fn rss_kib_of(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().strip_suffix("kB")?.trim().parse().ok())
}

fn ready_addrs(line: &str) -> Option<(SocketAddr, SocketAddr)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["fields"]["message"] != "kvm-rdp ready" {
        return None;
    }
    Some((
        v["fields"]["rdp"].as_str()?.parse().ok()?,
        v["fields"]["admin"].as_str()?.parse().ok()?,
    ))
}

/// Clock ticks per second (`sysconf(_SC_CLK_TCK)`).
pub fn clk_tck() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as f64 } else { 100.0 }
}
