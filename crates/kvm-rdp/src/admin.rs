//! The admin listener (spec §4.5) on the KVM runtime: `/metrics`, `/livez`
//! (the RDP runtime's heartbeat is fresh) and `/readyz` (TLS identity
//! loaded, RDP listener bound — never the KVM). One short-lived task per
//! connection; each request head is bounded in size and time, and
//! concurrent connections are capped (P17) so a scanner on this port cannot
//! starve the KVM runtime it shares with the session actor.
use crate::metrics::Metrics;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Largest request head accepted.
pub const MAX_REQUEST_HEAD: usize = 2048;
/// A request head must arrive within this.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest number of admin connections served at once (P17): past this, a
/// new connection is dropped without a response rather than queued, so a
/// flood on 9464 cannot grow unboundedly on the KVM runtime.
pub const MAX_CONNECTIONS: usize = 32;

pub struct Health {
    epoch: Instant,
    last_beat_ms: AtomicU64,
    tls_loaded: AtomicBool,
    rdp_bound: AtomicBool,
    liveness_timeout: Duration,
}

impl Health {
    #[must_use]
    pub fn new(liveness_timeout: Duration) -> Health {
        Health {
            epoch: Instant::now(),
            last_beat_ms: AtomicU64::new(0),
            tls_loaded: AtomicBool::new(false),
            rdp_bound: AtomicBool::new(false),
            liveness_timeout,
        }
    }
    /// The RDP runtime's heartbeat (a `LocalSet` task, every second).
    pub fn beat(&self) {
        let ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_beat_ms.store(ms, Ordering::Relaxed);
    }
    pub fn set_tls_loaded(&self) {
        self.tls_loaded.store(true, Ordering::Relaxed);
    }
    pub fn set_rdp_bound(&self) {
        self.rdp_bound.store(true, Ordering::Relaxed);
    }
    #[must_use]
    pub fn live(&self) -> bool {
        let last = Duration::from_millis(self.last_beat_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last) <= self.liveness_timeout
    }
    #[must_use]
    pub fn ready(&self) -> bool {
        self.tls_loaded.load(Ordering::Relaxed) && self.rdp_bound.load(Ordering::Relaxed)
    }
}

pub async fn serve(listener: TcpListener, health: Arc<Health>, metrics: Arc<Metrics>) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((sock, _)) => match permits.clone().try_acquire_owned() {
                Ok(permit) => {
                    let (h, m) = (health.clone(), metrics.clone());
                    tokio::spawn(async move {
                        handle(sock, h, m).await;
                        drop(permit);
                    });
                }
                // At the cap: drop the connection rather than queue it, so a
                // flood cannot grow unboundedly on the KVM runtime.
                Err(_) => drop(sock),
            },
            // EMFILE and friends: back off instead of spinning.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

enum Head {
    Complete(Vec<u8>),
    TooLarge,
    Closed,
}

async fn read_head(sock: &mut TcpStream) -> std::io::Result<Head> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Head::Closed);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        // The size before the terminator (final review Minor 6): a head
        // whose `\r\n\r\n` ends past 2 KiB is too large even when it arrived
        // in the read that crossed the limit.
        let end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|at| at.saturating_add(4));
        match end {
            Some(len) if len <= MAX_REQUEST_HEAD => return Ok(Head::Complete(buf)),
            Some(_) => return Ok(Head::TooLarge),
            None if buf.len() > MAX_REQUEST_HEAD => return Ok(Head::TooLarge),
            None => {}
        }
    }
}

async fn handle(mut sock: TcpStream, health: Arc<Health>, metrics: Arc<Metrics>) {
    let _ = sock.set_nodelay(true);
    let (status, body) = match tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut sock)).await {
        Ok(Ok(Head::Complete(head))) => route(&head, &health, &metrics),
        Ok(Ok(Head::TooLarge)) => (431, "request head too large\n".to_owned()),
        _ => return,
    };
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let ctype = if status == 200 && body.starts_with("# HELP") {
        "text/plain; version=0.0.4"
    } else {
        "text/plain"
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(body.as_bytes()).await;
    let _ = sock.shutdown().await;
    // Drain what the client still sends (an oversized head's tail) so the
    // close is a FIN, not a reset that could beat the response to it.
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(100), async {
        while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
}

fn route(head: &[u8], health: &Health, metrics: &Metrics) -> (u16, String) {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(&[]);
    let line = std::str::from_utf8(line).unwrap_or("");
    let mut parts = line.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    match (method, path) {
        ("GET", "/metrics") => (200, metrics.render()),
        ("GET", "/livez") if health.live() => (200, "ok\n".to_owned()),
        ("GET", "/livez") => (503, "rdp runtime heartbeat is stale\n".to_owned()),
        ("GET", "/readyz") if health.ready() => (200, "ready\n".to_owned()),
        ("GET", "/readyz") => (503, "not ready\n".to_owned()),
        _ => (404, "not found\n".to_owned()),
    }
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn start(liveness: Duration) -> (std::net::SocketAddr, Arc<Health>, Arc<Metrics>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let health = Arc::new(Health::new(liveness));
        let metrics = Arc::new(Metrics::default());
        tokio::spawn(serve(listener, health.clone(), metrics.clone()));
        (addr, health, metrics)
    }

    async fn raw(addr: std::net::SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        raw(
            addr,
            format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
        )
        .await
    }

    #[tokio::test]
    async fn livez_goes_stale_without_heartbeats() {
        // A 1 s liveness with a 2.5 s sleep: generous on both sides under
        // §13's niced, CPU-weighted test runs.
        let (addr, health, _) = start(Duration::from_secs(1)).await;
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 503"));
        health.beat();
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn readyz_needs_tls_and_the_rdp_listener_and_never_the_kvm() {
        let (addr, health, _) = start(Duration::from_secs(10)).await;
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 503"));
        health.set_tls_loaded();
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 503"));
        health.set_rdp_bound();
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn metrics_and_unknown_paths() {
        let (addr, _, metrics) = start(Duration::from_secs(10)).await;
        metrics.sessions.inc();
        let r = get(addr, "/metrics").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains("Content-Type: text/plain; version=0.0.4"), "{r}");
        assert!(r.contains("kvm_rdp_sessions_total 1"), "{r}");
        assert!(get(addr, "/").await.starts_with("HTTP/1.1 404"));
        assert!(
            raw(addr, b"POST /livez HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 404")
        );
    }

    /// Review Focus 4: an oversized head is refused at once, a silent
    /// connection is dropped after `REQUEST_TIMEOUT`, and `/livez` answers
    /// promptly the whole time.
    #[tokio::test]
    async fn slow_or_huge_admin_requests_do_not_wedge_livez() {
        let (addr, _, _) = start(Duration::from_secs(10)).await;
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut huge = b"GET /metrics HTTP/1.1\r\nX-Pad: ".to_vec();
        huge.extend(std::iter::repeat_n(b'a', 3 * 1024));
        huge.extend_from_slice(b"\r\n\r\n");
        assert!(raw(addr, &huge).await.starts_with("HTTP/1.1 431"));
        let t = Instant::now();
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
        // A listener that served the silent connection first would answer
        // only after its REQUEST_TIMEOUT.
        assert!(t.elapsed() < REQUEST_TIMEOUT, "{:?}", t.elapsed());
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(REQUEST_TIMEOUT * 2, silent.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "the silent connection is closed by the server");
    }

    /// Final review Minor 6 (§4.5): a head over 2 KiB is answered 431 even
    /// when its terminator arrives in the read that crosses the limit (one
    /// 512-byte read past 2 KiB); a head of exactly 2 KiB is served.
    #[tokio::test]
    async fn a_head_over_2_kib_is_always_431() {
        let (addr, _, _) = start(Duration::from_secs(10)).await;
        let head = |len: usize| {
            let mut h = b"GET /livez HTTP/1.1\r\nX-Pad: ".to_vec();
            let pad = len - h.len() - 4;
            h.extend(std::iter::repeat_n(b'a', pad));
            h.extend_from_slice(b"\r\n\r\n");
            assert_eq!(h.len(), len);
            h
        };
        let r = raw(addr, &head(MAX_REQUEST_HEAD)).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        for len in [MAX_REQUEST_HEAD + 1, 2100, MAX_REQUEST_HEAD + 511] {
            let r = raw(addr, &head(len)).await;
            assert!(r.starts_with("HTTP/1.1 431"), "{len} bytes: {r}");
        }
    }
}
