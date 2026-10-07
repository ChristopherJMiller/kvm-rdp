//! Clients for kvm-sim built on kvm-probe — the tool proven against the real
//! ES3 in the census — so kvm-sim is held to what the device does.
use kvm_probe::kvm::{BoxedIo, connect_to};
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag};
use kvm_sim::{KvmSim, Pacing, SimConfig, Source};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const T: Duration = Duration::from_secs(5);

/// kvm-sim in the ES3 profile over the ES3-like fixture, `f` adjusting its
/// config first.
pub async fn sim_with(f: impl FnOnce(&mut SimConfig)) -> KvmSim {
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    f(&mut cfg);
    KvmSim::start(cfg).await.unwrap()
}

pub async fn es3_sim(pacing: Pacing) -> KvmSim {
    sim_with(|c| c.pacing = pacing).await
}

pub fn target(sim: &KvmSim) -> KvmTarget {
    let p = sim.ports();
    KvmTarget {
        scheme: Scheme::Https,
        host: sim.host().to_owned(),
        login_port: p.web,
        video_port: p.video,
        control_port: p.control,
    }
}

pub async fn login(sim: &KvmSim) -> String {
    kvm_probe::kvm::login(
        &target(sim),
        Some(sim.spki_sha256()),
        sim.password(),
        0,
        "UTC",
    )
    .await
    .unwrap()
}

/// A raw `av.flv` reader: request with the token in the query and the
/// cookie, as the bridge sends it (§3.2), then kvm-proto's demuxer.
pub struct FlvClient {
    io: BoxedIo,
    pub demux: FlvDemuxer,
}

impl FlvClient {
    /// `Err(status)` when kvm-sim refuses the stream.
    pub async fn open(sim: &KvmSim, token: &str) -> Result<FlvClient, u16> {
        let mut io = connect_to(&target(sim), sim.ports().video, Some(sim.spki_sha256()))
            .await
            .unwrap();
        let req = format!(
            "GET /av.flv?token={token} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: token={token}\r\n\r\n"
        );
        io.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 4096, "response head too long");
            // Fix round 1 (m4): bounded, so a hang in `serve` after the TLS
            // handshake fails this test fast instead of hanging it.
            let n = tokio::time::timeout(T, io.read(&mut byte))
                .await
                .expect("timed out reading the response head")
                .unwrap();
            if n == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let status: u16 = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if status != 200 {
            return Err(status);
        }
        Ok(FlvClient {
            io,
            demux: FlvDemuxer::new(FlvLimits::default()),
        })
    }

    /// The next demuxed tag. `Ok(None)` on EOF *or* a read error (PB17, n3:
    /// a reset reads the same as a clean close — both mean "reconnect" to
    /// every caller here, so this does not distinguish them).
    ///
    /// Fix round 1 (m4): a timeout is `Err(NextError::Timeout)`, distinct
    /// from `Ok(None)` — the two used to be the same value, which let a
    /// stall pass for "the FLV closes".
    pub async fn next(&mut self) -> Result<Option<FlvTag>, NextError> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            if let Some(tag) = self.demux.next_tag()? {
                return Ok(Some(tag));
            }
            match tokio::time::timeout(T, self.io.read(&mut buf)).await {
                Ok(Ok(0)) => return Ok(None),
                Ok(Ok(n)) => self.demux.push(&buf[..n]),
                Ok(Err(_)) => return Ok(None), // reset: treat as closed
                Err(_) => return Err(NextError::Timeout),
            }
        }
    }
}

/// Why [`FlvClient::next`] stopped without a tag (fix round 1, m4). Never
/// matched on by name — only ever surfaced via `Debug` in a panic message
/// (`.unwrap()`/`.expect()`), which is why `Flv`'s payload needs the
/// `#[allow]`: clippy's dead-code pass doesn't count a derive as a use.
#[derive(Debug)]
#[allow(dead_code)]
pub enum NextError {
    Flv(kvm_proto::flv::FlvError),
    /// No tag arrived within `T`: a stall (or a bug), not a close.
    Timeout,
}

impl From<kvm_proto::flv::FlvError> for NextError {
    fn from(e: kvm_proto::flv::FlvError) -> Self {
        NextError::Flv(e)
    }
}

/// Task 8.5's fault tests read `FlvClient::next`'s error straight into the
/// bridge's own refusal type: a demux-level `FlvError` is exactly one of
/// `VideoAdmission::admit`'s framing refusals (`AdmissionError`'s own
/// `From<FlvError>`); no fault in this batch should ever leave a tag
/// unread for `T`, so a `Timeout` here is a test bug, not a refusal to
/// classify — it panics with a clear message instead of being silently
/// misclassified.
impl From<NextError> for kvm_proto::video::AdmissionError {
    fn from(e: NextError) -> Self {
        match e {
            NextError::Flv(e) => e.into(),
            NextError::Timeout => {
                panic!("FlvClient::next timed out instead of refusing or closing")
            }
        }
    }
}

/// `GET <path>` on the video port with `cookie` as the `Cookie: token=`
/// value (`None`: no `Cookie` header at all), returning the status and the
/// full response body — so a test can check the body itself (m1, P2), not
/// just the status `FlvClient::open` reports. Bounded by `T`: fails fast,
/// never hangs.
pub async fn flv_raw_request(sim: &KvmSim, path: &str, cookie: Option<&str>) -> (u16, Vec<u8>) {
    let mut io = connect_to(&target(sim), sim.ports().video, Some(sim.spki_sha256()))
        .await
        .unwrap();
    let cookie_hdr = cookie.map_or_else(String::new, |t| format!("Cookie: token={t}\r\n"));
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie_hdr}\r\n");
    io.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(T, io.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(buf.len(), |i| i + 4);
    let status = String::from_utf8_lossy(&buf[..head_end])
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, buf[head_end..].to_vec())
}
