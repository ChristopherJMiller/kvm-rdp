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
            if io.read(&mut byte).await.unwrap() == 0 {
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

    /// The next demuxed tag, `Ok(None)` on EOF or timeout.
    pub async fn next(&mut self) -> Result<Option<FlvTag>, kvm_proto::flv::FlvError> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            if let Some(tag) = self.demux.next_tag()? {
                return Ok(Some(tag));
            }
            match tokio::time::timeout(T, self.io.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => self.demux.push(&buf[..n]),
                _ => return Ok(None),
            }
        }
    }
}
