//! Clients for kvm-sim built on kvm-probe — the tool proven against the real
//! ES3 in the census — so kvm-sim is held to what the device does.
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_sim::{KvmSim, Pacing, SimConfig, Source};
use std::time::Duration;

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
