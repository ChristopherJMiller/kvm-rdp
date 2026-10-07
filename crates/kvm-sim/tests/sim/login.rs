use crate::support::{T, es3_sim, login, target};
use kvm_sim::{Pacing, PortKind, SimEvent};
use std::time::Duration;

#[tokio::test]
async fn one_certificate_pins_all_three_ports() {
    let sim = es3_sim(Pacing::Manual).await;
    let p = sim.ports();
    for port in [p.web, p.video, p.control] {
        let seen = kvm_probe::fingerprint::observe(&target(&sim), port)
            .await
            .unwrap();
        assert_eq!(seen, sim.spki_sha256(), "port {port}");
    }
    // P4 ruling 2: the Part 8 table pins `accepts_{web,video,control}` as
    // asserted by 8.3; one connection per port above must have counted.
    let s = sim.stats();
    assert_eq!(
        (s.accepts_web, s.accepts_video, s.accepts_control),
        (1, 1, 1)
    );
}

#[tokio::test]
async fn logins_coexist_and_a_wrong_password_is_refused() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let b = login(&sim).await;
    assert_ne!(a, b);
    assert!(a.starts_with("0.") && a[2..].bytes().all(|c| c.is_ascii_digit()));
    let bad = kvm_probe::kvm::login(&target(&sim), Some(sim.spki_sha256()), "nope", 0, "UTC").await;
    assert!(bad.is_err());
    let s = sim.stats();
    assert_eq!((s.logins_ok, s.logins_failed, s.logouts), (2, 1, 0));
}

#[tokio::test]
async fn a_rejecting_policy_fails_even_the_right_password() {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.reject_logins = true);
    let refused = kvm_probe::kvm::login(
        &target(&sim),
        Some(sim.spki_sha256()),
        sim.password(),
        0,
        "UTC",
    )
    .await;
    assert!(refused.is_err());
    assert_eq!((sim.stats().logins_ok, sim.stats().logins_failed), (0, 1));
    sim.set_policy(|p| p.reject_logins = false);
    login(&sim).await;
}

#[tokio::test]
async fn a_logout_is_recorded_and_counted() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &a)
        .await
        .unwrap();
    sim.wait_for(T, |e| e.contains(&SimEvent::Logout))
        .await
        .unwrap();
    assert_eq!(sim.stats().logouts, 1);
}

#[tokio::test]
async fn an_unreachable_kvm_accepts_and_never_answers() {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.blackhole = true);
    let kvm = target(&sim);
    let tls = kvm_probe::kvm::connect_to(&kvm, sim.ports().web, Some(sim.spki_sha256()));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), tls)
            .await
            .is_err(),
        "no TLS handshake ever completes"
    );
    sim.wait_for(T, |e| {
        e.contains(&SimEvent::Accept {
            port: PortKind::Web,
        })
    })
    .await
    .unwrap();
    assert_eq!(sim.stats().accepts_web, 1);
    sim.set_policy(|p| p.blackhole = false);
    login(&sim).await;
}
