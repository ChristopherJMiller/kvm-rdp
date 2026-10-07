//! kvm-sim's test-facing handle itself.
use crate::support::{FlvClient, T, es3_sim, login};
use kvm_sim::Pacing;

/// PB14 m6: `wait_for`'s predicate may read the sim — the natural L2
/// pattern. It used to run under the sim's own non-reentrant lock, so this
/// re-locked it and blocked the thread where `T` could not reach it. The
/// scenario runs on its own thread and runtime, so a regression fails here
/// after 2 × `T` instead of hanging the suite.
#[test]
fn wait_for_may_call_the_sim_from_its_predicate() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let done = rt.block_on(async {
            let sim = es3_sim(Pacing::Manual).await;
            let token = login(&sim).await;
            let _flv = FlvClient::open(&sim, &token).await.unwrap();
            sim.advance(3);
            let by_stats = sim.wait_for(T, |_| sim.stats().frames_sent >= 3).await;
            let by_events = sim.wait_for(T, |e| e.len() == sim.events().len()).await;
            by_stats.is_ok() && by_events.is_ok()
        });
        let _ = tx.send(done);
    });
    assert_eq!(
        rx.recv_timeout(2 * T),
        Ok(true),
        "wait_for hung, or its predicate never held"
    );
}
