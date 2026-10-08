//! §11.3 Stalled client, asserted on `/metrics` rather than timing.
use crate::client::{Ack, Opts, description, pictures, terminated};
use crate::harness::{T, env, es3, ms, sized, until};
use kvm_rdp::msg::Cause;
use kvm_sim::{Pacing, Timestamps};
use std::time::Instant;

/// Withheld acks: after the first soft-gate drop the sent-frame counter
/// never advances again before Closing; in flight never exceeds the hard
/// cap (60); the session closes with `client_stalled` (0x7).
///
/// `stall_timeout` is scaled to 3 s, not 1 s: the stall clock starts at the
/// gate's first closure, and once a tick has seen it closed the pump is in
/// NeedIdr, where a P frame is dropped as `awaiting_idr` and only an IDR
/// meets the closed gate as `soft_gate` (§6.4, §6.6). The ES3 fixture's
/// IDRs are 2 s apart (keyint 60), so a window shorter than that showed no
/// soft-gate drop at all in 3 of 15 runs; 3 s always holds one IDR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_acks_stop_sending_and_close_client_stalled() {
    let stall = ms(3000);
    let env = env(es3(), move |c| {
        sized(c);
        c.video.stall_timeout = stall;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    c.set_ack(Ack::Withhold);
    let m = env.metrics();
    let mut sent_at_first_drop = None;
    let t0 = Instant::now();
    loop {
        // Read first, so the counters are checked once more after Closing
        // was seen: nothing is sent after it either.
        let closed = m.disconnects.get("client_stalled") > 0;
        assert!(
            m.egfx_in_flight.get() <= 60,
            "in flight {}",
            m.egfx_in_flight.get()
        );
        // The drop counter first, then the sent counter: a count read after
        // the first drop was seen includes every frame sent before it, so
        // a frame sent before the drop is never mistaken for one after it.
        let dropped = m.frames_dropped.get("soft_gate") > 0;
        let sent = m.frames_sent.get();
        match sent_at_first_drop {
            None if dropped => sent_at_first_drop = Some(sent),
            Some(s) => assert_eq!(sent, s, "a frame was sent after the first soft-gate drop"),
            None => {}
        }
        if closed {
            break;
        }
        assert!(t0.elapsed() < T, "never closed");
        tokio::time::sleep(ms(5)).await;
    }
    assert!(
        sent_at_first_drop.is_some(),
        "closed before any soft-gate drop"
    );
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::ClientStalled));
}

/// A client that stops reading (§6.9; fork patch 3 on a live connection):
/// acks suspended, so the soft gate cannot stop sends (§6.6); a 4 KiB
/// receive buffer and a 64 KiB `backlog_limit`. Loopback autotunes the
/// server's send buffer to a few MB (its 64 KiB MSS), far more than the
/// ES3 fixture's ~80 KB/s fills in an L2 bound, so kvm-sim — manual pacing
/// with wall-clock stamps: live AUs, never a burst (§11.5) — floods about
/// 1000 AUs/s until IronRDP's write blocks. The suspended-backlog stall
/// then closes the session; its `Disconnect` queues behind the blocked
/// write (or meets IronRDP's own 500 ms write grace, after the 300 ms
/// watchdog), so the watchdog fires: release-all (`watchdog`), `Stop` to
/// the KVM side, and the abort through `ConnectionInfo::abort_handle()`.
/// kvm-sim sees the websocket and the FLV close within 5 × (`stall_timeout`
/// + watchdog) of the client going quiet — and no logout.
///
/// The abort, end to end (PC14 carry): the watchdog's `Stop` alone frees
/// the KVM side, so that proves nothing about the connection. With the
/// write blocked, IronRDP never reaches the queued `Disconnect`; only the
/// per-connection abort handle drops the connection's future, which runs
/// its teardown and `on_disconnected` — seen here as the session's
/// `release_all{session_end}`, within the same bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_stops_reading_is_aborted_and_frees_the_kvm() {
    let (stall, wd) = (ms(1000), ms(300));
    let mut sim = es3();
    sim.pacing = Pacing::Manual;
    sim.timestamps = Timestamps::WallClock;
    let env = env(sim, move |c| {
        sized(c);
        c.video.stall_timeout = stall;
        c.video.disconnect_watchdog = wd;
        c.video.backlog_limit = 64 << 10;
    })
    .await;
    let c = env.client(Opts::new(2).ack(Ack::Suspend).recv_buffer(4096));
    // Manual pacing writes only to FLVs already open: wait for the FLV.
    assert!(until(T, || env.sim.stats().flv_open == 1).await, "no FLV");
    let streaming = until(T, || {
        env.sim.advance(1);
        pictures(&c.events()).len() >= 10
    })
    .await;
    assert!(streaming, "no pictures");
    let t0 = Instant::now();
    c.stop_reading();
    // ~10 AUs every 10 ms, well inside kvm-sim's 512-slot viewer queue.
    let freed = until(T, || {
        env.sim.advance(10);
        let s = env.sim.stats();
        s.ws_open == 0 && s.flv_open == 0
    })
    .await;
    let took = t0.elapsed();
    assert!(freed, "the KVM side was never freed");
    assert!(
        took <= (stall + wd) * 5,
        "the KVM side was freed after {took:?}"
    );
    let m = env.metrics();
    let torn_down = until(T, || m.release_all.get("session_end") == 1).await;
    let took = t0.elapsed();
    assert!(
        torn_down,
        "the connection was never torn down: the abort handle did not end it"
    );
    assert!(
        took <= (stall + wd) * 5,
        "the connection was torn down after {took:?}"
    );
    assert_eq!(m.disconnects.get("client_stalled"), 1);
    assert_eq!(
        m.release_all.get("watchdog"),
        1,
        "the Disconnect went out: the watchdog and the abort handle never ran"
    );
    assert_eq!(m.sessions.get(), 1);
}

/// A client that suspends acks but keeps reading is never disconnected,
/// and keeps receiving frames (§6.6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_suspends_acks_is_never_disconnected() {
    let stall = ms(1000);
    let env = env(es3(), move |c| {
        sized(c);
        c.video.stall_timeout = stall;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    c.set_ack(Ack::Suspend);
    c.never(stall * 5, |e| terminated(e).is_some()).await;
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
    assert_eq!(env.metrics().egfx_ack_suspended.get(), 1);
    assert_eq!(env.metrics().disconnects.total(), 0);
}
