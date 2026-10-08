//! §11.3 Lifecycle.
use crate::client::{Opts, description, terminated, timeline, v8_only};
use crate::harness::{KBD_ZERO, SET_MODE, T, env, es3, hid_on, ms, until, within};
use kvm_rdp::msg::Cause;
use kvm_sim::SimEvent;
use std::time::Instant;

/// `default_size` 1920×1080 and a 360p fixture: the slate on the default
/// surface, then DeactivateAll and a 640×360 surface before any KVM frame —
/// IronRDP keeps the connection's `GraphicsPipelineServer` across a
/// reactivation, so the new Setup's `resize_with_monitors` first deletes
/// the slate's surface (`delete` before `reset`; §11.2's "no DeleteSurface"
/// is the re-advertise rule, not this one);
/// one login; after the disconnect kvm-sim's open connections reach 0; a
/// reconnect sends no Resize and costs one more login.
///
/// The plain disconnect is not a cause (PC13/PC14 carry): IronRDP runs the
/// EGFX `on_close` at every connection's teardown, just before
/// `on_disconnected`, and only the generation filter in the `GfxClosed`
/// mapping keeps that close from counting as `no_avc420`. Here the real
/// `RdpServer` produces that close order end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slate_then_resize_then_the_kvm_picture_and_a_clean_reconnect() {
    let env = env(es3(), |_| {}).await;
    let a = env.client(Opts::new(2));
    let evs = a
        .wait_for(T, |e| {
            timeline(e).iter().filter(|l| *l == "idr").count() >= 2
        })
        .await;
    let t = timeline(&evs);
    let d = t
        .iter()
        .position(|l| l == "deactivate")
        .expect("no DeactivateAll");
    assert_eq!(
        t[..d],
        [
            "confirm",
            "reset 1920x1080",
            "surface 1920x1080",
            "map",
            "idr"
        ],
        "{t:?}"
    );
    assert_eq!(
        t[d + 1..d + 7],
        [
            "reactivated 640x360",
            "delete",
            "reset 640x360",
            "surface 640x360",
            "map",
            "idr"
        ],
        "{t:?}"
    );
    assert_eq!(env.logins(), 1);
    // The websocket's session start (§3.3): from here a case may push HID.
    let ws = env.hid_ready().await;
    assert_eq!(
        hid_on(&env.sim.events(), ws)[..2],
        [SET_MODE.to_vec(), KBD_ZERO.to_vec()]
    );
    a.close();
    assert!(
        until(T, || {
            let s = env.sim.stats();
            s.flv_open == 0 && s.ws_open == 0
        })
        .await,
        "{:?}",
        env.sim.stats()
    );
    let b = env.client(Opts::new(3));
    let evs = b
        .wait_for(T, |e| timeline(e).contains(&"idr".to_owned()))
        .await;
    let t = timeline(&evs);
    assert_eq!(
        t[..5],
        ["confirm", "reset 640x360", "surface 640x360", "map", "idr"],
        "a reconnect sends no Resize: {t:?}"
    );
    assert_eq!(env.logins(), 2);
    // `a`'s teardown close and its `SessionStop` reach the pump on the one
    // ordered RDP→pump channel before `b`'s `SessionStart`, so with `b`'s
    // first picture in, the pump has stepped them.
    assert_eq!(
        env.metrics().disconnects.get("no_avc420"),
        0,
        "a plain disconnect was counted as no_avc420"
    );
    assert_eq!(
        env.metrics().disconnects.total(),
        0,
        "a plain disconnect is not bridge-initiated"
    );
}

/// §6.7: a client with no AVC420 decoder is closed with `no_avc420` (0x7)
/// after `avc420_timeout`, and connecting it cost no FLV.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_without_avc420_is_closed_with_no_avc420() {
    let wait = ms(1000);
    let env = env(es3(), move |c| c.video.avc420_timeout = wait).await;
    let c = env.client(Opts::new(2).caps(v8_only()));
    c.connected().await;
    let t0 = Instant::now();
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    within(t0.elapsed(), wait);
    assert_eq!(terminated(&evs).unwrap(), description(Cause::NoAvc420));
    assert_eq!(env.metrics().disconnects.get("no_avc420"), 1);
    assert!(
        !env.sim
            .events()
            .iter()
            .any(|e| matches!(e, SimEvent::FlvOpen { .. })),
        "no AVC420 cost an FLV"
    );
}
