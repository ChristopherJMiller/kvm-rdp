//! §11.3 Input and Stuck keys (DC7's carry): the real client → the input
//! handler → the core → the writer → kvm-sim. Each case waits for
//! `hid_ready` (the session-start sequence on the wire) before it sends,
//! and asserts on the frames kvm-sim recorded after that sequence. A
//! script's final check ends at a pointer move to `MARK`: one client
//! connection keeps every event in order, so a frame the script should not
//! have made shows up before the mark's frame, not after the check.
//!
//! Every release is followed, on the core's next step, by one extra
//! all-zero keyboard report: the step that sees the moved epoch pushes its
//! released state (PD6 m6). The session start's release is one, so the
//! first event of a case pushes that zero ahead of its own report; the
//! goldens expect it (`EPOCH_ZERO`).
use crate::client::{Client, FpButton, Opts, pictures};
use crate::harness::{
    Env, KBD_ZERO, SET_MODE, T, env, es3, hid_on, hid_stamped, ms, sized, streaming, until, within,
    ws_opens,
};
use kvm_proto::hid::{HidFrame, Wheel, scale_abs};
use kvm_rdp::hid::HidControl;
use std::time::{Duration, Instant};

/// The fixture's surface (`sized`): what §7.2 scales against.
const W: u16 = 640;
const H: u16 = 360;
/// Set-1 make codes.
const A: u8 = 0x1E; // usage 0x04
const B: u8 = 0x30; // usage 0x05
const K: u8 = 0x25; // usage 0x0E
const Z: u8 = 0x2C; // usage 0x1D
const LSHIFT: u8 = 0x2A; // modifier bit 0x02
const LCTRL: u8 = 0x1D; // modifier bit 0x01
const RIGHT: u8 = 0x4D; // E0 4D: usage 0x4F
/// The zero report the first step after a release pushes (module doc).
const EPOCH_ZERO: [u8; 12] = KBD_ZERO;
/// A client position no script otherwise uses: the end-of-script mark.
const MARK: (u16, u16) = (7, 11);

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    keys(modifiers, [k, 0, 0, 0, 0])
}

fn keys(modifiers: u8, keys: [u8; 5]) -> Vec<u8> {
    HidFrame::Keyboard { modifiers, keys }.to_vec()
}

fn zero() -> Vec<u8> {
    KBD_ZERO.to_vec()
}

/// An absolute-mouse frame for a client position, scaled per §7.2.
fn abs(buttons: u8, x: u16, y: u16) -> Vec<u8> {
    HidFrame::abs_mouse(buttons, scale_abs(x, W), scale_abs(y, H)).to_vec()
}

/// kvm-sim's frames on `ws` after its session start, once there are at
/// least `want` (everything recorded by then).
async fn after_start(env: &Env, ws: u64, want: usize) -> Vec<Vec<u8>> {
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).len() >= 2 + want)
        .await
        .unwrap_or_else(|l| {
            panic!(
                "fewer than {want} frames after the session start within {T:?}: {:02x?}",
                hid_on(&l, ws)
            )
        });
    let all = hid_on(&log, ws);
    assert_eq!(all[..2], [SET_MODE.to_vec(), zero()], "the session start");
    all[2..].to_vec()
}

/// End the script with a move to `MARK` (buttons up), and return kvm-sim's
/// frames on `ws` after its session start and before the mark's frame.
async fn until_mark(env: &Env, c: &Client, ws: u64) -> Vec<Vec<u8>> {
    c.mouse_move(MARK.0, MARK.1);
    let mark = abs(0, MARK.0, MARK.1);
    let log = env
        .sim
        .wait_for(T, |l| hid_on(l, ws).contains(&mark))
        .await
        .unwrap_or_else(|l| panic!("the mark never came: {:02x?}", hid_on(&l, ws)));
    let all = hid_on(&log, ws);
    assert_eq!(all[..2], [SET_MODE.to_vec(), zero()], "the session start");
    let end = all.iter().position(|f| *f == mark).unwrap();
    all[2..end].to_vec()
}

/// Where kvm-sim recorded the `n`th frame (0-based) after `ws`'s session
/// start, once it has.
async fn stamp_of(env: &Env, ws: u64, n: usize) -> Instant {
    let _ = after_start(env, ws, n + 1).await;
    hid_stamped(&env.sim, ws)[2 + n].0
}

/// §7.1–§7.3, byte-exact: a shifted key, an extended key, a Unicode unit,
/// a move to the surface centre, a click there (its own position, D8d) and
/// one wheel notch down, each the §3.3 frame its full state makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_input_event_maps_to_byte_exact_hid_frames() {
    let (env, c) = streaming(|_| {}).await;
    let ws = env.hid_ready().await;
    let (cx, cy) = (W / 2, H / 2);
    c.key(LSHIFT, true);
    c.key(A, true);
    c.key(A, false);
    c.key(LSHIFT, false);
    c.key_extended(RIGHT, true);
    c.key_extended(RIGHT, false);
    c.unicode(u16::from(b'A'), true); // through the US layout: Shift + a
    c.unicode(u16::from(b'A'), false);
    c.mouse_move(cx, cy);
    c.mouse_button(FpButton::Left, true, cx, cy);
    c.mouse_button(FpButton::Left, false, cx, cy);
    c.wheel(-120);
    let want = vec![
        EPOCH_ZERO.to_vec(),
        kbd(0x02, 0),
        kbd(0x02, 0x04),
        kbd(0x02, 0),
        zero(),
        kbd(0, 0x4F),
        zero(),
        kbd(0x02, 0x04),
        zero(),
        abs(0, cx, cy),
        abs(0x01, cx, cy),
        abs(0, cx, cy),
        HidFrame::Wheel {
            buttons: 0,
            wheel: Wheel::Down,
        }
        .to_vec(),
    ];
    assert_eq!(until_mark(&env, &c, ws).await, want);
}

/// D8d, §3.3: a click with no move before it this session goes where it
/// was made — never (0, 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_click_with_no_prior_move_goes_where_it_was_made() {
    let (env, c) = streaming(|_| {}).await;
    let ws = env.hid_ready().await;
    c.mouse_button(FpButton::Left, true, 100, 50);
    c.mouse_button(FpButton::Left, false, 100, 50);
    assert_eq!(
        until_mark(&env, &c, ws).await,
        [EPOCH_ZERO.to_vec(), abs(0x01, 100, 50), abs(0, 100, 50)]
    );
    assert_ne!(abs(0x01, 100, 50), HidFrame::abs_mouse(0x01, 0, 0).to_vec());
}

/// The HID queue's newest keyboard state (its resync state) is `frame`.
async fn newest(hid: &HidControl, frame: HidFrame) {
    assert!(
        until(T, || hid.current_state_frames().first() == Some(&frame)).await,
        "the HID queue never reached {:02x?}",
        frame.to_vec()
    );
}

fn k_state(held: bool) -> HidFrame {
    HidFrame::Keyboard {
        modifiers: 0,
        keys: [if held { 0x0E } else { 0 }, 0, 0, 0, 0],
    }
}

/// §7.3 through the client (Plan C's `hid::a_full_queue_resyncs`, now from
/// the client). With kvm-sim's reads paused, a flood fills kvm-sim's small
/// receive buffer and the bridge's capped send buffer until a write blocks
/// — checked: reports wait and none is written for `STALL` — overflowing
/// the input queue (its least, 9) on the way. The queue is then filled to
/// exactly its cap, so the final press is a push that finds it full:
/// queued nowhere, it reaches the KVM only as the resync's final state.
/// Once reads resume, the last frame kvm-sim sees is that state.
/// `hid_write_timeout` is raised so the blocked write never reconnects, and
/// `key_repeat_timeout` so the key held meanwhile is never released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_resyncs_to_the_correct_final_state_through_the_client() {
    const QUEUE: usize = 9;
    /// Far more reports than kvm-sim's 4 KiB receive buffer and the 16 KiB
    /// send cap hold together (about 18 bytes each on the wire).
    const FLOOD: usize = 4000;
    const STALL: Duration = Duration::from_millis(300);
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, |c| {
        sized(c);
        c.input.queue = QUEUE;
        c.input.hid_write_timeout = Duration::from_secs(5);
        c.input.key_repeat_timeout = Duration::from_secs(60);
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    let ws = env.hid_ready().await;
    let hid = env.bridge().hid().clone();
    let written = || env.metrics().hid_reports_sent.get();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    // Press and release a..j over and over: every event is a new state.
    let flood: Vec<(u8, bool)> = (0..FLOOD / 2)
        .flat_map(|i| {
            let k = [0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24][i % 10];
            [(k, true), (k, false)]
        })
        .collect();
    for round in 1.. {
        c.keys(&flood);
        // A marker press: once it is the queue's newest state, every event
        // before it has been pushed.
        c.key(K, true);
        newest(&hid, k_state(true)).await;
        let w = written();
        if !until(STALL, || written() != w).await && hid.queued() > 0 {
            break;
        }
        assert!(
            round < 5,
            "the writer never blocked: {} reports written",
            written()
        );
        c.key(K, false);
        newest(&hid, k_state(false)).await;
    }
    assert!(
        env.metrics().hid_resyncs.get() >= 1,
        "the flood never overflowed the queue"
    );
    // k's release and press, one push each, until the queue holds exactly
    // its cap: the writer is blocked, so nothing leaves it meanwhile.
    let mut held = true;
    while hid.queued() < QUEUE {
        held = !held;
        c.key(K, held);
        newest(&hid, k_state(held)).await;
    }
    let resyncs = env.metrics().hid_resyncs.get();
    c.key(Z, true);
    let last = HidFrame::Keyboard {
        modifiers: 0,
        keys: if held {
            [0x0E, 0x1D, 0, 0, 0]
        } else {
            [0x1D, 0, 0, 0, 0]
        },
    };
    newest(&hid, last).await;
    assert_eq!(
        (hid.queued(), env.metrics().hid_resyncs.get()),
        (0, resyncs + 1),
        "the final press was queued, not carried by a resync"
    );
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    env.sim
        .wait_for(T, |l| hid_on(l, ws).last() == Some(&last.to_vec()))
        .await
        .unwrap_or_else(|l| {
            panic!(
                "the final state never came last: {:02x?}",
                hid_on(&l, ws).last()
            )
        });
    assert_eq!(
        ws_opens(&env.sim.events()).len(),
        1,
        "the paused reads reconnected the websocket"
    );
    c.key(Z, false);
    c.key(K, false);
}

/// §3.2, §7.3: a websocket reopen's session start puts the pointer where
/// the client last moved it — never at (0, 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_websocket_reopen_restores_the_pointer_not_zero() {
    let (env, c) = streaming(|_| {}).await;
    let ws = env.hid_ready().await;
    c.mouse_move(320, 180);
    assert_eq!(
        after_start(&env, ws, 2).await,
        [EPOCH_ZERO.to_vec(), abs(0, 320, 180)]
    );
    env.sim.close_websockets();
    let ws2 = env.hid_ready_after(1).await;
    // The reopen's session start carries the pointer; the mark's step then
    // sees the reconnect's release (its epoch zero).
    assert_eq!(
        until_mark(&env, &c, ws2).await,
        [abs(0, 320, 180), EPOCH_ZERO.to_vec()]
    );
    assert_ne!(abs(0, 320, 180), HidFrame::abs_mouse(0, 0, 0).to_vec());
}

/// §7.4's Synchronize trigger through the client: a held key is released
/// at once (the zero report, `release_all{synchronize}`). The other
/// triggers — session end, websocket reconnect, suppression — are Plan C's
/// L2 and the lib's; the timers are below.
///
/// Deviation (PD5 review m6, binding since PD6): after a Synchronize the
/// core forgets every released-by-bridge mark, because MS-RDPBCGR's client
/// re-sends key-downs for what it still holds — so the held `a`'s next
/// key-down presses it again (Cmd held across a focus change, then C, must
/// reach the Mac as Cmd+C). The plan's "its later repeat does not re-press
/// it" is pinned across a release that keeps the marks instead
/// (`a_key_held_across_a_release_is_not_repressed_by_repeats`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_section_7_4_trigger_releases_all() {
    let (env, c) = streaming(|_| {}).await;
    let ws = env.hid_ready().await;
    c.key(A, true);
    assert_eq!(
        after_start(&env, ws, 2).await,
        [EPOCH_ZERO.to_vec(), kbd(0, 0x04)]
    );
    c.synchronize(false);
    assert_eq!(
        after_start(&env, ws, 3).await,
        [EPOCH_ZERO.to_vec(), kbd(0, 0x04), zero()],
        "Synchronize releases all at once"
    );
    assert_eq!(env.metrics().release_all.get("synchronize"), 1);
    // m6: the key-down the client re-sends for the held key presses it.
    c.key(A, true);
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws).await,
        [
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x04),
            zero(),
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x04),
            zero()
        ]
    );
}

/// §7.4 released-by-bridge: a key held across a release (here a websocket
/// reconnect, which keeps the marks) is not pressed again by its
/// typematic repeats — only by a fresh press after its client release.
/// (Deviation from the plan's Synchronize: see the case above.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_held_across_a_release_is_not_repressed_by_repeats() {
    let (env, c) = streaming(|_| {}).await;
    let ws = env.hid_ready().await;
    c.key(A, true);
    assert_eq!(
        after_start(&env, ws, 2).await,
        [EPOCH_ZERO.to_vec(), kbd(0, 0x04)]
    );
    env.sim.close_websockets();
    let ws2 = env.hid_ready_after(1).await;
    for _ in 0..3 {
        c.key(A, true); // typematic repeats of the still-held key
    }
    c.key(A, false);
    c.key(A, true); // a fresh press
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws2).await,
        [EPOCH_ZERO.to_vec(), kbd(0, 0x04), zero()],
        "a repeat re-pressed a key released by the bridge"
    );
    assert_eq!(env.metrics().release_all.get("websocket_reconnect"), 1);
}

/// §7.4 `key_repeat_timeout` (scaled to 1 s): typematic repeats keep a key
/// held; silence releases it — not before 0.5× and within 5× of the
/// timeout after the last repeat (§11.1) — and a repeat after that release
/// does not press it again (released-by-bridge).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typematic_repeats_hold_the_key_but_silence_releases_it() {
    let timeout = ms(1000);
    let (env, c) = streaming(|c| c.input.key_repeat_timeout = timeout).await;
    let ws = env.hid_ready().await;
    c.key(A, true);
    let mut last = Instant::now();
    for _ in 0..10 {
        tokio::time::sleep(ms(200)).await;
        c.key(A, true);
        last = Instant::now();
    }
    assert_eq!(
        after_start(&env, ws, 2).await,
        [EPOCH_ZERO.to_vec(), kbd(0, 0x04)],
        "a release while the repeats came"
    );
    let released = stamp_of(&env, ws, 2).await;
    within(released.saturating_duration_since(last), timeout);
    c.key(A, true); // a repeat after the release
    c.key(A, false);
    c.key(A, true);
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws).await,
        [
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x04),
            zero(),
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x04),
            zero()
        ]
    );
    assert_eq!(env.metrics().release_all.get("key_repeat"), 1);
}

/// §7.4: mouse motion is not keyboard activity — a held key with no repeat
/// releases at `key_repeat_timeout` (scaled to 1 s) while the pointer keeps
/// moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mouse_motion_never_resets_the_key_timers() {
    let timeout = ms(1000);
    let (env, c) = streaming(|c| c.input.key_repeat_timeout = timeout).await;
    let ws = env.hid_ready().await;
    let t0 = Instant::now();
    c.key(A, true);
    let mut moved_until = t0;
    for i in 0..10u16 {
        tokio::time::sleep(ms(200)).await;
        c.mouse_move(100 + i * 10, 100);
        moved_until = Instant::now();
    }
    let released = |f: &[Vec<u8>]| -> Option<usize> {
        let pressed = f.iter().position(|x| *x == kbd(0, 0x04))?;
        f[pressed..]
            .iter()
            .position(|x| *x == zero())
            .map(|i| pressed + i)
    };
    env.sim
        .wait_for(T, |l| released(&hid_on(l, ws)).is_some())
        .await
        .unwrap_or_else(|l| panic!("the key never released: {:02x?}", hid_on(&l, ws)));
    let stamped = hid_stamped(&env.sim, ws);
    let frames: Vec<Vec<u8>> = stamped.iter().map(|(_, f)| f.clone()).collect();
    let at = stamped[released(&frames).unwrap()].0;
    within(at.saturating_duration_since(t0), timeout);
    assert!(
        at < moved_until,
        "the release came only after the motion stopped"
    );
    assert_eq!(env.metrics().release_all.get("key_repeat"), 1);
}

/// §11.3 Stuck keys (D10b): two keys held, typematic repeats of the second
/// only → no release (`key_repeat_timeout` scaled to 1 s; 3 s of repeats):
/// both stay held until the client releases them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_keys_held_with_repeats_of_the_second_only_never_release() {
    let (env, c) = streaming(|c| c.input.key_repeat_timeout = ms(1000)).await;
    let ws = env.hid_ready().await;
    c.key(A, true);
    c.key(B, true);
    for _ in 0..15 {
        tokio::time::sleep(ms(200)).await;
        c.key(B, true);
    }
    c.key(B, false);
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws).await,
        [
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x04),
            keys(0, [0x04, 0x05, 0, 0, 0]),
            kbd(0, 0x04),
            zero()
        ],
        "a release while the second key repeated"
    );
    assert_eq!(env.metrics().release_all.get("key_repeat"), 0);
}

/// §7.4's second timer (D10b): a modifier held with no keyboard event for
/// `modifier_idle_timeout` (scaled to 1 s) is released — never before the
/// timeout, within 2.5× of it — and its typematic repeat after that does
/// not press it again until a client release (released-by-bridge, D3a).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_modifier_releases_after_modifier_idle_timeout() {
    let timeout = ms(1000);
    let (env, c) = streaming(|c| c.input.modifier_idle_timeout = timeout).await;
    let ws = env.hid_ready().await;
    let t0 = Instant::now();
    c.key(LCTRL, true);
    let took = stamp_of(&env, ws, 2).await.saturating_duration_since(t0);
    assert!(
        took >= timeout && took <= timeout * 5 / 2,
        "released {took:?} after the press (timeout {timeout:?})"
    );
    c.key(LCTRL, true); // a repeat after the release
    c.key(LCTRL, false);
    c.key(LCTRL, true);
    c.key(LCTRL, false);
    assert_eq!(
        until_mark(&env, &c, ws).await,
        [
            EPOCH_ZERO.to_vec(),
            kbd(0x01, 0),
            zero(),
            EPOCH_ZERO.to_vec(),
            kbd(0x01, 0),
            zero()
        ]
    );
    assert_eq!(env.metrics().release_all.get("modifier_idle"), 1);
}
