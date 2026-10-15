//! §11.3 Input and Stuck keys (DC7's carry): the real client → the input
//! handler → the core → the writer → kvm-sim. Each case waits for
//! `hid_ready` (the session-start sequence on the wire) before it sends,
//! and asserts on the frames kvm-sim recorded after that sequence. A
//! script's final check ends at a pointer move to `MARK` (`until_mark`).
//!
//! Every release is followed, on the core's next step, by one extra
//! all-zero keyboard report: the step that sees the moved epoch pushes its
//! released state (PD6 m6). The session start's release is one, so the
//! first event of a case pushes that zero ahead of its own report; the
//! goldens expect it (`EPOCH_ZERO`).
use crate::client::{Client, FpButton, Opts, pictures};
use crate::harness::{
    Env, KBD_ZERO, SURFACE, T, abs, after_start, env, es3, hid_on, hid_stamped, ms, sized,
    streaming, until, until_mark, within, ws_opens,
};
use kvm_proto::hid::{HidFrame, Wheel};
use kvm_rdp::hid::HidControl;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    keys(modifiers, [k, 0, 0, 0, 0])
}

fn keys(modifiers: u8, keys: [u8; 5]) -> Vec<u8> {
    HidFrame::Keyboard { modifiers, keys }.to_vec()
}

fn zero() -> Vec<u8> {
    KBD_ZERO.to_vec()
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
    let (cx, cy) = (SURFACE.0 / 2, SURFACE.1 / 2);
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

/// The toggled key of the blocked-writer cases (set-1 0x32, usage 0x10).
const M: u8 = 0x32;

/// The keyboard state with K held (it is, all through the blocked-writer
/// cases), M held if `m`, and then `then`'s usages, in press order.
fn with_k(m: bool, then: &[u8]) -> HidFrame {
    let mut keys = [0u8; 5];
    let held = std::iter::once(0x0E)
        .chain(m.then_some(0x10))
        .chain(then.iter().copied());
    for (slot, usage) in keys.iter_mut().zip(held) {
        *slot = usage;
    }
    HidFrame::Keyboard { modifiers: 0, keys }
}

/// A session whose HID writer is blocked: kvm-sim's reads are paused, and
/// a flood has filled kvm-sim's small receive buffer and the bridge's
/// capped send buffer until a write blocks — checked: reports wait in the
/// queue and none is written for `STALL`. K is held from before the flood
/// and stays held (PD10 re-review m5-r), so no report written before a
/// release is all-zero; M is the toggled key, `m_held` whether it is down.
struct Blocked {
    env: Env,
    c: Client,
    ws: u64,
    hid: Arc<HidControl>,
    m_held: bool,
}

/// `Blocked`, with the input queue at its least (9). The fill is bounded by
/// `T`, not by a count of floods: a starved writer may need many to fill
/// the buffers, because a full queue collapses each flood into resyncs
/// (PD10 review I2). `hid_write_timeout` is raised far past every bound
/// the cases wait on, so the blocked write never reconnects, and
/// `key_repeat_timeout` so the held keys are never released by the timer.
async fn blocked_writer() -> Blocked {
    /// Far more reports than kvm-sim's 4 KiB receive buffer and the 16 KiB
    /// send cap hold together (about 18 bytes each on the wire).
    const FLOOD: usize = 4000;
    const STALL: Duration = Duration::from_millis(300);
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, |c| {
        sized(c);
        c.input.queue = QUEUE;
        c.input.hid_write_timeout = Duration::from_secs(30);
        c.input.key_repeat_timeout = Duration::from_secs(60);
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    let ws = env.hid_ready().await;
    let hid = env.bridge().hid().clone();
    let written = || env.metrics().hid_reports_sent.get();
    c.key(K, true);
    newest(&hid, with_k(false, &[])).await;
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    // Press and release a..j over and over, K held: every event is a new
    // state, and none is all-zero.
    let flood: Vec<(u8, bool)> = (0..FLOOD / 2)
        .flat_map(|i| {
            let k = [0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24][i % 10];
            [(k, true), (k, false)]
        })
        .collect();
    let t0 = Instant::now();
    loop {
        c.keys(&flood);
        // A marker press: once it is the queue's newest state, every event
        // before it has been pushed.
        c.key(M, true);
        newest(&hid, with_k(true, &[])).await;
        let w = written();
        if !until(STALL, || written() != w).await && hid.queued() > 0 {
            break;
        }
        assert!(
            t0.elapsed() < T,
            "the writer never blocked within {T:?}: {} reports written",
            written()
        );
        c.key(M, false);
        newest(&hid, with_k(false, &[])).await;
    }
    assert!(
        env.metrics().hid_resyncs.get() >= 1,
        "the flood never overflowed the queue"
    );
    Blocked {
        env,
        c,
        ws,
        hid,
        m_held: true,
    }
}

impl Blocked {
    /// Toggle M: one push.
    async fn toggle(&mut self) {
        self.m_held = !self.m_held;
        self.c.key(M, self.m_held);
        newest(&self.hid, with_k(self.m_held, &[])).await;
    }

    /// M's release and press, one push each, until the queue holds exactly
    /// `n`: the writer is blocked, so nothing leaves the queue meanwhile.
    /// Bounded by `T` (PD10 re-review m-r2): a writer that is not blocked
    /// drains the queue, and this would chase it.
    async fn fill_to(&mut self, n: usize) {
        let t0 = Instant::now();
        while self.hid.queued() < n {
            assert!(
                t0.elapsed() < T,
                "the queue never held {n} reports within {T:?}: the writer is not blocked"
            );
            self.toggle().await;
        }
    }
}

/// The input queue's capacity in the blocked-writer cases: its least.
const QUEUE: usize = 9;

/// §7.3 through the client (Plan C's `hid::a_full_queue_resyncs`, now from
/// the client). With the writer blocked (`blocked_writer`, whose flood has
/// overflowed the queue on the way), the queue is filled to exactly its
/// cap, so the final press is a push that finds it full: queued nowhere,
/// it reaches the KVM only as the resync's final state. Once reads resume,
/// the last frame kvm-sim sees is that state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_resyncs_to_the_correct_final_state_through_the_client() {
    let mut b = blocked_writer().await;
    b.fill_to(QUEUE).await;
    let resyncs = b.env.metrics().hid_resyncs.get();
    b.c.key(Z, true);
    let last = with_k(b.m_held, &[0x1D]);
    newest(&b.hid, last).await;
    assert_eq!(
        (b.hid.queued(), b.env.metrics().hid_resyncs.get()),
        (0, resyncs + 1),
        "the final press was queued, not carried by a resync"
    );
    b.env.sim.set_policy(|p| p.pause_ws_reads = false);
    let ws = b.ws;
    b.env
        .sim
        .wait_for(T, |l| hid_on(l, ws).last() == Some(&last.to_vec()))
        .await
        .unwrap_or_else(|l| {
            panic!(
                "the final state never came last: {:02x?}",
                hid_on(&l, ws).last()
            )
        });
    assert_eq!(
        ws_opens(&b.env.sim.events()).len(),
        1,
        "the paused reads reconnected the websocket"
    );
    b.c.key(Z, false);
    b.c.key(M, false);
    b.c.key(K, false);
}

/// §11.3 Input (§7.3, §7.4; PD10 review m5): with reports queued behind a
/// blocked write, a release trigger — the client's Synchronize — produces
/// only the zero reports and then the current state. Q's press and release
/// are queued (the queue is emptied first by one clearing push), the
/// Synchronize releases all, and once reads resume no Q report ever
/// reaches kvm-sim: after what was already on the wire — every report of
/// it with K held, so none all-zero (re-review m5-r) — come the release's
/// zero, the next step's epoch zero and the new state, X held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_behind_a_blocked_write_sends_only_zeros_then_new_state() {
    const Q: u8 = 0x10; // usage 0x14
    const X: u8 = 0x2D; // usage 0x1B
    let mut b = blocked_writer().await;
    // Full, then one more push clears it (a resync): the queue is empty.
    b.fill_to(QUEUE).await;
    b.toggle().await;
    assert_eq!(b.hid.queued(), 0);
    b.c.key(Q, true);
    newest(&b.hid, with_k(b.m_held, &[0x14])).await;
    b.c.key(Q, false);
    newest(&b.hid, with_k(b.m_held, &[])).await;
    assert_eq!(b.hid.queued(), 2, "Q's reports are queued");
    b.c.synchronize(false);
    assert!(
        until(T, || b.env.metrics().release_all.get("synchronize") == 1).await,
        "the Synchronize released nothing"
    );
    b.c.key(X, true);
    let new_state = kbd(0, 0x1B);
    newest(
        &b.hid,
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0x1B, 0, 0, 0, 0],
        },
    )
    .await;
    b.env.sim.set_policy(|p| p.pause_ws_reads = false);
    let ws = b.ws;
    let log = b
        .env
        .sim
        .wait_for(T, |l| hid_on(l, ws).last() == Some(&new_state))
        .await
        .unwrap_or_else(|l| {
            panic!(
                "the new state never came last: {:02x?}",
                hid_on(&l, ws).last()
            )
        });
    let frames = hid_on(&log, ws);
    assert!(
        !frames
            .iter()
            .any(|f| f.len() == 12 && f[7..].contains(&0x14)),
        "a report queued behind the blocked write reached the KVM after the release"
    );
    assert_eq!(
        frames[frames.len() - 3..],
        [zero(), EPOCH_ZERO.to_vec(), new_state],
        "the release's zero, the epoch zero, then the new state"
    );
    assert_eq!(ws_opens(&log).len(), 1, "the paused reads reconnected");
    b.c.key(X, false);
    b.c.key(M, false);
    b.c.key(K, false);
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
/// And the release really is the core's (PD10 review m1): another key
/// pressed while the client still holds the first reports alone, never
/// with the first re-sent beside it — a reconnect that left the core's
/// state held would type the first key again here.
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
    c.key(B, true); // a held, not re-sent
    c.key(B, false);
    c.key(A, false);
    c.key(A, true); // a fresh press
    c.key(A, false);
    assert_eq!(
        until_mark(&env, &c, ws2).await,
        [
            EPOCH_ZERO.to_vec(),
            kbd(0, 0x05),
            zero(),
            kbd(0, 0x04),
            zero()
        ],
        "a key released by the bridge was pressed again"
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

/// Hold `held` (a set-1 make code whose report is `pressed`), then move the
/// pointer every 200 ms for 2 s with no keyboard event: the release (the
/// first all-zero keyboard report after `pressed`) comes `within` 0.5×–5×
/// of `timeout` after the press, and before the motion stopped.
async fn released_despite_motion(env: &Env, c: &Client, ws: u64, held: u8, pressed: Vec<u8>) {
    let timeout = ms(1000);
    let after = hid_on(&env.sim.events(), ws).len();
    let t0 = Instant::now();
    c.key(held, true);
    let mut moved_until = t0;
    for i in 0..10u16 {
        tokio::time::sleep(ms(200)).await;
        c.mouse_move(100 + i * 10, 100);
        moved_until = Instant::now();
    }
    let released = |f: &[Vec<u8>]| -> Option<usize> {
        let p = after + f.get(after..)?.iter().position(|x| *x == pressed)?;
        f[p..].iter().position(|x| *x == zero()).map(|i| p + i)
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
}

/// §7.4 / §11.3: mouse motion is not keyboard activity, for either timer
/// (both scaled to 1 s). A held key with no repeat releases at
/// `key_repeat_timeout`, and a held modifier with no keyboard event at
/// `modifier_idle_timeout` (PD10 review m3), while the pointer keeps moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mouse_motion_never_resets_the_key_timers() {
    let (env, c) = streaming(|c| {
        c.input.key_repeat_timeout = ms(1000);
        c.input.modifier_idle_timeout = ms(1000);
    })
    .await;
    let ws = env.hid_ready().await;
    released_despite_motion(&env, &c, ws, A, kbd(0, 0x04)).await;
    assert_eq!(env.metrics().release_all.get("key_repeat"), 1);
    c.key(A, false);
    released_despite_motion(&env, &c, ws, LCTRL, kbd(0x01, 0)).await;
    assert_eq!(env.metrics().release_all.get("modifier_idle"), 1);
    c.key(LCTRL, false);
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
