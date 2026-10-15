//! §11.3 Paste (Plan D): the chord, the Typist, newline handling, the
//! aborts and the limits, over the real client's CLIPRDR channel — the
//! client offers CF_UNICODETEXT, the chord makes the bridge ask for it, and
//! kvm-sim records what the Typist types. §11.1's scaled config: pace 0,
//! modifier wait 300 ms; a case that must act while typing is under way
//! paces it (10–20 ms) so there is a "mid-typing" to act in.
//!
//! The session start's release is followed by one all-zero report from the
//! core's next step (PD6 m6). Here that step is the client's format list or
//! the chord's first press, and the format list can beat the websocket's
//! open (then its zero is discarded with the queue): `settled` drops that
//! one leading zero when it landed.
use crate::client::{Client, Ev, FpButton, Opts, description, pictures, terminated};
use crate::harness::{
    CHORD_MODS, Env, KBD_ZERO, MARK, T, abs, env, es3, hid_on, ms, paste_chord, sized, typed,
    until, until_mark, until_mark_at, within, ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_rdp::config::{Config, Multiline};
use kvm_rdp::msg::Cause;
use kvm_sim::SimEvent;
use std::time::Instant;

/// A second session's mark: its session start already puts the pointer at
/// the first session's `MARK`.
const MARK2: (u16, u16) = (13, 17);
const ESC: u8 = 0x01; // usage 0x29
const Q: u8 = 0x10; // usage 0x14

fn mods(modifiers: u8) -> Vec<u8> {
    HidFrame::Keyboard {
        modifiers,
        keys: [0; 5],
    }
    .to_vec()
}

fn kbd(k: u8) -> Vec<u8> {
    HidFrame::Keyboard {
        modifiers: 0,
        keys: [k, 0, 0, 0, 0],
    }
    .to_vec()
}

/// The chord's own reports (`paste_chord`): LCtrl, LAlt, LShift down, and
/// with `release_mods` up again. V never reaches the KVM.
fn chord_frames(release_mods: bool) -> Vec<Vec<u8>> {
    let mut v = vec![mods(0x01), mods(0x05), mods(0x07)];
    if release_mods {
        v.extend([mods(0x06), mods(0x02), mods(0)]);
    }
    v
}

/// The frames after a session start less the start release's zero, when
/// it landed on this websocket (module doc).
fn settled(mut frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if frames.first() == Some(&KBD_ZERO.to_vec()) {
        frames.remove(0);
    }
    frames
}

/// Whether a keyboard frame in `frames` carries `usage` in a key slot.
fn carries(frames: &[Vec<u8>], usage: u8) -> bool {
    frames
        .iter()
        .any(|f| f.len() == 12 && f[2] == 0x08 && f[7..].contains(&usage))
}

/// Every HID frame kvm-sim received, on any websocket.
fn every_frame(log: &[SimEvent]) -> Vec<Vec<u8>> {
    ws_opens(log)
        .into_iter()
        .flat_map(|ws| hid_on(log, ws))
        .collect()
}

/// The client is streaming and its CLIPRDR channel is up: the bridge has
/// its format list.
async fn ready(c: &Client) {
    c.wait_for(T, |e| {
        pictures(e).len() >= 5 && e.iter().any(|x| matches!(x, Ev::ClipReady))
    })
    .await;
}

/// A bridge with §11.1's scaled paste config and `edit`; a client holding
/// `text`, ready; the HID websocket's session start on the wire.
async fn pasting(text: &str, edit: impl FnOnce(&mut Config)) -> (Env, Client, u64) {
    let env = env(es3(), |c| {
        sized(c);
        c.paste.pace = ms(0);
        c.paste.modifier_wait = ms(300);
        edit(c);
    })
    .await;
    let c = env.client(Opts::new(2).clipboard(text));
    ready(&c).await;
    let ws = env.hid_ready().await;
    (env, c, ws)
}

fn pasted(env: &Env, label: &str) -> u64 {
    env.metrics().paste_events.get(label)
}

async fn counted(env: &Env, label: &str, n: u64) {
    assert!(
        until(T, || pasted(env, label) >= n).await,
        "paste_events{{{label}}} never reached {n} (it is {})",
        pasted(env, label)
    );
}

/// The Typist's first press (`a`, usage 0x04) is on kvm-sim.
async fn typing(env: &Env, ws: u64) {
    env.sim
        .wait_for(T, |l| hid_on(l, ws).contains(&kbd(0x04)))
        .await
        .unwrap_or_else(|l| panic!("nothing was typed: {:02x?}", hid_on(&l, ws)));
}

/// §8 end to end: CRLF and LF type one Return each, Tab types Tab, the
/// emoji (a surrogate pair the US layout cannot type) is skipped and
/// counted, the trailing break and the NUL terminator type nothing (D4);
/// each character a press, then the all-zero release.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paste_types_the_exact_report_list() {
    let (env, c, ws) = pasting("a\r\nb\tc\u{1F600}\n", |_| {}).await;
    paste_chord(&c, true);
    counted(&env, "done", 1).await;
    let mut want = chord_frames(true);
    want.extend(typed("a\nb\tc"));
    assert_eq!(settled(until_mark(&env, &c, ws).await), want);
    assert_eq!(env.metrics().paste_skipped_chars.get(), 1, "the emoji");
    assert_eq!(pasted(&env, "started"), 1);
}

/// §8 `multiline = "refuse"`: an inner break refuses the paste (nothing
/// typed); a trailing one is dropped, so a second client's `"a\n"` (a new
/// session) types `a`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiline_refuse_refuses_an_inner_break_but_types_a_trailing_one() {
    let (env, c, ws) = pasting("a\nb", |c| c.paste.multiline = Multiline::Refuse).await;
    paste_chord(&c, true);
    counted(&env, "multiline", 1).await;
    assert_eq!(
        settled(until_mark(&env, &c, ws).await),
        chord_frames(true),
        "a refused paste typed"
    );
    let opens = ws_opens(&env.sim.events()).len();
    let c2 = env.client(Opts::new(3).clipboard("a\n"));
    ready(&c2).await;
    let ws2 = env.hid_ready_after(opens).await;
    paste_chord(&c2, true);
    counted(&env, "done", 1).await;
    let got = until_mark_at(&env, &c2, ws2, MARK2).await;
    assert_eq!(
        got[0],
        abs(0, MARK.0, MARK.1),
        "the session start's pointer"
    );
    let mut want = chord_frames(true);
    want.extend(typed("a"));
    assert_eq!(settled(got[1..].to_vec()), want);
    assert_eq!(pasted(&env, "multiline"), 1);
}

/// §8: a fresh Esc mid-typing aborts. kvm-sim's frames are a strict prefix
/// of the full report list, then the abort's all-zero report; Esc (usage
/// 0x29) is swallowed and never reaches the KVM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn esc_aborts_and_usage_0x29_is_never_sent() {
    let text = "abcdefghijklmnopqrstuvwxyz".repeat(4);
    let (env, c, ws) = pasting(&text, |c| c.paste.pace = ms(10)).await;
    paste_chord(&c, true);
    typing(&env, ws).await;
    c.key(ESC, true);
    c.key(ESC, false);
    counted(&env, "aborted", 1).await;
    let got = settled(until_mark(&env, &c, ws).await);
    let chord = chord_frames(true);
    assert_eq!(got[..chord.len()], chord);
    let (last, prefix) = got[chord.len()..].split_last().unwrap();
    assert_eq!(*last, KBD_ZERO.to_vec(), "the abort ends with all-zero");
    let full = typed(&text);
    assert!(
        prefix.len() < full.len() && full.starts_with(prefix),
        "not a strict prefix of the paste: {} of {} reports",
        prefix.len(),
        full.len()
    );
    assert!(
        !carries(&hid_on(&env.sim.events(), ws), 0x29),
        "Esc reached the KVM"
    );
    assert_eq!(pasted(&env, "done"), 0);
}

/// §8: a mouse click mid-typing aborts the paste; the click itself goes
/// through, after the abort's all-zero report.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mouse_click_aborts() {
    let text = "abcdefghij".repeat(10);
    let (env, c, ws) = pasting(&text, |c| c.paste.pace = ms(10)).await;
    paste_chord(&c, true);
    typing(&env, ws).await;
    c.mouse_button(FpButton::Left, true, 10, 10);
    c.mouse_button(FpButton::Left, false, 10, 10);
    counted(&env, "aborted", 1).await;
    let got = settled(until_mark(&env, &c, ws).await);
    let chord = chord_frames(true);
    assert_eq!(got[..chord.len()], chord);
    let (typed_part, tail) = got[chord.len()..].split_at(got.len() - chord.len() - 3);
    assert_eq!(
        tail,
        [KBD_ZERO.to_vec(), abs(0x01, 10, 10), abs(0, 10, 10)],
        "the abort's zero, then the click"
    );
    let full = typed(&text);
    assert!(typed_part.len() < full.len() && full.starts_with(typed_part));
    assert_eq!(pasted(&env, "done"), 0);
}

/// §11.3 (D10b, D30): a key pressed mid-typing never reaches kvm-sim — Q's
/// press only; its release comes after the paste. The swallowed Q is
/// released by the bridge (D3c), so its typematic repeat after the paste
/// pushes nothing, and only a fresh press after its release does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_pressed_mid_typing_never_reaches_the_kvm() {
    // 30 characters at 20 ms a report: 1.2 s of typing to press Q in.
    let text = "abcdefghij".repeat(3);
    let (env, c, ws) = pasting(&text, |c| c.paste.pace = ms(20)).await;
    paste_chord(&c, true);
    typing(&env, ws).await;
    c.key(Q, true);
    counted(&env, "done", 1).await;
    assert!(
        !carries(&hid_on(&env.sim.events(), ws), 0x14),
        "Q pressed mid-typing reached the KVM"
    );
    c.key(Q, true); // a typematic repeat: pushes nothing
    c.key(Q, false);
    c.key(Q, true); // a fresh press after the release
    c.key(Q, false);
    let mut want = chord_frames(true);
    want.extend(typed(&text));
    want.extend([kbd(0x14), KBD_ZERO.to_vec()]);
    assert_eq!(settled(until_mark(&env, &c, ws).await), want);
}

/// §11.3 (D10b): an 8 MiB CF_UNICODETEXT answer, sent in full over the
/// SVC, ends the session as `clipboard_oversize` (counted once, by the
/// pump's close: D17); nothing is typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_8_mib_payload_is_clipboard_oversize_and_types_nothing() {
    let text = "x".repeat(4 << 20); // 8 MiB of UTF-16
    let (env, c, _ws) = pasting(&text, |_| {}).await;
    paste_chord(&c, true);
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(
        terminated(&evs).unwrap(),
        description(Cause::ClipboardOversize)
    );
    assert!(
        until(T, || env.metrics().disconnects.get("clipboard_oversize")
            == 1)
        .await,
        "disconnects{{clipboard_oversize}} is {}",
        env.metrics().disconnects.get("clipboard_oversize")
    );
    // At the scaled 300 ms `modifier_wait` the transfer may outlast the
    // pending paste (DD4 bounds the answer's wait too): it ended once,
    // refused for the oversize or timed out first.
    assert_eq!(pasted(&env, "oversize") + pasted(&env, "aborted"), 1);
    assert!(
        !carries(&every_frame(&env.sim.events()), 0x1B),
        "an x reached the KVM"
    );
}

/// DD4: modifiers still held at `paste.modifier_wait` (scaled to 300 ms)
/// cancel the paste — within §11.1's bounds — and nothing is typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modifiers_held_past_the_wait_cancel() {
    let wait = ms(300);
    let (env, c, ws) = pasting("abc", |c| c.paste.modifier_wait = wait).await;
    let t0 = Instant::now();
    paste_chord(&c, false);
    counted(&env, "aborted", 1).await;
    within(t0.elapsed(), wait);
    for m in CHORD_MODS {
        c.key(m, false);
    }
    assert_eq!(
        settled(until_mark(&env, &c, ws).await),
        chord_frames(true),
        "a cancelled paste typed"
    );
    assert_eq!(pasted(&env, "done"), 0);
}

/// §8 (DD5): with the client's last Synchronize reporting Caps Lock on,
/// the paste is refused; nothing is typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_lock_on_refuses() {
    let (env, c, ws) = pasting("abc", |_| {}).await;
    c.synchronize(true);
    paste_chord(&c, true);
    counted(&env, "caps_lock", 1).await;
    let got = until_mark(&env, &c, ws).await;
    // Synchronize released all: zero reports only, then the chord's own.
    let chord = chord_frames(true);
    assert!(got.ends_with(&chord), "{got:02x?}");
    assert!(
        got[..got.len() - chord.len()]
            .iter()
            .all(|f| *f == KBD_ZERO.to_vec()),
        "{got:02x?}"
    );
    assert_eq!((pasted(&env, "started"), pasted(&env, "done")), (0, 0));
}

/// §8: the chord's key is swallowed — no frame of a paste carries V's
/// usage (0x19).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chord_key_never_reaches_the_kvm() {
    let (env, c, ws) = pasting("abc", |_| {}).await;
    paste_chord(&c, true);
    counted(&env, "done", 1).await;
    let got = settled(until_mark(&env, &c, ws).await);
    let mut want = chord_frames(true);
    want.extend(typed("abc"));
    assert_eq!(got, want);
    assert!(
        !carries(&hid_on(&env.sim.events(), ws), 0x19),
        "V reached the KVM"
    );
}

/// §8 `paste.max_bytes`: an answer one UTF-16 unit over 64 KiB (with its
/// terminator) ends the session as `clipboard_oversize` (the client sees
/// 0x7, ServerDeniedConnection; counted once, D17) and types nothing; a
/// second client's answer of exactly 64 KiB — 64 KiB − 2 bytes of text and
/// the terminator — is taken, and typed up to `paste.max_chars`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_response_drops_the_session() {
    const MAX: usize = 64 << 10;
    const CHARS: usize = 16;
    let over = "a".repeat(MAX / 2); // 64 KiB + the 2-byte terminator
    let (env, c, _ws) = pasting(&over, |c| {
        c.paste.max_bytes = MAX;
        c.paste.max_chars = CHARS;
    })
    .await;
    paste_chord(&c, true);
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(
        terminated(&evs).unwrap(),
        description(Cause::ClipboardOversize)
    );
    assert!(
        until(T, || env.metrics().disconnects.get("clipboard_oversize")
            == 1)
        .await,
        "disconnects{{clipboard_oversize}} is {}",
        env.metrics().disconnects.get("clipboard_oversize")
    );
    assert_eq!(pasted(&env, "oversize") + pasted(&env, "aborted"), 1);
    assert!(
        !carries(&every_frame(&env.sim.events()), 0x04),
        "an oversize paste typed"
    );
    let opens = ws_opens(&env.sim.events()).len();
    let c2 = env.client(Opts::new(3).clipboard(&"a".repeat(MAX / 2 - 1)));
    ready(&c2).await;
    let ws2 = env.hid_ready_after(opens).await;
    paste_chord(&c2, true);
    counted(&env, "done", 1).await;
    let mut want = chord_frames(true);
    want.extend(typed(&"a".repeat(CHARS)));
    assert_eq!(settled(until_mark(&env, &c2, ws2).await), want);
    assert_eq!(env.metrics().disconnects.get("clipboard_oversize"), 1);
}
