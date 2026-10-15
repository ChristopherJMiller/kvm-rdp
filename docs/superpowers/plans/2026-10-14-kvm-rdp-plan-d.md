# kvm-rdp Plan D — input, paste and the L4 hardware checks (Milestones 3b + 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure what only the real ES3 can tell (§11.6's L4 list, first), then turn the client's keyboard, mouse and clipboard-paste into the KVM's HID frames — scancode/US-layout mapping, absolute mouse scaling, the release epoch and released-by-bridge rule, both stuck-key timers, the paste chord and the Typist over CLIPRDR — proven by L0/L1-style sans-IO tests and L2 cases against kvm-sim through a real IronRDP client.

**Architecture:** Pure tables and pure functions go into `kvm-proto` (`keymap`: set-1 scancode → HID usage, the US layout, `paste.chord`; `hid::scale_abs`; `paste`: §8's text handling, UTF-16 decoding and the `Typist` pacer). The input state machine is one sans-IO core in `kvm-rdp` (`input::core::InputCore`, over `input::keys`, `input::pointer` and `input::paste`) that takes `now` and a context snapshot (release epoch, current generation, surface size, HID-queue room) and returns `Out`s. Its async shell, `rdp::input::InputShared`, is driven from two places — IronRDP's input handler on the RDP thread, and a driver task on the same `LocalSet` that sleeps until the core's next deadline — and carries the outs out: `HidControl::push_at` stamped with the epoch the core's state was built at, `release_all`, CLIPRDR requests (current generation only), metrics. CLIPRDR is IronRDP's own `CliprdrServer` with a per-connection backend bound to its generation like the GFX handle. The L4 checks are new `kvm-probe` subcommands, proven against kvm-sim in kvm-sim's own test binary, then run once against the ES3 as an agent-driven runbook.

**Tech Stack:** Rust 1.94.1 (edition 2024); IronRDP fork `ChristopherJMiller/IronRDP` branch `kvm-rdp-egfx-patches-v2` @ `c99eece22338e26ee6839ee89c29617bbcadbb65` (unchanged pin; Plan D adds `ironrdp-cliprdr` at the same rev — already compiled inside `ironrdp-server`'s graph, so no new compile unit); tokio 1, tokio-tungstenite 0.24, hyper 1, rustls 0.23 (aws-lc-rs only), socket2 0.6 (already in the graph); kvm-sim and kvm-probe from Plans A–C.

**Spec:** `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (Draft rev 6.2) — the binding authority — with `docs/census.md`. This plan is §12's planning unit **D**: "M3b + M4: first §11.6's L4 hardware checks (rev 6.2, moved from C); keyboard and mouse mapping, stuck-key timers and the released-by-bridge rule, the Typist, and their L2 cases". Plan C's plan (`docs/superpowers/plans/2026-10-07-kvm-rdp-plan-c.md`) is the format exemplar; its ledger (`.superpowers/sdd/2026-10-07-kvm-rdp-plan-c/progress.md`) and final review (`.superpowers/sdd/2026-10-07-kvm-rdp-plan-c/final-review.md`, "Recommendations") are binding inputs — see "Carries from Plan C".

**Scope:** in — §11.6's L4 checks (DC18's five and Plan C's four), §7.1–§7.4, §8, the §11.3 Input, Stuck keys and Paste cases, the secrets case's keystroke sentinel and paste canary (DC9), the mid-session KVM certificate change (PC7 W10), the replay-divergence L2 case (PC17 m1), re-asserting HID state after a reconnect (PC9 fix 2), and spec rev 6.3. Out: L3, kvm-bench, the container image, release builds, the perf pass and everything the final review carried to Plan E (remap-path-prefix, SHA-pinned actions, cargo-deny, the allocation budget, a minimum SPS frame size, gating the `Stall` hook); the owner's Windows App acceptance run (Plan D only adds items to its checklist); anything Plan C's final fix wave lands (the websocket's 16 KiB `SO_SNDBUF` cap, config errors that never echo a `*_file` value, bounded admin writes, the `kvm.scheme = http` warning).

**Design decisions** (one line each, with why):

1. **L4 first, as tooling plus one runbook task** — Part 1 builds `kvm-probe` subcommands for every L4 check (each proven against kvm-sim first), Task 1.6 runs them on the ES3 and writes derived facts only into `census.md`; later tasks read census values through explicit decision rules, so a missing owner never blocks the code tasks — because §12 orders the checks first, the census is the only place hardware facts may land, and an agent can drive every check whose observation is the video stream.
2. **The Mac is observed through the KVM's own video** — a committed, self-contained HID test page (a `data:` URL the owner opens on the Mac; the probe only prints it) shows held keys, keydown/repeat counts, buttons, wheel and a hash of the typed text; `kvm-probe snapshot` decodes one fresh IDR in the bwrap sandbox to a PNG under `captures/` that the agent reads — because the Mac's state is otherwise invisible, and the page is the "test pattern" §12's capture rule allows.
3. **The probe can never log out and never leaves a key held** — Task 1.2 removes `--logout` and `kvm::logout` from kvm-probe entirely; every HID subcommand ends through `ensure_released` (a fresh websocket's session-start sequence, retried for 30 s) on success, error, Ctrl-C, SIGTERM and SIGHUP, `hid-release` releases from a fresh process after a kill, and `hid-type` types only the generated pattern, into the test page the owner opened — because logout is global (it would end the owner's break-glass session) and the owner's rules are absolute.
4. **Tables and pure text rules in `kvm-proto`, the state machine in `kvm-rdp`** — `keymap`, `hid::scale_abs` and `paste` (prepare, UTF-16, `Typist`) are L0 in `kvm-proto` under its parser lints; `input::{keys, pointer, paste, core}` live in `kvm-rdp` beside `hid::queue`, whose `ReleaseTrigger` and epoch they use — because §4.1/§11.2 put tables and text handling in `kvm-proto`, and Plan C already put its other sans-IO cores (pump, upstream, HID queue) in `kvm-rdp` (DD2).
5. **One sans-IO input core, two drivers** — `InputCore::step(now, Ctx, Event, &mut Vec<Out>)` and `next_deadline()`; the IronRDP handler steps it per event, a `LocalSet` driver steps it with `Event::Tick` at the next deadline (key timers, the pending paste's deadline, the Typist's pace), both under one `std::sync::Mutex`, never across an await — because the final review requires the timers to stay sans-IO, and one lock gives one order.
6. **The epoch is the release channel** — every release-all, wherever it starts (session start/end, Closing, shutdown, suppression, websocket reconnect, the core's own Synchronize and timers), bumps `HidControl`'s epoch; the core reads the epoch into its context at the start of each step, treats a change as a release (held keys and buttons become released-by-bridge, a paste ends), builds its reports from that state and pushes them with `push_at(that epoch)` — because the final review requires the state and its stamp taken together, and a report built before a release must never land after its zeros (§7.3, PC7 I1).
7. **Paste is a small state machine inside the core** — Idle → Pending (chord seen, `RequestText` out, deadline `paste.modifier_wait`) → Typing (`kvm_proto::paste::Typist`) → Idle, with every outcome counted; the chord is matched on raw scancodes before any remap; the Typist waits for room in the HID queue as well as for `paste.pace` — because §8's rules are all timing and state, and a pace of 0 in L2 must not overflow `input.queue` (DD6).
8. **CLIPRDR is IronRDP's `CliprdrServer` with a per-connection backend** — `rdp::clipboard::ClipFactory` builds one backend per connection with a slot; `on_connection_info` binds (generation, latest slot), as the GFX handle is bound; callbacks from another slot or an ended generation are dropped; the backend advertises no capabilities and answers no data request; an oversize response ends the session through a new `RdpInput::Fatal` — because §4.3 allows `ServerEvent`s for the current generation only, and §8 is one way.
9. **Re-assert after a reconnect** — every websocket open re-asserts the full HID state once, `REASSERT_AFTER` (1 s; retuned from L4) after its session-start sequence, through the queue's resync path so it never overtakes a queued report — because the KVM may read what sat in its own receive buffer after an RST (PC9 fix 2), and a full-state report is idempotent.
10. **Budget** — no new heavy dependency: `ironrdp-cliprdr` and `socket2` are already compiled in the graph; kvm-probe gains `socket2` and tokio's `signal` feature (both already unified in the workspace build); every local command stays `cargo {clippy,test} --workspace --all-targets --all-features` — because §13's rules are mechanical and the target budget is 8 GiB.

## Global Constraints

Copied from the spec and the owner's rules; every task's requirements include these.

- "Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1" (§4.2).
- §4.1: "Every hostile-input parser lives in `kvm-proto`"; `kvm-proto` has "no IronRDP, no tokio, no TLS" and its crate-root lints deny `indexing_slicing`, `unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`, `as_conversions` — new `kvm-proto` code obeys them (use `get`, `checked_*`/`saturating_*`/`wrapping_*`, `try_from`).
- §4.2: "**IronRDP is git-pinned**: one rev … for every `ironrdp-*` crate used … — no `[patch.crates-io]`"; "CI fails if `cargo tree -d` shows a duplicate `ironrdp-*` crate"; "Never the `ironrdp` meta-crate"; "**One crypto provider, aws-lc-rs** … Nothing may pull in `ring`."
- §4.3: "`kvm-rdp`'s crate root sets `#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref)]`"; "Every time-dependent decision — … paste pacing — lives in a synchronous core that takes `now: Instant` and returns commands"; "Every `ServerEvent` send, including `Disconnect`, is only made for the current generation."; "**Input path** (§7.3) and the **HID writer** never block the RDP runtime."
- §4.5 / §9.2: "Bridge code never logs keystrokes, HID frames, pasted text, the KVM token or passwords. HID and paste activity is logged as counts." "`FormatDataResponse` is never `Debug`-formatted."
- §3.2: "**The bridge never calls logout.**" — and (owner) neither does any kvm-probe run.
- §7.3 (rev 6.2): "a report is stamped before the queue lock is taken, and dropped whole … if a release came in between"; final review: "The input handler must build each report's state and take its epoch stamp together, and push through `HidControl::push_at` semantics (`push` stamps at call time). Keep the timers (`key_repeat_timeout`, `modifier_idle_timeout`) in a sans-IO core."
- §7.4: "A stuck Cmd on a work Mac is the failure this exists to prevent; every trigger has a test (§11)."
- §8: "The Typist is the only HID keyboard source" while typing; "Contents are never logged".
- §11.1: "L2 checks wiring only, with scaled-down configs (e.g. watchdog 300 ms, paste pace 0 ms, modifier wait 300 ms, stall 1 s) and one-sided asserts: *happens within 5× the configured value* and *does not happen before 0.5× of it*."; "Scancode→HID goldens come from Microsoft's published USB HID ↔ PS/2 scan-code translation table."; "Pixel→HID scaling is tested only against §7.2's formula."
- §11.5: "**Real captures from the KVM are never committed** — they show the work Mac's screen. `captures/` is gitignored, 0700, and wiped after each census session."; §12: "During captures the Mac shows only test patterns or the lock screen."
- §13, verbatim: "`.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"`"; "The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`"; the target budget is gated by `scripts/target-budget.sh` at 8 GiB; disposable scratch worktrees use their own `CARGO_TARGET_DIR` and delete it.
- Final review: "keep `leak_shapes` the single list every new config key is added to, values of `*_file` keys included" — any config key or validation rule Plan D adds or changes gets a `leak_shapes` shape.
- L4 safety (owner, absolute): the probe never logs out; it never types the owner's Mac password or the KVM web UI password — secrets come from files only, and `hid-type` types only the generated pattern, into the test page the owner opened (nothing types into the Mac's browser chrome); during captures the Mac shows only the test page or the lock screen; captures stay in the 0700 `captures/` directory, are never committed, and are wiped at the end; a key is never left held; census.md receives derived facts only.
- Owner: panic-free code over hostile KVM and client input; no secrets, tokens or captures committed; licence MIT OR Apache-2.0; every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

Five inputs or conditions the spec implies but no §11 case names, most likely to bite first; each line's test is in the owning task.

1. **A key-up for a key the bridge swallowed or released** (the chord's V, Esc mid-paste, a key pressed while the Typist types, a key, modifier or button held across a release) → no report and no state change; its typematic `Pressed` repeats stay ignored until that `Released` — never a phantom press after the paste or the release (Task 2.2 `a_bumped_epoch_releases_held_keys_before_the_next_event`, `a_held_modifier_is_not_repressed_by_repeats_after_a_release`, `a_held_button_is_released_by_bridge`; Task 3.2 `esc_aborts_and_the_typists_keys_do_not_leak`, `a_key_swallowed_during_a_paste_stays_released_after_it`).
2. **Windows App in its Unicode keyboard mode** (or an IME) → Unicode presses type through the US layout with Shift as needed, release by code unit, an untypeable or surrogate unit is ignored and counted, and a Unicode key held across a release follows the released-by-bridge rule like a scancode (Task 2.1 `unicode_keys_type_through_the_us_layout_and_follow_the_rbb_rule`).
3. **A client that floods presses of distinct keys without releasing them** (a hostile client, a stuck client keyboard) → five slots reported, at most 16 keys tracked, the rest ignored and counted, constant memory, and the key-repeat timer still releases everything (Task 2.1 `a_flood_of_distinct_presses_is_bounded`; Task 2.2 `a_flood_still_releases_on_the_key_repeat_timeout`).
4. **Pointer coordinates outside the current surface, or before the first Setup** (a resize race; a client desktop larger than the surface) → clamped to 0..=32767 against the surface, or before one against the advertised size; never a panic, never (0, 0) unless the client put the pointer there (Task 2.1 `coordinates_outside_the_surface_clamp`).
5. **A clipboard response that never comes, comes late, or comes unasked** (a slow laptop; a client answering after the user moved on) → the pending paste ends at `paste.modifier_wait`, a response then or without a request types nothing, and an oversize one still ends the session (Task 3.2 `a_late_or_unasked_clipboard_response_types_nothing`; Task 3.3 `a_response_routes_text_or_a_fatal_oversize`).

## Recorded deviations from the spec

Task 6.1 writes these into the spec as rev 6.3. None admits anything the spec refuses.

- **DD1 — the L4 runbook never logs out** (§11.6 asks for "the ES3's refusal forms for an FLV and a websocket after a global logout", and DC18 carries Plan A's "the control websocket survives another session's logout"): both need a global logout, which would end the owner's break-glass session. Plan D measures the refusal forms for a never-issued token, no token, and a token that has lapsed on its own; the logout-specific checks run only in Task 1.6's optional, owner-run step 16, where the owner logs out in the vendor web UI while `logout-watch` (Task 1.3) only watches (controller ruling 1), and stay unmeasured if it is skipped; kvm-probe loses `--logout` (Task 1.2).
- **DD2 — the input state machine lives in `kvm-rdp`** (§4.1 and §11.2 put "the sans-IO cores … that need no IronRDP types" and their L0 tests in `kvm-proto`): `kvm-proto` gets the tables (`keymap`), `hid::scale_abs` and §8's text handling and pacer (`paste`), each with L0 tests; the released-by-bridge rule, the key timers and the paste states are `kvm-rdp`'s `input::` modules with injected-clock tests, beside `hid::queue` whose epoch and `ReleaseTrigger` they use — as Plan C did for the pump, upstream and HID-queue cores.
- **DD3 — `input.mac_remap` is a switch over the fixed table §7.1 names** (§7.1 says "a config-driven remap table"; §4.4 has only the boolean): on, a report holding Ctrl and one of C, V, X, A, Z, F, W carries GUI instead of that Ctrl; there is no configurable table until the owner's key-matrix fixture exists.
- **DD4 — the pending paste** (§8 bounds only the modifier wait): from the chord until typing begins, `paste.modifier_wait` bounds both the wait for the modifiers and the wait for the clipboard response; Esc (swallowed), a fresh non-modifier press (passed through), a mouse button or any release-all cancels it; a second chord meanwhile is swallowed; modifier presses and releases pass through as ever (the chord's modifier presses reached the KVM, so their releases must too); a response that arrives when no paste is pending types nothing. Every key the bridge swallows — the chord's key, Esc, any press while typing — is released by the bridge (§7.4's rule), so its repeats after the paste are not fresh presses.
- **DD5 — Caps Lock** (§8: "If the client's last `Synchronize` reported Caps Lock on, the paste is refused"): the tracked state is the last Synchronize, toggled by each fresh Caps Lock press since, which is what the Mac's state does.
- **DD6 — the Typist waits for room** as well as `paste.pace`: a step emits at most `8 − queued` reports, each only when `paste.pace` has passed since the last (no catch-up burst), and looks again 2 ms later when the queue has no room, so `paste.pace = 0` (L2) never overflows `input.queue` and loses typed characters to a resync, and the driver never spins.
- **DD7 — what the mapping drops**: relative motion, the X1/X2 buttons (and any later `MouseButton`), horizontal and `ainput` scroll, unmapped scancodes and untypeable or surrogate Unicode units are dropped and counted in `kvm_rdp_input_events_ignored_total` (the core reports each as `Out::Ignored`), which keeps that meaning (§10.4 said Plan D replaces it); the Keyboard Power usage (0x66, `E0 5E` in Microsoft's table) is never sent.
- **DD8 — "once a reconnect settles"** (§3.2, §7.4) is concrete: every websocket open re-asserts the full state once, `REASSERT_AFTER` after its session-start sequence: 1 s, unless Task 1.6 step 9 saw stale reports land after the fresh session start; then `max(1 s, ceil(1800 / hid_rate))`, capped at `MAX_DURATION`, where `hid_rate` is the test page's measured reports/s (Task 1.6 step 7, D28) — Task 6.1's rule. The assumption behind 1 800: a stalled websocket can leave the KVM's whole receive window of reports unread, and that window is taken as 64 KiB (Linux's default receive buffer) ÷ ~37 B per report (§7.3) ≈ 1 800 reports; the probe's 128-report test burst (D5) is not that bound (D29).
- **DD9 — bounds**: at most 16 keys are tracked (5 reported), at most 32 released-by-bridge keys and modifiers are remembered; a press past the first bound, or a held key the second has no room for, is dropped and counted.
- **DD10 — `paste.pace`** (§8: "measures the KVM's own HID report rate (L4) before the pace is fixed", no rule): twice the smallest pace at which the ES3 typed the 200-character pattern losslessly three times out of three, every slower pace also lossless; 15 ms stays if L4 could not run.
- **DD11 — `paste.chord` is validated at load**: one or more distinct modifiers (`ctrl`, `shift`, `alt`/`option`, `cmd`/`win`) then one letter or digit; a chord with no modifier would swallow plain typing, and an unparsable one would never fire.

## Carries from Plan C

Every ledger line that says "Carry to Plan D" or names an L4 check, and every final-review recommendation for Plan D.

| Carry (source) | Where in Plan D |
|---|---|
| The ES3's real refusal forms for an FLV and a websocket after a global logout — status, Content-Type, body (ledger PC6, l.35) | Task 1.3 `refusal-forms` and `token-life`'s lapsed-token form; Task 1.6 step 5; the logout-specific form is Task 1.3 `logout-watch` + Task 1.6 step 16 (optional, owner-run; else DD1, not measured) |
| Mid-session KVM certificate change on the websocket, PC7 W10 (ledger l.44, l.48; final review) | Task 5.3: kvm-sim `rotate_certificate`, L2 `a_certificate_change_mid_session_is_fatal_at_once` |
| Same-token FLV refusal; "a concurrent FLV with a valid token is never 403'd" (ledger PC8 n1, l.64; PC9 re-review) | Task 1.3 `concurrent-flv` (refusals counted with their form); Task 1.6 step 4 and its decision rule |
| Re-assert the full HID state once a reconnect settles, and measure it on the ES3 (ledger PC9 I2 fix 2, l.71; final review) | Task 4.2 (the bridge), Task 1.5 `hid-stale` + Task 1.6 step 9 (the measurement), Task 5.3 L2 |
| How the ES3 closes a websocket — close frame or bare EOF (ledger PC9, l.75) | Task 1.3 `ws-close`; Task 1.6 step 3 |
| The lag between the old FLV's forced IDR and a `ReconnectFlv` candidate's first tag (ledger PC17, l.175) | Task 1.3 `concurrent-flv` (`lag_ms`, `replay_aus` against the ring of 64); Task 1.6 step 4 |
| DC18: what the Mac sees when the websocket dies with a key held (→ §9.3) | Task 1.5 `hid-hold`; Task 1.6 step 8; Task 6.1 §9.3 |
| DC18: side request → main-FLV IDR latency over 20 trials | Task 1.3 `concurrent-flv`; Task 1.6 step 4 |
| DC18: how a preset change is signalled | Task 1.6 step 11 (`capture` + `summarize`, owner) |
| DC18: how long an abandoned token stays valid; whether the ES3 caps concurrent sessions | Task 1.3 `token-life`, `session-cap`; Task 1.6 steps 6, 12–13 |
| DC18: the KVM's HID report rate before `paste.pace` is fixed (§8) | Task 1.4's test page (`rate <n> <ms>`, D28) and `hid-type`; Task 1.6 step 7; Task 6.1 (DD10) |
| Final review: size the websocket's `SO_SNDBUF` cap from the HID report rate L4 measures | Task 1.4's page-measured rate (the probe's `write_rate`/`kernel_buffered` are diagnostics only, D28), Task 1.6 step 7's rule, Task 6.1 |
| DC18 / Plan A: the control websocket survives another session's logout, on the real ES3 | Task 1.3 `logout-watch`; Task 1.6 step 16 (optional, owner-run); otherwise recorded as unmeasured (DD1) |
| DC7: the input handler is a counting stub; Plan D adds the mapping | Tasks 2.1–2.2, 4.1 |
| DC7 / §11.3: the input-event L2 cases (RDP input → HID frames) | Task 5.1 |
| DC9 / final review: the secrets case's keystroke sentinel and paste canary | Task 5.2 |
| PC17 m1 / final review: the replay-divergence L2 case, with a kvm-sim one-connection knob | Task 5.3: `Policy::alter_candidate_frame`, L2 `a_divergent_replay_frame_ends_the_replay_at_an_idr` |
| Final review: epoch stamping through `push_at`; timers in a sans-IO core | Design decisions 5–6; Tasks 2.2, 4.1 |
| Final review: `leak_shapes` gets every new config key | Task 3.1 (`paste.chord`), Task 4.2 (`input.reassert_after`) |
| §10.4: `release_all` gains `Synchronize` and the timers; paste events and skipped characters | Tasks 2.2, 4.1, 4.2 |
| §12: the firmware version, still "pending" in census.md | Task 1.6 step 14 (owner) |

## Execution notes

- Repo `/home/chris/Repos/kvm-rdp`, branch `plan-d`, cut from `main` once Plan C (with its final fix wave) has merged. Task numbers are `Part.N`; parts run in order, except that Task 1.6 may be deferred (below).
- Every command runs inside `nix develop` from the repo root (the §13 cargo wrapper). Run `cargo fmt --all` before every commit; `git add` exact paths, never `-A`; never commit anything under `.superpowers/`, `target/` or `captures/`.
- **The per-task gate** (Plan C's): `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, then `scripts/target-budget.sh`. **Never `-p`** for a build or a test; a TDD step runs its filter in the gate's resolution: `cargo test --workspace --all-features --lib -- <filter>` for unit tests, `cargo test --workspace --all-features --test l2 -- <filter>` for L2, `cargo test --workspace --all-features --test sim -- <filter>` for kvm-sim's binary (where the probe's L4 code is tested), `cargo test --workspace --all-features --test stubs -- <filter>` for kvm-probe's own.
- Expected counts in "Expected: N passed" lines are minimums: the gate is "0 failed and every named test exists and passes".
- **Task 1.6 is the hardware task.** It needs network reach to the ES3 from the machine running it, the KVM password file the owner names, and the owner for the steps marked **[OWNER]** (unlocking the Mac and opening the test page; changing the KVM preset; consenting to the session-cap check; reading the firmware version). Every other step is agent-driven. If the owner is unavailable when Part 1's tooling is done, run the agent-only steps, record the rest as "not run" in census.md, carry on with Part 2, and come back; Task 6.1 reads census values through decision rules that have a default for "not run" (Task 4.2's `input.reassert_after` ships at 1 s and Task 6.1 retunes it).
- Scratch worktrees (reviewers) set their own `CARGO_TARGET_DIR` under the session scratchpad and delete it when done.

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `crates/kvm-proto/src/keymap.rs`, `src/lib.rs` | Set-1 scancode → usage, modifier bits and classes, the US layout, `Chord` | 1.1 |
| `crates/kvm-probe/src/{cli,kvm,main,trial,request,secret}.rs`, `tests/stubs/{login,trial,support}.rs` | No logout anywhere in kvm-probe; password-file errors never name the path | 1.2 |
| `crates/kvm-probe/src/l4/{mod,flv,ws,session}.rs`, `src/{lib,cli,main}.rs` | `concurrent-flv`, `refusal-forms`, `ws-close`, `token-life`, `session-cap`, `logout-watch` | 1.3 |
| `crates/kvm-probe/assets/hid-test.html`, `src/l4/{page,hid,snapshot}.rs`, `src/sandbox.rs`, `Cargo.toml` | The HID test page, the HID websocket and `ensure_released` (on Ctrl-C, SIGTERM, SIGHUP), `hid-page-url`, `hid-type`, `hid-release`, `snapshot` | 1.4 |
| `crates/kvm-probe/src/l4/{hold,web}.rs`, `src/l4/hid.rs` | `hid-hold`, the bounded `hid-stale`, `web-get` | 1.5 |
| `crates/kvm-sim/tests/sim/{main,l4}.rs` | The probe's L4 code against kvm-sim | 1.3–1.5 |
| `docs/census.md` | Leg D — Plan D's L4 results | 1.6 |
| `crates/kvm-proto/src/hid.rs` | `scale_abs` (§7.2) | 2.1 |
| `crates/kvm-rdp/src/input/{mod,keys,pointer}.rs`, `src/lib.rs` | Keyboard state (slots, released-by-bridge, Unicode, remap), pointer state | 2.1 |
| `crates/kvm-rdp/src/input/core.rs`, `src/hid/queue.rs` | The input core: events, §7.4 triggers and timers; `ReleaseTrigger` gains three | 2.2 |
| `crates/kvm-proto/src/paste.rs`, `crates/kvm-rdp/src/config.rs` | §8 text handling, UTF-16, the `Typist`; `paste.chord` validated | 3.1 |
| `crates/kvm-rdp/src/input/{paste,core}.rs` | The paste states, wired into the core | 3.2 |
| `crates/kvm-rdp/src/rdp/{clipboard,handler,mod}.rs`, `src/msg.rs`, `src/pump/shell.rs`, `Cargo.toml` | CLIPRDR backend and factory, generation binding, `RdpInput::Fatal` | 3.3 |
| `crates/kvm-rdp/src/rdp/{input,server}.rs`, `src/bridge.rs`, `src/metrics.rs`, `src/hid/queue.rs` | The handler, the driver, assembly, paste metrics | 4.1 |
| `crates/kvm-rdp/src/hid/{writer,queue}.rs`, `src/kvm/session.rs`, `src/metrics.rs`, `src/config.rs`, `tests/l2/harness.rs` | Re-assert once a reconnect settles; `input.reassert_after` | 4.2 |
| `crates/kvm-rdp/tests/l2/{client,input,main}.rs` | L2 client input and CLIPRDR; input and stuck-key cases | 5.1 |
| `crates/kvm-rdp/tests/l2/{paste,admin}.rs` | L2 paste cases; the secrets case's sentinel and canary | 5.2 |
| `crates/kvm-sim/src/{lib,tls,state,flv}.rs`, `tests/sim/conformance.rs`, `crates/kvm-rdp/tests/l2/{faults,video,hid}.rs` | Certificate rotation, a divergent-replay knob; W10, divergence, re-assert L2 | 5.3 |
| `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`, `README.md`, `crates/kvm-rdp/src/config.rs`, `crates/kvm-rdp/src/kvm/endpoint.rs` | Rev 6.3; L4 retunes | 6.1 |

---
## Part 1 — The L4 hardware checks (first, §12)

§12 orders Plan D to start with §11.6's L4 checks, before `paste.pace` and the stuck-key work consume them. Tasks 1.1–1.5 build and prove the tools against kvm-sim; Task 1.6 runs them on the ES3. Task 1.1 comes first because the probe types through the same US-layout table the bridge will.

### Task 1.1: `kvm_proto::keymap` — scancode set 1 → HID usage, the US layout, `paste.chord`

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/keymap.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (`pub mod keymap;`)
- Test: `crates/kvm-proto/src/keymap.rs` (`tests`)

**Interfaces:**
- Consumes: nothing.
- Produces (`kvm_proto::keymap`):
  - `pub const MOD_LCTRL: u8 = 0x01`, `MOD_LSHIFT = 0x02`, `MOD_LALT = 0x04`, `MOD_LGUI = 0x08`, `MOD_RCTRL = 0x10`, `MOD_RSHIFT = 0x20`, `MOD_RALT = 0x40`, `MOD_RGUI = 0x80` (the §3.3 keyboard frame's modifier byte).
  - `pub const CLASS_CTRL: u8 = 0x01`, `CLASS_SHIFT = 0x02`, `CLASS_ALT = 0x04`, `CLASS_GUI = 0x08`.
  - `pub const USAGE_ESC: u8 = 0x29`, `USAGE_CAPS_LOCK: u8 = 0x39`.
  - `pub fn usage_for_scancode(code: u8, extended: bool) -> Option<u8>` — set-1 make code (`extended` = the `E0` prefix) → keyboard-page usage.
  - `pub const fn modifier_bit(usage: u8) -> Option<u8>` — 0xE0..=0xE7 → its modifier bit.
  - `pub fn modifier_classes(bits: u8) -> u8` — modifier bits → class bits, either side.
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct Stroke { pub usage: u8, pub shift: bool }`; `pub fn us_stroke(c: char) -> Option<Stroke>` — printable ASCII, `'\t'`, `'\n'` (Return).
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct Chord { pub classes: u8, pub code: u8 }` — `pub fn parse(s: &str) -> Option<Chord>`, `pub fn matches(&self, code: u8, extended: bool, held_modifier_bits: u8) -> bool`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod keymap;` to `crates/kvm-proto/src/lib.rs` (after `pub mod hid;`). Create `crates/kvm-proto/src/keymap.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic
    )]
    use super::*;
    use std::collections::HashMap;

    /// Microsoft, "USB HID to PS/2 Scan Code Translation Table" (Keyboard
    /// Scan Code Specification, Appendix C), Scan Code Set 1 make codes:
    /// (usage, make bytes). The independent oracle §11.1 names.
    const MS_SET1: &[(u8, &[u8])] = &[
        (0x04, &[0x1E]), (0x05, &[0x30]), (0x06, &[0x2E]), (0x07, &[0x20]), (0x08, &[0x12]),
        (0x09, &[0x21]), (0x0A, &[0x22]), (0x0B, &[0x23]), (0x0C, &[0x17]), (0x0D, &[0x24]),
        (0x0E, &[0x25]), (0x0F, &[0x26]), (0x10, &[0x32]), (0x11, &[0x31]), (0x12, &[0x18]),
        (0x13, &[0x19]), (0x14, &[0x10]), (0x15, &[0x13]), (0x16, &[0x1F]), (0x17, &[0x14]),
        (0x18, &[0x16]), (0x19, &[0x2F]), (0x1A, &[0x11]), (0x1B, &[0x2D]), (0x1C, &[0x15]),
        (0x1D, &[0x2C]),
        (0x1E, &[0x02]), (0x1F, &[0x03]), (0x20, &[0x04]), (0x21, &[0x05]), (0x22, &[0x06]),
        (0x23, &[0x07]), (0x24, &[0x08]), (0x25, &[0x09]), (0x26, &[0x0A]), (0x27, &[0x0B]),
        (0x28, &[0x1C]), (0x29, &[0x01]), (0x2A, &[0x0E]), (0x2B, &[0x0F]), (0x2C, &[0x39]),
        (0x2D, &[0x0C]), (0x2E, &[0x0D]), (0x2F, &[0x1A]), (0x30, &[0x1B]), (0x31, &[0x2B]),
        (0x33, &[0x27]), (0x34, &[0x28]), (0x35, &[0x29]), (0x36, &[0x33]), (0x37, &[0x34]),
        (0x38, &[0x35]), (0x39, &[0x3A]),
        (0x3A, &[0x3B]), (0x3B, &[0x3C]), (0x3C, &[0x3D]), (0x3D, &[0x3E]), (0x3E, &[0x3F]),
        (0x3F, &[0x40]), (0x40, &[0x41]), (0x41, &[0x42]), (0x42, &[0x43]), (0x43, &[0x44]),
        (0x44, &[0x57]), (0x45, &[0x58]),
        (0x46, &[0xE0, 0x37]), (0x47, &[0x46]),
        (0x49, &[0xE0, 0x52]), (0x4A, &[0xE0, 0x47]), (0x4B, &[0xE0, 0x49]), (0x4C, &[0xE0, 0x53]),
        (0x4D, &[0xE0, 0x4F]), (0x4E, &[0xE0, 0x51]), (0x4F, &[0xE0, 0x4D]), (0x50, &[0xE0, 0x4B]),
        (0x51, &[0xE0, 0x50]), (0x52, &[0xE0, 0x48]),
        (0x53, &[0x45]), (0x54, &[0xE0, 0x35]), (0x55, &[0x37]), (0x56, &[0x4A]), (0x57, &[0x4E]),
        (0x58, &[0xE0, 0x1C]),
        (0x59, &[0x4F]), (0x5A, &[0x50]), (0x5B, &[0x51]), (0x5C, &[0x4B]), (0x5D, &[0x4C]),
        (0x5E, &[0x4D]), (0x5F, &[0x47]), (0x60, &[0x48]), (0x61, &[0x49]), (0x62, &[0x52]),
        (0x63, &[0x53]),
        (0x64, &[0x56]), (0x65, &[0xE0, 0x5D]), (0x67, &[0x59]),
        (0x68, &[0x64]), (0x69, &[0x65]), (0x6A, &[0x66]), (0x6B, &[0x67]), (0x6C, &[0x68]),
        (0x6D, &[0x69]), (0x6E, &[0x6A]), (0x6F, &[0x6B]), (0x70, &[0x6C]), (0x71, &[0x6D]),
        (0x72, &[0x6E]), (0x73, &[0x76]),
        (0x85, &[0x7E]), (0x87, &[0x73]), (0x88, &[0x70]), (0x89, &[0x7D]), (0x8A, &[0x79]),
        (0x8B, &[0x7B]),
        (0xE0, &[0x1D]), (0xE1, &[0x2A]), (0xE2, &[0x38]), (0xE3, &[0xE0, 0x5B]),
        (0xE4, &[0xE0, 0x1D]), (0xE5, &[0x36]), (0xE6, &[0xE0, 0x38]), (0xE7, &[0xE0, 0x5C]),
    ];

    /// Rows of the same table the bridge leaves out, and why: 0x32 (non-US
    /// #) shares 0x31's make code `2B`, which maps to 0x31; 0x48 Pause
    /// (`E1 1D 45`) reaches the server as LCtrl + NumLock with EXTENDED1
    /// dropped (§7.1); 0x66 Keyboard Power (`E0 5E`) is never sent (DD7);
    /// 0x90/0x91 LANG1/LANG2 (`F2`/`F1`) have no break code; 0x8C (Int'l 6,
    /// `5C`) and 0x92–0x94 (LANG3–5, `78`/`77`/`76`) are Japanese/Korean
    /// keys the US Mac never sees — 0x94 (LANG5) shares F24's `76` (D11).
    const EXCLUDED: &[u8] = &[0x32, 0x48, 0x66, 0x8C, 0x90, 0x91, 0x92, 0x93, 0x94];

    #[test]
    fn every_set1_make_code_maps_exactly_as_microsofts_table() {
        let mut want: HashMap<(u8, bool), u8> = HashMap::new();
        for (usage, make) in MS_SET1 {
            assert!(!EXCLUDED.contains(usage));
            let key = match make {
                [c] => (*c, false),
                [0xE0, c] => (*c, true),
                other => panic!("{other:?}"),
            };
            assert!(want.insert(key, *usage).is_none(), "{key:?} twice");
        }
        for code in 0..=255u8 {
            for extended in [false, true] {
                assert_eq!(
                    usage_for_scancode(code, extended),
                    want.get(&(code, extended)).copied(),
                    "{code:#04x} extended={extended}"
                );
            }
        }
        // The fake shifts of Print Screen's make sequence (E0 2A, E0 36)
        // are never mistaken for Shift.
        assert_eq!(usage_for_scancode(0x2A, true), None);
        assert_eq!(usage_for_scancode(0x36, true), None);
        assert_eq!(usage_for_scancode(0x5E, true), None, "Keyboard Power");
    }

    #[test]
    fn modifier_bits_and_classes() {
        let bits: Vec<_> = (0xE0..=0xE7u8).map(|u| modifier_bit(u).unwrap()).collect();
        assert_eq!(bits, [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
        assert_eq!(modifier_bit(0xDF), None);
        assert_eq!(modifier_bit(0x04), None);
        // Census: Cmd is the GUI bit 0x08 (`census.md`, Derived decisions).
        assert_eq!(modifier_bit(usage_for_scancode(0x5B, true).unwrap()), Some(MOD_LGUI));
        assert_eq!(modifier_classes(MOD_LCTRL | MOD_RALT), CLASS_CTRL | CLASS_ALT);
        assert_eq!(modifier_classes(MOD_RSHIFT | MOD_LSHIFT), CLASS_SHIFT);
        assert_eq!(modifier_classes(MOD_RGUI), CLASS_GUI);
        assert_eq!(modifier_classes(0), 0);
    }

    /// The US layout, row by row: (usage, unshifted, shifted).
    const US_ROWS: &[(u8, char, char)] = &[
        (0x1E, '1', '!'), (0x1F, '2', '@'), (0x20, '3', '#'), (0x21, '4', '$'), (0x22, '5', '%'),
        (0x23, '6', '^'), (0x24, '7', '&'), (0x25, '8', '*'), (0x26, '9', '('), (0x27, '0', ')'),
        (0x2D, '-', '_'), (0x2E, '=', '+'), (0x2F, '[', '{'), (0x30, ']', '}'), (0x31, '\\', '|'),
        (0x33, ';', ':'), (0x34, '\'', '"'), (0x35, '`', '~'), (0x36, ',', '<'), (0x37, '.', '>'),
        (0x38, '/', '?'),
    ];

    #[test]
    fn the_us_layout_types_every_printable_ascii_character() {
        let k = |usage, shift| Some(Stroke { usage, shift });
        for (i, (lower, upper)) in ('a'..='z').zip('A'..='Z').enumerate() {
            let usage = 0x04 + u8::try_from(i).unwrap();
            assert_eq!(us_stroke(lower), k(usage, false), "{lower}");
            assert_eq!(us_stroke(upper), k(usage, true), "{upper}");
        }
        for (usage, plain, shifted) in US_ROWS {
            assert_eq!(us_stroke(*plain), k(*usage, false), "{plain}");
            assert_eq!(us_stroke(*shifted), k(*usage, true), "{shifted}");
        }
        assert_eq!(us_stroke(' '), k(0x2C, false));
        assert_eq!(us_stroke('\t'), k(0x2B, false));
        assert_eq!(us_stroke('\n'), k(0x28, false));
        let typeable = (0u32..=0xFF)
            .filter_map(char::from_u32)
            .filter(|c| us_stroke(*c).is_some())
            .count();
        assert_eq!(typeable, 95 + 2, "printable ASCII, Tab and Return only");
        for c in ['\r', '\u{7f}', '\u{1b}', 'é', '€', '\u{1F600}', '\0'] {
            assert_eq!(us_stroke(c), None, "{c:?}");
        }
    }

    #[test]
    fn chords_parse_and_match_on_raw_modifier_classes() {
        let want = Chord {
            classes: CLASS_CTRL | CLASS_ALT | CLASS_SHIFT,
            code: 0x2F,
        };
        assert_eq!(Chord::parse("ctrl+option+shift+v"), Some(want));
        assert_eq!(Chord::parse("Ctrl + Alt + Shift + V"), Some(want));
        assert_eq!(
            Chord::parse("cmd+1"),
            Some(Chord {
                classes: CLASS_GUI,
                code: 0x02
            })
        );
        for bad in [
            "", "v", "ctrl+", "ctrl+ctrl+v", "ctrl+f1", "ctrl+vv", "hyper+v", "ctrl+shift",
            "+v", "ctrl+-",
        ] {
            assert_eq!(Chord::parse(bad), None, "{bad:?}");
        }
        // Either side of each modifier counts; nothing more may be held.
        assert!(want.matches(0x2F, false, MOD_LCTRL | MOD_LALT | MOD_RSHIFT));
        assert!(want.matches(0x2F, false, MOD_RCTRL | MOD_RALT | MOD_LSHIFT | MOD_RSHIFT));
        assert!(!want.matches(0x2F, false, MOD_LCTRL | MOD_LALT));
        assert!(!want.matches(0x2F, false, MOD_LCTRL | MOD_LALT | MOD_LSHIFT | MOD_LGUI));
        assert!(!want.matches(0x2F, true, MOD_LCTRL | MOD_LALT | MOD_LSHIFT));
        assert!(!want.matches(0x2E, false, MOD_LCTRL | MOD_LALT | MOD_LSHIFT));
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- keymap` — Expected: FAIL to compile (`usage_for_scancode`, `Stroke`, `Chord` … not found).

- [ ] **Step 3: Implement.** Above the tests in `keymap.rs`:

```rust
//! Keyboard tables (spec §7.1, §8): scancode set 1 → USB HID usages
//! (keyboard page 0x07), the US layout for Unicode key events and pasted
//! text, and `paste.chord`. Tables only; the oracle in `tests` is
//! Microsoft's published translation table (§11.1).

/// The §3.3 keyboard frame's modifier byte.
pub const MOD_LCTRL: u8 = 0x01;
pub const MOD_LSHIFT: u8 = 0x02;
pub const MOD_LALT: u8 = 0x04;
pub const MOD_LGUI: u8 = 0x08;
pub const MOD_RCTRL: u8 = 0x10;
pub const MOD_RSHIFT: u8 = 0x20;
pub const MOD_RALT: u8 = 0x40;
pub const MOD_RGUI: u8 = 0x80;

/// A modifier whichever side it is on (a chord's matching unit).
pub const CLASS_CTRL: u8 = 0x01;
pub const CLASS_SHIFT: u8 = 0x02;
pub const CLASS_ALT: u8 = 0x04;
pub const CLASS_GUI: u8 = 0x08;

pub const USAGE_ESC: u8 = 0x29;
pub const USAGE_CAPS_LOCK: u8 = 0x39;

/// The usage for a set-1 make code; `extended` is the `E0` prefix. Pause
/// (`E1 …`) never arrives as such: IronRDP drops EXTENDED1, so it is
/// LCtrl + NumLock (§7.1). Keyboard Power (`E0 5E`) is never sent (DD7).
#[must_use]
pub fn usage_for_scancode(code: u8, extended: bool) -> Option<u8> {
    let usage = if extended {
        extended_usage(code)
    } else {
        base_usage(code)
    };
    (usage != 0).then_some(usage)
}

const fn base_usage(code: u8) -> u8 {
    match code {
        0x01 => 0x29,
        0x02 => 0x1E,
        0x03 => 0x1F,
        0x04 => 0x20,
        0x05 => 0x21,
        0x06 => 0x22,
        0x07 => 0x23,
        0x08 => 0x24,
        0x09 => 0x25,
        0x0A => 0x26,
        0x0B => 0x27,
        0x0C => 0x2D,
        0x0D => 0x2E,
        0x0E => 0x2A,
        0x0F => 0x2B,
        0x10 => 0x14,
        0x11 => 0x1A,
        0x12 => 0x08,
        0x13 => 0x15,
        0x14 => 0x17,
        0x15 => 0x1C,
        0x16 => 0x18,
        0x17 => 0x0C,
        0x18 => 0x12,
        0x19 => 0x13,
        0x1A => 0x2F,
        0x1B => 0x30,
        0x1C => 0x28,
        0x1D => 0xE0,
        0x1E => 0x04,
        0x1F => 0x16,
        0x20 => 0x07,
        0x21 => 0x09,
        0x22 => 0x0A,
        0x23 => 0x0B,
        0x24 => 0x0D,
        0x25 => 0x0E,
        0x26 => 0x0F,
        0x27 => 0x33,
        0x28 => 0x34,
        0x29 => 0x35,
        0x2A => 0xE1,
        0x2B => 0x31,
        0x2C => 0x1D,
        0x2D => 0x1B,
        0x2E => 0x06,
        0x2F => 0x19,
        0x30 => 0x05,
        0x31 => 0x11,
        0x32 => 0x10,
        0x33 => 0x36,
        0x34 => 0x37,
        0x35 => 0x38,
        0x36 => 0xE5,
        0x37 => 0x55,
        0x38 => 0xE2,
        0x39 => 0x2C,
        0x3A => 0x39,
        0x3B => 0x3A,
        0x3C => 0x3B,
        0x3D => 0x3C,
        0x3E => 0x3D,
        0x3F => 0x3E,
        0x40 => 0x3F,
        0x41 => 0x40,
        0x42 => 0x41,
        0x43 => 0x42,
        0x44 => 0x43,
        0x45 => 0x53,
        0x46 => 0x47,
        0x47 => 0x5F,
        0x48 => 0x60,
        0x49 => 0x61,
        0x4A => 0x56,
        0x4B => 0x5C,
        0x4C => 0x5D,
        0x4D => 0x5E,
        0x4E => 0x57,
        0x4F => 0x59,
        0x50 => 0x5A,
        0x51 => 0x5B,
        0x52 => 0x62,
        0x53 => 0x63,
        0x56 => 0x64,
        0x57 => 0x44,
        0x58 => 0x45,
        0x59 => 0x67,
        0x64 => 0x68,
        0x65 => 0x69,
        0x66 => 0x6A,
        0x67 => 0x6B,
        0x68 => 0x6C,
        0x69 => 0x6D,
        0x6A => 0x6E,
        0x6B => 0x6F,
        0x6C => 0x70,
        0x6D => 0x71,
        0x6E => 0x72,
        0x70 => 0x88,
        0x73 => 0x87,
        0x76 => 0x73,
        0x79 => 0x8A,
        0x7B => 0x8B,
        0x7D => 0x89,
        0x7E => 0x85,
        _ => 0,
    }
}

const fn extended_usage(code: u8) -> u8 {
    match code {
        0x1C => 0x58,
        0x1D => 0xE4,
        0x35 => 0x54,
        0x37 => 0x46,
        0x38 => 0xE6,
        0x47 => 0x4A,
        0x48 => 0x52,
        0x49 => 0x4B,
        0x4B => 0x50,
        0x4D => 0x4F,
        0x4F => 0x4D,
        0x50 => 0x51,
        0x51 => 0x4E,
        0x52 => 0x49,
        0x53 => 0x4C,
        0x5B => 0xE3,
        0x5C => 0xE7,
        0x5D => 0x65,
        _ => 0,
    }
}

/// 0xE0..=0xE7 → its bit in the modifier byte.
#[must_use]
pub const fn modifier_bit(usage: u8) -> Option<u8> {
    match usage {
        0xE0 => Some(MOD_LCTRL),
        0xE1 => Some(MOD_LSHIFT),
        0xE2 => Some(MOD_LALT),
        0xE3 => Some(MOD_LGUI),
        0xE4 => Some(MOD_RCTRL),
        0xE5 => Some(MOD_RSHIFT),
        0xE6 => Some(MOD_RALT),
        0xE7 => Some(MOD_RGUI),
        _ => None,
    }
}

/// Modifier bits → class bits: the right-hand nibble folded onto the left.
#[must_use]
pub fn modifier_classes(bits: u8) -> u8 {
    (bits & 0x0F) | (bits & 0xF0).rotate_right(4)
}

/// One key of the US layout: its usage, and whether Shift is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stroke {
    pub usage: u8,
    pub shift: bool,
}

/// What the US layout types `c` with: printable ASCII, Tab, and `'\n'` as
/// Return (§8 turns CR/LF/CRLF into `'\n'` first). Anything else — control
/// characters, DEL, non-ASCII — has no stroke and is skipped by the caller.
#[must_use]
pub fn us_stroke(c: char) -> Option<Stroke> {
    let b = u8::try_from(c).ok()?;
    let (usage, shift) = match b {
        b'a'..=b'z' => (0x04u8.wrapping_add(b.wrapping_sub(b'a')), false),
        b'A'..=b'Z' => (0x04u8.wrapping_add(b.wrapping_sub(b'A')), true),
        b'1'..=b'9' => (0x1Eu8.wrapping_add(b.wrapping_sub(b'1')), false),
        b'0' => (0x27, false),
        b'!' => (0x1E, true),
        b'@' => (0x1F, true),
        b'#' => (0x20, true),
        b'$' => (0x21, true),
        b'%' => (0x22, true),
        b'^' => (0x23, true),
        b'&' => (0x24, true),
        b'*' => (0x25, true),
        b'(' => (0x26, true),
        b')' => (0x27, true),
        b'\n' => (0x28, false),
        b'\t' => (0x2B, false),
        b' ' => (0x2C, false),
        b'-' => (0x2D, false),
        b'_' => (0x2D, true),
        b'=' => (0x2E, false),
        b'+' => (0x2E, true),
        b'[' => (0x2F, false),
        b'{' => (0x2F, true),
        b']' => (0x30, false),
        b'}' => (0x30, true),
        b'\\' => (0x31, false),
        b'|' => (0x31, true),
        b';' => (0x33, false),
        b':' => (0x33, true),
        b'\'' => (0x34, false),
        b'"' => (0x34, true),
        b'`' => (0x35, false),
        b'~' => (0x35, true),
        b',' => (0x36, false),
        b'<' => (0x36, true),
        b'.' => (0x37, false),
        b'>' => (0x37, true),
        b'/' => (0x38, false),
        b'?' => (0x38, true),
        _ => return None,
    };
    Some(Stroke { usage, shift })
}

/// `paste.chord` (§8): matched on raw client scancodes, before any remap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    /// `CLASS_*` bits that must be held — exactly these.
    pub classes: u8,
    /// The key's set-1 make code (never extended).
    pub code: u8,
}

impl Chord {
    /// `ctrl+option+shift+v`: one or more distinct modifiers (`ctrl` or
    /// `control`, `shift`, `alt` or `option`, `cmd` or `win`), then one
    /// letter or digit; case and spaces around `+` ignored (DD11).
    #[must_use]
    pub fn parse(s: &str) -> Option<Chord> {
        let parts: Vec<&str> = s.split('+').map(str::trim).collect();
        let (key, mods) = parts.split_last()?;
        if mods.is_empty() {
            return None;
        }
        let mut classes = 0u8;
        for m in mods {
            let class = match m.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => CLASS_CTRL,
                "shift" => CLASS_SHIFT,
                "alt" | "option" => CLASS_ALT,
                "cmd" | "win" => CLASS_GUI,
                _ => return None,
            };
            if classes & class != 0 {
                return None;
            }
            classes |= class;
        }
        let mut chars = key.chars();
        let (Some(k), None) = (chars.next(), chars.next()) else {
            return None;
        };
        if !k.is_ascii_alphanumeric() {
            return None;
        }
        let usage = us_stroke(k.to_ascii_lowercase())?.usage;
        let code = (0x01..=0x7Fu8).find(|c| base_usage(*c) == usage)?;
        Some(Chord { classes, code })
    }

    /// A press of the chord's key with exactly its modifier classes held.
    #[must_use]
    pub fn matches(&self, code: u8, extended: bool, held_modifier_bits: u8) -> bool {
        !extended && code == self.code && modifier_classes(held_modifier_bits) == self.classes
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- keymap` — Expected: PASS — 4 passed.

- [ ] **Step 5: Check the oracle against the published document if it is reachable.** Run `curl -fsSL -o "$TMPDIR/translate.pdf" https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/translate.pdf` (inside the scratchpad, never the repo). If it downloads, compare `MS_SET1`'s rows and `EXCLUDED`'s nine rows (0x32, 0x48, 0x66, 0x8C, 0x90–0x94) against its Scan Code Set 1 column (`pdftotext` is in the devshell's poppler if present; otherwise read it with the Read tool, `pages` 1–6). The document wins: a row that differs is fixed in both `MS_SET1` and `base_usage`/`extended_usage`, and the fix is named in the commit body. If it does not download, say so in the commit body ("oracle transcribed, not re-checked against translate.pdf: unreachable").

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-proto/src/keymap.rs crates/kvm-proto/src/lib.rs
git commit -m "kvm-proto: keymap — set-1 scancodes to HID usages, the US layout, paste.chord (§7.1, §8)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 1.2: kvm-probe never logs out, and never echoes its password-file path

Logout is global on the ES3: one session's logout ends the owner's break-glass web-UI session (§3.2, `census.md` Leg A — sessions). kvm-probe still carries the census's optional `--logout`; an agent driving Task 1.6 must not be one typo away from it. This task removes logout from kvm-probe altogether. kvm-sim keeps modelling global logout (L2's "another session's logout" case needs it); its own tests send the request themselves. It also closes, for kvm-probe, the class Plan C's final fix wave closed for kvm-rdp (d7c6dc9, C1): a password written where `--password-file`'s path goes must never reach the terminal, so `read_password_file`'s errors no longer name the path.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/kvm.rs` (delete `LOGOUT_TIMEOUT`, `logout`, `logout_inner`, `Session`; `with_session` loses `do_logout` and returns the work's output)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/request.rs` (delete `logout_url` and its assertion)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/cli.rs` (delete `Conn::logout`; doc comments; the test)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/trial.rs` (`first_idr_run` loses `do_logout`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/main.rs` (`session`, `warn_if_logout_failed`, the `first-idr` arm)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/secret.rs` (errors name the flag and the I/O kind, never the path; D6a)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stubs/{login,trial}.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/{support,login,flv,websocket}.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `kvm_probe::kvm::with_session<T>(target: &KvmTarget, pin: Option<&str>, password: &str, now_unix: i64, timezone: &str, work: impl AsyncFnOnce(&str) -> T) -> Result<T, KvmError>`; `kvm_probe::trial::first_idr_run(target, web_pin, video_pin, password, now_unix, plan: &TrialPlan, on_trial) -> Result<TrialReport, KvmError>`; `kvm_probe::secret::read_password_file(path: &Path) -> Result<String, String>` whose errors are exactly `--password-file: cannot read the file: <io kind>`, `--password-file: over the 4096-byte cap` or `--password-file: not UTF-8`; kvm-sim test support `pub async fn logout(sim: &KvmSim, token: &str)`. kvm-probe has no `logout` function, no `logout_url` and no `--logout` flag.

- [ ] **Step 1: Write the failing tests.** In `crates/kvm-probe/src/cli.rs`'s `tests`, replace `logout_flag_defaults_off_and_is_settable` with:

```rust
    /// §3.2, owner: logout is global on the ES3, so no kvm-probe run may
    /// log out — there is no flag to ask for it on any subcommand.
    #[test]
    fn logout_is_never_an_argument() {
        for sub in [
            vec!["ws-open"],
            vec!["capture", "--name", "c.flv"],
            vec!["first-idr"],
        ] {
            let mut argv = vec!["kvm-probe"];
            argv.extend(&sub);
            argv.extend(["--host", "h", "--pin", "ab", "--password-file", "/tmp/pw"]);
            assert!(Cli::try_parse_from(&argv).is_ok(), "{sub:?}");
            argv.push("--logout");
            let err = Cli::try_parse_from(&argv).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument, "{sub:?}");
        }
    }
```

In `crates/kvm-probe/src/secret.rs`'s `tests`: in `exactly_4097_bytes_is_refused`, replace `assert!(err.contains(&path.display().to_string()));` with `assert!(!err.contains(&path.display().to_string()), "{err}");` (the `"4096"` and `"xxxx"` assertions stay); rename `error_names_the_path_never_the_contents` to `errors_never_name_the_path` and make its assertion `assert!(!err.contains(&missing.display().to_string()), "{err}"); assert_eq!(err, "--password-file: cannot read the file: entity not found");`; and add:

```rust
    /// C1 class (Plan C final review, d7c6dc9): a password pasted where the
    /// path goes never reaches the terminal through the error.
    #[test]
    fn a_password_passed_as_the_path_is_never_echoed() {
        let err = read_password_file(Path::new("/nonexistent/SNTL7qZq7vP2")).unwrap_err();
        assert!(!err.contains("SNTL7qZq7vP2"), "{err}");
        assert!(err.starts_with("--password-file: "), "{err}");
    }

    #[test]
    fn a_non_utf8_file_is_named_by_the_flag_only() {
        let path = tmp_file("notutf8", b"\xff\xfe");
        let err = read_password_file(&path).unwrap_err();
        assert_eq!(err, "--password-file: not UTF-8");
        let _ = std::fs::remove_file(&path);
    }
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- logout_is_never_an_argument secret::` — Expected: FAIL (`--logout` parses: "called `Result::unwrap_err()` on an `Ok` value"; the secret errors still contain the path).

- [ ] **Step 3: Remove logout from kvm-probe, and the path from its secret errors.**
  - `secret.rs`: `read_password_file`'s body becomes (the doc comment's "Every error here names only `path`" becomes "No error names the path — a password written where the path goes would otherwise be echoed (C1 class) — only `--password-file`, the I/O kind or the rule"):

```rust
pub fn read_password_file(path: &Path) -> Result<String, String> {
    let unreadable = |e: std::io::Error| format!("--password-file: cannot read the file: {}", e.kind());
    let mut file = std::fs::File::open(path).map_err(unreadable)?;
    let cap = MAX_PASSWORD_FILE_BYTES.saturating_add(1);
    let mut limited = (&mut file).take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).map_err(unreadable)?;
    let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if len > MAX_PASSWORD_FILE_BYTES {
        return Err(format!("--password-file: over the {MAX_PASSWORD_FILE_BYTES}-byte cap"));
    }
    let text = String::from_utf8(buf).map_err(|_| "--password-file: not UTF-8".to_owned())?;
    Ok(strip_one_trailing_newline(text))
}
```

  - `cli.rs`: delete the `logout` field of `Conn` and its doc comment (the eight lines, cli.rs:104–111, from `/// Log out when the run ends.` to `pub logout: bool,`). In the doc comments of `Capture`, `FirstIdr` and `WsOpen`, replace each sentence about `--logout` with "It never logs out: logout is global on this KVM (§3.2)." — `Capture`'s second paragraph becomes `/// Logs in, captures until --seconds or --max-mb, and leaves the session open: it never logs out (logout is global on this KVM). Each JSONL line also carries the hex of any SPS/PPS in the tag.`; `FirstIdr`'s becomes `/// Logs in once; every trial reopens av.flv with that one token (the bridge's reconnect-on-the-same-session path) and times FLV open → first IDR. It never logs out. A failed trial (a timeout, or the KVM refusing the token) is printed and counted, and the run goes on; p50/p95 are over the successful trials. Exits non-zero if the login fails or no trial succeeded.`; `WsOpen`'s becomes `/// Logs in first, and never logs out.` Elsewhere in the file, "login, logout" and "login/logout" in comments become "login".
  - `request.rs`: delete `pub fn logout_url` and, in `urls_and_cookie_match_the_web_ui`, its `assert_eq!(logout_url(&t), …)`.
  - `kvm.rs`: delete `LOGOUT_TIMEOUT`, `logout`, `logout_inner` and `Session`, and replace `with_session` with:

```rust
/// Log in and run `work` with the token. There is no logout: on the ES3
/// `GET /cgi-bin/login.lua?logout` is global — it would end every other
/// session, the owner's break-glass web UI included (§3.2) — so the token
/// is simply left to lapse. A failed login is the error.
pub async fn with_session<T>(
    target: &KvmTarget,
    pin: Option<&str>,
    password: &str,
    now_unix: i64,
    timezone: &str,
    work: impl AsyncFnOnce(&str) -> T,
) -> Result<T, KvmError> {
    let token = login(target, pin, password, now_unix, timezone).await?;
    Ok(work(&token).await)
}
```

  and in the module doc, `(final review m1)` notes about logout go; `bounded_debug`'s doc keeps its first sentence only.
  - `trial.rs`: `first_idr_run` drops `do_logout` (and the `#[allow(clippy::too_many_arguments)]` line, now 7 arguments) and returns `Result<TrialReport, KvmError>`; its doc's sentence about `do_logout` becomes "It never logs out (§3.2)."; the body passes no flag to `kvm::with_session`.
  - `main.rs`: delete `warn_if_logout_failed`; `session` becomes:

```rust
/// Log in on the web port and run `work` with the token; never log out
/// (logout is global on this KVM, §3.2).
async fn session<T>(
    conn: &Conn,
    password: &str,
    work: impl AsyncFnOnce(&str) -> T,
) -> Result<T, KvmError> {
    kvm::with_session(
        &target(conn),
        conn.pin_for(Port::Web),
        password,
        unix_now()?,
        kvm::PROBE_TIMEZONE,
        work,
    )
    .await
}
```

  and the `Cmd::FirstIdr` arm calls `trial::first_idr_run(&target(&conn), conn.pin_for(Port::Web), conn.pin_for(Port::Video), &pw, unix_now().map_err(|e| format!("{e:?}"))?, &plan, |n, line| println!("trial {n}/{trials}: {line}"))`, binds the report as `report`, and prints `report.summary()` and checks `report.all_failed()` where it used `s.output`; its comment becomes `// m1 (corrected): ONE login; every trial reopens av.flv on that token. Never a logout (§3.2). m7: a failed trial is printed with a bounded, escaped reason and the run goes on.`
  - `tests/stubs/login.rs`: delete `logout_sends_get_logout_with_the_token_cookie`, `with_session_logs_out_when_requested`, `with_session_logs_out_even_when_the_work_fails_when_requested`, `logout_is_bounded_against_a_silent_peer` and `refused_logout_names_the_status_but_never_the_body`. In the three that remain — rename `with_session_does_not_log_out_by_default` to `with_session_never_logs_out` and `with_session_sends_no_logout_by_default_even_when_the_work_fails` to `with_session_never_logs_out_even_when_the_work_fails`; keep `with_session_sends_no_logout_when_login_fails` — delete the `false`/`true` argument, replace `s.output` with `s`, delete every `s.logout` assertion, and in their doc comments replace "by default" / "regardless of `do_logout`" with "ever". Their request-count assertions stay: exactly one request, the login.
  - `tests/stubs/trial.rs`: delete `first_idr_run_logs_out_once_when_requested_for_any_trial_count` and `rejected_token_trials_fail_and_the_run_still_logs_out_once_when_requested`. In `first_idr_run_logs_in_once_and_does_not_log_out_by_default` (rename: `first_idr_run_logs_in_once_and_never_logs_out`) and `rejected_token_trials_fail_and_the_run_still_sends_no_logout_by_default` (rename: `rejected_token_trials_fail_and_the_run_never_logs_out`): delete the `false` argument, replace `s.output.` with `s.`, and delete the `s.logout` assertions; `tally`'s logout count stays and must be 0.

- [ ] **Step 4: kvm-sim's tests send their own logout.** kvm-sim must still model global logout (§11.5), so its tests keep exercising it with a raw request. In `crates/kvm-sim/tests/sim/support.rs`, after `login`:

```rust
/// `GET /cgi-bin/login.lua?logout` with `token`'s cookie, raw: kvm-probe
/// cannot log out (logout is global on the ES3, §3.2), but kvm-sim models
/// it, and these tests exercise the model.
pub async fn logout(sim: &KvmSim, token: &str) {
    let mut io = connect_to(&target(sim), sim.ports().web, Some(sim.spki_sha256()))
        .await
        .unwrap();
    let req = format!(
        "GET /cgi-bin/login.lua?logout HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: token={token}\r\nConnection: close\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 12];
    tokio::time::timeout(T, io.read_exact(&mut head))
        .await
        .expect("timed out waiting for the logout's answer")
        .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200", "{head:?}");
}
```

  and replace each `kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &X).await.unwrap();` in `tests/sim/login.rs` (l.59), `tests/sim/flv.rs` (l.352) and `tests/sim/websocket.rs` (l.194) with `logout(&sim, &X).await;`, adding `logout` to each file's `use crate::support::{…}` (and dropping `target` where it is no longer used).

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --lib -- logout_is_never_an_argument secret::` — Expected: PASS (1 + 8). Then `cargo test --workspace --all-features --test stubs` and `cargo test --workspace --all-features --test sim -- logout` — Expected: PASS, 0 failed (the sim's three logout cases pass on the raw request). Then `grep -rnE "fn logout\(|logout_url|pub logout:|do_logout|struct Session" crates/kvm-probe/src` — Expected: no output (the new test's name `fn logout_is_never_an_argument` has no `(` straight after `logout`). Then `grep -n "display()" crates/kvm-probe/src/secret.rs` — Expected: matches only in `tests` (none in `read_password_file`).

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-probe/src/cli.rs crates/kvm-probe/src/kvm.rs crates/kvm-probe/src/request.rs \
  crates/kvm-probe/src/trial.rs crates/kvm-probe/src/main.rs crates/kvm-probe/src/secret.rs \
  crates/kvm-probe/tests/stubs/login.rs crates/kvm-probe/tests/stubs/trial.rs \
  crates/kvm-sim/tests/sim/support.rs crates/kvm-sim/tests/sim/login.rs \
  crates/kvm-sim/tests/sim/flv.rs crates/kvm-sim/tests/sim/websocket.rs
git commit -m "kvm-probe: never log out — no --logout, no logout function (§3.2; L4 safety, DD1); --password-file errors never name the path (C1 class)" \
  -m "Logout is global on the ES3 and would end the owner's break-glass web-UI session. kvm-sim still models global logout; its own tests send the request. A password pasted where the path goes no longer reaches the terminal." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.3: kvm-probe L4 — FLV, websocket and session checks

Six subcommands, none of which logs out, and none of which sends a HID frame except `logout-watch`'s one all-zero keyboard report (a release, sent only to test whether the websocket survived): `concurrent-flv` (DC18's side request → main-FLV IDR latency over 20 trials; the same-token refusal carry; the forced-IDR → candidate lag and its replay count against the ring of 64), `refusal-forms` (the carry's status/Content-Type/body, DD1's tokens), `ws-close` (close frame or bare EOF), `token-life` and `session-cap` (DC18's token and session questions), and `logout-watch` (controller ruling 1: the OWNER logs out in the vendor web UI while the probe only watches — it records the refusal forms after a global logout and whether an open control websocket and FLV survive it; the probe still sends no logout). Their library code is proven against kvm-sim in kvm-sim's own test binary, which already drives kvm-probe as its client.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/l4/mod.rs`, `src/l4/flv.rs`, `src/l4/ws.rs`, `src/l4/session.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod l4;`), `src/cli.rs` (six subcommands, `validate`), `src/main.rs` (six arms), `Cargo.toml` (tokio `sync`; `futures-util` as a normal dependency)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/l4.rs`; Modify: `crates/kvm-sim/tests/sim/main.rs` (`mod l4;`)

**Interfaces:**
- Consumes: `kvm_probe::kvm::{connect_to, login, BoxedIo, KvmError, bounded_debug, PROBE_TIMEZONE}`, `kvm_probe::request::{KvmTarget, websocket_url, token_cookie_header}`, `kvm_probe::capture::record_for`, `kvm_probe::stats::percentile`, `kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, TagBody, VideoBody}`.
- Produces (`kvm_probe::l4`):
  - `pub struct RefusalForm { pub status: u16, pub content_type: String, pub body: String }` — `RefusalForm::new(status: u16, content_type: Option<&[u8]>, body: &[u8])`, `Display`; `pub const FORM_BODY_MAX: usize = 64`; `pub const NEVER_ISSUED: &str = "0.0"`; `pub fn escaped(bytes: &[u8], max: usize) -> String`; `pub fn now_unix() -> i64`; `pub fn ms(d: Duration) -> u64`; `pub fn since(t0: Instant, t: Instant) -> u64`; `pub fn deadline(d: Duration) -> tokio::time::Instant`.
  - `l4::flv`: `pub enum FlvOpen { Stream(FlvStream), Refused(RefusalForm) }`; `pub async fn open(t: &KvmTarget, pin: Option<&str>, token: Option<&str>, timeout: Duration) -> Result<FlvOpen, KvmError>`; `FlvStream::next_tag(&mut self) -> Result<Option<(Instant, FlvTag)>, KvmError>`; `pub fn is_coded(tag: &FlvTag) -> bool`; `pub fn is_idr(tag: &FlvTag) -> bool`; `pub struct ConcurrentPlan { pub trials: u32, pub gop: u32, pub timeout: Duration, pub pause: Duration }`; `pub enum Side { Served { first_tag_ms: u64, first_idr_ms: Option<u64> }, Refused(RefusalForm), Failed(String) }`; `pub struct Trial { pub side: Side, pub main_idr_ms: Option<u64>, pub forced: bool, pub lag_ms: Option<i64>, pub replay_aus: Option<u32> }`; `pub async fn concurrent_flv(t, pin, token: &str, plan: &ConcurrentPlan, on_trial: impl FnMut(u32, &Trial)) -> Result<Vec<Trial>, KvmError>`; `pub fn summary(trials: &[Trial]) -> String`.
  - `l4::ws`: `pub type Ws = tokio_tungstenite::WebSocketStream<BoxedIo>`; `pub enum Upgrade { Accepted(Box<Ws>), Refused(RefusalForm) }` (boxed: the stream is 296 bytes, `clippy::large_enum_variant`; callers that need the stream by value take `*w`); `pub async fn upgrade(t, pin, token: Option<&str>, timeout) -> Result<Upgrade, KvmError>`; `pub async fn upgrade_on(io: BoxedIo, t, token, timeout) -> Result<Upgrade, KvmError>`; `pub struct Inbound { pub text: u32, pub binary: u32, pub ping: u32, pub pong: u32, pub closed_by_kvm: bool }`; `pub enum Reply { CloseFrame { ms: u64 }, Eof { ms: u64 }, Error { ms: u64, what: String }, Timeout }`; `pub enum TcpEnd { Fin { ms: u64 }, Reset { ms: u64 }, Error { ms: u64, kind: String }, Timeout }`; `pub struct CloseReport { pub idle: Inbound, pub reply: Reply, pub tcp: TcpEnd }`; `pub async fn close_form(ws: Ws, idle: Duration, wait: Duration) -> CloseReport`.
  - `l4::session`: `pub enum Outcome { Accepted, Refused(RefusalForm), Failed(String) }`; `pub struct LifeProbe { pub age: Duration, pub outcome: Outcome }`; `pub async fn probe_token(t, control_pin, token: &str, timeout) -> Outcome`; `pub async fn token_life(t, web_pin, control_pin, password: &str, ages: &[Duration], timeout, on: impl FnMut(&LifeProbe)) -> Result<Vec<LifeProbe>, KvmError>`; `pub struct CapReport { pub logins: u32, pub stopped: Option<String> }`; `pub async fn session_cap(t, web_pin, control_pin, password, max: u32, timeout, on: impl FnMut(u32, &str)) -> Result<CapReport, KvmError>`; `pub struct WatchReport { pub logged_out_after: Option<Duration>, pub flv_form: Option<RefusalForm>, pub ws_form: Option<RefusalForm>, pub ws_survived: bool, pub ws_write_ok: bool, pub flv_survived: bool }`; `pub struct WatchPlan { pub max: Duration, pub poll: Duration }`; `pub async fn logout_watch(t, web_pin, video_pin, control_pin, password: &str, plan: WatchPlan, ready: impl FnOnce()) -> Result<WatchReport, KvmError>` (never sends a logout).
  - CLI: `concurrent-flv [--trials 20] [--gop 60]`, `refusal-forms`, `ws-close [--idle-secs 10]`, `token-life [--minutes 1,5,15,30,60]`, `session-cap [--max 16]`, `logout-watch [--max-secs 300]`, each with the shared `Conn` args.

- [ ] **Step 1: Write the failing tests.** Add `mod l4;` to `crates/kvm-sim/tests/sim/main.rs` and create `crates/kvm-sim/tests/sim/l4.rs`:

```rust
//! kvm-probe's L4 checks (Plan D, spec §11.6) against kvm-sim, before they
//! run on the ES3: each produces its report; none sends a HID frame except
//! `logout-watch`'s one all-zero release, and none logs out.
use crate::support::{T, login, sim_with, target};
use kvm_probe::l4::flv::{self, ConcurrentPlan, FlvOpen, Side};
use kvm_probe::l4::session::{self, CapReport, Outcome};
use kvm_probe::l4::ws::{self, Reply, TcpEnd, Upgrade};
use kvm_probe::l4::NEVER_ISSUED;
use kvm_sim::{KvmSim, SimEvent};
use std::time::Duration;

fn no_hid(sim: &KvmSim) {
    assert!(
        !sim.events().iter().any(|e| matches!(e, SimEvent::Hid { .. })),
        "an L4 check sent a HID frame"
    );
    assert_eq!(sim.stats().logouts, 0, "an L4 check logged out");
}

fn plan(trials: u32) -> ConcurrentPlan {
    ConcurrentPlan {
        trials,
        gop: 60,
        timeout: Duration::from_secs(3),
        pause: Duration::from_millis(100),
    }
}

/// kvm-sim's shared encoder forces an IDR into the main FLV whenever a
/// side FLV opens (the ES3's measured behaviour): every trial is served
/// and forced, and the replay count stays far under the ring of 64.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_flv_measures_one_forced_idr_per_side_open() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut lines = 0;
    let trials = flv::concurrent_flv(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &plan(3),
        |_, _| lines += 1,
    )
    .await
    .unwrap();
    assert_eq!((trials.len(), lines), (3, 3));
    for tr in &trials {
        assert!(
            matches!(tr.side, Side::Served { first_idr_ms: Some(_), .. }),
            "{tr:?}"
        );
        assert!(tr.forced, "{tr:?}");
        assert!(tr.main_idr_ms.is_some_and(|ms| ms < 1000), "{tr:?}");
        assert!(tr.replay_aus.is_some_and(|n| n < 30), "{tr:?}");
        assert!(tr.lag_ms.is_some(), "{tr:?}");
    }
    assert!(flv::summary(&trials).contains("served=3 refused=0"), "{}", flv::summary(&trials));
    assert_eq!(sim.stats().logins_ok, 1, "one token for every trial");
    no_hid(&sim);
}

/// The same-token refusal carry: a side FLV the KVM refuses is recorded
/// with its form, and the run goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_side_flv_is_recorded_with_its_form() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.refuse_concurrent_flv = 1);
    let trials = flv::concurrent_flv(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &plan(2),
        |_, _| {},
    )
    .await
    .unwrap();
    assert!(
        matches!(&trials[0].side, Side::Refused(f) if f.status == 503),
        "{:?}",
        trials[0]
    );
    assert!(!trials[0].forced, "{:?}", trials[0]);
    assert!(matches!(trials[1].side, Side::Served { .. }), "{:?}", trials[1]);
    no_hid(&sim);
}

/// DD1's tokens: a never-issued token and no token, on both services —
/// status, Content-Type and body, escaped — against a valid token's
/// baseline.
#[tokio::test]
async fn refusal_forms_name_status_type_and_body() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let Ok(FlvOpen::Refused(f)) = flv::open(&t, pin, Some(NEVER_ISSUED), T).await else {
        panic!("a never-issued token was served an FLV")
    };
    assert_eq!(
        (f.status, f.content_type.as_str(), f.body.as_str()),
        (403, "application/json", "{\\\"result\\\":403}")
    );
    let Ok(FlvOpen::Refused(f)) = flv::open(&t, pin, None, T).await else {
        panic!("no token was served an FLV")
    };
    assert_eq!(f.status, 403);
    for token in [Some(NEVER_ISSUED), None] {
        let Ok(Upgrade::Refused(f)) = ws::upgrade(&t, pin, token, T).await else {
            panic!("{token:?} upgraded the websocket")
        };
        assert_eq!(f.status, 403, "{token:?}");
    }
    let token = login(&sim).await;
    assert!(matches!(
        flv::open(&t, pin, Some(&token), T).await,
        Ok(FlvOpen::Stream(_))
    ));
    assert!(matches!(
        ws::upgrade(&t, pin, Some(&token), T).await,
        Ok(Upgrade::Accepted(_))
    ));
    no_hid(&sim);
}

/// The close-form carry: the report says how the KVM answered a close
/// frame and how its TCP connection ended, within the wait; nothing but a
/// close frame was sent.
#[tokio::test]
async fn ws_close_reports_the_answer_and_the_tcp_end() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let Ok(Upgrade::Accepted(w)) =
        ws::upgrade(&target(&sim), Some(sim.spki_sha256()), Some(&token), T).await
    else {
        panic!("not upgraded")
    };
    let r = ws::close_form(*w, Duration::from_millis(200), Duration::from_secs(2)).await;
    assert!(!r.idle.closed_by_kvm, "{r:?}");
    assert!(!matches!(r.reply, Reply::Timeout), "{r:?}");
    assert!(!matches!(r.tcp, TcpEnd::Timeout), "{r:?}");
    sim.wait_for(T, |e| e.iter().any(|e| matches!(e, SimEvent::WsClose { .. })))
        .await
        .unwrap();
    no_hid(&sim);
}

/// DC18's token question: each token is probed once, at its age, with a
/// bare websocket upgrade; one that lapsed meanwhile (here: expired by the
/// sim) is refused with its form. The expiry is gated on the 500 ms
/// probe's report, not on a clock that the logins before `t0` could
/// outrun on a loaded host (D15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_life_probes_each_token_once_at_its_age() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let ages = [Duration::ZERO, Duration::from_millis(500), Duration::from_millis(1500)];
    let mut seen = Vec::new();
    let gate = tokio::sync::Notify::new();
    let expire = async {
        gate.notified().await;
        sim.expire_tokens();
    };
    let (probes, ()) = tokio::join!(
        session::token_life(&t, pin, pin, sim.password(), &ages, T, |p| {
            seen.push(p.age);
            if p.age == Duration::from_millis(500) {
                gate.notify_one();
            }
        }),
        expire
    );
    let probes = probes.unwrap();
    let accepted: Vec<bool> = probes
        .iter()
        .map(|p| p.outcome == Outcome::Accepted)
        .collect();
    assert_eq!(accepted, [true, true, false], "{probes:?}");
    assert!(
        matches!(&probes[2].outcome, Outcome::Refused(f) if f.status == 403),
        "{probes:?}"
    );
    assert_eq!(seen, ages);
    assert_eq!(sim.stats().logins_ok, 3);
    no_hid(&sim);
}

/// DC18's session-cap question: logins up to the bound, each checked by a
/// bare upgrade of the first and the newest token; a refused first login
/// is the error.
#[tokio::test]
async fn session_cap_counts_logins_while_every_token_works() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let r = session::session_cap(&t, pin, pin, sim.password(), 5, T, |_, _| {})
        .await
        .unwrap();
    assert_eq!(
        r,
        CapReport {
            logins: 5,
            stopped: None
        }
    );
    sim.set_policy(|p| p.reject_logins = true);
    assert!(
        session::session_cap(&t, pin, pin, sim.password(), 5, T, |_, _| {})
            .await
            .is_err()
    );
    no_hid(&sim);
}

/// Controller ruling 1 (`logout-watch`): the probe never logs out; the
/// "owner" here is a second session that logs out (`support::logout`,
/// kvm-sim's global logout) once the probe says READY. The probe sees its
/// token refused, records both refusal forms, and reports that the
/// websocket and FLV it opened before the logout survived it (kvm-sim's
/// model, §11.5) — on the ES3 that is the fact Task 1.6 step 16 records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_watch_records_the_forms_after_someone_elses_logout() {
    let sim = sim_with(|_| {}).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let owner = login(&sim).await;
    let ready = tokio::sync::Notify::new();
    let owner_logs_out = async {
        ready.notified().await;
        crate::support::logout(&sim, &owner).await;
    };
    let (r, ()) = tokio::join!(
        session::logout_watch(
            &t,
            pin,
            pin,
            pin,
            sim.password(),
            session::WatchPlan {
                max: Duration::from_secs(10),
                poll: Duration::from_millis(100),
            },
            || ready.notify_one(),
        ),
        owner_logs_out
    );
    let r = r.unwrap();
    assert!(r.logged_out_after.is_some(), "{r:?}");
    assert!(matches!(&r.flv_form, Some(f) if f.status == 403), "{r:?}");
    assert!(matches!(&r.ws_form, Some(f) if f.status == 403), "{r:?}");
    assert!(r.ws_survived && r.ws_write_ok && r.flv_survived, "{r:?}");
    // Exactly one logout — the owner's; the probe sent none.
    assert_eq!(sim.stats().logouts, 1);
    // The probe's only HID frame is its one all-zero report.
    let hid: Vec<_> = sim
        .events()
        .into_iter()
        .filter_map(|e| if let SimEvent::Hid { bytes, .. } = e { Some(bytes) } else { None })
        .collect();
    assert_eq!(hid, [vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --test sim -- l4` — Expected: FAIL to compile (`kvm_probe::l4` not found).

- [ ] **Step 3: Implement.** In `crates/kvm-probe/Cargo.toml`, add `"sync"` to tokio's features (`features = ["rt-multi-thread", "rt", "net", "io-util", "macros", "time", "sync"]`) and, under `[dependencies]`, `futures-util = { version = "0.3", default-features = false, features = ["sink", "std"] }` (both already in the workspace's build graph). Add `pub mod l4;` to `src/lib.rs`. Create `src/l4/mod.rs`:

```rust
//! Plan D's L4 hardware checks (spec §11.6). Every check here reads the
//! KVM; none sends a HID frame except `logout-watch`'s one all-zero release
//! (the HID checks are `hid`, `hold`), and none logs out (kvm-probe cannot,
//! §3.2). Device text reaches the terminal
//! only escaped and bounded (§9.2): `escaped`, `RefusalForm`.
pub mod flv;
pub mod session;
pub mod ws;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A token the KVM never issued (DD1: the refusal forms are measured
/// without a logout).
pub const NEVER_ISSUED: &str = "0.0";

/// How much of a refusal's body is kept.
pub const FORM_BODY_MAX: usize = 64;

/// How the KVM refused a request: status, Content-Type and the start of
/// the body, each escaped and bounded — derived facts for census.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalForm {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl RefusalForm {
    #[must_use]
    pub fn new(status: u16, content_type: Option<&[u8]>, body: &[u8]) -> RefusalForm {
        RefusalForm {
            status,
            content_type: escaped(content_type.unwrap_or_default(), FORM_BODY_MAX),
            body: escaped(body, FORM_BODY_MAX),
        }
    }
}

impl std::fmt::Display for RefusalForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status {} content-type \"{}\" body \"{}\"",
            self.status, self.content_type, self.body
        )
    }
}

/// At most `max` bytes, every byte outside printable ASCII (and `"`, `\`)
/// escaped as `std::ascii::escape_default` does.
#[must_use]
pub fn escaped(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .flat_map(|b| std::ascii::escape_default(*b))
        .map(char::from)
        .collect()
}

/// Seconds since the Unix epoch, for the login body's `time`.
#[must_use]
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[must_use]
pub fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds from `t0` to `t` (0 if `t` is earlier).
#[must_use]
pub fn since(t0: Instant, t: Instant) -> u64 {
    ms(t.saturating_duration_since(t0))
}

/// `now + d` on tokio's clock, saturating.
#[must_use]
pub fn deadline(d: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(d).unwrap_or(now)
}
```

Create `src/l4/flv.rs`:

```rust
//! `av.flv` for the L4 checks: an open that tells a stream from a refusal
//! (a 200 whose body is not FLV is a refusal, as the bridge's classifier
//! reads it, §6.9), and `concurrent-flv` (§6.5, §11.6).
use super::{FORM_BODY_MAX, RefusalForm, deadline, since};
use crate::capture::record_for;
use crate::kvm::{self, KvmError};
use crate::request::{self, KvmTarget};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, TagBody, VideoBody};
use std::time::{Duration, Instant};

/// Hostile-input bound (§9.2) on one stream.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub enum FlvOpen {
    Stream(FlvStream),
    Refused(RefusalForm),
}

pub struct FlvStream {
    body: hyper::body::Incoming,
    demux: FlvDemuxer,
    bytes: u64,
}

/// `GET /av.flv` with `token` as query and cookie (§3.2), or with neither;
/// the open (through the first body bytes) bounded by `timeout`.
pub async fn open(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<FlvOpen, KvmError> {
    tokio::time::timeout(timeout, open_inner(t, pin, token))
        .await
        .map_err(|_| KvmError::Http(format!("av.flv open timed out after {timeout:?}")))?
}

async fn open_inner(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
) -> Result<FlvOpen, KvmError> {
    let io = kvm::connect_to(t, t.video_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .header("Host", &t.host);
    let req = match token {
        Some(tok) => req
            .uri(format!("/av.flv?token={tok}"))
            .header("Cookie", request::token_cookie_header(tok)),
        None => req.uri("/av.flv"),
    };
    let req = req
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.as_bytes().to_vec());
    let mut body = resp.into_body();
    // The first body bytes decide: FLV's signature, or a refusal.
    let mut first: Vec<u8> = Vec::new();
    while first.len() < 3 {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    first.extend_from_slice(d);
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    if status != 200 || !first.starts_with(b"FLV") {
        // A refusal: read on (still inside `open`'s timeout) until the form
        // holds FORM_BODY_MAX bytes or the body ends, so a body split over
        // frames is not cut at the first one (D14).
        while first.len() < FORM_BODY_MAX {
            match body.frame().await {
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        first.extend_from_slice(d);
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
        let shown = first.get(..first.len().min(FORM_BODY_MAX)).unwrap_or_default();
        return Ok(FlvOpen::Refused(RefusalForm::new(
            status,
            content_type.as_deref(),
            shown,
        )));
    }
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    demux.push(&first);
    Ok(FlvOpen::Stream(FlvStream {
        body,
        demux,
        bytes: u64::try_from(first.len()).unwrap_or(u64::MAX),
    }))
}

impl FlvStream {
    /// The next tag and when it was demuxed; `None` at the end of the
    /// stream.
    pub async fn next_tag(&mut self) -> Result<Option<(Instant, FlvTag)>, KvmError> {
        loop {
            if let Some(tag) = self
                .demux
                .next_tag()
                .map_err(|e| KvmError::Http(format!("{e:?}")))?
            {
                return Ok(Some((Instant::now(), tag)));
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(KvmError::Http(e.to_string())),
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        self.bytes = self
                            .bytes
                            .saturating_add(u64::try_from(d.len()).unwrap_or(u64::MAX));
                        if self.bytes > MAX_BYTES {
                            return Err(KvmError::Http(format!(
                                "av.flv passed the {MAX_BYTES}-byte cap"
                            )));
                        }
                        self.demux.push(d);
                    }
                }
            }
        }
    }
}

/// A coded (NALU) video tag: one access unit on the ES3 (§6.2).
#[must_use]
pub fn is_coded(tag: &FlvTag) -> bool {
    matches!(&tag.body, TagBody::Video(VideoBody::Nalus { .. }))
}

#[must_use]
pub fn is_idr(tag: &FlvTag) -> bool {
    record_for(tag, 0).nal_types.contains(&5)
}

#[derive(Debug, Clone)]
pub struct ConcurrentPlan {
    pub trials: u32,
    /// The main FLV's GOP length in frames (60 on the ES3, census Leg A).
    pub gop: u32,
    pub timeout: Duration,
    pub pause: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Served {
        first_tag_ms: u64,
        first_idr_ms: Option<u64>,
    },
    Refused(RefusalForm),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Trial {
    pub side: Side,
    /// Side open → the main FLV's next IDR.
    pub main_idr_ms: Option<u64>,
    /// That IDR came before the GOP's periodic slot: the side open forced it.
    pub forced: bool,
    /// The side's first IDR minus the main's forced IDR (a `ReconnectFlv`
    /// candidate's lag, §6.5).
    pub lag_ms: Option<i64>,
    /// Main AUs from its forced IDR up to the side's first IDR: what a
    /// swap's replay ring (64, §6.5) must hold.
    pub replay_aus: Option<u32>,
}

fn next_since(since: Option<u32>, idr: bool) -> Option<u32> {
    if idr {
        Some(0)
    } else {
        since.map(|s| s.saturating_add(1))
    }
}

fn signed_ms(from: Instant, to: Instant) -> i64 {
    let ahead = i64::try_from(since(from, to)).unwrap_or(i64::MAX);
    let behind = i64::try_from(since(to, from)).unwrap_or(i64::MAX);
    ahead.saturating_sub(behind)
}

async fn side_probe(
    t: KvmTarget,
    pin: Option<String>,
    token: String,
    timeout: Duration,
    t0: Instant,
) -> (Side, Option<Instant>) {
    let mut stream = match open(&t, pin.as_deref(), Some(&token), timeout).await {
        Ok(FlvOpen::Stream(s)) => s,
        Ok(FlvOpen::Refused(f)) => return (Side::Refused(f), None),
        Err(e) => return (Side::Failed(kvm::bounded_debug(&e)), None),
    };
    let until = deadline(timeout);
    let (mut first_tag, mut first_idr) = (None, None);
    while first_idr.is_none() {
        match tokio::time::timeout_at(until, stream.next_tag()).await {
            Ok(Ok(Some((at, tag)))) => {
                first_tag.get_or_insert(at);
                if is_coded(&tag) && is_idr(&tag) {
                    first_idr = Some(at);
                }
            }
            _ => break,
        }
    }
    // Dropping the stream closes the side FLV, as the bridge's does (§6.5).
    match first_tag {
        Some(ft) => (
            Side::Served {
                first_tag_ms: since(t0, ft),
                first_idr_ms: first_idr.map(|i| since(t0, i)),
            },
            first_idr,
        ),
        None => (Side::Failed("no tag before the timeout".to_owned()), None),
    }
}

/// `concurrent-flv`: one main FLV on `token`; per trial, wait until the
/// main is 10–20 frames into its GOP (so a forced IDR cannot be the
/// periodic one), open a side FLV on the same token, read it to its first
/// IDR and close it, and time the main's next IDR.
pub async fn concurrent_flv(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    plan: &ConcurrentPlan,
    mut on_trial: impl FnMut(u32, &Trial),
) -> Result<Vec<Trial>, KvmError> {
    let FlvOpen::Stream(mut main) = open(t, pin, Some(token), plan.timeout).await? else {
        return Err(KvmError::Http("the main av.flv was refused".to_owned()));
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, bool)>();
    let reader = tokio::spawn(async move {
        while let Ok(Some((at, tag))) = main.next_tag().await {
            if is_coded(&tag) && tx.send((at, is_idr(&tag))).is_err() {
                break;
            }
        }
    });
    let mut trials = Vec::new();
    let mut since_idr: Option<u32> = None;
    for n in 1..=plan.trials {
        // D7b: the AUs that queued during the pause are history — count
        // them into `since_idr`, then wait for a live AU in the window, with
        // nothing still queued behind it, so `t0` is "now" in GOP terms.
        while let Ok((_, idr)) = rx.try_recv() {
            since_idr = next_since(since_idr, idr);
        }
        let window_until = deadline(plan.timeout.saturating_mul(3));
        let in_window = loop {
            match tokio::time::timeout_at(window_until, rx.recv()).await {
                Ok(Some((_, idr))) => {
                    since_idr = next_since(since_idr, idr);
                    if since_idr.is_some_and(|s| (10..=20).contains(&s)) && rx.is_empty() {
                        break true;
                    }
                }
                _ => break false,
            }
        };
        if !in_window {
            reader.abort();
            return Err(KvmError::Http(
                "the main av.flv stopped before a trial window".to_owned(),
            ));
        }
        let t0 = Instant::now();
        let side = tokio::spawn(side_probe(
            t.clone(),
            pin.map(str::to_owned),
            token.to_owned(),
            plan.timeout,
            t0,
        ));
        let mut main_aus: Vec<(Instant, bool)> = Vec::new();
        let mut main_idr: Option<(Instant, u32)> = None;
        let until = deadline(plan.timeout);
        while main_idr.is_none() {
            match tokio::time::timeout_at(until, rx.recv()).await {
                Ok(Some((at, idr))) => {
                    main_aus.push((at, idr));
                    // An AU received before `t0` can never be the IDR this
                    // side open forced (D7b).
                    if idr && at >= t0 {
                        let frames = since_idr.map_or(0, |s| s.saturating_add(1));
                        main_idr = Some((at, frames));
                    }
                    since_idr = next_since(since_idr, idr);
                }
                _ => break,
            }
        }
        let (side, side_idr) = side
            .await
            .unwrap_or_else(|e| (Side::Failed(format!("side task: {e}")), None));
        while let Ok((at, idr)) = rx.try_recv() {
            main_aus.push((at, idr));
            since_idr = next_since(since_idr, idr);
        }
        let paired = side_idr.zip(main_idr);
        let trial = Trial {
            main_idr_ms: main_idr.map(|(at, _)| since(t0, at)),
            forced: main_idr.is_some_and(|(_, frames)| frames < plan.gop.saturating_sub(2)),
            lag_ms: paired.map(|(s, (m, _))| signed_ms(m, s)),
            replay_aus: paired.map(|(s, (m, _))| {
                let n = main_aus.iter().filter(|(at, _)| *at >= m && *at < s).count();
                u32::try_from(n).unwrap_or(u32::MAX)
            }),
            side,
        };
        on_trial(n, &trial);
        trials.push(trial);
        tokio::time::sleep(plan.pause).await;
    }
    reader.abort();
    Ok(trials)
}

/// One line for census.md: served/refused/failed, forced, the forced
/// trials' side → main IDR p50/p95, the lag's range and the most AUs a
/// replay would hold.
#[must_use]
pub fn summary(trials: &[Trial]) -> String {
    let count = |f: fn(&Side) -> bool| trials.iter().filter(|t| f(&t.side)).count();
    let served = count(|s| matches!(s, Side::Served { .. }));
    let refused = count(|s| matches!(s, Side::Refused(_)));
    let failed = count(|s| matches!(s, Side::Failed(_)));
    let forced: Vec<Duration> = trials
        .iter()
        .filter(|t| t.forced)
        .filter_map(|t| t.main_idr_ms.map(Duration::from_millis))
        .collect();
    let pct = |p| crate::stats::percentile(&forced, p).map_or("n/a".to_owned(), |d| format!("{} ms", d.as_millis()));
    let lags: Vec<i64> = trials.iter().filter_map(|t| t.lag_ms).collect();
    let replay = trials.iter().filter_map(|t| t.replay_aus).max();
    format!(
        "trials={} served={served} refused={refused} failed={failed} forced={} side->main IDR p50={} p95={} lag_ms min={:?} max={:?} replay_aus max={:?}",
        trials.len(),
        forced.len(),
        pct(50),
        pct(95),
        lags.iter().min(),
        lags.iter().max(),
        replay
    )
}
```

Create `src/l4/ws.rs`:

```rust
//! The control websocket for the L4 checks: an upgrade that tells an
//! acceptance from a refusal, and `ws-close` — how the KVM answers a close
//! frame and how its TCP connection ends (the PC9 carry: §3.2 counts only
//! an answered close frame as a clean close).
use super::{RefusalForm, deadline, escaped, since};
use crate::kvm::{self, BoxedIo, KvmError};
use crate::request::{self, KvmTarget};
use futures_util::StreamExt as _;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest as _, protocol::WebSocketConfig};

pub type Ws = tokio_tungstenite::WebSocketStream<BoxedIo>;

/// `Accepted` is boxed: the stream is 296 bytes against `RefusalForm`'s 56
/// (`clippy::large_enum_variant`, D12).
pub enum Upgrade {
    Accepted(Box<Ws>),
    Refused(RefusalForm),
}

/// Upgrade `/websocket` on the control port, with `token`'s cookie or none.
pub async fn upgrade(
    t: &KvmTarget,
    pin: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Upgrade, KvmError> {
    let io = kvm::connect_to(t, t.control_port, pin).await?;
    upgrade_on(io, t, token, timeout).await
}

/// The upgrade over a connection already made (the HID checks make theirs
/// resettable). The bridge's limits: 4 KiB messages and frames (§3.2).
pub async fn upgrade_on(
    io: BoxedIo,
    t: &KvmTarget,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Upgrade, KvmError> {
    let mut req = request::websocket_url(t)
        .as_str()
        .into_client_request()
        .map_err(|e| KvmError::Http(e.to_string()))?;
    if let Some(tok) = token {
        let cookie = request::token_cookie_header(tok)
            .parse()
            .map_err(|_| KvmError::Http("bad cookie header".to_owned()))?;
        req.headers_mut().insert("Cookie", cookie);
    }
    let cfg = WebSocketConfig {
        max_message_size: Some(4096),
        max_frame_size: Some(4096),
        ..WebSocketConfig::default()
    };
    match tokio::time::timeout(
        timeout,
        tokio_tungstenite::client_async_with_config(req, io, Some(cfg)),
    )
    .await
    {
        Err(_) => Err(KvmError::Http(format!(
            "websocket upgrade timed out after {timeout:?}"
        ))),
        Ok(Ok((ws, _))) => Ok(Upgrade::Accepted(Box::new(ws))),
        Ok(Err(tungstenite::Error::Http(resp))) => {
            let ct = resp.headers().get("content-type").map(|v| v.as_bytes());
            let body = resp.body().as_deref().unwrap_or_default();
            Ok(Upgrade::Refused(RefusalForm::new(resp.status().as_u16(), ct, body)))
        }
        Ok(Err(e)) => Err(KvmError::Http(escaped(e.to_string().as_bytes(), 200))),
    }
}

/// What the KVM sent while the websocket sat idle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inbound {
    pub text: u32,
    pub binary: u32,
    pub ping: u32,
    pub pong: u32,
    /// The KVM closed (a close frame, an EOF or an error) before we did.
    pub closed_by_kvm: bool,
}

/// How the KVM answered our close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    CloseFrame { ms: u64 },
    Eof { ms: u64 },
    Error { ms: u64, what: String },
    Timeout,
}

/// How the TCP connection then ended, read below the websocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpEnd {
    Fin { ms: u64 },
    Reset { ms: u64 },
    Error { ms: u64, kind: String },
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReport {
    pub idle: Inbound,
    pub reply: Reply,
    pub tcp: TcpEnd,
}

/// `ws-close`: read for `idle` (sending nothing), send a close frame, then
/// wait up to `wait` for the answer and for the TCP end.
pub async fn close_form(mut ws: Ws, idle: Duration, wait: Duration) -> CloseReport {
    let mut inbound = Inbound::default();
    let idle_until = deadline(idle);
    loop {
        match tokio::time::timeout_at(idle_until, ws.next()).await {
            Err(_) => break,
            Ok(Some(Ok(m))) => match m {
                Message::Text(_) => inbound.text = inbound.text.saturating_add(1),
                Message::Binary(_) => inbound.binary = inbound.binary.saturating_add(1),
                Message::Ping(_) => inbound.ping = inbound.ping.saturating_add(1),
                Message::Pong(_) => inbound.pong = inbound.pong.saturating_add(1),
                Message::Close(_) => {
                    inbound.closed_by_kvm = true;
                    break;
                }
                Message::Frame(_) => {}
            },
            Ok(Some(Err(_)) | None) => {
                inbound.closed_by_kvm = true;
                break;
            }
        }
    }
    let t0 = Instant::now();
    if inbound.closed_by_kvm {
        let tcp = tcp_end(ws.get_mut(), t0, wait).await;
        return CloseReport {
            idle: inbound,
            reply: Reply::Timeout,
            tcp,
        };
    }
    let _ = ws.close(None).await;
    let until = deadline(wait);
    let reply = loop {
        match tokio::time::timeout_at(until, ws.next()).await {
            Err(_) => break Reply::Timeout,
            Ok(Some(Ok(Message::Close(_)))) => {
                break Reply::CloseFrame {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => {
                break Reply::Error {
                    ms: since(t0, Instant::now()),
                    what: escaped(e.to_string().as_bytes(), 120),
                };
            }
            Ok(None) => {
                break Reply::Eof {
                    ms: since(t0, Instant::now()),
                };
            }
        }
    };
    let tcp = tcp_end(ws.get_mut(), t0, wait).await;
    CloseReport {
        idle: inbound,
        reply,
        tcp,
    }
}

async fn tcp_end(io: &mut BoxedIo, t0: Instant, wait: Duration) -> TcpEnd {
    let until = deadline(wait);
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout_at(until, io.read(&mut buf)).await {
            Err(_) => return TcpEnd::Timeout,
            Ok(Ok(0)) => {
                return TcpEnd::Fin {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return TcpEnd::Reset {
                    ms: since(t0, Instant::now()),
                };
            }
            Ok(Err(e)) => {
                return TcpEnd::Error {
                    ms: since(t0, Instant::now()),
                    kind: format!("{:?}", e.kind()),
                };
            }
        }
    }
}
```

Create `src/l4/session.rs`:

```rust
//! DC18's session questions: how long an abandoned token stays valid, and
//! whether the KVM caps concurrent sessions. A token is probed with a bare
//! websocket upgrade — accepted or refused, then closed with no data frame.
use super::RefusalForm;
use super::ws::{self, Upgrade};
use crate::kvm::{self, KvmError, PROBE_TIMEZONE};
use crate::request::KvmTarget;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Refused(RefusalForm),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifeProbe {
    pub age: Duration,
    pub outcome: Outcome,
}

pub async fn probe_token(
    t: &KvmTarget,
    control_pin: Option<&str>,
    token: &str,
    timeout: Duration,
) -> Outcome {
    match ws::upgrade(t, control_pin, Some(token), timeout).await {
        Ok(Upgrade::Accepted(mut w)) => {
            let _ = w.close(None).await;
            Outcome::Accepted
        }
        Ok(Upgrade::Refused(f)) => Outcome::Refused(f),
        Err(e) => Outcome::Failed(kvm::bounded_debug(&e)),
    }
}

async fn fresh_token(t: &KvmTarget, web_pin: Option<&str>, password: &str) -> Result<String, KvmError> {
    kvm::login(t, web_pin, password, super::now_unix(), PROBE_TIMEZONE).await
}

/// `token-life`: one login per age now, then each token probed once, when
/// it reaches its age — probing a token only once means a use cannot have
/// refreshed it.
pub async fn token_life(
    t: &KvmTarget,
    web_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    ages: &[Duration],
    timeout: Duration,
    mut on: impl FnMut(&LifeProbe),
) -> Result<Vec<LifeProbe>, KvmError> {
    let mut order: Vec<(Duration, String)> = Vec::with_capacity(ages.len());
    for age in ages {
        order.push((*age, fresh_token(t, web_pin, password).await?));
    }
    order.sort_by_key(|(age, _)| *age);
    let t0 = Instant::now();
    let mut out = Vec::with_capacity(order.len());
    for (age, token) in order {
        let at = t0.checked_add(age).unwrap_or(t0);
        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
        let probe = LifeProbe {
            age,
            outcome: probe_token(t, control_pin, &token, timeout).await,
        };
        on(&probe);
        out.push(probe);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapReport {
    pub logins: u32,
    /// Why the run stopped before `max`, if it did.
    pub stopped: Option<String>,
}

/// `session-cap`: up to `max` logins; after each, the newest and the first
/// token must both still upgrade. A refused first login is the error.
pub async fn session_cap(
    t: &KvmTarget,
    web_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    max: u32,
    timeout: Duration,
    mut on: impl FnMut(u32, &str),
) -> Result<CapReport, KvmError> {
    let first = fresh_token(t, web_pin, password).await?;
    on(1, "login ok");
    let mut logins = 1u32;
    for i in 2..=max {
        let token = match fresh_token(t, web_pin, password).await {
            Ok(tok) => tok,
            Err(e) => {
                return Ok(CapReport {
                    logins,
                    stopped: Some(format!("login {i} refused: {}", kvm::bounded_debug(&e))),
                });
            }
        };
        logins = i;
        let newest = probe_token(t, control_pin, &token, timeout).await;
        let oldest = probe_token(t, control_pin, &first, timeout).await;
        on(i, &format!("newest {newest:?}; first {oldest:?}"));
        if oldest != Outcome::Accepted {
            return Ok(CapReport {
                logins,
                stopped: Some(format!("the first token stopped working after login {i}: {oldest:?}")),
            });
        }
        if newest != Outcome::Accepted {
            return Ok(CapReport {
                logins,
                stopped: Some(format!("login {i}'s token was refused: {newest:?}")),
            });
        }
    }
    Ok(CapReport {
        logins,
        stopped: None,
    })
}

/// `logout-watch` (controller ruling 1): how often to poll, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct WatchPlan {
    pub max: Duration,
    pub poll: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchReport {
    /// How long after READY the probe's token was first refused; `None` if
    /// it never was within `max` (the owner did not log out, or the logout
    /// is not global after all).
    pub logged_out_after: Option<Duration>,
    /// The FLV and websocket refusal forms for the logged-out token.
    pub flv_form: Option<RefusalForm>,
    pub ws_form: Option<RefusalForm>,
    /// The websocket opened before the logout showed no close frame, EOF or
    /// error after it.
    pub ws_survived: bool,
    /// One all-zero keyboard report (a release) written on it afterwards
    /// succeeded.
    pub ws_write_ok: bool,
    /// The FLV opened before the logout still delivered tags afterwards.
    pub flv_survived: bool,
}

/// `logout-watch`: the probe NEVER logs out (§3.2, DD1). It logs in, opens
/// the control websocket and an FLV on its token, calls `ready` (the CLI
/// prints `READY: log out of the KVM web UI now` — the OWNER logs out), then
/// polls a fresh FLV open on the same token every `plan.poll` until it is
/// refused or `plan.max` passes. It records the FLV and websocket refusal
/// forms after the logout, and whether the pre-opened websocket and FLV
/// survived it — the facts the Plan A assumption and PC6's classifier rest
/// on.
pub async fn logout_watch(
    t: &KvmTarget,
    web_pin: Option<&str>,
    video_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    plan: WatchPlan,
    ready: impl FnOnce(),
) -> Result<WatchReport, KvmError> {
    use futures_util::{SinkExt as _, StreamExt as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio_tungstenite::tungstenite::Message;
    let open_wait = Duration::from_secs(10);
    let token = fresh_token(t, web_pin, password).await?;
    let mut held_ws = match ws::upgrade(t, control_pin, Some(&token), open_wait).await? {
        Upgrade::Accepted(w) => w,
        Upgrade::Refused(f) => {
            return Err(KvmError::Http(format!("websocket refused before the logout: {f}")));
        }
    };
    let mut held_flv = match super::flv::open(t, video_pin, Some(&token), open_wait).await? {
        super::flv::FlvOpen::Stream(s) => s,
        super::flv::FlvOpen::Refused(f) => {
            return Err(KvmError::Http(format!("av.flv refused before the logout: {f}")));
        }
    };
    let tags = Arc::new(AtomicU64::new(0));
    let counted = tags.clone();
    let reader = tokio::spawn(async move {
        while let Ok(Some(_)) = held_flv.next_tag().await {
            counted.fetch_add(1, Ordering::Relaxed);
        }
    });
    ready();
    let t0 = Instant::now();
    let until = t0.checked_add(plan.max).unwrap_or(t0);
    let mut report = WatchReport {
        logged_out_after: None,
        flv_form: None,
        ws_form: None,
        ws_survived: false,
        ws_write_ok: false,
        flv_survived: false,
    };
    while Instant::now() < until {
        // A poll is a plain FLV open (it forces an IDR into every viewer —
        // harmless); dropped at once when it is served.
        if let Ok(super::flv::FlvOpen::Refused(f)) =
            super::flv::open(t, video_pin, Some(&token), open_wait).await
        {
            report.logged_out_after = Some(t0.elapsed());
            report.flv_form = Some(f);
            break;
        }
        tokio::time::sleep(plan.poll).await;
    }
    if report.logged_out_after.is_some() {
        report.ws_form = match ws::upgrade(t, control_pin, Some(&token), open_wait).await {
            Ok(Upgrade::Refused(f)) => Some(f),
            _ => None,
        };
        // The websocket sat unread for up to `max`: read everything queued
        // on it (heartbeat text included), so a close behind it is seen (D32).
        let mut survived = true;
        while let Ok(m) = tokio::time::timeout(Duration::from_millis(200), held_ws.next()).await {
            if matches!(m, Some(Ok(Message::Close(_)) | Err(_)) | None) {
                survived = false;
                break;
            }
        }
        report.ws_survived = survived;
        let zero = kvm_proto::hid::HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        };
        report.ws_write_ok = matches!(
            tokio::time::timeout(Duration::from_secs(1), held_ws.send(Message::Binary(zero.to_vec())))
                .await,
            Ok(Ok(()))
        );
        let before = tags.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(1)).await;
        report.flv_survived = tags.load(Ordering::Relaxed) > before;
    }
    let _ = held_ws.close(None).await;
    reader.abort();
    Ok(report)
}
```

- [ ] **Step 4: The subcommands.** In `src/cli.rs`'s `Cmd`, after `WsOpen`:

```rust
    /// L4 (§11.6): side FLVs on the main FLV's own token — served or
    /// refused (with the form), the main FLV's forced-IDR latency, and how
    /// many AUs a ReconnectFlv swap would replay. No HID, no logout.
    ConcurrentFlv {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 20)]
        trials: u32,
        /// The main FLV's GOP in frames (60 on the ES3, census Leg A).
        #[arg(long, default_value_t = 60)]
        gop: u32,
    },
    /// L4: how the KVM refuses an FLV and a websocket with a never-issued
    /// token and with none (status, Content-Type, body prefix). No login.
    RefusalForms {
        #[command(flatten)]
        conn: Conn,
    },
    /// L4: open the control websocket, read for --idle-secs sending
    /// nothing, send a close frame, and report the KVM's answer and how its
    /// TCP connection ends. Never logs out.
    WsClose {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 10)]
        idle_secs: u64,
    },
    /// L4: log in once per --minutes value now, then probe each token once,
    /// at that age, with a bare websocket upgrade. Never logs out.
    TokenLife {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_delimiter = ',', default_value = "1,5,15,30,60")]
        minutes: Vec<u64>,
    },
    /// L4: log in up to --max times, checking after each that the first and
    /// the newest token still work. If the KVM evicts its oldest session at
    /// a cap, this can end the owner's web-UI session: run it only with the
    /// owner's consent. Never logs out.
    SessionCap {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 16)]
        max: u32,
    },
    /// L4 [OWNER, optional]: log in, open the control websocket and an FLV,
    /// print READY, and watch while the OWNER logs out in the vendor web UI
    /// (controller ruling 1). The probe never sends a logout. Only after
    /// the owner confirms nobody else is using the KVM.
    LogoutWatch {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 300)]
        max_secs: u64,
    },
```

and in `Cli::validate`'s match, before the `Fingerprint | SampleRange | Summarize` arm:

```rust
            Cmd::ConcurrentFlv { conn, .. } => (conn, &[Port::Web, Port::Video]),
            Cmd::RefusalForms { conn } => (conn, &[Port::Video, Port::Control]),
            Cmd::WsClose { conn, .. } | Cmd::TokenLife { conn, .. } | Cmd::SessionCap { conn, .. } => {
                (conn, &[Port::Web, Port::Control])
            }
            Cmd::LogoutWatch { conn, .. } => (conn, &[Port::Web, Port::Video, Port::Control]),
```

In `src/main.rs`, add `l4` to the `use kvm_probe::{…}` list and, after the `Cmd::WsOpen` arm:

```rust
        Cmd::ConcurrentFlv { conn, trials, gop } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let plan = l4::flv::ConcurrentPlan {
                trials,
                gop,
                timeout: Duration::from_secs(5),
                pause: Duration::from_millis(2500),
            };
            let report = session(&conn, &pw, async |tok: &str| {
                l4::flv::concurrent_flv(&t, conn.pin_for(Port::Video), tok, &plan, |n, tr| {
                    println!("trial {n}/{trials}: {tr:?}");
                })
                .await
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))?
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("{}", l4::flv::summary(&report));
        }
        Cmd::RefusalForms { conn } => {
            let t = target(&conn);
            let wait = Duration::from_secs(5);
            for (what, token) in [("never-issued token", Some(l4::NEVER_ISSUED)), ("no token", None)] {
                let flv = match l4::flv::open(&t, conn.pin_for(Port::Video), token, wait).await {
                    Ok(l4::flv::FlvOpen::Stream(_)) => "served an FLV".to_owned(),
                    Ok(l4::flv::FlvOpen::Refused(f)) => format!("refused: {f}"),
                    Err(e) => format!("failed: {}", kvm::bounded_debug(&e)),
                };
                println!("av.flv, {what}: {flv}");
                let ws = match l4::ws::upgrade(&t, conn.pin_for(Port::Control), token, wait).await {
                    Ok(l4::ws::Upgrade::Accepted(_)) => "upgraded".to_owned(),
                    Ok(l4::ws::Upgrade::Refused(f)) => format!("refused: {f}"),
                    Err(e) => format!("failed: {}", kvm::bounded_debug(&e)),
                };
                println!("websocket, {what}: {ws}");
            }
        }
        Cmd::WsClose { conn, idle_secs } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let report = session(&conn, &pw, async |tok: &str| {
                match l4::ws::upgrade(&t, conn.pin_for(Port::Control), Some(tok), Duration::from_secs(10)).await {
                    Ok(l4::ws::Upgrade::Accepted(w)) => Ok(l4::ws::close_form(
                        *w,
                        Duration::from_secs(idle_secs),
                        Duration::from_secs(5),
                    )
                    .await),
                    Ok(l4::ws::Upgrade::Refused(f)) => Err(format!("refused: {f}")),
                    Err(e) => Err(kvm::bounded_debug(&e)),
                }
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))??;
            println!("{report:?}");
        }
        Cmd::TokenLife { conn, minutes } => {
            let pw = password(&conn)?;
            let ages: Vec<Duration> = minutes
                .iter()
                .map(|m| Duration::from_secs(m.saturating_mul(60)))
                .collect();
            let probes = l4::session::token_life(
                &target(&conn),
                conn.pin_for(Port::Web),
                conn.pin_for(Port::Control),
                &pw,
                &ages,
                Duration::from_secs(10),
                |p| println!("age {} s: {:?}", p.age.as_secs(), p.outcome),
            )
            .await
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("{} tokens probed", probes.len());
        }
        Cmd::SessionCap { conn, max } => {
            eprintln!(
                "kvm-probe: session-cap can end other sessions if the KVM evicts its oldest; run it only with the owner's consent"
            );
            let pw = password(&conn)?;
            let r = l4::session::session_cap(
                &target(&conn),
                conn.pin_for(Port::Web),
                conn.pin_for(Port::Control),
                &pw,
                max,
                Duration::from_secs(10),
                |i, line| println!("login {i}: {line}"),
            )
            .await
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("logins={} stopped={:?}", r.logins, r.stopped);
        }
        Cmd::LogoutWatch { conn, max_secs } => {
            let pw = password(&conn)?;
            let r = l4::session::logout_watch(
                &target(&conn),
                conn.pin_for(Port::Web),
                conn.pin_for(Port::Video),
                conn.pin_for(Port::Control),
                &pw,
                l4::session::WatchPlan {
                    max: Duration::from_secs(max_secs),
                    poll: Duration::from_secs(2),
                },
                || println!("READY: log out of the KVM web UI now"),
            )
            .await
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("{r:?}");
        }
```

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --test sim -- l4` — Expected: PASS — 7 passed. `cargo test --workspace --all-features --lib -- cli` — Expected: PASS (the existing CLI tests; `password_is_never_an_argument` and `logout_is_never_an_argument` still hold).

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-probe/Cargo.toml crates/kvm-probe/src/lib.rs crates/kvm-probe/src/l4 \
  crates/kvm-probe/src/cli.rs crates/kvm-probe/src/main.rs \
  crates/kvm-sim/tests/sim/main.rs crates/kvm-sim/tests/sim/l4.rs Cargo.lock
git commit -m "kvm-probe: L4 checks — concurrent-flv, refusal-forms, ws-close, token-life, session-cap, logout-watch (§11.6, DC18)" \
  -m "None logs out (logout-watch watches while the owner does); only logout-watch sends HID, one all-zero release. Each is proven against kvm-sim in its own test binary first." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 1.4: kvm-probe L4 — the HID test page, the HID websocket, typing, snapshots

The HID checks need to see what the Mac does. The owner opens a committed test page on the Mac (a one-line `data:` URL that `hid-page-url` prints; the probe never types it, nor anything else, into the Mac's browser) that prints held keys, keydown and repeat counts, buttons, wheel and the length and FNV-1a hash of what was typed; `snapshot` decodes one fresh IDR from the KVM in the bwrap sandbox to a PNG in `captures/`, which the agent reads. Every HID subcommand runs inside `guarded`, which always ends with `ensure_released` — on success, on error, on Ctrl-C, on SIGTERM (an agent's tool timeout) and on SIGHUP (a closed terminal); `hid-release` releases from a fresh process after a SIGKILL or any failure (D6b). One `Interrupts` set per command carries the signals across `guarded` sections, so one arriving between them is never lost (D34). `hid-type` types only the generated pattern, after an Esc that resets the page's counters so every run is read on its own (D7a); nothing types a file, so no secret can be typed.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/assets/hid-test.html`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/l4/{page,hid,snapshot}.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/l4/mod.rs` (`pub mod page; pub mod hid; pub mod snapshot;`), `src/kvm.rs` (`over`, extracted), `src/capture.rs` (`open_capture_file` → `pub(crate)`), `src/captures.rs` (`#[derive(Debug, Clone)]` on `CaptureDir`), `src/sandbox.rs` (`sandbox_prefix`, `build_snapshot_argv`, `run_snapshot`), `src/cli.rs`, `src/main.rs`, `Cargo.toml` (`socket2 = "0.6"`; tokio `signal`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/l4.rs`

**Interfaces:**
- Consumes: Task 1.1's `kvm_proto::keymap::{us_stroke, Stroke, MOD_LSHIFT}`; Task 1.3's `l4::{ws::upgrade_on, ws::Upgrade, RefusalForm, escaped, deadline, since, flv::{is_coded, is_idr, MAX_BYTES}}`; `kvm_probe::capture::open_flv`, `captures::CaptureDir`, `sandbox::resolve_ffmpeg`.
- Produces (`kvm_probe::l4`):
  - `page::PAGE: &str`, `page::url() -> String`, `page::fnv1a32(s: &str) -> u32`, `page::pattern(n: usize) -> String`.
  - `hid::SNDBUF: usize = 16 * 1024`, `hid::WRITE_TIMEOUT: Duration = 1 s`, `hid::RELEASE_WINDOW: Duration = 30 s`, `hid::KBD_ZERO: HidFrame`; `pub enum End { CloseFrame, Fin, Reset }`; `pub struct HidWs` — `pub async fn open(t: &KvmTarget, pin: Option<&str>, token: &str, timeout: Duration) -> Result<HidWs, KvmError>` (sends the §3.3 session start: `SetMode`, `KBD_ZERO`), `pub async fn send(&mut self, f: HidFrame) -> Result<Duration, KvmError>` (the write's duration), `pub fn last_pos(&self) -> Option<(u16, u16)>`, `pub async fn end(self, how: End)`; `pub fn press(s: Stroke) -> HidFrame`; `pub struct TypeReport { pub chars: usize, pub reports: u64, pub elapsed: Duration, pub burst_capacity: u64, pub max_write: Duration, pub expected_len: usize, pub expected_hash: u32 }` with `Display` (`reports` counts the text's reports only, not the leading Esc pair; the `write_rate` and `kernel_buffered` figures are the probe's own, diagnostics only — the KVM's rate is the page's `rate` line, D28); `pub async fn type_text(ws: &mut HidWs, text: &str, pace: Duration) -> Result<TypeReport, KvmError>` (sends an Esc press and `KBD_ZERO`, waits 200 ms for the page to reset, then types); `pub async fn ensure_released(t, pin, token: &str, pointer: Option<(u16, u16)>) -> Result<(), KvmError>`, `pub async fn ensure_released_within(…, window: Duration)`; `pub struct Interrupts` — `Interrupts::new() -> Result<Interrupts, KvmError>` (SIGINT, SIGTERM and SIGHUP streams, created once per HID subcommand, D34), `async fn recv(&mut self) -> &'static str`, `fn check(&mut self) -> Result<(), KvmError>` (`Err` once any arrived), `async fn sleep(&mut self, d: Duration) -> Result<(), KvmError>` (a sleep that an interrupt ends); `pub async fn guarded<T>(t, pin, token, pointer: Option<(u16, u16)>, irq: &mut Interrupts, body: impl Future<Output = Result<T, KvmError>>) -> Result<T, KvmError>` (the body races `irq`; the release runs after whichever ends first).
  - `snapshot::write_first_idr(t, pin, token, out: &mut std::fs::File, timeout) -> Result<u64, KvmError>`; `snapshot::snapshot(t, pin, token, dir: &CaptureDir, name: &str, ffmpeg: &Path) -> Result<PathBuf, String>`.
  - `sandbox::build_snapshot_argv(ffmpeg, cap_host_dir, capture_name, out_name) -> Vec<String>`; `sandbox::run_snapshot(ffmpeg, dir: &CaptureDir, capture_name: &str) -> std::io::Result<PathBuf>` (writes `<capture_name>.png`).
  - CLI: `hid-page-url` (prints the page's URL; sends nothing), `hid-type [--chars 200] [--paces 0,5,10,15] [--runs 3] [--snapshot PREFIX] [--settle-ms 2000]` (one login; each pace × run typed separately, snapshot `<PREFIX><pace>_<run>`), `hid-release [--x X --y Y]` (a fresh session start, and a zero-button pointer report at (X, Y) if both are given), `snapshot --name NAME`.

- [ ] **Step 1: The test page.** Create `crates/kvm-probe/assets/hid-test.html` holding exactly this one line (and a final newline):

```html
<title>kvm-rdp HID test</title><body style="margin:0;background:black;color:white;font:40px monospace"><pre id=o></pre><script>var d={},n=0,r=0,t="",b=0,x=0,y=0,w=0,f=0,l=0;function h(s){var a=2166136261;for(var i=0;i<s.length;i++){a^=s.charCodeAt(i);a=Math.imul(a,16777619)>>>0}return a.toString(16)}function s(){o.textContent="held "+(Object.keys(d).join(" ")||"-")+"\nkeydown "+n+" repeat "+r+"\nbuttons "+b+" at "+x+","+y+"\nwheel "+w+"\ntext "+t.length+" "+h(t)+"\ntail "+t.slice(-24)+"\nrate "+n+" "+Math.round(l-f)+"\nclock "+Math.floor(performance.now())}onkeydown=function(e){e.preventDefault();if(e.code=="Escape"){t="";n=0;r=0;s();return}if(!n)f=performance.now();l=performance.now();n++;if(e.repeat)r++;d[e.code]=1;t+=e.key.length==1?e.key:e.key=="Enter"?"\n":e.key=="Tab"?"\t":"";s()};onkeyup=function(e){e.preventDefault();delete d[e.code];s()};onmousedown=onmouseup=onmousemove=function(e){b=e.buttons;x=e.clientX;y=e.clientY;s()};onwheel=function(e){w+=e.deltaY<0?1:-1;s()};setInterval(s,100);s()</script>
```

It shows `held <codes>` (what the browser believes is down — a key the Mac thinks is still held stays listed), `keydown`/`repeat` counts (macOS auto-repeat shows as a rising `repeat`), `buttons … at x,y`, `wheel`, `text <length> <fnv1a32 hex>`, the last 24 characters, and a clock. Esc clears the text and the `keydown`/`repeat` counts and is itself not counted, so each `hid-type` run (which begins with Esc) is read on its own (D7a). `rate <n> <ms>` is the keydown count and the milliseconds from the first keydown since the last Esc to the latest one: where the reports land, so it measures the KVM's own HID report rate (`2·(n−1)·1000/ms` reports/s at pace 0, D28), not how fast the probe could write. Nothing on it shows anything of the owner's.

- [ ] **Step 2: Write the failing tests.** `src/l4/page.rs`'s tests (create the file with just these):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;
    use kvm_proto::keymap::us_stroke;

    /// The owner opens the URL by hand: one line, no `#` (a fragment) or
    /// `%` (an escape), plain US-layout ASCII so it can be typed or pasted.
    #[test]
    fn the_page_url_is_one_typeable_line() {
        let u = url();
        assert!(u.starts_with("data:text/html,<title>"));
        assert!(u.len() <= 1500, "{} bytes", u.len());
        for c in u.chars() {
            assert!(c.is_ascii() && !c.is_ascii_control(), "{c:?}");
            assert!(!matches!(c, '#' | '%'), "{c:?}");
            assert!(us_stroke(c).is_some(), "{c:?}");
        }
    }

    /// The page's hash is FNV-1a 32 over UTF-16 code units, as `h()` in
    /// the page computes it.
    #[test]
    fn fnv1a32_matches_the_reference_vectors() {
        assert_eq!(fnv1a32(""), 0x811c_9dc5);
        assert_eq!(fnv1a32("a"), 0xe40c_292c);
        assert_eq!(fnv1a32("foobar"), 0xbf9c_f968);
        assert!(PAGE.contains("2166136261") && PAGE.contains("16777619"));
    }

    #[test]
    fn the_pattern_is_deterministic_and_typeable() {
        let p = pattern(200);
        assert_eq!(p.chars().count(), 200);
        assert_eq!(p, pattern(200));
        assert!(p.starts_with("abcdefghijklmnopqrstuvwxyzABC"));
        assert!(p.chars().all(|c| us_stroke(c).is_some()));
        assert!(p.chars().any(|c| us_stroke(c).unwrap().shift), "Shift is exercised");
    }
}
```

`src/sandbox.rs`'s tests, add:

```rust
    /// The snapshot runs in the same sandbox as `sample-range`, decoding
    /// one frame to a PNG beside the capture.
    #[test]
    fn the_snapshot_argv_is_the_sandbox_with_a_png_output() {
        let ffmpeg = Path::new("/nix/store/x-ffmpeg/bin/ffmpeg");
        let dir = Path::new("/repo/captures");
        let raw = build_ffmpeg_sandbox_argv(ffmpeg, dir, "a.flv", "a.flv.y");
        let png = build_snapshot_argv(ffmpeg, dir, "a.flv", "a.flv.png");
        let prefix = raw.iter().position(|a| a == "-i").unwrap();
        assert_eq!(png.get(..prefix), raw.get(..prefix));
        let tail: Vec<&str> = png.iter().skip(prefix).map(String::as_str).collect();
        assert_eq!(
            tail,
            ["-i", "/cap/a.flv", "-map", "0:v:0", "-frames:v", "1", "-update", "1", "/cap/a.flv.png"]
        );
    }
```

and in `crates/kvm-sim/tests/sim/l4.rs`, add:

```rust
use kvm_probe::l4::hid::{self, End, HidWs};
use kvm_proto::hid::HidFrame;

fn hid_on_ws(sim: &KvmSim, nth: usize) -> Vec<Vec<u8>> {
    let log = sim.events();
    let conn = log
        .iter()
        .filter_map(|e| if let SimEvent::WsOpen { conn } = e { Some(*conn) } else { None })
        .nth(nth)
        .unwrap_or_else(|| panic!("no websocket {nth}: {log:?}"));
    log.iter()
        .filter_map(|e| match e {
            SimEvent::Hid { conn: c, bytes } if *c == conn => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

async fn hid_count(sim: &KvmSim, nth: usize, n: usize) -> Vec<Vec<u8>> {
    sim.wait_for(T, |_| {
        sim.events().iter().filter(|e| matches!(e, SimEvent::WsOpen { .. })).count() > nth
            && hid_on_ws(sim, nth).len() >= n
    })
    .await
    .unwrap();
    hid_on_ws(sim, nth)
}

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    HidFrame::Keyboard { modifiers, keys: [k, 0, 0, 0, 0] }.to_vec()
}

/// §3.3's session start, the Esc pair that resets the test page, then one
/// press and one all-zero release per character, Shift in the press for a
/// shifted one (§8's report sequence). `reports` counts the text only.
#[tokio::test]
async fn a_hid_websocket_starts_the_session_and_types_press_release_pairs() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let mut w = HidWs::open(&target(&sim), Some(sim.spki_sha256()), &token, T).await.unwrap();
    let report = hid::type_text(&mut w, "aB1", Duration::ZERO).await.unwrap();
    assert_eq!((report.chars, report.reports, report.expected_len), (3, 6, 3));
    assert_eq!(report.expected_hash, kvm_probe::l4::page::fnv1a32("aB1"));
    let got = hid_count(&sim, 0, 10).await;
    assert_eq!(
        got,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            kbd(0, 0x29),
            kbd(0, 0),
            kbd(0, 0x04),
            kbd(0, 0),
            kbd(0x02, 0x05),
            kbd(0, 0),
            kbd(0, 0x1E),
            kbd(0, 0),
        ]
    );
    w.end(End::CloseFrame).await;
    no_logout(&sim);
}

/// A key is never left held: a websocket reset with a key down is followed
/// by a fresh websocket whose session start releases it, with the pointer
/// at the given position (never (0, 0)).
#[tokio::test]
async fn ensure_released_opens_a_fresh_websocket_that_releases() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut w = HidWs::open(&t, pin, &token, T).await.unwrap();
    w.send(HidFrame::Keyboard { modifiers: 0, keys: [0x04, 0, 0, 0, 0] }).await.unwrap();
    hid_count(&sim, 0, 3).await;
    w.end(End::Reset).await;
    hid::ensure_released(&t, pin, &token, Some((100, 200))).await.unwrap();
    assert_eq!(
        hid_count(&sim, 1, 3).await,
        [
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            kbd(0, 0),
            HidFrame::abs_mouse(0, 100, 200).to_vec(),
        ]
    );
    no_logout(&sim);
}

/// When no websocket can be opened, `ensure_released` gives up after its
/// window and says a key may be held — loud, never silent.
#[tokio::test]
async fn ensure_released_says_a_key_may_be_held_when_it_cannot_reach_the_kvm() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.ws_status = Some(503));
    let e = hid::ensure_released_within(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        None,
        Duration::from_millis(600),
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("KEY MAY BE HELD"), "{e:?}");
}

/// `guarded` releases after its body, whether the body succeeded or not.
#[tokio::test]
async fn guarded_releases_after_a_failing_body() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let (t, pin) = (target(&sim), Some(sim.spki_sha256()));
    let mut irq = hid::Interrupts::new().unwrap();
    let r: Result<(), _> = hid::guarded(&t, pin, &token, None, &mut irq, async {
        let mut w = HidWs::open(&t, pin, &token, T).await?;
        w.send(HidFrame::Keyboard { modifiers: 0x08, keys: [0; 5] }).await?;
        w.end(End::Fin).await;
        Err(kvm_probe::kvm::KvmError::Io("the body failed".to_owned()))
    })
    .await;
    assert!(r.is_err());
    assert_eq!(hid_count(&sim, 1, 2).await, [HidFrame::SetMode { hid_type: 0 }.to_vec(), kbd(0, 0)]);
}

/// `snapshot`'s capture: the stream up to and including its first IDR,
/// which demuxes to the sequence header and that IDR.
#[tokio::test]
async fn write_first_idr_captures_through_the_first_idr() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.flv");
    let mut f = std::fs::File::create(&path).unwrap();
    let n = kvm_probe::l4::snapshot::write_first_idr(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        &mut f,
        T,
    )
    .await
    .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(u64::try_from(bytes.len()).unwrap(), n);
    let mut d = kvm_proto::flv::FlvDemuxer::new(kvm_proto::flv::FlvLimits::default());
    d.push(&bytes);
    let mut idr = false;
    while let Some(tag) = d.next_tag().unwrap() {
        idr |= flv::is_coded(&tag) && flv::is_idr(&tag);
    }
    assert!(idr, "no IDR in the snapshot capture");
}
```

with `fn no_logout(sim: &KvmSim) { assert_eq!(sim.stats().logouts, 0); }` beside `no_hid`.

- [ ] **Step 3: Run them to see them fail.** `cargo test --workspace --all-features --lib -- l4::page` and `cargo test --workspace --all-features --test sim -- l4` — Expected: FAIL to compile (`l4::page`, `l4::hid`, `build_snapshot_argv` not found).

- [ ] **Step 4: Implement.** `Cargo.toml` (kvm-probe): add `socket2 = "0.6"` under `[dependencies]` and `"signal"` to tokio's features. `src/captures.rs`: `#[derive(Debug, Clone)]` on `CaptureDir`. `src/capture.rs`: `fn open_capture_file` → `pub(crate) fn open_capture_file`. `src/kvm.rs`: split `connect_and_handshake` so the TLS half is reusable:

```rust
async fn connect_and_handshake(
    target: &KvmTarget,
    port: u16,
    pin_sha256_hex: Option<&str>,
) -> Result<BoxedIo, KvmError> {
    let tcp = TcpStream::connect((target.host.as_str(), port))
        .await
        .map_err(|e| KvmError::Connect(e.to_string()))?;
    tcp.set_nodelay(true)
        .map_err(|e| KvmError::Connect(e.to_string()))?;
    over(target, tcp, pin_sha256_hex).await
}

/// Pinned TLS (`Https`) or nothing (`Http`) over a connected socket — the
/// one TLS path, shared by `connect_to` and the HID checks' resettable
/// sockets (`l4::hid`).
pub(crate) async fn over(
    target: &KvmTarget,
    tcp: TcpStream,
    pin_sha256_hex: Option<&str>,
) -> Result<BoxedIo, KvmError> {
    match target.scheme {
        Scheme::Http => Ok(Box::new(tcp)),
        Scheme::Https => {
            if pin_sha256_hex.is_none() {
                return Err(KvmError::Tls("pin required for https".into()));
            }
            let connector = TlsConnector::from(Arc::new(client_config(pin_sha256_hex)));
            let name = ServerName::try_from(target.host.clone())
                .map_err(|_| KvmError::Tls("bad server name".into()))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .map_err(|e| KvmError::Tls(format!("{e}")))?;
            Ok(Box::new(tls))
        }
    }
}
```

`src/sandbox.rs`: factor the prefix out of `build_ffmpeg_sandbox_argv` (its existing test must keep passing unchanged) and add the snapshot pair:

```rust
/// `nice -n 19 bwrap … ffmpeg <common options>`, up to its input (§12).
fn sandbox_prefix(ffmpeg: &Path, cap_host_dir: &Path) -> Vec<String> {
    [
        "nice", "-n", "19", "bwrap", "--new-session", "--unshare-all", "--die-with-parent",
        "--clearenv", "--dev", "/dev", "--proc", "/proc", "--ro-bind", "/nix", "/nix", "--bind",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .chain([
        cap_host_dir.to_string_lossy().into_owned(),
        "/cap".to_owned(),
        "--chdir".to_owned(),
        "/cap".to_owned(),
        "--".to_owned(),
        ffmpeg.to_string_lossy().into_owned(),
    ])
    .chain(
        ["-hide_banner", "-nostdin", "-y", "-threads", "4", "-loglevel", "verbose"]
            .iter()
            .map(|s| (*s).to_owned()),
    )
    .collect()
}
```

and `build_ffmpeg_sandbox_argv`'s body becomes `let mut v = sandbox_prefix(ffmpeg, cap_host_dir); v.extend(["-i".to_owned(), format!("/cap/{capture_name}"), "-map".to_owned(), "0:v:0".to_owned(), "-frames:v".to_owned(), "1".to_owned(), "-f".to_owned(), "rawvideo".to_owned(), format!("/cap/{out_name}")]); v` (its doc comment stays). Then:

```rust
/// The snapshot (Plan D L4): the same sandbox decoding one frame of an FLV
/// capture to a PNG — a picture of the HID test page for the agent to read.
pub fn build_snapshot_argv(
    ffmpeg: &Path,
    cap_host_dir: &Path,
    capture_name: &str,
    out_name: &str,
) -> Vec<String> {
    let mut v = sandbox_prefix(ffmpeg, cap_host_dir);
    v.extend([
        "-i".to_owned(),
        format!("/cap/{capture_name}"),
        "-map".to_owned(),
        "0:v:0".to_owned(),
        "-frames:v".to_owned(),
        "1".to_owned(),
        "-update".to_owned(),
        "1".to_owned(),
        format!("/cap/{out_name}"),
    ]);
    v
}

/// Decode `capture_name`'s first frame to `<capture_name>.png` in the
/// sandbox. Live only, like `run_sample_range`; names are validated by
/// `CaptureDir::resolve` before anything runs.
pub fn run_snapshot(ffmpeg: &Path, dir: &CaptureDir, capture_name: &str) -> std::io::Result<PathBuf> {
    let cap_in_host = dir.resolve(capture_name)?;
    let out_name = format!("{capture_name}.png");
    let out_host = dir.resolve(&out_name)?;
    let cap_host_dir = cap_in_host
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("no capture dir"))?;
    remove_stale_output(&out_host)?;
    let output = run_argv(&build_snapshot_argv(ffmpeg, &cap_host_dir, capture_name, &out_name))?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "sandboxed ffmpeg failed: {}",
            sanitize_for_terminal(&output.stderr)
        )));
    }
    Ok(out_host)
}
```

Add `pub mod hid; pub mod page; pub mod snapshot;` to `src/l4/mod.rs`. Above the tests in `src/l4/page.rs`:

```rust
//! The HID test page (Plan D L4): what the Mac shows while the probe sends
//! HID, so that a snapshot of the KVM's own video shows what the Mac did.

/// `assets/hid-test.html`, one line.
pub const PAGE: &str = include_str!("../../assets/hid-test.html");

/// The page as the `data:` URL `hid-page-url` prints for the owner.
#[must_use]
pub fn url() -> String {
    format!("data:text/html,{}", PAGE.trim_end())
}

/// FNV-1a 32 over UTF-16 code units: the page's `h()`.
#[must_use]
pub fn fnv1a32(s: &str) -> u32 {
    s.encode_utf16()
        .fold(0x811c_9dc5u32, |a, u| (a ^ u32::from(u)).wrapping_mul(0x0100_0193))
}

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-=[];',./";

/// What `hid-type` types: `n` characters cycling through `ALPHABET` —
/// letters both cases (Shift exercised), digits and punctuation.
#[must_use]
pub fn pattern(n: usize) -> String {
    ALPHABET.chars().cycle().take(n).collect()
}
```

Create `src/l4/hid.rs`:

```rust
//! The HID checks' websocket (Plan D L4). It opens the way the bridge does
//! — the token cookie, the §3.3 session start, the bridge's 16 KiB
//! `SO_SNDBUF` cap and 1 s write bound — and can end three ways (a close
//! frame, a FIN, a reset). A key is never left held: `guarded` runs every
//! HID subcommand's body and then `ensure_released`, whatever the body did.
use super::{escaped, ws};
use crate::kvm::{self, BoxedIo, KvmError};
use crate::request::{KvmTarget, Scheme};
use futures_util::{SinkExt as _, StreamExt as _};
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{MOD_LSHIFT, Stroke, us_stroke};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio_tungstenite::tungstenite::Message;

/// The bridge's websocket send buffer (Plan C's final fix wave), so the
/// probe sees the back-pressure the bridge would.
pub const SNDBUF: usize = 16 * 1024;
/// `input.hid_write_timeout`'s default.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// How long `ensure_released` keeps trying before it says a key may be held.
pub const RELEASE_WINDOW: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub const KBD_ZERO: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0; 5],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// A close frame, then up to 2 s for the KVM's.
    CloseFrame,
    /// Drop the connection: a FIN (an RST if the KVM's data is unread).
    Fin,
    /// `SO_LINGER` 0, then drop: an RST — what the bridge does to a
    /// websocket whose writes did not complete (§3.2).
    Reset,
}

pub struct HidWs {
    ws: ws::Ws,
    /// A second descriptor of the same socket: its options (linger) are
    /// the connection's.
    sock: socket2::Socket,
    last_pos: Option<(u16, u16)>,
}

/// The bridge's order (Plan C's fix wave, endpoint.rs): the send buffer is
/// capped BEFORE connect, so the kernel never autotunes it (§7.3 rev 6.2).
async fn connect(t: &KvmTarget, pin: Option<&str>) -> Result<(BoxedIo, socket2::Socket), KvmError> {
    if matches!(t.scheme, Scheme::Https) && pin.is_none() {
        return Err(KvmError::Tls("pin required for https".into()));
    }
    let made = async {
        let c = |e: std::io::Error| KvmError::Connect(e.to_string());
        let addr = tokio::net::lookup_host((t.host.as_str(), t.control_port))
            .await
            .map_err(c)?
            .next()
            .ok_or_else(|| KvmError::Connect("the host resolved to no address".to_owned()))?;
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(c)?;
        sock.set_send_buffer_size(SNDBUF).map_err(c)?;
        sock.set_nonblocking(true).map_err(c)?;
        let tcp: TcpStream = TcpSocket::from_std_stream(sock.into()).connect(addr).await.map_err(c)?;
        tcp.set_nodelay(true).map_err(c)?;
        let keep = socket2::SockRef::from(&tcp).try_clone().map_err(c)?;
        Ok::<_, KvmError>((kvm::over(t, tcp, pin).await?, keep))
    };
    tokio::time::timeout(CONNECT_TIMEOUT, made)
        .await
        .map_err(|_| KvmError::Connect(format!("connect timed out after {CONNECT_TIMEOUT:?}")))?
}

impl HidWs {
    /// Upgrade with `token` and send the §3.3 session start: absolute mode
    /// and an all-zero keyboard report (no pointer report: none was sent).
    pub async fn open(t: &KvmTarget, pin: Option<&str>, token: &str, timeout: Duration) -> Result<HidWs, KvmError> {
        let (io, sock) = connect(t, pin).await?;
        let ws = match ws::upgrade_on(io, t, Some(token), timeout).await? {
            ws::Upgrade::Accepted(w) => *w,
            ws::Upgrade::Refused(f) => return Err(KvmError::Http(format!("websocket refused: {f}"))),
        };
        let mut h = HidWs { ws, sock, last_pos: None };
        h.send(HidFrame::SetMode { hid_type: 0 }).await?;
        h.send(KBD_ZERO).await?;
        Ok(h)
    }

    /// One frame, bounded by `WRITE_TIMEOUT`; how long the write took.
    pub async fn send(&mut self, f: HidFrame) -> Result<Duration, KvmError> {
        let t0 = Instant::now();
        match tokio::time::timeout(WRITE_TIMEOUT, self.ws.send(Message::Binary(f.to_vec()))).await {
            Ok(Ok(())) => {
                if let HidFrame::AbsMouse { x, y, .. } = f {
                    self.last_pos = Some((x, y));
                }
                Ok(t0.elapsed())
            }
            Ok(Err(e)) => Err(KvmError::Http(escaped(e.to_string().as_bytes(), 120))),
            Err(_) => Err(KvmError::Http(format!("a HID write took longer than {WRITE_TIMEOUT:?}"))),
        }
    }

    #[must_use]
    pub fn last_pos(&self) -> Option<(u16, u16)> {
        self.last_pos
    }

    pub async fn end(mut self, how: End) {
        match how {
            End::CloseFrame => {
                let _ = self.ws.close(None).await;
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    while let Some(Ok(m)) = self.ws.next().await {
                        if matches!(m, Message::Close(_)) {
                            break;
                        }
                    }
                })
                .await;
            }
            End::Fin => {}
            End::Reset => {
                let _ = self.sock.set_linger(Some(Duration::ZERO));
            }
        }
        drop(self.ws);
        drop(self.sock);
    }
}

/// §8's press report: the usage in slot 1, Shift in the modifier byte.
#[must_use]
pub fn press(s: Stroke) -> HidFrame {
    HidFrame::Keyboard {
        modifiers: if s.shift { MOD_LSHIFT } else { 0 },
        keys: [s.usage, 0, 0, 0, 0],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeReport {
    pub chars: usize,
    pub reports: u64,
    pub elapsed: Duration,
    /// At pace 0: the reports written before the first write that took
    /// 2 ms or more — what the kernel buffered before anything waited.
    /// A diagnostic only: 400 reports fit the send buffer and the KVM's
    /// receive window, so this is not the KVM's rate (the page's `rate`
    /// line is, D28).
    pub burst_capacity: u64,
    pub max_write: Duration,
    /// What the test page should show: `text <expected_len> <hash>`.
    pub expected_len: usize,
    pub expected_hash: u32,
}

impl std::fmt::Display for TypeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ms = super::ms(self.elapsed).max(1);
        write!(
            f,
            "chars={} reports={} elapsed_ms={} write_rate={} kernel_buffered={} max_write_ms={} expect page: text {} {:x}",
            self.chars,
            self.reports,
            super::ms(self.elapsed),
            self.reports.saturating_mul(1000).checked_div(ms).unwrap_or(0),
            self.burst_capacity,
            super::ms(self.max_write),
            self.expected_len,
            self.expected_hash
        )
    }
}

/// Type `text` (US layout; characters without a stroke are left out) as
/// press/release pairs, `pace` after every report (§8). First an Esc press
/// and release, which the test page reads as "start over" (D7a), and 200 ms
/// for it to redraw; those two reports are not counted or timed.
pub async fn type_text(w: &mut HidWs, text: &str, pace: Duration) -> Result<TypeReport, KvmError> {
    let strokes: Vec<Stroke> = text.chars().filter_map(us_stroke).collect();
    w.send(press(Stroke { usage: kvm_proto::keymap::USAGE_ESC, shift: false })).await?;
    w.send(KBD_ZERO).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    let (mut reports, mut burst_capacity, mut max_write, mut bursting) = (0u64, 0u64, Duration::ZERO, true);
    for s in &strokes {
        for f in [press(*s), KBD_ZERO] {
            let took = w.send(f).await?;
            reports = reports.saturating_add(1);
            if bursting && took < Duration::from_millis(2) {
                burst_capacity = burst_capacity.saturating_add(1);
            } else {
                bursting = false;
            }
            max_write = max_write.max(took);
            if !pace.is_zero() {
                tokio::time::sleep(pace).await;
            }
        }
    }
    Ok(TypeReport {
        chars: strokes.len(),
        reports,
        elapsed: t0.elapsed(),
        burst_capacity,
        max_write,
        expected_len: text.chars().count(),
        expected_hash: super::page::fnv1a32(text),
    })
}

async fn release_once(t: &KvmTarget, pin: Option<&str>, token: &str, pointer: Option<(u16, u16)>) -> Result<(), KvmError> {
    let mut w = HidWs::open(t, pin, token, Duration::from_secs(5)).await?;
    if let Some((x, y)) = pointer {
        w.send(HidFrame::AbsMouse { buttons: 0, x, y }).await?;
    }
    w.end(End::CloseFrame).await;
    Ok(())
}

/// A fresh websocket whose session start releases every key (§3.3), and a
/// zero-button pointer report at `pointer` if given (never (0, 0)).
pub async fn ensure_released(t: &KvmTarget, pin: Option<&str>, token: &str, pointer: Option<(u16, u16)>) -> Result<(), KvmError> {
    ensure_released_within(t, pin, token, pointer, RELEASE_WINDOW).await
}

pub async fn ensure_released_within(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    window: Duration,
) -> Result<(), KvmError> {
    let started = Instant::now();
    let mut wait = Duration::from_millis(250);
    loop {
        match release_once(t, pin, token, pointer).await {
            Ok(()) => return Ok(()),
            Err(e) if started.elapsed() < window => {
                eprintln!("kvm-probe: release attempt failed, retrying: {}", kvm::bounded_debug(&e));
                tokio::time::sleep(wait.min(window.saturating_sub(started.elapsed()))).await;
                wait = wait.saturating_mul(2).min(Duration::from_secs(4));
            }
            Err(e) => {
                return Err(KvmError::Io(format!(
                    "KEY MAY BE HELD on the Mac: no websocket could release it within {window:?} ({}). Press and release the key on the Mac, or unplug the KVM's USB cable.",
                    kvm::bounded_debug(&e)
                )));
            }
        }
    }
}

fn interrupted(what: &str) -> KvmError {
    KvmError::Io(format!("interrupted ({what})"))
}

/// Ctrl-C (SIGINT), SIGTERM (an agent's tool timeout) and SIGHUP (a closed
/// terminal), created once per HID subcommand and passed to each `guarded`
/// section (D34). tokio keeps a signal's handler installed for the life of
/// the process once one is created, so per-section streams would swallow a
/// signal arriving between sections (a settle, a snapshot); one set, kept
/// for the whole command, buffers it for the next `check`, `sleep` or
/// `guarded`. A SIGKILL cannot be caught: `hid-release` is the release
/// after one (D6b).
pub struct Interrupts {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    seen: Option<&'static str>,
}

impl Interrupts {
    pub fn new() -> Result<Interrupts, KvmError> {
        use tokio::signal::unix::{SignalKind, signal};
        let s = |k| signal(k).map_err(|e| KvmError::Io(e.to_string()));
        Ok(Interrupts {
            int: s(SignalKind::interrupt())?,
            term: s(SignalKind::terminate())?,
            hup: s(SignalKind::hangup())?,
            seen: None,
        })
    }

    /// The next interrupt; its name. Cancel-safe (`Signal::recv` is).
    pub async fn recv(&mut self) -> &'static str {
        let name = tokio::select! {
            _ = self.int.recv() => "Ctrl-C",
            _ = self.term.recv() => "SIGTERM",
            _ = self.hup.recv() => "SIGHUP",
        };
        self.seen = Some(name);
        name
    }

    /// `Err` once any interrupt has arrived — including one buffered while
    /// nothing was waiting for it.
    pub fn check(&mut self) -> Result<(), KvmError> {
        if self.seen.is_none() {
            let _ = futures_util::FutureExt::now_or_never(self.recv());
        }
        self.seen.map_or(Ok(()), |n| Err(interrupted(n)))
    }

    /// Sleep `d`, unless an interrupt comes first.
    pub async fn sleep(&mut self, d: Duration) -> Result<(), KvmError> {
        self.check()?;
        tokio::select! {
            () = tokio::time::sleep(d) => Ok(()),
            n = self.recv() => Err(interrupted(n)),
        }
    }
}

/// Run a HID subcommand's `body`, then release — after success, failure
/// or an interrupt (`irq`). A failed release is the error, whatever the
/// body returned. An interrupt that came before the section skips its body
/// but never its release.
pub async fn guarded<T>(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    pointer: Option<(u16, u16)>,
    irq: &mut Interrupts,
    body: impl std::future::Future<Output = Result<T, KvmError>>,
) -> Result<T, KvmError> {
    let out = match irq.check() {
        Err(e) => Err(e),
        Ok(()) => tokio::select! {
            r = body => r,
            n = irq.recv() => Err(interrupted(n)),
        },
    };
    ensure_released(t, pin, token, pointer).await?;
    out
}
```

Create `src/l4/snapshot.rs`:

```rust
//! `snapshot`: the screen as of now, through the KVM's own video. A fresh
//! `av.flv` (its open forces an IDR, §6.5) is written to captures/ up to
//! its first IDR, then decoded in the bwrap sandbox to a PNG (§12). The
//! Mac must be showing the HID test page or the lock screen.
use super::{deadline, flv};
use crate::captures::CaptureDir;
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use http_body_util::BodyExt as _;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Write `av.flv` into `out` through the end of the chunk holding its first
/// IDR (bounded by `flv::MAX_BYTES` and `timeout`); the bytes written.
pub async fn write_first_idr(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    out: &mut std::fs::File,
    timeout: Duration,
) -> Result<u64, KvmError> {
    let until = deadline(timeout);
    let mut body = tokio::time::timeout_at(until, crate::capture::open_flv(t, pin, token))
        .await
        .map_err(|_| KvmError::Http(format!("av.flv open timed out after {timeout:?}")))??;
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut written: u64 = 0;
    loop {
        let frame = match tokio::time::timeout_at(until, body.frame()).await {
            Err(_) => return Err(KvmError::Http(format!("no IDR within {timeout:?}"))),
            Ok(None) => return Err(KvmError::Http("av.flv ended before an IDR".to_owned())),
            Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        out.write_all(chunk).map_err(|e| KvmError::Io(e.to_string()))?;
        written = written.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if written > flv::MAX_BYTES {
            return Err(KvmError::Http("av.flv passed the cap before an IDR".to_owned()));
        }
        demux.push(chunk);
        while let Some(tag) = demux.next_tag().map_err(|e| KvmError::Http(format!("{e:?}")))? {
            if flv::is_coded(&tag) && flv::is_idr(&tag) {
                out.sync_all().map_err(|e| KvmError::Io(e.to_string()))?;
                return Ok(written);
            }
        }
    }
}

/// `captures/<name>.flv`, then `captures/<name>.flv.png` (returned).
pub async fn snapshot(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    dir: &CaptureDir,
    name: &str,
    ffmpeg: &Path,
) -> Result<PathBuf, String> {
    let flv_name = format!("{name}.flv");
    let path = dir.resolve(&flv_name).map_err(|e| format!("{e:?}"))?;
    let mut file = crate::capture::open_capture_file(&path).map_err(|e| kvm::bounded_debug(&e))?;
    write_first_idr(t, pin, token, &mut file, Duration::from_secs(5))
        .await
        .map_err(|e| kvm::bounded_debug(&e))?;
    drop(file);
    let (ffmpeg, dir) = (ffmpeg.to_owned(), dir.clone());
    tokio::task::spawn_blocking(move || crate::sandbox::run_snapshot(&ffmpeg, &dir, &flv_name))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}
```

- [ ] **Step 5: The subcommands.** In `src/cli.rs`'s `Cmd`:

```rust
    /// L4 [OWNER]: print the HID test page's data: URL for the owner to
    /// open on the Mac. Sends nothing to the KVM.
    HidPageUrl,
    /// L4: on one login, type the generated pattern (never any other text)
    /// into the HID test page --runs times at each of --paces (ms); prints
    /// what the page should show after each run. Each run ends with a release.
    HidType {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 200)]
        chars: usize,
        #[arg(long, value_delimiter = ',', default_value = "0,5,10,15")]
        paces: Vec<u64>,
        #[arg(long, default_value_t = 3)]
        runs: u32,
        /// After each run and --settle-ms, a snapshot named
        /// `<PREFIX><pace>_<run>` (e.g. `type0_1`).
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, default_value_t = 2000)]
        settle_ms: u64,
    },
    /// L4: release every key and button from a fresh process — a new HID
    /// websocket's session start, and a zero-button pointer report at
    /// (--x, --y) if both are given. Run it after any HID command that
    /// failed, was interrupted or was killed (D6b).
    HidRelease {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        x: Option<u16>,
        #[arg(long)]
        y: Option<u16>,
    },
    /// L4: captures/<name>.flv up to its first IDR, decoded in the sandbox
    /// to captures/<name>.flv.png. Only while the Mac shows the HID test
    /// page or the lock screen.
    Snapshot {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        name: String,
    },
```

`validate`: `Cmd::HidType { conn, .. } => (conn, &[Port::Web, Port::Control, Port::Video])`, `Cmd::HidRelease { conn, .. } => (conn, &[Port::Web, Port::Control])`, `Cmd::Snapshot { conn, .. } => (conn, &[Port::Web, Port::Video])`, and `Cmd::HidPageUrl` joins the exempt arm (`Cmd::Fingerprint { .. } | Cmd::SampleRange { .. } | Cmd::Summarize { .. } | Cmd::HidPageUrl => return Ok(())`). In `src/main.rs`:

```rust
        Cmd::HidPageUrl => {
            // The owner opens this on the Mac themselves (Task 1.6 step 1).
            println!("{}", l4::page::url());
        }
        Cmd::HidType { conn, chars, paces, runs, snapshot, settle_ms } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let text = l4::page::pattern(chars);
            let ffmpeg = match &snapshot {
                Some(_) => Some(sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?),
                None => None,
            };
            // Once for the whole command, so an interrupt between runs is
            // never lost (D34).
            let mut irq = l4::hid::Interrupts::new().map_err(|e| kvm::bounded_debug(&e))?;
            session(&conn, &pw, async |tok: &str| {
                let pin = conn.pin_for(Port::Control);
                for &pace_ms in &paces {
                    for run in 1..=runs {
                        irq.check().map_err(|e| kvm::bounded_debug(&e))?; // stop between runs
                        let r = l4::hid::guarded(&t, pin, tok, None, &mut irq, async {
                            let mut w = l4::hid::HidWs::open(&t, pin, tok, Duration::from_secs(10)).await?;
                            let r = l4::hid::type_text(&mut w, &text, Duration::from_millis(pace_ms)).await?;
                            w.end(l4::hid::End::CloseFrame).await;
                            Ok(r)
                        })
                        .await
                        .map_err(|e| kvm::bounded_debug(&e))?;
                        println!("pace {pace_ms} ms, run {run}/{runs}: {r}");
                        if let (Some(prefix), Some(ffmpeg)) = (&snapshot, &ffmpeg) {
                            irq.sleep(Duration::from_millis(settle_ms))
                                .await
                                .map_err(|e| kvm::bounded_debug(&e))?;
                            let name = format!("{prefix}{pace_ms}_{run}");
                            let png = l4::snapshot::snapshot(&t, conn.pin_for(Port::Video), tok, &captures_dir()?, &name, ffmpeg).await?;
                            println!("snapshot: {}", png.display());
                        }
                    }
                }
                Ok::<_, String>(())
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))??;
        }
        Cmd::HidRelease { conn, x, y } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            session(&conn, &pw, async |tok: &str| {
                l4::hid::ensure_released(&t, conn.pin_for(Port::Control), tok, x.zip(y)).await
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))?
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("released");
        }
        Cmd::Snapshot { conn, name } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let ffmpeg = sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?;
            let png = session(&conn, &pw, async |tok: &str| {
                l4::snapshot::snapshot(&t, conn.pin_for(Port::Video), tok, &captures_dir()?, &name, &ffmpeg).await
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))??;
            println!("snapshot: {}", png.display());
        }
```

- [ ] **Step 6: Run the tests.** `cargo test --workspace --all-features --lib -- l4::page` — Expected: PASS — 3 passed. `cargo test --workspace --all-features --lib -- sandbox` — Expected: PASS (the new argv test and every existing sandbox test, `build_ffmpeg_sandbox_argv`'s unchanged). `cargo test --workspace --all-features --test sim -- l4` — Expected: PASS — 12 passed (Task 1.3's 7 and these 5).

- [ ] **Step 7: Gate** (clippy, test, budget). **Step 8: Commit.**

```bash
git add crates/kvm-probe/Cargo.toml crates/kvm-probe/assets/hid-test.html crates/kvm-probe/src/l4 \
  crates/kvm-probe/src/kvm.rs crates/kvm-probe/src/capture.rs crates/kvm-probe/src/captures.rs \
  crates/kvm-probe/src/sandbox.rs crates/kvm-probe/src/cli.rs crates/kvm-probe/src/main.rs \
  crates/kvm-sim/tests/sim/l4.rs Cargo.lock
git commit -m "kvm-probe: L4 HID tooling — the test page, a resettable HID websocket, hid-type, snapshot; every HID run ends released" \
  -m "The Mac is observed through the KVM's own video: one fresh IDR decoded in the bwrap sandbox to captures/. Only the generated pattern is ever typed; the owner opens the page." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 1.5: kvm-probe L4 — key-held-on-death, stale-after-reconnect, web diagnostics

Two more HID checks and a small web helper. `hid-hold` answers DC18's "what the Mac sees when the websocket dies with a key held" (→ §9.3): hold `HOLD_USAGE` ('1', which auto-repeats and has no macOS press-and-hold menu), kill the websocket one of three ways, snapshot the page while nothing has released it (`<N>_held`), release, and snapshot again (`<N>_released`). `hid-stale` answers the re-assert carry (PC9 fix 2 — the yes/no that sets `REASSERT_AFTER`): a **bounded** burst of `STALE_BURST` (128) reports that alternates press and all-zero release and ends on a release, so whatever the ES3 does with its receive buffer after the reset, at most one press is ever left down and the release that follows clears it; then a fresh websocket whose session start and Esc pair reset the page, so the page then counts only stale presses that landed **after** the fresh session start (D5). `web-get` fetches `/` for the firmware line (§12). Both HID subcommands run inside `guarded` (Task 1.4); `hid-stale` releases a second time 5 s after `guarded` returns, for a backlog that drains late.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/l4/{hold,web}.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/l4/mod.rs` (`pub mod hold; pub mod web;`), `src/l4/hid.rs` (`STALE_BURST`, `stale_frame`, `StaleReport`, `stale_after_reset`), `src/cli.rs`, `src/main.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/l4.rs`

**Interfaces:**
- Consumes: Task 1.4's `l4::hid::{HidWs, End, KBD_ZERO, Interrupts, press, guarded, ensure_released}`, `l4::snapshot::snapshot`; Task 1.1's `kvm_proto::keymap::{Stroke, USAGE_ESC}`; `kvm_probe::kvm::connect_to`.
- Produces (`kvm_probe::l4`):
  - `hold::HOLD_USAGE: u8 = 0x1E`; `hold::HoldReport { pub end: hid::End }`; `hold::hold_then_kill(t, pin, token, usage: u8, end: hid::End, observe: Duration) -> Result<HoldReport, KvmError>`.
  - `web::Page { pub status: u16, pub server: Option<String>, pub snippet: String }`; `web::get(t, pin, path: &str) -> Result<Page, KvmError>`.
  - `hid::STALE_BURST: u64 = 128`; `hid::stale_frame(i: u64) -> HidFrame` (the burst's i-th report: even i a press of `0x04 + (i / 2) % 20`, odd i `KBD_ZERO`); `hid::StaleReport { pub pushed: u64 }`; `hid::stale_after_reset(t, pin, token, settle: Duration) -> Result<StaleReport, KvmError>`.
  - `cli::EndArg { Close, Fin, Reset }` (`clap::ValueEnum`, `impl From<EndArg> for l4::hid::End`).
  - CLI: `hid-hold [--end close|fin|reset] [--observe-ms 1500] [--snapshot NAME]` (snapshots `NAME_held` and `NAME_released`), `hid-stale [--settle-ms 5000] [--snapshot NAME]`, `web-get [--path /]`.

- [ ] **Step 1: Write the failing tests.** Append to `crates/kvm-sim/tests/sim/l4.rs`:

```rust
/// A key held when the websocket is reset: kvm-sim records the session
/// start and the held press, and nothing after it on that socket. (On the
/// real ES3 the agent reads the page by snapshot; here, the mechanics.)
#[tokio::test]
async fn hid_hold_holds_one_key_and_ends_the_way_it_was_told() {
    let sim = sim_with(|_| {}).await;
    let token = login(&sim).await;
    let r = kvm_probe::l4::hold::hold_then_kill(
        &target(&sim),
        Some(sim.spki_sha256()),
        &token,
        kvm_probe::l4::hold::HOLD_USAGE,
        End::Reset,
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    assert_eq!(r.end, End::Reset);
    let got = hid_count(&sim, 0, 3).await;
    assert_eq!(got, [HidFrame::SetMode { hid_type: 0 }.to_vec(), kbd(0, 0), kbd(0, 0x1E)]);
    no_logout(&sim);
}

/// The re-assert carry (PC9 fix 2), bounded (D5): exactly STALE_BURST
/// reports, alternating press and release and ending on a release, then a
/// reset; the fresh websocket starts with the session start and the Esc
/// pair that resets the test page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_sends_a_bounded_alternating_burst_then_a_fresh_session_start() {
    let sim = sim_with(|c| c.control_recv_buffer = Some(4096)).await;
    let token = login(&sim).await;
    let r = hid::stale_after_reset(&target(&sim), Some(sim.spki_sha256()), &token, Duration::from_millis(300))
        .await
        .unwrap();
    assert_eq!(r.pushed, 128);
    assert_eq!(hid::STALE_BURST, 128);
    let fresh = hid_count(&sim, 1, 4).await;
    assert_eq!(
        fresh.get(..4).unwrap(),
        [HidFrame::SetMode { hid_type: 0 }.to_vec(), kbd(0, 0), kbd(0, 0x29), kbd(0, 0)]
    );
    let old = hid_on_ws(&sim, 0);
    assert_eq!(old.get(..2).unwrap(), [HidFrame::SetMode { hid_type: 0 }.to_vec(), kbd(0, 0)]);
    for (i, f) in old.iter().skip(2).enumerate() {
        assert_eq!(*f, hid::stale_frame(u64::try_from(i).unwrap()).to_vec(), "burst frame {i}");
    }
    if old.len() == 130 {
        assert_eq!(old.last().unwrap(), &kbd(0, 0), "a complete burst ends released");
    }
    no_logout(&sim);
}

/// `web-get` reads `/`: status and the `Server` header (absent on the ES3,
/// census), bounded.
#[tokio::test]
async fn web_get_reads_the_root_page() {
    let sim = sim_with(|_| {}).await;
    let p = kvm_probe::l4::web::get(&target(&sim), Some(sim.spki_sha256()), "/")
        .await
        .unwrap();
    assert!(p.status == 404 || p.status == 200, "{p:?}");
    no_logout(&sim);
}
```

and, in `src/cli.rs`'s tests:

```rust
    #[test]
    fn end_arg_maps_each_value_to_its_end() {
        use crate::l4::hid::End;
        assert_eq!(End::from(EndArg::Close), End::CloseFrame);
        assert_eq!(End::from(EndArg::Fin), End::Fin);
        assert_eq!(End::from(EndArg::Reset), End::Reset);
        let c = Cli::try_parse_from([
            "kvm-probe", "hid-hold", "--host", "h", "--pin", "ab", "--password-file", "/p", "--end", "fin",
        ])
        .unwrap();
        assert!(matches!(c.cmd, Cmd::HidHold { end: EndArg::Fin, observe_ms: 1500, .. }));
    }
```

(`hid_on_ws`, `hid_count`, `kbd` and `no_logout` are Task 1.4's; kvm-sim gains nothing — every count comes from the `Hid` and `WsOpen` events it already records.)

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --test sim -- l4` and `cargo test --workspace --all-features --lib -- cli` — Expected: FAIL to compile (`l4::hold`, `l4::web`, `stale_after_reset`, `EndArg` not found).

- [ ] **Step 3: Implement.** Add `pub mod hold; pub mod web;` to `src/l4/mod.rs`. Create `src/l4/hold.rs`:

```rust
//! DC18: what the Mac sees when the control websocket dies with a key held
//! (→ §9.3). Hold a key, kill the websocket one of three ways, and wait
//! with nothing released; the caller snapshots the page then, and again
//! after `guarded`'s release.
use super::hid::{End, HidWs};
use crate::kvm::KvmError;
use crate::request::KvmTarget;
use kvm_proto::hid::HidFrame;
use std::time::Duration;

/// '1': it auto-repeats on macOS (a rising `repeat` on the page) and has
/// no press-and-hold accent menu.
pub const HOLD_USAGE: u8 = 0x1E;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldReport {
    pub end: End,
}

/// Open the HID websocket, press `usage` (hold it), end the websocket by
/// `end`, then wait `observe` with the key never released. Every caller
/// wraps this in `hid::guarded`, so the release always runs.
pub async fn hold_then_kill(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    usage: u8,
    end: End,
    observe: Duration,
) -> Result<HoldReport, KvmError> {
    let mut w = HidWs::open(t, pin, token, Duration::from_secs(10)).await?;
    w.send(HidFrame::Keyboard {
        modifiers: 0,
        keys: [usage, 0, 0, 0, 0],
    })
    .await?;
    w.end(end).await;
    tokio::time::sleep(observe).await;
    Ok(HoldReport { end })
}
```

Create `src/l4/web.rs`:

```rust
//! `web-get` (§12): the KVM's web pages, for the firmware line the census
//! still lacks. Status, the `Server` header and a bounded, escaped snippet
//! — never the whole hostile page.
use super::escaped;
use crate::kvm::{self, KvmError};
use crate::request::KvmTarget;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use std::time::Duration;

const MAX_SNIPPET: usize = 512;
const GET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Page {
    pub status: u16,
    pub server: Option<String>,
    pub snippet: String,
}

pub async fn get(t: &KvmTarget, pin: Option<&str>, path: &str) -> Result<Page, KvmError> {
    tokio::time::timeout(GET_TIMEOUT, get_inner(t, pin, path))
        .await
        .map_err(|_| KvmError::Http(format!("GET {path} timed out")))?
}

async fn get_inner(t: &KvmTarget, pin: Option<&str>, path: &str) -> Result<Page, KvmError> {
    let io = kvm::connect_to(t, t.login_port, pin).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", &t.host)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| KvmError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    let server = resp
        .headers()
        .get("server")
        .map(|v| escaped(v.as_bytes(), 120));
    let mut body: Vec<u8> = Vec::new();
    let mut incoming = resp.into_body();
    while body.len() < MAX_SNIPPET {
        match incoming.frame().await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    body.extend_from_slice(d);
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    Ok(Page {
        status,
        server,
        snippet: escaped(&body, MAX_SNIPPET),
    })
}
```

Add to `src/l4/hid.rs`:

```rust
/// `hid-stale`'s burst length (D5): enough to see whether a reset
/// websocket's backlog is still read, small enough to type out harmlessly
/// as 64 letters into the test page if it is.
pub const STALE_BURST: u64 = 128;

/// The burst's `i`-th report: a press of `a`..`t` on even `i`, the
/// all-zero release on odd `i`. The burst ends on a release, so a backlog
/// read to its end leaves nothing held, and one cut anywhere leaves at most
/// one key down for the release after it to clear.
#[must_use]
pub fn stale_frame(i: u64) -> HidFrame {
    if i % 2 == 1 {
        return KBD_ZERO;
    }
    press(Stroke {
        usage: 0x04u8.saturating_add(u8::try_from((i / 2) % 20).unwrap_or(0)),
        shift: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleReport {
    /// Burst reports written before the reset (`STALE_BURST` unless a
    /// write failed).
    pub pushed: u64,
}

/// The re-assert measurement (PC9 fix 2): write the `STALE_BURST` burst at
/// pace 0 and reset the websocket (§3.2's rule for a stalled one), then
/// open a fresh one — its session start releases — and send Esc, which
/// clears the test page's text and counts, so the page then shows only
/// stale presses the KVM read **after** the fresh session start. Wait
/// `settle` for them; the caller snapshots the page before `guarded`
/// releases. Only the device (or kvm-sim) sees what it read, so the report
/// is just what was written.
pub async fn stale_after_reset(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    settle: Duration,
) -> Result<StaleReport, KvmError> {
    let mut w = HidWs::open(t, pin, token, Duration::from_secs(10)).await?;
    let mut pushed = 0u64;
    for i in 0..STALE_BURST {
        if w.send(stale_frame(i)).await.is_err() {
            break;
        }
        pushed = pushed.saturating_add(1);
    }
    w.end(End::Reset).await;
    let mut fresh = HidWs::open(t, pin, token, Duration::from_secs(10)).await?;
    fresh.send(press(Stroke { usage: kvm_proto::keymap::USAGE_ESC, shift: false })).await?;
    fresh.send(KBD_ZERO).await?;
    fresh.end(End::CloseFrame).await;
    tokio::time::sleep(settle).await;
    Ok(StaleReport { pushed })
}
```

In `src/cli.rs`, beside `SchemeArg`:

```rust
/// How `hid-hold` ends the websocket with the key held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EndArg {
    Close,
    Fin,
    Reset,
}

impl From<EndArg> for crate::l4::hid::End {
    fn from(e: EndArg) -> Self {
        match e {
            EndArg::Close => Self::CloseFrame,
            EndArg::Fin => Self::Fin,
            EndArg::Reset => Self::Reset,
        }
    }
}
```

and in `Cmd`:

```rust
    /// L4: hold '1', end the websocket by --end, wait --observe-ms with
    /// nothing released; with --snapshot N, snapshot `N_held` then and
    /// `N_released` after the release. Ends with a release.
    HidHold {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_enum, default_value_t = EndArg::Reset)]
        end: EndArg,
        #[arg(long, default_value_t = 1500)]
        observe_ms: u64,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// L4: the bounded stale burst, a reset, a fresh session start and Esc,
    /// --settle-ms, then (with --snapshot N) snapshot `N`. Ends with a
    /// release, and another 5 s later.
    HidStale {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value_t = 5000)]
        settle_ms: u64,
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// L4: GET a web-port path; status, `Server` header, bounded snippet.
    WebGet {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, default_value = "/")]
        path: String,
    },
```

`validate`: `Cmd::HidHold { conn, .. } | Cmd::HidStale { conn, .. } => (conn, &[Port::Web, Port::Control, Port::Video])` and `Cmd::WebGet { conn, .. } => (conn, &[Port::Web])`. In `src/main.rs`, a helper beside `captures_dir`:

```rust
/// One snapshot into captures/, printed. A `KvmError` so that a failed
/// snapshot ends a `guarded` body (and the release still runs).
async fn shot(conn: &Conn, tok: &str, ffmpeg: &Path, name: &str) -> Result<(), KvmError> {
    let dir = captures_dir().map_err(KvmError::Io)?;
    let png = l4::snapshot::snapshot(&target(conn), conn.pin_for(Port::Video), tok, &dir, name, ffmpeg)
        .await
        .map_err(KvmError::Io)?;
    println!("snapshot: {}", png.display());
    Ok(())
}
```

and the arms:

```rust
        Cmd::HidHold { conn, end, observe_ms, snapshot } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let ffmpeg = match &snapshot {
                Some(_) => Some(sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?),
                None => None,
            };
            let mut irq = l4::hid::Interrupts::new().map_err(|e| kvm::bounded_debug(&e))?;
            let report = session(&conn, &pw, async |tok: &str| {
                let pin = conn.pin_for(Port::Control);
                let r = l4::hid::guarded(&t, pin, tok, None, &mut irq, async {
                    let r = l4::hold::hold_then_kill(&t, pin, tok, l4::hold::HOLD_USAGE, end.into(), Duration::from_millis(observe_ms)).await?;
                    if let (Some(n), Some(f)) = (&snapshot, &ffmpeg) {
                        shot(&conn, tok, f, &format!("{n}_held")).await?;
                    }
                    Ok(r)
                })
                .await?;
                irq.check()?; // an interrupt during the release ends here (D34)
                if let (Some(n), Some(f)) = (&snapshot, &ffmpeg) {
                    shot(&conn, tok, f, &format!("{n}_released")).await?;
                }
                irq.check()?;
                Ok::<_, KvmError>(r)
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))?
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("{report:?}");
        }
        Cmd::HidStale { conn, settle_ms, snapshot } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let ffmpeg = match &snapshot {
                Some(_) => Some(sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?),
                None => None,
            };
            let mut irq = l4::hid::Interrupts::new().map_err(|e| kvm::bounded_debug(&e))?;
            let report = session(&conn, &pw, async |tok: &str| {
                let pin = conn.pin_for(Port::Control);
                let r = l4::hid::guarded(&t, pin, tok, None, &mut irq, async {
                    let r = l4::hid::stale_after_reset(&t, pin, tok, Duration::from_millis(settle_ms)).await?;
                    if let (Some(n), Some(f)) = (&snapshot, &ffmpeg) {
                        shot(&conn, tok, f, n).await?;
                    }
                    Ok(r)
                })
                .await;
                // A backlog that drains late can land after guarded's
                // release: release again once it surely has (D5). An
                // interrupt cuts the wait short but never this release (D34).
                let waited = irq.sleep(Duration::from_secs(5)).await;
                l4::hid::ensure_released(&t, pin, tok, None).await?;
                waited?;
                r
            })
            .await
            .map_err(|e| kvm::bounded_debug(&e))?
            .map_err(|e| kvm::bounded_debug(&e))?;
            println!("{report:?}");
        }
        Cmd::WebGet { conn, path } => {
            let p = l4::web::get(&target(&conn), conn.pin_for(Port::Web), &path)
                .await
                .map_err(|e| kvm::bounded_debug(&e))?;
            println!("status={} server={:?}\n{}", p.status, p.server, p.snippet);
        }
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --test sim -- l4` — Expected: PASS — 15 passed (Tasks 1.3 and 1.4's 12 and these 3). `cargo test --workspace --all-features --lib -- cli` — Expected: PASS (with `end_arg_maps_each_value_to_its_end`).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-probe/src/l4 crates/kvm-probe/src/cli.rs crates/kvm-probe/src/main.rs \
  crates/kvm-sim/tests/sim/l4.rs
git commit -m "kvm-probe: L4 hid-hold, hid-stale, web-get (DC18 key-held-on-death, PC9 re-assert, §12 firmware)" \
  -m "hid-stale's burst is bounded (128 reports, alternating, ending released) and releases twice, so no backlog can leave a key held on the Mac." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.6: Run the L4 checks against the ES3 and record Leg D in census.md

**This is the hardware task.** It runs Part 1's tools against the real ES3 and the work Mac and writes **derived facts only** into `docs/census.md`. It is the only task that touches live hardware; it is deferrable (see Execution notes). Steps marked **[OWNER]** need the owner physically at the Mac/KVM; the rest an agent drives. No step logs out (step 16's logout is the owner's, in the vendor UI), types a password into the Mac, or leaves a key held; captures stay in `captures/` and are wiped at the end.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/census.md` (add a "Leg D — Plan D L4" section; rewrite the "Leg A — crash behaviour" line)

**Preconditions (the operator sets these up once):**
- The machine running the probe can reach the ES3 (before isolation, the dev host; after, the §9.4 Job or dedicated host).
- **No kvm-rdp bridge runs against this ES3** (§11.6), and **the vendor web UI's remote-KVM view is closed** — either would hold the control websocket and interfere with the HID steps (D6c).
- The KVM password is in a file the owner names; its SPKI pin is in `census.md` (`f948…614f`). `export KVMHOST=<ip> PIN=f94841875ec7fa56220d48ffadaa5c0f2d84ffbbd1beeb060245ded1419b614f PW=<path>`.
- `captures/` exists (0700); it is wiped at step 15. **If the session stops early for any reason, run step 15's wipe (`rm -rf captures/*`) before ending it** (D26, §11.5).
- Build once, then run the binary (never `cargo run -p`: it resolves kvm-probe's features alone and builds a second set of artifacts, D6d):
  ```bash
  nix develop --command cargo build --workspace --all-features --bins
  KP="$(nix develop --command bash -c 'printf %s "$CARGO_TARGET_DIR"')/debug/kvm-probe"
  probe() { nix develop --command "$KP" "$@" --host "$KVMHOST" --pin "$PIN" --password-file "$PW"; }
  ```
  `probe` is for the subcommands that take the shared connection arguments. `hid-page-url`, `fingerprint` and `summarize` take none and run as `nix develop --command "$KP" …` (steps 1, 2, 11).
- **HID command rule (D6b).** Run every HID command (`hid-type`, `hid-hold`, `hid-stale`, `hid-release`) in the foreground, with the Bash tool's timeout at least the command's runtime plus 60 s, so a tool timeout never kills one mid-run. After any HID command that fails or is interrupted, run `probe hid-release`, then `probe snapshot --name after_<step>` and confirm the page shows `held -` before going on.
- **Page check (D6c).** Before each HID run, `probe snapshot --name pre_<step>` (for step 8, `pre_8<e>`); read the PNG and confirm the HID test page fills the screen (its `clock` line is there). If anything else is on the screen — the lock screen, another window — stop the HID steps and tell the owner.

**Order.** The numbers name the steps; run them in this order: **1 → 7 → 8 → 9** (the owner present, the page just opened, before the Mac can lock or sleep) **→ 2 → 3, 4, 11** (the remaining steps that log in, before step 6's tokens exist, D36) **→ 6** started in the background (`run_in_background`, watched with `Monitor`, about 61 min) **→ 5, 10, 13, 14** while it runs (none logs in) **→** once step 6 has finished, **12**, then **16** (both can end sessions, which would corrupt step 6) **→ 15** last, always. The session cap is unknown until step 12, so step 6's refusals are recorded as **"lapsed or evicted"** until step 12 rules out a cap (an ES3 that evicts its oldest session at a cap would end step 6's tokens early).

- [ ] **Step 1 — [OWNER] the Mac shows the test page.** `nix develop --command "$KP" hid-page-url` prints the URL (it sends nothing); the owner opens it in a new, otherwise empty Edge window on the Mac and leaves that window focused. (The lock screen is the only other allowed content; the page is needed for steps 7–9.) Record nothing yet.

- [ ] **Step 2 — fingerprint holds.** `nix develop --command "$KP" fingerprint --host "$KVMHOST"` (no pin) prints the SPKI; confirm it equals `$PIN`. If it differs, stop: the device or the pin changed — tell the owner, record nothing. (Steps 7–9 ran before this on pinned connections, which a changed key would have refused.)

- [ ] **Step 3 — ws-close (the close-form carry).** `probe ws-close --idle-secs 10`. Record from the `CloseReport`: whether the KVM sent anything while idle (`idle`), how it answered the close (`reply`: `CloseFrame`/`Eof`/`Error`/`Timeout`) and how TCP ended (`tcp`: `Fin`/`Reset`/…). `tcp: Error { kind: "UnexpectedEof" }` is a FIN without TLS `close_notify`: record it as FIN (D26). The derived fact for census.md: **"close answered by a close frame" or "bare EOF/reset"** — it decides whether the bridge's FIN-vs-RST rule (§3.2: only an answered close frame is a clean FIN) matches the device.

- [ ] **Step 4 — concurrent-flv (side IDR, same-token refusal, candidate lag).** `probe concurrent-flv --trials 20 --gop 60`. Record the summary line: served/refused/failed, the forced trials' side→main IDR p50/p95, `lag_ms` min/max, `replay_aus` max. Derived facts: **side request → forced main IDR p50/p95 over 20 trials**; **does a same-token side FLV ever get refused, and with what form** (if `refused > 0`, name the `RefusalForm`); **the forced-IDR → candidate lag, and the most AUs a swap would replay** (against §6.5's ring of 64 — flag if `replay_aus max ≥ 64`).

- [ ] **Step 5 — refusal-forms.** `probe refusal-forms`. Record, for `av.flv` and the websocket, each with a never-issued token and with none: status, Content-Type, body prefix. Derived fact: **the ES3's refusal form**, which confirms §6.9's classifier (a 200 whose body is JSON not FLV is a refusal; a `result:403` body is auth). The **after-a-global-logout** forms come from step 16 if it runs; otherwise census.md says they are **not measured** (DD1: a global logout ends the owner's session) and these never-issued/no-token forms stand in.

- [ ] **Step 6 — [OWNER consent] token-life (background).** After steps 2, 3, 4 and 11, and only with the owner's explicit consent (its five logins could evict the owner's web-UI session on a device that drops its oldest session at a cap): `probe token-life --owner-consent --minutes 1,5,15,30,60` with `run_in_background`, and `Monitor` it until it prints `5 tokens probed` (about 61 min). Record each age's outcome (Accepted/Refused), a Refused one as "lapsed or evicted" until step 12 rules out a session cap (D36). Derived fact: **how long an abandoned token stays valid** (the last age still Accepted). The bridge never logs out, so every RDP connection leaves one token to lapse.

- [ ] **Step 7 — [OWNER present] hid-type (the HID report rate).** `probe snapshot --name pre_7` and the page check, then, with the page focused: `probe hid-type --chars 200 --paces 0,5,10,15 --runs 3 --snapshot type` (one login, 12 runs; each begins with Esc, which resets the page, D7a; Bash timeout 300 s). For each run, read `captures/type<pace>_<run>.flv.png` (the Read tool) and compare the page's `text <len> <hash>` with that run's printed `expect page: text <len> <hash>`: a match means the run typed losslessly. Record: **the KVM's HID report rate**, from the pace-0 runs' snapshots — the page's `rate <n> <ms>` line gives `2·(n−1)·1000/ms` reports/s (press and release per key, from the first keydown to the last; take the median of the three runs) — which sizes the websocket's `SO_SNDBUF` cap (final review) and Task 6.1's `input.reassert_after` rule (D28, D29); and **the smallest pace that was lossless three runs out of three** (DD10: `paste.pace` = twice it). The probe's own `write_rate` and `kernel_buffered` at pace 0 are recorded as diagnostics only: 400 reports fit the send buffer and the KVM's receive window, so they measure the probe, not the KVM.

- [ ] **Step 8 — [OWNER present] hid-hold (key-held-on-death, → §9.3).** For each `<e>` in `close`, `fin`, `reset`: `probe snapshot --name pre_8<e>` and the page check, then `probe hid-hold --end <e> --observe-ms 1500 --snapshot hold_<e>`. Read `captures/hold_<e>_held.flv.png` (taken after the 1.5 s hold, before any release): does the page list `held Digit1`, and is `repeat` above `pre_8<e>`'s (the Mac auto-repeating a stuck key)? Then read `captures/hold_<e>_released.flv.png` (after `guarded`'s release): it must show `held -`; if not, follow the HID command rule at once. Record, per end kind: **does the Mac treat the key as held after the websocket dies** — the answer §9.3 needs, and the evidence for the stuck-key timers (§7.4) and the re-assert (DD8).

- [ ] **Step 9 — [OWNER present] hid-stale (the re-assert measurement).** `probe snapshot --name pre_9` and the page check, then `probe hid-stale --settle-ms 5000 --snapshot stale`. It sends a bounded 128-report burst (64 presses, each followed by a release), resets, opens a fresh websocket and sends Esc, so the page then counts only presses the KVM read **after** the fresh session start (D5). Read `captures/stale.flv.png`: its `keydown` count is that number. Then `probe snapshot --name after_9` must show `held -` (the command released twice). Record: **stale reports landed after the fresh session start: yes/no** (yes if `keydown` > 0), and **`keydown` on the page vs the 64 presses**. Task 6.1's `input.reassert_after` rule (DD8) reads the yes/no: if no, 1 s stands.

- [ ] **Step 10 — the bridge-side checks already covered on kvm-sim.** None to run here; note in census.md that the `side` policy, all three resize signals and the websocket surviving a global logout are proven on kvm-sim (L2, Plan C/D), and that the logout survival on the ES3 is step 16's answer if it ran, else **not confirmed** (DD1).

- [ ] **Step 11 — [OWNER] preset-change signalling.** The owner changes the KVM preset in its web UI while `probe capture --name preset --seconds 15` runs; then `nix develop --command "$KP" summarize --name preset`. Record: did the live FLV close (a new FLV, a new `initial` SPS), or did an in-band SPS/sequence header arrive? (Census Leg A saw a close, n = 1; this repeats it.) This is tentative and operator-driven; one observation is enough.

- [ ] **Step 12 — [OWNER consent] session-cap.** Only after step 6 has finished, only with the owner's explicit consent, and only if no one else is using the KVM (it may evict the oldest session): `probe session-cap --owner-consent --max 16`. Record `logins` and `stopped`. Derived fact: **whether the ES3 caps concurrent sessions**. If the owner declines, record "not run (needs owner consent)".

- [ ] **Step 13 — abandoned-token count.** The bridge never logs out, so tokens accumulate; token-life (step 6) already bounds how long one lives. Record the derived consequence: **one token lapses per RDP connection, living ~<step 6's answer>**; no action beyond what §5.1 already says.

- [ ] **Step 14 — [OWNER] firmware version.** The owner reads the firmware version from the KVM UI's about page (census.md has had this "pending" since Leg A). `probe web-get --path /` is a fallback if the about page is a known path; record the version string if either yields it, else leave "pending" with a note.

- [ ] **Step 16 — OPTIONAL, [OWNER], skippable: a coordinated logout (controller ruling 1).** Run only after step 6 has finished and only after Chris confirms nobody else is using the KVM; skip it otherwise, and census.md keeps DD1's "not measured". Run `probe logout-watch --max-secs 300` (it never sends a logout) with `run_in_background`, and `Monitor` it until it prints `READY: log out of the KVM web UI now` — a foreground call shows nothing until it exits (D33). Only then tell the **owner** to log out in the vendor web UI; they must not log out before READY (the probe's own login would come after it, and the run would wait for a second logout). Then `Monitor` it until the `WatchReport` line. Record from its `WatchReport`: the FLV and websocket **refusal forms after a global logout** (`flv_form`, `ws_form`), **whether the control websocket opened before the logout survived it** (`ws_survived`) and whether a release written on it then succeeded (`ws_write_ok`), and whether the pre-opened FLV kept delivering (`flv_survived`). Task 6.1's §11.6/§15 text uses these. (Numbered 16 so the earlier numbers stay; it runs before step 15.)

- [ ] **Step 15 — release, wipe captures and write Leg D (always last).** `probe hid-release` first (D6b). Then `rm -rf captures/*` (§11.5: captures are wiped each session and never committed). In `docs/census.md`, rewrite the "Leg A — crash behaviour" section's line (census.md:84) to "Moved to Plan D's L4: see Leg D (key-held-on-death)." (D25), and add a "Leg D — Plan D L4" section with one table of the derived facts above (no screen content, no frame bytes, no token) — each row: the fact, its value, and how it was obtained (the subcommand). For any step not run, the row says "not run" and why. Commit:

```bash
git add docs/census.md
git commit -m "census: Leg D — Plan D L4 results (§11.6, DC18)" \
  -m "Derived facts only; no screen content, no probe logout. Steps not run are marked." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

If a value retunes a config default, Task 6.1 applies it (it reads these rows): `paste.pace` (step 7, DD10), the websocket `SO_SNDBUF` cap (step 7's page-measured rate, D28), `input.reassert_after` (step 9's yes/no and step 7's page-measured rate, DD8, D29), `key_repeat_timeout` stays its 10 s acceptance default until the owner's Windows-App typematic capture (that is the acceptance checklist, not L4).

---
## Part 2 — The input mapping (§7)

### Task 2.1: `kvm_proto::hid::scale_abs`, and `kvm-rdp`'s keyboard and pointer state

The pure scaling formula goes in `kvm-proto`; the keyboard and pointer state machines — slots, the released-by-bridge rule for keys, modifiers and buttons, Unicode with its own Shift, Caps-Lock tracking, the Mac remap applied only when a report is built, button mask with click positions, wheel accumulation, clamping — go in `kvm-rdp`'s `input::{keys, pointer}`, which build §3.3 frames but do no I/O.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/hid.rs` (`scale_abs`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/mod.rs`, `src/input/keys.rs`, `src/input/pointer.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod input;`)
- Test: each new file's `tests`

**Interfaces:**
- Consumes: `kvm_proto::keymap::*` (Task 1.1), `kvm_proto::hid::{HidFrame, Wheel, ABS_MAX}`.
- Produces:
  - `kvm_proto::hid::scale_abs(v: u16, span: u16) -> u16` — §7.2: `v * 32767 / (span - 1)`, clamped, `span <= 1` → 0.
  - `kvm_rdp::input::keys::{Keyboard, KeyReport}`: `#[derive(Debug, Default)] Keyboard`; `set_mac_remap(&mut self, on: bool)`; `press(&mut self, code: u8, extended: bool) -> Option<KeyReport>`; `release(&mut self, code: u8, extended: bool) -> Option<KeyReport>` (both `None` only for an unmapped scancode); `unicode_press(&mut self, unit: u16) -> Option<KeyReport>`; `unicode_release(&mut self, unit: u16) -> Option<KeyReport>` (both always `Some`); `release_all(&mut self) -> KeyReport`; `mark_released_by_bridge(&mut self, usage: u8) -> bool` (false when `MAX_RBB` is full); `is_released_by_bridge(&self, usage: u8) -> bool`; `is_down(&self, usage: u8) -> bool`; `held_modifier_bits(&self) -> u8` (raw, never remapped); `held_nonmodifier_usages(&self) -> usize`; `caps_lock_on(&self) -> bool`; `set_caps_lock(&mut self, on: bool)`; `pub struct KeyReport { pub frame: HidFrame, pub ignored: bool, pub dropped: bool }` (`frame` is the full-state keyboard frame; `ignored`: no frame need be sent; `dropped`: DD7/DD9's counted drop, always `ignored` too).
  - `kvm_rdp::input::pointer::{Pointer, PointerReport, Button}`: `#[derive(Debug)] Pointer` with `Default` (surface 1920×1080); `set_surface(&mut self, w: u16, h: u16)`; `moved(&mut self, x: u16, y: u16) -> PointerReport`; `button(&mut self, b: Button, pressed: bool, x: u16, y: u16) -> Option<PointerReport>` (`None`: a press of a released-by-bridge button); `wheel(&mut self, units: i16) -> Vec<HidFrame>`; `release_all(&mut self)`; `last(&self) -> Option<(u16, u16)>`; `pub enum Button { Left, Right, Middle }`; `pub struct PointerReport { pub frame: HidFrame }`.

- [ ] **Step 1: Write the failing tests.** In `crates/kvm-proto/src/hid.rs`'s `tests`, add:

```rust
    /// §7.2: x_hid = x * 32767 / (w-1), clamped at the edges; a 1-wide or
    /// 0-wide span maps everything to 0 (no division by zero).
    #[test]
    fn scale_abs_matches_section_7_2() {
        assert_eq!(scale_abs(0, 1920), 0);
        assert_eq!(scale_abs(1919, 1920), 32_767);
        assert_eq!(scale_abs(960, 1920), 16_392); // 960·32767/1919, §7.2
        assert_eq!(scale_abs(959, 1919), 16_383); // the exact half
        assert_eq!(scale_abs(5000, 1920), 32_767, "past the edge clamps");
        assert_eq!(scale_abs(0, 1), 0);
        assert_eq!(scale_abs(7, 0), 0);
        assert_eq!(scale_abs(719, 720), 32_767);
    }
```

Create `crates/kvm-rdp/src/input/keys.rs` holding, for now, only its tests (set-1 make codes from Task 1.1: a `0x1E`, s `0x1F`, d `0x20`, f `0x21`, g `0x22`, h `0x23`, c `0x2E`, v `0x2F`, t `0x14`, LCtrl `0x1D`, RCtrl `E0 1D`, LShift `0x2A`, RShift `0x36`, LAlt `0x38`, LGUI `E0 5B`, Caps Lock `0x3A`; `0x54` is unmapped):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use kvm_proto::keymap::Chord;

    fn kbd(modifiers: u8, keys: [u8; 5]) -> HidFrame {
        HidFrame::Keyboard { modifiers, keys }
    }

    fn one(modifiers: u8, k: u8) -> HidFrame {
        kbd(modifiers, [k, 0, 0, 0, 0])
    }

    /// The frame of a report that must be sent.
    fn sent(r: Option<KeyReport>) -> HidFrame {
        let r = r.unwrap();
        assert!(!r.ignored && !r.dropped, "{r:?}");
        r.frame
    }

    fn ignored(r: Option<KeyReport>) -> bool {
        let r = r.unwrap();
        r.ignored && !r.dropped
    }

    #[test]
    fn five_slots_then_a_sixth_reported_when_one_frees() {
        let mut k = Keyboard::default();
        for code in [0x1E, 0x1F, 0x20, 0x21, 0x22] {
            sent(k.press(code, false));
        }
        // 'h': tracked, but every slot is full, so the frame is unchanged.
        assert_eq!(sent(k.press(0x23, false)), kbd(0, [0x04, 0x16, 0x07, 0x09, 0x0A]));
        assert_eq!(k.held_nonmodifier_usages(), 6);
        // 'a' up: 'h' moves into the fifth slot.
        assert_eq!(sent(k.release(0x1E, false)), kbd(0, [0x16, 0x07, 0x09, 0x0A, 0x0B]));
    }

    #[test]
    fn a_repeat_is_ignored() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.press(0x1E, false)), one(0, 0x04));
        let r = k.press(0x1E, false).unwrap();
        assert_eq!((r.frame, r.ignored, r.dropped), (one(0, 0x04), true, false));
        assert_eq!(k.held_nonmodifier_usages(), 1);
        assert_eq!(sent(k.press(0x2A, false)), one(0x02, 0x04));
        assert!(ignored(k.press(0x2A, false)), "a modifier's repeat too");
    }

    #[test]
    fn modifiers_go_to_the_byte_either_side() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.press(0x2A, false)), one(0x02, 0)); // LShift
        assert_eq!(sent(k.press(0x1D, true)), one(0x12, 0)); // RCtrl
        assert_eq!(sent(k.press(0x36, false)), one(0x32, 0)); // RShift
        assert_eq!(sent(k.press(0x5B, true)), one(0x3A, 0)); // LGUI
        assert_eq!(k.held_nonmodifier_usages(), 0, "a modifier never takes a slot");
        assert_eq!(sent(k.release(0x2A, false)), one(0x38, 0));
        assert_eq!(k.held_modifier_bits(), 0x38);
    }

    /// §7.4 (D3a): keys AND modifiers held at a release are released by
    /// the bridge; their repeats change nothing until the client's release.
    #[test]
    fn release_all_marks_keys_and_modifiers_released_by_bridge() {
        let mut k = Keyboard::default();
        sent(k.press(0x1D, false));
        assert_eq!(sent(k.press(0x1E, false)), one(0x01, 0x04));
        let r = k.release_all();
        assert_eq!((r.frame, r.ignored, r.dropped), (one(0, 0), false, false));
        assert!(ignored(k.press(0x1E, false)), "a's repeat");
        assert!(ignored(k.press(0x1D, false)), "LCtrl's repeat");
        assert_eq!(k.held_modifier_bits(), 0);
        assert!(ignored(k.release(0x1D, false)), "the KVM already has it up");
        assert_eq!(sent(k.press(0x1D, false)), one(0x01, 0));
        assert!(ignored(k.release(0x1E, false)));
        assert_eq!(sent(k.press(0x1E, false)), one(0x01, 0x04));
    }

    /// §7.1, D8b: a Unicode key types its US stroke; Shift comes only from
    /// the latest accepted Unicode press and never clears a physical Shift;
    /// repeats and released-by-bridge units are ignored; a lone surrogate
    /// or an untypeable unit is dropped (counted, DD7).
    #[test]
    fn unicode_keys_type_through_the_us_layout_and_follow_the_rbb_rule() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.unicode_press(u16::from(b'A'))), one(0x02, 0x04));
        assert!(ignored(k.unicode_press(u16::from(b'A'))), "a repeat");
        // '1' while 'A' is still down: unshifted — '1', never '!'.
        assert_eq!(sent(k.unicode_press(u16::from(b'1'))), kbd(0, [0x04, 0x1E, 0, 0, 0]));
        sent(k.unicode_release(u16::from(b'1')));
        assert_eq!(sent(k.unicode_release(u16::from(b'A'))), one(0, 0));
        assert_eq!(sent(k.unicode_press(u16::from(b'1'))), one(0, 0x1E));
        k.release_all();
        assert!(ignored(k.unicode_press(u16::from(b'1'))), "released by the bridge");
        assert!(ignored(k.unicode_release(u16::from(b'1'))));
        assert_eq!(sent(k.unicode_press(u16::from(b'1'))), one(0, 0x1E));
        sent(k.unicode_release(u16::from(b'1')));
        // A physical Shift survives a Unicode release.
        sent(k.press(0x2A, false));
        sent(k.unicode_press(u16::from(b'a')));
        assert_eq!(sent(k.unicode_release(u16::from(b'a'))), one(0x02, 0));
        for unit in [0xD800u16, 0x00E9] {
            let r = k.unicode_press(unit).unwrap();
            assert!(r.ignored && r.dropped, "{unit:#x}: {r:?}");
            assert_eq!(r.frame, one(0x02, 0));
        }
    }

    /// DD3 (D8a): with the remap on, Ctrl becomes GUI only beside
    /// C/V/X/A/Z/F/W; other Ctrl chords, the raw held bits (which the
    /// paste chord reads, §8) and a real GUI are left alone.
    #[test]
    fn mac_remap_moves_ctrl_to_gui_only_for_the_set() {
        let mut k = Keyboard::default();
        k.set_mac_remap(true);
        sent(k.press(0x1D, false));
        assert_eq!(sent(k.press(0x2E, false)), one(0x08, 0x06), "Ctrl+C → Cmd+C");
        sent(k.release(0x2E, false));
        assert_eq!(sent(k.press(0x14, false)), one(0x01, 0x17), "Ctrl+T stays");
        sent(k.release(0x14, false));
        sent(k.release(0x1D, false));
        sent(k.press(0x1D, true));
        assert_eq!(sent(k.press(0x2F, false)), one(0x80, 0x19), "RCtrl+V → RCmd+V");
        sent(k.release(0x2F, false));
        sent(k.release(0x1D, true));
        sent(k.press(0x1D, false));
        sent(k.press(0x38, false));
        sent(k.press(0x2A, false));
        let chord = Chord::parse("ctrl+option+shift+v").unwrap();
        assert!(chord.matches(0x2F, false, k.held_modifier_bits()), "the chord sees raw bits");
        let mut k = Keyboard::default();
        k.set_mac_remap(true);
        assert_eq!(sent(k.press(0x5B, true)), one(0x08, 0));
        assert_eq!(sent(k.press(0x1D, false)), one(0x09, 0));
        assert_eq!(sent(k.release(0x1D, false)), one(0x08, 0), "a real GUI stays held");
    }

    /// DD5 (D8c): Caps Lock follows each fresh press; a repeat or a
    /// released-by-bridge press does not toggle it.
    #[test]
    fn caps_lock_toggles_on_each_fresh_press() {
        let mut k = Keyboard::default();
        k.set_caps_lock(false);
        sent(k.press(0x3A, false));
        assert!(k.caps_lock_on());
        assert!(ignored(k.press(0x3A, false)));
        assert!(k.caps_lock_on(), "a repeat does not toggle");
        sent(k.release(0x3A, false));
        sent(k.press(0x3A, false));
        assert!(!k.caps_lock_on());
        k.release_all();
        assert!(ignored(k.press(0x3A, false)));
        assert!(!k.caps_lock_on(), "a released-by-bridge repeat does not toggle");
    }

    /// DD9: at most 16 non-modifier keys are tracked; the rest are dropped
    /// and counted, and the frame stays one constant-size report.
    #[test]
    fn a_flood_of_distinct_presses_is_bounded() {
        let mut k = Keyboard::default();
        let codes: Vec<u8> = (0x10..=0x1B).chain(0x1E..=0x28).chain(0x2C..=0x35).chain(0x02..=0x08).collect();
        assert_eq!(codes.len(), 40);
        let dropped = codes.iter().filter(|c| k.press(**c, false).unwrap().dropped).count();
        assert_eq!((k.held_nonmodifier_usages(), dropped), (16, 24));
        assert_eq!(k.release_all().frame, one(0, 0));
    }

    #[test]
    fn an_unmapped_scancode_maps_to_nothing() {
        let mut k = Keyboard::default();
        assert!(k.press(0x54, false).is_none());
        assert!(k.release(0x54, false).is_none());
    }

    /// D3c's hook: a key the paste path swallowed is released by the
    /// bridge, so its repeats after the paste are not fresh presses.
    #[test]
    fn a_key_marked_released_by_bridge_waits_for_its_release() {
        let mut k = Keyboard::default();
        assert!(k.mark_released_by_bridge(0x19));
        assert!(k.is_released_by_bridge(0x19));
        assert!(ignored(k.press(0x2F, false)));
        assert!(ignored(k.release(0x2F, false)));
        assert_eq!(sent(k.press(0x2F, false)), one(0, 0x19));
        assert!(k.is_down(0x19));
    }
}
```

Create `crates/kvm-rdp/src/input/pointer.rs` holding, for now, only its tests:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn abs(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse { buttons, x, y }
    }

    #[test]
    fn moves_scale_to_the_surface() {
        let mut p = Pointer::default();
        assert_eq!(p.moved(1919, 1079).frame, abs(0, 32_767, 32_767), "the default 1920×1080");
        p.set_surface(1280, 720);
        assert_eq!(p.moved(0, 0).frame, abs(0, 0, 0));
        assert_eq!(p.moved(1279, 719).frame, abs(0, 32_767, 32_767));
        assert_eq!(p.last(), Some((32_767, 32_767)));
    }

    #[test]
    fn coordinates_outside_the_surface_clamp() {
        let mut p = Pointer::default();
        assert_eq!(p.moved(5000, 5000).frame, abs(0, 32_767, 32_767));
    }

    #[test]
    fn the_button_mask_and_wheel_notches() {
        let mut p = Pointer::default();
        assert_eq!(p.button(Button::Left, true, 0, 0).unwrap().frame, abs(0x01, 0, 0));
        assert_eq!(p.button(Button::Right, true, 0, 0).unwrap().frame, abs(0x03, 0, 0));
        assert_eq!(p.button(Button::Middle, true, 0, 0).unwrap().frame, abs(0x07, 0, 0));
        assert_eq!(p.button(Button::Right, false, 0, 0).unwrap().frame, abs(0x05, 0, 0));
        assert_eq!(p.wheel(240), vec![HidFrame::Wheel { buttons: 0x05, wheel: Wheel::Up }; 2]);
        assert!(p.wheel(60).is_empty(), "half a notch accumulates");
        assert_eq!(p.wheel(-180), vec![HidFrame::Wheel { buttons: 0x05, wheel: Wheel::Down }]);
    }

    /// D8d: a click carries its own position — with no prior move it goes
    /// where it was made, never to (0, 0) (§3.3).
    #[test]
    fn a_click_with_no_prior_move_uses_its_own_position() {
        let mut p = Pointer::default();
        assert_eq!(p.button(Button::Left, true, 960, 540).unwrap().frame, abs(0x01, 16_392, 16_398));
        assert_eq!(p.last(), Some((16_392, 16_398)));
    }

    /// §7.4 (D3b): buttons held at a release are released by the bridge; a
    /// press of one changes nothing until the client's release.
    #[test]
    fn release_all_marks_buttons_released_by_bridge() {
        let mut p = Pointer::default();
        p.button(Button::Left, true, 10, 10).unwrap();
        p.release_all();
        assert_eq!(p.moved(10, 10).frame, abs(0, 170, 303));
        assert!(p.button(Button::Left, true, 10, 10).is_none());
        assert_eq!(p.button(Button::Left, false, 10, 10).unwrap().frame, abs(0, 170, 303));
        assert_eq!(p.button(Button::Left, true, 10, 10).unwrap().frame, abs(0x01, 170, 303));
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- scale_abs` then `-- input::keys` then `-- input::pointer` — Expected: FAIL to compile (`scale_abs`, `Keyboard`, `Pointer` not found; `input` not declared).

- [ ] **Step 3: Implement.** In `crates/kvm-proto/src/hid.rs`, after `ABS_MAX`:

```rust
/// §7.2: scale a client coordinate `v` on a `span`-wide (or -tall) axis to
/// 0..=`ABS_MAX`, clamped. `span <= 1` (an unknown or degenerate surface)
/// maps everything to 0.
#[must_use]
pub fn scale_abs(v: u16, span: u16) -> u16 {
    let Some(last) = span.checked_sub(1) else {
        return 0;
    };
    let v = u32::from(v.min(last));
    let scaled = v
        .saturating_mul(u32::from(ABS_MAX))
        .checked_div(u32::from(last))
        .unwrap_or(0);
    u16::try_from(scaled).unwrap_or(ABS_MAX)
}
```

Add `pub mod input;` to `crates/kvm-rdp/src/lib.rs` (after `pub mod hid;`) and create `crates/kvm-rdp/src/input/mod.rs` declaring only this task's modules (D1a: Task 2.2 adds `core`, Task 3.2 adds `paste`):

```rust
//! The input path (§7): the keyboard and pointer state (`keys`, `pointer`),
//! the paste state (`paste`), and the sans-IO core that drives them with a
//! clock and the §7.4 triggers (`core`). No I/O; the shell (`rdp::input`)
//! carries the reports out through `HidControl` (DD2).
pub mod keys;
pub mod pointer;
```

Above the tests in `crates/kvm-rdp/src/input/keys.rs`:

```rust
//! The keyboard's authoritative HID state (§7.1, §7.4): five key slots, the
//! modifier byte (raw, as the client holds it), the released-by-bridge set
//! for keys and modifiers, Caps-Lock tracking, Unicode typing through the
//! US layout with its own Shift, and the Mac remap — applied only when a
//! report is built (DD3). Synchronous and O(1); it builds full-state §3.3
//! frames and nothing else.
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{
    CLASS_CTRL, MOD_LCTRL, MOD_LGUI, MOD_LSHIFT, MOD_RCTRL, MOD_RGUI, Stroke, USAGE_CAPS_LOCK, modifier_bit,
    modifier_classes, us_stroke, usage_for_scancode,
};

/// At most this many non-modifier keys are tracked at once (DD9); a press
/// past it is dropped and counted. Five are reported (the device's slots).
const MAX_TRACKED: usize = 16;
/// At most this many released-by-bridge usages are remembered (DD9).
const MAX_RBB: usize = 32;

/// DD3: the chords Windows App rewrites from Cmd+letter to Ctrl+letter
/// (§7.1). With `mac_remap` on, a report that holds Ctrl and one of these
/// sends GUI in Ctrl's place; every other Ctrl chord is left alone.
const REMAP_USAGES: [u8; 7] = [0x06, 0x19, 0x1B, 0x04, 0x1D, 0x09, 0x1A]; // c v x a z f w

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    /// The full-state keyboard frame after this event.
    pub frame: HidFrame,
    /// No frame need be sent: a held key's repeat, a released-by-bridge
    /// key's repeat, the release of a key not down, or a dropped event.
    pub ignored: bool,
    /// Dropped and counted (DD7, DD9): an untypeable or surrogate Unicode
    /// unit, a press past `MAX_TRACKED`, or (from `release_all`) a held key
    /// `MAX_RBB` had no room to remember. Always `ignored` too.
    pub dropped: bool,
}

#[derive(Debug, Default)]
pub struct Keyboard {
    /// Raw modifier bits as the client holds them; never remapped (§8: the
    /// chord is matched before any remap).
    modifiers: u8,
    /// Non-modifier usages currently down, in press order (first five report).
    down: Vec<u8>,
    /// The usages in `down` a Unicode event pressed (D8b).
    unicode_down: Vec<u8>,
    /// The latest accepted Unicode press needed Shift; reports carry LShift
    /// while a Unicode-pressed key is down (D8b).
    unicode_shift: bool,
    /// Usages (keys and modifiers) released by the bridge whose client
    /// `Released` has not come: their `Pressed` repeats are ignored (§7.4).
    rbb: Vec<u8>,
    caps_lock: bool,
    mac_remap: bool,
}

impl Keyboard {
    pub fn set_mac_remap(&mut self, on: bool) {
        self.mac_remap = on;
    }

    #[must_use]
    pub fn held_modifier_bits(&self) -> u8 {
        self.modifiers
    }

    #[must_use]
    pub fn held_nonmodifier_usages(&self) -> usize {
        self.down.len()
    }

    #[must_use]
    pub fn is_down(&self, usage: u8) -> bool {
        self.down.contains(&usage)
    }

    #[must_use]
    pub fn is_released_by_bridge(&self, usage: u8) -> bool {
        self.rbb.contains(&usage)
    }

    #[must_use]
    pub fn caps_lock_on(&self) -> bool {
        self.caps_lock
    }

    pub fn set_caps_lock(&mut self, on: bool) {
        self.caps_lock = on;
    }

    fn report(&self) -> HidFrame {
        let mut keys = [0u8; 5];
        for (slot, usage) in keys.iter_mut().zip(self.down.iter()) {
            *slot = *usage;
        }
        let mut modifiers = self.modifiers;
        if self.mac_remap
            && modifier_classes(modifiers) & CLASS_CTRL != 0
            && keys.iter().any(|k| REMAP_USAGES.contains(k))
        {
            if modifiers & MOD_LCTRL != 0 {
                modifiers = (modifiers & !MOD_LCTRL) | MOD_LGUI;
            }
            if modifiers & MOD_RCTRL != 0 {
                modifiers = (modifiers & !MOD_RCTRL) | MOD_RGUI;
            }
        }
        if self.unicode_shift {
            modifiers |= MOD_LSHIFT;
        }
        HidFrame::Keyboard { modifiers, keys }
    }

    fn out(&self, ignored: bool, dropped: bool) -> KeyReport {
        KeyReport {
            frame: self.report(),
            ignored,
            dropped,
        }
    }

    /// A scancode press. `None` only when the key maps to nothing.
    pub fn press(&mut self, code: u8, extended: bool) -> Option<KeyReport> {
        let usage = usage_for_scancode(code, extended)?;
        Some(self.press_usage(usage))
    }

    pub fn release(&mut self, code: u8, extended: bool) -> Option<KeyReport> {
        let usage = usage_for_scancode(code, extended)?;
        Some(self.release_usage(usage))
    }

    /// A Unicode key event: the US-layout stroke's usage, with Shift from
    /// this press alone (D8b). An untypeable or surrogate unit is dropped
    /// (DD7).
    pub fn unicode_press(&mut self, unit: u16) -> Option<KeyReport> {
        let Some(Stroke { usage, shift }) = char::from_u32(u32::from(unit)).and_then(us_stroke) else {
            return Some(self.out(true, true));
        };
        let r = self.press_usage(usage);
        if r.ignored {
            return Some(r);
        }
        self.unicode_shift = shift;
        if !self.unicode_down.contains(&usage) {
            self.unicode_down.push(usage);
        }
        Some(self.out(false, false))
    }

    pub fn unicode_release(&mut self, unit: u16) -> Option<KeyReport> {
        let Some(Stroke { usage, .. }) = char::from_u32(u32::from(unit)).and_then(us_stroke) else {
            return Some(self.out(true, true));
        };
        self.unicode_down.retain(|u| *u != usage);
        if self.unicode_down.is_empty() {
            self.unicode_shift = false;
        }
        Some(self.release_usage(usage))
    }

    fn press_usage(&mut self, usage: u8) -> KeyReport {
        if self.rbb.contains(&usage) {
            return self.out(true, false); // §7.4: released by the bridge
        }
        if let Some(bit) = modifier_bit(usage) {
            if self.modifiers & bit != 0 {
                return self.out(true, false);
            }
            self.modifiers |= bit;
            return self.out(false, false);
        }
        if self.down.contains(&usage) {
            return self.out(true, false);
        }
        if self.down.len() >= MAX_TRACKED {
            return self.out(true, true); // DD9: bounded, counted
        }
        self.down.push(usage);
        if usage == USAGE_CAPS_LOCK {
            self.caps_lock = !self.caps_lock; // DD5
        }
        self.out(false, false)
    }

    fn release_usage(&mut self, usage: u8) -> KeyReport {
        self.rbb.retain(|u| *u != usage);
        if let Some(bit) = modifier_bit(usage) {
            if self.modifiers & bit == 0 {
                return self.out(true, false);
            }
            self.modifiers &= !bit;
            return self.out(false, false);
        }
        let before = self.down.len();
        self.down.retain(|u| *u != usage);
        if self.down.len() == before {
            return self.out(true, false);
        }
        self.out(false, false)
    }

    /// Remember `usage` as released by the bridge (§7.4): its presses are
    /// ignored until its release. False when `MAX_RBB` is full.
    pub fn mark_released_by_bridge(&mut self, usage: u8) -> bool {
        if self.rbb.contains(&usage) {
            return true;
        }
        if self.rbb.len() >= MAX_RBB {
            return false;
        }
        self.rbb.push(usage);
        true
    }

    /// §7.4: everything up, zeroed. Held keys AND held modifiers (D3a)
    /// become released-by-bridge, so their repeats are ignored until the
    /// client releases them; `dropped` if `MAX_RBB` could not hold one.
    pub fn release_all(&mut self) -> KeyReport {
        let mods = self.modifiers;
        let mut held: Vec<u8> = (0xE0..=0xE7u8)
            .filter(|u| modifier_bit(*u).is_some_and(|b| mods & b != 0))
            .collect();
        held.append(&mut self.down);
        let mut dropped = false;
        for usage in held {
            dropped |= !self.mark_released_by_bridge(usage);
        }
        self.modifiers = 0;
        self.unicode_down.clear();
        self.unicode_shift = false;
        KeyReport {
            frame: self.report(),
            ignored: false,
            dropped,
        }
    }
}
```

**Implementer note on the remap:** §7.1 says "Windows App rewrites Cmd+C/V/X/A/Z/F/W to Ctrl+… and sends other Cmd chords as the Windows key", and `input.mac_remap` "can undo this". The remap here undoes exactly that set (DD3) and nothing else, at report time, so the held bits — and with them §8's chord — stay raw. Whether production turns it on is the owner's key-matrix capture (acceptance item 4); it ships off (controller ruling 3).

Above the tests in `crates/kvm-rdp/src/input/pointer.rs`:

```rust
//! The pointer's authoritative state (§7.2): absolute position scaled to
//! the current surface, the three-button mask with the released-by-bridge
//! rule (§7.4), and wheel-notch accumulation. It builds §3.3 frames; no I/O.
use kvm_proto::hid::{HidFrame, Wheel, scale_abs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    const fn bit(self) -> u8 {
        match self {
            Button::Left => 0x01,
            Button::Right => 0x02,
            Button::Middle => 0x04,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerReport {
    pub frame: HidFrame,
}

#[derive(Debug)]
pub struct Pointer {
    /// The surface's size (Setup sets it, §6.4); before the first Setup,
    /// the advertised default.
    surface: (u16, u16),
    buttons: u8,
    /// Buttons released by the bridge whose client release has not come:
    /// their presses change nothing (§7.4, D3b).
    rbb_buttons: u8,
    pos: Option<(u16, u16)>,
    /// RDP ±120-per-notch rotation, accumulated.
    wheel_accum: i32,
}

impl Default for Pointer {
    fn default() -> Pointer {
        Pointer {
            surface: (1920, 1080),
            buttons: 0,
            rbb_buttons: 0,
            pos: None,
            wheel_accum: 0,
        }
    }
}

impl Pointer {
    pub fn set_surface(&mut self, w: u16, h: u16) {
        self.surface = (w, h);
    }

    fn scaled(&self, x: u16, y: u16) -> (u16, u16) {
        (scale_abs(x, self.surface.0), scale_abs(y, self.surface.1))
    }

    fn at(&mut self, x: u16, y: u16) -> PointerReport {
        let (hx, hy) = self.scaled(x, y);
        self.pos = Some((hx, hy));
        PointerReport {
            frame: HidFrame::AbsMouse {
                buttons: self.buttons,
                x: hx,
                y: hy,
            },
        }
    }

    pub fn moved(&mut self, x: u16, y: u16) -> PointerReport {
        self.at(x, y)
    }

    /// A button event at the client's (x, y) — IronRDP's button events
    /// carry the click position (D8d). A press of a released-by-bridge
    /// button changes nothing (`None`); its release clears the mark.
    pub fn button(&mut self, b: Button, pressed: bool, x: u16, y: u16) -> Option<PointerReport> {
        let bit = b.bit();
        if pressed {
            if self.rbb_buttons & bit != 0 {
                return None;
            }
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
            self.rbb_buttons &= !bit;
        }
        Some(self.at(x, y))
    }

    /// §7.4: the device's buttons are zeroed by the release the shell sends;
    /// this zeroes the mask to match and marks the held buttons released
    /// by the bridge, so nothing re-presses them (D3b).
    pub fn release_all(&mut self) {
        self.rbb_buttons |= self.buttons;
        self.buttons = 0;
    }

    /// RDP's ±120-per-notch rotation accumulated; one wheel frame per whole
    /// notch (§7.2, §3.3), with the current button mask.
    pub fn wheel(&mut self, units: i16) -> Vec<HidFrame> {
        self.wheel_accum = self.wheel_accum.saturating_add(i32::from(units));
        let mut out = Vec::new();
        while self.wheel_accum >= 120 {
            self.wheel_accum -= 120;
            out.push(HidFrame::Wheel {
                buttons: self.buttons,
                wheel: Wheel::Up,
            });
        }
        while self.wheel_accum <= -120 {
            self.wheel_accum += 120;
            out.push(HidFrame::Wheel {
                buttons: self.buttons,
                wheel: Wheel::Down,
            });
        }
        out
    }

    #[must_use]
    pub fn last(&self) -> Option<(u16, u16)> {
        self.pos
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- scale_abs input::keys input::pointer` — Expected: PASS — 1 in kvm-proto (`scale_abs_matches_section_7_2`) and 15 in kvm-rdp (10 `input::keys`, 5 `input::pointer`).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-proto/src/hid.rs crates/kvm-rdp/src/lib.rs crates/kvm-rdp/src/input/mod.rs \
  crates/kvm-rdp/src/input/keys.rs crates/kvm-rdp/src/input/pointer.rs
git commit -m "kvm-rdp: keyboard and pointer state — slots, released-by-bridge, Unicode, mac_remap, scaling (§7.1, §7.2)" \
  -m "Modifiers and buttons follow the released-by-bridge rule too; the remap is applied at report time, so held bits stay raw." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 2.2: `input::core` — the sans-IO input machine, §7.4 triggers and timers

One synchronous core over `keys` and `pointer` (paste joins in Task 3.2). It takes `now`, a context snapshot (the release epoch, the current generation, the surface, `mac_remap`, the timeouts), and an `Event`, and appends `Out`s. The release epoch is the release channel (design decision 6): the core reads it at the top of each step and, when it moved since its own last-seen epoch, releases (every held key and button becomes released-by-bridge) before handling the event — so the core never needs a `release_all` input from the shell, and a report it builds is stamped with the epoch it was built at. `Synchronize` and the two timers are the only triggers the core raises itself (DD7, §10.4: `release_all` gains `Synchronize` and the timers; the shell's own triggers stay in `HidControl`).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/core.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/queue.rs` (`ReleaseTrigger` gains `Synchronize`, `KeyRepeat`, `ModifierIdle`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/mod.rs` (`pub mod core;` and `pub use core::{Ctx, Event, InputCore, Out};`, D1a)
- Test: `crates/kvm-rdp/src/input/core.rs` (`tests`)

**Interfaces:**
- Consumes: Task 2.1's `input::keys::{Keyboard, KeyReport}` (`press(code, extended)`, `set_mac_remap`, `is_down`, `release_all`), `input::pointer::{Pointer, Button}` (`button(b, pressed, x, y) -> Option<_>`, `release_all`), Task 1.1's `kvm_proto::keymap::{modifier_bit, us_stroke, usage_for_scancode}`, `hid::ReleaseTrigger`, `kvm_proto::hid::HidFrame`.
- Produces (`kvm_rdp::input::core`):
  - `pub struct Ctx { pub now: Instant, pub epoch: u64, pub generation: Gen, pub surface: (u16, u16), pub mac_remap: bool, pub key_repeat_timeout: Duration, pub modifier_idle_timeout: Duration }`.
  - `pub enum Event { KeyPressed { code: u8, extended: bool }, KeyReleased { code: u8, extended: bool }, UnicodePressed(u16), UnicodeReleased(u16), Synchronize { caps_lock: bool }, MouseMove { x: u16, y: u16 }, MouseButton { button: Button, pressed: bool, x: u16, y: u16 }, Wheel { units: i16 }, Tick }` (a button event carries its click position, D8d).
  - `pub enum Out { Push { frame: HidFrame, motion_only: bool, stamp: u64 }, Release(ReleaseTrigger), Ignored }` — `Ignored` is one dropped input for `input_events_ignored` (DD7, DD9: an unmapped scancode, an untypeable or surrogate unit, a press past the bounds; D8f); a `Push`'s `stamp` is the epoch the core's state was built at (the `Ctx::epoch` of the step); the shell pushes it with `HidControl::push_at(stamp, …)`; a `Release` the shell carries out with `HidControl::release_all(trigger)` (which bumps the epoch that the next step reads).
  - `pub struct InputCore` — `InputCore::new()`; `step(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>)`; `next_deadline(&self) -> Option<Instant>` (the sooner of the two armed timers); `generation(&self) -> Gen`; `on_generation(&mut self, g: Gen)` (a new session: reset everything).
  - `Gen` is `crate::msg::Gen`.

- [ ] **Step 1: Write the failing tests.** `input/core.rs`'s tests, with an injected clock:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use kvm_proto::hid::HidFrame;

    fn kbd(modifiers: u8, k: u8) -> HidFrame {
        HidFrame::Keyboard { modifiers, keys: [k, 0, 0, 0, 0] }
    }

    struct Rig {
        core: InputCore,
        now: Instant,
        epoch: u64,
    }

    impl Rig {
        fn new() -> Rig {
            Rig { core: InputCore::new(), now: Instant::now(), epoch: 0 }
        }
        fn ctx(&self) -> Ctx {
            Ctx {
                now: self.now,
                epoch: self.epoch,
                generation: 1,
                surface: (1920, 1080),
                mac_remap: false,
                key_repeat_timeout: Duration::from_secs(10),
                modifier_idle_timeout: Duration::from_secs(30),
            }
        }
        /// Step and return the outs; a `Release` out bumps the rig's epoch,
        /// as the shell's `HidControl::release_all` would.
        fn step(&mut self, e: Event) -> Vec<Out> {
            let mut out = Vec::new();
            self.core.step(&self.ctx(), e, &mut out);
            if out.iter().any(|o| matches!(o, Out::Release(_))) {
                self.epoch += 1;
            }
            out
        }
        fn advance(&mut self, d: Duration) {
            self.now += d;
        }
    }

    fn pushes(out: &[Out]) -> Vec<(HidFrame, u64)> {
        out.iter()
            .filter_map(|o| match o {
                Out::Push { frame, stamp, .. } => Some((*frame, *stamp)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_press_and_release_push_full_state_at_the_current_epoch() {
        let mut r = Rig::new();
        assert_eq!(pushes(&r.step(Event::KeyPressed { code: 0x1E, extended: false })), [(kbd(0, 0x04), 0)]);
        assert_eq!(pushes(&r.step(Event::KeyReleased { code: 0x1E, extended: false })), [(kbd(0, 0), 0)]);
        // An unmapped scancode is dropped and counted (D8f), never pushed.
        assert_eq!(r.step(Event::KeyPressed { code: 0x54, extended: false }), [Out::Ignored]);
    }

    /// Design decision 6: a bumped epoch (a release the shell did) releases
    /// before the event, and reports carry the new stamp.
    #[test]
    fn a_bumped_epoch_releases_held_keys_before_the_next_event() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false }); // 'a' down
        r.epoch = 5; // the shell released all (websocket reconnect, say)
        // The next event first sees the release: 'a' is now released-by-
        // bridge, so its repeat is ignored, and everything is stamped 5.
        let out = r.step(Event::KeyPressed { code: 0x1E, extended: false });
        assert!(pushes(&out).iter().all(|(_, stamp)| *stamp == 5), "{out:?}");
        assert!(!out.iter().any(|o| matches!(o, Out::Push { frame: HidFrame::Keyboard { keys: [0x04, ..], .. }, .. })));
        // Its client Released clears the released-by-bridge mark.
        r.step(Event::KeyReleased { code: 0x1E, extended: false });
        assert_eq!(pushes(&r.step(Event::KeyPressed { code: 0x1E, extended: false })), [(kbd(0, 0x04), 5)]);
    }

    /// §7.4 (D3a): a modifier held at a release is released by the bridge
    /// too — the client's typematic repeats of a held Ctrl or Cmd never
    /// re-press it (the down-up-down glitch §7.4 forbids).
    #[test]
    fn a_held_modifier_is_not_repressed_by_repeats_after_a_release() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1D, extended: false }); // LCtrl
        r.epoch = 5;
        for _ in 0..3 {
            let out = r.step(Event::KeyPressed { code: 0x1D, extended: false });
            assert!(
                !pushes(&out).iter().any(|(f, _)| matches!(f, HidFrame::Keyboard { modifiers, .. } if *modifiers != 0)),
                "{out:?}"
            );
        }
        let mut out = r.step(Event::KeyReleased { code: 0x1D, extended: false });
        out.extend(r.step(Event::KeyPressed { code: 0x1D, extended: false }));
        assert_eq!(pushes(&out), [(kbd(0x01, 0), 5)]);
    }

    /// §7.4 (D3b): a reconnect never re-presses a button — the next move
    /// after a release carries no button, and a press before the client's
    /// release changes nothing.
    #[test]
    fn a_held_button_is_released_by_bridge() {
        let mut r = Rig::new();
        r.step(Event::MouseMove { x: 10, y: 10 });
        r.step(Event::MouseButton { button: Button::Left, pressed: true, x: 10, y: 10 });
        r.epoch = 1;
        let out = r.step(Event::MouseMove { x: 20, y: 20 });
        let moves: Vec<HidFrame> = pushes(&out)
            .into_iter()
            .map(|(f, _)| f)
            .filter(|f| matches!(f, HidFrame::AbsMouse { .. }))
            .collect();
        assert!(matches!(moves.as_slice(), [HidFrame::AbsMouse { buttons: 0, .. }]), "{out:?}");
        assert!(pushes(&r.step(Event::MouseButton { button: Button::Left, pressed: true, x: 20, y: 20 })).is_empty());
    }

    /// §7.4: Synchronize releases all and records Caps Lock.
    #[test]
    fn synchronize_releases_all_and_tracks_caps_lock() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false });
        let out = r.step(Event::Synchronize { caps_lock: true });
        assert!(out.iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::Synchronize))));
        assert!(r.core.caps_lock_on());
    }

    /// §7.4: non-modifier keys held and no Pressed repeat of any of them for
    /// key_repeat_timeout → release; a repeat before then resets it; mouse
    /// never resets it.
    #[test]
    fn the_key_repeat_timer_releases_after_silence() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false });
        assert_eq!(r.core.next_deadline(), Some(r.now + Duration::from_secs(10)));
        r.advance(Duration::from_secs(9));
        r.step(Event::MouseMove { x: 10, y: 10 }); // does not reset (§7.4)
        assert_eq!(r.core.next_deadline(), Some(r.now - Duration::from_secs(9) + Duration::from_secs(10)));
        r.advance(Duration::from_secs(2)); // 11 s since the press
        let out = r.step(Event::Tick);
        assert!(out.iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat))), "{out:?}");
        assert_eq!(r.core.next_deadline(), None);
    }

    #[test]
    fn a_repeat_of_the_held_key_resets_the_key_repeat_timer() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false });
        r.advance(Duration::from_secs(9));
        r.step(Event::KeyPressed { code: 0x1E, extended: false }); // a repeat
        r.advance(Duration::from_secs(9)); // 9 s since the repeat
        assert!(!r.step(Event::Tick).iter().any(|o| matches!(o, Out::Release(_))));
    }

    /// §7.4 (D8e): only a `Pressed` repeat of a held non-modifier key
    /// resets the key-repeat timer — Windows' typematic Shift does not, so a
    /// stuck letter is released while Shift repeats.
    #[test]
    fn a_modifier_repeat_does_not_reset_the_key_repeat_timer() {
        let mut r = Rig::new();
        let t0 = r.now;
        r.step(Event::KeyPressed { code: 0x1E, extended: false }); // a
        r.step(Event::KeyPressed { code: 0x2A, extended: false }); // LShift
        let mut released_at = None;
        for _ in 0..10 {
            r.advance(Duration::from_secs(2));
            let mut out = r.step(Event::KeyPressed { code: 0x2A, extended: false });
            out.extend(r.step(Event::Tick));
            if released_at.is_none() && out.iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat))) {
                released_at = Some(r.now - t0);
            }
        }
        assert_eq!(released_at, Some(Duration::from_secs(10)));
    }

    /// §7.4: two keys held, repeats of only the second → no release (the
    /// §11 case).
    #[test]
    fn two_keys_held_with_repeats_of_the_second_only_never_release() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false }); // a
        r.step(Event::KeyPressed { code: 0x30, extended: false }); // b
        for _ in 0..30 {
            r.advance(Duration::from_secs(9));
            r.step(Event::KeyPressed { code: 0x30, extended: false }); // repeat b
            assert!(!r.step(Event::Tick).iter().any(|o| matches!(o, Out::Release(_))));
        }
    }

    /// §7.4: modifiers held and no keyboard event of any kind for
    /// modifier_idle_timeout → release; a mouse event never resets it.
    #[test]
    fn the_modifier_idle_timer_releases_a_stuck_modifier() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1D, extended: false }); // LCtrl down
        assert_eq!(r.core.next_deadline(), Some(r.now + Duration::from_secs(30)));
        r.advance(Duration::from_secs(29));
        r.step(Event::MouseMove { x: 1, y: 1 });
        r.advance(Duration::from_secs(2));
        let out = r.step(Event::Tick);
        assert!(out.iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::ModifierIdle))), "{out:?}");
    }

    /// Review Focus 3: a flood still releases on the key-repeat timeout.
    #[test]
    fn a_flood_still_releases_on_the_key_repeat_timeout() {
        let mut r = Rig::new();
        for code in 0x02..=0x40u8 {
            r.step(Event::KeyPressed { code, extended: false });
        }
        r.advance(Duration::from_secs(11));
        assert!(r.step(Event::Tick).iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat))));
    }

    #[test]
    fn a_new_generation_resets_the_state_and_the_timers() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed { code: 0x1E, extended: false });
        r.core.on_generation(2);
        assert_eq!(r.core.next_deadline(), None);
        assert_eq!(r.core.generation(), 2);
    }

    /// A Tick with nothing armed and no state change pushes nothing.
    #[test]
    fn an_idle_tick_does_nothing() {
        let mut r = Rig::new();
        assert!(r.step(Event::Tick).is_empty());
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- input::core` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** First widen `ReleaseTrigger` in `crates/kvm-rdp/src/hid/queue.rs`: add `Synchronize`, `KeyRepeat`, `ModifierIdle` to the enum and to `label` (`"synchronize"`, `"key_repeat"`, `"modifier_idle"`). (§10.4: the `release_all{trigger}` family gains these three; the metric's label set widens with it — Task 4.1 adds nothing more.) Add to `crates/kvm-rdp/src/input/mod.rs`, after `pub mod keys;`:

```rust
pub mod core;
```

and, after the module list, `pub use core::{Ctx, Event, InputCore, Out};`. Then create `crates/kvm-rdp/src/input/core.rs` above the tests:

```rust
//! The input state machine (§7), sans-IO: `step(now, ctx, event)` appends
//! `Out`s, `next_deadline` says when a timer next needs a `Tick`. The
//! release epoch is the release channel: a step whose `ctx.epoch` moved
//! since the last one releases first (every held key and button becomes
//! released-by-bridge), and every report it then builds carries `ctx.epoch`
//! as its stamp, so the shell's `push_at(stamp, …)` drops it if a release
//! raced it (design decision 6; §7.3, §7.4). The two timers and
//! `Synchronize` are the triggers the core raises itself; the shell's own
//! triggers (session start/end, suppression, reconnect, Closing, shutdown)
//! reach the core only as a bumped epoch.
use crate::hid::ReleaseTrigger;
use crate::input::keys::{KeyReport, Keyboard};
use crate::input::pointer::{Button, Pointer};
use crate::msg::Gen;
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{modifier_bit, us_stroke, usage_for_scancode};
use std::time::{Duration, Instant};

pub struct Ctx {
    pub now: Instant,
    pub epoch: u64,
    pub generation: Gen,
    pub surface: (u16, u16),
    pub mac_remap: bool,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
}

pub enum Event {
    KeyPressed { code: u8, extended: bool },
    KeyReleased { code: u8, extended: bool },
    UnicodePressed(u16),
    UnicodeReleased(u16),
    Synchronize { caps_lock: bool },
    MouseMove { x: u16, y: u16 },
    /// A button event at the client's (x, y): IronRDP's carries the click
    /// position (D8d).
    MouseButton { button: Button, pressed: bool, x: u16, y: u16 },
    Wheel { units: i16 },
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    Push {
        frame: HidFrame,
        motion_only: bool,
        stamp: u64,
    },
    Release(ReleaseTrigger),
    /// One dropped input, counted as `input_events_ignored` (DD7, DD9).
    Ignored,
}

pub struct InputCore {
    keys: Keyboard,
    pointer: Pointer,
    generation: Gen,
    seen_epoch: u64,
    /// When a held non-modifier key last saw a `Pressed` (a new press or a
    /// repeat of a key held after it, D8e): the key-repeat timer's base.
    last_key_activity: Option<Instant>,
    /// When the keyboard last saw any event, if a modifier is held: the
    /// modifier-idle timer's base.
    last_kbd_event: Option<Instant>,
    /// The armed deadlines, recomputed by `arm` at the end of each step, so
    /// `next_deadline` needs no `Ctx`.
    key_repeat_at: Option<Instant>,
    modifier_idle_at: Option<Instant>,
}

impl InputCore {
    #[must_use]
    pub fn new() -> InputCore {
        InputCore {
            keys: Keyboard::default(),
            pointer: Pointer::default(),
            generation: 0,
            seen_epoch: 0,
            last_key_activity: None,
            last_kbd_event: None,
            key_repeat_at: None,
            modifier_idle_at: None,
        }
    }

    #[must_use]
    pub fn generation(&self) -> Gen {
        self.generation
    }

    pub fn on_generation(&mut self, g: Gen) {
        self.keys = Keyboard::default();
        self.pointer = Pointer::default();
        self.generation = g;
        self.last_key_activity = None;
        self.last_kbd_event = None;
        self.key_repeat_at = None;
        self.modifier_idle_at = None;
    }

    #[must_use]
    pub fn caps_lock_on(&self) -> bool {
        self.keys.caps_lock_on()
    }

    /// The sooner of the two armed timer deadlines.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        [self.key_repeat_at, self.modifier_idle_at]
            .into_iter()
            .flatten()
            .min()
    }

    fn arm(&mut self, ctx: &Ctx) {
        self.key_repeat_at = (self.keys.held_nonmodifier_usages() > 0)
            .then(|| self.last_key_activity.map(|t| t + ctx.key_repeat_timeout))
            .flatten();
        self.modifier_idle_at = (self.keys.held_modifier_bits() != 0)
            .then(|| self.last_kbd_event.map(|t| t + ctx.modifier_idle_timeout))
            .flatten();
    }

    pub fn step(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) {
        self.pointer.set_surface(ctx.surface.0, ctx.surface.1);
        self.keys.set_mac_remap(ctx.mac_remap); // D8a: applied at report time
        // The release channel: a moved epoch releases before the event.
        if ctx.epoch != self.seen_epoch {
            self.seen_epoch = ctx.epoch;
            let r = self.release_state(out);
            out.push(Out::Push {
                frame: r.frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
        self.handle(ctx, event, out);
        self.arm(ctx);
    }

    /// §7.4's release of the core's own state: keys and modifiers (D3a) and
    /// buttons (D3b) become released-by-bridge; both timers disarm. Every
    /// release path — the epoch step, `Synchronize`, both timers — comes
    /// through here.
    fn release_state(&mut self, out: &mut Vec<Out>) -> KeyReport {
        let r = self.keys.release_all();
        self.pointer.release_all();
        if r.dropped {
            out.push(Out::Ignored); // MAX_RBB had no room (DD9)
        }
        self.last_key_activity = None;
        self.last_kbd_event = None;
        r
    }

    fn push_key(ctx: &Ctx, r: Option<KeyReport>, out: &mut Vec<Out>) {
        match r {
            None => out.push(Out::Ignored), // unmapped (DD7)
            Some(r) if r.dropped => out.push(Out::Ignored),
            Some(r) if r.ignored => {}
            Some(r) => out.push(Out::Push {
                frame: r.frame,
                motion_only: false,
                stamp: ctx.epoch,
            }),
        }
    }

    /// D8e: a `Pressed` resets the key-repeat timer only when its usage is
    /// a non-modifier that is held after it (a new press or a repeat).
    fn note_key_activity(&mut self, ctx: &Ctx, usage: Option<u8>) {
        if usage.is_some_and(|u| modifier_bit(u).is_none() && self.keys.is_down(u)) {
            self.last_key_activity = Some(ctx.now);
        }
    }

    fn handle(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) {
        match event {
            Event::KeyPressed { code, extended } => {
                self.last_kbd_event = Some(ctx.now);
                let r = self.keys.press(code, extended);
                self.note_key_activity(ctx, usage_for_scancode(code, extended));
                Self::push_key(ctx, r, out);
            }
            Event::KeyReleased { code, extended } => {
                self.last_kbd_event = Some(ctx.now);
                Self::push_key(ctx, self.keys.release(code, extended), out);
            }
            Event::UnicodePressed(u) => {
                self.last_kbd_event = Some(ctx.now);
                let r = self.keys.unicode_press(u);
                let usage = char::from_u32(u32::from(u)).and_then(us_stroke).map(|s| s.usage);
                self.note_key_activity(ctx, usage);
                Self::push_key(ctx, r, out);
            }
            Event::UnicodeReleased(u) => {
                self.last_kbd_event = Some(ctx.now);
                Self::push_key(ctx, self.keys.unicode_release(u), out);
            }
            Event::Synchronize { caps_lock } => {
                out.push(Out::Release(ReleaseTrigger::Synchronize));
                self.release_state(out);
                self.keys.set_caps_lock(caps_lock);
            }
            Event::MouseMove { x, y } => {
                let r = self.pointer.moved(x, y);
                out.push(Out::Push {
                    frame: r.frame,
                    motion_only: true,
                    stamp: ctx.epoch,
                });
            }
            Event::MouseButton { button, pressed, x, y } => {
                // `None`: a press of a released-by-bridge button (D3b).
                if let Some(r) = self.pointer.button(button, pressed, x, y) {
                    out.push(Out::Push {
                        frame: r.frame,
                        motion_only: false,
                        stamp: ctx.epoch,
                    });
                }
            }
            Event::Wheel { units } => {
                for frame in self.pointer.wheel(units) {
                    out.push(Out::Push {
                        frame,
                        motion_only: false,
                        stamp: ctx.epoch,
                    });
                }
            }
            Event::Tick => self.timers(ctx, out),
        }
    }

    fn timers(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        if self.key_repeat_at.is_some_and(|at| ctx.now >= at) {
            out.push(Out::Release(ReleaseTrigger::KeyRepeat));
            self.release_state(out);
        } else if self.modifier_idle_at.is_some_and(|at| ctx.now >= at) {
            out.push(Out::Release(ReleaseTrigger::ModifierIdle));
            self.release_state(out);
        }
    }
}

impl Default for InputCore {
    fn default() -> InputCore {
        InputCore::new()
    }
}
```

**Note on §7.4's "typematic repeats only the most recently pressed key":** the key-repeat timer is reset by a `Pressed` of *any* held non-modifier key — a new press or a repeat — and by nothing else: not a modifier's repeat, an unmapped scancode, an ignored or dropped press, or the mouse (D8e). That is what the two-keys-held test pins; the device auto-repeats only the most recent, so in practice the repeats that reset it are of that key. The timer measures "no repeat of any held key for the timeout", per §7.4's first bullet.

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- input::core` — Expected: PASS — 13 passed (the ten above, plus D3a's, D3b's and D8e's). `cargo test --workspace --all-features --lib -- metrics::` — Expected: PASS (the widened `ReleaseTrigger` still renders; the metric's label set is checked in Task 4.1).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/input/core.rs crates/kvm-rdp/src/hid/queue.rs crates/kvm-rdp/src/input/mod.rs
git commit -m "kvm-rdp: the input core — epoch-driven release, §7.4 triggers and both timers, sans-IO (§7)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Part 3 — Clipboard paste as typing (§8)

### Task 3.1: `kvm_proto::paste` — §8's text handling and the Typist; `paste.chord` validated

§8's text rules (trailing line break removed, `multiline` refuse, CRLF/CR/LF → Return, Tab, skip untypeable per scalar, `max_chars` after) and the UTF-16LE decode of `CF_UNICODETEXT` are pure functions of the bytes and config, so they live in `kvm-proto`, fuzzable and panic-free. The `Typist` turns the prepared text into the §8 report sequence (one press, one all-zero release, Shift in the press), yielding one report at a time so the shell can pace and gate it. `paste.chord` is parsed and validated at config load.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/paste.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (`pub mod paste;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/config.rs` (`paste.chord` → `kvm_proto::keymap::Chord`, validated; `leak_shapes` gains a chord shape)
- Test: `crates/kvm-proto/src/paste.rs` (`tests`), `crates/kvm-rdp/src/config.rs` (`tests`)

**Interfaces:**
- Consumes: `kvm_proto::keymap::{Chord, Stroke, us_stroke, MOD_LSHIFT}`, `kvm_proto::hid::HidFrame`.
- Produces:
  - `kvm_proto::paste`: `pub struct PastePolicy { pub multiline_refuse: bool, pub max_chars: usize }`; `pub enum Prepared { Text(Vec<char>), RefusedMultiline }`; `pub struct Skips { pub kept: usize, pub skipped: usize }`; `pub fn decode_utf16le(bytes: &[u8]) -> (String, usize)` (the decoded text up to its first U+0000 — CF_UNICODETEXT's terminator, D4 — and the count of ill-formed units replaced); `pub fn prepare(text: &str, policy: &PastePolicy) -> (Prepared, Skips)`; `pub struct Typist`, `Typist::new(chars: &[char])`, `impl Iterator for Typist { type Item = HidFrame; }` (press then release, alternating; D1b), `Typist::is_done(&self) -> bool`, `pub const RELEASE: HidFrame`.
  - `kvm_rdp::config::PasteConfig::chord: Chord` (was `String`).

- [ ] **Step 1: Write the failing tests.** `crates/kvm-proto/src/paste.rs` tests:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn policy(multiline_refuse: bool, max_chars: usize) -> PastePolicy {
        PastePolicy { multiline_refuse, max_chars }
    }
    fn chars(p: &Prepared) -> &[char] {
        match p {
            Prepared::Text(v) => v,
            Prepared::RefusedMultiline => panic!("refused"),
        }
    }

    #[test]
    fn utf16le_decodes_and_counts_ill_formed_units() {
        let (s, bad) = decode_utf16le(&[b'h', 0, b'i', 0]);
        assert_eq!((s.as_str(), bad), ("hi", 0));
        // A lone high surrogate (D800) is ill-formed: counted, replaced.
        let (s, bad) = decode_utf16le(&[0x00, 0xD8, b'x', 0]);
        assert_eq!(bad, 1);
        assert!(s.ends_with('x'));
        // An odd trailing byte is dropped and counted.
        let (_, bad) = decode_utf16le(&[b'a', 0, b'b']);
        assert_eq!(bad, 1);
    }

    /// D4: CF_UNICODETEXT is NUL-terminated (IronRDP's `new_unicode_string`,
    /// Windows and FreeRDP all append U+0000). The text ends there, so a
    /// copied line's trailing break is still the last thing §8 sees — and
    /// is removed, never typed as a Return.
    #[test]
    fn the_cf_unicodetext_terminator_ends_the_text() {
        assert_eq!(
            decode_utf16le(&[b'l', 0, b's', 0, b'\r', 0, b'\n', 0, 0, 0, b'x', 0]),
            ("ls\r\n".to_owned(), 0)
        );
        assert_eq!(
            prepare(&decode_utf16le(&[b'l', 0, b's', 0, b'\r', 0, b'\n', 0, 0, 0]).0, &policy(false, 4096)),
            (Prepared::Text(vec!['l', 's']), Skips { kept: 2, skipped: 0 })
        );
        assert_eq!(
            prepare(&decode_utf16le(&[b'a', 0, b'\n', 0, 0, 0]).0, &policy(true, 4096)).0,
            Prepared::Text(vec!['a']),
            "multiline = refuse still types a copied single line"
        );
    }

    /// §8 text handling, in order: a trailing line break is removed; CRLF,
    /// CR and LF each become one Return ('\n'); Tab stays; other C0 and
    /// untypeable scalars are skipped and counted.
    #[test]
    fn prepare_follows_section_8() {
        let (p, s) = prepare("a\r\nb\tc\u{1F600}\n", &policy(false, 4096));
        assert_eq!(chars(&p), ['a', '\n', 'b', '\t', 'c']); // trailing \n removed, emoji skipped
        assert_eq!((s.kept, s.skipped), (5, 1));
        assert_eq!(prepare("a\r", &policy(false, 4096)).0, Prepared::Text(vec!['a']));
        assert_eq!(prepare("\n", &policy(false, 4096)).0, Prepared::Text(vec![]));
    }

    #[test]
    fn multiline_refuse_refuses_an_inner_break_but_types_a_trailing_one() {
        assert_eq!(prepare("a\nb", &policy(true, 4096)).0, Prepared::RefusedMultiline);
        assert_eq!(prepare("a\n", &policy(true, 4096)).0, Prepared::Text(vec!['a']));
    }

    #[test]
    fn max_chars_caps_after_the_other_steps() {
        let (p, s) = prepare("abcdef", &policy(false, 3));
        assert_eq!(chars(&p), ['a', 'b', 'c']);
        assert_eq!(s.kept, 3);
    }

    /// §8 report sequence: press (Shift in the modifier byte for a shifted
    /// character), then an all-zero release, per character.
    #[test]
    fn the_typist_emits_press_release_pairs() {
        let mut t = Typist::new(&['a', 'B', '\n', '\t']);
        let press = |m, k| HidFrame::Keyboard { modifiers: m, keys: [k, 0, 0, 0, 0] };
        let got: Vec<_> = std::iter::from_fn(|| t.next()).collect();
        assert_eq!(
            got,
            [
                press(0, 0x04), RELEASE,              // a
                press(MOD_LSHIFT, 0x05), RELEASE,     // B
                press(0, 0x28), RELEASE,              // Return
                press(0, 0x2B), RELEASE,              // Tab
            ]
        );
        assert!(t.is_done());
    }
}
```

`crates/kvm-rdp/src/config.rs` tests — add to the existing `tests` module:

```rust
    #[test]
    fn the_paste_chord_parses_at_load() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        assert_eq!(
            c.paste.chord,
            kvm_proto::keymap::Chord::parse("ctrl+option+shift+v").unwrap()
        );
        let bad = format!("{}[paste]\nchord = \"v\"\n", minimal(d.path()));
        assert!(load(d.path(), &bad).is_err(), "a chord with no modifier");
    }
```

(This uses the existing `minimal`/`load` test helpers. `minimal()` has no `[paste]` table, so the chord takes its default; `leak_shapes`'s `base` — also `minimal(dir)` — still parses, and the new chord shape appends its own `[paste]` table.)

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- paste` then `-- the_paste_chord_parses_at_load` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Add `pub mod paste;` to `crates/kvm-proto/src/lib.rs`. Create `crates/kvm-proto/src/paste.rs`:

```rust
//! Clipboard paste as typing (§8): the US-layout text handling and the
//! Typist, pure functions of the clipboard bytes and `paste.*`. Hostile
//! input (a client's `CF_UNICODETEXT`), so panic-free and bounded by the
//! crate lints.
use crate::hid::HidFrame;
use crate::keymap::{MOD_LSHIFT, Stroke, us_stroke};

/// An all-zero keyboard report: the release after every typed character.
pub const RELEASE: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0; 5],
};

/// Decode `bytes` as UTF-16LE, replacing each ill-formed unit (a lone
/// surrogate, or a trailing odd byte) with U+FFFD and counting it. The
/// text ends at its first U+0000 (CF_UNICODETEXT's terminator); nothing
/// after it is text, so nothing after it is counted either (D4).
#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> (String, usize) {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut it = bytes.chunks_exact(2);
    for c in it.by_ref() {
        if let &[lo, hi] = c {
            units.push(u16::from_le_bytes([lo, hi]));
        }
    }
    let mut odd = usize::from(!it.remainder().is_empty());
    if let Some(end) = units.iter().position(|&u| u == 0) {
        units.truncate(end);
        odd = 0;
    }
    let mut out = String::with_capacity(units.len());
    let mut bad = odd;
    for r in char::decode_utf16(units) {
        match r {
            Ok(c) => out.push(c),
            Err(_) => {
                bad = bad.saturating_add(1);
                out.push('\u{FFFD}');
            }
        }
    }
    (out, bad)
}

#[derive(Debug, Clone, Copy)]
pub struct PastePolicy {
    pub multiline_refuse: bool,
    pub max_chars: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    Text(Vec<char>),
    RefusedMultiline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skips {
    pub kept: usize,
    pub skipped: usize,
}

/// §8, in order: drop one trailing CRLF/CR/LF; with `multiline_refuse`,
/// refuse any text that still holds a break; turn CRLF/CR/LF into one
/// Return each and keep Tab; skip other controls and characters the US
/// layout cannot type (counted per Unicode scalar); cap at `max_chars`.
#[must_use]
pub fn prepare(text: &str, policy: &PastePolicy) -> (Prepared, Skips) {
    let trimmed = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .or_else(|| text.strip_suffix('\r'))
        .unwrap_or(text);
    if policy.multiline_refuse && trimmed.contains(['\n', '\r']) {
        return (Prepared::RefusedMultiline, Skips { kept: 0, skipped: 0 });
    }
    // CRLF → one '\n' first, so a CRLF is not two line breaks.
    let unified = trimmed.replace("\r\n", "\n").replace('\r', "\n");
    let mut kept: Vec<char> = Vec::new();
    let mut skipped = 0usize;
    for c in unified.chars() {
        if kept.len() >= policy.max_chars {
            break;
        }
        if us_stroke(c).is_some() {
            kept.push(c);
        } else {
            skipped = skipped.saturating_add(1);
        }
    }
    let kept_len = kept.len();
    (Prepared::Text(kept), Skips { kept: kept_len, skipped })
}

/// Emits the §8 report sequence for a prepared character list: a press
/// (Shift in the modifier byte for a shifted character), then an all-zero
/// release, one character at a time.
pub struct Typist {
    strokes: Vec<Stroke>,
    i: usize,
    release_next: bool,
}

impl Typist {
    #[must_use]
    pub fn new(chars: &[char]) -> Typist {
        Typist {
            strokes: chars.iter().filter_map(|c| us_stroke(*c)).collect(),
            i: 0,
            release_next: false,
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.i >= self.strokes.len() && !self.release_next
    }
}

impl Iterator for Typist {
    type Item = HidFrame;

    /// The next report, or `None` when done.
    fn next(&mut self) -> Option<HidFrame> {
        if self.release_next {
            self.release_next = false;
            self.i = self.i.saturating_add(1);
            return Some(RELEASE);
        }
        let s = self.strokes.get(self.i)?;
        self.release_next = true;
        Some(HidFrame::Keyboard {
            modifiers: if s.shift { MOD_LSHIFT } else { 0 },
            keys: [s.usage, 0, 0, 0, 0],
        })
    }
}
```

In `crates/kvm-rdp/src/config.rs`: change `PasteConfig::chord` from `String` to `kvm_proto::keymap::Chord`, and in `build`'s paste section replace the `chord.is_empty()` check with:

```rust
    let chord_text = rp.chord.clone().unwrap_or_else(|| "ctrl+option+shift+v".to_owned());
    let chord = kvm_proto::keymap::Chord::parse(&chord_text).ok_or_else(|| {
        invalid("paste.chord must be one or more modifiers (ctrl/shift/alt/option/cmd/win) then one letter or digit, e.g. \"ctrl+option+shift+v\"")
    })?;
```

Update the config `tests` that read `p.chord.as_str()` to compare the parsed `Chord` (the existing `defaults_match_section_4_4`-style test), and add a chord shape to `leak_shapes` — `t(format!("{base}[paste]\nchord = \"{s}\"\n"), "a bad chord")` — so a sentinel in `paste.chord` is covered (final review: `leak_shapes` gets every new or changed config key). Its error is "wrong value type"? No — the chord is a validated value, so its category is the fixed invalid-rule message, and `config_errors_never_echo_the_file` only checks the sentinel never appears; `invalid(…)` carries a static string, so it passes.

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- paste` then `-- config::` — Expected: PASS (paste's 7 — six in `kvm_proto::paste`, plus `the_paste_chord_parses_at_load` — and config's, including `config_errors_never_echo_the_file` over the new shape).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-proto/src/paste.rs crates/kvm-proto/src/lib.rs crates/kvm-rdp/src/config.rs
git commit -m "kvm-proto: paste text handling and the Typist (§8); config validates paste.chord" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 3.2: `input::paste` — the paste state machine, wired into the core

The paste states live in `input::paste` and are stepped by the core: the chord (matched on raw scancodes and raw held bits, before any remap) starts it; the core requests the clipboard text, waits for the modifiers to release and the response to arrive (both bounded by `paste.modifier_wait`), refuses on Caps Lock, types through the `Typist` at `paste.pace` and never more reports per step than the HID queue has room for (DD6), and ends on Esc, a mouse button, a §7.4 trigger or completion. While **Pending** it follows DD4: Esc cancels (swallowed), a fresh non-modifier press cancels and goes through, a second chord is swallowed, and modifier presses, repeats and releases are handled as ever — the chord's modifier presses reached the KVM, so their releases must too, or a paste that ends untyped would leave Ctrl+Option+Shift held on the Mac. While **Typing** it follows §8: the Typist is the only keyboard source; every client press is swallowed and released by the bridge, so no repeat after the paste is a fresh press, and a release updates the state but sends nothing (D3c). Every outcome is an `Out` the shell counts.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/paste.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/{core,mod}.rs` (`mod.rs`: `pub mod paste;` and `pub use paste::{PasteOutcome, PasteRefusal};`, D1a)
- Test: `crates/kvm-rdp/src/input/core.rs` (`tests`, paste cases)

**Interfaces:**
- Consumes: Task 3.1's `kvm_proto::paste::{PastePolicy, Prepared, Typist, RELEASE, prepare, decode_utf16le}`; Task 1.1's `kvm_proto::keymap::{Chord, USAGE_ESC, us_stroke, usage_for_scancode}`; Task 2.1's `Keyboard::{mark_released_by_bridge, is_released_by_bridge, release_all, release, unicode_release, held_modifier_bits, caps_lock_on}`; Task 2.2's `Ctx`/`Event`/`Out`/`release_state`/`push_key`.
- Produces (into `input::core`):
  - `Ctx` gains `pub chord: Chord`, `pub pace: Duration`, `pub modifier_wait: Duration`, `pub multiline_refuse: bool`, `pub max_chars: usize`, `pub queue_room: usize` (the HID queue's free room, `8 - queued` — DD6; D2b).
  - `Event` gains `ClipboardText(Vec<u8>)` (the reassembled `CF_UNICODETEXT` bytes) and `ClipboardAvailable(bool)` (a format list said Unicode text is or is not offered — the core's only availability signal; it stores it, and `on_generation` resets it to `false`, D9c).
  - `Out` gains `RequestClipboard`, `Paste(PasteOutcome)`; `pub enum PasteOutcome { Started, Refused(PasteRefusal), Done { typed: usize, skipped: usize }, Aborted(&'static str) }` (`"esc"`, `"key"`, `"mouse"`, `"release"`, `"modifier_wait"`); `pub enum PasteRefusal { NoText, CapsLock, Multiline, Oversize }` (`Oversize` is the shell's, Task 3.3; the core never builds it).
  - `input::paste::{State, ROOM_POLL}` (`ROOM_POLL = 2 ms`: how soon a typing step that found no queue room looks again).

- [ ] **Step 1: Write the failing tests.** In `input/core.rs`'s tests, the `Rig` gains `room: usize` (default 1), its `ctx()` fills the new fields (`chord: Chord::parse("ctrl+option+shift+v").unwrap()`, `pace: Duration::ZERO`, `modifier_wait: Duration::from_secs(5)`, `multiline_refuse: false`, `max_chars: 4096`, `queue_room: self.room`), and `Rig::new()` ends by stepping `Event::ClipboardAvailable(true)` (D9c):

```rust
        fn new() -> Rig {
            let mut r = Rig { core: InputCore::new(), now: Instant::now(), epoch: 0, room: 1 };
            r.step(Event::ClipboardAvailable(true));
            r
        }
```

Then append:

```rust
    fn chord_event() -> Event {
        // The chord is ctrl+option+shift+v; press V (0x2F) with them held.
        Event::KeyPressed { code: 0x2F, extended: false }
    }

    fn hold_chord(r: &mut Rig) {
        for code in [0x1D, 0x38, 0x2A] {
            // LCtrl, LAlt, LShift
            r.step(Event::KeyPressed { code, extended: false });
        }
    }

    fn outcomes(out: &[Out]) -> Vec<&PasteOutcome> {
        out.iter().filter_map(|o| if let Out::Paste(p) = o { Some(p) } else { None }).collect()
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// The chord, its release, and `text` arriving: typing has begun. The
    /// outs of the step the text arrived in.
    fn start_paste(r: &mut Rig, text: &str) -> Vec<Out> {
        hold_chord(r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased { code, extended: false });
        }
        r.step(Event::ClipboardText(utf16le(text)))
    }

    /// Ticks until the paste ends; its outcome.
    fn finish(r: &mut Rig) -> PasteOutcome {
        for _ in 0..64 {
            r.advance(Duration::from_millis(1));
            let o = r.step(Event::Tick);
            if let Some(p) = outcomes(&o).first() {
                return (*p).clone();
            }
        }
        panic!("the paste never ended");
    }

    /// §8: the chord (matched before any remap) with text available starts
    /// a paste and requests the clipboard; the chord's key never reaches
    /// the KVM.
    #[test]
    fn the_chord_starts_a_paste_and_swallows_its_key() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        let before = r.now;
        let out = r.step(chord_event());
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Started]));
        assert!(out.iter().any(|o| matches!(o, Out::RequestClipboard)));
        // No keyboard push carries V's usage (0x19).
        assert!(!pushes(&out).iter().any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == 0x19)));
        assert_eq!(r.core.next_deadline(), Some(before + Duration::from_secs(5)));
    }

    #[test]
    fn a_chord_with_no_text_is_swallowed_and_refused() {
        let mut r = Rig::new();
        r.step(Event::ClipboardAvailable(false));
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Refused(PasteRefusal::NoText)]));
        assert!(!out.iter().any(|o| matches!(o, Out::RequestClipboard)));
        assert!(!pushes(&out).iter().any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == 0x19)));
        // V's typematic repeat is not a second chord.
        assert!(outcomes(&r.step(chord_event())).is_empty());
    }

    /// §8: once the modifiers release and the text arrives, the Typist
    /// types it; a client key mid-typing never reaches the KVM (D2b).
    #[test]
    fn a_paste_types_the_text_once_modifiers_release() {
        let mut r = Rig::new();
        let out = start_paste(&mut r, "Hi");
        let typed: Vec<HidFrame> = pushes(&out).into_iter().map(|(f, _)| f).collect();
        assert_eq!(typed, [kbd(MOD_LSHIFT, 0x0B)], "'H' — one report: the rig's queue room is 1");
        assert!(!pushes(&r.step(Event::KeyPressed { code: 0x10, extended: false }))
            .iter()
            .any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == 0x14)));
        assert_eq!(finish(&mut r), PasteOutcome::Done { typed: 2, skipped: 0 });
    }

    /// DD6 (D2b): a step pushes at most `queue_room` Typist reports; with
    /// no room it pushes none and looks again ROOM_POLL later (no spin).
    #[test]
    fn the_typist_never_pushes_more_than_the_queue_room() {
        let mut r = Rig::new();
        assert!(pushes(&start_paste(&mut r, "abcd")).len() <= 1);
        for _ in 0..3 {
            r.advance(Duration::from_millis(1));
            assert!(pushes(&r.step(Event::Tick)).len() <= 1);
        }
        let mut r = Rig::new();
        r.room = 0;
        assert!(pushes(&start_paste(&mut r, "abcd")).is_empty());
        assert_eq!(r.core.next_deadline(), Some(r.now + crate::input::paste::ROOM_POLL));
        r.room = 3;
        r.advance(crate::input::paste::ROOM_POLL);
        assert_eq!(pushes(&r.step(Event::Tick)).len(), 3);
    }

    #[test]
    fn caps_lock_refuses_the_paste() {
        let mut r = Rig::new();
        r.step(Event::Synchronize { caps_lock: true });
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Refused(PasteRefusal::CapsLock)]));
    }

    /// DD5 (D8c): a Caps Lock press after a Synchronize is tracked.
    #[test]
    fn a_caps_lock_press_after_a_synchronize_is_tracked() {
        let mut r = Rig::new();
        r.step(Event::Synchronize { caps_lock: false });
        r.step(Event::KeyPressed { code: 0x3A, extended: false });
        r.step(Event::KeyReleased { code: 0x3A, extended: false });
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Refused(PasteRefusal::CapsLock)]));
    }

    /// Review Focus 1 / §8: Esc aborts (and is swallowed), an all-zero
    /// report clears the Typist's press, and Esc's repeats stay silent
    /// until its Released.
    #[test]
    fn esc_aborts_and_the_typists_keys_do_not_leak() {
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        let out = r.step(Event::KeyPressed { code: 0x01, extended: false }); // Esc
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("esc")]));
        assert_eq!(pushes(&out), [(kbd(0, 0), 0)]);
        assert!(pushes(&r.step(Event::KeyPressed { code: 0x01, extended: false })).is_empty());
        assert!(pushes(&r.step(Event::KeyReleased { code: 0x01, extended: false })).is_empty());
        assert_eq!(pushes(&r.step(Event::KeyPressed { code: 0x01, extended: false })), [(kbd(0, 0x29), 0)]);
    }

    /// D3c: a key pressed mid-typing is released by the bridge — after the
    /// paste, its repeats push nothing until its Released.
    #[test]
    fn a_key_swallowed_during_a_paste_stays_released_after_it() {
        let mut r = Rig::new();
        start_paste(&mut r, "ab");
        r.step(Event::KeyPressed { code: 0x10, extended: false }); // q, mid-typing
        assert!(matches!(finish(&mut r), PasteOutcome::Done { .. }));
        assert!(pushes(&r.step(Event::KeyPressed { code: 0x10, extended: false })).is_empty());
        assert!(pushes(&r.step(Event::KeyReleased { code: 0x10, extended: false })).is_empty());
        assert_eq!(pushes(&r.step(Event::KeyPressed { code: 0x10, extended: false })), [(kbd(0, 0x14), 0)]);
    }

    /// §8 (D3c): a §7.4 trigger aborts typing — a bumped epoch and a
    /// Synchronize each end it, with an all-zero report at the epoch.
    #[test]
    fn a_bumped_epoch_or_synchronize_aborts_typing() {
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        r.epoch = 7;
        let out = r.step(Event::MouseMove { x: 1, y: 1 });
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("release")]), "{out:?}");
        assert!(pushes(&out).contains(&(kbd(0, 0), 7)));
        r.advance(Duration::from_millis(1));
        assert!(pushes(&r.step(Event::Tick)).is_empty(), "nothing more is typed");
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        let out = r.step(Event::Synchronize { caps_lock: false });
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("release")]), "{out:?}");
        assert!(out.iter().any(|o| matches!(o, Out::Release(ReleaseTrigger::Synchronize))));
    }

    /// Review Focus 5 / DD4: a paste pending past modifier_wait with no
    /// response ends; a late or unasked response then types nothing.
    #[test]
    fn a_late_or_unasked_clipboard_response_types_nothing() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        r.advance(Duration::from_secs(6)); // past modifier_wait (5 s)
        let out = r.step(Event::Tick);
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("modifier_wait")]));
        assert!(pushes(&r.step(Event::ClipboardText(utf16le("x")))).is_empty());
    }

    /// DD4: while pending, a fresh non-modifier press cancels the paste and
    /// goes through (with the modifiers the KVM already holds); a second
    /// chord meanwhile is swallowed.
    #[test]
    fn a_fresh_key_while_pending_cancels_and_goes_through() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::KeyPressed { code: 0x2D, extended: false }); // x
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("key")]));
        assert_eq!(pushes(&out), [(kbd(0x07, 0x1B), 0)]);
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        r.step(Event::KeyReleased { code: 0x2F, extended: false });
        let out = r.step(chord_event());
        assert!(outcomes(&out).is_empty() && pushes(&out).is_empty(), "{out:?}");
    }

    #[test]
    fn a_mouse_button_aborts_a_paste() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::MouseButton { button: Button::Left, pressed: true, x: 0, y: 0 });
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("mouse")]));
    }
```

and in the test module's imports: `use crate::input::paste::{PasteOutcome, PasteRefusal}; use kvm_proto::keymap::{Chord, MOD_LSHIFT};` (`Button` and `ReleaseTrigger` are already in scope through `super::*`).

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- input::core` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Create `crates/kvm-rdp/src/input/paste.rs`:

```rust
//! The paste state machine (§8), sans-IO: the core calls into it per event
//! and per step. It owns no clock; `Ctx::now` and the deadlines come from
//! the core. The Typist is the only keyboard source while typing; client
//! keyboard input is swallowed (Esc aborts), mouse motion passes, a mouse
//! button or a §7.4 trigger aborts.
use kvm_proto::paste::Typist;
use std::time::{Duration, Instant};

/// How soon a typing step that found no HID queue room looks again (DD6):
/// short against any pace, long enough that the driver never spins.
pub const ROOM_POLL: Duration = Duration::from_millis(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteRefusal {
    NoText,
    CapsLock,
    Multiline,
    Oversize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteOutcome {
    Started,
    Refused(PasteRefusal),
    Done { typed: usize, skipped: usize },
    Aborted(&'static str),
}

pub enum State {
    Idle,
    /// Waiting for the clipboard text and for every physical modifier to
    /// release, until `deadline`.
    Pending { deadline: Instant, text: Option<Vec<char>>, skipped: usize },
    /// Typing; `next_report_at` paces the Typist.
    Typing { typist: Typist, typed: usize, skipped: usize, next_report_at: Instant },
}

impl State {
    #[must_use]
    pub fn is_active(&self) -> bool {
        !matches!(self, State::Idle)
    }

    /// When the core next needs a step for the paste: Pending's deadline,
    /// or Typing's next report.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            State::Idle => None,
            State::Pending { deadline, .. } => Some(*deadline),
            State::Typing { next_report_at, .. } => Some(*next_report_at),
        }
    }
}
```

In `input/core.rs`:

- Imports gain `use crate::input::paste::{PasteOutcome, PasteRefusal, ROOM_POLL, State};`, `use kvm_proto::keymap::{Chord, USAGE_ESC};` and `use kvm_proto::paste::{PastePolicy, Prepared, RELEASE, Typist, decode_utf16le, prepare};`.
- `Ctx`, `Event` and `Out` gain the fields and variants in Interfaces.
- `InputCore` gains `paste: State` (`State::Idle` in `new`) and `clipboard_text: bool` (`false` in `new`); `on_generation` also sets `self.paste = State::Idle` and `self.clipboard_text = false` (D9c).
- `next_deadline` becomes `[self.key_repeat_at, self.modifier_idle_at, self.paste.deadline()].into_iter().flatten().min()`.
- `release_state` gains a `ctx: &Ctx` parameter (its three callers pass theirs) and begins `if self.paste.is_active() { self.end_paste(ctx, PasteOutcome::Aborted("release"), out); }` — §8: a §7.4 trigger aborts (D3c).
- `step` becomes:

```rust
    pub fn step(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) {
        self.pointer.set_surface(ctx.surface.0, ctx.surface.1);
        self.keys.set_mac_remap(ctx.mac_remap); // D8a: applied at report time
        // The release channel: a moved epoch releases before the event.
        if ctx.epoch != self.seen_epoch {
            self.seen_epoch = ctx.epoch;
            let r = self.release_state(ctx, out);
            out.push(Out::Push {
                frame: r.frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
        if let Some(event) = self.paste_filter(ctx, event, out) {
            self.handle(ctx, event, out);
        }
        self.paste_step(ctx, out);
        self.arm(ctx);
    }
```

- `handle` gains two arms, and `Synchronize` and `timers` pass `ctx` to `release_state`; after a Synchronize or timer release, if that release aborted typing, `end_paste` has already pushed the all-zero report:

```rust
            Event::ClipboardAvailable(text) => self.clipboard_text = text,
            Event::ClipboardText(bytes) => self.clipboard_text_arrived(ctx, &bytes, out),
```

- and the paste functions:

```rust
    /// §8's input rules around a paste: DD4's while Pending, §8's "while
    /// typing" list while Typing. `None`: the event was swallowed.
    fn paste_filter(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) -> Option<Event> {
        let active = self.paste.is_active();
        let typing = matches!(self.paste, State::Typing { .. });
        match event {
            // The chord starts a paste; a second one meanwhile is swallowed.
            Event::KeyPressed { code, extended } if self.is_chord(ctx, code, extended) => {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(usage_for_scancode(code, extended), out);
                if !active {
                    self.start_paste(ctx, out);
                }
                None
            }
            // Esc aborts, Pending or Typing, and is itself swallowed.
            Event::KeyPressed { code, extended }
                if active && usage_for_scancode(code, extended) == Some(USAGE_ESC) =>
            {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(Some(USAGE_ESC), out);
                self.end_paste(ctx, PasteOutcome::Aborted("esc"), out);
                None
            }
            // Typing: every client press is swallowed and released by the
            // bridge; a release updates the state (all-zero since typing
            // began) and sends nothing (§8, D3c).
            Event::KeyPressed { code, extended } if typing => {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(usage_for_scancode(code, extended), out);
                None
            }
            Event::UnicodePressed(unit) if typing => {
                self.last_kbd_event = Some(ctx.now);
                let usage = char::from_u32(u32::from(unit)).and_then(us_stroke).map(|s| s.usage);
                self.swallow_press(usage, out);
                None
            }
            Event::KeyReleased { code, extended } if typing => {
                self.last_kbd_event = Some(ctx.now);
                if !self.keys.release(code, extended).is_some_and(|r| !r.dropped) {
                    out.push(Out::Ignored);
                }
                None
            }
            Event::UnicodeReleased(unit) if typing => {
                self.last_kbd_event = Some(ctx.now);
                if !self.keys.unicode_release(unit).is_some_and(|r| !r.dropped) {
                    out.push(Out::Ignored);
                }
                None
            }
            // Pending: a fresh non-modifier press cancels and goes through
            // (DD4). Modifier presses, repeats and releases fall through to
            // `handle` as ever, so the KVM's state follows the client's.
            Event::KeyPressed { code, extended } if active && self.is_fresh(usage_for_scancode(code, extended)) => {
                self.end_paste(ctx, PasteOutcome::Aborted("key"), out);
                Some(event)
            }
            Event::UnicodePressed(unit)
                if active && self.is_fresh(char::from_u32(u32::from(unit)).and_then(us_stroke).map(|s| s.usage)) =>
            {
                self.end_paste(ctx, PasteOutcome::Aborted("key"), out);
                Some(event)
            }
            Event::MouseButton { .. } if active => {
                self.end_paste(ctx, PasteOutcome::Aborted("mouse"), out);
                Some(event) // the click itself goes through
            }
            other => Some(other),
        }
    }

    /// The chord: matched on the raw scancode and the raw held bits (§8),
    /// and never on a repeat of a key the bridge released (a held V).
    fn is_chord(&self, ctx: &Ctx, code: u8, extended: bool) -> bool {
        usage_for_scancode(code, extended).is_some_and(|u| !self.keys.is_released_by_bridge(u))
            && ctx.chord.matches(code, extended, self.keys.held_modifier_bits())
    }

    /// A new press of a non-modifier key: not a modifier, not a repeat of a
    /// held key, not a released-by-bridge key's repeat.
    fn is_fresh(&self, usage: Option<u8>) -> bool {
        usage.is_some_and(|u| {
            modifier_bit(u).is_none() && !self.keys.is_down(u) && !self.keys.is_released_by_bridge(u)
        })
    }

    /// A swallowed press is released by the bridge (D3c): its repeats after
    /// the paste are not fresh presses. Unmapped or unremembered: counted.
    fn swallow_press(&mut self, usage: Option<u8>, out: &mut Vec<Out>) {
        if !usage.is_some_and(|u| self.keys.mark_released_by_bridge(u)) {
            out.push(Out::Ignored);
        }
    }

    fn start_paste(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        let refusal = if !self.clipboard_text {
            Some(PasteRefusal::NoText)
        } else if self.keys.caps_lock_on() {
            Some(PasteRefusal::CapsLock)
        } else {
            None
        };
        if let Some(why) = refusal {
            out.push(Out::Paste(PasteOutcome::Refused(why)));
            return;
        }
        self.paste = State::Pending {
            deadline: ctx.now + ctx.modifier_wait,
            text: None,
            skipped: 0,
        };
        out.push(Out::Paste(PasteOutcome::Started));
        out.push(Out::RequestClipboard);
    }

    /// DD4: only a paste that is Pending and has no text yet takes a
    /// response; any other response types nothing.
    fn clipboard_text_arrived(&mut self, ctx: &Ctx, bytes: &[u8], out: &mut Vec<Out>) {
        if !matches!(self.paste, State::Pending { text: None, .. }) {
            return;
        }
        let (decoded, bad) = decode_utf16le(bytes);
        let policy = PastePolicy {
            multiline_refuse: ctx.multiline_refuse,
            max_chars: ctx.max_chars,
        };
        match prepare(&decoded, &policy) {
            (Prepared::RefusedMultiline, _) => {
                self.end_paste(ctx, PasteOutcome::Refused(PasteRefusal::Multiline), out);
            }
            (Prepared::Text(chars), s) => {
                if let State::Pending { text, skipped, .. } = &mut self.paste {
                    *text = Some(chars);
                    *skipped = s.skipped.saturating_add(bad);
                }
            }
        }
    }

    /// End an active paste with `outcome`. If it was typing, the Typist may
    /// have left a press on the KVM: an all-zero report follows, stamped
    /// with the step's epoch (the core's keyboard state is all-zero while
    /// typing, so the two agree; §8: "abort and completion both end with an
    /// all-zero keyboard report"). A Pending paste sent nothing of its own:
    /// the KVM already holds exactly the core's state.
    fn end_paste(&mut self, ctx: &Ctx, outcome: PasteOutcome, out: &mut Vec<Out>) {
        let was_typing = matches!(self.paste, State::Typing { .. });
        self.paste = State::Idle;
        out.push(Out::Paste(outcome));
        if was_typing {
            out.push(Out::Push {
                frame: RELEASE,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
    }

    /// Every step's tail: Pending's deadline and its move to Typing, then
    /// Typing's paced, room-bounded reports (DD6, D2b).
    fn paste_step(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        self.paste = match std::mem::replace(&mut self.paste, State::Idle) {
            State::Pending { text: Some(chars), skipped, .. } if self.keys.held_modifier_bits() == 0 => {
                // From here the Typist is the only keyboard source: what the
                // client still holds is released by the bridge, and the
                // Typist's first full-state report zeroes it on the KVM.
                if self.keys.release_all().dropped {
                    out.push(Out::Ignored);
                }
                self.type_some(ctx, Typist::new(&chars), 0, skipped, ctx.now, out)
            }
            State::Pending { deadline, .. } if ctx.now >= deadline => {
                out.push(Out::Paste(PasteOutcome::Aborted("modifier_wait")));
                State::Idle
            }
            State::Typing { typist, typed, skipped, next_report_at } => {
                self.type_some(ctx, typist, typed, skipped, next_report_at, out)
            }
            other => other,
        };
    }

    /// At most `ctx.queue_room` reports, each only when its time has come;
    /// after each, the next is `pace` from now (no catch-up burst). With no
    /// room, look again `ROOM_POLL` from now.
    fn type_some(
        &mut self,
        ctx: &Ctx,
        mut typist: Typist,
        mut typed: usize,
        skipped: usize,
        mut next_report_at: Instant,
        out: &mut Vec<Out>,
    ) -> State {
        if ctx.queue_room == 0 {
            next_report_at = next_report_at.max(ctx.now + ROOM_POLL);
        }
        let mut room = ctx.queue_room;
        while room > 0 && ctx.now >= next_report_at {
            let Some(frame) = typist.next() else {
                break;
            };
            if frame != RELEASE {
                typed = typed.saturating_add(1);
            }
            out.push(Out::Push {
                frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
            room -= 1;
            next_report_at = ctx.now + ctx.pace;
        }
        if typist.is_done() {
            out.push(Out::Paste(PasteOutcome::Done { typed, skipped }));
            return State::Idle;
        }
        State::Typing { typist, typed, skipped, next_report_at }
    }
```

`type_some` borrows nothing of `self` but is a method for readability; if clippy's `unused_self` fires, make it an associated function (`Self::type_some(ctx, …)`). `Chord` is used by `Ctx`; `modifier_bit`, `us_stroke` and `usage_for_scancode` are already imported (Task 2.2).

Add to `input/mod.rs`, after `pub mod keys;`: `pub mod paste;`, and after the `pub use core::…` line: `pub use paste::{PasteOutcome, PasteRefusal};`.

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- input::core` — Expected: PASS — 25 passed (Task 2.2's 13 and these 12).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/input/paste.rs crates/kvm-rdp/src/input/core.rs crates/kvm-rdp/src/input/mod.rs
git commit -m "kvm-rdp: the paste state machine wired into the input core (§8)" \
  -m "Swallowed keys are released by the bridge; typing never pushes more than the HID queue has room for (DD6)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 3.3: CLIPRDR — a per-connection backend bound to its generation, and a Fatal input

The clipboard is IronRDP's own `CliprdrServer` with a backend the bridge supplies. The backend advertises no capabilities of its own, records only that Unicode text is offered (`on_remote_copy`, D18), and delivers a format-data response (`on_format_data_response`) to the input shell — both tagged with the connection's slot, so the shell routes them to the input core only for the current generation (as GFX callbacks are, §4.3). The bridge requests text with `ServerEvent::Clipboard(ClipboardMessage::SendInitiatePaste(CF_UNICODETEXT))`. A response larger than `paste.max_bytes` after reassembly ends the session with cause `clipboard_oversize` (§8), through a new `RdpInput::Fatal` that the shell steps as `Input::UpstreamFatal` — whose `close` counts the cause once (D17). The factory also keeps IronRDP's `ServerEvent` sender, handed over in `RdpServer::new`, in a shared `OnceLock` the input shell reads in Task 4.1 (D9a).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/clipboard.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/mod.rs` (`pub mod clipboard;`), `src/msg.rs` (`RdpInput::Fatal`, `RdpInput::Clipboard*`, `SessionStart::clip_slot`), `src/rdp/server.rs` (`ServerParts::cliprdr`, `with_cliprdr_factory`), `src/rdp/handler.rs` (bind the clipboard slot; its test rig), `src/pump/shell.rs` (route `Fatal`; drop the other two until Task 4.1; its test rigs), `src/bridge.rs` (build and wire the factory), `Cargo.toml` (`ironrdp-cliprdr`)
- Test: `crates/kvm-rdp/src/rdp/clipboard.rs` (`tests`)

**Interfaces:**
- Consumes: `ironrdp_cliprdr::{CliprdrServer, backend::{CliprdrBackend, CliprdrBackendFactory, ClipboardMessage}, pdu::{ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FormatDataRequest, FormatDataResponse, LockDataId}}`, `ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender}`.
- Produces:
  - `rdp::clipboard::{ClipFactory, ClipSlot, ServerEvents, take_latest_clip}`: `ClipFactory::new(slot_src: Arc<AtomicU64>, latest: ClipSlot, to_pump: UnboundedSender<RdpInput>, max_bytes: usize, events: ServerEvents)`; `pub type ClipSlot = Arc<Mutex<Option<u64>>>`; `pub type ServerEvents = Arc<std::sync::OnceLock<UnboundedSender<ServerEvent>>>` (set once by `ClipFactory::set_sender`, read by Task 4.1's input shell, D9a); `pub fn take_latest_clip(slot: &ClipSlot) -> Option<u64>`.
  - `msg::RdpInput::SessionStart` gains `clip_slot: Option<u64>`; `rdp::server::ServerParts` gains `pub cliprdr: ClipFactory` (concrete, as `gfx: GfxFactory` is: `CliprdrServerFactory` has no `Send` supertrait and `ServerParts` moves to the RDP thread, D1d).
  - `msg::RdpInput` gains `ClipboardAvailable { slot: u64, text: bool }`, `ClipboardText { slot: u64, bytes: Vec<u8> }`, `Fatal { slot: u64, cause: Cause }`.
  - `ServerEvent::Clipboard(ClipboardMessage::SendInitiatePaste(ClipboardFormatId::CF_UNICODETEXT))` — how the shell requests text (Task 4.1 sends it).

- [ ] **Step 1: Write the failing test.** `rdp/clipboard.rs`'s tests (the backend is driven directly, as IronRDP would):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use tokio::sync::mpsc::UnboundedReceiver;

    fn factory_with(max_bytes: usize) -> (ClipFactory, ClipSlot, UnboundedReceiver<RdpInput>, ServerEvents) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let latest = ClipSlot::default();
        let events = ServerEvents::default();
        let f = ClipFactory::new(Arc::new(AtomicU64::new(0)), latest.clone(), tx, max_bytes, events.clone());
        (f, latest, rx, events)
    }

    fn factory() -> (ClipFactory, ClipSlot, UnboundedReceiver<RdpInput>) {
        let (f, slot, rx, _) = factory_with(64 * 1024);
        (f, slot, rx)
    }

    /// The backend advertises nothing of its own (§8: the server advertises
    /// no clipboard capabilities).
    #[test]
    fn the_backend_advertises_no_capabilities() {
        let (f, _slot, _rx) = factory();
        let b = f.build_cliprdr_backend();
        assert!(b.client_capabilities().is_empty());
    }

    /// `build_cliprdr_backend` mints a slot and records it as the latest,
    /// as the GFX factory does; the backend tags its inputs with it. Only
    /// CF_UNICODETEXT — the one format the bridge requests — is text (D18).
    #[test]
    fn a_backend_mints_and_records_its_slot() {
        let (f, slot, mut rx) = factory();
        let mut b = f.build_cliprdr_backend();
        assert_eq!(take_latest_clip(&slot), Some(1));
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert!(matches!(rx.try_recv(), Ok(RdpInput::ClipboardAvailable { slot: 1, text: true })));
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_BITMAP)]);
        assert!(matches!(rx.try_recv(), Ok(RdpInput::ClipboardAvailable { slot: 1, text: false })));
        b.on_remote_copy(&[
            ClipboardFormat::new(ClipboardFormatId::CF_TEXT),
            ClipboardFormat::new(ClipboardFormatId::CF_OEMTEXT),
        ]);
        assert!(matches!(rx.try_recv(), Ok(RdpInput::ClipboardAvailable { slot: 1, text: false })));
    }

    /// D9a: IronRDP hands the factory its `ServerEvent` sender; the input
    /// shell reads it from the shared cell.
    #[test]
    fn set_sender_fills_the_shared_cell_once() {
        let (mut f, _slot, _rx, events) = factory_with(64);
        assert!(events.get().is_none());
        let (tx, _erx) = tokio::sync::mpsc::unbounded_channel();
        f.set_sender(tx);
        assert!(events.get().is_some());
    }

    /// A text response under the cap becomes `ClipboardText`; an oversize
    /// one becomes `Fatal(ClipboardOversize)` (§8), and the data is never
    /// Debug-formatted (§9.2: assert by construction — no Debug call here).
    #[test]
    fn a_response_routes_text_or_a_fatal_oversize() {
        let (f, _slot, mut rx, _) = factory_with(8);
        let mut b = f.build_cliprdr_backend();
        b.on_format_data_response(FormatDataResponse::new_unicode_string("hi"));
        assert!(matches!(rx.try_recv(), Ok(RdpInput::ClipboardText { slot: 1, bytes }) if !bytes.is_empty()));
        b.on_format_data_response(FormatDataResponse::new_unicode_string("far too long"));
        assert!(matches!(rx.try_recv(), Ok(RdpInput::Fatal { slot: 1, cause: Cause::ClipboardOversize })));
        // An error response types nothing.
        b.on_format_data_response(FormatDataResponse::new_error());
        assert!(rx.try_recv().is_err());
    }
}
```

(`ClipboardFormat`, `ClipboardFormatId` and `FormatDataResponse` come from the module's own imports through `super::*`; the tokio receiver is read with `try_recv`.)

- [ ] **Step 2: Run it to see it fail.** `cargo test --workspace --all-features --lib -- rdp::clipboard` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Add to `crates/kvm-rdp/Cargo.toml` under `[dependencies]`: `ironrdp-cliprdr = { workspace = true }`, and to `[workspace.dependencies]` in the root `Cargo.toml` an `ironrdp-cliprdr` entry at the same `rev` as the others (it is already compiled inside `ironrdp-server`'s graph, so no new compile unit; `cargo tree -d` stays clean). Add `RdpInput::ClipboardAvailable { slot, text }`, `RdpInput::ClipboardText { slot, bytes }` and `RdpInput::Fatal { slot, cause }` to `msg.rs`'s enum and its `Debug` impl (`"ClipboardAvailable"`, `"ClipboardText"`, `"Fatal"`). Create `crates/kvm-rdp/src/rdp/clipboard.rs`:

```rust
//! Clipboard paste (§8), server side: IronRDP's `CliprdrServer` with a
//! backend that advertises nothing, records only that text is offered, and
//! hands a format-data response to the input shell — one backend per
//! connection, tagged with its slot like the GFX handle (§4.3). The data
//! itself is never logged or Debug-formatted (§9.2). One way only: nothing
//! reads the Mac's clipboard.
use crate::msg::{Cause, RdpInput};
use ironrdp_cliprdr::backend::{CliprdrBackend, CliprdrBackendFactory};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tokio::sync::mpsc::UnboundedSender;

pub type ClipSlot = Arc<Mutex<Option<u64>>>;

/// IronRDP's `ServerEvent` sender. It exists only once `RdpServer::new`
/// has run (it calls `set_sender` on this factory), after `ServerParts` is
/// built, so the input shell reads it from this shared cell (D9a).
pub type ServerEvents = Arc<OnceLock<UnboundedSender<ServerEvent>>>;

#[must_use]
pub fn take_latest_clip(slot: &ClipSlot) -> Option<u64> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

pub struct ClipFactory {
    slot_src: Arc<AtomicU64>,
    latest: ClipSlot,
    to_pump: UnboundedSender<RdpInput>,
    max_bytes: usize,
    events: ServerEvents,
}

impl ClipFactory {
    #[must_use]
    pub fn new(
        slot_src: Arc<AtomicU64>,
        latest: ClipSlot,
        to_pump: UnboundedSender<RdpInput>,
        max_bytes: usize,
        events: ServerEvents,
    ) -> ClipFactory {
        ClipFactory { slot_src, latest, to_pump, max_bytes, events }
    }
}

impl ServerEventSender for ClipFactory {
    /// Called once, inside `RdpServer::new` (server.rs:1647–1648): keep the
    /// sender for the input shell's `SendInitiatePaste` (Task 4.1).
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        let _ = self.events.set(sender);
    }
}

impl CliprdrBackendFactory for ClipFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        let slot = self.slot_src.fetch_add(1, Ordering::SeqCst).wrapping_add(1).max(1);
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(slot);
        Box::new(ClipBackend {
            slot,
            to_pump: self.to_pump.clone(),
            max_bytes: self.max_bytes,
        })
    }
}

impl CliprdrServerFactory for ClipFactory {}

struct ClipBackend {
    slot: u64,
    to_pump: UnboundedSender<RdpInput>,
    max_bytes: usize,
}

// `CliprdrBackend: AsAny + Debug + Send`, and `AsAny` has no blanket impl
// (ironrdp-core as_any.rs) — D1c.
ironrdp_core::impl_as_any!(ClipBackend);

impl std::fmt::Debug for ClipBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render clipboard contents (§9.2); this backend holds none,
        // but the derive would still be a foot-gun if a field were added.
        f.debug_struct("ClipBackend").field("slot", &self.slot).finish()
    }
}

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        "." // No file transfer (§8 non-goals); never used.
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {}

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    /// The client announced its formats: record only whether Unicode text
    /// — the one format the bridge requests — is there (D18). A client that
    /// offers only ANSI text gets a `no_text` refusal at once, not a 5 s
    /// wait that ends in `modifier_wait`.
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let text = formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT);
        let _ = self.to_pump.send(RdpInput::ClipboardAvailable { slot: self.slot, text });
    }

    fn on_format_data_request(&mut self, _request: FormatDataRequest) {
        // The server offers nothing to copy from the Mac (§8 non-goals).
    }

    /// The response to our paste request. Under the cap → the bytes;
    /// over it → fatal `clipboard_oversize` (§8), counted once, by the
    /// pump's `close` (D17). Never logged.
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            return;
        }
        let data = response.data();
        if data.len() > self.max_bytes {
            let _ = self.to_pump.send(RdpInput::Fatal {
                slot: self.slot,
                cause: Cause::ClipboardOversize,
            });
            return;
        }
        let _ = self.to_pump.send(RdpInput::ClipboardText {
            slot: self.slot,
            bytes: data.to_vec(),
        });
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: ironrdp_cliprdr::pdu::FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}
```

The backend counts nothing: the shell steps the `Fatal` as `Input::UpstreamFatal`, and `close` already counts its cause (pump/core.rs:501), so a backend `inc` would count it twice — and a stale slot's `Fatal`, which the shell drops, would count a disconnect that never happens (D17).

In `src/rdp/server.rs`, add `pub cliprdr: crate::rdp::clipboard::ClipFactory` to `ServerParts`, and `.with_cliprdr_factory(Some(Box::new(p.cliprdr)))` to `build`'s chain right after `.with_gfx_factory(Some(Box::new(p.gfx)))` (D1d). In `src/rdp/handler.rs`, add `pub clip: crate::rdp::clipboard::ClipSlot` to `Lifecycle` and, in `on_connection_info` right after taking the GFX slot, `let clip_slot = crate::rdp::clipboard::take_latest_clip(&self.clip);` and include it in the `RdpInput::SessionStart` (add a `clip_slot: Option<u64>` field to that variant in `msg.rs`).

In `src/pump/shell.rs` (D19, the interim routing until Task 4.1):
- `Link` gains `clip_slot: Option<u64>`, set from `SessionStart`'s new field (add `clip_slot` to the destructure at shell.rs:236–242 and to the `Link` it builds).
- `RdpInput::Fatal { slot, cause }`: when `self.link` is `Some` and its `clip_slot == Some(slot)`, step `Input::UpstreamFatal(cause)` exactly as the other fatal inputs do; any other slot is stale and dropped, as `GfxClosed` is.
- `RdpInput::ClipboardAvailable { .. } | RdpInput::ClipboardText { .. } => {} // Task 4.1 routes these to the input core.`

The struct literals the new fields reach: `clip: ClipSlot::default()` in the `Lifecycle` test rigs at handler.rs:166 and pump/shell.rs:1039; `clip_slot: Some(1)` in the test `SessionStart` send at pump/shell.rs:797.

In `src/bridge.rs` `spawn`, beside `gfx_slot`: `let clip_slot = ClipSlot::default(); let server_events = ServerEvents::default();` (Task 4.1 hands `server_events` to the input shell too). `ServerParts` gains `cliprdr: ClipFactory::new(Arc::new(AtomicU64::new(0)), clip_slot.clone(), to_pump.clone(), cfg.paste.max_bytes, server_events.clone())` — the factory itself, by value — and `Lifecycle` gains `clip: clip_slot`.

- [ ] **Step 4: Run the test.** `cargo test --workspace --all-features --lib -- rdp::clipboard` — Expected: PASS — 4 passed. `cargo test --workspace --all-features --lib -- rdp::handler pump::shell` — Expected: PASS (the rigs with the new fields; the shell's existing cases). `nix develop --command cargo tree -d 2>&1 | grep -c ironrdp` — Expected: `0` (no duplicate `ironrdp-*`).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add Cargo.toml crates/kvm-rdp/Cargo.toml crates/kvm-rdp/src/rdp/clipboard.rs crates/kvm-rdp/src/rdp/mod.rs \
  crates/kvm-rdp/src/rdp/server.rs crates/kvm-rdp/src/rdp/handler.rs crates/kvm-rdp/src/msg.rs \
  crates/kvm-rdp/src/pump/shell.rs crates/kvm-rdp/src/bridge.rs Cargo.lock
git commit -m "kvm-rdp: CLIPRDR — a per-connection backend bound to its generation; clipboard_oversize is fatal (§8)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Part 4 — Wiring the input path into the bridge

### Task 4.1: the input handler, the driver, the paste metrics, and assembly

`rdp::input` becomes `InputShared` — the `InputCore` under a `std::sync::Mutex`, beside `HidControl`, `DisplayShared`, the shared `ServerEvent` cell (Task 3.3's `ServerEvents`, filled by IronRDP inside `RdpServer::new`, D9a), `Generations`, the config and the metrics — and the IronRDP `RdpServerInputHandler` that feeds it. `InputShared` is built in `spawn` beside the other parts; a driver task on the RDP `LocalSet` ticks the core at its next deadline. The pump shell forwards the clipboard inputs (Task 3.3) to it and tells it each generation (`0` on `SessionStop`, D27). Every step reads the release epoch and the HID queue's free room into its `Ctx` and pushes with `push_at` (design decision 6); no lock is held across an await (§4.3). Every `feed` caller — the handler, the driver, the pump shell — runs on the one RDP `LocalSet` (bridge.rs `rdp_main`), which is why carrying out the `Out`s after the lock is released keeps their order (D27).

**Files:**
- Rewrite: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/input.rs` (`InputShared`, `InputHandler`, the driver)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/queue.rs` (`pub fn queued(&self) -> usize`), `src/metrics.rs` (paste metrics), `src/pump/shell.rs` (`ShellDeps::input`; route clipboard inputs and the generation to `InputShared`), `src/rdp/server.rs` (`ServerParts::input: InputHandler`) and `src/bridge.rs` (`ShellParts::input`; build in `spawn`, spawn the driver in `rdp_main`)
- Test: `crates/kvm-rdp/src/rdp/input.rs` (`tests`)

**Interfaces:**
- Consumes: `input::{InputCore, Ctx, Event, Out, PasteOutcome, PasteRefusal}` (Tasks 2.2, 3.2: `Out::Ignored`, `Ctx::queue_room: usize`, `Event::MouseButton { button, pressed, x, y }`), `input::pointer::Button`, `hid::HidControl`, Task 3.3's `rdp::clipboard::ServerEvents`, `ironrdp_server::{KeyboardEvent, MouseEvent, MouseButton, RdpServerInputHandler, ServerEvent}`, `ironrdp_cliprdr::{backend::ClipboardMessage, pdu::ClipboardFormatId}`, `ironrdp_pdu::input::fast_path::SynchronizeFlags`.
- Produces:
  - `rdp::input::{InputRuntimeConfig, InputDeps}` — `InputRuntimeConfig::from_config(&Config)` (and `#[cfg(test)] InputRuntimeConfig::test()`); `InputDeps { hid, display, events: ServerEvents, gens, metrics, cfg }`.
  - `rdp::input::InputShared` — `new(InputDeps)`; `set_generation(&self, g: Gen)` (`0` = no session); `keyboard(&self, KeyboardEvent)`; `mouse(&self, MouseEvent)`; `clipboard_available(&self, text: bool)`; `clipboard_text(&self, bytes: Vec<u8>)`; `async fn run_driver(self: Arc<Self>)`.
  - `rdp::input::InputHandler` — `new(shared: Arc<InputShared>)`, `impl RdpServerInputHandler`.
  - `hid::HidControl::queued(&self) -> usize`.
  - metrics `kvm_rdp_paste_events_total{outcome}` (`started`, `done`, `no_text`, `caps_lock`, `multiline`, `oversize`, `aborted`) and `kvm_rdp_paste_skipped_chars_total`.

- [ ] **Step 1: Write the failing test.** `rdp/input.rs`'s tests drive `InputShared` directly (no IronRDP), on a `current_thread` runtime, asserting on kvm-sim-free pieces — the `HidControl`'s drained frames and the metrics:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::hid::ReleaseTrigger;
    use crate::msg::Generations;
    use crate::rdp::clipboard::ServerEvents;
    use kvm_proto::hid::HidFrame;

    fn shared() -> Arc<InputShared> {
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(256, metrics.clone()));
        let gens = Arc::new(Generations::default());
        gens.begin();
        let display = DisplayShared::new((1920, 1080));
        Arc::new(InputShared::new(InputDeps {
            hid,
            display,
            events: ServerEvents::default(),
            gens: gens.clone(),
            metrics,
            cfg: InputRuntimeConfig::test(),
        }))
    }
    fn drain(h: &HidControl) -> Vec<HidFrame> {
        std::iter::from_fn(|| h.next_frame()).collect()
    }

    /// A scancode press and release reach the HID queue as §3.3 frames,
    /// stamped at the live epoch; every event counts, none is "ignored".
    #[tokio::test(flavor = "current_thread")]
    async fn a_keypress_reaches_the_hid_queue() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed { code: 0x1E, extended: false });
        s.mouse(MouseEvent::Move { x: 960, y: 540 });
        s.keyboard(KeyboardEvent::Released { code: 0x1E, extended: false });
        let got = drain(&s.hid_for_test());
        assert_eq!(got[0], HidFrame::Keyboard { modifiers: 0, keys: [0x04, 0, 0, 0, 0] });
        // 960·32767/1919 and 540·32767/1079 (§7.2, D2a).
        assert!(got.iter().any(|f| matches!(f, HidFrame::AbsMouse { x: 16_392, y: 16_398, .. })));
        assert_eq!(got.last(), Some(&HidFrame::Keyboard { modifiers: 0, keys: [0; 5] }));
    }

    /// DD7: a relative or horizontal-scroll event is dropped and counted.
    #[tokio::test(flavor = "current_thread")]
    async fn unmapped_mouse_events_are_counted_not_mapped() {
        let s = shared();
        s.set_generation(1);
        s.mouse(MouseEvent::RelMove { x: 3, y: 4 });
        s.mouse(MouseEvent::HorizontalScroll { value: 120 });
        assert_eq!(s.metrics_for_test().input_events_ignored.get(), 2);
        assert!(drain(&s.hid_for_test()).is_empty());
    }

    /// DD7 (D8f): an unmapped scancode is dropped by the core and counted
    /// by the shell.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unmapped_scancode_is_counted() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed { code: 0x54, extended: false });
        assert_eq!(s.metrics_for_test().input_events_ignored.get(), 1);
        assert!(drain(&s.hid_for_test()).is_empty());
    }

    /// D8d: a click goes where it was made, with no prior move.
    #[tokio::test(flavor = "current_thread")]
    async fn a_click_carries_its_own_position() {
        let s = shared();
        s.set_generation(1);
        s.mouse(MouseEvent::Button { x: 960, y: 540, button: MouseButton::Left, pressed: true });
        assert_eq!(drain(&s.hid_for_test()), [HidFrame::AbsMouse { buttons: 1, x: 16_392, y: 16_398 }]);
    }

    /// A new generation resets the core, and a release the shell did (an
    /// epoch bump) still lands: a held key does not survive into the new
    /// session.
    #[tokio::test(flavor = "current_thread")]
    async fn a_release_all_from_the_shell_clears_held_state() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed { code: 0x1E, extended: false });
        s.hid_for_test().release_all(ReleaseTrigger::WebsocketReconnect);
        let _ = drain(&s.hid_for_test());
        // The held 'a' is now released-by-bridge: its repeat is swallowed.
        s.keyboard(KeyboardEvent::Pressed { code: 0x1E, extended: false });
        assert!(drain(&s.hid_for_test()).iter().all(|f| !matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == 0x04)));
    }

    /// Paste metrics: a chord with text available counts `started`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_paste_counts_its_outcome() {
        let s = shared();
        s.set_generation(1);
        s.clipboard_available(true);
        for code in [0x1D, 0x38, 0x2A, 0x2F] {
            s.keyboard(KeyboardEvent::Pressed { code, extended: false });
        }
        assert_eq!(s.metrics_for_test().paste_events.get("started"), 1);
    }
}
```

with these test helpers in `rdp/input.rs`, above the tests (D22):

```rust
#[cfg(test)]
impl InputRuntimeConfig {
    pub fn test() -> Self {
        Self {
            mac_remap: false,
            key_repeat_timeout: Duration::from_secs(10),
            modifier_idle_timeout: Duration::from_secs(30),
            chord: Chord::parse("ctrl+option+shift+v").unwrap_or(Chord { classes: 0x07, code: 0x2F }),
            pace: Duration::ZERO,
            modifier_wait: Duration::from_secs(5),
            multiline_refuse: false,
            max_chars: 4096,
        }
    }
}

#[cfg(test)]
impl InputShared {
    pub(crate) fn hid_for_test(&self) -> &HidControl {
        &self.hid
    }

    pub(crate) fn metrics_for_test(&self) -> &Metrics {
        &self.metrics
    }
}
```

- [ ] **Step 2: Run it to see it fail.** `cargo test --workspace --all-features --lib -- rdp::input` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Add `pub fn queued(&self) -> usize { self.q().len() }` to `HidControl`. Add the paste metrics to `Metrics` (a `Family` `paste_events` with label `outcome`, and a `Counter` `paste_skipped_chars`), render them, and widen `every_metric_name_is_unique_and_well_formed`'s count (now 41: 17 counters, 11 families, 8 gauges, 5 histograms — count the exact additions: `paste_skipped_chars` is a counter, `paste_events` a family). Rewrite `crates/kvm-rdp/src/rdp/input.rs`:

```rust
//! The input path (§7, §8), wired: `InputShared` holds the sans-IO
//! `InputCore` under a mutex beside `HidControl`, the display, the server's
//! event sender and the config; `InputHandler` is IronRDP's callback, and
//! `run_driver` ticks the core at its next deadline. Every step reads the
//! release epoch into its `Ctx` and pushes with `push_at`, so a report
//! built before a release never lands after its zeros (§7.3; design
//! decision 6). The mutex is never held across an await (§4.3).
use crate::config::Config;
use crate::hid::HidControl;
use crate::input::core::{Ctx, Event, InputCore, Out};
use crate::input::paste::{PasteOutcome, PasteRefusal};
use crate::input::pointer::Button;
use crate::metrics::Metrics;
use crate::msg::Gen;
use crate::rdp::clipboard::ServerEvents;
use crate::rdp::display::DisplayShared;
use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_cliprdr::pdu::ClipboardFormatId;
use ironrdp_pdu::input::fast_path::SynchronizeFlags;
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler, ServerEvent};
use kvm_proto::keymap::Chord;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// The `input.*`/`paste.*` the core reads, resolved from `Config` once.
#[derive(Debug, Clone)]
pub struct InputRuntimeConfig {
    pub mac_remap: bool,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
    pub chord: Chord,
    pub pace: Duration,
    pub modifier_wait: Duration,
    pub multiline_refuse: bool,
    pub max_chars: usize,
}

impl InputRuntimeConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> InputRuntimeConfig {
        InputRuntimeConfig {
            mac_remap: c.input.mac_remap,
            key_repeat_timeout: c.input.key_repeat_timeout,
            modifier_idle_timeout: c.input.modifier_idle_timeout,
            chord: c.paste.chord,
            pace: c.paste.pace,
            modifier_wait: c.paste.modifier_wait,
            multiline_refuse: matches!(c.paste.multiline, crate::config::Multiline::Refuse),
            max_chars: c.paste.max_chars,
        }
    }
}

pub struct InputDeps {
    pub hid: Arc<HidControl>,
    pub display: Arc<DisplayShared>,
    /// IronRDP's `ServerEvent` sender, once `RdpServer::new` has handed it
    /// to `ClipFactory::set_sender` (D9a).
    pub events: ServerEvents,
    pub gens: Arc<crate::msg::Generations>,
    pub metrics: Arc<Metrics>,
    pub cfg: InputRuntimeConfig,
}

/// The input core and what its `Out`s need. Every `feed` caller — the
/// handler, the driver and the pump shell — runs on the RDP `LocalSet`, so
/// two feeds never interleave their `Out`s. A second thread must carry out
/// `Out::Push`/`Out::Release` under the core lock (D27).
pub struct InputShared {
    core: Mutex<InputCore>,
    hid: Arc<HidControl>,
    display: Arc<DisplayShared>,
    events: ServerEvents,
    gens: Arc<crate::msg::Generations>,
    metrics: Arc<Metrics>,
    cfg: InputRuntimeConfig,
    /// The driver's next wake, in epoch-nanos from a fixed base, or 0 for
    /// "nothing armed"; a `Notify` wakes the driver when it changes.
    deadline: AtomicU64,
    base: Instant,
    wake: Notify,
}

impl InputShared {
    #[must_use]
    pub fn new(d: InputDeps) -> InputShared {
        InputShared {
            core: Mutex::new(InputCore::new()),
            hid: d.hid,
            display: d.display,
            events: d.events,
            gens: d.gens,
            metrics: d.metrics,
            cfg: d.cfg,
            deadline: AtomicU64::new(0),
            base: Instant::now(),
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, InputCore> {
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ctx(&self, now: Instant, generation: Gen) -> Ctx {
        let surface = self.display.surface().unwrap_or_else(|| self.display.size());
        Ctx {
            now,
            epoch: self.hid.epoch(),
            generation,
            surface,
            mac_remap: self.cfg.mac_remap,
            key_repeat_timeout: self.cfg.key_repeat_timeout,
            modifier_idle_timeout: self.cfg.modifier_idle_timeout,
            chord: self.cfg.chord,
            pace: self.cfg.pace,
            modifier_wait: self.cfg.modifier_wait,
            multiline_refuse: self.cfg.multiline_refuse,
            max_chars: self.cfg.max_chars,
            // DD6 (D2b): how many more reports the HID queue takes before
            // a resync, so typing never overflows it.
            queue_room: 8usize.saturating_sub(self.hid.queued()),
        }
    }

    /// Step the core with `event`, under the lock; carry out its `Out`s
    /// with the lock released, and re-arm the driver.
    fn feed(&self, event: Event) {
        let now = Instant::now();
        let outs = {
            let mut core = self.lock();
            // A new generation (set by the shell via `gens`) resets first.
            if let Some(g) = self.gens.current() {
                if core.generation() != g {
                    core.on_generation(g);
                }
            }
            let generation = core.generation();
            let mut outs = Vec::new();
            core.step(&self.ctx(now, generation), event, &mut outs);
            outs
        };
        self.carry_out(outs);
        self.rearm();
    }

    fn carry_out(&self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Push { frame, motion_only, stamp } => {
                    let _ = self.hid.push_at(stamp, frame, motion_only);
                }
                Out::Release(trigger) => self.hid.release_all(trigger),
                Out::Ignored => self.metrics.input_events_ignored.inc(), // DD7, DD9 (D8f)
                Out::RequestClipboard => {
                    // Before `RdpServer::new` there is no sender — and no
                    // connection to paste into (D9a).
                    if let Some(tx) = self.events.get() {
                        let _ = tx.send(ServerEvent::Clipboard(ClipboardMessage::SendInitiatePaste(
                            ClipboardFormatId::CF_UNICODETEXT,
                        )));
                    }
                }
                Out::Paste(outcome) => self.count_paste(&outcome),
            }
        }
    }

    fn count_paste(&self, outcome: &PasteOutcome) {
        let label = match outcome {
            PasteOutcome::Started => "started",
            PasteOutcome::Done { typed: _, skipped } => {
                self.metrics.paste_skipped_chars.add(u64::try_from(*skipped).unwrap_or(0));
                "done"
            }
            PasteOutcome::Refused(PasteRefusal::NoText) => {
                // §8: swallowed *and logged* (D20). Never any content.
                tracing::info!("paste chord with no text on the clipboard");
                "no_text"
            }
            PasteOutcome::Refused(PasteRefusal::CapsLock) => "caps_lock",
            PasteOutcome::Refused(PasteRefusal::Multiline) => "multiline",
            PasteOutcome::Refused(PasteRefusal::Oversize) => "oversize",
            PasteOutcome::Aborted(_) => "aborted",
        };
        self.metrics.paste_events.inc(label);
    }

    fn rearm(&self) {
        let next = self.lock().next_deadline();
        let v = next.map_or(0, |at| {
            u64::try_from(at.saturating_duration_since(self.base).as_nanos()).unwrap_or(u64::MAX)
        });
        self.deadline.store(v, Ordering::SeqCst);
        self.wake.notify_one();
    }

    pub fn set_generation(&self, g: Gen) {
        self.lock().on_generation(g);
        self.rearm();
    }

    pub fn keyboard(&self, e: KeyboardEvent) {
        match to_key_event(e) {
            Some(ev) => self.feed(ev),
            None => self.metrics.input_events_ignored.inc(),
        }
    }

    pub fn mouse(&self, e: MouseEvent) {
        match to_mouse_event(e) {
            Some(ev) => self.feed(ev),
            None => self.metrics.input_events_ignored.inc(),
        }
    }

    pub fn clipboard_available(&self, text: bool) {
        self.feed(Event::ClipboardAvailable(text));
    }

    pub fn clipboard_text(&self, bytes: Vec<u8>) {
        self.feed(Event::ClipboardText(bytes));
    }

    /// Tick the core when a timer or the Typist's pace is due. Lives on the
    /// RDP `LocalSet`; it only locks, steps and sends — never blocks.
    pub async fn run_driver(self: Arc<Self>) {
        loop {
            let d = self.deadline.load(Ordering::SeqCst);
            if d == 0 {
                self.wake.notified().await;
                continue;
            }
            let at = self.base + Duration::from_nanos(d);
            tokio::select! {
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => self.feed(Event::Tick),
                () = self.wake.notified() => {}
            }
        }
    }
}

fn to_key_event(e: KeyboardEvent) -> Option<Event> {
    Some(match e {
        KeyboardEvent::Pressed { code, extended } => Event::KeyPressed { code, extended },
        KeyboardEvent::Released { code, extended } => Event::KeyReleased { code, extended },
        KeyboardEvent::UnicodePressed(u) => Event::UnicodePressed(u),
        KeyboardEvent::UnicodeReleased(u) => Event::UnicodeReleased(u),
        KeyboardEvent::Synchronize(flags) => Event::Synchronize {
            caps_lock: flags.contains(SynchronizeFlags::CAPS_LOCK),
        },
    })
}

fn to_mouse_event(e: MouseEvent) -> Option<Event> {
    match e {
        MouseEvent::Move { x, y } => Some(Event::MouseMove { x, y }),
        // The click's own position rides on the button event (D8d): a
        // click with no prior move goes where it was made, never (0, 0).
        MouseEvent::Button { x, y, button, pressed } => {
            button_for(button).map(|b| Event::MouseButton { button: b, pressed, x, y })
        }
        MouseEvent::VerticalScroll { value } => Some(Event::Wheel { units: value }),
        // DD7: relative motion, X1/X2, horizontal and ainput scroll are
        // dropped and counted by the caller.
        _ => None,
    }
}

fn button_for(b: MouseButton) -> Option<Button> {
    match b {
        MouseButton::Left => Some(Button::Left),
        MouseButton::Right => Some(Button::Right),
        MouseButton::Middle => Some(Button::Middle),
        _ => None, // X1, X2 and any later button (DD7); `MouseButton` is #[non_exhaustive]
    }
}

/// IronRDP's input handler: it only feeds `InputShared` (never blocks the
/// RDP runtime, §4.3).
pub struct InputHandler {
    shared: Arc<InputShared>,
}

impl InputHandler {
    #[must_use]
    pub fn new(shared: Arc<InputShared>) -> InputHandler {
        InputHandler { shared }
    }
}

impl RdpServerInputHandler for InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        self.shared.keyboard(event);
    }
    fn mouse(&mut self, event: MouseEvent) {
        self.shared.mouse(event);
    }
}
```

**Button position:** `MouseEvent::Button` carries the click's own x/y (IronRDP handler.rs:28–45), and the core's `Pointer::button` scales it and moves there (D8d), so a click with no prior move goes where it was made.

Wire it (D9a):
- `src/rdp/server.rs`: `ServerParts::input: crate::rdp::input::InputHandler` (replacing `InputStub`); `build` is unchanged (`.with_input_handler(p.input)`).
- `src/bridge.rs` `spawn`, beside the other parts (after Task 3.3's `server_events`): `let input = Arc::new(InputShared::new(InputDeps { hid: hid.clone(), display: display.clone(), events: server_events.clone(), gens: gens.clone(), metrics: metrics.clone(), cfg: InputRuntimeConfig::from_config(&cfg) }));`. `ServerParts` gets `input: InputHandler::new(input.clone())`; `ShellParts` gains `input: Arc<InputShared>` and gets `input`.
- `rdp_main`: after `server::build`, `tokio::task::spawn_local(shell.input.clone().run_driver());`, and `ShellDeps` gains `pub input: Arc<InputShared>` (filled from `shell.input`).
- `src/pump/shell.rs`: on `SessionStart`, `self.deps.input.set_generation(generation)`; on `SessionStop` (both paths, shell.rs:246 and 273), `self.deps.input.set_generation(0)` — the core resets; the KVM's release is `HidControl`'s `SessionEnd` (D27). Task 3.3's interim arm becomes: `RdpInput::ClipboardAvailable { slot, text }` and `RdpInput::ClipboardText { slot, bytes }` reach `self.deps.input.clipboard_available(text)` / `.clipboard_text(bytes)` only when the link's `clip_slot == Some(slot)`; a stale slot is dropped. `Fatal` stays as Task 3.3 wired it.
- Delete `InputStub` and its test. `InputShared` holds only `Send` types, but it lives on the RDP thread with the server; the handler, the driver and the shell all feed it from that `LocalSet`.

- [ ] **Step 4: Run the test.** `cargo test --workspace --all-features --lib -- rdp::input metrics::` — Expected: PASS (the 6 input tests and the metrics tests, count 41).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/rdp/input.rs crates/kvm-rdp/src/rdp/server.rs crates/kvm-rdp/src/bridge.rs \
  crates/kvm-rdp/src/hid/queue.rs crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/src/pump/shell.rs \
  crates/kvm-rdp/src/config.rs
git commit -m "kvm-rdp: wire the input path — handler, driver, paste metrics, CLIPRDR routing (§7, §8)" \
  -m "The input core steps under one mutex, reads the release epoch per step and pushes with push_at; the driver ticks it at its next deadline. Plan C's counting stub is gone." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 4.2: re-assert the full HID state once a reconnect settles (PC9 fix 2)

After a websocket reconnect, the KVM may still read stale reports that sat in its own receive buffer when the old socket was reset (PC9 fix 2): a stale press can land *after* the new websocket's session-start zeros, leaving a key down on the Mac. The fix is to re-assert the full current HID state once, `REASSERT_AFTER` after the session start, so whatever landed in between is overwritten. The authoritative "full state" is the HID queue's own `latest_kbd`/`latest_mouse` (its resync state), so this lives in the writer.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/queue.rs` (`current_state_frames`), `src/hid/writer.rs` (`REASSERT_AFTER`, the re-assert in `drive`, the `task` rig), `src/metrics.rs` (`hid_reasserts`), `src/kvm/session.rs` (`SessionConfig::reassert_after`, its two test literals), `src/config.rs` (`input.reassert_after`, its leak shape)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/harness.rs` (`sized()` sets a 600 s re-assert, D10a)
- Test: `crates/kvm-rdp/src/hid/writer.rs` (`tests`)

**Interfaces:**
- Consumes: `HidQueue::{latest_kbd, latest_mouse}` (private; a new `current_state`), `tokio::time`.
- Produces:
  - `HidControl::current_state_frames(&self) -> Vec<HidFrame>` — the last full keyboard report and, if any, the last mouse report (the resync state); empty before any report.
  - `WsTask` gains `reassert_after: Duration`; `pub const REASSERT_AFTER: Duration = Duration::from_secs(1)`.
  - Config key `input.reassert_after` (duration, default `1s`) → `InputConfig::reassert_after: Duration` → `SessionConfig::reassert_after` (D10a: the key arrives here, with its leak shape, not in Task 5.3).
  - metric `kvm_rdp_hid_reasserts_total`.

- [ ] **Step 1: Write the failing test.** In `hid/writer.rs`'s tests, add (using the `GateSink` harness):

```rust
    /// PC9 fix 2 / DD8: after the session-start sequence, the writer
    /// re-asserts the current full state once, REASSERT_AFTER later, so a
    /// stale press the KVM read from its own buffer is overwritten. `drive`
    /// discards what was queued before it (writer.rs:254), so the reports
    /// are pushed after the session start (D2c).
    #[tokio::test(start_paused = true)]
    async fn the_writer_reasserts_the_full_state_after_a_reconnect() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(500);
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await; // SET_MODE, KBD_ZERO
        // The client has 'a' down and the pointer at (300, 400).
        hid.push(kbd(0x04), false);
        hid.push(HidFrame::abs_mouse(0, 300, 400), false);
        wait_sent(&sink, 4).await;
        let before = sink.sent().len(); // 4
        tokio::time::sleep(Duration::from_millis(600)).await;
        // One re-assert: the current keyboard and mouse state again.
        let after = sink.sent();
        assert_eq!(after.len(), before + 2, "{after:?}");
        assert_eq!(after[4], kbd(0x04).to_vec());
        assert_eq!(after[5], HidFrame::abs_mouse(0, 300, 400).to_vec());
        assert_eq!(hid.metrics.hid_reasserts.get(), 1);
        drive.abort();
    }

    /// The re-assert happens once per websocket, not repeatedly.
    #[tokio::test(start_paused = true)]
    async fn the_reassert_is_once_per_websocket() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(200);
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        hid.push(kbd(0x04), false);
        wait_sent(&sink, 3).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(hid.metrics.hid_reasserts.get(), 1);
        drive.abort();
    }

    /// D21: continuous motion keeps the HID side busy, and the re-assert
    /// still goes out at its deadline.
    #[tokio::test(start_paused = true)]
    async fn the_reassert_is_not_starved_by_motion() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(100);
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        for i in 0..40u16 {
            hid.push(HidFrame::abs_mouse(0, i, i), true);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(hid.metrics.hid_reasserts.get(), 1);
        drive.abort();
    }
```

In the `task(..)` rig (writer.rs:470–495) the `WsTask` literal gains `reassert_after: REASSERT_AFTER`; the tests scale it.

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- the_writer_reasserts the_reassert_is_once` — Expected: FAIL to compile (`reassert_after`, `current_state_frames`, `hid_reasserts` not found).

- [ ] **Step 3: Implement.** In `hid/queue.rs`, add to `HidQueue`:

```rust
    /// The last full keyboard report, then the last mouse report (the
    /// resync state): what a re-assert re-sends.
    #[must_use]
    pub fn current_state(&self) -> Vec<HidFrame> {
        let mut v = Vec::new();
        v.extend(self.latest_kbd);
        v.extend(self.latest_mouse);
        v
    }
```

and to `HidControl`:

```rust
    /// §7.4/§3.2 (PC9 fix 2): the full state to re-assert once a reconnect
    /// settles — the last keyboard and mouse reports the KVM should hold.
    #[must_use]
    pub fn current_state_frames(&self) -> Vec<HidFrame> {
        self.q().current_state()
    }
```

Add `hid_reasserts: Counter` to `Metrics` (`"kvm_rdp_hid_reasserts"`, "Full-state re-asserts after a reconnect"), render it, and bump `every_metric_name_is_unique_and_well_formed`'s count to 42. In `hid/writer.rs`, add `pub const REASSERT_AFTER: Duration = Duration::from_secs(1);` and a `pub reassert_after: Duration` field to `WsTask`, and arm the re-assert in `drive`. After `self.backoff.reset();`:

```rust
        // PC9 fix 2: once, `reassert_after` past the session start.
        let mut reassert_at = tokio::time::Instant::now()
            .checked_add(self.reassert_after)
            .map(|at| (at, false));
```

The deadline is checked at the loop top — after the release and `next_frame` drains, before the `select!` — so continuous motion, which keeps the HID side ready and wins the `biased` select, can never starve it (D21). Between the `next_frame` block and the `select!`:

```rust
            if let Some((at, false)) = reassert_at
                && tokio::time::Instant::now() >= at
            {
                for f in self.hid.current_state_frames() {
                    if !self.write(&mut sink, f).await {
                        return Exit::Failed;
                    }
                }
                self.metrics.hid_reasserts.inc();
                reassert_at = Some((at, true));
                continue;
            }
```

and the `select!` gains, after its existing arms, one that only wakes the loop:

```rust
                () = async {
                    match reassert_at {
                        Some((at, false)) => tokio::time::sleep_until(at).await,
                        _ => std::future::pending().await,
                    }
                } => {}
```

A pending release or a queued report still goes before the re-assert (the loop drains them first), which is right: the re-assert is the *latest* full state. A write failure in it reconnects like any other.

The key (D10a), in `src/config.rs`: `RawInput` gains `reassert_after: Option<String>`; `InputConfig` gains `pub reassert_after: Duration`, built with `reassert_after: dur(ri.reassert_after.as_ref(), s(1), "input.reassert_after")?,`; and `leak_shapes` gains `t(format!("{base}[input]\nreassert_after = \"{s}\"\n"), "a bad reassert_after"),` beside the other value shapes. In `kvm/session.rs`: `SessionConfig` gains `pub reassert_after: Duration`, `from_config` reads `reassert_after: c.input.reassert_after`, the `WsTask` literal (session.rs:175) gets `reassert_after: cfg.reassert_after`, and the two test `SessionConfig` literals (session.rs:620 and 1075) get `reassert_after: crate::hid::writer::REASSERT_AFTER` (D19).

In L2 (`tests/l2/harness.rs`), `sized()` adds `c.input.reassert_after = Duration::from_secs(600);`, so the exact-frame cases (Plan C's `reports_reach_the_kvm_and_a_reopen_restores_the_pointer`, Tasks 5.1 and 5.2) never see a re-assert on the shared host; Task 5.3's re-assert case sets its own (D10a).

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- hid::writer` — Expected: PASS (the three new cases and the existing writer suite). `cargo test --workspace --all-features --lib -- metrics:: config::` — Expected: PASS (count 42; `config_errors_never_echo_the_file` over the new shape). `cargo test --workspace --all-features --test l2` — Expected: PASS (unchanged; the re-assert never fires in 600 s).

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/hid/queue.rs crates/kvm-rdp/src/hid/writer.rs crates/kvm-rdp/src/metrics.rs \
  crates/kvm-rdp/src/kvm/session.rs crates/kvm-rdp/src/config.rs crates/kvm-rdp/tests/l2/harness.rs
git commit -m "kvm-rdp: re-assert the full HID state once a reconnect settles (PC9 fix 2, §3.2, §7.4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Part 5 — L2 against kvm-sim (§11.3)

### Task 5.1: L2 — the client sends input; the §11.3 Input and Stuck-key cases

The L2 client gains the ability to send fast-path input (scancode, Unicode, mouse, wheel, Synchronize) through its `ActiveStage`; the new cases assert the §11.3 Input and Stuck-key lists against kvm-sim's recorded HID frames. This is the input half of DC7's carry (Plan C drove `HidControl` directly; Plan D drives the real client → handler → core → writer → kvm-sim path).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/client.rs` (input senders)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/input.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod input;`), `tests/l2/harness.rs` (a HID-settling helper if needed)

**Interfaces:**
- Consumes: the harness (`streaming`, `env`, `hid_on`, `ws_opens`, `SET_MODE`, `KBD_ZERO`, `T`, `ms`), kvm-sim's recorded `Hid` frames, `kvm_proto::hid::HidFrame`.
- Produces on `Client`: `pub fn key(&self, code: u8, pressed: bool)`, `pub fn key_extended(&self, code: u8, pressed: bool)`, `pub fn unicode(&self, unit: u16, pressed: bool)`, `pub fn mouse_move(&self, x: u16, y: u16)`, `pub fn mouse_button(&self, button: FpButton, pressed: bool, x: u16, y: u16)` (the click's own position, as a real client sends it, D8d), `pub fn wheel(&self, units: i16)`, `pub fn synchronize(&self, caps_lock: bool)` — each sends one fast-path input PDU; `pub enum FpButton { Left, Right, Middle }`.

- [ ] **Step 1: Extend the client.** In `tests/l2/client.rs`, add an input channel the run loop drains and sends through the stage. Add to `Ctl`: `Input(Vec<FastPathInputEvent>)`. Add the senders to `Client` (each builds the events and `self.ctl.send(Ctl::Input(..))`), and in `run`'s `select!`, a `Some(Ctl::Input(events))` arm:

```rust
                    Some(Ctl::Input(events)) => {
                        match stage.process_fastpath_input(&mut image, &events) {
                            Ok(out) => {
                                for o in out {
                                    if let ActiveStageOutput::ResponseFrame(f) = o {
                                        let _ = framed.write_all(&f).await;
                                    }
                                }
                            }
                            Err(e) => return push(&log, Ev::Closed(format!("input: {e}"))),
                        }
                    }
```

with `use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};`, `use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};`, and the senders:

```rust
#[derive(Clone, Copy)]
pub enum FpButton {
    Left,
    Right,
    Middle,
}

impl Client {
    fn input(&self, e: FastPathInputEvent) {
        let _ = self.ctl.send(Ctl::Input(vec![e]));
    }
    pub fn key(&self, code: u8, pressed: bool) {
        let flags = if pressed { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
        self.input(FastPathInputEvent::KeyboardEvent(flags, code));
    }
    pub fn key_extended(&self, code: u8, pressed: bool) {
        let mut flags = KeyboardFlags::EXTENDED;
        if !pressed {
            flags |= KeyboardFlags::RELEASE;
        }
        self.input(FastPathInputEvent::KeyboardEvent(flags, code));
    }
    pub fn unicode(&self, unit: u16, pressed: bool) {
        let flags = if pressed { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
        self.input(FastPathInputEvent::UnicodeKeyboardEvent(flags, unit));
    }
    pub fn mouse_move(&self, x: u16, y: u16) {
        self.input(FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        }));
    }
    pub fn mouse_button(&self, button: FpButton, pressed: bool, x: u16, y: u16) {
        let mut flags = match button {
            FpButton::Left => PointerFlags::LEFT_BUTTON,
            FpButton::Right => PointerFlags::RIGHT_BUTTON,
            FpButton::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
        };
        if pressed {
            flags |= PointerFlags::DOWN;
        }
        self.input(FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        }));
    }
    pub fn wheel(&self, units: i16) {
        self.input(FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL,
            number_of_wheel_rotation_units: units,
            x_position: 0,
            y_position: 0,
        }));
    }
    pub fn synchronize(&self, caps_lock: bool) {
        use ironrdp_pdu::input::fast_path::SynchronizeFlags;
        let flags = if caps_lock { SynchronizeFlags::CAPS_LOCK } else { SynchronizeFlags::empty() };
        self.input(FastPathInputEvent::SyncEvent(flags));
    }
}
```

(A negative wheel uses a negative `number_of_wheel_rotation_units`, which IronRDP encodes as 9-bit two's complement; `-120` is in range.)

- [ ] **Step 2: Write the failing cases.** Create `tests/l2/input.rs`. It streams (so a session is live and the HID websocket is up — `env.hid_ready()`), sends input through the client, and reads kvm-sim's HID frames with `hid_on`. Cases:

```rust
//! §11.3 Input and Stuck keys (DC7's carry): the real client → the input
//! handler → the core → the writer → kvm-sim. Each waits for `hid_ready`
//! (the session-start sequence on the wire) and then asserts on the frames
//! kvm-sim recorded after it.
use crate::client::FpButton;
use crate::harness::{KBD_ZERO, SET_MODE, T, hid_on, ms, streaming, ws_opens};
use kvm_proto::hid::HidFrame;

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    HidFrame::Keyboard { modifiers, keys: [k, 0, 0, 0, 0] }.to_vec()
}
/// kvm-sim's HID frames on the current websocket after the session start.
async fn after_start(env: &crate::harness::Env, ws: u64, want: usize) -> Vec<Vec<u8>> {
    env.sim.wait_for(T, |l| hid_on(l, ws).len() >= 2 + want).await.unwrap();
    let all = hid_on(&env.sim.events(), ws);
    all[2..].to_vec()
}
```

- `every_input_event_maps_to_byte_exact_hid_frames`: press `A` (scancode 0x1E with Shift 0x2A held), release; a mouse move to the surface centre; a left click there (`mouse_button(FpButton::Left, true, cx, cy)`); one wheel notch (`-120`). Assert the exact HID frame list: `[kbd(Shift,0), kbd(Shift,0x04), kbd(Shift,0), kbd(0,0), AbsMouse(0, centre), AbsMouse(1, centre), Wheel down]` (the surface is 640×360, so centre scales by §7.2; the click's frame carries the click's own position, D8d). Build the expected list from `scale_abs`.
- `a_click_with_no_prior_move_goes_where_it_was_made`: with no mouse move this session, `mouse_button(FpButton::Left, true, 100, 50)` → the first frame after the session start is `AbsMouse(1, scale_abs(100, 640), scale_abs(50, 360))`, never (0, 0) (D8d, §3.3).
- `a_full_queue_resyncs_to_the_correct_final_state_through_the_client`: set `input.queue` small (e.g. 4) and the websocket's reads paused, flood distinct key presses, then one last press; resume; the last frame kvm-sim sees is that last full state (§7.3; mirrors Plan C's `hid::a_full_queue_resyncs`, now driven by the client).
- `a_websocket_reopen_restores_the_pointer_not_zero`: move the pointer, `env.sim.close_websockets()`, and assert the reopen's session start carries the pointer at the last scaled position, never (0, 0) (reuses the harness's reopen wait).
- `every_section_7_4_trigger_releases_all`: for `Synchronize`, hold `a`, send `synchronize(false)`, and assert kvm-sim sees a zero keyboard report and the held `a`'s later repeat does not re-press it (released-by-bridge); the other triggers (session end, websocket reconnect, suppression) are Plan C's L2 and the lib's.
- `a_key_held_across_a_release_is_not_repressed_by_repeats`: hold `a`; `synchronize`; send three `Pressed` repeats of `a`; assert no `a` press reaches kvm-sim until a `Released` then a fresh `Pressed`.
- `typematic_repeats_hold_the_key_but_silence_releases_it`: scaled `key_repeat_timeout` (e.g. 1 s via `c.input.key_repeat_timeout = ms(1000)`); hold `a`, repeat it every 200 ms for 2 s → no release; then stop and wait 1.5 s → a zero keyboard report (§11.1's one-sided bound, `within`).
- `mouse_motion_never_resets_the_key_timers`: hold `a`, move the mouse every 200 ms for 2 s with no key repeat, scaled `key_repeat_timeout` 1 s → the key releases despite the motion.
- `two_keys_held_with_repeats_of_the_second_only_never_release` (§11.3 Stuck keys, D10b): scaled `key_repeat_timeout` 1 s; hold `a` then `b`, repeat only `b` every 200 ms for 3 s → no zero keyboard report on kvm-sim in that window (both stay held: `kbd(0, [0x04, 0x05, …])` is the last frame); then release both.
- `a_held_modifier_releases_after_modifier_idle_timeout` (§7.4's second trigger, D10b): `c.input.modifier_idle_timeout = ms(1000)`; hold LCtrl (0x1D) and send nothing else → `within` 1–2.5 s kvm-sim sees a zero keyboard report; a later LCtrl `Pressed` repeat does not re-press it (released-by-bridge, D3a) until a `Released`.

Write each as `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, waiting on kvm-sim's log with `wait_for`/`within`, asserting exact frames or the released-by-bridge behaviour. Add `mod input;` to `tests/l2/main.rs`.

- [ ] **Step 3: Run the cases.** `cargo test --workspace --all-features --test l2 -- input::` — Expected: PASS. (They need the real input path from Task 4.1; if a case is load-sensitive, bound it with `within` and the harness's `T`, never a bare sleep assertion.)

- [ ] **Step 4: Gate** (clippy, test, budget). **Step 5: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/client.rs crates/kvm-rdp/tests/l2/input.rs crates/kvm-rdp/tests/l2/main.rs crates/kvm-rdp/tests/l2/harness.rs
git commit -m "kvm-rdp: L2 input and stuck-key cases through the real client (§11.3, DC7)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5.2: L2 — CLIPRDR in the client, the Paste cases, and the secrets sentinel and canary

The L2 client gains a CLIPRDR channel with a backend that offers text and answers the bridge's paste request; the new cases assert §11.3's Paste list. The secrets-hygiene case (Plan C's, which ran without them, DC9) gains the keystroke sentinel and the paste canary.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/client.rs` (a CLIPRDR client channel and `Opts::clipboard`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/paste.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod paste;`), `tests/l2/admin.rs` (the sentinel and canary), `tests/l2/harness.rs` (chord scancodes)

**Interfaces:**
- Consumes: `ironrdp_cliprdr::{CliprdrClient, backend::{CliprdrBackend, ClipboardMessage, ClipboardMessageProxy}, pdu::{ClipboardFormat, ClipboardFormatId, FormatDataRequest, FormatDataResponse, OwnedFormatDataResponse}}`, the input senders (Task 5.1), kvm-sim's HID frames.
- Produces on `Client`/`Opts`: `pub fn clipboard(mut self, text: &str) -> Opts` (sets the client's offered `CF_UNICODETEXT`); the client attaches a `CliprdrClient` when it is set. Harness: `pub const CHORD_MODS: [u8; 3]` (LCtrl, LAlt, LShift), `pub const CHORD_KEY: u8` (V), and `pub fn paste_chord(c: &Client, release_mods: bool)` — presses the three modifiers and V, releases V, then the modifiers only if `release_mods` (D23).

- [ ] **Step 1: The client's CLIPRDR channel.** In `tests/l2/client.rs`, add `Opts::clipboard(mut self, text: &str) -> Opts` (it stores `Some(text.to_owned())`). When set, `connect` attaches a `CliprdrClient::new(Box::new(ClientClip { … }))` as a static channel (`connector.with_static_channel(CliprdrClient::new(backend))`), and the client offers `CF_UNICODETEXT` in its first format list and answers a `FormatDataRequest` for it with the stored text. The first list goes out from `on_request_format_list`, which the client runs on the server's Monitor Ready (ironrdp-cliprdr lib.rs:669–690: that first `initiate_copy` carries Capabilities, TempDir and the FormatList); `on_ready` fires only after the server's `FormatListResponse::Ok` (lib.rs:693–700), so it does nothing (D9b). The backend pushes its outbound intents through a `ClipboardMessageProxy` into a channel the run loop drains and encodes with the active stage's SVC path (`stage.get_svc_processor_mut::<CliprdrClient>()` then `initiate_copy(&[CF_UNICODETEXT])` on `on_request_format_list` (the server's Monitor Ready), `submit_format_data(OwnedFormatDataResponse::new_unicode_string(&text))` on request; encode with `stage.process_svc_processor_messages(..)` and write the frames). The backend:

```rust
#[derive(Debug)]
struct ClientClip {
    text: String,
    proxy: Box<dyn ClipboardMessageProxy>,
}

impl CliprdrBackend for ClientClip {
    fn temporary_directory(&self) -> &str { "." }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags { ClipboardGeneralCapabilityFlags::empty() }
    fn on_ready(&mut self) {}
    fn on_request_format_list(&mut self) {
        // Monitor Ready: announce that we hold Unicode text (D9b).
        self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ]));
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {}
    fn on_format_data_request(&mut self, _req: FormatDataRequest) {
        self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(
            OwnedFormatDataResponse::new_unicode_string(&self.text),
        ));
    }
    fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

// `CliprdrBackend: AsAny + Debug + Send`; `AsAny` has no blanket impl (D1c).
ironrdp_core::impl_as_any!(ClientClip);
```

`OwnedFormatDataResponse::new_unicode_string` appends the `\0\0` terminator, as Windows, Windows App and FreeRDP do; the bridge's `decode_utf16le` ends the text there (D4), so these cases see what a real client sends.

**Implementer note (the riskiest wiring in this plan):** the client's proactive/reactive CLIPRDR sends go through IronRDP's SVC path, not the EGFX DVC path the Plan C client already has. Read `ironrdp-cliprdr`'s `lib.rs` (`initiate_copy`, `submit_format_data`, `Cliprdr as SvcProcessor`) and `ironrdp-session`'s `ActiveStage::{get_svc_processor_mut, process_svc_processor_messages}` before writing the loop integration. The `ClipboardMessageProxy` is a small `Send` shim over a `std::sync::mpsc::Sender<ClipboardMessage>` the run loop owns; after each `stage.process`, drain it and encode. The acceptance is the Paste cases below — if the exact API differs from this sketch, follow the crates and keep the cases' assertions.

- [ ] **Step 2: Write the failing cases.** Add to `harness.rs`:

```rust
/// The default paste chord's make codes (`ctrl+option+shift+v`, §8).
pub const CHORD_MODS: [u8; 3] = [0x1D, 0x38, 0x2A]; // LCtrl, LAlt, LShift
pub const CHORD_KEY: u8 = 0x2F; // V

/// Press the chord's modifiers and V, release V, then — if `release_mods`
/// — the modifiers (they must release for the paste to type, §8).
pub fn paste_chord(c: &Client, release_mods: bool) {
    for m in CHORD_MODS {
        c.key(m, true);
    }
    c.key(CHORD_KEY, true);
    c.key(CHORD_KEY, false);
    if release_mods {
        for m in CHORD_MODS {
            c.key(m, false);
        }
    }
}
```

Create `tests/l2/paste.rs`:

```rust
//! §11.3 Paste (Plan D): the chord, the Typist, newline handling, the
//! aborts and the limits, over the real client's CLIPRDR channel.
use crate::client::{FpButton, Opts};
use crate::harness::{T, env, es3, hid_on, ms, paste_chord, sized, ws_opens};
use kvm_proto::hid::HidFrame;
use kvm_rdp::config::Multiline;
```

Each case `env(es3(), |c| { sized(c); c.paste.pace = ms(0); c.paste.modifier_wait = ms(300); … })`, a client with `Opts::new(2).clipboard("<text>")`, waits for `hid_ready`, sends the chord (`paste_chord(&c, true)` unless the case says otherwise), and reads the typed frames on the HID websocket:

- `a_paste_types_the_exact_report_list`: clipboard `"a\r\nb\tc\u{1F600}\n"`; after the chord, kvm-sim's HID frames (after the session start and the chord's own modifier reports) are exactly the §8 list — `a`, Return, `b`, Tab, `c`, each a press then `KBD_ZERO`, the emoji skipped, no trailing Return — and `paste_events{done}` is 1, `paste_skipped_chars` is 1.
- `multiline_refuse_refuses_an_inner_break_but_types_a_trailing_one`: `c.paste.multiline = Multiline::Refuse`; clipboard `"a\nb"` → nothing typed, `paste_events{multiline}` 1; a second client (new session) with `"a\n"` → types `a`.
- `esc_aborts_and_usage_0x29_is_never_sent`: clipboard a long string; chord; then `key(0x01, true)` (Esc) mid-type; kvm-sim's frames are a strict prefix then `KBD_ZERO`, and no frame carries usage 0x29.
- `a_mouse_click_aborts`: chord, then `mouse_button(FpButton::Left, true, 10, 10)` → `paste_events{aborted}` 1.
- `a_key_pressed_mid_typing_never_reaches_the_kvm` (§11.3, D10b): `c.paste.pace = ms(20)`; clipboard `"abcdefghij"`; chord; once the first typed press is on kvm-sim, only `key(0x10, true)` (Q's press; its release comes after the paste, D30); after `paste_events{done}` is 1, no frame on the websocket carries usage 0x14 (Q), and a second `key(0x10, true)` (a typematic repeat) pushes nothing (released-by-bridge, D3c); then `key(0x10, false)` and `key(0x10, true)`, which pushes `kbd(0, 0x14)` — a fresh press after the release.
- `an_8_mib_payload_is_clipboard_oversize_and_types_nothing` (§11.3, D10b): clipboard `"x".repeat(4 << 20)` (8 MiB of `CF_UNICODETEXT`, sent in full over the SVC); chord → the session ends with `clipboard_oversize` (`env.metrics().disconnects.get("clipboard_oversize") == 1`), and no typed frame reached kvm-sim.
- `modifiers_held_past_the_wait_cancel`: `paste_chord(&c, false)` (never release the modifiers); after `modifier_wait` (scaled) → `paste_events{aborted}` 1, nothing typed.
- `caps_lock_on_refuses`: `synchronize(true)`, chord → `paste_events{caps_lock}` 1.
- `the_chord_key_never_reaches_the_kvm`: after a paste, no HID frame carries V's usage (0x19).
- `an_oversize_response_drops_the_session`: `c.paste.max_bytes = 64 << 10`; clipboard a string whose `CF_UNICODETEXT` bytes exceed it; chord → the session ends with `clipboard_oversize` (the client is `Terminated` with 0x7; `env.metrics().disconnects.get("clipboard_oversize") == 1` — counted once, by the pump's `close`, D17), nothing typed. `64 KiB − 2 bytes` → typed up to `max_chars`.

Add `mod paste;` to `tests/l2/main.rs`.

- [ ] **Step 3: The secrets case gains the sentinel and canary (DC9).** In `tests/l2/admin.rs`'s `secrets_never_reach_the_logs`, after the client connects and five pictures arrive, drive input and a paste through it: send a keystroke sentinel (a distinct ASCII string, each char as a scancode press/release) and paste a text canary (a client with `Opts::clipboard(CANARY)` and the chord). Add to the forbidden list the sentinel, the canary, and the hex of the 12-byte keyboard HID frames those keystrokes produce (compute the expected frames with `kvm_proto::keymap::us_stroke` + `HidFrame::Keyboard` and format each as lowercase hex). The existing checks stay (no `NTLMSSP`, no `TlRMTVNTUA`, no `token=`, no DEBUG/TRACE from `ironrdp_*`/`sspi`, at least one bridge TRACE, `SSLKEYLOGFILE` never created, zero logouts). Define `const SENTINEL: &str = "sentinel-6b1f0c9d2a";` and `const CANARY: &str = "paste-canary-3e7a";` in the harness beside `NLA`.

- [ ] **Step 4: Run the cases.** `cargo test --workspace --all-features --test l2 -- paste:: admin::secrets` — Expected: PASS. (The secrets case now types and pastes; it still spawns the real binary, so the writer, input core and CLIPRDR all run under the production log filters.)

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/client.rs crates/kvm-rdp/tests/l2/paste.rs crates/kvm-rdp/tests/l2/main.rs \
  crates/kvm-rdp/tests/l2/admin.rs crates/kvm-rdp/tests/l2/harness.rs
git commit -m "kvm-rdp: L2 paste cases over real CLIPRDR; the secrets case types a sentinel and pastes a canary (§11.3, DC9)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5.3: kvm-sim — a mid-session certificate swap and a divergent-replay knob; the W10, divergence and re-assert L2 cases

Three loose ends the final review and the ledger carry to Plan D: a mid-session KVM certificate change on the websocket (PC7 W10), which needs a kvm-sim certificate swap; the replay-divergence L2 case (PC17 m1), which needs a one-connection knob that makes a candidate's replay diverge in content (not just skip, which the committed case already covers via the resync path); and an L2 case for the re-assert (Task 4.2).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/{lib,tls,state,flv}.rs` (certificate swap, `alter_candidate_frame`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/conformance.rs` (the knobs' own tests)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/{faults,video,hid}.rs` (the `input.reassert_after` key the re-assert case scales is Task 4.2's, D10a)

**Interfaces:**
- Produces on `KvmSim`: `pub fn rotate_certificate(&self) -> std::io::Result<()>` (every new TLS connection after it uses a fresh self-signed certificate — a different SPKI, so the bridge's pin no longer matches); `Policy::alter_candidate_frame: Option<u64>` (a FLV opened while another is open mangles one byte of its Nth coded AU's first slice, so that AU matches no ring entry at the pump → `replay_diverged`).

- [ ] **Step 1: Write the failing cases.**
  - In `crates/kvm-rdp/tests/l2/faults.rs`, a W10 case:

```rust
/// PC7 W10 (ledger carry): the KVM's certificate changes mid-session, on
/// the websocket's next reconnect. The bridge pins the SPKI (§3.2), so the
/// new certificate fails the pin: fatal at once, `kvm_cert_mismatch`, its
/// writer idling rather than reconnecting (rev 6.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_change_mid_session_is_fatal_at_once() {
    let (env, c) = streaming(|_| {}).await;
    env.hid_ready().await;
    env.sim.rotate_certificate().unwrap();
    // Force a websocket reconnect: its reopen now hits the new certificate.
    env.sim.close_websockets();
    c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(
        terminated(&c.events()).as_deref(),
        Some(client::description(Cause::KvmCertMismatch).as_str())
    );
    assert_eq!(env.metrics().disconnects.get("kvm_cert_mismatch"), 1);
}
```

  - In `crates/kvm-rdp/tests/l2/video.rs`, the true-divergence case (beside the existing skip case):

```rust
/// PC17 m1 (final review carry): a candidate whose replayed P frame
/// diverges in content from the one the old main already gave the client
/// matches no ring entry — the pump drops it (`replay_diverged`), enters
/// NeedIdr, and the picture recovers at the next IDR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_divergent_replay_frame_ends_the_replay_at_an_idr() {
    let env = env(es3(), |c| {
        sized(c);
        c.video.idr_policy = IdrPolicy::Reconnect;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 45).await;
    env.sim.set_policy(|p| {
        p.delay_flv_header = Some(ms(200));
        p.alter_candidate_frame = Some(3);
    });
    let n = c.with_log(<[Ev]>::len);
    c.readvertise();
    // After the swap the client still ends on an IDR and never shows a
    // corrupt (out-of-sequence) P frame; replay_diverged was counted.
    c.wait_for(T, |e| {
        confirmed(e, n).is_some_and(|k| pictures(&e[k..]).iter().any(|p| nal_types(&p.annex_b).contains(&5)))
    })
    .await;
    assert!(env.metrics().frames_dropped.get("replay_diverged") >= 1, "no divergence");
}
```

  - In `crates/kvm-rdp/tests/l2/hid.rs`, the re-assert case:

```rust
/// PC9 fix 2 / DD8 (Task 4.2): after a websocket reconnect, the fresh
/// websocket's session start is followed, ~REASSERT_AFTER later, by the
/// current full state again — so a stale press is overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_reasserts_the_full_state() {
    // `sized()` sets a 600 s re-assert so the exact-frame cases never see
    // one (Task 4.2, D10a); this case scales it back down.
    let (env, c) = streaming(|c| c.input.reassert_after = ms(300)).await;
    let ws = env.hid_ready().await;
    c.mouse_move(320, 180); // centre of the 640×360 surface
    env.sim.wait_for(T, |l| hid_on(l, ws).len() >= 3).await.unwrap();
    env.sim.close_websockets();
    // The reopen: session start (SET_MODE, KBD_ZERO, the pointer), then the
    // re-assert repeats the current state.
    let log = env
        .sim
        .wait_for(T, |l| ws_opens(l).len() >= 2 && hid_on(l, ws_opens(l)[1]).len() >= 4)
        .await
        .unwrap();
    let ws2 = ws_opens(&log)[1];
    assert!(env.metrics().hid_reasserts.get() >= 1);
    let on_new = hid_on(&env.sim.events(), ws2);
    assert_eq!(&on_new[..2], &[SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
    // The current state is zero keys and the pointer at the last position.
}
```

(`streaming`'s `edit` runs after `sized`, so the 300 ms wins over the harness's 600 s.)

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --test l2 -- a_certificate_change a_divergent_replay a_reconnect_reasserts` — Expected: FAIL to compile (`rotate_certificate`, `alter_candidate_frame` not found).

- [ ] **Step 3: Implement the kvm-sim knobs.**
  - Certificate swap (D24): `ConnCtx`'s `acceptor: TlsAcceptor` (lib.rs:222–231) becomes `acceptor: std::sync::Mutex<TlsAcceptor>` (no new dependency); `Shared` (`#[derive(Default)]`) is untouched. `KvmSim` gains a `ctx: Arc<ConnCtx>` field (the one `start` builds at lib.rs:278 and hands every listener). `serve_connection` clones the acceptor under the lock at accept time — `let acceptor = ctx.acceptor.lock().unwrap_or_else(PoisonError::into_inner).clone();` — and never holds the lock across the handshake. `pub fn rotate_certificate(&self) -> std::io::Result<()>` swaps in `tls::identity()?.acceptor` under the lock (a fresh self-signed certificate and SPKI each call; on an error the old one stays). The L2 case and the conformance test call it as `env.sim.rotate_certificate().unwrap()`. The bridge pinned the first SPKI, so a connection after the swap fails the pin inside the bridge's own TLS — `KvmError::CertMismatch` (kvm/error.rs:17) → `kvm_cert_mismatch` on the websocket path (§6.9). Keep the first identity's SPKI as `spki_sha256()` (the pin the bridge was configured with) unchanged, so only *new* connections see the new cert.
  - `alter_candidate_frame`: in `state.rs`'s `Policy`, add `pub alter_candidate_frame: Option<u64>`; in `flv.rs`'s `Writer`, carry it like `skip` (set at open from `policy.alter_candidate_frame`), and in `frame`, when `frames_seen == n`, flip one byte of the first VCL NAL's payload (not its header or a start-code position — e.g. a byte well inside the slice) so the AU's bytes differ from what every other viewer got. The pump's replay ring matches on (len, hash) of the AU as handed to IronRDP, so an altered P frame matches nothing → `replay_diverged`.
  - `conformance.rs`: a test that a connection after `rotate_certificate` presents a different SPKI (connect with kvm-probe pinned to the old SPKI → a TLS error), and a test that `alter_candidate_frame` changes exactly one AU's bytes.

- [ ] **Step 4: Run the cases.** `cargo test --workspace --all-features --test l2 -- a_certificate_change a_divergent_replay a_reconnect_reasserts` and `cargo test --workspace --all-features --test sim -- conformance` — Expected: PASS.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-sim/src/lib.rs crates/kvm-sim/src/tls.rs crates/kvm-sim/src/state.rs crates/kvm-sim/src/flv.rs \
  crates/kvm-sim/tests/sim/conformance.rs crates/kvm-rdp/tests/l2/faults.rs crates/kvm-rdp/tests/l2/video.rs \
  crates/kvm-rdp/tests/l2/hid.rs
git commit -m "kvm-sim: mid-session cert swap and a divergent-replay knob; L2 W10, divergence and re-assert (PC7 W10, PC17 m1, PC9 fix 2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Part 6 — Close-out

### Task 6.1: spec rev 6.3, the README, and the L4 retunes

Write the deviations and the L4 facts into the spec as rev 6.3, update the README's status, and apply any config retunes the Leg D results (Task 1.6) call for. This is the last task; it reads `census.md`'s Leg D rows.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`
- Modify: `/home/chris/Repos/kvm-rdp/README.md`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/config.rs`, `src/kvm/endpoint.rs` (only if Leg D retunes a default)

- [ ] **Step 1: Spec rev 6.3.** In the spec's status table, change `Draft rev 6.2` to `Draft rev 6.3` and add a leading paragraph like rev 6.2's: "**Rev 6.3 — Plan D (date).** Records what building M3b + M4 settled, against the code as built. DD*n* are Plan D's recorded deviations (`docs/superpowers/plans/…plan-d.md`)." Then one line per DD1–DD11 (the "Recorded deviations" list above), and one line per later-§ change Plan D made, each marked "rev 6.3":
  - §7.1: the Mac remap is the fixed table (DD3), off by default; `input.mac_remap` is the switch.
  - §7.3: the input handler is built (no longer the DC7 stub); it builds each report's state and epoch together and pushes via `push_at`; the re-assert after a reconnect settles (DD8).
  - §7.4: `ReleaseTrigger` gains `Synchronize`, `KeyRepeat`, `ModifierIdle`; both timers live in `input::core` (sans-IO).
  - §8: `paste.chord` is validated at load (DD11); the pending-paste bounds (DD4); Caps-Lock tracking (DD5); the Typist waits for queue room (DD6); `paste.pace` is set from L4 (DD10); the text ends at CF_UNICODETEXT's U+0000 terminator, before step 1 strips a trailing break. And: "rev 6.3: Milestone 4's comparison with the KVM's `hid.lua?type=text` is deferred to Plan E's perf pass (controller ruling, 2026-10-14); ours stays the default." (controller ruling 2, D25)
  - §9.3: the answer to "what the Mac does when the websocket dies with a key held", from Leg D (Task 1.6 step 8) — fill the sentence the spec left for Plan D.
  - §10.4: the `release_all` trigger set, the `paste_events{outcome}` and `paste_skipped_chars` metrics, and `hid_reasserts`, as built; `input_events_ignored` keeps its meaning (DD7).
  - §11.6 / §15: fold the Leg D results — replace "Open for Plan D's L4" with "Settled by Leg D (date, `census.md`)" and list what each check found. The global-logout refusal forms and the websocket's survival of another session's logout are settled only if Task 1.6's optional step 16 ran (`logout-watch`, the owner logging out); otherwise they stay open as DD1's "not measured". Keep as open only what was "not run" (those, and any owner-gated step the owner declined).
  - §12: DC18's items are done or recorded; add any new owner acceptance item Plan D surfaced (e.g. if Windows App's Cmd remap needs the key-matrix fixture before `mac_remap` can ship — already acceptance item 4).
  - §4.4: the new/changed keys — `paste.chord` is a `Chord`, `input.reassert_after` (1 s, §3.2/§7.4, retuned by L4 as `max(1 s, ceil(1800 / hid_rate))` when stale reports land after a fresh session start; state the assumption: 1 800 ≈ 64 KiB ÷ 37 B, the ES3's receive window taken at Linux's default, D29), and `paste.pace`'s source (DD10). Record `CONTROL_SNDBUF` as sized from L4's page-measured HID rate (final review, D28), not a config key.
  The change log supersedes nothing in Plan C's; it is appended.

- [ ] **Step 2: Apply the L4 retunes.** Read `census.md`'s Leg D rows (Task 1.6). For each, apply the decision rule:
  - `paste.pace` (step 7, DD10): if the smallest lossless pace was measured, set `PasteConfig`'s default to twice it (the default lives in `config.rs`'s `build`, currently `ms(15)`); else leave 15 ms and note "not retuned (L4 step 7 not run)" in the commit.
  - `CONTROL_SNDBUF` (step 7): if the page-measured HID report rate (D28; not the probe's `write_rate`) makes 16 KiB wrong — a full buffer would take more than ~1 s of input to drain, or less than a few reports — adjust the const in `endpoint.rs` and `hid::SNDBUF` in kvm-probe; else leave 16 KiB. Record the measured rate in the const's doc comment.
  - `input.reassert_after` (step 9's yes/no, DD8; D29, which replaces controller ruling 7): if no stale report landed after the fresh session start, 1 s stands (the re-assert is a backstop). If yes, the re-assert is load-bearing: set the default to `max(1 s, ceil(1800 / hid_rate))`, capped at `config::MAX_DURATION`, where `hid_rate` is step 7's page-measured reports/s — the time the KVM takes to read out a full receive window of stale reports (1 800 ≈ 64 KiB ÷ ~37 B, the ES3's receive window taken at Linux's default; write that assumption into the default's doc comment and rev 6.3). If no rate was measured, 1 s stands and the commit says so.
  - `input.key_repeat_timeout`: unchanged — it stays the 10 s acceptance default until the owner's Windows-App typematic capture (acceptance item 4, not L4).
  If Task 1.6 was not run (Execution notes), leave every default as written and say so in the commit body; the spec's rev 6.3 marks those rows "not measured".

- [ ] **Step 3: README.** Update the status line from "Milestone 3a" to "Milestones 3b + 4": the bridge now maps keyboard, mouse and clipboard paste to HID, with the stuck-key safety; input is no longer a stub. Keep the acceptance-items caveat (Windows App is still unrun). If a `## Input` or `## Paste` section fits the README's shape, add a short one (the chord, that paste is one-way, the stuck-key timers); do not restate the spec.

- [ ] **Step 4: Verify.** `cargo test --workspace --all-features` — Expected: 0 failed. `nix develop --command cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean. `scripts/target-budget.sh` — Expected: under 8 GiB. `nix develop --command actionlint` and `shellcheck scripts/*.sh` if CI or scripts changed — Expected: clean (Plan D adds no CI; this is a backstop). Confirm the spec and README read correctly (no leftover "DC7 stub" or "Plan D's" claims that are now done).

- [ ] **Step 5: Commit.**

```bash
git add docs/superpowers/specs/2026-10-05-kvm-rdp-design.md README.md crates/kvm-rdp/src/config.rs crates/kvm-rdp/src/kvm/endpoint.rs
git commit -m "docs: spec rev 6.3 (Plan D deviations and Leg D), README; apply the L4 retunes" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Running the input and paste paths

```bash
# Build once, in the gate's feature resolution (never `cargo run -p`, D6d):
nix develop --command cargo build --workspace --all-features --bins
KP="$(nix develop --command bash -c 'printf %s "$CARGO_TARGET_DIR"')/debug/kvm-probe"

# The HID test page the owner opens on the Mac (prints a data: URL; sends nothing):
nix develop --command "$KP" hid-page-url

# An L4 check against the real ES3 (never logs out, never leaves a key held):
nix develop --command "$KP" ws-close \
  --host 192.168.0.50 --pin "$PIN" --password-file ./kvm.pass

# After any HID command that failed, was interrupted or was killed:
nix develop --command "$KP" hid-release \
  --host 192.168.0.50 --pin "$PIN" --password-file ./kvm.pass

# The full L2 input/paste suite:
nix develop --command env CARGO_BUILD_JOBS=4 cargo test --workspace --all-features --test l2 -- input:: paste::
```

## Planning notes

- Parts run in order; Task 1.6 (the hardware task) is deferrable (Execution notes). Within Part 1, Task 1.1 (the keymap) precedes the probe's typing (1.4). Parts 2–4 depend only on Task 1.1 and Plan C, so they can proceed while Task 1.6 waits for the owner; Task 6.1's retunes (`paste.pace`, the websocket `SO_SNDBUF` cap, `input.reassert_after`) read Leg D if it has run, and fall back to the written defaults if not.
- Every task's gate is Plan C's: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `scripts/target-budget.sh`. Never `-p`.
- The two IronRDP-linked test executables stay lib + L2 (§13); `ironrdp-cliprdr` adds no compile unit (it is in `ironrdp-server`'s graph). kvm-probe gains `socket2` and tokio `signal`/`sync`, all already in the workspace build.

## Appendix — Pre-flight resolutions

Every pre-flight finding (`.superpowers/sdd/plan-d-draft/preflight.md`, D1–D27, and the verification re-scan's D28–D37) is adopted with its proposed ruling and folded into the task text above (controller rulings 6 and 9); the briefs are cut from the tasks, not from this list. One line per finding: where the plan now carries it (task, plan line).

- **D1** (Critical, won't compile) — T2.1 l.4042 (`input/mod.rs` declares only `keys`, `pointer`; T2.2 and T3.2 add `core`, `paste`); T3.1 l.4995 (`impl Iterator for Typist`, no self-`use`, `if let &[lo, hi]`); T3.3 l.6052 and T5.2 l.7005 (`impl_as_any!`); T3.3 l.6123 (`ServerParts::cliprdr: ClipFactory`, `Some(Box::new(p.cliprdr))`); T4.1 l.6586 (`_ => None` for the `#[non_exhaustive]` `MouseButton`).
- **D2** (Critical, tests that cannot pass) — T2.1 l.3753 and T4.1 l.6210 (goldens 16 392 / 16 398, plus `scale_abs(959, 1919) == 16 383`); T3.2 l.5400 (`queue_room: usize`, at most that many pushes per step, `next_report_at = now + pace`, `ROOM_POLL`, rig room 1, the new queue-room test) and T4.1 l.6433 (`8usize.saturating_sub(queued)`); T4.2 l.6669 (spawn `drive`, `wait_sent(&sink, 2)`, then push).
- **D3** (Critical, released-by-bridge gaps) — T2.1 l.3830 (`release_all` marks held modifiers; `press_usage` checks rbb first; `mark_released_by_bridge`, `is_released_by_bridge` l.4132); T2.1 l.4335 and T2.2 l.4552, l.4572 (the modifier test; `Pointer::rbb_buttons`, `release_all`, `button -> Option`; every core release path calls both); T3.2 l.5455 (swallowed presses marked rbb, epoch/Synchronize abort typing, both tests).
- **D4** (Critical, the CF_UNICODETEXT terminator) — T3.1 l.5034 (truncate at the first U+0000, the `ls\r\n` and `a\n` goldens); T5.2 l.7005 (the client's `\0\0` is what real clients send).
- **D5** (Critical, `hid-stale` could leave a key held) — T1.5 l.3444 (`STALE_BURST = 128`, alternating, ending on `KBD_ZERO`; `--settle-ms 5000`; snapshot inside `guarded`; a second release 5 s later; `StaleReport { pushed }`; no `hid_per_ws`); T1.6 l.3699 (step 9 records the yes/no and `keydown` vs 64).
- **D6** (Important, Part 1 safety) — T1.2 l.699 (`secret.rs`: errors never name the path; the new tests); T1.4 l.2927 and l.2980 (`Interrupts`, which `guarded` races: Ctrl-C, SIGTERM, SIGHUP; `hid-release`); T1.6 l.3678 (foreground HID runs, timeout ≥ runtime + 60 s, `hid-release` after any failure), l.3681 (order: HID steps right after step 1, token-life in the background after step 2, the page check before each HID run, no bridge or vendor KVM view), l.3674 (build once, `$KP`); T1.4 l.3095 (`hid-type --paces 0,5,10,15 --runs 3`, one login); T6.1 l.7239 ("Running" uses `$KP`).
- **D7** (Important, L4 facts unreadable as written) — T1.3 l.1478 (`concurrent-flv` drains stale AUs, `rx.is_empty()`, `at >= t0`); T1.4 l.2268 (the page resets on Esc; `type_text` sends Esc first; the sim test's Esc pair); T1.5 l.3505 (`EndArg`, `HOLD_USAGE = 0x1E`, `N_held`/`N_released`, `HidStale`, `WebGet`); T1.3 l.2096 and l.2212 (`logout-watch`, CLI and arm); T1.6 l.3711 (optional owner-run step 16).
- **D8** (Important, mapping vs §7 and DD3/5/7/9) — T2.1 l.3879 (remap at report time, raw held bits, the four remap tests); T2.1 l.4103 (`unicode_shift`/`unicode_down`); T2.1 l.4235 (Caps Lock toggles on a fresh press) and T3.2 l.5427 (the Synchronize-then-press test); T2.1 l.3999, T2.2, T4.1 l.6238 and T5.1 l.6932 (button events carry x, y); T2.2 l.4628 (only a held non-modifier `Pressed` resets the key-repeat timer); T2.1 l.4089 (`KeyReport::dropped`), T2.2 l.4871 (`Out::Ignored`), T4.1 l.6228 and l.6465 (counted); T2.1 l.3792 on (the ten named tests, written out).
- **D9** (Important, input/CLIPRDR wiring) — T3.3 l.5881 (`ServerEvents = Arc<OnceLock<…>>`, filled by `set_sender`); T4.1 l.6469 (sent only when set), l.6617 (`InputShared` built in `spawn`; `ShellParts`/`ShellDeps::input`; `rdp_main` spawns the driver); T5.2 l.6982 (`SendInitiateCopy` from `on_request_format_list`); T3.2 l.5303 (availability is the `ClipboardAvailable` event; `on_generation` resets it).
- **D10** (Important, L2 timing and §11.3 gaps) — T4.2 l.6790 (`input.reassert_after` key, leak shape, `sized()` 600 s); T5.3 l.7150 (its case sets 300 ms; its old Step 4 deleted); T5.1 l.6939 (two-keys and modifier-idle cases); T5.2 l.7050 (mid-typing key and 8 MiB cases).
- **D11** (Minor) — T1.1 l.218 (`EXCLUDED` gains 0x8C, 0x92–0x94, with the LANG5/F24 note; Step 5 checks them).
- **D12** (Minor, clippy) — T1.1 l.168; T1.3 l.842 (`Accepted(Box<Ws>)`, callers `*w`); T1.5 l.3328 (`saturating_add`, `use super::hid::{End, HidWs}`); T2.1 l.4036 (`checked_div`); T3.2 l.5311 (`fn chord_event()`, Esc by `usage_for_scancode`); T3.3 l.5979 (imports, `!bytes.is_empty()`, tokio receiver, no `drain`); T4.1 l.6174 (imports).
- **D13** (Minor) — T1.2 l.811 (`fn logout\(` grep; "the eight lines (cli.rs:104–111)").
- **D14** (Minor) — T1.3 l.1294 (a refusal body is read on to `FORM_BODY_MAX`).
- **D15** (Minor) — T1.3 l.1005 (`token_life` test gated by a `Notify`).
- **D16** (Minor) — T1.4 l.2722 (`SO_SNDBUF` set before connect via `socket2::Socket` + `TcpSocket::from_std_stream`; linger handle `SockRef::try_clone`).
- **D17** (Minor) — T3.3 l.6121 (the backend counts nothing; `metrics` field gone); T5.2 l.7054 (`== 1`).
- **D18** (Minor) — T3.3 l.6082 (only CF_UNICODETEXT is text, with its test).
- **D19** (Minor) — T3.3 l.6125 (interim routing: `Link::clip_slot`, `Fatal` → `UpstreamFatal`, the other two dropped until T4.1; rig and literal fields); T4.2 l.6790 (`reassert_after` in the `SessionConfig` literals).
- **D20** (Minor) — T4.1 l.6489 (`NoText` logged, no content).
- **D21** (Minor) — T4.2 l.6705 (the deadline checked at the loop top; the select arm only wakes; the motion test).
- **D22** (Minor) — T2.2 l.4969 (13 passed: the ten, D3a's, D3b's and D8e's); T4.1 l.6295 (`InputRuntimeConfig::test`, `hid_for_test`, `metrics_for_test` written).
- **D23** (Minor) — T5.2 l.6966 (`Opts::clipboard(mut self, &str)`, `CHORD_MODS`, `CHORD_KEY`, `paste_chord(c, release_mods)`, imports).
- **D24** (Minor) — header l.96 (the Carries row names `alter_candidate_frame` and its case); T5.3 l.7175 (`ConnCtx::acceptor: Mutex<TlsAcceptor>`, `KvmSim::ctx`, `Shared` untouched).
- **D25** (Minor) — T6.1 l.7207 (§8's rev 6.3 line deferring the `hid.lua?type=text` comparison to Plan E, controller ruling 2); T1.6 l.3713 (census.md:84 rewritten).
- **D26** (Minor) — T1.6 l.3670 (wipe captures if the session stops early); l.3687 (`UnexpectedEof` = FIN).
- **D27** (Minor) — T4.1 l.6376 (the `LocalSet` invariant on `InputShared`); l.6619 (`SessionStop` → `set_generation(0)`).

Verification re-scan (controller ruling 9; D29 replaces controller ruling 7):

- **D28** (Important, the HID rate was the probe's write rate) — T1.4 l.2268 and l.2271 (the page records its first and last keydown since Esc: `rate <n> <ms>`); T1.4 l.2823 (`TypeReport` prints `write_rate` and `kernel_buffered`, diagnostics only); T1.6 l.3695 (step 7 takes the KVM's rate from the pace-0 snapshots, `2·(n−1)·1000/ms`); T6.1 l.7217 (`CONTROL_SNDBUF` reads the page-measured rate); header l.90–91.
- **D29** (Important, 128 is the probe's cap, not the bridge's backlog) — header l.69 (DD8: `max(1 s, ceil(1800 / hid_rate))`, capped at `MAX_DURATION`, and the 64 KiB ÷ ~37 B receive-window assumption); T6.1 l.7218 (the retune rule; 1 s with no measured rate) and l.7212 (rev 6.3's §4.4 line states the assumption).
- **D30** (Important, the mid-typing case contradicted itself) — T5.2 l.7049 (only Q's press mid-typing; a repeat after the paste sends nothing; release, then a fresh press sends `kbd(0, 0x14)`).
- **D31** (Minor) — T1.3 l.850 and l.1114 ("none sends a HID frame except `logout-watch`'s one all-zero release, and none logs out").
- **D32** (Minor) — T1.3 l.2017 (`logout_watch` reads everything queued on the websocket before calling it survived).
- **D33** (Minor) — T1.6 l.3711 (step 16 runs `logout-watch` in the background, `Monitor` until READY, then the owner logs out, never before READY).
- **D34** (Minor) — T1.4 l.2927 (`Interrupts`, created once per HID command and passed to every `guarded`); l.3150 (`hid-type` checks it between runs; the settle sleeps race it); l.2454 (the sim test builds its own); T1.5 l.3627 (`hid-stale`'s 5 s wait races it, and the second release always runs).
- **D35** (Minor) — T5.2 l.6968 (`initiate_copy` on `on_request_format_list`, the server's Monitor Ready).
- **D36** (Minor) — T1.6 l.3681 (steps 3, 4 and 11 run before step 6 starts; step 6's refusals are "lapsed or evicted" until step 12 rules out a cap) and l.3693.
- **D37** (Minor) — T5.3 l.7175 (`KvmError::CertMismatch`).

Two refinements beyond the rulings' letter, both in Task 3.2, both for the same owner rule (a key is never left held), with tests:

- **D3c, while Pending:** a release still goes out (T3.2 l.5683). The chord's modifier presses reached the KVM before the chord was recognised, so if their releases were swallowed, a paste that then ends untyped (`modifier_wait`, `Multiline`, Esc, a click) would leave Ctrl+Option+Shift held on the Mac. While Typing, releases are swallowed exactly as D3c rules, since the Typist's full-state reports already zero them.
- **DD4 against the old Task 3.2 text:** the old text swallowed every key while Pending, but DD4 says a fresh non-modifier press cancels the paste and goes through. The pre-flight did not catch this. Task 3.2 now follows DD4: Esc cancels and is swallowed, a fresh non-modifier press cancels with `Aborted("key")` and goes through, and a second chord is swallowed (`a_fresh_key_while_pending_cancels_and_goes_through`, l.5501). DD4's line in the header says the same.
