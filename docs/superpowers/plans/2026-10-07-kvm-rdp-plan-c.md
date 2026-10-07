# kvm-rdp Plan C — the bridge core (Milestone 3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kvm-rdp`, the bridge: config, logging, metrics and the admin endpoints; the KVM session actor (pinned TLS, one login per session and never a logout, the main FLV through `kvm-proto` admission, side-FLV IDR requests and make-before-break reconnects, the control websocket and HID writer with its release epoch); the EGFX pump as a sans-IO state machine (§6.4–§6.6, §6.9) and its async shell; NLA, Preempt, generations and the §5 lifecycle on the IronRDP fork; graceful shutdown — proven by L1 sans-IO tests and L2 tests against kvm-sim with an in-process IronRDP client.

**Architecture:** One new crate, `crates/kvm-rdp` (lib `kvm_rdp` + bin `kvm-rdp`). Two runtimes, as §4.3 fixes: a current-thread runtime under a `LocalSet` owns IronRDP's `!Send` `RdpServer`, the IronRDP callbacks and the pump shell; a one-worker runtime owns the KVM actor, its FLV/websocket/side-FLV tasks, the HID writer and the admin listener. Every timing decision lives in a synchronous core that takes `now` — `pump::core::Pump::step(&mut GraphicsPipelineServer, now, Input) -> Vec<Command>` with `pump::flow`, `pump::idr` and `pump::debounce` beneath it, and `kvm::upstream` (backoff, auth gate, deadline) and `hid::queue` (release epoch) on the KVM side; the async shells only lock, call the core and carry out its commands.

**Tech Stack:** Rust 1.94.1 (edition 2024); IronRDP fork `ChristopherJMiller/IronRDP` branch `kvm-rdp-egfx-patches-v2` @ `c99eece22338e26ee6839ee89c29617bbcadbb65` (`ironrdp-server` with only `egfx`, `ironrdp-egfx`, `-dvc`, `-svc`, `-pdu`, `-core`; dev: `-connector`, `-async`, `-tokio`, `-tls` (`rustls`), `-session`, `-graphics`); tokio 1, rustls 0.23 + tokio-rustls 0.26 (aws-lc-rs only), hyper 1 (client, http1), tokio-tungstenite 0.24, x509-parser 0.16, toml 0.9, tracing-subscriber 0.3 (json, env-filter); kvm-sim (dev) and kvm-proto from Plans A/B; rcgen 0.13 (`aws_lc_rs`), tempfile and libc (dev: L2 certificates, temp dirs and the subprocess's SIGTERM).

**Spec:** `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (Draft rev 6.1, census-filled) — the binding authority — with `docs/census.md` (Legs A–C). This plan is §12's planning unit **C** (Milestone 3a): config, logging, admin endpoints, metrics, shutdown, lifecycle (§5), NLA, the EGFX pump and its state machine (§6.4–§6.6, §6.9), the KVM control websocket, the HID writer skeleton and release epoch (§7), L1 and the video/lifecycle L2. Plan B's plan (`docs/superpowers/plans/2026-10-06-kvm-rdp-plan-b.md`) is the format exemplar; Plan B's final review's "Re-review (final fix wave)" (`.superpowers/sdd/2026-10-06-kvm-rdp-plan-b/final-review.md`) is Task 1.1–1.2's brief.

**Scope:** in — everything above, and Plan B's carry-over (Part 1). Out, by §12: the scancode/US-layout mapping, mouse scaling, stuck-key timers, the released-by-bridge rule, the Typist and clipboard (Plan D — Plan C's input handler is a counting stub, and its L2 drives the HID writer through `HidControl` directly); L3, the image, kvm-bench, release builds and the perf pass (Plan E). Moved by this plan: §11.6's five L4 hardware checks go to Plan D's first task (DC18) — Plan D consumes two of them (the HID report rate for `paste.pace`; the Mac with a key held when the websocket dies, for §9.3 and the stuck-key rules).

**Design decisions** (one line each, with why):

1. **Crate layout — `crates/kvm-rdp`: lib `kvm_rdp` + bin `kvm-rdp` (`src/main.rs` only parses `--config`/`KVM_RDP_CONFIG`, logs, spawns, waits for SIGTERM/SIGINT), modules `config`, `logging`, `metrics`, `admin`, `msg` (generations, causes, the three channels' message types), `kvm::{endpoint, error, login, flv, ws, upstream, video, side, session}`, `hid::{queue, writer}`, `pump::{types, flow, idr, debounce, slate, core, shell}`, `rdp::{tls, accept, handler, gfx, display, input, server}`, `bridge`; one L2 test binary `tests/l2/`** — because §4.1 puts the bridge in one crate over `kvm-proto`, every module maps to one spec section, and one integration binary keeps IronRDP linked into exactly two test executables (lib + L2) (§13).
2. **Async architecture — RDP runtime: `current_thread` + `LocalSet` running `RdpServer::run`, a 1 s heartbeat, and the pump shell; KVM runtime: `multi_thread` with 1 worker running the KVM actor (one task per process, one `Session` per generation), the websocket/HID-writer task, side-FLV tasks, the admin listener and the certificate watcher. Channels: RDP→KVM `KvmCommand` unbounded (lifecycle and IDR commands only, rate-limited by the pump); KVM→pump `KvmEvent` bounded at `hard_cap + 8` (AUs by `try_send`, a drop marks the next AU `after_drop`; control by `send().await`); IronRDP callbacks→pump `RdpInput` unbounded (callbacks run under the GFX lock and may not block); HID release by an epoch `AtomicU64` + flag + `Notify`** — because §4.3 requires the two runtimes, the ordered never-dropped control stream and non-blocking callbacks, and a bounded AU stream is what makes "the KVM never sees back-pressure" true.
3. **Pump state machine — `enum State { Idle, WaitReady, NeedIdr, Live, WaitReactivation, Paused, Closing }` and one `match` per input in `Pump::step`, which runs under the GFX lock with `&mut GraphicsPipelineServer` (Setup, `send_avc420_frame`, `drain_output` in one hold) and returns `Command`s (`SendDvc`, `DisplayResize`, `ReleaseAll`, `OpenFlv`, `RequestIdr`, `ReconnectFlv`, `CancelIdrRequest`, `ProbeRtt`, `Disconnect`, `Abort`, `SurfaceSize`); `Idle` is "no generation"; flow gates, stall, ack-suspension mirroring and standing delay are `pump::flow`, IDR acquisition is `pump::idr`, suppression debounce is `pump::debounce`; Task 4.6 tests every cell of §6.4's table** — because §4.3 makes the step function the unit of truth and §11.2 demands one L1 case per cell against the real `GraphicsPipelineServer`.
4. **IDR requests — the pump's `IdrCore` owns `idr_pending`, the idr-wait accounting, the two clocks (setup 1 s, flow 10 s), deferral, cancellation and the side fallback; `side` → `RequestIdr` → the session spawns a side FLV on the session's token that reads through `FlvDemuxer` to its first tag and closes (counted, never retried, never re-logged-in); no IDR `idr_side_timeout` later → `ReconnectFlv` on the same clock → the session opens a second main FLV and swaps at its first tag (make-before-break), emitting `FlvOpened{Commanded}`** — because Leg A showed any new FLV forces an IDR from the shared encoder (§6.5), and keeping every timing rule in the sans-IO core makes §11.2's IDR cases exact.
5. **Config and secrets — one TOML file (`toml` 0.9, `deny_unknown_fields`), every §4.4 key with its default, durations as `"250ms"`/`"1.6s"` strings bounded to ≤ 1 h; secrets only from files (`kvm.password_file`, `rdp.nla_password_file`, `rdp.tls_cert_file`, `rdp.tls_key_file`, relative to the config's directory, ≤ 4 KiB, one trailing newline trimmed) held in a `Secret` whose `Debug` is `<redacted>`; the NLA password must be ≥ 22 characters (128 bits as base64); no environment variable but `KVM_RDP_CONFIG` is read; validation fails before anything binds** — because §4.4/§9.1/§9.2 fix the rules and the bounds make every `Instant + Duration` in the cores overflow-free.
6. **Metrics and admin — a hand-rolled registry (atomics, label families keyed by `&'static str`, five histograms with per-histogram bounds and unit — every §10.4 metric that belongs to Plan C's scope) rendered as Prometheus text; one admin listener on the KVM runtime serving `/metrics`, `/livez` (heartbeat age ≤ `admin.liveness_timeout`, 10 s) and `/readyz` (TLS identity loaded and the RDP listener's address answered by `ServerEvent::GetLocalAddr`) with a 2 KiB/2 s bound per request; it binds `admin.listen` (`0.0.0.0:9464` by default; exposure is the companion spec's NetworkPolicy/firewall, §9.4)** — because §4.5 fixes the endpoints, no metrics crate is worth its compile time, and labels never carry device text.
7. **Shutdown — `on_accept` refuses once shutdown starts; release-all and `KvmCommand::FlushHid` (≤ 500 ms); the pump closes the live session with cause `shutdown` (ErrorInfo 0x1) and a 2 s watchdog that aborts through `ConnectionInfo::abort_handle()`; `KvmCommand::Shutdown` closes websocket, FLVs and side FLVs (≤ 1 s, **never a logout** — the KVM client has no logout function at all); then `ServerEvent::Quit`, and a second `Quit` if `run()` has not returned 500 ms later (a `Quit` consumed by a live connection ends only it, §5.2); exit 0 within 5 s; a changed TLS certificate (60 s poll) runs the same sequence, but only once no client is connected (DC21)** — because §5.2 and §4.4 fix the order and the bound, §3.2 forbids logout outright, and the deployment spec's decision 8 (Plan B ledger) forbids an LE renewal cutting a live session.
8. **IronRDP build budget — one git rev in `[workspace.dependencies]` for every `ironrdp-*` crate; `ironrdp-server` with `default-features = false, features = ["egfx"]` (no rayon/qoi/zstd, no `helper`), `ironrdp-egfx` without openh264, never the meta-crate; the only test-only IronRDP compile units are `ironrdp-session` and `ironrdp-tls`'s `rustls` backend (connector, async, graphics, tokio and tls are already in `ironrdp-server`'s own graph); every local command is `cargo {clippy,test} --workspace --all-targets --all-features`, never `-p`, so one feature resolution compiles each crate once per profile; no local `--release`, no `cargo doc`; `[build] incremental = false`; one shared `CARGO_TARGET_DIR` (scratch worktrees use their own and delete it); `scripts/target-budget.sh` fails the gate above `KVM_RDP_TARGET_BUDGET_GIB` (default 8, set in Task 2.1 from the measured size + 30 % and re-measured once in Task 6.1, when the binary and the L2 executable exist; over budget straight after one `cargo clean` means stop and report) and prints the one cleanup that is always safe (`cargo clean`)** — because an unmanaged IronRDP target grows past 20 GB (Plan B's final review measured 18 GB without IronRDP churn) on a host with 112 GB free.
9. **Generations — `on_connection_info` mints `generation` (`Generations::begin`), binds it to the GFX handle the factory built for this connection (`build_server_with_handle` runs once per served connection and always before its `on_connection_info` — before auth in `attach_channels` for a fresh connection, after CredSSP in `serve_negotiated` for a Preempt winner — and stores the latest `(slot, handle)`), and pushes `RdpInput::SessionStart` to the pump before sending `KvmCommand::Start`; `on_disconnected` swaps the generation to none before returning, releases all, pushes `SessionStop`, sends `Stop`; every `KvmEvent` carries its `generation` and the pump drops the rest; the pump's `biased` select drains `RdpInput` first, so a KVM event never overtakes its session's start** — because §4.3 requires synchronous invalidation and "only the current generation" for every `ServerEvent`, and IronRDP's GFX callbacks arrive on the RDP thread before the KVM side has logged in.
10. **L2 harness — the bridge spawned in-process (`bridge::spawn` → `BridgeHandle` with its RDP thread and KVM runtime), kvm-sim on the test runtime (multi-thread, 2 workers), and an IronRDP client (`ironrdp-connector`/`-async`/`-session` with NLA, a capture `DvcProcessor` for EGFX that ZGFX-decodes, records every PDU and acks per mode) on its own thread with its own `LocalSet`, each client bound to its own `127.0.0.N` source address; scaled configs and one-sided asserts (§11.1)** — because §11.3 asks for exactly this stack and the source-address rule keeps Preempt's cooldown from coupling tests.

## Global Constraints

Copied from the spec; every task's requirements include these.

- "Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1" (§4.2).
- §4.1: `kvm-rdp` depends on "`kvm-proto`, IronRDP, tokio, rustls (aws-lc)"; "Every hostile-input parser lives in `kvm-proto`".
- §4.2: "**IronRDP is git-pinned**: one rev … for every `ironrdp-*` crate used (including `ironrdp-pdu`, for ErrorInfo codes), as direct git dependencies in `[workspace.dependencies]` — no `[patch.crates-io]`." Plan C pins the fork branch `kvm-rdp-egfx-patches-v2` at `c99eece2`, which carries three patches over upstream `2c08bda7`: (1) ack suspension survives `FrameTracker::clear`; (2) `EgfxServerMessage::send_messages(..).with_write_counter(counter, weight)`; (3) `ConnectionInfo::abort_handle()` plus a bounded disconnect teardown.
- §4.2: "CI fails if `cargo tree -d` shows a duplicate `ironrdp-*` crate."; "Never the `ironrdp` meta-crate. `ironrdp-egfx` without `openh264`."; "**One crypto provider, aws-lc-rs**, installed idempotently at startup (`let _ = install_default()`). Nothing may pull in `ring`."
- §4.3: "`RdpServer` is `!Send`: it runs on a current-thread runtime under a `LocalSet`. Everything touching the KVM runs on a separate one-worker runtime."; "Every time-dependent decision … lives in a synchronous core that takes `now: Instant` and returns commands"; "`GraphicsPipelineHandler` callbacks run with the GFX mutex held: they only set flags or push inputs, never lock the handle. The pump calls `send_*`/Setup **and** `drain_output()` within one lock hold"; "`kvm-rdp`'s crate root sets `#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref)]` and CI runs clippy with `-D warnings`."; "Every `ServerEvent` send, including `Disconnect`, is only made for the current generation."
- §4.4: "One TOML file, path from `--config` or `KVM_RDP_CONFIG`. Environment variables other than that path (including `RUST_LOG`) are not read. Secrets come only from files named in the config … and are never logged. The file is validated at startup; any error exits non-zero before binding."
- §4.5: "a **second, independent `Targets` filter** holds `ironrdp_*`, `sspi`, `tungstenite`, `tokio_tungstenite`, `hyper` and `rustls` at INFO … combined with it via `FilterExt::and`, so nothing in config can raise them"; "Bridge code never logs keystrokes, HID frames, pasted text, the KVM token or passwords … URLs are logged as `scheme://host:port/path`, query removed. No per-frame events above `trace`."
- §3.2: "**The bridge never calls logout.**"; "`TCP_NODELAY` on every KVM socket."; "Websocket limits: max message and frame 4 KiB, small write buffer; inbound data messages are read and discarded; an oversize message closes the socket without buffering it."; "There is no accept-any verifier."
- §5.1: "**No KVM traffic before auth.**"; "`RdpServer::run()` with **`ConnectionPolicy::Preempt`**".
- §5.2: "exit within 5 s"; "stopping the server takes a second `Quit` after that connection has drained"; "Release builds use `panic = "abort"`."
- §9.1: "The release binary only ever calls `with_hybrid`."; "TLS: our own rustls `ServerConfig` (not `TlsIdentityCtx::make_acceptor`, which honours `SSLKEYLOGFILE`)".
- §9.2: "KVM password, NLA password, TLS key, the KVM token, keystrokes, HID frames and pasted text are never logged (§4.5). Secrets come only from files (§4.4)."
- §11.1: "L2 checks wiring only, with scaled-down configs … and one-sided asserts: *happens within 5× the configured value* and *does not happen before 0.5× of it*."; "Each L2 test client binds its own loopback source address (127.0.0.2, 127.0.0.3, …)".
- §13 ("The rules are mechanical, not advisory"), verbatim: "`.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"`"; "The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`"; "One shared `CARGO_TARGET_DIR` across any worktrees, never one per worktree"; "Profiles: `[profile.dev] debug = "line-tables-only"`, dependencies `debug = false`; `[profile.release] lto = "thin", codegen-units = 16, debug = "line-tables-only", panic = "abort"` … One integration-test binary (`autotests = false`); `CARGO_INCREMENTAL=0` in CI" — plus the owner's rules: scratch git worktrees use their **own** `CARGO_TARGET_DIR` (a shared-target test binary breaks when its worktree is deleted) and delete it afterwards; IronRDP feature sets stay minimal; target size is gated (Design decision 8).
- Owner: panic-free code over hostile KVM input; no secrets, tokens or captures committed; licence MIT OR Apache-2.0; every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

Five inputs or conditions the spec implies but no §11 case names, most likely to bite first; each line's test is in the owning task.

1. **A client that connects and drops again while the KVM side is still logging in or opening** (rdpgw retries, a flaky laptop) → `Stop` cancels the in-flight login/open at once, never leaves a websocket or FLV open, never logs out, and the next `Start` begins clean — never two websockets (Task 3.8 `start_stop_storm_leaves_nothing_open`).
2. **A secret file written with `echo` (trailing `\n`) or on Windows (`\r\n`)** → exactly one line ending is trimmed, inner and leading spaces are kept, an empty file is refused — otherwise NLA fails with a "wrong password" nobody can see (Task 2.2 `secret_files_lose_one_line_ending_only`).
3. **A hostile KVM answering login with an endless body, a 1 MiB header, or nothing at all** → login fails within `login_timeout`, buffers at most 64 KiB of body and 16 KiB of response head (hyper's `max_buf_size`, set explicitly — its default is ~400 KiB), and the failure carries no device text (Task 3.2 `hostile_login_responses_are_bounded`).
4. **Slow or oversized requests to the admin port** (a scanner on 9464) → a request head over 2 KiB is answered 431 and closed, a silent connection is dropped after 2 s, and `/livez` keeps answering meanwhile (Task 2.5 `slow_or_huge_admin_requests_do_not_wedge_livez`).
5. **SIGTERM while a client is connected and the KVM is unreachable** (the actor stuck in a TLS handshake that never answers) → the client still gets ErrorInfo 0x1, and the process is out within 5 s (Task 6.6 `shutdown_completes_with_the_kvm_unreachable`, the real binary under a real SIGTERM).

## Recorded deviations from the spec

Task 7.1 writes these into the spec as rev 6.2. None admits anything the spec refuses.

- **DC1 — burst marking uses a sliding median baseline** (Plan B final review I3, replacing D11): an AU is `burst` when its delivery delay (receive time − FLV timestamp) is more than 100 ms below the **median** delay of the AUs received in the last 1 s on that FLV connection (≤ 256 kept). A baseline fixed at the first coded tag marked every later AU after one late tag (300/300 measured), which disabled the soft gate and blinded kvm-bench; a sliding *maximum* would do the same for a second after any late tag, and the census's https inter-tag maximum is 136 ms (one tag ~103 ms late). With the median a replay is still marked (from its seventh AU), live AUs after it stop being marked within 1 s, and a late first tag or one late tag mid-stream marks nothing (Task 1.1's L0 cases).
- **DC2 — `ironrdp-server` uses only the `egfx` feature** (§4.2 said `["egfx", "helper"]`): `helper`'s only item, `TlsIdentityCtx`, is what §9.1 forbids; PEM loading uses `rustls-pki-types`' `PemObject`, and the CredSSP public key comes from x509-parser (already in the workspace).
- **DC3 — the fork carries three patches, and the patch-1 fallback is not built**: §6.9's "aborts the connection (§4.2 patch 4)" is patch 3 (`ConnectionInfo::abort_handle()`); the shadow suspension flag and `InjectSuspendAck` (§4.2 patch 1's fallback, §6.4 Setup) are unnecessary with patch 1 pinned.
- **DC4 — `SessionStart`/`SessionStop` reach the pump from the RDP side**, not through the KVM stream (§4.3): every `KvmEvent` carries its generation, the pump drops other generations' events, and its `biased` select drains the RDP side first — so no KVM event can overtake its session's start, and the GFX handle (an RDP-side object) travels with the start.
- **DC5 — config placement and additions** (§4.4): secrets are `kvm.password_file`, `rdp.nla_password_file`, `rdp.tls_cert_file`, `rdp.tls_key_file`; new keys `admin.liveness_timeout` (10 s, §4.5's constant made configurable for L2), `rdp.cert_poll_interval` (60 s), `security.accept_window` (60 s); durations are strings (`"250ms"`, `"1.6s"`) bounded to ≤ 1 h; the NLA password must be ≥ 22 characters.
- **DC6 — samples are taken by the shell** (§4.3 inputs): every 50 ms tick and before each AU the shell feeds `Suppress(flag)` and `Backlog{written}`; the `Rtt` sample is the handle's value read immediately before each `ProbeRtt` (so it reflects the previous probe); the shell feeds every read, and the core's `Rtt` — fresh per generation — keeps the generation's first read as its reference only and goes live once the handle moves (the handle is per server). The rule lives in that one place: applied in the shell as well, it made the first live answer the reference and kept it out of the baseline.
- **DC7 — Plan C's input handler is a counting stub**; L2's input cases drive `HidControl` directly (the handler's only production entry point). The Preemption case pushes a pointer report through it before the takeover and asserts the new session-start sequence is exactly `[SET_MODE, KBD_ZERO, pointer at the evicted session's last position]` — never a pointer at (0, 0); Plan D adds the handler.
- **DC8 — the FreeRDP 11-set capability ladder fixture moves to Plan E's L3** (FreeRDP is not in the flake yet); Plan C's L1 replays the census V8/V8_1 pair and IronRDP's own 11-set ladder.
- **DC9 — the §11.3 secrets-hygiene case runs without the keystroke sentinel and paste canary** (Plan D adds them) and spawns the binary through `CARGO_BIN_EXE_kvm-rdp` (kvm-bench's harness is Plan E's).
- **DC10 — the §13 target budget is exceeded by IronRDP's graph**; Task 2.1 records the measured size, the gate in `scripts/target-budget.sh` replaces "~1.5 GB", and `[build] incremental = false` is committed.
- **DC11 — `CancelIdrRequest` is pump-internal**: deferred requests live in `IdrCore`, so the command only reaches the shell's metrics.
- **DC12 — an AU dropped on a full KVM→pump channel marks the next delivered AU `after_drop`**, which the pump treats as the flow cause (§6.5) — the ordered stream carries the cause, so no side channel can reorder it.
- **DC13 — "stop accepting" is `on_accept` refusing once shutdown begins** (`RdpServer::run` owns the listener); the shutdown's disconnect watchdog is 2 s, not `disconnect_watchdog`, to fit §5.2's 5 s.
- **DC14 — the KVM→pump channel's capacity is `hard_cap + 8`** (§4.3: "≥ the hard cap").
- **DC15 — `security.accept_rate` counts admitted attempts only**, so a refused flood does not extend its own lockout past the window.
- **DC16 — `/readyz` means "TLS identity loaded and `GetLocalAddr` answered"**, the observable form of §4.5's "the RDP listener is bound".
- **DC17 — the L1 rig decodes with IronRDP's own PDU types, not `ironrdp_egfx::client::GraphicsPipelineClient`** (§11.2 says "`GraphicsPipelineServer` ↔ `GraphicsPipelineClient` in memory"): the L1 cases assert the exact PDU sequence and the AVC420 payload bytes, which a client consumes through its handler rather than exposes; the rig ZGFX-unwraps and decodes `GfxPdu`s, and its `wire()` asserts every `WireToSurface1` is AVC420 (§11.2's "only AVC420 `WireToSurface1` is ever sent"). IronRDP's client stack (connector, session) runs in L2.
- **DC18 — §11.6's five L4 hardware checks move to Plan D's first task**: the Mac with a key held when the websocket dies (→ §9.3), side request → main-FLV IDR latency over 20 trials, how a preset change is signalled, how long an abandoned token stays valid and whether the ES3 caps concurrent sessions, and the KVM's HID report rate (→ `paste.pace`). Three need HID input the probe has never sent and Plan D's mapping is the first code that sends it; the two Plan D consumes are measured right before it uses them; the bridge ships no input path before Plan D, so nothing deployed depends on them first. Plan C covers the bridge side on kvm-sim: the `side` default and its fallback (Task 6.3), all three resize signals (Task 6.4), the websocket surviving a global logout (Task 6.5). Plan A's "Assumption for Plan C L4: the control websocket survives another session's logout" is one of these checks on the real ES3 and moves with them.
- **DC19 — the CI job timeout and the tracked-secrets gate land here** (Task 7.1), ahead of Plan E's CI work (M5): the L2 suite needs a bound on a hung case, and the owner's no-secrets-or-captures rule applies from the first commit that writes secret files in tests.
- **DC20 — `video.sps_rewrite` must name all three rewrites**: §6.8 makes the rewrite required ("there is no pass-through"), so config validation refuses a set lacking `level`, `vui` or `restriction` rather than starting a bridge whose every ES3 session would end `stream_incompatible`.
- **DC21 — a renewed certificate restarts the bridge only once no client is connected** (§4.4 said "on change, runs graceful shutdown"): the companion deployment spec's decision 8, ruled in Plan B's ledger — an LE renewal must not cut the operator's live session; the watcher polls `Generations::current()` (≤ 1 s) after the change and exits when it is `None`.
- **DC22 — disposable scratch worktrees use their own `CARGO_TARGET_DIR`** and delete it afterwards (§13 said "never one per worktree"): a shared-target test binary bakes in its worktree's `CARGO_MANIFEST_DIR` and breaks when that worktree is deleted (Plan B's process lesson); long-lived worktrees still share one target.

## Plan B carry-overs

Folded in: final review I3 (`BurstMarker` baseline, Task 1.1, with spec §6.2/D11), N1 (`wait_for` returns a log at least as new as its predicate saw, Task 1.2), N2 (§11.5 source-burst wording, Task 1.2); the ledger's "Plan C" notes — the abort handle is taken in `on_connection_info` only (Task 5.2), `send_messages(..).with_write_counter(..)` (Task 5.3), a mid-connection `Quit` ends only that connection (Task 5.4), upstream drops pre-queued events except the lifecycle allowlist (Task 5.4 never queues a session event before a connection), the side-FLV IDR path (Tasks 3.7, 3.8), the POC-0 stranding re-check that Plan A's ledger and spec §6.8 (row 4) hand to Plan C's L2 — the last AU kvm-sim ships on the ES3-shaped POC-type-0 fixture reaches the client with no further input, and the SPS the client gets carries the rewritten VUI, level and `bitstream_restriction` (Task 6.3 `the_last_au_shipped_reaches_the_client_and_its_sps_is_rewritten`), and the deployment ruling "kvm-rdp defers cert-rotation restart until no client is connected (carry to Plan C/E)" (Task 5.4, DC21).
Moved, not folded: Plan A's "Assumption for Plan C L4: the control websocket survives another session's logout" — kvm-sim models survival and Task 6.5 asserts the bridge keeps its websocket on kvm-sim, which says nothing about the real ES3; the hardware check moves with §11.6's other L4 items to Plan D (DC18).
Not folded: Plan B's deferred minors on kvm-sim internals (PB14 m3/m5–m9, PB15, PB16 n1/m5–m7) — no Plan C test depends on them.

## Execution notes

- Repo `/home/chris/Repos/kvm-rdp`, branch `plan-c` (already checked out). Task numbers are `Part.N`; parts run in order.
- Every command runs inside `nix develop` from the repo root (the §13 cargo wrapper). Run `cargo fmt --all` before every commit; `git add` exact paths, never `-A`; never commit anything under `.superpowers/`, `target/` or `captures/`.
- **The per-task gate**: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, then `scripts/target-budget.sh`. Always these flags: one feature resolution means each IronRDP crate compiles once per profile. Never `cargo build --release`, `cargo doc` or `cargo test` without `--all-features` locally.
- **Never `-p` for a build or a test.** `-p` changes feature unification (`cargo tree -p kvm-sim --all-features` resolves tokio without `test-util` and kvm-proto without `fuzzing`; the workspace resolves both on), so every tokio and kvm-proto dependent — IronRDP included — would compile a second time, and the IronRDP-linked test executables would double. A TDD step runs its filter in the gate's resolution: `cargo test --workspace --all-features --lib -- <filter>` for unit tests, `cargo test --workspace --all-features --test l2 -- <filter>` for L2 (other crates' tests matching the filter are harmless). `cargo tree -p …` (no compile) is fine.
- The first build after Task 2.1 fetches the fork over https from GitHub; later builds are offline-capable.
- **Scratch worktrees** (reviewers, experiments) set their own `CARGO_TARGET_DIR` under the session scratchpad and delete it when done; never point a scratch worktree at the shared target. The devshell's shellHook exports `<main checkout>/target` in every worktree *unless `CARGO_TARGET_DIR` is already set*, so set it on the way in: `CARGO_TARGET_DIR="$SCRATCH/wt-target" nix develop --command cargo …` (from the scratch worktree), and `rm -rf "$SCRATCH/wt-target"` when finished. Spec §13 is amended to match in Task 7.1 (rev 6.2).
- Expected counts in "Run … Expected: N passed" lines are minimums: the gate is "0 failed and every named test exists and passes".
- L2 tests need no network beyond loopback and no extra tools; they are part of `cargo test --workspace --all-features`.

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `crates/kvm-proto/src/flv/{burst,mod}.rs`, `src/video/{mod,tests}.rs` | Sliding median burst baseline, `BURST_WINDOW`, the seventh-AU burst case | 1.1 |
| `crates/kvm-sim/src/{state,lib}.rs`, `tests/sim/flv.rs` | `wait_for` final catch-up; burst wording | 1.2 |
| `Cargo.toml`, `.cargo/config.toml`, `scripts/target-budget.sh`, `.github/workflows/ci.yml` | IronRDP pin, budget gate, duplicate gate | 2.1, 7.1 |
| `crates/kvm-rdp/Cargo.toml`, `src/lib.rs`, `src/pin_goldens.rs` | Crate, lints, IronRDP goldens; `[[bin]]` (5.4), `[[test]] l2` and `libc` (6.1) | 2.1, 5.4, 6.1 |
| `crates/kvm-rdp/src/config.rs` | TOML config, defaults, secrets; `config_path` | 2.2, 5.4 |
| `crates/kvm-rdp/src/logging.rs` | JSON logs, capped targets | 2.3 |
| `crates/kvm-rdp/src/metrics.rs` | Registry and Prometheus text | 2.4 |
| `crates/kvm-rdp/src/admin.rs` | `/metrics`, `/livez`, `/readyz` | 2.5 |
| `crates/kvm-rdp/src/msg.rs` | Generations, causes, channel messages | 3.1 |
| `crates/kvm-rdp/src/kvm/{mod,error,endpoint,login}.rs` | Pinned TLS, login | 3.2 |
| `crates/kvm-rdp/src/kvm/{flv,ws}.rs` | FLV connection, control websocket | 3.3 |
| `crates/kvm-rdp/src/kvm/upstream.rs` | Backoff, auth gate, deadline | 3.4 |
| `crates/kvm-rdp/src/hid/{mod,queue}.rs` | Release epoch, report queue | 3.5 |
| `crates/kvm-rdp/src/hid/writer.rs` | Websocket task and HID writer | 3.6 |
| `crates/kvm-rdp/src/kvm/{video,side}.rs` | The main FLV state machine, the side-FLV IDR request | 3.7 |
| `crates/kvm-rdp/src/kvm/session.rs` | The KVM actor | 3.8 |
| `crates/kvm-rdp/src/pump/{mod,types,slate}.rs` | Pump vocabulary, slate | 4.1 |
| `crates/kvm-rdp/src/pump/flow.rs` | Gates, unacked set, stall, standing delay | 4.2 |
| `crates/kvm-rdp/src/pump/idr.rs` | IDR acquisition | 4.3 |
| `crates/kvm-rdp/src/pump/{debounce,core,rig}.rs` | Suppression debounce, the state machine, L1 rig | 4.4–4.6 |
| `crates/kvm-rdp/src/rdp/{mod,tls,accept}.rs` | RDP TLS identity, accept rate | 5.1 |
| `crates/kvm-rdp/src/rdp/{handler,gfx,display,input}.rs` | IronRDP callbacks | 5.2 |
| `crates/kvm-rdp/src/pump/shell.rs` | The pump's async shell | 5.3 |
| `crates/kvm-rdp/src/{rdp/server,bridge,main}.rs` | Assembly, shutdown, binary | 5.4 |
| `crates/kvm-rdp/tests/l2/{main,harness,client}.rs` | L2 harness (with the barcode oracle helpers) and client | 6.1 |
| `crates/kvm-rdp/tests/l2/{lifecycle,sessions,video,resize,faults,flow,hid,admin}.rs` | L2 cases | 6.1–6.6 |
| `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`, `README.md` | Rev 6.2 | 1.1, 1.2, 7.1 |

---

## Part 1 — Plan B carry-overs

Plan B's final review left one Important finding and two minors; the ledger ruling makes them Plan C's first work, before anything relies on `AccessUnit::burst`.

### Task 1.1: `BurstMarker` — a sliding median baseline (I3), spec §6.2

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/burst.rs` (whole file)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/mod.rs` (re-export `BURST_WINDOW`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/mod.rs` (two doc comments)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/tests.rs` (`bursts_are_marked_against_real_time`)
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (§6.2 Bursts bullet, rev 6.1 preface, a rev 6.2 stub)
- Test: `crates/kvm-proto/src/flv/burst.rs` (`tests`)

**Interfaces:**
- Consumes: nothing new.
- Produces: unchanged API — `BurstMarker::new(threshold: Duration) -> BurstMarker`, `reset(&mut self)`, `mark(&mut self, flv_ts_ms: u32, now: Instant) -> bool` — plus `pub const BURST_WINDOW: Duration` (1 s), re-exported as `kvm_proto::flv::BURST_WINDOW`. `AccessUnit::burst` keeps its type and meaning ("ran more than 100 ms ahead of real time"); only the baseline changes (DC1): the **median** delivery delay of the last second on the connection, so one late tag cannot mark the on-time AUs after it.

The baseline was chosen against the census (`docs/census.md` Leg A: https inter-tag jitter max 136 ms, i.e. one tag about 103 ms late). A sliding *maximum* would treat that tag as the baseline and mark the next second of on-time AUs `burst` — the same harm I3 was raised for (no soft gate, excluded from kvm-bench latency). The median is outvoted by neither a late first tag nor one late tag, and a replay still drives it: in a replay the median trails the replay itself, so the first six AUs of a back-to-back batch are unmarked and every later one is (`bursts_are_marked_against_real_time` changes from "the fifth" to "the seventh"). Verified in a scratch copy: kvm-proto's 175 + 9 tests pass and clippy is clean with the code below.

- [ ] **Step 1: Write the failing tests.** Append inside `mod tests` in `crates/kvm-proto/src/flv/burst.rs` (after `reset_rebaselines_on_new_connection`):

```rust
    /// I3 (Plan B final review): a GOP-caching replay is marked, and the
    /// live frames that follow stop being marked within `BURST_WINDOW` —
    /// the old baseline, fixed at the first coded tag, marked 300 of 300.
    #[test]
    fn a_replay_is_marked_and_live_frames_after_it_stop_within_the_window() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut m = BurstMarker::new(Duration::from_millis(100));
        // 60 frames (2 s of timestamps) replayed in 60 ms of receive time …
        let replayed = (0..60u32)
            .filter(|&i| m.mark(i * 33, at(u64::from(i))))
            .count();
        assert_eq!(
            replayed, 54,
            "frames 6..=59 run > 100 ms below the median delay before them"
        );
        // … then live at the real cadence, 1920 ms ahead of the first tag.
        let mut marked = Vec::new();
        for j in 60..360u32 {
            let recv = u64::from(j) * 33 - 1920;
            if m.mark(j * 33, at(recv)) {
                marked.push(recv);
            }
        }
        assert!(marked.len() <= 31, "{} live frames marked", marked.len());
        assert!(
            marked.iter().all(|&r| r <= 1100),
            "a live frame was marked after the window: {marked:?}"
        );
    }

    /// I3's second scenario: a real-time source whose first coded tag is
    /// read 150 ms late (the bridge busy at connect) — every later AU was
    /// marked; now none is.
    #[test]
    fn a_late_first_tag_marks_nothing_after_it() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        let mut marked = Vec::new();
        for i in 0..300u32 {
            let recv = u64::from(i * 33).max(150);
            if m.mark(i * 33, t0 + Duration::from_millis(recv)) {
                marked.push(recv);
            }
        }
        assert!(
            marked.is_empty(),
            "{} frames marked, the first {:?}",
            marked.len(),
            marked.first()
        );
    }

    /// The census's worst https inter-tag gap (136 ms, `census.md` Leg A):
    /// frame 100 read 103 ms late with 101..=103 in the same read, then on
    /// time. A baseline at the window's *largest* delay would mark the next
    /// second of on-time AUs (about 30); the median marks none.
    #[test]
    fn one_late_tag_mid_stream_marks_nothing_after_it() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        let mut marked = Vec::new();
        for i in 0..300u32 {
            let recv = if (100..=103).contains(&i) {
                100 * 33 + 103
            } else {
                u64::from(i * 33)
            };
            if m.mark(i * 33, t0 + Duration::from_millis(recv)) {
                marked.push(i);
            }
        }
        assert!(
            marked.is_empty(),
            "{} frames marked, the first {:?}",
            marked.len(),
            marked.first()
        );
    }

    /// A hostile stream (every tag at one instant) cannot grow the window.
    #[test]
    fn the_baseline_window_is_bounded_under_a_hostile_stream() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        for i in 0..100_000u32 {
            let _ = m.mark(i, t0);
        }
        assert!(m.window.len() <= 256, "{}", m.window.len());
    }
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test --workspace --all-features --lib -- flv::burst`
Expected: FAIL to compile — `no field window on type BurstMarker`. (With that one assertion commented out, the old marker fails two cases — the replay with `left: 56, right: 54`, the late first tag with "296 frames marked" — and passes `one_late_tag_mid_stream_marks_nothing_after_it`, which guards against a sliding-maximum baseline rather than the old one.)

- [ ] **Step 3: Implement.** Replace everything above `#[cfg(test)]` in `crates/kvm-proto/src/flv/burst.rs` with:

```rust
use core::time::Duration;
use std::collections::VecDeque;
use std::time::Instant;

/// How far back, in receive time, the burst baseline looks (§6.2, rev 6.2).
pub const BURST_WINDOW: Duration = Duration::from_secs(1);

/// Bound on the baseline window: a hostile source cannot grow it.
const MAX_SAMPLES: usize = 256;

/// Marks access units that arrive faster than real time — a GOP-caching
/// source replaying on connect (§6.2). An AU is a burst when its delivery
/// delay (receive time − FLV timestamp) is more than `threshold` below the
/// median delay of the AUs received in the last `BURST_WINDOW` on this FLV
/// connection (rev 6.2, DC1). A replay is marked; a late first tag, a past
/// replay or one late tag mid-stream is outvoted by the on-time AUs around
/// it and marks nothing after it. State is per FLV connection; `reset`
/// starts afresh. The caller (`video::VideoAdmission::coded`) calls `mark`
/// for coded tags only.
pub struct BurstMarker {
    /// Receive-time origin of this connection (its first marked tag).
    epoch: Option<Instant>,
    /// `(receive ms since epoch, delay ms)` in arrival order: at most
    /// `MAX_SAMPLES`, none older than `BURST_WINDOW`.
    window: VecDeque<(i64, i64)>,
    /// Scratch for the median, reused so `mark` does not allocate.
    sorted: Vec<i64>,
    threshold: Duration,
}

impl BurstMarker {
    pub fn new(threshold: Duration) -> Self {
        Self {
            epoch: None,
            window: VecDeque::with_capacity(MAX_SAMPLES),
            sorted: Vec::with_capacity(MAX_SAMPLES),
            threshold,
        }
    }

    pub fn reset(&mut self) {
        self.epoch = None;
        self.window.clear();
    }

    /// Record a tag's FLV timestamp (ms) and receive time; returns whether
    /// it is a burst. The first call after construction or `reset` is never
    /// a burst.
    pub fn mark(&mut self, flv_ts_ms: u32, now: Instant) -> bool {
        let epoch = *self.epoch.get_or_insert(now);
        let recv =
            i64::try_from(now.saturating_duration_since(epoch).as_millis()).unwrap_or(i64::MAX);
        let delay = recv.saturating_sub(i64::from(flv_ts_ms));
        let window = i64::try_from(BURST_WINDOW.as_millis()).unwrap_or(i64::MAX);
        while let Some(&(at, _)) = self.window.front() {
            if recv.saturating_sub(at) > window {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.sorted.clear();
        self.sorted.extend(self.window.iter().map(|&(_, d)| d));
        self.sorted.sort_unstable();
        let threshold = i64::try_from(self.threshold.as_millis()).unwrap_or(i64::MAX);
        let burst = self
            .sorted
            .get(self.sorted.len() / 2)
            .is_some_and(|&median| delay < median.saturating_sub(threshold));
        if self.window.len() >= MAX_SAMPLES {
            self.window.pop_front();
        }
        self.window.push_back((recv, delay));
        burst
    }
}
```

In `crates/kvm-proto/src/flv/mod.rs` replace `pub use burst::BurstMarker;` with `pub use burst::{BURST_WINDOW, BurstMarker};`.

In `crates/kvm-proto/src/video/tests.rs`, `bursts_are_marked_against_real_time`: replace the comment and the `run(&[ … ])` call with

```rust
    // All tags "arrive" at t0 while their timestamps run 33 ms apart: the
    // seventh AU's delay is 132 ms below the median of the six before it,
    // past §6.2's 100 ms (rev 6.2): a burst. The sixth is 99 ms below.
    let r = run(&[
        (16, vec![idr()]),
        (16, vec![p(1)]),
        (16, vec![p(2)]),
        (16, vec![p(3)]),
        (16, vec![p(4)]),
        (16, vec![p(5)]),
        (16, vec![p(6)]),
    ]);
```

and its assertion with `assert_eq!(bursts, [false, false, false, false, false, false, true]);`.

- [ ] **Step 4: Run the tests.**

Run: `cargo test --workspace --all-features --lib -- flv::burst`
Expected: PASS — 6 passed (the two existing tests unchanged).
Run: `cargo test --workspace --all-features`
Expected: PASS — 0 failed (`an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins` still passes: `reset` still restarts the baseline per connection, and 200 ms ahead of a one-sample median is a burst; kvm-sim's `manual_pacing_bursts_with_frame_count_stamps_and_never_with_wall_clock_ones` still sees ≥ 20 of 30 — 24 when read back to back).

- [ ] **Step 5: Update the two doc comments** in `crates/kvm-proto/src/video/mod.rs`. Replace

```rust
    /// Ran more than `burst_threshold` ahead of real time, measured from
    /// this FLV connection's first *coded* tag, not its sequence header
    /// (D11; fix round 1, P10/m5).
    pub burst: bool,
```

with

```rust
    /// Ran more than `burst_threshold` ahead of real time: its delivery
    /// delay is that much below the median of the last second on this FLV
    /// connection (§6.2, rev 6.2 — the sliding baseline that replaced D11).
    pub burst: bool,
```

and in `flv_opened`'s doc replace `its first coded tag sets the
    /// `CompositionTime` and becomes the burst baseline (D11), and POC order
    /// starts afresh.` with `its first coded tag sets the
    /// `CompositionTime`, the burst baseline starts afresh, and POC order
    /// starts afresh.`

- [ ] **Step 6: Amend the spec.** In `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`:

(a) Replace the §6.2 bullet

```
- **Bursts**: an AU whose FLV timestamp runs more than 100 ms ahead of its
  receive time (measured since the FLV connection's first coded tag, rev
  6.1) is marked
  `burst` — a GOP-caching source replaying on connect. The ES3 sends none
  (burst on connect 0 frames, `census.md`); the marking stays as a defence.
```

with

```
- **Bursts**: an AU whose FLV timestamp runs more than 100 ms ahead of its
  receive time is marked `burst` — a GOP-caching source replaying on
  connect. "Ahead" is measured against a sliding baseline (rev 6.2): the
  AU's delivery delay (receive time − FLV timestamp) is more than 100 ms
  below the **median** delay of the AUs received in the last 1 s on that
  FLV connection (at most 256 of them). A replay is marked from about its
  seventh AU on, and live AUs after it stop being marked within 1 s; a late
  first tag, and one late tag mid-stream — the census's worst https gap is
  136 ms — are outvoted by the on-time AUs around them and mark nothing.
  (Rev 6.1's baseline, fixed at the connection's first coded tag, marked
  every later AU after one late tag — Plan B's final review measured 300
  of 300 — which disabled the soft gate; a sliding *maximum* would do the
  same for a second after every late tag.) The ES3 sends none (burst on
  connect 0 frames, `census.md`); the marking stays as a defence.
```

(b) In the rev 6.1 preface paragraph, replace `burst marking is
measured from the first coded tag,` with `burst marking is
measured from the first coded tag (superseded in rev 6.2),`.

(c) Insert, immediately before the paragraph that starts `**Rev 6.1 — Plan B (2026-10-06).**`:

```
**Rev 6.2 — Plan C (in progress, 2026-10-07).** Burst marking uses a
sliding median baseline (§6.2; Plan B's final review I3). Plan C's last
task completes this revision.

```

- [ ] **Step 7: Gate.**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: no warnings.
Run: `cargo test --workspace --all-features` — Expected: 0 failed.

- [ ] **Step 8: Commit.**

```bash
git add crates/kvm-proto/src/flv/burst.rs crates/kvm-proto/src/flv/mod.rs \
  crates/kvm-proto/src/video/mod.rs crates/kvm-proto/src/video/tests.rs \
  docs/superpowers/specs/2026-10-05-kvm-rdp-design.md
git commit -m "kvm-proto: burst marking against a sliding 1 s median baseline (Plan B final review I3)" \
  -m "A baseline fixed at the first coded tag marked every later AU after one late tag; a median is not moved by one late tag (census max gap 136 ms). Spec §6.2 amended (rev 6.2, DC1)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.2: kvm-sim `wait_for` final catch-up (N1) and §11.5's burst wording (N2)

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/state.rs` (`wait_for`, tests)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs` (two doc comments)
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (§11.5)
- Test: `crates/kvm-sim/src/state.rs` (`tests::wait_for_returns_at_least_what_its_predicate_saw`)

**Interfaces:**
- Consumes: Task 1.1's sliding baseline (for the doc wording).
- Produces: `KvmSim::wait_for` (unchanged signature) now guarantees that on `Ok` the returned log contains every event recorded before its predicate last returned `true`.

- [ ] **Step 1: Write the failing test.** Append inside `mod tests` in `crates/kvm-sim/src/state.rs`:

```rust
    /// N1 (Plan B final review): an event recorded after `wait_for`'s
    /// snapshot but before its predicate reads the counters is in the
    /// returned log. The predicate records it itself, which forces the race.
    #[tokio::test]
    async fn wait_for_returns_at_least_what_its_predicate_saw() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shared = Arc::new(Shared::default());
        let s = shared.clone();
        let recorded = AtomicBool::new(false);
        let log = shared
            .wait_for(Duration::from_secs(5), |_| {
                if !recorded.swap(true, Ordering::SeqCst) {
                    s.record(SimEvent::FlvOpen { conn: 7 });
                }
                s.stats().flv_open == 1
            })
            .await;
        assert_eq!(log, Ok(vec![SimEvent::FlvOpen { conn: 7 }]));
    }
```

- [ ] **Step 2: Run it to see it fail.**

Run: `cargo test --workspace --all-features --lib -- wait_for_returns_at_least`
Expected: FAIL — `left: Ok([])`, `right: Ok([FlvOpen { conn: 7 }])`.

- [ ] **Step 3: Implement.** In `Shared::wait_for`, replace

```rust
            if pred(&seen) {
                return Ok(seen);
            }
```

with

```rust
            if pred(&seen) {
                // The predicate may have read counters bumped by events
                // recorded after the snapshot (N1): return them too.
                self.catch_up(&mut seen);
                return Ok(seen);
            }
```

and in its doc comment replace `either way
    /// the result carries the log as `pred` last saw it, brought up to date.` with `either way
    /// the result carries the log brought up to date after `pred` last ran —
    /// on `Ok`, at least every event `pred` could have observed (N1).`

- [ ] **Step 4: Update kvm-sim's burst wording** in `crates/kvm-sim/src/lib.rs`. In the `Timestamps` doc replace `Admission marks an AU
/// `burst` when its stamp runs more than 100 ms ahead of its receive time,
/// both measured from the connection's first coded tag (§6.2), and §6.5/§6.6` with `Admission marks an AU
/// `burst` when its stamp runs more than 100 ms further ahead of its receive
/// time than the median delivery of the last second on that connection
/// (§6.2, rev 6.2), and §6.5/§6.6`. In `KvmSim::advance`'s doc replace `so every AU more than 100 ms (three
    /// frames) ahead of the wall clock since the connection's first coded
    /// tag arrives as a `burst` — with back-to-back calls, every AU from the
    /// fifth on.` with `so within one batch every AU more than 100 ms
    /// further ahead than the median of the batch before it arrives as a
    /// `burst` — every AU from the seventh on.` In the `FrameCount` doc replace `so nearly every AU
    /// is a burst (the final review saw 282 of 290)` with `so nearly every AU
    /// is a burst (all but the first six of a batch, rev 6.2)`. In
`crates/kvm-sim/tests/sim/flv.rs` (`manual_pacing_bursts_with_frame_count_stamps_and_never_with_wall_clock_ones`) replace the three comment lines above `assert!(bursts >= 20, …)` with

```rust
                // AU k's delay is 33·k ms below the first's, less the read
                // time; more than 100 ms below the median of those before
                // it is a burst (§6.2, rev 6.2) — every AU from the seventh
                // on when the tags are read back to back (24 of 30).
```

- [ ] **Step 5: Amend §11.5** in the spec: replace `uses it, and a source-burst case keeps the default or
  `burst_on_connect`.` with `uses it, and a source-burst case keeps the default `FrameCount` (with
  `burst_on_connect` for a replay on connect) — under `WallClock` a replay
  is stamped live (rev 6.2).` In the rev 6.2 stub paragraph Task 1.1 added, replace `(§6.2; Plan B's final review I3).` with `(§6.2; Plan B's final review I3); kvm-sim's `wait_for` returns every event its predicate could have seen, and §11.5's source-burst wording is fixed (N1, N2).`

- [ ] **Step 6: Gate.**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: no warnings.
Run: `cargo test --workspace --all-features` — Expected: 0 failed (the sim suite is unchanged; the new test passes).

- [ ] **Step 7: Commit.**

```bash
git add crates/kvm-sim/src/state.rs crates/kvm-sim/src/lib.rs crates/kvm-sim/tests/sim/flv.rs \
  docs/superpowers/specs/2026-10-05-kvm-rdp-design.md
git commit -m "kvm-sim: wait_for returns every event its predicate could see (N1); §11.5 burst wording (N2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 2 — The `kvm-rdp` crate and its foundations

The crate, the IronRDP pin with its goldens and the build budget, then the four leaf modules every later task uses: config, logging, metrics and the admin listener.

### Task 2.1: Workspace — the IronRDP pin, the crate, its goldens, the budget gate

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.toml` (`[workspace.dependencies]`)
- Modify: `/home/chris/Repos/kvm-rdp/.cargo/config.toml` (`[build] incremental = false`)
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (duplicate `ironrdp-*` gate)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/Cargo.toml`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pin_goldens.rs`
- Create: `/home/chris/Repos/kvm-rdp/scripts/target-budget.sh`
- Modify: `Cargo.lock`
- Test: `crates/kvm-rdp/src/pin_goldens.rs`

**Interfaces:**
- Consumes: kvm-proto, kvm-sim (dev) from Plans A/B.
- Produces: the `kvm_rdp` lib crate with crate-root lints `#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::as_conversions)]` (test modules opt out locally); workspace dependencies `ironrdp-{server,egfx,dvc,svc,pdu,core,graphics,connector,async,tokio,tls,session}` at one rev; every production and dev dependency later tasks use, except `libc` (Task 6.1 adds it with the L2 binary); `scripts/target-budget.sh` (exit 1 over budget).

- [ ] **Step 1: Add the IronRDP pin.** Append to the root `Cargo.toml`'s `[workspace.dependencies]`:

```toml
# IronRDP: the owner's fork, branch kvm-rdp-egfx-patches-v2 — three patches
# over upstream 2c08bda7 (spec §4.2). One rev for every ironrdp-* crate; a
# pin bump is its own PR and must pass crates/kvm-rdp/src/pin_goldens.rs.
# ironrdp-server: only `egfx` (no rayon/qoi/zstd; no `helper`, DC2).
ironrdp-server = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65", default-features = false, features = ["egfx"] }
ironrdp-egfx = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-dvc = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-svc = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-pdu = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-core = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
# Used only by tests (the L1 decoder and the L2 client). All but ironrdp-session
# are already in ironrdp-server's own graph (connector, async, graphics, tokio
# with reqwest, tls through rdpeudp-tokio), so only ironrdp-session and
# ironrdp-tls's `rustls` backend are new compile units for the tests.
ironrdp-graphics = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-connector = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-async = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-tokio = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-tls = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
ironrdp-session = { git = "https://github.com/ChristopherJMiller/IronRDP.git", rev = "c99eece22338e26ee6839ee89c29617bbcadbb65" }
```

- [ ] **Step 2: Create the crate.** `crates/kvm-rdp/Cargo.toml`:

```toml
[package]
name = "kvm-rdp"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false
autotests = false

[lib]
name = "kvm_rdp"
path = "src/lib.rs"
doctest = false

[dependencies]
kvm-proto = { path = "../kvm-proto" }
ironrdp-server = { workspace = true }
ironrdp-egfx = { workspace = true }
ironrdp-dvc = { workspace = true }
ironrdp-svc = { workspace = true }
ironrdp-pdu = { workspace = true }
ironrdp-core = { workspace = true }
bytes = { workspace = true }
sha2 = { workspace = true }
serde_json = { workspace = true }
serde = { version = "1", features = ["derive"] }
toml = { version = "0.9", default-features = false, features = ["std", "serde", "parse"] }
tokio = { version = "1", features = ["rt", "rt-multi-thread", "net", "io-util", "macros", "time", "sync", "signal"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12", "logging"] }
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
tokio-tungstenite = { version = "0.24", default-features = false, features = ["handshake"] }
futures-util = { version = "0.3", default-features = false, features = ["sink", "std"] }
x509-parser = "0.16"
async-trait = "0.1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "json", "env-filter", "registry", "std"] }

[dev-dependencies]
kvm-sim = { path = "../kvm-sim" }
ironrdp-graphics = { workspace = true }
ironrdp-connector = { workspace = true }
ironrdp-async = { workspace = true }
ironrdp-tokio = { workspace = true, features = ["reqwest"] }
ironrdp-tls = { workspace = true, features = ["rustls"] }
ironrdp-session = { workspace = true }
# default features would pull in ring (rcgen 0.13's default backend, §4.2)
rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs", "pem"] }
tempfile = "3"
```

`crates/kvm-rdp/src/lib.rs`:

```rust
//! `kvm-rdp`: the bridge from the ES3 IP-KVM to RDP (spec §4).
//!
//! Hostile input is parsed only in `kvm-proto`; this crate still never
//! panics on anything the KVM or a client sends. The await lints are §4.3's
//! (no lock held across an await); test modules opt out of the panic lints
//! locally.
#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions
)]

#[cfg(test)]
mod pin_goldens;
```

- [ ] **Step 3: Write the goldens.** `crates/kvm-rdp/src/pin_goldens.rs`:

```rust
//! IronRDP goldens (§11.2) — required on every pin bump — and the three
//! fork patches Plan C depends on (§4.2): if a pin bump changes any of
//! these bytes or drops a patch, this file fails first.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use ironrdp_core::encode_vec;
use ironrdp_dvc::DvcProcessor as _;
use ironrdp_egfx::pdu::{
    Avc420Region, CapabilitiesAdvertisePdu, CapabilitiesV81Flags, CapabilitySet,
    FrameAcknowledgePdu, GfxPdu, QueueDepth, ResetGraphicsPdu, encode_avc420_bitmap_stream,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_pdu::gcc::{KeyboardType, Monitor, MonitorFlags};
use ironrdp_server::{ConnectionInfo, EgfxServerMessage};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

struct Null;
impl GraphicsPipelineHandler for Null {
    fn capabilities_advertise(&mut self, _pdu: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _negotiated: &CapabilitySet) {}
}

fn advertise_v8_1() -> Vec<u8> {
    encode_vec(&GfxPdu::CapabilitiesAdvertise(
        CapabilitiesAdvertisePdu::from_typed(&[CapabilitySet::V8_1 {
            flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
        }]),
    ))
    .unwrap()
}

#[test]
fn avc420_bitmap_stream_bytes_are_pinned() {
    let got = encode_avc420_bitmap_stream(
        &[Avc420Region::full_frame(640, 360, 22)],
        &[0, 0, 0, 1, 0x65, 0x88],
    );
    #[rustfmt::skip]
    let want = [
        1, 0, 0, 0,             // one region
        0, 0, 0, 0,             // left, top
        0x80, 0x02, 0x68, 0x01, // right 640, bottom 360 (exclusive)
        0x16, 0x64,             // QP 22, quality 100
        0, 0, 0, 1, 0x65, 0x88, // the Annex-B payload, verbatim
    ];
    assert_eq!(got, want);
}

#[test]
fn reset_graphics_monitor_bytes_are_pinned() {
    let pdu = GfxPdu::ResetGraphics(ResetGraphicsPdu {
        width: 1920,
        height: 1080,
        monitors: vec![Monitor {
            left: 0,
            top: 0,
            right: 1919,
            bottom: 1079,
            flags: MonitorFlags::PRIMARY,
        }],
    });
    let bytes = encode_vec(&pdu).unwrap();
    assert_eq!(bytes.len(), 340, "RDPGFX_RESET_GRAPHICS_PDU is fixed at 340 bytes");
    #[rustfmt::skip]
    let head = [
        0x0e, 0x00, 0x00, 0x00, 0x54, 0x01, 0x00, 0x00, // cmdId 0x000e, flags, length 340
        0x80, 0x07, 0, 0, 0x38, 0x04, 0, 0,             // 1920 × 1080
        1, 0, 0, 0,                                     // one monitor
        0, 0, 0, 0, 0, 0, 0, 0,                         // left 0, top 0
        0x7f, 0x07, 0, 0, 0x37, 0x04, 0, 0,             // right 1919, bottom 1079 (inclusive)
        1, 0, 0, 0,                                     // PRIMARY
    ];
    assert_eq!(&bytes[..40], &head);
    assert!(bytes[40..].iter().all(|&b| b == 0), "padding is zero");
}

#[test]
fn patch_1_ack_suspension_survives_a_reset_and_a_readvertise() {
    let mut s = GraphicsPipelineServer::new(Box::new(Null));
    s.start(7).unwrap();
    s.process(7, &advertise_v8_1()).unwrap();
    assert!(s.supports_avc420());
    let sid = s.create_surface(640, 360).unwrap();
    let id = s
        .send_avc420_frame(sid, &[0, 0, 0, 1, 0x65, 0x88], &[Avc420Region::full_frame(640, 360, 22)], 0)
        .unwrap();
    let _ = s.drain_output();
    let suspend = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
        queue_depth: QueueDepth::Suspend,
        frame_id: id,
        total_frames_decoded: 1,
    });
    s.process(7, &encode_vec(&suspend).unwrap()).unwrap();
    assert!(s.is_ack_suspended());
    s.resize(640, 360);
    assert!(s.is_ack_suspended(), "FrameTracker::clear keeps the suspension (patch 1)");
    s.process(7, &advertise_v8_1()).unwrap();
    assert!(s.is_ack_suspended(), "a re-advertise keeps it too (patch 1)");
}

#[test]
fn patch_2_write_counter_rides_on_the_event() {
    let counter = Arc::new(AtomicU64::new(0));
    let ev = EgfxServerMessage::send_messages(Vec::new()).with_write_counter(Arc::clone(&counter), 42);
    assert!(matches!(ev, EgfxServerMessage::SendMessages { .. }));
    assert_eq!(Arc::strong_count(&counter), 2, "the event holds the counter");
}

#[test]
fn patch_3_connection_info_hands_out_an_abort_handle() {
    let info = ConnectionInfo::new(0, KeyboardType::IBM_ENHANCED, String::new());
    // Inert outside a live connection, by construction (patch 3).
    info.abort_handle().abort();
}
```

- [ ] **Step 4: Resolve and align the lockfile before the first compile.** The first resolution fetches the fork and the new crates over the network; `cargo tree` resolves without compiling anything, and only adds entries to `Cargo.lock` (no existing version moves).

Run: `cargo tree -i picky-krb --depth 0 --prefix none`
Expected: `picky-krb v0.12.4`. If any other version prints, run `cargo update -p sspi --precise 0.21.3 && cargo update -p picky-krb --precise 0.12.4` — IronRDP's own `Cargo.lock` at `c99eece2` holds these, and sspi 0.21.3 fails to build against picky-krb ≥ 0.12.5 (E0004, found by Plan A's Leg B spike). Re-run the tree command: `picky-krb v0.12.4`.

Run: `cargo tree --workspace --target all -i ring`
Expected: `warning: nothing to print.` (ring may sit in `Cargo.lock` as rustls-webpki's optional dependency, never activated).

Run: `cargo tree --workspace --target all -d --depth 0 --prefix none | grep -E '^ironrdp' || echo none`
Expected: `none`.

- [ ] **Step 5: Run the goldens.** They pin IronRDP's behaviour, so they pass on the right pin.

Run: `cargo test --workspace --all-features --lib -- pin_goldens`
Expected: PASS — 5 passed. (If a golden fails, the pin is wrong — stop: these bytes are §11.2's pin-bump gate.)

- [ ] **Step 6: Prove the goldens bite.** Change `0x16, 0x64,` to `0x17, 0x64,` in `avc420_bitmap_stream_bytes_are_pinned`, and `1, 0, 0, 0,                                     // PRIMARY` to `0, 0, 0, 0,                                     // PRIMARY` in the ResetGraphics golden.

Run: `cargo test --workspace --all-features --lib -- pin_goldens`
Expected: FAIL — 2 failed (`assertion left == right failed` in both). Restore both bytes; re-run: 5 passed.

- [ ] **Step 7: The build budget.** Append to `.cargo/config.toml`'s `[build]` table (after `jobs = 4`):

```toml
# Plan C design decision 8: incremental caches for the IronRDP-sized test
# binaries cost disk the shared host does not have (spec §13, DC10).
incremental = false
```

Create `scripts/target-budget.sh` (then `chmod +x scripts/target-budget.sh`, so git records it as 100755 like `scripts/fuzz.sh`):

```bash
#!/usr/bin/env bash
# Spec §13 / Plan C design decision 8: fail when the shared target dir grows
# past the budget. The one cleanup that is always safe is `cargo clean`; the
# next gate rebuilds (jobs = 4, niced).
set -euo pipefail
budget_gib=${KVM_RDP_TARGET_BUDGET_GIB:-8}
case "$budget_gib" in
  ''|*[!0-9]*|0) echo "target-budget: KVM_RDP_TARGET_BUDGET_GIB must be a positive integer" >&2; exit 2 ;;
esac
dir=${CARGO_TARGET_DIR:-$(git rev-parse --show-toplevel)/target}
if [ ! -d "$dir" ]; then
  echo "target-budget: $dir does not exist (nothing built yet)"
  exit 0
fi
used_kib=$(du -sk "$dir" | cut -f1)
budget_kib=$(( budget_gib * 1024 * 1024 ))
used_gib=$(awk -v k="$used_kib" 'BEGIN { printf "%.2f", k / 1048576 }')
if [ "$used_kib" -gt "$budget_kib" ]; then
  echo "target-budget: $dir is ${used_gib} GiB, over the ${budget_gib} GiB budget." >&2
  echo "target-budget: run 'cargo clean', then the per-task gate again. If it is over" >&2
  echo "target-budget: budget again straight after that, stop and report the size;" >&2
  echo "target-budget: never raise KVM_RDP_TARGET_BUDGET_GIB to get past this gate." >&2
  exit 1
fi
echo "target-budget: $dir is ${used_gib} GiB of ${budget_gib} GiB"
```

- [ ] **Step 8: The CI duplicate gate.** In `.github/workflows/ci.yml` replace the step

```yaml
      - name: Duplicate-dependency check (informational in Plan A)
        run: |
          # Plan A has no IronRDP dependency, so this only prints duplicates.
          # Plan C turns it into a hard gate that fails on a duplicate
          # ironrdp-* crate (spec §4.2). Until then it must not fail CI.
          cargo tree --workspace --duplicates || true
```

with

```yaml
      - name: No duplicate ironrdp-* crate (spec §4.2)
        run: |
          set -o pipefail
          dups=$(cargo tree --workspace --target all -d --depth 0 --prefix none | grep -E '^ironrdp' || true)
          if [ -n "$dups" ]; then
            echo "::error::duplicate ironrdp-* crates (spec §4.2 pins one rev):"
            echo "$dups"
            exit 1
          fi
          echo "ironrdp: one version of every crate"
```

- [ ] **Step 9: Gate and measure.**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: no warnings.
Run: `cargo test --workspace --all-features` — Expected: 0 failed.
Run: `du -sh "$CARGO_TARGET_DIR"` — record the size in the task report. Then set the script's default (`budget_gib=${KVM_RDP_TARGET_BUDGET_GIB:-8}`) to the measured GiB × 1.3, rounded up to a whole GiB (never below 8), and note the number for Task 7.1's DC10. This is a provisional budget: the kvm-rdp binary (Task 5.4) and the L2 executable (Task 6.1) do not exist yet, so Task 6.1 Step 8 re-measures once and sets the final default.
Run: `chmod +x scripts/target-budget.sh && scripts/target-budget.sh` — Expected: `target-budget: … GiB of N GiB`, exit 0.

**If the budget gate ever fails** (here or in a later task): run `cargo clean`, then the per-task gate once. If it fails again straight after the clean rebuild, the steady-state build is over budget — **stop and report the measured size** (the controller decides; it is a DC10 re-measure, not a retry loop). Never raise `KVM_RDP_TARGET_BUDGET_GIB` or the script's default silently, and never clean-and-rebuild more than once per task.

- [ ] **Step 10: Commit.**

```bash
git add Cargo.toml Cargo.lock .cargo/config.toml .github/workflows/ci.yml \
  scripts/target-budget.sh crates/kvm-rdp/Cargo.toml crates/kvm-rdp/src/lib.rs \
  crates/kvm-rdp/src/pin_goldens.rs
git commit -m "kvm-rdp: crate, IronRDP fork pin (c99eece2) with its goldens, target-budget gate" \
  -m "ironrdp-server with only egfx (DC2); duplicate ironrdp-* is a CI failure (§4.2); incremental off and a measured target budget (DC10)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.2: `config` — one TOML file, the §4.4 defaults, secrets from files

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/config.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod config;`)
- Test: `crates/kvm-rdp/src/config.rs` (`tests`)

**Interfaces:**
- Consumes: `kvm_proto::video::AdmissionConfig`, `kvm_proto::h264::rewrite::RewriteConfig`.
- Produces (`kvm_rdp::config`):
  - `pub struct Secret` — `Secret::new(impl Into<String>) -> Secret`, `expose(&self) -> &str`; `Debug` prints `Secret(<redacted>)`.
  - `pub enum ConfigError { Read { path: PathBuf, kind: std::io::ErrorKind }, Parse(String), Invalid(String) }` (`Display`, `Error`).
  - `pub fn parse_duration(s: &str) -> Option<Duration>`; `pub const MAX_DURATION: Duration` (1 h); `pub const MIN_NLA_PASSWORD: usize` (22).
  - `pub enum Scheme { Https, Http }`, `pub enum IdrPolicy { Side, Reconnect, Wait }`, `pub enum Multiline { Enter, Refuse }` (all `Copy + Eq + Debug`).
  - `pub struct BackoffConfig { pub initial: Duration, pub factor: u32, pub max: Duration, pub jitter_percent: u32 }`, `pub struct SpsRewrite { pub level: bool, pub vui: bool, pub restriction: bool }` (validation refuses any set lacking one of the three: §6.8's rewrite is required).
  - `pub struct Config { pub rdp: RdpConfig, pub admin: AdminConfig, pub kvm: KvmConfig, pub video: VideoConfig, pub input: InputConfig, pub paste: PasteConfig, pub security: SecurityConfig, pub log: LogConfig }` with `Config::load(&Path) -> Result<Config, ConfigError>` and `Config::from_toml(text: &str, base: &Path) -> Result<Config, ConfigError>`; every field `pub` as listed in the code below; `VideoConfig::hard_cap_frames(&self) -> u32`, `VideoConfig::admission(&self) -> AdmissionConfig`.

- [ ] **Step 1: Write the failing tests.** Create `crates/kvm-rdp/src/config.rs` with only the test module, and add `pub mod config;` to `lib.rs` (above `#[cfg(test)]`):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use std::path::Path;

    const PIN: &str = "F94841875EC7FA56220D48FFADAA5C0F2D84FFBBD1BEEB060245DED1419B614F";
    const NLA: &str = "0123456789abcdefghijklmnop";

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    /// The four secret files and the smallest valid config.
    fn minimal(dir: &Path) -> String {
        write(dir, "kvm.pass", "kvm-secret\n");
        write(dir, "nla.pass", &format!("{NLA}\n"));
        write(dir, "cert.pem", "not read by config\n");
        write(dir, "key.pem", "not read by config\n");
        format!(
            "[rdp]\nnla_password_file = \"nla.pass\"\ntls_cert_file = \"cert.pem\"\n\
             tls_key_file = \"key.pem\"\n[kvm]\nhost = \"192.168.0.50\"\n\
             spki_sha256 = \"{PIN}\"\npassword_file = \"kvm.pass\"\n"
        )
    }

    fn load(dir: &Path, toml: &str) -> Result<Config, ConfigError> {
        Config::from_toml(toml, dir)
    }

    #[test]
    fn defaults_match_the_spec_table() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        let s = Duration::from_secs;
        let ms = Duration::from_millis;
        assert_eq!(c.rdp.listen.to_string(), "0.0.0.0:3389");
        assert_eq!(c.rdp.username, "kvm");
        assert_eq!(c.rdp.cert_poll_interval, s(60));
        assert_eq!(c.admin.listen.to_string(), "0.0.0.0:9464");
        assert_eq!(c.admin.liveness_timeout, s(10));
        assert_eq!(c.kvm.spki_sha256, PIN.to_ascii_lowercase());
        assert_eq!(c.kvm.scheme, Scheme::Https);
        assert_eq!((c.kvm.web_port, c.kvm.video_port, c.kvm.control_port), (443, 8881, 8889));
        assert_eq!((c.kvm.connect_timeout, c.kvm.login_timeout), (s(3), s(5)));
        assert_eq!(
            c.kvm.backoff,
            BackoffConfig { initial: ms(250), factor: 2, max: s(8), jitter_percent: 20 }
        );
        assert_eq!(c.kvm.upstream_deadline, s(20));
        let v = &c.video;
        assert_eq!((v.default_size, v.max_fps), ((1920, 1080), 30));
        assert_eq!((v.soft_gate, v.hard_cap, v.backlog_limit), (ms(500), s(2), 4 << 20));
        assert_eq!(v.hard_cap_frames(), 60);
        assert_eq!((v.standing_delay_limit, v.rtt_probe_interval), (ms(500), ms(250)));
        assert_eq!((v.first_ack_grace, v.stall_timeout), (ms(1600), s(10)));
        assert_eq!((v.idr_policy, v.idr_side_timeout, v.idr_wait_max), (IdrPolicy::Side, s(1), s(3)));
        assert_eq!((v.flv_reconnect_interval_setup, v.flv_reconnect_interval_flow), (s(1), s(10)));
        assert_eq!((v.flv_idle_timeout, v.burst_chunk), (s(10), 8));
        assert_eq!(v.sps_rewrite, SpsRewrite { level: true, vui: true, restriction: true });
        assert_eq!((v.avc420_timeout, v.suppress_debounce, v.disconnect_watchdog), (s(10), s(1), s(5)));
        assert_eq!(v.region_qp, 22);
        assert_eq!(v.admission().rewrite, RewriteConfig::ES3);
        let i = &c.input;
        assert_eq!((i.queue, i.hid_write_timeout, i.key_repeat_timeout), (256, s(1), s(10)));
        assert_eq!((i.modifier_idle_timeout, i.mac_remap), (s(30), false));
        let p = &c.paste;
        assert_eq!((p.chord.as_str(), p.pace, p.max_chars), ("ctrl+option+shift+v", ms(15), 4096));
        assert_eq!((p.max_bytes, p.modifier_wait, p.multiline), (64 << 10, s(5), Multiline::Enter));
        assert_eq!((c.security.accept_rate, c.security.accept_window), (30, s(60)));
        assert_eq!(c.log.filter, "info");
        assert_eq!(c.kvm.password.expose(), "kvm-secret");
        assert_eq!(c.rdp.nla_password.expose(), NLA);
    }

    /// Review Focus 2: `echo` adds `\n`, Windows adds `\r\n`; exactly one
    /// line ending goes, everything else (spaces too) stays.
    #[test]
    fn secret_files_lose_one_line_ending_only() {
        let d = tempfile::tempdir().unwrap();
        let toml = minimal(d.path());
        for (body, want) in [
            ("kvm-secret\n", "kvm-secret"),
            ("kvm-secret\r\n", "kvm-secret"),
            ("kvm-secret", "kvm-secret"),
            (" spaced secret \n", " spaced secret "),
            ("two\n\n", "two\n"),
        ] {
            write(d.path(), "kvm.pass", body);
            assert_eq!(load(d.path(), &toml).unwrap().kvm.password.expose(), want, "{body:?}");
        }
        write(d.path(), "kvm.pass", "\n");
        assert!(matches!(load(d.path(), &toml), Err(ConfigError::Invalid(_))));
        write(d.path(), "kvm.pass", &"x".repeat(5000));
        assert!(matches!(load(d.path(), &toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn relative_secret_paths_resolve_against_the_config_directory() {
        let d = tempfile::tempdir().unwrap();
        let toml = minimal(d.path());
        let file = d.path().join("kvm-rdp.toml");
        std::fs::write(&file, &toml).unwrap();
        assert_eq!(Config::load(&file).unwrap().kvm.password.expose(), "kvm-secret");
        let missing = Config::load(&d.path().join("absent.toml"));
        assert!(matches!(missing, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn bad_values_are_refused_before_anything_binds() {
        let d = tempfile::tempdir().unwrap();
        let base = minimal(d.path());
        for (extra, what) in [
            ("[video]\nbogus = 1\n", "unknown key"),
            ("[video]\nsoft_gate = \"10000000s\"\n", "duration above 1 h"),
            ("[video]\nsoft_gate = \"fast\"\n", "duration syntax"),
            ("[video]\nstall_timeout = \"0s\"\n", "zero duration"),
            ("[video]\nregion_qp = 52\n", "QP above 51"),
            ("[video]\ndefault_size = \"1921x1080\"\n", "odd width"),
            ("[video]\nidr_policy = \"magic\"\n", "unknown policy"),
            ("[video]\nsps_rewrite = [\"level\", \"colour\"]\n", "unknown rewrite"),
            ("[video]\nsps_rewrite = [\"vui\", \"restriction\"]\n", "rewrite without level"),
            ("[video]\nsps_rewrite = []\n", "no rewrite"),
            ("[video]\nmax_fps = 0\n", "zero fps"),
            ("[input]\nqueue = 0\n", "empty HID queue"),
        ] {
            let r = load(d.path(), &format!("{base}{extra}"));
            assert!(matches!(r, Err(ConfigError::Invalid(_) | ConfigError::Parse(_))), "{what}: {r:?}");
        }
        let swap = |from: &str, to: &str| load(d.path(), &base.replace(from, to));
        assert!(swap("host = \"192.168.0.50\"\n", "").is_err(), "missing kvm.host");
        assert!(swap(PIN, "abcd").is_err(), "short pin");
        assert!(swap("[kvm]\n", "[kvm]\nscheme = \"ftp\"\n").is_err(), "scheme");
        write(d.path(), "nla.pass", "short\n");
        assert!(load(d.path(), &base).is_err(), "NLA password under 22 characters");
    }

    #[test]
    fn secrets_never_show_in_debug() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains("kvm-secret") && !shown.contains(NLA), "{shown}");
        assert!(shown.contains("Secret(<redacted>)"));
    }

    #[test]
    fn durations_parse_and_are_bounded() {
        assert_eq!(parse_duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(parse_duration("1.6s"), Some(Duration::from_millis(1600)));
        assert_eq!(parse_duration(" 10s "), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("3600s"), Some(MAX_DURATION));
        for bad in ["3601s", "-1s", "1h", "s", "", "NaNs", "infs"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test --workspace --all-features --lib -- config`
Expected: FAIL to compile — `cannot find type Config in this scope` (and the other items).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/kvm-rdp/src/config.rs`:

```rust
//! The bridge's one TOML file (spec §4.4). Every key has the §4.4 default;
//! secrets come only from files named here (§9.2) and live in [`Secret`],
//! whose `Debug` never shows them. Validation happens before anything binds,
//! and bounds every duration to [`MAX_DURATION`] so `Instant + d` in the
//! sans-IO cores cannot overflow. Only `KVM_RDP_CONFIG` is ever read from
//! the environment, by `main` (DC5).
use kvm_proto::h264::rewrite::RewriteConfig;
use kvm_proto::video::AdmissionConfig;
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Longest accepted duration for any key.
pub const MAX_DURATION: Duration = Duration::from_secs(3600);
/// §9.1: the NLA password is ≥ 128 random bits — 22 characters of base64.
pub const MIN_NLA_PASSWORD: usize = 22;
const MAX_SECRET_FILE: u64 = 4096;

/// A secret read from a file. Never `Display`; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read { path: PathBuf, kind: std::io::ErrorKind },
    Parse(String),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, kind } => write!(f, "cannot read {}: {kind}", path.display()),
            ConfigError::Parse(e) => write!(f, "invalid TOML: {e}"),
            ConfigError::Invalid(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdrPolicy {
    Side,
    Reconnect,
    Wait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiline {
    Enter,
    Refuse,
}

/// `kvm.backoff` (§4.4): `initial` ×`factor` up to `max`, ±`jitter_percent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub factor: u32,
    pub max: Duration,
    pub jitter_percent: u32,
}

/// `video.sps_rewrite` (§6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpsRewrite {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
}

#[derive(Debug, Clone)]
pub struct RdpConfig {
    pub listen: SocketAddr,
    pub username: String,
    pub nla_password: Secret,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub cert_poll_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub listen: SocketAddr,
    pub liveness_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct KvmConfig {
    pub host: String,
    /// Lowercase hex SHA-256 of the KVM certificate's SPKI (§3.2).
    pub spki_sha256: String,
    pub scheme: Scheme,
    pub web_port: u16,
    pub video_port: u16,
    pub control_port: u16,
    pub password: Secret,
    pub connect_timeout: Duration,
    pub login_timeout: Duration,
    pub backoff: BackoffConfig,
    pub upstream_deadline: Duration,
}

#[derive(Debug, Clone)]
pub struct VideoConfig {
    pub default_size: (u16, u16),
    pub max_fps: u32,
    pub soft_gate: Duration,
    pub hard_cap: Duration,
    pub backlog_limit: u64,
    pub standing_delay_limit: Duration,
    pub rtt_probe_interval: Duration,
    pub first_ack_grace: Duration,
    pub stall_timeout: Duration,
    pub idr_policy: IdrPolicy,
    pub idr_side_timeout: Duration,
    pub idr_wait_max: Duration,
    pub flv_reconnect_interval_setup: Duration,
    pub flv_reconnect_interval_flow: Duration,
    pub flv_idle_timeout: Duration,
    pub burst_chunk: u32,
    pub sps_rewrite: SpsRewrite,
    pub avc420_timeout: Duration,
    pub suppress_debounce: Duration,
    pub disconnect_watchdog: Duration,
    pub region_qp: u8,
}

impl VideoConfig {
    /// §6.6: ceil(`hard_cap` × `max_fps`) + the census maximum burst (0).
    #[must_use]
    pub fn hard_cap_frames(&self) -> u32 {
        let millis = self.hard_cap.as_millis().saturating_mul(u128::from(self.max_fps));
        u32::try_from(millis.div_ceil(1000)).unwrap_or(u32::MAX)
    }

    /// The admission settings §6.1/§6.2/§6.8 derive from `video.*`.
    #[must_use]
    pub fn admission(&self) -> AdmissionConfig {
        AdmissionConfig {
            rewrite: RewriteConfig {
                level: self.sps_rewrite.level,
                vui: self.sps_rewrite.vui,
                restriction: self.sps_rewrite.restriction,
                max_fps: self.max_fps,
            },
            ..AdmissionConfig::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputConfig {
    pub queue: usize,
    pub hid_write_timeout: Duration,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
    pub mac_remap: bool,
}

/// `paste.*` — parsed and validated now, consumed by Plan D.
#[derive(Debug, Clone)]
pub struct PasteConfig {
    pub chord: String,
    pub pace: Duration,
    pub max_chars: usize,
    pub max_bytes: usize,
    pub modifier_wait: Duration,
    pub multiline: Multiline,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub accept_rate: u32,
    pub accept_window: Duration,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub filter: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub rdp: RdpConfig,
    pub admin: AdminConfig,
    pub kvm: KvmConfig,
    pub video: VideoConfig,
    pub input: InputConfig,
    pub paste: PasteConfig,
    pub security: SecurityConfig,
    pub log: LogConfig,
}

impl Config {
    /// Read and validate the config file; secrets resolve against its
    /// directory.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_owned(),
            kind: e.kind(),
        })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Config::from_toml(&text, base)
    }

    pub fn from_toml(text: &str, base: &Path) -> Result<Config, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        build(raw, base)
    }
}

/// `"250ms"`, `"1.6s"`, `"10s"`: a non-negative number of ms or s, ≤ 1 h.
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, scale) = if let Some(n) = s.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1.0)
    } else {
        return None;
    };
    let v: f64 = num.trim().parse().ok()?;
    let secs = v * scale;
    if !secs.is_finite() || secs < 0.0 || secs > MAX_DURATION.as_secs_f64() {
        return None;
    }
    Some(Duration::from_secs_f64(secs))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct Raw {
    rdp: RawRdp,
    admin: RawAdmin,
    kvm: RawKvm,
    video: RawVideo,
    input: RawInput,
    paste: RawPaste,
    security: RawSecurity,
    log: RawLog,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawRdp {
    listen: Option<String>,
    username: Option<String>,
    nla_password_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    cert_poll_interval: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawAdmin {
    listen: Option<String>,
    liveness_timeout: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawBackoff {
    initial: Option<String>,
    factor: Option<u32>,
    max: Option<String>,
    jitter_percent: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawKvm {
    host: Option<String>,
    spki_sha256: Option<String>,
    scheme: Option<String>,
    web_port: Option<u16>,
    video_port: Option<u16>,
    control_port: Option<u16>,
    password_file: Option<PathBuf>,
    connect_timeout: Option<String>,
    login_timeout: Option<String>,
    backoff: RawBackoff,
    upstream_deadline: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawVideo {
    default_size: Option<String>,
    max_fps: Option<u32>,
    soft_gate: Option<String>,
    hard_cap: Option<String>,
    backlog_limit: Option<u64>,
    standing_delay_limit: Option<String>,
    rtt_probe_interval: Option<String>,
    first_ack_grace: Option<String>,
    stall_timeout: Option<String>,
    idr_policy: Option<String>,
    idr_side_timeout: Option<String>,
    idr_wait_max: Option<String>,
    flv_reconnect_interval_setup: Option<String>,
    flv_reconnect_interval_flow: Option<String>,
    flv_idle_timeout: Option<String>,
    burst_chunk: Option<u32>,
    sps_rewrite: Option<Vec<String>>,
    avc420_timeout: Option<String>,
    suppress_debounce: Option<String>,
    disconnect_watchdog: Option<String>,
    region_qp: Option<u8>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawInput {
    queue: Option<usize>,
    hid_write_timeout: Option<String>,
    key_repeat_timeout: Option<String>,
    modifier_idle_timeout: Option<String>,
    mac_remap: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawPaste {
    chord: Option<String>,
    pace: Option<String>,
    max_chars: Option<usize>,
    max_bytes: Option<usize>,
    modifier_wait: Option<String>,
    multiline: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawSecurity {
    accept_rate: Option<u32>,
    accept_window: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawLog {
    filter: Option<String>,
}

fn dur(v: Option<&String>, default: Duration, key: &str) -> Result<Duration, ConfigError> {
    let d = match v {
        None => default,
        Some(s) => parse_duration(s)
            .ok_or_else(|| invalid(format!("{key}: {s:?} is not a duration like \"250ms\" or \"1.6s\" (at most 1 h)")))?,
    };
    if d.is_zero() {
        return Err(invalid(format!("{key} must be more than zero")));
    }
    Ok(d)
}

fn dur_or_zero(v: Option<&String>, default: Duration, key: &str) -> Result<Duration, ConfigError> {
    match v {
        None => Ok(default),
        Some(s) => parse_duration(s).ok_or_else(|| invalid(format!("{key}: {s:?} is not a duration"))),
    }
}

fn addr(v: Option<&String>, default: &str, key: &str) -> Result<SocketAddr, ConfigError> {
    v.map_or(default, String::as_str)
        .parse()
        .map_err(|_| invalid(format!("{key} must be an ip:port")))
}

fn ranged<T: PartialOrd + Copy + fmt::Display>(v: Option<T>, default: T, lo: T, hi: T, key: &str) -> Result<T, ConfigError> {
    let x = v.unwrap_or(default);
    if x < lo || x > hi {
        return Err(invalid(format!("{key} must be between {lo} and {hi}")));
    }
    Ok(x)
}

fn size(v: Option<&String>) -> Result<(u16, u16), ConfigError> {
    let Some(s) = v else { return Ok((1920, 1080)) };
    let bad = || invalid("video.default_size must be WIDTHxHEIGHT, even, 16..=4096 × 16..=2304");
    let (w, h) = s.split_once('x').ok_or_else(bad)?;
    let w: u16 = w.trim().parse().map_err(|_| bad())?;
    let h: u16 = h.trim().parse().map_err(|_| bad())?;
    if !(16..=4096).contains(&w) || !(16..=2304).contains(&h) || !w.is_multiple_of(2) || !h.is_multiple_of(2) {
        return Err(bad());
    }
    Ok((w, h))
}

fn required_path(v: Option<PathBuf>, key: &str) -> Result<PathBuf, ConfigError> {
    v.ok_or_else(|| invalid(format!("{key} is required")))
}

/// A secret file: ≤ 4 KiB, UTF-8, exactly one trailing `\n` or `\r\n`
/// removed, not empty after that.
fn read_secret(base: &Path, rel: &Path, key: &str) -> Result<Secret, ConfigError> {
    let path = base.join(rel);
    let meta = std::fs::metadata(&path).map_err(|e| ConfigError::Read { path: path.clone(), kind: e.kind() })?;
    if meta.len() > MAX_SECRET_FILE {
        return Err(invalid(format!("{key}: larger than 4 KiB")));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| ConfigError::Read { path, kind: e.kind() })?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if text.is_empty() {
        return Err(invalid(format!("{key}: empty")));
    }
    Ok(Secret(text.to_owned()))
}

fn build(raw: Raw, base: &Path) -> Result<Config, ConfigError> {
    let ms = Duration::from_millis;
    let s = Duration::from_secs;

    let username = raw.rdp.username.unwrap_or_else(|| "kvm".to_owned());
    if username.is_empty() {
        return Err(invalid("rdp.username must not be empty"));
    }
    let nla_password = read_secret(
        base,
        &required_path(raw.rdp.nla_password_file, "rdp.nla_password_file")?,
        "rdp.nla_password_file",
    )?;
    if nla_password.expose().chars().count() < MIN_NLA_PASSWORD {
        return Err(invalid("rdp.nla_password_file: at least 22 characters (128 random bits, §9.1)"));
    }
    let rdp = RdpConfig {
        listen: addr(raw.rdp.listen.as_ref(), "0.0.0.0:3389", "rdp.listen")?,
        username,
        nla_password,
        tls_cert_file: base.join(required_path(raw.rdp.tls_cert_file, "rdp.tls_cert_file")?),
        tls_key_file: base.join(required_path(raw.rdp.tls_key_file, "rdp.tls_key_file")?),
        cert_poll_interval: dur(raw.rdp.cert_poll_interval.as_ref(), s(60), "rdp.cert_poll_interval")?,
    };
    let admin = AdminConfig {
        listen: addr(raw.admin.listen.as_ref(), "0.0.0.0:9464", "admin.listen")?,
        liveness_timeout: dur(raw.admin.liveness_timeout.as_ref(), s(10), "admin.liveness_timeout")?,
    };

    let host = raw.kvm.host.ok_or_else(|| invalid("kvm.host is required"))?;
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '/') {
        return Err(invalid("kvm.host must be a bare host name or address"));
    }
    let pin = raw.kvm.spki_sha256.ok_or_else(|| invalid("kvm.spki_sha256 is required"))?;
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("kvm.spki_sha256 must be 64 hex digits (kvm-probe fingerprint)"));
    }
    let scheme = match raw.kvm.scheme.as_deref().unwrap_or("https") {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => return Err(invalid("kvm.scheme must be \"https\" or \"http\"")),
    };
    let (dw, dv, dc) = match scheme {
        Scheme::Https => (443, 8881, 8889),
        Scheme::Http => (80, 8880, 8888),
    };
    let rb = &raw.kvm.backoff;
    let backoff = BackoffConfig {
        initial: dur(rb.initial.as_ref(), ms(250), "kvm.backoff.initial")?,
        factor: ranged(rb.factor, 2, 1, 16, "kvm.backoff.factor")?,
        max: dur(rb.max.as_ref(), s(8), "kvm.backoff.max")?,
        jitter_percent: ranged(rb.jitter_percent, 20, 0, 50, "kvm.backoff.jitter_percent")?,
    };
    if backoff.initial > backoff.max {
        return Err(invalid("kvm.backoff.initial must not exceed kvm.backoff.max"));
    }
    let kvm = KvmConfig {
        host,
        spki_sha256: pin.to_ascii_lowercase(),
        scheme,
        web_port: raw.kvm.web_port.unwrap_or(dw),
        video_port: raw.kvm.video_port.unwrap_or(dv),
        control_port: raw.kvm.control_port.unwrap_or(dc),
        password: read_secret(
            base,
            &required_path(raw.kvm.password_file, "kvm.password_file")?,
            "kvm.password_file",
        )?,
        connect_timeout: dur(raw.kvm.connect_timeout.as_ref(), s(3), "kvm.connect_timeout")?,
        login_timeout: dur(raw.kvm.login_timeout.as_ref(), s(5), "kvm.login_timeout")?,
        backoff,
        upstream_deadline: dur(raw.kvm.upstream_deadline.as_ref(), s(20), "kvm.upstream_deadline")?,
    };

    let rv = &raw.video;
    let idr_policy = match rv.idr_policy.as_deref().unwrap_or("side") {
        "side" => IdrPolicy::Side,
        "reconnect" => IdrPolicy::Reconnect,
        "wait" => IdrPolicy::Wait,
        _ => return Err(invalid("video.idr_policy must be side, reconnect or wait")),
    };
    let mut sps_rewrite = SpsRewrite::default();
    let names = rv.sps_rewrite.clone().unwrap_or_else(|| vec!["level".into(), "vui".into(), "restriction".into()]);
    for name in &names {
        match name.as_str() {
            "level" => sps_rewrite.level = true,
            "vui" => sps_rewrite.vui = true,
            "restriction" => sps_rewrite.restriction = true,
            _ => return Err(invalid("video.sps_rewrite holds only level, vui, restriction")),
        }
    }
    // §6.8: the rewrite is required, never pass-through — without `level`
    // every ES3 session would end `stream_incompatible` with nothing at
    // startup to say why. The key stays (§4.4) but must name all three.
    if !(sps_rewrite.level && sps_rewrite.vui && sps_rewrite.restriction) {
        return Err(invalid("video.sps_rewrite must hold level, vui and restriction (§6.8: the rewrite is required)"));
    }
    let video = VideoConfig {
        default_size: size(rv.default_size.as_ref())?,
        max_fps: ranged(rv.max_fps, 30, 1, 60, "video.max_fps")?,
        soft_gate: dur(rv.soft_gate.as_ref(), ms(500), "video.soft_gate")?,
        hard_cap: dur(rv.hard_cap.as_ref(), s(2), "video.hard_cap")?,
        backlog_limit: ranged(rv.backlog_limit, 4 << 20, 1, 1 << 30, "video.backlog_limit")?,
        standing_delay_limit: dur(rv.standing_delay_limit.as_ref(), ms(500), "video.standing_delay_limit")?,
        rtt_probe_interval: dur(rv.rtt_probe_interval.as_ref(), ms(250), "video.rtt_probe_interval")?,
        first_ack_grace: dur(rv.first_ack_grace.as_ref(), ms(1600), "video.first_ack_grace")?,
        stall_timeout: dur(rv.stall_timeout.as_ref(), s(10), "video.stall_timeout")?,
        idr_policy,
        idr_side_timeout: dur(rv.idr_side_timeout.as_ref(), s(1), "video.idr_side_timeout")?,
        idr_wait_max: dur(rv.idr_wait_max.as_ref(), s(3), "video.idr_wait_max")?,
        flv_reconnect_interval_setup: dur(rv.flv_reconnect_interval_setup.as_ref(), s(1), "video.flv_reconnect_interval_setup")?,
        flv_reconnect_interval_flow: dur(rv.flv_reconnect_interval_flow.as_ref(), s(10), "video.flv_reconnect_interval_flow")?,
        flv_idle_timeout: dur(rv.flv_idle_timeout.as_ref(), s(10), "video.flv_idle_timeout")?,
        burst_chunk: ranged(rv.burst_chunk, 8, 1, 64, "video.burst_chunk")?,
        sps_rewrite,
        avc420_timeout: dur(rv.avc420_timeout.as_ref(), s(10), "video.avc420_timeout")?,
        suppress_debounce: dur(rv.suppress_debounce.as_ref(), s(1), "video.suppress_debounce")?,
        disconnect_watchdog: dur(rv.disconnect_watchdog.as_ref(), s(5), "video.disconnect_watchdog")?,
        region_qp: ranged(rv.region_qp, 22, 0, 51, "video.region_qp")?,
    };
    if !(1..=4096).contains(&video.hard_cap_frames()) {
        return Err(invalid("video.hard_cap × video.max_fps must be 1..=4096 frames"));
    }

    let ri = &raw.input;
    let input = InputConfig {
        queue: ranged(ri.queue, 256, 1, 4096, "input.queue")?,
        hid_write_timeout: dur(ri.hid_write_timeout.as_ref(), s(1), "input.hid_write_timeout")?,
        key_repeat_timeout: dur(ri.key_repeat_timeout.as_ref(), s(10), "input.key_repeat_timeout")?,
        modifier_idle_timeout: dur(ri.modifier_idle_timeout.as_ref(), s(30), "input.modifier_idle_timeout")?,
        mac_remap: ri.mac_remap.unwrap_or(false),
    };
    let rp = &raw.paste;
    let chord = rp.chord.clone().unwrap_or_else(|| "ctrl+option+shift+v".to_owned());
    if chord.is_empty() {
        return Err(invalid("paste.chord must not be empty"));
    }
    let paste = PasteConfig {
        chord,
        pace: dur_or_zero(rp.pace.as_ref(), ms(15), "paste.pace")?,
        max_chars: ranged(rp.max_chars, 4096, 1, 1 << 20, "paste.max_chars")?,
        max_bytes: ranged(rp.max_bytes, 64 << 10, 1, 16 << 20, "paste.max_bytes")?,
        modifier_wait: dur(rp.modifier_wait.as_ref(), s(5), "paste.modifier_wait")?,
        multiline: match rp.multiline.as_deref().unwrap_or("enter") {
            "enter" => Multiline::Enter,
            "refuse" => Multiline::Refuse,
            _ => return Err(invalid("paste.multiline must be enter or refuse")),
        },
    };
    let security = SecurityConfig {
        accept_rate: ranged(raw.security.accept_rate, 30, 1, 10_000, "security.accept_rate")?,
        accept_window: dur(raw.security.accept_window.as_ref(), s(60), "security.accept_window")?,
    };
    let log = LogConfig {
        filter: raw.log.filter.unwrap_or_else(|| "info".to_owned()),
    };
    Ok(Config { rdp, admin, kvm, video, input, paste, security, log })
}
```

- [ ] **Step 4: Run the tests.**

Run: `cargo test --workspace --all-features --lib -- config`
Expected: PASS — 6 passed.

- [ ] **Step 5: Gate.** `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `scripts/target-budget.sh`. Expected: clean, 0 failed, within budget.

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/config.rs crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: config — one TOML file, the §4.4 defaults, secrets only from files" \
  -m "Durations bounded to 1 h; one trailing line ending trimmed from secrets; Secret's Debug is redacted (DC5)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.3: `logging` — JSON lines, one user filter, an uncrossable cap

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/logging.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod logging;`)
- Test: `crates/kvm-rdp/src/logging.rs` (`tests`)

**Interfaces:**
- Consumes: nothing new.
- Produces (`kvm_rdp::logging`): `pub const CAPPED_TARGETS: &[&str]`; `pub struct LogError(pub String)` (`Display`, `Error`); `pub fn subscriber<W>(filter: &str, writer: W) -> Result<impl tracing::Subscriber + Send + Sync + 'static, LogError> where W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static`; `pub fn init(filter: &str) -> Result<(), LogError>` (global, stdout); `pub fn redact_url(scheme: &str, host: &str, port: u16, path: &str) -> String`.

- [ ] **Step 1: Write the failing tests.** Create `crates/kvm-rdp/src/logging.rs` with the test module and add `pub mod logging;` to `lib.rs`:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` into a shared buffer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    struct BufWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for BufWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> BufWriter {
            BufWriter(self.0.clone())
        }
    }
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn emit_all() {
        tracing::debug!(target: "ironrdp_server::server", "ironrdp-debug");
        tracing::info!(target: "ironrdp_server::server", "ironrdp-info");
        tracing::debug!(target: "ironrdp_acceptor::credssp", "credssp-debug");
        tracing::trace!(target: "sspi::ntlm", "ntlm-trace");
        tracing::debug!(target: "tokio_tungstenite::compat", "ws-debug");
        tracing::trace!(target: "kvm_rdp::pump", "bridge-trace");
        tracing::info!(target: "kvm_rdp::bridge", "bridge-info");
    }

    fn run(filter: &str) -> String {
        let buf = Buf::default();
        let sub = subscriber(filter, buf.clone()).unwrap();
        tracing::subscriber::with_default(sub, emit_all);
        buf.text()
    }

    #[test]
    fn third_party_debug_is_capped_even_at_trace() {
        let out = run("trace");
        for hidden in ["ironrdp-debug", "credssp-debug", "ntlm-trace", "ws-debug"] {
            assert!(!out.contains(hidden), "{hidden} leaked: {out}");
        }
        for shown in ["ironrdp-info", "bridge-trace", "bridge-info"] {
            assert!(out.contains(shown), "{shown} missing: {out}");
        }
    }

    /// §11.3's second secrets-hygiene filter: naming a capped target in
    /// config cannot raise it.
    #[test]
    fn a_filter_naming_a_capped_target_cannot_raise_it() {
        let out = run("kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace");
        assert!(!out.contains("credssp-debug") && !out.contains("ntlm-trace"), "{out}");
        assert!(out.contains("bridge-trace"), "{out}");
    }

    #[test]
    fn the_user_filter_still_narrows() {
        let out = run("info");
        assert!(!out.contains("bridge-trace") && out.contains("bridge-info"), "{out}");
    }

    #[test]
    fn every_line_is_json() {
        let out = run("trace");
        assert!(out.lines().count() >= 3);
        for line in out.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("level").is_some() && v.get("target").is_some(), "{line}");
        }
    }

    #[test]
    fn a_bad_filter_is_an_error() {
        assert!(subscriber("kvm_rdp=loud", Buf::default()).is_err());
    }

    #[test]
    fn urls_are_logged_without_their_query() {
        assert_eq!(
            redact_url("https", "192.168.0.50", 8881, "/av.flv?token=0.123"),
            "https://192.168.0.50:8881/av.flv"
        );
        assert_eq!(redact_url("wss", "kvm", 8889, "/websocket"), "wss://kvm:8889/websocket");
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test --workspace --all-features --lib -- logging`
Expected: FAIL to compile — `cannot find function subscriber`.

- [ ] **Step 3: Implement.** Above the test module:

```rust
//! Logging (spec §4.5): `tracing` JSON lines on stdout. `log.filter` is one
//! `EnvFilter` (parsed from config, never from `RUST_LOG`); a second,
//! independent `Targets` filter holds the libraries that log credentials or
//! payloads at INFO, combined with `FilterExt::and`, so nothing in config can
//! raise them. Bridge code logs no keystrokes, HID frames, pasted text,
//! tokens or passwords, and no per-frame event above `trace`.
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{EnvFilter, FilterExt as _, LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

/// Targets held at INFO whatever `log.filter` says: sspi and the acceptor
/// log NTLM tokens at debug, `ironrdp_server` traces every event, and the
/// websocket/HTTP/TLS stacks trace payloads (§4.5). Prefix matches, plus the
/// IronRDP crates spelled out.
pub const CAPPED_TARGETS: &[&str] = &[
    "ironrdp",
    "ironrdp_server",
    "ironrdp_acceptor",
    "ironrdp_connector",
    "ironrdp_egfx",
    "ironrdp_dvc",
    "ironrdp_svc",
    "ironrdp_pdu",
    "ironrdp_tokio",
    "ironrdp_async",
    "ironrdp_cliprdr",
    "ironrdp_displaycontrol",
    "ironrdp_graphics",
    "sspi",
    "picky",
    "picky_krb",
    "tungstenite",
    "tokio_tungstenite",
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tokio_rustls",
];

#[derive(Debug)]
pub struct LogError(pub String);

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "logging: {}", self.0)
    }
}

impl std::error::Error for LogError {}

/// The bridge's subscriber writing to `writer` (tests pass a buffer).
pub fn subscriber<W>(filter: &str, writer: W) -> Result<impl tracing::Subscriber + Send + Sync + 'static, LogError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let user = EnvFilter::builder()
        .parse(filter)
        .map_err(|e| LogError(format!("log.filter: {e}")))?;
    let cap = CAPPED_TARGETS
        .iter()
        .fold(Targets::new().with_default(LevelFilter::TRACE), |t, name| {
            t.with_target(*name, LevelFilter::INFO)
        });
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(user.and(cap));
    Ok(tracing_subscriber::registry().with(layer))
}

/// Install the subscriber process-wide, writing to stdout.
pub fn init(filter: &str) -> Result<(), LogError> {
    let sub = subscriber(filter, std::io::stdout)?;
    tracing::subscriber::set_global_default(sub).map_err(|e| LogError(e.to_string()))
}

/// `scheme://host:port/path`, query removed (§4.5): a URL can carry the
/// KVM token (`av.flv?token=`).
#[must_use]
pub fn redact_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    format!("{scheme}://{host}:{port}{path}")
}
```

- [ ] **Step 4: Run the tests.**

Run: `cargo test --workspace --all-features --lib -- logging`
Expected: PASS — 6 passed.

- [ ] **Step 5: Gate** (clippy, test, `scripts/target-budget.sh`) — Expected: clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/logging.rs crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: logging — JSON lines, log.filter, an INFO cap on ironrdp/sspi/http/ws/tls (§4.5)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.4: `metrics` — the §10.4 registry as Prometheus text

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/metrics.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod metrics;`)
- Test: `crates/kvm-rdp/src/metrics.rs` (`tests`)

**Interfaces:**
- Consumes: nothing.
- Produces (`kvm_rdp::metrics`): `Counter { inc(&self), add(&self, u64), get(&self) -> u64 }`, `Gauge { set(&self, i64), get(&self) -> i64 }`, `Family { inc(&self, value: &'static str), get(&self, value: &str) -> u64, total(&self) -> u64 }`, `Histogram { observe(&self, Duration), observe_bytes(&self, u64), count(&self) -> u64 }`, and `pub struct Metrics` (`Default`, `render(&self) -> String`) with exactly these public fields — field (kind, label) → exposition name; counters and families add `_total`:
  - counters: `flv_bytes` → `kvm_rdp_flv_bytes`, `flv_tags` → `kvm_rdp_flv_tags`, `logins` → `kvm_rdp_kvm_logins`, `relogins` → `kvm_rdp_kvm_relogins`, `idr_side_fallbacks` → `kvm_rdp_idr_side_fallbacks`, `idr_cancelled` → `kvm_rdp_idr_cancelled`, `bursts` → `kvm_rdp_burst_frames`, `frames_sent` → `kvm_rdp_egfx_frames_sent`, `frames_acked` → `kvm_rdp_egfx_frames_acked`, `hid_reports_sent`, `hid_reports_coalesced`, `hid_resyncs`, `hid_epoch_discards`, `sessions`, `accept_refused`, `input_events_ignored` → `kvm_rdp_<field>`;
  - families: `frames` (type) → `kvm_rdp_kvm_frames`; `parse_errors` (kind), `upstream_reconnects` (reason), `idr_requests` (kind), `idr_side_failures` (kind), `sps_rewrites` (field), `sps_changes` (class), `frames_dropped` (reason), `release_all` (trigger), `disconnects` (cause) → `kvm_rdp_<field>`;
  - gauges: `kvm_fps` → `kvm_rdp_kvm_fps`; `egfx_in_flight`, `egfx_backlog_bytes`, `egfx_ack_suspended`, `egfx_oldest_unacked_ms`, `autodetect_rtt_ms`, `standing_delay_ms`, `egfx_capability_version` → `kvm_rdp_<field>`;
  - histograms: `frame_bytes` (bytes) → `kvm_rdp_kvm_frame_bytes`, `inter_arrival` → `kvm_rdp_kvm_inter_arrival_seconds`, `enqueue_latency` → `kvm_rdp_enqueue_latency_seconds`, `ack_rtt` → `kvm_rdp_egfx_ack_rtt_seconds`, `qoe_decode` → `kvm_rdp_egfx_qoe_decode_seconds`.
  - §10.4's paste events and skipped characters are Plan D's; allocations per frame (`alloc-stats` builds) are Plan E's.

- [ ] **Step 1: Write the failing tests.** Create `metrics.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn counters_families_gauges_and_the_histograms_render() {
        let m = Metrics::default();
        m.sessions.inc();
        m.frames_dropped.inc("soft_gate");
        m.frames_dropped.inc("soft_gate");
        m.frames_dropped.inc("paused");
        m.egfx_in_flight.set(7);
        m.enqueue_latency.observe(Duration::from_micros(300));
        m.enqueue_latency.observe(Duration::from_millis(3));
        m.frame_bytes.observe_bytes(3000);
        let t = m.render();
        assert!(t.contains("# TYPE kvm_rdp_sessions_total counter\nkvm_rdp_sessions_total 1\n"), "{t}");
        assert!(t.contains("kvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 2\n"), "{t}");
        assert!(t.contains("kvm_rdp_frames_dropped_total{reason=\"paused\"} 1\n"), "{t}");
        assert!(t.contains("# TYPE kvm_rdp_egfx_in_flight gauge\nkvm_rdp_egfx_in_flight 7\n"), "{t}");
        assert!(t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.0005\"} 1\n"), "{t}");
        assert!(t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 2\n"), "{t}");
        assert!(t.contains("kvm_rdp_enqueue_latency_seconds_bucket{le=\"+Inf\"} 2\n"), "{t}");
        assert!(t.contains("kvm_rdp_enqueue_latency_seconds_count 2\n"), "{t}");
        assert!(t.contains("kvm_rdp_kvm_frame_bytes_bucket{le=\"1024\"} 0\n"), "{t}");
        assert!(t.contains("kvm_rdp_kvm_frame_bytes_bucket{le=\"4096\"} 1\n"), "{t}");
        assert!(t.contains("kvm_rdp_kvm_frame_bytes_sum 3000\n"), "{t}");
        assert_eq!(m.frames_dropped.get("soft_gate"), 2);
        assert_eq!(m.frames_dropped.total(), 3);
    }

    #[test]
    fn every_metric_name_is_unique_and_well_formed() {
        let t = Metrics::default().render();
        let names: Vec<&str> = t
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        assert_eq!(names.len(), 39, "16 counters, 10 families, 8 gauges, 5 histograms");
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate metric name");
        for n in names {
            assert!(n.starts_with("kvm_rdp_"), "{n}");
            assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'), "{n}");
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- metrics` — Expected: FAIL to compile (`Metrics` not found).

- [ ] **Step 3: Implement.** Above the tests (the histogram takes its bounds and unit, so §10.4's frame bytes sit beside the latency histograms — verified in a scratch crate with the crate-root lints: clippy clean, 2 passed):

```rust
//! The bridge's metrics (spec §10.4), rendered as Prometheus text for
//! `/metrics` (§4.5). Label values are `&'static str` from bridge code —
//! never device or client text.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

pub struct Counter {
    name: &'static str,
    help: &'static str,
    v: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Counter {
        Counter { name, help, v: AtomicU64::new(0) }
    }
    pub fn inc(&self) {
        self.add(1);
    }
    pub fn add(&self, n: u64) {
        self.v.fetch_add(n, Ordering::Relaxed);
    }
    #[must_use]
    pub fn get(&self) -> u64 {
        self.v.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(out, "# HELP {0}_total {1}\n# TYPE {0}_total counter\n{0}_total {2}\n", self.name, self.help, self.get());
    }
}

pub struct Gauge {
    name: &'static str,
    help: &'static str,
    v: AtomicI64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Gauge {
        Gauge { name, help, v: AtomicI64::new(0) }
    }
    pub fn set(&self, v: i64) {
        self.v.store(v, Ordering::Relaxed);
    }
    #[must_use]
    pub fn get(&self) -> i64 {
        self.v.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(out, "# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n", self.name, self.help, self.get());
    }
}

/// A counter with one label.
pub struct Family {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    v: Mutex<BTreeMap<&'static str, u64>>,
}

impl Family {
    const fn new(name: &'static str, help: &'static str, label: &'static str) -> Family {
        Family { name, help, label, v: Mutex::new(BTreeMap::new()) }
    }
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, u64>> {
        self.v.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn inc(&self, value: &'static str) {
        let mut m = self.map();
        let e = m.entry(value).or_insert(0);
        *e = e.saturating_add(1);
    }
    #[must_use]
    pub fn get(&self, value: &str) -> u64 {
        self.map().get(value).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn total(&self) -> u64 {
        self.map().values().fold(0, |a, b| a.saturating_add(*b))
    }
    fn render(&self, out: &mut String) {
        let _ = write!(out, "# HELP {0}_total {1}\n# TYPE {0}_total counter\n", self.name, self.help);
        for (k, v) in self.map().iter() {
            let _ = writeln!(out, "{}_total{{{}=\"{k}\"}} {v}", self.name, self.label);
        }
    }
}

/// Bucket bounds, in the histogram's unit.
const LATENCY: &[f64] = &[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.05, 0.25, 1.0];
const FRAME_BYTES: &[f64] = &[1024.0, 4096.0, 16384.0, 65536.0, 262_144.0, 1_048_576.0, 4_194_304.0];
const INTER_ARRIVAL: &[f64] = &[0.01, 0.02, 0.03, 0.035, 0.04, 0.05, 0.1, 0.25, 1.0];
const ACK_RTT: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];
const QOE_DECODE: &[f64] = &[0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25];

/// What a histogram measures: which `observe` it takes and its `_sum`'s unit.
#[derive(Clone, Copy)]
enum Unit {
    Seconds,
    Bytes,
}

pub struct Histogram {
    name: &'static str,
    help: &'static str,
    bounds: &'static [f64],
    unit: Unit,
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    /// Microseconds (`Seconds`) or bytes (`Bytes`).
    sum: AtomicU64,
}

impl Histogram {
    fn new(name: &'static str, help: &'static str, bounds: &'static [f64], unit: Unit) -> Histogram {
        Histogram {
            name,
            help,
            bounds,
            unit,
            buckets: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
        }
    }
    /// A duration (a seconds histogram).
    pub fn observe(&self, d: Duration) {
        self.record(d.as_secs_f64(), u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    }
    /// A byte count (a bytes histogram).
    pub fn observe_bytes(&self, n: u64) {
        self.record(f64::from(u32::try_from(n).unwrap_or(u32::MAX)), n);
    }
    fn record(&self, v: f64, sum: u64) {
        if let Some(i) = self.bounds.iter().position(|&b| v <= b)
            && let Some(b) = self.buckets.get(i)
        {
            b.fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(sum, Ordering::Relaxed);
    }
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    fn render(&self, out: &mut String) {
        let _ = write!(out, "# HELP {0} {1}\n# TYPE {0} histogram\n", self.name, self.help);
        let mut cumulative = 0u64;
        for (bound, b) in self.bounds.iter().zip(self.buckets.iter()) {
            cumulative = cumulative.saturating_add(b.load(Ordering::Relaxed));
            let _ = writeln!(out, "{}_bucket{{le=\"{bound}\"}} {cumulative}", self.name);
        }
        let count = self.count();
        let raw = self.sum.load(Ordering::Relaxed);
        let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {count}", self.name);
        let _ = match self.unit {
            Unit::Seconds => writeln!(out, "{}_sum {}", self.name, Duration::from_micros(raw).as_secs_f64()),
            Unit::Bytes => writeln!(out, "{}_sum {raw}", self.name),
        };
        let _ = writeln!(out, "{}_count {count}", self.name);
    }
}

pub struct Metrics {
    pub flv_bytes: Counter,
    pub flv_tags: Counter,
    pub frames: Family,
    pub frame_bytes: Histogram,
    pub inter_arrival: Histogram,
    pub kvm_fps: Gauge,
    pub parse_errors: Family,
    pub upstream_reconnects: Family,
    pub logins: Counter,
    pub relogins: Counter,
    pub idr_requests: Family,
    pub idr_side_failures: Family,
    pub idr_side_fallbacks: Counter,
    pub idr_cancelled: Counter,
    pub sps_rewrites: Family,
    pub sps_changes: Family,
    pub bursts: Counter,
    pub frames_sent: Counter,
    pub frames_acked: Counter,
    pub frames_dropped: Family,
    pub enqueue_latency: Histogram,
    pub ack_rtt: Histogram,
    pub qoe_decode: Histogram,
    pub egfx_in_flight: Gauge,
    pub egfx_backlog_bytes: Gauge,
    pub egfx_ack_suspended: Gauge,
    pub egfx_oldest_unacked_ms: Gauge,
    pub autodetect_rtt_ms: Gauge,
    pub standing_delay_ms: Gauge,
    pub egfx_capability_version: Gauge,
    pub hid_reports_sent: Counter,
    pub hid_reports_coalesced: Counter,
    pub hid_resyncs: Counter,
    pub hid_epoch_discards: Counter,
    pub release_all: Family,
    pub sessions: Counter,
    pub disconnects: Family,
    pub accept_refused: Counter,
    pub input_events_ignored: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            flv_bytes: Counter::new("kvm_rdp_flv_bytes", "FLV bytes read from the KVM (main stream)"),
            flv_tags: Counter::new("kvm_rdp_flv_tags", "FLV tags demuxed (main stream)"),
            frames: Family::new("kvm_rdp_kvm_frames", "Access units admitted, by type", "type"),
            frame_bytes: Histogram::new("kvm_rdp_kvm_frame_bytes", "VCL bytes per admitted access unit", FRAME_BYTES, Unit::Bytes),
            inter_arrival: Histogram::new(
                "kvm_rdp_kvm_inter_arrival_seconds",
                "Time between admitted access units on one FLV connection",
                INTER_ARRIVAL,
                Unit::Seconds,
            ),
            kvm_fps: Gauge::new("kvm_rdp_kvm_fps", "Access units admitted per second, over the last whole second"),
            parse_errors: Family::new("kvm_rdp_parse_errors", "Framing violations (§6.9)", "kind"),
            upstream_reconnects: Family::new("kvm_rdp_upstream_reconnects", "KVM reconnects by reason", "reason"),
            logins: Counter::new("kvm_rdp_kvm_logins", "Successful KVM logins"),
            relogins: Counter::new("kvm_rdp_kvm_relogins", "Re-logins after an auth failure"),
            idr_requests: Family::new("kvm_rdp_idr_requests", "IDR requests by mechanism", "kind"),
            idr_side_failures: Family::new("kvm_rdp_idr_side_failures", "Side-FLV failures by kind", "kind"),
            idr_side_fallbacks: Counter::new("kvm_rdp_idr_side_fallbacks", "Side requests that fell back to a reconnect"),
            idr_cancelled: Counter::new("kvm_rdp_idr_cancelled", "Deferred IDR requests cancelled"),
            sps_rewrites: Family::new("kvm_rdp_sps_rewrites", "SPS rewrites by field (§6.8)", "field"),
            sps_changes: Family::new("kvm_rdp_sps_changes", "SpsChanged by class", "class"),
            bursts: Counter::new("kvm_rdp_burst_frames", "Access units marked burst"),
            frames_sent: Counter::new("kvm_rdp_egfx_frames_sent", "KVM frames handed to IronRDP"),
            frames_acked: Counter::new("kvm_rdp_egfx_frames_acked", "EGFX frame acknowledgements"),
            frames_dropped: Family::new("kvm_rdp_frames_dropped", "Frames dropped by reason (§10.4)", "reason"),
            enqueue_latency: Histogram::new(
                "kvm_rdp_enqueue_latency_seconds",
                "Tag parsed to ServerEvent enqueued",
                LATENCY,
                Unit::Seconds,
            ),
            ack_rtt: Histogram::new(
                "kvm_rdp_egfx_ack_rtt_seconds",
                "Frame handed to IronRDP to its FrameAcknowledge",
                ACK_RTT,
                Unit::Seconds,
            ),
            qoe_decode: Histogram::new(
                "kvm_rdp_egfx_qoe_decode_seconds",
                "Client-reported decode and render time (QoE, V10+)",
                QOE_DECODE,
                Unit::Seconds,
            ),
            egfx_in_flight: Gauge::new("kvm_rdp_egfx_in_flight", "EGFX frames awaiting acknowledgement"),
            egfx_backlog_bytes: Gauge::new("kvm_rdp_egfx_backlog_bytes", "Handed minus written EGFX bytes"),
            egfx_ack_suspended: Gauge::new("kvm_rdp_egfx_ack_suspended", "1 while the client suspends acks"),
            egfx_oldest_unacked_ms: Gauge::new("kvm_rdp_egfx_oldest_unacked_ms", "Age of the oldest unacked frame"),
            autodetect_rtt_ms: Gauge::new("kvm_rdp_autodetect_rtt_ms", "Last live auto-detect RTT sample"),
            standing_delay_ms: Gauge::new("kvm_rdp_standing_delay_ms", "Standing delay estimate (§6.6)"),
            egfx_capability_version: Gauge::new("kvm_rdp_egfx_capability_version", "Negotiated EGFX capability version"),
            hid_reports_sent: Counter::new("kvm_rdp_hid_reports_sent", "HID frames written to the websocket"),
            hid_reports_coalesced: Counter::new("kvm_rdp_hid_reports_coalesced", "Motion reports replaced in the queue"),
            hid_resyncs: Counter::new("kvm_rdp_hid_resyncs", "Full-queue resyncs"),
            hid_epoch_discards: Counter::new("kvm_rdp_hid_epoch_discards", "Reports discarded by a release epoch"),
            release_all: Family::new("kvm_rdp_release_all", "Release-all by trigger (§7.4)", "trigger"),
            sessions: Counter::new("kvm_rdp_sessions", "Authenticated RDP sessions started"),
            disconnects: Family::new("kvm_rdp_disconnects", "Bridge-initiated disconnects by cause", "cause"),
            accept_refused: Counter::new("kvm_rdp_accept_refused", "TCP connections refused by on_accept"),
            input_events_ignored: Counter::new("kvm_rdp_input_events_ignored", "Client input events not yet mapped (Plan D)"),
        }
    }
}

impl Metrics {
    /// The Prometheus text exposition (version 0.0.4).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(12 * 1024);
        for c in [
            &self.flv_bytes, &self.flv_tags, &self.logins, &self.relogins, &self.idr_side_fallbacks,
            &self.idr_cancelled, &self.bursts, &self.frames_sent, &self.frames_acked,
            &self.hid_reports_sent, &self.hid_reports_coalesced, &self.hid_resyncs,
            &self.hid_epoch_discards, &self.sessions, &self.accept_refused, &self.input_events_ignored,
        ] {
            c.render(&mut out);
        }
        for f in [
            &self.frames, &self.parse_errors, &self.upstream_reconnects, &self.idr_requests,
            &self.idr_side_failures, &self.sps_rewrites, &self.sps_changes, &self.frames_dropped,
            &self.release_all, &self.disconnects,
        ] {
            f.render(&mut out);
        }
        for g in [
            &self.kvm_fps, &self.egfx_in_flight, &self.egfx_backlog_bytes, &self.egfx_ack_suspended,
            &self.egfx_oldest_unacked_ms, &self.autodetect_rtt_ms, &self.standing_delay_ms,
            &self.egfx_capability_version,
        ] {
            g.render(&mut out);
        }
        for h in [&self.frame_bytes, &self.inter_arrival, &self.enqueue_latency, &self.ack_rtt, &self.qoe_decode] {
            h.render(&mut out);
        }
        out
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- metrics` — Expected: PASS — 2 passed.

- [ ] **Step 5: Gate** (clippy, test, budget) — Expected: clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: metrics — the §10.4 registry as Prometheus text" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.5: `admin` — `/metrics`, `/livez`, `/readyz`

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/admin.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod admin;`)
- Test: `crates/kvm-rdp/src/admin.rs` (`tests`)

**Interfaces:**
- Consumes: `metrics::Metrics` (Task 2.4).
- Produces (`kvm_rdp::admin`): `pub struct Health` — `Health::new(liveness_timeout: Duration) -> Health`, `beat(&self)`, `set_tls_loaded(&self)`, `set_rdp_bound(&self)`, `live(&self) -> bool`, `ready(&self) -> bool`; `pub const MAX_REQUEST_HEAD: usize` (2048); `pub const REQUEST_TIMEOUT: Duration` (2 s); `pub async fn serve(listener: tokio::net::TcpListener, health: Arc<Health>, metrics: Arc<Metrics>)` (runs until its task is aborted).

- [ ] **Step 1: Write the failing tests.** Create `admin.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn start(liveness: Duration) -> (std::net::SocketAddr, Arc<Health>, Arc<Metrics>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let health = Arc::new(Health::new(liveness));
        let metrics = Arc::new(Metrics::default());
        tokio::spawn(serve(listener, health.clone(), metrics.clone()));
        (addr, health, metrics)
    }

    async fn raw(addr: std::net::SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await.unwrap().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        raw(addr, format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await
    }

    #[tokio::test]
    async fn livez_goes_stale_without_heartbeats() {
        // A 1 s liveness with a 2.5 s sleep: generous on both sides under
        // §13's niced, CPU-weighted test runs.
        let (addr, health, _) = start(Duration::from_secs(1)).await;
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 503"));
        health.beat();
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn readyz_needs_tls_and_the_rdp_listener_and_never_the_kvm() {
        let (addr, health, _) = start(Duration::from_secs(10)).await;
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 503"));
        health.set_tls_loaded();
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 503"));
        health.set_rdp_bound();
        assert!(get(addr, "/readyz").await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn metrics_and_unknown_paths() {
        let (addr, _, metrics) = start(Duration::from_secs(10)).await;
        metrics.sessions.inc();
        let r = get(addr, "/metrics").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains("Content-Type: text/plain; version=0.0.4"), "{r}");
        assert!(r.contains("kvm_rdp_sessions_total 1"), "{r}");
        assert!(get(addr, "/").await.starts_with("HTTP/1.1 404"));
        assert!(raw(addr, b"POST /livez HTTP/1.1\r\n\r\n").await.starts_with("HTTP/1.1 404"));
    }

    /// Review Focus 4: an oversized head is refused at once, a silent
    /// connection is dropped after `REQUEST_TIMEOUT`, and `/livez` answers
    /// promptly the whole time.
    #[tokio::test]
    async fn slow_or_huge_admin_requests_do_not_wedge_livez() {
        let (addr, _, _) = start(Duration::from_secs(10)).await;
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut huge = b"GET /metrics HTTP/1.1\r\nX-Pad: ".to_vec();
        huge.extend(std::iter::repeat_n(b'a', 3 * 1024));
        huge.extend_from_slice(b"\r\n\r\n");
        assert!(raw(addr, &huge).await.starts_with("HTTP/1.1 431"));
        let t = Instant::now();
        assert!(get(addr, "/livez").await.starts_with("HTTP/1.1 200"));
        // A listener that served the silent connection first would answer
        // only after its REQUEST_TIMEOUT.
        assert!(t.elapsed() < REQUEST_TIMEOUT, "{:?}", t.elapsed());
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(REQUEST_TIMEOUT * 2, silent.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(n, 0, "the silent connection is closed by the server");
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- admin` — Expected: FAIL to compile (`Health` not found).

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! The admin listener (spec §4.5) on the KVM runtime: `/metrics`, `/livez`
//! (the RDP runtime's heartbeat is fresh) and `/readyz` (TLS identity
//! loaded, RDP listener bound — never the KVM). One short-lived task per
//! connection; each request head is bounded in size and time.
use crate::metrics::Metrics;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Largest request head accepted.
pub const MAX_REQUEST_HEAD: usize = 2048;
/// A request head must arrive within this.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub struct Health {
    epoch: Instant,
    last_beat_ms: AtomicU64,
    tls_loaded: AtomicBool,
    rdp_bound: AtomicBool,
    liveness_timeout: Duration,
}

impl Health {
    #[must_use]
    pub fn new(liveness_timeout: Duration) -> Health {
        Health {
            epoch: Instant::now(),
            last_beat_ms: AtomicU64::new(0),
            tls_loaded: AtomicBool::new(false),
            rdp_bound: AtomicBool::new(false),
            liveness_timeout,
        }
    }
    /// The RDP runtime's heartbeat (a `LocalSet` task, every second).
    pub fn beat(&self) {
        let ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_beat_ms.store(ms, Ordering::Relaxed);
    }
    pub fn set_tls_loaded(&self) {
        self.tls_loaded.store(true, Ordering::Relaxed);
    }
    pub fn set_rdp_bound(&self) {
        self.rdp_bound.store(true, Ordering::Relaxed);
    }
    #[must_use]
    pub fn live(&self) -> bool {
        let last = Duration::from_millis(self.last_beat_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last) <= self.liveness_timeout
    }
    #[must_use]
    pub fn ready(&self) -> bool {
        self.tls_loaded.load(Ordering::Relaxed) && self.rdp_bound.load(Ordering::Relaxed)
    }
}

pub async fn serve(listener: TcpListener, health: Arc<Health>, metrics: Arc<Metrics>) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                tokio::spawn(handle(sock, health.clone(), metrics.clone()));
            }
            // EMFILE and friends: back off instead of spinning.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

enum Head {
    Complete(Vec<u8>),
    TooLarge,
    Closed,
}

async fn read_head(sock: &mut TcpStream) -> std::io::Result<Head> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Head::Closed);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(Head::Complete(buf));
        }
        if buf.len() > MAX_REQUEST_HEAD {
            return Ok(Head::TooLarge);
        }
    }
}

async fn handle(mut sock: TcpStream, health: Arc<Health>, metrics: Arc<Metrics>) {
    let _ = sock.set_nodelay(true);
    let (status, body) = match tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut sock)).await {
        Ok(Ok(Head::Complete(head))) => route(&head, &health, &metrics),
        Ok(Ok(Head::TooLarge)) => (431, "request head too large\n".to_owned()),
        _ => return,
    };
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let ctype = if status == 200 && body.starts_with("# HELP") {
        "text/plain; version=0.0.4"
    } else {
        "text/plain"
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(body.as_bytes()).await;
    let _ = sock.shutdown().await;
    // Drain what the client still sends (an oversized head's tail) so the
    // close is a FIN, not a reset that could beat the response to it.
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(100), async {
        while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
}

fn route(head: &[u8], health: &Health, metrics: &Metrics) -> (u16, String) {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(&[]);
    let line = std::str::from_utf8(line).unwrap_or("");
    let mut parts = line.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    match (method, path) {
        ("GET", "/metrics") => (200, metrics.render()),
        ("GET", "/livez") if health.live() => (200, "ok\n".to_owned()),
        ("GET", "/livez") => (503, "rdp runtime heartbeat is stale\n".to_owned()),
        ("GET", "/readyz") if health.ready() => (200, "ready\n".to_owned()),
        ("GET", "/readyz") => (503, "not ready\n".to_owned()),
        _ => (404, "not found\n".to_owned()),
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- admin` — Expected: PASS — 4 passed.

- [ ] **Step 5: Gate** (clippy, test, budget) — Expected: clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/admin.rs crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: admin listener — /metrics, /livez, /readyz with bounded requests (§4.5)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 3 — The KVM side

The vocabulary the three channels speak, then the KVM client from the bottom up — pinned TLS and login, the FLV and the websocket, the sans-IO upstream cores, the HID queue and writer — and finally the session actor that owns them per generation.

### Task 3.1: `msg` — generations, causes and the channel messages

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/msg.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod msg;`)
- Test: `crates/kvm-rdp/src/msg.rs` (`tests`)

**Interfaces:**
- Consumes: `ironrdp_server::{ConnectionAbortHandle, ErrorInfo, GfxServerHandle}`, `ironrdp_pdu::rdp::server_error_info::ProtocolIndependentCode`, `kvm_proto::video::{AccessUnit, ParamClass, ParamSets}`.
- Produces (`kvm_rdp::msg`):
  - `pub type Gen = u64;` `pub struct Generations` (`Default`) — `begin(&self) -> Gen` (nonzero, also made current), `end(&self) -> Option<Gen>` (swaps to none), `current(&self) -> Option<Gen>`, `is_current(&self, Gen) -> bool`.
  - `pub enum Cause { Shutdown, KvmUnreachable, StreamCorrupt, StreamIncompatible, NoAvc420, ClientStalled, ClipboardOversize, KvmAuthFailed, KvmCertMismatch }` — `label(self) -> &'static str`, `error_info(self) -> ErrorInfo` (§6.9's table).
  - `pub enum FlvOrigin { First, Transient, Commanded }` — `label(self) -> &'static str`.
  - `pub struct KvmAu { pub au: AccessUnit, pub after_drop: bool, pub received: Instant }`.
  - `pub enum KvmEvent { FlvOpened { generation, origin }, SpsChanged { generation, class: ParamClass, params: ParamSets }, Au { generation, au: KvmAu }, UpstreamFatal { generation, cause: Cause } }` — `generation(&self) -> Gen`.
  - `pub enum KvmCommand { Start { generation }, Stop { generation, done: Option<oneshot::Sender<()>> }, OpenFlv { generation }, RequestIdr { generation }, ReconnectFlv { generation }, FlushHid { done: oneshot::Sender<()> }, Shutdown { done: oneshot::Sender<()> } }`.
  - `pub enum RdpInput { SessionStart { generation, slot: u64, gfx: GfxServerHandle, counter: Arc<AtomicU64>, abort: ConnectionAbortHandle }, SessionStop { generation }, CapsAdvertised { slot, sets: Vec<String> }, OnReady { slot, version: u32 }, FrameAck { slot, frame_id: u32, queue_depth: u32 }, Updates, Shutdown { done: oneshot::Sender<()> }, Stall(Duration) }` (`Stall` is a doc-hidden test hook).
  - `pub fn kvm_stream_capacity(hard_cap_frames: u32) -> usize` (hard cap + 8, DC14).

- [ ] **Step 1: Write the failing tests.** Create `msg.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use ironrdp_pdu::rdp::server_error_info::ProtocolIndependentCode as P;

    const ALL: [Cause; 9] = [
        Cause::Shutdown,
        Cause::KvmUnreachable,
        Cause::StreamCorrupt,
        Cause::StreamIncompatible,
        Cause::NoAvc420,
        Cause::ClientStalled,
        Cause::ClipboardOversize,
        Cause::KvmAuthFailed,
        Cause::KvmCertMismatch,
    ];

    /// §6.9's ErrorInfo table, one row per cause.
    #[test]
    fn every_cause_maps_to_its_errorinfo() {
        for c in ALL {
            let code = c.error_info();
            let ok = match c {
                Cause::Shutdown => matches!(code, ErrorInfo::ProtocolIndependentCode(P::RpcInitiatedDisconnect)),
                Cause::KvmAuthFailed | Cause::KvmCertMismatch => {
                    matches!(code, ErrorInfo::ProtocolIndependentCode(P::ServerInsufficientPrivileges))
                }
                _ => matches!(code, ErrorInfo::ProtocolIndependentCode(P::ServerDeniedConnection)),
            };
            assert!(ok, "{c:?} → {code:?}");
        }
        let mut labels: Vec<_> = ALL.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL.len());
    }

    #[test]
    fn generations_begin_end_and_never_reuse() {
        let g = Generations::default();
        assert_eq!(g.current(), None);
        let a = g.begin();
        assert!(a != 0 && g.is_current(a));
        assert_eq!(g.end(), Some(a));
        assert!(!g.is_current(a) && g.end().is_none());
        let b = g.begin();
        assert!(b > a && g.is_current(b) && !g.is_current(0));
    }

    #[test]
    fn the_kvm_stream_holds_at_least_the_hard_cap() {
        assert_eq!(kvm_stream_capacity(60), 68);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- msg` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! What the RDP side, the pump and the KVM actor say to each other (§4.3),
//! and the generation that tags every word of it: `on_connection_info`
//! begins one, `on_disconnected` ends it before returning, and anything
//! carrying another generation is dropped (DC4).
use ironrdp_pdu::rdp::server_error_info::ProtocolIndependentCode;
use ironrdp_server::{ConnectionAbortHandle, ErrorInfo, GfxServerHandle};
use kvm_proto::video::{AccessUnit, ParamClass, ParamSets};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub type Gen = u64;

#[derive(Debug, Default)]
pub struct Generations {
    current: AtomicU64,
    next: AtomicU64,
}

impl Generations {
    /// A new, never-reused generation, made current.
    pub fn begin(&self) -> Gen {
        let g = self.next.fetch_add(1, Ordering::SeqCst).wrapping_add(1).max(1);
        self.current.store(g, Ordering::SeqCst);
        g
    }
    /// Invalidate the current generation; returns it.
    pub fn end(&self) -> Option<Gen> {
        let g = self.current.swap(0, Ordering::SeqCst);
        (g != 0).then_some(g)
    }
    #[must_use]
    pub fn current(&self) -> Option<Gen> {
        let g = self.current.load(Ordering::SeqCst);
        (g != 0).then_some(g)
    }
    #[must_use]
    pub fn is_current(&self, g: Gen) -> bool {
        g != 0 && self.current.load(Ordering::SeqCst) == g
    }
}

/// Why the bridge ends a session (§6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Shutdown,
    KvmUnreachable,
    StreamCorrupt,
    StreamIncompatible,
    NoAvc420,
    ClientStalled,
    ClipboardOversize,
    KvmAuthFailed,
    KvmCertMismatch,
}

impl Cause {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Cause::Shutdown => "shutdown",
            Cause::KvmUnreachable => "kvm_unreachable",
            Cause::StreamCorrupt => "stream_corrupt",
            Cause::StreamIncompatible => "stream_incompatible",
            Cause::NoAvc420 => "no_avc420",
            Cause::ClientStalled => "client_stalled",
            Cause::ClipboardOversize => "clipboard_oversize",
            Cause::KvmAuthFailed => "kvm_auth_failed",
            Cause::KvmCertMismatch => "kvm_cert_mismatch",
        }
    }

    /// MS-RDPBCGR 2.2.5.1.1 server-initiated codes, so clients do not
    /// auto-reconnect into a loop (§6.9).
    #[must_use]
    pub fn error_info(self) -> ErrorInfo {
        use ProtocolIndependentCode as P;
        ErrorInfo::ProtocolIndependentCode(match self {
            Cause::Shutdown => P::RpcInitiatedDisconnect,
            Cause::KvmAuthFailed | Cause::KvmCertMismatch => P::ServerInsufficientPrivileges,
            Cause::KvmUnreachable
            | Cause::StreamCorrupt
            | Cause::StreamIncompatible
            | Cause::NoAvc420
            | Cause::ClientStalled
            | Cause::ClipboardOversize => P::ServerDeniedConnection,
        })
    }
}

/// Why an FLV connection opened (§4.3 `FlvOpened`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlvOrigin {
    /// The first Setup's `OpenFlv`.
    First,
    /// A reconnect after the FLV was lost (§6.9 transient).
    Transient,
    /// A `ReconnectFlv` (make-before-break).
    Commanded,
}

impl FlvOrigin {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            FlvOrigin::First => "first",
            FlvOrigin::Transient => "transient",
            FlvOrigin::Commanded => "commanded",
        }
    }
}

/// One admitted access unit on its way to the pump.
#[derive(Debug, Clone)]
pub struct KvmAu {
    pub au: AccessUnit,
    /// An earlier AU was dropped on a full channel: a flow cause (DC12).
    pub after_drop: bool,
    /// When its tag was parsed (the enqueue-latency start, §10.1).
    pub received: Instant,
}

/// KVM → pump, on the one ordered, bounded stream (§4.3).
#[derive(Debug)]
pub enum KvmEvent {
    FlvOpened { generation: Gen, origin: FlvOrigin },
    SpsChanged { generation: Gen, class: ParamClass, params: ParamSets },
    Au { generation: Gen, au: KvmAu },
    UpstreamFatal { generation: Gen, cause: Cause },
}

impl KvmEvent {
    #[must_use]
    pub fn generation(&self) -> Gen {
        match self {
            KvmEvent::FlvOpened { generation, .. }
            | KvmEvent::SpsChanged { generation, .. }
            | KvmEvent::Au { generation, .. }
            | KvmEvent::UpstreamFatal { generation, .. } => *generation,
        }
    }
}

/// RDP side and pump → the KVM actor (unbounded: lifecycle and
/// rate-limited IDR commands only).
#[derive(Debug)]
pub enum KvmCommand {
    Start { generation: Gen },
    Stop { generation: Gen, done: Option<oneshot::Sender<()>> },
    OpenFlv { generation: Gen },
    RequestIdr { generation: Gen },
    ReconnectFlv { generation: Gen },
    /// Write any pending release-all now (shutdown, §5.2).
    FlushHid { done: oneshot::Sender<()> },
    /// Close everything (never a logout) and stop the actor.
    Shutdown { done: oneshot::Sender<()> },
}

/// IronRDP's callbacks → the pump (unbounded: they run under the GFX lock
/// and may only push, §4.3). `slot` names the GFX handle a callback came
/// from; a stale slot is dropped.
pub enum RdpInput {
    SessionStart {
        generation: Gen,
        slot: u64,
        gfx: GfxServerHandle,
        counter: Arc<AtomicU64>,
        abort: ConnectionAbortHandle,
    },
    SessionStop { generation: Gen },
    CapsAdvertised { slot: u64, sets: Vec<String> },
    OnReady { slot: u64, version: u32 },
    FrameAck { slot: u64, frame_id: u32, queue_depth: u32 },
    /// `RdpServerDisplay::updates()` ran: an activation or reactivation.
    Updates,
    /// Close the live session with cause `shutdown` (§5.2).
    Shutdown { done: oneshot::Sender<()> },
    /// Test hook: block the RDP runtime (L2 `/livez`).
    #[doc(hidden)]
    Stall(Duration),
}

impl std::fmt::Debug for RdpInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RdpInput::SessionStart { .. } => "SessionStart",
            RdpInput::SessionStop { .. } => "SessionStop",
            RdpInput::CapsAdvertised { .. } => "CapsAdvertised",
            RdpInput::OnReady { .. } => "OnReady",
            RdpInput::FrameAck { .. } => "FrameAck",
            RdpInput::Updates => "Updates",
            RdpInput::Shutdown { .. } => "Shutdown",
            RdpInput::Stall(_) => "Stall",
        };
        f.write_str(name)
    }
}

/// The KVM→pump channel's capacity: at least the hard cap (§4.3, DC14).
#[must_use]
pub fn kvm_stream_capacity(hard_cap_frames: u32) -> usize {
    usize::try_from(hard_cap_frames).unwrap_or(4096).saturating_add(8)
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- msg` — Expected: PASS — 3 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/msg.rs crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: msg — generations, causes with the §6.9 ErrorInfo table, channel messages" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.2: `kvm::{endpoint, error, login}` — pinned TLS and a login that never logs out

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/mod.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/error.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/endpoint.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/login.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod kvm;`)
- Test: `crates/kvm-rdp/src/kvm/login.rs` (`tests`)

**Interfaces:**
- Consumes: `config::{KvmConfig, Scheme, Secret}` (2.2), `logging::redact_url` (2.3), `kvm_proto::{parse_login_token, LoginError, Token}`.
- Produces:
  - `kvm::error`: `pub enum FailClass { Transient, Auth, Cert }`; `pub enum KvmError { CertMismatch, Auth, Timeout(&'static str), Connect(std::io::ErrorKind), Tls, Http(u16), Protocol(&'static str), Closed }` (`Clone + Eq + Debug`) — `class(&self) -> FailClass`, `kind(&self) -> &'static str` (metric label). Never carries device text.
  - `kvm::endpoint`: `pub trait IoStream` (blanket for `AsyncRead + AsyncWrite + Unpin + Send`), `pub type KvmIo = Box<dyn IoStream>`; `pub struct KvmEndpoint { pub scheme: Scheme, pub host: String, pub web_port: u16, pub video_port: u16, pub control_port: u16, .. }` — `KvmEndpoint::new(scheme: Scheme, host: impl Into<String>, ports: (u16, u16, u16), spki_sha256_hex: &str) -> KvmEndpoint`, `KvmEndpoint::from_config(&KvmConfig) -> KvmEndpoint`, `async fn connect(&self, port: u16, timeout: Duration) -> Result<KvmIo, KvmError>` (TCP_NODELAY; pinned TLS for `Https`), `fn url_for_log(&self, port: u16, path: &str) -> String`; `pub fn spki_sha256_hex(cert_der: &[u8]) -> Option<String>`.
  - `kvm::login`: `pub const MAX_LOGIN_BODY: usize` (64 KiB); `pub(crate) const MAX_RESPONSE_HEAD: usize` (16 KiB, hyper's `max_buf_size` for every KVM response head, login and FLV); `pub async fn login(ep: &KvmEndpoint, password: &Secret, connect_timeout: Duration, login_timeout: Duration) -> Result<Token, KvmError>`; `pub(crate) struct AbortOnDrop(pub tokio::task::JoinHandle<()>)`; `pub(crate) async fn read_capped(body: hyper::body::Incoming, cap: usize) -> Result<Vec<u8>, KvmError>`. **There is no logout function** (§3.2).

- [ ] **Step 1: Write the failing tests.** Create `kvm/mod.rs`:

```rust
//! The KVM side (spec §3): pinned TLS, login, the FLV and the control
//! websocket, the sans-IO upstream cores and the session actor. Nothing in
//! this module logs out — ES3 logout is global (§3.2) — and there is no
//! function that could.
pub mod endpoint;
pub mod error;
pub mod login;

pub use endpoint::KvmEndpoint;
pub use error::{FailClass, KvmError};
```

add `pub mod kvm;` to `lib.rs`, and create `kvm/login.rs` with only:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::Scheme;
    use crate::kvm::error::FailClass;
    use kvm_sim::{KvmSim, SimConfig, Source};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CT: Duration = Duration::from_secs(1);
    const LT: Duration = Duration::from_secs(2);

    async fn sim() -> KvmSim {
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        KvmSim::start(SimConfig::es3(src)).await.unwrap()
    }

    fn endpoint(sim: &KvmSim, pin: &str) -> KvmEndpoint {
        let p = sim.ports();
        KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), pin)
    }

    #[tokio::test]
    async fn login_with_the_pinned_certificate() {
        let sim = sim().await;
        let ep = endpoint(&sim, sim.spki_sha256());
        let token = login(&ep, &Secret::new(sim.password()), CT, LT).await.unwrap();
        assert!(token.as_str().starts_with("0."));
        assert_eq!(sim.stats().logins_ok, 1);
        assert_eq!(sim.stats().logouts, 0);
    }

    #[tokio::test]
    async fn a_wrong_password_is_an_auth_failure() {
        let sim = sim().await;
        let ep = endpoint(&sim, sim.spki_sha256());
        let e = login(&ep, &Secret::new("nope"), CT, LT).await.unwrap_err();
        assert_eq!((e.clone(), e.class()), (KvmError::Auth, FailClass::Auth));
    }

    /// §6.9: a pin mismatch is fatal at once and no login is ever sent.
    #[tokio::test]
    async fn a_wrong_pin_refuses_before_any_request() {
        let sim = sim().await;
        let ep = endpoint(&sim, &"0".repeat(64));
        let e = login(&ep, &Secret::new(sim.password()), CT, LT).await.unwrap_err();
        assert_eq!((e.clone(), e.class()), (KvmError::CertMismatch, FailClass::Cert));
        let s = sim.stats();
        assert_eq!((s.logins_ok, s.logins_failed), (0, 0));
    }

    #[tokio::test]
    async fn an_unreachable_kvm_times_out_as_transient() {
        let sim = sim().await;
        sim.set_policy(|p| p.blackhole = true);
        let ep = endpoint(&sim, sim.spki_sha256());
        let t = Instant::now();
        let e = login(&ep, &Secret::new(sim.password()), CT, LT).await.unwrap_err();
        assert_eq!(e.class(), FailClass::Transient, "{e:?}");
        assert!(t.elapsed() >= CT / 2 && t.elapsed() < CT * 5, "{:?}", t.elapsed());
    }

    #[derive(Clone, Copy)]
    enum Hostile {
        EndlessBody,
        HugeHeader,
        Silent,
    }

    /// A plain-HTTP KVM (scheme `http`, §3.2's diagnosis option) that
    /// answers every request the hostile way.
    async fn hostile(mode: Hostile) -> KvmEndpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut req = [0u8; 4096];
                    let _ = s.read(&mut req).await;
                    match mode {
                        Hostile::EndlessBody => {
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n").await;
                            let chunk = vec![b'{'; 16 * 1024];
                            while s.write_all(&chunk).await.is_ok() {}
                        }
                        Hostile::HugeHeader => {
                            let mut h = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
                            h.extend(std::iter::repeat_n(b'a', 1 << 20));
                            h.extend_from_slice(b"\r\n\r\n");
                            let _ = s.write_all(&h).await;
                        }
                        Hostile::Silent => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        KvmEndpoint::new(Scheme::Http, "127.0.0.1", (port, port, port), &"0".repeat(64))
    }

    /// Review Focus 3: whatever a hostile KVM answers, login ends within
    /// `login_timeout` and carries no device text; the 1 MiB header is
    /// refused at `MAX_RESPONSE_HEAD` (16 KiB), the endless body at
    /// `MAX_LOGIN_BODY` (64 KiB).
    #[tokio::test]
    async fn hostile_login_responses_are_bounded() {
        for (mode, want) in [
            (Hostile::EndlessBody, KvmError::Protocol("body too large")),
            (Hostile::HugeHeader, KvmError::Protocol("response")),
            (Hostile::Silent, KvmError::Timeout("login")),
        ] {
            let ep = hostile(mode).await;
            let t = Instant::now();
            let e = login(&ep, &Secret::new("pw"), CT, LT).await.unwrap_err();
            assert_eq!(e, want);
            assert!(t.elapsed() < LT + Duration::from_millis(500), "{:?}", t.elapsed());
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- kvm::login` — Expected: FAIL to compile (`kvm::endpoint` missing).

- [ ] **Step 3: Implement the error type.** `kvm/error.rs`:

```rust
//! KVM-side failures by §6.9 class. Variants carry codes and static
//! strings only — never text the device sent.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// Reconnect with backoff.
    Transient,
    /// Re-login once (§6.9 auth).
    Auth,
    /// Fatal at once: `kvm_cert_mismatch`.
    Cert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvmError {
    /// The certificate's SPKI is not the pinned one (§3.2).
    CertMismatch,
    /// Login rejected, HTTP 401/403, or `result: 403`.
    Auth,
    Timeout(&'static str),
    Connect(std::io::ErrorKind),
    /// Any other TLS failure.
    Tls,
    /// An HTTP status other than 200/401/403.
    Http(u16),
    Protocol(&'static str),
    /// The connection ended.
    Closed,
}

impl KvmError {
    #[must_use]
    pub fn class(&self) -> FailClass {
        match self {
            KvmError::CertMismatch => FailClass::Cert,
            KvmError::Auth => FailClass::Auth,
            _ => FailClass::Transient,
        }
    }

    /// A metric label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            KvmError::CertMismatch => "cert",
            KvmError::Auth => "auth",
            KvmError::Timeout(_) => "timeout",
            KvmError::Connect(_) => "connect",
            KvmError::Tls => "tls",
            KvmError::Http(_) => "http",
            KvmError::Protocol(_) => "protocol",
            KvmError::Closed => "eof",
        }
    }
}
```

- [ ] **Step 4: Implement the endpoint.** `kvm/endpoint.rs`:

```rust
//! Connections to the KVM (§3.2): `TCP_NODELAY` on every socket and, for
//! `https`, TLS whose only certificate check is the SPKI pin — one pin for
//! all three ports. There is no accept-any verifier.
use crate::config::{KvmConfig, Scheme};
use crate::kvm::error::KvmError;
use crate::logging::redact_url;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type KvmIo = Box<dyn IoStream>;

pub struct KvmEndpoint {
    pub scheme: Scheme,
    pub host: String,
    pub web_port: u16,
    pub video_port: u16,
    pub control_port: u16,
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl KvmEndpoint {
    pub fn new(scheme: Scheme, host: impl Into<String>, ports: (u16, u16, u16), spki_sha256_hex: &str) -> KvmEndpoint {
        KvmEndpoint {
            scheme,
            host: host.into(),
            web_port: ports.0,
            video_port: ports.1,
            control_port: ports.2,
            pin: spki_sha256_hex.to_ascii_lowercase(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }

    #[must_use]
    pub fn from_config(c: &KvmConfig) -> KvmEndpoint {
        KvmEndpoint::new(c.scheme, c.host.clone(), (c.web_port, c.video_port, c.control_port), &c.spki_sha256)
    }

    /// `scheme://host:port/path` for logs (§4.5).
    #[must_use]
    pub fn url_for_log(&self, port: u16, path: &str) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        redact_url(scheme, &self.host, port, path)
    }

    /// TCP (+ pinned TLS) to `port`, bounded by `timeout`.
    pub async fn connect(&self, port: u16, timeout: Duration) -> Result<KvmIo, KvmError> {
        match tokio::time::timeout(timeout, self.connect_inner(port)).await {
            Ok(r) => r,
            Err(_) => Err(KvmError::Timeout("connect")),
        }
    }

    async fn connect_inner(&self, port: u16) -> Result<KvmIo, KvmError> {
        let tcp = TcpStream::connect((self.host.as_str(), port))
            .await
            .map_err(|e| KvmError::Connect(e.kind()))?;
        tcp.set_nodelay(true).map_err(|e| KvmError::Connect(e.kind()))?;
        match self.scheme {
            Scheme::Http => Ok(Box::new(tcp)),
            Scheme::Https => {
                let mismatch = Arc::new(AtomicBool::new(false));
                let verifier = Arc::new(PinVerifier {
                    expected: self.pin.clone(),
                    provider: self.provider.clone(),
                    mismatch: mismatch.clone(),
                });
                let cfg = ClientConfig::builder_with_provider(self.provider.clone())
                    .with_safe_default_protocol_versions()
                    .map_err(|_| KvmError::Tls)?
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();
                let name = ServerName::try_from(self.host.clone()).map_err(|_| KvmError::Tls)?;
                match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
                    Ok(tls) => Ok(Box::new(tls)),
                    Err(_) if mismatch.load(Ordering::SeqCst) => Err(KvmError::CertMismatch),
                    Err(_) => Err(KvmError::Tls),
                }
            }
        }
    }
}

/// Lowercase hex SHA-256 of a certificate's SubjectPublicKeyInfo.
#[must_use]
pub fn spki_sha256_hex(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(Sha256::digest(cert.public_key().raw).iter().map(|b| format!("{b:02x}")).collect())
}

struct PinVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
    mismatch: Arc<AtomicBool>,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinVerifier")
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if spki_sha256_hex(end_entity.as_ref()).as_deref() == Some(self.expected.as_str()) {
            Ok(ServerCertVerified::assertion())
        } else {
            self.mismatch.store(true, Ordering::SeqCst);
            Err(TlsError::General("kvm_cert_mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
```

- [ ] **Step 5: Implement login.** Put above the tests in `kvm/login.rs`:

```rust
//! `POST /cgi-bin/login.lua` (§3.1). One login per session, a re-login only
//! after an auth failure (§5.1), bounded in time and size. No logout exists.
use crate::config::Secret;
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kvm_proto::{LoginError, Token, parse_login_token};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A login response body larger than this is refused unread (§9.2).
pub const MAX_LOGIN_BODY: usize = 64 * 1024;
/// hyper's read buffer for a KVM response head (login and FLV): a hostile
/// header is refused once this much is buffered — hyper's default is
/// ~400 KiB; 8 KiB is its minimum.
pub(crate) const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Aborts a hyper connection task when the request is done or dropped.
pub(crate) struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
struct LoginBody<'a> {
    pass: &'a str,
    timezone: &'a str,
    time: u64,
}

pub async fn login(
    ep: &KvmEndpoint,
    password: &Secret,
    connect_timeout: Duration,
    login_timeout: Duration,
) -> Result<Token, KvmError> {
    match tokio::time::timeout(login_timeout, login_inner(ep, password, connect_timeout)).await {
        Ok(r) => r,
        Err(_) => Err(KvmError::Timeout("login")),
    }
}

async fn login_inner(ep: &KvmEndpoint, password: &Secret, connect_timeout: Duration) -> Result<Token, KvmError> {
    let io = ep.connect(ep.web_port, connect_timeout).await?;
    let mut http = hyper::client::conn::http1::Builder::new();
    http.max_buf_size(MAX_RESPONSE_HEAD);
    let (mut sender, conn) = http
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| KvmError::Protocol("http handshake"))?;
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let time = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // The password reaches only this body; it is never logged (§9.2).
    let body = serde_json::to_vec(&LoginBody { pass: password.expose(), timezone: "UTC", time })
        .map_err(|_| KvmError::Protocol("login body"))?;
    let req = Request::builder()
        .method("POST")
        .uri("/cgi-bin/login.lua")
        .header("Host", &ep.host)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| KvmError::Protocol("request"))?;
    let resp = sender.send_request(req).await.map_err(|_| KvmError::Protocol("response"))?;
    match resp.status().as_u16() {
        200 => {}
        401 | 403 => return Err(KvmError::Auth),
        s => return Err(KvmError::Http(s)),
    }
    let bytes = read_capped(resp.into_body(), MAX_LOGIN_BODY).await?;
    parse_login_token(&bytes).map_err(|e| match e {
        LoginError::ResultNotOk => KvmError::Auth,
        _ => KvmError::Protocol("login body"),
    })
}

/// Read a body, refusing it once it passes `cap` bytes.
pub(crate) async fn read_capped(mut body: Incoming, cap: usize) -> Result<Vec<u8>, KvmError> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| KvmError::Protocol("body"))?;
        if let Some(d) = frame.data_ref() {
            if buf.len().saturating_add(d.len()) > cap {
                return Err(KvmError::Protocol("body too large"));
            }
            buf.extend_from_slice(d);
        }
    }
    Ok(buf)
}
```

- [ ] **Step 6: Run the tests.** `cargo test --workspace --all-features --lib -- kvm::login` — Expected: PASS — 5 passed.

- [ ] **Step 7: Gate** (clippy, test, budget). **Step 8: Commit.**

```bash
git add crates/kvm-rdp/src/kvm crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: KVM endpoint with the SPKI pin, bounded login, no logout (§3.2)" \
  -m "Hostile login responses end within login_timeout; ≤ 16 KiB of head and 64 KiB of body buffered (Review Focus 3)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.3: `kvm::{flv, ws}` — the FLV connection and the control websocket

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/flv.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/ws.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/mod.rs` (`pub mod flv; pub mod ws;`)
- Test: `crates/kvm-rdp/src/kvm/flv.rs`, `crates/kvm-rdp/src/kvm/ws.rs` (`tests`)

**Interfaces:**
- Consumes: Task 3.2's `KvmEndpoint`, `KvmError`, `AbortOnDrop`, `read_capped`.
- Produces:
  - `kvm::flv`: `pub struct FlvConn` — `async fn open(ep: &KvmEndpoint, token: &Token, connect_timeout: Duration) -> Result<FlvConn, KvmError>` (401/403 or a JSON body with `"result":403` → `Auth`; other non-200 → `Http`), `async fn chunk(&mut self) -> Result<Option<Bytes>, KvmError>` (cancel-safe; `Ok(None)` at EOF).
  - `kvm::ws`: `pub const WS_MAX_MESSAGE: usize` (4096); `pub type KvmWs = tokio_tungstenite::WebSocketStream<KvmIo>`; `pub fn ws_config() -> WebSocketConfig`; `pub async fn open_ws(ep: &KvmEndpoint, token: &Token, connect_timeout: Duration) -> Result<KvmWs, KvmError>`.

- [ ] **Step 1: Write the failing tests.** `kvm/flv.rs`:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::{Scheme, Secret};
    use crate::kvm::login::login;
    use kvm_proto::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
    use kvm_sim::{KvmSim, SimConfig, Source};

    const CT: Duration = Duration::from_secs(1);

    async fn sim_and_token() -> (KvmSim, KvmEndpoint, Token) {
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let sim = KvmSim::start(SimConfig::es3(src)).await.unwrap();
        let p = sim.ports();
        let ep = KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), sim.spki_sha256());
        let token = login(&ep, &Secret::new(sim.password()), CT, CT * 2).await.unwrap();
        (sim, ep, token)
    }

    #[tokio::test]
    async fn an_open_flv_starts_with_the_sequence_header() {
        let (_sim, ep, token) = sim_and_token().await;
        let mut flv = FlvConn::open(&ep, &token, CT).await.unwrap();
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        let tag = loop {
            if let Some(t) = demux.next_tag().unwrap() {
                break t;
            }
            demux.push(&flv.chunk().await.unwrap().unwrap());
        };
        assert!(matches!(tag.body, TagBody::Video(VideoBody::SequenceHeader(_))), "{tag:?}");
    }

    #[tokio::test]
    async fn an_expired_token_is_an_auth_failure() {
        let (sim, ep, token) = sim_and_token().await;
        sim.expire_tokens();
        let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
        assert_eq!(e, KvmError::Auth);
    }

    #[tokio::test]
    async fn a_5xx_is_transient() {
        let (sim, ep, token) = sim_and_token().await;
        sim.set_policy(|p| p.flv_status = Some(503));
        let e = FlvConn::open(&ep, &token, CT).await.err().unwrap();
        assert_eq!((e.clone(), e.class()), (KvmError::Http(503), crate::kvm::FailClass::Transient));
    }

    #[test]
    fn a_json_result_403_is_recognised() {
        assert!(result_403(br#"{"result":403}"#));
        assert!(result_403(b"{ \"result\" : 403 }"));
        assert!(!result_403(br#"{"result":0}"#));
    }
}
```

`kvm/ws.rs`:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::{Scheme, Secret};
    use crate::kvm::login::login;
    use futures_util::StreamExt as _;
    use kvm_sim::{KvmSim, SimConfig, Source};

    const CT: Duration = Duration::from_secs(1);

    async fn sim_and_token() -> (KvmSim, KvmEndpoint, Token) {
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let sim = KvmSim::start(SimConfig::es3(src)).await.unwrap();
        let p = sim.ports();
        let ep = KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), sim.spki_sha256());
        let token = login(&ep, &Secret::new(sim.password()), CT, CT * 2).await.unwrap();
        (sim, ep, token)
    }

    #[tokio::test]
    async fn the_websocket_opens_with_the_token_cookie() {
        let (sim, ep, token) = sim_and_token().await;
        let _ws = open_ws(&ep, &token, CT).await.unwrap();
        sim.wait_for(CT, |_| sim.stats().ws_open == 1).await.unwrap();
        sim.expire_tokens();
        assert_eq!(open_ws(&ep, &token, CT).await.err().unwrap(), KvmError::Auth);
    }

    /// §3.2: an oversize message closes the socket without buffering it —
    /// kvm-sim declares 64 MiB and sends 4 KiB of it.
    #[tokio::test]
    async fn an_oversize_message_is_an_error_not_a_buffer() {
        let (sim, ep, token) = sim_and_token().await;
        let mut ws = open_ws(&ep, &token, CT).await.unwrap();
        sim.wait_for(CT, |_| sim.stats().ws_open == 1).await.unwrap();
        sim.send_ws_oversize(64 << 20);
        let next = tokio::time::timeout(CT, ws.next()).await.unwrap();
        assert!(matches!(next, Some(Err(_))), "{next:?}");
    }

    #[test]
    fn the_limits_are_the_spec_limits() {
        let c = ws_config();
        assert_eq!((c.max_message_size, c.max_frame_size), (Some(4096), Some(4096)));
        assert_eq!(c.write_buffer_size, 0);
    }
}
```

and add `pub mod flv;` and `pub mod ws;` to `kvm/mod.rs`.

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- kvm::flv kvm::ws` — Expected: FAIL to compile.

- [ ] **Step 3: Implement the FLV connection.** Above the tests in `kvm/flv.rs`:

```rust
//! `GET /av.flv?token=…` on the video port (§3.1, §3.2): the token as query
//! and cookie, as the web UI sends it. The body is read chunk by chunk;
//! `kvm_proto`'s demuxer checks every limit before buffering.
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use crate::kvm::login::{AbortOnDrop, MAX_RESPONSE_HEAD, read_capped};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kvm_proto::Token;
use std::time::Duration;

/// A refusal's JSON body is read up to this (it holds `{"result":403}`).
const MAX_REFUSAL_BODY: usize = 4096;

pub struct FlvConn {
    body: Incoming,
    _conn: AbortOnDrop,
}

impl FlvConn {
    pub async fn open(ep: &KvmEndpoint, token: &Token, connect_timeout: Duration) -> Result<FlvConn, KvmError> {
        let io = ep.connect(ep.video_port, connect_timeout).await?;
        match tokio::time::timeout(connect_timeout, request(ep, io, token)).await {
            Ok(r) => r,
            Err(_) => Err(KvmError::Timeout("flv response")),
        }
    }

    /// The next body chunk; `Ok(None)` when the KVM closes the stream.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, KvmError> {
        loop {
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(_)) => return Err(KvmError::Closed),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }
}

async fn request(ep: &KvmEndpoint, io: crate::kvm::endpoint::KvmIo, token: &Token) -> Result<FlvConn, KvmError> {
    let mut http = hyper::client::conn::http1::Builder::new();
    http.max_buf_size(MAX_RESPONSE_HEAD);
    let (mut sender, conn) = http
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| KvmError::Protocol("http handshake"))?;
    let conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("/av.flv?token={}", token.as_str()))
        .header("Host", &ep.host)
        .header("Cookie", format!("token={}", token.as_str()))
        .body(Empty::<Bytes>::new())
        .map_err(|_| KvmError::Protocol("request"))?;
    let resp = sender.send_request(req).await.map_err(|_| KvmError::Protocol("response"))?;
    let status = resp.status().as_u16();
    let json = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("json"));
    match status {
        401 | 403 => Err(KvmError::Auth),
        200 if json => {
            let body = read_capped(resp.into_body(), MAX_REFUSAL_BODY).await?;
            if result_403(&body) {
                Err(KvmError::Auth)
            } else {
                Err(KvmError::Protocol("flv answered json"))
            }
        }
        200 => Ok(FlvConn { body: resp.into_body(), _conn: conn }),
        s => Err(KvmError::Http(s)),
    }
}

/// `"result":403` anywhere in a refusal body (§6.9 auth), whitespace-blind.
pub(crate) fn result_403(body: &[u8]) -> bool {
    let compact: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let needle: &[u8] = b"\"result\":403";
    compact.windows(needle.len()).any(|w| w == needle)
}
```

- [ ] **Step 4: Implement the websocket.** Above the tests in `kvm/ws.rs`:

```rust
//! The control websocket (`/websocket` on the control port, §3.1, §3.2):
//! the token cookie, 4 KiB message and frame limits (an oversize message is
//! an error before it is buffered), no write buffering.
use crate::config::Scheme;
use crate::kvm::endpoint::{KvmEndpoint, KvmIo};
use crate::kvm::error::KvmError;
use kvm_proto::Token;
use std::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub const WS_MAX_MESSAGE: usize = 4096;
pub type KvmWs = WebSocketStream<KvmIo>;

#[must_use]
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(WS_MAX_MESSAGE),
        max_frame_size: Some(WS_MAX_MESSAGE),
        write_buffer_size: 0,
        max_write_buffer_size: 64 * 1024,
        ..WebSocketConfig::default()
    }
}

pub async fn open_ws(ep: &KvmEndpoint, token: &Token, connect_timeout: Duration) -> Result<KvmWs, KvmError> {
    let io = ep.connect(ep.control_port, connect_timeout).await?;
    let scheme = match ep.scheme {
        Scheme::Https => "wss",
        Scheme::Http => "ws",
    };
    let mut req = format!("{scheme}://{}:{}/websocket", ep.host, ep.control_port)
        .into_client_request()
        .map_err(|_| KvmError::Protocol("ws request"))?;
    let cookie = HeaderValue::from_str(&format!("token={}", token.as_str()))
        .map_err(|_| KvmError::Protocol("ws cookie"))?;
    req.headers_mut().insert("Cookie", cookie);
    match tokio::time::timeout(
        connect_timeout,
        tokio_tungstenite::client_async_with_config(req, io, Some(ws_config())),
    )
    .await
    {
        Err(_) => Err(KvmError::Timeout("ws upgrade")),
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => match resp.status().as_u16() {
            401 | 403 => Err(KvmError::Auth),
            s => Err(KvmError::Http(s)),
        },
        Ok(Err(_)) => Err(KvmError::Protocol("ws upgrade")),
    }
}
```

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --lib -- kvm::flv kvm::ws` — Expected: PASS — 7 passed.

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-rdp/src/kvm/flv.rs crates/kvm-rdp/src/kvm/ws.rs crates/kvm-rdp/src/kvm/mod.rs
git commit -m "kvm-rdp: the FLV connection and the 4 KiB-limited control websocket (§3.1, §3.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.4: `kvm::upstream` — backoff, the auth gate and the deadline (sans-IO)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/upstream.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/mod.rs` (`pub mod upstream;`)
- Test: `crates/kvm-rdp/src/kvm/upstream.rs` (`tests`)

**Interfaces:**
- Consumes: `config::BackoffConfig`.
- Produces (`kvm::upstream`):
  - `pub struct Jitter` — `Jitter::new(seed: u64) -> Jitter`, `Jitter::from_clock() -> Jitter`, `next_u64(&mut self) -> u64` (splitmix64).
  - `pub struct Backoff` — `Backoff::new(cfg: BackoffConfig, rng: Jitter) -> Backoff`, `next_delay(&mut self) -> Duration`, `reset(&mut self)`.
  - `pub enum AuthStep { Relogin, Wait, Fatal }`; `pub struct AuthGate` (`Default`) — `seq(&self) -> u64` (the current token's sequence number; 0 before any login), `login_ok(&mut self)`, `login_rejected(&mut self) -> AuthStep`, `refused(&mut self, seq: u64) -> AuthStep`.
  - `pub struct Deadline` — `Deadline::new(limit: Duration) -> Deadline`, `started(&mut self, now)`, `logged_in(&mut self)`, `flv_wanted(&mut self, now)`, `tag(&mut self)`, `flv_lost(&mut self, now)`, `expired(&self, now: Instant) -> bool`.

- [ ] **Step 1: Write the failing tests.**

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn cfg(jitter: u32) -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_millis(250),
            factor: 2,
            max: Duration::from_secs(8),
            jitter_percent: jitter,
        }
    }

    /// §4.4: 250 ms ×2 → 8 s.
    #[test]
    fn backoff_doubles_to_its_cap_and_resets() {
        let mut b = Backoff::new(cfg(0), Jitter::new(1));
        let got: Vec<u64> = (0..8).map(|_| u64::try_from(b.next_delay().as_millis()).unwrap()).collect();
        assert_eq!(got, [250, 500, 1000, 2000, 4000, 8000, 8000, 8000]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(250));
    }

    /// ±20 %: every draw in [0.8, 1.2] × the base, and they differ.
    #[test]
    fn backoff_jitter_stays_inside_twenty_percent() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..200 {
            let mut b = Backoff::new(cfg(20), Jitter::new(seed));
            let d = b.next_delay().as_micros();
            assert!((200_000..=300_000).contains(&d), "{d}");
            seen.insert(d);
        }
        assert!(seen.len() > 50, "jitter is not spreading: {}", seen.len());
    }

    /// §6.9: re-login once; a second consecutive failure with no successful
    /// re-login in between is fatal; a success resets the count.
    #[test]
    fn the_auth_gate_allows_one_relogin_per_failure_run() {
        let mut g = AuthGate::default();
        assert_eq!(g.login_rejected(), AuthStep::Relogin, "the first login rejected: retry once");
        assert_eq!(g.login_rejected(), AuthStep::Fatal, "rejected twice running");

        let mut g = AuthGate::default();
        g.login_ok();
        let s1 = g.seq();
        assert_eq!(g.refused(s1), AuthStep::Relogin, "token expiry");
        assert_eq!(g.refused(s1), AuthStep::Wait, "the websocket refused with the same stale token");
        g.login_ok();
        assert_eq!(g.refused(s1), AuthStep::Wait, "an older token's refusal after the re-login");
        assert_eq!(g.refused(g.seq()), AuthStep::Relogin, "expiry again, after a successful re-login");
        assert_eq!(g.login_rejected(), AuthStep::Fatal, "then the re-login is rejected");
    }

    /// §6.9 deadline: login within the limit of Start; a tag within the
    /// limit of the first open, or of losing the FLV.
    #[test]
    fn the_deadline_covers_login_and_tags() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut d = Deadline::new(Duration::from_secs(20));
        d.started(t0);
        assert!(!d.expired(at(19)) && d.expired(at(20)));
        d.logged_in();
        assert!(!d.expired(at(100)));
        d.flv_wanted(at(100));
        assert!(d.expired(at(120)));
        d.tag();
        assert!(!d.expired(at(500)));
        d.flv_lost(at(500));
        d.flv_lost(at(510));
        assert!(d.expired(at(520)), "losing it again does not extend the deadline");
        d.tag();
        assert!(!d.expired(at(600)));
    }
}
```

Add `pub mod upstream;` to `kvm/mod.rs`.

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- kvm::upstream` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! The KVM side's sans-IO cores (§4.3): reconnect backoff with jitter, the
//! auth rule (re-login once, §6.9) and the upstream deadline. Callers pass
//! `now`; nothing here sleeps or reads a clock except `Jitter::from_clock`.
use crate::config::BackoffConfig;
use std::time::{Duration, Instant};

/// splitmix64: enough randomness to keep reconnects from synchronising.
pub struct Jitter(u64);

impl Jitter {
    #[must_use]
    pub fn new(seed: u64) -> Jitter {
        Jitter(seed)
    }
    #[must_use]
    pub fn from_clock() -> Jitter {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        Jitter(u64::from(nanos) ^ u64::from(std::process::id()).rotate_left(32))
    }
    /// The next draw (not `next`: clippy's `should_implement_trait`).
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// `kvm.backoff` (§4.4): one per connection kind; the caller resets it once
/// the connection proves healthy.
pub struct Backoff {
    cfg: BackoffConfig,
    attempt: u32,
    rng: Jitter,
}

impl Backoff {
    #[must_use]
    pub fn new(cfg: BackoffConfig, rng: Jitter) -> Backoff {
        Backoff { cfg, attempt: 0, rng }
    }

    pub fn next_delay(&mut self) -> Duration {
        let base = (0..self.attempt).fold(self.cfg.initial, |d, _| {
            d.saturating_mul(self.cfg.factor).min(self.cfg.max)
        });
        let base = base.min(self.cfg.max);
        self.attempt = self.attempt.saturating_add(1).min(64);
        let base_us = u64::try_from(base.as_micros()).unwrap_or(u64::MAX);
        let span = base_us.saturating_mul(u64::from(self.cfg.jitter_percent)) / 100;
        if span == 0 {
            return base;
        }
        let offset = self.rng.next_u64() % span.saturating_mul(2).saturating_add(1);
        Duration::from_micros(base_us.saturating_sub(span).saturating_add(offset))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStep {
    /// Log in again (once).
    Relogin,
    /// A newer token exists or a re-login is in flight: retry with it.
    Wait,
    /// `kvm_auth_failed`.
    Fatal,
}

/// §6.9 auth: an auth failure re-logs in once; a second consecutive failure
/// with no successful re-login in between is fatal. Tokens are numbered so
/// a refusal of an already-replaced token (the websocket and the FLV both
/// hitting a global logout) counts once.
#[derive(Debug, Default)]
pub struct AuthGate {
    consecutive: u8,
    seq: u64,
    pending: bool,
}

impl AuthGate {
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn login_ok(&mut self) {
        self.consecutive = 0;
        self.seq = self.seq.saturating_add(1);
        self.pending = false;
    }

    pub fn login_rejected(&mut self) -> AuthStep {
        self.pending = true;
        self.bump()
    }

    /// A request made with token `seq` was refused (401/403/`result: 403`).
    pub fn refused(&mut self, seq: u64) -> AuthStep {
        if seq < self.seq || self.pending {
            return AuthStep::Wait;
        }
        self.pending = true;
        self.bump()
    }

    fn bump(&mut self) -> AuthStep {
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive >= 2 {
            AuthStep::Fatal
        } else {
            AuthStep::Relogin
        }
    }
}

/// §6.9 deadline: no successful login within `limit` of Start, or no FLV
/// tag within `limit` of the first open or of losing the FLV.
#[derive(Debug)]
pub struct Deadline {
    limit: Duration,
    login_by: Option<Instant>,
    tag_by: Option<Instant>,
}

impl Deadline {
    #[must_use]
    pub fn new(limit: Duration) -> Deadline {
        Deadline { limit, login_by: None, tag_by: None }
    }
    pub fn started(&mut self, now: Instant) {
        self.login_by = Some(now + self.limit);
    }
    pub fn logged_in(&mut self) {
        self.login_by = None;
    }
    pub fn flv_wanted(&mut self, now: Instant) {
        self.tag_by.get_or_insert(now + self.limit);
    }
    pub fn tag(&mut self) {
        self.tag_by = None;
    }
    pub fn flv_lost(&mut self, now: Instant) {
        self.tag_by.get_or_insert(now + self.limit);
    }
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        self.login_by.is_some_and(|t| now >= t) || self.tag_by.is_some_and(|t| now >= t)
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- kvm::upstream` — Expected: PASS — 4 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/kvm/upstream.rs crates/kvm-rdp/src/kvm/mod.rs
git commit -m "kvm-rdp: upstream cores — jittered backoff, the re-login-once gate, the deadline (§6.9)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.5: `hid::queue` — full-state reports, the release epoch, resync

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/mod.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/queue.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod hid;`)
- Test: `crates/kvm-rdp/src/hid/queue.rs` (`tests`)

**Interfaces:**
- Consumes: `kvm_proto::hid::HidFrame`, `metrics::Metrics`.
- Produces (`kvm_rdp::hid`, re-exported from `hid::queue`):
  - `pub enum ReleaseTrigger { SessionStart, SessionEnd, Closing, Watchdog, Shutdown, WebsocketReconnect, Suppression }` — `label(self) -> &'static str` (Plan D adds Synchronize and the timers).
  - `pub struct Report { pub epoch: u64, pub frame: HidFrame, pub motion_only: bool }`; `pub enum Push { Queued, Coalesced, Resync }`.
  - `pub struct HidQueue` — `new(cap: usize)`, `len`, `is_empty`, `push(&mut self, Report) -> Push`, `pop(&mut self, epoch: u64, discarded: &mut u64) -> Option<HidFrame>`, `release(&mut self)`, `clear(&mut self)`.
  - `pub struct HidControl` — `new(capacity: usize, metrics: Arc<Metrics>)`, `epoch(&self) -> u64`, `push(&self, frame: HidFrame, motion_only: bool) -> Push`, `release_all(&self, ReleaseTrigger)`, `take_release(&self) -> bool`, `next_frame(&self) -> Option<HidFrame>`, `discard_queued(&self)`, `async fn wait(&self)`, `last_position(&self) -> Option<(u16, u16)>`, `note_sent(&self, &HidFrame)`, `release_frames(&self) -> Vec<HidFrame>`, `session_start_frames(&self) -> Vec<HidFrame>`. Plan D's input handler is `push`'s only production caller.

- [ ] **Step 1: Write the failing tests.** `hid/mod.rs`:

```rust
//! The HID path (§7.3): a bounded queue of full-state reports, each stamped
//! with the release epoch, and the websocket task that writes them.
pub mod queue;

pub use queue::{HidControl, HidQueue, Push, ReleaseTrigger, Report};
```

Add `pub mod hid;` to `lib.rs`. `hid/queue.rs`:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use std::time::Duration;

    fn ctl(cap: usize) -> HidControl {
        HidControl::new(cap, Arc::new(Metrics::default()))
    }
    fn kbd(k: u8) -> HidFrame {
        HidFrame::Keyboard { modifiers: 0, keys: [k, 0, 0, 0, 0] }
    }
    fn mouse(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse { buttons, x, y }
    }
    fn drain(c: &HidControl) -> Vec<HidFrame> {
        std::iter::from_fn(|| c.next_frame()).collect()
    }

    #[test]
    fn reports_come_out_in_order_and_only_motion_coalesces() {
        let c = ctl(16);
        c.push(kbd(4), false);
        c.push(mouse(0, 10, 10), true);
        assert_eq!(c.push(mouse(0, 20, 20), true), Push::Coalesced);
        c.push(kbd(5), false);
        c.push(mouse(1, 20, 20), false);
        c.push(mouse(1, 30, 30), true);
        assert_eq!(
            drain(&c),
            [kbd(4), mouse(0, 20, 20), kbd(5), mouse(1, 20, 20), mouse(1, 30, 30)]
        );
        assert_eq!(c.metrics.hid_reports_coalesced.get(), 1);
    }

    /// §7.3: release-all bumps the epoch; nothing queued before it is sent
    /// after it.
    #[test]
    fn a_release_discards_every_older_report() {
        let c = ctl(16);
        c.push(kbd(4), false);
        c.push(kbd(5), false);
        c.release_all(ReleaseTrigger::Closing);
        c.push(kbd(6), false);
        assert!(c.take_release());
        assert!(!c.take_release());
        assert_eq!(drain(&c), [kbd(6)]);
        assert_eq!(c.metrics.hid_epoch_discards.get(), 2);
        assert_eq!(c.metrics.release_all.get("closing"), 1);
    }

    /// The race §7.3 names: a report stamped before a release, queued after
    /// it, is still discarded.
    #[test]
    fn a_report_stamped_before_a_release_is_never_popped_after_it() {
        let mut q = HidQueue::new(8);
        q.push(Report { epoch: 0, frame: kbd(4), motion_only: false });
        let mut discarded = 0;
        assert_eq!(q.pop(1, &mut discarded), None);
        assert_eq!(discarded, 1);
    }

    /// §7.3: a full queue is cleared and resynced to the final state.
    #[test]
    fn a_full_queue_resyncs_to_the_final_state() {
        let c = ctl(4);
        for k in 1..=4 {
            assert_eq!(c.push(kbd(k), false), Push::Queued);
        }
        assert_eq!(c.push(kbd(5), false), Push::Resync);
        c.push(mouse(2, 7, 7), false);
        let out = drain(&c);
        assert_eq!(out, [mouse(2, 7, 7), kbd(5), mouse(2, 7, 7)]);
        assert_eq!(c.metrics.hid_resyncs.get(), 1);
    }

    #[test]
    fn a_release_clears_a_pending_resync() {
        let c = ctl(2);
        c.push(kbd(1), false);
        c.push(kbd(2), false);
        c.push(kbd(3), false);
        c.release_all(ReleaseTrigger::Suppression);
        assert!(c.take_release());
        assert_eq!(drain(&c), []);
    }

    /// §3.3/§7.4: zero reports at the last position sent — none before any
    /// position, never a made-up (0, 0).
    #[test]
    fn release_frames_use_the_last_position_sent() {
        let c = ctl(4);
        let zero = HidFrame::Keyboard { modifiers: 0, keys: [0; 5] };
        assert_eq!(c.release_frames(), [zero]);
        assert_eq!(c.session_start_frames(), [HidFrame::SetMode { hid_type: 0 }, zero]);
        c.note_sent(&mouse(1, 300, 400));
        c.note_sent(&kbd(4));
        assert_eq!(c.last_position(), Some((300, 400)));
        assert_eq!(c.release_frames(), [zero, mouse(0, 300, 400)]);
        assert_eq!(
            c.session_start_frames(),
            [HidFrame::SetMode { hid_type: 0 }, zero, mouse(0, 300, 400)]
        );
        assert_eq!(c.metrics.hid_reports_sent.get(), 2);
    }

    #[tokio::test]
    async fn a_push_wakes_the_writer_even_before_it_waits() {
        let c = Arc::new(ctl(4));
        c.push(kbd(4), false);
        tokio::time::timeout(Duration::from_secs(1), c.wait()).await.unwrap();
        let c2 = c.clone();
        let waiter = tokio::spawn(async move { c2.wait().await });
        tokio::task::yield_now().await;
        c.release_all(ReleaseTrigger::SessionEnd);
        tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- hid::queue` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests in `hid/queue.rs`:

```rust
//! §7.3's queue: the input handler pushes full-state reports stamped with
//! the current release epoch; a motion-only report replaces a motion-only
//! tail; a full queue is cleared and resynced to the final state;
//! release-all bumps the epoch, clears the queue and raises a flag the
//! writer services before anything else (§7.4). O(1) per push.
use crate::metrics::Metrics;
use kvm_proto::hid::HidFrame;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::Notify;

const KBD_ZERO: HidFrame = HidFrame::Keyboard { modifiers: 0, keys: [0; 5] };

/// What triggered a release-all (§7.4); the `release_all{trigger}` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTrigger {
    SessionStart,
    SessionEnd,
    Closing,
    Watchdog,
    Shutdown,
    WebsocketReconnect,
    Suppression,
}

impl ReleaseTrigger {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ReleaseTrigger::SessionStart => "session_start",
            ReleaseTrigger::SessionEnd => "session_end",
            ReleaseTrigger::Closing => "closing",
            ReleaseTrigger::Watchdog => "watchdog",
            ReleaseTrigger::Shutdown => "shutdown",
            ReleaseTrigger::WebsocketReconnect => "websocket_reconnect",
            ReleaseTrigger::Suppression => "suppression",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub epoch: u64,
    pub frame: HidFrame,
    /// Only the pointer moved (no button or key change): coalescable.
    pub motion_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    Queued,
    Coalesced,
    /// The queue was full: cleared, and the final state goes out next.
    Resync,
}

pub struct HidQueue {
    cap: usize,
    items: VecDeque<Report>,
    resync: bool,
    /// A resync's frames, waiting to be popped.
    out: VecDeque<HidFrame>,
    latest_kbd: Option<HidFrame>,
    latest_mouse: Option<HidFrame>,
}

impl HidQueue {
    #[must_use]
    pub fn new(cap: usize) -> HidQueue {
        HidQueue {
            cap: cap.max(1),
            items: VecDeque::with_capacity(cap.clamp(1, 4096)),
            resync: false,
            out: VecDeque::with_capacity(2),
            latest_kbd: None,
            latest_mouse: None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.out.is_empty()
    }

    pub fn push(&mut self, r: Report) -> Push {
        match r.frame {
            HidFrame::Keyboard { .. } => self.latest_kbd = Some(r.frame),
            HidFrame::AbsMouse { .. } => self.latest_mouse = Some(r.frame),
            HidFrame::SetMode { .. } | HidFrame::Wheel { .. } => {}
        }
        if r.motion_only
            && let Some(tail) = self.items.back_mut()
            && tail.motion_only
            && tail.epoch == r.epoch
        {
            *tail = r;
            return Push::Coalesced;
        }
        if self.items.len() >= self.cap {
            self.items.clear();
            self.resync = true;
            return Push::Resync;
        }
        self.items.push_back(r);
        Push::Queued
    }

    /// The next frame to write at `epoch`; reports of older epochs are
    /// dropped and counted in `discarded`.
    pub fn pop(&mut self, epoch: u64, discarded: &mut u64) -> Option<HidFrame> {
        if let Some(f) = self.out.pop_front() {
            return Some(f);
        }
        while let Some(r) = self.items.pop_front() {
            if r.epoch < epoch {
                *discarded = discarded.saturating_add(1);
                continue;
            }
            return Some(r.frame);
        }
        if self.resync {
            self.resync = false;
            self.out.extend(self.latest_kbd);
            self.out.extend(self.latest_mouse);
            return self.out.pop_front();
        }
        None
    }

    /// Release-all: nothing queued survives; the remembered state becomes
    /// "nothing pressed" at the same position.
    pub fn release(&mut self) {
        self.clear();
        if self.latest_kbd.is_some() {
            self.latest_kbd = Some(KBD_ZERO);
        }
        if let Some(HidFrame::AbsMouse { x, y, .. }) = self.latest_mouse {
            self.latest_mouse = Some(HidFrame::AbsMouse { buttons: 0, x, y });
        }
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.out.clear();
        self.resync = false;
    }
}

pub struct HidControl {
    epoch: AtomicU64,
    release_pending: AtomicBool,
    notify: Notify,
    queue: Mutex<HidQueue>,
    last_pos: Mutex<Option<(u16, u16)>>,
    pub(crate) metrics: Arc<Metrics>,
}

impl HidControl {
    #[must_use]
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> HidControl {
        HidControl {
            epoch: AtomicU64::new(0),
            release_pending: AtomicBool::new(false),
            notify: Notify::new(),
            queue: Mutex::new(HidQueue::new(capacity)),
            last_pos: Mutex::new(None),
            metrics,
        }
    }

    fn q(&self) -> MutexGuard<'_, HidQueue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Queue one full-state report at the current epoch (never blocks).
    pub fn push(&self, frame: HidFrame, motion_only: bool) -> Push {
        let epoch = self.epoch();
        let r = self.q().push(Report { epoch, frame, motion_only });
        match r {
            Push::Coalesced => self.metrics.hid_reports_coalesced.inc(),
            Push::Resync => self.metrics.hid_resyncs.inc(),
            Push::Queued => {}
        }
        self.notify.notify_one();
        r
    }

    /// §7.3/§7.4: bump the epoch, drop everything queued, and have the
    /// writer send the zero reports before anything else.
    pub fn release_all(&self, trigger: ReleaseTrigger) {
        {
            let mut q = self.q();
            self.epoch.fetch_add(1, Ordering::SeqCst);
            self.metrics
                .hid_epoch_discards
                .add(u64::try_from(q.len()).unwrap_or(u64::MAX));
            q.release();
        }
        self.release_pending.store(true, Ordering::SeqCst);
        self.metrics.release_all.inc(trigger.label());
        self.notify.notify_one();
    }

    pub fn take_release(&self) -> bool {
        self.release_pending.swap(false, Ordering::SeqCst)
    }

    pub fn next_frame(&self) -> Option<HidFrame> {
        let mut discarded = 0;
        let f = self.q().pop(self.epoch(), &mut discarded);
        if discarded > 0 {
            self.metrics.hid_epoch_discards.add(discarded);
        }
        f
    }

    /// Reports made while the websocket was down are discarded (§7.3).
    pub fn discard_queued(&self) {
        self.q().clear();
    }

    /// Resolves after a push or release (a permit is kept if none waits).
    pub async fn wait(&self) {
        self.notify.notified().await;
    }

    #[must_use]
    pub fn last_position(&self) -> Option<(u16, u16)> {
        *self.last_pos.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The writer wrote `frame`.
    pub fn note_sent(&self, frame: &HidFrame) {
        if let HidFrame::AbsMouse { x, y, .. } = *frame {
            *self.last_pos.lock().unwrap_or_else(PoisonError::into_inner) = Some((x, y));
        }
        self.metrics.hid_reports_sent.inc();
    }

    /// §7.4: an all-zero keyboard report and a zero-button pointer report at
    /// the last position sent — none if no position was ever sent.
    #[must_use]
    pub fn release_frames(&self) -> Vec<HidFrame> {
        let mut v = vec![KBD_ZERO];
        if let Some((x, y)) = self.last_position() {
            v.push(HidFrame::AbsMouse { buttons: 0, x, y });
        }
        v
    }

    /// §3.3: absolute mode, then the release frames.
    #[must_use]
    pub fn session_start_frames(&self) -> Vec<HidFrame> {
        let mut v = vec![HidFrame::SetMode { hid_type: 0 }];
        v.extend(self.release_frames());
        v
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- hid::queue` — Expected: PASS — 7 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/hid crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: HID queue — full-state reports, the release epoch, motion coalescing, resync (§7.3)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.6: `hid::writer` — the control websocket task

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/writer.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/mod.rs` (`pub mod writer;`)
- Test: `crates/kvm-rdp/src/hid/writer.rs` (`tests`)

**Interfaces:**
- Consumes: `HidControl` (3.5), `open_ws` (3.3), `Backoff` (3.4), `KvmEndpoint`, `FailClass`.
- Produces (`kvm_rdp::hid::writer`): `pub enum WsCtl { Flush { done: oneshot::Sender<()> }, Close { done: oneshot::Sender<()> } }`; `pub enum WsEvent { Up, Down, AuthRefused { seq: u64 }, CertMismatch }`; `pub type TokenWatch = watch::Receiver<Option<(u64, Token)>>`; `pub struct WsTask { pub ep, pub token: TokenWatch, pub ctl, pub events, pub hid, pub backoff, pub connect_timeout, pub write_timeout, pub metrics }` with `async fn run(self)` and `async fn drive<S, St>(&mut self, sink: S, stream: St) -> Exit` (`S: Sink<Message, Error = WsError> + Unpin`, `St: Stream<Item = Result<Message, WsError>> + Unpin`); `pub enum Exit { Closed, Failed }`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod writer;` to `hid/mod.rs`; create `hid/writer.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::{BackoffConfig, Scheme, Secret};
    use crate::kvm::login::login;
    use crate::kvm::upstream::Jitter;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    #[derive(Default)]
    struct Gate {
        open: bool,
        sent: Vec<Vec<u8>>,
        waker: Option<Waker>,
    }

    /// A sink a test can block and unblock; records every binary message.
    #[derive(Clone, Default)]
    struct GateSink(Arc<Mutex<Gate>>);

    impl GateSink {
        fn new(open: bool) -> GateSink {
            let s = GateSink::default();
            s.0.lock().unwrap().open = open;
            s
        }
        fn set(&self, open: bool) {
            let mut g = self.0.lock().unwrap();
            g.open = open;
            if let (true, Some(w)) = (open, g.waker.take()) {
                w.wake();
            }
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().sent.clone()
        }
    }

    impl Sink<Message> for GateSink {
        type Error = WsError;
        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            let mut g = self.0.lock().unwrap();
            if g.open {
                Poll::Ready(Ok(()))
            } else {
                g.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
            if let Message::Binary(b) = item {
                self.0.lock().unwrap().sent.push(b);
            }
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
    const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn kbd(k: u8) -> HidFrame {
        HidFrame::Keyboard { modifiers: 0, keys: [k, 0, 0, 0, 0] }
    }

    fn task(hid: Arc<HidControl>, write_timeout: Duration) -> (WsTask, mpsc::UnboundedSender<WsCtl>) {
        let (ctl_tx, ctl) = mpsc::unbounded_channel();
        let (events, _events_rx) = mpsc::unbounded_channel();
        let (_tok_tx, token) = watch::channel(None);
        let backoff = BackoffConfig {
            initial: Duration::from_millis(50),
            factor: 2,
            max: Duration::from_millis(400),
            jitter_percent: 0,
        };
        let t = WsTask {
            ep: Arc::new(KvmEndpoint::new(Scheme::Http, "127.0.0.1", (1, 1, 1), &"0".repeat(64))),
            token,
            ctl,
            events,
            metrics: hid.metrics.clone(),
            hid,
            backoff: Backoff::new(backoff, Jitter::new(1)),
            connect_timeout: Duration::from_secs(1),
            write_timeout,
        };
        (t, ctl_tx)
    }

    async fn wait_sent(sink: &GateSink, n: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while sink.sent().len() < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn close(ctl: &mpsc::UnboundedSender<WsCtl>) {
        let (done, rx) = oneshot::channel();
        ctl.send(WsCtl::Close { done }).unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx).await.unwrap().unwrap();
    }

    /// §3.3: on open the session-start sequence goes first, with no pointer
    /// report before one was ever sent; reports made while down are gone.
    #[tokio::test]
    async fn the_session_start_sequence_comes_first() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        hid.push(kbd(9), false);
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        hid.push(kbd(5), false);
        wait_sent(&sink, 3).await;
        close(&ctl).await;
        assert_eq!(drive.await.unwrap(), Exit::Closed);
        assert_eq!(sink.sent(), [SET_MODE.to_vec(), KBD_ZERO.to_vec(), kbd(5).to_vec()]);
    }

    /// §11.3 Input: with reports queued behind a blocked write, a release
    /// trigger produces only the zero reports and then current state — no
    /// queued report is sent after it.
    #[tokio::test]
    async fn a_release_behind_a_blocked_write_sends_only_zeros_then_new_state() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(5));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        sink.set(false);
        hid.push(kbd(1), false); // taken by the writer, blocked in poll_ready
        tokio::time::sleep(Duration::from_millis(50)).await;
        hid.push(kbd(2), false);
        hid.push(kbd(3), false);
        hid.release_all(ReleaseTrigger::Closing);
        hid.push(kbd(4), false);
        sink.set(true);
        wait_sent(&sink, 5).await;
        close(&ctl).await;
        drive.await.unwrap();
        let sent = sink.sent();
        assert_eq!(sent[2..], [kbd(1).to_vec(), KBD_ZERO.to_vec(), kbd(4).to_vec()]);
    }

    /// §6.9: a write that takes longer than `hid_write_timeout` ends the
    /// websocket (the task reconnects).
    #[tokio::test]
    async fn a_blocked_write_fails_within_the_write_timeout() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_millis(100));
        let t0 = Instant::now();
        // Bounded from outside: a writer that lost its `hid_write_timeout`
        // must fail this test, not hang it.
        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            t.drive(GateSink::new(false), futures_util::stream::pending()),
        )
        .await
        .expect("drive never returned: the write is not bounded by hid_write_timeout");
        assert_eq!(exit, Exit::Failed);
        assert!(t0.elapsed() >= Duration::from_millis(50) && t0.elapsed() < Duration::from_millis(500));
        assert_eq!(hid.metrics.upstream_reconnects.get("websocket_write"), 1);
    }

    /// §3.2: inbound data is read and discarded; a stream error ends it.
    #[tokio::test]
    async fn inbound_data_is_discarded_and_an_error_ends_the_websocket() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid, Duration::from_secs(1));
        let sink = GateSink::new(true);
        let inbound = futures_util::stream::iter(vec![
            Ok(Message::Binary(vec![1, 2, 3])),
            Err(WsError::ConnectionClosed),
        ]);
        assert_eq!(t.drive(sink.clone(), inbound).await, Exit::Failed);
        assert_eq!(sink.sent().len(), 2, "only the session-start sequence went out");
    }

    /// §7.3: `on_disconnected` releases and then closes over the same path —
    /// the zero reports are written before the close.
    #[tokio::test]
    async fn close_writes_a_pending_release_first() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        hid.push(kbd(7), false);
        wait_sent(&sink, 3).await;
        hid.release_all(ReleaseTrigger::SessionEnd);
        close(&ctl).await;
        assert_eq!(drive.await.unwrap(), Exit::Closed);
        assert_eq!(sink.sent().last().unwrap(), &KBD_ZERO.to_vec());
    }

    /// End to end against kvm-sim: a dropped websocket is reopened with the
    /// session-start sequence, counted as a release-all trigger.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_websocket_reopens_with_the_session_start_sequence() {
        use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
        let sim = KvmSim::start(SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap()))
            .await
            .unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), sim.spki_sha256()));
        let token = login(&ep, &Secret::new(sim.password()), Duration::from_secs(1), Duration::from_secs(2))
            .await
            .unwrap();
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let (tok_tx, tok_rx) = watch::channel(Some((1, token)));
        t.token = tok_rx;
        t.ep = ep;
        let run = tokio::spawn(t.run());
        let hid_events = |e: &[SimEvent]| e.iter().filter(|e| matches!(e, SimEvent::Hid { .. })).count();
        sim.wait_for(Duration::from_secs(3), |e| hid_events(e) >= 2).await.unwrap();
        sim.close_websockets();
        let log = sim.wait_for(Duration::from_secs(3), |e| hid_events(e) >= 4).await.unwrap();
        let bytes: Vec<&Vec<u8>> = log
            .iter()
            .filter_map(|e| if let SimEvent::Hid { bytes, .. } = e { Some(bytes) } else { None })
            .collect();
        assert_eq!(bytes, [&SET_MODE.to_vec(), &KBD_ZERO.to_vec(), &SET_MODE.to_vec(), &KBD_ZERO.to_vec()]);
        assert_eq!(hid.metrics.release_all.get("websocket_reconnect"), 1);
        close(&ctl).await;
        run.await.unwrap();
        drop(tok_tx);
        sim.wait_for(Duration::from_secs(2), |_| sim.stats().ws_open == 0).await.unwrap();
        assert_eq!(sim.stats().logouts, 0);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- hid::writer` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! The control websocket's task (§7.3): opens the websocket with the
//! session's token, sends the session-start sequence (§3.3), then writes
//! HID reports — a pending release-all before anything else — each write
//! bounded by `hid_write_timeout` (a blocked write reconnects, §6.9).
//! Inbound data is read and discarded (§3.2); every reconnect is a
//! release-all trigger (§7.4). Auth failures go to the session, which owns
//! the token; this task never logs in.
use crate::hid::{HidControl, ReleaseTrigger};
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::FailClass;
use crate::kvm::upstream::Backoff;
use crate::kvm::ws::open_ws;
use crate::metrics::Metrics;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use kvm_proto::Token;
use kvm_proto::hid::HidFrame;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A close may spend this long writing the release and the close frame.
const CLOSE_BUDGET: Duration = Duration::from_millis(400);

pub enum WsCtl {
    /// Write a pending release-all now, then ack.
    Flush { done: oneshot::Sender<()> },
    /// Write a pending release-all, close the websocket, end the task.
    Close { done: oneshot::Sender<()> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEvent {
    Up,
    Down,
    /// The upgrade was refused for the token with this sequence number.
    AuthRefused { seq: u64 },
    CertMismatch,
}

/// The session's token and its sequence number (`AuthGate::seq`).
pub type TokenWatch = watch::Receiver<Option<(u64, Token)>>;

pub struct WsTask {
    pub ep: Arc<KvmEndpoint>,
    pub token: TokenWatch,
    pub ctl: mpsc::UnboundedReceiver<WsCtl>,
    pub events: mpsc::UnboundedSender<WsEvent>,
    pub hid: Arc<HidControl>,
    pub backoff: Backoff,
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// `WsCtl::Close` (or the session went away): end the task.
    Closed,
    /// The websocket failed: reconnect.
    Failed,
}

impl WsTask {
    pub async fn run(mut self) {
        loop {
            let Some((seq, token)) = self.wait_token(None).await else {
                return;
            };
            let opened = tokio::select! {
                r = open_ws(&self.ep, &token, self.connect_timeout) => r,
                ctl = self.ctl.recv() => {
                    if self.idle_ctl(ctl) {
                        return;
                    }
                    continue;
                }
            };
            match opened {
                Ok(ws) => {
                    let _ = self.events.send(WsEvent::Up);
                    let (sink, stream) = ws.split();
                    if self.drive(sink, stream).await == Exit::Closed {
                        return;
                    }
                    self.hid.release_all(ReleaseTrigger::WebsocketReconnect);
                    self.metrics.upstream_reconnects.inc("websocket");
                    let _ = self.events.send(WsEvent::Down);
                    let d = self.backoff.next_delay();
                    if !self.sleep(d).await {
                        return;
                    }
                }
                Err(e) => match e.class() {
                    FailClass::Auth => {
                        let _ = self.events.send(WsEvent::AuthRefused { seq });
                        if self.wait_token(Some(seq)).await.is_none() {
                            return;
                        }
                    }
                    FailClass::Cert => {
                        let _ = self.events.send(WsEvent::CertMismatch);
                        while !self.idle_ctl(self.ctl.recv().await) {}
                        return;
                    }
                    FailClass::Transient => {
                        self.metrics.upstream_reconnects.inc("websocket_open");
                        let d = self.backoff.next_delay();
                        if !self.sleep(d).await {
                            return;
                        }
                    }
                },
            }
        }
    }

    /// The session's token, newer than `after`; `None` once told to close.
    async fn wait_token(&mut self, after: Option<u64>) -> Option<(u64, Token)> {
        loop {
            let current = self.token.borrow().clone();
            if let Some((seq, token)) = current
                && after.is_none_or(|a| seq > a)
            {
                return Some((seq, token));
            }
            tokio::select! {
                changed = self.token.changed() => if changed.is_err() {
                    return None;
                },
                ctl = self.ctl.recv() => if self.idle_ctl(ctl) {
                    return None;
                },
            }
        }
    }

    /// A control message while no websocket is open: true to end the task.
    fn idle_ctl(&mut self, ctl: Option<WsCtl>) -> bool {
        match ctl {
            Some(WsCtl::Flush { done }) => {
                let _ = done.send(());
                false
            }
            Some(WsCtl::Close { done }) => {
                let _ = done.send(());
                true
            }
            None => true,
        }
    }

    /// Back off for `d`, still answering control messages; false to end.
    async fn sleep(&mut self, d: Duration) -> bool {
        let until = tokio::time::Instant::now() + d;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(until) => return true,
                ctl = self.ctl.recv() => if self.idle_ctl(ctl) {
                    return false;
                },
            }
        }
    }

    /// Serve one open websocket until it fails or is closed.
    pub async fn drive<S, St>(&mut self, mut sink: S, mut stream: St) -> Exit
    where
        S: Sink<Message, Error = WsError> + Unpin,
        St: Stream<Item = Result<Message, WsError>> + Unpin,
    {
        self.hid.discard_queued();
        // The session-start sequence is itself a release (§3.3).
        let _ = self.hid.take_release();
        for f in self.hid.session_start_frames() {
            if !self.write(&mut sink, f).await {
                return Exit::Failed;
            }
        }
        self.backoff.reset();
        loop {
            if self.hid.take_release() {
                for f in self.hid.release_frames() {
                    if !self.write(&mut sink, f).await {
                        return Exit::Failed;
                    }
                }
                continue;
            }
            if let Some(f) = self.hid.next_frame() {
                if !self.write(&mut sink, f).await {
                    return Exit::Failed;
                }
                continue;
            }
            tokio::select! {
                () = self.hid.wait() => {}
                msg = stream.next() => match msg {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return Exit::Failed,
                    Some(Ok(_)) => {}
                },
                ctl = self.ctl.recv() => match ctl {
                    Some(WsCtl::Flush { done }) => {
                        let mut ok = true;
                        if self.hid.take_release() {
                            for f in self.hid.release_frames() {
                                ok = ok && self.write(&mut sink, f).await;
                            }
                        }
                        let _ = done.send(());
                        if !ok {
                            return Exit::Failed;
                        }
                    }
                    Some(WsCtl::Close { done }) => {
                        let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                            if self.hid.take_release() {
                                for f in self.hid.release_frames() {
                                    if !self.write(&mut sink, f).await {
                                        break;
                                    }
                                }
                            }
                            let _ = sink.close().await;
                            // Wait for the KVM's side of the close, so the
                            // next session's websocket never overlaps this one.
                            while let Some(Ok(_)) = stream.next().await {}
                        })
                        .await;
                        let _ = done.send(());
                        return Exit::Closed;
                    }
                    None => return Exit::Closed,
                },
            }
        }
    }

    async fn write<S: Sink<Message, Error = WsError> + Unpin>(&self, sink: &mut S, f: HidFrame) -> bool {
        match tokio::time::timeout(self.write_timeout, sink.send(Message::Binary(f.to_vec()))).await {
            Ok(Ok(())) => {
                self.hid.note_sent(&f);
                true
            }
            _ => {
                self.metrics.upstream_reconnects.inc("websocket_write");
                false
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- hid::writer` — Expected: PASS — 6 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/hid/writer.rs crates/kvm-rdp/src/hid/mod.rs
git commit -m "kvm-rdp: the control websocket task — session-start, release first, bounded writes (§3.3, §7.3)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.7: `kvm::{video, side}` — the main FLV state machine and the side-FLV IDR request

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/video.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/side.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/mod.rs` (`pub mod side; pub mod video;`)
- Test: `crates/kvm-rdp/src/kvm/video.rs` (`tests`, including the side request's)

**Interfaces:**
- Consumes: `FlvConn` (3.3), `Backoff`, `Deadline` (3.4), `msg::{Cause, FlvOrigin, Gen, KvmAu, KvmEvent}` (3.1), `kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, FlvError}`, `kvm_proto::video::{VideoAdmission, AdmissionConfig, AdmissionError, ViolationWindow, ViolationVerdict, ParamClass, AccessUnit}`.
- Produces:
  - `kvm::video`: `pub struct FlvSettings { pub connect_timeout: Duration, pub idle_timeout: Duration, pub deadline: Duration, pub admission: AdmissionConfig }`; `pub enum Ready` (opaque to callers); `pub enum Outcome { Refused { seq: u64 }, Fatal(Cause) }`; `pub struct Video` — `Video::new(generation: Gen, ep: Arc<KvmEndpoint>, to_pump: mpsc::Sender<KvmEvent>, metrics: Arc<Metrics>, settings: FlvSettings, backoff: Backoff) -> Video`, `want(&mut self, now: Instant, token: Option<&(u64, Token)>)` (`OpenFlv`), `reconnect(&mut self, now: Instant, token: Option<&(u64, Token)>)` (`ReconnectFlv`, make-before-break), `token_ready(&mut self, token: &(u64, Token))`, `close(&mut self)`, `async fn ready(&mut self) -> Ready` (cancel-safe), `async fn on_ready(&mut self, r: Ready, now: Instant) -> Option<Outcome>`, `tick(&mut self, now: Instant, token: Option<&(u64, Token)>) -> Option<Outcome>`. It also records §10.4's `frame_bytes`, `inter_arrival` and `kvm_fps` per admitted AU (`pub(crate) struct FpsMeter`, sans-IO).
  - `kvm::side`: `pub async fn request_idr(ep: Arc<KvmEndpoint>, token: Token, connect_timeout: Duration, side_timeout: Duration) -> Result<(), KvmError>` — open, read to the first tag, close; no retry, no re-login (§6.5).

- [ ] **Step 1: Write the failing tests.** Add `pub mod side;` and `pub mod video;` to `kvm/mod.rs`; create `kvm/side.rs` empty but for its doc line (`//! The side FLV (§6.5).`), and `kvm/video.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::{BackoffConfig, Scheme, Secret};
    use crate::kvm::login::login;
    use crate::kvm::side::request_idr;
    use crate::kvm::upstream::Jitter;
    use kvm_proto::video::ParamClass;
    use kvm_sim::{Fault, KvmSim, Pacing, SimConfig, SimEvent, Source};

    const CT: Duration = Duration::from_secs(1);

    struct Rig {
        sim: KvmSim,
        ep: Arc<KvmEndpoint>,
        video: Video,
        rx: mpsc::Receiver<KvmEvent>,
        token: (u64, Token),
        metrics: Arc<Metrics>,
    }

    async fn rig(cap: usize, sim_cfg: impl FnOnce(&mut SimConfig), set: impl FnOnce(&mut FlvSettings)) -> Rig {
        let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
        sim_cfg(&mut cfg);
        let sim = KvmSim::start(cfg).await.unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(Scheme::Https, sim.host(), (p.web, p.video, p.control), sim.spki_sha256()));
        let token = login(&ep, &Secret::new(sim.password()), CT, CT * 2).await.unwrap();
        let (tx, rx) = mpsc::channel(cap);
        let metrics = Arc::new(Metrics::default());
        let mut settings = FlvSettings {
            connect_timeout: CT,
            idle_timeout: Duration::from_secs(2),
            deadline: Duration::from_secs(5),
            admission: AdmissionConfig::default(),
        };
        set(&mut settings);
        let backoff = Backoff::new(
            BackoffConfig { initial: Duration::from_millis(50), factor: 2, max: Duration::from_millis(400), jitter_percent: 0 },
            Jitter::new(1),
        );
        let video = Video::new(1, ep.clone(), tx, metrics.clone(), settings, backoff);
        Rig { sim, ep, video, rx, token: (1, token), metrics }
    }

    impl Rig {
        /// Run the state machine for up to `d`, collecting what reaches the
        /// pump; an outcome ends it early. `read` false leaves the pump's
        /// channel alone (it fills).
        async fn run(&mut self, d: Duration, read: bool) -> (Vec<KvmEvent>, Option<Outcome>) {
            let until = tokio::time::Instant::now() + d;
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            let mut out = Vec::new();
            loop {
                tokio::select! {
                    r = self.video.ready() => {
                        // Bounded from outside: an AU path that waited on the
                        // full channel (the "never waited for" property of
                        // `a_full_channel_drops_aus_and_marks_the_next`) must
                        // fail the test, not hang it — `sleep_until` below
                        // cannot fire while this arm's body is blocked.
                        let step = tokio::time::timeout(Duration::from_secs(5), self.video.on_ready(r, Instant::now())).await;
                        let Ok(step) = step else {
                            panic!("on_ready blocked for 5 s: an AU send waited on the pump's channel (§4.3)");
                        };
                        if let Some(o) = step {
                            while let Ok(ev) = self.rx.try_recv() { out.push(ev); }
                            return (out, Some(o));
                        }
                    }
                    _ = tick.tick() => {
                        if let Some(o) = self.video.tick(Instant::now(), Some(&self.token)) {
                            return (out, Some(o));
                        }
                    }
                    ev = self.rx.recv(), if read => if let Some(ev) = ev { out.push(ev) },
                    () = tokio::time::sleep_until(until) => {
                        if read {
                            while let Ok(ev) = self.rx.try_recv() { out.push(ev); }
                        }
                        return (out, None);
                    }
                }
            }
        }

        /// Run until `done` holds over what reached the pump, or an outcome,
        /// for at most `t`: a positive outcome is waited for, not timed
        /// (§11.1 — a niced, loaded test host must not flake it).
        async fn run_until(&mut self, t: Duration, done: impl Fn(&[KvmEvent]) -> bool) -> (Vec<KvmEvent>, Option<Outcome>) {
            let t0 = Instant::now();
            let mut out = Vec::new();
            while t0.elapsed() < t {
                let (evs, o) = self.run(Duration::from_millis(50), true).await;
                out.extend(evs);
                if o.is_some() || done(&out) {
                    return (out, o);
                }
            }
            (out, None)
        }

        async fn relogin(&mut self) {
            let t = login(&self.ep, &Secret::new(self.sim.password()), CT, CT * 2).await.unwrap();
            self.token = (self.token.0 + 1, t);
            self.video.token_ready(&self.token);
        }
    }

    fn kinds(evs: &[KvmEvent]) -> Vec<String> {
        evs.iter()
            .map(|e| match e {
                KvmEvent::FlvOpened { origin, .. } => format!("open:{}", origin.label()),
                KvmEvent::SpsChanged { class, .. } => format!("sps:{class:?}"),
                KvmEvent::Au { au, .. } => (if au.au.idr { "idr" } else { "p" }).to_owned(),
                KvmEvent::UpstreamFatal { cause, .. } => format!("fatal:{}", cause.label()),
            })
            .collect()
    }

    /// The events after the first `open:transient`, once two more arrived.
    fn reopened(evs: &[KvmEvent]) -> bool {
        let k = kinds(evs);
        k.iter().position(|s| s == "open:transient").is_some_and(|at| k.len() >= at + 3)
    }

    /// Also §10.4: every admitted AU's bytes, the gaps between them, and fps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_open_streams_initial_params_then_an_idr() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        let (evs, out) = r.run_until(Duration::from_secs(5), |e| e.len() > 12).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        assert_eq!(k[..3], ["open:first", "sps:Initial", "idr"], "{k:?}");
        assert!(k.len() > 10, "frames keep coming: {k:?}");
        assert_eq!(r.sim.stats().flv_open, 1);
        let aus = u64::try_from(k.iter().filter(|s| *s == "idr" || *s == "p").count()).unwrap();
        assert!(r.metrics.frame_bytes.count() >= aus, "frame bytes per AU");
        assert!(r.metrics.inter_arrival.count() >= aus - 1, "inter-arrival per AU after the first");
    }

    /// §10.4 fps: 30 fps in, 30 out, once a second.
    #[test]
    fn the_fps_meter_publishes_once_a_second() {
        let t0 = Instant::now();
        let mut m = FpsMeter::default();
        let got: Vec<u32> = (0..64u64).filter_map(|k| m.au(t0 + Duration::from_millis(k * 33))).collect();
        assert_eq!(got, [30, 30]);
    }

    /// §6.9 transient: an FLV drop reconnects with backoff and the new
    /// connection's first SPS is `Initial` again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_flv_reconnects_as_transient() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::Close);
        let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        let at = k.iter().position(|s| s == "open:transient").unwrap();
        assert_eq!(k[at + 1..at + 3], ["sps:Initial", "idr"], "{k:?}");
        assert!(r.metrics.upstream_reconnects.total() >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_b_slice_is_stream_incompatible() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::BSlice);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::StreamIncompatible)));
    }

    /// §6.9 framing: transient, but three within 60 s is `stream_corrupt`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_framing_violations_in_a_minute_are_stream_corrupt() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        for _ in 0..2 {
            r.sim.inject(Fault::BadPrevTagSize);
            let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
            assert_eq!(out, None);
            assert!(kinds(&evs).contains(&"open:transient".to_owned()));
        }
        r.sim.inject(Fault::BadPrevTagSize);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::StreamCorrupt)));
        assert_eq!(r.metrics.parse_errors.get("bad_prev_tag_size"), 3);
    }

    /// §6.9 auth: a refused reopen reports the token it used; with a new
    /// token the stream resumes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_token_is_refused_with_its_sequence_number() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.expire_tokens();
        r.sim.inject(Fault::Close);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Refused { seq: 1 }));
        r.relogin().await;
        let (evs, out) = r.run_until(Duration::from_secs(5), |e| e.len() >= 2).await;
        assert_eq!(out, None);
        assert!(kinds(&evs).starts_with(&["open:transient".to_owned(), "sps:Initial".to_owned()]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_flv_reconnects_after_the_idle_timeout() {
        let idle = Duration::from_millis(400);
        let mut r = rig(64, |_| {}, |s| s.idle_timeout = idle).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::Silence);
        let t0 = Instant::now();
        let mut reopened = None;
        while t0.elapsed() < idle * 5 && reopened.is_none() {
            let (evs, _) = r.run(Duration::from_millis(50), true).await;
            if kinds(&evs).contains(&"open:transient".to_owned()) {
                reopened = Some(t0.elapsed());
            }
        }
        let after = reopened.unwrap();
        assert!(after >= idle / 2, "{after:?}");
        assert_eq!(r.metrics.upstream_reconnects.get("idle"), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_tag_by_the_deadline_is_kvm_unreachable() {
        let deadline = Duration::from_millis(600);
        let mut r = rig(64, |_| {}, |s| s.deadline = deadline).await;
        r.sim.set_policy(|p| p.flv_status = Some(503));
        let t0 = Instant::now();
        r.video.want(t0, Some(&r.token));
        let (_, out) = r.run(deadline * 5, true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::KvmUnreachable)));
        assert!(t0.elapsed() >= deadline / 2, "{:?}", t0.elapsed());
    }

    /// §4.3: AUs that do not fit are dropped, never waited for, and the next
    /// AU that fits carries `after_drop` (DC12).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_channel_drops_aus_and_marks_the_next() {
        let mut r = rig(8, |c| c.pacing = Pacing::Manual, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        // Manual pacing writes only to FLVs already subscribed: let the
        // FLV open (sequence header) before encoding its first frame.
        let (mut evs, _) = r.run(Duration::from_millis(300), true).await;
        r.sim.advance(1);
        evs.extend(r.run(Duration::from_millis(400), true).await.0);
        assert_eq!(kinds(&evs)[..3], ["open:first", "sps:Initial", "idr"]);
        r.sim.advance(20);
        r.run(Duration::from_millis(600), false).await;
        assert!(r.metrics.frames_dropped.get("channel_full") >= 12);
        let mut queued = Vec::new();
        while let Ok(ev) = r.rx.try_recv() {
            queued.push(ev);
        }
        assert_eq!(queued.len(), 8);
        assert!(queued.iter().all(|e| matches!(e, KvmEvent::Au { au, .. } if !au.after_drop)));
        r.sim.advance(1);
        let (evs, _) = r.run(Duration::from_millis(400), true).await;
        assert!(matches!(&evs[0], KvmEvent::Au { au, .. } if au.after_drop), "{:?}", kinds(&evs));
    }

    /// §6.5 `reconnect`: the new FLV opens while the old one keeps flowing,
    /// and the old one closes only once the new one delivered its first tag.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_is_make_before_break() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.video.reconnect(Instant::now(), Some(&r.token));
        let commanded = |e: &[KvmEvent]| {
            let k = kinds(e);
            k.iter().position(|s| s == "open:commanded").is_some_and(|at| k.len() >= at + 3)
        };
        let (evs, out) = r.run_until(Duration::from_secs(5), commanded).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        let at = k.iter().position(|s| s == "open:commanded").unwrap();
        assert_eq!(k[at + 1..at + 3], ["sps:Initial", "idr"], "{k:?}");
        // The old connection's close reaches kvm-sim's log asynchronously.
        let log = r
            .sim
            .wait_for(Duration::from_secs(5), |l| l.iter().any(|e| matches!(e, SimEvent::FlvClose { .. })))
            .await
            .unwrap();
        let opens: Vec<u64> = log.iter().filter_map(|e| if let SimEvent::FlvOpen { conn } = e { Some(*conn) } else { None }).collect();
        assert_eq!(opens.len(), 2);
        let pos = |want: &SimEvent| log.iter().position(|e| e == want).unwrap();
        assert!(pos(&SimEvent::FlvOpen { conn: opens[1] }) < pos(&SimEvent::FlvClose { conn: opens[0] }));
        assert_eq!(r.sim.stats().flv_open, 1);
        assert_eq!(r.metrics.idr_requests.get("reconnect"), 1);
    }

    /// §6.5 `side`: one extra FLV, closed after its first tag; the main FLV
    /// never closes and carries the forced IDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_request_opens_one_flv_and_forces_an_idr_into_the_main_one() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(500), true).await;
        let main = r.sim.events().iter().find_map(|e| if let SimEvent::FlvOpen { conn } = e { Some(*conn) } else { None }).unwrap();
        request_idr(r.ep.clone(), r.token.1.clone(), CT, CT).await.unwrap();
        let (_, out) = r.run(Duration::from_millis(500), true).await;
        assert_eq!(out, None);
        let log = r.sim.events();
        let side = log.iter().filter_map(|e| if let SimEvent::FlvOpen { conn } = e { Some(*conn) } else { None }).nth(1).unwrap();
        let side_open = log.iter().position(|e| *e == SimEvent::FlvOpen { conn: side }).unwrap();
        assert!(log.contains(&SimEvent::FlvClose { conn: side }));
        assert!(!log.contains(&SimEvent::FlvClose { conn: main }));
        assert!(log[side_open..].iter().any(|e| matches!(e, SimEvent::FlvAu { conn, idr: true, .. } if *conn == main)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_side_request_is_an_error_never_a_retry() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
        let e = request_idr(r.ep.clone(), r.token.1.clone(), CT, CT).await.unwrap_err();
        assert_eq!(e, KvmError::Http(503));
        r.run(Duration::from_millis(300), true).await;
        let refused = r.sim.events().iter().filter(|e| matches!(e, SimEvent::FlvRefused { .. })).count();
        assert_eq!(refused, 1);
        assert_eq!(r.sim.stats().logins_ok, 1);
    }

    #[test]
    fn class_labels() {
        assert_eq!(class_label(ParamClass::Initial), "initial");
        assert_eq!(class_label(ParamClass::Resize), "resize");
        assert_eq!(class_label(ParamClass::Other), "other");
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- kvm::video` — Expected: FAIL to compile (`Video` not found).

- [ ] **Step 3: Implement the side request.** Replace `kvm/side.rs` with:

```rust
//! The side FLV (§6.5 `side`): the ES3's one shared encoder forces an IDR
//! into every open stream whenever a new FLV connection opens, so the
//! bridge requests an IDR by opening a short second FLV on the session's
//! token, reading it through the §6.2 demuxer to its first tag, and closing
//! it. Nothing it reads reaches the pump; a failure is counted by the
//! caller, never retried and never answered with a re-login.
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::KvmError;
use crate::kvm::flv::FlvConn;
use kvm_proto::Token;
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use std::sync::Arc;
use std::time::Duration;

pub async fn request_idr(
    ep: Arc<KvmEndpoint>,
    token: Token,
    connect_timeout: Duration,
    side_timeout: Duration,
) -> Result<(), KvmError> {
    let read_to_first_tag = async {
        let mut conn = FlvConn::open(&ep, &token, connect_timeout).await?;
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        loop {
            let Some(bytes) = conn.chunk().await? else {
                return Err(KvmError::Closed);
            };
            demux.push(&bytes);
            match demux.next_tag() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(_) => return Err(KvmError::Protocol("side flv framing")),
            }
        }
    };
    match tokio::time::timeout(side_timeout, read_to_first_tag).await {
        Ok(r) => r,
        Err(_) => Err(KvmError::Timeout("side flv")),
    }
}
```

- [ ] **Step 4: Implement the video state machine.** Above the tests in `kvm/video.rs`:

```rust
//! One session's main FLV (§6.2, §6.9): opened with the session's token,
//! every tag through `kvm_proto`'s demuxer and `VideoAdmission`, parameter
//! changes and AUs to the pump on the ordered stream (AUs by `try_send`,
//! DC12), and §6.9's response to each failure — transient reconnects with
//! backoff, the idle timeout, three framing violations a minute, the tag
//! deadline — plus `ReconnectFlv`'s make-before-break swap (§6.5).
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::{FailClass, KvmError};
use crate::kvm::flv::FlvConn;
use crate::kvm::upstream::{Backoff, Deadline};
use crate::metrics::Metrics;
use crate::msg::{Cause, FlvOrigin, Gen, KvmAu, KvmEvent};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use kvm_proto::Token;
use kvm_proto::flv::{FlvDemuxer, FlvError, FlvLimits, FlvTag};
use kvm_proto::video::{
    AccessUnit, AdmissionConfig, AdmissionError, ParamClass, VideoAdmission, ViolationVerdict,
    ViolationWindow,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, error::TrySendError};

pub struct FlvSettings {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub deadline: Duration,
    pub admission: AdmissionConfig,
}

/// What `ready` produced, for `on_ready`.
pub enum Ready {
    Opened(Result<FlvConn, KvmError>),
    Main(Result<Option<Bytes>, KvmError>),
    Pending(Result<Option<Bytes>, KvmError>),
}

/// What the session must act on.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The FLV was refused for the token with this sequence number.
    Refused { seq: u64 },
    Fatal(Cause),
}

struct Stream {
    conn: FlvConn,
    demux: FlvDemuxer,
    got_tag: bool,
}

struct Opening {
    fut: BoxFuture<'static, Result<FlvConn, KvmError>>,
    origin: FlvOrigin,
    seq: u64,
}

pub struct Video {
    generation: Gen,
    ep: Arc<KvmEndpoint>,
    to_pump: mpsc::Sender<KvmEvent>,
    metrics: Arc<Metrics>,
    settings: FlvSettings,
    admission: VideoAdmission,
    violations: ViolationWindow,
    backoff: Backoff,
    deadline: Deadline,
    wanted: bool,
    waiting_token: bool,
    main: Option<Stream>,
    /// A `ReconnectFlv` candidate, read until its first tag (§6.5).
    pending: Option<Stream>,
    opening: Option<Opening>,
    retry_at: Option<Instant>,
    next_origin: FlvOrigin,
    last_tag: Instant,
    dropped: bool,
    /// The previous AU on this connection (§10.4 inter-arrival).
    last_au: Option<Instant>,
    fps: FpsMeter,
}

/// §10.4 fps: AUs admitted over the last whole second, published once a
/// second. Sans-IO: `au` takes `now`.
#[derive(Debug, Default)]
pub(crate) struct FpsMeter {
    since: Option<Instant>,
    count: u32,
}

impl FpsMeter {
    /// Count one AU; `Some(fps)` when a second (or more) has closed.
    pub(crate) fn au(&mut self, now: Instant) -> Option<u32> {
        let Some(since) = self.since else {
            self.since = Some(now);
            self.count = 1;
            return None;
        };
        let elapsed = now.saturating_duration_since(since);
        if elapsed < Duration::from_secs(1) {
            self.count = self.count.saturating_add(1);
            return None;
        }
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX).max(1);
        let fps = u64::from(self.count).saturating_mul(1000) / ms;
        self.since = Some(now);
        self.count = 1;
        Some(u32::try_from(fps).unwrap_or(u32::MAX))
    }

    pub(crate) fn reset(&mut self) {
        *self = FpsMeter::default();
    }
}

pub(crate) fn class_label(c: ParamClass) -> &'static str {
    match c {
        ParamClass::Initial => "initial",
        ParamClass::Resize => "resize",
        ParamClass::Other => "other",
    }
}

fn drain(demux: &mut FlvDemuxer, bytes: &[u8]) -> (Vec<FlvTag>, Option<FlvError>) {
    demux.push(bytes);
    let mut tags = Vec::new();
    loop {
        match demux.next_tag() {
            Ok(Some(t)) => tags.push(t),
            Ok(None) => return (tags, None),
            Err(e) => return (tags, Some(e)),
        }
    }
}

async fn opening_result(slot: &mut Option<Opening>) -> Result<FlvConn, KvmError> {
    match slot {
        Some(o) => (&mut o.fut).await,
        None => std::future::pending().await,
    }
}

async fn stream_chunk(slot: &mut Option<Stream>) -> Result<Option<Bytes>, KvmError> {
    match slot {
        Some(s) => s.conn.chunk().await,
        None => std::future::pending().await,
    }
}

impl Video {
    pub fn new(
        generation: Gen,
        ep: Arc<KvmEndpoint>,
        to_pump: mpsc::Sender<KvmEvent>,
        metrics: Arc<Metrics>,
        settings: FlvSettings,
        backoff: Backoff,
    ) -> Video {
        Video {
            generation,
            ep,
            to_pump,
            metrics,
            admission: VideoAdmission::new(settings.admission.clone()),
            violations: ViolationWindow::stream_corrupt(),
            deadline: Deadline::new(settings.deadline),
            settings,
            backoff,
            wanted: false,
            waiting_token: false,
            main: None,
            pending: None,
            opening: None,
            retry_at: None,
            next_origin: FlvOrigin::First,
            last_tag: Instant::now(),
            dropped: false,
            last_au: None,
            fps: FpsMeter::default(),
        }
    }

    /// `OpenFlv`: the first Setup wants video (§6.4).
    pub fn want(&mut self, now: Instant, token: Option<&(u64, Token)>) {
        if self.wanted {
            return;
        }
        self.wanted = true;
        self.next_origin = FlvOrigin::First;
        self.deadline.flv_wanted(now);
        match token {
            Some(t) => self.start_open(t, FlvOrigin::First),
            None => self.waiting_token = true,
        }
    }

    /// `ReconnectFlv`: open a second FLV and swap at its first tag (§6.5).
    pub fn reconnect(&mut self, now: Instant, token: Option<&(u64, Token)>) {
        let Some(t) = token else { return };
        if !self.wanted {
            self.want(now, Some(t));
            return;
        }
        if self.opening.is_some() || self.pending.is_some() {
            return;
        }
        self.metrics.idr_requests.inc("reconnect");
        self.start_open(t, FlvOrigin::Commanded);
    }

    /// A (new) token is available: open if we were waiting for one.
    pub fn token_ready(&mut self, token: &(u64, Token)) {
        if self.wanted && self.waiting_token && self.opening.is_none() && self.main.is_none() {
            self.start_open(token, self.next_origin);
        }
    }

    /// Drop every connection; nothing reopens.
    pub fn close(&mut self) {
        self.stopped_streaming();
        self.main = None;
        self.pending = None;
        self.opening = None;
        self.wanted = false;
        self.retry_at = None;
        self.waiting_token = false;
    }

    fn start_open(&mut self, token: &(u64, Token), origin: FlvOrigin) {
        self.retry_at = None;
        self.waiting_token = false;
        let (ep, tok, ct) = (self.ep.clone(), token.1.clone(), self.settings.connect_timeout);
        self.opening = Some(Opening {
            fut: Box::pin(async move { FlvConn::open(&ep, &tok, ct).await }),
            origin,
            seq: token.0,
        });
    }

    /// The next thing to act on. Cancel-safe.
    pub async fn ready(&mut self) -> Ready {
        tokio::select! {
            r = opening_result(&mut self.opening) => Ready::Opened(r),
            c = stream_chunk(&mut self.pending) => Ready::Pending(c),
            c = stream_chunk(&mut self.main) => Ready::Main(c),
        }
    }

    pub async fn on_ready(&mut self, r: Ready, now: Instant) -> Option<Outcome> {
        match r {
            Ready::Opened(res) => {
                let o = self.opening.take()?;
                match res {
                    Ok(conn) => self.opened(conn, o.origin, now).await,
                    Err(e) => self.open_failed(e, o.origin, o.seq, now),
                }
            }
            Ready::Main(c) => self.main_chunk(c, now).await,
            Ready::Pending(c) => self.pending_chunk(c, now).await,
        }
    }

    /// Idle timeout, deadline and scheduled reconnects (§6.9).
    pub fn tick(&mut self, now: Instant, token: Option<&(u64, Token)>) -> Option<Outcome> {
        if !self.wanted {
            return None;
        }
        if self.deadline.expired(now) {
            self.close();
            return Some(Outcome::Fatal(Cause::KvmUnreachable));
        }
        if self.main.is_some() && now.saturating_duration_since(self.last_tag) >= self.settings.idle_timeout {
            self.lost("idle", now);
        }
        if self.main.is_none()
            && self.opening.is_none()
            && !self.waiting_token
            && self.retry_at.is_some_and(|t| now >= t)
        {
            match token {
                Some(t) => self.start_open(t, self.next_origin),
                None => self.waiting_token = true,
            }
        }
        None
    }

    async fn opened(&mut self, conn: FlvConn, origin: FlvOrigin, now: Instant) -> Option<Outcome> {
        let stream = Stream { conn, demux: FlvDemuxer::new(FlvLimits::default()), got_tag: false };
        if origin == FlvOrigin::Commanded && self.main.is_some() {
            self.pending = Some(stream);
            return None;
        }
        self.main = Some(stream);
        self.became_main(origin, now).await;
        None
    }

    async fn became_main(&mut self, origin: FlvOrigin, now: Instant) {
        self.last_tag = now;
        self.last_au = None; // inter-arrival is per FLV connection
        self.admission.flv_opened();
        self.send(KvmEvent::FlvOpened { generation: self.generation, origin }).await;
    }

    fn open_failed(&mut self, e: KvmError, origin: FlvOrigin, seq: u64, now: Instant) -> Option<Outcome> {
        if origin == FlvOrigin::Commanded && self.main.is_some() {
            // The old FLV still flows; the IDR core asks again later.
            self.metrics.upstream_reconnects.inc("commanded_failed");
            return None;
        }
        match e.class() {
            FailClass::Auth => {
                self.waiting_token = true;
                Some(Outcome::Refused { seq })
            }
            FailClass::Cert => {
                self.close();
                Some(Outcome::Fatal(Cause::KvmCertMismatch))
            }
            FailClass::Transient => {
                self.metrics.upstream_reconnects.inc(e.kind());
                self.retry_at = Some(now + self.backoff.next_delay());
                None
            }
        }
    }

    async fn main_chunk(&mut self, c: Result<Option<Bytes>, KvmError>, now: Instant) -> Option<Outcome> {
        let bytes = match c {
            Ok(Some(b)) => b,
            Ok(None) => {
                self.lost("eof", now);
                return None;
            }
            Err(e) => {
                self.lost(e.kind(), now);
                return None;
            }
        };
        self.metrics.flv_bytes.add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let s = self.main.as_mut()?;
        let (tags, err) = drain(&mut s.demux, &bytes);
        self.admit_all(tags, err, now).await
    }

    async fn pending_chunk(&mut self, c: Result<Option<Bytes>, KvmError>, now: Instant) -> Option<Outcome> {
        let Ok(Some(bytes)) = c else {
            self.pending = None;
            self.metrics.upstream_reconnects.inc("commanded_failed");
            return None;
        };
        let p = self.pending.as_mut()?;
        let (tags, err) = drain(&mut p.demux, &bytes);
        if tags.is_empty() && err.is_none() {
            return None;
        }
        // Its first tag: the old FLV closes now (make-before-break, §6.5).
        self.main = self.pending.take();
        self.became_main(FlvOrigin::Commanded, now).await;
        self.admit_all(tags, err, now).await
    }

    async fn admit_all(&mut self, tags: Vec<FlvTag>, err: Option<FlvError>, now: Instant) -> Option<Outcome> {
        for tag in tags {
            if self.main.is_none() {
                return None;
            }
            if let Some(o) = self.admit(tag, now).await {
                return Some(o);
            }
        }
        match err {
            Some(e) if self.main.is_some() => self.refusal(AdmissionError::from(e), now),
            _ => None,
        }
    }

    async fn admit(&mut self, tag: FlvTag, now: Instant) -> Option<Outcome> {
        self.metrics.flv_tags.inc();
        self.last_tag = now;
        self.deadline.tag();
        if let Some(s) = self.main.as_mut()
            && !s.got_tag
        {
            s.got_tag = true;
            self.backoff.reset();
        }
        match self.admission.admit(tag, now) {
            Ok(a) => {
                if let Some(p) = a.params {
                    let r = p.rewrites;
                    for (on, field) in [(r.level, "level"), (r.vui, "vui"), (r.restriction, "restriction")] {
                        if on {
                            self.metrics.sps_rewrites.inc(field);
                        }
                    }
                    self.metrics.sps_changes.inc(class_label(p.class));
                    self.send(KvmEvent::SpsChanged { generation: self.generation, class: p.class, params: p.params }).await;
                }
                if let Some(au) = a.au {
                    self.forward(au, now);
                }
                if a.end_of_sequence {
                    self.lost("end_of_sequence", now);
                }
                None
            }
            Err(e) => self.refusal(e, now),
        }
    }

    fn refusal(&mut self, e: AdmissionError, now: Instant) -> Option<Outcome> {
        match e {
            AdmissionError::Incompatible(_) => {
                tracing::warn!(kind = e.kind(), "kvm stream is incompatible");
                self.close();
                Some(Outcome::Fatal(Cause::StreamIncompatible))
            }
            AdmissionError::Framing(_) => {
                self.metrics.parse_errors.inc(e.kind());
                match self.violations.record(now) {
                    ViolationVerdict::Fatal => {
                        self.close();
                        Some(Outcome::Fatal(Cause::StreamCorrupt))
                    }
                    ViolationVerdict::Transient => {
                        self.lost("framing", now);
                        None
                    }
                }
            }
        }
    }

    fn lost(&mut self, reason: &'static str, now: Instant) {
        self.stopped_streaming();
        self.main = None;
        self.metrics.upstream_reconnects.inc(reason);
        self.next_origin = FlvOrigin::Transient;
        self.deadline.flv_lost(now);
        self.retry_at = Some(now + self.backoff.next_delay());
    }

    /// No main FLV: no inter-arrival across the gap, and fps reads 0.
    fn stopped_streaming(&mut self) {
        self.last_au = None;
        self.fps.reset();
        self.metrics.kvm_fps.set(0);
    }

    fn forward(&mut self, au: AccessUnit, now: Instant) {
        self.metrics.frames.inc(if au.idr { "idr" } else { "p" });
        if au.burst {
            self.metrics.bursts.inc();
        }
        // §10.4: frame bytes, inter-arrival on this connection, fps.
        let bytes = au.vcl.iter().fold(0u64, |a, n| a.saturating_add(u64::try_from(n.bytes.len()).unwrap_or(u64::MAX)));
        self.metrics.frame_bytes.observe_bytes(bytes);
        if let Some(prev) = self.last_au.replace(now) {
            self.metrics.inter_arrival.observe(now.saturating_duration_since(prev));
        }
        if let Some(fps) = self.fps.au(now) {
            self.metrics.kvm_fps.set(i64::from(fps));
        }
        let ev = KvmEvent::Au { generation: self.generation, au: KvmAu { au, after_drop: self.dropped, received: now } };
        match self.to_pump.try_send(ev) {
            Ok(()) => self.dropped = false,
            Err(TrySendError::Full(_)) => {
                self.dropped = true;
                self.metrics.frames_dropped.inc("channel_full");
            }
            Err(TrySendError::Closed(_)) => {}
        }
    }

    /// Control messages are never dropped (§4.3): the FLV pauses instead.
    /// `&mut self`, not `&self`: `Video` holds a `BoxFuture` (`Send` but not
    /// `Sync`), and a `&Video` held across this await would make the
    /// session's future `!Send` — `tokio::spawn(run_actor(..))` refuses it.
    async fn send(&mut self, ev: KvmEvent) {
        let _ = self.to_pump.send(ev).await;
    }
}
```

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --lib -- kvm::video` — Expected: PASS — 13 passed.

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-rdp/src/kvm/video.rs crates/kvm-rdp/src/kvm/side.rs crates/kvm-rdp/src/kvm/mod.rs
git commit -m "kvm-rdp: the main FLV state machine and the side-FLV IDR request (§6.2, §6.5, §6.9)" \
  -m "Transient reconnects, idle timeout, 3-in-60s stream_corrupt, tag deadline, make-before-break ReconnectFlv; full channel drops AUs and marks the next (DC12)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.8: `kvm::session` — the KVM actor

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/session.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/kvm/mod.rs` (`pub mod session;`)
- Test: `crates/kvm-rdp/src/kvm/session.rs` (`tests`)

**Interfaces:**
- Consumes: everything in Part 3 so far; `config::Config`.
- Produces (`kvm::session`): `pub struct SessionConfig { pub password: Secret, pub connect_timeout: Duration, pub login_timeout: Duration, pub backoff: BackoffConfig, pub upstream_deadline: Duration, pub flv_idle_timeout: Duration, pub idr_side_timeout: Duration, pub hid_write_timeout: Duration, pub admission: AdmissionConfig }` with `SessionConfig::from_config(&Config) -> SessionConfig`; `pub struct KvmDeps { pub ep: Arc<KvmEndpoint>, pub cfg: Arc<SessionConfig>, pub to_pump: mpsc::Sender<KvmEvent>, pub hid: Arc<HidControl>, pub metrics: Arc<Metrics> }`; `pub async fn run_actor(rx: mpsc::UnboundedReceiver<KvmCommand>, deps: KvmDeps)`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod session;` to `kvm/mod.rs`; create `kvm/session.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::Scheme;
    use crate::msg::FlvOrigin;
    use kvm_proto::hid::HidFrame;
    use kvm_sim::{Fault, KvmSim, SimConfig, SimEvent, Source};

    const T: Duration = Duration::from_secs(3);
    const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
    const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    struct Rig {
        sim: KvmSim,
        tx: mpsc::UnboundedSender<KvmCommand>,
        rx: mpsc::Receiver<KvmEvent>,
        hid: Arc<HidControl>,
        metrics: Arc<Metrics>,
        actor: tokio::task::JoinHandle<()>,
    }

    async fn rig(pin: Option<&str>, set: impl FnOnce(&mut SessionConfig)) -> Rig {
        let sim = KvmSim::start(SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap()))
            .await
            .unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            pin.unwrap_or(sim.spki_sha256()),
        ));
        let mut cfg = SessionConfig {
            password: Secret::new(sim.password()),
            connect_timeout: Duration::from_secs(1),
            login_timeout: Duration::from_secs(2),
            backoff: BackoffConfig {
                initial: Duration::from_millis(50),
                factor: 2,
                max: Duration::from_millis(400),
                jitter_percent: 0,
            },
            upstream_deadline: Duration::from_secs(4),
            flv_idle_timeout: Duration::from_secs(2),
            idr_side_timeout: Duration::from_secs(1),
            hid_write_timeout: Duration::from_secs(1),
            admission: AdmissionConfig::default(),
        };
        set(&mut cfg);
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(256, metrics.clone()));
        let (tx, crx) = mpsc::unbounded_channel();
        let (ptx, rx) = mpsc::channel(68);
        let deps = KvmDeps { ep, cfg: Arc::new(cfg), to_pump: ptx, hid: hid.clone(), metrics: metrics.clone() };
        let actor = tokio::spawn(run_actor(crx, deps));
        Rig { sim, tx, rx, hid, metrics, actor }
    }

    impl Rig {
        async fn stop(&self, generation: Gen) {
            let (done, r) = oneshot::channel();
            self.tx.send(KvmCommand::Stop { generation, done: Some(done) }).unwrap();
            tokio::time::timeout(T, r).await.unwrap().unwrap();
        }
        /// The next event matching `pred`, skipping AUs and the rest.
        async fn wait(&mut self, pred: impl Fn(&KvmEvent) -> bool) -> KvmEvent {
            tokio::time::timeout(T, async {
                loop {
                    let ev = self.rx.recv().await.unwrap();
                    if pred(&ev) {
                        return ev;
                    }
                }
            })
            .await
            .unwrap()
        }
        async fn fatal(&mut self) -> Cause {
            match self.wait(|e| matches!(e, KvmEvent::UpstreamFatal { .. })).await {
                KvmEvent::UpstreamFatal { cause, .. } => cause,
                _ => unreachable!(),
            }
        }
        fn hid_bytes(&self) -> Vec<Vec<u8>> {
            self.sim
                .events()
                .into_iter()
                .filter_map(|e| if let SimEvent::Hid { bytes, .. } = e { Some(bytes) } else { None })
                .collect()
        }
    }

    fn opened(e: &KvmEvent, want: FlvOrigin) -> bool {
        matches!(e, KvmEvent::FlvOpened { origin, .. } if *origin == want)
    }

    /// §5.1: Start logs in once and opens the websocket with the
    /// session-start sequence; no FLV until `OpenFlv` (the first Setup).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_logs_in_once_and_sends_the_session_start_sequence() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.sim.wait_for(T, |e| e.iter().filter(|e| matches!(e, SimEvent::Hid { .. })).count() >= 2).await.unwrap();
        // Exactly these two: no pointer report was ever sent, so none is
        // parked at (0, 0) (§3.3, rev 5.1).
        assert_eq!(r.hid_bytes(), [SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
        let s = r.sim.stats();
        assert_eq!((s.logins_ok, s.ws_open, s.flv_open), (1, 1, 0));
        r.stop(1).await;
    }

    /// §7.3/§3.2: Stop flushes the release before the websocket closes, and
    /// never logs out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_flushes_the_release_and_never_logs_out() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 1).await.unwrap();
        r.hid.push(HidFrame::Keyboard { modifiers: 0x08, keys: [4, 0, 0, 0, 0] }, false);
        r.sim.wait_for(T, |e| e.iter().filter(|e| matches!(e, SimEvent::Hid { .. })).count() >= 3).await.unwrap();
        r.hid.release_all(crate::hid::ReleaseTrigger::SessionEnd);
        r.stop(1).await;
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 0).await.unwrap();
        assert_eq!(r.hid_bytes().last().unwrap(), &KBD_ZERO.to_vec());
        assert_eq!(r.sim.stats().logouts, 0);
    }

    /// Review Focus 1: Start/Stop storms — including a Stop while the login
    /// is still in flight — leave nothing open, never two websockets, no
    /// logout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_stop_storm_leaves_nothing_open() {
        // A login that would hang for 30 s: a Stop that waited for it
        // could not meet the bound below.
        let r = rig(None, |c| {
            c.connect_timeout = Duration::from_secs(30);
            c.login_timeout = Duration::from_secs(30);
        })
        .await;
        r.sim.set_policy(|p| p.blackhole = true);
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = std::time::Instant::now();
        r.stop(1).await;
        assert!(t0.elapsed() < CLOSE_WAIT * 5, "Stop waited for the hung login: {:?}", t0.elapsed());
        r.sim.set_policy(|p| p.blackhole = false);
        for generation in 2..12 {
            r.tx.send(KvmCommand::Start { generation }).unwrap();
            r.tx.send(KvmCommand::OpenFlv { generation }).unwrap();
            if generation % 2 == 0 {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            r.stop(generation).await;
        }
        r.tx.send(KvmCommand::Start { generation: 20 }).unwrap();
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 1).await.unwrap();
        r.stop(20).await;
        r.sim
            .wait_for(T, |_| {
                let s = r.sim.stats();
                s.ws_open == 0 && s.flv_open == 0
            })
            .await
            .unwrap();
        let s = r.sim.stats();
        assert_eq!(s.ws_max_open, 1, "two websockets at once");
        assert_eq!(s.logouts, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_login_rejected_twice_is_kvm_auth_failed() {
        let mut r = rig(None, |_| {}).await;
        r.sim.set_policy(|p| p.reject_logins = true);
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        assert_eq!(r.sim.stats().logins_failed, 2);
        r.stop(1).await;
    }

    /// §6.9: a pin mismatch is fatal at once, no login request is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrong_pin_is_kvm_cert_mismatch_with_no_login() {
        let pin = "1".repeat(64);
        let mut r = rig(Some(&pin), |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmCertMismatch);
        let s = r.sim.stats();
        assert_eq!((s.logins_ok, s.logins_failed), (0, 0));
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_login_by_the_deadline_is_kvm_unreachable() {
        let deadline = Duration::from_millis(800);
        let mut r = rig(None, |c| c.upstream_deadline = deadline).await;
        r.sim.set_policy(|p| p.blackhole = true);
        let t0 = std::time::Instant::now();
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        assert_eq!(r.fatal().await, Cause::KvmUnreachable);
        assert!(t0.elapsed() >= deadline / 2 && t0.elapsed() < deadline * 5, "{:?}", t0.elapsed());
        r.stop(1).await;
    }

    /// §6.9 auth, §11.3 "token expiry": the FLV and the websocket both hit
    /// the dead token, the bridge re-logs in exactly once, and the stream
    /// continues with no disconnect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_token_relogs_in_exactly_once_and_the_stream_continues() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 1).await.unwrap();
        r.sim.expire_tokens();
        r.sim.close_websockets();
        r.sim.inject(Fault::Close);
        r.wait(|e| opened(e, FlvOrigin::Transient)).await;
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 1).await.unwrap();
        assert_eq!(r.sim.stats().logins_ok, 2);
        assert_eq!(r.metrics.relogins.get(), 1);
        while let Ok(ev) = r.rx.try_recv() {
            assert!(!matches!(ev, KvmEvent::UpstreamFatal { .. }), "{ev:?}");
        }
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_consecutive_auth_failure_is_fatal() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.sim.expire_tokens();
        r.sim.set_policy(|p| p.reject_logins = true);
        r.sim.inject(Fault::Close);
        assert_eq!(r.fatal().await, Cause::KvmAuthFailed);
        r.stop(1).await;
    }

    /// §6.5: `RequestIdr` → one side FLV; a refused one is counted and
    /// neither retried nor answered with a re-login.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn request_idr_runs_one_side_flv_and_counts_a_refusal() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        r.sim
            .wait_for(T, |e| e.iter().filter(|e| matches!(e, SimEvent::FlvClose { .. })).count() == 1)
            .await
            .unwrap();
        assert_eq!(r.metrics.idr_requests.get("side"), 1);
        let count = |r: &Rig, f: fn(&SimEvent) -> bool| r.sim.events().iter().filter(|e| f(e)).count();
        let opens_before = count(&r, |e| matches!(e, SimEvent::FlvOpen { .. }));
        r.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
        r.tx.send(KvmCommand::RequestIdr { generation: 1 }).unwrap();
        tokio::time::timeout(T, async {
            while r.metrics.idr_side_failures.get("http") == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        // `refuse_concurrent_flv` is spent: a retry would now open a side
        // FLV. Wait past `idr_side_timeout` (1 s) and look for one.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(count(&r, |e| matches!(e, SimEvent::FlvRefused { .. })), 1, "one refusal");
        assert_eq!(
            count(&r, |e| matches!(e, SimEvent::FlvOpen { .. })),
            opens_before,
            "a refused side FLV was retried"
        );
        assert_eq!(r.sim.stats().logins_ok, 1, "a refusal is never answered with a re-login");
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_flv_is_make_before_break() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        r.tx.send(KvmCommand::ReconnectFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::Commanded)).await;
        r.sim.wait_for(T, |_| r.sim.stats().flv_open == 1).await.unwrap();
        r.stop(1).await;
    }

    /// §5.2: FlushHid writes a pending release while the websocket stays up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_hid_acks_after_the_release_is_written() {
        let r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.sim.wait_for(T, |_| r.sim.stats().ws_open == 1).await.unwrap();
        r.hid.push(HidFrame::Keyboard { modifiers: 0, keys: [5, 0, 0, 0, 0] }, false);
        r.sim.wait_for(T, |e| e.iter().filter(|e| matches!(e, SimEvent::Hid { .. })).count() >= 3).await.unwrap();
        r.hid.release_all(crate::hid::ReleaseTrigger::Shutdown);
        let (done, rx) = oneshot::channel();
        r.tx.send(KvmCommand::FlushHid { done }).unwrap();
        tokio::time::timeout(T, rx).await.unwrap().unwrap();
        r.sim.wait_for(T, |e| e.iter().filter(|e| matches!(e, SimEvent::Hid { .. })).count() >= 4).await.unwrap();
        assert_eq!(r.hid_bytes().last().unwrap(), &KBD_ZERO.to_vec());
        assert_eq!(r.sim.stats().ws_open, 1);
        r.stop(1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_closes_everything_and_ends_the_actor() {
        let mut r = rig(None, |_| {}).await;
        r.tx.send(KvmCommand::Start { generation: 1 }).unwrap();
        r.tx.send(KvmCommand::OpenFlv { generation: 1 }).unwrap();
        r.wait(|e| opened(e, FlvOrigin::First)).await;
        let (done, rx) = oneshot::channel();
        r.tx.send(KvmCommand::Shutdown { done }).unwrap();
        tokio::time::timeout(T, rx).await.unwrap().unwrap();
        tokio::time::timeout(T, r.actor).await.unwrap().unwrap();
        r.sim
            .wait_for(T, |_| {
                let s = r.sim.stats();
                s.ws_open == 0 && s.flv_open == 0
            })
            .await
            .unwrap();
        assert_eq!(r.sim.stats().logouts, 0);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- kvm::session` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests in `kvm/session.rs`:

```rust
//! The KVM actor (§4.3): one task for the process, one `Session` per
//! generation, commands processed strictly in order. `Start{generation}` logs in
//! and opens the websocket (§5.1, the session-start sequence); `OpenFlv`
//! (the first Setup) opens the FLV; `Stop{generation}` completes — release flushed,
//! websocket, FLV and side FLV closed, **never a logout** (§3.2) — before
//! the next command is read. The token lives from Start to Stop and is
//! reused for every reopen; re-login happens only after an auth failure.
use crate::config::{BackoffConfig, Config, Secret};
use crate::hid::HidControl;
use crate::hid::writer::{WsCtl, WsEvent, WsTask};
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::{FailClass, KvmError};
use crate::kvm::login::login;
use crate::kvm::side;
use crate::kvm::upstream::{AuthGate, AuthStep, Backoff, Deadline, Jitter};
use crate::kvm::video::{FlvSettings, Outcome, Video};
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, KvmCommand, KvmEvent};
use futures_util::future::BoxFuture;
use kvm_proto::Token;
use kvm_proto::video::AdmissionConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// Housekeeping cadence: retries, the idle timeout, the deadline.
const TICK: Duration = Duration::from_millis(100);
/// A Stop waits this long for the websocket to flush and close (§5.2).
const CLOSE_WAIT: Duration = Duration::from_millis(500);

pub struct SessionConfig {
    pub password: Secret,
    pub connect_timeout: Duration,
    pub login_timeout: Duration,
    pub backoff: BackoffConfig,
    pub upstream_deadline: Duration,
    pub flv_idle_timeout: Duration,
    pub idr_side_timeout: Duration,
    pub hid_write_timeout: Duration,
    pub admission: AdmissionConfig,
}

impl SessionConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> SessionConfig {
        SessionConfig {
            password: c.kvm.password.clone(),
            connect_timeout: c.kvm.connect_timeout,
            login_timeout: c.kvm.login_timeout,
            backoff: c.kvm.backoff,
            upstream_deadline: c.kvm.upstream_deadline,
            flv_idle_timeout: c.video.flv_idle_timeout,
            idr_side_timeout: c.video.idr_side_timeout,
            hid_write_timeout: c.input.hid_write_timeout,
            admission: c.video.admission(),
        }
    }
}

pub struct KvmDeps {
    pub ep: Arc<KvmEndpoint>,
    pub cfg: Arc<SessionConfig>,
    pub to_pump: mpsc::Sender<KvmEvent>,
    pub hid: Arc<HidControl>,
    pub metrics: Arc<Metrics>,
}

fn ack(done: Option<oneshot::Sender<()>>) {
    if let Some(d) = done {
        let _ = d.send(());
    }
}

pub async fn run_actor(mut rx: mpsc::UnboundedReceiver<KvmCommand>, deps: KvmDeps) {
    let mut next: Option<KvmCommand> = None;
    loop {
        let cmd = match next.take() {
            Some(c) => c,
            None => match rx.recv().await {
                Some(c) => c,
                None => return,
            },
        };
        match cmd {
            KvmCommand::Start { generation } => next = Session::new(generation, &deps).run(&mut rx).await,
            KvmCommand::Stop { done, .. } => ack(done),
            KvmCommand::FlushHid { done } => {
                let _ = done.send(());
            }
            KvmCommand::Shutdown { done } => {
                let _ = done.send(());
                return;
            }
            KvmCommand::OpenFlv { .. } | KvmCommand::RequestIdr { .. } | KvmCommand::ReconnectFlv { .. } => {}
        }
    }
}

async fn login_slot(slot: &mut Option<BoxFuture<'static, Result<Token, KvmError>>>) -> Result<Token, KvmError> {
    match slot {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match slot {
        Some(h) => h.await,
        None => std::future::pending().await,
    }
}

struct Session<'d> {
    generation: Gen,
    deps: &'d KvmDeps,
    auth: AuthGate,
    login_backoff: Backoff,
    login: Option<BoxFuture<'static, Result<Token, KvmError>>>,
    login_retry_at: Option<Instant>,
    token: watch::Sender<Option<(u64, Token)>>,
    deadline: Deadline,
    ws_ctl: mpsc::UnboundedSender<WsCtl>,
    ws_events: mpsc::UnboundedReceiver<WsEvent>,
    ws_alive: bool,
    ws_task: JoinHandle<()>,
    video: Video,
    side: Option<JoinHandle<Result<(), KvmError>>>,
    fatal: bool,
}

impl<'d> Session<'d> {
    fn new(generation: Gen, deps: &'d KvmDeps) -> Session<'d> {
        let cfg = &deps.cfg;
        let (token_tx, token_rx) = watch::channel(None);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let ws_task = tokio::spawn(
            WsTask {
                ep: deps.ep.clone(),
                token: token_rx,
                ctl: ctl_rx,
                events: ev_tx,
                hid: deps.hid.clone(),
                backoff: Backoff::new(cfg.backoff, Jitter::from_clock()),
                connect_timeout: cfg.connect_timeout,
                write_timeout: cfg.hid_write_timeout,
                metrics: deps.metrics.clone(),
            }
            .run(),
        );
        let video = Video::new(
            generation,
            deps.ep.clone(),
            deps.to_pump.clone(),
            deps.metrics.clone(),
            FlvSettings {
                connect_timeout: cfg.connect_timeout,
                idle_timeout: cfg.flv_idle_timeout,
                deadline: cfg.upstream_deadline,
                admission: cfg.admission.clone(),
            },
            Backoff::new(cfg.backoff, Jitter::from_clock()),
        );
        Session {
            generation,
            deps,
            auth: AuthGate::default(),
            login_backoff: Backoff::new(cfg.backoff, Jitter::from_clock()),
            login: None,
            login_retry_at: None,
            token: token_tx,
            deadline: Deadline::new(cfg.upstream_deadline),
            ws_ctl: ctl_tx,
            ws_events: ev_rx,
            ws_alive: true,
            ws_task,
            video,
            side: None,
            fatal: false,
        }
    }

    /// Serve this generation; returns a command that must be handled by
    /// the actor next (a `Start` or `Shutdown` that ended it), if any.
    async fn run(mut self, rx: &mut mpsc::UnboundedReceiver<KvmCommand>) -> Option<KvmCommand> {
        self.deadline.started(Instant::now());
        self.start_login();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        self.close().await;
                        return None;
                    };
                    if let Some(exit) = self.command(cmd).await {
                        return exit;
                    }
                }
                ev = self.ws_events.recv(), if self.ws_alive => self.ws_event(ev).await,
                r = login_slot(&mut self.login) => {
                    self.login = None;
                    self.login_done(r).await;
                }
                r = self.video.ready() => {
                    if let Some(o) = self.video.on_ready(r, Instant::now()).await {
                        self.outcome(o).await;
                    }
                }
                r = join_slot(&mut self.side) => {
                    self.side = None;
                    match r {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => self.deps.metrics.idr_side_failures.inc(e.kind()),
                        Err(_) => self.deps.metrics.idr_side_failures.inc("task"),
                    }
                }
                _ = tick.tick() => self.tick().await,
            }
        }
    }

    /// `Some(exit)` ends the session.
    async fn command(&mut self, cmd: KvmCommand) -> Option<Option<KvmCommand>> {
        match cmd {
            KvmCommand::Stop { generation, done } if generation == self.generation => {
                self.close().await;
                ack(done);
                Some(None)
            }
            KvmCommand::Stop { done, .. } => {
                ack(done);
                None
            }
            KvmCommand::Start { generation } => {
                self.close().await;
                Some(Some(KvmCommand::Start { generation }))
            }
            KvmCommand::Shutdown { done } => {
                self.close().await;
                Some(Some(KvmCommand::Shutdown { done }))
            }
            KvmCommand::FlushHid { done } => {
                // If the task is gone, `done` is dropped and the waiter sees it.
                let _ = self.ws_ctl.send(WsCtl::Flush { done });
                None
            }
            KvmCommand::OpenFlv { generation } if generation == self.generation && !self.fatal => {
                let token = self.token.borrow().clone();
                self.video.want(Instant::now(), token.as_ref());
                None
            }
            KvmCommand::ReconnectFlv { generation } if generation == self.generation && !self.fatal => {
                let token = self.token.borrow().clone();
                self.video.reconnect(Instant::now(), token.as_ref());
                None
            }
            KvmCommand::RequestIdr { generation } if generation == self.generation && !self.fatal => {
                self.request_idr();
                None
            }
            KvmCommand::OpenFlv { .. } | KvmCommand::ReconnectFlv { .. } | KvmCommand::RequestIdr { .. } => None,
        }
    }

    fn start_login(&mut self) {
        let (ep, cfg) = (self.deps.ep.clone(), self.deps.cfg.clone());
        self.login = Some(Box::pin(async move {
            login(&ep, &cfg.password, cfg.connect_timeout, cfg.login_timeout).await
        }));
        self.login_retry_at = None;
    }

    async fn login_done(&mut self, r: Result<Token, KvmError>) {
        match r {
            Ok(token) => {
                if self.auth.seq() > 0 {
                    self.deps.metrics.relogins.inc();
                }
                self.deps.metrics.logins.inc();
                self.auth.login_ok();
                self.deadline.logged_in();
                self.login_backoff.reset();
                let current = (self.auth.seq(), token);
                self.video.token_ready(&current);
                self.token.send_replace(Some(current));
            }
            Err(e) => match e.class() {
                FailClass::Auth => match self.auth.login_rejected() {
                    AuthStep::Fatal => self.fatal(Cause::KvmAuthFailed).await,
                    AuthStep::Relogin | AuthStep::Wait => self.start_login(),
                },
                FailClass::Cert => self.fatal(Cause::KvmCertMismatch).await,
                FailClass::Transient => {
                    self.login_retry_at = Some(Instant::now() + self.login_backoff.next_delay());
                }
            },
        }
    }

    async fn ws_event(&mut self, ev: Option<WsEvent>) {
        match ev {
            Some(WsEvent::AuthRefused { seq }) => self.refused(seq).await,
            Some(WsEvent::CertMismatch) => self.fatal(Cause::KvmCertMismatch).await,
            Some(WsEvent::Up | WsEvent::Down) => {}
            None => self.ws_alive = false,
        }
    }

    async fn refused(&mut self, seq: u64) {
        match self.auth.refused(seq) {
            AuthStep::Relogin => {
                if self.login.is_none() {
                    self.start_login();
                }
            }
            AuthStep::Wait => {
                // A token newer than the refused one may already be here:
                // hand it to the FLV (never the refused one again).
                let current = self.token.borrow().clone();
                if let Some(t) = current
                    && t.0 > seq
                {
                    self.video.token_ready(&t);
                }
            }
            AuthStep::Fatal => self.fatal(Cause::KvmAuthFailed).await,
        }
    }

    async fn outcome(&mut self, o: Outcome) {
        match o {
            Outcome::Refused { seq } => self.refused(seq).await,
            Outcome::Fatal(cause) => self.fatal(cause).await,
        }
    }

    fn request_idr(&mut self) {
        self.deps.metrics.idr_requests.inc("side");
        if self.side.is_some() {
            self.deps.metrics.idr_side_failures.inc("busy");
            return;
        }
        let Some((_, token)) = self.token.borrow().clone() else {
            self.deps.metrics.idr_side_failures.inc("no_token");
            return;
        };
        let cfg = &self.deps.cfg;
        self.side = Some(tokio::spawn(side::request_idr(
            self.deps.ep.clone(),
            token,
            cfg.connect_timeout,
            cfg.idr_side_timeout,
        )));
    }

    async fn tick(&mut self) {
        if self.fatal {
            return;
        }
        let now = Instant::now();
        if self.deadline.expired(now) {
            self.fatal(Cause::KvmUnreachable).await;
            return;
        }
        if self.login.is_none() && self.login_retry_at.is_some_and(|t| now >= t) {
            self.start_login();
        }
        let token = self.token.borrow().clone();
        if let Some(o) = self.video.tick(now, token.as_ref()) {
            self.outcome(o).await;
        }
    }

    /// One fatal cause per session (§6.9): stop the KVM-side video and tell
    /// the pump; the websocket stays up so Closing's release-all reaches the
    /// KVM; the pump's disconnect ends the session with a `Stop`.
    async fn fatal(&mut self, cause: Cause) {
        if self.fatal {
            return;
        }
        self.fatal = true;
        self.video.close();
        self.login = None;
        tracing::warn!(cause = cause.label(), "kvm session failed");
        let _ = self.deps.to_pump.send(KvmEvent::UpstreamFatal { generation: self.generation, cause }).await;
    }

    async fn close(&mut self) {
        self.login = None;
        if let Some(side) = self.side.take() {
            side.abort();
        }
        // §11.3's order: release-all and the websocket close first (the
        // writer sends any pending release before closing), then the FLV.
        let (done, rx) = oneshot::channel();
        if self.ws_ctl.send(WsCtl::Close { done }).is_ok() {
            let _ = tokio::time::timeout(CLOSE_WAIT, rx).await;
        }
        self.ws_task.abort();
        self.video.close();
        // Never a logout (§3.2): the token lapses on the KVM.
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- kvm::session` — Expected: PASS — 12 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/kvm/session.rs crates/kvm-rdp/src/kvm/mod.rs
git commit -m "kvm-rdp: the KVM actor — Start/Stop in order, one login, re-login once, never a logout (§4.3, §5.1)" \
  -m "Start/Stop storms leave nothing open (Review Focus 1)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 4 — The EGFX pump core (sans-IO)

§6.4–§6.6 as code: the pump's vocabulary and the slate, the flow core (gates, unacked set, stall, standing delay), the IDR core, then the state machine in three slices and the table test of every §6.4 cell. Every test here drives a real `GraphicsPipelineServer` in memory with an injected clock (§11.2 L1).

### Task 4.1: `pump::{types, slate}` — inputs, commands, config, the connecting slate

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/mod.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/types.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/slate.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod pump;`)
- Test: `crates/kvm-rdp/src/pump/types.rs`, `crates/kvm-rdp/src/pump/slate.rs` (`tests`)

**Interfaces:**
- Consumes: `config::{Config, IdrPolicy}`, `hid::ReleaseTrigger`, `msg::{Cause, FlvOrigin, Gen, KvmAu}`, `ironrdp_dvc::DvcMessage`, `kvm_proto::video::{ParamClass, ParamSets}`, `kvm_proto::h264::{parse_sps, split_annex_b}`.
- Produces (`kvm_rdp::pump`):
  - `types::FlowConfig { soft_gate, backlog_limit: u64, standing_delay_limit, first_ack_grace, stall_timeout }`, `types::IdrConfig { policy: IdrPolicy, side_timeout, wait_max, interval_setup, interval_flow }`, `types::PumpConfig { hard_cap: u32, flow: FlowConfig, idr: IdrConfig, rtt_probe_interval, burst_chunk: u32, avc420_timeout, suppress_debounce, disconnect_watchdog, region_qp: u8 }` with `PumpConfig::from_config(&Config)` (all `Duration` unless noted; `Clone + Debug`).
  - `types::State { Idle, WaitReady, NeedIdr, Live, WaitReactivation, Paused, Closing }` (`Copy + Eq + Debug`).
  - `types::Input { SessionStart { generation, size: (u16, u16) }, SessionStop { generation }, OnReady { avc420: bool }, ReactivationComplete, FrameAck { frame_id: u32, queue_depth: u32 }, Tick, Suppress(bool), SpsChanged { class, params }, FlvOpened { origin }, Au(KvmAu), UpstreamFatal(Cause), Shutdown { watchdog: Duration }, Backlog { written: u64 }, Rtt(u32) }`.
  - `types::DvcBatch { pub channel_id: u32, pub messages: Vec<DvcMessage>, pub weight: u64, pub frames: u32, pub received: Option<Instant>, pub yield_after: bool }` (`Debug` without the payload).
  - `types::Command { SendDvc(DvcBatch), DisplayResize { width: u16, height: u16 }, SurfaceSize { width: u16, height: u16 }, ReleaseAll(ReleaseTrigger), OpenFlv, RequestIdr, ReconnectFlv, CancelIdrRequest, ProbeRtt, Disconnect(Cause), Abort }` with `kind(&self) -> &'static str`.
  - `slate::Slate { pub annex_b: Vec<u8>, pub size: (u16, u16) }` with `Slate::embedded() -> Option<Slate>` and `Slate::from_annex_b(&[u8]) -> Option<Slate>`.

- [ ] **Step 1: Write the failing tests.** Create `pump/mod.rs`:

```rust
//! The EGFX pump (spec §4.3, §6.4–§6.6, §6.9): a sans-IO core (`core`) over
//! the flow, IDR and debounce cores, and an async shell (Task 5.3) that
//! only locks, steps and carries out commands.
pub mod slate;
pub mod types;

pub use types::{Command, DvcBatch, FlowConfig, IdrConfig, Input, PumpConfig, State};
```

add `pub mod pump;` to `lib.rs`; create `pump/types.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn command_kinds_are_distinct() {
        let all = [
            Command::DisplayResize { width: 1, height: 1 },
            Command::SurfaceSize { width: 1, height: 1 },
            Command::ReleaseAll(ReleaseTrigger::Closing),
            Command::OpenFlv,
            Command::RequestIdr,
            Command::ReconnectFlv,
            Command::CancelIdrRequest,
            Command::ProbeRtt,
            Command::Disconnect(Cause::Shutdown),
            Command::Abort,
            Command::SendDvc(DvcBatch {
                channel_id: 1,
                messages: Vec::new(),
                weight: 0,
                frames: 0,
                received: None,
                yield_after: false,
            }),
        ];
        let mut k: Vec<_> = all.iter().map(Command::kind).collect();
        k.sort_unstable();
        k.dedup();
        assert_eq!(k.len(), all.len());
    }

    #[test]
    fn a_batch_debug_never_dumps_its_payload() {
        let b = DvcBatch { channel_id: 7, messages: Vec::new(), weight: 99, frames: 1, received: None, yield_after: true };
        let s = format!("{b:?}");
        assert!(s.contains("weight: 99") && s.contains("messages: 0"), "{s}");
    }
}
```

and `pump/slate.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    /// §6.4: the slate is a 1920×1080 IDR; only allowlisted NALs survive
    /// (x264's SEI does not), each behind a 4-byte start code (§6.3).
    #[test]
    fn the_embedded_slate_is_a_1080p_idr_with_allowlisted_nals_only() {
        let s = Slate::embedded().unwrap();
        assert_eq!(s.size, (1920, 1080));
        assert_eq!(s.annex_b[..4], [0, 0, 0, 1]);
        let types: Vec<u8> = split_annex_b(&s.annex_b).map(|n| n[0] & 0x1F).collect();
        assert!(types.contains(&5) && types.contains(&7) && types.contains(&8), "{types:?}");
        assert!(types.iter().all(|t| matches!(t, 1 | 5 | 7 | 8 | 9)), "{types:?}");
    }

    #[test]
    fn a_stream_without_a_picture_is_no_slate() {
        assert!(Slate::from_annex_b(&[0, 0, 0, 1, 0x09, 0x10]).is_none());
        assert!(Slate::from_annex_b(&[]).is_none());
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- pump::` — Expected: FAIL to compile.

- [ ] **Step 3: Implement the types.** Above the tests in `pump/types.rs`:

```rust
//! The pump's vocabulary (§4.3): what the core is told, what it orders.
use crate::config::{Config, IdrPolicy};
use crate::hid::ReleaseTrigger;
use crate::msg::{Cause, FlvOrigin, Gen, KvmAu};
use ironrdp_dvc::DvcMessage;
use kvm_proto::video::{ParamClass, ParamSets};
use std::time::{Duration, Instant};

/// §6.6's gates and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowConfig {
    pub soft_gate: Duration,
    pub backlog_limit: u64,
    pub standing_delay_limit: Duration,
    pub first_ack_grace: Duration,
    pub stall_timeout: Duration,
}

/// §6.5's IDR acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdrConfig {
    pub policy: IdrPolicy,
    pub side_timeout: Duration,
    pub wait_max: Duration,
    pub interval_setup: Duration,
    pub interval_flow: Duration,
}

#[derive(Debug, Clone)]
pub struct PumpConfig {
    /// IronRDP's `max_frames_in_flight`, set at every Setup (§6.6).
    pub hard_cap: u32,
    pub flow: FlowConfig,
    pub idr: IdrConfig,
    pub rtt_probe_interval: Duration,
    pub burst_chunk: u32,
    pub avc420_timeout: Duration,
    pub suppress_debounce: Duration,
    pub disconnect_watchdog: Duration,
    pub region_qp: u8,
}

impl PumpConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> PumpConfig {
        let v = &c.video;
        PumpConfig {
            hard_cap: v.hard_cap_frames(),
            flow: FlowConfig {
                soft_gate: v.soft_gate,
                backlog_limit: v.backlog_limit,
                standing_delay_limit: v.standing_delay_limit,
                first_ack_grace: v.first_ack_grace,
                stall_timeout: v.stall_timeout,
            },
            idr: IdrConfig {
                policy: v.idr_policy,
                side_timeout: v.idr_side_timeout,
                wait_max: v.idr_wait_max,
                interval_setup: v.flv_reconnect_interval_setup,
                interval_flow: v.flv_reconnect_interval_flow,
            },
            rtt_probe_interval: v.rtt_probe_interval,
            burst_chunk: v.burst_chunk,
            avc420_timeout: v.avc420_timeout,
            suppress_debounce: v.suppress_debounce,
            disconnect_watchdog: v.disconnect_watchdog,
            region_qp: v.region_qp,
        }
    }
}

/// §6.4's states; `Idle` means "no generation".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    WaitReady,
    NeedIdr,
    Live,
    WaitReactivation,
    Paused,
    Closing,
}

/// One input to `Pump::step` (§4.3's list, with `Shutdown`).
#[derive(Debug)]
pub enum Input {
    SessionStart { generation: Gen, size: (u16, u16) },
    SessionStop { generation: Gen },
    OnReady { avc420: bool },
    ReactivationComplete,
    FrameAck { frame_id: u32, queue_depth: u32 },
    Tick,
    /// The display-suppressed flag, sampled (§6.6).
    Suppress(bool),
    SpsChanged { class: ParamClass, params: ParamSets },
    FlvOpened { origin: FlvOrigin },
    Au(KvmAu),
    UpstreamFatal(Cause),
    /// §5.2: close with cause `shutdown` and this watchdog (DC13).
    Shutdown { watchdog: Duration },
    /// This generation's write-progress counter (§6.6 backlog gate).
    Backlog { written: u64 },
    /// The auto-detect RTT handle (ms; `u32::MAX` = no answer).
    Rtt(u32),
}

/// One `ServerEvent::Egfx` worth of drained EGFX PDUs.
pub struct DvcBatch {
    pub channel_id: u32,
    pub messages: Vec<DvcMessage>,
    /// Σ `DvcMessage::size()` (§4.2 patch 2's weight).
    pub weight: u64,
    /// AVC420 frames in the batch (the slate counts, Setup PDUs do not).
    pub frames: u32,
    /// The earliest receive time of a KVM AU in the batch (§10.1).
    pub received: Option<Instant>,
    /// A burst chunk: yield after sending so input interleaves (§6.5).
    pub yield_after: bool,
}

impl std::fmt::Debug for DvcBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DvcBatch")
            .field("channel_id", &self.channel_id)
            .field("messages", &self.messages.len())
            .field("weight", &self.weight)
            .field("frames", &self.frames)
            .field("yield_after", &self.yield_after)
            .finish()
    }
}

/// What the shell carries out (§4.3's list).
#[derive(Debug)]
pub enum Command {
    SendDvc(DvcBatch),
    DisplayResize { width: u16, height: u16 },
    /// Mouse scaling switches to this surface (§6.4, Plan D).
    SurfaceSize { width: u16, height: u16 },
    ReleaseAll(ReleaseTrigger),
    OpenFlv,
    RequestIdr,
    ReconnectFlv,
    /// A deferred IDR request was cancelled (metrics only, DC11).
    CancelIdrRequest,
    ProbeRtt,
    Disconnect(Cause),
    /// The disconnect watchdog fired: stop the KVM side, abort (§6.9).
    Abort,
}

impl Command {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Command::SendDvc(_) => "SendDvc",
            Command::DisplayResize { .. } => "DisplayResize",
            Command::SurfaceSize { .. } => "SurfaceSize",
            Command::ReleaseAll(_) => "ReleaseAll",
            Command::OpenFlv => "OpenFlv",
            Command::RequestIdr => "RequestIdr",
            Command::ReconnectFlv => "ReconnectFlv",
            Command::CancelIdrRequest => "CancelIdrRequest",
            Command::ProbeRtt => "ProbeRtt",
            Command::Disconnect(_) => "Disconnect",
            Command::Abort => "Abort",
        }
    }
}
```

- [ ] **Step 4: Implement the slate.** Above the tests in `pump/slate.rs`:

```rust
//! The connecting slate (§6.4): a pre-encoded 1920×1080 "Connecting to
//! KVM…" IDR built by `gen-fixtures`, sent on the first Setup when the
//! surface has its size. Rebuilt once into §6.3's form — allowlisted NALs
//! only, 4-byte start codes. Not a KVM frame: it does not arm suppression
//! and does not count for delivery.
use kvm_proto::h264::{parse_sps, split_annex_b};

const SLATE: &[u8] = include_bytes!("../../../../fixtures/slate_1080p.h264");

pub struct Slate {
    pub annex_b: Vec<u8>,
    pub size: (u16, u16),
}

impl Slate {
    #[must_use]
    pub fn embedded() -> Option<Slate> {
        Slate::from_annex_b(SLATE)
    }

    #[must_use]
    pub fn from_annex_b(data: &[u8]) -> Option<Slate> {
        let mut annex_b = Vec::with_capacity(data.len());
        let mut size = None;
        let mut picture = false;
        for nal in split_annex_b(data) {
            let t = nal.first()? & 0x1F;
            if !matches!(t, 1 | 5 | 7 | 8 | 9) {
                continue;
            }
            if t == 7 {
                let s = parse_sps(nal).ok()?;
                size = Some((u16::try_from(s.width).ok()?, u16::try_from(s.height).ok()?));
            }
            picture |= matches!(t, 1 | 5);
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(nal);
        }
        if !picture {
            return None;
        }
        Some(Slate { annex_b, size: size? })
    }
}
```

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --lib -- pump::` — Expected: PASS — 4 passed.

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-rdp/src/pump crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: pump vocabulary — inputs, commands, config — and the connecting slate (§4.3, §6.4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.2: `pump::flow` — gates, the unacked set, the stall timer, standing delay

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/flow.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/mod.rs` (`pub mod flow;`)
- Test: `crates/kvm-rdp/src/pump/flow.rs` (`tests`)

**Interfaces:**
- Consumes: `pump::types::FlowConfig`.
- Produces (`pump::flow`): `pub const SUSPEND: u32` (`0xFFFF_FFFF`); `pub enum Gate { Open, Soft, Backlog, StandingDelay, Backpressure }` with `is_open(self) -> bool`, `drop_reason(self) -> &'static str`; `pub struct Flow` — `new(FlowConfig)`, `on_setup(&mut self)`, `on_flv_opened(&mut self)`, `take_grace(&mut self, idr: bool) -> bool`, `add_handed(&mut self, u64)`, `set_written(&mut self, u64)`, `backlog(&self) -> u64`, `record(&mut self, frame_id: u32, now: Instant, burst: bool, grace: bool, suspended: bool)`, `on_ack(&mut self, frame_id: u32, queue_depth: u32)`, `gates(&mut self, now: Instant, burst: bool, suspended: bool, backpressure: bool) -> Gate`, `set_frozen(&mut self, now: Instant, frozen: bool)`, `stall_expired(&self, now: Instant, suspended: bool) -> bool`, `suspended_backlog_expired(&mut self, now: Instant, suspended: bool) -> bool`, `rtt_sample(&mut self, u32) -> bool` (true for a live sample; a generation's first is only the reference — DC6's rule lives here, nowhere else), `standing_delay_ms(&self) -> Option<u32>`, `in_flight(&self) -> usize`, `sent_at(&self, frame_id: u32) -> Option<Instant>` (the §10.4 ack RTT), `oldest_age(&self, now: Instant) -> Duration`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod flow;` to `pump/mod.rs`; create `pump/flow.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn cfg() -> FlowConfig {
        FlowConfig {
            soft_gate: Duration::from_millis(500),
            backlog_limit: 4 << 20,
            standing_delay_limit: Duration::from_millis(500),
            first_ack_grace: Duration::from_millis(1600),
            stall_timeout: Duration::from_secs(10),
        }
    }

    struct Clock(Instant);
    impl Clock {
        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    /// §6.6 grace: a first ack slower than `soft_gate` but within
    /// `first_ack_grace` does not close the soft gate.
    #[test]
    fn a_grace_frame_tolerates_a_slow_first_ack() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.on_setup();
        let grace = f.take_grace(true);
        assert!(grace && !f.take_grace(true), "one grace IDR per Setup");
        f.record(0, c.at(0), false, grace, false);
        assert_eq!(f.gates(c.at(1000), false, false, false), Gate::Open);
        assert_eq!(f.gates(c.at(1700), false, false, false), Gate::Soft);
        f.on_ack(0, 0);
        assert_eq!(f.gates(c.at(1700), false, false, false), Gate::Open);
    }

    /// §6.6: the soft gate is the age of the oldest unacked frame, so a
    /// 5 fps → 60 fps transition never closes it.
    #[test]
    fn the_soft_gate_is_time_based_so_fps_changes_do_not_close_it() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        let mut id = 0u32;
        let mut t = 0u64;
        // (frame period, ack delay): 5 fps idle, then 60 fps motion — at 60
        // fps two frames are in flight where at 5 fps there was one.
        let mut pending: VecDeque<(u32, u64)> = VecDeque::new();
        let mut most = 0;
        for (period, ack_after) in [(200u64, 100u64), (16, 30)] {
            for _ in 0..60 {
                while let Some(&(pid, due)) = pending.front() {
                    if due > t {
                        break;
                    }
                    f.on_ack(pid, 0);
                    pending.pop_front();
                }
                assert_eq!(f.gates(c.at(t), false, false, false), Gate::Open, "t={t}");
                f.record(id, c.at(t), false, false, false);
                pending.push_back((id, t + ack_after));
                most = most.max(f.in_flight());
                id += 1;
                t += period;
            }
        }
        assert!(most >= 2, "the 60 fps phase had more in flight: {most}");
    }

    /// §6.5/§6.6: burst frames are exempt; live frames after a burst are
    /// gated on the oldest non-burst, non-grace frame.
    #[test]
    fn burst_frames_are_exempt_and_live_frames_gate_on_the_oldest_non_burst() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        for id in 0..10 {
            f.record(id, c.at(0), true, false, false);
        }
        assert_eq!(f.gates(c.at(900), true, false, false), Gate::Open);
        assert_eq!(f.gates(c.at(900), false, false, false), Gate::Open, "only burst frames are old");
        f.record(10, c.at(900), false, false, false);
        assert_eq!(f.gates(c.at(1300), false, false, false), Gate::Open);
        assert_eq!(f.gates(c.at(1450), false, false, false), Gate::Soft);
        assert_eq!(f.gates(c.at(1450), true, false, false), Gate::Open, "a burst AU skips the soft gate");
        assert_eq!(f.gates(c.at(1450), true, false, true), Gate::Backpressure, "but not the hard cap");
    }

    /// §6.6 stall: arms at the first closure, survives a Setup, is frozen in
    /// Paused/WaitReactivation, fires at `stall_timeout`; any ack disarms.
    #[test]
    fn the_stall_arms_survives_setup_freezes_and_fires() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        assert_eq!(f.gates(c.at(600), false, false, false), Gate::Soft);
        f.on_setup();
        f.set_frozen(c.at(2_000), true);
        assert!(!f.stall_expired(c.at(20_000), false), "frozen");
        f.set_frozen(c.at(20_000), false);
        assert!(!f.stall_expired(c.at(28_000), false));
        assert!(f.stall_expired(c.at(28_700), false), "1.4 s + 8.7 s ≥ 10 s");
        assert!(!f.stall_expired(c.at(28_700), true), "disabled while suspended");
        f.on_ack(99, 0);
        assert!(!f.stall_expired(c.at(40_000), false), "any ack disarms");
    }

    /// §6.6 suspension: nothing is recorded, the soft gate and back-pressure
    /// are bypassed; the first non-suspend ack clears the set first.
    #[test]
    fn suspended_acks_record_nothing_and_a_resume_clears_the_set() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        f.record(1, c.at(0), false, false, false);
        f.on_ack(0, SUSPEND);
        assert_eq!(f.in_flight(), 0);
        f.record(2, c.at(10), false, false, true);
        assert_eq!(f.in_flight(), 0, "nothing recorded while suspended");
        assert_eq!(f.gates(c.at(5_000), false, true, true), Gate::Open);
        f.record(3, c.at(5_000), false, false, false);
        f.on_ack(2, 0);
        assert_eq!(f.in_flight(), 0, "the resume ack cleared the set before removing its own id");
        assert_eq!(f.gates(c.at(5_100), false, false, false), Gate::Open);
    }

    /// §6.6: while suspended, backlog held ≥ the limit for `stall_timeout`
    /// is a stall; a dip resets it.
    #[test]
    fn suspended_backlog_held_for_the_stall_timeout_is_a_stall() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.add_handed(5 << 20);
        assert!(!f.suspended_backlog_expired(c.at(0), true));
        f.set_written(2 << 20);
        assert!(!f.suspended_backlog_expired(c.at(5_000), true), "dipped below the limit");
        f.set_written(0);
        assert!(!f.suspended_backlog_expired(c.at(6_000), true));
        assert!(f.suspended_backlog_expired(c.at(16_000), true));
        assert!(!f.suspended_backlog_expired(c.at(16_000), false), "only while suspended");
    }

    /// §6.6 backlog gate with the per-generation counter; acks for unknown
    /// ids are ignored and nothing underflows.
    #[test]
    fn the_backlog_gate_follows_the_counter_and_nothing_underflows() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.add_handed(5 << 20);
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Backlog);
        f.set_written(2 << 20);
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Open);
        f.set_written(9 << 20);
        assert_eq!(f.backlog(), 0);
        f.on_ack(12345, 0);
        f.on_ack(12345, 0);
        assert_eq!(f.in_flight(), 0);
    }

    /// §6.6 standing delay: inactive before this generation's first sample,
    /// median − baseline against the limit, and a stale handle (unchanged
    /// for 8 probes, or `u32::MAX`) is no signal.
    #[test]
    fn standing_delay_needs_a_live_signal() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.rtt_sample(900); // the previous connection's last value: a reference only
        assert_eq!(f.standing_delay_ms(), None);
        for v in [10, 12, 11] {
            f.rtt_sample(v);
        }
        assert_eq!(f.standing_delay_ms(), Some(1));
        for v in [600, 700, 650, 620, 640] {
            f.rtt_sample(v);
        }
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::StandingDelay);
        for _ in 0..8 {
            f.rtt_sample(640);
        }
        assert_eq!(f.standing_delay_ms(), None, "unchanged for 8 probes");
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Open);
        f.rtt_sample(u32::MAX);
        assert_eq!(f.standing_delay_ms(), None);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- pump::flow` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! §6.6's flow control, sans-IO: the unacked set mirroring IronRDP's
//! tracker, grace frames, the soft / backlog / standing-delay /
//! back-pressure gates, the stall timer (frozen in Paused and
//! WaitReactivation, disabled while suspended) and the suspended-backlog
//! bound. Arithmetic saturates.
use crate::pump::types::FlowConfig;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// `queue_depth` meaning "acknowledgements suspended" (MS-RDPEGFX 2.2.2.13).
pub const SUSPEND: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Open,
    Soft,
    Backlog,
    StandingDelay,
    Backpressure,
}

impl Gate {
    #[must_use]
    pub fn is_open(self) -> bool {
        self == Gate::Open
    }

    /// The `frames_dropped{reason}` label (§10.4).
    #[must_use]
    pub fn drop_reason(self) -> &'static str {
        match self {
            Gate::Open => "none",
            Gate::Soft => "soft_gate",
            Gate::Backlog => "backlog_gate",
            Gate::StandingDelay => "standing_delay",
            Gate::Backpressure => "backpressure",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sent {
    at: Instant,
    burst: bool,
    grace: bool,
}

#[derive(Debug, Default)]
struct Stall {
    armed: bool,
    elapsed: Duration,
    since: Option<Instant>,
    frozen: bool,
}

impl Stall {
    fn arm(&mut self, now: Instant) {
        if !self.armed {
            self.armed = true;
            self.elapsed = Duration::ZERO;
            self.since = (!self.frozen).then_some(now);
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
        self.elapsed = Duration::ZERO;
        self.since = None;
    }
    fn set_frozen(&mut self, now: Instant, frozen: bool) {
        if frozen == self.frozen {
            return;
        }
        self.frozen = frozen;
        if frozen {
            if let Some(s) = self.since.take() {
                self.elapsed = self.elapsed.saturating_add(now.saturating_duration_since(s));
            }
        } else if self.armed {
            self.since = Some(now);
        }
    }
    fn running(&self, now: Instant) -> Duration {
        self.elapsed
            .saturating_add(self.since.map_or(Duration::ZERO, |s| now.saturating_duration_since(s)))
    }
}

/// The auto-detect RTT samples of one generation (§6.6 standing delay).
#[derive(Debug, Default)]
struct Rtt {
    /// The handle's value at the generation's first sample (it is per
    /// server, so it may be the previous connection's).
    reference: Option<u32>,
    active: bool,
    last: Option<u32>,
    unchanged: u32,
    samples: VecDeque<u32>,
    baseline: Option<u32>,
}

impl Rtt {
    /// One read of the handle; true when it is a live sample (in the window).
    /// This is the one place DC6's reference rule lives: the shell feeds
    /// every read, and a generation's first is only the reference.
    fn sample(&mut self, v: u32) -> bool {
        if self.reference.is_none() {
            self.reference = Some(v);
            self.last = Some(v);
            return false;
        }
        if Some(v) == self.last {
            self.unchanged = self.unchanged.saturating_add(1);
        } else {
            self.unchanged = 0;
        }
        self.last = Some(v);
        if v == u32::MAX {
            return false;
        }
        if !self.active && Some(v) != self.reference {
            self.active = true;
        }
        if !self.active {
            return false;
        }
        if self.samples.len() >= 8 {
            self.samples.pop_front();
        }
        self.samples.push_back(v);
        self.baseline = Some(self.baseline.map_or(v, |b| b.min(v)));
        true
    }

    fn standing_ms(&self) -> Option<u32> {
        if !self.active || self.unchanged >= 8 || self.last == Some(u32::MAX) {
            return None;
        }
        let mut sorted: Vec<u32> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        let median = *sorted.get(sorted.len() / 2)?;
        Some(median.saturating_sub(self.baseline?))
    }
}

pub struct Flow {
    cfg: FlowConfig,
    unacked: BTreeMap<u32, Sent>,
    grace_next_idr: bool,
    /// A suspend ack was seen; the next ordinary ack clears the set first.
    resume_pending: bool,
    handed: u64,
    written: u64,
    rtt: Rtt,
    stall: Stall,
    backlog_since: Option<Instant>,
}

impl Flow {
    #[must_use]
    pub fn new(cfg: FlowConfig) -> Flow {
        Flow {
            cfg,
            unacked: BTreeMap::new(),
            grace_next_idr: true,
            resume_pending: false,
            handed: 0,
            written: 0,
            rtt: Rtt::default(),
            stall: Stall::default(),
            backlog_since: None,
        }
    }

    /// Setup cleared IronRDP's tracker (§6.6); the next IDR is a grace
    /// frame. The stall timer survives.
    pub fn on_setup(&mut self) {
        self.unacked.clear();
        self.grace_next_idr = true;
    }

    pub fn on_flv_opened(&mut self) {
        self.grace_next_idr = true;
    }

    /// Whether this frame is the grace IDR (consumed by the first IDR).
    pub fn take_grace(&mut self, idr: bool) -> bool {
        if idr && self.grace_next_idr {
            self.grace_next_idr = false;
            true
        } else {
            false
        }
    }

    pub fn add_handed(&mut self, weight: u64) {
        self.handed = self.handed.saturating_add(weight);
    }

    pub fn set_written(&mut self, written: u64) {
        self.written = written;
    }

    #[must_use]
    pub fn backlog(&self) -> u64 {
        self.handed.saturating_sub(self.written)
    }

    /// A frame IronRDP accepted (`Some(frame_id)`); nothing is recorded while
    /// acks are suspended.
    pub fn record(&mut self, frame_id: u32, now: Instant, burst: bool, grace: bool, suspended: bool) {
        if !suspended {
            self.unacked.insert(frame_id, Sent { at: now, burst, grace });
        }
    }

    pub fn on_ack(&mut self, frame_id: u32, queue_depth: u32) {
        self.stall.disarm();
        if queue_depth == SUSPEND {
            self.unacked.clear();
            self.resume_pending = true;
            return;
        }
        if self.resume_pending {
            self.unacked.clear();
            self.resume_pending = false;
        }
        self.unacked.remove(&frame_id);
    }

    /// The gates before an AU (`burst` exempts it from the soft gate) or on
    /// a tick; a closure arms the stall timer unless acks are suspended.
    pub fn gates(&mut self, now: Instant, burst: bool, suspended: bool, backpressure: bool) -> Gate {
        let g = self.check(now, burst, suspended, backpressure);
        if suspended {
            self.stall.disarm();
        } else if g != Gate::Open {
            self.stall.arm(now);
        }
        g
    }

    fn check(&self, now: Instant, burst: bool, suspended: bool, backpressure: bool) -> Gate {
        if !suspended
            && !burst
            && self
                .oldest_gated(now)
                .is_some_and(|at| now.saturating_duration_since(at) >= self.cfg.soft_gate)
        {
            return Gate::Soft;
        }
        if self.backlog() >= self.cfg.backlog_limit {
            return Gate::Backlog;
        }
        if self
            .rtt
            .standing_ms()
            .is_some_and(|ms| Duration::from_millis(u64::from(ms)) >= self.cfg.standing_delay_limit)
        {
            return Gate::StandingDelay;
        }
        if !suspended && backpressure {
            return Gate::Backpressure;
        }
        Gate::Open
    }

    /// The oldest unacked frame that is neither burst nor in its grace.
    fn oldest_gated(&self, now: Instant) -> Option<Instant> {
        self.unacked
            .values()
            .filter(|s| !(s.burst || (s.grace && now.saturating_duration_since(s.at) < self.cfg.first_ack_grace)))
            .map(|s| s.at)
            .min()
    }

    pub fn set_frozen(&mut self, now: Instant, frozen: bool) {
        self.stall.set_frozen(now, frozen);
    }

    #[must_use]
    pub fn stall_expired(&self, now: Instant, suspended: bool) -> bool {
        !suspended && self.stall.armed && self.stall.running(now) >= self.cfg.stall_timeout
    }

    pub fn suspended_backlog_expired(&mut self, now: Instant, suspended: bool) -> bool {
        if suspended && self.backlog() >= self.cfg.backlog_limit {
            let since = *self.backlog_since.get_or_insert(now);
            now.saturating_duration_since(since) >= self.cfg.stall_timeout
        } else {
            self.backlog_since = None;
            false
        }
    }

    /// True when `v` was taken as a live sample (not the reference, not
    /// `u32::MAX`, not before the handle first moved).
    pub fn rtt_sample(&mut self, v: u32) -> bool {
        self.rtt.sample(v)
    }

    #[must_use]
    pub fn standing_delay_ms(&self) -> Option<u32> {
        self.rtt.standing_ms()
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.unacked.len()
    }

    /// When an unacked frame was handed to IronRDP (the §10.4 ack RTT).
    #[must_use]
    pub fn sent_at(&self, frame_id: u32) -> Option<Instant> {
        self.unacked.get(&frame_id).map(|s| s.at)
    }

    #[must_use]
    pub fn oldest_age(&self, now: Instant) -> Duration {
        self.unacked
            .values()
            .map(|s| now.saturating_duration_since(s.at))
            .max()
            .unwrap_or(Duration::ZERO)
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- pump::flow` — Expected: PASS — 8 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/pump/flow.rs crates/kvm-rdp/src/pump/mod.rs
git commit -m "kvm-rdp: pump flow core — gates, unacked set, grace, stall, standing delay (§6.6)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.3: `pump::idr` — getting an IDR (§6.5)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/idr.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/mod.rs` (`pub mod idr;`)
- Test: `crates/kvm-rdp/src/pump/idr.rs` (`tests`)

**Interfaces:**
- Consumes: `pump::types::IdrConfig`, `config::IdrPolicy`.
- Produces (`pump::idr`): `pub enum IdrAction { RequestIdr, ReconnectFlv, FallbackReconnect }`; `pub struct IdrCore` — `new(IdrConfig)`, `setup_cause(&mut self, now: Instant) -> Option<IdrAction>`, `flow_cause(&mut self, now: Instant)`, `observe_gates(&mut self, now: Instant, open: bool) -> Option<IdrAction>`, `flv_opened(&mut self, now: Instant)`, `resolve(&mut self) -> bool` (true when a deferred request was cancelled), `tick(&mut self, now: Instant) -> Option<IdrAction>`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod idr;` to `pump/mod.rs`; create `pump/idr.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::config::IdrPolicy;

    fn core(policy: IdrPolicy) -> (IdrCore, impl Fn(u64) -> Instant) {
        let t0 = Instant::now();
        let cfg = IdrConfig {
            policy,
            side_timeout: Duration::from_secs(1),
            wait_max: Duration::from_secs(3),
            interval_setup: Duration::from_secs(1),
            interval_flow: Duration::from_secs(10),
        };
        (IdrCore::new(cfg), move |ms| t0 + Duration::from_millis(ms))
    }

    /// Ticks every 10 ms over (from, to], collecting actions.
    fn ticks(c: &mut IdrCore, at: &impl Fn(u64) -> Instant, from: u64, to: u64) -> Vec<(u64, IdrAction)> {
        (from / 10 + 1..=to / 10).filter_map(|i| c.tick(at(i * 10)).map(|a| (i * 10, a))).collect()
    }

    /// §11.2: two Setup causes 300 ms apart → exactly two `RequestIdr`, the
    /// second deferred to the window's end.
    #[test]
    fn two_setup_causes_300ms_apart_are_two_requests_the_second_deferred() {
        let (mut c, at) = core(IdrPolicy::Side);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::RequestIdr));
        assert_eq!(c.setup_cause(at(300)), None);
        let got = ticks(&mut c, &at, 300, 1500);
        assert_eq!(got, [(1000, IdrAction::RequestIdr)]);
    }

    /// §11.2: a deferred request whose NeedIdr is resolved by an IDR inside
    /// the window is cancelled, and nothing more is requested.
    #[test]
    fn a_deferred_request_resolved_by_an_idr_is_cancelled() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.setup_cause(at(0));
        c.setup_cause(at(300));
        assert!(c.resolve(), "the deferred request is cancelled");
        assert_eq!(ticks(&mut c, &at, 300, 5000), []);
    }

    /// §11.2: no IDR within `idr_side_timeout` of a `RequestIdr` → exactly one
    /// `ReconnectFlv`, at the window's end.
    #[test]
    fn no_idr_within_the_side_timeout_falls_back_to_one_reconnect() {
        let (mut c, at) = core(IdrPolicy::Side);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::RequestIdr));
        assert_eq!(ticks(&mut c, &at, 0, 5000), [(1000, IdrAction::FallbackReconnect)]);
    }

    /// §6.5: a flow cause starts idr-wait accounting; the request comes only
    /// once the gates were open for a cumulative `idr_wait_max` — flapping
    /// does not reset it — on the flow clock.
    #[test]
    fn a_flow_cause_requests_after_cumulative_open_gate_time() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.flow_cause(at(0));
        assert_eq!(c.observe_gates(at(0), true), None);
        assert_eq!(c.observe_gates(at(2000), false), None, "2 s open");
        assert_eq!(c.observe_gates(at(5000), true), None, "closed time does not count");
        assert_eq!(c.observe_gates(at(5900), true), None);
        assert_eq!(c.observe_gates(at(6000), true), Some(IdrAction::RequestIdr), "2 s + 1 s");
    }

    /// §6.5: any FLV open clears a pending request, cancels a deferred one,
    /// resets idr-wait and restarts both clocks; it never requests.
    #[test]
    fn an_flv_open_clears_everything_and_restarts_the_clocks() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.setup_cause(at(0));
        c.setup_cause(at(300));
        c.flow_cause(at(300));
        c.observe_gates(at(300), true);
        c.flv_opened(at(400));
        assert_eq!(ticks(&mut c, &at, 400, 3000), [], "no deferred, no fallback, no idr-wait request");
        assert_eq!(c.setup_cause(at(1200)), None, "the setup clock restarted at 400");
        assert_eq!(ticks(&mut c, &at, 1200, 1500), [(1400, IdrAction::RequestIdr)]);
    }

    #[test]
    fn reconnect_policy_reconnects_and_has_no_fallback() {
        let (mut c, at) = core(IdrPolicy::Reconnect);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::ReconnectFlv));
        assert_eq!(ticks(&mut c, &at, 0, 5000), []);
    }

    #[test]
    fn wait_policy_never_requests() {
        let (mut c, at) = core(IdrPolicy::Wait);
        assert_eq!(c.setup_cause(at(0)), None);
        c.flow_cause(at(0));
        assert_eq!(c.observe_gates(at(0), true), None);
        assert_eq!(c.observe_gates(at(60_000), true), None);
        assert_eq!(ticks(&mut c, &at, 0, 5000), []);
    }

    /// A flow-clock request's fallback waits for the flow window (10 s).
    #[test]
    fn a_flow_requests_fallback_lands_at_the_flow_windows_end() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.flow_cause(at(0));
        c.observe_gates(at(0), true);
        assert_eq!(c.observe_gates(at(3000), true), Some(IdrAction::RequestIdr));
        assert_eq!(ticks(&mut c, &at, 3000, 14_000), [(13_000, IdrAction::FallbackReconnect)]);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- pump::idr` — Expected: FAIL to compile.

- [ ] **Step 3: Implement.** Above the tests:

```rust
//! §6.5's IDR acquisition, sans-IO. A Setup cause requests an IDR (except
//! the first Setup, whose `OpenFlv` serves); a flow cause starts idr-wait
//! accounting and requests once the gates were open for `idr_wait_max`;
//! an FLV open never requests. Two clocks rate-limit requests; one inside
//! its clock's window is deferred to the window's end and cancelled if an
//! IDR arrives or the pump leaves NeedIdr first. Under `side`, a request
//! that brings no IDR within `idr_side_timeout` falls back to a
//! `ReconnectFlv` on the same clock.
use crate::config::IdrPolicy;
use crate::pump::types::IdrConfig;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdrAction {
    RequestIdr,
    ReconnectFlv,
    /// A `side` request's fallback (`ReconnectFlv` + a metric).
    FallbackReconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clock {
    Setup,
    Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Primary,
    Fallback,
}

pub struct IdrCore {
    cfg: IdrConfig,
    /// When the last request went out or the last FLV opened: both clocks.
    last_issue: Option<Instant>,
    deferred: Option<(Instant, Clock, Kind)>,
    waiting: bool,
    wait_accum: Duration,
    wait_open_since: Option<Instant>,
    /// An outstanding `side` request: when, and on which clock.
    fallback: Option<(Instant, Clock)>,
}

impl IdrCore {
    #[must_use]
    pub fn new(cfg: IdrConfig) -> IdrCore {
        IdrCore {
            cfg,
            last_issue: None,
            deferred: None,
            waiting: false,
            wait_accum: Duration::ZERO,
            wait_open_since: None,
            fallback: None,
        }
    }

    /// A Setup (re-advertise, resize, leaving Paused). The caller does not
    /// call this for a connection's first Setup.
    pub fn setup_cause(&mut self, now: Instant) -> Option<IdrAction> {
        self.request(now, Clock::Setup, Kind::Primary)
    }

    /// A gate closed, an IDR was dropped, `send_avc420_frame` refused, an
    /// AU was dropped on a full channel, a burst was truncated, or
    /// `SpsChanged{other}`.
    pub fn flow_cause(&mut self, _now: Instant) {
        if self.cfg.policy != IdrPolicy::Wait && !self.waiting {
            self.waiting = true;
            self.wait_accum = Duration::ZERO;
            self.wait_open_since = None;
        }
    }

    /// Idr-wait accounting: the gates' state now.
    pub fn observe_gates(&mut self, now: Instant, open: bool) -> Option<IdrAction> {
        if !self.waiting {
            return None;
        }
        match (open, self.wait_open_since) {
            (true, None) => self.wait_open_since = Some(now),
            (false, Some(s)) => {
                self.wait_accum = self.wait_accum.saturating_add(now.saturating_duration_since(s));
                self.wait_open_since = None;
            }
            _ => {}
        }
        let total = self
            .wait_accum
            .saturating_add(self.wait_open_since.map_or(Duration::ZERO, |s| now.saturating_duration_since(s)));
        if total >= self.cfg.wait_max {
            self.waiting = false;
            return self.request(now, Clock::Flow, Kind::Primary);
        }
        None
    }

    pub fn flv_opened(&mut self, now: Instant) {
        self.deferred = None;
        self.fallback = None;
        self.reset_wait();
        self.last_issue = Some(now);
    }

    /// The pump left NeedIdr (an IDR went out, or Paused, WaitReactivation,
    /// Closing). True when a deferred request was cancelled.
    pub fn resolve(&mut self) -> bool {
        self.fallback = None;
        self.reset_wait();
        self.deferred.take().is_some()
    }

    pub fn tick(&mut self, now: Instant) -> Option<IdrAction> {
        if let Some((at, clock, kind)) = self.deferred
            && now >= at
        {
            self.deferred = None;
            return self.issue(now, clock, kind);
        }
        if let Some((at, clock)) = self.fallback
            && now >= at + self.cfg.side_timeout
        {
            self.fallback = None;
            return self.request(now, clock, Kind::Fallback);
        }
        None
    }

    fn interval(&self, clock: Clock) -> Duration {
        match clock {
            Clock::Setup => self.cfg.interval_setup,
            Clock::Flow => self.cfg.interval_flow,
        }
    }

    fn request(&mut self, now: Instant, clock: Clock, kind: Kind) -> Option<IdrAction> {
        if self.cfg.policy == IdrPolicy::Wait {
            return None;
        }
        if let Some(t) = self.last_issue {
            let end = t + self.interval(clock);
            if now < end {
                if self.deferred.is_none_or(|(at, _, _)| at > end) {
                    self.deferred = Some((end, clock, kind));
                }
                return None;
            }
        }
        self.issue(now, clock, kind)
    }

    fn issue(&mut self, now: Instant, clock: Clock, kind: Kind) -> Option<IdrAction> {
        self.last_issue = Some(now);
        self.deferred = None;
        self.reset_wait();
        match (self.cfg.policy, kind) {
            (IdrPolicy::Wait, _) => None,
            (IdrPolicy::Side, Kind::Primary) => {
                self.fallback = Some((now, clock));
                Some(IdrAction::RequestIdr)
            }
            (IdrPolicy::Reconnect, Kind::Primary) => {
                self.fallback = None;
                Some(IdrAction::ReconnectFlv)
            }
            (_, Kind::Fallback) => {
                self.fallback = None;
                Some(IdrAction::FallbackReconnect)
            }
        }
    }

    fn reset_wait(&mut self) {
        self.waiting = false;
        self.wait_accum = Duration::ZERO;
        self.wait_open_since = None;
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- pump::idr` — Expected: PASS — 8 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/src/pump/idr.rs crates/kvm-rdp/src/pump/mod.rs
git commit -m "kvm-rdp: pump IDR core — two clocks, deferral, cancellation, side fallback (§6.5)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.4: `pump::{debounce, core, rig}` — the §6.4 state machine and its L1 rig

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/debounce.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/core.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/rig.rs` (test-only)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/mod.rs`
- Test: `crates/kvm-rdp/src/pump/debounce.rs`, `crates/kvm-rdp/src/pump/core.rs` (`tests`)

**Interfaces:**
- Consumes: Tasks 4.1–4.3; `ironrdp_egfx::server::GraphicsPipelineServer` (`resize_with_monitors`, `create_surface`, `map_surface_to_output`, `set_max_frames_in_flight`, `send_avc420_frame`, `drain_output`, `channel_id`, `is_ack_suspended`, `should_backpressure`, `frames_in_flight`), `ironrdp_egfx::pdu::Avc420Region`, `ironrdp_pdu::gcc::{Monitor, MonitorFlags}`, `AccessUnit::write_annex_b`.
- Produces:
  - `pump::debounce`: `pub enum Edge { On, Off }`; `pub struct Debounce` — `new(hold: Duration)`, `sample(&mut self, now: Instant, raw: bool) -> Option<Edge>`.
  - `pump::core::Pump` — `Pump::new(cfg: PumpConfig, metrics: Arc<Metrics>) -> Pump` (embedded slate), `Pump::with_slate(cfg, metrics, slate: Option<Slate>) -> Pump`, `state(&self) -> State`, `generation(&self) -> Gen`, `size(&self) -> (u16, u16)`, `step(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, input: Input) -> Vec<Command>`. Re-exported as `pump::Pump`.
  - `pump::rig` (`#[cfg(test)]`, `pub(crate)`): `Rig { gfx, pump, cfg, t0, now, metrics }` with `new(PumpConfig)`, `with_slate(PumpConfig, Option<Slate>)`, `at(ms)`, `ms()`, `step(Input)`, `advertise(Vec<RawCapabilitySet>) -> Vec<GfxPdu>`, `negotiate(Vec<RawCapabilitySet>) -> Vec<Command>`, `start((u16, u16))`, `need_idr()`, `live()`, `ack(frame_id, QueueDepth)`, `hold_suppress(on: bool)`, `new_connection()`; free functions `cfg()`, `census_caps()`, `v8_only()`, `full_ladder()`, `params(&str) -> ParamSets`, `sps(ParamClass, &str) -> Input`, `au(idr, burst) -> Input`, `decode_msgs(&[DvcMessage]) -> Vec<GfxPdu>`, `pdus(&[Command]) -> Vec<GfxPdu>`, `names(&[GfxPdu]) -> Vec<&'static str>`, `kinds(&[Command]) -> Vec<&'static str>`, `wire(&[Command]) -> Vec<(Vec<u8>, u8, (u16, u16, u16, u16))>` (Annex-B, QP, rectangle), `nal_types(&[u8]) -> Vec<u8>`; constants `ES3` and `P480` (fixture names).

- [ ] **Step 1: Write the rig.** Replace `pump/mod.rs` with:

```rust
//! The EGFX pump (spec §4.3, §6.4–§6.6, §6.9): a sans-IO core (`core`) over
//! the flow, IDR and debounce cores, and an async shell (Task 5.3) that
//! only locks, steps and carries out commands.
pub mod core;
pub mod debounce;
pub mod flow;
pub mod idr;
#[cfg(test)]
pub(crate) mod rig;
pub mod slate;
pub mod types;

pub use core::Pump;
pub use types::{Command, DvcBatch, FlowConfig, IdrConfig, Input, PumpConfig, State};
```

and create `pump/rig.rs`:

```rust
//! The L1 rig (§11.2): a real `GraphicsPipelineServer` driven in memory,
//! an injected clock, real parameter sets from the fixtures, and a decoder
//! for everything the pump hands IronRDP.
//! The decoder is hand-rolled over IronRDP's own PDU types rather than an
//! `ironrdp_egfx::client::GraphicsPipelineClient` (DC17): the client pulls in
//! a decoder trait and surface bookkeeping the L1 asserts do not need, and
//! the L2 client (Task 6.1) is where a real client stack runs.
//! `dead_code` is allowed: some helpers are first used by Tasks 4.5–4.6.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
use crate::config::IdrPolicy;
use crate::metrics::Metrics;
use crate::msg::{FlvOrigin, KvmAu};
use crate::pump::core::Pump;
use crate::pump::slate::Slate;
use crate::pump::types::{Command, FlowConfig, IdrConfig, Input, PumpConfig, State};
use bytes::Bytes;
use ironrdp_core::{ReadCursor, decode, decode_cursor, encode_vec};
use ironrdp_dvc::{DvcMessage, DvcProcessor as _};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, CapabilitiesAdvertisePdu, CapabilitySet, CapabilityVersion, Codec1Type, FrameAcknowledgePdu,
    GfxPdu, QueueDepth, RawCapabilitySet,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_graphics::zgfx::Decompressor;
use kvm_proto::flv::mux::{TAG_VIDEO, avc_sequence_header_body, write_flv_header, write_tag};
use kvm_proto::flv::{FlvDemuxer, FlvLimits, Nal};
use kvm_proto::h264::split_annex_b;
use kvm_proto::video::{AccessUnit, AdmissionConfig, ParamClass, ParamSets, VideoAdmission};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const CHAN: u32 = 7;
/// The ES3-shaped POC-0 fixture (640×360, Baseline) and the 480p one.
pub(crate) const ES3: &str = "360p30_es3like_poc0.h264";
pub(crate) const P480: &str = "480p30_main_full.h264";

pub(crate) struct Null;
impl GraphicsPipelineHandler for Null {
    fn capabilities_advertise(&mut self, _: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _: &CapabilitySet) {}
}

/// FreeRDP's `/gfx:AVC420` pair, as recorded in `census.md` (Legs B, C).
pub(crate) fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

/// A client without AVC420.
pub(crate) fn v8_only() -> Vec<RawCapabilitySet> {
    vec![RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0])]
}

/// IronRDP's own 11-set ladder (the shape of FreeRDP's no-`/gfx` ladder, DC8).
pub(crate) fn full_ladder() -> Vec<RawCapabilitySet> {
    CapabilitiesAdvertisePdu::from_typed(&Null.preferred_capabilities()).0
}

/// The spec defaults (§4.4), `side` policy.
pub(crate) fn cfg() -> PumpConfig {
    PumpConfig {
        hard_cap: 60,
        flow: FlowConfig {
            soft_gate: Duration::from_millis(500),
            backlog_limit: 4 << 20,
            standing_delay_limit: Duration::from_millis(500),
            first_ack_grace: Duration::from_millis(1600),
            stall_timeout: Duration::from_secs(10),
        },
        idr: IdrConfig {
            policy: IdrPolicy::Side,
            side_timeout: Duration::from_secs(1),
            wait_max: Duration::from_secs(3),
            interval_setup: Duration::from_secs(1),
            interval_flow: Duration::from_secs(10),
        },
        rtt_probe_interval: Duration::from_millis(250),
        burst_chunk: 8,
        avc420_timeout: Duration::from_secs(10),
        suppress_debounce: Duration::from_secs(1),
        disconnect_watchdog: Duration::from_secs(5),
        region_qp: 22,
    }
}

/// A fixture's rewritten, admitted parameter sets (through kvm-proto).
pub(crate) fn params(fixture: &str) -> ParamSets {
    let src = kvm_sim::Source::fixture(fixture).unwrap();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let body = avc_sequence_header_body(&[&src.sps], &[&src.pps], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &body).unwrap();
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let tag = d.next_tag().unwrap().unwrap();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(tag, Instant::now()).unwrap().params.unwrap().params
}

pub(crate) fn sps(class: ParamClass, fixture: &str) -> Input {
    Input::SpsChanged { class, params: params(fixture) }
}

/// A one-NAL access unit (the pump never parses slice data).
pub(crate) fn au(idr: bool, burst: bool) -> Input {
    let nal: &'static [u8] = if idr { &[0x65, 0x88, 0x84, 0x21] } else { &[0x41, 0x9a, 0x02, 0x10] };
    Input::Au(KvmAu {
        au: AccessUnit { flv_timestamp_ms: 0, idr, burst, aud: None, vcl: vec![Nal { bytes: Bytes::from_static(nal) }] },
        after_drop: false,
        received: Instant::now(),
    })
}

/// Every GFX PDU in a batch of server→client DVC messages (ZGFX-unwrapped).
pub(crate) fn decode_msgs(msgs: &[DvcMessage]) -> Vec<GfxPdu> {
    let mut out = Vec::new();
    for m in msgs {
        let wrapped = encode_vec(m.as_ref()).unwrap();
        let mut plain = Vec::new();
        Decompressor::new().decompress(&wrapped, &mut plain).unwrap();
        let mut cur = ReadCursor::new(&plain);
        while !cur.is_empty() {
            out.push(decode_cursor::<GfxPdu>(&mut cur).unwrap());
        }
    }
    out
}

pub(crate) fn pdus(cmds: &[Command]) -> Vec<GfxPdu> {
    cmds.iter()
        .filter_map(|c| if let Command::SendDvc(b) = c { Some(decode_msgs(&b.messages)) } else { None })
        .flatten()
        .collect()
}

pub(crate) fn names(pdus: &[GfxPdu]) -> Vec<&'static str> {
    pdus.iter()
        .map(|p| match p {
            GfxPdu::CapabilitiesConfirm(_) => "CapabilitiesConfirm",
            GfxPdu::ResetGraphics(_) => "ResetGraphics",
            GfxPdu::CreateSurface(_) => "CreateSurface",
            GfxPdu::DeleteSurface(_) => "DeleteSurface",
            GfxPdu::MapSurfaceToOutput(_) => "MapSurfaceToOutput",
            GfxPdu::StartFrame(_) => "StartFrame",
            GfxPdu::WireToSurface1(_) => "WireToSurface1",
            GfxPdu::EndFrame(_) => "EndFrame",
            GfxPdu::CacheImportReply(_) => "CacheImportReply",
            _ => "Other",
        })
        .collect()
}

pub(crate) fn kinds(cmds: &[Command]) -> Vec<&'static str> {
    cmds.iter().map(Command::kind).collect()
}

/// Each `WireToSurface1`'s Annex-B payload, QP and destination rectangle;
/// every one must be AVC420 (§11.2: "only AVC420 `WireToSurface1` is ever
/// sent"), so every L1 case that looks at a frame asserts the codec.
pub(crate) fn wire(cmds: &[Command]) -> Vec<(Vec<u8>, u8, (u16, u16, u16, u16))> {
    pdus(cmds)
        .into_iter()
        .filter_map(|p| if let GfxPdu::WireToSurface1(w) = p { Some(w) } else { None })
        .map(|w| {
            assert_eq!(w.codec_id, Codec1Type::Avc420, "only AVC420 is ever sent (§11.2)");
            let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
            let r = &s.rectangles[0];
            (s.data.to_vec(), s.quant_qual_vals[0].quantization_parameter, (r.left, r.top, r.right, r.bottom))
        })
        .collect()
}

pub(crate) fn nal_types(annex_b: &[u8]) -> Vec<u8> {
    split_annex_b(annex_b).map(|n| n[0] & 0x1F).collect()
}

pub(crate) struct Rig {
    pub gfx: GraphicsPipelineServer,
    pub pump: Pump,
    pub cfg: PumpConfig,
    pub t0: Instant,
    pub now: Instant,
    pub metrics: Arc<Metrics>,
}

impl Rig {
    pub fn new(cfg: PumpConfig) -> Rig {
        Rig::with_slate(cfg, None)
    }

    pub fn with_slate(cfg: PumpConfig, slate: Option<Slate>) -> Rig {
        let mut gfx = GraphicsPipelineServer::new(Box::new(Null));
        gfx.start(CHAN).unwrap();
        let metrics = Arc::new(Metrics::default());
        let t0 = Instant::now();
        Rig { gfx, pump: Pump::with_slate(cfg.clone(), metrics.clone(), slate), cfg, t0, now: t0, metrics }
    }

    pub fn at(&mut self, ms: u64) {
        self.now = self.t0 + Duration::from_millis(ms);
    }

    pub fn ms(&self) -> u64 {
        u64::try_from(self.now.duration_since(self.t0).as_millis()).unwrap()
    }

    pub fn step(&mut self, input: Input) -> Vec<Command> {
        self.pump.step(&mut self.gfx, self.now, input)
    }

    /// The client advertises; returns what IronRDP itself answered.
    pub fn advertise(&mut self, sets: Vec<RawCapabilitySet>) -> Vec<GfxPdu> {
        let pdu = GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(sets));
        decode_msgs(&self.gfx.process(CHAN, &encode_vec(&pdu).unwrap()).unwrap())
    }

    /// Advertise, then tell the pump what IronRDP negotiated (`on_ready`).
    pub fn negotiate(&mut self, sets: Vec<RawCapabilitySet>) -> Vec<Command> {
        self.advertise(sets);
        let avc420 = self.gfx.supports_avc420();
        self.step(Input::OnReady { avc420 })
    }

    pub fn start(&mut self, size: (u16, u16)) -> Vec<Command> {
        self.step(Input::SessionStart { generation: 1, size })
    }

    /// 640×360 session, census capabilities, the first FLV's Initial sets.
    pub fn need_idr(&mut self) -> Vec<Command> {
        let mut out = self.start((640, 360));
        out.extend(self.negotiate(census_caps()));
        out.extend(self.step(Input::FlvOpened { origin: FlvOrigin::First }));
        out.extend(self.step(sps(ParamClass::Initial, ES3)));
        assert_eq!(self.pump.state(), State::NeedIdr);
        out
    }

    /// `need_idr` plus the first KVM IDR (frame id 0).
    pub fn live(&mut self) -> Vec<Command> {
        let mut out = self.need_idr();
        out.extend(self.step(au(true, false)));
        assert_eq!(self.pump.state(), State::Live);
        out
    }

    /// The client acknowledges `frame_id`: IronRDP first, then the pump.
    pub fn ack(&mut self, frame_id: u32, depth: QueueDepth) -> Vec<Command> {
        let queue_depth = depth.to_u32();
        let pdu = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::from_u32(queue_depth),
            frame_id,
            total_frames_decoded: 0,
        });
        let _ = self.gfx.process(CHAN, &encode_vec(&pdu).unwrap()).unwrap();
        self.step(Input::FrameAck { frame_id, queue_depth })
    }

    /// Suppression held at `on` for the debounce time (one edge).
    pub fn hold_suppress(&mut self, on: bool) -> Vec<Command> {
        let mut out = self.step(Input::Suppress(on));
        let later = self.ms() + u64::try_from(self.cfg.suppress_debounce.as_millis()).unwrap();
        self.at(later);
        out.extend(self.step(Input::Suppress(on)));
        out
    }

    /// A new RDP connection: a fresh `GraphicsPipelineServer` (one per
    /// connection, as IronRDP builds them), the same pump.
    pub fn new_connection(&mut self) {
        let mut gfx = GraphicsPipelineServer::new(Box::new(Null));
        gfx.start(CHAN).unwrap();
        self.gfx = gfx;
    }
}
```

- [ ] **Step 2: Write the failing tests.** Create `pump/debounce.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    /// §6.6: only edges held for `suppress_debounce` count.
    #[test]
    fn only_held_edges_count() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut d = Debounce::new(Duration::from_secs(1));
        assert_eq!(d.sample(at(0), true), None);
        assert_eq!(d.sample(at(500), false), None, "a short pulse");
        assert_eq!(d.sample(at(2000), false), None);
        assert_eq!(d.sample(at(2000), true), None);
        assert_eq!(d.sample(at(2999), true), None);
        assert_eq!(d.sample(at(3000), true), Some(Edge::On));
        assert_eq!(d.sample(at(3500), true), None);
        assert_eq!(d.sample(at(4000), false), None);
        assert_eq!(d.sample(at(5000), false), Some(Edge::Off));
    }
}
```

and `pump/core.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use ironrdp_egfx::pdu::{CapabilityVersion, GfxPdu, QueueDepth};

    /// §11.2 "Every policy": connecting costs exactly one FLV open, and the
    /// first FLV's NeedIdr requests nothing.
    #[test]
    fn connecting_costs_exactly_one_flv_open() {
        for policy in [IdrPolicy::Side, IdrPolicy::Reconnect, IdrPolicy::Wait] {
            let mut c = cfg();
            c.idr.policy = policy;
            let mut r = Rig::new(c);
            let mut out = r.start((640, 360));
            assert_eq!(r.pump.state(), State::WaitReady);
            out.extend(r.negotiate(census_caps()));
            assert_eq!(r.pump.state(), State::NeedIdr);
            out.extend(r.step(Input::FlvOpened { origin: FlvOrigin::First }));
            out.extend(r.step(sps(ParamClass::Initial, ES3)));
            for i in 1..=20 {
                r.at(i * 100);
                out.extend(r.step(Input::Tick));
            }
            out.extend(r.step(au(true, false)));
            assert_eq!(r.pump.state(), State::Live);
            let k = kinds(&out);
            assert_eq!(k.iter().filter(|k| **k == "OpenFlv").count(), 1, "{policy:?}");
            assert!(!k.contains(&"RequestIdr") && !k.contains(&"ReconnectFlv"), "{policy:?}: {k:?}");
        }
    }

    /// §6.3: the first KVM AU is an IDR carrying the cached SPS and PPS, on
    /// the current surface's full frame at `region_qp`.
    #[test]
    fn the_first_kvm_au_is_an_idr_carrying_sps_and_pps() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        let out = r.step(au(true, false));
        assert_eq!(names(&pdus(&out)), ["StartFrame", "WireToSurface1", "EndFrame"]);
        let w = wire(&out);
        let (annex_b, qp, rect) = &w[0];
        assert_eq!(nal_types(annex_b), [7, 8, 5]);
        let p = params(ES3);
        assert!(annex_b.windows(p.sps.len()).any(|x| x == p.sps.as_ref()), "the rewritten SPS");
        assert_eq!((*qp, *rect), (22, (0, 0, 640, 360)));
        assert_eq!(r.metrics.frames_sent.get(), 1);
        let later = r.step(au(false, false));
        assert_eq!(nal_types(&wire(&later)[0].0), [1], "P frames carry no parameter sets");
    }

    #[test]
    fn p_frames_wait_for_an_idr() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert!(pdus(&r.step(au(false, false))).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("awaiting_idr"), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §6.1's classes: `initial` at the current size raises no NeedIdr; at
    /// another size it starts a resize.
    #[test]
    fn an_initial_sps_resizes_only_at_another_size() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Initial, ES3));
        assert_eq!(r.pump.state(), State::Live);
        let out = r.step(sps(ParamClass::Initial, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        assert!(matches!(out.last(), Some(Command::DisplayResize { width: 854, height: 480 })), "{out:?}");
        assert_eq!(r.pump.size(), (854, 480));
    }

    /// §6.1 `other`: a flow cause — NeedIdr, never a reconnect, and a request
    /// only after `idr_wait_max` of open gates, on the flow clock the first
    /// FLV open started.
    #[test]
    fn an_other_sps_is_a_flow_cause_never_a_reconnect() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        assert_eq!(r.metrics.ack_rtt.count(), 1, "§10.4 ack RTT: handed → acknowledged");
        let mut out = r.step(sps(ParamClass::Other, ES3));
        assert_eq!(r.pump.state(), State::NeedIdr);
        for i in 1..=105 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        let k = kinds(&out);
        assert!(!k.contains(&"ReconnectFlv"), "{k:?}");
        assert_eq!(k.iter().filter(|k| **k == "RequestIdr").count(), 1, "deferred to the flow window's end");
    }

    /// §6.6: `send_avc420_frame` returning `None` is a flow cause and a metric.
    #[test]
    fn send_none_drops_to_need_idr() {
        let mut r = Rig::new(cfg());
        r.live();
        r.advertise(v8_only()); // IronRDP renegotiated; the pump is not told yet
        assert!(pdus(&r.step(au(true, false))).is_empty());
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(r.metrics.frames_dropped.get("send_none"), 1);
    }

    /// §6.4 slate: on the first Setup, only when the surface matches it.
    #[test]
    fn the_slate_precedes_the_first_kvm_idr_only_when_the_surface_matches() {
        let mut r = Rig::with_slate(cfg(), Slate::embedded());
        r.start((1920, 1080));
        let n = names(&pdus(&r.negotiate(census_caps())));
        assert_eq!(
            n,
            ["ResetGraphics", "CreateSurface", "MapSurfaceToOutput", "StartFrame", "WireToSurface1", "EndFrame"]
        );
        assert_eq!(r.metrics.frames_sent.get(), 0, "the slate is not a KVM frame");
        let mut r = Rig::with_slate(cfg(), Slate::embedded());
        r.start((640, 360));
        let n = names(&pdus(&r.negotiate(census_caps())));
        assert_eq!(n, ["ResetGraphics", "CreateSurface", "MapSurfaceToOutput"]);
    }

    /// §11.2: after Live, a second CapsAdvertise produces exactly
    /// CapabilitiesConfirm, ResetGraphics (w, h, one monitor), CreateSurface,
    /// MapSurfaceToOutput, StartFrame, WireToSurface1 (IDR with SPS/PPS),
    /// EndFrame — no DeleteSurface, no P-frame before the IDR.
    #[test]
    fn a_readvertise_after_live_is_exactly_setup_then_an_idr() {
        let mut r = Rig::new(cfg());
        r.live();
        let mut seen = r.advertise(census_caps());
        let avc420 = r.gfx.supports_avc420();
        let mut out = r.step(Input::OnReady { avc420 });
        out.extend(r.step(au(false, false)));
        out.extend(r.step(au(true, false)));
        seen.extend(pdus(&out));
        assert_eq!(
            names(&seen),
            ["CapabilitiesConfirm", "ResetGraphics", "CreateSurface", "MapSurfaceToOutput", "StartFrame", "WireToSurface1", "EndFrame"]
        );
        let GfxPdu::ResetGraphics(rg) = &seen[1] else { panic!("{:?}", names(&seen)) };
        assert_eq!((rg.width, rg.height, rg.monitors.len()), (640, 360, 1));
        assert_eq!((rg.monitors[0].right, rg.monitors[0].bottom), (639, 359), "inclusive bounds (§6.4)");
        assert_eq!(nal_types(&wire(&out)[0].0), [7, 8, 5]);
    }

    /// §11.2: each replayed advertise yields the confirm the census recorded.
    #[test]
    fn capability_replays_confirm_what_the_census_recorded() {
        let mut r = Rig::new(cfg());
        let c = r.advertise(census_caps());
        let [GfxPdu::CapabilitiesConfirm(c)] = c.as_slice() else { panic!("{c:?}") };
        assert_eq!((c.0.version, c.0.data.as_slice()), (CapabilityVersion::V8_1, &[0x12, 0, 0, 0][..]));
        assert!(r.gfx.supports_avc420());
        let mut r = Rig::new(cfg());
        let c = r.advertise(full_ladder());
        let [GfxPdu::CapabilitiesConfirm(c)] = c.as_slice() else { panic!("{c:?}") };
        assert_eq!(c.0.version, CapabilityVersion::V10_7);
        assert!(r.gfx.supports_avc420());
        let mut r = Rig::new(cfg());
        r.advertise(v8_only());
        assert!(!r.gfx.supports_avc420());
    }

    /// §6.5 source bursts: exempt from the soft gate, sent in chunks of
    /// `burst_chunk` (one event each, with a yield), counted against the
    /// hard cap; past it, truncated — a flow cause.
    #[test]
    fn bursts_are_chunked_and_truncated_at_the_hard_cap() {
        let mut c = cfg();
        c.hard_cap = 12;
        let mut r = Rig::new(c);
        r.live(); // the IDR is in flight: 11 more fit
        let mut out = Vec::new();
        for _ in 0..20 {
            // As the shell feeds them (DC6): samples before every AU. They
            // must not flush a half-filled chunk.
            out.extend(r.step(Input::Suppress(false)));
            out.extend(r.step(Input::Backlog { written: 0 }));
            out.extend(r.step(au(false, true)));
        }
        out.extend(r.step(Input::Tick));
        let batches: Vec<(u32, bool)> = out
            .iter()
            .filter_map(|c| if let Command::SendDvc(b) = c { Some((b.frames, b.yield_after)) } else { None })
            .collect();
        assert_eq!(batches, [(8, true), (3, true)]);
        assert_eq!(r.metrics.frames_dropped.get("burst_truncated"), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §4.3 generations: a stop for another generation is ignored; the
    /// current one's stop returns to Idle, where nothing reaches IronRDP.
    #[test]
    fn only_the_current_generations_stop_ends_the_session() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::SessionStop { generation: 7 });
        assert_eq!(r.pump.state(), State::Live);
        r.step(Input::SessionStop { generation: 1 });
        assert_eq!((r.pump.state(), r.pump.generation()), (State::Idle, 0));
        assert!(r.step(au(true, false)).is_empty());
        assert!(r.step(Input::Tick).is_empty());
    }
}
```

- [ ] **Step 3: Run them to see them fail.** `cargo test --workspace --all-features --lib -- pump::` — Expected: FAIL to compile (`Pump`, `Debounce` not found).

- [ ] **Step 4: Implement the debounce.** Above the tests in `pump/debounce.rs`:

```rust
//! §6.6 display suppression: IronRDP exposes it as a polled flag clients
//! pulse; only edges held for `suppress_debounce` count.
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    On,
    Off,
}

pub struct Debounce {
    hold: Duration,
    stable: bool,
    raw: bool,
    since: Option<Instant>,
}

impl Debounce {
    #[must_use]
    pub fn new(hold: Duration) -> Debounce {
        Debounce { hold, stable: false, raw: false, since: None }
    }

    pub fn sample(&mut self, now: Instant, raw: bool) -> Option<Edge> {
        if raw != self.raw {
            self.raw = raw;
            self.since = Some(now);
        }
        if raw == self.stable {
            self.since = None;
            return None;
        }
        let since = *self.since.get_or_insert(now);
        if now.saturating_duration_since(since) >= self.hold {
            self.stable = raw;
            self.since = None;
            return Some(if raw { Edge::On } else { Edge::Off });
        }
        None
    }
}
```

- [ ] **Step 5: Implement the core.** Above the tests in `pump/core.rs`:

```rust
//! The EGFX pump's sans-IO core (§4.3, §6.4–§6.6, §6.9). `step` takes one
//! input and the time, drives the `GraphicsPipelineServer` the caller has
//! locked — Setup, `send_avc420_frame` and `drain_output` in one hold — and
//! returns the commands the shell carries out. §6.4's state × input table is
//! the dispatch below (every cell is a case in Task 4.6).
use crate::config::IdrPolicy;
use crate::hid::ReleaseTrigger;
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, KvmAu};
use crate::pump::debounce::{Debounce, Edge};
use crate::pump::flow::{Flow, Gate};
use crate::pump::idr::{IdrAction, IdrCore};
use crate::pump::slate::Slate;
use crate::pump::types::{Command, DvcBatch, Input, PumpConfig, State};
use ironrdp_core::Encode as _;
use ironrdp_egfx::pdu::Avc420Region;
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use kvm_proto::video::{ParamClass, ParamSets};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Pump {
    cfg: PumpConfig,
    metrics: Arc<Metrics>,
    slate: Option<Slate>,
    state: State,
    generation: Gen,
    started: Instant,
    /// The size `size()` reports and the next Setup uses (§5.1, §6.4).
    size: (u16, u16),
    /// `(surface id, width, height)` of the latest Setup.
    surface: Option<(u16, u16, u16)>,
    pending_size: Option<(u16, u16)>,
    return_to_paused: bool,
    /// An AVC420 `on_ready` was seen this session.
    ready_seen: bool,
    first_setup_done: bool,
    avc420_deadline: Option<Instant>,
    params: Option<ParamSets>,
    flow: Flow,
    idr: IdrCore,
    suppress: Debounce,
    suppressed: bool,
    /// A ReleaseAll already went out for the current suppression edge.
    released_for_edge: bool,
    kvm_frame_delivered: bool,
    closing: Option<(Instant, Duration)>,
    aborted: bool,
    next_probe: Option<Instant>,
    /// A burst chunk being filled (§6.5).
    batch: Option<DvcBatch>,
    /// The one reused Annex-B buffer (§6.2 ownership).
    annexb: Vec<u8>,
}

impl Pump {
    #[must_use]
    pub fn new(cfg: PumpConfig, metrics: Arc<Metrics>) -> Pump {
        Pump::with_slate(cfg, metrics, Slate::embedded())
    }

    #[must_use]
    pub fn with_slate(cfg: PumpConfig, metrics: Arc<Metrics>, slate: Option<Slate>) -> Pump {
        Pump {
            flow: Flow::new(cfg.flow),
            idr: IdrCore::new(cfg.idr),
            suppress: Debounce::new(cfg.suppress_debounce),
            cfg,
            metrics,
            slate,
            state: State::Idle,
            generation: 0,
            started: Instant::now(),
            size: (0, 0),
            surface: None,
            pending_size: None,
            return_to_paused: false,
            ready_seen: false,
            first_setup_done: false,
            avc420_deadline: None,
            params: None,
            suppressed: false,
            released_for_edge: false,
            kvm_frame_delivered: false,
            closing: None,
            aborted: false,
            next_probe: None,
            batch: None,
            annexb: Vec::new(),
        }
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn generation(&self) -> Gen {
        self.generation
    }

    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    pub fn step(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, input: Input) -> Vec<Command> {
        let mut out = Vec::new();
        // A burst chunk (§6.5) fills across consecutive burst AUs. The shell
        // samples `Suppress`, `Backlog` and acks between AUs (DC6); those
        // must not split a chunk, so they flush it only if they change the
        // state. Anything else — a live AU, a tick (every 50 ms), a session
        // or Setup input — flushes it first.
        let sample = matches!(&input, Input::Suppress(_) | Input::Backlog { .. } | Input::Rtt(_) | Input::FrameAck { .. });
        if !sample && !matches!(&input, Input::Au(a) if a.au.burst) {
            self.flush_batch(&mut out);
        }
        let before = self.state;
        match input {
            Input::SessionStart { generation, size } => self.start(generation, size, now),
            Input::SessionStop { generation } => {
                if generation == self.generation {
                    self.reset();
                }
            }
            other if self.state != State::Idle => self.session_input(gfx, now, other, &mut out),
            Input::Au(_) => self.metrics.frames_dropped.inc("not_ready"),
            _ => {}
        }
        if sample
            && self.state != before
            && let Some(b) = self.batch.take()
        {
            // The chunk's frames came before the state change: send them first.
            out.insert(0, Command::SendDvc(b));
        }
        if self.state != State::Idle {
            self.gauges(gfx, now);
        }
        out
    }

    fn session_input(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, input: Input, out: &mut Vec<Command>) {
        match input {
            Input::UpstreamFatal(cause) => self.close(now, cause, self.cfg.disconnect_watchdog, out),
            Input::Shutdown { watchdog } => {
                self.close(now, Cause::Shutdown, watchdog.min(self.cfg.disconnect_watchdog), out);
            }
            Input::FrameAck { frame_id, queue_depth } => {
                // §10.4 ack RTT: handed to IronRDP → acknowledged.
                if let Some(at) = self.flow.sent_at(frame_id) {
                    self.metrics.ack_rtt.observe(now.saturating_duration_since(at));
                }
                self.flow.on_ack(frame_id, queue_depth);
            }
            Input::Backlog { written } => self.flow.set_written(written),
            Input::Rtt(v) => {
                // Only a live sample shows: never the stale reference.
                if self.flow.rtt_sample(v) {
                    self.metrics.autodetect_rtt_ms.set(i64::from(v));
                }
            }
            Input::Tick => self.on_tick(gfx, now, out),
            Input::Au(_) if self.state == State::Closing => self.metrics.frames_dropped.inc("closing"),
            _ if self.state == State::Closing => {}
            Input::OnReady { avc420 } => self.on_ready(gfx, now, avc420, out),
            Input::ReactivationComplete => self.on_reactivated(gfx, now, out),
            Input::Suppress(raw) => self.on_suppress(now, raw, out),
            Input::SpsChanged { class, params } => self.on_sps(now, class, params, out),
            Input::FlvOpened { .. } => self.on_flv_opened(now, out),
            Input::Au(au) => self.on_au(gfx, now, au, out),
            Input::SessionStart { .. } | Input::SessionStop { .. } => {}
        }
    }

    fn start(&mut self, generation: Gen, size: (u16, u16), now: Instant) {
        self.reset();
        self.state = State::WaitReady;
        self.generation = generation;
        self.started = now;
        self.size = size;
        self.avc420_deadline = Some(now + self.cfg.avc420_timeout);
        self.next_probe = Some(now + self.cfg.rtt_probe_interval);
    }

    /// Fresh per-session state (generations never share anything, §4.3).
    fn reset(&mut self) {
        let (cfg, metrics, slate) = (self.cfg.clone(), self.metrics.clone(), self.slate.take());
        let annexb = std::mem::take(&mut self.annexb);
        *self = Pump::with_slate(cfg, metrics, slate);
        self.annexb = annexb;
    }

    fn set_state(&mut self, now: Instant, new: State, out: &mut Vec<Command>) {
        if self.state == new {
            return;
        }
        if self.state == State::NeedIdr && self.idr.resolve() {
            self.metrics.idr_cancelled.inc();
            out.push(Command::CancelIdrRequest);
        }
        self.flow.set_frozen(now, matches!(new, State::Paused | State::WaitReactivation));
        self.state = new;
    }

    /// Setup (§6.4): ResetGraphics with one PRIMARY monitor (inclusive
    /// bounds), CreateSurface, MapSurfaceToOutput, the hard cap; the slate
    /// and `OpenFlv` on the connection's first Setup.
    fn setup(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, out: &mut Vec<Command>) -> bool {
        let (w, h) = self.size;
        let monitor = Monitor {
            left: 0,
            top: 0,
            right: i32::from(w).saturating_sub(1),
            bottom: i32::from(h).saturating_sub(1),
            flags: MonitorFlags::PRIMARY,
        };
        gfx.resize_with_monitors(w, h, vec![monitor]);
        let Some(sid) = gfx.create_surface(w, h) else {
            tracing::warn!("EGFX Setup failed: no surface");
            return false;
        };
        if !gfx.map_surface_to_output(sid, 0, 0) {
            return false;
        }
        gfx.set_max_frames_in_flight(self.cfg.hard_cap);
        self.surface = Some((sid, w, h));
        self.flow.on_setup();
        out.push(Command::SurfaceSize { width: w, height: h });
        let first = !self.first_setup_done;
        let mut frames = 0;
        if first && self.slate.as_ref().is_some_and(|s| s.size == (w, h)) && self.send_slate(gfx, now) {
            frames = 1;
        }
        self.drain(gfx, out, None, frames, false);
        if first {
            self.first_setup_done = true;
            out.push(Command::OpenFlv);
        }
        true
    }

    fn send_slate(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant) -> bool {
        let (Some(slate), Some((sid, w, h))) = (self.slate.as_ref(), self.surface) else {
            return false;
        };
        let region = Avc420Region::full_frame(w, h, self.cfg.region_qp);
        let suspended = gfx.is_ack_suspended();
        match gfx.send_avc420_frame(sid, &slate.annex_b, &[region], self.timestamp(now)) {
            Some(id) => {
                self.flow.record(id, now, false, true, suspended);
                true
            }
            None => false,
        }
    }

    fn timestamp(&self, now: Instant) -> u32 {
        let ms = now.saturating_duration_since(self.started).as_millis() & 0xFFFF_FFFF;
        u32::try_from(ms).unwrap_or(0)
    }

    /// Drain IronRDP's queue into one batch (or the burst chunk).
    fn drain(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        out: &mut Vec<Command>,
        received: Option<Instant>,
        frames: u32,
        burst: bool,
    ) {
        let messages = gfx.drain_output();
        if messages.is_empty() {
            return;
        }
        let Some(channel_id) = gfx.channel_id() else { return };
        let weight = messages
            .iter()
            .fold(0u64, |a, m| a.saturating_add(u64::try_from(m.size()).unwrap_or(u64::MAX)));
        self.flow.add_handed(weight);
        if !burst {
            out.push(Command::SendDvc(DvcBatch { channel_id, messages, weight, frames, received, yield_after: false }));
            return;
        }
        let full = {
            let b = self.batch.get_or_insert_with(|| DvcBatch {
                channel_id,
                messages: Vec::new(),
                weight: 0,
                frames: 0,
                received,
                yield_after: true,
            });
            b.messages.extend(messages);
            b.weight = b.weight.saturating_add(weight);
            b.frames = b.frames.saturating_add(frames);
            b.frames >= self.cfg.burst_chunk
        };
        if full {
            self.flush_batch(out);
        }
    }

    fn flush_batch(&mut self, out: &mut Vec<Command>) {
        if let Some(b) = self.batch.take() {
            out.push(Command::SendDvc(b));
        }
    }

    fn push_idr(&mut self, a: IdrAction, out: &mut Vec<Command>) {
        match a {
            IdrAction::RequestIdr => out.push(Command::RequestIdr),
            IdrAction::ReconnectFlv => out.push(Command::ReconnectFlv),
            IdrAction::FallbackReconnect => {
                self.metrics.idr_side_fallbacks.inc();
                out.push(Command::ReconnectFlv);
            }
        }
    }

    fn setup_cause(&mut self, now: Instant, out: &mut Vec<Command>) {
        if let Some(a) = self.idr.setup_cause(now) {
            self.push_idr(a, out);
        }
    }

    fn flow_cause(&mut self, now: Instant) {
        self.idr.flow_cause(now);
    }

    fn close(&mut self, now: Instant, cause: Cause, watchdog: Duration, out: &mut Vec<Command>) {
        if self.state == State::Closing {
            return;
        }
        self.set_state(now, State::Closing, out);
        self.closing = Some((now, watchdog));
        self.batch = None; // stop all EGFX sends before the disconnect (§6.9)
        self.avc420_deadline = None;
        self.metrics.disconnects.inc(cause.label());
        out.push(Command::ReleaseAll(ReleaseTrigger::Closing));
        out.push(Command::Disconnect(cause));
    }

    fn on_ready(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, avc420: bool, out: &mut Vec<Command>) {
        if !avc420 {
            if self.state == State::WaitReady && !self.ready_seen {
                // First negotiation: wait `avc420_timeout` for a better one (§6.7).
                tracing::info!("EGFX negotiated without AVC420; waiting for a better capability set");
                return;
            }
            self.close(now, Cause::NoAvc420, self.cfg.disconnect_watchdog, out);
            return;
        }
        match self.state {
            State::WaitReady => {
                self.ready_seen = true;
                self.avc420_deadline = None;
                self.setup(gfx, now, out);
                match self.pending_size.take() {
                    Some(size) if size != self.size => self.start_resize(now, size, false, out),
                    _ => self.set_state(now, State::NeedIdr, out),
                }
            }
            State::NeedIdr | State::Live => {
                self.setup(gfx, now, out);
                self.set_state(now, State::NeedIdr, out);
                self.setup_cause(now, out);
            }
            // Merged: the Setup runs at ReactivationComplete.
            State::WaitReactivation => self.ready_seen = true,
            State::Paused => {
                self.setup(gfx, now, out);
            }
            State::Idle | State::Closing => {}
        }
    }

    /// Start resize (§6.4): stop sends, take the new size, emit
    /// `DisplayUpdate::Resize`. The only resize path.
    fn start_resize(&mut self, now: Instant, size: (u16, u16), return_to_paused: bool, out: &mut Vec<Command>) {
        self.set_state(now, State::WaitReactivation, out);
        self.size = size;
        self.pending_size = None;
        self.return_to_paused = return_to_paused;
        self.batch = None;
        out.push(Command::DisplayResize { width: size.0, height: size.1 });
    }

    fn on_reactivated(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, out: &mut Vec<Command>) {
        if self.state != State::WaitReactivation {
            return;
        }
        if self.ready_seen {
            self.setup(gfx, now, out);
        }
        if let Some(size) = self.pending_size.take()
            && size != self.size
        {
            let back = self.return_to_paused;
            self.start_resize(now, size, back, out);
            return;
        }
        if self.suppressed || self.return_to_paused {
            self.return_to_paused = false;
            self.enter_paused(now, out);
        } else if !self.ready_seen {
            self.set_state(now, State::WaitReady, out);
        } else {
            self.set_state(now, State::NeedIdr, out);
            self.setup_cause(now, out);
        }
    }

    fn enter_paused(&mut self, now: Instant, out: &mut Vec<Command>) {
        if !self.released_for_edge {
            self.released_for_edge = true;
            out.push(Command::ReleaseAll(ReleaseTrigger::Suppression));
        }
        self.set_state(now, State::Paused, out);
    }

    fn on_suppress(&mut self, now: Instant, raw: bool, out: &mut Vec<Command>) {
        if !self.kvm_frame_delivered {
            return; // mstsc pulses it during connect (§6.6)
        }
        let Some(edge) = self.suppress.sample(now, raw) else { return };
        match edge {
            Edge::On => {
                self.suppressed = true;
                match self.state {
                    State::NeedIdr | State::Live => self.enter_paused(now, out),
                    State::WaitReactivation if !self.released_for_edge => {
                        self.released_for_edge = true;
                        out.push(Command::ReleaseAll(ReleaseTrigger::Suppression));
                    }
                    _ => {}
                }
            }
            Edge::Off => {
                self.suppressed = false;
                self.released_for_edge = false;
                if self.state == State::Paused {
                    self.set_state(now, State::NeedIdr, out);
                    self.setup_cause(now, out);
                }
            }
        }
    }

    fn on_sps(&mut self, now: Instant, class: ParamClass, params: ParamSets, out: &mut Vec<Command>) {
        let (Ok(w), Ok(h)) = (u16::try_from(params.summary.width), u16::try_from(params.summary.height)) else {
            self.close(now, Cause::StreamIncompatible, self.cfg.disconnect_watchdog, out);
            return;
        };
        let new = (w, h);
        let sized = matches!(class, ParamClass::Initial | ParamClass::Resize);
        let needs_resize = sized && new != self.size;
        let flow = !needs_resize && matches!(class, ParamClass::Other | ParamClass::Resize);
        self.params = Some(params);
        match self.state {
            State::WaitReady | State::WaitReactivation => {
                if sized {
                    self.pending_size = (new != self.size).then_some(new);
                }
            }
            State::NeedIdr => {
                if needs_resize {
                    self.start_resize(now, new, false, out);
                } else if flow {
                    self.flow_cause(now);
                }
            }
            State::Live => {
                if needs_resize {
                    self.start_resize(now, new, false, out);
                } else if flow {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
            }
            State::Paused => {
                if needs_resize {
                    self.start_resize(now, new, true, out);
                }
            }
            State::Idle | State::Closing => {}
        }
    }

    fn on_flv_opened(&mut self, now: Instant, out: &mut Vec<Command>) {
        match self.state {
            State::Live | State::NeedIdr | State::Paused => {
                if self.state == State::Live {
                    self.set_state(now, State::NeedIdr, out);
                }
                // The NeedIdr waits for this connection's first IDR; an open
                // never requests one (§6.5).
                self.idr.flv_opened(now);
                self.flow.on_flv_opened();
            }
            State::WaitReady | State::WaitReactivation | State::Idle | State::Closing => {}
        }
    }

    fn on_au(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, a: KvmAu, out: &mut Vec<Command>) {
        if a.after_drop {
            // An AU was dropped on a full channel: a flow cause (DC12).
            match self.state {
                State::Live => {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
                State::NeedIdr => self.flow_cause(now),
                _ => {}
            }
        }
        let dropped = match self.state {
            State::NeedIdr | State::Live => None,
            State::Paused => Some("paused"),
            State::WaitReactivation => Some("wait_reactivation"),
            State::WaitReady | State::Idle => Some("not_ready"),
            State::Closing => Some("closing"),
        };
        if let Some(reason) = dropped {
            self.metrics.frames_dropped.inc(reason);
            return;
        }
        let suspended = gfx.is_ack_suspended();
        let gate = self.flow.gates(now, a.au.burst, suspended, gfx.should_backpressure());
        if self.state == State::NeedIdr {
            if let Some(act) = self.idr.observe_gates(now, gate.is_open()) {
                self.push_idr(act, out);
            }
            if !a.au.idr {
                self.metrics.frames_dropped.inc("awaiting_idr");
                return;
            }
            if !gate.is_open() {
                self.metrics.frames_dropped.inc(gate.drop_reason());
                self.flow_cause(now);
                return;
            }
            if self.send_au(gfx, now, &a, out) {
                self.set_state(now, State::Live, out);
            } else {
                self.flow_cause(now);
            }
            return;
        }
        if !gate.is_open() {
            let reason = if a.au.burst && gate == Gate::Backpressure { "burst_truncated" } else { gate.drop_reason() };
            self.metrics.frames_dropped.inc(reason);
            self.set_state(now, State::NeedIdr, out);
            self.flow_cause(now);
            return;
        }
        if !self.send_au(gfx, now, &a, out) {
            self.set_state(now, State::NeedIdr, out);
            self.flow_cause(now);
        }
    }

    /// §6.3: [AUD] + SPS/PPS (IDR only) + VCL NALs, 4-byte start codes, one
    /// AU per `send_avc420_frame`, full-frame region at `region_qp`.
    fn send_au(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, a: &KvmAu, out: &mut Vec<Command>) -> bool {
        let (Some(params), Some((sid, w, h))) = (self.params.as_ref(), self.surface) else {
            self.metrics.frames_dropped.inc("not_ready");
            return false;
        };
        self.annexb.clear();
        a.au.write_annex_b(params, &mut self.annexb);
        let region = Avc420Region::full_frame(w, h, self.cfg.region_qp);
        let suspended = gfx.is_ack_suspended();
        let ts = self.timestamp(now);
        match gfx.send_avc420_frame(sid, &self.annexb, &[region], ts) {
            Some(id) => {
                let grace = self.flow.take_grace(a.au.idr);
                self.flow.record(id, now, a.au.burst, grace, suspended);
                self.kvm_frame_delivered = true;
                self.metrics.frames_sent.inc();
                self.drain(gfx, out, Some(a.received), 1, a.au.burst);
                true
            }
            None => {
                self.metrics.frames_dropped.inc("send_none");
                false
            }
        }
    }

    fn on_tick(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, out: &mut Vec<Command>) {
        if self.state == State::Closing {
            if let Some((since, watchdog)) = self.closing
                && !self.aborted
                && now.saturating_duration_since(since) >= watchdog
            {
                // §6.9: on_disconnected never came — release, stop, abort.
                self.aborted = true;
                out.push(Command::ReleaseAll(ReleaseTrigger::Watchdog));
                out.push(Command::Abort);
            }
            return;
        }
        if self.avc420_deadline.is_some_and(|d| now >= d) {
            self.close(now, Cause::NoAvc420, self.cfg.disconnect_watchdog, out);
            return;
        }
        if self.next_probe.is_some_and(|t| now >= t) {
            out.push(Command::ProbeRtt);
            self.next_probe = Some(now + self.cfg.rtt_probe_interval);
        }
        let suspended = gfx.is_ack_suspended();
        if self.flow.stall_expired(now, suspended) || self.flow.suspended_backlog_expired(now, suspended) {
            self.close(now, Cause::ClientStalled, self.cfg.disconnect_watchdog, out);
            return;
        }
        match self.state {
            State::Live => {
                let gate = self.flow.gates(now, false, suspended, gfx.should_backpressure());
                if !gate.is_open() {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
            }
            State::NeedIdr => {
                let gate = self.flow.gates(now, false, suspended, gfx.should_backpressure());
                if !gate.is_open() {
                    self.flow_cause(now);
                }
                if let Some(a) = self.idr.observe_gates(now, gate.is_open()) {
                    self.push_idr(a, out);
                }
                if let Some(a) = self.idr.tick(now) {
                    self.push_idr(a, out);
                }
            }
            State::WaitReady | State::WaitReactivation | State::Paused | State::Idle | State::Closing => {}
        }
    }

    fn gauges(&self, gfx: &GraphicsPipelineServer, now: Instant) {
        let m = &self.metrics;
        m.egfx_in_flight.set(i64::from(gfx.frames_in_flight()));
        m.egfx_backlog_bytes.set(i64::try_from(self.flow.backlog()).unwrap_or(i64::MAX));
        m.egfx_ack_suspended.set(i64::from(gfx.is_ack_suspended()));
        m.egfx_oldest_unacked_ms
            .set(i64::try_from(self.flow.oldest_age(now).as_millis()).unwrap_or(i64::MAX));
        m.standing_delay_ms.set(self.flow.standing_delay_ms().map_or(-1, i64::from));
    }
}

/// The IDR policy in force (for the shell's metrics).
impl Pump {
    #[must_use]
    pub fn idr_policy(&self) -> IdrPolicy {
        self.cfg.idr.policy
    }
}
```

- [ ] **Step 6: Run the tests.** `cargo test --workspace --all-features --lib -- pump::` — Expected: PASS — every `pump::` test (Tasks 4.1–4.4), 0 failed; the 12 new ones included.

- [ ] **Step 7: Gate** (clippy, test, budget). **Step 8: Commit.**

```bash
git add crates/kvm-rdp/src/pump
git commit -m "kvm-rdp: the EGFX pump's sans-IO state machine and its L1 rig (§6.4–§6.6)" \
  -m "Setup + drain in one lock hold; slate; §6.3 composition; bursts chunked and truncated at the hard cap." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.5: L1 — resize, suppression, stall, suspension, closing and the IDR policies

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/core.rs` (a second test module, `lifecycle`)
- Test: `crates/kvm-rdp/src/pump/core.rs` (`lifecycle`)

**Interfaces:**
- Consumes: `Pump` and the rig (Task 4.4), `pump::flow::SUSPEND`.
- Produces: nothing new — §11.2's L1 cases for §6.4's resize path, §6.6's suppression, stall, suspension and gates, §6.7, §6.9's Closing and watchdog, and §6.5 per policy. This task changes no production code unless a case finds a bug; the mutation step proves the cases bite.

- [ ] **Step 1: Write the tests.** Append to `crates/kvm-rdp/src/pump/core.rs`:

```rust
#[cfg(test)]
mod lifecycle {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use ironrdp_egfx::pdu::{GfxPdu, QueueDepth};

    fn ticks(r: &mut Rig, from_ms: u64, to_ms: u64) -> Vec<Command> {
        let mut out = Vec::new();
        for i in from_ms / 100 + 1..=to_ms / 100 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        out
    }

    fn disconnects(out: &[Command]) -> Vec<Cause> {
        out.iter().filter_map(|c| if let Command::Disconnect(c) = c { Some(*c) } else { None }).collect()
    }

    fn frame_id(out: &[Command]) -> u32 {
        pdus(out).iter().find_map(|p| if let GfxPdu::StartFrame(s) = p { Some(s.frame_id) } else { None }).unwrap()
    }

    /// §11.2: a second resize SPS during WaitReactivation is carried out
    /// after the first reactivation; the surface ends at the latest size.
    #[test]
    fn a_second_resize_during_wait_reactivation_runs_after_the_first() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(sps(ParamClass::Resize, P480));
        assert!(matches!(out.last(), Some(Command::DisplayResize { width: 854, height: 480 })));
        r.step(sps(ParamClass::Resize, ES3));
        let out = r.step(Input::ReactivationComplete);
        assert!(matches!(out.last(), Some(Command::DisplayResize { width: 640, height: 360 })), "{:?}", kinds(&out));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        let out = r.step(Input::ReactivationComplete);
        let reset = pdus(&out).into_iter().find_map(|p| if let GfxPdu::ResetGraphics(g) = p { Some((g.width, g.height)) } else { None });
        assert_eq!(reset, Some((640, 360)));
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §11.2: `on_ready` during WaitReactivation is merged into the one
    /// Setup at ReactivationComplete.
    #[test]
    fn on_ready_during_wait_reactivation_is_merged() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Resize, P480));
        r.advertise(census_caps());
        assert!(pdus(&r.step(Input::OnReady { avc420: true })).is_empty());
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(names(&pdus(&out)).iter().filter(|n| **n == "ResetGraphics").count(), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    #[test]
    fn reactivation_complete_outside_wait_reactivation_is_ignored() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert!(r.step(Input::ReactivationComplete).is_empty());
        r.step(au(true, false));
        assert!(r.step(Input::ReactivationComplete).is_empty());
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2: a resize started from Paused returns to Paused, with no second
    /// release for the same suppression edge.
    #[test]
    fn a_resize_started_from_paused_returns_to_paused() {
        let mut r = Rig::new(cfg());
        r.live();
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(!kinds(&out).contains(&"ReleaseAll"));
    }

    /// §11.2 suppression: a short pulse does nothing; a held pulse pauses
    /// and releases; nothing is sent while Paused; the falling edge is a
    /// Setup cause.
    #[test]
    fn suppression_pauses_on_a_held_pulse_and_resumes_as_a_setup_cause() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::Suppress(true));
        r.at(500);
        r.step(Input::Suppress(false));
        r.at(2_000);
        r.step(Input::Suppress(false));
        assert_eq!(r.pump.state(), State::Live, "a short pulse does nothing");
        let out = r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(out.iter().any(|c| matches!(c, Command::ReleaseAll(ReleaseTrigger::Suppression))));
        assert!(pdus(&r.step(au(true, false))).is_empty());
        r.at(6_000);
        let out = r.hold_suppress(false);
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(kinds(&out).contains(&"RequestIdr"), "{:?}", kinds(&out));
    }

    #[test]
    fn suppression_before_the_first_kvm_frame_is_ignored() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        let out = r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(!kinds(&out).contains(&"ReleaseAll"));
    }

    /// §11.2: suppression arriving in WaitReactivation releases at once and
    /// lands in Paused after reactivation.
    #[test]
    fn suppression_in_wait_reactivation_releases_at_once_then_lands_in_paused() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(kinds(&r.hold_suppress(true)), ["ReleaseAll"]);
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(!kinds(&out).contains(&"ReleaseAll"), "one release per edge");
    }

    /// §11.2 stall: fires at `stall_timeout` after the first closure; any
    /// ack disarms it; frozen in Paused for longer than the timeout → no
    /// disconnect.
    #[test]
    fn the_stall_fires_disarms_on_an_ack_and_freezes_in_paused() {
        let mut r = Rig::new(cfg());
        r.live(); // the IDR (grace 1.6 s) is never acked
        let out = ticks(&mut r, 0, 12_000);
        assert_eq!(disconnects(&out), [Cause::ClientStalled]);

        let mut r = Rig::new(cfg());
        r.live();
        let mut out = ticks(&mut r, 0, 6_000);
        out.extend(r.ack(0, QueueDepth::Unavailable));
        out.extend(ticks(&mut r, 6_000, 14_000));
        assert_eq!(disconnects(&out), [], "any ack disarms");

        let mut r = Rig::new(cfg());
        r.live();
        ticks(&mut r, 0, 2_000); // armed at 1.6 s, NeedIdr
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        let out = ticks(&mut r, 3_000, 20_000);
        assert_eq!(disconnects(&out), [], "frozen in Paused");
    }

    /// §11.2 suspension: frames keep flowing and are not recorded; the
    /// suspension survives a server resize and a re-advertise and the
    /// picture continues (fork patch 1).
    #[test]
    fn suspended_acks_keep_frames_flowing_across_a_resize_and_a_readvertise() {
        let mut c = cfg();
        c.hard_cap = 4;
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Suspend);
        for _ in 0..10 {
            assert_eq!(wire(&r.step(au(false, false))).len(), 1, "more than the hard cap, all accepted");
        }
        r.step(sps(ParamClass::Resize, P480));
        r.step(Input::ReactivationComplete);
        assert!(r.gfx.is_ack_suspended());
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        for _ in 0..10 {
            assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        }
        r.negotiate(census_caps());
        assert!(r.gfx.is_ack_suspended());
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        for _ in 0..10 {
            assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        }
    }

    /// §11.2: suspended, a backlog spike ≥ the limit that drains costs an IDR
    /// and no disconnect; held ≥ the limit for `stall_timeout` it closes.
    #[test]
    fn a_suspended_backlog_spike_costs_an_idr_and_a_held_one_closes() {
        let mut c = cfg();
        c.flow.backlog_limit = 1000;
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Suspend);
        r.step(Input::Backlog { written: 0 });
        for _ in 0..40 {
            r.step(au(false, false));
        }
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(r.metrics.frames_dropped.get("backlog_gate") >= 1);
        r.step(Input::Backlog { written: u64::MAX });
        assert_eq!(disconnects(&ticks(&mut r, 0, 1_000)), []);
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
        r.step(Input::Backlog { written: 0 });
        assert_eq!(disconnects(&ticks(&mut r, 1_000, 12_500)), [Cause::ClientStalled]);
    }

    /// §11.2: a resume ack clears the unacked set and restores normal gating
    /// without closing the soft gate.
    #[test]
    fn a_resume_ack_restores_gating_without_closing_the_soft_gate() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Suspend);
        let mut last = 0;
        for i in 1..=10 {
            r.at(i * 100);
            last = frame_id(&r.step(au(false, false)));
        }
        r.ack(last, QueueDepth::Unavailable);
        assert!(!r.gfx.is_ack_suspended());
        r.at(1_600);
        assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2 standing delay: a previous connection's samples never affect
    /// the next (IronRDP's handle is per server). The core owns DC6's
    /// reference rule: a generation's first sample is only a reference,
    /// never in the baseline, and the signal is live once the handle moves.
    #[test]
    fn a_previous_connections_rtt_never_gates_the_next() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        // 900: the handle's stale value (reference only); then a live 10 ms
        // baseline and a standing queue: median 650 − 10 = 640 ms ≥ 500.
        for v in [900, 10, 600, 650, 700, 620, 640, 660, 680] {
            r.step(Input::Rtt(v));
        }
        assert!(wire(&r.step(au(false, false))).is_empty(), "standing delay closes the gate");
        assert_eq!(r.metrics.frames_dropped.get("standing_delay"), 1);
        r.step(Input::SessionStop { generation: 1 });
        r.new_connection();
        r.step(Input::SessionStart { generation: 2, size: (640, 360) });
        r.negotiate(census_caps());
        r.step(Input::FlvOpened { origin: FlvOrigin::First });
        r.step(sps(ParamClass::Initial, ES3));
        r.step(Input::Rtt(680)); // the handle still holds the old value: a reference only
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2 Closing: EGFX sends stop before `Disconnect`; the watchdog
    /// releases keys, stops the KVM side and aborts — once.
    #[test]
    fn closing_stops_sends_then_the_watchdog_aborts_once() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(Input::UpstreamFatal(Cause::StreamIncompatible));
        assert_eq!(kinds(&out), ["ReleaseAll", "Disconnect"]);
        assert!(r.step(au(true, false)).is_empty());
        let out = ticks(&mut r, 0, 6_000);
        assert_eq!(kinds(&out), ["ReleaseAll", "Abort"]);
        assert!(matches!(out[0], Command::ReleaseAll(ReleaseTrigger::Watchdog)));
        assert_eq!(r.metrics.disconnects.get("stream_incompatible"), 1);
    }

    /// §5.2, DC13: shutdown closes with cause `shutdown` and its own watchdog.
    #[test]
    fn shutdown_closes_with_its_own_watchdog() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(Input::Shutdown { watchdog: Duration::from_secs(2) });
        assert!(matches!(out.last(), Some(Command::Disconnect(Cause::Shutdown))));
        assert_eq!(kinds(&ticks(&mut r, 0, 1_900)), Vec::<&str>::new());
        assert_eq!(kinds(&ticks(&mut r, 1_900, 2_000)), ["ReleaseAll", "Abort"]);
    }

    /// §6.7: a first negotiation without AVC420 waits `avc420_timeout` (and a
    /// better set before it is taken); a re-advertise without it closes at
    /// once; a client that never negotiates is `no_avc420` at the timeout.
    #[test]
    fn no_avc420_waits_on_first_negotiation_and_closes_on_a_readvertise() {
        let mut r = Rig::new(cfg());
        r.start((640, 360));
        assert!(r.negotiate(v8_only()).is_empty());
        assert_eq!(r.pump.state(), State::WaitReady);
        assert_eq!(disconnects(&ticks(&mut r, 0, 9_900)), []);
        assert_eq!(disconnects(&ticks(&mut r, 9_900, 10_000)), [Cause::NoAvc420]);

        let mut r = Rig::new(cfg());
        r.start((640, 360));
        r.negotiate(v8_only());
        assert!(kinds(&r.negotiate(census_caps())).contains(&"OpenFlv"));

        let mut r = Rig::new(cfg());
        r.live();
        assert_eq!(disconnects(&r.negotiate(v8_only())), [Cause::NoAvc420]);

        let mut r = Rig::new(cfg());
        r.start((640, 360));
        assert_eq!(disconnects(&ticks(&mut r, 0, 10_000)), [Cause::NoAvc420]);
    }

    /// §11.2 "Every policy": a later Setup → `RequestIdr` (side),
    /// `ReconnectFlv` (reconnect), nothing (wait).
    #[test]
    fn a_later_setup_requests_per_policy() {
        for (policy, want) in [
            (IdrPolicy::Side, Some("RequestIdr")),
            (IdrPolicy::Reconnect, Some("ReconnectFlv")),
            (IdrPolicy::Wait, None),
        ] {
            let mut c = cfg();
            c.idr.policy = policy;
            let mut r = Rig::new(c);
            r.live();
            r.ack(0, QueueDepth::Unavailable);
            r.at(2_000);
            let k = kinds(&r.negotiate(census_caps()));
            match want {
                Some(w) => assert_eq!(k.iter().filter(|x| **x == w).count(), 1, "{policy:?}: {k:?}"),
                None => assert!(!k.contains(&"RequestIdr") && !k.contains(&"ReconnectFlv"), "{k:?}"),
            }
        }
    }

    /// §11.2: a transient reconnect clears `idr_pending` (a deferred request)
    /// and restarts both clocks.
    #[test]
    fn a_transient_reconnect_cancels_a_deferred_request() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(200);
        r.negotiate(census_caps()); // a Setup cause inside the setup window: deferred to 1 s
        r.at(500);
        r.step(Input::FlvOpened { origin: FlvOrigin::Transient });
        let out = ticks(&mut r, 500, 4_000);
        assert!(!kinds(&out).contains(&"RequestIdr"), "{:?}", kinds(&out));
    }

    /// §11.2: a deferred request whose NeedIdr an IDR resolves inside the
    /// window → `CancelIdrRequest`, counted, and nothing requested later.
    #[test]
    fn an_idr_inside_the_window_cancels_the_deferred_request() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(200);
        let k = kinds(&r.negotiate(census_caps())); // a Setup cause: deferred to 1 s
        assert!(!k.contains(&"RequestIdr"), "{k:?}");
        r.at(300);
        let out = r.step(au(true, false));
        assert_eq!(wire(&out).len(), 1);
        assert!(kinds(&out).contains(&"CancelIdrRequest"), "{:?}", kinds(&out));
        assert_eq!(r.metrics.idr_cancelled.get(), 1);
        r.ack(frame_id(&out), QueueDepth::Unavailable);
        let later = kinds(&ticks(&mut r, 300, 3_000));
        assert!(!later.contains(&"RequestIdr") && !later.contains(&"ReconnectFlv"), "{later:?}");
    }

    /// §11.2: an IDR dropped at a closed gate counts as a flow cause: the
    /// request comes after `idr_wait_max` of open gates, deferred to the
    /// flow clock's window (10 s from the FLV open). `stall_timeout` is set
    /// past that window: no ack can arrive (nothing was sent), so at the
    /// default 10 s the stall would close the session at the same tick.
    #[test]
    fn an_idr_dropped_at_a_closed_gate_is_a_flow_cause() {
        let mut c = cfg();
        c.flow.backlog_limit = 10;
        c.flow.stall_timeout = Duration::from_secs(30);
        let mut r = Rig::new(c);
        r.need_idr(); // the Setup batch alone is over 10 bytes, none written
        assert!(pdus(&r.step(au(true, false))).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("backlog_gate"), 1);
        r.step(Input::Backlog { written: u64::MAX });
        let early = ticks(&mut r, 0, 9_900);
        assert!(!kinds(&early).contains(&"RequestIdr"), "not before the flow window's end: {:?}", kinds(&early));
        let out = ticks(&mut r, 9_900, 10_500);
        assert_eq!(kinds(&out).iter().filter(|k| **k == "RequestIdr").count(), 1, "at 10 000 ms, on the flow clock");
        assert_eq!(disconnects(&early), []);
        assert_eq!(disconnects(&out), []);
    }
}
```

- [ ] **Step 2: Run them.** `cargo test --workspace --all-features --lib -- pump::core::lifecycle` — Expected: PASS — 19 passed. A failure is a bug in Task 4.4's core: check the case against §6.4–§6.6 first (each case's comment derives its numbers), then fix the core, not the case, and say which case found it in the report.

- [ ] **Step 3: Prove they bite.** In `Pump::set_state`, delete the line `self.flow.set_frozen(now, matches!(new, State::Paused | State::WaitReactivation));`.

Run: `cargo test --workspace --all-features --lib -- pump::core::lifecycle`
Expected: FAIL — `the_stall_fires_disarms_on_an_ack_and_freezes_in_paused` ("frozen in Paused"). Restore the line; re-run: 19 passed.

- [ ] **Step 4: Gate** (clippy, test, budget). **Step 5: Commit.**

```bash
git add crates/kvm-rdp/src/pump/core.rs
git commit -m "kvm-rdp: L1 — resize, suppression, stall, suspension, Closing and per-policy IDR cases (§11.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.6: L1 — every cell of the §6.4 table

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/core.rs` (a third test module, `table`)
- Test: `crates/kvm-rdp/src/pump/core.rs` (`table::every_cell_of_the_section_6_4_table`)

**Interfaces:**
- Consumes: `Pump` and the rig (Task 4.4).
- Produces: §11.2's "every cell of the §6.4 state × input table, one case each" — 6 states × 12 inputs, each reached the same canonical way and checked for its next state and the commands it must and must not issue.

- [ ] **Step 1: Write the table test.** Append to `crates/kvm-rdp/src/pump/core.rs`:

```rust
#[cfg(test)]
mod table {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use State::{Closing, Live, NeedIdr, Paused, WaitReactivation, WaitReady};

    /// §6.4's columns.
    #[derive(Debug, Clone, Copy)]
    enum Col {
        ReadyAvc,
        ReadyNoAvc,
        SpsNeedingResize,
        SpsSameOrOther,
        FlvOpened,
        Reactivated,
        SuppressOn,
        SuppressOff,
        IdrAu,
        PAu,
        GateCloses,
        Fatal,
    }
    use Col::*;

    /// Each row's canonical state; suppression counts in every one (a KVM
    /// frame was delivered) except WaitReady.
    fn rig_in(s: State) -> Rig {
        let mut r = Rig::new(cfg());
        match s {
            WaitReady => {
                r.start((640, 360));
            }
            NeedIdr => {
                r.live();
                r.step(Input::FlvOpened { origin: FlvOrigin::Transient });
            }
            Live => {
                r.live();
            }
            WaitReactivation => {
                r.live();
                r.step(sps(ParamClass::Resize, P480));
            }
            Paused => {
                r.live();
                r.hold_suppress(true);
            }
            Closing => {
                r.live();
                r.step(Input::UpstreamFatal(Cause::KvmUnreachable));
            }
            State::Idle => {}
        }
        assert_eq!(r.pump.state(), s);
        r
    }

    fn apply(r: &mut Rig, c: Col) -> Vec<Command> {
        let at_size = if r.pump.size() == (640, 360) { ES3 } else { P480 };
        let other_size = if r.pump.size() == (640, 360) { P480 } else { ES3 };
        match c {
            ReadyAvc => r.negotiate(census_caps()),
            ReadyNoAvc => r.negotiate(v8_only()),
            SpsNeedingResize => r.step(sps(ParamClass::Resize, other_size)),
            SpsSameOrOther => r.step(sps(ParamClass::Other, at_size)),
            FlvOpened => r.step(Input::FlvOpened { origin: FlvOrigin::Transient }),
            Reactivated => r.step(Input::ReactivationComplete),
            SuppressOn => r.hold_suppress(true),
            SuppressOff => r.hold_suppress(false),
            IdrAu => r.step(au(true, false)),
            PAu => r.step(au(false, false)),
            GateCloses => {
                let later = r.ms() + 2_000; // the unacked IDR's grace runs out
                r.at(later);
                r.step(Input::Tick)
            }
            Fatal => r.step(Input::UpstreamFatal(Cause::StreamCorrupt)),
        }
    }

    const SEND: &str = "SendDvc";
    const RESIZE: &str = "DisplayResize";
    const RELEASE: &str = "ReleaseAll";
    const DISC: &str = "Disconnect";
    const OPEN: &str = "OpenFlv";

    /// (state, column, next state, must issue, must not issue).
    type Cell = (State, Col, State, &'static [&'static str], &'static [&'static str]);

    #[rustfmt::skip]
    const TABLE: &[Cell] = &[
        (WaitReady, ReadyAvc, NeedIdr, &[SEND, OPEN], &[]),
        (WaitReady, ReadyNoAvc, WaitReady, &[], &[DISC]),
        (WaitReady, SpsNeedingResize, WaitReady, &[], &[RESIZE]),
        (WaitReady, SpsSameOrOther, WaitReady, &[], &[SEND]),
        (WaitReady, FlvOpened, WaitReady, &[], &[SEND]),
        (WaitReady, Reactivated, WaitReady, &[], &[SEND]),
        (WaitReady, SuppressOn, WaitReady, &[], &[RELEASE]),
        (WaitReady, SuppressOff, WaitReady, &[], &[RELEASE]),
        (WaitReady, IdrAu, WaitReady, &[], &[SEND]),
        (WaitReady, PAu, WaitReady, &[], &[SEND]),
        (WaitReady, GateCloses, WaitReady, &[], &[SEND]),
        (WaitReady, Fatal, Closing, &[DISC], &[SEND]),

        (NeedIdr, ReadyAvc, NeedIdr, &[SEND], &[DISC]),
        (NeedIdr, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (NeedIdr, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (NeedIdr, SpsSameOrOther, NeedIdr, &[], &[SEND, "ReconnectFlv"]),
        (NeedIdr, FlvOpened, NeedIdr, &[], &[SEND, "RequestIdr"]),
        (NeedIdr, Reactivated, NeedIdr, &[], &[SEND]),
        (NeedIdr, SuppressOn, Paused, &[RELEASE], &[SEND]),
        (NeedIdr, SuppressOff, NeedIdr, &[], &[RELEASE]),
        (NeedIdr, IdrAu, Live, &[SEND], &[]),
        (NeedIdr, PAu, NeedIdr, &[], &[SEND]),
        (NeedIdr, GateCloses, NeedIdr, &[], &[SEND]),
        (NeedIdr, Fatal, Closing, &[DISC], &[SEND]),

        (Live, ReadyAvc, NeedIdr, &[SEND], &[DISC]),
        (Live, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (Live, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (Live, SpsSameOrOther, NeedIdr, &[], &[SEND, "ReconnectFlv"]),
        (Live, FlvOpened, NeedIdr, &[], &[SEND, "RequestIdr"]),
        (Live, Reactivated, Live, &[], &[SEND]),
        (Live, SuppressOn, Paused, &[RELEASE], &[SEND]),
        (Live, SuppressOff, Live, &[], &[RELEASE]),
        (Live, IdrAu, Live, &[SEND], &[]),
        (Live, PAu, Live, &[SEND], &[]),
        (Live, GateCloses, NeedIdr, &[], &[SEND]),
        (Live, Fatal, Closing, &[DISC], &[SEND]),

        (WaitReactivation, ReadyAvc, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (WaitReactivation, SpsNeedingResize, WaitReactivation, &[], &[RESIZE, SEND]),
        (WaitReactivation, SpsSameOrOther, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, FlvOpened, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, Reactivated, NeedIdr, &[SEND], &[]),
        (WaitReactivation, SuppressOn, WaitReactivation, &[RELEASE], &[SEND]),
        (WaitReactivation, SuppressOff, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, IdrAu, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, PAu, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, GateCloses, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, Fatal, Closing, &[DISC], &[SEND]),

        (Paused, ReadyAvc, Paused, &[SEND], &[DISC]),
        (Paused, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (Paused, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (Paused, SpsSameOrOther, Paused, &[], &[SEND]),
        (Paused, FlvOpened, Paused, &[], &[SEND]),
        (Paused, Reactivated, Paused, &[], &[SEND]),
        (Paused, SuppressOn, Paused, &[], &[RELEASE]),
        (Paused, SuppressOff, NeedIdr, &[], &[RELEASE]),
        (Paused, IdrAu, Paused, &[], &[SEND]),
        (Paused, PAu, Paused, &[], &[SEND]),
        (Paused, GateCloses, Paused, &[], &[SEND]),
        (Paused, Fatal, Closing, &[DISC], &[SEND]),

        (Closing, ReadyAvc, Closing, &[], &[SEND, OPEN, DISC]),
        (Closing, ReadyNoAvc, Closing, &[], &[SEND, DISC]),
        (Closing, SpsNeedingResize, Closing, &[], &[RESIZE, SEND]),
        (Closing, SpsSameOrOther, Closing, &[], &[SEND]),
        (Closing, FlvOpened, Closing, &[], &[SEND]),
        (Closing, Reactivated, Closing, &[], &[SEND]),
        (Closing, SuppressOn, Closing, &[], &[RELEASE]),
        (Closing, SuppressOff, Closing, &[], &[RELEASE]),
        (Closing, IdrAu, Closing, &[], &[SEND]),
        (Closing, PAu, Closing, &[], &[SEND]),
        (Closing, GateCloses, Closing, &[], &[SEND, "Abort"]),
        (Closing, Fatal, Closing, &[], &[DISC]),
    ];

    #[test]
    fn every_cell_of_the_section_6_4_table() {
        assert_eq!(TABLE.len(), 72, "6 states × 12 inputs");
        let mut failures = Vec::new();
        for &(state, col, next, must, must_not) in TABLE {
            let mut r = rig_in(state);
            let out = apply(&mut r, col);
            let k = kinds(&out);
            if r.pump.state() != next {
                failures.push(format!("{state:?} × {col:?}: now {:?}, want {next:?} ({k:?})", r.pump.state()));
            }
            for m in must {
                if !k.contains(m) {
                    failures.push(format!("{state:?} × {col:?}: missing {m} ({k:?})"));
                }
            }
            for m in must_not {
                if k.contains(m) {
                    failures.push(format!("{state:?} × {col:?}: must not {m} ({k:?})"));
                }
            }
        }
        assert!(failures.is_empty(), "{} cells wrong:\n{}", failures.len(), failures.join("\n"));
    }
}
```

- [ ] **Step 2: Run it.** `cargo test --workspace --all-features --lib -- pump::core::table` — Expected: PASS — 1 passed. A failing cell is a bug in the core: fix the core to §6.4, never the table (the table is the spec's), and name the cell in the report.

- [ ] **Step 3: Prove it bites.** In `Pump::on_suppress`, change `State::NeedIdr | State::Live => self.enter_paused(now, out),` to `State::Live => self.enter_paused(now, out),`.

Run: `cargo test --workspace --all-features --lib -- pump::core::table`
Expected: FAIL — `2 cells wrong:` with `NeedIdr × SuppressOn: now NeedIdr, want Paused` and `NeedIdr × SuppressOn: missing ReleaseAll`. Restore; re-run: 1 passed.

- [ ] **Step 4: Gate** (clippy, test, budget). **Step 5: Commit.**

```bash
git add crates/kvm-rdp/src/pump/core.rs
git commit -m "kvm-rdp: L1 — every cell of the §6.4 state × input table (§11.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---


## Part 5 — The RDP side

IronRDP's half of §4.3 and §5: the listener's TLS identity and accept rate, the callbacks (lifecycle, GFX, display, the input stub), the pump's async shell, and the assembly — the server, the two runtimes, §5.2's shutdown and the binary. Callbacks only push; the shell only locks, steps and carries out.

### Task 5.1: `rdp::{tls, accept}` — the listener's identity and the accept rate

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/mod.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/tls.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/accept.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod rdp;`)
- Test: `crates/kvm-rdp/src/rdp/tls.rs`, `crates/kvm-rdp/src/rdp/accept.rs` (`tests`)

**Interfaces:**
- Consumes: rustls 0.23 (`aws_lc_rs`) and its re-exported `pki_types::pem::PemObject`, tokio-rustls 0.26 `TlsAcceptor`, x509-parser 0.16; dev: rcgen 0.13 (`aws_lc_rs`), tempfile.
- Produces:
  - `rdp::tls`: `pub const MAX_PEM: u64` (64 KiB); `pub enum TlsError { Read { what: &'static str, kind: std::io::ErrorKind }, TooLarge(&'static str), NoCertificate, BadCertificate, NoKey, KeyMismatch }` (`Clone + Eq + Debug`, `Display`, `Error`); `pub struct TlsIdentity { pub acceptor: tokio_rustls::TlsAcceptor, pub public_key: Vec<u8> }`; `pub fn install_crypto_provider()`; `pub fn load(cert_file: &Path, key_file: &Path) -> Result<TlsIdentity, TlsError>`; `pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsIdentity, TlsError>`; `pub type Fingerprint = [(SystemTime, u64); 2]`; `pub fn fingerprint(cert_file: &Path, key_file: &Path) -> Option<Fingerprint>`.
  - `rdp::accept`: `pub struct AcceptRate` — `AcceptRate::new(rate: u32, window: Duration) -> AcceptRate`, `admit(&mut self, now: Instant) -> bool`.

- [ ] **Step 1: Write the failing tests.** Create `rdp/mod.rs`:

```rust
//! The RDP side (spec §5, §9.1): the listener's TLS identity and accept
//! rate, IronRDP's callbacks, and the server's assembly. Callbacks run on
//! the RDP runtime and only push (§4.3).
pub mod accept;
pub mod tls;
```

add `pub mod rdp;` to `lib.rs`; create `rdp/tls.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    /// A fresh self-signed pair: (cert PEM, key PEM, the raw public key).
    fn pair() -> (String, String, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["kvm-rdp.test".to_owned()]).unwrap();
        (ck.cert.pem(), ck.key_pair.serialize_pem(), ck.key_pair.public_key_raw().to_vec())
    }

    /// §9.1: CredSSP binds to the certificate's subjectPublicKey — the BIT
    /// STRING's contents, what `ironrdp-tls` extracts on the client — and
    /// our `ServerConfig` never logs keys, whatever `SSLKEYLOGFILE` says.
    #[test]
    fn a_generated_identity_loads_with_its_credssp_key_and_no_key_log() {
        install_crypto_provider();
        let (cert, key, raw) = pair();
        let id = from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(id.public_key, raw);
        assert!(!id.acceptor.config().key_log.will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn broken_or_mismatched_pairs_are_refused() {
        let (cert, key, _) = pair();
        let (_, other_key, _) = pair();
        assert_eq!(from_pem(cert.as_bytes(), other_key.as_bytes()).err(), Some(TlsError::KeyMismatch));
        assert_eq!(from_pem(b"", key.as_bytes()).err(), Some(TlsError::NoCertificate));
        assert_eq!(from_pem(cert.as_bytes(), b"").err(), Some(TlsError::NoKey));
        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(from_pem(garbage.as_bytes(), key.as_bytes()).err(), Some(TlsError::BadCertificate));
    }

    /// Files are read capped (§4.4's secret-file rule, at PEM size), and the
    /// fingerprint the certificate watcher polls changes on a rewrite.
    #[test]
    fn files_are_read_capped_and_fingerprinted() {
        let d = tempfile::tempdir().unwrap();
        let (cert, key, _) = pair();
        let (c, k) = (d.path().join("cert.pem"), d.path().join("key.pem"));
        std::fs::write(&c, &cert).unwrap();
        std::fs::write(&k, &key).unwrap();
        assert!(load(&c, &k).is_ok());
        let before = fingerprint(&c, &k).unwrap();
        std::fs::write(&c, format!("{cert}\n")).unwrap();
        assert_ne!(fingerprint(&c, &k).unwrap(), before, "a renewal rewrites the file");
        assert!(fingerprint(&d.path().join("absent.pem"), &k).is_none());
        assert!(matches!(load(&d.path().join("absent.pem"), &k), Err(TlsError::Read { what: "certificate", .. })));
        std::fs::write(&c, vec![b'A'; 70_000]).unwrap();
        assert_eq!(load(&c, &k).err(), Some(TlsError::TooLarge("certificate")));
    }
}
```

and `rdp/accept.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn admits_the_rate_per_sliding_window() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(3, s(60));
        assert!(r.admit(t0) && r.admit(t0 + s(1)) && r.admit(t0 + s(2)));
        assert!(!r.admit(t0 + s(3)));
        assert!(!r.admit(t0 + s(59)));
        assert!(r.admit(t0 + s(60)), "the first admission has left the window");
        assert!(!r.admit(t0 + s(60)));
    }

    /// DC15: refusals are not counted, so a refused flood cannot extend its
    /// own lockout past the window.
    #[test]
    fn a_refused_flood_does_not_extend_the_lockout() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(1, s(10));
        assert!(r.admit(t0));
        for i in 1..1000u64 {
            assert!(!r.admit(t0 + Duration::from_millis(i)));
        }
        assert!(r.admit(t0 + s(10)));
    }

    #[test]
    fn memory_is_bounded_by_the_rate() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(5, s(60));
        for i in 0..10_000u64 {
            r.admit(t0 + Duration::from_millis(i));
        }
        assert_eq!(r.held(), 5);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- rdp::` — Expected: FAIL to compile (`from_pem`, `AcceptRate` not found).

- [ ] **Step 3: Implement the identity.** Above the tests in `rdp/tls.rs`:

```rust
//! The RDP listener's TLS identity (§9.1): our own rustls `ServerConfig` on
//! aws-lc-rs — never `TlsIdentityCtx` (DC2), never a key log — and the
//! certificate's subjectPublicKey, which CredSSP binds the NLA exchange to.
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio_rustls::TlsAcceptor;

/// Largest PEM file read (a chain of a few certificates fits easily).
pub const MAX_PEM: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Read { what: &'static str, kind: std::io::ErrorKind },
    TooLarge(&'static str),
    NoCertificate,
    BadCertificate,
    NoKey,
    KeyMismatch,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Read { what, kind } => write!(f, "cannot read the {what} file: {kind}"),
            TlsError::TooLarge(what) => write!(f, "the {what} file is over {MAX_PEM} bytes"),
            TlsError::NoCertificate => f.write_str("no certificate in the certificate file"),
            TlsError::BadCertificate => f.write_str("the certificate does not parse"),
            TlsError::NoKey => f.write_str("no private key in the key file"),
            TlsError::KeyMismatch => f.write_str("the key does not match the certificate"),
        }
    }
}

impl std::error::Error for TlsError {}

pub struct TlsIdentity {
    pub acceptor: TlsAcceptor,
    /// The leaf certificate's subjectPublicKey (BIT STRING contents).
    pub public_key: Vec<u8>,
}

/// §4.2: aws-lc-rs is the one provider, installed idempotently.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn load(cert_file: &Path, key_file: &Path) -> Result<TlsIdentity, TlsError> {
    let cert = read_capped(cert_file, "certificate")?;
    let key = read_capped(key_file, "key")?;
    from_pem(&cert, &key)
}

pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsIdentity, TlsError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::BadCertificate)?;
    let public_key = subject_public_key(certs.first().ok_or(TlsError::NoCertificate)?)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::NoKey)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // `key_log` stays rustls' default `NoKeyLog` (§9.1: no SSLKEYLOGFILE).
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::BadCertificate)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::KeyMismatch)?;
    Ok(TlsIdentity { acceptor: TlsAcceptor::from(Arc::new(config)), public_key })
}

fn subject_public_key(cert: &CertificateDer<'_>) -> Result<Vec<u8>, TlsError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| TlsError::BadCertificate)?;
    let spk = &parsed.public_key().subject_public_key;
    if spk.unused_bits != 0 {
        return Err(TlsError::BadCertificate);
    }
    Ok(spk.data.to_vec())
}

fn read_capped(path: &Path, what: &'static str) -> Result<Vec<u8>, TlsError> {
    let file = std::fs::File::open(path).map_err(|e| TlsError::Read { what, kind: e.kind() })?;
    let mut buf = Vec::new();
    file.take(MAX_PEM + 1)
        .read_to_end(&mut buf)
        .map_err(|e| TlsError::Read { what, kind: e.kind() })?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_PEM {
        return Err(TlsError::TooLarge(what));
    }
    Ok(buf)
}

/// Both files' modification time and length: what the certificate watcher
/// compares (§4.4: a renewed certificate restarts the bridge).
pub type Fingerprint = [(SystemTime, u64); 2];

#[must_use]
pub fn fingerprint(cert_file: &Path, key_file: &Path) -> Option<Fingerprint> {
    let one = |p: &Path| {
        let m = std::fs::metadata(p).ok()?;
        Some((m.modified().ok()?, m.len()))
    };
    Some([one(cert_file)?, one(key_file)?])
}
```

- [ ] **Step 4: Implement the accept rate.** Above the tests in `rdp/accept.rs`:

```rust
//! `security.accept_rate` (§5.1, §9.1): at most `rate` admitted TCP accepts
//! per sliding `window`, across all peers. Only admissions are counted
//! (DC15), so the memory is `rate` instants and a refused flood cannot
//! extend its own lockout.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct AcceptRate {
    rate: usize,
    window: Duration,
    admitted: VecDeque<Instant>,
}

impl AcceptRate {
    #[must_use]
    pub fn new(rate: u32, window: Duration) -> AcceptRate {
        AcceptRate { rate: usize::try_from(rate).unwrap_or(usize::MAX), window, admitted: VecDeque::new() }
    }

    pub fn admit(&mut self, now: Instant) -> bool {
        while let Some(&t) = self.admitted.front() {
            if now.saturating_duration_since(t) < self.window {
                break;
            }
            self.admitted.pop_front();
        }
        if self.admitted.len() >= self.rate {
            return false;
        }
        self.admitted.push_back(now);
        true
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.admitted.len()
    }
}
```

- [ ] **Step 5: Run the tests.** `cargo test --workspace --all-features --lib -- rdp::` — Expected: PASS — 6 passed.

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-rdp/src/rdp crates/kvm-rdp/src/lib.rs
git commit -m "kvm-rdp: the RDP listener's TLS identity (own rustls config, no key log) and the accept rate (§9.1)" \
  -m "PEM via rustls-pki-types, the CredSSP key via x509-parser (DC2); refusals do not count (DC15)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5.2: `rdp::{handler, gfx, display, input}` — IronRDP's callbacks

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/gfx.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/display.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/input.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/handler.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/mod.rs`
- Test: `crates/kvm-rdp/src/rdp/handler.rs`, `crates/kvm-rdp/src/rdp/display.rs`, `crates/kvm-rdp/src/rdp/input.rs` (`tests`)

**Interfaces:**
- Consumes: `msg::{Generations, KvmCommand, RdpInput}` (3.1), `hid::{HidControl, ReleaseTrigger}` (3.5), `metrics::Metrics` (2.4), `rdp::accept::AcceptRate` (5.1); `ironrdp_server::{ConnectionHandler, ConnectionInfo, PostConnectionAction, ServerError, GfxServerFactory, GfxDvcBridge, GfxServerHandle, ServerEvent, ServerEventSender, RdpServerDisplay, RdpServerDisplayUpdates, DisplayUpdate, DesktopSize, ServerResult, RdpServerInputHandler, KeyboardEvent, MouseEvent}`, `ironrdp_egfx::{pdu::{CapabilitiesAdvertisePdu, CapabilitySet}, server::{GraphicsPipelineHandler, GraphicsPipelineServer}}`; test: `pump::rig::census_caps` (4.4).
- Produces:
  - `rdp::gfx`: `pub type GfxSlot = Arc<Mutex<Option<(u64, GfxServerHandle)>>>`; `pub struct GfxFactory` — `GfxFactory::new(latest: GfxSlot, tx: UnboundedSender<RdpInput>, hard_cap: u32, metrics: Arc<Metrics>) -> GfxFactory`, implementing `GfxServerFactory` (`build_server_with_handle` records `(slot, handle)`, slots from 1; the callbacks observe QoE decode time into `metrics.qoe_decode`); `pub fn take_latest(slot: &GfxSlot) -> Option<(u64, GfxServerHandle)>`; `pub fn caps_hex(pdu: &CapabilitiesAdvertisePdu) -> Vec<String>` (`"00080105:12000000"`, at most 32 sets × 64 bytes).
  - `rdp::display`: `pub struct DisplayShared` — `DisplayShared::new(size: (u16, u16)) -> Arc<DisplayShared>`, `size(&self) -> (u16, u16)`, `set_size(&self, (u16, u16))`, `surface(&self) -> Option<(u16, u16)>`, `set_surface(&self, (u16, u16))`, `resize(&self, width: u16, height: u16) -> bool`; `pub struct BridgeDisplay` — `BridgeDisplay::new(shared: Arc<DisplayShared>, tx: UnboundedSender<RdpInput>) -> BridgeDisplay`, implementing `RdpServerDisplay`.
  - `rdp::input`: `pub struct InputStub` — `InputStub::new(metrics: Arc<Metrics>) -> InputStub`, implementing `RdpServerInputHandler`.
  - `rdp::handler`: `pub struct Lifecycle { pub gens: Arc<Generations>, pub accepting: Arc<AtomicBool>, pub rate: AcceptRate, pub gfx: GfxSlot, pub hid: Arc<HidControl>, pub metrics: Arc<Metrics>, pub to_pump: UnboundedSender<RdpInput>, pub to_kvm: UnboundedSender<KvmCommand> }`, implementing `ConnectionHandler`.

- [ ] **Step 1: Write the failing tests.** Replace `rdp/mod.rs` with:

```rust
//! The RDP side (spec §5, §9.1): the listener's TLS identity and accept
//! rate, IronRDP's callbacks, and the server's assembly. Callbacks run on
//! the RDP runtime and only push (§4.3).
pub mod accept;
pub mod display;
pub mod gfx;
pub mod handler;
pub mod input;
pub mod tls;
```

Create `rdp/handler.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::rdp::gfx::GfxFactory;
    use ironrdp_core::encode_vec;
    use ironrdp_dvc::DvcProcessor as _;
    use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, FrameAcknowledgePdu, GfxPdu, QoeFrameAcknowledgePdu, QueueDepth};
    use ironrdp_pdu::gcc::KeyboardType;
    use ironrdp_server::GfxServerFactory as _;
    use tokio::sync::mpsc;

    struct Rig {
        h: Lifecycle,
        factory: GfxFactory,
        pump: mpsc::UnboundedReceiver<RdpInput>,
        kvm: mpsc::UnboundedReceiver<KvmCommand>,
        metrics: Arc<Metrics>,
        hid: Arc<HidControl>,
        gens: Arc<Generations>,
        accepting: Arc<AtomicBool>,
    }

    fn rig(rate: u32) -> Rig {
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(16, metrics.clone()));
        let gens = Arc::new(Generations::default());
        let accepting = Arc::new(AtomicBool::new(true));
        let latest = GfxSlot::default();
        let (ptx, pump) = mpsc::unbounded_channel();
        let (ktx, kvm) = mpsc::unbounded_channel();
        let factory = GfxFactory::new(latest.clone(), ptx.clone(), 60, metrics.clone());
        let h = Lifecycle {
            gens: gens.clone(),
            accepting: accepting.clone(),
            rate: AcceptRate::new(rate, Duration::from_secs(60)),
            gfx: latest,
            hid: hid.clone(),
            metrics: metrics.clone(),
            to_pump: ptx,
            to_kvm: ktx,
        };
        Rig { h, factory, pump, kvm, metrics, hid, gens, accepting }
    }

    fn info() -> ConnectionInfo {
        ConnectionInfo::new(0x409, KeyboardType::IBM_ENHANCED, String::new())
    }

    fn peer() -> SocketAddr {
        "127.0.0.2:50000".parse().unwrap()
    }

    /// §5.1, DC4: the generation is minted, bound to the GFX handle built
    /// for this connection (the latest), and reaches the pump before the
    /// KVM side hears `Start`; release-all runs first (session start).
    #[test]
    fn connection_info_begins_a_generation_bound_to_the_latest_gfx_handle() {
        let mut r = rig(30);
        let (_, first) = r.factory.build_server_with_handle().unwrap();
        let (_, second) = r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart { generation, slot, gfx, .. }) = r.pump.try_recv() else { panic!("no SessionStart") };
        assert_eq!((generation, slot), (1, 2));
        assert!(Arc::ptr_eq(&gfx, &second) && !Arc::ptr_eq(&gfx, &first));
        assert!(matches!(r.kvm.try_recv(), Ok(KvmCommand::Start { generation: 1 })));
        assert_eq!(r.gens.current(), Some(1));
        assert_eq!(r.metrics.sessions.get(), 1);
        assert_eq!(r.metrics.release_all.get("session_start"), 1);
        assert_eq!(r.hid.epoch(), 1);
    }

    /// §4.3: `on_disconnected` invalidates the generation before it returns.
    #[test]
    fn disconnect_ends_the_generation_before_returning() {
        let mut r = rig(30);
        r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let _ = (r.pump.try_recv(), r.kvm.try_recv());
        let action = r.h.on_disconnected(peer(), Duration::from_secs(3), None);
        assert_eq!(action, PostConnectionAction::Continue);
        assert_eq!(r.gens.current(), None);
        assert!(matches!(r.pump.try_recv(), Ok(RdpInput::SessionStop { generation: 1 })));
        assert!(matches!(r.kvm.try_recv(), Ok(KvmCommand::Stop { generation: 1, done: None })));
        assert_eq!(r.metrics.release_all.get("session_end"), 1);
        // A connection that never authenticated touches nothing.
        r.h.on_disconnected(peer(), Duration::ZERO, None);
        assert!(r.pump.try_recv().is_err() && r.kvm.try_recv().is_err());
    }

    #[test]
    fn accept_refuses_over_the_rate_and_once_shutdown_begins() {
        let mut r = rig(2);
        assert!(r.h.on_accept(peer()) && r.h.on_accept(peer()));
        assert!(!r.h.on_accept(peer()));
        assert_eq!(r.metrics.accept_refused.get(), 1);
        let mut r = rig(30);
        r.accepting.store(false, Ordering::SeqCst);
        assert!(!r.h.on_accept(peer()));
        assert_eq!(r.metrics.accept_refused.get(), 1);
    }

    /// DC13: a connection that wins after shutdown began starts nothing.
    #[test]
    fn a_late_winner_during_shutdown_starts_nothing() {
        let mut r = rig(30);
        r.factory.build_server_with_handle().unwrap();
        r.accepting.store(false, Ordering::SeqCst);
        r.h.on_connection_info(&info());
        assert!(r.pump.try_recv().is_err() && r.kvm.try_recv().is_err());
        assert_eq!(r.gens.current(), None);
    }

    /// §4.3: the callbacks run with the GFX mutex held and never lock the
    /// handle. Driven through IronRDP's own bridge (which holds the lock
    /// around `process`) on another thread: a relock would deadlock it.
    #[test]
    fn gfx_callbacks_only_push_their_slot_and_never_relock() {
        let mut r = rig(30);
        let (mut bridge, _handle) = r.factory.build_server_with_handle().unwrap();
        let advertise =
            encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(crate::pump::rig::census_caps()))).unwrap();
        let ack = encode_vec(&GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::Unavailable,
            frame_id: 9,
            total_frames_decoded: 1,
        }))
        .unwrap();
        let qoe = encode_vec(&GfxPdu::QoeFrameAcknowledge(QoeFrameAcknowledgePdu {
            frame_id: 9,
            timestamp: 0,
            time_diff_se: 1,
            time_diff_dr: 4,
        }))
        .unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            bridge.start(7).unwrap();
            bridge.process(7, &advertise).unwrap();
            bridge.process(7, &ack).unwrap();
            bridge.process(7, &qoe).unwrap();
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(Duration::from_secs(5)).expect("a callback relocked the GFX handle");
        let Ok(RdpInput::CapsAdvertised { slot: 1, sets }) = r.pump.try_recv() else { panic!("no CapsAdvertised") };
        assert_eq!(sets, ["00080004:02000000", "00080105:12000000"]);
        assert!(matches!(r.pump.try_recv(), Ok(RdpInput::OnReady { slot: 1, version: 0x8_0105 })));
        assert!(matches!(r.pump.try_recv(), Ok(RdpInput::FrameAck { slot: 1, frame_id: 9, queue_depth: 0 })));
        assert_eq!(r.metrics.qoe_decode.count(), 1, "QoE decode time (§10.4)");
    }
}
```

Create `rdp/display.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use std::time::Duration;

    /// §6.4: `size()` is the shared last-known size; `updates()` replaces
    /// the stream and announces itself; a Resize reaches the current stream
    /// only; a replaced stream pends rather than ending (`Ok(None)` would be
    /// a disconnect).
    #[tokio::test(flavor = "current_thread")]
    async fn updates_replace_the_stream_and_resize_reaches_the_current_one() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shared = DisplayShared::new((1920, 1080));
        let mut d = BridgeDisplay::new(shared.clone(), tx);
        assert_eq!(d.size().await, DesktopSize { width: 1920, height: 1080 });
        assert!(!shared.resize(640, 360), "no stream yet");
        let mut first = d.updates().await.unwrap();
        assert!(matches!(rx.try_recv(), Ok(RdpInput::Updates)));
        assert!(shared.resize(640, 360));
        match first.next_update().await.unwrap() {
            Some(DisplayUpdate::Resize(s)) => assert_eq!((s.width, s.height), (640, 360)),
            other => panic!("{other:?}"),
        }
        shared.set_size((640, 360));
        assert_eq!(d.size().await, DesktopSize { width: 640, height: 360 });
        let mut second = d.updates().await.unwrap();
        assert!(shared.resize(854, 480));
        assert!(matches!(second.next_update().await.unwrap(), Some(DisplayUpdate::Resize(_))));
        assert!(tokio::time::timeout(Duration::from_millis(100), first.next_update()).await.is_err());
        shared.set_surface((854, 480));
        assert_eq!(shared.surface(), Some((854, 480)));
    }
}
```

Create `rdp/input.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn input_events_are_counted_and_dropped() {
        let m = Arc::new(Metrics::default());
        let mut h = InputStub::new(m.clone());
        h.keyboard(KeyboardEvent::Pressed { code: 0x1E, extended: false });
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        assert_eq!(m.input_events_ignored.get(), 2);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- rdp::` — Expected: FAIL to compile (`Lifecycle`, `GfxFactory`, `BridgeDisplay`, `InputStub` not found).

- [ ] **Step 3: Implement the GFX factory.** Create `rdp/gfx.rs`:

```rust
//! EGFX for each served connection (§4.3, DC4). IronRDP calls
//! `build_server_with_handle` once per served connection, and always before
//! that connection's `on_connection_info`: for a fresh connection in
//! `attach_channels`, before auth; for a Preempt winner in
//! `serve_negotiated`, after CredSSP (IronRDP builds a takeover candidate's
//! channels only once it has authenticated). Either way the factory
//! records `(slot, handle)` and `on_connection_info` takes the latest. The
//! callbacks run inside `GraphicsPipelineServer` with its mutex held: they
//! only push `RdpInput`s tagged with their slot, or bump a metric.
use crate::metrics::Metrics;
use crate::msg::RdpInput;
use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, CapabilitySet};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer, QoeMetrics};
use ironrdp_server::{GfxDvcBridge, GfxServerFactory, GfxServerHandle, ServerEvent, ServerEventSender};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

/// The latest connection's EGFX handle and its slot.
pub type GfxSlot = Arc<Mutex<Option<(u64, GfxServerHandle)>>>;

pub struct GfxFactory {
    latest: GfxSlot,
    next_slot: AtomicU64,
    tx: UnboundedSender<RdpInput>,
    hard_cap: u32,
    metrics: Arc<Metrics>,
}

impl GfxFactory {
    #[must_use]
    pub fn new(latest: GfxSlot, tx: UnboundedSender<RdpInput>, hard_cap: u32, metrics: Arc<Metrics>) -> GfxFactory {
        GfxFactory { latest, next_slot: AtomicU64::new(0), tx, hard_cap, metrics }
    }

    fn callbacks(&self, slot: u64) -> Box<dyn GraphicsPipelineHandler> {
        Box::new(GfxCallbacks { slot, tx: self.tx.clone(), hard_cap: self.hard_cap, metrics: self.metrics.clone() })
    }
}

/// `on_connection_info`: take the handle built for this connection.
#[must_use]
pub fn take_latest(slot: &GfxSlot) -> Option<(u64, GfxServerHandle)> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

impl ServerEventSender for GfxFactory {
    fn set_sender(&mut self, _sender: UnboundedSender<ServerEvent>) {}
}

impl GfxServerFactory for GfxFactory {
    /// Unused while `build_server_with_handle` always answers; slot 0 never
    /// matches a session, so the pump drops its callbacks.
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        self.callbacks(0)
    }

    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst).wrapping_add(1).max(1);
        let handle: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(self.callbacks(slot))));
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some((slot, handle.clone()));
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

/// `version:data` in hex, the census's notation; bounded, because the
/// client chose it (the `no_avc420` log line, §6.7).
#[must_use]
pub fn caps_hex(pdu: &CapabilitiesAdvertisePdu) -> Vec<String> {
    pdu.0
        .iter()
        .take(32)
        .map(|s| {
            let mut out = format!("{:08x}:", s.version.0);
            for b in s.data.iter().take(64) {
                let _ = write!(out, "{b:02x}");
            }
            out
        })
        .collect()
}

struct GfxCallbacks {
    slot: u64,
    tx: UnboundedSender<RdpInput>,
    hard_cap: u32,
    metrics: Arc<Metrics>,
}

impl GraphicsPipelineHandler for GfxCallbacks {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        let _ = self.tx.send(RdpInput::CapsAdvertised { slot: self.slot, sets: caps_hex(pdu) });
    }

    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        let _ = self.tx.send(RdpInput::OnReady { slot: self.slot, version: negotiated.version().0 });
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, _total_frames_decoded: u32) {
        let _ = self.tx.send(RdpInput::FrameAck { slot: self.slot, frame_id, queue_depth });
    }

    /// §10.4 QoE decode time (V10+ clients). MS-RDPEGFX's QoE frame
    /// acknowledgement gives `timeDiffEDR` in milliseconds (IronRDP's doc comment says µs; the
    /// wire value is the client's). A metric only — atomics, no lock, no
    /// generation needed (a Preempt candidate's sample is harmless).
    fn on_qoe_metrics(&mut self, m: QoeMetrics) {
        self.metrics.qoe_decode.observe(Duration::from_millis(u64::from(m.time_diff_dr)));
    }

    fn max_frames_in_flight(&self) -> u32 {
        self.hard_cap
    }
}
```

- [ ] **Step 4: Implement the display.** Above the tests in `rdp/display.rs`:

```rust
//! `RdpServerDisplay` (§5.1, §6.4): `size()` is the last-known KVM
//! resolution (`video.default_size` until the first SPS), and `updates()`
//! — called on every activation and reactivation — hands IronRDP a fresh
//! stream whose sender the shell uses for `DisplayUpdate::Resize`. A stream
//! never ends: IronRDP reads `Ok(None)` as a disconnect.
use crate::msg::RdpInput;
use ironrdp_server::{DesktopSize, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::mpsc;

pub struct DisplayShared {
    size: Mutex<(u16, u16)>,
    surface: Mutex<Option<(u16, u16)>>,
    updates: Mutex<Option<mpsc::UnboundedSender<DisplayUpdate>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl DisplayShared {
    #[must_use]
    pub fn new(size: (u16, u16)) -> Arc<DisplayShared> {
        Arc::new(DisplayShared { size: Mutex::new(size), surface: Mutex::new(None), updates: Mutex::new(None) })
    }

    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        *lock(&self.size)
    }

    pub fn set_size(&self, size: (u16, u16)) {
        *lock(&self.size) = size;
    }

    /// The surface mouse scaling uses (§6.4 Setup; Plan D reads it).
    #[must_use]
    pub fn surface(&self) -> Option<(u16, u16)> {
        *lock(&self.surface)
    }

    pub fn set_surface(&self, surface: (u16, u16)) {
        *lock(&self.surface) = Some(surface);
    }

    /// `DisplayUpdate::Resize` on the current stream; `false` if none.
    pub fn resize(&self, width: u16, height: u16) -> bool {
        let tx = lock(&self.updates).clone();
        tx.is_some_and(|tx| tx.send(DisplayUpdate::Resize(DesktopSize { width, height })).is_ok())
    }
}

pub struct BridgeDisplay {
    shared: Arc<DisplayShared>,
    tx: mpsc::UnboundedSender<RdpInput>,
}

impl BridgeDisplay {
    #[must_use]
    pub fn new(shared: Arc<DisplayShared>, tx: mpsc::UnboundedSender<RdpInput>) -> BridgeDisplay {
        BridgeDisplay { shared, tx }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for BridgeDisplay {
    async fn size(&mut self) -> DesktopSize {
        let (width, height) = self.shared.size();
        DesktopSize { width, height }
    }

    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        let (tx, rx) = mpsc::unbounded_channel();
        *lock(&self.shared.updates) = Some(tx);
        let _ = self.tx.send(RdpInput::Updates);
        Ok(Box::new(Updates { rx }))
    }
}

struct Updates {
    rx: mpsc::UnboundedReceiver<DisplayUpdate>,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        match self.rx.recv().await {
            Some(u) => Ok(Some(u)),
            // Replaced by a later `updates()`: this stream's connection is
            // gone or reactivating. Never report the end (a disconnect).
            None => std::future::pending().await,
        }
    }
}
```

- [ ] **Step 5: Implement the input stub.** Above the tests in `rdp/input.rs`:

```rust
//! Plan C's input handler is a counting stub (DC7): every event is counted
//! and dropped, never logged (§4.5: no keystrokes). Plan D replaces it with
//! §7's scancode/US-layout mapping and mouse scaling.
use crate::metrics::Metrics;
use ironrdp_server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
use std::sync::Arc;

pub struct InputStub {
    metrics: Arc<Metrics>,
}

impl InputStub {
    #[must_use]
    pub fn new(metrics: Arc<Metrics>) -> InputStub {
        InputStub { metrics }
    }
}

impl RdpServerInputHandler for InputStub {
    fn keyboard(&mut self, _event: KeyboardEvent) {
        self.metrics.input_events_ignored.inc();
    }

    fn mouse(&mut self, _event: MouseEvent) {
        self.metrics.input_events_ignored.inc();
    }
}
```

- [ ] **Step 6: Implement the lifecycle.** Above the tests in `rdp/handler.rs`:

```rust
//! The §5.1 lifecycle as IronRDP's `ConnectionHandler`. `on_accept` runs
//! before anything else (the accept rate; refuse once shutdown began,
//! DC13); `on_connection_info` — once per connection, after NLA — mints
//! the generation, binds it to this connection's GFX handle and abort
//! handle, and starts the KVM side; `on_disconnected` ends the generation
//! before it returns. Under Preempt the evicted session's
//! `on_disconnected` runs before the winner's `on_connection_info`.
use crate::hid::{HidControl, ReleaseTrigger};
use crate::metrics::Metrics;
use crate::msg::{Generations, KvmCommand, RdpInput};
use crate::rdp::accept::AcceptRate;
use crate::rdp::gfx::{GfxSlot, take_latest};
use ironrdp_server::{ConnectionHandler, ConnectionInfo, PostConnectionAction, ServerError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

pub struct Lifecycle {
    pub gens: Arc<Generations>,
    /// Cleared when shutdown begins (§5.2, DC13).
    pub accepting: Arc<AtomicBool>,
    pub rate: AcceptRate,
    pub gfx: GfxSlot,
    pub hid: Arc<HidControl>,
    pub metrics: Arc<Metrics>,
    pub to_pump: UnboundedSender<RdpInput>,
    pub to_kvm: UnboundedSender<KvmCommand>,
}

impl ConnectionHandler for Lifecycle {
    fn on_accept(&mut self, _peer: SocketAddr) -> bool {
        if !self.accepting.load(Ordering::SeqCst) {
            self.metrics.accept_refused.inc();
            return false;
        }
        if !self.rate.admit(Instant::now()) {
            self.metrics.accept_refused.inc();
            tracing::warn!("security.accept_rate exceeded; connection refused");
            return false;
        }
        true
    }

    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        let abort = info.abort_handle();
        if !self.accepting.load(Ordering::SeqCst) {
            // Won a takeover after shutdown began: never start the KVM side.
            abort.abort();
            return;
        }
        let Some((slot, gfx)) = take_latest(&self.gfx) else {
            tracing::error!("no EGFX handle was built for this connection; aborting it");
            abort.abort();
            return;
        };
        let generation = self.gens.begin();
        self.metrics.sessions.inc();
        self.hid.release_all(ReleaseTrigger::SessionStart);
        let counter = Arc::new(AtomicU64::new(0));
        let _ = self.to_pump.send(RdpInput::SessionStart { generation, slot, gfx, counter, abort });
        let _ = self.to_kvm.send(KvmCommand::Start { generation });
        tracing::info!(generation, "session start");
    }

    fn on_disconnected(
        &mut self,
        _peer: SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        if let Some(generation) = self.gens.end() {
            self.hid.release_all(ReleaseTrigger::SessionEnd);
            let _ = self.to_pump.send(RdpInput::SessionStop { generation });
            let _ = self.to_kvm.send(KvmCommand::Stop { generation, done: None });
            tracing::info!(generation, secs = duration.as_secs(), error = error.is_some(), "session end");
        }
        PostConnectionAction::Continue
    }
}
```

- [ ] **Step 7: Run the tests.** `cargo test --workspace --all-features --lib -- rdp::` — Expected: PASS — 13 passed (Task 5.1's 6, these 7).

- [ ] **Step 8: Gate** (clippy, test, budget). **Step 9: Commit.**

```bash
git add crates/kvm-rdp/src/rdp
git commit -m "kvm-rdp: IronRDP callbacks — lifecycle and generations, per-connection GFX slots, display, input stub (§5.1)" \
  -m "Callbacks only push, tagged by slot; a relock would deadlock the test (§4.3). The display stream never ends." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5.3: `pump::shell` — the pump's async shell

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/shell.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/mod.rs` (`pub mod shell;`)
- Test: `crates/kvm-rdp/src/pump/shell.rs` (`tests`)

**Interfaces:**
- Consumes: `pump::{Pump, Command, DvcBatch, Input, PumpConfig}` (4.1–4.4), `msg::{Cause, Gen, Generations, KvmCommand, KvmEvent, RdpInput}` (3.1), `hid::HidControl` (3.5), `rdp::display::DisplayShared` (5.2), `metrics::Metrics`; `ironrdp_server::{ConnectionAbortHandle, EgfxServerMessage, GfxServerHandle, ServerEvent}`, `ironrdp_dvc::encode_dvc_messages`, `ironrdp_svc::ChannelFlags`; test: `pump::rig::{cfg, census_caps, sps, au, Null, CHAN, ES3}`.
- Produces (`pump::shell`): `pub const TICK: Duration` (50 ms); `pub const SHUTDOWN_WATCHDOG: Duration` (2 s, DC13); `pub struct ShellDeps { pub cfg: PumpConfig, pub metrics: Arc<Metrics>, pub gens: Arc<Generations>, pub hid: Arc<HidControl>, pub display: Arc<DisplayShared>, pub events: mpsc::UnboundedSender<ServerEvent>, pub suppressed: Arc<AtomicBool>, pub rtt: Arc<AtomicU32>, pub to_kvm: mpsc::UnboundedSender<KvmCommand> }`; `pub struct PumpShell` — `PumpShell::new(deps: ShellDeps) -> PumpShell` (embedded slate), `PumpShell::with_pump(deps: ShellDeps, pump: Pump) -> PumpShell`, `pub async fn run(self, rdp: mpsc::UnboundedReceiver<RdpInput>, kvm: mpsc::Receiver<KvmEvent>)` (returns when `rdp` closes).

The shell sends `ServerEvent::Disconnect(cause.error_info())` on the server's event channel itself — exactly what `ErrorInfoDisconnectHandle::disconnect` sends — so one sender carries every `ServerEvent` and tests can observe them.

- [ ] **Step 1: Write the failing tests.** Add `pub mod shell;` to `pump/mod.rs` (after `pub mod rig;`); create `pump/shell.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::{self, CHAN, ES3, Null};
    use ironrdp_core::encode_vec;
    // `start` and `process` are `DvcProcessor` methods on the server.
    use ironrdp_dvc::DvcProcessor as _;
    use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, FrameAcknowledgePdu, GfxPdu, QueueDepth};
    use ironrdp_pdu::gcc::KeyboardType;
    use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode as P};
    use ironrdp_server::ConnectionInfo;
    use kvm_proto::video::ParamClass;
    use std::sync::Mutex;
    use tokio::task::LocalSet;

    /// Wait (bounded) for a condition the shell task makes true.
    async fn until(what: &str, f: impl Fn() -> bool) {
        let waited = tokio::time::timeout(Duration::from_secs(2), async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "timed out waiting for {what}");
    }

    struct T {
        rdp: mpsc::UnboundedSender<RdpInput>,
        kvm: mpsc::Sender<KvmEvent>,
        events: mpsc::UnboundedReceiver<ServerEvent>,
        cmds: mpsc::UnboundedReceiver<KvmCommand>,
        gfx: GfxServerHandle,
        gens: Arc<Generations>,
        metrics: Arc<Metrics>,
        suppressed: Arc<AtomicBool>,
        rtt: Arc<AtomicU32>,
        counter: Arc<AtomicU64>,
    }

    /// The shell on the current `LocalSet` over a 640×360 display (the ES3
    /// fixture's size: no resize), no slate, RTT probes off unless `set`
    /// turns them on, and a GFX server the test plays the client for.
    fn shell(set: impl FnOnce(&mut PumpConfig)) -> T {
        let mut cfg = rig::cfg();
        cfg.rtt_probe_interval = Duration::from_secs(3600);
        set(&mut cfg);
        let metrics = Arc::new(Metrics::default());
        let (rdp, rdp_rx) = mpsc::unbounded_channel();
        let (kvm, kvm_rx) = mpsc::channel(68);
        let (etx, events) = mpsc::unbounded_channel();
        let (ktx, cmds) = mpsc::unbounded_channel();
        let gens = Arc::new(Generations::default());
        let suppressed = Arc::new(AtomicBool::new(false));
        let rtt = Arc::new(AtomicU32::new(u32::MAX));
        let deps = ShellDeps {
            cfg: cfg.clone(),
            metrics: metrics.clone(),
            gens: gens.clone(),
            hid: Arc::new(HidControl::new(16, metrics.clone())),
            display: DisplayShared::new((640, 360)),
            events: etx,
            suppressed: suppressed.clone(),
            rtt: rtt.clone(),
            to_kvm: ktx,
        };
        let pump = Pump::with_slate(cfg, metrics.clone(), None);
        tokio::task::spawn_local(PumpShell::with_pump(deps, pump).run(rdp_rx, kvm_rx));
        let gfx: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(Null))));
        gfx.lock().unwrap().start(CHAN).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        T { rdp, kvm, events, cmds, gfx, gens, metrics, suppressed, rtt, counter }
    }

    impl T {
        fn session_start(&self) -> Gen {
            let generation = self.gens.begin();
            let abort = ConnectionInfo::new(0, KeyboardType::IBM_ENHANCED, String::new()).abort_handle();
            self.rdp
                .send(RdpInput::SessionStart { generation, slot: 1, gfx: self.gfx.clone(), counter: self.counter.clone(), abort })
                .unwrap();
            generation
        }

        /// The client advertises the census pair; IronRDP's `on_ready`.
        fn ready(&self) {
            let adv = encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(rig::census_caps()))).unwrap();
            self.gfx.lock().unwrap().process(CHAN, &adv).unwrap();
            self.rdp.send(RdpInput::OnReady { slot: 1, version: 0x8_0105 }).unwrap();
        }

        fn start(&self) -> Gen {
            let generation = self.session_start();
            self.ready();
            generation
        }

        async fn event(&mut self) -> ServerEvent {
            tokio::time::timeout(Duration::from_secs(2), self.events.recv()).await.unwrap().unwrap()
        }

        async fn quiet(&mut self, d: Duration) -> bool {
            tokio::time::timeout(d, self.events.recv()).await.is_err()
        }

        async fn cmd(&mut self) -> KvmCommand {
            tokio::time::timeout(Duration::from_secs(2), self.cmds.recv()).await.unwrap().unwrap()
        }

        /// The FLV's first tag, its parameter sets, then one IDR.
        async fn first_idr(&self, generation: Gen) {
            self.kvm.send(KvmEvent::FlvOpened { generation, origin: FlvOrigin::First }).await.unwrap();
            let Input::SpsChanged { class, params } = rig::sps(ParamClass::Initial, ES3) else { unreachable!() };
            self.kvm.send(KvmEvent::SpsChanged { generation, class, params }).await.unwrap();
            let Input::Au(au) = rig::au(true, false) else { unreachable!() };
            self.kvm.send(KvmEvent::Au { generation, au }).await.unwrap();
        }

        /// The client acknowledges `frame_id`: IronRDP first, then the
        /// callback's push (as `GfxCallbacks::on_frame_ack` would).
        fn ack(&self, frame_id: u32) {
            let pdu = encode_vec(&GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
                queue_depth: QueueDepth::Unavailable,
                frame_id,
                total_frames_decoded: 1,
            }))
            .unwrap();
            self.gfx.lock().unwrap().process(CHAN, &pdu).unwrap();
            self.rdp.send(RdpInput::FrameAck { slot: 1, frame_id, queue_depth: 0 }).unwrap();
        }
    }

    fn egfx(ev: &ServerEvent) -> Option<(&Arc<AtomicU64>, u64)> {
        match ev {
            ServerEvent::Egfx(EgfxServerMessage::SendMessages { write_progress: Some((c, w)), .. }) => Some((c, *w)),
            _ => None,
        }
    }

    /// §4.3, §4.2 patch 2: Setup and frames leave only as
    /// `ServerEvent::Egfx`, each carrying this generation's write counter
    /// and its weight; the first Setup opens the FLV for this generation.
    #[tokio::test(flavor = "current_thread")]
    async fn a_session_reaches_the_wire_through_server_events_with_its_counter() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                let setup = t.event().await;
                let (c, w) = egfx(&setup).expect("the Setup batch");
                assert!(Arc::ptr_eq(c, &t.counter) && w > 0);
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { generation: g } if g == generation));
                t.first_idr(generation).await;
                assert!(egfx(&t.event().await).is_some());
                assert_eq!(t.metrics.frames_sent.get(), 1);
                assert_eq!(t.metrics.egfx_capability_version.get(), 0x8_0105);
            })
            .await;
    }

    /// DC4: only the current generation's KVM events reach the core.
    #[tokio::test(flavor = "current_thread")]
    async fn another_generations_kvm_events_are_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                t.first_idr(generation + 100).await;
                assert!(t.quiet(Duration::from_millis(300)).await);
                assert_eq!(t.metrics.frames_sent.get(), 0);
                t.first_idr(generation).await;
                assert!(egfx(&t.event().await).is_some());
            })
            .await;
    }

    /// §4.3: once `on_disconnected` has ended the generation, nothing more
    /// reaches IronRDP for it — even before `SessionStop` is processed.
    #[tokio::test(flavor = "current_thread")]
    async fn nothing_is_sent_for_an_ended_generation() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.session_start();
                t.gens.end();
                t.ready();
                assert!(t.quiet(Duration::from_millis(300)).await, "a Setup went out for an ended generation");
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
            })
            .await;
    }

    /// §6.9: a fatal cause → release (closing), then `Disconnect` with the
    /// cause's ErrorInfo.
    #[tokio::test(flavor = "current_thread")]
    async fn an_upstream_fatal_disconnects_with_its_errorinfo() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                t.kvm.send(KvmEvent::UpstreamFatal { generation, cause: Cause::KvmAuthFailed }).await.unwrap();
                match t.event().await {
                    ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(P::ServerInsufficientPrivileges)) => {}
                    other => panic!("{other:?}"),
                }
                assert_eq!(t.metrics.release_all.get("closing"), 1);
                assert_eq!(t.metrics.disconnects.get("kvm_auth_failed"), 1);
            })
            .await;
    }

    /// §6.9: `on_disconnected` never comes → release (watchdog), `Stop` to
    /// the KVM side, abort; within 5× the scaled watchdog, not before 0.5×.
    #[tokio::test(flavor = "current_thread")]
    async fn the_disconnect_watchdog_releases_and_stops_the_kvm_side() {
        LocalSet::new()
            .run_until(async {
                let wd = Duration::from_millis(300);
                let mut t = shell(|c| c.disconnect_watchdog = wd);
                let generation = t.start();
                t.event().await;
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { .. }));
                let t0 = Instant::now();
                t.kvm.send(KvmEvent::UpstreamFatal { generation, cause: Cause::StreamCorrupt }).await.unwrap();
                assert!(matches!(t.event().await, ServerEvent::Disconnect(_)));
                assert!(matches!(t.cmd().await, KvmCommand::Stop { generation: g, done: None } if g == generation));
                let took = t0.elapsed();
                assert!(took >= wd / 2 && took <= wd * 5, "{took:?}");
                assert_eq!(t.metrics.release_all.get("watchdog"), 1);
            })
            .await;
    }

    /// §5.2: shutdown disconnects with `shutdown` (0x1) and is answered only
    /// once the session stopped; with no session, at once.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_is_answered_when_the_session_stops() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                let (done, mut rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                let ev = t.event().await;
                assert!(
                    matches!(ev, ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(P::RpcInitiatedDisconnect))),
                    "{ev:?}"
                );
                assert!(rx.try_recv().is_err(), "answered before the session stopped");
                t.gens.end();
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), &mut rx).await.unwrap().unwrap();
                let (done, rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
            })
            .await;
    }

    /// DC6: the tick samples IronRDP's suppression flag into the core: held
    /// past the debounce after a KVM frame → ReleaseAll(suppression).
    #[tokio::test(flavor = "current_thread")]
    async fn the_tick_samples_suppression() {
        LocalSet::new()
            .run_until(async {
                let hold = Duration::from_millis(200);
                let mut t = shell(|c| c.suppress_debounce = hold);
                let generation = t.start();
                t.event().await;
                t.first_idr(generation).await;
                t.event().await;
                let t0 = Instant::now();
                t.suppressed.store(true, Ordering::SeqCst);
                while t.metrics.release_all.get("suppression") == 0 {
                    assert!(t0.elapsed() < hold * 5, "no release within 5× the debounce");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(t0.elapsed() >= hold / 2, "{:?}", t0.elapsed());
            })
            .await;
    }

    /// DC6 through shell and core together: each probe reads the handle
    /// first (the previous probe's answer); the core keeps a generation's
    /// first read as its reference only. A stale 900 left by the last
    /// connection, then answers of 2 ms, give a 2 ms baseline, and a
    /// standing queue around 700 ms closes the gate (§6.6). (With the rule
    /// applied in the shell too, 2 became the reference, ~700 the baseline,
    /// and the gate never closed.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_handle_then_live_answers_close_the_standing_delay_gate() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|c| c.rtt_probe_interval = Duration::from_millis(100));
                t.rtt.store(900, Ordering::SeqCst); // the last connection's answer
                let generation = t.start();
                t.first_idr(generation).await;
                until("the first IDR", || t.metrics.frames_sent.get() == 1).await;
                t.ack(0); // keep the soft gate out of the way
                let mut first = true;
                for v in [2, 2, 2, 690, 700, 710, 720, 705, 695, 715] {
                    while !matches!(t.event().await, ServerEvent::AutoDetectRttRequest) {}
                    if first {
                        assert_eq!(t.metrics.autodetect_rtt_ms.get(), 0, "the stale read was used as a sample");
                        first = false;
                    }
                    t.rtt.store(v, Ordering::SeqCst); // the next probe reads it
                }
                while !matches!(t.event().await, ServerEvent::AutoDetectRttRequest) {}
                let sd = t.metrics.standing_delay_ms.get();
                assert!(sd >= 500, "baseline 2 ms, median ~705 ms: standing delay {sd}");
                let Input::Au(au) = rig::au(true, false) else { unreachable!() };
                t.kvm.send(KvmEvent::Au { generation, au }).await.unwrap();
                until("a standing-delay drop", || t.metrics.frames_dropped.get("standing_delay") > 0).await;
            })
            .await;
    }

    /// §6.5 through the shell: burst AUs leave in chunks of `burst_chunk`
    /// (8), one `ServerEvent` each. The shell steps `Suppress` and `Backlog`
    /// before every AU (DC6); those samples must not split a chunk.
    #[tokio::test(flavor = "current_thread")]
    async fn burst_aus_leave_in_chunks_of_burst_chunk() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await; // the Setup
                t.first_idr(generation).await;
                assert!(egfx(&t.event().await).is_some(), "the IDR");
                for _ in 0..20 {
                    let Input::Au(au) = rig::au(false, true) else { unreachable!() };
                    t.kvm.send(KvmEvent::Au { generation, au }).await.unwrap();
                }
                let mut events = 0;
                while !t.quiet(Duration::from_millis(300)).await {
                    events += 1;
                }
                assert_eq!(events, 20_usize.div_ceil(8), "8 + 8 + the last 4 at the next tick");
                assert_eq!(t.metrics.frames_sent.get(), 21);
            })
            .await;
    }

    /// A callback from another connection's GFX handle (a Preempt
    /// candidate's slot) is dropped: no Setup, no ack accounting.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_slots_callbacks_are_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                t.session_start();
                let adv = encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(rig::census_caps()))).unwrap();
                t.gfx.lock().unwrap().process(CHAN, &adv).unwrap();
                t.rdp.send(RdpInput::OnReady { slot: 2, version: 0x8_0105 }).unwrap();
                t.rdp.send(RdpInput::FrameAck { slot: 2, frame_id: 0, queue_depth: 0 }).unwrap();
                assert!(t.quiet(Duration::from_millis(300)).await, "a stale slot's on_ready ran a Setup");
                assert_eq!(t.metrics.frames_acked.get(), 0);
                t.rdp.send(RdpInput::OnReady { slot: 1, version: 0x8_0105 }).unwrap();
                assert!(egfx(&t.event().await).is_some(), "the current slot's Setup");
            })
            .await;
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- pump::shell` — Expected: FAIL to compile (`PumpShell`, `ShellDeps` not found).

- [ ] **Step 3: Implement.** Above the tests in `pump/shell.rs`:

```rust
//! The pump's async shell (§4.3). It owns no timing rule: it feeds the core
//! — RDP-side inputs first (`biased`, DC4), then this generation's KVM
//! events, then a 50 ms tick, sampling the suppression flag and the write
//! counter before each tick and each AU (DC6) — one GFX lock per step, and
//! carries out the commands. Every `ServerEvent`, `Disconnect` included, is
//! sent only for the current generation.
use crate::hid::HidControl;
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, Generations, KvmCommand, KvmEvent, RdpInput};
use crate::pump::core::Pump;
use crate::pump::types::{Command, DvcBatch, Input, PumpConfig};
use crate::rdp::display::DisplayShared;
use ironrdp_dvc::encode_dvc_messages;
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_server::{ConnectionAbortHandle, EgfxServerMessage, GfxServerHandle, ServerEvent};
use ironrdp_svc::ChannelFlags;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

pub const TICK: Duration = Duration::from_millis(50);
/// §5.2's disconnect watchdog, inside the 5 s exit (DC13).
pub const SHUTDOWN_WATCHDOG: Duration = Duration::from_secs(2);
/// The `Stall` test hook never blocks longer than this.
const MAX_STALL: Duration = Duration::from_secs(30);

pub struct ShellDeps {
    pub cfg: PumpConfig,
    pub metrics: Arc<Metrics>,
    pub gens: Arc<Generations>,
    pub hid: Arc<HidControl>,
    pub display: Arc<DisplayShared>,
    /// The server's event channel (`RdpServer::event_sender`).
    pub events: mpsc::UnboundedSender<ServerEvent>,
    /// `RdpServer`'s display-suppressed flag (§6.6).
    pub suppressed: Arc<AtomicBool>,
    /// `RdpServer`'s auto-detect RTT handle (ms; `u32::MAX` = none).
    pub rtt: Arc<AtomicU32>,
    pub to_kvm: mpsc::UnboundedSender<KvmCommand>,
}

/// The live session: what `SessionStart` brought.
struct Link {
    generation: Gen,
    slot: u64,
    gfx: GfxServerHandle,
    counter: Arc<AtomicU64>,
    abort: ConnectionAbortHandle,
    caps: Vec<String>,
}

pub struct PumpShell {
    d: ShellDeps,
    pump: Pump,
    link: Option<Link>,
    waiters: Vec<oneshot::Sender<()>>,
    shutting_down: bool,
}

fn lock(gfx: &GfxServerHandle) -> MutexGuard<'_, GraphicsPipelineServer> {
    gfx.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PumpShell {
    #[must_use]
    pub fn new(deps: ShellDeps) -> PumpShell {
        let pump = Pump::new(deps.cfg.clone(), deps.metrics.clone());
        PumpShell::with_pump(deps, pump)
    }

    #[must_use]
    pub fn with_pump(deps: ShellDeps, pump: Pump) -> PumpShell {
        PumpShell { d: deps, pump, link: None, waiters: Vec::new(), shutting_down: false }
    }

    pub async fn run(mut self, mut rdp: mpsc::UnboundedReceiver<RdpInput>, mut kvm: mpsc::Receiver<KvmEvent>) {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut kvm_open = true;
        loop {
            tokio::select! {
                biased;
                input = rdp.recv() => match input {
                    Some(i) => self.rdp_input(i).await,
                    None => return,
                },
                ev = kvm.recv(), if kvm_open => match ev {
                    Some(e) => self.kvm_event(e).await,
                    None => kvm_open = false,
                },
                _ = tick.tick() => self.tick().await,
            }
        }
    }

    /// Step `inputs` in order under one GFX lock hold (§4.3).
    fn step(&mut self, inputs: impl IntoIterator<Item = Input>) -> Vec<Command> {
        let Some(gfx) = self.link.as_ref().map(|l| l.gfx.clone()) else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut g = lock(&gfx);
        let mut out = Vec::new();
        for i in inputs {
            out.extend(self.pump.step(&mut g, now, i));
        }
        out
    }

    fn link_for(&mut self, slot: u64) -> Option<&mut Link> {
        self.link.as_mut().filter(|l| l.slot == slot)
    }

    async fn rdp_input(&mut self, input: RdpInput) {
        match input {
            RdpInput::SessionStart { generation, slot, gfx, counter, abort } => {
                if let Some(old) = self.link.as_ref().map(|l| l.generation) {
                    // `on_disconnected` always comes first; never let two
                    // sessions share a pump.
                    let cmds = self.step([Input::SessionStop { generation: old }]);
                    self.exec(cmds).await;
                    self.end_link();
                }
                self.link = Some(Link { generation, slot, gfx, counter, abort, caps: Vec::new() });
                let mut inputs = vec![Input::SessionStart { generation, size: self.d.display.size() }];
                if self.shutting_down {
                    inputs.push(Input::Shutdown { watchdog: SHUTDOWN_WATCHDOG });
                }
                let cmds = self.step(inputs);
                self.exec(cmds).await;
            }
            RdpInput::SessionStop { generation } => {
                if self.link.as_ref().is_some_and(|l| l.generation == generation) {
                    let cmds = self.step([Input::SessionStop { generation }]);
                    self.exec(cmds).await;
                    self.end_link();
                }
            }
            RdpInput::CapsAdvertised { slot, sets } => {
                if let Some(l) = self.link_for(slot) {
                    l.caps = sets;
                }
            }
            RdpInput::OnReady { slot, version } => {
                if self.link_for(slot).is_none() {
                    return;
                }
                self.d.metrics.egfx_capability_version.set(i64::from(version));
                let cmds = self.on_ready();
                self.exec(cmds).await;
            }
            RdpInput::FrameAck { slot, frame_id, queue_depth } => {
                if self.link_for(slot).is_none() {
                    return;
                }
                self.d.metrics.frames_acked.inc();
                let cmds = self.step([Input::FrameAck { frame_id, queue_depth }]);
                self.exec(cmds).await;
            }
            RdpInput::Updates => {
                let cmds = self.step([Input::ReactivationComplete]);
                self.exec(cmds).await;
            }
            RdpInput::Shutdown { done } => {
                self.shutting_down = true;
                if self.link.is_none() {
                    let _ = done.send(());
                    return;
                }
                self.waiters.push(done);
                let cmds = self.step([Input::Shutdown { watchdog: SHUTDOWN_WATCHDOG }]);
                self.exec(cmds).await;
            }
            // Test hook (L2 `/livez`): block this runtime's thread.
            RdpInput::Stall(d) => std::thread::sleep(d.min(MAX_STALL)),
        }
    }

    /// `on_ready`: what IronRDP negotiated, read under the same lock hold.
    fn on_ready(&mut self) -> Vec<Command> {
        let Some(gfx) = self.link.as_ref().map(|l| l.gfx.clone()) else {
            return Vec::new();
        };
        let mut g = lock(&gfx);
        let avc420 = g.supports_avc420();
        self.pump.step(&mut g, Instant::now(), Input::OnReady { avc420 })
    }

    async fn kvm_event(&mut self, ev: KvmEvent) {
        let generation = ev.generation();
        if !self.link.as_ref().is_some_and(|l| l.generation == generation) || !self.d.gens.is_current(generation) {
            return; // another generation's word (§4.3)
        }
        let inputs = match ev {
            KvmEvent::FlvOpened { origin, .. } => vec![Input::FlvOpened { origin }],
            KvmEvent::SpsChanged { class, params, .. } => vec![Input::SpsChanged { class, params }],
            KvmEvent::Au { au, .. } => {
                let mut v = self.samples();
                v.push(Input::Au(au));
                v
            }
            KvmEvent::UpstreamFatal { cause, .. } => vec![Input::UpstreamFatal(cause)],
        };
        let cmds = self.step(inputs);
        self.exec(cmds).await;
    }

    /// DC6: the suppression flag and this generation's write counter.
    fn samples(&self) -> Vec<Input> {
        let written = self.link.as_ref().map_or(0, |l| l.counter.load(Ordering::Relaxed));
        vec![Input::Suppress(self.d.suppressed.load(Ordering::Relaxed)), Input::Backlog { written }]
    }

    async fn tick(&mut self) {
        if self.link.is_none() {
            return;
        }
        let mut inputs = self.samples();
        inputs.push(Input::Tick);
        let cmds = self.step(inputs);
        self.exec(cmds).await;
    }

    fn end_link(&mut self) {
        self.link = None;
        let m = &self.d.metrics;
        m.egfx_in_flight.set(0);
        m.egfx_backlog_bytes.set(0);
        m.egfx_ack_suspended.set(0);
        m.egfx_oldest_unacked_ms.set(0);
        m.standing_delay_ms.set(-1);
        for w in self.waiters.drain(..) {
            let _ = w.send(());
        }
    }

    async fn exec(&mut self, cmds: Vec<Command>) {
        let mut queue: VecDeque<Command> = cmds.into();
        while let Some(c) = queue.pop_front() {
            let Some(generation) = self.link.as_ref().map(|l| l.generation) else { return };
            let current = self.d.gens.is_current(generation);
            tracing::trace!(generation, kind = c.kind(), current, "pump command");
            match c {
                Command::SendDvc(b) => {
                    if current {
                        self.send_dvc(b).await;
                    }
                }
                Command::DisplayResize { width, height } => {
                    self.d.display.set_size((width, height));
                    if current && !self.d.display.resize(width, height) {
                        tracing::warn!(width, height, "no display stream for a resize");
                    }
                }
                Command::SurfaceSize { width, height } => self.d.display.set_surface((width, height)),
                Command::ReleaseAll(trigger) => self.d.hid.release_all(trigger),
                Command::OpenFlv => {
                    let _ = self.d.to_kvm.send(KvmCommand::OpenFlv { generation });
                }
                Command::RequestIdr => {
                    let _ = self.d.to_kvm.send(KvmCommand::RequestIdr { generation });
                }
                Command::ReconnectFlv => {
                    let _ = self.d.to_kvm.send(KvmCommand::ReconnectFlv { generation });
                }
                // Counted by the core (`idr_cancelled`, DC11).
                Command::CancelIdrRequest => {}
                Command::ProbeRtt => {
                    if current {
                        queue.extend(self.probe_rtt());
                    }
                }
                Command::Disconnect(cause) => {
                    if current {
                        self.disconnect(cause);
                    }
                }
                Command::Abort => {
                    let _ = self.d.to_kvm.send(KvmCommand::Stop { generation, done: None });
                    if let Some(l) = self.link.as_ref() {
                        l.abort.abort();
                    }
                    tracing::warn!(generation, "disconnect watchdog fired: aborting the connection");
                }
            }
        }
    }

    async fn send_dvc(&mut self, b: DvcBatch) {
        let Some(counter) = self.link.as_ref().map(|l| l.counter.clone()) else { return };
        let DvcBatch { channel_id, messages, weight, received, yield_after, .. } = b;
        match encode_dvc_messages(channel_id, messages, ChannelFlags::SHOW_PROTOCOL) {
            Ok(svc) => {
                let msg = EgfxServerMessage::send_messages(svc).with_write_counter(counter, weight);
                if self.d.events.send(ServerEvent::Egfx(msg)).is_err() {
                    tracing::debug!("the server's event channel is closed");
                }
            }
            Err(e) => {
                // Keep the backlog honest: this batch will never be written.
                counter.fetch_add(weight, Ordering::Relaxed);
                tracing::warn!(error = %e, "EGFX batch encoding failed");
            }
        }
        if let Some(t) = received {
            self.d.metrics.enqueue_latency.observe(t.elapsed());
        }
        if yield_after {
            // A burst chunk: let input interleave (§6.5).
            tokio::task::yield_now().await;
        }
    }

    /// DC6: read the previous probe's answer, probe again, feed every read.
    /// The reference rule (a generation's first sample is only a reference:
    /// the handle outlives connections) lives in the core's `Rtt`, once —
    /// applying it here as well would make the first *live* answer the
    /// core's reference and keep it out of the baseline.
    fn probe_rtt(&mut self) -> Vec<Command> {
        let v = self.d.rtt.load(Ordering::Relaxed);
        let _ = self.d.events.send(ServerEvent::AutoDetectRttRequest);
        self.step([Input::Rtt(v)])
    }

    fn disconnect(&mut self, cause: Cause) {
        if cause == Cause::NoAvc420 {
            let caps = self.link.as_ref().map(|l| l.caps.clone()).unwrap_or_default();
            tracing::warn!(?caps, "the client offered no AVC420 capability set (§6.7)");
        }
        tracing::info!(cause = cause.label(), "disconnecting the client");
        // What `ErrorInfoDisconnectHandle::disconnect` sends.
        let _ = self.d.events.send(ServerEvent::Disconnect(cause.error_info()));
    }
}
```

- [ ] **Step 4: Run the tests.** `cargo test --workspace --all-features --lib -- pump::shell` — Expected: PASS — 10 passed.

- [ ] **Step 5: Prove the generation check bites.** In `exec`, change `if current {` (the `Command::SendDvc` arm) to `if true {`.

Run: `cargo test --workspace --all-features --lib -- pump::shell::tests::nothing_is_sent_for_an_ended_generation`
Expected: FAIL — `a Setup went out for an ended generation`. Restore; re-run: 1 passed.

- [ ] **Step 6: Gate** (clippy, test, budget). **Step 7: Commit.**

```bash
git add crates/kvm-rdp/src/pump/shell.rs crates/kvm-rdp/src/pump/mod.rs
git commit -m "kvm-rdp: the pump's async shell — biased inputs, one lock per step, current-generation sends (§4.3)" \
  -m "Write counter on every EGFX event (patch 2); samples per tick and AU without splitting burst chunks; every RTT read fed to the core (DC6)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5.4: `rdp::server`, `bridge`, `main` — assembly, §5.2's shutdown, the binary

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/server.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/bridge.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/main.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/mod.rs` (`pub mod server;`), `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/lib.rs` (`pub mod bridge;`), `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/config.rs` (`config_path`), `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/Cargo.toml` (`[[bin]]`)
- Test: `crates/kvm-rdp/src/bridge.rs`, `crates/kvm-rdp/src/config.rs` (`tests`)

**Interfaces:**
- Consumes: everything above; `admin::{serve, Health}` (2.5), `kvm::session::{run_actor, KvmDeps, SessionConfig}` (3.8), `kvm::endpoint::KvmEndpoint` (3.2), `logging::init` (2.3); `ironrdp_server::{RdpServer, ConnectionPolicy, Credentials, ServerEvent}`; tokio `signal`.
- Produces:
  - `config::config_path(args: impl IntoIterator<Item = OsString>, env: Option<OsString>) -> Result<PathBuf, ConfigError>` (`args` without argv[0]).
  - `rdp::server`: `pub struct ServerParts { pub listen: SocketAddr, pub tls: TlsIdentity, pub username: String, pub password: Secret, pub input: InputStub, pub display: BridgeDisplay, pub gfx: GfxFactory, pub lifecycle: Lifecycle, pub suppressed: Arc<AtomicBool>, pub rtt: Arc<AtomicU32> }`; `pub fn build(p: ServerParts) -> RdpServer`.
  - `bridge`: `pub const STARTUP_WAIT, FLUSH_WAIT, DISCONNECT_WAIT, KVM_CLOSE_WAIT, QUIT_WAIT: Duration` (5 s, 500 ms, 2.2 s, 1 s, 500 ms); `pub enum BridgeError { Tls(TlsError), AdminBind(std::io::ErrorKind), RdpBind(String), Runtime(std::io::ErrorKind), Timeout }` (`Debug`, `Display`, `Error`); `pub enum Exit { Signal, CertificateChanged, ServerStopped }` (`label`); `pub fn spawn(cfg: Config) -> Result<BridgeHandle, BridgeError>` (blocking, ≤ `STARTUP_WAIT`); `pub struct BridgeHandle { pub rdp_addr: SocketAddr, pub admin_addr: SocketAddr, .. }` — `metrics(&self) -> &Arc<Metrics>`, `#[doc(hidden)] hid(&self) -> &Arc<HidControl>`, `async fn exit_requested(&mut self)`, `async fn shutdown(self)`, `#[doc(hidden)] async fn shutdown_skipping_disconnect(self) -> u32` (§5.2 without step 3; returns the `Quit`s it took), `fn run_until_signal(self) -> Exit`, `#[doc(hidden)] fn block_rdp_runtime_for(&self, d: Duration)`; `Drop` stops everything best-effort.
  - The `kvm-rdp` binary: `kvm-rdp --config <file>` (or `KVM_RDP_CONFIG`); exit 0 after a signal or a certificate change, 1 if startup failed or the RDP server stopped, 2 on a config or logging error.

- [ ] **Step 1: Write the failing tests.** Append to `config.rs`'s `tests` module:

```rust
    #[test]
    fn the_config_path_comes_from_the_flag_or_the_variable() {
        use std::ffi::OsString;
        let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        let p = PathBuf::from;
        assert_eq!(config_path(os(&["--config", "/a.toml"]), Some("/b.toml".into())).unwrap(), p("/a.toml"));
        assert_eq!(config_path(os(&["--config=/a.toml"]), None).unwrap(), p("/a.toml"));
        assert_eq!(config_path(os(&[]), Some("/b.toml".into())).unwrap(), p("/b.toml"));
        assert!(config_path(os(&[]), None).is_err());
        assert!(config_path(os(&["--config"]), None).is_err());
        assert!(config_path(os(&["--verbose"]), None).is_err());
    }
```

Add `pub mod server;` to `rdp/mod.rs` and `pub mod bridge;` to `lib.rs`; create `bridge.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use kvm_sim::{KvmSim, SimConfig, Source};
    use std::path::Path;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn sim() -> KvmSim {
        KvmSim::start(SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap())).await.unwrap()
    }

    /// The real loader over the files a deployment has: loopback and
    /// ephemeral ports, a fresh TLS pair, the certificate polled every 200 ms.
    fn config_for(sim: &KvmSim, dir: &Path, edit: impl FnOnce(&mut Config)) -> Config {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
        std::fs::write(dir.join("nla.pass"), "bridge-unit-test-nla-password\n").unwrap();
        std::fs::write(dir.join("kvm.pass"), format!("{}\n", sim.password())).unwrap();
        let p = sim.ports();
        let toml = format!(
            "[rdp]\nlisten = \"127.0.0.1:0\"\nnla_password_file = \"nla.pass\"\ntls_cert_file = \"cert.pem\"\n\
             tls_key_file = \"key.pem\"\ncert_poll_interval = \"200ms\"\n[admin]\nlisten = \"127.0.0.1:0\"\n\
             [kvm]\nhost = \"{}\"\nspki_sha256 = \"{}\"\npassword_file = \"kvm.pass\"\n\
             web_port = {}\nvideo_port = {}\ncontrol_port = {}\n",
            sim.host(),
            sim.spki_sha256(),
            p.web,
            p.video,
            p.control
        );
        std::fs::write(dir.join("kvm-rdp.toml"), toml).unwrap();
        let mut c = Config::load(&dir.join("kvm-rdp.toml")).unwrap();
        edit(&mut c);
        c
    }

    async fn start(cfg: Config) -> Result<BridgeHandle, BridgeError> {
        tokio::task::spawn_blocking(move || spawn(cfg)).await.unwrap()
    }

    async fn get(addr: SocketAddr, path: &str) -> u16 {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).split(' ').nth(1).unwrap().parse().unwrap()
    }

    /// §4.5, §5.1, §5.2: ready and live; a raw TCP connect costs no KVM
    /// traffic; shutdown without a session stops the server with the first
    /// `Quit` (no connection is there to consume it — Task 6.6 proves the
    /// second), inside §5.2's 5 s, and frees the listener; never a logout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_binds_reports_ready_and_shuts_down_promptly() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        let (rdp, admin) = (h.rdp_addr, h.admin_addr);
        assert_eq!(get(admin, "/readyz").await, 200);
        assert_eq!(get(admin, "/livez").await, 200);
        drop(tokio::net::TcpStream::connect(rdp).await.unwrap());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = Instant::now();
        h.shutdown().await;
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
        assert!(tokio::net::TcpStream::connect(rdp).await.is_err(), "the RDP listener is still open");
        let s = sim.stats();
        assert_eq!((s.accepts_web, s.accepts_video, s.accepts_control, s.logouts), (0, 0, 0, 0));
    }

    /// §4.4: with no client connected, a renewed certificate asks for an exit
    /// (to be restarted with it) within 5× the poll; no change, no exit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_changed_certificate_requests_an_exit() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let mut h = start(config_for(&sim, d.path(), |_| {})).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(500), h.exit_requested()).await.is_err());
        let cert = d.path().join("cert.pem");
        let pem = std::fs::read(&cert).unwrap();
        std::fs::write(&cert, [pem.as_slice(), b"\n"].concat()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), h.exit_requested())
            .await
            .expect("no exit request within 5× the poll interval");
        h.shutdown().await;
    }

    /// §4.4 (rev 6.2; the deployment spec's decision 8): a renewed
    /// certificate never ends a live session — the exit waits until no
    /// client is connected. Driven on the watcher itself, with the
    /// generation a connected client would hold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_change_waits_for_the_session_to_end() {
        let d = tempfile::tempdir().unwrap();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let (cert, key) = (d.path().join("cert.pem"), d.path().join("key.pem"));
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        let gens = Arc::new(Generations::default());
        let generation = gens.begin(); // a client is connected
        let (tx, mut rx) = watch::channel(false);
        let poll = Duration::from_millis(100);
        tokio::spawn(watch_certificate(cert.clone(), key, poll, gens.clone(), tx));
        let pem = std::fs::read(&cert).unwrap();
        std::fs::write(&cert, [pem.as_slice(), b"\n"].concat()).unwrap();
        assert!(
            tokio::time::timeout(poll * 10, rx.wait_for(|v| *v)).await.is_err(),
            "the certificate change cut a live session"
        );
        assert_eq!(gens.end(), Some(generation)); // the client leaves
        let exited = tokio::time::timeout(poll * 5 + Duration::from_secs(1), rx.wait_for(|v| *v)).await;
        assert!(exited.is_ok_and(|r| r.is_ok()), "no exit once the session ended");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unbindable_rdp_listener_fails_spawn() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let r = start(config_for(&sim, d.path(), |c| c.rdp.listen = addr)).await;
        assert!(matches!(r, Err(BridgeError::RdpBind(_))), "{:?}", r.err());
    }

    /// §4.4: a bad TLS identity fails before anything binds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bad_tls_identity_fails_before_anything_binds() {
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let cfg = config_for(&sim, d.path(), |_| {});
        std::fs::write(d.path().join("key.pem"), "not a key\n").unwrap();
        let r = start(cfg).await;
        assert!(matches!(r, Err(BridgeError::Tls(TlsError::NoKey))), "{:?}", r.err());
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- bridge config::tests::the_config_path` — Expected: FAIL to compile (`spawn`, `config_path` not found).

- [ ] **Step 3: Implement `config_path`.** In `config.rs`, after `impl Config { .. }`:

```rust
/// `--config <file>` or `--config=<file>`, else `KVM_RDP_CONFIG` (§4.4) —
/// the only environment variable the bridge reads. `args` excludes argv[0].
pub fn config_path(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    env: Option<std::ffi::OsString>,
) -> Result<PathBuf, ConfigError> {
    let mut args = args.into_iter();
    let mut found = None;
    while let Some(a) = args.next() {
        if a == "--config" {
            found = Some(PathBuf::from(args.next().ok_or_else(|| invalid("--config needs a file"))?));
        } else if let Some(v) = a.to_str().and_then(|s| s.strip_prefix("--config=")) {
            found = Some(PathBuf::from(v));
        } else {
            return Err(invalid(format!("unknown argument {a:?} (usage: kvm-rdp --config <file>)")));
        }
    }
    found
        .or_else(|| env.map(PathBuf::from))
        .ok_or_else(|| invalid("no config: pass --config <file> or set KVM_RDP_CONFIG"))
}
```

- [ ] **Step 4: Implement the server.** Create `rdp/server.rs`:

```rust
//! The `RdpServer` (§5.1, §9.1): NLA only — `with_hybrid` over our own
//! rustls config and the certificate's CredSSP key — Preempt, the
//! callbacks of Task 5.2, the suppression and RTT handles the shell
//! samples, and auto-detect enabled (§6.6).
use crate::config::Secret;
use crate::rdp::display::BridgeDisplay;
use crate::rdp::gfx::GfxFactory;
use crate::rdp::handler::Lifecycle;
use crate::rdp::input::InputStub;
use crate::rdp::tls::TlsIdentity;
use ironrdp_server::{ConnectionPolicy, Credentials, RdpServer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32};

pub struct ServerParts {
    pub listen: SocketAddr,
    pub tls: TlsIdentity,
    pub username: String,
    pub password: Secret,
    pub input: InputStub,
    pub display: BridgeDisplay,
    pub gfx: GfxFactory,
    pub lifecycle: Lifecycle,
    pub suppressed: Arc<AtomicBool>,
    pub rtt: Arc<AtomicU32>,
}

/// Build the server on the RDP runtime's thread (`RdpServer` is `!Send`).
#[must_use]
pub fn build(p: ServerParts) -> RdpServer {
    let TlsIdentity { acceptor, public_key } = p.tls;
    let mut server = RdpServer::builder()
        .with_addr(p.listen)
        .with_hybrid(acceptor, public_key)
        .with_input_handler(p.input)
        .with_display_handler(p.display)
        .with_gfx_factory(Some(Box::new(p.gfx)))
        .with_connection_policy(ConnectionPolicy::Preempt)
        .with_connection_handler(Some(Box::new(p.lifecycle)))
        .with_display_suppressed_handle(p.suppressed)
        .with_autodetect_rtt_handle(p.rtt)
        .build();
    // CredSSP compares the account name exactly and ignores the domain.
    server.set_credentials(Some(Credentials {
        username: p.username,
        password: p.password.expose().to_owned(),
        domain: None,
    }));
    server.enable_autodetect();
    server
}
```

- [ ] **Step 5: Implement the bridge.** Above the tests in `bridge.rs`:

```rust
//! The assembly (§4.3, §5.2). The RDP runtime — current-thread under a
//! `LocalSet`, on its own thread — runs IronRDP's `!Send` server, the
//! heartbeat and the pump's shell; the one-worker KVM runtime runs the KVM
//! actor, the admin listener and the certificate watcher. `shutdown` is
//! §5.2 in order, inside 5 s (DC13).
use crate::admin::{self, Health};
use crate::config::Config;
use crate::hid::{HidControl, ReleaseTrigger};
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::session::{self, KvmDeps, SessionConfig};
use crate::metrics::Metrics;
use crate::msg::{Generations, KvmCommand, KvmEvent, RdpInput, kvm_stream_capacity};
use crate::pump::PumpConfig;
use crate::pump::shell::{PumpShell, ShellDeps};
use crate::rdp::accept::AcceptRate;
use crate::rdp::display::{BridgeDisplay, DisplayShared};
use crate::rdp::gfx::{GfxFactory, GfxSlot};
use crate::rdp::handler::Lifecycle;
use crate::rdp::input::InputStub;
use crate::rdp::server::{self, ServerParts};
use crate::rdp::tls::{self, TlsError};
use ironrdp_server::ServerEvent;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, watch};

/// How long `spawn` waits for the RDP listener.
pub const STARTUP_WAIT: Duration = Duration::from_secs(5);
/// §5.2's steps (DC13): 4.7 s in all, inside the 5 s exit.
pub const FLUSH_WAIT: Duration = Duration::from_millis(500);
pub const DISCONNECT_WAIT: Duration = Duration::from_millis(2200);
pub const KVM_CLOSE_WAIT: Duration = Duration::from_secs(1);
pub const QUIT_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub enum BridgeError {
    Tls(TlsError),
    AdminBind(std::io::ErrorKind),
    RdpBind(String),
    Runtime(std::io::ErrorKind),
    Timeout,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Tls(e) => write!(f, "TLS identity: {e}"),
            BridgeError::AdminBind(k) => write!(f, "admin listener: {k}"),
            BridgeError::RdpBind(e) => write!(f, "RDP listener: {e}"),
            BridgeError::Runtime(k) => write!(f, "runtime: {k}"),
            BridgeError::Timeout => write!(f, "the RDP listener did not start within {STARTUP_WAIT:?}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Why the bridge stopped (the binary's exit code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Signal,
    CertificateChanged,
    ServerStopped,
}

impl Exit {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Exit::Signal => "signal",
            Exit::CertificateChanged => "certificate_changed",
            Exit::ServerStopped => "server_stopped",
        }
    }
}

/// What the shutdown sequence touches.
struct Control {
    accepting: Arc<AtomicBool>,
    hid: Arc<HidControl>,
    to_kvm: mpsc::UnboundedSender<KvmCommand>,
    to_pump: mpsc::UnboundedSender<RdpInput>,
    events: mpsc::UnboundedSender<ServerEvent>,
    rdp_done: watch::Receiver<bool>,
}

pub struct BridgeHandle {
    pub rdp_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    metrics: Arc<Metrics>,
    hid: Arc<HidControl>,
    ctl: Arc<Control>,
    exit: watch::Receiver<bool>,
    kvm_rt: Option<Runtime>,
    // Detached on shutdown: it ends once `RdpServer::run` returns.
    _rdp_thread: std::thread::JoinHandle<()>,
}

/// The shell's dependencies that cross to the RDP thread.
struct ShellParts {
    cfg: PumpConfig,
    metrics: Arc<Metrics>,
    gens: Arc<Generations>,
    hid: Arc<HidControl>,
    display: Arc<DisplayShared>,
    suppressed: Arc<AtomicBool>,
    rtt: Arc<AtomicU32>,
    to_kvm: mpsc::UnboundedSender<KvmCommand>,
}

struct RdpParts {
    server: ServerParts,
    shell: ShellParts,
    rdp_inputs: mpsc::UnboundedReceiver<RdpInput>,
    kvm_events: mpsc::Receiver<KvmEvent>,
    health: Arc<Health>,
    beat: Duration,
}

type Ready = Result<(SocketAddr, mpsc::UnboundedSender<ServerEvent>), BridgeError>;

/// Start the bridge; returns once the RDP listener is bound (blocking).
pub fn spawn(cfg: Config) -> Result<BridgeHandle, BridgeError> {
    tls::install_crypto_provider();
    let identity = tls::load(&cfg.rdp.tls_cert_file, &cfg.rdp.tls_key_file).map_err(BridgeError::Tls)?;
    let metrics = Arc::new(Metrics::default());
    let health = Arc::new(Health::new(cfg.admin.liveness_timeout));
    health.set_tls_loaded();
    let gens = Arc::new(Generations::default());
    let hid = Arc::new(HidControl::new(cfg.input.queue, metrics.clone()));
    let display = DisplayShared::new(cfg.video.default_size);
    let accepting = Arc::new(AtomicBool::new(true));
    let suppressed = Arc::new(AtomicBool::new(false));
    let rtt = Arc::new(AtomicU32::new(u32::MAX));
    let gfx_slot = GfxSlot::default();
    let pump_cfg = PumpConfig::from_config(&cfg);
    let (to_kvm, kvm_cmds) = mpsc::unbounded_channel();
    let (kvm_tx, kvm_events) = mpsc::channel(kvm_stream_capacity(pump_cfg.hard_cap));
    let (to_pump, rdp_inputs) = mpsc::unbounded_channel();
    let (exit_tx, exit) = watch::channel(false);
    let (done_tx, rdp_done) = watch::channel(false);

    let admin_std = std::net::TcpListener::bind(cfg.admin.listen).map_err(|e| BridgeError::AdminBind(e.kind()))?;
    admin_std.set_nonblocking(true).map_err(|e| BridgeError::AdminBind(e.kind()))?;
    let admin_addr = admin_std.local_addr().map_err(|e| BridgeError::AdminBind(e.kind()))?;

    let kvm_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("kvm-rdp-kvm")
        .enable_all()
        .build()
        .map_err(|e| BridgeError::Runtime(e.kind()))?;
    let admin_listener = {
        let _rt = kvm_rt.enter();
        tokio::net::TcpListener::from_std(admin_std).map_err(|e| BridgeError::AdminBind(e.kind()))?
    };
    kvm_rt.spawn(admin::serve(admin_listener, health.clone(), metrics.clone()));
    kvm_rt.spawn(session::run_actor(
        kvm_cmds,
        KvmDeps {
            ep: Arc::new(KvmEndpoint::from_config(&cfg.kvm)),
            cfg: Arc::new(SessionConfig::from_config(&cfg)),
            to_pump: kvm_tx,
            hid: hid.clone(),
            metrics: metrics.clone(),
        },
    ));
    kvm_rt.spawn(watch_certificate(
        cfg.rdp.tls_cert_file.clone(),
        cfg.rdp.tls_key_file.clone(),
        cfg.rdp.cert_poll_interval,
        gens.clone(),
        exit_tx,
    ));

    let parts = RdpParts {
        server: ServerParts {
            listen: cfg.rdp.listen,
            tls: identity,
            username: cfg.rdp.username.clone(),
            password: cfg.rdp.nla_password.clone(),
            input: InputStub::new(metrics.clone()),
            display: BridgeDisplay::new(display.clone(), to_pump.clone()),
            gfx: GfxFactory::new(gfx_slot.clone(), to_pump.clone(), pump_cfg.hard_cap, metrics.clone()),
            lifecycle: Lifecycle {
                gens: gens.clone(),
                accepting: accepting.clone(),
                rate: AcceptRate::new(cfg.security.accept_rate, cfg.security.accept_window),
                gfx: gfx_slot,
                hid: hid.clone(),
                metrics: metrics.clone(),
                to_pump: to_pump.clone(),
                to_kvm: to_kvm.clone(),
            },
            suppressed: suppressed.clone(),
            rtt: rtt.clone(),
        },
        shell: ShellParts {
            cfg: pump_cfg,
            metrics: metrics.clone(),
            gens,
            hid: hid.clone(),
            display,
            suppressed,
            rtt,
            to_kvm: to_kvm.clone(),
        },
        rdp_inputs,
        kvm_events,
        health: health.clone(),
        beat: (cfg.admin.liveness_timeout / 4).clamp(Duration::from_millis(10), Duration::from_secs(1)),
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Ready>();
    let rdp_thread = match std::thread::Builder::new()
        .name("kvm-rdp-rdp".to_owned())
        .spawn(move || rdp_main(parts, ready_tx, done_tx))
    {
        Ok(t) => t,
        Err(e) => {
            kvm_rt.shutdown_background();
            return Err(BridgeError::Runtime(e.kind()));
        }
    };
    let (rdp_addr, events) = match ready_rx.recv_timeout(STARTUP_WAIT) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            kvm_rt.shutdown_background();
            return Err(e);
        }
        Err(_) => {
            kvm_rt.shutdown_background();
            return Err(BridgeError::Timeout);
        }
    };
    health.set_rdp_bound();
    tracing::info!(rdp = %rdp_addr, admin = %admin_addr, "kvm-rdp ready");
    let ctl = Arc::new(Control { accepting, hid: hid.clone(), to_kvm, to_pump, events, rdp_done });
    Ok(BridgeHandle { rdp_addr, admin_addr, metrics, hid, ctl, exit, kvm_rt: Some(kvm_rt), _rdp_thread: rdp_thread })
}

/// The RDP runtime's thread.
fn rdp_main(p: RdpParts, ready: std::sync::mpsc::Sender<Ready>, done: watch::Sender<bool>) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(BridgeError::Runtime(e.kind())));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let RdpParts { server: parts, shell, rdp_inputs, kvm_events, health, beat } = p;
        let mut server = server::build(parts);
        let events = server.event_sender().clone();
        let deps = ShellDeps {
            cfg: shell.cfg,
            metrics: shell.metrics,
            gens: shell.gens,
            hid: shell.hid,
            display: shell.display,
            events: events.clone(),
            suppressed: shell.suppressed,
            rtt: shell.rtt,
            to_kvm: shell.to_kvm,
        };
        tokio::task::spawn_local(PumpShell::new(deps).run(rdp_inputs, kvm_events));
        tokio::task::spawn_local(heartbeat(health, beat));
        let run = tokio::task::spawn_local(async move { server.run().await.map_err(|e| format!("{e:#}")) });
        let (tx, rx) = oneshot::channel();
        let _ = events.send(ServerEvent::GetLocalAddr(tx));
        match tokio::time::timeout(STARTUP_WAIT, rx).await {
            Ok(Ok(Some(addr))) => {
                if ready.send(Ok((addr, events.clone()))).is_err() {
                    // `spawn` gave up: stop the server again.
                    let _ = events.send(ServerEvent::Quit("startup abandoned".to_owned()));
                }
            }
            _ => {
                // `run()` failed to bind (the queued `GetLocalAddr` died with it).
                let why = match tokio::time::timeout(Duration::from_millis(500), run).await {
                    Ok(Ok(Err(e))) => e,
                    _ => "the RDP listener did not start".to_owned(),
                };
                let _ = ready.send(Err(BridgeError::RdpBind(why)));
                return;
            }
        }
        match run.await {
            Ok(Ok(())) => tracing::info!("RDP server stopped"),
            Ok(Err(e)) => tracing::error!(error = %e, "RDP server failed"),
            Err(_) => tracing::error!("RDP server task failed"),
        }
        done.send_replace(true);
    });
}

/// §4.5: the RDP runtime's heartbeat for `/livez`.
async fn heartbeat(health: Arc<Health>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        health.beat();
    }
}

/// §4.4 (rev 6.2): a renewed certificate restarts the bridge — exit 0, then
/// the orchestrator starts it again with the new pair — but never under a
/// live session: once the change is seen, the exit waits until no client is
/// connected (the companion deployment spec's decision 8: an LE renewal
/// must not cut the operator off). Polled at most every second meanwhile;
/// a client that connects in the gap before §5.2 stops accepting is ended
/// with cause `shutdown` like any other.
async fn watch_certificate(
    cert: PathBuf,
    key: PathBuf,
    every: Duration,
    gens: Arc<Generations>,
    exit: watch::Sender<bool>,
) {
    let first = tls::fingerprint(&cert, &key);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tick.tick().await;
        if tls::fingerprint(&cert, &key) != first {
            break;
        }
    }
    tracing::info!("the TLS certificate changed; restarting once no client is connected");
    let mut idle = tokio::time::interval(every.min(Duration::from_secs(1)));
    loop {
        idle.tick().await;
        if gens.current().is_none() {
            tracing::info!("no client connected; exiting to load the new certificate");
            exit.send_replace(true);
            return;
        }
    }
}

/// §5.2 in order (DC13), each step bounded; never a logout. Returns how
/// many `Quit`s stopping the server took (2 when a live connection consumed
/// the first). `disconnect` false skips step 3 — a test hook only, so that
/// a connected client is still being served when the first `Quit` goes out.
async fn shutdown_sequence(c: Arc<Control>, disconnect: bool) -> u32 {
    let t0 = Instant::now();
    // 1. Stop accepting: `on_accept` refuses from here on.
    c.accepting.store(false, Ordering::SeqCst);
    // 2. Release-all and wait for the websocket flush.
    c.hid.release_all(ReleaseTrigger::Shutdown);
    let (done, rx) = oneshot::channel();
    if c.to_kvm.send(KvmCommand::FlushHid { done }).is_ok() {
        let _ = tokio::time::timeout(FLUSH_WAIT, rx).await;
    }
    // 3. Disconnect the client with cause `shutdown` (2 s watchdog).
    if disconnect {
        let (done, rx) = oneshot::channel();
        if c.to_pump.send(RdpInput::Shutdown { done }).is_ok() {
            let _ = tokio::time::timeout(DISCONNECT_WAIT, rx).await;
        }
    }
    // 4. Close the FLV and websocket; the actor ends (no logout, §5.1).
    let (done, rx) = oneshot::channel();
    if c.to_kvm.send(KvmCommand::Shutdown { done }).is_ok() {
        let _ = tokio::time::timeout(KVM_CLOSE_WAIT, rx).await;
    }
    // 5. `Quit`, and a second one if a connection consumed the first (§5.2).
    let mut done = c.rdp_done.clone();
    let mut quits = 0u32;
    for _ in 0..2 {
        let _ = c.events.send(ServerEvent::Quit("shutdown".to_owned()));
        quits = quits.saturating_add(1);
        if tokio::time::timeout(QUIT_WAIT, done.wait_for(|v| *v)).await.is_ok() {
            break;
        }
    }
    tracing::info!(ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX), quits, "shutdown complete");
    quits
}

async fn signal_or_pending(kind: tokio::signal::unix::SignalKind) {
    match tokio::signal::unix::signal(kind) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

/// Resolves when `rx` turns true; never, if its sender went away first.
async fn turned_true(mut rx: watch::Receiver<bool>) {
    if rx.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn wait_for_exit(exit: watch::Receiver<bool>, mut done: watch::Receiver<bool>) -> Exit {
    use tokio::signal::unix::SignalKind;
    tokio::select! {
        () = signal_or_pending(SignalKind::terminate()) => Exit::Signal,
        () = signal_or_pending(SignalKind::interrupt()) => Exit::Signal,
        () = turned_true(exit) => Exit::CertificateChanged,
        // A dropped sender means the RDP thread ended: stopped too.
        _ = done.wait_for(|v| *v) => Exit::ServerStopped,
    }
}

impl BridgeHandle {
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// L2 drives the HID writer directly until Plan D's input handler (DC7).
    #[doc(hidden)]
    #[must_use]
    pub fn hid(&self) -> &Arc<HidControl> {
        &self.hid
    }

    /// Resolves once the bridge asks to exit (the certificate changed).
    pub async fn exit_requested(&mut self) {
        let _ = self.exit.wait_for(|v| *v).await;
    }

    /// §5.2's sequence; returns once the RDP server has stopped.
    pub async fn shutdown(mut self) {
        let _ = self.run_shutdown(true).await;
    }

    /// Test hook (L2, §5.2's second `Quit`): the sequence without step 3,
    /// so a connected client is still being served when the first `Quit`
    /// goes out; returns how many `Quit`s stopping the server took.
    #[doc(hidden)]
    pub async fn shutdown_skipping_disconnect(mut self) -> u32 {
        self.run_shutdown(false).await
    }

    async fn run_shutdown(&mut self, disconnect: bool) -> u32 {
        let Some(rt) = self.kvm_rt.take() else { return 0 };
        let quits = rt.spawn(shutdown_sequence(self.ctl.clone(), disconnect)).await.unwrap_or(0);
        rt.shutdown_background();
        quits
    }

    /// The binary's main loop: wait for SIGTERM, SIGINT, a certificate
    /// change or the RDP server stopping, then shut down (blocking).
    #[must_use]
    pub fn run_until_signal(mut self) -> Exit {
        let Some(rt) = self.kvm_rt.take() else { return Exit::ServerStopped };
        let (ctl, exit, done) = (self.ctl.clone(), self.exit.clone(), self.ctl.rdp_done.clone());
        let why = rt.block_on(async move {
            let why = wait_for_exit(exit, done).await;
            tracing::info!(reason = why.label(), "shutting down");
            let _ = shutdown_sequence(ctl, true).await;
            why
        });
        rt.shutdown_timeout(Duration::from_millis(200));
        why
    }

    /// Test hook (L2 `/livez`): block the RDP runtime's thread for `d`.
    #[doc(hidden)]
    pub fn block_rdp_runtime_for(&self, d: Duration) {
        let _ = self.ctl.to_pump.send(RdpInput::Stall(d));
    }
}

impl Drop for BridgeHandle {
    /// Best effort for a handle dropped without `shutdown` (a failing test).
    fn drop(&mut self) {
        if let Some(rt) = self.kvm_rt.take() {
            self.ctl.accepting.store(false, Ordering::SeqCst);
            let (done, _) = oneshot::channel();
            let _ = self.ctl.to_pump.send(RdpInput::Shutdown { done });
            for _ in 0..2 {
                let _ = self.ctl.events.send(ServerEvent::Quit("dropped".to_owned()));
            }
            rt.shutdown_background();
        }
    }
}
```

- [ ] **Step 6: The binary.** Create `src/main.rs`:

```rust
//! `kvm-rdp` (spec §4.4, §5.2): read the config named by `--config` or
//! `KVM_RDP_CONFIG` — the only environment variable read — start the
//! bridge, and run until SIGTERM, SIGINT or a certificate change; exit 0
//! after §5.2's shutdown.
use kvm_rdp::bridge::{self, Exit};
use kvm_rdp::config::{Config, config_path};
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match config_path(std::env::args_os().skip(1), std::env::var_os("KVM_RDP_CONFIG")) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kvm-rdp: {e}");
            return ExitCode::from(2);
        }
    };
    let cfg = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kvm-rdp: {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };
    if let Err(e) = kvm_rdp::logging::init(&cfg.log.filter) {
        eprintln!("kvm-rdp: {e}");
        return ExitCode::from(2);
    }
    let handle = match bridge::spawn(cfg) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    match handle.run_until_signal() {
        Exit::Signal | Exit::CertificateChanged => ExitCode::SUCCESS,
        Exit::ServerStopped => ExitCode::FAILURE,
    }
}
```

and add to `crates/kvm-rdp/Cargo.toml`, after the `[lib]` table:

```toml
# No unit tests in the binary: a third IronRDP-linked test executable would
# cost a link and its disk (§13). L2's secrets case runs it as a subprocess.
[[bin]]
name = "kvm-rdp"
path = "src/main.rs"
test = false
bench = false
```

- [ ] **Step 7: Run the tests.** `cargo test --workspace --all-features --lib -- bridge config::tests::the_config_path` — Expected: PASS — 6 passed.

- [ ] **Step 8: Prove the certificate watcher bites.** In `watch_certificate`, change `!= first` to `!= tls::fingerprint(&cert, &cert)`.

Run: `cargo test --workspace --all-features --lib -- bridge::tests::a_changed_certificate_requests_an_exit`
Expected: FAIL — the first `assert!(… .is_err())` (an exit was requested with no change). Restore; re-run: 1 passed. Then, in `watch_certificate`, change `if gens.current().is_none() {` to `if true {` and run `cargo test --workspace --all-features --lib -- bridge::tests::a_certificate_change_waits` — Expected: FAIL — `the certificate change cut a live session`. Restore; re-run: 1 passed. (The second `Quit` is proven in Task 6.6's `a_live_connection_consumes_the_first_quit`, through `shutdown_skipping_disconnect`.)

- [ ] **Step 9: Gate** (clippy, test, budget). Then `cargo build --workspace --all-features --all-targets` (the gate's feature resolution, so no dependency is rebuilt; never `-p`) and `"$CARGO_TARGET_DIR/debug/kvm-rdp" --verbose; echo $?` — Expected: `kvm-rdp: invalid config: unknown argument "--verbose" (usage: kvm-rdp --config <file>)` then `2`.

- [ ] **Step 10: Commit.**

```bash
git add crates/kvm-rdp/src/rdp/server.rs crates/kvm-rdp/src/rdp/mod.rs crates/kvm-rdp/src/bridge.rs \
  crates/kvm-rdp/src/main.rs crates/kvm-rdp/src/lib.rs crates/kvm-rdp/src/config.rs crates/kvm-rdp/Cargo.toml
git commit -m "kvm-rdp: the bridge — two runtimes, Preempt + NLA server, §5.2 shutdown in 5 s, the binary (§4.3, §5)" \
  -m "Stop accepting via on_accept and a 2 s disconnect watchdog (DC13); a second Quit when a connection took the first; certificate change restarts." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 6 — L2 against kvm-sim

§11.3 on the real stack: the bridge in process (`bridge::spawn`), kvm-sim on the test runtime, and an in-process IronRDP client with NLA on its own thread. One test binary, `tests/l2` (§13). Scaled timers and one-sided bounds (§11.1); every case also asserts, on drop, that kvm-sim saw no logout.

### Task 6.1: The L2 harness, the client, and the lifecycle case

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/harness.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/client.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/lifecycle.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/Cargo.toml` (`[[test]]`)

**Interfaces:**
- Consumes: `kvm_rdp::{bridge, config::Config, metrics::Metrics, msg::Cause}`; `kvm_sim::{KvmSim, SimConfig, SimEvent, Source}`; IronRDP's client crates (dev): `ironrdp-connector`, `-async`, `-tokio` (`reqwest`), `-tls` (`rustls`), `-session`, `-graphics`, plus `-dvc`, `-egfx`, `-core`, `-pdu`, `-svc`; `kvm_proto::h264::split_annex_b`.
- Produces (test-only):
  - `harness`: `USER`, `NLA` (also the secrets canary), `T` (10 s), `SET_MODE`, `KBD_ZERO`; `ms(u64) -> Duration`; `es3() -> SimConfig`; `main_360p() -> SimConfig`; `source(&str) -> Source`; `sized(&mut Config)` (default size 640×360: no connect-time resize); `write_files(sim: &KvmSim, dir: &Path)`; `edit_toml(dir: &Path, from: &str, to: &str)`; `struct Env { pub sim, pub dir, pub rdp, pub admin, .. }` with `env(SimConfig, impl FnOnce(&mut Config)) -> Env`, `bridge()`, `metrics()`, `client(Opts) -> Client`, `get(&str) -> (u16, String)`, `logins() -> u64`, `shutdown(&mut self)`, `take_bridge(&mut self) -> BridgeHandle`; `streaming(impl FnOnce(&mut Config)) -> (Env, Client)`; `until(Duration, impl FnMut() -> bool) -> bool`; `within(took, configured)`; `flv_opens`, `ws_opens`, `hid_on(log, conn)`; the oracle — `LONGGOP`, `barcodes(fixture) -> HashMap<Vec<u8>, usize>`, `index_of(&map, annex_b) -> usize`, `sent_on(log, conn) -> Vec<usize>`, `assert_run(got, sent, what)`.
  - `client`: `enum Ack { Normal, Withhold, Suspend }`; `enum Ev { Connected, ConnectFailed(String), Gfx(GfxPdu), DeactivateAll, Reactivated(u16, u16), Terminated(String), Closed(String) }`; `struct Opts` (`new(source: u8)`, `user`, `domain`, `password`, `no_credssp`, `caps`, `ack`, `recv_buffer`); `census_caps()`, `v8_only()`; `struct Client` — `connect(SocketAddr, Opts)`, `with_log`, `events`, `wait_for`, `never`, `connected`, `refused`, `set_ack`, `stop_reading`, `readvertise`, `close`; `struct Picture { frame_id, annex_b }`, `pictures(&[Ev])`, `nal_types(&[u8])`, `timeline(&[Ev]) -> Vec<String>`, `terminated(&[Ev]) -> Option<String>`, `description(Cause) -> String`, `takeover() -> String`.

- [ ] **Step 1: Register the binary.** Append to `crates/kvm-rdp/Cargo.toml`:

```toml
# The one integration-test binary (§13): every L2 case links here.
[[test]]
name = "l2"
path = "tests/l2/main.rs"
```

and under `[dev-dependencies]`:

```toml
# L2's secrets case sends the real binary a SIGTERM (already in the graph via tokio).
libc = "0.2"
```

- [ ] **Step 2: The binary root.** Create `tests/l2/main.rs`:

```rust
//! L2 (spec §11.3): the bridge in process, kvm-sim on loopback, and an
//! in-process IronRDP client with NLA. One integration-test binary (§13).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod client;
mod harness;
mod lifecycle;
```

- [ ] **Step 3: The harness.** Create `tests/l2/harness.rs`:

```rust
//! The L2 environment (§11.1, §11.3): kvm-sim on this test's runtime, the
//! bridge in process from the files a deployment would write, scaled
//! timers, and the assertion every case shares: kvm-sim never sees a
//! logout (§3.2). Each case uses a subset of these helpers.
#![allow(dead_code)]
use crate::client::{Client, Opts};
use kvm_proto::h264::split_annex_b;
use kvm_rdp::bridge::{self, BridgeHandle};
use kvm_rdp::config::Config;
use kvm_rdp::metrics::Metrics;
use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const USER: &str = "kvm";
/// The NLA password — and the secrets case's canary (§11.3).
pub const NLA: &str = "l2-canary-7f3a9c2e5b1d4a6f8e0c";
/// The upper bound on anything L2 waits for.
pub const T: Duration = Duration::from_secs(10);
pub const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
pub const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const ES3_FIXTURE: &str = "360p30_es3like_poc0.h264";
pub const P360: &str = "360p30_main_full.h264";
pub const P480: &str = "480p30_main_full.h264";
/// Main, 640×360, keyint 300: no periodic IDR for 10 s after a GOP restart,
/// so a side-FLV case sees only the IDR it forced.
pub const LONGGOP: &str = "360p30_main_longgop.h264";

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// The ES3-shaped POC-0 fixture (640×360, Baseline) at the ES3's pacing.
pub fn es3() -> SimConfig {
    SimConfig::es3(source(ES3_FIXTURE))
}

/// The Main 360p fixture: the resolution-change pair's first half.
pub fn main_360p() -> SimConfig {
    SimConfig::es3(source(P360))
}

pub fn source(name: &str) -> Source {
    Source::fixture(name).unwrap()
}

/// The fixtures' size as the default: no connect-time resize, no slate.
pub fn sized(c: &mut Config) {
    c.video.default_size = (640, 360);
}

/// A deployment's files in `dir`: the secrets, a fresh TLS pair, and a
/// config for `sim` with ephemeral loopback listeners, scaled per §11.1.
pub fn write_files(sim: &KvmSim, dir: &Path) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    std::fs::write(dir.join("nla.pass"), format!("{NLA}\n")).unwrap();
    std::fs::write(dir.join("kvm.pass"), format!("{}\n", sim.password())).unwrap();
    let p = sim.ports();
    let toml = format!(
        "[rdp]\nlisten = \"127.0.0.1:0\"\nusername = \"{USER}\"\nnla_password_file = \"nla.pass\"\n\
         tls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\n\
         [admin]\nlisten = \"127.0.0.1:0\"\nliveness_timeout = \"1s\"\n\
         [kvm]\nhost = \"{host}\"\nspki_sha256 = \"{pin}\"\npassword_file = \"kvm.pass\"\n\
         web_port = {web}\nvideo_port = {video}\ncontrol_port = {control}\n\
         connect_timeout = \"1s\"\nlogin_timeout = \"2s\"\nupstream_deadline = \"5s\"\n\
         [kvm.backoff]\ninitial = \"50ms\"\nmax = \"400ms\"\n\
         [video]\navc420_timeout = \"2s\"\ndisconnect_watchdog = \"1s\"\nsuppress_debounce = \"300ms\"\n\
         [input]\nhid_write_timeout = \"300ms\"\n\
         [security]\naccept_rate = 1000\n",
        host = sim.host(),
        pin = sim.spki_sha256(),
        web = p.web,
        video = p.video,
        control = p.control,
    );
    std::fs::write(dir.join("kvm-rdp.toml"), toml).unwrap();
}

/// Replace one exact line fragment of the written config.
pub fn edit_toml(dir: &Path, from: &str, to: &str) {
    let path = dir.join("kvm-rdp.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{from:?} is not in the config");
    std::fs::write(&path, text.replace(from, to)).unwrap();
}

pub struct Env {
    pub sim: KvmSim,
    pub dir: tempfile::TempDir,
    pub rdp: SocketAddr,
    pub admin: SocketAddr,
    bridge: Option<BridgeHandle>,
}

/// kvm-sim, then the bridge over it, configured by the real loader and
/// then `edit`.
pub async fn env(sim: SimConfig, edit: impl FnOnce(&mut Config)) -> Env {
    let sim = KvmSim::start(sim).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_files(&sim, dir.path());
    let mut cfg = Config::load(&dir.path().join("kvm-rdp.toml")).unwrap();
    edit(&mut cfg);
    let bridge = tokio::task::spawn_blocking(move || bridge::spawn(cfg)).await.unwrap().unwrap();
    Env { rdp: bridge.rdp_addr, admin: bridge.admin_addr, sim, dir, bridge: Some(bridge) }
}

/// A sized ES3 session with `edit`, streaming (five pictures in).
pub async fn streaming(edit: impl FnOnce(&mut Config)) -> (Env, Client) {
    let env = env(es3(), |c| {
        sized(c);
        edit(c);
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| crate::client::pictures(e).len() >= 5).await;
    (env, c)
}

impl Env {
    pub fn bridge(&self) -> &BridgeHandle {
        self.bridge.as_ref().unwrap()
    }

    pub fn metrics(&self) -> &Metrics {
        self.bridge().metrics()
    }

    pub fn client(&self, opts: Opts) -> Client {
        Client::connect(self.rdp, opts)
    }

    pub fn logins(&self) -> u64 {
        self.sim.stats().logins_ok
    }

    pub async fn shutdown(&mut self) {
        if let Some(b) = self.bridge.take() {
            b.shutdown().await;
        }
    }

    /// The bridge, for a case that shuts it down its own way.
    pub fn take_bridge(&mut self) -> BridgeHandle {
        self.bridge.take().unwrap()
    }

    /// One admin request: (status, body).
    pub async fn get(&self, path: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(self.admin).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: l2\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(T, s.read_to_end(&mut buf)).await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        (status, body)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert_eq!(self.sim.stats().logouts, 0, "§3.2: the bridge never logs out");
        }
    }
}

/// Poll `f` every 10 ms until it holds or `timeout` passes.
pub async fn until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    loop {
        if f() {
            return true;
        }
        if t0.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(ms(10)).await;
    }
}

/// §11.1's one-sided bound: within 5× the configured value, not before 0.5×.
pub fn within(took: Duration, configured: Duration) {
    assert!(took >= configured / 2 && took <= configured * 5, "took {took:?} for a configured {configured:?}");
}

pub fn flv_opens(log: &[SimEvent]) -> Vec<u64> {
    log.iter().filter_map(|e| if let SimEvent::FlvOpen { conn } = e { Some(*conn) } else { None }).collect()
}

pub fn ws_opens(log: &[SimEvent]) -> Vec<u64> {
    log.iter().filter_map(|e| if let SimEvent::WsOpen { conn } = e { Some(*conn) } else { None }).collect()
}

/// Every HID frame kvm-sim received on websocket `conn`, in order.
pub fn hid_on(log: &[SimEvent], conn: u64) -> Vec<Vec<u8>> {
    log.iter()
        .filter_map(|e| match e {
            SimEvent::Hid { conn: c, bytes } if *c == conn => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// A slice NAL with any trailing zero bytes trimmed (§6.2 trims them).
fn key(nal: &[u8]) -> Vec<u8> {
    let end = nal.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    nal[..end].to_vec()
}

fn first_slice<'a>(nals: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    key(nals.into_iter().find(|n| matches!(n[0] & 0x1F, 1 | 5)).unwrap())
}

/// The oracle (§11.1), independent of the bridge: a fixture's frames by
/// first slice NAL → barcode index. Every frame must be distinct.
pub fn barcodes(fixture: &str) -> HashMap<Vec<u8>, usize> {
    let src = source(fixture);
    let map: HashMap<_, _> = src.frames.iter().map(|f| (first_slice(f.nals.iter().map(|n| &n[..])), f.index)).collect();
    assert_eq!(map.len(), src.frames.len(), "{fixture}: the frames are not distinct");
    map
}

/// A received picture's barcode index.
pub fn index_of(map: &HashMap<Vec<u8>, usize>, annex_b: &[u8]) -> usize {
    map[&first_slice(split_annex_b(annex_b))]
}

/// The `source_index` of every AU kvm-sim sent on FLV `conn`, in order.
pub fn sent_on(log: &[SimEvent], conn: u64) -> Vec<usize> {
    log.iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { conn: c, source_index, .. } if *c == conn => Some(*source_index),
            _ => None,
        })
        .collect()
}

/// `got` (the client's pictures as barcode indices) is one contiguous run
/// of `sent` (kvm-sim's AUs on one FLV), from `got[0]`'s first occurrence:
/// nothing dropped, reordered, duplicated or from another connection.
pub fn assert_run(got: &[usize], sent: &[usize], what: &str) {
    let start = sent.iter().position(|i| *i == got[0]).unwrap_or_else(|| panic!("{what}: picture {} was never sent", got[0]));
    assert!(sent.len() >= start + got.len(), "{what}: more pictures than AUs sent ({} vs {})", got.len(), sent.len() - start);
    assert_eq!(got, &sent[start..start + got.len()], "{what}");
}
```

- [ ] **Step 4: The client.** Create `tests/l2/client.rs`:

```rust
//! The L2 client (§11.3): IronRDP's own connector with NLA over TLS, a
//! capture `DvcProcessor` for EGFX that ZGFX-unwraps and records every
//! server PDU and acknowledges per mode — no H.264 decoder is ever an
//! oracle — and controls to re-advertise, stop reading or close. Each
//! client runs on its own thread and runtime and binds its own `127.0.0.N`
//! source address (§11.1). Each case uses a subset of these helpers.
#![allow(dead_code)]
use crate::harness::{NLA, T, USER};
use ironrdp_async::FramedWrite as _;
use ironrdp_connector::connection_activation::{ConnectionActivationFactory, ConnectionActivationState};
use ironrdp_connector::{ClientConnector, ConnectionResult, Credentials, DesktopSize};
use ironrdp_core::{ReadCursor, WriteBuf, decode, decode_cursor, impl_as_any};
use ironrdp_dvc::{DrdynvcClient, DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, CapabilitiesAdvertisePdu, CapabilityVersion, FrameAcknowledgePdu, GfxPdu, QueueDepth,
    RawCapabilitySet,
};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::zgfx::Decompressor;
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode};
use ironrdp_pdu::{PduResult, gcc};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::ChannelFlags;
use kvm_proto::h264::split_annex_b;
use kvm_rdp::msg::Cause;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

type Upgraded = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;
type Log = Arc<Mutex<Vec<Ev>>>;

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    Normal,
    /// Never acknowledge (a stalled client).
    Withhold,
    /// Acknowledge with `queue_depth = SUSPEND` (MS-RDPEGFX 2.2.2.13).
    Suspend,
}

#[derive(Debug, Clone)]
pub enum Ev {
    Connected,
    ConnectFailed(String),
    Gfx(GfxPdu),
    DeactivateAll,
    Reactivated(u16, u16),
    /// `ActiveStageOutput::Terminate`: an ErrorInfo's description.
    Terminated(String),
    Closed(String),
}

pub struct Opts {
    source: u8,
    user: String,
    domain: Option<String>,
    password: String,
    credssp: bool,
    caps: Option<Vec<RawCapabilitySet>>,
    ack: Ack,
    /// `SO_RCVBUF` for the client socket (a client that stops reading
    /// should block the server's writes quickly).
    recv_buffer: Option<u32>,
}

impl Opts {
    /// `127.0.0.<source>`, `kvm` with the right password, NLA, the census pair.
    pub fn new(source: u8) -> Opts {
        Opts {
            source,
            user: USER.to_owned(),
            domain: None,
            password: NLA.to_owned(),
            credssp: true,
            caps: Some(census_caps()),
            ack: Ack::Normal,
            recv_buffer: None,
        }
    }
    pub fn user(mut self, u: &str) -> Opts {
        self.user = u.to_owned();
        self
    }
    /// `DOMAIN\user`, as FreeRDP sends it through rdpgw.
    pub fn domain(mut self, d: &str) -> Opts {
        self.domain = Some(d.to_owned());
        self
    }
    pub fn recv_buffer(mut self, bytes: u32) -> Opts {
        self.recv_buffer = Some(bytes);
        self
    }
    pub fn password(mut self, p: &str) -> Opts {
        self.password = p.to_owned();
        self
    }
    pub fn no_credssp(mut self) -> Opts {
        self.credssp = false;
        self
    }
    pub fn caps(mut self, caps: Vec<RawCapabilitySet>) -> Opts {
        self.caps = Some(caps);
        self
    }
    pub fn ack(mut self, ack: Ack) -> Opts {
        self.ack = ack;
        self
    }
}

/// FreeRDP's `/gfx:AVC420` pair (`census.md`, Legs B and C).
pub fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

/// A client with no AVC420 decoder.
pub fn v8_only() -> Vec<RawCapabilitySet> {
    vec![RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0])]
}

enum Ctl {
    StopReading,
    Readvertise,
    Close,
}

pub struct Client {
    log: Log,
    ack: Arc<Mutex<Ack>>,
    ctl: mpsc::UnboundedSender<Ctl>,
}

impl Client {
    pub fn connect(server: SocketAddr, opts: Opts) -> Client {
        let log: Log = Arc::default();
        let ack = Arc::new(Mutex::new(opts.ack));
        let (ctl, rx) = mpsc::unbounded_channel();
        let (l, a) = (log.clone(), ack.clone());
        std::thread::Builder::new()
            .name(format!("l2-client-{}", opts.source))
            .spawn(move || run(server, opts, l, a, rx))
            .unwrap();
        Client { log, ack, ctl }
    }

    pub fn with_log<R>(&self, f: impl FnOnce(&[Ev]) -> R) -> R {
        f(&lock(&self.log))
    }

    pub fn events(&self) -> Vec<Ev> {
        lock(&self.log).clone()
    }

    /// Wait until `pred` holds over the log; panic with the timeline if not.
    pub async fn wait_for(&self, timeout: Duration, pred: impl Fn(&[Ev]) -> bool) -> Vec<Ev> {
        let t0 = Instant::now();
        loop {
            if self.with_log(&pred) {
                return self.events();
            }
            if t0.elapsed() > timeout {
                panic!("no match within {timeout:?}; timeline: {:?}", self.with_log(timeline));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// `pred` never holds for `d`.
    pub async fn never(&self, d: Duration, pred: impl Fn(&[Ev]) -> bool) {
        let t0 = Instant::now();
        while t0.elapsed() < d {
            assert!(!self.with_log(&pred), "it happened; timeline: {:?}", self.with_log(timeline));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn outcome(&self) -> Vec<Ev> {
        self.wait_for(T, |e| e.iter().any(|x| matches!(x, Ev::Connected | Ev::ConnectFailed(_)))).await
    }

    pub async fn connected(&self) {
        let evs = self.outcome().await;
        if let Some(Ev::ConnectFailed(why)) = evs.iter().find(|x| matches!(x, Ev::ConnectFailed(_))) {
            panic!("connect failed: {why}");
        }
    }

    /// The connection was refused; why.
    pub async fn refused(&self) -> String {
        let evs = self.outcome().await;
        evs.iter()
            .find_map(|x| if let Ev::ConnectFailed(w) = x { Some(w.clone()) } else { None })
            .expect("the connection was accepted")
    }

    pub fn set_ack(&self, ack: Ack) {
        *lock(&self.ack) = ack;
    }

    pub fn stop_reading(&self) {
        let _ = self.ctl.send(Ctl::StopReading);
    }

    /// Send the capabilities again on the open EGFX channel.
    pub fn readvertise(&self) {
        let _ = self.ctl.send(Ctl::Readvertise);
    }

    pub fn close(&self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

fn push(log: &Log, ev: Ev) {
    lock(log).push(ev);
}

fn config(opts: &Opts) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size: DesktopSize { width: 1920, height: 1080 },
        monitor_layout: None,
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: opts.credssp,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword { username: opts.user.clone(), password: opts.password.clone() },
        domain: opts.domain.clone(),
        client_build: 0,
        client_name: "kvm-rdp-l2".to_owned(),
        keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0x409,
        keyboard_functional_keys_count: 12,
        connection_type: gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        license_cache: None,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: true,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: opts.caps.is_some(),
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::SUPPORTED,
    }
}

/// TCP from `127.0.0.<source>`, TLS, CredSSP, finalization.
async fn connect(server: SocketAddr, opts: &Opts, log: &Log, ack: &Arc<Mutex<Ack>>) -> Result<(Upgraded, ConnectionResult), String> {
    let socket = TcpSocket::new_v4().map_err(|e| e.to_string())?;
    if let Some(n) = opts.recv_buffer {
        socket.set_recv_buffer_size(n).map_err(|e| format!("SO_RCVBUF: {e}"))?;
    }
    socket
        .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, opts.source), 0)))
        .map_err(|e| format!("bind: {e}"))?;
    let tcp = socket.connect(server).await.map_err(|e| format!("connect: {e}"))?;
    let client_addr = tcp.local_addr().map_err(|e| e.to_string())?;
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config(opts), client_addr);
    if let Some(caps) = &opts.caps {
        let capture = Capture { caps: caps.clone(), log: log.clone(), ack: ack.clone(), zgfx: Decompressor::new(), decoded: 0 };
        connector = connector.with_static_channel(DrdynvcClient::new().with_dynamic_channel(capture));
    }
    let should_upgrade =
        ironrdp_async::connect_begin(&mut framed, &mut connector).await.map_err(|e| format!("begin: {e}"))?;
    let (upgraded, cert) = ironrdp_tls::upgrade_with_certificate_validation(
        framed.into_inner_no_leftover(),
        "localhost",
        ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate,
    )
    .await
    .map_err(|e| format!("tls: {e}"))?;
    let marked = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_tokio::TokioFramed::new(upgraded);
    let key = ironrdp_tls::extract_tls_server_public_key(&cert).ok_or("no server public key")?.to_owned();
    let result = ironrdp_async::connect_finalize(
        marked,
        connector,
        &mut framed,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        "localhost".into(),
        key,
        None,
    )
    .await
    .map_err(|e| format!("finalize: {e}"))?;
    Ok((framed, result))
}

/// The Deactivation-Reactivation Sequence (as IronRDP's own e2e test).
async fn reactivate(framed: &mut Upgraded, factory: &ConnectionActivationFactory, stage: &mut ActiveStage) -> Result<(u16, u16), String> {
    let mut seq = factory.create();
    let mut buf = WriteBuf::new();
    loop {
        let written = ironrdp_async::single_sequence_step_read(framed, &mut seq, &mut buf)
            .await
            .map_err(|e| format!("reactivation: {e}"))?;
        if written.size().is_some() {
            framed.write_all(buf.filled()).await.map_err(|e| format!("reactivation write: {e}"))?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
            ..
        } = seq.connection_activation_state()
        {
            if !stage.reactivate(
                seq.io_channel_id(),
                seq.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            ) {
                return Err("reactivate refused".to_owned());
            }
            return Ok((desktop_size.width, desktop_size.height));
        }
    }
}

fn run(server: SocketAddr, opts: Opts, log: Log, ack: Arc<Mutex<Ack>>, mut ctl: mpsc::UnboundedReceiver<Ctl>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let (mut framed, result) = match tokio::time::timeout(Duration::from_secs(15), connect(server, &opts, &log, &ack)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return push(&log, Ev::ConnectFailed(e)),
            Err(_) => return push(&log, Ev::ConnectFailed("timeout".to_owned())),
        };
        push(&log, Ev::Connected);
        let factory = result.activation_factory;
        let mut stage = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }
        .build();
        // EGFX only: no bitmap ever reaches this image.
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 1920, 1080);
        let mut reading = true;
        loop {
            tokio::select! {
                c = ctl.recv() => match c {
                    Some(Ctl::StopReading) => reading = false,
                    Some(Ctl::Readvertise) => {
                        let Some(caps) = opts.caps.clone() else { continue };
                        let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                        let msg: DvcMessage = Box::new(GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(caps)));
                        let bytes = ironrdp_dvc::encode_dvc_messages(cid, vec![msg], ChannelFlags::empty())
                            .map_err(|e| e.to_string())
                            .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()));
                        match bytes {
                            Ok(b) => {
                                if framed.write_all(&b).await.is_err() {
                                    return push(&log, Ev::Closed("write".to_owned()));
                                }
                            }
                            Err(e) => push(&log, Ev::Closed(format!("readvertise: {e}"))),
                        }
                    }
                    Some(Ctl::Close) | None => {
                        if let Ok(out) = stage.graceful_shutdown() {
                            for o in out {
                                if let ActiveStageOutput::ResponseFrame(f) = o {
                                    let _ = framed.write_all(&f).await;
                                }
                            }
                        }
                        return push(&log, Ev::Closed("client".to_owned()));
                    }
                },
                pdu = framed.read_pdu(), if reading => {
                    let (action, frame) = match pdu {
                        Ok(v) => v,
                        Err(e) => return push(&log, Ev::Closed(format!("read: {e}"))),
                    };
                    let outputs = match stage.process(&mut image, action, &frame) {
                        Ok(o) => o,
                        Err(e) => return push(&log, Ev::Closed(format!("process: {e}"))),
                    };
                    for o in outputs {
                        match o {
                            ActiveStageOutput::ResponseFrame(f) => {
                                if framed.write_all(&f).await.is_err() {
                                    return push(&log, Ev::Closed("write".to_owned()));
                                }
                            }
                            ActiveStageOutput::DeactivateAll => {
                                push(&log, Ev::DeactivateAll);
                                match reactivate(&mut framed, &factory, &mut stage).await {
                                    Ok((w, h)) => push(&log, Ev::Reactivated(w, h)),
                                    Err(e) => return push(&log, Ev::Closed(e)),
                                }
                            }
                            ActiveStageOutput::Terminate(reason) => {
                                return push(&log, Ev::Terminated(reason.description()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    });
}

/// EGFX's client side: records, and acknowledges each `EndFrame` per mode.
struct Capture {
    caps: Vec<RawCapabilitySet>,
    log: Log,
    ack: Arc<Mutex<Ack>>,
    zgfx: Decompressor,
    decoded: u32,
}

impl_as_any!(Capture);

impl DvcProcessor for Capture {
    fn channel_name(&self) -> &str {
        ironrdp_egfx::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        Ok(vec![Box::new(GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(self.caps.clone())))])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let mut plain = Vec::new();
        if let Err(e) = self.zgfx.decompress(payload, &mut plain) {
            push(&self.log, Ev::Closed(format!("zgfx: {e:?}")));
            return Ok(Vec::new());
        }
        let mut cur = ReadCursor::new(&plain);
        let mut replies: Vec<DvcMessage> = Vec::new();
        while !cur.is_empty() {
            let pdu = match decode_cursor::<GfxPdu>(&mut cur) {
                Ok(p) => p,
                Err(e) => {
                    push(&self.log, Ev::Closed(format!("gfx decode: {e:?}")));
                    break;
                }
            };
            if let GfxPdu::EndFrame(end) = &pdu {
                self.decoded = self.decoded.wrapping_add(1);
                let depth = match *lock(&self.ack) {
                    Ack::Normal => Some(QueueDepth::Unavailable),
                    Ack::Suspend => Some(QueueDepth::Suspend),
                    Ack::Withhold => None,
                };
                if let Some(queue_depth) = depth {
                    replies.push(Box::new(GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
                        queue_depth,
                        frame_id: end.frame_id,
                        total_frames_decoded: self.decoded,
                    })));
                }
            }
            push(&self.log, Ev::Gfx(pdu));
        }
        Ok(replies)
    }
}

impl DvcClientProcessor for Capture {}

pub struct Picture {
    pub frame_id: u32,
    pub annex_b: Vec<u8>,
}

/// Every `WireToSurface1`'s Annex-B, with its `StartFrame`'s frame id.
pub fn pictures(evs: &[Ev]) -> Vec<Picture> {
    let mut frame_id = 0;
    let mut out = Vec::new();
    for e in evs {
        match e {
            Ev::Gfx(GfxPdu::StartFrame(s)) => frame_id = s.frame_id,
            Ev::Gfx(GfxPdu::WireToSurface1(w)) => {
                let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
                out.push(Picture { frame_id, annex_b: s.data.to_vec() });
            }
            _ => {}
        }
    }
    out
}

pub fn nal_types(annex_b: &[u8]) -> Vec<u8> {
    split_annex_b(annex_b).map(|n| n[0] & 0x1F).collect()
}

/// The log as labels: `confirm`, `reset WxH`, `surface WxH`, `map`,
/// `idr`/`p`, `delete`, `deactivate`, `reactivated WxH`, `terminated`,
/// `closed`, `failed` (frame markers and acks omitted).
pub fn timeline(evs: &[Ev]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Ev::Connected => None,
            Ev::ConnectFailed(_) => Some("failed".to_owned()),
            Ev::Gfx(GfxPdu::CapabilitiesConfirm(_)) => Some("confirm".to_owned()),
            Ev::Gfx(GfxPdu::ResetGraphics(r)) => Some(format!("reset {}x{}", r.width, r.height)),
            Ev::Gfx(GfxPdu::CreateSurface(s)) => Some(format!("surface {}x{}", s.width, s.height)),
            Ev::Gfx(GfxPdu::MapSurfaceToOutput(_)) => Some("map".to_owned()),
            Ev::Gfx(GfxPdu::DeleteSurface(_)) => Some("delete".to_owned()),
            Ev::Gfx(GfxPdu::WireToSurface1(w)) => {
                let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
                Some(if nal_types(s.data).contains(&5) { "idr" } else { "p" }.to_owned())
            }
            Ev::Gfx(_) => None,
            Ev::DeactivateAll => Some("deactivate".to_owned()),
            Ev::Reactivated(w, h) => Some(format!("reactivated {w}x{h}")),
            Ev::Terminated(_) => Some("terminated".to_owned()),
            Ev::Closed(_) => Some("closed".to_owned()),
        })
        .collect()
}

pub fn terminated(evs: &[Ev]) -> Option<String> {
    evs.iter().find_map(|e| if let Ev::Terminated(s) = e { Some(s.clone()) } else { None })
}

/// What the client shows for `cause` (§6.9's ErrorInfo table).
pub fn description(cause: Cause) -> String {
    cause.error_info().description()
}

/// What an evicted client shows (Preempt, §6.9).
pub fn takeover() -> String {
    ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection).description()
}
```

- [ ] **Step 5: The lifecycle case.** Create `tests/l2/lifecycle.rs`:

```rust
//! §11.3 Lifecycle.
use crate::client::{Opts, description, terminated, timeline, v8_only};
use crate::harness::{T, env, es3, ms, until, within};
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slate_then_resize_then_the_kvm_picture_and_a_clean_reconnect() {
    let env = env(es3(), |_| {}).await;
    let a = env.client(Opts::new(2));
    let evs = a.wait_for(T, |e| timeline(e).iter().filter(|l| *l == "idr").count() >= 2).await;
    let t = timeline(&evs);
    let d = t.iter().position(|l| l == "deactivate").expect("no DeactivateAll");
    assert_eq!(t[..d], ["confirm", "reset 1920x1080", "surface 1920x1080", "map", "idr"], "{t:?}");
    assert_eq!(
        t[d + 1..d + 7],
        ["reactivated 640x360", "delete", "reset 640x360", "surface 640x360", "map", "idr"],
        "{t:?}"
    );
    assert_eq!(env.logins(), 1);
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
    let evs = b.wait_for(T, |e| timeline(e).contains(&"idr".to_owned())).await;
    let t = timeline(&evs);
    assert_eq!(t[..5], ["confirm", "reset 640x360", "surface 640x360", "map", "idr"], "a reconnect sends no Resize: {t:?}");
    assert_eq!(env.logins(), 2);
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
    assert!(!env.sim.events().iter().any(|e| matches!(e, SimEvent::FlvOpen { .. })), "no AVC420 cost an FLV");
}
```

- [ ] **Step 6: Run them.** `cargo test --workspace --all-features --test l2` — Expected: PASS — 2 passed. Both run the whole stack: a failure here is a wiring bug in Parts 3–5 (fix the code, never the expectation), and its panic prints the client's timeline.

- [ ] **Step 7: Prove the oracle bites.** In `pump/core.rs` `Pump::setup`, change `if first && self.slate.as_ref().is_some_and(|s| s.size == (w, h)) && self.send_slate(gfx, now) {` to `if false && self.send_slate(gfx, now) {`.

Run: `cargo test --workspace --all-features --test l2 -- lifecycle::slate_then_resize`
Expected: FAIL — `assertion left == right failed` on `t[..d]` (no `idr` before `deactivate`). Restore; re-run: 1 passed.

- [ ] **Step 8: Gate, and set the final target budget.** Run the clippy and test gate. This is the first build with every IronRDP-linked unit Plan C has — the lib test binary, the `kvm-rdp` binary and the `l2` executable — so re-measure once, as Task 2.1 promised: `du -sh "$CARGO_TARGET_DIR"`, then set `scripts/target-budget.sh`'s default to the measured GiB × 1.3, rounded up to a whole GiB, never below Task 2.1's value; record both numbers in the report for Task 7.1's DC10 text. Then `scripts/target-budget.sh` — Expected: within budget. (`libc` re-hashed the lib test unit, so the first measurement can include a stale copy: if it is over budget, `cargo clean` and the gate once, then measure; over again means stop and report.)

- [ ] **Step 9: Commit.**

```bash
git add crates/kvm-rdp/Cargo.toml Cargo.lock crates/kvm-rdp/tests/l2 scripts/target-budget.sh
git commit -m "kvm-rdp: L2 harness — bridge in process, kvm-sim, an IronRDP NLA client with a capture EGFX channel (§11.3)" \
  -m "Lifecycle: slate, resize before any KVM frame, one login, clean reconnect; no_avc420 (0x7)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6.2: L2 — auth and pre-auth, preemption, generations

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/sessions.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod sessions;`)

**Interfaces:**
- Consumes: Task 6.1's harness (with the oracle helpers) and client; `kvm_sim::{SimEvent, SimStats}`; `kvm_proto::hid::HidFrame`; `BridgeHandle::hid()` (5.4).
- Produces: four L2 cases.

- [ ] **Step 1: Write the cases.** Add `mod sessions;` to `main.rs`; create `tests/l2/sessions.rs`:

```rust
//! §11.3 Auth and pre-auth, Preemption, Generations.
use crate::client::{Opts, pictures, takeover, terminated, timeline};
use crate::harness::{
    ES3_FIXTURE, KBD_ZERO, SET_MODE, T, assert_run, barcodes, env, es3, flv_opens, hid_on, index_of, ms, sent_on, sized,
    ws_opens,
};
use kvm_proto::hid::HidFrame;
use kvm_sim::{SimEvent, SimStats};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn accepts(s: &SimStats) -> u64 {
    s.accepts_web + s.accepts_video + s.accepts_control
}

/// §5.1: with a live session, a wrong-password client, a client without
/// CredSSP and a raw TCP connect sending garbage all fail; the live session
/// keeps receiving frames; kvm-sim records no new TCP accept on any port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_and_pre_auth_attempts_cost_no_kvm_traffic() {
    let env = env(es3(), sized).await;
    let live = env.client(Opts::new(2));
    live.wait_for(T, |e| pictures(e).len() >= 5).await;
    let before = accepts(&env.sim.stats());
    let wrong = env.client(Opts::new(3).password("not-the-password-at-all-0"));
    let plain = env.client(Opts::new(4).no_credssp());
    assert!(!wrong.refused().await.is_empty());
    assert!(!plain.refused().await.is_empty());
    let mut raw = tokio::net::TcpStream::connect(env.rdp).await.unwrap();
    raw.write_all(b"\x03\x00\x00\x13garbage, not an X.224 request").await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(T, raw.read_to_end(&mut sink)).await;
    let n = pictures(&live.events()).len();
    live.wait_for(T, |e| pictures(e).len() >= n + 10 && terminated(e).is_none()).await;
    assert_eq!(accepts(&env.sim.stats()), before, "§5.1: no KVM traffic before auth");
    assert_eq!(env.metrics().sessions.get(), 1);
}

/// §11.3 Preemption: release-all → websocket close → FLV close → login →
/// websocket open → session-start, whose pointer report is at the evicted
/// session's last position (DC7: pushed through `HidControl`, the input
/// handler's entry point) — exactly `[SET_MODE, KBD_ZERO, pointer]`, never a
/// pointer at (0, 0); no logout, never two websockets; the evicted client
/// gets 0x5; a retake from its address within 5 s is refused and the new
/// session is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_releases_closes_and_starts_clean_without_a_logout() {
    let env = env(es3(), sized).await;
    let a = env.client(Opts::new(2));
    a.wait_for(T, |e| pictures(e).len() >= 3).await;
    let ws1 = *ws_opens(&env.sim.events()).last().unwrap();
    let pointer = HidFrame::abs_mouse(0, 1000, 2000);
    let _ = env.bridge().hid().push(pointer, false);
    env.sim.wait_for(T, |l| hid_on(l, ws1).contains(&pointer.to_vec())).await.unwrap();
    let log0 = env.sim.events();
    let flv1 = flv_opens(&log0)[0];
    let b = env.client(Opts::new(3));
    let evs = a.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), takeover());
    b.wait_for(T, |e| pictures(e).len() >= 3).await;
    let n0 = log0.len();
    let log = env
        .sim
        .wait_for(T, |l| ws_opens(&l[n0..]).first().is_some_and(|w| hid_on(&l[n0..], *w).len() >= 3))
        .await
        .unwrap();
    let after = &log[n0..];
    let pos = |what: &str, pred: &dyn Fn(&SimEvent) -> bool| {
        after.iter().position(pred).unwrap_or_else(|| panic!("no {what} in {after:?}"))
    };
    let release = pos("release", &|e| matches!(e, SimEvent::Hid { conn, bytes } if *conn == ws1 && bytes[..] == KBD_ZERO));
    let ws_close = pos("websocket close", &|e| *e == SimEvent::WsClose { conn: ws1 });
    let flv_close = pos("FLV close", &|e| *e == SimEvent::FlvClose { conn: flv1 });
    let login = pos("login", &|e| matches!(e, SimEvent::Login { ok: true }));
    let ws2 = *ws_opens(after).first().unwrap();
    let ws_open = pos("websocket open", &|e| *e == SimEvent::WsOpen { conn: ws2 });
    assert!(release < ws_close && ws_close < flv_close && flv_close < login && login < ws_open, "{after:?}");
    assert_eq!(hid_on(after, ws2), [SET_MODE.to_vec(), KBD_ZERO.to_vec(), pointer.to_vec()]);
    let s = env.sim.stats();
    assert_eq!((s.ws_max_open, s.logouts), (1, 0));
    let retake = env.client(Opts::new(2));
    assert!(!retake.refused().await.is_empty(), "a retake inside the cooldown was let in");
    let n = pictures(&b.events()).len();
    b.wait_for(T, |e| pictures(e).len() >= n + 10 && terminated(e).is_none()).await;
    assert_eq!(env.metrics().sessions.get(), 2);
}

/// §4.3 generations: end the first session with work in flight — a
/// re-advertise's IDR request, deferred inside the setup window — and
/// reconnect at once. The second session sees no frame, timer, request or
/// `Disconnect` from the first: no side FLV opens after its login, and its
/// pictures are exactly its own main FLV's AUs (the barcode oracle, which
/// would catch a first-generation AU reaching it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quick_reconnect_sees_nothing_of_the_previous_generation() {
    let wd = ms(300);
    let env = env(es3(), move |c| {
        sized(c);
        c.video.disconnect_watchdog = wd;
    })
    .await;
    let a = env.client(Opts::new(2));
    a.wait_for(T, |e| pictures(e).len() >= 10).await;
    a.readvertise(); // a Setup cause: an IDR request, deferred or in flight
    a.close();
    let b = env.client(Opts::new(3));
    let evs = b.wait_for(T, |e| pictures(e).len() >= 30).await;
    let t = timeline(&evs);
    assert_eq!(t[..5], ["confirm", "reset 640x360", "surface 640x360", "map", "idr"], "{t:?}");
    b.never(wd * 5, |e| terminated(e).is_some()).await;
    assert_eq!(env.metrics().disconnects.total(), 0);
    assert_eq!(env.metrics().sessions.get(), 2);
    let log = env.sim.events();
    let second_login = log
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, SimEvent::Login { ok: true }))
        .nth(1)
        .unwrap()
        .0;
    let opens = flv_opens(&log[second_login..]);
    assert_eq!(opens.len(), 1, "an IDR request leaked into the second generation: {opens:?}");
    let main2 = opens[0];
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pictures(&b.events()).iter().map(|p| index_of(&map, &p.annex_b)).collect();
    let log = env.sim.wait_for(T, |l| sent_on(l, main2).len() >= got.len()).await.unwrap();
    assert_run(&got, &sent_on(&log, main2), "the second generation");
}

/// §9.1: the account name compares exactly (case-sensitive) and the domain
/// is not part of the compare — `KVM` is refused, `ROWLETT\kvm` (the form
/// FreeRDP sends through rdpgw) is let in. ironrdp-acceptor's
/// `auth_data_by_user` compares `account_name()` only, and sspi computes
/// NTLMv2 from what the client sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_username_compare_is_exact_and_ignores_the_domain() {
    let env = env(es3(), sized).await;
    let upper = env.client(Opts::new(2).user("KVM"));
    assert!(!upper.refused().await.is_empty(), "`KVM` was let in");
    assert_eq!(env.metrics().sessions.get(), 0);
    let domain = env.client(Opts::new(3).domain("ROWLETT"));
    domain.wait_for(T, |e| pictures(e).len() >= 3).await;
    assert_eq!(env.metrics().sessions.get(), 1);
    assert_eq!(env.logins(), 1);
}
```

- [ ] **Step 2: Run them.** `cargo test --workspace --all-features --test l2 -- sessions::` — Expected: PASS — 4 passed. (A failure is a wiring bug: fix the code, never the order — it is §11.3's.)

- [ ] **Step 3: Prove the order bites.** In `kvm/session.rs` `Session::close`, move `self.video.close();` back above the websocket close.

Run: `cargo test --workspace --all-features --test l2 -- sessions::a_takeover`
Expected: FAIL — `assertion failed: release < ws_close && ws_close < flv_close …` (the FLV closes first). Restore; re-run: 1 passed.

- [ ] **Step 4: Gate** (clippy, test, budget). **Step 5: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/sessions.rs crates/kvm-rdp/tests/l2/main.rs
git commit -m "kvm-rdp: L2 — no KVM traffic before auth, a clean takeover with no logout, generations (§11.3)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6.3: L2 — the video oracle per `idr_policy`, side IDR, stranding, NO SIGNAL

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/video.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod video;`)

**Interfaces:**
- Consumes: Task 6.1 (the harness's oracle helpers `barcodes`, `index_of`, `sent_on`, `assert_run`, `LONGGOP`); `kvm_rdp::config::IdrPolicy`; `kvm_sim::{Pacing, SimConfig, SimEvent, Timestamps}`, `KvmSim::{advance, set_signal}`; `kvm_proto::h264::{parse_sps, split_annex_b}`.
- Produces: seven L2 cases.

The oracle is independent of the bridge (§11.1): a received picture is identified by its first slice NAL — byte-identical to one fixture frame, whose index is the frame's barcode — and compared with the `source_index` kvm-sim logged for each AU it sent on the main FLV. The oracle cases run at the ES3's real-time pacing and compare a contiguous window. The **stranding** case is the separate check Plan A's ledger and spec §6.8 (row 4) hand to Plan C's L2: with kvm-sim stopped after each batch (`Pacing::Manual`, `Timestamps::WallClock` so nothing is a burst, §11.5), the last AU kvm-sim shipped must reach the client with no later frame to push it out, and the SPS the client gets must carry the rewrites (§6.8 (a)–(c)) that let a decoder present a POC-type-0 stream at once. Whether a real decoder (Windows App) holds frames stays an acceptance item (§12, L5). The two side-IDR cases run on the long-GOP fixture (keyint 300): no periodic IDR for 10 s after kvm-sim restarts the GOP at the main FLV's subscription, so the only IDR in the window is the one the side FLV forces — on the ES3 fixture's 2 s GOP the periodic IDR races the fallback window.

- [ ] **Step 1: Write the cases.** Add `mod video;` to `main.rs`; create `tests/l2/video.rs`:

```rust
//! §11.3 Video oracle (once per `idr_policy`), Side IDR, the POC-0
//! stranding check (§6.8), NO SIGNAL.
use crate::client::{Opts, nal_types, pictures, terminated};
use crate::harness::{
    ES3_FIXTURE, LONGGOP, T, assert_run, barcodes, env, es3, flv_opens, index_of, ms, sent_on, sized, source, until,
    within,
};
use kvm_proto::h264::{parse_sps, split_annex_b};
use kvm_rdp::config::IdrPolicy;
use kvm_sim::{Pacing, SimConfig, SimEvent, Timestamps};
use std::time::{Duration, Instant};

/// §11.3: from the first KVM IDR on, the client's pictures are exactly
/// kvm-sim's AUs on the main FLV, in order; each matches §6.3's
/// composition (IDR: SPS, PPS, slice; P: slice); EGFX frame ids are
/// consecutive; the first is an IDR carrying SPS/PPS.
async fn oracle(policy: IdrPolicy) {
    let env = env(es3(), move |c| {
        sized(c);
        c.video.idr_policy = policy;
    })
    .await;
    let c = env.client(Opts::new(2));
    let evs = c.wait_for(T, |e| pictures(e).len() >= 60).await;
    let pics = pictures(&evs);
    assert_eq!(nal_types(&pics[0].annex_b), [7, 8, 5], "{policy:?}");
    for p in &pics {
        let t = nal_types(&p.annex_b);
        assert!(t == [7, 8, 5] || t == [1], "{policy:?}: {t:?}");
    }
    for w in pics.windows(2) {
        assert_eq!(w[1].frame_id, w[0].frame_id.wrapping_add(1), "{policy:?}");
    }
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    let main = flv_opens(&env.sim.events())[0];
    // kvm-sim logs an AU once its write returned: wait for the last ones.
    let log = env.sim.wait_for(T, |l| sent_on(l, main).len() >= got.len()).await.unwrap();
    assert_run(&got, &sent_on(&log, main), &format!("{policy:?}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_side() {
    oracle(IdrPolicy::Side).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_reconnect() {
    oracle(IdrPolicy::Reconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_wait() {
    oracle(IdrPolicy::Wait).await;
}

/// The long-GOP fixture at the ES3's pacing, sized, `idr_side_timeout` set.
async fn longgop(side_timeout: Duration) -> crate::harness::Env {
    env(SimConfig::es3(source(LONGGOP)), move |c| {
        sized(c);
        c.video.idr_side_timeout = side_timeout;
    })
    .await
}

/// §11.3 Side IDR (kvm-sim's shared encoder, `side`): a re-advertise → one
/// extra FLV, closed by the bridge after its first tag; the main FLV never
/// closes; the first KVM AU after it is the IDR the side open forced into
/// the main FLV — not a periodic one (none for 10 s on this fixture) — and
/// it resolves NeedIdr, so no fallback follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_readvertise_takes_one_side_flv_and_never_closes_the_main_one() {
    let side_timeout = ms(500);
    let env = longgop(side_timeout).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    let main = flv_opens(&env.sim.events())[0];
    let n = c.with_log(|e| e.len());
    let t0 = Instant::now();
    c.readvertise();
    let evs = c.wait_for(T, |e| e.len() > n && pictures(&e[n..]).len() >= 3).await;
    assert!(t0.elapsed() < Duration::from_secs(5), "picture after {:?}: a periodic IDR, not the side one", t0.elapsed());
    let log = env
        .sim
        .wait_for(T, |l| flv_opens(l).len() == 2 && l.contains(&SimEvent::FlvClose { conn: flv_opens(l)[1] }))
        .await
        .unwrap();
    let side = flv_opens(&log)[1];
    let after = pictures(&evs[n..]);
    assert_eq!(nal_types(&after[0].annex_b), [7, 8, 5], "the first KVM AU after the re-advertise");
    let side_open = log.iter().position(|e| *e == SimEvent::FlvOpen { conn: side }).unwrap();
    let forced = log[side_open..]
        .iter()
        .find_map(|e| match e {
            SimEvent::FlvAu { conn, idr: true, source_index, .. } if *conn == main => Some(*source_index),
            _ => None,
        })
        .expect("no forced IDR on the main FLV after the side open");
    assert_eq!(index_of(&barcodes(LONGGOP), &after[0].annex_b), forced, "the client's IDR is the forced one");
    // Past `idr_side_timeout`: no fallback, and the main FLV is still open.
    tokio::time::sleep(side_timeout * 3).await;
    assert_eq!(env.metrics().idr_side_fallbacks.get(), 0, "the side IDR did not resolve NeedIdr");
    assert!(!env.sim.events().contains(&SimEvent::FlvClose { conn: main }), "the main FLV closed");
    assert_eq!(env.metrics().idr_requests.get("side"), 1);
    assert_eq!(env.logins(), 1);
}

/// §11.3: with side connections refused, exactly one make-before-break
/// `ReconnectFlv` after `idr_side_timeout` (re-deferred to its setup
/// window's end), and no re-login. No periodic IDR can resolve NeedIdr
/// first on this fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_side_flvs_fall_back_to_one_make_before_break_reconnect() {
    let side_timeout = ms(500);
    let env = longgop(side_timeout).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    let main = flv_opens(&env.sim.events())[0];
    env.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
    let t0 = Instant::now();
    c.readvertise();
    assert!(until(T, || env.metrics().idr_side_fallbacks.get() == 1).await);
    within(t0.elapsed(), side_timeout);
    let log = env
        .sim
        .wait_for(T, |l| flv_opens(l).len() == 2 && l.contains(&SimEvent::FlvClose { conn: main }))
        .await
        .unwrap();
    let pos = |e: &SimEvent| log.iter().position(|x| x == e).unwrap();
    let new = flv_opens(&log)[1];
    assert!(pos(&SimEvent::FlvOpen { conn: new }) < pos(&SimEvent::FlvClose { conn: main }), "make-before-break");
    assert_eq!(log.iter().filter(|e| matches!(e, SimEvent::FlvRefused { .. })).count(), 1);
    assert_eq!(env.metrics().idr_requests.get("reconnect"), 1);
    assert_eq!(env.logins(), 1, "no re-login");
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
}

/// §6.8 row 4 — the POC-0 stranding check (Plan A's ledger, §12's Leg B
/// deviation): on the ES3-shaped POC-type-0 fixture, after each batch the
/// last AU kvm-sim shipped reaches the client with nothing after it to push
/// it out, and nothing else arrives; every AU sent is shown, in order. The
/// SPS the client decodes with carries (a) the raised level, (b) the true
/// VUI and (c) `bitstream_restriction` with no reordering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_au_shipped_reaches_the_client_and_its_sps_is_rewritten() {
    let mut sim = es3();
    sim.pacing = Pacing::Manual;
    sim.timestamps = Timestamps::WallClock;
    let env = env(sim, sized).await;
    let c = env.client(Opts::new(2));
    // Manual pacing writes only to FLVs already open: wait for the FLV.
    assert!(until(T, || env.sim.stats().flv_open == 1).await, "no FLV");
    let main = flv_opens(&env.sim.events())[0];
    let map = barcodes(ES3_FIXTURE);
    let mut total = 0;
    for batch in [1u32, 4, 1, 7, 1] {
        env.sim.advance(batch);
        total += usize::try_from(batch).unwrap();
        let log = env.sim.wait_for(T, |l| sent_on(l, main).len() >= total).await.unwrap();
        let last = *sent_on(&log, main).last().unwrap();
        let evs = c
            .wait_for(T, |e| pictures(e).last().is_some_and(|p| index_of(&map, &p.annex_b) == last))
            .await;
        let n = pictures(&evs).len();
        c.never(ms(300), |e| pictures(e).len() != n).await;
    }
    let pics = pictures(&c.events());
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    assert_eq!(got, sent_on(&env.sim.events(), main), "every AU shown, in order, none withheld");
    let sps = parse_sps(split_annex_b(&pics[0].annex_b).next().unwrap()).unwrap();
    assert_eq!(sps.pic_order_cnt_type, 0, "the ES3-shaped POC-0 fixture");
    assert_eq!(
        (sps.max_num_reorder_frames, sps.max_dec_frame_buffering),
        (Some(0), Some(sps.num_ref_frames.max(1))),
        "(c) bitstream_restriction: 0 and 1 on the ES3"
    );
    assert_eq!(
        (sps.video_full_range_flag, sps.colour_primaries, sps.matrix_coefficients),
        (Some(false), Some(1), Some(1)),
        "(b) VUI: limited range, BT.709"
    );
    // (a) 640×360 at 30 fps: 920 MBs > level 2.1's MaxFS 792; level 3 is the
    // lowest with MaxFS ≥ 920 and MaxMBPS ≥ 27 600 (the ES3's 1080p30 → 40).
    assert_eq!(sps.level_idc, 30, "(a) level");
}

/// The ES3 whenever the Mac sleeps (rev 6.1 kvm-sim): NO SIGNAL — every
/// frame an IDR, alternating between GOP starts, each with its SPS/PPS, at
/// several times the bitrate. §6.3's composition, the gates and the oracle
/// hold through it with no NeedIdr and no disconnect, and P frames resume
/// when the signal returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_signal_is_all_idr_and_p_frames_resume_when_it_ends() {
    let env = env(es3(), sized).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    let awaiting = env.metrics().frames_dropped.get("awaiting_idr");
    let n = pictures(&c.events()).len();
    env.sim.set_signal(false);
    let idr = |p: &crate::client::Picture| nal_types(&p.annex_b) == [7, 8, 5];
    let evs = c.wait_for(T, |e| pictures(e)[n..].iter().filter(|p| idr(p)).count() >= 31).await;
    let pics = pictures(&evs);
    let first = n + pics[n..].iter().position(|p| idr(p)).unwrap();
    assert!(pics[first..first + 30].iter().all(|p| idr(p)), "NO SIGNAL: every picture an IDR with SPS/PPS");
    for w in pics.windows(2) {
        assert_eq!(w[1].frame_id, w[0].frame_id.wrapping_add(1), "a frame was dropped");
    }
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    let main = flv_opens(&env.sim.events())[0];
    let log = env.sim.wait_for(T, |l| sent_on(l, main).len() >= got.len()).await.unwrap();
    assert_run(&got, &sent_on(&log, main), "through NO SIGNAL");
    assert_eq!(env.metrics().frames_dropped.get("awaiting_idr"), awaiting, "NO SIGNAL caused a NeedIdr");
    env.sim.set_signal(true);
    let m = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e)[m..].iter().any(|p| nal_types(&p.annex_b) == [1])).await;
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().disconnects.total(), 0);
}
```

- [ ] **Step 2: Run them.** `cargo test --workspace --all-features --test l2 -- video::` — Expected: PASS — 7 passed.

- [ ] **Step 3: Prove the oracle bites.** In `crates/kvm-proto/src/video/mod.rs` `AccessUnit::write_annex_b`, change `if self.idr {` to `if false {` (no SPS/PPS before an IDR).

Run: `cargo test --workspace --all-features --test l2 -- video::the_video_oracle_holds_under_side`
Expected: FAIL — `assertion left == right failed` with `left: [5]`, `right: [7, 8, 5]`. Restore; re-run: 1 passed.

Then prove the stranding case bites. In `pump/core.rs`, change `send_au`'s `self.drain(gfx, out, Some(a.received), 1, a.au.burst);` to `self.drain(gfx, out, Some(a.received), 1, true);` and `step`'s `if !sample && !matches!(&input, Input::Au(a) if a.au.burst) {` to `if false {` — every AU now waits in a chunk until eight fill.

Run: `cargo test --workspace --all-features --test l2 -- video::the_last_au_shipped`
Expected: FAIL — `no match within …` on the first batch (its one AU is withheld). Restore both; re-run: 1 passed.

- [ ] **Step 4: Gate** (clippy, test, budget). **Step 5: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/video.rs crates/kvm-rdp/tests/l2/main.rs
git commit -m "kvm-rdp: L2 — the video oracle per IDR policy, side IDR and its fallback, POC-0 stranding, NO SIGNAL (§11.3, §6.8)" \
  -m "Side cases on the long-GOP fixture so only the forced IDR is in the window; the last AU shipped reaches the client with nothing after it; the client's SPS carries the rewrites." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6.4: L2 — resolution change and the §6.9 faults

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/resize.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/faults.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod faults; mod resize;`)

**Interfaces:**
- Consumes: Task 6.1; `kvm_sim::{Fault, ResizeSignal}`; `kvm_proto::h264::{parse_sps, split_annex_b}`.
- Produces: three resize cases and nine fault cases.

The fault table follows §6.9 and §11.3's list. "Another session's logout" is driven as `expire_tokens` — what a logout does to the bridge's token (§3.2) — so every case keeps its zero-logout assertion.

- [ ] **Step 1: Write the resize cases.** Add `mod faults;` and `mod resize;` to `main.rs`; create `tests/l2/resize.rs`:

```rust
//! §11.3 Resolution change, by each of §6.4's three signals.
use crate::client::{Ev, Opts, nal_types, pictures, timeline};
use crate::harness::{P360, P480, T, env, main_360p, sized, source};
use kvm_proto::h264::{parse_sps, split_annex_b};
use kvm_sim::ResizeSignal;

/// DeactivateAll; no EGFX PDU until the reactivated Demand Active; the old
/// surface deleted (IronRDP keeps the connection's `GraphicsPipelineServer`
/// across a reactivation, and `resize_with_monitors` deletes every surface
/// before its ResetGraphics — §11.2's "no DeleteSurface" is the
/// re-advertise rule); ResetGraphics and CreateSurface at the new size; the first KVM AU after
/// is an IDR whose SPS has the new size; login count unchanged; and a
/// second resize in the same session works.
async fn resize_by(signal: ResizeSignal) {
    let env = env(main_360p(), sized).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    for (fixture, (w, h)) in [(P480, (854u16, 480u16)), (P360, (640, 360))] {
        let n = c.with_log(|e| e.len());
        env.sim.switch_source(source(fixture), signal);
        let evs = c
            .wait_for(T, |e| {
                let new = &e[n..];
                let reactivated = new.iter().position(|x| matches!(x, Ev::Reactivated(..)));
                reactivated.is_some_and(|r| !pictures(&new[r..]).is_empty())
            })
            .await;
        let new = &evs[n..];
        let d = new.iter().position(|x| matches!(x, Ev::DeactivateAll)).unwrap();
        let r = new.iter().position(|x| matches!(x, Ev::Reactivated(..))).unwrap();
        assert!(!new[d..r].iter().any(|x| matches!(x, Ev::Gfx(_))), "{signal:?}: EGFX before the reactivation");
        let t = timeline(&new[d..]);
        let want = [
            format!("reactivated {w}x{h}"),
            "delete".to_owned(),
            format!("reset {w}x{h}"),
            format!("surface {w}x{h}"),
            "map".to_owned(),
        ];
        assert_eq!(t[1..6], want, "{signal:?}: {t:?}");
        let first = &pictures(&new[r..])[0];
        assert_eq!(nal_types(&first.annex_b), [7, 8, 5], "{signal:?}");
        let sps = parse_sps(split_annex_b(&first.annex_b).next().unwrap()).unwrap();
        assert_eq!((sps.width, sps.height), (u32::from(w), u32::from(h)), "{signal:?}");
    }
    assert_eq!(env.logins(), 1, "{signal:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_sequence_header_resizes_twice() {
    resize_by(ResizeSignal::SequenceHeader).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_band_sps_resizes_twice() {
    resize_by(ResizeSignal::InBandSps).await;
}

/// The ES3's observed preset change: the FLV closes; the new one opens at
/// the new size (§6.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_flv_close_at_a_new_size_resizes_twice() {
    resize_by(ResizeSignal::CloseFlv).await;
}
```

- [ ] **Step 2: Write the fault cases.** Create `tests/l2/faults.rs`:

```rust
//! §11.3 Faults, each against its §6.9 class and ErrorInfo.
use crate::client::{Opts, description, pictures, terminated};
use crate::harness::{KBD_ZERO, SET_MODE, T, env, es3, flv_opens, hid_on, ms, sized, streaming, until, within, ws_opens};
use kvm_rdp::msg::Cause;
use kvm_sim::Fault;
use std::time::Instant;

/// Framing violations (§6.2): each one is transient — a reconnect, the
/// picture resumes, the session lives — and three within 60 s are
/// `stream_corrupt` (0x7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framing_violations_reconnect_and_three_are_stream_corrupt() {
    for fault in [Fault::OversizeTag, Fault::BadPrevTagSize, Fault::EncryptedTag, Fault::StartCodeInNal, Fault::TwoPictures] {
        let (env, c) = streaming(|_| {}).await;
        for round in 1..=2 {
            let opens = flv_opens(&env.sim.events()).len();
            env.sim.inject(fault);
            assert!(until(T, || flv_opens(&env.sim.events()).len() > opens).await, "{fault:?} {round}: no reconnect");
            let n = pictures(&c.events()).len();
            c.wait_for(T, |e| pictures(e).len() > n).await;
            assert!(terminated(&c.events()).is_none(), "{fault:?} {round}: disconnected");
        }
        env.sim.inject(fault);
        let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
        assert_eq!(terminated(&evs).unwrap(), description(Cause::StreamCorrupt), "{fault:?}");
        assert_eq!(env.metrics().parse_errors.total(), 3, "{fault:?}");
        assert_eq!(env.metrics().disconnects.get("stream_corrupt"), 1, "{fault:?}");
    }
}

/// A NALU before any sequence header, on every reopen: three framing
/// violations → `stream_corrupt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nalus_before_the_sequence_header_are_stream_corrupt() {
    let (env, c) = streaming(|_| {}).await;
    env.sim.set_policy(|p| p.skip_sequence_header = true);
    env.sim.inject(Fault::Close);
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::StreamCorrupt));
    assert_eq!(env.metrics().parse_errors.total(), 3);
}

/// Stream-incompatible (§6.9): fatal at once with 0x7, never a reconnect;
/// the ES3's constant 16 ms `CompositionTime` is admitted until it changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_incompatible_faults_are_fatal_at_once() {
    for fault in [Fault::HevcCodecId, Fault::CompositionTime(20), Fault::BSlice] {
        let (env, c) = streaming(|_| {}).await;
        assert_eq!(env.metrics().disconnects.total(), 0, "the constant 16 ms CompositionTime was refused");
        env.sim.inject(fault);
        let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
        assert_eq!(terminated(&evs).unwrap(), description(Cause::StreamIncompatible), "{fault:?}");
        assert_eq!(env.metrics().disconnects.get("stream_incompatible"), 1, "{fault:?}");
        assert_eq!(flv_opens(&env.sim.events()).len(), 1, "{fault:?}: fatal is never a reconnect");
    }
}

/// Transient (§6.9): end of sequence, an FLV drop, and an FLV silent past
/// `flv_idle_timeout` each reconnect with no disconnect and no new login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_of_sequence_drop_and_silence_reconnect_without_a_disconnect() {
    let idle = ms(500);
    let (env, c) = streaming(move |c| c.video.flv_idle_timeout = idle).await;
    for fault in [Fault::EndOfSequence, Fault::Close, Fault::Silence] {
        let opens = flv_opens(&env.sim.events()).len();
        let t0 = Instant::now();
        env.sim.inject(fault);
        assert!(until(T, || flv_opens(&env.sim.events()).len() > opens).await, "{fault:?}");
        if fault == Fault::Silence {
            within(t0.elapsed(), idle);
        }
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() > n).await;
    }
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().disconnects.total(), 0);
    assert_eq!(env.logins(), 1);
}

/// Auth (§6.9): token expiry twice in one session, with a successful
/// re-login between — the open FLV keeps streaming meanwhile (as after
/// another session's logout, §3.2), the next reopen re-logs in once, and
/// nothing disconnects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_expiry_twice_relogs_in_each_time() {
    let (env, c) = streaming(|_| {}).await;
    for round in 1..=2u64 {
        env.sim.expire_tokens();
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() >= n + 5).await;
        assert_eq!(env.logins(), round, "a re-login while nothing reopened");
        env.sim.inject(Fault::Close);
        assert!(until(T, || env.logins() == round + 1).await, "round {round}: no re-login");
        let n = pictures(&c.events()).len();
        c.wait_for(T, |e| pictures(e).len() > n).await;
    }
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().relogins.get(), 2);
}

/// Auth (§6.9): a refused reopen re-logs in once; that login refused too
/// is fatal — `kvm_auth_failed` (0x9) — and never retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_consecutive_auth_failure_is_fatal() {
    let (env, c) = streaming(|_| {}).await;
    env.sim.set_policy(|p| p.reject_logins = true);
    env.sim.expire_tokens();
    env.sim.inject(Fault::Close);
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::KvmAuthFailed));
    // 0x9 is shared with `kvm_cert_mismatch`: the label tells them apart.
    assert_eq!(env.metrics().disconnects.get("kvm_auth_failed"), 1);
    assert_eq!(env.sim.stats().logins_failed, 1, "re-login once, never again");
}

/// Websocket (§6.9): a drop and a 64 MiB message each reconnect with the
/// session-start sequence and no NeedIdr — the oversize one closed at the
/// 4 KiB limit (a bridge that waited for the whole message would never
/// reconnect: kvm-sim sends 4 KiB of it; Task 3.3 checks the error itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_drop_and_oversize_reconnect_with_the_session_start() {
    let (env, c) = streaming(|_| {}).await;
    let awaiting = env.metrics().frames_dropped.get("awaiting_idr");
    for oversize in [false, true] {
        let before = ws_opens(&env.sim.events()).len();
        if oversize {
            env.sim.send_ws_oversize(64 << 20);
        } else {
            env.sim.close_websockets();
        }
        let log = env.sim.wait_for(T, |l| ws_opens(l).len() > before).await.unwrap();
        let new = *ws_opens(&log).last().unwrap();
        let log = env.sim.wait_for(T, |l| hid_on(l, new).len() >= 2).await.unwrap();
        // Exactly these two: no pointer was ever sent, none parked at (0, 0).
        assert_eq!(hid_on(&log, new), [SET_MODE.to_vec(), KBD_ZERO.to_vec()], "oversize: {oversize}");
    }
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
    assert_eq!(env.metrics().frames_dropped.get("awaiting_idr"), awaiting, "a websocket reconnect is no NeedIdr");
    assert_eq!(flv_opens(&env.sim.events()).len(), 1);
    assert_eq!(env.sim.stats().ws_max_open, 1);
}

/// Deadline (§6.9): a KVM that accepts and then says nothing → disconnect
/// with `kvm_unreachable` (0x7) at `upstream_deadline`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_kvm_disconnects_at_the_deadline() {
    let deadline = ms(1500);
    let env = env(es3(), move |c| {
        sized(c);
        c.kvm.upstream_deadline = deadline;
    })
    .await;
    env.sim.set_policy(|p| p.blackhole = true);
    let c = env.client(Opts::new(2));
    c.connected().await;
    let t0 = Instant::now();
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    within(t0.elapsed(), deadline);
    assert_eq!(terminated(&evs).unwrap(), description(Cause::KvmUnreachable));
    // 0x7 is shared with five other causes: the label tells them apart.
    assert_eq!(env.metrics().disconnects.get("kvm_unreachable"), 1);
    assert_eq!(env.logins(), 0);
}

/// Certificate (§6.9): an SPKI mismatch is fatal at once, and no login
/// request is ever sent — `kvm_cert_mismatch` (0x9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_kvm_certificate_sends_no_login() {
    let env = env(es3(), |c| {
        sized(c);
        c.kvm.spki_sha256 = "00".repeat(32);
    })
    .await;
    let c = env.client(Opts::new(2));
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::KvmCertMismatch));
    assert_eq!(env.metrics().disconnects.get("kvm_cert_mismatch"), 1);
    let s = env.sim.stats();
    assert_eq!(s.logins_ok + s.logins_failed, 0);
}
```

- [ ] **Step 3: Run them.** `cargo test --workspace --all-features --test l2 -- resize:: faults::` — Expected: PASS — 12 passed.

- [ ] **Step 4: Prove the fault table bites.** In `kvm/upstream.rs` `AuthGate::bump`, change `if self.consecutive >= 2 {` to `if self.consecutive >= 3 {`.

Run: `cargo test --workspace --all-features --test l2 -- faults::a_second_consecutive_auth_failure_is_fatal`
Expected: FAIL — `re-login once, never again` (`left: 2`, `right: 1`). Restore; re-run: 1 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/resize.rs crates/kvm-rdp/tests/l2/faults.rs crates/kvm-rdp/tests/l2/main.rs
git commit -m "kvm-rdp: L2 — resolution change by all three signals, the §6.9 fault table (§11.3)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6.5: L2 — the stalled client and the HID writer

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/flow.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/hid.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod flow; mod hid;`)

**Interfaces:**
- Consumes: Task 6.1 (`Opts::ack`, `Opts::recv_buffer`); `BridgeHandle::hid()` (5.4) and `HidControl::push` (3.5); `kvm_proto::hid::HidFrame`.
- Produces: three stalled-client cases and four HID-writer cases.

DC7: until Plan D's input handler exists, these cases push reports through `HidControl` — the handler's only production entry point — so they test the writer, the release epoch and the websocket, not the scancode mapping.

- [ ] **Step 1: Write the stalled-client cases.** Add `mod flow;` and `mod hid;` to `main.rs`; create `tests/l2/flow.rs`:

```rust
//! §11.3 Stalled client, asserted on `/metrics` rather than timing.
use crate::client::{Ack, Opts, description, pictures, terminated};
use crate::harness::{T, env, es3, ms, sized, until};
use kvm_rdp::msg::Cause;
use kvm_sim::{Pacing, Timestamps};
use std::time::Instant;

/// Withheld acks: after the first soft-gate drop the sent-frame counter
/// never advances again before Closing; in flight never exceeds the hard
/// cap (60); the session closes with `client_stalled` (0x7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_acks_stop_sending_and_close_client_stalled() {
    let stall = ms(1000);
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
    while m.disconnects.get("client_stalled") == 0 {
        assert!(t0.elapsed() < T, "never closed");
        assert!(m.egfx_in_flight.get() <= 60, "in flight {}", m.egfx_in_flight.get());
        let sent = m.frames_sent.get();
        match sent_at_first_drop {
            None if m.frames_dropped.get("soft_gate") > 0 => sent_at_first_drop = Some(sent),
            Some(s) => assert_eq!(sent, s, "a frame was sent after the first soft-gate drop"),
            None => {}
        }
        tokio::time::sleep(ms(5)).await;
    }
    assert!(sent_at_first_drop.is_some(), "closed before any soft-gate drop");
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
    assert!(took <= (stall + wd) * 5, "the KVM side was freed after {took:?}");
    let m = env.metrics();
    assert_eq!(m.disconnects.get("client_stalled"), 1);
    assert_eq!(m.release_all.get("watchdog"), 1, "the Disconnect went out: the watchdog and the abort handle never ran");
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
```

- [ ] **Step 2: Write the HID-writer cases.** Create `tests/l2/hid.rs`:

```rust
//! §7.3's writer through the bridge (DC7: driven via `HidControl`).
use crate::client::{Opts, pictures, terminated};
use crate::harness::{KBD_ZERO, SET_MODE, T, env, es3, hid_on, ms, sized, streaming, until, ws_opens};
use kvm_proto::hid::HidFrame;
use kvm_sim::SimEvent;

/// Reports reach kvm-sim byte-exact, in order, after the session-start
/// sequence; a websocket reopen's session-start carries the pointer at the
/// last position sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_reach_the_kvm_and_a_reopen_restores_the_pointer() {
    let (env, _c) = streaming(|_| {}).await;
    let hid = env.bridge().hid().clone();
    let ws = *ws_opens(&env.sim.events()).last().unwrap();
    let frames = [
        HidFrame::abs_mouse(0, 1000, 2000),
        HidFrame::Keyboard { modifiers: 0, keys: [0x04, 0, 0, 0, 0] },
        HidFrame::Keyboard { modifiers: 0, keys: [0; 5] },
    ];
    for f in frames {
        let _ = hid.push(f, false);
    }
    let log = env.sim.wait_for(T, |l| hid_on(l, ws).len() >= 5).await.unwrap();
    let mut want = vec![SET_MODE.to_vec(), KBD_ZERO.to_vec()];
    want.extend(frames.iter().map(HidFrame::to_vec));
    assert_eq!(hid_on(&log, ws), want, "exactly the session start, then the reports");
    env.sim.close_websockets();
    let log = env
        .sim
        .wait_for(T, |l| ws_opens(l).len() >= 2 && hid_on(l, ws_opens(l)[1]).len() >= 3)
        .await
        .unwrap();
    let ws2 = ws_opens(&log)[1];
    assert_eq!(
        hid_on(&log, ws2),
        [SET_MODE.to_vec(), KBD_ZERO.to_vec(), HidFrame::abs_mouse(0, 1000, 2000).to_vec()]
    );
}

/// §7.3: a full queue resyncs to the correct final state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_resyncs_to_the_final_state() {
    let (env, _c) = streaming(|c| c.input.queue = 4).await;
    let hid = env.bridge().hid().clone();
    let ws = *ws_opens(&env.sim.events()).last().unwrap();
    for i in 0..64u8 {
        let _ = hid.push(HidFrame::Keyboard { modifiers: 0, keys: [0x04 + i % 20, 0, 0, 0, 0] }, false);
    }
    let last = HidFrame::Keyboard { modifiers: 0x02, keys: [0x1D, 0, 0, 0, 0] };
    let _ = hid.push(last, false);
    env.sim.wait_for(T, |l| hid_on(l, ws).last() == Some(&last.to_vec())).await.unwrap();
    assert!(env.metrics().hid_resyncs.get() >= 1);
}

/// §6.9 websocket: a write blocked past `hid_write_timeout` reconnects, and
/// the new websocket starts with the session-start sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_websocket_write_reconnects() {
    let wt = ms(300);
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, move |c| {
        sized(c);
        c.input.hid_write_timeout = wt;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    let before = ws_opens(&env.sim.events()).len();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    let hid = env.bridge().hid().clone();
    let mut x = 0u16;
    let reconnected = until(T, || {
        for _ in 0..200 {
            x = x % 29_999 + 1; // 1..=29 999: the test itself never sends (0, 0)
            let _ = hid.push(HidFrame::abs_mouse(0, x, x), false);
        }
        ws_opens(&env.sim.events()).len() > before
    })
    .await;
    assert!(reconnected, "no reconnect after a blocked write");
    assert!(env.metrics().upstream_reconnects.get("websocket_write") >= 1);
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    let new = *ws_opens(&env.sim.events()).last().unwrap();
    let log = env.sim.wait_for(T, |l| hid_on(l, new).len() >= 2).await.unwrap();
    // The new websocket starts with the session start; the pointer report
    // after it is at the last position the old one wrote — never (0, 0).
    let on_new = hid_on(&log, new);
    assert_eq!(on_new[..2], [SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
    assert!(!on_new.contains(&HidFrame::abs_mouse(0, 0, 0).to_vec()), "the pointer was parked at (0, 0)");
    assert!(terminated(&c.events()).is_none(), "a websocket fault never disconnects the client");
}

/// Plan A's assumption for L4, on kvm-sim: another session's logout (every
/// token invalidated) leaves the control websocket up, and reports keep
/// flowing on it. kvm-sim was built on that assumption, so this checks the
/// bridge's side only; the real ES3 is one of DC18's L4 checks (Plan D).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_websocket_survives_another_sessions_logout() {
    let (env, _c) = streaming(|_| {}).await;
    let hid = env.bridge().hid().clone();
    let ws = *ws_opens(&env.sim.events()).last().unwrap();
    env.sim.expire_tokens();
    tokio::time::sleep(ms(300)).await;
    let k = HidFrame::Keyboard { modifiers: 0, keys: [0x05, 0, 0, 0, 0] };
    let _ = hid.push(k, false);
    let log = env.sim.wait_for(T, |l| hid_on(l, ws).contains(&k.to_vec())).await.unwrap();
    assert!(!log.contains(&SimEvent::WsClose { conn: ws }));
    assert_eq!(ws_opens(&log).len(), 1);
}
```

- [ ] **Step 3: Run them.** `cargo test --workspace --all-features --test l2 -- flow:: hid::` — Expected: PASS — 7 passed.

- [ ] **Step 4: Prove the stall rule bites.** In `pump/flow.rs` `Flow::stall_expired`, change `!suspended && self.stall.armed && self.stall.running(now) >= self.cfg.stall_timeout` to `false && self.stall.running(now) >= self.cfg.stall_timeout`.

Run: `cargo test --workspace --all-features --test l2 -- flow::withheld_acks`
Expected: FAIL — `never closed`. Restore; re-run: 1 passed.

- [ ] **Step 5: Gate** (clippy, test, budget). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/flow.rs crates/kvm-rdp/tests/l2/hid.rs crates/kvm-rdp/tests/l2/main.rs
git commit -m "kvm-rdp: L2 — stalled, non-reading and suspending clients; the HID writer and its websocket (§11.3)" \
  -m "The control websocket survives another session's logout (Plan A's L4 assumption, on kvm-sim)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6.6: L2 — admin, secrets hygiene, and shutdown on the real binary

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/admin.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod admin;`)

**Interfaces:**
- Consumes: Task 6.1 (`streaming`, `Env::take_bridge`); `BridgeHandle::{block_rdp_runtime_for, shutdown_skipping_disconnect}` (5.4); the `kvm-rdp` binary (`CARGO_BIN_EXE_kvm-rdp`); `libc::kill`; `serde_json`.
- Produces: five L2 cases — Review Focus 5 and §5.2's second `Quit` among them.

DC9: the secrets case runs without Plan D's keystroke sentinel and paste canary, and spawns the binary itself (kvm-bench's spawn harness is Plan E's). The binary's environment is cleared and then given `SSLKEYLOGFILE` and `RUST_LOG=trace`: neither may change anything (§4.4, §9.1).

- [ ] **Step 1: Write the cases.** Add `mod admin;` to `main.rs`; create `tests/l2/admin.rs`:

```rust
//! §11.3 Admin; Secrets hygiene (DC9) and Review Focus 5 on the real
//! binary, as a subprocess, under a real SIGTERM.
use crate::client::{Client, Ev, Opts, description, pictures, terminated, timeline};
use crate::harness::{NLA, T, edit_toml, env, es3, ms, sized, streaming, until, write_files};
use kvm_rdp::msg::Cause;
use kvm_sim::KvmSim;
use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// §4.5: `/livez` goes stale while the RDP runtime is blocked (not before
/// 0.5× the 1 s liveness timeout) and recovers; `/readyz` stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn livez_goes_stale_while_the_rdp_runtime_is_blocked() {
    let env = env(es3(), sized).await;
    assert_eq!(env.get("/livez").await.0, 200);
    let t0 = Instant::now();
    env.bridge().block_rdp_runtime_for(ms(3000));
    let mut stale = None;
    while t0.elapsed() < ms(2900) {
        if env.get("/livez").await.0 == 503 {
            stale = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(ms(50)).await;
    }
    let stale = stale.expect("/livez never went stale");
    assert!(stale >= ms(500), "stale after {stale:?}");
    assert_eq!(env.get("/readyz").await.0, 200);
    let t1 = Instant::now();
    let mut live = false;
    while !live && t1.elapsed() < T {
        live = env.get("/livez").await.0 == 200;
        tokio::time::sleep(ms(50)).await;
    }
    assert!(live, "/livez never recovered");
}

/// §4.5: `/readyz` never checks the KVM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_succeeds_without_a_kvm() {
    let env = env(es3(), sized).await;
    env.sim.set_policy(|p| p.blackhole = true);
    assert_eq!(env.get("/readyz").await.0, 200);
    let (code, body) = env.get("/metrics").await;
    assert_eq!(code, 200);
    assert!(body.contains("kvm_rdp_sessions_total"), "{body}");
    assert_eq!(env.sim.stats().accepts_web, 0);
}

/// The real binary on `dir`'s config; stdout and stderr captured by line.
struct Bin {
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    ready: Option<std::sync::mpsc::Receiver<SocketAddr>>,
}

fn ready_addr(line: &str) -> Option<SocketAddr> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["fields"]["message"] != "kvm-rdp ready" {
        return None;
    }
    v["fields"]["rdp"].as_str()?.parse().ok()
}

impl Bin {
    fn spawn(dir: &Path, envs: &[(&str, &OsStr)]) -> Bin {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kvm-rdp"));
        cmd.arg("--config").arg(dir.join("kvm-rdp.toml")).env_clear().env("RUST_LOG", "trace");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (stdout, o) = (child.stdout.take().unwrap(), out.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(addr) = ready_addr(&line) {
                    let _ = tx.send(addr);
                }
                o.lock().unwrap().push(line);
            }
        });
        let (stderr, o) = (child.stderr.take().unwrap(), out.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                o.lock().unwrap().push(line);
            }
        });
        Bin { child, out, ready: Some(rx) }
    }

    /// The RDP address from the `kvm-rdp ready` line.
    async fn ready(&mut self) -> SocketAddr {
        let rx = self.ready.take().unwrap();
        tokio::task::spawn_blocking(move || rx.recv_timeout(T)).await.unwrap().expect("the bridge never got ready")
    }

    fn sigterm(&self) {
        let pid = libc::pid_t::try_from(self.child.id()).unwrap();
        // SAFETY: kill(2) on our own child's pid, which it still is (not reaped).
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    }

    async fn wait(&mut self, limit: Duration) -> ExitStatus {
        let t0 = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(t0.elapsed() < limit, "the bridge did not exit within {limit:?}");
            tokio::time::sleep(ms(20)).await;
        }
    }

    fn output(&self) -> Vec<String> {
        self.out.lock().unwrap().clone()
    }
}

impl Drop for Bin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// §11.3 secrets hygiene, both filters: an NLA session whose password is
/// the canary, then SIGTERM. Neither the canary, the KVM password, NTLM
/// (raw or base64) nor a token query reaches stdout or stderr; no DEBUG or
/// TRACE line from `ironrdp_*`/`sspi`; at least one TRACE line from bridge
/// code; `SSLKEYLOGFILE` is never created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secrets_never_reach_the_logs() {
    for filter in ["trace", "kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace"] {
        let sim = KvmSim::start(es3()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_files(&sim, dir.path());
        let toml = dir.path().join("kvm-rdp.toml");
        let mut text = std::fs::read_to_string(&toml).unwrap();
        text.push_str(&format!("[log]\nfilter = \"{filter}\"\n"));
        std::fs::write(&toml, text).unwrap();
        let keylog = dir.path().join("keylog.txt");
        let mut bin = Bin::spawn(dir.path(), &[("SSLKEYLOGFILE", keylog.as_os_str())]);
        let rdp = bin.ready().await;
        let c = Client::connect(rdp, Opts::new(2));
        c.wait_for(T, |e| pictures(e).len() >= 5).await;
        bin.sigterm();
        assert!(bin.wait(T).await.success(), "{filter}");
        let out = bin.output();
        let all = out.join("\n");
        for secret in [NLA, sim.password(), "NTLMSSP", "TlRMTVNTUA", "token="] {
            assert!(!all.contains(secret), "{filter}: {secret:?} reached the logs");
        }
        let mut bridge_trace = false;
        for line in &out {
            let v: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|_| panic!("{filter}: not a JSON line: {line}"));
            let (level, target) = (v["level"].as_str().unwrap_or(""), v["target"].as_str().unwrap_or(""));
            if target.starts_with("ironrdp") || target.starts_with("sspi") {
                assert!(!matches!(level, "DEBUG" | "TRACE"), "{filter}: {line}");
            }
            bridge_trace |= level == "TRACE" && target.starts_with("kvm_rdp");
        }
        assert!(bridge_trace, "{filter}: no TRACE line from bridge code — the filter did not take effect");
        assert!(!keylog.exists(), "{filter}: SSLKEYLOGFILE was honoured");
        assert_eq!(sim.stats().logouts, 0);
    }
}

/// Review Focus 5: SIGTERM while a client is connected and the KVM is
/// unreachable (the actor stuck in a TLS handshake that never answers) →
/// the client still gets ErrorInfo 0x1, and the process exits 0 within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_completes_with_the_kvm_unreachable() {
    let sim = KvmSim::start(es3()).await.unwrap();
    sim.set_policy(|p| p.blackhole = true);
    let dir = tempfile::tempdir().unwrap();
    write_files(&sim, dir.path());
    edit_toml(dir.path(), "upstream_deadline = \"5s\"", "upstream_deadline = \"60s\"");
    let mut bin = Bin::spawn(dir.path(), &[]);
    let rdp = bin.ready().await;
    let c = Client::connect(rdp, Opts::new(2));
    c.wait_for(T, |e| timeline(e).contains(&"map".to_owned())).await;
    assert!(until(T, || sim.stats().accepts_web >= 1).await, "the actor never tried the KVM");
    let t0 = Instant::now();
    bin.sigterm();
    let status = bin.wait(T).await;
    let took = t0.elapsed();
    assert!(status.success(), "{status:?}");
    assert!(took < Duration::from_secs(5), "exit took {took:?}");
    let evs = c.wait_for(T, |e| terminated(e).is_some()).await;
    assert_eq!(terminated(&evs).unwrap(), description(Cause::Shutdown));
    assert_eq!(sim.stats().logouts, 0);
}

/// §5.2: a `Quit` that a live connection consumes ends only that connection;
/// stopping the server takes a second. The test hook runs §5.2 without step
/// 3 (the disconnect), so the client is still connected when the first
/// `Quit` goes out, and reports how many `Quit`s the sequence sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_connection_consumes_the_first_quit_and_a_second_stops_the_server() {
    let (mut env, c) = streaming(|_| {}).await;
    let rdp = env.rdp;
    let t0 = Instant::now();
    let quits = env.take_bridge().shutdown_skipping_disconnect().await;
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert_eq!(quits, 2, "the first Quit stopped the server although a client was connected");
    c.wait_for(T, |e| e.iter().any(|x| matches!(x, Ev::Closed(_) | Ev::Terminated(_)))).await;
    assert!(tokio::net::TcpStream::connect(rdp).await.is_err(), "the RDP listener is still open");
}
```

- [ ] **Step 2: Run them.** `cargo test --workspace --all-features --test l2 -- admin::` — Expected: PASS — 5 passed. (The binary is built for the test binary by cargo; nothing else to run.)

- [ ] **Step 3: Prove Review Focus 5 bites.** In `bridge.rs` `shutdown_sequence`, change step 3's `if disconnect {` to `if false {` (what `shutdown_skipping_disconnect` does on purpose).

Run: `cargo test --workspace --all-features --test l2 -- admin::shutdown_completes_with_the_kvm_unreachable`
Expected: FAIL — the first `Quit` reaches the live connection and ends only it, without ErrorInfo: either `terminated` differs from the 0x1 description or the wait panics with the client's timeline (`… "closed"`). The process still exits in time — the second `Quit` stops the server (§5.2). Restore; re-run: 1 passed.

- [ ] **Step 4: The whole suite.** `cargo test --workspace --all-features` — Expected: 0 failed; the `l2` binary reports 37 passed. Then `scripts/target-budget.sh` — Expected: within budget.

- [ ] **Step 5: Gate** (clippy). **Step 6: Commit.**

```bash
git add crates/kvm-rdp/tests/l2/admin.rs crates/kvm-rdp/tests/l2/main.rs
git commit -m "kvm-rdp: L2 — /livez and /readyz, secrets hygiene and SIGTERM on the real binary (§11.3, Review Focus 5)" \
  -m "SSLKEYLOGFILE and RUST_LOG are set in the child and change nothing; ErrorInfo 0x1 and exit 0 within 5 s with the KVM unreachable; a live connection consumes the first Quit and a second stops the server (§5.2)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 7 — Close-out

### Task 7.1: CI, the spec's rev 6.2, the README

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml`
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`
- Modify: `/home/chris/Repos/kvm-rdp/README.md`

**Interfaces:**
- Consumes: DC1–DC22 (this plan's "Recorded deviations"), the target sizes Tasks 2.1 and 6.1 measured, every task's report.
- Produces: CI that bounds the job and refuses tracked secrets or captures; the spec at rev 6.2; a README that says how to run the bridge.

- [ ] **Step 1: CI — bound the job (DC19).** In `.github/workflows/ci.yml` replace

```yaml
  check:
    runs-on: ubuntu-latest
    steps:
```

with

```yaml
  check:
    runs-on: ubuntu-latest
    # IronRDP's graph plus L2 (§13): a hung L2 case must not hold a runner.
    timeout-minutes: 45
    steps:
```

- [ ] **Step 2: CI — no secrets or captures tracked (DC19).** In the same file, after the step

```yaml
      - name: Format
        run: cargo fmt --all -- --check
```

insert

```yaml
      - name: No secrets or captures tracked (owner rule; spec §9.2, §11.5)
        run: |
          bad=$(git ls-files | grep -E '\.(pem|key|pass|p12|der|pcap|pcapng|rdp)$|^captures/' || true)
          if [ -n "$bad" ]; then
            echo "::error::secret-shaped or capture files are tracked:"
            echo "$bad"
            exit 1
          fi
          echo "no secrets or captures tracked"
```

Run locally: `git ls-files | grep -E '\.(pem|key|pass|p12|der|pcap|pcapng|rdp)$|^captures/' || echo none` — Expected: `none`.

- [ ] **Step 3: The spec — status and the rev 6.2 paragraph.** In `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`:

(a) Replace `| Status | Draft rev 6.1 — Plan B's deviations recorded (2026-10-06); rev 6: census-filled.` with `| Status | Draft rev 6.2 — Plan C's deviations recorded (2026-10-07); rev 6.1: Plan B's (2026-10-06); rev 6: census-filled.`

(b) Replace the whole paragraph that starts `**Rev 6.2 — Plan C (in progress, 2026-10-07).**` (Tasks 1.1 and 1.2 wrote it; it ends `completes this revision.`) with:

```
**Rev 6.2 — Plan C (2026-10-07).** Records what building Milestone 3a
settled. Burst marking uses a sliding 1 s median baseline: an AU is `burst`
when its delivery delay is more than 100 ms below the median delay of the
last second on its FLV connection, so neither a late first tag nor one late
tag mid-stream marks the on-time AUs after it (§6.2; Plan B's final review
I3); kvm-sim's `wait_for` returns every event its predicate could have
seen, and §11.5's source-burst wording is fixed (N1, N2). `ironrdp-server`
uses only the `egfx` feature — `helper` holds nothing but the
`TlsIdentityCtx` §9.1 forbids — so PEM loading uses `rustls-pki-types` and
the CredSSP key comes from x509-parser (§4.2). The fork carries three
patches, patch 1 is pinned and its no-fork fallback (the shadow suspension
flag and the suspend-ack injection) is not built, and §6.9's "patch 4" is
patch 3, `ConnectionInfo::abort_handle()` (§4.2, §4.3, §6.4, §6.6, §6.9,
§11.2, §12). `SessionStart`/`SessionStop` reach the pump from the RDP side,
not the KVM stream: every `KvmEvent` carries its generation and the pump's
`biased` select drains the RDP side first (§4.3). The shell samples the
suppression flag and the write counter every 50 ms tick and before each AU,
and feeds every RTT read; the pump core alone keeps a generation's first
read as its reference (§4.3, §6.6). An AU dropped on a full KVM → pump
channel marks the next delivered AU `after_drop`, a flow cause carried in
order; the channel holds the hard cap + 8; `CancelIdrRequest` is
pump-internal (§4.3, §6.5). Configuration: the secret files are
`kvm.password_file`, `rdp.nla_password_file`, `rdp.tls_cert_file` and
`rdp.tls_key_file`; new keys `admin.liveness_timeout` (10 s),
`rdp.cert_poll_interval` (60 s) and `security.accept_window` (60 s);
durations are strings bounded to 1 h; the NLA password has at least 22
characters; `security.accept_rate` counts admitted attempts only;
`video.sps_rewrite` must name all three rewrites; a renewed certificate
restarts the bridge only once no client is connected (§4.4, §6.8).
`/readyz` means "TLS identity loaded and `GetLocalAddr` answered" (§4.5).
Shutdown stops accepting through `on_accept` and uses a 2 s disconnect
watchdog, inside the 5 s exit (§5.2). Plan C's input handler is a counting
stub and its L2 drives the HID writer through `HidControl` (§7, §11.3); the
L1 rig decodes `GraphicsPipelineServer`'s output with IronRDP's own PDU
types rather than `GraphicsPipelineClient` (§11.2); the FreeRDP 11-set
capability fixture moves to Plan E's L3 (§11.2, §12); the secrets-hygiene
case runs without the keystroke sentinel and paste canary and spawns the
binary itself (§11.3). §11.6's five L4 hardware checks move to Plan D's
first task, which consumes two of them (§5.2, §8, §9.3, §11.6, §12, §15);
clipboard data is Plan D's to test (§8). CI gains a job timeout and a
tracked-secrets gate ahead of Plan E (§12). IronRDP's graph is far past
§13's target estimate: `scripts/target-budget.sh` gates the shared target,
`[build] incremental = false` is committed, and disposable scratch worktrees
use their own target dir (§13).
```

- [ ] **Step 4: The spec — the sections the deviations amend.** Each `old` text below occurs exactly once in the spec (a whole line unless marked "part of one line"); replace it with its `new` text (a `new` of several lines replaces the one `old` line).

(1) §4.2 — old:

```text
- `ironrdp-server` with `default-features = false, features = ["egfx", "helper"]`.
```

new:

```text
- `ironrdp-server` with `default-features = false, features = ["egfx"]` (**rev 6.2**: not `helper`, whose only item is the `TlsIdentityCtx` §9.1 forbids).
```

(2) §4.2, patch 1's fallback — old:

```text
     *No-fork fallback*: the pump keeps a shadow suspension flag from
```

new:

```text
     *No-fork fallback* (rev 6.2: not built — Plan C pins patch 1): the pump keeps a shadow suspension flag from
```

(3) §4.3, the command list — old:

```text
  `InjectSuspendAck`,
```

new:

```text
  `SurfaceSize`, `Abort` (rev 6.2; no suspend-ack injection — patch 1 is pinned),
```

(4) §4.3 — old:

```text
- **Input path** (§7.3) and the **HID writer** never block the RDP runtime.
```

new:

```text
- **Input path** (§7.3) and the **HID writer** never block the RDP runtime.
- **Rev 6.2 (Plan C).** `SessionStart`/`SessionStop` come from the RDP side with the GFX handle, and the pump drains the RDP side first; the shell samples suppression and the write counter per tick and per AU and feeds every RTT read (the core alone treats a generation's first read as a reference); a dropped AU marks the next one `after_drop`; the KVM → pump channel holds the hard cap + 8.
```

(5) §4.4, the secrets sentence — old:

```text
`tls_cert_file`, `tls_key_file` — and are never logged. The file is validated
```

new:

```text
`tls_cert_file`, `tls_key_file` (rev 6.2: `kvm.password_file`, `rdp.nla_password_file`, `rdp.tls_cert_file`, `rdp.tls_key_file`) — and are never logged. The file is validated
```

(6) §4.4, the certificate restart — old:

```text
once. The bridge polls the certificate file's mtime every 60 s and, on change,
```

new:

```text
once. The bridge polls the certificate file's mtime every 60 s and, on change — once no client is connected (rev 6.2: a renewal must never cut a live session; the companion deployment spec's decision 8) —
```

(7) §4.4, the table — old:

```text
| `security.accept_rate` | 30 connection attempts per sliding 60 s, global | §9.1 |
```

new:

```text
| `security.accept_rate` | 30 admitted connection attempts per sliding `security.accept_window`, global; refusals do not count (rev 6.2) | §9.1 |
| `security.accept_window` | 60 s (rev 6.2) | |
| `rdp.cert_poll_interval` | 60 s (rev 6.2) | A changed certificate or key runs §5.2 and exits 0, once no client is connected |
| `admin.liveness_timeout` | 10 s (rev 6.2) | §4.5's heartbeat age, configurable for L2 |
```

(8) §4.5 — old:

```text
  once the TLS identity is loaded and the RDP listener is bound; it never
```

new:

```text
  once the TLS identity is loaded and the RDP listener is bound (rev 6.2: `ServerEvent::GetLocalAddr` answered); it never
```

(9) §5.2 — old:

```text
On SIGTERM or SIGINT: stop accepting; release-all and wait for the websocket
```

new:

```text
On SIGTERM or SIGINT: stop accepting (`on_accept` refuses, rev 6.2); release-all and wait for the websocket
```

(10) §5.2 — old:

```text
drained (rev 6.1). Release builds use
```

new:

```text
drained (rev 6.1). The shutdown's disconnect watchdog is 2 s, not `video.disconnect_watchdog`, to fit the 5 s (rev 6.2). Release builds use
```

(11) §5.2, L4 — old:

```text
websocket TCP connection dies with a key held moved from Leg A to Plan C's L4
```

new:

```text
websocket TCP connection dies with a key held moved from Leg A to Plan D's L4 (rev 6.2; Plan C has no HID input path)
```

(12) §6.4 Setup — old:

```text
and — if suspended without upstream patch 1 — `InjectSuspendAck`. The first
```

new:

```text
and nothing more for suspension: patch 1 keeps it across Setup (rev 6.2; the fallback's re-arm is not built). The first
```

(13) §6.6 — old (part of one line):

```text
Suspension is read from `is_ack_suspended()` (§4.2 patch 1), or
```

new:

```text
Suspension is read from `is_ack_suspended()` (§4.2 patch 1) only
```

and old:

```text
  from the pump's shadow flag under the fallback, and survives Setup and
```

new:

```text
  (rev 6.2: patch 1 is pinned; the fallback's own flag is not built), and survives Setup and
```

(14) §6.8 — old:

```text
`video.sps_rewrite` is `["level", "vui", "restriction"]`.
```

new:

```text
`video.sps_rewrite` is `["level", "vui", "restriction"]`; a set lacking any of the three is refused at load (rev 6.2).
```

(15) §6.9 — old (part of one line):

```text
connection (§4.2 patch 4) — so a client
```

new:

```text
connection (§4.2 patch 3; rev 6.2) — so a client
```

(16) §8, L4 — old:

```text
per-keystroke work is mixed in), so Plan C measures the KVM's own HID report
```

new:

```text
per-keystroke work is mixed in), so Plan D (rev 6.2; was Plan C) measures the KVM's own HID report
```

(17) §8, clipboard — old:

```text
  (`census.md`, Leg C; clipboard data itself is Plan C's to test).
```

new:

```text
  (`census.md`, Leg C; clipboard data itself is Plan D's to test, rev 6.2).
```

(18) §9.3 — old (part of one line):

```text
(Plan C L4, §12)
```

new:

```text
(Plan D's L4, §12; rev 6.2)
```

(19) §11.2, the L1 row — old (part of one line):

```text
`GraphicsPipelineServer` ↔ `GraphicsPipelineClient` in memory (cases below)
```

new:

```text
`GraphicsPipelineServer` in memory, its output decoded with IronRDP's own PDU types (rev 6.2: not `GraphicsPipelineClient`, whose handler consumes the PDUs the cases assert; every `WireToSurface1` is checked to be AVC420) (cases below)
```

(20) §11.2, the capability ladder — old:

```text
  so Plan C captures them from the flake's FreeRDP); byte-identical through
```

new:

```text
  so they are captured from the flake's FreeRDP — by Plan E's L3 since rev 6.2); byte-identical through
```

(21) §11.2, ack suspension — old:

```text
  and separately with the shadow flag and `InjectSuspendAck` fallback); backlog
```

new:

```text
  which `pin_goldens.rs` pins; rev 6.2: the fallback is not built); backlog
```

(22) §11.6 — old:

```text
- Plan C's L4 also carries what Leg A handed on (§12, §15): the Mac's
```

new:

```text
- Plan D's L4 (rev 6.2: moved from Plan C, which has no HID input path; Plan D's first task, before its `paste.pace` and stuck-key work) also carries what Leg A handed on (§12, §15): the Mac's
```

(23) §12, the Leg A deviation — old:

```text
  held moved to Plan C's L4 (it needs HID input, which the probe never
```

new:

```text
  held moved to Plan C's L4 — Plan D's since rev 6.2 — (it needs HID input, which the probe never
```

(24) §12, the Leg B deviation — old:

```text
  committed with its bytes as a separate fixture file (Plan C captures them
```

new:

```text
  committed with its bytes as a separate fixture file (captured, since rev 6.2 by Plan E's L3,
```

(25) §12, planning unit C — old (part of one line):

```text
Requires the four IronRDP patches, git-pinned from the fork branch (§4.2), or their fallbacks |
```

new:

```text
Requires the three IronRDP patches of `kvm-rdp-egfx-patches-v2` @ `c99eece2`, git-pinned (§4.2; rev 6.2: the patch-1 fallback is not built) |
```

(26) §12, planning unit D — old (part of one line):

```text
| D | M3b + M4: keyboard and mouse mapping,
```

new:

```text
| D | M3b + M4: first §11.6's L4 hardware checks (rev 6.2, moved from C); keyboard and mouse mapping,
```

(27) §13, the target dir — old:

```text
- One shared `CARGO_TARGET_DIR` across any worktrees, never one per worktree.
```

new:

```text
- One shared `CARGO_TARGET_DIR` across long-lived worktrees, never one per worktree — except disposable scratch worktrees, which set their own and delete it when done (rev 6.2: a shared-target test binary bakes in its worktree's path and breaks once that worktree is deleted).
```

(28) §13, the budget — old:

```text
- Budget: ~1.5 GB of target for debug + tests; ~3–4 GB with release and clippy.
```

new:

```text
- Budget (**rev 6.2**): IronRDP's graph puts debug + tests far past the ~1.5 GB once estimated; `scripts/target-budget.sh` fails the gate above `KVM_RDP_TARGET_BUDGET_GIB` — default: the size Plan C measured once its binary and L2 executable existed, × 1.3 — and names the one safe cleanup, `cargo clean`; `[build] incremental = false` is committed.
```

(29) §15 — old:

```text
Open for Plan C's L4 (§11.6): what the Mac sees when the websocket dies with
```

new:

```text
Open for Plan D's L4 (§11.6; rev 6.2): what the Mac sees when the websocket dies with
```

Then check: `grep -c 'rev 6.2' docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` — Expected: at least 28. `grep -n '"egfx", "helper"\|§4.2 patch 4\|in progress, 2026-10-07\|four IronRDP patches, git-pinned\|InjectSuspendAck\|shadow flag\|Plan C captures\|Plan C.s to test\|Plan C L4\|Plan C measures\|Open for Plan C\|Plan C.s L4 also\|to Plan C.s L4$\|never one per worktree\.$' docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` — Expected: no output.

- [ ] **Step 5: The README.** Replace the paragraph

```
**Status:** in development. `kvm-proto` (hardened FLV/H.264 admission, the
SPS rewriter, HID frames) and `kvm-sim` (a fake ES3 for tests) are built and
tested; the bridge itself does not run yet.
```

with

```
**Status:** in development (Milestone 3a). The bridge runs: NLA-only RDP
with EGFX AVC420 passthrough of the KVM's H.264, one session at a time (a
new authenticated client takes over), the KVM's control websocket and HID
writer, admin endpoints and a graceful shutdown — tested against `kvm-sim`
with an in-process IronRDP client. Keyboard and mouse mapping, paste and
clipboard come next (Milestone 3b), after the hardware checks they depend
on; the bridge has not yet driven the real device.
```

and insert, before `## Development`:

````
## Running

    kvm-rdp --config /etc/kvm-rdp/kvm-rdp.toml

(or `KVM_RDP_CONFIG`; no other environment variable is read). A minimal
config — every other key has the spec's default (§4.4):

```toml
[rdp]
nla_password_file = "nla.pass"   # at least 22 characters
tls_cert_file = "tls.crt"
tls_key_file = "tls.key"

[kvm]
host = "192.168.0.50"
# The KVM certificate's SPKI SHA-256 (64 hex digits):
# `kvm-probe fingerprint --host 192.168.0.50 --port 443` prints it; this one is an example.
spki_sha256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
password_file = "kvm.pass"
```

Secret files are read relative to the config's directory (at most 4 KiB,
one trailing newline trimmed) and are never logged. RDP clients log in as
`kvm` (`rdp.username`, compared exactly; a `DOMAIN\` prefix is ignored)
with the NLA password. `/metrics`, `/livez` and `/readyz` listen on
`0.0.0.0:9464`: expose them to the cluster only. On SIGTERM the bridge
disconnects the client (ErrorInfo 0x1), closes the KVM connections — it
never logs out of the KVM — and exits 0 within 5 s. A renewed certificate
(polled every 60 s) does the same once no client is connected, so the
supervisor restarts it with the new pair without cutting a session.

````

- [ ] **Step 6: The final gate.**

Run: `cargo fmt --all -- --check` — Expected: no output.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: no warnings.
Run: `cargo test --workspace --all-features` — Expected: 0 failed (the `l2` binary: 37 passed).
Run: `cargo tree --workspace --target all -i ring` — Expected: `warning: nothing to print.`
Run: `cargo tree --workspace --target all -d --depth 0 --prefix none | grep -E '^ironrdp' || echo none` — Expected: `none`.
Run: `scripts/target-budget.sh` — Expected: within budget; record the size in the report.

- [ ] **Step 7: Commit.**

```bash
git add .github/workflows/ci.yml docs/superpowers/specs/2026-10-05-kvm-rdp-design.md README.md
git commit -m "docs: spec rev 6.2 — Plan C's deviations (DC1–DC22); README: running the bridge; CI bounds and a no-secrets gate (DC19)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Planning notes

Revision after the plan review (2026-10-07). Every Critical and Important finding is resolved in the tasks above; where the fix differs from the one the review proposed, the reason is here.

**Resolved differently from the proposal**

- **Burst baseline (Task 1.1, DC1).** The review offered a robust baseline or a documented 1 s of mid-stream marking; the plan takes the robust one — the window's **median** delay, not its maximum — because the census's https inter-tag maximum (136 ms) would otherwise mark a second of on-time ES3 AUs. Verified in a scratch copy of the repo (own `CARGO_TARGET_DIR`, deleted): the new L0 cases fail on the old marker exactly as Step 2 says (`left: 56, right: 54`; "296 frames marked"), pass on the new one, kvm-proto's 175 + 9 and kvm-sim's 11 + 37 tests pass (with Task 1.2's change), and clippy is clean. One existing test changes with it: `bursts_are_marked_against_real_time` (the seventh AU, not the fifth).
- **The RTT reference rule (Tasks 4.2, 4.4, 5.3, DC6).** The review proposed keeping the rule in the shell; the plan keeps it in the core instead — `Pump` builds a fresh `Flow` (and `Rtt`) at every `SessionStart`, so the core knows a generation's first sample, and the rule stays under L1. The shell now feeds every read, and the review's end-to-end shell test (stale 900, answers 2, 2, 2, then ~700 → a `standing_delay` drop) is added. The gauge shows live samples only.
- **L4 (DC18).** Taken as the review's second option: §11.6's five hardware checks move, by name, to Plan D's first task, with rev 6.2 amendments to every spec line that said "Plan C's L4" (Task 7.1 Step 4 items 11, 16, 18, 22, 23, 26, 29). Writing new `kvm-probe` subcommands that send HID input to the real ES3 belongs with the first code that has a reason to send it, and the bridge ships no input path before Plan D.
- **The non-reading client (Task 6.5).** The review's recipe (suspended acks, a 4 KiB `SO_RCVBUF`, a 64 KiB `backlog_limit`) is used, with one addition: loopback autotunes the server's send buffer to a few MB (64 KiB MSS), which the ES3 fixture's ~80 KB/s would take ~30 s to fill, so kvm-sim floods ~1000 live AUs/s (manual pacing, wall-clock stamps) until IronRDP's write blocks. The watchdog is 300 ms, below the fork's 500 ms `DISCONNECT_STEP_GRACE`, so the abort path runs even if IronRDP gets to the `Disconnect` write.
- **The double `Quit` (Tasks 5.4, 6.6).** Through the review's "test hook that skips step 3": `BridgeHandle::shutdown_skipping_disconnect` (doc-hidden) runs §5.2 without the disconnect and returns how many `Quit`s it took; the L2 case asserts 2 with a client connected.
- **POC-0 stranding (Task 6.3).** The review asked for level 40 in the forwarded SPS; that is the ES3's 1080p30. The fixture is 640×360, which §6.8 (a) raises to level 3 (920 MBs > level 2.1's MaxFS 792; level 3: MaxFS 1620, MaxMBPS 40 500 ≥ 27 600), so the case asserts 30 and says why. Whether a real decoder holds frames stays L5 / the owner's acceptance run.
- **hyper's head buffer (Review Focus 3, Tasks 3.2–3.3).** `max_buf_size` is now set explicitly (16 KiB) for login and the FLV; the bound is stated rather than measured with a counting stream, because `login` opens its own connection and a test-only IO wrapper is not worth the seam.
- **Metrics (Task 2.4, §10.4).** Implemented rather than deferred: frame bytes, inter-arrival and fps in `kvm::video`, ack RTT from the unacked set's `sent_at`, QoE decode time in the GFX callbacks (an atomic metric, no lock). Paste metrics are Plan D's, allocation counts Plan E's. QoE's `timeDiffEDR` is recorded as milliseconds (MS-RDPEGFX), although IronRDP's doc comment says µs.

**Verified by compiling in scratch (own target dirs, deleted afterwards)**: Task 1.1 and 1.2 code and tests; Task 2.4's whole `metrics.rs` under the crate-root lints (clippy clean, 2 passed); the `&mut self` fix for `Video::send` (a minimal probe compiles under `tokio::spawn`, and the `&self` form reproduces "future cannot be sent between threads safely"); hyper 1's `http1::Builder::max_buf_size` + `handshake`. Nothing that links IronRDP was built here (the budget).

**Deferred minors**

- Task 3.7's `a_full_channel_drops_aus_and_marks_the_next` (fixed windows by design: `read = false` must be time-boxed), `a_silent_flv_reconnects_after_the_idle_timeout` and the two side-request unit cases still use fixed `run(d)` windows for positive outcomes; convert them to `run_until` if they flake under §13's throttling.
- Task 6.5's flood rate (`advance(10)` per 10 ms poll) is an estimate from loopback's send-buffer autotuning and the fixture's ~2.6 KB P frames; if the write does not block inside the bound on the dev host, raise the per-poll advance (kvm-sim's viewer queue holds 512) rather than the bound.
- Task 6.2's username case relies on ironrdp-acceptor's `auth_data_by_user` comparing `account_name()` only; a pin bump that changes it fails the case, which is the point.
