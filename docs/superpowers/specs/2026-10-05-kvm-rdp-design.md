# kvm-rdp — design

| | |
|---|---|
| Status | Draft rev 6.1 — Plan B's deviations recorded (2026-10-06); rev 6: census-filled. Design agreed in conversation 2026-10-05; revised after a source-level research pass (IronRDP `38b074e`, macrdp), a five-lens adversarial review, and three coverage/consistency checks (rev 5); amended with the Milestone 0 Leg A census, 2026-10-06 (rev 5.1); filled from the whole census — Legs A, B and C, with FreeRDP 3.31.1 standing in for Windows App — and the Milestone 0 verdict recorded, 2026-10-06 (rev 6) |
| Repo | `github.com/ChristopherJMiller/kvm-rdp` (public, MIT OR Apache-2.0) |
| First target | Angeet/Yeeso ES3 "ONE KVM" wired to a Mac Studio |
| Client | Microsoft Windows App on macOS, through an rdpgw RD Gateway on 443 |
| Companion spec | Deployment, gateway, edge gating and KVM isolation live in `luma-homeops` (separate spec, written after Milestone 0). §9.4 lists what this spec requires of it |

**Rev 6.1 — Plan B (2026-10-06).** Records what building Milestones 1 and 2
settled: POC type 1 is refused (§6.1); trailing zero bytes are trimmed from
every NAL before the §6.2 checks, at most one AUD per tag comes before any
slice, unknown FLV tag types are framing violations, burst marking is
measured from the first coded tag, and the 4 SPS / 16 PPS limits also bound
each tag's in-band sets (§6.2); one active SPS and a sequence header that
replaces every PPS, with a PPS-only change classed `other` and
byte-identical repeats raising nothing (§6.1); the level rewrite applies
H.264 A.3.1's frame-size rules in full, and with level ≤ 5.1 admits at most
32 768 MBs per frame at 30 fps (§6.8 (a)); a `level_idc` outside Table A-1,
or naming level 6, 6.1 or 6.2, is `stream_incompatible` rather than guessed
at (level 5.2 is ranked, then refused by §6.1's limits), level
1b ranks strictly between level 1 and level 1.1, and `constraint_set3_flag`
clears on every level raise of a profile 66/77/88 SPS (§6.8); the
fuzz-oracle module is the one `kvm-proto` module outside the parser lint
denies (§6.2); kvm-sim speaks HTTP through httparse rather than hyper
(§4.1), disconnects a full-but-connected viewer on its next control item
instead of starving it forever, and alternates `idr_pic_id` between
consecutive NO SIGNAL IDRs (§11.5); the POC-type-0 fixture is ES3-shaped —
limited-range BT.709 pixels under the ES3's mislabels (§11.5); and the
IronRDP fork pin moves to `kvm-rdp-egfx-patches-v2`, rebased onto upstream
`2c08bda7` (§4.2).

**Rev 6.1 — Plan B's final review (2026-10-07).** Slice-header lists are
bounded as they are read, from the NAL's first 4 KiB, and the AUD is
checked like a slice header (§6.1, §6.2, §9.3). kvm-sim's manual pacing
marks nearly every AU a burst under its default timestamps, so it gains
wall-clock timestamps for cases of the live path, and `wait_for`'s
predicate may read the sim (§11.5).

**Rev 6 — census-filled (2026-10-06).** Fills every census-dependent value
from `docs/census.md` — Leg A, Leg B (direct) and Leg C (through rdpgw
`16cdaaf`) — and records the Milestone 0 verdict: **go for passthrough**
(§12). Legs B and C ran with FreeRDP 3.31.1 as the stand-in client, because
Windows App could not easily be tested yet; everything only Windows App can
answer is an explicit owner acceptance checklist (§12), and the values that
depend on it ship with safe defaults until then. Video: the SPS rewrite
always adds `bitstream_restriction` (§6.8); `first_ack_grace` 1.6 s and
`flv_idle_timeout` 10 s (§4.4); FreeRDP ignores the VUI, so the ES3's
limited-range pixels show mildly washed out — a known limitation (§6.8,
§10.3, §15); the channel-only resize is broken on FreeRDP, so the real
resize path is the only one (§6.4); the ErrorInfo table is confirmed for
0x7 only (§6.9). Input: `key_repeat_timeout` 10 s and `mac_remap` off until
the key matrix is captured (§7.1, §7.4). Gateway: rdpgw token mode works
only over the websocket transport, clipboard needs `Caps.EnableClipboard`,
the username comes from `Client.Defaults`, the `RDPGWSESSION` cookie must be
stripped at the edge, and tokens are reusable for about 6 min, so they are
pinned to the client's address (§8, §9). IronRDP: the four patches are on a
fork branch that Plan C git-pins; the upstream PR waits for the owner
(§4.2). Plan A's deviations from this spec are recorded (§9.4, §11.5, §12).

**Rev 5.1 — Leg A census amendments (2026-10-06).** Applies only the
`docs/census.md` Leg A findings that no Leg B or C result can change; Legs B
and C are pending and Plan A's Task 9.1 still makes the full census revision
(§12). Transport: one self-signed certificate (one SPKI pin) on all three TLS
ports, TLS 1.3 negotiates with rustls, `https` confirmed (§3.2). Sessions:
logins coexist but **logout is global**, so the bridge never logs out (§3.2,
§5.1, §5.2, §11.3). HID: the session-start pointer report no longer parks the
pointer at (0, 0) (§3.3, §7.4). Video: the ES3's measured stream is recorded
and the preset pinned to 1080p30 (§6.1, §10.3); `CompositionTime` must be
constant, not 0 (§6.1); tag = AU, burst 0 (§6.2); a short side FLV
connection becomes the primary IDR mechanism, with N = 1.8 s (§6.5); the SPS
rewrite becomes required — `level_idc` and a mislabelled VUI (§6.8); a preset
change closing the FLV needs no new mechanism (§6.4). Config, tests,
milestones and open questions follow (§4.4, §11, §12, §15).

## 1. Goal

Drive a machine through a cheap IP-KVM from a native RDP client, with no
browser and no re-encode. kvm-rdp logs in to the KVM, forwards the KVM's own
H.264 to the client untouched (RDP's EGFX AVC420 codec), and turns the
client's keyboard, mouse and clipboard-paste into the KVM's USB-HID frames.

Success means: from a managed work laptop, Windows App opens the Mac Studio's
screen through the gateway behind Dex sign-in; typing and pointing feel
interactive (§10.3 bounds); the bridge costs almost nothing to run (§10.1).

### Non-goals (v1)

- Audio, multi-monitor, file transfer, USB redirection, horizontal scroll.
- Copying from the Mac to the laptop. The KVM only sees pixels and sends
  keystrokes; nothing can read the Mac's clipboard. Paste *into* the Mac is in
  scope, as typing (§8).
- Re-encoding. A client that cannot take AVC420 is disconnected with a clear
  error (§6.7). A re-encode mode may come later if the census demands it, and
  is never silent.
- A bridge-side GOP cache. Getting a keyframe means provoking one from the
  KVM's shared encoder or waiting for one (§6.5); Leg A's measurements meet
  §10.3 without a cache (`census.md`, Census gates).
- More than one client at a time (a new connection replaces the old), or more
  than one KVM per process (more machines = more instances).

## 2. Context and constraints

- **The KVM is hostile.** The ES3 has an unpatched pre-auth root RCE
  (CVE-2026-32297, the unauthenticated `/upload` on :8888, chained with
  CVE-2026-32298 command injection in `cfg.lua`; Eclypsium 2026-03, no vendor
  fix). Everything it sends is attacker-controlled input. Its WAN egress is
  blocked at the router; isolation is the companion spec's job (§9.4).
- **The client is a managed work laptop.** Only App Store apps can be assumed.
- **The work Mac must not be exposed to the internet.** Every path is
  authenticated before it reaches the bridge.
- **The KVM's video is fixed.** Its UI offers resolution and fps only — no
  codec, GOP, profile, range or bitrate control. What it sends at the pinned
  1080p30 preset is in §6.1 and §6.8.
- **The development host is shared and loaded** (§13).

## 3. The KVM interface

Reverse-engineered from the ES3 web UI (`kvm.js`, `index.js`, `common.js`),
and checked against the device by the Leg A census (`census.md`). The one
item the census did not measure is marked *open*.

### 3.1 Endpoints

| Function | How |
|---|---|
| Login | `POST /cgi-bin/login.lua`, body `{"pass","timezone","time"}` → token `0.<digits>`. Concurrent logins coexist (§3.2) |
| Logout | `GET /cgi-bin/login.lua?logout`. **Global**: invalidates every session's token (§3.2). The bridge never calls it |
| Video | `GET /av.flv?token=…` on the video port. HTTP-FLV, H.264 Baseline (§6.1). One encoder serves every viewer (§6.5). The vendor calls FLV "high compatibility" and WebRTC (SRS, :1988) "low latency". FLV source latency is *open*: the census measured FLV open → first IDR and inter-tag jitter, not glass-to-glass; Milestone 6 compares it with the WebRTC baseline (§10.3, §15) |
| Input | WebSocket `/websocket` on the control port |
| Mode | `88 88 01 <0x30+type>` sets HID type; type 0 = absolute mouse. `88 88 03 …` is UART text (unused) |

### 3.2 Transport

- **Scheme `https`** for login, video and websocket, on ports 443 /
  8881 / 8889 (config, not read from `mapping.lua`). The KVM's certificate is
  self-signed, so it is **pinned by SHA-256 of its SPKI** from config;
  `kvm-probe fingerprint` records it once. The ES3 serves **one certificate on
  all three TLS ports**, so one pin (`kvm.spki_sha256`) covers them. A
  mismatch refuses the connection. There is no accept-any verifier.
  (`census.md`, Leg A — transport.)
- Leg A confirmed `https`: rustls negotiates TLS 1.3
  (`TLS_AES_256_GCM_SHA384`) on all three ports; TLS costs ~90 ms on each
  connection open (FLV open → first IDR p50 183 vs 97 ms over `http`) and
  nothing measurable in steady state on a moving screen (inter-tag jitter is
  the same or better) — the static capture's tail is worse (p99 83 vs 49 ms,
  max 136 vs 55 ms, n = 1 capture each; `census.md`, Leg A — transport), but
  the decision is unaffected. Scheme `http` (80 / 8880 / 8888) stays a config option
  for diagnosis on the isolated segment only; neither of the conditions that
  would have justified it (rustls cannot negotiate, measurable TLS latency)
  holds. TLS here buys confidentiality against the LAN, not trust in the
  device.
- After login the token is sent as `Cookie: token=<token>` on **every** request
  — FLV and websocket upgrade — and as the `token` query parameter on the
  FLV URL.
- **Sessions** (`census.md`, Leg A — sessions): concurrent logins coexist (a
  second login leaves the first token valid); **logout is global** — one
  session's logout invalidates every token, including the vendor web UI's;
  an FLV already open survives another session's logout. So an operator
  logging out of the vendor UI also invalidates the bridge's token: the open
  FLV keeps running, and the next FLV or websocket open fails auth and
  re-logs in once (§6.9).
- Clients: hyper and tokio-tungstenite over tokio-rustls (aws-lc provider,
  default features off). `TCP_NODELAY` on every KVM socket.
- Websocket limits: max message and frame 4 KiB, small write buffer; inbound
  data messages are read and discarded; an oversize message closes the socket
  without buffering it.
- **The bridge never calls logout.** Because logout is global, it would end
  the operator's break-glass web-UI session (and any `kvm-probe` run).
  Teardown closes the websocket and the FLV and lets the token lapse (§5.1).

### 3.3 HID frames

Byte-exact with `kvm.js`:

| Frame | Bytes |
|---|---|
| Keyboard | `AA AA 08 00 mod 00 00 k1 k2 k3 k4 k5` — 12 bytes; USB HID modifier byte, five key slots |
| Absolute mouse | `AA AA 05 51 btn xLo xHi yLo yHi` — x, y in 0..=32767 |
| Wheel | `AA AA 04 20 btn 00 00 w` — `w` = `01` up / `FF` down; `btn` = current button mask |

Session-start sequence on every websocket (re)open: `88 88 01 30` (absolute
mode), an all-zero keyboard report, and a zero-button absolute report **at the
last position the bridge sent** — or no mouse report at all if it has sent
none in this process, until the client's first pointer event. Never a fixed
(0, 0): Leg A found that a zero-button report at (0, 0) parks the pointer in
the top-left corner on every websocket (re)open, which on macOS reveals the
menu bar over full-screen apps (`census.md`, Derived decisions, §7 input).

Keyboard frames are verified on the real device: they drive macOS as
specified, US layout, Cmd = GUI modifier bit `0x08` (`census.md`, Derived
decisions).

`kvm.js` does not resend held keys. Its 100 ms timer is a focus heartbeat
feeding a browser-side watchdog that sends an all-zero report after 500 ms
without one. The device needs no refresh; the bridge keeps the safety intent
(§7.4), not the mechanism.

## 4. Architecture

```
                     ┌──────────────────────────────── kvm-rdp ────────────────────────────────┐
                     │  RDP runtime (current_thread + LocalSet)      KVM runtime (1 worker)     │
Windows App ─ rdpgw ─┼─▶ RdpServer (Preempt, Hybrid/NLA)                                       │
                     │     ├─ EGFX pump ◀── ordered KVM stream ◀── KvmSession actor ◀── av.flv ┼── ES3
                     │     ├─ input handler ── HID queue + release epoch ──▶ hid::Writer ──────┼─▶ websocket
                     │     └─ cliprdr ─▶ paste::Typist ──┘                                     │
                     │  admin listener: /metrics /livez /readyz                                │
                     └─────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Workspace

| Crate | Depends on | Holds |
|---|---|---|
| `kvm-proto` | `bytes`, `h264-reader` — no IronRDP, no tokio, no TLS | FLV demux **and mux**, AVCC→Annex-B, NAL sanitiser, SPS/PPS/slice-header checks and SPS-change classification, SPS rewriter, HID encoders, scancode→HID and US-layout tables, login response parsing, and the sans-IO cores of §4.3 that need no IronRDP types |
| `kvm-probe` | `kvm-proto`, tokio, hyper, tungstenite, rustls (aws-lc) | Census tool (§12). No IronRDP |
| `kvm-sim` | `kvm-proto`, tokio, httparse (hyper's parser), tokio-tungstenite, rustls (aws-lc) | Fake ES3 for tests and benches (§11.5), served over TLS; it writes HTTP itself so every FLV byte is observable and corruptible (rev 6.1) |
| `kvm-rdp` | `kvm-proto`, IronRDP, tokio, rustls (aws-lc) | The bridge binary |
| `kvm-bench` | `kvm-sim`, IronRDP client crates | Perf harness (§10.2) |
| `fuzz/` | `kvm-proto` only | Separate cargo workspace, nightly, CI-only |

Every hostile-input parser lives in `kvm-proto`, so fuzzing and most tests
never compile IronRDP or aws-lc. The container image ships `kvm-rdp` and
`kvm-probe`.

### 4.2 Dependencies

- **IronRDP is git-pinned**: one rev, at or after `38b074e` (2026-10-01; for
  Plan C, a rev on the fork branch below), for every `ironrdp-*` crate used
  (including `ironrdp-pdu`, for ErrorInfo codes),
  as direct git dependencies in `[workspace.dependencies]` — no
  `[patch.crates-io]`. crates.io `ironrdp-server 0.13.0` / `ironrdp-egfx 0.3.0`
  lack `ConnectionPolicy::Preempt`, `on_connection_info`, the full EGFX
  capability ladder, re-advertise recovery, the ack-suspend fix and the pre-TLS
  DoS fix (#1515), and their `Avc420Region` bounds are inclusive where HEAD's
  are exclusive.
- **Upstream prerequisites for Plan C.** Plan A wrote four IronRDP patches
  (each roughly 30–50 lines plus a test) on branch `kvm-rdp-egfx-patches`,
  off `38b074e`, of the owner's public fork
  (`github.com/ChristopherJMiller/IronRDP`). **Rev 6.1**: rebased onto
  upstream `2c08bda7`, which merged Devolutions/IronRDP#2034 — the
  equivalent of the old patch 3 below. Upstream's version runs the discard
  inside `run_connection`/`run_connection_with` themselves, so it covers both
  entry points and also drops an embedder's `ServerEvent`s queued *before*
  the call, not only ones left over from an earlier connection — except the
  lifecycle events it keeps by allowlist (`discard_stale_session_events`,
  upstream `server.rs` ~:2229–2240): `Quit`, `GetLocalAddr`,
  `SetCredentials` and `SetAutoReconnectCookie` survive the discard, so a
  `Quit` queued before the call is still seen (§5.2). Patch 3 is
  dropped; the fork, renamed `kvm-rdp-egfx-patches-v2`, now carries three
  patches. The upstream PR for what remains is deferred until the owner says
  to open it:
  1. **Ack suspension survives resets.** (a) `FrameTracker::clear()` keeps
     `ack_suspended` — used by `resize_with_monitors`, i.e. every Setup;
     MS-RDPEGFX's ResetGraphics says nothing about acknowledgement. (b) The
     mid-session re-advertise branch keeps it too — a deliberate deviation from
     MS-RDPEGFX 3.2.5.18 (which asks the server to reset protocol state),
     justified by asymmetric risk: wrongly kept costs ~one RTT of untracked
     frames; wrongly cleared wedges video for good. (c)
     `GraphicsPipelineServer::is_ack_suspended()`. Test: suspend, resize,
     re-advertise, send more than `max_frames_in_flight` frames — all `Some`.
     *No-fork fallback*: the pump keeps a shadow suspension flag from
     `on_frame_ack` (set on `queue_depth == 0xFFFFFFFF`, cleared on any other
     value, its own synthetic acks excluded) and uses it wherever §6.6 reads
     `is_ack_suspended()`; after each Setup while suspended it re-arms
     suspension by feeding a synthetic `FrameAcknowledge{queue_depth: Suspend,
     frame_id: last_issued}` through the handle's `DvcProcessor::process`,
     ignores the resulting `on_frame_ack`, and forwards `drain_output()`.
  2. **A per-generation outbound write-progress counter.** Shipped as
     `EgfxServerMessage::send_messages(..).with_write_counter(weight)` on a
     `#[non_exhaustive]` variant (**rev 6.1**, breaking: not the bare
     `(Arc<AtomicU64>, weight)` tuple field earlier drafts of this patch
     carried) — once every byte of a batch has been written (TCP
     `write_all` + flush returned; a UDP send counts when the send queue
     *accepts* the payload, not when the send itself returns), IronRDP adds
     `weight` to the counter. The bridge sets `weight` = Σ
     `DvcMessage::size()` of the drained batch and owns one counter per
     generation (§6.6).
  3. **A hard-close path**: the per-connection abort handle now comes from
     upstream's own `ConnectionInfo::abort_handle()`, taken in
     `on_connection_info` (**rev 6.1**: not a fork-added field, as earlier
     drafts had it) — dropping the connection future (so `on_disconnected`
     runs) even while the writer is blocked on a peer that stopped reading;
     and a bounded write of the SetErrorInfo PDU on bridge-initiated
     disconnects.

  **Plan C git-pins the fork branch** (`kvm-rdp-egfx-patches-v2`), which
  carries only these three patches — a documented, temporary exception to
  "upstream IronRDP", reverted when the patches merge upstream (the PR is
  opened only when the owner says so). Patch 1 alone can be replaced by its
  fallback; Leg B gave no reason to prefer either, because FreeRDP never
  suspended acks (§6.6, `census.md` Leg B), and Windows App's suspension
  behaviour is an acceptance item (§12).
- CI fails if `cargo tree -d` shows a duplicate `ironrdp-*` crate. A pin bump
  is its own PR, reviewed monthly, and must pass the IronRDP golden tests (§11.2).
- `ironrdp-server` with `default-features = false, features = ["egfx", "helper"]`.
  Never the `ironrdp` meta-crate. `ironrdp-egfx` without `openh264`.
- **One crypto provider, aws-lc-rs**, installed idempotently at startup
  (`let _ = install_default()`). Nothing may pull in `ring`.
- Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1; a nix
  flake devshell provides it with `cc`, `cmake`, ffmpeg/x264, FreeRDP 3 (built
  with OpenH264), Xvfb and bubblewrap.

### 4.3 Runtime, channels and sans-IO cores

- `RdpServer` is `!Send`: it runs on a current-thread runtime under a
  `LocalSet`. Everything touching the KVM runs on a separate one-worker runtime.
- **Sans-IO cores.** Every time-dependent decision — flow control, IDR
  acquisition, watchdogs, stall and negotiation timeouts, backoff, suppression
  debounce, paste pacing — lives in a synchronous core that takes
  `now: Instant` and returns commands. The EGFX pump's core is
  `Pump::step(&mut GraphicsPipelineServer, Input) -> Vec<Command>`, driven by
  the state × input table of §6.4. Its inputs include `SessionStart{gen}`,
  `SessionStop{gen}`, `Au{gen, bytes, idr, burst}`, `OnReady{avc420}`,
  `ReactivationComplete`, `FrameAck{id, queue_depth}`, `Tick`,
  `SuppressSample`, `SpsChanged{class: initial | resize | other, sps, pps}`,
  `FlvOpened{gen, origin: first | transient | commanded}`,
  `UpstreamFatal(Cause)`, `BacklogSample` and `RttSample`; its commands include
  `SendDvc`, `SendSlate`, `DisplayResize`, `ReleaseAll`, `OpenFlv`,
  `RequestIdr`, `ReconnectFlv`, `CancelIdrRequest`, `SetMaxFramesInFlight`,
  `InjectSuspendAck`,
  `ProbeRtt` and `Disconnect(Cause)`. The
  lists are the minimum; the implementation may add variants but not fold
  decisions back into the async shells, which only take locks, call `step`,
  and carry out commands.
- **Locking.** `GraphicsPipelineHandler` callbacks run with the GFX mutex held:
  they only set flags or push inputs, never lock the handle. The pump calls
  `send_*`/Setup **and** `drain_output()` within one lock hold (so a concurrent
  `process()` never flushes bridge frames by the other path), releases the
  lock, then sends one `ServerEvent` per frame (or per burst chunk). `kvm-rdp`'s
  crate root sets `#![deny(clippy::await_holding_lock,
  clippy::await_holding_refcell_ref)]` and CI runs clippy with `-D warnings`.
- **Generations.** `on_connection_info` assigns a connection generation, with
  its own outbound counter (§4.2 patch 2). `on_disconnected` synchronously
  invalidates it (sets it to none) before returning, stops the pump and cancels
  its timers (AVC420 negotiation, stall, IDR wait, suppression, disconnect
  watchdog). All KVM work runs in one `KvmSession` actor that processes
  `Start{gen}` and `Stop{gen}` strictly in order; a `Stop` completes
  (release-all flushed, websocket, FLV and any side FLV closed; never a
  logout, §3.2) before the next `Start` begins. Every `ServerEvent` send,
  including `Disconnect`, is only made for the current generation. Events
  already queued in IronRDP when a connection ends are dropped by IronRDP
  (§4.2 patch 3), not by the bridge.
- **KVM → pump: one ordered stream.** Control messages (`SessionStart/Stop`,
  `SpsChanged`, `FlvOpened`, `UpstreamFatal`) and AUs share one channel, so
  they never reorder. AUs are sent with `try_send` and dropped when the channel
  is full (a flow cause, §6.5; metric); control messages are sent with
  `send().await` and are never dropped (the KVM actor briefly pauses FLV
  reading; the pump drains continuously). SPS/PPS are classified on the KVM
  side (SPSs after the rewrite, §6.8) and travel as `SpsChanged`, so a
  dropped AU can never lose a parameter set; the pump's SPS/PPS cache updates
  only from this stream. Capacity: ≥ the hard cap (§6.6). The FLV is
  otherwise drained at line rate; the KVM never sees back-pressure.
- **Input path** (§7.3) and the **HID writer** never block the RDP runtime.

### 4.4 Configuration

One TOML file, path from `--config` or `KVM_RDP_CONFIG`. Environment variables
other than that path (including `RUST_LOG`) are not read. Secrets come only
from files named in the config — `kvm_password_file`, `nla_password_file`,
`tls_cert_file`, `tls_key_file` — and are never logged. The file is validated
at startup; any error exits non-zero before binding. The TLS identity is loaded
once. The bridge polls the certificate file's mtime every 60 s and, on change,
runs graceful shutdown (§5.2) and exits 0 so its supervisor (Kubernetes, or
systemd on a dedicated host) restarts it — CredSSP binds to the public key read
at startup.

Defaults (every duration is configurable). Census-derived values cite
`census.md`; values marked *acceptance* are safe defaults that the owner's
Windows App run retunes (§12):

| Key | Default | Notes |
|---|---|---|
| `rdp.listen` | `0.0.0.0:3389` | |
| `rdp.username` | `kvm` | Exact, case-sensitive match (§9.1) |
| `admin.listen` | `0.0.0.0:9464` | §4.5 |
| `kvm.host`, `kvm.spki_sha256` | required | One pin covers all three TLS ports (§3.2) |
| `kvm.scheme` / ports | `https` / 443, 8881, 8889 | Confirmed by Leg A (§3.2) |
| `kvm.connect_timeout` / `login_timeout` | 3 s / 5 s | No logout timeout: the bridge never logs out (§3.2) |
| `kvm.backoff` | 250 ms ×2 → 8 s, ±20% jitter | Transient reconnects (§6.9). One backoff state per connection (FLV, websocket): the FLV's resets when a new FLV delivers its first tag, the websocket's once a reopened websocket has sent the session-start sequence |
| `kvm.upstream_deadline` | 20 s | §6.9 |
| `video.default_size` | 1920×1080 | `size()` before any SPS; the ES3 preset is pinned to it (§6.1) |
| `video.max_fps` | 30 | The ES3 preset is pinned to 30 fps (§6.1). Sizes the hard cap and the rewritten level (§6.8) |
| `video.soft_gate` | 500 ms | Age of the oldest unacked live frame (§6.6) |
| `video.hard_cap` | 2 s | hard = ceil(2 s × `max_fps`) + census max burst (0) = 60 frames (§6.6) |
| `video.backlog_limit` | 4 MiB | §6.6 |
| `video.standing_delay_limit` | 500 ms | Used only when auto-detect is negotiated (§6.6) |
| `video.rtt_probe_interval` | 250 ms | §6.6 |
| `video.first_ack_grace` | 1.6 s (*acceptance*) | FreeRDP's first-frame ack p95, 97 ms direct (95 ms through rdpgw), + the 1.5 s pre-census default as margin, because Windows App's p95 is unmeasured (`census.md`, Leg B and Leg C). Once it is measured: its p95 + `soft_gate` (§6.6, §12) |
| `video.stall_timeout` | 10 s | §6.6 |
| `video.idr_policy` | `side` | Leg A (§6.5); `reconnect` and `wait` remain options |
| `video.idr_side_timeout` | 1 s | A side request with no IDR by then falls back to `ReconnectFlv` (§6.5) |
| `video.idr_wait_max` | 3 s | Cumulative open-gate time (§6.5) |
| `video.flv_reconnect_interval_setup` | 1 s | §6.5 |
| `video.flv_reconnect_interval_flow` | 10 s | §6.5 |
| `video.flv_idle_timeout` | 10 s | Far above the ES3's cadence: one tag every 33 ms, static or moving; inter-tag max 136 ms (`census.md`, Leg A — stream and transport). §6.9 |
| `video.burst_chunk` | 8 frames | §6.5 |
| `video.sps_rewrite` | `["level", "vui", "restriction"]` | Required on the ES3 (§6.8): `level_idc` 31 → 40, the VUI made true, and `bitstream_restriction` added (POC type 0 without it, `census.md` Leg A — stream) |
| `video.avc420_timeout` | 10 s from `on_connection_info` | §6.7 |
| `video.suppress_debounce` | 1 s | §6.6 |
| `video.disconnect_watchdog` | 5 s | §6.9 |
| `video.region_qp` | 22 | Constant; client hint only |
| `input.queue` | 256 reports | §7.3 |
| `input.hid_write_timeout` | 1 s | |
| `input.key_repeat_timeout` | 10 s (*acceptance*) | Repeats are not yet confirmed: the typematic capture needs Windows App (`census.md`, Leg B — deferred). Then: measured max initial delay + 2 × repeat interval + 250 ms, floor 1 s (§7.4, §12) |
| `input.modifier_idle_timeout` | 30 s | Confirmed; nothing in the census bears on it (§7.4) |
| `input.mac_remap` | off (*acceptance*) | Until the key-matrix capture shows Windows App's Cmd rewrite can be told apart from a real Ctrl+key (§7.1, §12) |
| `paste.chord` | Ctrl+Option+Shift+V (raw scancodes) | §8 |
| `paste.pace` | 15 ms between HID reports | §8 |
| `paste.max_chars` / `max_bytes` / `modifier_wait` | 4096 / 64 KiB / 5 s | |
| `paste.multiline` | `enter` | or `refuse` |
| `security.accept_rate` | 30 connection attempts per sliding 60 s, global | §9.1 |
| `log.filter` | `info` | EnvFilter syntax; capped (§4.5) |

### 4.5 Admin endpoints and logging

- An admin listener on the KVM runtime serves `/metrics`, `/livez` and
  `/readyz`. `/livez` fails when the RDP runtime's heartbeat (a `LocalSet` task
  bumping an `AtomicU64` each second) is more than 10 s old. `/readyz` succeeds
  once the TLS identity is loaded and the RDP listener is bound; it never
  checks the KVM.
- Logs are `tracing` JSON lines on stdout. `log.filter` is one filter; a
  **second, independent `Targets` filter** holds `ironrdp_*`, `sspi`,
  `tungstenite`, `tokio_tungstenite`, `hyper` and `rustls` at INFO (everything
  else at TRACE) and is combined with it via `FilterExt::and`, so nothing in
  config can raise them. (sspi and the acceptor log NTLM tokens at debug;
  `ironrdp_server` traces every dispatched event; tungstenite traces HID
  payloads.)
- Bridge code never logs keystrokes, HID frames, pasted text, the KVM token or
  passwords. HID and paste activity is logged as counts. URLs are logged as
  `scheme://host:port/path`, query removed. No per-frame events above `trace`.

## 5. Session lifecycle

### 5.1 Connection

- `RdpServer::run()` with **`ConnectionPolicy::Preempt`**; `run()` sets
  `TCP_NODELAY`. A new authenticated connection evicts the old one. A takeover
  must finish TLS + NLA within 10 s (an IronRDP constant), so the client must
  trust the bridge certificate without a prompt and have the NLA credential
  pre-filled or saved.
- `RdpServer::enable_autodetect()` is called, so RTT probes are available when
  the client negotiates the message channel (§6.6).
- `ConnectionHandler::on_accept` enforces `security.accept_rate`.
- Everything that runs before authentication on every TCP connect — `size()`,
  `monitor_count()`, channel factory builds, `build_server_with_handle` — is
  inert. **No KVM traffic before auth.**
- **`on_connection_info`** (once per connection, after credentials are
  validated, skipped on reactivation) assigns the generation and sends
  `Start{gen}`: login → websocket (session-start sequence, §3.3). The FLV is
  **not** opened here: the first Setup opens it (`OpenFlv`, §6.4), so a client
  that never negotiates AVC420 costs no video, and connecting costs exactly one
  FLV open.
- **`on_disconnected`** and eviction invalidate the generation and send
  `Stop{gen}` (§4.3). A client killed mid-session through rdpgw reaches the
  server as a TLS read error (`AlertReceived(DecodeError)`), where a direct
  kill closes cleanly (Leg C); both are a client disconnect.
- **The KVM token** lives from `Start` to `Stop`: one login per `Start`; FLV,
  side-FLV and websocket reopens reuse the token, and the bridge logs in again
  only on an auth failure (§6.9). **It never logs out** — ES3 logout is global
  and would end the operator's break-glass web-UI session (§3.2,
  `census.md` Leg A — sessions). `Stop` closes the websocket and the FLV and
  drops the token, which lapses on the KVM; a takeover is `Stop` then
  `Start`, so it costs one new login and no logout.
- `size()` returns the last-known KVM resolution, held in memory per process;
  a restart falls back to `video.default_size`. If the first SPS disagrees, the
  resolution change runs after the first Setup (§6.4).
- Preempt's evicted-peer cooldown is keyed by source IP. Behind rdpgw every
  client shares one IP, so a retake within 5–30 s of a takeover is refused.
  Documented, not worked around.

### 5.2 Shutdown

On SIGTERM or SIGINT: stop accepting; release-all and wait for the websocket
flush (≤ 500 ms); disconnect the client with cause `shutdown`; close FLV and
websocket (no logout, §5.1); exit within 5 s. A `ServerEvent::Quit` sent
while a client is connected ends only that connection — IronRDP's
connection loop returns `Disconnect` and `run` goes back to accepting — so
stopping the server takes a second `Quit` after that connection has
drained (rev 6.1). Release builds use
`panic = "abort"`. A crash cannot release keys: what the Mac does when the
websocket TCP connection dies with a key held moved from Leg A to Plan C's L4
hardware checks (§12), and the answer goes in §9.3.

## 6. Video: EGFX AVC420 passthrough

### 6.1 Admission

Checked on the KVM side (`kvm-proto`) on the first sequence header and on every
SPS/PPS after it. SPS checks run on the **rewritten** SPS (§6.8): the ES3's
SPS as sent fails them.

- FLV `CodecID == 7` (AVC). `12` or Enhanced-RTMP `hvc1` (HEVC) is refused:
  EGFX has no HEVC codec.
- `CompositionTime` **constant per stream** on coded (NALU) tags (no
  B-frames): the first coded tag after each FLV open sets it, and a coded tag
  that differs is refused. Sequence-header tags are exempt. The ES3 sends a
  constant 16 ms (0 on the sequence header), so a `== 0` rule would refuse it
  (`census.md`, Leg A — stream).
- **SPS limits**: `profile_idc ∈ {66, 77, 100}` — the ES3 sends 66, and 77
  and 100 stay admitted for the committed fixtures (Main) and other sources;
  within a KVM session the first SPS pins the profile (below); chroma 4:2:0,
  8-bit; `frame_mbs_only_flag == 1`; level ≤ 5.1; width ≤ 4096 and height ≤
  2304, both even; `num_ref_frames` ≤ 1, the census value (`census.md`,
  Leg A — stream), and never above 16 (`SpsLimits`' ceiling; tests that
  replay fixtures with more reference frames raise it, never past 16);
  `seq_scaling_matrix_present_flag == 0` and VUI
  `nal/vcl_hrd_parameters_present_flag == 0` — the ES3 uses neither
  (`census.md`: no scaling matrices, `nal_hrd` 0, `vcl_hrd` 0), so these stay
  refusals and no values are pinned.
- **POC type 1 is refused** (rev 6.1): the POC rule below is computed for
  types 0 (the ES3) and 2 (x264), and no source in scope uses type 1.
- **PPS**: `num_slice_groups_minus1 == 0`; `num_ref_idx` defaults bounded;
  `pic_scaling_matrix_present_flag == 0` (the ES3 has none, `census.md`).
- **Slice headers**: `slice_type ∈ {0, 2, 5, 7}` (P and I only); `pps_id` refers
  to a validated PPS; `first_mb_in_slice < PicSizeInMbs`; POC strictly
  increasing in decode order within a GOP. Lists are bounded (rev 6.1,
  final review): at most 16 active references
  (`num_ref_idx_lX_active_minus1` ≤ 15, frames only), at most
  `num_ref_idx_lX_active_minus1 + 1` `ref_pic_list_modification` entries
  per list (H.264 7.4.3.1) and at most 66 memory-management operations
  (ffmpeg's `MAX_MMCO_COUNT`) — refused as each list is read, so a hostile
  header never costs memory in proportion to its length. The header is
  read from the NAL's first 4 KiB only: the longest conforming header §6.1
  can admit is about 1 KiB on the wire, so one that does not fit is
  unparsable.

**The ES3's stream** (`census.md`, Leg A — stream; 1920×1080 at 30 fps, the
only preset measured). These are the values kvm-sim's ES3 profile, the
fixtures and the limits above are held to:

| Field | ES3 value | Consequence |
|---|---|---|
| Codec | AVC (`CodecID 7`), no Enhanced-RTMP FourCC | Admitted |
| Profile / constraints / level | Baseline (66), `constraint_set0–5` all 0, `level_idc` 31 | Level rewritten to 40 before any check (§6.8). FreeRDP decodes an ES3-shaped x264 stream as labelled (level 31, `constraint_set1_flag` 0) and with level 40 alike (`census.md`, Leg B); Windows App is an acceptance item (§12) |
| Size | 120×68 MBs (1920×1088), `frame_cropping` bottom 8 → 1920×1080 | `video.default_size`; the slate matches |
| POC type / refs | POC type 0, `log2_max_frame_num_minus4` 4; `max_num_ref_frames` 1; progressive | `num_ref_frames` limit 1 |
| Entropy / PPS | CAVLC, 1 slice group, no scaling matrices, no HRD | The slice-group, scaling-matrix and HRD rules above hold as written |
| VUI | Present; claims full range, BT.601 (primaries 5, matrix 5); no timing, no `bitstream_restriction` | Wrong: rewritten, and `bitstream_restriction` added (§6.8) |
| Cadence | 30 fps (timestamp steps 33/34 ms), one tag every 33 ms static or moving; GOP 60 frames (2 s) | No idle gaps; `wait` would give N = 2.5 s (§6.5) |
| Framing | tag = AU (no multi-picture, continuation or non-VCL-picture tags in ≈ 2 700); AVCC length size 4; coded tags carry only NAL types 1 and 5 (no AUD, SEI or in-band SPS/PPS) | No AU assembler (§6.2) |

**The KVM preset is pinned to 1920×1080 at 30 fps** — not "auto", which
invites resolution changes (and lets the Mac drive 4K at level 5.1), and not
60 fps, which would need level 4.2 and double the bitrate for no gain on a
remote desktop. Display sleep does not change the SPS: the KVM switches to
its own NO SIGNAL card (all-intra, every frame an IDR) with the same SPS
bytes, so it raises no resize.

**SPS changes.** After the first SPS of a KVM session, `profile_idc`, chroma
format, bit depth and POC type are pinned; the pins and the "previous SPS"
persist across FLV reconnects within one KVM session and reset at `Start`.
Every SPS is classified on the KVM side and sent to the pump as
`SpsChanged{class}`:

| Class | Change | Pump action |
|---|---|---|
| incompatible | A pinned field changes, or the SPS is outside the limits | Not sent: fatal, `stream_incompatible` (§6.9) |
| initial | The first SPS after each FLV open (no comparison on the KVM side) | Replace the cache. If its dimensions differ from the current surface (or `size()` before the first Setup), resolution change; otherwise no NeedIdr cause |
| resize | Dimensions or level change, within limits | Replace the cache; resolution change (§6.4) |
| other | Anything else (`num_ref_frames`, VUI, `log2_max_frame_num`, cropping, `sps_id`), within limits | Replace the cache; a flow cause (§6.5) — drop until the next IDR, which carries the new SPS; never a reconnect |

Parameter-set model (rev 6.1): one active SPS, the latest admitted; a
sequence header replaces every PPS, and cached PPSs that no longer parse
against a new SPS are dropped; a PPS-only change is `other`; a byte-identical
repeat (in-band SPS/PPS with every IDR) raises nothing.

### 6.2 FLV demux and NAL sanitiser (`kvm-proto`)

Hand-rolled incremental state machine on `BytesMut`; no AMF0 parsing; no
resync scanning.

- Header `FLV`, version 1, `DataOffset` 9 (≤ 64 tolerated). Tag type 9 parsed;
  8 and 18 skipped; any other tag type is a framing violation (rev 6.1). `DataSize` is checked against the limit **before** anything
  is buffered. `PrevTagSize` must equal `11 + DataSize`. `StreamID` must be 0.
  An encrypted tag (`0x20`) or a bad header is a framing violation (§6.9).
- `AVCDecoderConfigurationRecord`: version 1, `lengthSizeMinusOne ∈ {0,1,3}`,
  1–4 SPS and 1–16 PPS of ≤ 1 KiB each, validated per §6.1.
- `AVCPacketType 2` (end of sequence) → FLV reconnect (transient, §6.9).
- NALU tags: length-prefixed NALs, `0 < n ≤ remaining`, forbidden bit 0.
- **Allowlist `{1, 5, 7, 8, 9}`** — slices, IDR, SPS, PPS, AUD. SEI, filler and
  everything else is dropped. In-band SPS/PPS are classified (§6.1) and
  removed from the AU; they travel as `SpsChanged`.
- **Any NAL containing `00 00 00`, `00 00 01` or `00 00 02` is refused**, or
  the client's start-code scanner would find NALs we never checked.
- Trailing zero bytes are trimmed from every NAL before these checks (rev
  6.1): Annex B cannot tell them from `trailing_zero_8bits`, a conforming NAL
  never ends in `00`, and the ES3 appends them to its SPS and PPS
  (`census.md` `sps_hex`, `pps_hex`).
- At most one AUD per tag, before any slice (rev 6.1); §6.3 sends it first.
  It reaches the client verbatim, so it is checked like a slice header (rev
  6.1, final review): exactly `access_unit_delimiter_rbsp` — two bytes once
  trimmed, `primary_pic_type` then the stop bit — with a `primary_pic_type`
  whose Table 7-5 set holds every slice type in the tag (7.4.2.4); anything
  else is `stream_incompatible`.
- Limits: tag 4 MiB, 128 NALs per AU, 4 SPS, 16 PPS — the SPS/PPS limits
  bound a config record and, separately, each NALU tag's in-band sets: a
  fifth SPS or seventeenth PPS in one tag is a framing violation, refused
  before it is rewritten or parsed (rev 6.1).
- One FLV tag is one access unit: Leg A found no multi-picture, continuation
  or non-VCL-picture tags in ≈ 2 700 (`census.md`). There is no AU assembler;
  a tag that is not exactly one picture (a second picture start, or a first
  slice with `first_mb_in_slice ≠ 0`) is a framing violation (§6.9).
- **Bursts**: an AU whose FLV timestamp runs more than 100 ms ahead of its
  receive time (measured since the FLV connection's first coded tag, rev
  6.1) is marked
  `burst` — a GOP-caching source replaying on connect. The ES3 sends none
  (burst on connect 0 frames, `census.md`); the marking stays as a defence.
- Parser modules deny `clippy::{indexing_slicing, unwrap_used, expect_used,
  panic, arithmetic_side_effects, as_conversions}`. The one exception is
  `kvm_proto::fuzzing` (rev 6.1): the fuzz targets' bodies, whose panics are
  findings, compiled only for tests and for `fuzz/` (feature `fuzzing`, which
  CI forbids any workspace crate to enable). It parses nothing the bridge
  receives.
- Ownership: the demuxer splits AU payloads out of the FLV buffer as
  refcounted `Bytes` (no copy); the pump converts each AU into one reused
  Annex-B `Vec` immediately before sending.

### 6.3 Output contract

- Annex-B with 4-byte start codes, one access unit per `send_avc420_frame`,
  converted by our code (never IronRDP's `avc_to_annex_b`).
- Each sent AU = [AUD if present] + the cached SPS (as rewritten, §6.8) and
  PPS (IDR only) + the source AU's allowlisted VCL NALs, in order. Only AUs
  with a VCL NAL are sent.
- Region `Avc420Region::full_frame(w, h, video.region_qp)` (exclusive bounds,
  QP ≤ 63). Surface = display size; the 16-aligned coded size is cropped by
  the SPS.

### 6.4 State machine

**Setup** (an action, not a state; pump, under the lock):
`resize_with_monitors(w, h, [Monitor{left: 0, top: 0, right: w-1, bottom: h-1,
flags: PRIMARY}])` (inclusive bounds, unlike `Avc420Region`; never an empty
list), `create_surface`, `map_surface_to_output`, `SetMaxFramesInFlight(hard)`,
and — if suspended without upstream patch 1 — `InjectSuspendAck`. The first
Setup of a connection also issues `OpenFlv`; every Setup is a Setup cause
(§6.5). Surface ids from before an `on_ready` are invalid; Setup always uses
the latest `create_surface` id. Mouse scaling switches to the new surface here.

**Slate**: on the first Setup of a connection, if the surface equals the
embedded slate's dimensions (read from its SPS; the slate is a pre-encoded
"Connecting to KVM…" IDR built by `gen-fixtures` at 1920×1080 and embedded with
`include_bytes!`), the pump sends it. The slate is not a KVM frame: it does not
arm suppression, does not count for delivery metrics, and oracles start at the
first KVM IDR.

**NeedIdr** means P-frames are dropped until an IDR is handed to IronRDP. Two
flags drive what it does while waiting (§6.5): `idr_pending` and the
idr-wait accounting.

**ReactivationComplete** is an `updates()` call made while in
`WaitReactivation` after a Resize was emitted (IronRDP builds a new updates
stream on every call); in any other state it is ignored.

States: `WaitReady`, `NeedIdr`, `Live`, `WaitReactivation`, `Paused`,
`Closing` (terminal). `pending_size` holds a resize that cannot be carried out
yet; `return_to_paused` marks a resize started from `Paused`. **Every
transition into `Paused` performs ReleaseAll unless one was already done for
the same suppression edge.**

| State ↓ / Input → | `OnReady` (AVC420) | `OnReady` (no AVC420) | `SpsChanged` initial/resize needing a resize | `SpsChanged` initial (same size) / other | `FlvOpened` | `ReactivationComplete` | Suppress on (debounced) | Suppress off (debounced) | IDR AU | P AU | Gate closes | Fatal / timeout |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **WaitReady** | Setup (+ slate, `OpenFlv` if first); if `pending_size`: start resize; else → NeedIdr | first negotiation: wait `avc420_timeout`, then → Closing(`no_avc420`) | set `pending_size` | update cache | ignore | ignore | ignore | ignore | drop | drop | — | → Closing |
| **NeedIdr** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` is a flow cause | satisfies `idr_pending`, resets idr-wait | ignore | → Paused | — | gates open: send → Live; closed: drop, flow cause | drop | flow cause | → Closing |
| **Live** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` → NeedIdr (flow cause) | → NeedIdr (await this connection's first IDR) | ignore | → Paused | — | send if gates open, else → NeedIdr (flow cause) | send if gates open, else → NeedIdr (flow cause) | → NeedIdr (flow cause) | → Closing |
| **WaitReactivation** | record (merged) | → Closing(`no_avc420`) | set `pending_size` (latest wins) | update cache | ignore | Setup at the reactivated size; if `pending_size` is set and differs: clear it, start resize again; else if suppressed or `return_to_paused` → Paused; else if `on_ready` was never seen → WaitReady; else → NeedIdr (Setup cause) | ReleaseAll; record | record | drop | drop | — | → Closing |
| **Paused** | Setup; stay Paused | → Closing(`no_avc420`) | start resize with `return_to_paused` | update cache | stay Paused | ignore | — | → NeedIdr (Setup cause) | drop | drop | — | → Closing |
| **Closing** | ignore | ignore | ignore | ignore | ignore | ignore | ignore | ignore | drop | drop | ignore | ignore |

*Start resize*: stop sends (→ `WaitReactivation`); update the size used by
`size()` and `request_initial_size()`; emit `DisplayUpdate::Resize` on the
current updates stream; continue per the `ReactivationComplete` cell. AUs
arriving during `WaitReactivation` are dropped. **This is the only resize
path.** Leg B measured it on FreeRDP: `DisplayUpdate::Resize` → reactivation
→ Setup → new-size IDR brought the picture back in 34 ms (37 ms through
rdpgw, Leg C). A channel-only surface swap is never used: it blinks on
Windows App, and on FreeRDP it is broken outright — Leg B's channel-only
Setup (the same 1080p stream on a 1280×720 surface) made FreeRDP reject
every later frame (`areRectsValid: … outside of bounding frame`)
(`census.md`, Leg B).

**Resolution change on the ES3.** One tentative observation (n = 1,
`census.md`): while presets were switched in the KVM UI, a live FLV delivered
8 tags and ended — a preset change appears to **close live FLV connections**
rather than signal in-band. No new mechanism is needed either way: a closed
FLV is a transient reconnect (§6.9), and the new FLV's first SPS is
classified `initial` and, at a new size, starts a resize; a new sequence
header or in-band SPS on a live FLV is classified `resize`. With the preset
pinned (§6.1), this is a rare, operator-driven event.

The stall timer (§6.6) is frozen in `Paused` and `WaitReactivation`.

### 6.5 Getting an IDR

Passthrough can wait for an IDR or provoke one, never make one. Leg A
measured how the ES3 can be provoked (`census.md`, Leg A — stream): it has
**one encoder shared by every viewer, and any new FLV connection forces an
IDR into every open stream** and restarts its GOP (a second viewer connecting
at +12.0 s gave the first an extra IDR at +12.2 s, off its regular cadence).
A new connection's first tag is always an IDR; FLV open → first IDR is p50
183 ms, p95 300 ms over https (20 trials); nothing is replayed on connect
(burst 0); the GOP is 60 frames (2 s).

- **Setup cause**: a Setup (connect, re-advertise, resize), leaving Paused.
- **Flow cause**: a gate closes (§6.6), an IDR is dropped because a gate is
  closed, `send_avc420_frame` returns `None`, an AU is dropped on a full
  channel, a burst is truncated at the hard cap, `SpsChanged other`.
- **FLV opened** (`FlvOpened`, any origin): the NeedIdr waits for that
  connection's first IDR; it never requests one by itself.

Under `side` and `reconnect`, a Setup cause sets `idr_pending`, except for
the first Setup, whose `OpenFlv` already serves; a flow cause starts idr-wait
accounting, and once the gates have been open for a cumulative
`idr_wait_max` (flapping does not reset it) it sets `idr_pending` — usually
the 2 s GOP answers first. `video.idr_policy` says how `idr_pending` is
served:

- `side` (default, from Leg A) — `RequestIdr`: the KVM actor opens a short
  **side FLV connection** with the session's token, reads it through the
  §6.2 demuxer and limits until its first tag, then closes it and discards
  everything it read. The main FLV keeps flowing and carries the forced IDR,
  so there is no `FlvOpened`, no `initial` SPS and no gap. The side
  connection is closed at its first tag or after `idr_side_timeout`,
  whichever comes first; it never feeds the pump, and its failures (refused,
  auth, framing, timeout) are counted, never retried and never re-logged-in.
  **Fallback**: if the NeedIdr is still unresolved `idr_side_timeout` after
  the request, `idr_pending` is set again and served by `ReconnectFlv`.
  Leg A measured it on one token: a second FLV on the main stream's own
  token is served while the main stream keeps flowing, and it forced an
  off-cadence IDR into the main stream (n = 1, `census.md`); L4 repeats it
  over 20 trials (§15), and a refusal would cost only the fallback.
- `reconnect` — `ReconnectFlv`, make-before-break: Leg A shows the new
  connection forces an IDR, so the old FLV closes once the new one delivers
  its first tag. It is `side`'s fallback, and a policy of its own for a
  source whose encoder is not shared.
- `wait` — `idr_pending` is never set; every NeedIdr waits for the next
  periodic IDR.

**Rate limits and cancellation.** Two clocks, `flv_reconnect_interval_setup`
(Setup-caused requests) and `flv_reconnect_interval_flow` (idr-wait
requests), limit how often the bridge forces an IDR on every viewer. **Any**
FLV open (first, transient, commanded) and every `RequestIdr` clears
`idr_pending`, cancels a deferred request, resets idr-wait accounting, and
restarts both clocks. A `RequestIdr` or `ReconnectFlv` that falls inside its
clock's window is **deferred** to the window's end, not dropped — and
**cancelled** (`CancelIdrRequest`) if, before it fires, an IDR is handed to
IronRDP or the pump leaves NeedIdr (Paused, `WaitReactivation`, Closing); a
later cause requests it again. A side fallback is a request like any other;
with the 1 s defaults its `ReconnectFlv` lands at the end of the window its
side request opened. Websocket-only failures never touch NeedIdr.

**Source bursts** (§6.2): burst AUs are exempt from the soft gate, count
against the hard cap and backlog gate, and go out in chunks of `burst_chunk`
frames, one `ServerEvent` per chunk, yielding between chunks so input PDUs
interleave. The hard cap includes the census maximum burst length (§6.6) —
0 on the ES3, so the term is 0 — and a burst within that length is never
truncated; a longer one is truncated (a flow cause). Census gate (§12): max
burst ≤ hard cap and ≤ channel capacity — passed.

**Bound.** The picture must return within N of any Setup cause (§10.3). For
`side` and `reconnect`, N = `flv_reconnect_interval_setup` + census
FLV-open→first-IDR p95 + 0.5 s (the worst case is a request deferred by a
full window) = 1 s + 0.3 s + 0.5 s = **1.8 s** over https. A side request's
IDR comes from the same connection open and the same shared encoder; Leg A
saw it once (~0.2 s), so N uses the 20-trial p95 and L4 re-measures the side
path. A side request that falls back adds `idr_side_timeout`: 2.8 s worst
case, still within §10.3's 3 s. For `wait`, N = GOP length + 0.5 s = 2.5 s.
The census gate — N ≤ 3 s for the chosen policy (for `reconnect` with a 1 s
interval: p95 ≤ 1.5 s) — passes with p95 300 ms (`census.md`, Census gates),
so there is no bridge-side GOP cache. The RDP side adds little: Leg B's
picture returned 34 ms after a server resize (37 ms through rdpgw), but it
replayed a fixture that starts at an IDR, so it measures the RDP path only;
N's KVM term is Leg A's.

### 6.6 Flow control

IronRDP must never drop a P-frame silently; the bridge gates at GOP
granularity.

- **Hard cap** = ceil(`hard_cap` × `max_fps`) + census max burst (60 + 0 on
  the ES3) → IronRDP's `max_frames_in_flight`, set at every Setup. A memory
  backstop only; never `u32::MAX`, never the default 3. Static: it does not
  follow measured fps.
- **Unacked set.** The pump records `sent_at` for every frame id it sends
  (burst and grace frames flagged) and removes ids on ack. It mirrors IronRDP's
  tracker: the set is cleared at every Setup, re-advertise and suspend ack;
  **while acks are suspended nothing is recorded**; the first non-suspend ack
  clears the set before removing its own id; an ack for an id not in the set is
  ignored. Arithmetic is saturating.
- **Grace frames**: the slate and the first IDR after each Setup or FLV open
  are exempt from the soft gate until acked or until `first_ack_grace` has
  elapsed, so a slow first ack (large IDR, decoder start-up) does not freeze
  the picture.
- **Gates**, checked before each live AU (any one closed → a flow cause,
  §6.5):
  - *soft gate*: the oldest unacked frame that is neither burst nor grace is
    older than `soft_gate` (500 ms). Time-based, so frame-rate changes
    (idle ↔ motion) do not move it;
  - *backlog gate*: `handed − written` ≥ `backlog_limit`, where `handed` is the
    sum of weights the bridge attached to this generation's EGFX events and
    `written` is the generation's counter (§4.2 patch 2). Both count
    Σ `DvcMessage::size()` (post-ZGFX, before DVC/SVC/MCS/TLS framing);
    CapsConfirm and CacheImportReply, which IronRDP sends itself, are not
    counted. "Written" means accepted into TLS and the kernel socket buffer, so
    this gate is a lower bound on queueing, not end-to-end latency;
  - *standing delay* (only when the client negotiated auto-detect; FreeRDP
    does and answers the probes — RTT 0–4 ms direct, 119 of 120 answered
    through rdpgw — `census.md`, Leg B and Leg C; Windows App is an
    acceptance item, §12): IronRDP sends RTT probes only on request, so
    while auto-detect is negotiated the pump issues `ProbeRtt` (`ServerEvent::AutoDetectRttRequest`,
    current generation only) every `rtt_probe_interval` and reads
    `autodetect_rtt_handle` after each probe as an `RttSample`. Standing delay =
    median of the last 8 samples − the pump's own baseline (minimum since
    `on_connection_info`; IronRDP's handles are per server, not per
    connection). The gate closes at ≥ `standing_delay_limit`. It is inactive
    until this generation's first sample; a handle at `u32::MAX`, or unchanged
    for 8 consecutive probes, means no signal (gate open; the backlog gate still
    applies). RTT probes queue behind video in every downstream buffer, so this
    sees what the backlog gate cannot;
  - `should_backpressure()`.
- **Stall.** The stall timer arms at the first gate closure after the most
  recent ack (or after Setup, if no ack has arrived since), is disarmed by any
  ack (including a suspend ack), is frozen in `Paused` and `WaitReactivation`,
  and is disabled while acks are suspended. If it reaches `stall_timeout` →
  Closing(`client_stalled`).
- **Ack suspension** (`on_frame_ack` with `queue_depth == 0xFFFFFFFF`):
  **sending never stops** — a client resumes only by acknowledging an EndFrame
  it received. Suspension is read from `is_ack_suspended()` (§4.2 patch 1), or
  from the pump's shadow flag under the fallback, and survives Setup and
  re-advertise. While suspended: the soft gate and
  `should_backpressure()` are bypassed, the stall timer is disabled, and the
  bounds are the backlog gate and standing delay (flow causes); backlog
  continuously ≥ `backlog_limit` for `stall_timeout` → Closing(`client_stalled`).
  A non-suspend ack restores normal gating. FreeRDP never suspended:
  `queue_depth` was 0 on every ack, direct (895 acks) and through rdpgw
  (`census.md`, Leg B and Leg C); L3 exercises suspension with
  `/gfx:frame-ack:off` (§11.4), and whether Windows App suspends — and
  re-sends a suspend ack after a re-advertise or a server resize — is an
  acceptance item (§12).
- **`send_avc420_frame` returns `None` anyway** → a flow cause and a metric.
- **Display suppression.** IronRDP exposes it as a polled flag that clients
  pulse (mstsc sends `SuppressOutput` during connect). The pump samples
  `display_suppressed_handle()` before each AU and on each tick, ignores it
  until the connection's first KVM frame has been delivered, and acts only on
  debounced edges (true or false for `suppress_debounce`), per the §6.4 table.

### 6.7 Clients without AVC420

IronRDP always confirms some EGFX capability set; sending legacy bitmaps after
that is a protocol error on some clients. An `on_ready` whose negotiated set
lacks AVC420 never runs Setup (§6.4): on the first negotiation the bridge waits
`avc420_timeout` for a better one, on a re-advertise it gives up at once; either
way it logs every advertised capability set and disconnects with cause
`no_avc420`. No fallback in v1.

### 6.8 Census-dependent risks

Leg A's results (`census.md`, Leg A — stream and colour) and Leg B's
(`census.md`, Leg B — FreeRDP 3.31.1, direct) are in each row.

| Finding | Effect | Response |
|---|---|---|
| Level below the coded size. **Found**: 1920×1080 labelled `level_idc` 31, but 8160 MBs > level 3.1's MaxFS 3600 | h264-reader — so `kvm-proto`'s `parse_sps` — refuses the SPS as sent (`FieldValueTooLarge { pic_size_in_map_units: 8160 }`); a strict client decoder may too. FreeRDP does not care: an ES3-shaped x264 stream decodes the same at level 31 and 40 (Leg B) | Rewrite (a), below — required for `kvm-proto`'s own checks whatever the client does. Whether Windows App decodes the stream as labelled is an acceptance item (§12) |
| Limited-range or BT.601 samples. **Found**: the pixels are limited-range BT.709 (decoded Y: black 16, white 233–236; pure red Y 63, where BT.601 would give ≈ 81), but the VUI claims full range (`video_full_range_flag` 1) and BT.601 (primaries 5, matrix 5) | MS-RDPEGFX fixes AVC420 to full-range BT.709. A client that applies that fixed conversion ignores the VUI and shows limited-range pixels **mildly washed out**: black → 16, white → 235 (~14 % contrast loss). **FreeRDP does exactly this**: Y 16 / 235 render as RGB 16,16,16 / 235,235,235 whether the VUI says full or limited (Leg B). A decoder that honours the VUI as sent shows washed-out, slightly mis-tinted colour | Measured on **decoded** samples, not flags. Rewrite (b), below, makes the VUI true — right for a client that honours it, but it cannot change a client that applies the fixed conversion. **Known limitation**, below |
| POC type 0 without `bitstream_restriction`. **Found** | Client decoders may hold frames | Rewrite (c), below, **always** — decided in Plan A's Task 9.1 instead of a POC-0 presentation-hold experiment: the SPS is re-serialised for (b) anyway, and the structure is valid for Baseline. Safe because §6.1 already refuses B-slices and non-increasing POC. Leg B's stranding test passed on FreeRDP, but with x264 fixtures, not a POC-0 stream; whether Windows App holds frames on the rewritten stream is an acceptance item (§12) |
| Encoder stops sending on a static screen. **Not found**: one tag every 33 ms whether the screen is static or moving | Some clients hold the last ~2 frames, so the last keystroke never appears | Cannot strand a keystroke on the ES3 at 30 fps. Leg B's barcode stranding test on FreeRDP showed a stable picture while stranded (screens 3 s apart byte-identical; no blank, no partial frame) — not confirmed as the last frame shipped, and run on x264 streams with POC type 2 and `bitstream_restriction`, which cannot fail the presentation-hold gate a real POC-0, no-restriction stream could; that check moves to Plan C's L2 with Plan B's ES3-shaped POC-type-0 fixture (§11.5, Task 6.1). `flv_idle_timeout` (10 s) sits far above the 33 ms cadence |

**Known limitation: mild wash-out on fixed-conversion clients.** The ES3's
pixels are limited-range, and a client that follows MS-RDPEGFX's fixed
full-range AVC420 conversion shows them with black at 16 and white at 235 —
no VUI rewrite can change that (`census.md`, Leg B). The options:

1. **Accept it** — the v1 default. The picture is mildly washed out, not
   wrong; L5 records it (§11.6).
2. **A KVM encoder setting for full range** — the vendor UI has no range
   control (§2), so this means finding one elsewhere on the device. If one
   exists, rewrite (b) changes with it: the VUI must say what the pixels
   measure.
3. **Re-encode** — rejected (§14): a C decoder on hostile input and the CPU
   target broken, to fix a mild contrast loss.

Whether Windows App honours the VUI is the **first** owner acceptance item
(§12): if it does, rewrite (b) fixes colour there and the limitation is
FreeRDP's alone.

**The SPS rewrite (`video.sps_rewrite`) is required**, not conditional: the
ES3's SPS as sent fails §6.1. It runs on the KVM side, on every SPS
(sequence header or in-band), **before** anything parses or checks it;
h264-reader parses only its output, and the rewritten SPS is what is
admitted, classified, cached and sent to IronRDP (§6.1, §6.3). `kvm-proto`
reads the input with its own bounded bit reader (h264-reader refuses it), and
Plan B builds the rewriter, with the POC-type-0 fixture (§11.5, §12).
`video.sps_rewrite` is `["level", "vui", "restriction"]`.

- (a) `"level"`: `level_idc` is raised to the lowest level whose MaxFS and
  MaxMBPS (H.264 Table A-1) admit the coded size at `video.max_fps` — with
  A.3.1's `PicWidthInMbs²` and `FrameHeightInMbs²` ≤ 8 × MaxFS as well (rev
  6.1), which matters only for extreme aspect ratios — and never lowered. With
  §6.1's level ≤ 5.1 this admits at most 32 768 MBs per frame at 30 fps (e.g.
  4096×2048): 4096×2304 needs level 5.2 and is refused after the rewrite.
  **31 → 40** for the ES3's 1080p30 (MaxFS 8192 ≥ 8160 MBs; MaxMBPS
  245 760 ≥ 8160 × 30 = 244 800; 60 fps would need 4.2). Level 1b (`level_idc`
  11 with `constraint_set3_flag` set for profile 66/77/88, or `level_idc` 9
  otherwise) ranks strictly between level 1 and level 1.1 and is never
  lowered to level 1; on every level raise of a profile 66/77/88 SPS,
  `constraint_set3_flag` (0x10) is cleared, even when the input was not
  itself 1b (rev 6.1) — a stray flag below a non-1b level is reserved and
  must not survive the raise. A `level_idc` outside Table A-1, or naming
  level 6, 6.1 or 6.2 (real Table A-1 entries the rewriter does not rank,
  since §6.1 refuses above 5.1 regardless), is refused
  (`RewriteError::UnknownLevel`) rather than guessed at. Level 5.2 is
  ranked like any other: a stream that needs it is rewritten, then refused
  one layer later by §6.1's admission check
  (`SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::Level(52))`).
  `level_idc` is the
  SPS's third payload byte, before any Exp-Golomb field, so on its own this is
  a one-byte patch with no emulation-prevention change.
- (b) `"vui"`: `video_full_range_flag` 0 and colour description **1/1/1**
  (BT.709 primaries, transfer characteristics and matrix), with
  `video_signal_type_present_flag` and `colour_description_present_flag` set
  — what the pixels measure. These fields come after Exp-Golomb fields, so
  this is a bit-level re-serialisation of the SPS with emulation prevention
  re-applied.
- (c) `"restriction"`: add `bitstream_restriction` with
  `max_num_reorder_frames = 0` and `max_dec_frame_buffering =
  max(num_ref_frames, 1)` — **0 and 1** on the ES3 (`max_num_ref_frames` 1,
  `census.md` Leg A — stream) — and the structure's other fields at the
  values H.264 infers when it is absent, so nothing else changes. An SPS that
  already carries `bitstream_restriction` keeps it. The same
  re-serialisation as (b), so it costs nothing extra.

An SPS the rewriter cannot read (it reads only what §6.1 admits), whose
`level_idc` names no level in Table A-1, or level 6, 6.1 or 6.2
(`RewriteError::UnknownLevel`, rev 6.1), or whose output h264-reader does
not parse back to the input's fields apart from the rewritten ones, is
`stream_incompatible` (§6.9). There is no pass-through: without the
rewrite the ES3's stream cannot be admitted at all.

### 6.9 Upstream failure taxonomy and disconnects

| Class | Events | Response |
|---|---|---|
| Transient (FLV) | connect refused or timeout; FLV EOF (including a KVM preset change, §6.4); end of sequence; HTTP 5xx; FLV open but silent for `flv_idle_timeout` | Reconnect with `kvm.backoff`, keep the last picture; the new FLV's `FlvOpened` puts the pump in NeedIdr for its first IDR (§6.4) |
| Transient (websocket) | websocket close or oversize message; a write exceeding `hid_write_timeout` | Reconnect with `kvm.backoff`; the session-start sequence; no NeedIdr |
| Auth | login rejected; HTTP 401/403 or `result: 403` on FLV/WS — e.g. after any session's logout, which is global (§3.2). Side FLVs are excluded (§6.5) | Re-login once (the only time the bridge logs in again within a session, §5.1). A second consecutive failure, with no successful re-login in between, is fatal: `kvm_auth_failed` |
| Certificate | SPKI mismatch | Fatal immediately, no login sent: `kvm_cert_mismatch` |
| Stream-incompatible | HEVC; B-frames (including a `CompositionTime` change); outside §6.1 limits; a pinned field changes; a slice, PPS or AUD check fails; an SPS the rewriter cannot read or verify (§6.8) | Fatal immediately: `stream_incompatible` |
| Framing violation | bad header, encrypted tag, `StreamID ≠ 0`, bad `PrevTagSize`, oversize tag, start code in a NAL, NAL limits, NALU before any sequence header, a tag that is not one picture (§6.2) | Transient (FLV reconnect, `parse_errors{kind}`); three within 60 s is fatal: `stream_corrupt` |
| Deadline | No successful login within `upstream_deadline` of `on_connection_info`; or no FLV tag within `upstream_deadline` of the first FLV open, or since the FLV connection was lost, despite reconnecting | Fatal: `kvm_unreachable` |

Paused, NeedIdr and `WaitReactivation` never count toward the
deadline; it measures KVM-side evidence only.

**Disconnecting.** Every fatal cause moves the pump to `Closing`: it stops all
EGFX sends, then sends `Disconnect(ErrorInfo)` through
`ErrorInfoDisconnectHandle`, and arms `disconnect_watchdog`. If
`on_disconnected` has not fired when the watchdog expires, the bridge
releases all keys, sends `Stop{gen}` to the KVM side anyway, and aborts the
connection (§4.2 patch 4) — so a client that has stopped reading cannot hold
the session or the KVM connections open.

Codes are explicit server-initiated ErrorInfo values (MS-RDPBCGR 2.2.5.1.1),
so the client does not auto-reconnect into a loop; the log line names the
cause. **Confirmed for 0x7 on FreeRDP only**: FreeRDP logs
`ERRINFO_SERVER_DENIED_CONNECTION` and exits without auto-reconnecting,
directly and through rdpgw (`census.md`, Leg B and Leg C). The table stands
as written; Windows App's dialog and reconnect behaviour for each code
(0x1, 0x5, 0x7, 0x9), and whether `0x19` SERVER_SHUTDOWN suits `shutdown`
better, are an acceptance item (§12) that may revise it.

| Cause | ErrorInfo |
|---|---|
| `shutdown` | `ERRINFO_RPC_INITIATED_DISCONNECT` (0x1) |
| `kvm_unreachable`, `stream_corrupt`, `stream_incompatible`, `no_avc420`, `client_stalled`, `clipboard_oversize` | `ERRINFO_SERVER_DENIED_CONNECTION` (0x7) |
| `kvm_auth_failed`, `kvm_cert_mismatch` | `ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES` (0x9) |
| Takeover (IronRDP) | `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (0x5) |

## 7. Input

### 7.1 Keyboard

- RDP scancodes (set 1, extended flag) → USB HID usages via a static table;
  Unicode key events → a US-layout table (usage + Shift). The Mac applies its
  own layout.
- Five key slots, as on the device. A sixth simultaneous key is not reported;
  when a slot frees while it is still held, it is reported then.
- A repeated `Pressed` for a held key changes no state (the Mac auto-repeats
  from the held report), but counts as input for §7.4.
- **Mac remap**: Windows App rewrites Cmd+C/V/X/A/Z/F/W to Ctrl+… and sends
  other Cmd chords as the Windows key; Cmd+Tab, Cmd+Space and Cmd+Q stay on the
  laptop. A config-driven remap table can undo this; it ships **off** until
  the key-matrix capture shows whether the rewrite can be told apart from a
  real Ctrl+key. Leg B could not capture it — FreeRDP has no Windows App
  rewrite — so it is an owner acceptance item (`census.md`, Leg B — deferred;
  §12).
- Known limits: no horizontal scroll (the server does not advertise
  `TS_MOUSE_HWHEEL`); Pause arrives as LCtrl+NumLock (`EXTENDED1` is dropped).

### 7.2 Mouse

- Absolute only: `x_hid = x * 32767 / (w - 1)`, clamped (x = 0 → 0, x = w−1 →
  32767); same for y. w, h are the current surface's (switched at Setup,
  §6.4). This intentionally differs from `kvm.js`'s `floor(x / w × 32767)`.
- Buttons left/right/middle = HID bits 0/1/2.
- Wheel: RDP's ±120-per-notch rotation is accumulated; each whole notch emits
  one wheel frame (§3.3) with the current button mask.

### 7.3 HID output path

- The input handler owns the authoritative HID state (pressed keys, button
  mask, last absolute position) and is synchronous and O(1).
- It pushes **full-state** reports, each stamped with the current **release
  epoch**, into a bounded queue (`input.queue`) with `try_send`. A motion-only
  report replaces a motion-only tail already queued. Key and button reports are
  always queued.
- If the queue is full, the handler clears it and sets `resync`; once the
  writer drains, it sends the current full state. Because every report is full
  state, the final state is always right; a tap that starts and ends entirely
  inside a stall can be lost, and this is documented.
- **Release-all** bumps the epoch and sets an atomic flag plus a `Notify`. The
  writer services it before anything else and **discards every queued report
  (keyboard, mouse or Typist) stamped with an older epoch**, so nothing queued
  before a release can re-press a key after it.
- While the websocket is down, reports are discarded; reconnect sends the
  session-start sequence.
- A websocket write that takes longer than `hid_write_timeout` closes and
  reconnects the websocket (transient, §6.9).
- `on_disconnected` sets release-all and then closes over the same ordered
  path, so the release is flushed before the socket closes.

### 7.4 Stuck-key safety

RDP gives the server no focus-loss signal. **Release-all** — for every trigger
— resets the handler's state to nothing pressed and sends an all-zero keyboard
report and a zero-button mouse report at the last position sent (none if no
position has been sent yet; never (0, 0), §3.3). Keys and buttons that were
held at that moment are marked *released-by-bridge*: further `Pressed`
events for them (typematic repeats) are ignored until the client sends their
`Released`, after which they behave normally. So a release never turns into
a down-up-down glitch, and a reconnect never re-presses anything. Mouse
position is kept.

Triggers:

- `KeyboardEvent::Synchronize`
- `on_connection_info` (a new session never inherits held keys)
- `on_disconnected`, eviction, `Closing` and process shutdown (§5.2, §6.9)
- websocket reconnect
- debounced display suppression (§6.6)
- **timers** (mouse events never reset them):
  - non-modifier keys held and no `Pressed` repeat of **any** held
    non-modifier key for `key_repeat_timeout` (typematic repeats only the most
    recently pressed key). It is 10 s — the value for unconfirmed repeats —
    until the owner's Windows App typematic capture sets it from §4.4's
    formula (§12);
  - modifiers held and no keyboard event of any kind for
    `modifier_idle_timeout`.

A stuck Cmd on a work Mac is the failure this exists to prevent; every trigger
has a test (§11).

## 8. Clipboard: paste as typing

One way only, laptop → Mac.

1. The user copies on the laptop; Windows App announces its formats over
   CLIPRDR. The bridge records only that text is available. The server
   advertises no clipboard capabilities of its own.
2. The user presses the **chord** (default Ctrl+Option+Shift+V), matched on raw
   client scancodes before any remap. Cmd+V can't be used: Windows App rewrites
   it to Ctrl+V. The chord's key is swallowed. A chord with no text announced is
   swallowed and logged.
3. The bridge requests `CF_UNICODETEXT` and waits until every physical modifier
   is released; if they are not released within `paste.modifier_wait`, the paste
   is cancelled.
4. The Typist types the text.

**Report sequence.** Each character is one press report and one all-zero
release report; a shifted character carries Shift in the press report's
modifier byte. `paste.pace` separates every report (so ~30 ms per character).
`paste.pace` is provisional: in Leg A an 842-character URL sent at one report
per 20 ms took ~60–90 s to land in Edge's address bar (the omnibox's
per-keystroke work is mixed in), so Plan C measures the KVM's own HID report
rate (L4) before the pace is fixed (`census.md`, Derived decisions).

While typing:

- **The Typist is the only HID keyboard source.** Client keyboard input is
  swallowed except Esc, which aborts (and is itself swallowed). Mouse motion
  passes through; any mouse button, `Synchronize` or §7.4 trigger aborts.
  Abort and completion both end with an all-zero keyboard report.
- If the client's last `Synchronize` reported Caps Lock on, the paste is
  refused (typing would invert case).

Text handling, in order:

1. A trailing line break (CRLF, CR or LF) is removed; it is never typed.
2. With `paste.multiline = refuse`, text that still contains a line break is
   refused.
3. CRLF, CR and LF each become one Return; Tab is typed; other C0 controls and
   characters the US layout can't type are skipped and counted per Unicode
   scalar.
4. At most `paste.max_chars` characters are typed, counted after steps 1–3.

Limits and hygiene:

- IronRDP reassembles the whole client-declared SVC/DVC payload (up to 4 GiB)
  before the bridge sees it — CLIPRDR included; there is no declared-size hook.
  A response larger than `paste.max_bytes` after reassembly is discarded and the
  session dropped (cause `clipboard_oversize`). Memory during reassembly is
  bounded only by the memory limit (container or systemd); OOM-kill on an
  abusive NLA-authenticated client is the accepted failure mode. An upstream
  reassembly cap for SVC and DVC is tracked in the pin review.
- Contents are never logged; `FormatDataResponse` is never `Debug`-formatted.
- Deployment must enable the channel or CLIPRDR never opens: rdpgw needs
  **`Caps.EnableClipboard: true`**. Without it rdpgw sends
  `HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD` and FreeRDP leaves `cliprdr` out of
  its channel list; with it, `cliprdr` is requested and given an MCS channel
  (`census.md`, Leg C; clipboard data itself is Plan C's to test).
  `redirectclipboard:i:1` is rdpgw's own default, so rdpgw leaves it out of
  the `.rdp` (it writes no field equal to its default) and the client's
  default applies. Whether Windows App obeys rdpgw's redirect flags is an
  acceptance item (§12).
- Milestone 4 compares our typing with the KVM's own `hid.lua?type=text`
  endpoint; ours stays the default unless the device's paces better.

## 9. Security

### 9.1 Authentication

1. **rdpgw** (companion spec): `/connect` sits behind the oauth2-proxy admin
   tier (Dex; one allowlisted address); the gateway hands out an `.rdp` with a
   gateway token. Leg C (rdpgw `16cdaaf`, header mode behind a stand-in
   proxy, `census.md`) showed the gateway refuses a missing, tampered,
   wrongly signed, `alg:none` or expired token, and a token whose host was
   changed. Two properties shape the edge (§9.3): a token is a **reusable
   bearer credential** until `exp` + 60 s (rdpgw sets `exp` = now + 5 min and
   allows 1 min of leeway, so about 6 min), and rdpgw's own `RDPGWSESSION`
   cookie lets a direct `/connect` skip its trusted-proxy check.
   Requirements in §9.4.
2. **Network**: a NetworkPolicy (or, on a dedicated host, a host firewall)
   admitting only rdpgw to the RDP port counts as a layer **only if the
   companion spec shows it is enforced**.
3. **NLA on the bridge**: `RdpServerSecurity::Hybrid` (CredSSP/NTLM).
   - The release binary only ever calls `with_hybrid`. TLS-only exists only
     behind a `test-insecure` cargo feature that is excluded from the container
     build and refuses to start without a credential validator; no-security is
     never compiled in. CI checks the published image rejects any other mode.
   - One static username and password via `set_credentials`. The username
     compare is exact and case-sensitive; it must equal what rdpgw pre-fills.
     A client may add its own host name as the NTLM domain: through rdpgw,
     FreeRDP sent `ROWLETT\kvm` (direct: `kvm`) and IronRDP accepted it
     (`census.md`, Leg C), so the domain is not part of the compare.
   - The password is stored recoverably (NTLM needs it), ≥ 128 random bits, as
     a SealedSecret.
   - TLS: our own rustls `ServerConfig` (not `TlsIdentityCtx::make_acceptor`,
     which honours `SSLKEYLOGFILE`), with our own RSA certificate for the name
     in the `.rdp` — never the edge wildcard. (FreeRDP also completes NLA
     with an ECDSA certificate, `census.md` Leg B; RSA stays because Windows
     App has not been tried with one.)
   - `on_accept` rate-limits attempts (`security.accept_rate`).

### 9.2 Secrets and logging

KVM password, NLA password, TLS key, the KVM token, keystrokes, HID frames and
pasted text are never logged (§4.5). Secrets come only from files (§4.4).

### 9.3 Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Hostile FLV/H.264 attacks the bridge | Hardened, fuzzed parsers in `kvm-proto` with output invariants; no C decoder in the bridge; size limits checked before buffering | Bugs in `h264-reader` |
| Hostile video attacks the **laptop's decoder** | NAL allowlist; start-code check; SPS, PPS, AUD and slice headers limit-checked, slice-header lists bounded as they are read (§6.1) | **Slice data cannot be sanitised without decoding.** A compromised KVM could target the laptop's hardware decoder. Accepted for v1; the answer is containment |
| Compromised KVM records input | — | Every keystroke and paste through the bridge — including passwords typed into the Mac — is visible to a compromised KVM. Accepted explicitly. Don't paste secrets through the bridge |
| Compromised KVM injects keystrokes on its own | Factory reset (or reflash, if a vendor image exists) before first use and after isolation lands; power the KVM or its USB link off when not in use; alert on the router's NO-WAN drop rule (forward rule 120, `NO-WAN-v4`) and on KVM-originated LAN flows (companion spec) | Isolation limits who can reach the KVM, not what it does |
| Anyone who can reach the KVM types into the Mac (port 8888 is the CVE port) | WAN egress blocked; isolation (§9.4) | Until isolation lands, the LAN, the tailnet, and every galaxy pod and hostNetwork process can reach :8888/:8889 |
| Session hijack | Dex + gateway token + NLA (+ NetworkPolicy/firewall if enforced) | In-cluster attacker: NLA only. An in-cluster caller can occupy Preempt's single 10 s candidate slot, delaying a takeover by 10 s per attempt |
| A gateway token is replayed (a leaked `.rdp`) | Tokens are bound to the bridge's host; **`VerifyClientIp: true`** with `Server.TrustedProxies` = the edge and the edge stamping `X-Forwarded-For`, so a token works only from the address that fetched it — Leg C: a token minted for another address is refused (`E_PROXY_RAP_ACCESSDENIED`); NLA still applies (§9.4) | A token is reusable — Leg C opened two tunnels with one — until `exp` + 60 s (about 6 min) from the pinned address. Pinning refuses legitimate connections if `/connect` and the tunnel reach rdpgw from different addresses (split routing, NAT) |
| rdpgw's session cookie bypasses its trusted-proxy check | **The edge strips `Set-Cookie: RDPGWSESSION`** from `/connect` responses, and `/connect` is reachable only through the auth proxy (§9.4). Leg C: the cookie from a proxied `/connect`, sent directly from an untrusted address with no identity header, got 200 and a fresh token, because rdpgw accepts an authenticated session before it checks `TrustedProxies`; IP pinning does not help, since that token carries the caller's own address | If a cookie escapes anyway, it mints tokens for its 120 s lifetime (`Max-Age=120`) |
| A client that stops reading pins the session | `Closing` + disconnect watchdog + hard abort (§6.9) | — |
| Bridge crash with a key held | `panic = "abort"`; release on every orderly path | Depends on the KVM's behaviour on websocket loss (Plan C L4, §12) |
| Census capture leaks or attacks the dev host | Sandbox (§12) | — |

### 9.4 Requirements on the companion spec

- **Isolation with a distinguishable bridge identity.** Pods SNAT to node IPs,
  so a node-IP allowlist only narrows the KVM to "anything on galaxy". The
  bridge needs either:
  - a **dedicated host** on a KVM-only VLAN (its CPU target makes a satellite
    plausible), with systemd as supervisor (`MemoryMax=` sized as the memory
    limit below; `Restart=` on exit; a systemd timer that probes `/livez` and
    restarts the unit when it fails — not `WatchdogSec=`, which would need
    `NOTIFY_SOCKET`, and the bridge reads no environment), a host firewall
    admitting only rdpgw to 3389 and Prometheus to
    9464, Prometheus scraping it as a static target, L4 run on that host with
    the service stopped, and L5 "direct" over an SSH local forward; or
  - a **dedicated pod interface** (Multus/macvlan) on that VLAN.

  Verified by TCP connects to **every KVM service port** — :80/:443/:1988/
  :8880/:8881/:8888/:8889, the vendor's documented ports, all open in Leg A —
  plus a full TCP port scan (Leg A connected to the documented ports only, not
  every port; `census.md`, Leg A — transport), from a non-bridge pod, a node
  shell and the tailnet — all must fail.
- Remove the KVM's Tailscale `/32` route once the bridge works.
- On Kubernetes: whether the CNI enforces NetworkPolicy; if it does, policies
  admitting rdpgw to 3389, and Prometheus plus the node CIDR (kubelet probes)
  to 9464, only.
- rdpgw (Leg C findings at `16cdaaf`, `census.md`; any other pin is
  re-checked against them):
  - Header trust local to the pod: an oauth2-proxy (admin tier) sidecar with
    rdpgw bound to `127.0.0.1` and `header.trustedproxies = [127.0.0.1/32]` —
    or rdpgw's openid mode against Dex. Never trust a pod-network address.
  - `caps.tokenauth: true`; host selection fixed to the bridge's name and port
    (never `any`); `/remoteDesktopGateway/` is the only path exempt from
    forward-auth, and `/`, `/connect` and `/api/v1/*` are never exposed without
    it — path-level routing, since the tunnel shares `/connect`'s port.
  - **Strip `Set-Cookie: RDPGWSESSION`** from `/connect` responses at the edge
    (§9.3): rdpgw's session cookie otherwise lets a direct `/connect` from an
    untrusted address mint a token.
  - **Pin tokens to the client**: `VerifyClientIp: true`, `Server.TrustedProxies`
    = the edge, and the edge stamping `X-Forwarded-For`. Leg C showed rdpgw
    then takes the token's client address from that header and refuses the
    token from any other address. The companion spec shows that `/connect`
    and the tunnel reach rdpgw with the same client address.
  - **Websocket transport only.** In token mode `16cdaaf` refuses the legacy
    two-channel HTTP transport (`RDG_IN_DATA` gets 401: rdpgw #185 ties the
    second half-channel to a non-empty user name, and in token mode the
    gateway endpoint carries no HTTP identity), and
    rdpgw implements no RPC transport. Windows App's transport is an
    acceptance item (§12); if it uses legacy HTTP, rdpgw needs a patch or a
    different pin.
  - **`Caps.EnableClipboard: true`** (§8).
  - `.rdp` username: **`Client.Defaults`** (a one-line `.rdp` holding
    `username:s:kvm`, equal to `rdp.username`) plus **`Client.NoUsername:
    true`**. By default rdpgw writes the proxy identity into `username:s:`,
    and a fixed `Client.UsernameTemplate` without `{{ username }}` is
    rejected on every request (read in rdpgw's code, not run). A full-address
    name that resolves to the bridge from the rdpgw pod. rdpgw writes only
    fields that differ from its defaults, so the `.rdp` has 7 lines and the
    client's defaults apply to the rest (`redirectclipboard`,
    `networkautodetect`, `enablecredsspsupport`).
  - Checks: a `GET /connect` with a forged auth header from another pod is
    refused (Leg C: 401 `Untrusted upstream`); so is a direct `/connect`
    carrying an `RDPGWSESSION` cookie; a token used from another address is
    refused.
- A certificate for that name, with a restart on rotation (§4.4).
- A memory limit (container or systemd) sized from §10.1's stalled-client bound
  plus headroom; the clipboard residual is unbounded by design (§8).
- The ServiceMonitor (on Kubernetes) carries `release=prometheus`, or it is
  never scraped.
- Liveness and readiness probes on `/livez` and `/readyz`.

## 10. Performance

Passthrough should make the bridge nearly free; the perf pass proves it and
keeps it that way.

### 10.1 Targets

| Metric | Target | Measured |
|---|---|---|
| Bridge video latency | p99 < 5 ms | Inside the bridge: last byte of the FLV tag parsed → `ServerEvent::Egfx` enqueued (the enqueue-latency histogram), per frame |
| Bridge input latency | p99 < 5 ms | Client writes an input PDU → kvm-sim reads the HID frame (same-process epoch), while 1080p60 video with IDRs and a source burst is flowing. kvm-bench only |
| Delivery | 1.0 | Frames the bridge handed to IronRDP (`Some`) vs frames acked by the client, in unshaped, non-suspended runs. Shaped runs report the drop rate instead; suspended runs are matched by FrameId |
| CPU | < 5% of one core at 1080p30, 8 Mbit/s | Release build as a subprocess, `/proc/<pid>/stat`; also reported as CPU per Mbit/s |
| Bridge-owned allocations | ≤ 2 per frame | In-process microbench of `kvm-proto` demux → sanitise → Annex-B, plus the pump with a stub server, under a counting allocator |
| Whole-process allocations | ≤ 40 + bytes/1590 per frame | Subprocess, exported via `/metrics`; regression metric |
| Memory (soak) | Over minutes 5–60, RSS least-squares slope < 2 MiB/h and max − min < 16 MiB | `VmRSS` sampled every 10 s, `MALLOC_ARENA_MAX=2`. Every 5 minutes a churn cycle: a preempting reconnect, FLV drop, websocket drop, re-advertise, resize and 1 KiB paste. Nightly, not per PR |
| Stalled client | RSS growth ≤ `backlog_limit` + 16 MiB. Withheld acks or stopped reading: ended within `soft_gate` + `stall_timeout` + `disconnect_watchdog` (+ one RTT) of the first withheld ack or last read. Suspended and not reading: ended within `stall_timeout` + `disconnect_watchdog` of the backlog first reaching `backlog_limit`. Suspended and reading: never ended | Test client withholds acks; separately suspends them; separately stops reading; separately suspends and keeps reading |

End-to-end latency (`sim_tx` = when `write_all` of the tag's last byte
returns, → client `EndFrame` parsed, TLS on both legs) is reported for
information **alongside** a null bridge's distribution — the same client
against a minimal IronRDP server sending kvm-sim's pre-converted AUs from
memory on the same schedule — p50 and p99 of each, never subtracted.

### 10.2 Harness (`kvm-bench`)

- kvm-sim and the measuring client in one process (shared `Instant` epoch); the
  bridge as a subprocess.
- **FrameId** = hash of the concatenated VCL NAL payloads (types 1 and 5) in
  order, without start codes or length prefixes. kvm-sim records FrameId →
  (seq, `sim_tx`) on every send. The bench stream carries the barcode; a load
  check asserts FrameIds are unique within one loop and the loop lasts ≥ 10 s.
  Burst frames are counted separately and excluded from latency.
- The client is a lean EGFX `DvcProcessor` (zgfx decompress, decode the PDU,
  ack on EndFrame) with in-process shaping that needs no root: ack delay, read
  throttle, ack-suspend mode, stop-reading mode. Scenarios: unshaped;
  50 ms / 20 Mbit/s; 150 ms / 5 Mbit/s; a 2 s RTT spike; an idle → motion
  transition. Reports NeedIdr entries per minute, drops by reason and
  time-to-picture after each spike. The soft gate, backlog limit and standing
  delay limit are tuned from these.
- While the client withholds acks, no kvm-sim FLV write blocks for more than
  100 ms (the KVM never sees back-pressure).
- Bench streams: high-entropy source (testsrc2 plus full-frame noise) at
  `-b:v 8M -maxrate 8M -bufsize 8M`, no filler, 30 and 60 fps, at two
  resolutions (1080p and 720p, for resize churn), ≤ 60 s (~60 MB) each,
  generated on demand into `target/` and looped by kvm-sim. The harness asserts
  forwarded VCL bitrate within ±10% of target. kvm-sim uses the production
  scheme (TLS with a pinned test certificate).
- Absolute targets are measured serially, on a quiet host or dedicated runner,
  pinned with `taskset`, at nice 0 (nice 19 is for builds only). CI runs the
  harness with loose thresholds that catch 10× regressions.
- Profiling with `perf` or `samply` from outside; `dhat` only in a dedicated
  single-test binary. No tokio-console (it needs `--cfg tokio_unstable` and a
  full rebuild); tracing spans and §10.4 metrics instead.
- Hot-path rules: `TCP_NODELAY` everywhere; one reusable Annex-B buffer; no
  per-frame logging above trace.

### 10.3 End to end (hardware, Milestone 6 and L5)

- Glass-to-glass: a millisecond clock on the Mac filmed with a slow-motion
  phone camera next to the Windows App window; ≥ 20 samples. **p50 ≤ the
  vendor WebRTC baseline + 30 ms direct, + 50 ms through rdpgw.**
- Picture after connect, reconnect, resize or re-advertise within **N (§6.5),
  ≤ 3 s** — 1.8 s for the `side` policy Leg A chose.
- The KVM preset is pinned to 1920×1080 at 30 fps (§6.1): not auto (the Mac
  may otherwise drive 4K at level 5.1), not 60 fps (level 4.2, twice the
  bitrate). Each result is recorded as pass or fail.
- **Colour is a known limitation, not a bound.** On a client that applies
  MS-RDPEGFX's fixed full-range AVC420 conversion — FreeRDP does — the ES3's
  limited-range pixels show mildly washed out (black 16, white 235;
  `census.md`, Leg B). §6.8 has the options; L5 records what Windows App
  shows.

### 10.4 Metrics

FLV bytes and tags; frames by type; frame bytes; inter-arrival; fps; parse
errors by kind; upstream reconnects by reason; IDR requests by policy (side
requests, side failures by kind, side fallbacks); SPS rewrites by field;
re-logins; frames dropped by reason (soft
gate, backlog gate, standing delay, backpressure, `send_avc420_frame` =
`None`, awaiting IDR, not ready, channel full, Paused, `WaitReactivation`,
burst truncated, Closing); enqueue latency; oldest-unacked age; EGFX
in-flight, backlog bytes, ack suspension, ack RTT, auto-detect RTT and
standing delay, QoE decode time; negotiated capability version; bursts; HID
reports sent, coalesced, resyncs and epoch discards; release-all by trigger;
paste events and skipped characters; disconnects by cause; allocations per
frame (`alloc-stats` builds).

## 11. Testing

### 11.1 Principles

- Time-dependent logic is tested in sans-IO cores with an injected clock
  (L0/L1). L2 checks wiring only, with scaled-down configs (e.g. watchdog
  300 ms, paste pace 0 ms, modifier wait 300 ms, stall 1 s) and one-sided
  asserts: *happens within 5× the configured value* and *does not happen before
  0.5× of it*. Absolute latency bounds live in kvm-bench, not L2.
- Each L2 test client binds its own loopback source address (127.0.0.2,
  127.0.0.3, … — Linux routes all of 127/8 to lo) so Preempt's per-IP cooldown
  cannot couple tests.
- Oracles are independent of the code under test. Scancode→HID goldens come
  from Microsoft's published USB HID ↔ PS/2 scan-code translation table. HID
  frame goldens pin only the encoders and take HID-unit inputs (`x_hid`,
  `y_hid`, wheel ±1), from `kvm.js` behaviour (vectors committed, vendor JS
  not). Pixel→HID scaling is tested only against §7.2's formula.

### 11.2 Tiers

| Tier | Where | What |
|---|---|---|
| L0 unit | `kvm-proto` | Goldens (HID encoders, scancode table, AVCC→Annex-B, SPS fields); SPS rewriter goldens: the ES3's SPS (`census.md` `sps_hex`) → `level_idc` 40, VUI full-range 0, colour 1/1/1 and `bitstream_restriction` added (`max_num_reorder_frames` 0, `max_dec_frame_buffering` 1), emulation prevention re-applied, and the output accepted by h264-reader; a level that already admits the size is never lowered; an SPS already labelled BT.709 limited, at an adequate level and carrying `bitstream_restriction` is byte-identical; a re-serialisation that produces `00 00 0[0-3]` gains an emulation-prevention byte; with `"restriction"`, `bitstream_restriction` already present is kept; an unreadable SPS → `stream_incompatible`; `CompositionTime` constant (16) is admitted and a change refused; FLV mux→demux round-trip property tests; parse of a committed ffmpeg-muxed FLV; burst marking; mouse scaling at the edges; **one hostile vector per §6.1/§6.2 rule, each asserting its specific error kind**; SPS-change classification per §6.1's table; a pre-buffer test (`DataSize = 0xFFFFFF` rejected after ≤ 11 bytes, nothing reserved); sans-IO cores with injected clock (release epoch and released-by-bridge rule, both key timers including two keys held with repeats of the second only → no release, backoff, paste pacing and text handling, debounce) |
| L0 fuzz | `fuzz/` | FLV demux, AVCC, sanitiser, SPS/PPS/slice checks, SPS rewriter, login response; a differential mux→demux target. Output invariants in every target: emitted NAL types ∈ {1,5,7,8,9}; no emitted NAL contains `00 00 0[0-2]`; re-splitting the Annex-B yields exactly the emitted NALs; any emitted SPS is byte-identical to the last admitted (after rewrite) SPS and its pinned fields equal the first SPS's; any emitted AUD is two bytes; every admitted slice header re-parses, from the whole NAL and with no bound, to lists within §6.1's ceilings (rev 6.1, final review). Rewriter: the output re-parses with every field equal to the input except `level_idc` (never lower than the input's), the VUI's video-signal-type and colour-description fields, with `"restriction"`, `max_num_reorder_frames`, `max_dec_frame_buffering` and `bitstream_restriction_flag`, and, on any level raise of a profile 66/77/88 SPS, `constraint_set3_flag` (`constraint_flags & 0x10`), which the rewriter clears (§6.8 (a); rev 6.1, Plan B D12). 5 s per target per PR, longer nightly. CI-only |
| L1 sans-IO | `kvm-rdp` | `Pump::step` and `GraphicsPipelineServer` ↔ `GraphicsPipelineClient` in memory (cases below). IronRDP goldens: `encode_avc420_bitmap_stream(full_frame(640,360,22))` bytes and the ResetGraphics monitor bytes — required on every pin bump |
| L2 full stack | `kvm-rdp` (one test binary) | Bridge + kvm-sim + in-process IronRDP client over loopback (§11.3) |
| L3 interop | CI, `#[ignore]` test | FreeRDP 3 from the flake (§11.4) |
| L4 hardware | opt-in | `kvm-probe` and `--features hil` tests against the real ES3 (§11.6) |
| L5 manual | checklist | Windows App direct and through rdpgw (§11.6) |

L1 cases:

- **Every cell of the §6.4 state × input table**, one case each.
- Each replayed `CapabilitiesAdvertise` yields exactly the
  CapabilitiesConfirm recorded in `census.md`; only AVC420 `WireToSurface1` is
  ever sent. FreeRDP's are recorded (Leg B): with `/gfx:AVC420`, `V8`
  `02000000` and `V8_1` `12000000` → `V8_1`; without it, an 11-set ladder
  `V8`…`V10_7` → `V10_7` (`census.md` names these sets but not their bytes,
  so Plan C captures them from the flake's FreeRDP); byte-identical through
  rdpgw (Leg C), and FreeRDP never re-advertised. Windows App's (direct,
  through rdpgw, any re-advertise) are added from the owner's acceptance run
  (§12). A re-advertise whose confirmed set lacks AVC420 →
  Closing(`no_avc420`) at once.
- After Live, a second CapsAdvertise produces exactly: CapabilitiesConfirm,
  ResetGraphics (w, h, one monitor), CreateSurface, MapSurfaceToOutput,
  StartFrame, WireToSurface1 (IDR with SPS/PPS), EndFrame — no DeleteSurface,
  no P-frame before the IDR.
- Every policy: connecting costs exactly one FLV open (the first Setup's
  `OpenFlv`; no `RequestIdr`, no `ReconnectFlv`); an `FlvOpened` never
  requests an IDR; a transient reconnect clears `idr_pending` and restarts
  both clocks; a flow cause → nothing until a live IDR, and a request only
  after cumulative open-gate time reaches `idr_wait_max`; an IDR dropped at a
  closed gate counts as a flow cause.
  `side` policy: a later Setup → `RequestIdr` (no `ReconnectFlv`, no
  `FlvOpened`), and the first AU sent after it is an IDR from the main
  stream; two Setup causes 300 ms apart → exactly two `RequestIdr`, the second
  deferred to the window's end; a deferred request whose NeedIdr is resolved
  by an IDR inside the window → `CancelIdrRequest`, zero further requests; no
  IDR within `idr_side_timeout` of a `RequestIdr` → exactly one
  `ReconnectFlv`, at the window's end.
  `reconnect` policy: the same cases with `ReconnectFlv` in place of
  `RequestIdr`, and no side fallback.
  `wait` policy: nothing until the next live IDR; no request after the first
  open.
- `SpsChanged`: `initial` at the current size raises no NeedIdr; `initial` at a
  different size (including a reconnect after a mode change) starts a resize;
  `other` is a flow cause and never commands a reconnect.
- Source burst: exempt from the soft gate, chunked, counted against the hard
  cap; a burst over the hard cap is truncated (a flow cause); live frames after
  a burst are gated on the oldest non-burst, non-grace frame.
- Grace frames: a first ack slower than `soft_gate` but within
  `first_ack_grace` does not close the soft gate.
- Soft gate: a 5 fps → 60 fps transition does not close the gate.
- Stall: arms at the first gate closure after the last ack, survives a Setup,
  is frozen in Paused and WaitReactivation (armed, then Paused for more than
  `stall_timeout` → no disconnect), fires at `stall_timeout`; any ack disarms.
- Ack suspension: frames keep flowing and are not recorded; suspension survives
  a server resize and a re-advertise and the picture continues (with patch 1,
  and separately with the shadow flag and `InjectSuspendAck` fallback); backlog
  spikes ≥ limit then drains → NeedIdr, no disconnect; backlog held ≥ limit for
  `stall_timeout` → Closing; a resume ack clears the unacked set and restores
  normal gating without closing the soft gate.
- Standing delay: inactive before the first sample of this generation; a stale
  handle (unchanged for 8 probes) opens the gate; a previous connection's
  samples never affect the next.
- Backlog gate closes and reopens with the per-generation counter; the
  unacked set never underflows.
- Suppression: a short pulse does nothing; a held pulse pauses and releases;
  suppression arriving in `WaitReactivation` releases at once and lands in
  Paused after reactivation; the falling edge is a Setup cause; suppression
  before the first KVM frame is ignored.
- Resolution change: a second resize SPS during `WaitReactivation` is carried
  out after the first reactivation (the surface ends at the latest size);
  `on_ready` during `WaitReactivation` is merged; `ReactivationComplete` outside
  `WaitReactivation` is ignored; a resize started from Paused returns to Paused.
- `send_avc420_frame` = `None` → NeedIdr; the slate precedes the first KVM IDR
  only when the surface matches the slate.
- Closing: stops EGFX sends before `Disconnect`; the watchdog releases keys,
  stops the KVM side and aborts if `on_disconnected` does not come.

### 11.3 L2 cases

Each asserts something exact. The in-process client advertises Windows App's
capability bytes once the acceptance run records them (FreeRDP's `V8` /
`V8_1` pair from `census.md` until then) and uses a capture decoder that records bytes and
returns a dummy frame; a wrapper `DvcProcessor` can withhold or suspend
`FrameAcknowledge`, and the client can stop reading its socket. IronRDP's
`OpenH264Decoder` is never an oracle (it expects length-prefixed input). No
upstream test does AVC420 end to end, in-process NLA or server-side CLIPRDR;
time is budgeted for the harness itself. The video cases run once per
`idr_policy`.

- **Auth and pre-auth**: with a live session, a wrong-password client and an
  `enable_credssp = false` client both fail, the live session keeps receiving
  frames, and kvm-sim records **zero new TCP accepts on all its ports**. A raw
  TCP connect sending garbage → zero kvm-sim accepts.
- **Preemption**: kvm-sim sees exactly release-all → websocket close → FLV
  close → login → websocket open → session-start sequence (its pointer report
  at the evicted session's last position, §3.3), **no logout request**, and
  never two concurrent websockets; the evicted client
  gets `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION`. A retake from the same source
  address within 5 s of an eviction is refused and the live session is
  unaffected.
- **Generations**: disconnect while the pump is streaming, reconnect at once:
  the second session sees no frame, timer or `Disconnect` from the first.
- **Video oracle**: from the first KVM IDR on, the client's FrameId sequence
  equals kvm-sim's, and each received AU matches §6.3's composition; the first
  KVM AU is an IDR carrying SPS/PPS.
- **Lifecycle**: with `default_size` 1920×1080 and a 360p fixture: the slate on
  the default surface, then DeactivateAll and a 640×360 surface before any KVM
  frame, login count 1 throughout; a reconnect sends no Resize; after
  disconnect kvm-sim's open-connection gauge reaches 0; a client with no
  decoder → `no_avc420` (0x7). In every L2 case kvm-sim records zero logout
  requests.
- **Side IDR** (kvm-sim's shared-encoder mode, `side` policy): a re-advertise
  → kvm-sim sees one extra FLV connection, closed by the bridge after its
  first tag; the main FLV never closes; the first KVM AU after the
  re-advertise is the main FLV's forced IDR; with side connections refused,
  exactly one make-before-break `ReconnectFlv` after `idr_side_timeout`, and
  no re-login.
- **Resolution change**, injected as a new sequence header, as an in-band
  SPS, and as an FLV close followed by a new FLV at the new size (the ES3's
  observed behaviour, §6.4), using the second-resolution fixture:
  DeactivateAll; ResetGraphics and CreateSurface at the new size; first KVM
  AU after is an IDR with the new SPS; no EGFX PDU between DeactivateAll and
  the reactivated Demand Active;
  login count unchanged; a second resize in the same session works.
- **Faults**, each asserted against its §6.9 class and ErrorInfo: oversize tag,
  bad `PrevTagSize`, encrypted tag, HEVC codec id, a `CompositionTime` change
  within a stream (a constant 16 ms is admitted), a tag holding two pictures,
  B-slice, start code inside a NAL, NALU before sequence header, end of
  sequence, FLV drop, FLV silent past `flv_idle_timeout` (reconnect, no
  disconnect), token expiry twice in one session with a successful re-login
  between (no disconnect), another session's logout while streaming (kvm-sim
  invalidates every token: the open FLV continues, the next reopen re-logs in
  once, no disconnect), a second consecutive auth failure (fatal), websocket
  drop (reconnect + session-start, no NeedIdr), a 64 MiB websocket message
  (closed at the 4 KiB limit without buffering, reconnect, RSS bounded), KVM
  unreachable (disconnect at the deadline), wrong KVM certificate (no login
  request; `kvm_cert_mismatch`).
- **Stalled client** (asserted on `/metrics`, not timing): withheld acks →
  after the bridge's first soft-gate drop (`frames_dropped{reason="soft_gate"}`
  > 0) its sent-frame counter does not advance again before Closing,
  `egfx_in_flight` ≤ hard throughout, and the session closes with
  `client_stalled`; a client that **stops reading** → the session still ends
  (Closing + watchdog + abort) and kvm-sim sees the websocket and FLV close
  (and no logout); a client that
  suspends acks but keeps reading is never disconnected.
- **Input**: every input event → byte-exact HID frames; a full queue resyncs to
  the correct final state; a blocked websocket write reconnects; with reports
  queued behind a blocked write, a release trigger produces only the zero
  reports and then current state — no queued report is sent after it; a
  websocket reopen's session-start sequence carries the pointer report at the
  last position sent, and none before the client's first pointer event — never
  (0, 0) unless the client put the pointer there.
- **Stuck keys**: every §7.4 trigger releases all; a key held across a release
  is not re-pressed by later repeats until its `Released`; typematic repeats at
  0.2× the timeout for 2× the timeout → no release; no repeats → release; two
  keys held with repeats of the second only → no release; mouse motion never
  resets the timers.
- **Paste**: `"a\r\nb\tc\u{1F600}\n"` → the exact report list (one Return, Tab,
  emoji skipped and counted, no trailing Return); `multiline = refuse` refuses
  `"a\nb"` but types `"a\n"`; a key pressed mid-typing never reaches kvm-sim;
  Esc → a strict prefix, then the zero report, and usage 0x29 never sent; a
  mouse click aborts; modifiers held past the (scaled) wait cancel; Caps Lock
  on refuses; the chord key never reaches kvm-sim; 64 KiB + 2 bytes → session
  dropped, nothing typed; 64 KiB − 2 bytes → typed up to `max_chars`; an 8 MiB
  payload, fully sent → `clipboard_oversize`, nothing typed.
- **Admin**: `/livez` goes stale when the `LocalSet` is blocked; `/readyz`
  succeeds without a KVM.
- **Secrets hygiene** (subprocess, reusing kvm-bench's spawn harness), with
  `SSLKEYLOGFILE=<tmp>` set only in the bridge subprocess's environment (`Command::env`; the test process, kvm-sim and the in-process IronRDP client — whose `ironrdp-tls` config honours the variable — run without it), two runs: `log.filter = "trace"`,
  and `log.filter = "kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace"`.
  Each completes NLA with a password canary, types a sentinel string through RDP
  keyboard input, and pastes a text canary. Capturing stdout and stderr:
  neither canary, nor the sentinel, nor the hex of its 12-byte HID frames
  appears; no `NTLMSSP` or `TlRMTVNTUA`; no DEBUG/TRACE lines from `ironrdp_*`
  or `sspi`; at least one TRACE line from bridge code appears (the filter took
  effect); `<tmp>` is never created.

### 11.4 L3 interop

Bridge and `xfreerdp /gfx:AVC420 /log-level:WARN` as subprocesses, kvm-sim in
process, under `xvfb-run` with `-fbdir`. FreeRDP comes from the flake (nixpkgs
3.32.1, built with OpenH264, which decodes the no-B-frame streams we accept);
Ubuntu's FreeRDP has no H.264. Oracles:

1. No log line matches `avc420_decompress failure|rdpgfx_decode failed|h264`.
2. The Xvfb framebuffer read at two instants ≥ 1 s apart shows the fixture's
   barcode advancing and equal to a counter kvm-sim sent.
3. Bridge metrics: negotiated version, AVC420 frames acked, decode count
   advancing.

A second run uses `/gfx:frame-ack:off` to exercise ack suspension. FreeRDP
models a conformant, non-buffering client; colour and presentation-hold
questions belong to L5.

### 11.5 kvm-sim and fixtures

- kvm-sim serves login, logout, FLV (muxed live by `kvm-proto`'s muxer,
  controlling length-prefix size 1/2/4, pacing, bursts and faults) and the
  websocket (recording every HID frame), over TLS with one test certificate
  on all its ports, which the test config pins.
- Its default profile is the ES3's (`census.md`, Artifacts — parameter sets
  only, never frame data): AVCC length size 4, 30 fps, GOP 60, no burst on
  connect, tag = AU, `CompositionTime` 16 ms; a **shared encoder** — every
  new FLV connection forces an IDR into every open FLV and restarts the GOP;
  concurrent logins coexist and **logout is global** (it invalidates every
  token; open FLVs continue). It counts logout requests so tests can assert
  there are none. The ES3's SPS/PPS bytes (`sps_hex`, `pps_hex`) are L0
  rewriter goldens, not kvm-sim streams: they do not match any fixture's
  slices.
- Review hardenings (rev 6.1): a full-but-connected viewer is disconnected,
  not left to silently drop frames forever, on its next control item (a
  fault or a source switch); an evicted-but-stalled viewer's FLV write races
  eviction so the server-side connection closes promptly instead of leaking,
  bounded by a 50 ms shutdown timeout; the NO SIGNAL card alternates
  `idr_pic_id` between consecutive IDRs, as a real encoder would; and
  `Policy::refuse_concurrent_flv` is a count, so a make-before-break
  reconnect after the refused opens is itself servable (§11.3). Every
  refused `av.flv` carries `{"result":403}` only on an actual HTTP 403 — a
  5xx or other refusal has no body — so §6.9's auth-vs-transient
  classification cannot be confused.
- **Pacing and timestamps** (rev 6.1, final review). Real-time pacing sends
  one frame per `1/fps`; manual pacing sends frames only when a test calls
  `advance(n)`, back to back. FLV timestamps are, by default, `frames ×
  1000 / fps` per connection — the ES3's cadence, which tracks the wall
  clock under real-time pacing but not under manual pacing: there a batch
  is stamped 33 ms apart while it arrives at once, so §6.2 marks nearly
  every AU `burst` and the case exercises §6.5/§6.6's burst path, never
  the soft gate. `Timestamps::WallClock` stamps each tag with the time
  since its FLV connection opened instead, so no AU is a burst: a
  manual-paced L2 case of the live path (soft gate, stall, flow causes)
  uses it, and a source-burst case keeps the default or
  `burst_on_connect`.
- `KvmSim::wait_for` runs its predicate with no lock held, so the
  predicate may read the sim (`sim.stats()`), and re-runs it after every
  event and counter change (rev 6.1, final review).
- Fixtures: ≤ 9 small Annex-B streams (≤ 0.5 MB each), generated by
  `scripts/gen-fixtures.sh` with the flake's pinned ffmpeg/x264 and committed:
  - full-range BT.709, baseline and main profile (360p);
  - `repeat-headers=0`; long GOP; multi-slice with `slice-max-size=250`
    (exercises 1-byte length prefixes, stays ≤ 128 NALs per AU);
  - a limited-range encode plus a twin made with
    `-bsf:v h264_metadata=video_full_range_flag=1` (identical slices, colour A/B);
  - a POC-type-0 variant without `bitstream_restriction`, produced by a
    deterministic transform of a POC-2 stream (SPS `pic_order_cnt_type = 0`,
    `log2_max_pic_order_cnt_lsb` set, restriction removed,
    `pic_order_cnt_lsb = 2 × frame_num` inserted in each slice header with
    re-escaping), verified by `trace_headers` and a decoded-frame md5 equal to
    the source. **Moved to Plan B** (a Plan A deviation): the transform needs
    the same bit-level SPS re-serialisation as the rewriter (§6.8), so Plan B
    builds both together. Built as `360p30_es3like_poc0.h264` (rev 6.1):
    Baseline, keyint 60, ref 1, limited-range BT.709 pixels as the ES3's
    measure, under the ES3's mislabels (level 2.1 for 640×360, VUI full
    range 5/6/5, constraint flags 0), and a decode md5 equal to its x264
    source's — kvm-sim's ES3 profile streams it;
  - a second-resolution stream (480p) for resize cases.

  Plus one small ffmpeg-muxed `.flv` (`-c copy -f flv`) as an independent demux
  oracle, and the 1920×1080 connecting slate. Plan A built all of these but
  the POC-type-0 variant. `gen-fixtures.sh large` also generates gitignored
  1080p30 (full range, limited range and its full-range-flag twin) and 720p30
  streams for the spikes and benches.
- Flags pinned: `-bf 0 -threads 1 -x264-params
  sliced-threads=0:keyint=N:min-keyint=N:scenecut=0:aud=1`; each frame carries a
  16-bit barcode.
- Each fixture has a committed manifest (sha256 plus a `trace_headers`
  summary: profile, POC type, range, `bitstream_restriction`, slices per AU,
  keyint); a test checks it so regeneration drift is caught.
- **Real captures from the KVM are never committed** — they show the work Mac's
  screen. `captures/` is gitignored, 0700, and wiped after each census session.

### 11.6 Hardware and manual tiers

- Before isolation, L4 runs from the dev host. After isolation, L4 is limited
  to `kvm-probe` checks, run either as a one-shot Kubernetes Job carrying the
  bridge's network identity with the bridge scaled to 0, or on the dedicated
  host with the bridge service stopped (§9.4). L5 "direct" becomes a
  `kubectl port-forward` or an SSH local forward to the bridge.
- Plan C's L4 also carries what Leg A handed on (§12, §15): the Mac's
  behaviour when the websocket dies with a key held, side request → main-FLV
  IDR latency over 20 trials (one-token concurrency seen once in Leg A), how a preset
  change is signalled, how long an abandoned token stays valid, and the KVM's
  HID report rate.
- L5 checklist (pass/fail, recorded): key matrix; Mac remap profile; paste
  (including newline handling); reconnect and a takeover of a stale session;
  resize; display sleep/wake; each fatal cause's dialog (no auto-reconnect);
  **washed-out blacks?** (the §6.8 known limitation); **does the last
  keystroke appear without further input?**; picture within N (§10.3);
  glass-to-glass bounds (§10.3). The owner acceptance checklist (§12) asks
  the Milestone 0 questions only Windows App can answer; L5 repeats its items
  against the finished bridge.

## 12. Milestones and planning units

**Milestone 0 — census and spikes (go/no-go for passthrough).** It includes
the unhardened subset of `kvm-proto` it needs (FLV tag reader, AVCC→NAL split,
NAL header, SPS/slice inspection via h264-reader, login parsing),
`gen-fixtures.sh`, `kvm-probe`, and the four IronRDP patches on the owner's
fork (§4.2; the upstream PR waits for the owner).
Milestone 1 hardens these parsers rather than writing them.

**Status (rev 6).** **The census is done** (2026-10-06; results in
`docs/census.md`) and the verdict is **go for passthrough** (Milestone 0
verdict, below). Leg A ran against the ES3 in two sessions. **Legs B and C
ran with FreeRDP 3.31.1 standing in for Windows App**, which could not
easily be tested yet: stock IronRDP HEAD `38b074e` replaying fixtures
(gitignored, generated by `gen-fixtures.sh large`), direct (Leg B) and
through rdpgw `16cdaaf` (Leg C). Every
Windows App run step below became a FreeRDP run; what only Windows App can
answer is the owner acceptance checklist (below). Recorded deviations from
the lists below:

- Leg A: the pin is recorded by the `kvm-probe fingerprint` subcommand, not
  `--print-fingerprint`; what the Mac sees when the websocket dies with a key
  held moved to Plan C's L4 (it needs HID input, which the probe never
  sends); "every open TCP port" became the KVM's documented service ports
  (so §9.4 adds a full scan); "HID round trip" became control-websocket open
  latency (`kvm-probe ws-open`); only the 1920×1080 / 30 fps preset was
  measured — auto and 60 fps deliberately not, since the preset is pinned
  (§6.1).
- Leg B: it also replayed an ES3-shaped local x264 stream (Baseline,
  1080p30, `level_idc` 31, VUI full range and BT.601, and the same at level
  40), generated into `captures/` and not committed. The barcode stranding
  test and the ES3-shaped decode both ran on x264 encodes (POC type 2,
  `bitstream_restriction` present), not a POC-type-0 stream like the real
  ES3 — a stable picture while stranded on these streams is not proof that
  the presentation-hold gate a POC-0, no-restriction stream could fail
  would also pass; that check moves to Plan C's L2 with Plan B's
  ES3-shaped POC-type-0 fixture (Plan B Task 6.1, §11.5). The POC-0
  presentation-hold experiment itself was replaced by always adding
  `bitstream_restriction` (§6.8). The first-frame ack p95 gate was measured
  over 10 fresh connections, not the ≥ 20 the brief and checklist ask for;
  the recorded p95 is the maximum of 10, not a true 95th percentile. The
  colour A/B result is recorded as an observation, not scored as a
  pass/fail gate — the verdict table marks it "Recorded, not a gate" (rev 5
  §6.8 had already planned to ship with documented contrast loss). Only the
  `/gfx:AVC420` two-set capability pair's bytes are recorded in
  `census.md`; the 11-set ladder (no `/gfx`, Leg C) is named but not
  committed with its bytes as a separate fixture file (Plan C captures them
  from the flake's FreeRDP, §11.2). Windows App's capability and key-matrix
  fixtures wait for the acceptance run.
- Leg C: everything ran on loopback, so the stand-in proxy's source address
  (127.0.0.2) played the trusted proxy and 127.0.0.1 "another LAN host";
  every certificate was a throwaway self-signed one (`/cert:ignore`).
- The IronRDP patches are written on the owner's fork, branch
  `kvm-rdp-egfx-patches`; the upstream PR is
  deferred until the owner says so, and Plan C git-pins the fork (§4.2).
  Renamed `kvm-rdp-egfx-patches-v2` in Plan B, after a rebase onto upstream
  `2c08bda7` dropped patch 3 (rev 6.1, §4.2).

Left open: the firmware version (no `Server` header; it is read from the
UI's about page), and resolution-change signalling rests on one tentative
observation (§6.4).

The legs as planned (results in `census.md`; verdict and acceptance
checklist at the end of this section):

- **Leg A — census** (`kvm-probe`):
  - Logs in, saves raw FLV, and writes one JSONL line per tag: receive time,
    tag type, timestamp, CompositionTime, frame type, codec, packet type, NAL
    types, `nal_ref_idc`, slice type, size.
  - Measures: codec; profile/level; POC type; VUI; `bitstream_restriction`;
    scaling matrices; HRD; `num_ref_frames`; GOP length; cadence on a static
    screen vs typing; whether tag = AU; FLV-reconnect→first-IDR over 20 trials;
    **burst length in frames** on connect (a GOP-caching source); whether a
    second connection triggers an IDR; the `Server` header; how the ES3
    signals a resolution change (new sequence header or in-band SPS); every
    open TCP port; TLS version, cipher and key per TLS port, and whether rustls
    negotiates; `http` vs `https` request→first-IDR, inter-tag jitter and HID
    round trip (20 trials each); what the Mac sees when the websocket TCP
    connection is killed with a key held.
  - **Sample range**: a full-screen black, white and grey ramp (including codes
    0–15 and 236–255) shown on the Mac; Y min/max read from the decoder's
    native Y plane (`ffmpeg -f rawvideo` in the decoder's own pix_fmt, no
    `-vf`/scale; the run fails if ffmpeg logs an auto-inserted scaler) — never
    from RGB.
  - Repeated at the presets we would ship (1920×1080 vs auto; 30 vs 60 fps).
  - **Sandboxing**: `kvm-probe` writes only under the 0700 `captures/`
    directory and refuses other paths. Flag fields come from `kvm-proto`'s
    Rust parsers. Any `ffmpeg`/`ffprobe` run on a capture happens in a
    disposable sandbox with no network, no home directory, no SSH agent and no
    repo checkouts (e.g. `bwrap --unshare-all --die-with-parent --ro-bind /nix
    /nix --bind $CAPDIR /cap …`). During captures the Mac shows only test
    patterns or the lock screen.
- **Leg B — Windows App spike, direct** (stock IronRDP HEAD, throwaway code,
  replaying fixtures, not all committed — see Status above; run with
  FreeRDP 3.31.1). Logs and commits every capability set and the
  confirmed one (with FreeRDP's), ack latency and every `queue_depth` (does
  Windows App suspend acks; does it re-send a suspend ack after its own
  re-advertise or after a server resize?), whether it negotiates the
  auto-detect message channel and answers RTT probes, QoE and re-advertises;
  the key-matrix capture (committed as the remap-table fixture) including
  Windows App's typematic initial delay and repeat interval (≥ 20 samples,
  default macOS settings); and each ErrorInfo's dialog and auto-reconnect
  behaviour.
  **Gates** (pass/fail in `census.md`): NLA completes; the confirmed set has
  AVC420; first-frame ack p95 within 1 s (it sets `first_ack_grace`); picture
  returns **within N (§6.5)**
  after a server-initiated resize and after a re-advertise; colour A/B;
  barcode stranding test.
- **Leg C — gateway**: rdpgw on the LAN (not internet-facing), header mode
  behind a throwaway local proxy — the Dex part belongs to the companion spec
  (run on loopback with FreeRDP 3.31.1, Status above).
  Logs and commits the capability bytes (initial and any re-advertise), every
  `queue_depth`, and whether auto-detect works through the gateway. **Gates**:
  Windows App connects with a gateway-token `.rdp`; NLA with the pre-filled
  username; the CLIPRDR channel opens; the Leg B video gates hold through the
  gateway. If Leg C fails, the VNC fallback (§14) is revisited before
  Milestone 1.
- **Census gates**: max burst length ≤ the resulting hard cap and ≤ the
  KVM→pump channel capacity; N ≤ 3 s for the chosen policy (§6.5; for
  `reconnect`, reconnect→first-IDR p95 ≤ 1.5 s). Both pass on Leg A: burst
  0; p95 300 ms (https), N = 1.8 s.
- **Output**: a committed `census.md` with derived parameters only (no screen
  content); the kvm-sim profile; the capability and key-matrix fixtures; the
  decisions for §3.2's scheme, §6.1's pinned values, §6.5's policy and N,
  `first_ack_grace`, the hard cap's burst term, §6.8's rewrite,
  §6.9's ErrorInfo table and `flv_idle_timeout`, and §7.4's timeout; and a
  spec revision filling every census-dependent value.

Then: **M1** `kvm-proto` hardening, fuzzing, L0. **M2** kvm-sim. **M3** the
bridge core. **M4** clipboard. **M5** interop, CI, image. **M6** perf pass.

**Planning units** (one implementation plan each; no plan after A is written
before `census.md` is committed):

| Plan | Covers |
|---|---|
| A | Milestone 0 (with the `kvm-proto` subset, fixtures, `kvm-probe`, spikes, the IronRDP fork patches) → `census.md` + spec revision |
| B | M1 + M2, including the SPS rewriter — required: level patch, VUI re-serialisation and `bitstream_restriction` (§6.8), with the POC-type-0 fixture (§11.5) — and kvm-sim's ES3 profile. No AU assembler and no GOP cache: Leg A needs neither (§6.2, §6.5) |
| C | M3a: config, logging, admin endpoints, metrics, shutdown, lifecycle, NLA, EGFX pump and state machine, the websocket, the HID writer skeleton and release epoch, L1 and video/lifecycle L2. Requires the four IronRDP patches, git-pinned from the fork branch (§4.2), or their fallbacks |
| D | M3b + M4: keyboard and mouse mapping, stuck-key timers and the released-by-bridge rule, the Typist, and their L2 cases |
| E | M5 + M6: L3, CI, image, perf pass |

The companion `luma-homeops` spec is written once Milestone 0 passes. It has
passed (verdict below), so the companion spec can be written now; it takes
§9.4, including Leg C's rdpgw findings, as input.

### Milestone 0 verdict

**Go for passthrough** (2026-10-06). Every census gate passes, so Plans B–E
may be written, and the §14 VNC fallback is not revisited: Leg C did not
fail. The protocol gates were validated with FreeRDP 3.31.1 standing in for
Windows App; what only Windows App can settle is the acceptance checklist
below. If Windows App rejects something FreeRDP accepted, the bridge adapts
— or, if it cannot, the §14 fallback is reconsidered then.

| Gate | Result | `census.md` |
|---|---|---|
| AVC420 in the confirmed set | **Pass**: `V8_1` with `/gfx:AVC420`, `V10_7` with FreeRDP's full 11-set ladder (`confirmed_has_avc=true`) | Leg B, Leg C |
| NLA completes | **Pass**: direct with an ECDSA certificate; through rdpgw with the pre-filled username `kvm` | Leg B, Leg C |
| First-frame ack p95 ≤ 1 s | **Pass**: 97 ms direct, 95 ms through rdpgw (10 fresh connections each) | Leg B, Leg C |
| Picture within N after a server resize | **Pass**: 34 ms direct, 37 ms through rdpgw, on the real resize path (§6.4) | Leg B, Leg C |
| Picture within N after a re-advertise | **N/A**: FreeRDP never re-advertised — acceptance item 8 | Leg B, Leg C |
| Colour A/B | **Recorded, not a gate**: FreeRDP ignores the VUI; mild wash-out on limited-range pixels (§6.8 known limitation) — acceptance item 1 | Leg B |
| Barcode stranding | **Pass, non-diagnostic for POC-0**: a stable picture while stranded (no blank, no partial frame), not confirmed as the last frame shipped; run on x264 streams (POC type 2, `bitstream_restriction` present), which cannot fail the presentation-hold gate a real POC-0, no-restriction stream could — that check moves to Plan C's L2 with Plan B's ES3-shaped fixture (Task 6.1) | Leg B |
| N ≤ 3 s for the chosen policy | **Pass**: FLV open → first IDR p95 300 ms over https; N = 1.8 s for `side` (§6.5) | Leg A, Census gates |
| Max burst ≤ hard cap and ≤ channel capacity | **Pass**: burst on connect 0 frames; hard cap 60 frames (§6.6) | Leg A, Census gates |
| Leg C: the gateway-token `.rdp` connects | **Pass** over the websocket transport; legacy HTTP and RPC fail at `16cdaaf` (§9.4) — acceptance item 2 | Leg C |
| Leg C: NLA with the pre-filled username | **Pass** (`Client.Defaults` + `Client.NoUsername`, §9.4) | Leg C |
| Leg C: the CLIPRDR channel opens | **Pass with `Caps.EnableClipboard: true`**; rdpgw's default disables it (§8) | Leg C |
| Leg C: the Leg B video gates hold through the gateway | **Pass**: identical capability bytes, AVC420, ack p95 95 ms, resize 37 ms; nothing measurable added on loopback | Leg C |

### Owner acceptance checklist (Windows App)

Every Milestone 0 item that only Windows App can answer, run by the owner
with Windows App on macOS, direct and through rdpgw — against the
**finished bridge** (Plans C–E), with the real KVM, or `kvm-sim` for a dry
run. The Leg B/C spikes (`spikes/legb-winapp`, `spikes/legc-rdpgw`) are
throwaway and are not re-run for this; they stay only as historical
evidence (§12, Status). Each result goes into `census.md`, and the values
marked *acceptance* in §4.4 are retuned from it. In priority order:

1. **VUI and colour.** Does Windows App honour the VUI? Replay
   `fixtures/large/1080p30_main_limited.h264` and its `…_flagfull` twin
   (identical slices; only the range flag differs) and compare black
   levels. Honoured: rewrite (b) fixes colour on Windows App. Not honoured:
   the §6.8 known limitation stands, with its options.
2. **Gateway transport through rdpgw.** Windows App must use the websocket
   transport: `rdpgw_websocket_connections` 1 while connected, and no
   `Opening RDGOUT` in rdpgw's log. If it falls back to the legacy HTTP
   transport, rdpgw `16cdaaf` refuses it (#185): patch rdpgw or change the
   pin before deploying. Also: does it accept the `gatewayaccesstoken` `.rdp`
   with a self-signed LAN certificate, and does it obey rdpgw's
   `HTTP_TUNNEL_REDIR_DISABLE_*` flags (§8)?
3. **Baseline and level decode.** Does Windows App decode the ES3-shaped
   stream (Baseline, `constraint_set1_flag` 0) as labelled (level 3.1), and
   with the rewrite (level 40, VUI corrected, `bitstream_restriction`
   added)? Does the last frame appear without further input (barcode
   stranding)? If only the rewritten stream decodes, the rewrite is
   confirmed; if neither does, the rewrite also sets `constraint_set1_flag`
   (§15).
4. **Key matrix and typematic.** Every physical key and chord → scancode,
   extended flag and Windows App's Cmd rewrite; ≥ 20 typematic samples at
   default macOS settings. Sets `input.key_repeat_timeout` (max initial delay
   + 2 × repeat interval + 250 ms, floor 1 s, §7.4) and decides
   `input.mac_remap` (on only if the Cmd rewrite can be told apart from a
   real Ctrl+key, §7.1); committed as the remap-table fixture.
5. **ErrorInfo dialogs and auto-reconnect** for 0x1, 0x5, 0x7 and 0x9 (no
   auto-reconnect loop), and whether `0x19` SERVER_SHUTDOWN suits `shutdown`
   better (§6.9).
6. **First-frame ack p95** over ≥ 20 reconnects. Must be ≤ 1 s; sets
   `video.first_ack_grace` = p95 + `soft_gate` (§6.6).
7. **Ack suspension.** Does Windows App suspend acks (`queue_depth`
   0xFFFFFFFF), and does it re-send a suspend ack after its own re-advertise
   and after a server resize (§4.2 patch 1, §6.6)? Also: does it negotiate
   auto-detect and answer RTT probes (the standing-delay gate, §6.6), and
   does it send QoE?
8. **Re-advertise.** Does Windows App re-advertise, and does the picture
   return within N (§6.5) after it? Record every capability set it
   advertises, direct and through rdpgw, as the L1/L2 fixture (§11.2,
   §11.3).
9. **NLA against the shipped certificate.** §9.1 ships an RSA certificate
   for NLA; the Leg B/C spikes used rcgen ECDSA instead (FreeRDP completed
   NLA against it, `census.md` Leg B). Confirm Windows App completes NLA
   against RSA, and record which username/domain form it sends — `kvm`,
   `DOMAIN\kvm` or `.\kvm` — direct and through rdpgw (FreeRDP sent
   `ROWLETT\kvm` through the gateway, `kvm` direct; §9.1's compare is built
   on that). The result decides whether §9.1's RSA requirement stands, or
   whether ECDSA is enough.
10. **Picture return after a server-initiated resize, on Windows App.**
    Time from `DisplayUpdate::Resize` to the first ack of the new-size IDR,
    on the real resize path (§6.4) — the only one used, since the
    channel-only swap blinks on Windows App and is broken outright on
    FreeRDP. Leg B/C measured this on FreeRDP (34 ms direct, 37 ms through
    rdpgw); Windows App's own deactivation/reactivation handling on this
    path is untested. **Gate N ≤ 3 s** (§6.5).

## 13. Development resource budget

The host is shared and loaded (16 cores, ~12 GiB free RAM, 143 GB free disk at
83% use). The rules are mechanical, not advisory:

- `.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"`
  (CI overrides with `CARGO_BUILD_JOBS`).
- The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20
  -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`, falling back to `nice`
  without user systemd.
- One shared `CARGO_TARGET_DIR` across any worktrees, never one per worktree.
- Committed rust-analyzer settings: `check.extraArgs = ["--jobs=2"]` and the
  same target dir.
- Profiles: `[profile.dev] debug = "line-tables-only"`, dependencies
  `debug = false`; `[profile.release] lto = "thin", codegen-units = 16,
  debug = "line-tables-only", panic = "abort"`; `[profile.bench]` inherits
  release; no fat-LTO profile. One integration-test binary
  (`autotests = false`); `CARGO_INCREMENTAL=0` in CI.
- ffmpeg runs under `nice -n 19` with `-threads 4`.
- Budget: ~1.5 GB of target for debug + tests; ~3–4 GB with release and clippy.
- Fuzzing and the 1-hour soak run in CI only; bench streams live in `target/`;
  census captures (15–60 MB each) are wiped after each session.

## 14. Rejected alternatives

| Alternative | Why not |
|---|---|
| xrdp or Weston session showing a player or browser | Decodes and re-encodes every frame: ~200–350 ms and 2–4 cores at 1080p30 |
| VNC bridge (neatvnc) through a Pomerium tunnel | Viable; was the fallback had Milestone 0 Leg C failed. Leg C passed (§12), so it is reconsidered only if Windows App fails acceptance in a way the bridge cannot adapt to. RDP preferred for the App Store client and plain HTTPS through the gateway |
| Tailscale on the work laptop | Unofficial without admin rights; most likely to trip endpoint security |
| An RDP server (macrdp) on the Mac itself | Installing a remote-access server on the managed Mac is what IT disabled Screen Sharing to prevent |
| crates.io IronRDP 0.13 | §4.2 |
| Re-encode fallback in v1 | No clean decline path; a C decoder on hostile input; breaks the CPU target. Nor is it worth it for colour: the ES3's limited range costs a mild wash-out on fixed-conversion clients (§6.8) |
| Bridge-side GOP cache in v1 | Interacts with every gate and cap, and Leg A makes it unnecessary: any new FLV connection forces an IDR from the ES3's shared encoder (p95 300 ms) and nothing is replayed on connect (§6.5) |
| Frame-count soft gate from measured fps | Stalls on idle → motion transitions; the oldest-unacked-age gate does not depend on frame rate |
| RTT auto-detect as the only suspension bound | It is timestamped when written, so it cannot see the server-side queue; kept only as the downstream standing-delay signal |
| Go or TypeScript RDP server | None exists server-side (`grdp`, `gopher-rdp` are client-only; `node-rdpjs` abandoned) |

## 15. Open questions

Settled by Leg A (rev 5.1, `census.md`): the KVM transport scheme (`https`,
one pin for all ports); session semantics (logout is global, so the bridge
never logs out); the stream's parameters and the 1080p30 preset pin; tag =
AU; burst on connect (0); static-screen cadence (no skipped frames); the IDR
policy (`side`, fallback `reconnect`) and N (1.8 s); the pixels' range and
matrix (limited BT.709) and the VUI's mislabel; the level mislabel.

Settled by Legs B and C (rev 6, `census.md`, with FreeRDP 3.31.1 standing
in for Windows App): stock IronRDP HEAD completes NLA (an ECDSA certificate
is enough for FreeRDP) and confirms AVC420, directly and through rdpgw, with
identical capability bytes; first-frame ack p95 97 ms (95 ms through rdpgw),
so `first_ack_grace` is 1.6 s until Windows App is measured; the real resize
path is the only resize path (§6.4); FreeRDP neither suspends acks nor
re-advertises, and answers auto-detect; the stranding test passes;
`flv_idle_timeout` is 10 s; the `"restriction"` rewrite is always applied
(§6.8); ErrorInfo 0x7 ends the session without auto-reconnect; rdpgw
`16cdaaf` works in token mode over websocket only, needs
`Caps.EnableClipboard`, `Client.Defaults` + `Client.NoUsername`, the
`RDPGWSESSION` cookie stripped at the edge and tokens pinned to the client
(§9.4).

**Known limitation** (not open; options in §6.8): FreeRDP applies
MS-RDPEGFX's fixed full-range AVC420 conversion and ignores the VUI, so the
ES3's limited-range pixels show mildly washed out (black 16, white 235).
The VUI rewrite cannot help such a client; a KVM-side full-range setting
could; re-encoding is rejected (§14).

**Open for the owner's Windows App acceptance run** (§12, in priority
order): whether Windows App honours the VUI; whether it uses rdpgw's
websocket transport (the biggest open risk: legacy HTTP fails at
`16cdaaf`); whether it decodes the ES3's Baseline stream with
`constraint_set1_flag` 0 as labelled (level 3.1) and with the rewrite — if
neither, the rewrite also sets `constraint_set1_flag` (Leg A saw one slice
group and no ASO); the key matrix and typematic (`key_repeat_timeout`,
`mac_remap`); the ErrorInfo dialogs and auto-reconnect (and `0x19` for
`shutdown`); its first-frame ack p95 (`first_ack_grace`); its ack
suspension, auto-detect and QoE; its re-advertise behaviour and capability
ladder.

Open for Plan C's L4 (§11.6): what the Mac sees when the websocket dies with
a key held (moved from Leg A); side request → main-FLV IDR latency over 20
trials (Leg A saw it once, on one token: the ES3 serves two concurrent FLVs
on the same token); how a preset change is
signalled (Leg A: n = 1, tentative); how long an abandoned token stays valid
and whether the ES3 caps concurrent sessions (the bridge never logs out, so
every RDP connection leaves one token to lapse); the KVM's HID report rate
before `paste.pace` is fixed (§8). Still to be recorded in `census.md`: the
firmware version (from the UI's about page).

Watched: the IronRDP fork branch `kvm-rdp-egfx-patches-v2` and, once the owner
opens it, its upstream PR (§4.2); IronRDP API churn and an upstream SVC/DVC
reassembly cap (monthly pin review); rdpgw's legacy-transport refusal in
token mode (#185) and any pin past `16cdaaf` (§9.4); FLV source latency —
*open*, not measured by the census: if SRS buffers ~350 ms, the WebRTC
source on :1988 becomes a future option (§3.1, §10.3).
