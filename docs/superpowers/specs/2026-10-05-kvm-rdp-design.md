# kvm-rdp — design

| | |
|---|---|
| Status | Draft rev 5, for review. Design agreed in conversation 2026-10-05; revised after a source-level research pass (IronRDP `38b074e`, macrdp), a five-lens adversarial review, and three coverage/consistency checks |
| Repo | `github.com/ChristopherJMiller/kvm-rdp` (public, MIT OR Apache-2.0) |
| First target | Angeet/Yeeso ES3 "ONE KVM" wired to a Mac Studio |
| Client | Microsoft Windows App on macOS, through an rdpgw RD Gateway on 443 |
| Companion spec | Deployment, gateway, edge gating and KVM isolation live in `luma-homeops` (separate spec, written after Milestone 0). §9.4 lists what this spec requires of it |

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
- A bridge-side GOP cache. Getting a keyframe is `reconnect` or `wait` (§6.5);
  a cache is designed only if the census shows neither meets §10.3.
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
  codec, GOP, profile, range or bitrate control.
- **The development host is shared and loaded** (§13).

## 3. The KVM interface

Reverse-engineered from the ES3 web UI (`kvm.js`, `index.js`, `common.js`).
Items marked *(census)* are unverified until Milestone 0.

### 3.1 Endpoints

| Function | How |
|---|---|
| Login | `POST /cgi-bin/login.lua`, body `{"pass","timezone","time"}` → token `0.<digits>` |
| Logout | `GET /cgi-bin/login.lua?logout` |
| Video | `GET /av.flv?token=…` on the video port. HTTP-FLV, H.264 *(census)*. The vendor calls FLV "high compatibility" and WebRTC (SRS, :1988) "low latency", so FLV source latency is *(census)* |
| Input | WebSocket `/websocket` on the control port |
| Mode | `88 88 01 <0x30+type>` sets HID type; type 0 = absolute mouse. `88 88 03 …` is UART text (unused) |

### 3.2 Transport

- **Scheme `https` by default** for login, video and websocket, on ports 443 /
  8881 / 8889 (config, not read from `mapping.lua`). The KVM's certificate is
  self-signed, so it is **pinned by SHA-256 of its SPKI** from config;
  `kvm-probe --print-fingerprint` records it once. A mismatch refuses the
  connection. There is no accept-any verifier.
- Scheme `http` (80 / 8880 / 8888) is a config option, allowed only if the
  census shows rustls cannot negotiate with the KVM or TLS costs measurable
  latency, and only on the isolated segment. TLS here buys confidentiality
  against the LAN, not trust in the device.
- After login the token is sent as `Cookie: token=<token>` on **every** request
  — FLV, websocket upgrade, logout — and as the `token` query parameter on the
  FLV URL.
- Clients: hyper and tokio-tungstenite over tokio-rustls (aws-lc provider,
  default features off). `TCP_NODELAY` on every KVM socket.
- Websocket limits: max message and frame 4 KiB, small write buffer; inbound
  data messages are read and discarded; an oversize message closes the socket
  without buffering it.
- Teardown calls logout, best effort, bounded by `kvm.logout_timeout`.

### 3.3 HID frames

Byte-exact with `kvm.js`:

| Frame | Bytes |
|---|---|
| Keyboard | `AA AA 08 00 mod 00 00 k1 k2 k3 k4 k5` — 12 bytes; USB HID modifier byte, five key slots |
| Absolute mouse | `AA AA 05 51 btn xLo xHi yLo yHi` — x, y in 0..=32767 |
| Wheel | `AA AA 04 20 btn 00 00 w` — `w` = `01` up / `FF` down; `btn` = current button mask |

Session-start sequence on every websocket (re)open: `88 88 01 30` (absolute
mode), an all-zero keyboard report, a zero-button absolute report.

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
| `kvm-sim` | `kvm-proto`, tokio, hyper, tokio-tungstenite, rustls (aws-lc) | Fake ES3 for tests and benches (§11.5), served over TLS |
| `kvm-rdp` | `kvm-proto`, IronRDP, tokio, rustls (aws-lc) | The bridge binary |
| `kvm-bench` | `kvm-sim`, IronRDP client crates | Perf harness (§10.2) |
| `fuzz/` | `kvm-proto` only | Separate cargo workspace, nightly, CI-only |

Every hostile-input parser lives in `kvm-proto`, so fuzzing and most tests
never compile IronRDP or aws-lc. The container image ships `kvm-rdp` and
`kvm-probe`.

### 4.2 Dependencies

- **IronRDP is git-pinned**: one rev, at or after `38b074e` (2026-10-01), for
  every `ironrdp-*` crate used (including `ironrdp-pdu`, for ErrorInfo codes),
  as direct git dependencies in `[workspace.dependencies]` — no
  `[patch.crates-io]`. crates.io `ironrdp-server 0.13.0` / `ironrdp-egfx 0.3.0`
  lack `ConnectionPolicy::Preempt`, `on_connection_info`, the full EGFX
  capability ladder, re-advertise recovery, the ack-suspend fix and the pre-TLS
  DoS fix (#1515), and their `Avc420Region` bounds are inclusive where HEAD's
  are exclusive.
- **Upstream prerequisites for Plan C.** Plan A opens one IronRDP PR (each
  patch is roughly 30–50 lines plus a test):
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
  2. **A per-generation outbound counter.** `EgfxServerMessage::SendMessages`
     gains an optional `(Arc<AtomicU64>, weight: u64)`; once every byte of that
     event has been written (TCP `write_all` + flush returned, or each UDP send
     returned), IronRDP adds `weight` to the counter. The bridge sets `weight`
     = Σ `DvcMessage::size()` of the drained batch and owns one counter per
     generation (§6.6). The enum becomes `#[non_exhaustive]`.
  3. **No stale events across connections**: `discard_stale_session_events()`
     runs before serving every connection, on the Fresh path as well as after
     preemption.
  4. **A hard-close path**: a per-connection abort handle that drops the
     connection future (so `on_disconnected` runs) even while the writer is
     blocked on a peer that stopped reading; and a bounded write of the
     SetErrorInfo PDU on bridge-initiated disconnects.

  If the PR is not merged when Plan C starts, the pin moves to a fork branch
  carrying only these patches — a documented, temporary exception, reverted
  when upstream merges. (Patch 1 alone can be replaced by its fallback.)
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
  `ReconnectFlv`, `CancelReconnect`, `SetMaxFramesInFlight`, `InjectSuspendAck`,
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
  (release-all flushed, websocket and FLV closed, logout attempted) before the
  next `Start` begins. Every `ServerEvent` send, including `Disconnect`, is only
  made for the current generation. Events already queued in IronRDP when a
  connection ends are dropped by IronRDP (§4.2 patch 3), not by the bridge.
- **KVM → pump: one ordered stream.** Control messages (`SessionStart/Stop`,
  `SpsChanged`, `FlvOpened`, `UpstreamFatal`) and AUs share one channel, so
  they never reorder. AUs are sent with `try_send` and dropped when the channel
  is full (a flow cause, §6.5; metric); control messages are sent with
  `send().await` and are never dropped (the KVM actor briefly pauses FLV
  reading; the pump drains continuously). SPS/PPS are classified on the KVM
  side and travel as `SpsChanged`, so a dropped AU can never lose a parameter
  set; the pump's SPS/PPS cache updates only from this stream. Capacity:
  ≥ the hard cap (§6.6). The FLV is otherwise drained at line rate; the KVM
  never sees back-pressure.
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

Defaults (every duration is configurable; values marked *census* are set in
`census.md`):

| Key | Default | Notes |
|---|---|---|
| `rdp.listen` | `0.0.0.0:3389` | |
| `rdp.username` | `kvm` | Exact, case-sensitive match (§9.1) |
| `admin.listen` | `0.0.0.0:9464` | §4.5 |
| `kvm.host`, `kvm.spki_sha256` | required | |
| `kvm.scheme` / ports | `https` / 443, 8881, 8889 | *census* (§3.2) |
| `kvm.connect_timeout` / `login_timeout` / `logout_timeout` | 3 s / 5 s / 1 s | |
| `kvm.backoff` | 250 ms ×2 → 8 s, ±20% jitter | Transient reconnects (§6.9). One backoff state per connection (FLV, websocket): the FLV's resets when a new FLV delivers its first tag, the websocket's once a reopened websocket has sent the session-start sequence |
| `kvm.upstream_deadline` | 20 s | §6.9 |
| `video.default_size` | 1920×1080 | `size()` before any SPS |
| `video.max_fps` | 60 | Sizes the hard cap |
| `video.soft_gate` | 500 ms | Age of the oldest unacked live frame (§6.6) |
| `video.hard_cap` | 2 s | hard = ceil(2 s × `max_fps`) + census max burst (§6.6) |
| `video.backlog_limit` | 4 MiB | §6.6 |
| `video.standing_delay_limit` | 500 ms | Used only when auto-detect is negotiated (§6.6) |
| `video.rtt_probe_interval` | 250 ms | §6.6 |
| `video.first_ack_grace` | *census*: first-frame ack p95 + `soft_gate`, default 1.5 s | §6.6 |
| `video.stall_timeout` | 10 s | §6.6 |
| `video.idr_policy` | *census* | `reconnect` or `wait` (§6.5) |
| `video.idr_wait_max` | 3 s | Cumulative open-gate time (§6.5) |
| `video.flv_reconnect_interval_setup` | 1 s | §6.5 |
| `video.flv_reconnect_interval_flow` | 10 s | §6.5 |
| `video.flv_idle_timeout` | *census*, default 10 s | §6.9 |
| `video.burst_chunk` | 8 frames | §6.5 |
| `video.sps_rewrite` | *census*, default off | §6.8 |
| `video.avc420_timeout` | 10 s from `on_connection_info` | §6.7 |
| `video.suppress_debounce` | 1 s | §6.6 |
| `video.disconnect_watchdog` | 5 s | §6.9 |
| `video.region_qp` | 22 | Constant; client hint only |
| `input.queue` | 256 reports | §7.3 |
| `input.hid_write_timeout` | 1 s | |
| `input.key_repeat_timeout` | *census*: measured max initial delay + 2 × repeat interval + 250 ms, floor 1 s; 10 s if repeats aren't confirmed | §7.4 |
| `input.modifier_idle_timeout` | 30 s | §7.4 |
| `input.mac_remap` | off | §7.1 |
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
  `Stop{gen}` (§4.3).
- `size()` returns the last-known KVM resolution, held in memory per process;
  a restart falls back to `video.default_size`. If the first SPS disagrees, the
  resolution change runs after the first Setup (§6.4).
- Preempt's evicted-peer cooldown is keyed by source IP. Behind rdpgw every
  client shares one IP, so a retake within 5–30 s of a takeover is refused.
  Documented, not worked around.

### 5.2 Shutdown

On SIGTERM or SIGINT: stop accepting; release-all and wait for the websocket
flush (≤ 500 ms); disconnect the client with cause `shutdown`; close FLV and
websocket; logout (≤ `kvm.logout_timeout`); exit within 5 s. Release builds use
`panic = "abort"`. A crash cannot release keys: what the Mac does when the
websocket TCP connection dies with a key held is a census item (§12), and the
answer goes in §9.3.

## 6. Video: EGFX AVC420 passthrough

### 6.1 Admission

Checked on the KVM side (`kvm-proto`) on the first sequence header and on every
SPS/PPS after it:

- FLV `CodecID == 7` (AVC). `12` or Enhanced-RTMP `hvc1` (HEVC) is refused:
  EGFX has no HEVC codec.
- `CompositionTime == 0` on every tag (no B-frames).
- **SPS limits**: `profile_idc ∈ {66, 77, 100}`; chroma 4:2:0, 8-bit;
  `frame_mbs_only_flag == 1`; level ≤ 5.1; width ≤ 4096 and height ≤ 2304,
  both even; `num_ref_frames` ≤ the census value (≤ 16);
  `seq_scaling_matrix_present_flag == 0` and VUI
  `nal/vcl_hrd_parameters_present_flag == 0`, unless `census.md` records the
  KVM using them, in which case the exact values are pinned.
- **PPS**: `num_slice_groups_minus1 == 0`; `num_ref_idx` defaults bounded;
  `pic_scaling_matrix_present_flag == 0` unless the census pins it.
- **Slice headers**: `slice_type ∈ {0, 2, 5, 7}` (P and I only); `pps_id` refers
  to a validated PPS; `first_mb_in_slice < PicSizeInMbs`; POC strictly
  increasing in decode order within a GOP.

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

### 6.2 FLV demux and NAL sanitiser (`kvm-proto`)

Hand-rolled incremental state machine on `BytesMut`; no AMF0 parsing; no
resync scanning.

- Header `FLV`, version 1, `DataOffset` 9 (≤ 64 tolerated). Tag type 9 parsed;
  8 and 18 skipped. `DataSize` is checked against the limit **before** anything
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
- Limits: tag 4 MiB, 128 NALs per AU, 4 SPS, 16 PPS.
- One FLV tag is assumed to be one access unit *(census)*. If not, an AU
  assembler (FLV timestamp plus `first_mb_in_slice` / AUD) goes in `kvm-proto`.
- **Bursts**: an AU whose FLV timestamp runs more than 100 ms ahead of its
  receive time (measured since the FLV connection's first tag) is marked
  `burst` — a GOP-caching source replaying on connect.
- Parser modules deny `clippy::{indexing_slicing, unwrap_used, expect_used,
  panic, arithmetic_side_effects, as_conversions}`.
- Ownership: the demuxer splits AU payloads out of the FLV buffer as
  refcounted `Bytes` (no copy); the pump converts each AU into one reused
  Annex-B `Vec` immediately before sending.

### 6.3 Output contract

- Annex-B with 4-byte start codes, one access unit per `send_avc420_frame`,
  converted by our code (never IronRDP's `avc_to_annex_b`).
- Each sent AU = [AUD if present] + the cached SPS/PPS (IDR only) + the source
  AU's allowlisted VCL NALs, in order. Only AUs with a VCL NAL are sent.
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
flags drive what it does while waiting (§6.5): `reopen_pending` and the
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
| **NeedIdr** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` is a flow cause | satisfies `reopen_pending`, resets idr-wait | ignore | → Paused | — | gates open: send → Live; closed: drop, flow cause | drop | flow cause | → Closing |
| **Live** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` → NeedIdr (flow cause) | → NeedIdr (await this connection's first IDR) | ignore | → Paused | — | send if gates open, else → NeedIdr (flow cause) | send if gates open, else → NeedIdr (flow cause) | → NeedIdr (flow cause) | → Closing |
| **WaitReactivation** | record (merged) | → Closing(`no_avc420`) | set `pending_size` (latest wins) | update cache | ignore | Setup at the reactivated size; if `pending_size` is set and differs: clear it, start resize again; else if suppressed or `return_to_paused` → Paused; else if `on_ready` was never seen → WaitReady; else → NeedIdr (Setup cause) | ReleaseAll; record | record | drop | drop | — | → Closing |
| **Paused** | Setup; stay Paused | → Closing(`no_avc420`) | start resize with `return_to_paused` | update cache | stay Paused | ignore | — | → NeedIdr (Setup cause) | drop | drop | — | → Closing |
| **Closing** | ignore | ignore | ignore | ignore | ignore | ignore | ignore | ignore | drop | drop | ignore | ignore |

*Start resize*: stop sends (→ `WaitReactivation`); update the size used by
`size()` and `request_initial_size()`; emit `DisplayUpdate::Resize` on the
current updates stream; continue per the `ReactivationComplete` cell. Never a
channel-only surface swap (it blinks on Windows App). AUs arriving during
`WaitReactivation` are dropped.

The stall timer (§6.6) is frozen in `Paused` and `WaitReactivation`.

### 6.5 Getting an IDR

Passthrough can wait for an IDR or provoke one, never make one.

- **Setup cause**: a Setup (connect, re-advertise, resize), leaving Paused.
- **Flow cause**: a gate closes (§6.6), an IDR is dropped because a gate is
  closed, `send_avc420_frame` returns `None`, an AU is dropped on a full
  channel, a burst is truncated at the hard cap, `SpsChanged other`.
- **FLV opened** (`FlvOpened`, any origin): the NeedIdr waits for that
  connection's first IDR; it never issues `ReconnectFlv` by itself.

`video.idr_policy` (from the census):

- `reconnect` — a Setup cause sets `reopen_pending`, which issues
  `ReconnectFlv` (make-before-break if the census shows a second connection
  triggers an IDR), except for the first Setup, whose `OpenFlv` already serves.
  A flow cause starts idr-wait accounting: once the gates have been open for a
  cumulative `idr_wait_max` (flapping does not reset it), it sets
  `reopen_pending`.
- `wait` — every NeedIdr waits for the next periodic IDR; `reopen_pending` is
  never set after the first open. Chosen only if the census shows reconnecting
  is not faster.

**Rate limits and cancellation.** Two clocks, `flv_reconnect_interval_setup`
(Setup-caused reopens) and `flv_reconnect_interval_flow` (idr-wait reopens).
**Any** FLV open (first, transient, commanded) clears `reopen_pending`,
cancels a deferred `ReconnectFlv`, resets idr-wait accounting, and restarts
both clocks. A `ReconnectFlv` that falls inside its clock's window is
**deferred** to the window's end, not dropped — and **cancelled** if, before it
fires, an IDR is handed to IronRDP or the pump leaves NeedIdr (Paused,
`WaitReactivation`, Closing); a later cause requests it again. Websocket-only
failures never touch NeedIdr.

**Source bursts** (§6.2): burst AUs are exempt from the soft gate, count
against the hard cap and backlog gate, and go out in chunks of `burst_chunk`
frames, one `ServerEvent` per chunk, yielding between chunks so input PDUs
interleave. The hard cap includes the census maximum burst length (§6.6), so a
burst within that length is never truncated; a longer one is truncated (a flow
cause). Census gate (§12): max burst ≤ hard cap and ≤ channel capacity.

**Bound.** The picture must return within N of any Setup cause (§10.3). For
`reconnect`, N = `flv_reconnect_interval_setup` + census
FLV-reconnect→first-IDR p95 + 0.5 s (the worst case is a reopen deferred by a
full window); for `wait`, N = census GOP length + 0.5 s. The census gate is
N ≤ 3 s for the chosen policy (for `reconnect` with a 1 s interval: p95 ≤
1.5 s). If neither policy passes, the census spec revision designs a
bridge-side GOP cache before Plan C.

### 6.6 Flow control

IronRDP must never drop a P-frame silently; the bridge gates at GOP
granularity.

- **Hard cap** = ceil(`hard_cap` × `max_fps`) + census max burst →
  IronRDP's `max_frames_in_flight`, set at every Setup. A memory backstop only;
  never `u32::MAX`, never the default 3. Static: it does not follow measured
  fps.
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
  - *standing delay* (only when the client negotiated auto-detect, a census
    item): IronRDP sends RTT probes only on request, so while auto-detect is
    negotiated the pump issues `ProbeRtt` (`ServerEvent::AutoDetectRttRequest`,
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
  A non-suspend ack restores normal gating.
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

| Finding | Effect | Response |
|---|---|---|
| Limited-range or BT.601 samples | MS-RDPEGFX fixes AVC420 to full-range BT.709; conformant clients ignore the VUI, so blacks lift to ~6% grey | Measured on **decoded** samples, not flags. Look for a KVM or EDID fix; otherwise ship passthrough with documented contrast loss. A colour-correct re-encode is a later opt-in mode with its own CPU budget |
| POC type 0 without `bitstream_restriction` | Client decoders may hold frames | `video.sps_rewrite = on` (set statically from `census.md`): `kvm-proto` rewrites every SPS to add `max_num_reorder_frames = 0` and `max_dec_frame_buffering = max(num_ref_frames, 1)`; any parse anomaly passes the SPS through unchanged. Safe because §6.1 already refuses B-slices and non-increasing POC. Measured in Windows App |
| Encoder stops sending on a static screen | Some clients hold the last ~2 frames, so the last keystroke never appears | Tested in Windows App with the barcode fixture before being treated as a re-encode trigger. `flv_idle_timeout` is set above the static-screen cadence |

### 6.9 Upstream failure taxonomy and disconnects

| Class | Events | Response |
|---|---|---|
| Transient (FLV) | connect refused or timeout; FLV EOF; end of sequence; HTTP 5xx; FLV open but silent for `flv_idle_timeout` | Reconnect with `kvm.backoff`, keep the last picture; the new FLV's `FlvOpened` puts the pump in NeedIdr for its first IDR (§6.4) |
| Transient (websocket) | websocket close or oversize message; a write exceeding `hid_write_timeout` | Reconnect with `kvm.backoff`; the session-start sequence; no NeedIdr |
| Auth | login rejected; HTTP 401/403 or `result: 403` on FLV/WS | Re-login once. A second consecutive failure, with no successful re-login in between, is fatal: `kvm_auth_failed` |
| Certificate | SPKI mismatch | Fatal immediately, no login sent: `kvm_cert_mismatch` |
| Stream-incompatible | HEVC; B-frames; outside §6.1 limits; a pinned field changes; a slice/PPS check fails | Fatal immediately: `stream_incompatible` |
| Framing violation | bad header, encrypted tag, `StreamID ≠ 0`, bad `PrevTagSize`, oversize tag, start code in a NAL, NAL limits, NALU before any sequence header | Transient (FLV reconnect, `parse_errors{kind}`); three within 60 s is fatal: `stream_corrupt` |
| Deadline | No successful login within `upstream_deadline` of `on_connection_info`; or no FLV tag within `upstream_deadline` of the first FLV open, or since the FLV connection was lost, despite reconnecting | Fatal: `kvm_unreachable` |

Paused, NeedIdr and `WaitReactivation` never count toward the
deadline; it measures KVM-side evidence only.

**Disconnecting.** Every fatal cause moves the pump to `Closing`: it stops all
EGFX sends, then sends `Disconnect(ErrorInfo)` through
`ErrorInfoDisconnectHandle`, and arms `disconnect_watchdog`. If
`on_disconnected` has not fired when the watchdog expires, the bridge
releases all keys, sends `Stop{gen}` to the KVM side anyway, and aborts the
connection (§4.2 patch 4) — so a client that has stopped reading cannot hold
the session or the KVM login open.

Codes are explicit server-initiated ErrorInfo values (MS-RDPBCGR 2.2.5.1.1),
so the client does not auto-reconnect into a loop; the log line names the
cause. Milestone 0 Leg B verifies Windows App's dialog and reconnect behaviour
for each and revises the table if needed (e.g. `0x19` SERVER_SHUTDOWN may suit
`shutdown` better).

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
  Milestone 0's key-matrix capture shows whether the rewrite can be told apart
  from a real Ctrl+key.
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
report and a zero-button mouse report. Keys and buttons that were held at that
moment are marked *released-by-bridge*: further `Pressed` events for them
(typematic repeats) are ignored until the client sends their `Released`, after
which they behave normally. So a release never turns into a down-up-down
glitch, and a reconnect never re-presses anything. Mouse position is kept.

Triggers:

- `KeyboardEvent::Synchronize`
- `on_connection_info` (a new session never inherits held keys)
- `on_disconnected`, eviction, `Closing` and process shutdown (§5.2, §6.9)
- websocket reconnect
- debounced display suppression (§6.6)
- **timers** (mouse events never reset them):
  - non-modifier keys held and no `Pressed` repeat of **any** held
    non-modifier key for `key_repeat_timeout` (typematic repeats only the most
    recently pressed key);
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
- Deployment must enable the channel (`EnableClipboard` in rdpgw,
  `redirectclipboard:i:1` in the `.rdp`) or CLIPRDR never opens.
- Milestone 4 compares our typing with the KVM's own `hid.lua?type=text`
  endpoint; ours stays the default unless the device's paces better.

## 9. Security

### 9.1 Authentication

1. **rdpgw** (companion spec): `/connect` sits behind the oauth2-proxy admin
   tier (Dex; one allowlisted address); the gateway hands out an `.rdp` with a
   gateway token. Requirements in §9.4.
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
   - The password is stored recoverably (NTLM needs it), ≥ 128 random bits, as
     a SealedSecret.
   - TLS: our own rustls `ServerConfig` (not `TlsIdentityCtx::make_acceptor`,
     which honours `SSLKEYLOGFILE`), with our own RSA certificate for the name
     in the `.rdp` — never the edge wildcard.
   - `on_accept` rate-limits attempts (`security.accept_rate`).

### 9.2 Secrets and logging

KVM password, NLA password, TLS key, the KVM token, keystrokes, HID frames and
pasted text are never logged (§4.5). Secrets come only from files (§4.4).

### 9.3 Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Hostile FLV/H.264 attacks the bridge | Hardened, fuzzed parsers in `kvm-proto` with output invariants; no C decoder in the bridge; size limits checked before buffering | Bugs in `h264-reader` |
| Hostile video attacks the **laptop's decoder** | NAL allowlist; start-code check; SPS, PPS and slice headers limit-checked | **Slice data cannot be sanitised without decoding.** A compromised KVM could target the laptop's hardware decoder. Accepted for v1; the answer is containment |
| Compromised KVM records input | — | Every keystroke and paste through the bridge — including passwords typed into the Mac — is visible to a compromised KVM. Accepted explicitly. Don't paste secrets through the bridge |
| Compromised KVM injects keystrokes on its own | Factory reset (or reflash, if a vendor image exists) before first use and after isolation lands; power the KVM or its USB link off when not in use; alert on the router's NO-WAN drop rule (forward rule 120, `NO-WAN-v4`) and on KVM-originated LAN flows (companion spec) | Isolation limits who can reach the KVM, not what it does |
| Anyone who can reach the KVM types into the Mac (port 8888 is the CVE port) | WAN egress blocked; isolation (§9.4) | Until isolation lands, the LAN, the tailnet, and every galaxy pod and hostNetwork process can reach :8888/:8889 |
| Session hijack | Dex + gateway token + NLA (+ NetworkPolicy/firewall if enforced) | In-cluster attacker: NLA only. An in-cluster caller can occupy Preempt's single 10 s candidate slot, delaying a takeover by 10 s per attempt |
| A client that stops reading pins the session | `Closing` + disconnect watchdog + hard abort (§6.9) | — |
| Bridge crash with a key held | `panic = "abort"`; release on every orderly path | Depends on the KVM's behaviour on websocket loss (census) |
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

  Verified by TCP connects to **every port the census finds open on the KVM**
  (at least :80/:443/:1988/:8880/:8881/:8888/:8889) from a non-bridge pod, a
  node shell and the tailnet — all must fail.
- Remove the KVM's Tailscale `/32` route once the bridge works.
- On Kubernetes: whether the CNI enforces NetworkPolicy; if it does, policies
  admitting rdpgw to 3389, and Prometheus plus the node CIDR (kubelet probes)
  to 9464, only.
- rdpgw:
  - Header trust local to the pod: an oauth2-proxy (admin tier) sidecar with
    rdpgw bound to `127.0.0.1` and `header.trustedproxies = [127.0.0.1/32]` —
    or rdpgw's openid mode against Dex. Never trust a pod-network address.
  - `caps.tokenauth: true`; host selection fixed to the bridge's name and port
    (never `any`); `/remoteDesktopGateway/` is the only path exempt from
    forward-auth, and `/`, `/connect` and `/api/v1/*` are never exposed without
    it. `VerifyClientIp` set for Traefik.
  - `EnableClipboard`; `.rdp` with `redirectclipboard:i:1`, a pre-filled
    username equal to `rdp.username`, and a full-address name that resolves to
    the bridge from the rdpgw pod.
  - Check: a `GET /connect` with a forged auth header from another pod is
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
  ≤ 3 s**, for the census-chosen policy.
- Tune the KVM's presets (pinning 1920×1080 is expected; the Mac may otherwise
  drive 4K at level 5.1). Each result is recorded as pass or fail.

### 10.4 Metrics

FLV bytes and tags; frames by type; frame bytes; inter-arrival; fps; parse
errors by kind; upstream reconnects by reason; frames dropped by reason (soft
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
| L0 unit | `kvm-proto` | Goldens (HID encoders, scancode table, AVCC→Annex-B, SPS fields); SPS rewriter output goldens plus pass-through goldens for (a) `bitstream_restriction` already present, (b) a parse anomaly → SPS byte-identical to input; FLV mux→demux round-trip property tests; parse of a committed ffmpeg-muxed FLV; burst marking; mouse scaling at the edges; **one hostile vector per §6.1/§6.2 rule, each asserting its specific error kind**; SPS-change classification per §6.1's table; a pre-buffer test (`DataSize = 0xFFFFFF` rejected after ≤ 11 bytes, nothing reserved); sans-IO cores with injected clock (release epoch and released-by-bridge rule, both key timers including two keys held with repeats of the second only → no release, backoff, paste pacing and text handling, debounce) |
| L0 fuzz | `fuzz/` | FLV demux, AVCC, sanitiser, SPS/PPS/slice checks, SPS rewriter, login response; a differential mux→demux target. Output invariants in every target: emitted NAL types ∈ {1,5,7,8,9}; no emitted NAL contains `00 00 0[0-2]`; re-splitting the Annex-B yields exactly the emitted NALs; any emitted SPS is byte-identical to the last admitted (after rewrite) SPS and its pinned fields equal the first SPS's. Rewriter: the output re-parses with every field equal to the input except `max_num_reorder_frames`, `max_dec_frame_buffering` and `bitstream_restriction_flag`. 5 s per target per PR, longer nightly. CI-only |
| L1 sans-IO | `kvm-rdp` | `Pump::step` and `GraphicsPipelineServer` ↔ `GraphicsPipelineClient` in memory (cases below). IronRDP goldens: `encode_avc420_bitmap_stream(full_frame(640,360,22))` bytes and the ResetGraphics monitor bytes — required on every pin bump |
| L2 full stack | `kvm-rdp` (one test binary) | Bridge + kvm-sim + in-process IronRDP client over loopback (§11.3) |
| L3 interop | CI, `#[ignore]` test | FreeRDP 3 from the flake (§11.4) |
| L4 hardware | opt-in | `kvm-probe` and `--features hil` tests against the real ES3 (§11.6) |
| L5 manual | checklist | Windows App direct and through rdpgw (§11.6) |

L1 cases:

- **Every cell of the §6.4 state × input table**, one case each.
- Each replayed `CapabilitiesAdvertise` (Windows App direct, through rdpgw, and
  any re-advertise; FreeRDP — Milestone 0 fixtures) yields exactly the
  CapabilitiesConfirm recorded in `census.md`; only AVC420 `WireToSurface1` is
  ever sent. A re-advertise whose confirmed set lacks AVC420 → Closing(`no_avc420`)
  at once.
- After Live, a second CapsAdvertise produces exactly: CapabilitiesConfirm,
  ResetGraphics (w, h, one monitor), CreateSurface, MapSurfaceToOutput,
  StartFrame, WireToSurface1 (IDR with SPS/PPS), EndFrame — no DeleteSurface,
  no P-frame before the IDR.
- `reconnect` policy: connecting costs exactly one FLV open (the first Setup's
  `OpenFlv`; no `ReconnectFlv`); a later Setup → `ReconnectFlv`, first AU sent
  is an IDR; an `FlvOpened` never commands a reconnect; two Setup causes 300 ms
  apart → exactly two `ReconnectFlv`, the second deferred to the window's end;
  a deferred `ReconnectFlv` whose NeedIdr is resolved by an IDR inside the
  window → zero further `ReconnectFlv`; a transient reconnect clears
  `reopen_pending` and restarts both clocks; a flow cause → nothing until a
  live IDR, and `ReconnectFlv` only after cumulative open-gate time reaches
  `idr_wait_max`; an IDR dropped at a closed gate counts as a flow cause.
  `wait` policy: nothing until the next live IDR; no `ReconnectFlv` after the
  first open.
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

Each asserts something exact. The in-process client advertises the Milestone 0
Windows App capability bytes and uses a capture decoder that records bytes and
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
  close → logout (with the token cookie) → login → websocket open →
  session-start sequence, never two concurrent websockets; the evicted client
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
  decoder → `no_avc420` (0x7).
- **Resolution change**, injected both as a new sequence header and as an
  in-band SPS (using the second-resolution fixture): DeactivateAll; ResetGraphics
  and CreateSurface at the new size; first KVM AU after is an IDR with the new
  SPS; no EGFX PDU between DeactivateAll and the reactivated Demand Active;
  login count unchanged; a second resize in the same session works.
- **Faults**, each asserted against its §6.9 class and ErrorInfo: oversize tag,
  bad `PrevTagSize`, encrypted tag, HEVC codec id, nonzero CompositionTime,
  B-slice, start code inside a NAL, NALU before sequence header, end of
  sequence, FLV drop, FLV silent past `flv_idle_timeout` (reconnect, no
  disconnect), token expiry twice in one session with a successful re-login
  between (no disconnect), a second consecutive auth failure (fatal), websocket
  drop (reconnect + session-start, no NeedIdr), a 64 MiB websocket message
  (closed at the 4 KiB limit without buffering, reconnect, RSS bounded), KVM
  unreachable (disconnect at the deadline), wrong KVM certificate (no login
  request; `kvm_cert_mismatch`).
- **Stalled client** (asserted on `/metrics`, not timing): withheld acks →
  after the bridge's first soft-gate drop (`frames_dropped{reason="soft_gate"}`
  > 0) its sent-frame counter does not advance again before Closing,
  `egfx_in_flight` ≤ hard throughout, and the session closes with
  `client_stalled`; a client that **stops reading** → the session still ends
  (Closing + watchdog + abort) and kvm-sim sees the logout; a client that
  suspends acks but keeps reading is never disconnected.
- **Input**: every input event → byte-exact HID frames; a full queue resyncs to
  the correct final state; a blocked websocket write reconnects; with reports
  queued behind a blocked write, a release trigger produces only the zero
  reports and then current state — no queued report is sent after it.
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
  websocket (recording every HID frame), over TLS with a test certificate the
  test config pins.
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
    the source;
  - a second-resolution stream (480p) for resize cases.

  Plus one small ffmpeg-muxed `.flv` (`-c copy -f flv`) as an independent demux
  oracle, and the 1920×1080 connecting slate.
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
- L5 checklist (pass/fail, recorded): key matrix; Mac remap profile; paste
  (including newline handling); reconnect and a takeover of a stale session;
  resize; display sleep/wake; each fatal cause's dialog (no auto-reconnect);
  **washed-out blacks?**; **does the last keystroke appear without further
  input?**; picture within N (§10.3); glass-to-glass bounds (§10.3).

## 12. Milestones and planning units

**Milestone 0 — census and spikes (go/no-go for passthrough).** It includes
the unhardened subset of `kvm-proto` it needs (FLV tag reader, AVCC→NAL split,
NAL header, SPS/slice inspection via h264-reader, login parsing),
`gen-fixtures.sh`, `kvm-probe`, and opening the upstream IronRDP PR (§4.2).
Milestone 1 hardens these parsers rather than writing them.

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
  replaying committed fixtures). Logs and commits every capability set and the
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
  behind a throwaway local proxy — the Dex part belongs to the companion spec.
  Logs and commits the capability bytes (initial and any re-advertise), every
  `queue_depth`, and whether auto-detect works through the gateway. **Gates**:
  Windows App connects with a gateway-token `.rdp`; NLA with the pre-filled
  username; the CLIPRDR channel opens; the Leg B video gates hold through the
  gateway. If Leg C fails, the VNC fallback (§14) is revisited before
  Milestone 1.
- **Census gates**: max burst length ≤ the resulting hard cap and ≤ the
  KVM→pump channel capacity; N ≤ 3 s for the chosen policy (§6.5; for
  `reconnect`, reconnect→first-IDR p95 ≤ 1.5 s).
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
| A | Milestone 0 (with the `kvm-proto` subset, fixtures, `kvm-probe`, spikes, the upstream PR) → `census.md` + spec revision |
| B | M1 + M2, including the AU assembler, SPS rewriter and a GOP cache only if `census.md` requires them |
| C | M3a: config, logging, admin endpoints, metrics, shutdown, lifecycle, NLA, EGFX pump and state machine, the websocket, the HID writer skeleton and release epoch, L1 and video/lifecycle L2. Requires the upstream patches (§4.2) or their fallbacks |
| D | M3b + M4: keyboard and mouse mapping, stuck-key timers and the released-by-bridge rule, the Typist, and their L2 cases |
| E | M5 + M6: L3, CI, image, perf pass |

The companion `luma-homeops` spec is written once Milestone 0 passes.

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
| VNC bridge (neatvnc) through a Pomerium tunnel | Viable; kept as the fallback if Milestone 0 Leg C fails. RDP preferred for the App Store client and plain HTTPS through the gateway |
| Tailscale on the work laptop | Unofficial without admin rights; most likely to trip endpoint security |
| An RDP server (macrdp) on the Mac itself | Installing a remote-access server on the managed Mac is what IT disabled Screen Sharing to prevent |
| crates.io IronRDP 0.13 | §4.2 |
| Re-encode fallback in v1 | No clean decline path; a C decoder on hostile input; breaks the CPU target |
| Bridge-side GOP cache in v1 | Interacts with every gate and cap; `reconnect`/`wait` plus source bursts may suffice — designed only if the census says otherwise |
| Frame-count soft gate from measured fps | Stalls on idle → motion transitions; the oldest-unacked-age gate does not depend on frame rate |
| RTT auto-detect as the only suspension bound | It is timestamped when written, so it cannot see the server-side queue; kept only as the downstream standing-delay signal |
| Go or TypeScript RDP server | None exists server-side (`grdp`, `gopher-rdp` are client-only; `node-rdpjs` abandoned) |

## 15. Open questions

Settled by Milestone 0: every *(census)* item; Windows App's capability ladder,
ack-suspension, auto-detect, typematic and ErrorInfo behaviour; whether stock
IronRDP HEAD completes NLA + AVC420 with Windows App, directly and through
rdpgw; colour; presentation hold; the IDR policy and N; the Mac remap; the KVM
transport scheme.

Watched: the upstream IronRDP PR (§4.2); IronRDP API churn and an upstream
SVC/DVC reassembly cap (monthly pin review); FLV source latency — if SRS
buffers ~350 ms, the WebRTC source on :1988 becomes a future option.
