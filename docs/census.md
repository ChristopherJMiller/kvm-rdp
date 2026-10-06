# kvm-rdp census (Milestone 0)

> Derived parameters only — no frame bytes, no screen content, no secrets.
> Real captures live in the gitignored, 0700 `captures/` directory and are wiped
> at the end of every session (spec §11.5, §12).

| | |
|---|---|
| Date | 2026-10-06 (Leg A, sessions 1 and 2) |
| Device | Angeet/Yeeso ES3 ("ONE KVM"), self-signed cert `C=CN, O=OneKVM, CN=OneKVM` |
| Firmware | no `Server` header and no version string on `/`; read it from the KVM UI's about page — *pending* |
| Source | Mac Studio over HDMI. Session 1: the Mac's **lock screen** (display kept awake by a Shift keep-alive). Session 2: unlocked; a full-screen test-pattern page (black / white / grey ramp / ms clock, a `data:` URL in Edge) and a pure-red page, driven through the KVM's own HID websocket by a throwaway helper (not in the repo) |
| Presets covered | 1920×1080 at 30 fps only. 60 fps and "auto" deliberately not measured: the bridge pins the KVM to 1080p30 (see Derived decisions) |
| Tool | `kvm-probe` at `plan-a` `b7cc2b9`, release build |

Every value below says how it was obtained. *pending* = not yet measured.

## Leg A — stream (kvm-probe)

| Field | Value | How |
|---|---|---|
| Codec | AVC, FLV `CodecID == 7`; no Enhanced-RTMP FourCC | `summarize` (`codecs`, `fourccs`) |
| profile_idc / constraint flags / level | **66 (Baseline)**, constraint_set0–5 all 0, **level_idc 31** | SPS hex; `trace_headers` cross-check |
| Coded size | 120×68 MBs (1920×1088), `frame_cropping` bottom 8 → **1920×1080** | `trace_headers` |
| Level consistency | **Violates level 3.1**: 8160 MBs > MaxFS 3600. h264-reader (so kvm-proto's `parse_sps`) refuses it: `FieldValueTooLarge { pic_size_in_map_units: 8160 }` | `summarize` → `sps[].summary` |
| POC type | 0; `log2_max_frame_num_minus4` 4 | `trace_headers` |
| max_num_ref_frames | 1 | `trace_headers` |
| frame_mbs_only | 1 (progressive) | `trace_headers` |
| Entropy coding | CAVLC (`entropy_coding_mode_flag` 0); 1 slice group; deblocking control present | `trace_headers` (PPS) |
| VUI | present: **`video_full_range_flag` 1**, colour_primaries **5**, matrix_coefficients **5** (BT.601/BT.470BG), no timing info | `trace_headers` |
| bitstream_restriction | absent (no `max_num_reorder_frames` / `max_dec_frame_buffering`; Baseline has no reordering anyway) | `trace_headers` |
| Scaling matrices | not present (Baseline) | `trace_headers` |
| HRD | `nal_hrd` 0, `vcl_hrd` 0 | `trace_headers` |
| GOP length | **60 frames (2 s)** on HDMI input. The KVM's own NO SIGNAL card is all-intra (every frame IDR, 13 365 B each) | `summarize` `gop_len`; JSONL IDR indices |
| Frame rate / timestamps | 30 fps: FLV timestamp steps 33/34 ms | JSONL `timestamp_ms` deltas |
| CompositionTime | **constant 16 ms** on every coded frame (0 on the sequence header) | JSONL `composition_time` |
| NAL types in coded tags | only 1 and 5 — no AUD, no SEI, no in-band SPS/PPS | JSONL `nal_types` |
| **tag == AU?** | **Yes**: `multi_picture_tags` 0, `continuation_tags` 0, `non_vcl_picture_tags` 0 (≈ 2 700 tags over three captures) | `summarize` |
| Frame sizes (static screen) | IDR up to 264 KB; P 208 B – 91 KB | JSONL `size` |
| Static vs typing cadence | the same: one tag every 33 ms whether the screen is static (lock screen) or moving (ms clock); the KVM never skips frames on a static screen | JSONL `recv_ms` / `timestamp_ms` deltas |
| Frame sizes (moving clock) | IDR ≤ 24.5 KB; P 3.3–17.4 KB (~2 Mbit/s) | JSONL `size` |
| **FLV-reconnect → first IDR, 20 trials** | https p50 **183 ms**, p95 **300 ms**; http p50 **97 ms**, p95 **129 ms** (20/20 ok each) | `first-idr --trials 20` |
| First tag on connect | always an IDR; the GOP restarts at the connection | JSONL |
| **Burst on connect** | **0 frames** (no GOP-cache replay; 26–29 tags in the first second) | JSONL burst query (Part 6 step 4) |
| **Second connection triggers an IDR?** | **Yes, for every viewer.** b connected at +12.0 s; a got an extra IDR at +12.2 s (3 frames after its regular one) and a's GOP cadence restarted there. One shared encoder: any new FLV connection forces an IDR into all streams. **Same token too:** a second FLV opened on the main stream's own token is served (HTTP 200) while the main stream keeps flowing, and it forced an off-cadence IDR into the main stream (45 frames after the previous one, then the 60-frame cadence restarted) — the side-connection IDR mechanism works end to end (n = 1) | a/b capture JSONL; same-token pair via the HID helper's token + `ffprobe` keyframe list |
| Resolution-change signalling | Not measured in detail. One observation (n = 1, tentative): while presets were being switched in the KVM UI, a live FLV delivered 8 tags and then ended — a preset change appears to **close live FLV connections** rather than signal in-band. Signal loss does **not** change the SPS: the NO SIGNAL card uses the same SPS bytes at 1920×1080 | 10 s capture during preset switching; JSONL `param_sets_hex` |

## Leg A — sessions (not in the §12 list; found here and load-bearing for §5)

| Behaviour | Result | How |
|---|---|---|
| Concurrent logins | coexist: a second login does not invalidate the first token | driver test: A, then B, A still accepted |
| Logout | **global**: one session's logout invalidates **every** token (A rejected after B logged out) | driver test |
| Live streams on another session's logout | **survive**: a.flv ran its full 30 s through b's logout | a/b captures |
| Display sleep | the KVM switches to its own NO SIGNAL card (all-intra, same SPS); HID input wakes the Mac | frame grabs |

## Leg A — transport

| Field | Value | How |
|---|---|---|
| Service ports (vendor UI) | web 80/443, video 8880/8881, control 8888/8889, WebRTC 1988 | vendor UI; TCP connect to the six documented ports (all open) |
| TLS ports | 443, 8881, 8889 — **one certificate** for all three; SPKI SHA-256 `f94841875ec7fa56220d48ffadaa5c0f2d84ffbbd1beeb060245ded1419b614f` (one `--pin` covers all ports) | `fingerprint --port` ×3 |
| TLS version / cipher | TLSv1.3, `TLS_AES_256_GCM_SHA384` on all three | `openssl s_client -brief` |
| rustls negotiates? | **Yes** (fingerprint, capture, first-idr, ws-open all over https) | kvm-probe |
| FLV open → first IDR | https p50 183 / p95 300 ms; http p50 97 / p95 129 ms | `first-idr` |
| Inter-tag jitter (30 s static) | https p50 33, p95 38, p99 83, max 136 ms; http p50 33, p95 36, p99 49, max 55 ms | JSONL `recv_ms` deltas |
| Inter-tag jitter (30 s moving) | https p50 33, p95 36, p99 40, max 82 ms; http p50 33, p95 39, p99 50, max 59 ms — no consistent TLS penalty | JSONL `recv_ms` deltas |
| Control websocket open | https 42 ms; http 32 ms | `ws-open` |

## Leg A — colour (decoded Y only)

| Pattern | Y min | Y max | How |
|---|---|---|---|
| Black | 16 | 16 | `sample-range` |
| White | 233 | 236 | `sample-range` |
| Grey ramp (0–15, 64/128/192, 236–255) | 15 | 235 | `sample-range` |
| Pure red `rgb(255,0,0)` (400×400 crop) | Y 63, U 110, V 239 (flat) | | `signalstats` on one decoded frame, in the sandbox |

Verdict: the pixels are **limited range (16–235) and BT.709** — red's Y of 63 matches BT.709 (BT.601 would be ≈ 81; U is off pure red's 102, probably macOS colour management on the Mac's output). The SPS's VUI is **wrong on both counts**: it claims full range (`video_full_range_flag` 1) and BT.601 (primaries 5, matrix 5). A decoder that honours the VUI shows washed-out, slightly mis-tinted colour (an ffmpeg PNG export of "black" came out dark grey); one that assumes BT.709 limited shows it correctly. Which range Windows App's AVC420 path assumes when it ignores the VUI (the spec reads MS-RDPEGFX as full-range BT.709) is Leg B's colour A/B — if it assumes full range and ignores the VUI, passthrough looks washed out whatever the SPS says.

## Leg A — crash behaviour

Moved to Plan C's L4 hardware checks (it needs HID input, which `kvm-probe` never sends).

## Leg B — FreeRDP 3.31.1 (direct), stock IronRDP HEAD 38b074e

Run: `legb-winapp` with a committed fixture; FreeRDP 3.31.1 on rowlett (R22 —
Windows App is hard to test from here; every Windows-App run step in this
batch becomes a FreeRDP run instead). The server listens on `127.0.0.1:13389`
by default (fix round 1, I1 — loopback-only; override with `LEGB_LISTEN` if
the client runs on another host):
`env -u LD_LIBRARY_PATH xvfb-run -a xfreerdp /v:127.0.0.1:13389 /u:kvm
/p:legb-spike-pw /sec:nla /gfx:AVC420 /cert:ignore /log-level:INFO`.

### Results — 2026-10-06, FreeRDP 3.31.1 on rowlett (Xvfb 1920×1080), loopback `127.0.0.1:23389`

(`13389` is also taken on rowlett, by a microvm listener; runs set `LEGB_LISTEN=127.0.0.1:23389`.)

| Gate / observation | Result | Evidence |
|---|---|---|
| NLA with the rcgen **ECDSA** cert | **Pass** — `/sec:nla` completes; no RSA cert needed | `LEGB_CONN on_accept` → `on_connection_info`; clean disconnects |
| Confirmed capability set has AVC420 | **Pass** — FreeRDP advertises 2 sets: `V8` (`02000000`, SMALL_CACHE) and `V8_1` (`12000000`, SMALL_CACHE \| AVC420_ENABLED); server confirms `V8_1`, `confirmed_has_avc=true` | `LEGB_CAP advertise entry` ×2, `LEGB_READY` |
| First-frame ack p95 ≤ 1 s | **Pass** — 10 fresh connections: min 77, p50 84, **p95 97**, max 97 ms (IronRDP's own `latency_us`, send → FrameAcknowledge) | `ironrdp_egfx::server` "EGFX FrameAcknowledge received" |
| Steady-state ack latency (1080p30, 895 frames) | p50 11.4, p95 26.6, p99 36.2, max 82.4 ms; ≤ 2 frames in flight | same, 30 s run |
| Picture returns after a server resize (real path) | **Pass** — `DisplayUpdate::Resize` → reactivation (`updates_calls` 1→2) → Setup → 720p IDR: **picture_return_ms = 34** | `LEGB_DISPLAY`, `LEGB_RESIZE label=resize` |
| `resize-channel` (channel-only Setup, same 1080p stream on a 1280×720 surface) | **Broken** — logs a 7 ms "return" but FreeRDP rejects every later frame (`areRectsValid: Rectangle 0 {0x0-1280x720} outside of bounding frame 0x0`). The real resize path is required (spec §6.4 already says so) | client log |
| Picture returns after a client re-advertise | **N/A** — FreeRDP never re-advertised (`re_advertise=false` throughout) | `LEGB_READY` |
| Ack suspension | **Never** — `queue_depth` 0 on all 895 acks; `suspended=false` | `LEGB_ACK` |
| Auto-detect | **Answered** — RTT 0–4 ms on loopback | `LEGB_AUTODETECT autodetect_answered=true` |
| QoE | **Never fired** (FreeRDP sends no QoE frame acks by default) | no `LEGB_QOE` |
| Stranding (stdin `strand`) | **Pass** — the last frame stays fully displayed while stranded (screens 3 s apart are byte-identical; no blank, no partial frame); resume continues | `LEGB_SHIP: STRAND` / `RESUME`, screenshots |
| ErrorInfo 0x7 | FreeRDP logs `ERRINFO_SERVER_DENIED_CONNECTION` and exits; no auto-reconnect | client log, `LEGB_ERRORINFO` |
| **ES3-shaped stream** (Baseline, 1080p30, **level_idc 31** mislabelled, VUI full range + BT.601) | **Decodes** — 445 acks over 15 s, picture correct; identical with `level_idc` 40. FreeRDP does not care about the level | local x264 fixtures `captures/es3like_l31/l40.h264` (R23, not committed) |
| **Colour: does the client honour the VUI?** | **No (FreeRDP).** Limited-range pixels (Y 16 / 235) render as RGB **16,16,16 / 235,235,235** whether the VUI says full or limited — FreeRDP applies a fixed full-range conversion to AVC420, as MS-RDPEGFX specifies. Same result for `1080p30_main_limited` vs `…_limited_flagfull` | screenshots, pixel reads |

**Consequence for passthrough (colour):** the KVM's pixels are limited-range, so a client that follows MS-RDPEGFX's fixed full-range AVC420 conversion shows them **mildly washed out** (black → grey 16, white → 235; ~14 % contrast loss), and rewriting the VUI cannot change that for such a client. Whether Windows App honours the VUI is now the top item on Chris's acceptance list; if it does not, options are (a) accept the mild wash-out, (b) find a KVM setting that makes its encoder emit full-range YUV, or (c) re-encode — rejected by the design (§14).

Capture (one row per observation; raw log line id in brackets):
- [x] NLA completes with the rcgen **ECDSA** cert. If NLA fails, mint an RSA
      cert (`openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out
      cert.pem -subj /CN=kvm-bridge.spike -days 2`, load via
      `ironrdp_server::TlsIdentityCtx::init_from_paths` for the pub key) and
      retry. RECORD which key type FreeRDP requires. [LEGB_CONN/handshake]
- [ ] Confirmed capability set contains AVC420 (`confirmed_has_avc=true`;
      fix round 1, I2 — this is the one real field `on_ready` logs for this
      gate, `gfx.rs`'s `LEGB_READY` line; there is no `server_supports_avc420`
      field anywhere in the code, despite an earlier draft of this checklist
      citing one). RECORD the exact confirmed version from the same line's
      `confirmed` field (the full negotiated `CapabilitySet`, e.g. `V8_1`).
      [LEGB_READY]
- [ ] Full advertised ladder (every `LEGB_CAP advertise entry`: version + hex +
      parsed). Commit as the capability fixture for the L1 golden (§11.2).
- [ ] First-frame ack p95 over ≥20 reconnects (time first `LEGB_SHIP shipped IDR`
      → its matching `LEGB_ACK`). This sets `video.first_ack_grace`. GATE ≤ 1 s.
- [ ] Picture returns within N (§6.5, ≤ 3 s) after a server-initiated resize
      (Task 6b; stdin `resize` with `LEGB_FIXTURE_RESIZE=$PWD/fixtures/large/720p30_main_full.h264`): fix round 1 (a) — read `picture_return_ms` straight off the `LEGB_RESIZE picture_return_ms` line (`label="resize"`) rather than correlating "RESIZE emitted" / "new-size stream starts at IDR" / "shipped IDR" / `LEGB_ACK` by hand. Also record `resize-channel` (channel-only swap, stdin `resize-channel`; same line, `label="resize-channel"`): does it blink?
- [ ] Picture returns within N after a client re-advertise (`re_advertise=true`
      in LEGB_READY): same measurement.
- [ ] Does FreeRDP SUSPEND acks? (`LEGB_ACK suspended=true`,
      queue_depth=0xFFFFFFFF). Does it re-send a suspend ack AFTER its own
      re-advertise and AFTER a server resize? (Decides §4.2 patch-1 fallback.)
- [ ] Auto-detect: does `LEGB_AUTODETECT autodetect_answered` ever become true?
      (Decides the standing-delay gate, §6.6.)
- [ ] QoE: does `LEGB_QOE` ever fire? Record `time_diff_dr_us`.
- [ ] Barcode stranding (stdin `strand`): does the last frame appear without
      further input? Sets §6.8's idle-encoder decision + `flv_idle_timeout`.

Deferred — Chris's acceptance (Windows-App-only; FreeRDP has no UI for these,
so they wait for a real Windows App run before Plan A's spec revision reads
them as pass/fail):
- [ ] Key matrix: every physical key/chord → the `LEGB_INPUT keyboard` scancode
      + extended flag + Cmd-rewrite behaviour. ≥ 20 typematic samples: initial
      delay + repeat interval (sets §7.4 `key_repeat_timeout`; feeds §7.1 Mac
      remap decision). Commit as the remap-table fixture.
- [ ] Each ErrorInfo dialog + auto-reconnect behaviour: trigger 0x1, 0x5, 0x7,
      0x9 via stdin `errorinfo <hex>` (fix round 1, b — now wired to
      `error_info_disconnect_handle().disconnect(...)`; logs
      `LEGB_ERRORINFO` with the code sent). The *dialog* itself stays
      deferred (FreeRDP has no UI to screenshot), but FreeRDP's own
      disconnect-and-log behaviour for each code is observable now and worth
      spot-checking in this same run. Revise §6.9 if 0x19 SERVER_SHUTDOWN
      suits `shutdown` better.
- [ ] Colour A/B: run twice — `LEGB_FIXTURE=$PWD/fixtures/large/1080p30_main_limited.h264`, then `…/1080p30_main_limited_flagfull.h264` (identical slices, only the VUI range flag differs);
      eyeball black level in Windows App; record whether the two differ (does it honour the VUI?). **Add for this device:** does Windows App decode the KVM's Baseline / level-3.1-labelled 1080p stream as is, and with `level_idc` rewritten to 40?

## Leg C — gateway gates

*pending* (Part 7). Gateway-token `.rdp` connects (P/F); NLA with pre-filled username (P/F); CLIPRDR opens (P/F); Leg B video gates hold through the gateway (P/F); capability bytes, `queue_depth`, auto-detect through the gateway.

## Census gates (go/no-go)

| Gate | Result |
|---|---|
| Max burst length ≤ hard cap and ≤ KVM→pump channel capacity | **Pass** — burst on connect is 0 frames |
| N ≤ 3 s for the chosen policy (`reconnect`: reconnect → first IDR p95 ≤ 1.5 s) | **Pass** — p95 300 ms (https), 129 ms (http) |

## Derived decisions (handoff to Task 9.1) — provisional until Legs B/C

- **§3.2 scheme:** **https** (rustls negotiates; one pin for all ports). TLS costs ~90 ms on each FLV/websocket open and nothing measurable in steady state (moving-screen jitter is the same or better than http), so it is not the "measurable latency" that would justify http.
- **§6.1 pinned values:** Baseline 66, level as **rewritten** (below), 1920×1080 (120×68 MBs, crop 8), POC 0, 1 ref frame, CAVLC, tag = AU.
- **§6.2 admission:** `CompositionTime == 0` must become "constant per stream" (the KVM sends a constant 16 ms).
- **§6.5 `idr_policy`:** `reconnect` passes (N ≈ 0.3 s). Better: since any new FLV connection forces an IDR from the shared encoder, the bridge can **request an IDR by opening and closing a short side FLV connection**, keeping its main stream. Propose this as the primary IDR mechanism; keep `reconnect` as the fallback.
- **§6.8 `sps_rewrite`: required.** `level_idc` 31 → **40** (1080p30 needs MaxFS 8192, MaxMBPS 244 800 ≤ 245 760); 60 fps would need 4.2. The level byte sits before any Exp-Golomb field, so the rewrite is a one-byte patch with no emulation-prevention change. Consider also setting `constraint_set1_flag` (constrained Baseline: 1 slice group, no ASO observed) if Leg B shows Windows App needs it. **Also correct the VUI:** `video_full_range_flag` 0 and colour description 1/1/1 (BT.709) — or drop `colour_description_present_flag` — because the pixels are limited-range BT.709 and the VUI says otherwise. Those fields sit after Exp-Golomb fields, so this is a bit-level SPS re-serialisation (re-apply emulation prevention), not a byte patch — a Plan B parser/writer task. Leg B's colour A/B shows whether Windows App honours the VUI at all.
- **§7 input (Plan C):** HID keyboard frames drive macOS as specified (US layout, `cmd` = GUI bit 0x08). The §3.3 session-start sequence's zero-button absolute report at (0, 0) **parks the pointer in the top-left corner on every websocket (re)open**, which reveals the menu bar over full-screen apps — send the last known pointer position instead. An 842-character URL sent at one report per 20 ms took ~60–90 s to land in Edge's address bar (the omnibox's per-keystroke work is mixed in); measure the KVM's own HID rate in Plan C before fixing the §8 paste rate.
- **§5 sessions:** never call logout while another client (the vendor UI as break-glass, the census tool) may be using the device: logout is global. Teardown should close the websocket and the FLV, and let the token lapse.
- **§6.9 ErrorInfo / `flv_idle_timeout`:** *pending*.
- **§7.4 `key_repeat_timeout` / `modifier_idle_timeout`:** *pending* (Leg B key matrix).
- **`video.default_size`:** 1920×1080, and the KVM preset is **pinned to 1920×1080 at 30 fps** (not "auto", not 60 fps): 60 fps would need level 4.2 and double the bitrate for no gain on a remote desktop, and "auto" invites resolution changes. A preset or Mac resolution change is a rare, operator-driven event; the bridge handles it on its existing paths either way — a closed FLV takes the reconnect path, and a new sequence header or in-band SPS goes through `classify_sps_change` (a new size classifies as `Resize`, which takes the §6.4 resize path).

## Artifacts

kvm-sim profile (parameter sets only — never frame data):

```toml
[kvm_sim.es3]
avcc_length_size = 4          # ffprobe nal_length_size (sequence header); pix_fmt yuvj420p, color_range pc
fps = 30
gop_len = 60
burst_on_connect = 0
tag_is_au = true
composition_time_ms = 16
idr_on_new_connection = true  # shared encoder: every new FLV forces an IDR for all viewers
no_signal_card = "all-intra, same SPS"
pixel_range = "limited"       # measured: black 16, white 233-236
pixel_matrix = "bt709"        # measured: red Y 63
vui_claims = "full range, bt601 (primaries 5, matrix 5)"  # wrong; see Leg A colour
sps_hex = "6742001f965403c0112f2cdc1418140800"
pps_hex = "68ce31120000"
```

Capability fixture and key-matrix fixture: *pending* (Leg B). `captures/` is gitignored, 0700, and wiped after every session.
