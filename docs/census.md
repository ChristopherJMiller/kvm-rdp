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

## Leg C — gateway (rdpgw `16cdaaf`, header mode behind a loopback stub)

Run: `bash spikes/legc-rdpgw/run.sh` from the repo root. It builds rdpgw from
git `16cdaaf` (nixpkgs Go 1.26.7, `nice -n 19`, `GOMAXPROCS=4`), renders
`spikes/legc-rdpgw/rdpgw.yaml` into the gitignored `state/` with a fresh random
32-char PAA key, and starts rdpgw on `127.0.0.1:9443` and `header-proxy.py` (the
stand-in for the oauth2-proxy admin tier) on `127.0.0.1:8443`. `legb-winapp`
(`LEGB_LISTEN=127.0.0.1:23389`, fixture `1080p30_main_full`) is `Server.Hosts[0]`.
The client is FreeRDP 3.31.1 on rowlett (R22), following the Windows App flow:
download the `.rdp` from `/connect` through the proxy, then open it:
`curl -sk -o legc.rdp https://127.0.0.1:8443/connect`, then
`env -u LD_LIBRARY_PATH xvfb-run … xfreerdp legc.rdp /p:legb-spike-pw /cert:ignore
[/gfx:AVC420 /size:1920x1080]`.

How this run differs from the brief, and why:
- **Loopback only.** The task forbids LAN listeners, so everything binds to
  127.0.0.x. The stub connects to rdpgw from **127.0.0.2**, and
  `Header.TrustedProxies` is `127.0.0.2/32`. A direct request from 127.0.0.1
  therefore plays the brief's "another LAN host".
- **`/cert:ignore`.** Every certificate here is a throwaway self-signed spike
  cert on loopback: rdpgw and the stub share one, and `legb-winapp` has its
  rcgen cert. This is not a production setting.
- **`username:s:kvm` needs two settings.** By default rdpgw writes the proxy
  identity (`kvm-admin@example.test`) into `username:s:`. The fix is
  `Client.Defaults` (a one-line `.rdp` containing `username:s:kvm`) plus
  `Client.NoUsername: true`. A fixed `Client.UsernameTemplate` without
  `{{ username }}` would not work: `web.go` rejects it on every request. That
  last point comes from reading the code; it was not run.
- **The `.rdp` is only 7 lines.** It holds `gatewayhostname`, `full address`,
  `username`, `gatewaycredentialssource:i:5`, `gatewayprofileusagemethod:i:1`,
  `gatewayusagemethod:i:1` and `gatewayaccesstoken`. rdpgw leaves out every
  setting that equals its own default (`rdp.go` `isZero`). So
  `redirectclipboard:i:1`, `networkautodetect:i:1` and
  `enablecredsspsupport:i:1`, which the brief expected, are absent, and the
  client's own defaults apply.
- **No key in git.** The committed `rdpgw.yaml` is a template with placeholders.
  The key, the cert and every `.rdp` stay in gitignored paths. rdpgw does not
  commit a `go.sum`, so the build first runs `go mod tidy`, as rdpgw's own
  Makefile does.

### Results — 2026-10-06, FreeRDP 3.31.1 through rdpgw `16cdaaf` (websocket transport)

Three gateway configs were run. **A** is the brief's config as written (no
`Caps.EnableClipboard`, `VerifyClientIp: false`). **B** is A plus
`Caps.EnableClipboard: true`. **C** is B plus `VerifyClientIp: true`, with
`Server.TrustedProxies: [127.0.0.2/32]` and the stub stamping `X-Forwarded-For`.
Unless a row says otherwise, numbers come from B. 17 sessions completed end to
end through the gateway.

| Gate / observation | Result | Evidence |
|---|---|---|
| Gateway-token `.rdp` connects end to end | **Pass.** FreeRDP opens the downloaded `.rdp`, upgrades `RDG_OUT_DATA` to a websocket, offers PAA, and is tunnelled to `legb-winapp`. The `/gateway:g:…,access-token:…,type:http` CLI form also works | FreeRDP `Upgraded to websocket. RDG_IN_DATA not required`, `extendedAuth=HTTP_EXTENDED_AUTH_PAA`. rdpgw logs `ext auth: 2` → `Tunnel create` → `Tunnel auth` → `Channel create` → `Checking host for user kvm-admin@example.test` → `Connection established` |
| NLA with the pre-filled username | **Pass.** HYBRID/CredSSP completes for `kvm` with the password given on the command line. FreeRDP puts its own host name into the NTLM domain when the `.rdp` has no `domain:s:`: the mstshash cookie is `ROWLETT\kvm`, against `kvm` when connecting directly. IronRDP accepts it | acceptor `ConnectionRequest … Cookie("ROWLETT\\kvm")`, then `LEGB_CONN on_connection_info` |
| CLIPRDR: brief config (A) | **Fail: the gateway switches clipboard off.** Unless `Caps.EnableClipboard: true`, rdpgw sends `HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD`. FreeRDP obeys it and leaves `cliprdr` out of its channel list: through the gateway it requests `rdpdr, rdpsnd, drdynvc`, where a direct connection requests `rdpdr, rdpsnd, cliprdr, drdynvc` | client `[RDG] policy denies clipboard redirections`. acceptor `ConnectInitial … ClientNetworkData` |
| CLIPRDR: `EnableClipboard: true` (B) | **The channel opens at the MCS level.** `cliprdr` is requested and given ID 1006 (of 1004–1007, with SKIP_CHANNELJOIN). `legb-winapp` registers no CLIPRDR handler, so the channel is never initialised (no Monitor Ready). Clipboard data was not tested; that belongs to Plan C | client log no longer denies clipboard. `ServerNetworkData { channel_ids: [1004, 1005, 1006, 1007] }` |
| Confirmed capability set has AVC420 | **Pass, same as direct.** With `/gfx:AVC420` the server confirms `V8_1` (`confirmed_has_avc=true`). With the bare `.rdp` (no `/gfx`), FreeRDP advertises 11 sets (`V8`…`V10_7`), the server confirms `V10_7` (`confirmed_has_avc=true`), and the stream decodes | `LEGB_READY` |
| Capability bytes through the gateway | **Identical to direct**, byte for byte. With `/gfx:AVC420`: `V8` `02000000` and `V8_1` `12000000`. With the bare `.rdp`: the same 11-set ladder as a direct run with no `/gfx`. No re-advertise | `LEGB_CAP advertise entry`, diffed against direct runs on the same day |
| First-frame ack p95 ≤ 1 s | **Pass.** 10 fresh connections, each with a fresh `.rdp`: min 72, p50 78, **p95 95**, max 95 ms. Direct (Leg B): 77 / 84 / 97 / 97 | `ironrdp_egfx::server` `latency_us` of frame 0 |
| Steady-state ack latency (1080p30) | 961 acks over a 32 s session that includes one resize: p50 14.1, p95 23.0, p99 30.2, max 80.9 ms; ≤ 2 frames in flight. Leg B direct: 11.4 / 26.6 / 36.2 / 82.4. A direct run on the same day gave p50 15.0, p95 24.2. On loopback the gateway adds nothing measurable | same |
| Picture returns after a server resize | **Pass.** `picture_return_ms = 37` (direct 34) | `LEGB_RESIZE label=resize`, screenshots of 1080p then 720p |
| Picture returns after a client re-advertise | **N/A.** FreeRDP never re-advertised (`re_advertise=false`) | `LEGB_READY` |
| `queue_depth` / ack suspension | **No change.** `queue_depth` was 0 on every ack and `suspended=false` | `LEGB_ACK` |
| Auto-detect through the gateway | **Y.** 119 of 120 probes answered, RTT 0–3 ms; the first probe goes unanswered, as it does direct | `LEGB_AUTODETECT autodetect_answered=true` |
| QoE | **Never fired** (as direct) | no `LEGB_QOE` |
| ErrorInfo 0x7 through the gateway | Delivered. FreeRDP logs `ERRINFO_SERVER_DENIED_CONNECTION` and exits, as it does direct | `LEGB_ERRORINFO`, client log |
| Transport used | **Websocket** (MS-TSGU over websocket on `/remoteDesktopGateway/`) | `rdpgw_websocket_connections 1` and `rdpgw_legacy_connections 0` while connected |
| Legacy HTTP transport (FreeRDP `no-websockets`) | **Fail.** `RDG_OUT_DATA` returns 200, then `RDG_IN_DATA` returns **401**: `rejecting reuse of Rdg-Connection-Id … from a different identity`. rdpgw #185 (`628046b`, 2026-04-30) ties the second half-channel to a non-empty user name, but in token (header/openid) mode the gateway endpoint carries no HTTP identity, so the check always fails. **Any client that uses the two-channel HTTP transport cannot connect through 16cdaaf.** Which transport Windows App uses is an acceptance item | FreeRDP `RDG_IN_DATA authorization result: HTTP_STATUS_DENIED [401]`; rdpgw log |
| RPC transport (`type:rpc`) | **Fail.** rdpgw does not implement RPC-over-HTTP | FreeRDP `rpc_ncacn_http_send_in_channel_request failure` |
| Token missing | **Refused.** In raw-protocol probes, a handshake that offers no PAA gets `E_PROXY_CAPABILITYMISMATCH`, and a tunnel create with no cookie gets `E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED`. FreeRDP without `access-token` never reaches tunnel create: it expects a 401 auth challenge and gets a 101 instead | raw RDG-over-websocket probe; rdpgw `Invalid PAA cookie` |
| Token bad | **Refused** (`E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED`). Tried: the real token with its signature altered (both in FreeRDP and in the raw probe), an HS256 token signed with the wrong key, `alg:none`, and garbage. `legb-winapp` never sees a connection | rdpgw `token signature validation failed` / `cannot parse token` |
| Token expired | **Refused 60 s after `exp`.** rdpgw issues tokens with `exp` = now + 5 min, and go-jose allows 1 min of leeway, so a token works for **6 min** in practice. Used 11 s after `exp`: accepted. Used 66 s after: refused | rdpgw `token is expired (exp)` |
| Token bound to its host | **Pass.** Changing `full address` in the `.rdp` gets `E_PROXY_RAP_ACCESSDENIED` | rdpgw `Client specified host … does not match token host` |
| Token reuse | **Accepted.** The same token opened two tunnels. PAA tokens are bearer tokens for their whole lifetime, not single-use; with `VerifyClientIp: false` they work from any address | raw probe, `ERROR_SUCCESS` both times |
| Exploit guard: `/connect` from outside `Header.TrustedProxies` | **Pass.** A direct request from 127.0.0.1, with or without a forged `X-Forwarded-User`, gets **401 `Untrusted upstream`**. From the trusted 127.0.0.2: no header gets **401 `No authenticated user from proxy`**; with the header, 200. Through the stub, a client-supplied `X-Forwarded-User: mallory@evil.test` is stripped (the token's `sub` is `kvm-admin@example.test`). `/` and `/api/v1/hosts` are gated the same way | curl status codes; rdpgw `header auth: rejecting request from untrusted remote` |
| **Exploit guard bypass: the session cookie** | **Finding.** The proxied `/connect` response sets rdpgw's own `RDPGWSESSION` cookie (`Max-Age=120`). Presented **directly** from the untrusted address with no header, that cookie gets 200 and a freshly minted token. `header.go` accepts an already-authenticated session before it checks `TrustedProxies`. So the trusted-proxy gate covers only requests without a session. Fix: the edge strips `Set-Cookie: RDPGWSESSION` from `/connect` responses, or `/connect` is reachable only through the proxy | curl; pre-auth cookie gets 401 |
| IP pinning through the proxy (C) | **Works when the proxy stamps XFF.** With `Server.TrustedProxies` set to the proxy, rdpgw uses the proxy's `X-Forwarded-For` as the token's `clientIp`, so `VerifyClientIp: true` holds: a token minted for 127.0.0.1 connects from 127.0.0.1, and a token minted for 127.0.0.3 is refused (`E_PROXY_RAP_ACCESSDENIED`, `Current client ip address 127.0.0.1 does not match token client ip 127.0.0.3`). The brief's "the two never match" is true only without XFF. Pinning does not stop the cookie bypass above, because that token carries the bypassing caller's own address | token claims; rdpgw log |

Checklist (from the brief). Every "Windows App" item was run with FreeRDP
3.31.1 instead (R22):
- [x] The client connects with the gateway-token `.rdp`, end to end through
      `/remoteDesktopGateway/` (websocket), with the PAA token validated by
      TokenAuth.
- [x] NLA completes with the pre-filled username `kvm` (== `rdp.username`).
- [x] The CLIPRDR channel opens, **but only with `Caps.EnableClipboard: true`**.
      The brief's config gets it disabled by gateway policy. Note that
      `redirectclipboard:i:1` is *not* in the `.rdp` (it is rdpgw's default,
      so rdpgw omits it). `legb-winapp` has no clipboard handler, so "Leg B
      logs the clipboard channel registering" became "the client requests
      `cliprdr` and the server assigns it an MCS channel ID".
- [x] The Leg B video gates hold through the gateway: AVC420 confirmed,
      first-frame ack p95 95 ms, picture back 37 ms after a resize.
      Re-advertise is N/A (FreeRDP never re-advertises).
- [x] Capability bytes captured through the gateway: identical to the direct
      Leg B ladder, no diff.
- [x] Every `queue_depth` captured through the gateway: all 0, never
      suspended. Gatewaying does not change ack behaviour.
- [x] Auto-detect through the gateway: `autodetect_answered` becomes true
      (119 of 120 probes).
- [x] Exploit guard: a `/connect` request reaching rdpgw from outside
      `Header.TrustedProxies` is refused with 401, **unless it carries a
      `RDPGWSESSION` cookie** (see the finding above).
- Leg C did not fail, so the VNC fallback (§14) need not be revisited before
  Milestone 1.

**Verdict: Leg C passes. The VNC fallback (§14) does not need revisiting.**
Every Leg B video gate holds through rdpgw with identical capability bytes and no
measurable latency cost. Before this becomes the bridge's gateway, the design
needs these changes:
1. **`Caps.EnableClipboard: true`.** Without it rdpgw tells the client to
   disable clipboard, and FreeRDP does (§8 paste depends on CLIPRDR). Whether
   Windows App obeys the redirect flags too goes on Chris's acceptance list.
2. **Websocket transport only.** rdpgw 16cdaaf refuses the legacy two-channel
   HTTP transport in token mode (#185), and it has no RPC transport. Chris's
   Windows App run must show `rdpgw_websocket_connections 1`, or no
   `Opening RDGOUT` in rdpgw's log. If Windows App falls back to legacy HTTP,
   rdpgw needs a patch or a different pin.
3. **Strip `RDPGWSESSION` at the edge,** or keep rdpgw's `/connect`
   unreachable except through the proxy. Otherwise a 120 s session cookie
   lets anyone holding it skip the trusted-proxy gate.
4. **Pin tokens to the client.** Use `Server.TrustedProxies` = the edge,
   have the edge stamp XFF, and set `VerifyClientIp: true`. Tokens are
   reusable bearer credentials for about 6 min, so pinning is the only thing
   that ties one to the client that fetched it. Pinning breaks if the client
   reaches `/connect` and the tunnel from different addresses (split routing
   or NAT).
5. **Username:** use `Client.Defaults` (`username:s:kvm`) with
   `Client.NoUsername: true`.

Deferred to Chris's acceptance (Windows App): the gateway-token `.rdp` in
Windows App itself; its transport (websocket vs legacy, item 2); whether it
honours `HTTP_TUNNEL_REDIR_DISABLE_*`; and whether it accepts the
`gatewayaccesstoken` flow with a self-signed LAN cert (the brief assumes
trust-on-first-use).

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
