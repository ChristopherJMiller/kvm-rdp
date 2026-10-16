# kvm-rdp — design

| | |
|---|---|
| Status | Draft rev 6.3 — Plan D's deviations recorded (2026-10-15); rev 6.2: Plan C's (2026-10-08); rev 6.1: Plan B's (2026-10-06); rev 6: census-filled. Design agreed in conversation 2026-10-05; revised after a source-level research pass (IronRDP `38b074e`, macrdp), a five-lens adversarial review, and three coverage/consistency checks (rev 5); amended with the Milestone 0 Leg A census, 2026-10-06 (rev 5.1); filled from the whole census — Legs A, B and C, with FreeRDP 3.31.1 standing in for Windows App — and the Milestone 0 verdict recorded, 2026-10-06 (rev 6) |
| Repo | `github.com/ChristopherJMiller/kvm-rdp` (public, MIT OR Apache-2.0) |
| First target | Angeet/Yeeso ES3 "ONE KVM" wired to a Mac Studio |
| Client | Microsoft Windows App on macOS, through an rdpgw RD Gateway on 443 |
| Companion spec | Deployment, gateway, edge gating and KVM isolation live in `luma-homeops` (separate spec, written after Milestone 0). §9.4 lists what this spec requires of it |

**Rev 6.3 — Plan D (2026-10-14 to 2026-10-15).** Records what building
Milestones 3b and 4 settled, against the code as built. DD*n* are Plan D's
recorded deviations (`docs/superpowers/plans/2026-10-14-kvm-rdp-plan-d.md`);
every amended passage below is marked "rev 6.3". Plan D's hardware run
(Task 1.6, Leg D in `census.md`) has not happened yet — it waits for the
owner — so every value it would retune keeps its written default and every
L4 question stays open (§11.6, §15). The change log supersedes nothing in
rev 6.2's; it is added to it. One line per change:

- DD1 (§11.6, §15): the L4 runbook never logs out. kvm-probe has no `--logout`; the refusal forms are measured for a never-issued token, no token and a token that lapsed on its own; the forms after a global logout, and whether the control websocket survives another session's logout, are measured only if the owner logs out in the vendor web UI during Task 1.6's optional step (`logout-watch` only watches), and are otherwise "not measured".
- DD2 (§4.1, §11.2): `kvm-proto` holds the tables (`keymap`), `hid::scale_abs`, and §8's text handling, UTF-16 decoding and Typist (`paste`); the input state machine — the released-by-bridge rule, both §7.4 timers, the paste states — is `kvm-rdp`'s `input::` modules, beside `hid::queue`, tested with an injected clock.
- DD3 (§4.4, §7.1): `input.mac_remap` switches a fixed table: on, a report holding Ctrl and one of C, V, X, A, Z, F, W carries GUI in that Ctrl's place (left for left, right for right). There is no configurable table until the key-matrix fixture exists; off by default.
- DD4 (§8): the pending paste — from the chord until typing starts, `paste.modifier_wait` bounds both the wait for the clipboard text and the wait for every modifier's release; a fresh Esc (swallowed), a fresh non-modifier press or a mouse button (both passed through), or any release-all (§7.4) cancels it; a second chord is swallowed; modifier presses and releases pass through; an answer no paste waits for types nothing.
- DD5 (§8): Caps Lock is the last `Synchronize`'s state, toggled by each fresh Caps Lock press since.
- DD6 (§8): the Typist waits for HID-queue room as well as `paste.pace`: a step pushes at most 8 − queued reports, each `paste.pace` after the last (no catch-up burst), and looks again 2 ms later when there is no room, so `paste.pace = 0` never overflows `input.queue`.
- DD7 (§7.1, §7.2, §10.4): relative motion and presses, the X1/X2 buttons (and any later one), horizontal and ainput scroll, unmapped scancodes and untypeable or surrogate Unicode units are dropped and counted in `input_events_ignored`, which keeps that meaning; a relative button release is honoured (PD9 I4); the Keyboard Power usage is never sent.
- DD8 (§3.2, §4.4, §7.3): "once a reconnect settles" is every websocket open re-asserting the full HID state once, `input.reassert_after` (1 s) past its session-start sequence; L4's retune rule and its receive-window assumption are in §4.4.
- DD9 (§7.1, §7.4): at most 16 non-modifier keys are tracked (5 reported) and 32 released-by-bridge keys and modifiers remembered; a press past the first bound, or a held key the second has no room for, is dropped and counted.
- DD10 (§4.4, §8): `paste.pace` is twice the smallest pace at which the ES3 typed L4's 200-character pattern losslessly three runs out of three, every slower pace lossless too; not measured yet, so 15 ms stands.
- DD11 (§4.4, §8): `paste.chord` is parsed at load — one or more distinct modifiers, then one letter or digit; anything else is refused.
- §4.2: `ironrdp-cliprdr` joins at the same pin; it was already compiled in `ironrdp-server`'s graph.
- §4.3: the input core is a sans-IO core (`input::core::InputCore`), stepped by IronRDP's input handler and by a driver on the RDP `LocalSet`, under one mutex held from a feed's first step to its last output carried out (PD9 I1); it follows the live generation, so the pump shell's word is advisory (PD9 m5); handler calls off the RDP thread (IronRDP's ainput DVC — FreeRDP's Advanced Input, mouse only — from `spawn_blocking`) are dropped and counted (PD9 I1).
- §4.4: `input.queue` is at least 9 (DD6); `input.reassert_after` with L4's rule (DD8, D29); `paste.chord` is a parsed chord (DD11); `paste.pace`'s source (DD10); `CONTROL_SNDBUF` is sized from L4's page-measured HID rate, is not a config key, and stays 16 KiB until Leg D; every new or changed key has its `leak_shapes` shape.
- §4.5 (PD8 m4): `ironrdp_cliprdr` is held at ERROR (`logging::ERROR_CAPPED_TARGETS`), not INFO: its WARNs carry client-chosen file names and fire once per hostile PDU.
- §5.2: the input core's driver joins the essential tasks; the key-held-on-death check is built (`kvm-probe hid-hold`) and waits for Leg D.
- §6.9, §8 (PD8): `clipboard_oversize` reaches the pump as `RdpInput::Fatal` from the session's own CLIPRDR backend, and counts only for the current generation; a failed clipboard response is no cause.
- §7.1, §7.2: the mapping as built — Unicode presses type through the US layout with their own Shift; a button event carries its own position, so a click with no prior move lands where it was made; coordinates clamp to the surface, or to the advertised size before the first Setup.
- §7.1, §8, §12 (PD11b I5; PD5 m7, PD7 m5): live Unicode key events map CR, BS and ESC to Return, Backspace and Esc, and a fresh Unicode Esc aborts a paste like a scancode Esc; paste's own text handling is unchanged; acceptance item 12 is resolved in code, Windows App's behaviour still to confirm.
- §7.3: the input handler is built, replacing DC7's counting stub: a step takes each report's state and its epoch stamp together and pushes with `push_at`; the re-assert (DD8) waits for a drained queue, and from `reassert_after` past its deadline goes after the next frame written only while no keyboard report waits, without its pointer part while pointer reports wait (PD9 m1, PD9 R-I1) — so it never overtakes a queued report.
- §7.4: `ReleaseTrigger` gains `Synchronize`, `KeyRepeat` and `ModifierIdle`, raised by the input core, whose timers fire only on a step; after a `Synchronize` the core forgets every released-by-bridge mark, so a held key's next key-down presses it again (PD5 m6), while every other release within a session, a websocket reconnect included, keeps the marks; typing's start releases what the client still holds.
- §8 step 1 (PD8 m5): the server advertises no clipboard capability beyond IronRDP's own `USE_LONG_FORMAT_NAMES`.
- §8 text handling (D4, PD7 m1, m1-r): the text ends at CF_UNICODETEXT's U+0000; skipped scalars are dropped before step 1, so a trailing break followed only by skipped units is still removed, and a skipped unit between a CR and its LF never splits that CRLF into a typed Return and a removed LF.
- §8 (PD9 carry 3, I2): clipboard requests are counted per generation and each answer belongs to the oldest outstanding; only the pending paste whose own request that is takes it, and every other text or failure answer is discarded and counted; a failed answer ends its paste at once; a request no answer has come for is retired after `max(60 s, 2 × paste.modifier_wait)`; a file-list answer counts as one.
- §8 (PD9 m-R1, m-R2): two accepted residuals — a never-answering client's drift heals only after a 60 s pause in paste attempts, and an answer more than 60 s late can be typed by a newer paste; a paste past 64 outstanding requests is refused locally (`backlog`).
- §8 (PD8 I2): a format list whose first `FileGroupDescriptorW`-named format has CF_UNICODETEXT's id offers no text: IronRDP would parse the answer as a file list, past `paste.max_bytes`.
- §8 (controller ruling 2): Milestone 4's comparison with the KVM's `hid.lua?type=text` is deferred to Plan E's perf pass; ours stays the default.
- §9.2 (PD5 ruling): every type that holds input has a redacted `Debug`; DC9's L2 case is the proof.
- §9.3: what the Mac does when the websocket dies with a key held waits for Leg D.
- §10.4 (PD9 ruling 4): the registry as built has 43 families; `hid_reasserts`, `paste_events{outcome}`, `paste_skipped_chars` and `clipboard_discarded{reason}` join it, and `release_all{trigger}` gains `synchronize`, `key_repeat` and `modifier_idle`.
- §11.2 (DD2): the input core's injected-clock tests are `kvm-rdp` unit tests, not `kvm-proto` L0.
- §11.3: the input, stuck-key and paste cases run through a real IronRDP client (Tasks 5.1, 5.2); W10, the divergent replay and the re-assert are exercised (Task 5.3); the secrets case types the keystroke sentinel and pastes the canary (DC9), with two accepted residuals.
- §11.6, §15: every L4 check is a `kvm-probe` subcommand proven against kvm-sim; Leg D, the run on the ES3, is pending (owner), so they all stay open.
- §11.6 (PD3): kvm-probe's HID commands are bounded — at most 500 characters a run, a 100 ms pace, 10 runs per pace and 8 paces per `hid-type` — and a bound passed is refused before anything is sent.
- §12: planning unit D's status; owner acceptance items 12–14 and a note on item 4; one list of what is carried to Plan E.
- §7.3, §8 (Plan D final review I1): a websocket open whose discard drops anything — a queued report or a pending resync — is a release (`release_all{websocket_reconnect}`), so a paste whose reports were queued during an outage aborts instead of typing its text less its first characters.
- §7.3, §7.4, §9.3 (Plan D final review I2): a release lands only if the KVM reads it. A session end writes a ping after its release, and the KVM's pong (or its answer to the close) proves the read; a session end without that proof, with something held written since the last proof, opens one bounded release websocket (`hid::release`: the pinned TLS, the token or one fresh login, the session start and a ping, the release again `input.reassert_after` after the pong; 3 opens in 10 s; a FIN; never a logout), superseded by the next session's `Start`; and a websocket lost while input is held reopens without its backoff. Both ship before Leg D; plan Task 1.6 step 8 gains the decision rule (harmless if the ES3 releases on websocket loss, required if it keeps a key).
- §5.2 (I2): a `Shutdown` waits for a release websocket up to 350 ms (`SHUTDOWN_BOUND` 950 ms, inside the KVM step's 1 s); past it the release runs on, detached, until the runtime's teardown.
- §10.4 (I2): 44 families; `release_websockets{outcome}` joins the registry.
- §11.3 (I2): L2 cases for a session end during a KVM stall, one with the websocket down, and the release websocket's bound.

**Rev 6.2 — Plan C (2026-10-07 to 2026-10-08).** Records what building
Milestone 3a settled, against the code as built. DC*n* are Plan C's recorded
deviations (`docs/superpowers/plans/2026-10-07-kvm-rdp-plan-c.md`); every
amended passage below is marked "rev 6.2". One line per change:

- DC1 (§6.2): burst marking uses a sliding 1 s **median** delivery-delay baseline, so neither a late first tag nor one late tag mid-stream marks the on-time AUs after it (Plan B's final review I3).
- Plan B N1, N2 (§11.5): kvm-sim's `wait_for` returns every event its predicate could have seen; the source-burst wording is fixed.
- DC2 (§4.2): `ironrdp-server` uses only the `egfx` feature — `helper` holds nothing but the `TlsIdentityCtx` §9.1 forbids; PEM loading uses `rustls-pki-types`, the CredSSP key comes from x509-parser.
- DC3 (§4.2, §4.3, §6.4, §6.6, §6.9, §11.2, §12): the fork carries three patches; patch 1 is pinned and its no-fork fallback (the shadow suspension flag and the suspend-ack injection) is not built; §6.9's "patch 4" is patch 3, `ConnectionInfo::abort_handle()`.
- DC4 (§4.3): `SessionStart`/`SessionStop` reach the pump from the RDP side with the GFX handle; the shell's `biased` select takes the RDP side, then the 50 ms tick, then the KVM stream.
- §4.3: the pump's input and command lists are the real enums (`Shutdown`, `Backlog`, `Rtt`, `SurfaceSize`, `Abort`; no slate, max-frames or suspend-ack command — Setup and the slate run inside `step`).
- DC5, P31 (§4.4): the secret files are `kvm.password_file` and `rdp.nla_password_file` (≤ 4 KiB, one trailing line ending trimmed) and `rdp.tls_cert_file`/`rdp.tls_key_file` (PEM, ≤ 64 KiB, untrimmed); new keys `admin.liveness_timeout`, `rdp.cert_poll_interval`, `security.accept_window`; durations are strings ≤ 1 h; the NLA password has ≥ 22 characters.
- §4.4 (PC15 I1): a config error is the path and either a line, a column and a fixed category (a TOML error) or the key and the rule (a value that parses but is invalid) — never the file's text; the file is read through a 1 MiB cap; exit 2.
- §4.4, §9.2 (final review C1): no `*_file` key's value is ever shown in an error, a log line or a `Debug` — it may be a secret, or a pasted PEM, written where the file name goes; a file that cannot be read is its key and the I/O kind.
- DC6 (§4.3, §6.6): the shell samples suppression and the write counter per tick and per AU and feeds every RTT read; the core alone treats a generation's first read as its reference.
- DC7 (§7, §11.3): Plan C's input handler is a counting stub; L2 drives the HID writer through `HidControl`.
- DC8 (§11.2, §12): the FreeRDP 11-set capability fixture moves to Plan E's L3.
- DC9, P48 (§11.3): the secrets-hygiene case runs without the keystroke sentinel and paste canary, spawns the binary itself, and sets `SSLKEYLOGFILE` and `RUST_LOG=off` in its cleared environment.
- DC10, P49 (§13): the target budget is gated by `scripts/target-budget.sh` at 8 GiB; measured 2.4 GiB after Task 2.1, 3.31 GiB once the binary and L2 existed, 3.42 GiB at the end of Plan C.
- DC11, P34 (§4.3, §6.5): `CancelIdrRequest` is pump-internal; the core counts `idr_cancelled`, the shell ignores the command.
- DC12 (§4.3, §6.5): an AU dropped on a full KVM → pump channel marks the next delivered AU `after_drop`, a flow cause carried in order.
- DC13, P32 (§5.2): stop-accepting is `on_accept` refusing; the shutdown's disconnect watchdog is 2 s; a Preempt winner that completes NLA after that is aborted without ErrorInfo and never starts the KVM side.
- DC14 (§4.3): the KVM → pump channel holds the hard cap + 8.
- DC15 (§4.4, §9.1): `security.accept_rate` counts admitted attempts only; refusals are logged once, then at most once per 10 s with a count.
- DC16 (§4.5): `/readyz` means "TLS identity loaded and `GetLocalAddr` answered".
- §4.5 (P17, PC4 M1): the admin listener serves at most 32 connections at once and drops the rest unanswered.
- §4.5 (final review Minor 6): a request head is over 2 KiB by where its blank line ends, so one whose terminator arrives in the read that crosses the limit is still answered 431.
- §4.5 (final review Minor 2): the response write and shutdown are bounded by the same 2 s as the head, so a peer that never reads cannot hold a connection, and one of the 32 permits, indefinitely.
- §3.2, §4.4 (final review Minor 3): `kvm.scheme = "http"` logs one WARN at startup — no pin, the KVM password and token in cleartext, diagnosis only.
- DC17 (§11.2): the L1 rig decodes `GraphicsPipelineServer`'s output with IronRDP's own PDU types, not `GraphicsPipelineClient`.
- DC18 (§5.2, §8, §9.3, §11.6, §12, §15): §11.6's five L4 hardware checks move to Plan D's first task; Plan C adds four more to that list (§11.6).
- DC19 (§12): CI gains a job timeout and a tracked-secrets gate ahead of Plan E.
- DC20 (§6.8): a `video.sps_rewrite` lacking any of the three rewrites is refused at load.
- §6.8 (Task 6.3): the POC-type-0 stranding re-check Leg B handed on ran in Plan C's L2 — the last AU shipped reaches the client with no further input, its SPS rewritten.
- DC21 (§4.4): a renewed certificate restarts the bridge only once no client is connected; a client still handshaking holds it off for at most 45 s.
- DC22 (§13): disposable scratch worktrees use their own target dir.
- DC23, P5 (§6.4): an Off edge recorded during `WaitReactivation` clears `return_to_paused`, so a resize started from Paused whose client un-minimises meanwhile ends in NeedIdr, not frozen in Paused.
- DC24, P46 (§11.3): the 64 MiB websocket message's "RSS bounded" rests on the 4 KiB websocket cap (its unit test) and the L2 reconnect; the real binary's peak RSS (`VmHWM`, ≈ 30.5 MiB, +8 KiB around the message) shows only that nothing sized from the declared length was touched — kvm-sim sends 4 KiB of the declared 64 MiB, and untouched pages are not resident.
- §5.2: the KVM step's `Stop`/`Shutdown` takes at most 600 ms (`session::STOP_BOUND`) within its 1 s; the ready line follows the signal handlers; a panicked essential task stops the server in every build.
- §6.4 (PC11 m1): `FlvOpened` in `WaitReady` and `WaitReactivation` restarts both §6.5 clocks.
- §6.4 (PC11 m6): a shutdown during `Closing` shortens the running watchdog to the shutdown's 2 s if that is sooner.
- §6.4 (PC11 m5, m7): a second negotiation without AVC420 closes at once; a Setup IronRDP refuses (its EGFX channel closed) closes with `no_avc420`.
- §6.4 (PC17 I4): a `DisplayUpdate::Resize` is held until IronRDP has written the EGFX sent before it.
- §6.4 (ruling 1): `WaitReactivation` has no deadline — a known limitation, bounded by Preempt alone (nothing sets `SO_KEEPALIVE` or `TCP_USER_TIMEOUT`).
- §6.5 (PC11 m2, m3): idr-wait open time is sampled on ticks only.
- §6.5 (PC17 I2, N1, N2): after a `ReconnectFlv` swap the candidate's replay of what the client already has is dropped (a ring of 64), resyncing past a skipped AU; a diverging P frame is dropped with a flow cause.
- §6.5 (PC8 I1): a `ReconnectFlv` candidate swaps in only at its first tag; one that fails first is dropped and the old FLV kept.
- §6.6 (PC10 m5, m6): the resume-clear rule can drop about one RTT of frames IronRDP still tracks; an ack for an id never issued still disarms the stall.
- §6.9 (PC9 I1): a "successful re-login" is one whose token the KVM then accepted; every re-login after a session's first waits on a backoff.
- §6.9 (PC8 m1, m7): a refused `ReconnectFlv` candidate is in the auth class; a pin mismatch on a candidate or side FLV is fatal.
- §6.9 (PC11, PC13): `no_avc420` also covers a client closing its EGFX channel mid-session; one accepted window (a teardown during a Preempt candidate's handoff grace) can miscount a plain disconnect as one.
- §6.9 (PC18 m5, ruling 3): the ErrorInfo of a fatal cause at session start may not reach Windows App; a lingering close in IronRDP's teardown (a candidate fork patch 4) is the remedy if acceptance item 11 shows it lost.
- §3.2, §7.3 (PC9 I2): a websocket whose writes did not all complete is reset (`SO_LINGER` 0), never closed with a FIN; only a close the KVM answered is a FIN.
- §3.2, §7.3 (final review I1): the control websocket's `SO_SNDBUF` is capped at 16 KiB before connect, so `hid_write_timeout` sees a KVM that stops or slows reading within under a thousand reports, not ~45 000; Plan D's L4 resizes it from the ES3's HID report rate.
- §7.3 (PC7 I1): a report is stamped with the epoch before the queue lock and dropped whole (`hid_epoch_discards`) if a release came between.
- §9.1 (PC13, PC15): Hybrid is the only mode built; a client without CredSSP gets a plain disconnect; the TLS key type is logged at startup, never judged.
- §10.4 (ruling 2, ruling 6): a registry table of every metric and label as built, with `frames_dropped{reason="repeat"}` and `{reason="replay_diverged"}`; only a frame a gate drops counts the gate (§11.3's stalled-client case notes what that asks of a test).
- §11.3 (Task 6.6, PC7 W10): the admin case floods past the connection cap; SIGTERM and secrets hygiene run on the real binary; a mid-session KVM certificate change is left for Plan D to exercise.
- §11.6 (DC18): the L4 list moves to Plan D and gains the ES3's refusal forms, same-token FLV refusal, its websocket close form and the forced-IDR → candidate lag.
- §12: planning unit C names the three pinned patches; unit D starts with the L4 checks; owner acceptance item 11 asks whether a fatal cause at session start shows.
- §13: one shared target dir except disposable scratch worktrees; the budget is the measured one.

**Rev 6.1 — Plan B (2026-10-06).** Records what building Milestones 1 and 2
settled: POC type 1 is refused (§6.1); trailing zero bytes are trimmed from
every NAL before the §6.2 checks, at most one AUD per tag comes before any
slice, unknown FLV tag types are framing violations, burst marking is
measured from the first coded tag (superseded in rev 6.2), and the 4 SPS / 16 PPS limits also bound
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
  for diagnosis on the isolated segment only (rev 6.2, final review Minor 3:
  startup logs one WARN saying so — no pin, and the KVM password and token
  in cleartext); neither of the conditions that
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
  default features off). `TCP_NODELAY` on every KVM socket (rev 6.2: and
  the control websocket's `SO_SNDBUF` capped at 16 KiB, §7.3).
- Websocket limits: max message and frame 4 KiB, small write buffer; inbound
  data messages are read and discarded; an oversize message closes the socket
  without buffering it. Rev 6.2: the bridge ends a websocket with a FIN only
  after a close the KVM answered with its own close frame; every other end —
  a failed or blocked write, a lost read side, a close never answered, the
  task aborted — resets the connection (`SO_LINGER` 0), so HID reports the
  KVM had not yet read are discarded with it, never delivered after the next
  websocket's session-start sequence. What already sits in the KVM's own
  receive buffer it may still read: so (rev 6.3, DD8) every websocket open
  re-asserts the full HID state once, `input.reassert_after` past its
  session-start sequence (§7.3, §7.4, §9.3).
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

Rev 6.3 (DD2): of the input path, `kvm-proto` holds the tables (`keymap`:
set-1 scancode → usage, the US layout, `paste.chord`'s `Chord`),
`hid::scale_abs` (§7.2) and `paste` (§8's text handling, UTF-16 decoding
and the Typist). The input state machine — keyboard and pointer state,
the released-by-bridge rule, both §7.4 timers and the paste states — is
`kvm-rdp`'s `input::{keys, pointer, paste, core}`, beside `hid::queue`
whose release epoch and `ReleaseTrigger` it uses, as Plan C put its other
sans-IO cores (pump, upstream, HID queue) in `kvm-rdp`.

### 4.2 Dependencies

- **IronRDP is git-pinned**: one rev, at or after `38b074e` (2026-10-01; for
  Plan C, a rev on the fork branch below), for every `ironrdp-*` crate used
  (including `ironrdp-pdu`, for ErrorInfo codes),
  as direct git dependencies in `[workspace.dependencies]` — no
  `[patch.crates-io]` (rev 6.3: Plan D adds `ironrdp-cliprdr`, §8, at the
  same rev; it was already compiled in `ironrdp-server`'s graph). crates.io `ironrdp-server 0.13.0` / `ironrdp-egfx 0.3.0`
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
     *No-fork fallback* (rev 6.2: not built — Plan C pins patch 1): the pump keeps a shadow suspension flag from
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
  behaviour is an acceptance item (§12). Rev 6.2: Plan C pins patch 1 and
  builds no fallback (DC3).
- CI fails if `cargo tree -d` shows a duplicate `ironrdp-*` crate. A pin bump
  is its own PR, reviewed monthly, and must pass the IronRDP golden tests (§11.2).
- `ironrdp-server` with `default-features = false, features = ["egfx"]` (**rev 6.2**: not `helper`, whose only item is the `TlsIdentityCtx` §9.1 forbids).
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
  `Pump::step(&mut GraphicsPipelineServer, now, Input) -> Vec<Command>`, driven by
  the state × input table of §6.4. Its inputs (rev 6.2: the enums as built)
  are `SessionStart{generation, size}`, `SessionStop{generation}`,
  `OnReady{avc420}`, `ReactivationComplete`, `FrameAck{frame_id,
  queue_depth}`, `Tick`, `Suppress(bool)`, `SpsChanged{class: initial |
  resize | other, params}`, `FlvOpened{origin: first | transient |
  commanded}`, `Au(KvmAu)` (the AU with its `idr`, `burst`, `after_drop` and
  receive time), `UpstreamFatal(Cause)`, `Shutdown{watchdog}`,
  `Backlog{written}` and `Rtt(u32)` — the shell drops other generations'
  events before it steps, so only the session inputs carry one; its
  commands are `SendDvc` (one drained EGFX batch, the slate included),
  `DisplayResize`, `SurfaceSize`, `ReleaseAll`, `OpenFlv`, `RequestIdr`,
  `ReconnectFlv`, `CancelIdrRequest` (pump-internal, DC11: the core counts
  `idr_cancelled` and the shell ignores the command), `ProbeRtt`,
  `Disconnect(Cause)` and `Abort` (rev 6.2; Setup, the slate and `set_max_frames_in_flight` run inside
  `step` under the lock, and there is no suspend-ack injection — patch 1 is
  pinned). The
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
  logout, §3.2) before the next `Start` begins (rev 6.2: within
  `session::STOP_BOUND`, 600 ms — the websocket flushes and closes within
  500 ms, or its task is aborted and its socket reset within 100 ms more —
  and the FLV sockets are closed, not only their tasks aborted, so an old
  FLV's close is on the wire before the next login). Every `ServerEvent` send,
  including `Disconnect`, is only made for the current generation. Events
  already queued in IronRDP when a connection ends are dropped by IronRDP
  (§4.2 patch 3), not by the bridge.
- **KVM → pump: one ordered stream.** Control messages (`SpsChanged`,
  `FlvOpened`, `UpstreamFatal`; rev 6.2: `SessionStart/Stop` come from the
  RDP side, below) and AUs share one channel, so
  they never reorder. AUs are sent with `try_send` and dropped when the channel
  is full (a flow cause, §6.5; metric); control messages are sent with
  `send().await` and are never dropped (the KVM actor briefly pauses FLV
  reading; the pump drains continuously). SPS/PPS are classified on the KVM
  side (SPSs after the rewrite, §6.8) and travel as `SpsChanged`, so a
  dropped AU can never lose a parameter set; the pump's SPS/PPS cache updates
  only from this stream. Capacity: ≥ the hard cap (§6.6). The FLV is
  otherwise drained at line rate; the KVM never sees back-pressure.
- **Input path** (§7.3) and the **HID writer** never block the RDP runtime.
- **Rev 6.2 (Plan C).** `SessionStart`/`SessionStop` come from the RDP side with the GFX handle (DC4): every `KvmEvent` carries its generation, and the shell's `biased` select takes the RDP side first, then the 50 ms tick, then the KVM stream — so no KVM event overtakes its session's start, and a KVM stream that never empties cannot stop the tick-driven watchdog, stall, IDR and probe timers. The tick runs only while a session (or a closing pump) needs it. The shell samples suppression and the write counter per tick and per AU and feeds every RTT read; the core alone treats a generation's first read as its reference (DC6). A dropped AU marks the next one `after_drop` (DC12); the KVM → pump channel holds the hard cap + 8 (DC14).
- **Rev 6.3 (Plan D): the input core.** `input::core::InputCore` is the input path's sans-IO core: `step(ctx, event, &mut outs)`, where the context carries `now`, the release epoch, the live generation, the surface size, the `input.*`/`paste.*` values and the HID queue's room, and `next_deadline()` says when a timer, the pending paste or the Typist next needs a `Tick`. Its outputs are pushes stamped with the epoch they were built at, releases, a clipboard request, paste outcomes and counts. `rdp::input::InputShared` holds it under one `std::sync::Mutex`, fed from IronRDP's input handler, from a driver on the RDP `LocalSet` that sleeps until the core's next deadline (an essential task, §5.2), and from the pump shell's clipboard words. A feed holds the lock from its first step until its last output is carried out, so two feeds never interleave their reports (PD9 I1); the lock is never held across an await, every lock taken under it is a leaf, and nothing under it calls into IronRDP — a clipboard request is a `ServerEvent` channel send, for the current generation only. The core follows the live generation (`Generations`), which the connection handler (`rdp::handler`) moves, with its release, inside `on_connection_info` and `on_disconnected`; the pump shell's `set_generation` word is advisory, so a `SessionStop` read after the next session's keys began (Preempt) never resets them (PD9 m5). The handler takes input only on the RDP thread: IronRDP's ainput DVC — FreeRDP's Advanced Input extension (`FreeRDP::Advanced::Input`), which carries only mouse events and is not a Microsoft RDP channel, so Windows App is not expected to open it — calls it from `spawn_blocking`, one task per PDU in no order, and those calls are dropped and counted (`input_events_ignored`, PD9 I1). A client that did use it would lose its mouse input, counted there; acceptance would show it.

### 4.4 Configuration

One TOML file, path from `--config` or `KVM_RDP_CONFIG`. Environment variables
other than that path (including `RUST_LOG`) are not read. Secrets come only
from files named in the config — `kvm_password_file`, `nla_password_file`,
`tls_cert_file`, `tls_key_file` (rev 6.2: `kvm.password_file` and `rdp.nla_password_file` — at most 4 KiB, exactly one trailing line ending (`\n` or `\r\n`) trimmed, not empty; `rdp.tls_cert_file` and `rdp.tls_key_file` — PEM, at most 64 KiB (`rdp::tls::MAX_PEM`), read untrimmed by `rdp::tls::load` before anything binds; all relative to the config's directory) — and are never logged. The file is validated
at startup; any error exits non-zero before binding (rev 6.2: exit 2; the
file is read through a 1 MiB cap; a TOML error names only the path, a line
and column, and a fixed category — unknown key, wrong value type, missing
required key, duplicate key, syntax error, file too large, not UTF-8 — and a
value that parses but breaks a rule names the path, the key and the rule,
with no position; neither ever echoes any of the file's text, which may be a
secret pointed at by mistake or an inline password. Nor is any `*_file`
key's value ever shown — in an error, a log line or a `Debug` — since it may
be the secret itself written where the file name goes, or a pasted PEM: a
file that cannot be read, a secret file at load or the TLS pair at startup,
is named by its key and the I/O kind only, e.g. `rdp.nla_password_file:
cannot read the file: entity not found`, and a secret file that is not UTF-8
says so; final review C1). The TLS identity is loaded
once. The bridge polls the certificate file's mtime every 60 s and, on change — once no client is connected (rev 6.2: a renewal must never cut a live session; the companion deployment spec's decision 8; a client still in TLS or CredSSP holds it off for at most `HANDSHAKE_GRACE`, 45 s, once no session is live, so an unauthenticated peer cannot pin the old certificate) —
runs graceful shutdown (§5.2) and exits 0 so its supervisor (Kubernetes, or
systemd on a dedicated host) restarts it — CredSSP binds to the public key read
at startup.

Defaults (every duration is configurable; rev 6.2: durations are strings such
as `"250ms"` or `"1.6s"`, at most 1 h, unknown keys are refused, and the NLA
password has at least 22 characters — 128 bits as base64). Census-derived values cite
`census.md`; values marked *acceptance* are safe defaults that the owner's
Windows App run retunes (§12):

| Key | Default | Notes |
|---|---|---|
| `rdp.listen` | `0.0.0.0:3389` | |
| `rdp.username` | `kvm` | Exact, case-sensitive match (§9.1) |
| `admin.listen` | `0.0.0.0:9464` | §4.5 |
| `kvm.host`, `kvm.spki_sha256` | required | One pin covers all three TLS ports (§3.2) |
| `kvm.scheme` / ports | `https` / 443, 8881, 8889 | Confirmed by Leg A (§3.2). `http` (80, 8880, 8888) is for diagnosis only, and startup warns once (rev 6.2) |
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
| `input.queue` | 256 reports | §7.3. Rev 6.3: 9 to 4096 — at least `TYPIST_ROOM` + 1, so the Typist's up to 8 reports a step, and typing's start one more, never overflow it into a resync (DD6) |
| `input.hid_write_timeout` | 1 s | |
| `input.key_repeat_timeout` | 10 s (*acceptance*) | Repeats are not yet confirmed: the typematic capture needs Windows App (`census.md`, Leg B — deferred). Then: measured max initial delay + 2 × repeat interval + 250 ms, floor 1 s (§7.4, §12) |
| `input.modifier_idle_timeout` | 30 s | Confirmed; nothing in the census bears on it (§7.4) |
| `input.mac_remap` | off (*acceptance*) | Until the key-matrix capture shows Windows App's Cmd rewrite can be told apart from a real Ctrl+key (§7.1, §12). Rev 6.3: the switch for DD3's fixed table (§7.1) |
| `input.reassert_after` (rev 6.3) | 1 s | §3.2, §7.3, §7.4 (DD8): how long past each websocket open's session-start sequence the full HID state is re-asserted, once; more than 0, at most 1 h. L4's rule (D29): if Leg D sees stale reports land after a fresh session start (`hid-stale`), the default becomes `max(1 s, ceil(1800 / hid_rate))` s, capped at 1 h, where `hid_rate` is the KVM's HID reports/s as the test page measures them (`hid-type` at pace 0): the page prints `rate <n> <ms>`, `n` the characters typed (never keydowns), each one a press and a release, so `hid_rate` = 2·(n − 1)·1000 / `ms`, the median of three runs (D28) — the time the KVM takes to read out a whole receive window of stale reports, taken as 64 KiB (Linux's default receive buffer) ÷ ~37 B per report (§7.3) ≈ 1 800; if not, or with no rate measured, 1 s stands (a backstop). Not measured yet: 1 s |
| `paste.chord` | Ctrl+Option+Shift+V (raw scancodes) | §8. Rev 6.3 (DD11): written `"ctrl+option+shift+v"` and parsed at load into a `Chord` — one or more distinct modifiers (`ctrl` or `control`, `shift`, `alt` or `option`, `cmd` or `win`; case and spaces around `+` ignored; either side's key matches), then one letter or digit, held with exactly those modifiers; anything else is refused at load |
| `paste.pace` | 15 ms between HID reports | §8. Rev 6.3 (DD10): set from L4 as twice the smallest pace at which the ES3 typed the 200-character pattern losslessly three runs out of three, every slower pace lossless too (`hid-type`); not measured yet, so 15 ms stands. 0 is allowed (L2) |
| `paste.max_chars` / `max_bytes` / `modifier_wait` | 4096 / 64 KiB / 5 s | |
| `paste.multiline` | `enter` | or `refuse` |
| `security.accept_rate` | 30 admitted connection attempts per sliding `security.accept_window`, global; refusals do not count (rev 6.2) | §9.1 |
| `security.accept_window` | 60 s (rev 6.2) | |
| `rdp.cert_poll_interval` | 60 s (rev 6.2) | A changed certificate or key runs §5.2 and exits 0, once no client is connected |
| `admin.liveness_timeout` | 10 s (rev 6.2) | §4.5's heartbeat age, configurable for L2 |
| `log.filter` | `info` | EnvFilter syntax; capped (§4.5) |

Rev 6.3: the control websocket's `SO_SNDBUF` cap (`kvm::endpoint::CONTROL_SNDBUF`,
16 KiB, §7.3) is not a config key. L4 sizes it from the HID report rate the
test page measures (D28 — the probe's own write rate is only a diagnostic):
adjusted, with kvm-probe's matching `hid::SNDBUF`, only if a full buffer
would take more than about 1 s of input to drain, or hold fewer than a few
reports. Not measured yet, so it stays 16 KiB. Every key Plan D added or
changed — `input.queue`'s bound, `input.reassert_after`, `paste.chord` —
has its `leak_shapes` shape, and its error never echoes the value (the C1
rule).

### 4.5 Admin endpoints and logging

- An admin listener on the KVM runtime serves `/metrics`, `/livez` and
  `/readyz`. `/livez` fails when the RDP runtime's heartbeat (a `LocalSet` task
  bumping an `AtomicU64` each second) is more than 10 s old (rev 6.2:
  `admin.liveness_timeout`; the heartbeat beats every quarter of it, capped
  at 1 s). `/readyz` succeeds
  once the TLS identity is loaded and the RDP listener is bound (rev 6.2: `ServerEvent::GetLocalAddr` answered); it never
  checks the KVM. Each request head is bounded (rev 6.2): over 2 KiB is
  answered 431 (final review Minor 6: measured to the end of its blank
  line, whatever read that arrives in), one not complete within 2 s is
  dropped, a connection whose response is not written and shut down within
  a further 2 s is dropped too (final review Minor 2: a peer that never
  reads, a zero window, cannot hold one), and at most 32
  connections are served at once — past that a connection is dropped
  unanswered rather than queued, so a scanner on 9464 cannot grow work on the
  KVM runtime the listener shares with the session actor; `/livez` answers
  again once the held connections time out.
- Logs are `tracing` JSON lines on stdout. `log.filter` is one filter; a
  **second, independent `Targets` filter** holds `ironrdp_*`, `sspi`,
  `tungstenite`, `tokio_tungstenite`, `hyper` and `rustls` at INFO (everything
  else at TRACE) and is combined with it via `FilterExt::and`, so nothing in
  config can raise them. (sspi and the acceptor log NTLM tokens at debug;
  `ironrdp_server` traces every dispatched event; tungstenite traces HID
  payloads.) Rev 6.3 (PD8 m4): `ironrdp_cliprdr` is held at ERROR instead
  (`logging::ERROR_CAPPED_TARGETS`; the more specific target wins over the
  `ironrdp` prefix): its WARNs carry client-chosen data — the file-list
  sanitiser logs the client's file names — and fire once per hostile PDU,
  so a client could otherwise flood the log.
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

On SIGTERM or SIGINT: stop accepting (`on_accept` refuses, rev 6.2); release-all and wait for the websocket
flush (≤ 500 ms); disconnect the client with cause `shutdown`; close FLV and
websocket (no logout, §5.1); exit within 5 s. A `ServerEvent::Quit` sent
while a client is connected ends only that connection — IronRDP's
connection loop returns `Disconnect` and `run` goes back to accepting — so
stopping the server takes a second `Quit` after that connection has
drained (rev 6.1). The shutdown's disconnect watchdog is 2 s, not `video.disconnect_watchdog`, to fit the 5 s (rev 6.2). Release builds use
`panic = "abort"`. A crash cannot release keys: what the Mac does when the
websocket TCP connection dies with a key held moved from Leg A to Plan D's L4 (rev 6.2; Plan C has no HID input path)
hardware checks (§12), and the answer goes in §9.3. Rev 6.3: Plan D built
the check (`kvm-probe hid-hold`, ending the websocket with a close, a FIN
or a reset while a key is held); it waits for Leg D (§11.6).

Rev 6.2 (Plan C), as built (DC13): the steps are bounded at 500 ms (flush),
2.2 s (the 2 s watchdog plus a tick), 1 s (the KVM actor's `Stop`/`Shutdown`,
itself at most 600 ms, `session::STOP_BOUND`) and 2 × 500 ms (the two
`Quit`s, spaced because a live connection drops whatever shares a batch
with the `Quit` it consumes), then 200 ms of runtime teardown — 4.9 s at
worst. A Preempt winner that completes NLA after stop-accepting is aborted
through its `ConnectionAbortHandle` without ErrorInfo and never starts the
KVM side: the exiting bridge cannot serve its auto-reconnect, and the
restarted one can. A changed certificate runs the same sequence (§4.4). The
binary logs `kvm-rdp ready` only after its SIGTERM and SIGINT handlers are
registered, so a signal sent the moment the line appears still runs this
sequence. Rev 6.3 (Plan D final review I2): the KVM step's `Shutdown`
also waits up to 350 ms (`session::SHUTDOWN_RELEASE_WAIT`) for a release
websocket still running (§7.4) — with a `Stop`'s 600 ms, 950 ms
(`session::SHUTDOWN_BOUND`), inside the step's 1 s. Past it the release
runs on, detached, through the `Quit`s, until the runtime's teardown drops
it: a shutdown attempts what fits of it, and the exit stays inside 5 s. A panic in a task the bridge cannot run without (the pump shell,
the KVM actor, the admin listener, the certificate watcher; rev 6.3: and
the input core's driver, §4.3) stops the RDP server in every build, not only under `panic = "abort"`. Exit codes: 0
after a signal or a certificate change, 1 if startup failed or the RDP
server stopped on its own, 2 on a config or logging error.

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
and nothing more for suspension: patch 1 keeps it across Setup (rev 6.2; the fallback's re-arm is not built). The first
Setup of a connection also issues `OpenFlv`; every Setup is a Setup cause
(§6.5). A Setup IronRDP refuses — `create_surface` fails only once its EGFX
channel has closed under the pump — closes with `no_avc420` (rev 6.2): no
picture can follow on that connection, and a NeedIdr without the first
Setup's `OpenFlv` would wait on nothing. Surface ids from before an `on_ready` are invalid; Setup always uses
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
| **WaitReady** | Setup (+ slate, `OpenFlv` if first); if `pending_size`: start resize; else → NeedIdr | first negotiation: wait `avc420_timeout`, then → Closing(`no_avc420`); a later one: → Closing(`no_avc420`) at once (rev 6.2, §6.7) | set `pending_size` | update cache | restart both §6.5 clocks (rev 6.2) | ignore | ignore | ignore | drop | drop | — | → Closing |
| **NeedIdr** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` is a flow cause | satisfies `idr_pending`, resets idr-wait | ignore | → Paused | — | gates open: send → Live; closed: drop, flow cause | drop | flow cause | → Closing |
| **Live** | Setup → NeedIdr (Setup cause) | → Closing(`no_avc420`) | start resize | update cache; `other` → NeedIdr (flow cause) | → NeedIdr (await this connection's first IDR) | ignore | → Paused | — | send if gates open, else → NeedIdr (flow cause) | send if gates open, else → NeedIdr (flow cause) | → NeedIdr (flow cause) | → Closing |
| **WaitReactivation** | record (merged) | → Closing(`no_avc420`) | set `pending_size` (latest wins) | update cache | restart both §6.5 clocks (rev 6.2) | Setup at the reactivated size; if `pending_size` is set and differs: clear it, start resize again; else if suppressed or `return_to_paused` → Paused; else if `on_ready` was never seen → WaitReady; else → NeedIdr (Setup cause) | ReleaseAll; record | record; an Off edge clears `return_to_paused` (rev 6.2, DC23) | drop | drop | — | → Closing |
| **Paused** | Setup; stay Paused | → Closing(`no_avc420`) | start resize with `return_to_paused` | update cache | stay Paused | ignore | — | → NeedIdr (Setup cause) | drop | drop | — | → Closing |
| **Closing** | ignore | ignore | ignore | ignore | ignore | ignore | ignore | ignore | drop | drop | ignore | ignore; a shutdown (§5.2) shortens the running watchdog to its own 2 s if that is sooner, keeping the first cause (rev 6.2) |

*Start resize*: stop sends (→ `WaitReactivation`); update the size used by
`size()` and `request_initial_size()`; emit `DisplayUpdate::Resize` on the
current updates stream; continue per the `ReactivationComplete` cell. AUs
arriving during `WaitReactivation` are dropped. (Rev 6.2: EGFX and the
`Resize` travel on two IronRDP channels that are written concurrently, so
the shell holds the `Resize` until the generation's write counter shows
every EGFX batch sent before it written — the slate before its
DeactivateAll — re-reading the counter each loop turn and on a timer that
backs off from 5 ms to 250 ms while it is held.) **This is the only resize
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

**Known limitation (rev 6.2): `WaitReactivation` has no deadline.** Neither
this table nor the pump times a reactivation out, so a client that never
completes one (it stopped reading mid-resize, or never answers the
Deactivation-Reactivation) holds its session — and the KVM connections —
until it disconnects. Preempt bounds it: a new authenticated client takes
over. TCP does not: neither the bridge nor IronRDP (`c99eece2`) sets
`SO_KEEPALIVE` or `TCP_USER_TIMEOUT`, so a vanished peer is noticed only
once a server write fails — after the kernel's retransmission timeout, and
only if something is written at all — and a live client that has stopped
reading is bounded by Preempt alone. A deployment must not count on TCP to
end a session stuck here. The held `Resize`'s re-read backs off to 250 ms,
so such a session costs next to nothing meanwhile.

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
  channel (rev 6.2, DC12: carried in order, as the next delivered AU's
  `after_drop`), a burst is truncated at the hard cap, `SpsChanged other`.
- **FLV opened** (`FlvOpened`, any origin): the NeedIdr waits for that
  connection's first IDR; it never requests one by itself.

Under `side` and `reconnect`, a Setup cause sets `idr_pending`, except for
the first Setup, whose `OpenFlv` already serves; a flow cause starts idr-wait
accounting, and once the gates have been open for a cumulative
`idr_wait_max` (flapping does not reset it) it sets `idr_pending` — usually
the 2 s GOP answers first. (Rev 6.2: the open time is sampled on the pump's
50 ms ticks only, never on an AU — so a burst AU's soft-gate exemption never
counts as open time, and the AU that resolves a NeedIdr never also requests
the IDR it brings; the cost is up to one tick of resolution.) `video.idr_policy` says how `idr_pending` is
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
  source whose encoder is not shared. Rev 6.2, as built:
  - The candidate swaps in only at its first tag, emitting
    `FlvOpened{Commanded}` then. One whose first chunk is a framing error,
    or that has no tag `kvm.connect_timeout` after it opened, is dropped
    (`upstream_reconnects{reason="commanded_failed"}`; a framing error also
    counts toward `stream_corrupt`) and the old FLV keeps flowing — so from
    `ReconnectFlv` to giving up takes at most 3 × `connect_timeout`
    (connect, response, first tag) plus one 100 ms actor tick, 9.1 s at the
    defaults, inside `upstream_deadline`. (kvm-sim logs an FLV open when it
    subscribes the viewer, so its log cannot tell a swap at open from a swap
    at the first tag; the L1 candidate cases do.)
  - **Replays are not sent twice.** The shared encoder forces the
    candidate's IDR into the old FLV too, and the old FLV may deliver it —
    and P frames after it — before the candidate's first tag; the candidate
    then replays them. A repeated P frame would predict from the wrong
    reference with a backwards `frame_num`, corrupting the picture until the
    next IDR. So the pump keeps the (length, hash) of each AU handed to
    IronRDP since the last IDR, as it went out (SPS rewritten; FLV
    timestamps excluded), in a ring of 64 (≈ 2 s), and after a commanded
    swap drops the candidate's AUs while they match it in order
    (`frames_dropped{reason="repeat"}`). The candidate's first AU, its IDR,
    is dropped like the rest when it matches the ring's first entry — the
    client already has that picture — and that match ends the swap's
    NeedIdr. An AU the candidate left out is skipped by resyncing to the
    later entry it matches. An AU that matches nothing mid-replay ends the
    replay: a P frame is dropped and the pump enters NeedIdr with a flow
    cause (`frames_dropped{reason="replay_diverged"}`) — its reference is
    not the client's — while an IDR, which needs no reference, goes out. A
    replay longer than the ring, or a candidate whose IDR is not the ring's
    first entry, is forwarded from the candidate's IDR, a decodable rewind.
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
later cause requests it again. (Rev 6.2, DC11: the cancellation is the
pump core's own — deferred requests live in its IDR core, which counts
`idr_cancelled` on leaving NeedIdr or on an FLV open that cancels one; the
`CancelIdrRequest` command exists for L1's assertions, and the shell ignores
it.) A side fallback is a request like any other;
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
  ignored. Arithmetic is saturating. (Rev 6.2: IronRDP's own tracker does not
  clear on a resume ack, so a frame sent after IronRDP has processed the
  resume ack but before the pump has is tracked there and dropped here —
  at most about one RTT of frames escapes the soft gate; IronRDP's own
  back-pressure still bounds them.)
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
    `autodetect_rtt_handle` after each probe as an `RttSample`. (Rev 6.2, DC6: the
    shell reads the handle just before each `ProbeRtt`, so a read reflects the
    previous probe, and feeds every read; the core keeps a generation's first
    read as its reference only and goes live once the handle moves.) Standing delay =
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
  ack (including a suspend ack — rev 6.2: and an ack for an id never issued,
  which IronRDP forwards after a warning, so a client that acks a stale id
  more often than `stall_timeout` keeps a closed gate and a frozen picture
  rather than ending as `client_stalled`; only that authenticated client is
  affected), is frozen in `Paused` and `WaitReactivation`,
  and is disabled while acks are suspended. If it reaches `stall_timeout` →
  Closing(`client_stalled`).
- **Ack suspension** (`on_frame_ack` with `queue_depth == 0xFFFFFFFF`):
  **sending never stops** — a client resumes only by acknowledging an EndFrame
  it received. Suspension is read from `is_ack_suspended()` (§4.2 patch 1) only
  (rev 6.2: patch 1 is pinned; the fallback's own flag is not built), and survives Setup and
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
| Encoder stops sending on a static screen. **Not found**: one tag every 33 ms whether the screen is static or moving | Some clients hold the last ~2 frames, so the last keystroke never appears | Cannot strand a keystroke on the ES3 at 30 fps. Leg B's barcode stranding test on FreeRDP showed a stable picture while stranded (screens 3 s apart byte-identical; no blank, no partial frame) — not confirmed as the last frame shipped, and run on x264 streams with POC type 2 and `bitstream_restriction`, which cannot fail the presentation-hold gate a real POC-0, no-restriction stream could; that check moves to Plan C's L2 with Plan B's ES3-shaped POC-type-0 fixture (§11.5, Task 6.1) — rev 6.2: done, `the_last_au_shipped_reaches_the_client_and_its_sps_is_rewritten`, which shows the last AU kvm-sim ships reaching the in-process client with no further input and carrying the rewritten SPS; whether a real decoder holds frames stays acceptance item 3 and L5. `flv_idle_timeout` (10 s) sits far above the 33 ms cadence |

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
`video.sps_rewrite` is `["level", "vui", "restriction"]`; a set lacking any of the three is refused at load (rev 6.2).

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
| Auth | login rejected; HTTP 401/403 or `result: 403` on FLV/WS — e.g. after any session's logout, which is global (§3.2). Side FLVs are excluded (§6.5) | Re-login once (the only time the bridge logs in again within a session, §5.1). A second consecutive failure, with no successful re-login in between, is fatal: `kvm_auth_failed`. Rev 6.2: a re-login is *successful* only once the KVM accepts its token — the websocket upgrades with it, or an FLV opened with it reaches its first tag — so a KVM that answers logins but refuses every fresh token is fatal at the second refusal rather than logged into as fast as it answers; the first re-login of a session is immediate, every later one waits on a backoff that only an accepted token resets; a `ReconnectFlv` candidate refused for its token is in this class (a KVM refusing every new FLV is fatal at the second refused candidate) |
| Certificate | SPKI mismatch | Fatal immediately, no login sent: `kvm_cert_mismatch` (rev 6.2: on any connection — a side FLV or a `ReconnectFlv` candidate included) |
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
connection (§4.2 patch 3; rev 6.2) — so a client that has stopped reading cannot hold
the session or the KVM connections open.

Rev 6.2: `no_avc420` also ends a session whose client closes its EGFX
channel mid-session (a DVC Close while its generation is current), and one
whose Setup IronRDP refuses because the channel is gone (§6.4): no picture
can follow either way. IronRDP also runs the channel's close at every
connection's teardown, just before `on_disconnected`; that one belongs to an
ended generation and is filtered out, so a plain disconnect is not a cause —
except in one accepted window: a session that ends during a
Deactivation-Reactivation while a Preempt candidate is negotiating waits up
to IronRDP's `CANDIDATE_HANDOFF_GRACE` (750 ms) for `on_disconnected`, and a
teardown close read in that window, its generation still current, counts
one `disconnects{no_avc420}` and a log line (PC13 review m1). Dashboards
should not read every `no_avc420` as a client fault.

Codes are explicit server-initiated ErrorInfo values (MS-RDPBCGR 2.2.5.1.1),
so the client does not auto-reconnect into a loop; the log line names the
cause. **Confirmed for 0x7 on FreeRDP only**: FreeRDP logs
`ERRINFO_SERVER_DENIED_CONNECTION` and exits without auto-reconnecting,
directly and through rdpgw (`census.md`, Leg B and Leg C). The table stands
as written; Windows App's dialog and reconnect behaviour for each code
(0x1, 0x5, 0x7, 0x9), and whether `0x19` SERVER_SHUTDOWN suits `shutdown`
better, are an acceptance item (§12) that may revise it.

**A fatal cause at session start** (rev 6.2; e.g. `kvm_auth_failed`,
`kvm_cert_mismatch` or `no_avc420` before the first picture): IronRDP writes
the ErrorInfo and closes at once, with the client's DVC answers still
unread, so the close can become a reset that destroys an ErrorInfo the
client has not read yet — L2's client reports it only because it keeps
reading after a failed write, and Windows App may show a plain connection
loss instead. Owner acceptance item 11 checks it.
If it is lost, the remedy is a lingering close in IronRDP's teardown
(`finalize_and_shutdown`: after `shutdown()`, read and discard until EOF,
bounded by its `DISCONNECT_STEP_GRACE`) — a candidate fourth fork patch
(§4.2); Plan C changes nothing here.

**`clipboard_oversize`** (rev 6.3, Plan D, as built): the session's own
CLIPRDR backend — one per connection, bound to its generation as the GFX
handle is (§8) — sends `RdpInput::Fatal` for a response over
`paste.max_bytes`, and nothing more after it. The pump shell steps it as
`UpstreamFatal` only when it comes from the current link's backend and that
generation is still current: a Preempt candidate's or an evicted session's
is dropped, and so is one read after `on_disconnected`, so no disconnect
is counted that never happens. A failed clipboard response (`CB_RESPONSE_FAIL`) is not a
cause; it ends the paste waiting for it (§8).

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
- Rev 6.3 (as built; DD3, DD5, DD7, DD9): the remap table is DD3's fixed
  one — with `input.mac_remap` on, a report holding Ctrl and one of C, V,
  X, A, Z, F, W carries GUI in that Ctrl's place, applied only when a
  report is built, so the held state and the paste chord (§8) stay raw.
  Unicode key events type through the US layout, with Shift from the
  latest Unicode press alone, and release by code unit; that Shift is
  reported while a Unicode-pressed key is down and never longer, and a
  later scancode press of a non-modifier ends it. Live Unicode key events
  also map the three control units a client in Unicode mode may send for
  keys — CR (U+000D) to Return (0x28), BS (U+0008) to Backspace (0x2A)
  and ESC (U+001B) to Esc (0x29), each with no Shift
  (`keymap::unicode_key_stroke`; PD11b I5, closing PD5 m7 and PD7 m5);
  they follow the released-by-bridge rule like any key, and a fresh
  Unicode Esc aborts a paste as a scancode Esc does (§8). LF was already
  Return. Paste keeps the US layout alone (§8: a pasted CR is a line
  break, BS and ESC are skipped). Whether Windows App actually sends
  these units is still to be seen (acceptance item 12). Caps Lock is the
  last `Synchronize`'s state, toggled by each fresh Caps Lock press
  (DD5). At most 16 non-modifier keys are tracked;
  a press past that, an unmapped scancode (counted on its press only) or
  an untypeable or surrogate Unicode unit is dropped and counted in
  `input_events_ignored` (DD7, DD9). The Keyboard Power usage (`E0 5E`) is
  never sent.

### 7.2 Mouse

- Absolute only: `x_hid = x * 32767 / (w - 1)`, clamped (x = 0 → 0, x = w−1 →
  32767); same for y. w, h are the current surface's (switched at Setup,
  §6.4). This intentionally differs from `kvm.js`'s `floor(x / w × 32767)`.
- Buttons left/right/middle = HID bits 0/1/2.
- Wheel: RDP's ±120-per-notch rotation is accumulated; each whole notch emits
  one wheel frame (§3.3) with the current button mask.
- Rev 6.3 (as built): a button event carries the client's position
  (IronRDP's do), so a click with no move before it lands where it was
  made, never (0, 0); before the first Setup, coordinates scale against
  the advertised size.
  A relative button release (`ButtonRel`) is honoured where the pointer
  is (PD9 I4: a release is always safe); relative motion and presses, the
  X1/X2 buttons, horizontal and ainput scroll are dropped and counted
  (DD7).

### 7.3 HID output path

Rev 6.3 (Plan D): the input handler is built, replacing rev 6.2's
counting stub (DC7). Its state is the input core's (§4.3,
`input::core::InputCore`); each step reads the release epoch into its
context first, builds its reports from the state that epoch left, and
pushes each with `HidControl::push_at(stamp)` — the state and its stamp
taken together — so a report built before a release is dropped whole
rather than landing after the zeros. Every feed carries its reports out
under the core lock, and only input taken on the RDP thread is fed (§4.3).

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
  before a release can re-press a key after it. (Rev 6.2: a report is
  stamped before the queue lock is taken, and dropped whole under it —
  neither queued nor kept as resync state, `Push::Discarded`, counted in
  `hid_epoch_discards` — if a release came in between; so a push racing a
  release can never land after the zeros. A fresh press that loses that
  race is lost, never stuck.)
- While the websocket is down, reports are discarded; reconnect sends the
  session-start sequence. Rev 6.3 (Plan D final review I1): and an open
  that discards reports is a release — when its discard drops anything (a
  queued report, or a resync's state still to go out) it moves the epoch
  and zeroes the resync state under the queue lock, as release-all does,
  counted `release_all{websocket_reconnect}`. The input core then releases
  its state on its next step: keys pressed into the outage become
  released-by-bridge (a reconnect never re-presses anything, §7.4), and an
  active paste aborts (§8) instead of typing the rest of its text with the
  queued first characters gone.
- A websocket write that takes longer than `hid_write_timeout` closes and
  reconnects the websocket (transient, §6.9) — rev 6.2: with a reset, so
  its unsent backlog is discarded, not delivered late (§3.2).
- Rev 6.2 (final review I1): for that timeout to see a KVM that stops or
  slows reading, the websocket's socket has its `SO_SNDBUF` capped at
  16 KiB (`kvm::endpoint::CONTROL_SNDBUF`), set before connect so the
  kernel never autotunes it (Linux doubles the value it is given: 32 KiB).
  Autotuned, it reached 2.6 MB on loopback, and ~45 000 reports — minutes
  of input — were queued in the kernel before any write blocked; a slow
  reader would get a key-up queued behind ~1 MB while the target
  auto-repeated the key held down (§7.4), and the queue's coalescing never
  engages while the writer is never behind. Capped, a HID report being
  ~37 bytes on the wire, under a thousand fit before a write blocks. Plan
  D's L4 sizes the cap from the ES3's measured HID report rate (rev 6.3:
  the test page's, D28; not measured yet, so 16 KiB stands, §4.4).
- Rev 6.3 (DD8, PC9 fix 2): every websocket open re-asserts the full HID
  state once, `input.reassert_after` past its session-start sequence —
  the queue's resync state, the last keyboard and pointer reports pushed
  (zeros after a release, so it never brings a released key back),
  counted in `hid_reasserts` — and only once the queue is drained and no
  release is pending, so it overtakes neither and repeats what the KVM
  should hold anyway. A queue that never drains (motion under
  backpressure) does not hold it for ever: from `reassert_after` past its
  deadline it goes after the next frame written instead of waiting for a
  lull, but only while no keyboard report waits, and without its pointer
  part while pointer reports wait (PD9 m1, re-review R-I1) — the newest
  state written ahead of a queued report would type a key early and then
  again, or break a drag. So it never overtakes a queued report.
- `on_disconnected` sets release-all and then closes over the same ordered
  path, so the release is flushed before the socket closes. Rev 6.3 (Plan D
  final review I2): flushed is not read. The close writes a ping after the
  release, and only the KVM's pong to it (or its answer to the close)
  proves the KVM read it (`HidControl::confirm_read`); a KVM that answers
  no close frame — kvm-sim, perhaps the ES3 — still answers a ping. A
  session end without that proof opens a release websocket (§7.4).

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

Rev 6.3 (Plan D, as built): `Synchronize` and both timers are raised by the
input core (`ReleaseTrigger::Synchronize`, `KeyRepeat`, `ModifierIdle`;
`release_all{trigger}` `synchronize`, `key_repeat`, `modifier_idle`);
every other trigger reaches the core only as a moved release epoch, which
releases its state before the event it comes with. The timers are sans-IO
(`input::core`): each is armed only while something it watches is held,
and fires only on a step — the driver ticks the core at its next deadline,
and an event that arrives after a deadline the driver has not ticked yet
is stepped after a `Tick` whose release is carried out first. A `Pressed`
resets the key-repeat timer only when its key is a non-modifier still held
after it (a new press or a repeat). Released-by-bridge covers keys,
modifiers and buttons (bounded, DD9), every key a paste swallows, and
every non-modifier key the client still holds when a paste starts typing
(§8). One exception (PD5 review m6): after a `Synchronize` the core
forgets every mark. MS-RDPBCGR's Synchronize resets the server's key state
to all keys up, and the client should then send key-downs for what it
still holds (a SHOULD: a key with no key-down after it is simply not
held); so a key held across it is pressed again by its next key-down, and
a stale mark (a `Released` lost after an earlier release) can never
swallow a fresh press — Cmd held across a focus change, then C, reaches
the Mac as Cmd+C, not a typed c. Every other release within a session
keeps the marks, a websocket reconnect included, so a reconnect still
never re-presses anything; a new session (or the end of one) starts the
keyboard clean, marks included.

Rev 6.3 (Plan D final review I2): **a release lands only if the KVM reads
it.** If the session ends while the KVM is not reading — stalled, so the
close's writes block or go unanswered and the websocket is reset with them
unread, or the websocket down in a backoff — the release never arrives,
and a KVM that keeps the last report it read holds Cmd until the next
session. Two mechanisms close that, both built before Leg D answers
whether the ES3 keeps HID state across a websocket loss:

- **The release websocket** (`hid::release`). The bridge tracks whether
  something held — a key, a modifier or a button — was written since the
  KVM last proved it read an all-up state: its pong to the ping written
  after a release, or its answer to a close (`HidControl::kvm_may_hold`).
  A session that ends with that still open makes the KVM actor open one
  more websocket, bounded: the same pinned TLS, the session's token or one
  fresh login when it is refused (none after `kvm_auth_failed`, nothing at
  all after `kvm_cert_mismatch`), never a logout. It writes the
  session-start sequence (§3.3) and a ping; once the pong proves the KVM
  reads, it writes the release once more `input.reassert_after` later —
  past the stale reports the abandoned websocket left in the KVM's buffer,
  as every open does (DD8) — and closes. At most 3 opens, 1 s apart, all
  inside 10 s; it ends with a FIN (it wrote only zeros); counted in
  `release_websockets{outcome}`: `confirmed`, `unconfirmed` (written,
  never proved), `failed`, `superseded`. A new session's `Start`
  supersedes it — aborted and awaited, so the bridge holds one websocket
  at a time, and that session's own open is the release — and a shutdown
  waits for it only what §5.2's KVM step has left. A normal session end,
  the KVM reading, opens nothing.
- **No backoff while input is held.** A websocket lost mid-session while
  the last reports written (or the core's newest state) hold a key or a
  button reopens at once, not after `kvm.backoff`: a KVM that keeps a key
  held across the loss repeats it until the session-start sequence lands.
  Once per loss: a failed reopen backs off as ever, and the reopen's own
  session start holds nothing.

Leg D step 8 (plan Task 1.6) decides whether they are needed, and its
rule keeps both either way: if the ES3 releases its HID state when a
websocket dies, they are extra releases — harmless; if it keeps a key held,
they are required. What neither reaches: a key held while the KVM refuses
every open or stays stalled — mid-session until a reopen lands (backing
off up to `kvm.backoff.max` after the first), after a session end once the
release websocket's 10 s are spent, until the next session — and a crash
(§5.2).

## 8. Clipboard: paste as typing

One way only, laptop → Mac.

1. The user copies on the laptop; Windows App announces its formats over
   CLIPRDR. The bridge records only that text is available. The server
   advertises no clipboard capabilities of its own (rev 6.3, PD8 m5: none
   beyond IronRDP's own `USE_LONG_FORMAT_NAMES` format-list encoding).
   Rev 6.3: "text" is CF_UNICODETEXT in the latest format list — a list
   offering only ANSI text has none — and a list whose first format named
   `FileGroupDescriptorW` has CF_UNICODETEXT's id offers none either
   (PD8 I2): IronRDP takes that first name as the client's file list
   whatever its id, and would parse the answer as a file list, past
   `paste.max_bytes`; a benign client never names a standard format.
2. The user presses the **chord** (default Ctrl+Option+Shift+V), matched on raw
   client scancodes before any remap. Cmd+V can't be used: Windows App rewrites
   it to Ctrl+V. The chord's key is swallowed. A chord with no text announced is
   swallowed and logged. (Rev 6.3: the chord is parsed at load, DD11, §4.4,
   and fires only on a fresh press of its key, never a repeat; a client
   that sends its keys as Unicode units never fires it — acceptance item 13.)
3. The bridge requests `CF_UNICODETEXT` and waits until every physical modifier
   is released; if they are not released within `paste.modifier_wait`, the paste
   is cancelled. (Rev 6.3, DD4: the same bound covers the wait for the text;
   until typing starts, a fresh Esc — scancode or Unicode, swallowed — a
   fresh non-modifier press or a mouse button — both passed through — or
   any release-all (§7.4) cancels the paste, a second chord is swallowed,
   key releases cancel nothing, and modifier presses and releases
   pass through, since the chord's own modifier presses reached the KVM.)
4. The Typist types the text.

**Report sequence.** Each character is one press report and one all-zero
release report; a shifted character carries Shift in the press report's
modifier byte. `paste.pace` separates every report (so ~30 ms per character).
`paste.pace` is provisional: in Leg A an 842-character URL sent at one report
per 20 ms took ~60–90 s to land in Edge's address bar (the omnibox's
per-keystroke work is mixed in), so Plan D (rev 6.2; was Plan C) measures the KVM's own HID report
rate (L4) before the pace is fixed (`census.md`, Derived decisions). Rev 6.3
(DD10): `paste.pace` is then twice the smallest pace at which the ES3 typed
L4's 200-character pattern losslessly three runs out of three (§4.4); Leg D
has not run, so 15 ms stands. And (DD6) the Typist also waits for room in
the HID queue: a step pushes at most 8 − queued reports, each `paste.pace`
after the last, with no catch-up burst, and looks again 2 ms later when
the queue is full — so `paste.pace = 0` (L2) never overflows
`input.queue` into a resync that would lose characters, and the driver
never spins.

While typing:

- **The Typist is the only HID keyboard source.** Client keyboard input is
  swallowed except Esc, which aborts (and is itself swallowed). Mouse motion
  passes through; any mouse button, `Synchronize` or §7.4 trigger aborts.
  Abort and completion both end with an all-zero keyboard report.
  (Rev 6.3: Esc is a fresh scancode Esc or a fresh Unicode ESC, U+001B,
  §7.1; a repeat of an Esc held since before the chord aborts nothing.
  The mouse button itself passes through. Every press swallowed
  while typing is released by the bridge, so its repeats after the
  paste are not fresh presses; and when typing starts, every non-modifier
  key the client still holds is released by the bridge and zeroed at
  once, even if the Typist then has nothing to send.)
- Rev 6.3 (Plan D final review I1): a websocket reopen that discards the
  paste's queued reports — a chord, or typing, that met an outage — is a
  release (§7.3), so the paste aborts (`release`) and types nothing more.
  Without it the reopen dropped the chord's reports and the Typist's first
  presses and typing went on: the Mac received the text less its first
  characters, counted `done` — a lost leading `#` or `cd x &&` changes what
  a terminal runs.
- If the client's last `Synchronize` reported Caps Lock on, the paste is
  refused (typing would invert case). (Rev 6.3, DD5: that state is toggled
  by each fresh Caps Lock press since, as the Mac's is.)

Text handling, in order:

1. A trailing line break (CRLF, CR or LF) is removed; it is never typed.
2. With `paste.multiline = refuse`, text that still contains a line break is
   refused.
3. CRLF, CR and LF each become one Return; Tab is typed; other C0 controls and
   characters the US layout can't type are skipped and counted per Unicode
   scalar.
4. At most `paste.max_chars` characters are typed, counted after steps 1–3.

Rev 6.3 (as built; D4, PD7 m1 and m1-r): the text ends at CF_UNICODETEXT's
U+0000 terminator — nothing after it is text, or counted — and each
ill-formed UTF-16 unit is one U+FFFD, skipped and counted at step 3. The
scalars step 3 skips are dropped before step 1 (CR excepted: it is a line
break), so no skipped unit changes which break is the trailing one: a
trailing break followed only by skipped units is still removed, and a
skipped unit between a CR and its LF never splits that CRLF into a typed
Return and a removed LF. Skips are counted only while `max_chars` has
room.

Limits and hygiene:

- IronRDP reassembles the whole client-declared SVC/DVC payload (up to 4 GiB)
  before the bridge sees it — CLIPRDR included; there is no declared-size hook.
  A response larger than `paste.max_bytes` after reassembly is discarded and the
  session dropped (cause `clipboard_oversize`). Memory during reassembly is
  bounded only by the memory limit (container or systemd); OOM-kill on an
  abusive NLA-authenticated client is the accepted failure mode. An upstream
  reassembly cap for SVC and DVC is tracked in the pin review. (Rev 6.3:
  the CLIPRDR backend checks a response's length before it copies a byte;
  over the cap it ends the session through `RdpInput::Fatal`, §6.9, says
  nothing more, and the paste that asked counts `oversize`.)
- Contents are never logged; `FormatDataResponse` is never `Debug`-formatted.
- Deployment must enable the channel or CLIPRDR never opens: rdpgw needs
  **`Caps.EnableClipboard: true`**. Without it rdpgw sends
  `HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD` and FreeRDP leaves `cliprdr` out of
  its channel list; with it, `cliprdr` is requested and given an MCS channel
  (`census.md`, Leg C; clipboard data itself is Plan D's to test, rev 6.2;
  rev 6.3: L2 tests it over real CLIPRDR, §11.3).
  `redirectclipboard:i:1` is rdpgw's own default, so rdpgw leaves it out of
  the `.rdp` (it writes no field equal to its default) and the client's
  default applies. Whether Windows App obeys rdpgw's redirect flags is an
  acceptance item (§12).
- Milestone 4 compares our typing with the KVM's own `hid.lua?type=text`
  endpoint; ours stays the default unless the device's paces better.
  Rev 6.3: that comparison is deferred to Plan E's perf pass (controller
  ruling, 2026-10-14); ours stays the default.

**Clipboard answers** (rev 6.3, as built; PD9 carry 3, review I2,
re-review m-R1 and m-R2). CLIPRDR answers data requests in order, and
IronRDP forwards every answer, asked for or not, so the input core counts
the requests it has made this generation and not seen answered, and an
answer — text, a failure, the fatal oversize, or one the backend dropped
in flight — belongs to the oldest of them. Only the pending paste whose
own request that is takes it; any other text or failure answer is
discarded and counted (`clipboard_discarded{late}`, or `{unasked}` with
none outstanding), so a paste never types the answer to an earlier one
that timed out — an answer dropped in flight is counted `{in_flight}`
instead (below), and an oversize one ends the session. A failed
answer (`CB_RESPONSE_FAIL`, the client's or IronRDP's own) ends the paste
waiting for it at once, not at `paste.modifier_wait`. An answer IronRDP
parsed as a file list — a client that renamed a format between the chord
and the request — reaches the core as an answer with no text, like a
failure, so the count stays true; one that does not parse as a list comes
through raw, under `paste.max_bytes` like any other. The backend keeps at
most one
availability word and one answer in flight to the pump shell per
connection; an answer that comes meanwhile is dropped before a byte is
copied and counted (`{in_flight}`), and still answers its request. A
request no answer has come for would shift every later answer onto the
request before it for the rest of the session, so each keeps its instant
and is retired, counted `{unanswered}`, once `max(60 s, 2 ×
paste.modifier_wait)` old — never while its own paste still waits —
when the next paste starts or the next answer comes. Two residuals are
accepted:

- Retirement goes by age, so with a client that leaves a request
  unanswered, a paste made before that request is retired takes the
  phantom's place with its own prompt answer (discarded, `late`), and its
  own request becomes the phantom, with a fresh age: retrying within 60 s
  moves the drift forward, and only a 60 s pause in paste attempts heals
  it. Ending the chain would let a paste take an answer while an older
  request may still be answered.
- An answer more than 60 s late, once its request is retired, pairs with
  a newer one and can be typed. CLIPRDR's format data responses carry no
  request id, and with delayed rendering a merely slow answer carries the
  clipboard as of answering; stale content needs a transport stall over
  `request_retire` (60 s). While video flows to the client, that stall
  closes the EGFX gates and `video.stall_timeout` (10 s) ends the session
  as `client_stalled` first. It does not while the client has suppressed
  its display (`Paused`) or is reactivating (`WaitReactivation`), when the
  stall timer is frozen, nor while it suspends acks, when the stall timer
  is off and only a backlog held at `backlog_limit` for `stall_timeout`
  ends the session (§6.6): there the residual stands.

At most 64 requests are outstanding (ironrdp-cliprdr's own cap): a paste
past that is refused locally and asks nothing (`paste_events{backlog}`) —
IronRDP would fail the request itself, and that failure would be taken
for the oldest request's answer.

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
     (Rev 6.2: Plan C builds no `test-insecure` feature at all — Hybrid is
     the only mode in any build, L2 included. A client that does not offer
     CredSSP is refused at the X.224 negotiation with a plain disconnect, not
     a "CredSSP required" reply — IronRDP's acceptor sends none — so such a
     client reports a generic connection failure.)
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
     App has not been tried with one.) Rev 6.2: nothing enforces RSA — the
     key's type and size are logged at INFO when the identity loads (`TLS
     identity loaded`, `key_type`, `key_bits`) and left to acceptance item 9;
     aws-lc-rs refuses a key it cannot sign with (RSA under 2048 bits, an
     unsupported curve) at startup, `TlsError::UnsupportedKey`, with no key
     bytes in the error.
   - `on_accept` rate-limits attempts (`security.accept_rate`; rev 6.2:
     admitted attempts only, DC15, and a refusal is logged once, then at most
     one line per 10 s with a count, `REFUSAL_LOG_INTERVAL`, so a TCP flood
     does not become a log flood; `kvm_rdp_accept_refused` counts every one).

### 9.2 Secrets and logging

KVM password, NLA password, TLS key, the KVM token, keystrokes, HID frames and
pasted text are never logged (§4.5). Secrets come only from files (§4.4).
Rev 6.2 (final review C1): nor is any `*_file` key's value, in an error, a
log line or a `Debug` — an operator may write the secret, or paste the PEM,
where the file name goes; a file that cannot be read is named by its key.
Rev 6.3 (PD5 ruling; Plan D): keystrokes and pasted text are as sensitive
as a password, so no type that holds them derives `Debug` — HID frames
and queued reports, the keyboard, pointer and paste state, US-layout
strokes, prepared text and the Typist, the input core's events and
outputs, and the clipboard's words to the pump: each shows its kind and
counts only. The input path logs paste activity as metrics and one line
(a chord with no text offered, which names no content). DC9's secrets
case is the proof (§11.3).

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
| Bridge crash, or a session end the KVM does not read, with a key held | `panic = "abort"`; a release is sent on every orderly path — rev 6.3 (Plan D final review I2): it lands only if the KVM reads it, so a session end the KVM did not prove released (no pong to the ping after the release, nor an answer to the close) opens one bounded release websocket, and a websocket lost with input held reopens without its backoff (§7.4) | Depends on the KVM's behaviour on websocket loss (Plan D's L4, §12; rev 6.2). Rev 6.3: `kvm-probe hid-hold` measures it for a close, a FIN and a reset; Leg D has not run, so it is still unknown. Leg D step 8's rule: if the ES3 releases on websocket loss, the release websocket and the immediate reopen are harmless extra releases; if it keeps a key held, they are required — both ship either way. A crash cannot release (§5.2), nor can a release websocket the KVM never takes within its 10 s |
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

**The registry as built** (rev 6.2, Plan C's `kvm_rdp::metrics`). Counters
and labelled families are exposed with `_total`; label values are fixed
strings from bridge code, never device or client text. Paste events and
skipped characters are Plan D's, allocations per frame Plan E's. Rev 6.3
(Plan D's `kvm_rdp::metrics`, as built): 44 families — 18 counters, 13
labelled families, 8 gauges and 5 histograms, a count `metrics`'s own test
pins (the final review's I2 added `release_websockets`); Plan D's rows are
marked.

| Metric | Kind | Labels (values) |
|---|---|---|
| `kvm_rdp_flv_bytes_total`, `kvm_rdp_flv_tags_total` | counter | — (main stream only) |
| `kvm_rdp_kvm_frames_total` | counter | `type`: `idr`, `p` |
| `kvm_rdp_kvm_frame_bytes` | histogram (bytes) | — (VCL bytes per admitted AU) |
| `kvm_rdp_kvm_inter_arrival_seconds` | histogram | — |
| `kvm_rdp_kvm_fps` | gauge | — |
| `kvm_rdp_parse_errors_total` | counter | `kind`: the framing violation (`kvm_proto::video::AdmissionError::kind`), e.g. `oversize_tag`, `bad_prev_tag_size`, `encrypted_tag`, `bad_stream_id`, `nal_before_sequence_header`, `start_code_in_nal`, `not_one_picture`, `unknown_tag_type`, `too_many_nals` |
| `kvm_rdp_upstream_reconnects_total` | counter | `reason`: FLV — `eof`, `idle`, `end_of_sequence`, `framing`, `commanded_failed`, or a failed open's or read's `KvmError` kind (`timeout`, `connect`, `tls`, `http`, `protocol`); websocket — `websocket_open`, `websocket`, `websocket_write` |
| `kvm_rdp_kvm_logins_total`, `kvm_rdp_kvm_relogins_total` | counter | — |
| `kvm_rdp_idr_requests_total` | counter | `kind`: `side`, `reconnect` |
| `kvm_rdp_idr_side_failures_total` | counter | `kind`: `busy`, `no_token`, `cert`, `task`, or the `KvmError` kind (`auth`, `timeout`, `connect`, `tls`, `http`, `protocol`, `eof`) |
| `kvm_rdp_idr_side_fallbacks_total`, `kvm_rdp_idr_cancelled_total` | counter | — |
| `kvm_rdp_sps_rewrites_total` | counter | `field`: `level`, `vui`, `restriction` |
| `kvm_rdp_sps_changes_total` | counter | `class`: `initial`, `resize`, `other` |
| `kvm_rdp_burst_frames_total` | counter | — |
| `kvm_rdp_egfx_frames_sent_total`, `kvm_rdp_egfx_frames_acked_total` | counter | — |
| `kvm_rdp_frames_dropped_total` | counter | `reason`: `soft_gate`, `backlog_gate`, `standing_delay`, `backpressure`, `burst_truncated`, `send_none`, `awaiting_idr`, `not_ready`, `channel_full`, `paused`, `wait_reactivation`, `closing`, `repeat`, `replay_diverged` |
| `kvm_rdp_enqueue_latency_seconds` | histogram | — |
| `kvm_rdp_egfx_ack_rtt_seconds` | histogram | — |
| `kvm_rdp_egfx_qoe_decode_seconds` | histogram | — (QoE, V10+ clients) |
| `kvm_rdp_egfx_in_flight`, `kvm_rdp_egfx_backlog_bytes`, `kvm_rdp_egfx_ack_suspended`, `kvm_rdp_egfx_oldest_unacked_ms`, `kvm_rdp_autodetect_rtt_ms`, `kvm_rdp_standing_delay_ms`, `kvm_rdp_egfx_capability_version` | gauge | — |
| `kvm_rdp_hid_reports_sent_total`, `kvm_rdp_hid_reports_coalesced_total`, `kvm_rdp_hid_resyncs_total`, `kvm_rdp_hid_epoch_discards_total` | counter | — |
| `kvm_rdp_hid_reasserts_total` (rev 6.3) | counter | — (full-state re-asserts after a websocket open, DD8, §7.3) |
| `kvm_rdp_release_all_total` | counter | `trigger`: `session_start`, `session_end`, `closing`, `watchdog`, `shutdown`, `websocket_reconnect`, `suppression`; rev 6.3: `synchronize`, `key_repeat`, `modifier_idle` (the input core's, §7.4) |
| `kvm_rdp_sessions_total` | counter | — |
| `kvm_rdp_disconnects_total` | counter | `cause`: §6.9's causes (`shutdown`, `kvm_unreachable`, `stream_corrupt`, `stream_incompatible`, `no_avc420`, `client_stalled`, `clipboard_oversize`, `kvm_auth_failed`, `kvm_cert_mismatch`) — bridge-initiated only |
| `kvm_rdp_accept_refused_total` | counter | — |
| `kvm_rdp_input_events_ignored_total` | counter | — (Plan C's input stub; Plan D replaces it). Rev 6.3: it keeps the name and means client input dropped — unmapped, untypeable or past a bound (DD7, DD9), taken off the RDP thread (§4.3), or arriving with no session live |
| `kvm_rdp_paste_events_total` (rev 6.3) | counter | `outcome`: `started`, `done`, `no_text`, `caps_lock`, `multiline`, `oversize`, `backlog`, `aborted` (§8). A paste that starts counts `started`, then one of `done`, `multiline`, `oversize` and `aborted`; one refused at the chord counts only `no_text`, `caps_lock` or `backlog` |
| `kvm_rdp_paste_skipped_chars_total` (rev 6.3) | counter | — (scalars §8's text handling skipped, counted when a paste is done) |
| `kvm_rdp_clipboard_discarded_total` (rev 6.3) | counter | `reason`: `late`, `unasked` (answers no paste took), `in_flight` (dropped by the backend while another was in flight), `unanswered` (requests retired with no answer) — §8's clipboard answers |
| `kvm_rdp_release_websockets_total` (rev 6.3, final review I2) | counter | `outcome`: `confirmed` (the KVM's pong after the release), `unconfirmed` (written, never proved), `failed` (no open carried it), `superseded` (a new session, or the exit, ended it first) — the release websocket after a session end the KVM did not prove released (§7.4) |

`frames_dropped` counts frames, not gate events (rev 6.2): a frame a gate
drops counts that gate's reason — in Live, `burst_truncated` for a burst AU
dropped at the backpressure gate; in NeedIdr a burst IDR that meets that gate
counts `backpressure` — and a gate closure the 50 ms tick notices first drops no
frame and counts nothing. A P frame dropped while in NeedIdr
counts `awaiting_idr` whatever the gates say, so `soft_gate` counts only an
IDR (or a live AU that beats the tick) that meets the closed gate. `repeat`
and `replay_diverged` are §6.5's replay rule after a `ReconnectFlv` swap.

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
| L1 sans-IO | `kvm-rdp` | `Pump::step` and `GraphicsPipelineServer` in memory, its output decoded with IronRDP's own PDU types (rev 6.2: not `GraphicsPipelineClient`, whose handler consumes the PDUs the cases assert; every `WireToSurface1` is checked to be AVC420) (cases below). IronRDP goldens: `encode_avc420_bitmap_stream(full_frame(640,360,22))` bytes and the ResetGraphics monitor bytes — required on every pin bump |
| L2 full stack | `kvm-rdp` (one test binary) | Bridge + kvm-sim + in-process IronRDP client over loopback (§11.3) |
| L3 interop | CI, `#[ignore]` test | FreeRDP 3 from the flake (§11.4) |
| L4 hardware | opt-in | `kvm-probe` and `--features hil` tests against the real ES3 (§11.6) |
| L5 manual | checklist | Windows App direct and through rdpgw (§11.6) |

Rev 6.3 (DD2): the L0 row's input cores — the release epoch and the
released-by-bridge rule, both key timers, paste pacing — are the input
core's, so they are `kvm-rdp` unit tests with an injected clock (beside
`hid::queue`'s), not `kvm-proto` L0; `kvm-proto`'s L0 keeps the scancode
table (against Microsoft's, §11.1), the US layout, `scale_abs` and §8's
text handling and Typist.

L1 cases:

- **Every cell of the §6.4 state × input table**, one case each.
- Each replayed `CapabilitiesAdvertise` yields exactly the
  CapabilitiesConfirm recorded in `census.md`; only AVC420 `WireToSurface1` is
  ever sent. FreeRDP's are recorded (Leg B): with `/gfx:AVC420`, `V8`
  `02000000` and `V8_1` `12000000` → `V8_1`; without it, an 11-set ladder
  `V8`…`V10_7` → `V10_7` (`census.md` names these sets but not their bytes,
  so they are captured from the flake's FreeRDP — by Plan E's L3 since rev 6.2); byte-identical through
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
  which `pin_goldens.rs` pins; rev 6.2: the fallback is not built); backlog
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
  KVM AU is an IDR carrying SPS/PPS. Rev 6.3 (PC17 m1, Task 5.3): a
  `ReconnectFlv` candidate whose replayed P frame differs from the one the
  client already has is dropped (`frames_dropped{replay_diverged}`, §6.5)
  and the picture recovers at the next IDR; the client never gets the
  altered frame, an AU twice, or a P frame out of sequence.
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
  (closed at the 4 KiB limit without buffering, reconnect, RSS bounded —
  rev 6.2, DC24: shown by construction, Task 3.3's unit test erroring at the
  4 KiB frame limit with nothing buffered and the L2 reconnect, because the
  in-process bridge shares the test process's RSS; and measured once on the
  real binary as a subprocess, where kvm-sim declares 64 MiB and sends 4 KiB
  of it: peak RSS (`VmHWM`) ≈ 30.5 MiB before and +8 KiB after — which shows
  only that nothing sized from the declared length was touched, since pages
  allocated but never touched are not resident; the 4 KiB cap is what bounds
  it), KVM
  unreachable (disconnect at the deadline), wrong KVM certificate (no login
  request; `kvm_cert_mismatch`). Rev 6.2: a certificate that changes
  mid-session, after a good login, on the websocket — fatal at once, its
  writer idling rather than reconnecting — is not exercised until kvm-sim
  can swap its certificate; Plan D's (PC7 W10). Rev 6.3: exercised (Task
  5.3) — kvm-sim swaps its certificate mid-session and drops the
  websocket; the reopen fails the pin: `kvm_cert_mismatch` at once, no
  re-login, no logout, no websocket upgraded and no further control
  connection.
- **Stalled client** (asserted on `/metrics`, not timing): withheld acks →
  after the bridge's first soft-gate drop (`frames_dropped{reason="soft_gate"}`
  > 0) its sent-frame counter does not advance again before Closing,
  `egfx_in_flight` ≤ hard throughout, and the session closes with
  `client_stalled` (rev 6.2: a `soft_gate` drop needs an IDR — or a live AU
  that beats the tick — to meet the closed gate, §10.4, so the case's
  `stall_timeout` must exceed the source's IDR interval); a client that **stops reading** → the session still ends
  (Closing + watchdog + abort) and kvm-sim sees the websocket and FLV close
  (and no logout); a client that
  suspends acks but keeps reading is never disconnected.
- **Input**: every input event → byte-exact HID frames; a full queue resyncs to
  the correct final state; a blocked websocket write reconnects; with reports
  queued behind a blocked write, a release trigger produces only the zero
  reports and then current state — no queued report is sent after it; a
  websocket reopen's session-start sequence carries the pointer report at the
  last position sent, and none before the client's first pointer event — never
  (0, 0) unless the client put the pointer there. Rev 6.2 (DC7): Plan C's L2
  drives the HID writer through `HidControl` directly — reports reach kvm-sim,
  a full queue resyncs, a blocked write reconnects (final review I1: within
  a bounded number of reports written, and with at most 400 of the old
  websocket's reports reaching kvm-sim after the new one opens — a reset,
  where a FIN delivers its whole send buffer), a reopen restores the
  pointer, the websocket survives another session's logout — and the
  input-event cases (RDP input → HID frames) are Plan D's, with its handler.
  Rev 6.3: built (Task 5.1) — the cases above run through the real handler
  from an in-process IronRDP client, a click with no prior move lands
  where it was made, and (Task 5.3) a reconnect's re-assert carries the
  current state once more, `reassert_after` later — zeros for a key held
  across it, which stays released by the bridge.
- **Stuck keys**: every §7.4 trigger releases all; a key held across a release
  is not re-pressed by later repeats until its `Released` (rev 6.3: a
  `Synchronize` excepted — it forgets the marks, §7.4 — so the case holds
  the key across a websocket reconnect); typematic repeats at
  0.2× the timeout for 2× the timeout → no release; no repeats → release; two
  keys held with repeats of the second only → no release; mouse motion never
  resets the timers. Rev 6.3 (Plan D final review I2): a session that ends
  while kvm-sim is not reading (Cmd held, its buffer full, reads paused)
  ends released once it reads again; one that ends with the websocket down
  is released by the release websocket once kvm-sim takes one; and the
  release websocket gives up inside its 10 s, after at most 3 opens, never
  logging out.
- **Paste**: `"a\r\nb\tc\u{1F600}\n"` → the exact report list (one Return, Tab,
  emoji skipped and counted, no trailing Return); `multiline = refuse` refuses
  `"a\nb"` but types `"a\n"`; a key pressed mid-typing never reaches kvm-sim;
  Esc → a strict prefix, then the zero report, and usage 0x29 never sent; a
  mouse click aborts; modifiers held past the (scaled) wait cancel; Caps Lock
  on refuses; the chord key never reaches kvm-sim; 64 KiB + 2 bytes → session
  dropped, nothing typed; 64 KiB − 2 bytes → typed up to `max_chars`; an 8 MiB
  payload, fully sent → `clipboard_oversize`, nothing typed. Rev 6.3: built
  (Task 5.2), over real CLIPRDR from the in-process client, which answers
  only the CF_UNICODETEXT it holds, terminator included.
- **Admin**: `/livez` goes stale when the `LocalSet` is blocked; `/readyz`
  succeeds without a KVM. Rev 6.2 adds: a flood past the 32-connection cap —
  each connection past it is dropped unanswered although it sends a full
  `/livez` request, the session keeps streaming, and `/livez` answers again
  once the server has timed the held ones out; SIGTERM to the real binary
  with a client connected and the KVM unreachable → ErrorInfo 0x1 and exit 0
  within 5 s; a `Quit` a live connection consumes ends only it, and a second
  stops the server.
- **Secrets hygiene** (subprocess, reusing kvm-bench's spawn harness), with
  `SSLKEYLOGFILE=<tmp>` set only in the bridge subprocess's environment (`Command::env`; the test process, kvm-sim and the in-process IronRDP client — whose `ironrdp-tls` config honours the variable — run without it), two runs: `log.filter = "trace"`,
  and `log.filter = "kvm_rdp=trace,ironrdp_acceptor::credssp=trace,sspi::ntlm=trace"`.
  Each completes NLA with a password canary, types a sentinel string through RDP
  keyboard input, and pastes a text canary. Capturing stdout and stderr:
  neither canary, nor the sentinel, nor the hex of its 12-byte HID frames
  appears; no `NTLMSSP` or `TlRMTVNTUA`; no DEBUG/TRACE lines from `ironrdp_*`
  or `sspi`; at least one TRACE line from bridge code appears (the filter took
  effect); `<tmp>` is never created. Rev 6.2 (DC9, P10, P48): Plan C's case
  runs without the keystroke sentinel and paste canary (Plan D adds them)
  and spawns the binary itself through `CARGO_BIN_EXE_kvm-rdp`, with its
  environment cleared and then given `SSLKEYLOGFILE` and `RUST_LOG=off` — a
  bridge that read `RUST_LOG` would log nothing and never report ready; the
  log is checked only once both pipe readers have drained, and must hold the
  shutdown's own last lines. Rev 6.3 (DC9, Plan D): the case now types the
  keystroke sentinel and pastes the canary, and is the proof §9.2 rests
  on. In stdout, stderr and `/metrics` (read before the SIGTERM) it
  forbids each encoding of either string it enumerates — the text, its
  characters, bytes and code units, each keystroke's frame, key slots and
  codes, in hex, decimal and base64 — and every 6-character fragment of
  either. A
  line from the input path must be one of a reviewed list, each field in
  its value's shape (an integer, a boolean or a word from a fixed list), so
  no reviewed line can carry free text; a bridge log target outside the
  reviewed lists fails the case; every `/metrics` name and label is the
  bridge's own vocabulary; and no `Debug` the input path could emit shows
  what was typed or pasted. Two residuals are accepted: a lone number
  equal to one key code or code unit — a `/metrics` sample value, or an
  integer field of a reviewed line — and a line logged under a reviewed
  target outside the input path, which faces the encoding and fragment
  checks but not the value shapes.

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
  uses it, and a source-burst case keeps the default `FrameCount` (with
  `burst_on_connect` for a replay on connect) — under `WallClock` a replay
  is stamped live (rev 6.2).
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
- Plan D's L4 (rev 6.2: moved from Plan C, which has no HID input path; Plan D's first task, before its `paste.pace` and stuck-key work) also carries what Leg A handed on (§12, §15): the Mac's
  behaviour when the websocket dies with a key held, side request → main-FLV
  IDR latency over 20 trials (one-token concurrency seen once in Leg A), how a preset
  change is signalled, how long an abandoned token stays valid, and the KVM's
  HID report rate. Plan C adds (rev 6.2): the ES3's refusal forms for an FLV
  and a websocket after a global logout (status, Content-Type, body — they
  confirm §6.9's auth classifier, which treats a 200 whose body is JSON
  rather than FLV as a refusal); whether the ES3 refuses a second FLV on the
  same token (a KVM that does is `kvm_auth_failed` at the second refused
  `ReconnectFlv`); how the ES3 closes a websocket — a close frame or a bare
  EOF (the bridge treats only a close frame as an answered close, §3.2);
  and the lag between the old FLV's forced IDR and a `ReconnectFlv`
  candidate's first tag (§6.5's replay ring holds 64 AUs, about 2 s).
- Rev 6.3 (Plan D; DD1): each of these checks but the preset change is a
  new `kvm-probe` subcommand, proven against kvm-sim in kvm-sim's own test
  binary — `hid-hold` (the websocket ended by a close, a FIN or a reset
  while a key is held),
  `concurrent-flv` (side request → forced main-FLV IDR over 20 trials,
  same-token refusal and its form, the forced-IDR → candidate lag and how
  many AUs a swap would replay), `token-life` and `session-cap` (the
  abandoned token's life and a session cap; each runs only with the
  owner's consent, since its logins could evict the owner's web-UI
  session), the HID test page with `hid-type` (the KVM's HID report rate,
  read off the page — it sizes `CONTROL_SNDBUF` and enters
  `input.reassert_after`'s rule — and the smallest pace typed losslessly,
  which sets `paste.pace`), `refusal-forms` (a never-issued token,
  and none), `ws-close` (the close form) — and one new check,
  `hid-stale`: whether stale reports land after a fresh session start,
  which decides `input.reassert_after` (§4.4). A preset change uses
  Plan A's `capture` and `summarize` while the owner changes it. The forms
  after a global logout, and the control websocket's survival of another
  session's logout, come only from `logout-watch`, which watches while the
  owner logs out in the vendor web UI and never sends a logout (DD1). The
  probe sees the Mac only through the KVM's own video — a committed HID
  test page the owner opens, and `snapshot`, which decodes one fresh IDR
  in the sandbox to a PNG under `captures/` — types only a generated
  pattern into that page, and ends every HID command released (Ctrl-C,
  SIGTERM, SIGHUP and SIGQUIT included; `hid-release` from a fresh process
  after a kill). No HID burst it sends is unbounded, and a bound passed is
  refused before anything is sent (PD3): `hid-type` types at most 500
  characters a run (`MAX_CHARS` — at pace 0, 2 × 500 + 2 reports, under
  DD8's ~1 800-report receive window), waits at most 100 ms after each
  report (`MAX_PACE` — a press is held for one pace, under macOS's
  shortest delay until repeat, about 225 ms, a figure from memory rather
  than measured, so the page never auto-repeats), and takes at most 10
  runs per pace and 8 paces (`MAX_RUNS`, `MAX_PACES`); `hid-hold` watches
  its one held key for at most 10 s (24 s at most before its release
  starts, every step bounded), and `hid-stale` sends one 128-report
  burst. The run on the ES3 (Task 1.6; Leg D in `census.md`) is
  pending (owner): until it runs, every question above stays open (§15).
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
  held moved to Plan C's L4 — Plan D's since rev 6.2 — (it needs HID input, which the probe never
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
  committed with its bytes as a separate fixture file (captured, since rev 6.2 by Plan E's L3,
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
| C | M3a: config, logging, admin endpoints, metrics, shutdown, lifecycle, NLA, EGFX pump and state machine, the websocket, the HID writer skeleton and release epoch, L1 and video/lifecycle L2. Requires the three IronRDP patches of `kvm-rdp-egfx-patches-v2` @ `c99eece2`, git-pinned (§4.2; rev 6.2: the patch-1 fallback is not built) |
| D | M3b + M4: first §11.6's L4 hardware checks (rev 6.2, moved from C); keyboard and mouse mapping, stuck-key timers and the released-by-bridge rule, the Typist, and their L2 cases (rev 6.3: built, with CLIPRDR paste, the re-assert and Plan C's L2 carries; the L4 checks are tooling proven on kvm-sim, and their run on the ES3, Task 1.6, is pending (owner) — DC18's items are built, not yet measured) |
| E | M5 + M6: L3, CI, image, perf pass (rev 6.2: CI's job timeout, tracked-secrets gate and target-budget step landed with Plan C, DC19; rev 6.3: also the carries below) |

**Carried to Plan E** (rev 6.3: one list, from Plan C's final review and
Plan D's rulings):

- `--remap-path-prefix` (or `trim-paths` once stable) in the image build,
  so no build-host source path reaches an error message (PC15).
- Actions pinned by SHA, and `cargo deny` (licences and advisories) over
  the production graph.
- §10.1's allocation budget, including PC14 n4 (one extra `Vec` copy per
  AU in the pump's `step`) and the per-chunk `Vec<FlvTag>`.
- A minimum frame size in admission: a hostile SPS can resize the client
  to a tiny desktop (16×16) — e.g. refused below MS-RDPBCGR's 200 px as
  `stream_incompatible`.
- Gating the `RdpInput::Stall` test hook (a `std::thread::sleep` on the RDP
  runtime, reachable only through a hidden test handle) behind a
  non-default feature.
- IronRDP's format-list amplification (PD8 m3): `get_formats` builds the
  client's whole format list, about 5–10× its wire size, before the
  backend runs, and `paste.max_bytes` caps only responses — the
  reassembly class §8 accepts; a format-count cap joins the pin review's
  upstream-cap note.
- Milestone 4's comparison of our typing with the KVM's
  `hid.lua?type=text` (§8), in the perf pass.
- A nightly L2 run under a CPU stressor at the wrapper's nice 19, so
  load-sensitive cases surface in CI rather than on the shared host.
- The disk pass: pruning the stale incremental cache
  (`target/debug/incremental`).
- kvm-bench measuring how often the KVM → pump channel fills (PC17 m2): an
  AU dropped there mid-replay freezes the picture until the next IDR
  (≤ 2 s), accepted as designed (DC12).
- Rate limiting IronRDP's per-PDU WARNs past the INFO cap (PD8 m4):
  `ironrdp_server`'s "Unexpected channel received" lets an authenticated
  client cause one WARN per PDU (pre-existing; `ironrdp_cliprdr`'s are
  held at ERROR since rev 6.3, §4.5).

Not carried: bounding the admin response write and shutdown — Plan C did
it (§4.5, rev 6.2).

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
   real Ctrl+key, §7.1); committed as the remap-table fixture. Rev 6.3:
   `mac_remap` switches DD3's fixed table (Ctrl + C, V, X, A, Z, F, W →
   GUI), so the capture must also show that table is exactly Windows
   App's rewrite before it ships on; `key_repeat_timeout` stays 10 s until
   this capture retunes it.
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
11. **A fatal cause at session start** (rev 6.2, Plan C). Does Windows App
    show the cause when the session ends before its first picture — e.g.
    `kvm_auth_failed` (0x9: a wrong `kvm.password_file`), `kvm_cert_mismatch`
    (0x9: a wrong `kvm.spki_sha256`) or `no_avc420` (0x7) — and stay
    without auto-reconnecting, direct and through rdpgw? IronRDP writes the
    ErrorInfo and closes at once, so a real client may lose it to a reset
    (§6.9). Lost: carry the lingering-close patch to the fork (a candidate
    patch 4, §4.2, §6.9) and re-check.
12. **Return, Backspace and Esc as Unicode units** (rev 6.3, Plan D: PD5
    m7, PD7 m5) — resolved in code. A client in its Unicode keyboard mode,
    or through an IME, may send Return, Backspace or Esc as the units
    U+000D, U+0008 and U+001B rather than as scancodes. Without a mapping
    they would never reach the Mac — Enter and Backspace lost, Esc doing
    nothing, not even aborting a paste — so the bridge maps them to
    Return, Backspace and Esc, and a Unicode Esc aborts a paste (§7.1,
    §8). Still to confirm: whether Windows App sends them so at all, and
    that they then work.
13. **The paste chord in Unicode mode** (rev 6.3, PD7). The chord is
    matched on raw scancodes only (§8), so a client that sends its keys as
    Unicode units never fires it. Check that Windows App sends
    Ctrl+Option+Shift+V as scancodes, direct and through rdpgw.
14. **The HID test page in Edge** (rev 6.3; L4's, not Windows App's — the
    owner checks it at the start of Task 1.6). The committed page opens
    on the Mac as a `data:` URL in Edge, and a Right Ctrl tap resets its
    counters (the probe never sends Esc). If it does not, Leg D's HID
    steps cannot be read.

## 13. Development resource budget

The host is shared and loaded (16 cores, ~12 GiB free RAM, 143 GB free disk at
83% use). The rules are mechanical, not advisory:

- `.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"`
  (CI overrides with `CARGO_BUILD_JOBS`).
- The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20
  -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`, falling back to `nice`
  without user systemd.
- One shared `CARGO_TARGET_DIR` across long-lived worktrees, never one per worktree — except disposable scratch worktrees, which set their own and delete it when done (rev 6.2: a shared-target test binary bakes in its worktree's path and breaks once that worktree is deleted).
- Committed rust-analyzer settings: `check.extraArgs = ["--jobs=2"]` and the
  same target dir.
- Profiles: `[profile.dev] debug = "line-tables-only"`, dependencies
  `debug = false`; `[profile.release] lto = "thin", codegen-units = 16,
  debug = "line-tables-only", panic = "abort"`; `[profile.bench]` inherits
  release; no fat-LTO profile. One integration-test binary
  (`autotests = false`); `CARGO_INCREMENTAL=0` in CI.
- ffmpeg runs under `nice -n 19` with `-threads 4`.
- Budget (**rev 6.2**): IronRDP's graph puts debug + tests far past the ~1.5 GB once estimated; `scripts/target-budget.sh` fails the gate above `KVM_RDP_TARGET_BUDGET_GIB` — default: 8 GiB, Task 2.1's floor, which stands: 3.31 GiB measured once Plan C's binary and L2 executable existed (2.4 GiB after Task 2.1) × 1.3 is 4.3 GiB, under it; 3.42 GiB at Plan C's end — and names the one safe cleanup, `cargo clean`; `[build] incremental = false` is committed. CI runs the same script after its tests (DC19).
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

Open for Plan D's L4 (§11.6; rev 6.2): what the Mac sees when the websocket dies with
a key held (moved from Leg A); side request → main-FLV IDR latency over 20
trials (Leg A saw it once, on one token: the ES3 serves two concurrent FLVs
on the same token); how a preset change is
signalled (Leg A: n = 1, tentative); how long an abandoned token stays valid
and whether the ES3 caps concurrent sessions (the bridge never logs out, so
every RDP connection leaves one token to lapse); the KVM's HID report rate
before `paste.pace` is fixed (§8); and the four checks Plan C added (§11.6,
rev 6.2): the refusal forms after a global logout, same-token FLV refusal,
the websocket close form, and the forced-IDR → candidate lag. Still to be recorded in `census.md`: the
firmware version (from the UI's about page).

Rev 6.3: still open, for Leg D. Plan D built every one of these checks as
a `kvm-probe` subcommand proven against kvm-sim (§11.6), and added one:
whether stale reports land after a fresh session start (`hid-stale`),
which decides `input.reassert_after` (§4.4). The run on the ES3 (Task 1.6,
`census.md` Leg D) is pending (owner), so nothing here is settled yet, and
`paste.pace` (15 ms), `CONTROL_SNDBUF` (16 KiB) and `input.reassert_after`
(1 s) keep their written defaults. Even after Leg D, the refusal forms
after a global logout and the control websocket's survival of another
session's logout stay "not measured" (DD1) unless the owner runs Task
1.6's optional logout step; the never-issued-token, no-token and
lapsed-token forms Leg D measures stand in for them.

Watched: the IronRDP fork branch `kvm-rdp-egfx-patches-v2` and, once the owner
opens it, its upstream PR (§4.2); IronRDP API churn and an upstream SVC/DVC
reassembly cap (monthly pin review); rdpgw's legacy-transport refusal in
token mode (#185) and any pin past `16cdaaf` (§9.4); FLV source latency —
*open*, not measured by the census: if SRS buffers ~350 ms, the WebRTC
source on :1988 becomes a future option (§3.1, §10.3).
