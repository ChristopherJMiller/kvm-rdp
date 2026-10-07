# kvm-rdp Plan B — kvm-proto hardening, fuzzing, L0 and kvm-sim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Plan A's unhardened `kvm-proto` subset into the bridge's complete KVM-side video admission — §6.1/§6.2 limits, the required §6.8 SPS rewriter, PPS/slice/POC checks, the §6.3 output form — prove it with L0 goldens, property tests and bounded fuzzing, and build `kvm-sim`, the ES3 test double that Plans C–E's L2/L3 tests and kvm-bench run against.

**Architecture:** `kvm-proto` stays sans-IO and panic-free. Every FLV tag the KVM sends goes demuxer (`flv`, now with every §6.2 limit and a muxer) → `video::VideoAdmission::admit(tag, now)`, which runs the NAL sanitiser (`h264::sanitize`), rewrites every SPS (`h264::sps_syntax` + `h264::rewrite`, verified against h264-reader), checks PPS (`h264::pps`) and slices/POC (`h264::picture`), enforces tag = one picture, and returns `Admitted { params: Option<ParamsChange>, au: Option<AccessUnit>, .. }` — exactly what Plan C's KVM actor forwards as `SpsChanged` and `Au`. `AccessUnit::write_annex_b` produces §6.3's output. Fuzz-target bodies and their output invariants live in `kvm_proto::fuzzing` (stable `cargo test` runs them over generated seeds); `fuzz/` is a separate nightly workspace of one-line libFuzzer targets that only CI fuzzes. `kvm-sim` (new crate) serves login, `av.flv` from one shared encoder in the ES3 profile, and the control websocket over TLS on loopback, with an event log, policies and faults for the bridge's tests; kvm-probe — the tool proven against the real ES3 — is its conformance oracle.

**Tech Stack:** Rust 1.94.1 (edition 2024), `bytes`, `h264-reader` 0.9.0, proptest 1.11 (dev); tokio, tokio-rustls/rustls 0.23 (aws-lc-rs only), tokio-tungstenite 0.24, httparse, rcgen 0.13 (kvm-sim); cargo-fuzz 0.13.2 + libfuzzer-sys 0.4.13 on `nightly-2026-10-01` (fuzz/ only); nix flake devshells (`default`, new `fuzz`); ffmpeg/x264 from the flake for fixtures.

**Spec:** `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (Draft rev 6, census-filled) — the binding authority — with `docs/census.md` (the ES3 profile: `sps_hex`, `pps_hex`, GOP 60, 30 fps, CT 16, burst 0, tag = AU, shared encoder, global logout, NO SIGNAL card). This plan is §12's planning unit **B**: Milestone 1 (kvm-proto hardening, fuzzing, L0) and Milestone 2 (kvm-sim with the ES3 profile), including the required SPS rewriter and the POC-type-0 fixture moved here from Plan A (§11.5). No AU assembler and no GOP cache (§6.2, §6.5). No IronRDP and no bridge runtime (Plans C–E). Plan A's plan (`docs/superpowers/plans/2026-10-05-kvm-rdp-plan-a.md`) is the format exemplar.

**Scope:** in — everything above. Out, by §12's planning units: the scancode→HID and US-layout tables, mouse scaling and the sans-IO cores (release epoch, key timers, backoff, paste pacing, debounce) with their L0 tests (Plans C and D; Plan B supplies the §3.3 HID frame codec they encode with); IronRDP, the pump and the bridge runtime (Plan C); L3, the image and kvm-bench (Plan E).

**Design decisions** (each one line, with why):

1. **Fuzzing: cargo-fuzz + libFuzzer + AddressSanitizer on a pinned `nightly-2026-10-01`, only in `fuzz/` and only in CI** (its own cargo workspace; the main workspace stays on 1.94.1; a `nix develop .#fuzz` shell exists only to reproduce a CI crash), with every target a one-liner over `kvm_proto::fuzzing` (feature `fuzzing`, D8), which holds the bodies and their §11.2 output invariants — because the spec fixes `fuzz/` as a nightly, CI-only workspace (§4.1, §11.2, §13), ASan needs nightly, and keeping the bodies in kvm-proto lets plain `cargo test` run every target over generated seeds on stable, so the developer host never fuzzes (locally `fuzz/` is only `cargo check`ed, on stable). Bounded by `scripts/fuzz.sh` (`-max_total_time`, `-rss_limit_mb=2048`, `-malloc_limit_mb=2048`, `-max_len=262144`, `-timeout=10`, a fresh corpus per run refused past 64 MB, corpus/seeds/ASan build under the shared target dir, `clean` for all three), never by `cargo test`; CI runs 5 s/target per PR and 300 s/target nightly (§11.2). The L0 mux→demux property uses proptest (stable, 256 cases, fixed seed, no regression files), not the fuzzer.
2. **kvm-sim: a library crate at `crates/kvm-sim` (no binary)** serving the ES3's three ports over TLS on 127.0.0.1 with one rcgen certificate (one SPKI pin) — `login.lua` (coexisting logins, **global** logout, token expiry), `av.flv` from **one shared encoder** in the ES3 profile (tag = AU, CT 16, AVCC length 4, NAL types 1 and 5 only, GOP from the source = 60, an IDR forced into every open stream by each new connection, the NO SIGNAL card), and the control websocket recording every message verbatim — plus an ordered event log with `wait_for`, counters, `Policy` switches, one-shot `Fault`s and source switches by three resize signals; it speaks HTTP/1.1 itself (httparse, hyper's own parser) so every FLV write is observable (`sim_tx`, back-pressure) and corruptible — because it is the test double of Plans C–E's L2/L3 cases (§11.3) and kvm-bench (§10.2), whose asserts need exactly these observations, and kvm-probe measuring it the way it measured the device pins its fidelity.
3. **SPS rewriter: kvm-proto's own bounded `bits::{BitReader, BitWriter}` and a full `SpsSyntax` read/write**, because h264-reader refuses the ES3's SPS as sent (§6.8); the rewriter parses every field, patches level/VUI/restriction, re-serialises every field, re-applies emulation prevention with `escape_rbsp_into`, then verifies (its own reader reads back exactly the rewritten fields, and h264-reader parses the output and its new 0.9 SPS writer reproduces it byte for byte — otherwise `stream_incompatible`). h264-reader 0.9.0 (2026-09-14) does ship an RBSP writer (`rbsp::BitWriter`, `ByteWriter`, `WritableNal`); it serves as an independent oracle, not as the serialiser. Goldens: the census `sps_hex` → a literal hex checked bit by bit while writing this plan; `scripts/gen-fixtures.sh` cross-checks against ffmpeg — `h264_metadata`'s level+VUI rewrite of the ES3-like fixture's SPS is recorded in its manifest and must equal ours byte for byte, `trace_headers` plus an unchanged-decode md5 are run over kvm-proto's full rewrite, and `trace_headers` re-reads the census goldens themselves on every `es3like` run.

## Global Constraints

Copied from the spec; every task's requirements include these.

- "Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1" (§4.2); `fuzz/` only: "Separate cargo workspace, nightly, CI-only" (§4.1), pinned here to `nightly-2026-10-01`.
- Dependencies (§4.1): `kvm-proto` — "`bytes`, `h264-reader` — no IronRDP, no tokio, no TLS"; `kvm-sim` — "`kvm-proto`, tokio, hyper, tokio-tungstenite, rustls (aws-lc)" (hyper's parser httparse in place of hyper, deviation D5); `fuzz/` — "`kvm-proto` only" (plus libfuzzer-sys).
- "**One crypto provider, aws-lc-rs** … Nothing may pull in `ring`." (§4.2) — rcgen and rustls with `default-features = false` and `aws_lc_rs`; CI's ring gate must stay green.
- "Parser modules deny `clippy::{indexing_slicing, unwrap_used, expect_used, panic, arithmetic_side_effects, as_conversions}`." (§6.2) — every non-test `kvm-proto` module except `kvm_proto::fuzzing`, the fuzz oracle behind feature `fuzzing` that panics by design and that no bridge crate may enable (D8).
- §6.2: "Header `FLV`, version 1, `DataOffset` 9 (≤ 64 tolerated)"; "`DataSize` is checked against the limit **before** anything is buffered. `PrevTagSize` must equal `11 + DataSize`. `StreamID` must be 0"; "`AVCDecoderConfigurationRecord`: version 1, `lengthSizeMinusOne ∈ {0,1,3}`, 1–4 SPS and 1–16 PPS of ≤ 1 KiB each"; "NALU tags: length-prefixed NALs, `0 < n ≤ remaining`, forbidden bit 0"; "**Allowlist `{1, 5, 7, 8, 9}`**"; "**Any NAL containing `00 00 00`, `00 00 01` or `00 00 02` is refused**"; "Limits: tag 4 MiB, 128 NALs per AU, 4 SPS, 16 PPS"; "a tag that is not exactly one picture … is a framing violation"; bursts: "more than 100 ms ahead".
- §6.1: "`CompositionTime` **constant per stream** on coded (NALU) tags"; "`profile_idc ∈ {66, 77, 100}` … chroma 4:2:0, 8-bit; `frame_mbs_only_flag == 1`; level ≤ 5.1; width ≤ 4096 and height ≤ 2304, both even; `num_ref_frames` ≤ 1 … never above 16"; "`seq_scaling_matrix_present_flag == 0` and VUI `nal/vcl_hrd_parameters_present_flag == 0`"; PPS "`num_slice_groups_minus1 == 0`; `num_ref_idx` defaults bounded; `pic_scaling_matrix_present_flag == 0`"; slices "`slice_type ∈ {0, 2, 5, 7}`; `pps_id` refers to a validated PPS; `first_mb_in_slice < PicSizeInMbs`; POC strictly increasing in decode order within a GOP"; pinned after the first SPS: "`profile_idc`, chroma format, bit depth and POC type".
- §6.8: "`video.sps_rewrite` is `["level", "vui", "restriction"]`" — level: "the lowest level whose MaxFS and MaxMBPS (H.264 Table A-1) admit the coded size at `video.max_fps`, and never lowered — **31 → 40**"; VUI: "`video_full_range_flag` 0 and colour description **1/1/1**"; restriction: "`max_num_reorder_frames = 0` and `max_dec_frame_buffering = max(num_ref_frames, 1)` … the structure's other fields at the values H.264 infers"; "An SPS that already carries `bitstream_restriction` keeps it"; "An SPS the rewriter cannot read … or whose output h264-reader does not parse back … is `stream_incompatible`".
- §6.3: "Annex-B with 4-byte start codes … Each sent AU = [AUD if present] + the cached SPS (as rewritten, §6.8) and PPS (IDR only) + the source AU's allowlisted VCL NALs, in order."
- §6.9: framing violations are transient (FLV reconnect); "three within 60 s is fatal: `stream_corrupt`"; HEVC, B-frames (incl. a `CompositionTime` change), limits, pinned fields, slice/PPS checks and an unreadable SPS are `stream_incompatible`.
- §11.5: fixtures "≤ 0.5 MB each, generated by `scripts/gen-fixtures.sh` with the flake's pinned ffmpeg/x264 and committed", flags "`-bf 0 -threads 1 -x264-params sliced-threads=0:keyint=N:min-keyint=N:scenecut=0:aud=1`", "Each fixture has a committed manifest (sha256 …)"; "**Real captures from the KVM are never committed**".
- §13 ("The rules are mechanical, not advisory"), verbatim: "`.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"` (CI overrides with `CARGO_BUILD_JOBS`)"; "The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`, falling back to `nice` without user systemd"; "One shared `CARGO_TARGET_DIR` across any worktrees, never one per worktree"; "Profiles: `[profile.dev] debug = "line-tables-only"`, dependencies `debug = false`; `[profile.release] lto = "thin", codegen-units = 16, debug = "line-tables-only", panic = "abort"`; `[profile.bench]` inherits release; no fat-LTO profile. One integration-test binary (`autotests = false`); `CARGO_INCREMENTAL=0` in CI"; "ffmpeg runs under `nice -n 19` with `-threads 4`" (fixture encodes keep §11.5's `-threads 1`; Plan B's new decodes and traces pass `-threads 4` through `DEC`, Task 6.1); "Budget: ~1.5 GB of target for debug + tests; ~3–4 GB with release and clippy"; "Fuzzing and the 1-hour soak run in CI only; bench streams live in `target/`" — plus the owner's rule: no fuzz run without a time cap and an RSS cap, and never by default.
- Licence MIT OR Apache-2.0; every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

Five inputs the spec implies but does not spell out, most likely first; each line's test is in the owning task.

1. **The ES3's own parameter sets end in zero bytes** (`sps_hex` …`08 00`, `pps_hex` …`12 00 00`, `census.md`) → trimmed (Annex B cannot tell them from `trailing_zero_8bits`), admitted, never mistaken for a start code, and re-emitted canonically — on the real path, FLV config record → demux → trim → rewrite → §6.3 output, and kvm-sim's ES3 profile sends them padded the same way so Plans C–E's L2 tests see it too (Task 4.1 `es3_pps_trailing_zeros_are_trimmed_not_refused`; Task 2.3 `writes_back_the_same_bytes_without_the_trailing_zero`; Task 4.3 `the_es3_pps_passes_with_or_without_its_trailing_zeros`; Task 4.6 `the_es3s_own_parameter_sets_admit_through_mux_and_demux`; Task 8.4 `es3_tag_shape_on_the_wire_and_the_bridge_admits_it`; Task 8.7 `census_capture_sees_the_es3_profile`).
2. **Display sleep switches the ES3 to its NO SIGNAL card** (every frame an IDR, same SPS) → every frame admitted, no `SpsChanged`, no POC refusal; waking restarts at an IDR; a byte-identical sequence header mid-connection raises nothing either (Task 8.2 `no_signal_is_all_intra_and_the_signal_returns_on_an_idr`; Task 8.4 `no_signal_card_admits_without_a_params_change`; Task 4.6 `an_identical_sequence_header_mid_connection_raises_nothing`).
3. **In-band SPS/PPS repeated with every IDR** (x264 `repeat-headers`, or a firmware update) → byte-identical sets raise no `SpsChanged` (each would be a flow cause and churn NeedIdr), never reach the AU, and a new size in-band is `Resize`; more than §6.2's 4 SPS / 16 PPS in one tag is refused before each costs a rewrite (D10) (Task 4.6 `in_band_parameter_sets_are_classified_and_removed_from_the_au`, `in_band_parameter_sets_up_to_the_section_6_2_cap_are_admitted` and the two flood vectors in `each_admission_rule_has_its_own_refusal`; Task 4.5 `es3_sets_are_initial_rewritten_then_silent_when_repeated`).
4. **One viewer stops reading its FLV** (the bridge stalled, or a side connection never read) → kvm-sim's encoder and every other viewer keep going, frames are dropped only for that viewer, as the real KVM never sees back-pressure (§4.3, §10.2) (Task 8.2 `a_full_viewer_queue_drops_only_that_viewers_frames`; Task 8.4 `a_viewer_that_stops_reading_does_not_stall_the_others`, which uses a 64 KiB `SimConfig::video_send_buffer` so the stalled writer blocks and `frames_dropped > 0` is asserted, not hoped for).
5. **An FLV reconnect inside one KVM session** → its first SPS is `Initial` again even when identical, `CompositionTime`, POC order and burst marking restart, while the pins persist so a reconnect onto a different profile is still fatal — until a new session (`Start`) resets them (Task 4.6 `an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins`, where each of the three resets and the pins has an assertion that fails without it; Task 4.5 `pinned_fields_and_limits_refuse`, which calls `flv_opened()` before the Main SPS).

## Recorded deviations from the spec

Task 9.1 writes these into the spec as rev 6.1. Each makes a rule computable or matches what the ES3 sends; none admits anything the spec refuses except where noted.

- **D1 — POC type 1 is refused** (`SpsLimitViolation::PocType1`). §6.1's POC rule needs a computed POC; types 0 (the ES3) and 2 (x264) are computed, type 1 (offset cycles) is used by no source in scope, and refusing it is the safe direction.
- **D2 — trailing zero bytes are trimmed from every NAL before the §6.2 checks.** Annex B cannot distinguish them from `trailing_zero_8bits`; a conforming NAL never ends in `00` (H.264 7.4.1); the ES3 appends them to its SPS and PPS. The start-code refusal then applies to the trimmed NAL. Safe: the bridge's own 4-byte start code follows every NAL it sends.
- **D3 — at most one AUD per tag, before any slice**, rather than "the first NAL": an AUD after SPS/PPS is accepted (Plan A's `360p30_main_norepeat` fixture splices SPS/PPS ahead of its first AUD). The output puts the AUD first regardless (§6.3).
- **D4 — parameter-set model.** One active SPS (the latest admitted); a sequence header replaces every PPS; cached PPSs that no longer parse against a new SPS are dropped; a PPS-only change raises `SpsChanged{other}`; a byte-identical repeat raises nothing.
- **D5 — kvm-sim uses httparse, not hyper** (§4.1's dependency row), for byte-level control of every response.
- **D6 — the POC-type-0 fixture is ES3-shaped**: `fixtures/360p30_es3like_poc0.h264` — Baseline, keyint 60, ref 1, POC type 0 with `pic_order_cnt_lsb = 2 × frame_num`, no `bitstream_restriction`, limited-range BT.709 pixels (what Leg A measured on the ES3's), and the ES3's mislabels (level 2.1 for 640×360, VUI full range with 5/6/5, constraint flags 0) — a superset of §11.5's POC-0 variant, so kvm-sim's ES3 profile exercises the whole rewrite, and the rewritten VUI (limited-range BT.709) tells the truth about its pixels as it does about the ES3's.
- **D7 — FLV tag types other than 8, 9 and 18 are framing violations** (§6.2 names only what is parsed and skipped).
- **D8 — `kvm_proto::fuzzing` is exempt from §6.2's lint denies.** It is the fuzz oracle — target bodies whose panics are findings — compiled only under `cfg(test)` or kvm-proto's `fuzzing` feature, which only `fuzz/` (its own workspace) enables; CI fails if a workspace crate enables it (Task 7.3). It parses nothing the bridge receives.
- **D9 — the level rule is H.264 A.3.1 in full.** Besides Table A-1's MaxFS and MaxMBPS (§6.8 (a)), `PicWidthInMbs²` and `FrameHeightInMbs²` must not exceed 8 × MaxFS, which picks a higher level only for extreme aspect ratios (a 4096×16 strip needs 4.0); the ES3's 31 → 40 is unchanged. A consequence of §6.1's level ≤ 5.1 that rev 6 already implied: at `video.max_fps` 30 the largest admitted frame is 32 768 MBs (e.g. 4096×2048); §6.1's 4096×2304 needs level 5.2 and is refused after the rewrite (`OutsideLimits(Level(52))`).
- **D10 — §6.2's "4 SPS, 16 PPS" also bound each NALU tag's in-band parameter sets**: a fifth SPS or a seventeenth PPS in one tag is a framing violation (`param_set_count`), checked before that set is rewritten or parsed. Byte-identical in-band repeats under the cap raise nothing (D4). Refuses more than rev 6, never less.
- **D11 — the burst baseline is the FLV connection's first coded tag, not its sequence header** (PB9 preflight P10). `BurstMarker::mark` runs only in `coded()`; a sequence header is not an AU, and the ES3's first tags share timestamp 0, so marking from the first *coded* tag — not the literal first tag §6.2 originally said — is what keeps `an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins` correct. §6.2's wording is amended to say so.
- **D12 — the level rewrite's edge cases (PB4 fix rounds, RB3 and its amendment).** `RewriteError::UnknownLevel`: a `level_idc` not in Table A-1, or naming level 6, 6.1 or 6.2 (§6.1 already refuses above 5.1), is `stream_incompatible` rather than guessed at; level 5.2 is ranked, and refused one layer later by admission as `OutsideLimits(Level(52))` (PB18 review I3). Level 1b (`level_idc` 11 with `constraint_set3_flag` set, or 9 for High/Main) ranks strictly between level 1 and level 1.1 and is never lowered to level 1. `constraint_set3_flag` (0x10) is cleared on **every** level raise of a profile 66/77/88 SPS, not only when the input was itself 1b — a stray flag below a non-1b level is reserved and must not survive the raise.
- **D13 — `ViolationWindow::new` cannot panic on an absurd threshold** (PB9 fix round 1): `VecDeque::with_capacity(threshold.min(8))`, not the raw threshold.
- **D14 — cached PPS bytes are copied out of the tag buffer, not shared with it** (PB9 fix round 1): a `Bytes` cache of a demuxer buffer that gets reused would otherwise outlive the data it points at.
- **D15 — kvm-sim disconnects a full-but-connected viewer on its next control item, and closes an evicted-but-stalled viewer's FLV promptly** (PB14/PB16 fix rounds): a viewer whose queue fills no longer silently drops frames forever — a fault or a source switch disconnects it instead — and the eviction races the viewer's own stalled write so the server-side FLV closes rather than leaking, bounded by a 50 ms `SHUTDOWN_TIMEOUT` on the final `shutdown()`.
- **D16 — the NO SIGNAL card alternates `idr_pic_id` between consecutive IDRs** (PB14 fix round 1): kvm-sim reuses the source frame's own `idr_pic_id`, so two IDRs in a row must come from different source frames, matching a real encoder (two same-`idr_pic_id` IDRs would look like one picture split across tags).
- **D17 — `Policy::refuse_concurrent_flv` is a count (`u32`), not a flag** (PB18 preflight P3): each refusal decrements it, so §11.3's make-before-break reconnect after a refused side open is itself servable, rather than refused forever by a policy a test must race to clear.
- **D18 — every refused `av.flv` carries `{"result":403}` only on an actual HTTP 403** (PB18 preflight P2): a `Policy`-refused 503 (or any other non-403 refusal) has no body, so §6.9's auth-vs-transient classification cannot be confused by a 5xx that also claims `result: 403`.
- **D19 — `scripts/fuzz.sh` validates its own arguments, and the D8 CI gate uses `--target all` and fails closed on a `cargo tree` error** (PB13 fix round 1): `run` refuses (exit 2, nothing touched) unless its numeric arguments are positive integers and every target is known, rather than fuzzing unbounded or deleting an unintended path on a typo; the D8 gate (no workspace crate enables `kvm-proto`'s `fuzzing` feature) now catches a target-specific dependency on another platform and treats `cargo tree` itself erroring as a failure, not a pass.

## Plan A deferred items

Folded in: m9 shared `CARGO_TARGET_DIR` (Task 1.1); m11 `Token` redacting `Debug` (Task 1.1); m15 doctest/bin test harnesses (Task 1.1); m18 `name()` scaffolding (Task 1.1); 4.2 workspace dev-deps (Task 1.1) and literal BT.709 asserts (Task 6.1); 3.7 `SpsLimits` doc (Task 4.2); 3.9 pinned-field tie-break test (Task 4.2); 3.1 duplicate `pub use` lines (Task 4.2); 2.3/2.4 `data_offset` 8 / padding / zero-length-body tests (Tasks 3.1, 3.2); 2.8 `BurstMarker` wired into the demux path (Task 4.6); 4.1 `sps_count` comment and masked `mktemp` (Task 6.1); m5 per-tag NAL cap in the census path (Task 3.1's 128-NAL cap applies to kvm-probe's demuxer too); and every §6.1/§6.2 item the final review's "Declined to judge" put in Plan B (128 NALs/AU, 1–4 SPS and 1–16 PPS ≤ 1 KiB, the start-code refusal, the allowlist on the demux path, constant `CompositionTime`, PPS and full slice validation, fuzzing).
Not folded (no behaviour, or not kvm-proto/kvm-sim): 2.7 duplicated frame-type match, R19's duplicated length loop, 3.5 test-only arithmetic, 1.7 CI actions pinned by tag, and the kvm-probe-only items (m3, m4, m12–m14, m16, m17, m19, B13 M2–M4/M8–M10, N3).

## Execution notes

- Repo `/home/chris/Repos/kvm-rdp`. Execute on a branch `plan-b` created from `plan-a`'s current head (Plan A is complete and not yet merged; merge order is the owner's call).
- Every command runs inside `nix develop` from the repo root (the §13 cargo wrapper). Run `cargo fmt --all` before every commit; the gate after each task is `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test --workspace --all-features`.
- **No step fuzzes on this host** (§4.1, §11.2, §13: fuzzing is CI-only). Locally, every fuzz-target body runs over its seeds in `cargo test` (stable), `fuzz/` is `cargo check`ed on stable, and `scripts/fuzz.sh run` is exercised only as a dry run (`FUZZ_CARGO='echo cargo'`, which prints the capped command instead of running it). No step enters `nix develop .#fuzz`, so the nightly toolchain is never downloaded here.
- Task numbers are `Part.N`. Parts run in order: Part 6's fixture feeds Parts 7 and 8.
- Tests that read fixtures use `concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures")`; nothing reads `captures/`.
- `scripts/gen-fixtures.sh` must reproduce committed bytes: Task 6.1 expects `360p30_es3like_poc0.h264` to hash to `131ea43747b288b8c1aede036645ac525c629c31100439b84c4b4128f731e091` (318 186 bytes) on the locked flake (re-pinned after the source encode moved to limited range, D6; reproduced twice while revising this plan); regenerating the existing fixtures must leave their hashes unchanged.
- Disk, against §13's budget (~1.5 GB of target for debug + tests, ~3–4 GB with release and clippy): a scratch build of every Part 1–8 block — kvm-proto, kvm-probe, kvm-sim with tokio/rustls/aws-lc-sys, all tests and clippy, in debug — took ~0.93 GB of target; Part 7's stable `cargo check` of `fuzz/` adds ~0.2 GB (libFuzzer's C++ objects); the generated seeds are ~0.3 MB under `$CARGO_TARGET_DIR/fuzz-seeds`. Nothing here builds release or ASan. In CI, `scripts/fuzz.sh clean` removes corpus, seeds and the ASan build (`$CARGO_TARGET_DIR/fuzz-build`).

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `crates/kvm-proto/src/bits.rs` | Bounded RBSP bit reader/writer, emulation prevention, start-code check | 2.1 |
| `crates/kvm-proto/src/h264/annexb.rs` | + Annex-B splitter, FrameId | 2.2 |
| `crates/kvm-proto/src/h264/sps_syntax.rs` | Full SPS syntax read/write | 2.3 |
| `crates/kvm-proto/src/h264/rewrite.rs` | §6.8 rewriter, Table A-1, verification | 2.4 |
| `crates/kvm-proto/src/flv/{header,avc,demux}.rs` | §6.2 limits, error kinds, poison | 3.1, 3.2 |
| `crates/kvm-proto/src/flv/mux.rs` | FLV muxer (kvm-sim, property tests, fuzz) | 3.3 |
| `crates/kvm-proto/src/h264/sanitize.rs` | Per-NAL §6.2 checks | 4.1 |
| `crates/kvm-proto/src/h264/sps.rs` | Limits (refs 1, POC type 1), `SpsPins` | 4.2 |
| `crates/kvm-proto/src/h264/pps.rs` | §6.1 PPS admission | 4.3 |
| `crates/kvm-proto/src/h264/picture.rs` | Slice checks, `PocTracker` | 4.4 |
| `crates/kvm-proto/src/h264/test_support.rs` | + `PpsCfg`, `SliceCfg` builders | 4.3, 4.4 |
| `crates/kvm-proto/src/video/{error,params,violations}.rs` | §6.9 classes, parameter-set state, 3-in-60 s window | 4.5 |
| `crates/kvm-proto/src/video/{mod,tests}.rs` | `VideoAdmission`, `AccessUnit`, §6.3 output | 4.6 |
| `crates/kvm-proto/src/hid.rs` | §3.3 HID frame encode/decode | 5.1 |
| `crates/kvm-proto/examples/es3_fixture.rs` | ES3-shaping transform and rewrite tool (trusted fixtures only) | 6.1 |
| `fixtures/360p30_es3like_poc0.h264` (+ manifest) | The POC-type-0, ES3-shaped fixture | 6.1 |
| `crates/kvm-proto/tests/fixtures.rs` | ffmpeg-manifest oracle for the new fixture | 6.1 |
| `crates/kvm-proto/tests/admission.rs` | Every fixture through admission | 6.2 |
| `crates/kvm-proto/src/fuzzing.rs`, `examples/fuzz_seeds.rs` | Fuzz bodies + invariants (nine targets), seeds | 7.1 |
| `fuzz/` | Nightly cargo-fuzz workspace (one-line targets) | 7.2 |
| `scripts/fuzz.sh`, `flake.nix` (`.#fuzz`) | Bounded CI fuzz runner, crash-reproduction shell | 7.2 |
| `.github/workflows/{ci,fuzz-nightly}.yml` | 5 s/target per PR, 300 s/target nightly, D8 gate | 7.3 |
| `crates/kvm-sim/src/source.rs` | Fixture → frames and GOPs | 8.1 |
| `crates/kvm-sim/src/{state,encoder}.rs` | Event log/stats/policy; the shared encoder | 8.2 |
| `crates/kvm-sim/src/{tls,http,web,lib}.rs` | TLS identity, HTTP, login.lua, `KvmSim` (+ blackhole) | 8.3 |
| `crates/kvm-sim/src/flv.rs` | `av.flv` in the ES3 profile, resize | 8.4 |
| `crates/kvm-sim/src/flv.rs` (faults) | One-shot faults on the wire | 8.5 |
| `crates/kvm-sim/src/ws.rs` | The HID-recording control websocket | 8.6 |
| `crates/kvm-sim/tests/sim/*.rs` | kvm-sim's single integration-test binary | 8.1–8.7 |

---

## Part 1 — Groundwork

Build hygiene and the Plan A carry-overs every later task leans on.

### Task 1.1: Workspace hygiene and Plan A carry-overs

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/login.rs` (`Token`'s `Debug`; new test module)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (drop the `name()` scaffolding)
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.toml` (`[workspace.dependencies]`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml`, `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml`
- Modify: `/home/chris/Repos/kvm-rdp/flake.nix`, `/home/chris/Repos/kvm-rdp/.cargo/config.toml`
- Test: `crates/kvm-proto/src/login.rs` (`redaction_tests::debug_never_shows_the_token`)

**Interfaces:**
- Consumes: Plan A's `kvm_proto::login::{Token, parse_login_token, LoginError}`.
- Produces: `impl core::fmt::Debug for Token` printing `Token(<redacted>)` (no derive); `[workspace.dependencies]` entries `sha2 = "0.10"`, `serde_json = "1"`, `proptest = { version = "1.11", default-features = false, features = ["std"] }` for every later dev-dependency; the devshell exports `CARGO_TARGET_DIR=<main checkout>/target` for every worktree; `kvm_proto::name()` no longer exists.

- [ ] **Step 1: Write the failing test.** Append to `crates/kvm-proto/src/login.rs`:

```rust
#[cfg(test)]
mod redaction_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn debug_never_shows_the_token() {
        let t = parse_login_token(br#"{"result":0,"token":"0.987654321"}"#).unwrap();
        let shown = format!("{t:?} {:?}", Ok::<_, LoginError>(t.clone()));
        assert!(!shown.contains("987654321"), "{shown}");
        assert_eq!(format!("{t:?}"), "Token(<redacted>)");
        assert_eq!(t.as_str(), "0.987654321");
    }
}
```

- [ ] **Step 2: Run it to see it fail.**

Run: `cargo test -p kvm-proto --lib redaction_tests`
Expected: FAIL — the panic message shows `Token("0.987654321")` (the derived `Debug` prints the secret, §9.2).

- [ ] **Step 3: Implement.** In `login.rs`, replace

```rust
/// A validated session token of the form `0.<digits>` (the vendor matches
/// `/token=0\.\d+/`), sent back as `Cookie: token=<token>` and `?token=`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token(String);
```

with

```rust
/// A validated session token of the form `0.<digits>` (the vendor matches
/// `/token=0\.\d+/`), sent back as `Cookie: token=<token>` and `?token=`.
/// A secret (§9.2): its `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}
```

- [ ] **Step 4: Drop the scaffolding (m18).** Replace the whole of `crates/kvm-proto/src/lib.rs` with:

```rust
//! `kvm-proto`: sans-IO parsers and encoders for the kvm-rdp bridge.
//!
//! This crate faces hostile input from the KVM (spec §2, §4.1) and must
//! never panic, index out of bounds, or overflow. The crate-root lints
//! below are denied crate-wide; test modules that legitimately need
//! `unwrap`/`panic` opt out locally with a scoped `#![allow(...)]`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

pub mod flv;
pub mod h264;
pub mod login;
pub use login::{LoginError, Token, parse_login_token};
```

- [ ] **Step 5: Workspace dev-dependencies and test harnesses (4.2 minor, m15).** Append to the root `Cargo.toml`'s `[workspace.dependencies]`:

```toml
sha2 = "0.10"
serde_json = "1"
proptest = { version = "1.11", default-features = false, features = ["std"] }
```

In `crates/kvm-proto/Cargo.toml`, add a `[lib]` table right after the `[package]` table, and replace the `[dev-dependencies]` table:

```toml
[lib]
doctest = false
```

```toml
[dev-dependencies]
sha2 = { workspace = true }
serde_json = { workspace = true }
proptest = { workspace = true }
```

In `crates/kvm-probe/Cargo.toml`, add `doctest = false` to the `[lib]` table and `test = false` to the `[[bin]]` table:

```toml
[lib]
name = "kvm_probe"
path = "src/lib.rs"
doctest = false

[[bin]]
name = "kvm-probe"
path = "src/main.rs"
test = false
```

- [ ] **Step 6: One shared target dir for every worktree (m9).** In `flake.nix`, add this binding to the `let` block, after `cargoWrapper`:

```nix
      # §13: one shared target dir for every worktree of this repo.
      sharedTarget = ''
        if [ -z "''${CARGO_TARGET_DIR:-}" ] && common=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
          export CARGO_TARGET_DIR="$(dirname "$common")/target"
        fi
      '';
```

and replace the `shellHook` with:

```nix
        shellHook = ''
          ${sharedTarget}
          echo "kvm-rdp devshell: $(${rustToolchain}/bin/rustc --version)"
        '';
```

In `.cargo/config.toml`, replace the last comment paragraph (from `# CARGO_TARGET_DIR: keep ONE shared target dir` to the end) with:

```toml
# CARGO_TARGET_DIR: ONE shared target dir across all git worktrees (spec
# §13). The devshell's shellHook exports `<main checkout>/target` (from
# `git rev-parse --git-common-dir`) unless CARGO_TARGET_DIR is already set;
# it is not hard-coded here because the path is machine-specific. CI
# overrides build parallelism with the CARGO_BUILD_JOBS env var.
```

- [ ] **Step 7: Verify.**

Run: `cargo test -p kvm-proto --lib redaction_tests` — Expected: PASS.
Run: `nix develop -c bash -c 'echo $CARGO_TARGET_DIR'` — Expected: `/home/chris/Repos/kvm-rdp/target` (the same from inside any `git worktree` of this repo).
Run: `cargo test --workspace --all-features 2>&1 | grep -c Doc-tests` — Expected: `0`.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: no warnings.

- [ ] **Step 8: Commit.**

```bash
git add Cargo.toml Cargo.lock crates/kvm-proto/Cargo.toml crates/kvm-probe/Cargo.toml \
  crates/kvm-proto/src/lib.rs crates/kvm-proto/src/login.rs flake.nix .cargo/config.toml
git commit -m "Plan B groundwork: redacted Token Debug, shared target dir, workspace dev-deps" \
  -m "Plan A carry-overs m9, m11, m15, m18 and the 4.2 workspace dev-deps minor." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 2 — Bit-level H.264

The pieces the §6.8 rewriter is built from: a bounded bit reader and writer with emulation prevention, an Annex-B splitter, the full SPS syntax, and the rewriter with its goldens.

### Task 2.1: `bits` — bounded RBSP reader and writer, emulation prevention

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/bits.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (`pub mod bits;`)
- Test: `crates/kvm-proto/src/bits.rs` (`tests`)

**Interfaces:**
- Consumes: nothing new (h264-reader's `rbsp::{BitReader, ByteWriter}` only as test oracles).
- Produces (`kvm_proto::bits`):
  - `pub enum BitError { Eof, ExpGolombTooLong, TooManyBits, TrailingData }` (`Copy`, `Eq`)
  - `pub struct BitReader<'a>`: `new(&'a [u8]) -> Self`, `position(&self) -> usize`, `remaining(&self) -> usize`, `read_bit(&mut self) -> Result<bool, BitError>`, `read_bits(&mut self, n: u32) -> Result<u32, BitError>` (n ≤ 32), `read_u8`, `read_flag`, `read_ue(&mut self) -> Result<u32, BitError>` (≤ 31 leading zeros), `read_se(&mut self) -> Result<i32, BitError>`, `more_rbsp_data(&self) -> bool`, `finish(self) -> Result<(), BitError>` (only `rbsp_trailing_bits` and zero bytes left), `stop_bit_position(&self) -> Option<usize>`
  - `pub struct BitWriter`: `new()`, `write_bit(bool)`, `write_bits(u64, n: u32)`, `write_u8(u8)`, `write_flag(bool)`, `write_ue(u32)`, `write_se(i32)`, `write_trailing_bits()`, `is_byte_aligned() -> bool`, `into_rbsp(self) -> Vec<u8>`
  - `pub fn unescape_rbsp(nal_payload: &[u8]) -> Vec<u8>`; `pub fn escape_rbsp_into(rbsp: &[u8], out: &mut Vec<u8>)`; `pub fn contains_start_code(nal: &[u8]) -> bool`

- [ ] **Step 1: Write the failing tests.** Add `pub mod bits;` to `crates/kvm-proto/src/lib.rs` (above `pub mod flv;`) and create `crates/kvm-proto/src/bits.rs` containing only the test module:

```rust
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;
    use h264_reader::rbsp::BitRead as _;

    #[test]
    fn ue_and_se_round_trip_including_extremes() {
        let ues = [0u32, 1, 2, 3, 7, 8, 254, 255, 65_535, u32::MAX - 1];
        let ses = [0i32, 1, -1, 2, -2, 1000, -1000, i32::MAX, i32::MIN + 1];
        let mut w = BitWriter::new();
        for v in ues {
            w.write_ue(v);
        }
        for v in ses {
            w.write_se(v);
        }
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut r = BitReader::new(&rbsp);
        for v in ues {
            assert_eq!(r.read_ue().unwrap(), v);
        }
        for v in ses {
            assert_eq!(r.read_se().unwrap(), v);
        }
        r.finish().unwrap();
    }

    #[test]
    fn writer_agrees_with_h264_reader_bit_reader() {
        // Independent oracle: h264-reader's reader decodes what we wrote.
        let mut w = BitWriter::new();
        w.write_ue(300);
        w.write_se(-17);
        w.write_bits(0b101, 3);
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut r = h264_reader::rbsp::BitReader::new(&rbsp[..]);
        assert_eq!(r.read_ue("a").unwrap(), 300);
        assert_eq!(r.read_se("b").unwrap(), -17);
        assert_eq!(r.read::<3, u8>("c").unwrap(), 0b101);
        r.finish_rbsp().unwrap();
    }

    #[test]
    fn ue_with_32_leading_zeros_is_refused_not_wrapped() {
        // 32 zero bits then a 1: the value would be ≥ 2^32 - 1.
        let data = [0u8, 0, 0, 0, 0x80, 0, 0, 0, 0];
        assert_eq!(
            BitReader::new(&data).read_ue(),
            Err(BitError::ExpGolombTooLong)
        );
    }

    #[test]
    fn reads_past_the_end_are_eof() {
        let mut r = BitReader::new(&[0xFF]);
        assert_eq!(r.read_bits(8), Ok(0xFF));
        assert_eq!(r.read_bit(), Err(BitError::Eof));
        assert_eq!(BitReader::new(&[]).read_ue(), Err(BitError::Eof));
        assert_eq!(
            BitReader::new(&[0]).read_bits(33),
            Err(BitError::TooManyBits)
        );
    }

    #[test]
    fn finish_accepts_trailing_zero_bytes_and_refuses_data() {
        // stop bit at the top of 0x80, then two Annex B trailing zero bytes.
        BitReader::new(&[0x80, 0x00, 0x00]).finish().unwrap();
        let mut r = BitReader::new(&[0b1010_0000]);
        assert!(r.more_rbsp_data());
        r.read_bit().unwrap();
        assert!(r.more_rbsp_data());
        r.read_bit().unwrap();
        assert!(!r.more_rbsp_data());
        assert_eq!(
            BitReader::new(&[0b1100_0000]).finish(),
            Err(BitError::TrailingData)
        );
    }

    #[test]
    fn escape_matches_h264_reader_byte_writer_and_unescape_inverts_it() {
        use std::io::Write as _;
        let cases: [&[u8]; 6] = [
            &[0, 0, 0],
            &[0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 4],
            &[0x67, 0, 0, 0, 0, 0],
            &[1, 2, 3],
            &[0, 0],
            &[],
        ];
        for rbsp in cases {
            let mut ours = Vec::new();
            escape_rbsp_into(rbsp, &mut ours);
            let mut theirs = h264_reader::rbsp::ByteWriter::new(Vec::new());
            theirs.write_all(rbsp).unwrap();
            let theirs = theirs.into_writer();
            assert_eq!(ours, theirs, "escape of {rbsp:02x?}");
            assert!(!contains_start_code(&ours));
            assert_eq!(unescape_rbsp(&ours), rbsp, "round trip of {rbsp:02x?}");
        }
    }

    #[test]
    fn a_stop_bit_byte_after_two_zeros_is_escaped_and_still_found() {
        // An RBSP ending `00 00 01` (the stop bit alone in its byte) goes out
        // as `00 00 03 01`; reading it back still finds that stop bit.
        let rbsp = [0x42, 0x00, 0x00, 0x01];
        let mut nal = Vec::new();
        escape_rbsp_into(&rbsp, &mut nal);
        assert_eq!(nal, [0x42, 0x00, 0x00, 0x03, 0x01]);
        assert!(!contains_start_code(&nal));
        let back = unescape_rbsp(&nal);
        assert_eq!(back, rbsp);
        let mut r = BitReader::new(&back);
        assert_eq!(r.stop_bit_position(), Some(31));
        r.read_bits(31).unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn start_code_patterns_detected() {
        assert!(contains_start_code(&[0x65, 0, 0, 1, 0x88]));
        assert!(contains_start_code(&[0x65, 0, 0, 0]));
        assert!(contains_start_code(&[0x65, 0, 0, 2]));
        assert!(!contains_start_code(&[0x65, 0, 0, 3, 0]));
        assert!(!contains_start_code(&[0x68, 0xce, 0x31, 0x12, 0, 0]));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib bits::`
Expected: FAIL to compile — `cannot find type BitReader`, `BitWriter`, `BitError` and the three functions.

- [ ] **Step 3: Implement.** Put this above the test module in `bits.rs`:

```rust
//! Bounded bit reader and writer over H.264 RBSP bytes (H.264 7.2), and
//! emulation prevention (7.4.1). The reader faces hostile input: every
//! read is bounds-checked and every Exp-Golomb code is length-capped, so
//! nothing here can panic, overflow or allocate without bound.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Why a bit-level read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitError {
    /// The read ran past the end of the RBSP.
    Eof,
    /// An Exp-Golomb code had more than 31 leading zero bits (its value
    /// would not fit in a `u32`).
    ExpGolombTooLong,
    /// `read_bits` was asked for more than 32 bits.
    TooManyBits,
    /// `finish` found data where `rbsp_trailing_bits()` belongs.
    TrailingData,
}

/// Forward-only MSB-first bit reader over an RBSP (emulation prevention
/// already removed, see [`unescape_rbsp`]).
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Position in bits from the start of `data`.
    pos: usize,
}

impl<'a> BitReader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bits consumed so far.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bits not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_mul(8).saturating_sub(self.pos)
    }

    pub fn read_bit(&mut self) -> Result<bool, BitError> {
        let byte = self
            .data
            .get(self.pos.wrapping_shr(3))
            .copied()
            .ok_or(BitError::Eof)?;
        let shift = 7_u32.saturating_sub(u32::try_from(self.pos & 7).unwrap_or(0));
        self.pos = self.pos.checked_add(1).ok_or(BitError::Eof)?;
        Ok(byte.wrapping_shr(shift) & 1 == 1)
    }

    /// `u(n)` for `n` in `0..=32`.
    pub fn read_bits(&mut self, n: u32) -> Result<u32, BitError> {
        if n > 32 {
            return Err(BitError::TooManyBits);
        }
        let mut v: u32 = 0;
        for _ in 0..n {
            v = v.wrapping_shl(1) | u32::from(self.read_bit()?);
        }
        Ok(v)
    }

    pub fn read_u8(&mut self) -> Result<u8, BitError> {
        u8::try_from(self.read_bits(8)?).map_err(|_| BitError::TooManyBits)
    }

    pub fn read_flag(&mut self) -> Result<bool, BitError> {
        self.read_bit()
    }

    /// `ue(v)`: unsigned Exp-Golomb, at most 31 leading zeros (0..=u32::MAX-1).
    pub fn read_ue(&mut self) -> Result<u32, BitError> {
        let mut zeros: u32 = 0;
        while !self.read_bit()? {
            zeros = zeros.checked_add(1).ok_or(BitError::ExpGolombTooLong)?;
            if zeros > 31 {
                return Err(BitError::ExpGolombTooLong);
            }
        }
        let suffix = self.read_bits(zeros)?;
        // (2^zeros - 1) + suffix, computed in u64 so zeros == 31 cannot overflow.
        let base = 1_u64.wrapping_shl(zeros).saturating_sub(1);
        u32::try_from(base.saturating_add(u64::from(suffix)))
            .map_err(|_| BitError::ExpGolombTooLong)
    }

    /// `se(v)`: signed Exp-Golomb (H.264 9.1.1).
    pub fn read_se(&mut self) -> Result<i32, BitError> {
        let k = i64::from(self.read_ue()?);
        let magnitude = k.saturating_add(1).wrapping_shr(1);
        let v = if k & 1 == 1 {
            magnitude
        } else {
            magnitude.saturating_neg()
        };
        i32::try_from(v).map_err(|_| BitError::ExpGolombTooLong)
    }

    /// `more_rbsp_data()` (7.2): true while anything other than the
    /// `rbsp_trailing_bits()` (a 1 then only zeros to the end) remains.
    #[must_use]
    pub fn more_rbsp_data(&self) -> bool {
        match self.last_one_bit() {
            Some(last) => self.pos < last,
            None => false,
        }
    }

    /// Checks that only `rbsp_trailing_bits()` remain: the next bit is the
    /// stop bit and every bit after it is zero. Trailing zero bytes after
    /// the stop bit (Annex B `trailing_zero_8bits`) are accepted.
    pub fn finish(self) -> Result<(), BitError> {
        match self.last_one_bit() {
            Some(last) if last == self.pos => Ok(()),
            _ => Err(BitError::TrailingData),
        }
    }

    /// Bit index of the last 1 bit in `data` — the `rbsp_stop_one_bit` of a
    /// well-formed RBSP — if any.
    #[must_use]
    pub fn stop_bit_position(&self) -> Option<usize> {
        self.last_one_bit()
    }

    fn last_one_bit(&self) -> Option<usize> {
        let (idx, byte) = self.data.iter().enumerate().rev().find(|(_, b)| **b != 0)?;
        let tz = usize::try_from(byte.trailing_zeros()).ok()?;
        idx.checked_mul(8)?.checked_add(7)?.checked_sub(tz)
    }
}

/// MSB-first bit writer that produces an RBSP. Infallible: it only appends
/// to its own buffer.
#[derive(Debug, Default, Clone)]
pub struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u32,
}

impl BitWriter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_bit(&mut self, bit: bool) {
        self.cur = self.cur.wrapping_shl(1) | u8::from(bit);
        self.nbits = self.nbits.saturating_add(1);
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// The low `n` bits of `value`, MSB first; `n` is clamped to 64.
    pub fn write_bits(&mut self, value: u64, n: u32) {
        for i in (0..n.min(64)).rev() {
            self.write_bit(value.wrapping_shr(i) & 1 == 1);
        }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.write_bits(u64::from(value), 8);
    }

    pub fn write_flag(&mut self, value: bool) {
        self.write_bit(value);
    }

    /// `ue(v)` for every `u32` (u32::MAX takes a 32-zero prefix).
    pub fn write_ue(&mut self, value: u32) {
        let code = u64::from(value).saturating_add(1);
        let len = 64_u32.saturating_sub(code.leading_zeros());
        for _ in 1..len {
            self.write_bit(false);
        }
        self.write_bits(code, len);
    }

    /// `se(v)` for every `i32`.
    pub fn write_se(&mut self, value: i32) {
        let v = i64::from(value);
        let code = if v > 0 {
            v.saturating_mul(2).saturating_sub(1)
        } else {
            v.saturating_mul(-2)
        };
        self.write_ue_u64(u64::try_from(code).unwrap_or(0));
    }

    fn write_ue_u64(&mut self, value: u64) {
        let code = value.saturating_add(1);
        let len = 64_u32.saturating_sub(code.leading_zeros());
        for _ in 1..len {
            self.write_bit(false);
        }
        self.write_bits(code, len);
    }

    /// `rbsp_trailing_bits()`: a stop bit, then zeros to a byte boundary.
    pub fn write_trailing_bits(&mut self) {
        self.write_bit(true);
        while self.nbits != 0 {
            self.write_bit(false);
        }
    }

    #[must_use]
    pub fn is_byte_aligned(&self) -> bool {
        self.nbits == 0
    }

    /// The RBSP written so far; a partial last byte is zero-padded.
    #[must_use]
    pub fn into_rbsp(mut self) -> Vec<u8> {
        if self.nbits != 0 {
            let pad = 8_u32.saturating_sub(self.nbits);
            self.bytes.push(self.cur.wrapping_shl(pad));
        }
        self.bytes
    }
}

/// NAL payload → RBSP: drop every `0x03` that follows `00 00` (7.4.1).
#[must_use]
pub fn unescape_rbsp(nal_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal_payload.len());
    let mut zeros: u8 = 0;
    for &b in nal_payload {
        if zeros >= 2 && b == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(b);
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
    }
    out
}

/// RBSP → NAL payload: insert `0x03` wherever `00 00` would be followed by a
/// byte ≤ `0x03` (7.4.1), so the payload never contains `00 00 00`,
/// `00 00 01` or `00 00 02`. Every RBSP this crate writes ends in a stop
/// bit, so 7.4.1's final-`0x03` rule (only for a trailing `cabac_zero_word`)
/// never applies.
pub fn escape_rbsp_into(rbsp: &[u8], out: &mut Vec<u8>) {
    let mut zeros: u8 = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
    }
}

/// True when `nal` contains `00 00 00`, `00 00 01` or `00 00 02` — a byte
/// pattern a decoder's start-code scanner would treat as a NAL boundary
/// (§6.2: such a NAL is refused).
#[must_use]
pub fn contains_start_code(nal: &[u8]) -> bool {
    nal.windows(3)
        .any(|w| matches!(w, [0, 0, 0] | [0, 0, 1] | [0, 0, 2]))
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib bits::` — Expected: 8 passed.
Run: `cargo clippy -p kvm-proto --all-targets -- -D warnings` — Expected: clean (the module denies the six panicking lints).

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/bits.rs crates/kvm-proto/src/lib.rs
git commit -m "kvm-proto: bounded RBSP bit reader/writer and emulation prevention" \
  -m "Cross-checked against h264-reader's reader and ByteWriter (§6.8 rewriter groundwork)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2.2: Annex-B splitter and FrameId

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/annexb.rs` (append)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (re-exports)
- Test: `crates/kvm-proto/src/h264/annexb.rs` (`split_tests`)

**Interfaces:**
- Consumes: `avcc_to_annex_b` (Plan A).
- Produces (`kvm_proto::h264`): `pub struct AnnexBNals<'a>` (`Iterator<Item = &'a [u8]>`), `pub fn split_annex_b(data: &[u8]) -> AnnexBNals<'_>` — NALs between 3- or 4-byte start codes with trailing zero bytes removed; `pub fn frame_id<'a>(vcl: impl IntoIterator<Item = &'a [u8]>) -> u64` — §10.2 FrameId, FNV-1a 64 over the VCL NALs concatenated. Used by Tasks 2.3, 4.6, 6.1, 6.2, 7.1 and kvm-sim (Tasks 8.1, 8.4), and later by kvm-bench.

- [ ] **Step 1: Write the failing tests.** Append to `crates/kvm-proto/src/h264/annexb.rs`:

```rust
#[cfg(test)]
mod split_tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn splits_three_and_four_byte_start_codes_and_drops_trailing_zeros() {
        let s = [
            0xAA, 0xBB, // junk before the first start code
            0, 0, 0, 1, 0x67, 0x42, 0, 0, // SPS + trailing_zero_8bits
            0, 0, 1, 0x68, 0xCE, // 3-byte start code
            0, 0, 0, 1, 0x65, 0x88, 0x80,
        ];
        let nals: Vec<&[u8]> = split_annex_b(&s).collect();
        assert_eq!(
            nals,
            [&[0x67, 0x42][..], &[0x68, 0xCE], &[0x65, 0x88, 0x80]]
        );
    }

    #[test]
    fn empty_and_start_code_only_input_yield_nothing() {
        assert_eq!(split_annex_b(&[]).count(), 0);
        assert_eq!(split_annex_b(&[0, 0, 1]).count(), 0);
        assert_eq!(split_annex_b(&[0, 0, 0, 1, 0, 0, 0, 1]).count(), 0);
        assert_eq!(split_annex_b(&[1, 2, 3]).count(), 0);
    }

    #[test]
    fn re_splits_what_avcc_to_annex_b_writes() {
        let avcc = [0, 0, 0, 3, 0x67, 0x42, 0x10, 0, 0, 0, 2, 0x68, 0xCE];
        let mut out = Vec::new();
        avcc_to_annex_b(&avcc, 4, &mut out).unwrap_or_default();
        let nals: Vec<&[u8]> = split_annex_b(&out).collect();
        assert_eq!(nals, [&[0x67, 0x42, 0x10][..], &[0x68, 0xCE]]);
    }

    #[test]
    fn frame_id_is_fnv1a_64_over_the_concatenation() {
        // FNV-1a 64 reference values: "" and "a".
        assert_eq!(frame_id(std::iter::empty::<&[u8]>()), 0xcbf2_9ce4_8422_2325);
        assert_eq!(frame_id([&b"a"[..]]), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(
            frame_id([&[0x41, 0x9A][..], &[0x01, 0x02]]),
            frame_id([&[0x41, 0x9A, 0x01, 0x02][..]])
        );
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib split_tests`
Expected: FAIL to compile — `cannot find function split_annex_b` / `frame_id`.

- [ ] **Step 3: Implement.** Insert this above Plan A's existing `#[cfg(test)] mod tests` in `annexb.rs` (so both test modules stay last):

```rust
/// Iterator over the NAL units of an Annex-B byte stream (B.1): each NAL is
/// the bytes between one `00 00 01` start code (3- or 4-byte form) and the
/// next, with trailing zero bytes (`trailing_zero_8bits` and a 4-byte start
/// code's leading zero) removed. Bytes before the first start code are
/// skipped. Panic-free over any input.
#[derive(Debug, Clone)]
pub struct AnnexBNals<'a> {
    rest: &'a [u8],
}

/// Split an Annex-B stream into NAL units (see [`AnnexBNals`]).
#[must_use]
pub fn split_annex_b(data: &[u8]) -> AnnexBNals<'_> {
    let start = find_start_code(data).map_or(data.len(), |(_, after)| after);
    AnnexBNals {
        rest: data.get(start..).unwrap_or(&[]),
    }
}

/// `(index of the 00 00 01, index just past it)` of the first start code.
fn find_start_code(data: &[u8]) -> Option<(usize, usize)> {
    let at = data.windows(3).position(|w| w == [0, 0, 1])?;
    Some((at, at.checked_add(3)?))
}

impl<'a> Iterator for AnnexBNals<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            if self.rest.is_empty() {
                return None;
            }
            let (nal, rest) = match find_start_code(self.rest) {
                Some((at, after)) => (
                    self.rest.get(..at).unwrap_or(&[]),
                    self.rest.get(after..).unwrap_or(&[]),
                ),
                None => (self.rest, &[][..]),
            };
            self.rest = rest;
            let end = nal
                .iter()
                .rposition(|&b| b != 0)
                .map_or(0, |i| i.saturating_add(1));
            let nal = nal.get(..end).unwrap_or(&[]);
            if !nal.is_empty() {
                return Some(nal);
            }
        }
    }
}

/// §10.2 FrameId: FNV-1a 64 over the VCL NALs (types 1 and 5) of one access
/// unit, concatenated in order, header bytes included, without start codes
/// or length prefixes. kvm-sim records it on send and test clients on
/// receipt; the bridge never changes VCL bytes, so the two agree.
#[must_use]
pub fn frame_id<'a>(vcl: impl IntoIterator<Item = &'a [u8]>) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for nal in vcl {
        for &b in nal {
            h = (h ^ u64::from(b)).wrapping_mul(PRIME);
        }
    }
    h
}
```

and in `crates/kvm-proto/src/h264/mod.rs` replace `pub use annexb::{AvccError, avcc_to_annex_b};` with:

```rust
pub use annexb::{AnnexBNals, AvccError, avcc_to_annex_b, frame_id, split_annex_b};
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib split_tests` — Expected: 4 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/annexb.rs crates/kvm-proto/src/h264/mod.rs
git commit -m "kvm-proto: Annex-B splitter and §10.2 FrameId" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2.3: `SpsSyntax` — the full SPS, read and written

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps_syntax.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (`pub mod sps_syntax;`)
- Test: `crates/kvm-proto/src/h264/sps_syntax.rs` (`tests`)

**Interfaces:**
- Consumes: `kvm_proto::bits::{BitError, BitReader, BitWriter, escape_rbsp_into, unescape_rbsp}` (Task 2.1); `kvm_proto::h264::split_annex_b` (Task 2.2).
- Produces (`kvm_proto::h264::sps_syntax`):
  - `pub enum SpsSyntaxError { NotSps, Bits(BitError), OutOfRange(&'static str), Unsupported(&'static str) }` (`Copy`, `Eq`)
  - `pub struct ChromaSyntax { chroma_format_idc: u32, separate_colour_plane_flag: bool, bit_depth_luma_minus8: u32, bit_depth_chroma_minus8: u32, qpprime_y_zero_transform_bypass_flag: bool }`
  - `pub enum PocSyntax { Type0 { log2_max_pic_order_cnt_lsb_minus4: u32 }, Type1 { delta_pic_order_always_zero_flag: bool, offset_for_non_ref_pic: i32, offset_for_top_to_bottom_field: i32, offset_for_ref_frame: Vec<i32> }, Type2 }`
  - `pub struct ColourDescription { colour_primaries: u8, transfer_characteristics: u8, matrix_coefficients: u8 }`, `pub struct VideoSignalType { video_format: u8, video_full_range_flag: bool, colour_description: Option<ColourDescription> }`, `pub struct TimingInfo { num_units_in_tick: u32, time_scale: u32, fixed_frame_rate_flag: bool }`
  - `pub struct BitstreamRestriction { motion_vectors_over_pic_boundaries_flag: bool, max_bytes_per_pic_denom: u32, max_bits_per_mb_denom: u32, log2_max_mv_length_horizontal: u32, log2_max_mv_length_vertical: u32, max_num_reorder_frames: u32, max_dec_frame_buffering: u32 }` with `pub fn inferred(max_num_reorder_frames: u32, max_dec_frame_buffering: u32) -> Self` (E.2.1's inferred values: 1, 2, 1, 15, 15)
  - `pub struct VuiSyntax { aspect_ratio: Option<(u8, Option<(u16, u16)>)>, overscan_appropriate: Option<bool>, video_signal_type: Option<VideoSignalType>, chroma_loc: Option<(u32, u32)>, timing: Option<TimingInfo>, pic_struct_present_flag: bool, bitstream_restriction: Option<BitstreamRestriction> }` (`Copy`, `Default`)
  - `pub struct SpsSyntax { nal_ref_idc: u8, profile_idc: u8, constraint_flags: u8, level_idc: u8, seq_parameter_set_id: u32, chroma: Option<ChromaSyntax>, log2_max_frame_num_minus4: u32, poc: PocSyntax, max_num_ref_frames: u32, gaps_in_frame_num_value_allowed_flag: bool, pic_width_in_mbs_minus1: u32, pic_height_in_map_units_minus1: u32, frame_mbs_only_flag: bool, mb_adaptive_frame_field_flag: bool, direct_8x8_inference_flag: bool, frame_cropping: Option<[u32; 4]>, vui: Option<VuiSyntax> }` (`Clone`, `Eq`): `parse(nal: &[u8]) -> Result<SpsSyntax, SpsSyntaxError>`, `width_in_mbs(&self) -> u32`, `frame_height_in_mbs(&self) -> u32`, `to_nal(&self) -> Vec<u8>` (header byte + escaped RBSP)

- [ ] **Step 1: Write the failing tests.** Add `pub mod sps_syntax;` to `crates/kvm-proto/src/h264/mod.rs` (next to `mod slice;`) and create `crates/kvm-proto/src/h264/sps_syntax.rs` with the test module:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    /// `census.md` `sps_hex`: the ES3's SPS as sent (with a trailing zero byte).
    pub(crate) const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];

    #[test]
    fn reads_the_es3_sps_as_census_md_describes_it() {
        let s = SpsSyntax::parse(&ES3_SPS).unwrap();
        assert_eq!(
            (
                s.nal_ref_idc,
                s.profile_idc,
                s.constraint_flags,
                s.level_idc
            ),
            (3, 66, 0, 31)
        );
        assert_eq!(s.chroma, None); // Baseline: no chroma block
        assert_eq!(s.log2_max_frame_num_minus4, 4);
        assert_eq!(
            s.poc,
            PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4: 4
            }
        );
        assert_eq!(s.max_num_ref_frames, 1);
        assert_eq!((s.width_in_mbs(), s.frame_height_in_mbs()), (120, 68));
        assert!(s.frame_mbs_only_flag);
        assert_eq!(s.frame_cropping, Some([0, 0, 0, 4])); // 1088 → 1080
        let vui = s.vui.unwrap();
        assert_eq!(
            vui.video_signal_type,
            Some(VideoSignalType {
                video_format: 5,
                video_full_range_flag: true,
                colour_description: Some(ColourDescription {
                    colour_primaries: 5,
                    transfer_characteristics: 6,
                    matrix_coefficients: 5,
                }),
            })
        );
        assert_eq!((vui.timing, vui.bitstream_restriction), (None, None));
    }

    #[test]
    fn writes_back_the_same_bytes_without_the_trailing_zero() {
        let s = SpsSyntax::parse(&ES3_SPS).unwrap();
        assert_eq!(s.to_nal(), &ES3_SPS[..16]);
    }

    #[test]
    fn every_committed_fixture_sps_round_trips_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "h264") {
                continue;
            }
            let data = std::fs::read(&path).unwrap();
            for sps in crate::h264::split_annex_b(&data).filter(|n| n[0] & 0x1F == 7) {
                assert_eq!(SpsSyntax::parse(sps).unwrap().to_nal(), sps, "{path:?}");
                seen += 1;
            }
        }
        assert!(seen >= 10, "only {seen} SPSs found");
    }

    fn nal(w: BitWriter) -> Vec<u8> {
        let mut out = vec![0x67];
        escape_rbsp_into(&w.into_rbsp(), &mut out);
        out
    }

    #[test]
    fn refuses_what_section_6_1_refuses_and_what_is_malformed() {
        // High profile with seq_scaling_matrix_present_flag = 1.
        let mut w = BitWriter::new();
        w.write_u8(100);
        w.write_u8(0);
        w.write_u8(40);
        w.write_ue(0);
        w.write_ue(1); // chroma_format_idc
        w.write_ue(0);
        w.write_ue(0);
        w.write_flag(false);
        w.write_flag(true); // seq_scaling_matrix_present_flag
        w.write_trailing_bits();
        assert_eq!(
            SpsSyntax::parse(&nal(w)),
            Err(SpsSyntaxError::Unsupported(
                "seq_scaling_matrix_present_flag"
            ))
        );
        // Baseline with a VUI announcing NAL, then VCL, HRD parameters.
        let hrd = |nal_hrd: bool| {
            let mut w = BitWriter::new();
            w.write_u8(66);
            w.write_u8(0);
            w.write_u8(30);
            for v in [0, 0, 2, 1] {
                w.write_ue(v); // sps_id, log2_max_frame_num_minus4, poc type, refs
            }
            w.write_flag(false);
            w.write_ue(39);
            w.write_ue(22);
            w.write_flag(true);
            w.write_flag(true);
            w.write_flag(false);
            w.write_flag(true); // vui_parameters_present_flag
            for _ in 0..5 {
                w.write_flag(false);
            }
            w.write_flag(nal_hrd); // nal_hrd_parameters_present_flag
            w.write_flag(!nal_hrd); // vcl_hrd_parameters_present_flag
            w.write_trailing_bits();
            nal(w)
        };
        assert_eq!(
            SpsSyntax::parse(&hrd(true)),
            Err(SpsSyntaxError::Unsupported(
                "nal_hrd_parameters_present_flag"
            ))
        );
        assert_eq!(
            SpsSyntax::parse(&hrd(false)),
            Err(SpsSyntaxError::Unsupported(
                "vcl_hrd_parameters_present_flag"
            ))
        );
        // seq_parameter_set_id 32.
        let mut w = BitWriter::new();
        w.write_u8(66);
        w.write_u8(0);
        w.write_u8(30);
        w.write_ue(32);
        w.write_trailing_bits();
        assert_eq!(
            SpsSyntax::parse(&nal(w)),
            Err(SpsSyntaxError::OutOfRange("seq_parameter_set_id"))
        );
        // Truncated, trailing data, and not an SPS at all.
        assert_eq!(
            SpsSyntax::parse(&ES3_SPS[..8]),
            Err(SpsSyntaxError::Bits(BitError::Eof))
        );
        let mut extra = ES3_SPS[..16].to_vec();
        extra.push(0x80);
        assert_eq!(
            SpsSyntax::parse(&extra),
            Err(SpsSyntaxError::Bits(BitError::TrailingData))
        );
        assert_eq!(SpsSyntax::parse(&[0x68, 0xce]), Err(SpsSyntaxError::NotSps));
        assert_eq!(SpsSyntax::parse(&[0xE7, 0x42]), Err(SpsSyntaxError::NotSps));
        assert_eq!(SpsSyntax::parse(&[]), Err(SpsSyntaxError::NotSps));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib sps_syntax`
Expected: FAIL to compile — `cannot find type SpsSyntax` (and the other types).

- [ ] **Step 3: Implement.** Put this above the test module in `sps_syntax.rs`. It reads only what §6.1 admits — a scaling matrix or HRD parameters are `Unsupported` before their bits are read — and bounds every syntax element to its H.264 range:

```rust
//! The full `seq_parameter_set_rbsp()` syntax (H.264 7.3.2.1.1 and E.1.1),
//! read with kvm-proto's own bounded bit reader and written back field by
//! field (§6.8). h264-reader refuses the ES3's SPS as sent (its level is
//! below its coded size), so the rewriter cannot start from h264-reader's
//! parse. Scaling matrices and HRD parameters are not read: §6.1 refuses
//! both, so such an SPS is `Unsupported`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::bits::{BitError, BitReader, BitWriter, escape_rbsp_into, unescape_rbsp};

/// Why an SPS could not be read into an [`SpsSyntax`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpsSyntaxError {
    /// Empty NAL, forbidden bit set, or not `nal_unit_type` 7.
    NotSps,
    /// The bitstream ended early, an Exp-Golomb code was too long, or data
    /// followed the syntax where `rbsp_trailing_bits()` belongs.
    Bits(BitError),
    /// A syntax element was outside its H.264 range.
    OutOfRange(&'static str),
    /// Syntax the rewriter does not read because §6.1 refuses it.
    Unsupported(&'static str),
}

impl From<BitError> for SpsSyntaxError {
    fn from(e: BitError) -> Self {
        SpsSyntaxError::Bits(e)
    }
}

/// `chroma_format_idc` .. `qpprime_y_zero_transform_bypass_flag`, present
/// only for the profiles listed in 7.3.2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromaSyntax {
    pub chroma_format_idc: u32,
    pub separate_colour_plane_flag: bool,
    pub bit_depth_luma_minus8: u32,
    pub bit_depth_chroma_minus8: u32,
    pub qpprime_y_zero_transform_bypass_flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocSyntax {
    Type0 {
        log2_max_pic_order_cnt_lsb_minus4: u32,
    },
    Type1 {
        delta_pic_order_always_zero_flag: bool,
        offset_for_non_ref_pic: i32,
        offset_for_top_to_bottom_field: i32,
        offset_for_ref_frame: Vec<i32>,
    },
    Type2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColourDescription {
    pub colour_primaries: u8,
    pub transfer_characteristics: u8,
    pub matrix_coefficients: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoSignalType {
    pub video_format: u8,
    pub video_full_range_flag: bool,
    pub colour_description: Option<ColourDescription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingInfo {
    pub num_units_in_tick: u32,
    pub time_scale: u32,
    pub fixed_frame_rate_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitstreamRestriction {
    pub motion_vectors_over_pic_boundaries_flag: bool,
    pub max_bytes_per_pic_denom: u32,
    pub max_bits_per_mb_denom: u32,
    pub log2_max_mv_length_horizontal: u32,
    pub log2_max_mv_length_vertical: u32,
    pub max_num_reorder_frames: u32,
    pub max_dec_frame_buffering: u32,
}

impl BitstreamRestriction {
    /// The structure's fields at the values H.264 infers when it is absent
    /// (E.2.1), with the two reordering fields set as §6.8 (c) requires.
    #[must_use]
    pub fn inferred(max_num_reorder_frames: u32, max_dec_frame_buffering: u32) -> Self {
        Self {
            motion_vectors_over_pic_boundaries_flag: true,
            max_bytes_per_pic_denom: 2,
            max_bits_per_mb_denom: 1,
            log2_max_mv_length_horizontal: 15,
            log2_max_mv_length_vertical: 15,
            max_num_reorder_frames,
            max_dec_frame_buffering,
        }
    }
}

/// `vui_parameters()` without HRD parameters (§6.1 refuses them).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VuiSyntax {
    /// `aspect_ratio_idc`, and `(sar_width, sar_height)` when it is 255.
    pub aspect_ratio: Option<(u8, Option<(u16, u16)>)>,
    /// `overscan_appropriate_flag` when `overscan_info_present_flag` is 1.
    pub overscan_appropriate: Option<bool>,
    pub video_signal_type: Option<VideoSignalType>,
    /// `(chroma_sample_loc_type_top_field, …_bottom_field)`.
    pub chroma_loc: Option<(u32, u32)>,
    pub timing: Option<TimingInfo>,
    pub pic_struct_present_flag: bool,
    pub bitstream_restriction: Option<BitstreamRestriction>,
}

/// Every syntax element of an SPS the rewriter admits, in syntax order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpsSyntax {
    /// `nal_ref_idc` of the NAL header (the header is rebuilt from it).
    pub nal_ref_idc: u8,
    pub profile_idc: u8,
    /// `constraint_set0_flag` .. `constraint_set5_flag` and
    /// `reserved_zero_2bits`, as one byte.
    pub constraint_flags: u8,
    pub level_idc: u8,
    pub seq_parameter_set_id: u32,
    pub chroma: Option<ChromaSyntax>,
    pub log2_max_frame_num_minus4: u32,
    pub poc: PocSyntax,
    pub max_num_ref_frames: u32,
    pub gaps_in_frame_num_value_allowed_flag: bool,
    pub pic_width_in_mbs_minus1: u32,
    pub pic_height_in_map_units_minus1: u32,
    pub frame_mbs_only_flag: bool,
    /// Present only when `frame_mbs_only_flag` is 0.
    pub mb_adaptive_frame_field_flag: bool,
    pub direct_8x8_inference_flag: bool,
    /// `frame_crop_{left,right,top,bottom}_offset`.
    pub frame_cropping: Option<[u32; 4]>,
    pub vui: Option<VuiSyntax>,
}

/// Profiles whose SPS carries the chroma block (7.3.2.1.1).
fn has_chroma_block(profile_idc: u8) -> bool {
    matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    )
}

fn ue_max(r: &mut BitReader<'_>, max: u32, name: &'static str) -> Result<u32, SpsSyntaxError> {
    let v = r.read_ue()?;
    if v > max {
        return Err(SpsSyntaxError::OutOfRange(name));
    }
    Ok(v)
}

impl SpsSyntax {
    /// Read a wire SPS NAL (header byte + emulation-prevented payload).
    pub fn parse(nal: &[u8]) -> Result<SpsSyntax, SpsSyntaxError> {
        let (&header, payload) = nal.split_first().ok_or(SpsSyntaxError::NotSps)?;
        if header & 0x80 != 0 || header & 0x1F != 7 {
            return Err(SpsSyntaxError::NotSps);
        }
        let rbsp = unescape_rbsp(payload);
        let mut r = BitReader::new(&rbsp);
        let profile_idc = r.read_u8()?;
        let constraint_flags = r.read_u8()?;
        let level_idc = r.read_u8()?;
        let seq_parameter_set_id = ue_max(&mut r, 31, "seq_parameter_set_id")?;
        let chroma = if has_chroma_block(profile_idc) {
            let chroma_format_idc = ue_max(&mut r, 3, "chroma_format_idc")?;
            let separate_colour_plane_flag = chroma_format_idc == 3 && r.read_flag()?;
            let bit_depth_luma_minus8 = ue_max(&mut r, 6, "bit_depth_luma_minus8")?;
            let bit_depth_chroma_minus8 = ue_max(&mut r, 6, "bit_depth_chroma_minus8")?;
            let qpprime_y_zero_transform_bypass_flag = r.read_flag()?;
            if r.read_flag()? {
                return Err(SpsSyntaxError::Unsupported(
                    "seq_scaling_matrix_present_flag",
                ));
            }
            Some(ChromaSyntax {
                chroma_format_idc,
                separate_colour_plane_flag,
                bit_depth_luma_minus8,
                bit_depth_chroma_minus8,
                qpprime_y_zero_transform_bypass_flag,
            })
        } else {
            None
        };
        let log2_max_frame_num_minus4 = ue_max(&mut r, 12, "log2_max_frame_num_minus4")?;
        let poc = match r.read_ue()? {
            0 => PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4: ue_max(
                    &mut r,
                    12,
                    "log2_max_pic_order_cnt_lsb_minus4",
                )?,
            },
            1 => {
                let delta_pic_order_always_zero_flag = r.read_flag()?;
                let offset_for_non_ref_pic = r.read_se()?;
                let offset_for_top_to_bottom_field = r.read_se()?;
                let n = ue_max(&mut r, 255, "num_ref_frames_in_pic_order_cnt_cycle")?;
                let mut offset_for_ref_frame = Vec::new();
                for _ in 0..n {
                    offset_for_ref_frame.push(r.read_se()?);
                }
                PocSyntax::Type1 {
                    delta_pic_order_always_zero_flag,
                    offset_for_non_ref_pic,
                    offset_for_top_to_bottom_field,
                    offset_for_ref_frame,
                }
            }
            2 => PocSyntax::Type2,
            _ => return Err(SpsSyntaxError::OutOfRange("pic_order_cnt_type")),
        };
        let max_num_ref_frames = ue_max(&mut r, 16, "max_num_ref_frames")?;
        let gaps_in_frame_num_value_allowed_flag = r.read_flag()?;
        let pic_width_in_mbs_minus1 = ue_max(&mut r, 1023, "pic_width_in_mbs_minus1")?;
        let pic_height_in_map_units_minus1 =
            ue_max(&mut r, 1023, "pic_height_in_map_units_minus1")?;
        let frame_mbs_only_flag = r.read_flag()?;
        let mb_adaptive_frame_field_flag = !frame_mbs_only_flag && r.read_flag()?;
        let direct_8x8_inference_flag = r.read_flag()?;
        let frame_cropping = if r.read_flag()? {
            Some([r.read_ue()?, r.read_ue()?, r.read_ue()?, r.read_ue()?])
        } else {
            None
        };
        let vui = if r.read_flag()? {
            Some(read_vui(&mut r)?)
        } else {
            None
        };
        r.finish()?;
        Ok(SpsSyntax {
            nal_ref_idc: header.wrapping_shr(5) & 0x03,
            profile_idc,
            constraint_flags,
            level_idc,
            seq_parameter_set_id,
            chroma,
            log2_max_frame_num_minus4,
            poc,
            max_num_ref_frames,
            gaps_in_frame_num_value_allowed_flag,
            pic_width_in_mbs_minus1,
            pic_height_in_map_units_minus1,
            frame_mbs_only_flag,
            mb_adaptive_frame_field_flag,
            direct_8x8_inference_flag,
            frame_cropping,
            vui,
        })
    }

    /// `PicWidthInMbs`.
    #[must_use]
    pub fn width_in_mbs(&self) -> u32 {
        self.pic_width_in_mbs_minus1.saturating_add(1)
    }

    /// `FrameHeightInMbs` = (2 − `frame_mbs_only_flag`) × `PicHeightInMapUnits`.
    #[must_use]
    pub fn frame_height_in_mbs(&self) -> u32 {
        let units = self.pic_height_in_map_units_minus1.saturating_add(1);
        if self.frame_mbs_only_flag {
            units
        } else {
            units.saturating_mul(2)
        }
    }

    /// The SPS as a wire NAL: header byte, then the escaped RBSP.
    #[must_use]
    pub fn to_nal(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_u8(self.profile_idc);
        w.write_u8(self.constraint_flags);
        w.write_u8(self.level_idc);
        w.write_ue(self.seq_parameter_set_id);
        if let Some(c) = &self.chroma {
            w.write_ue(c.chroma_format_idc);
            if c.chroma_format_idc == 3 {
                w.write_flag(c.separate_colour_plane_flag);
            }
            w.write_ue(c.bit_depth_luma_minus8);
            w.write_ue(c.bit_depth_chroma_minus8);
            w.write_flag(c.qpprime_y_zero_transform_bypass_flag);
            w.write_flag(false); // seq_scaling_matrix_present_flag
        }
        w.write_ue(self.log2_max_frame_num_minus4);
        match &self.poc {
            PocSyntax::Type0 {
                log2_max_pic_order_cnt_lsb_minus4,
            } => {
                w.write_ue(0);
                w.write_ue(*log2_max_pic_order_cnt_lsb_minus4);
            }
            PocSyntax::Type1 {
                delta_pic_order_always_zero_flag,
                offset_for_non_ref_pic,
                offset_for_top_to_bottom_field,
                offset_for_ref_frame,
            } => {
                w.write_ue(1);
                w.write_flag(*delta_pic_order_always_zero_flag);
                w.write_se(*offset_for_non_ref_pic);
                w.write_se(*offset_for_top_to_bottom_field);
                w.write_ue(u32::try_from(offset_for_ref_frame.len()).unwrap_or(u32::MAX));
                for o in offset_for_ref_frame {
                    w.write_se(*o);
                }
            }
            PocSyntax::Type2 => w.write_ue(2),
        }
        w.write_ue(self.max_num_ref_frames);
        w.write_flag(self.gaps_in_frame_num_value_allowed_flag);
        w.write_ue(self.pic_width_in_mbs_minus1);
        w.write_ue(self.pic_height_in_map_units_minus1);
        w.write_flag(self.frame_mbs_only_flag);
        if !self.frame_mbs_only_flag {
            w.write_flag(self.mb_adaptive_frame_field_flag);
        }
        w.write_flag(self.direct_8x8_inference_flag);
        match &self.frame_cropping {
            Some(c) => {
                w.write_flag(true);
                for v in c {
                    w.write_ue(*v);
                }
            }
            None => w.write_flag(false),
        }
        match &self.vui {
            Some(v) => {
                w.write_flag(true);
                write_vui(&mut w, v);
            }
            None => w.write_flag(false),
        }
        w.write_trailing_bits();
        let rbsp = w.into_rbsp();
        let mut nal = Vec::with_capacity(rbsp.len().saturating_add(8));
        nal.push(self.nal_ref_idc.wrapping_shl(5) & 0x60 | 7);
        escape_rbsp_into(&rbsp, &mut nal);
        nal
    }
}

fn read_vui(r: &mut BitReader<'_>) -> Result<VuiSyntax, SpsSyntaxError> {
    let aspect_ratio = if r.read_flag()? {
        let idc = r.read_u8()?;
        let sar = if idc == 255 {
            let w = u16::try_from(r.read_bits(16)?).map_err(|_| BitError::TooManyBits)?;
            let h = u16::try_from(r.read_bits(16)?).map_err(|_| BitError::TooManyBits)?;
            Some((w, h))
        } else {
            None
        };
        Some((idc, sar))
    } else {
        None
    };
    let overscan_appropriate = if r.read_flag()? {
        Some(r.read_flag()?)
    } else {
        None
    };
    let video_signal_type = if r.read_flag()? {
        let video_format = u8::try_from(r.read_bits(3)?).map_err(|_| BitError::TooManyBits)?;
        let video_full_range_flag = r.read_flag()?;
        let colour_description = if r.read_flag()? {
            Some(ColourDescription {
                colour_primaries: r.read_u8()?,
                transfer_characteristics: r.read_u8()?,
                matrix_coefficients: r.read_u8()?,
            })
        } else {
            None
        };
        Some(VideoSignalType {
            video_format,
            video_full_range_flag,
            colour_description,
        })
    } else {
        None
    };
    let chroma_loc = if r.read_flag()? {
        Some((
            ue_max(r, 5, "chroma_sample_loc_type_top_field")?,
            ue_max(r, 5, "chroma_sample_loc_type_bottom_field")?,
        ))
    } else {
        None
    };
    let timing = if r.read_flag()? {
        Some(TimingInfo {
            num_units_in_tick: r.read_bits(32)?,
            time_scale: r.read_bits(32)?,
            fixed_frame_rate_flag: r.read_flag()?,
        })
    } else {
        None
    };
    if r.read_flag()? {
        return Err(SpsSyntaxError::Unsupported(
            "nal_hrd_parameters_present_flag",
        ));
    }
    if r.read_flag()? {
        return Err(SpsSyntaxError::Unsupported(
            "vcl_hrd_parameters_present_flag",
        ));
    }
    let pic_struct_present_flag = r.read_flag()?;
    let bitstream_restriction = if r.read_flag()? {
        Some(BitstreamRestriction {
            motion_vectors_over_pic_boundaries_flag: r.read_flag()?,
            max_bytes_per_pic_denom: ue_max(r, 16, "max_bytes_per_pic_denom")?,
            max_bits_per_mb_denom: ue_max(r, 16, "max_bits_per_mb_denom")?,
            log2_max_mv_length_horizontal: ue_max(r, 16, "log2_max_mv_length_horizontal")?,
            log2_max_mv_length_vertical: ue_max(r, 16, "log2_max_mv_length_vertical")?,
            max_num_reorder_frames: ue_max(r, 16, "max_num_reorder_frames")?,
            max_dec_frame_buffering: ue_max(r, 16, "max_dec_frame_buffering")?,
        })
    } else {
        None
    };
    Ok(VuiSyntax {
        aspect_ratio,
        overscan_appropriate,
        video_signal_type,
        chroma_loc,
        timing,
        pic_struct_present_flag,
        bitstream_restriction,
    })
}

fn write_vui(w: &mut BitWriter, v: &VuiSyntax) {
    match v.aspect_ratio {
        Some((idc, sar)) => {
            w.write_flag(true);
            w.write_u8(idc);
            if idc == 255 {
                let (sw, sh) = sar.unwrap_or((0, 0));
                w.write_bits(u64::from(sw), 16);
                w.write_bits(u64::from(sh), 16);
            }
        }
        None => w.write_flag(false),
    }
    match v.overscan_appropriate {
        Some(f) => {
            w.write_flag(true);
            w.write_flag(f);
        }
        None => w.write_flag(false),
    }
    match v.video_signal_type {
        Some(s) => {
            w.write_flag(true);
            w.write_bits(u64::from(s.video_format), 3);
            w.write_flag(s.video_full_range_flag);
            match s.colour_description {
                Some(c) => {
                    w.write_flag(true);
                    w.write_u8(c.colour_primaries);
                    w.write_u8(c.transfer_characteristics);
                    w.write_u8(c.matrix_coefficients);
                }
                None => w.write_flag(false),
            }
        }
        None => w.write_flag(false),
    }
    match v.chroma_loc {
        Some((top, bottom)) => {
            w.write_flag(true);
            w.write_ue(top);
            w.write_ue(bottom);
        }
        None => w.write_flag(false),
    }
    match v.timing {
        Some(t) => {
            w.write_flag(true);
            w.write_bits(u64::from(t.num_units_in_tick), 32);
            w.write_bits(u64::from(t.time_scale), 32);
            w.write_flag(t.fixed_frame_rate_flag);
        }
        None => w.write_flag(false),
    }
    w.write_flag(false); // nal_hrd_parameters_present_flag
    w.write_flag(false); // vcl_hrd_parameters_present_flag
    w.write_flag(v.pic_struct_present_flag);
    match v.bitstream_restriction {
        Some(b) => {
            w.write_flag(true);
            w.write_flag(b.motion_vectors_over_pic_boundaries_flag);
            w.write_ue(b.max_bytes_per_pic_denom);
            w.write_ue(b.max_bits_per_mb_denom);
            w.write_ue(b.log2_max_mv_length_horizontal);
            w.write_ue(b.log2_max_mv_length_vertical);
            w.write_ue(b.max_num_reorder_frames);
            w.write_ue(b.max_dec_frame_buffering);
        }
        None => w.write_flag(false),
    }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib sps_syntax` — Expected: 4 passed (`every_committed_fixture_sps_round_trips_byte_for_byte` covers every SPS in all 9 committed `.h264` fixtures — at least 10 SPSs, since x264 repeats them — and Task 6.1's 10th fixture joins it there).

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/sps_syntax.rs crates/kvm-proto/src/h264/mod.rs
git commit -m "kvm-proto: full SPS syntax reader and writer (§6.8)" \
  -m "Reads the ES3's SPS as census.md describes it; every committed fixture SPS round-trips byte for byte." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2.4: The SPS rewriter (§6.8) and its goldens

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/rewrite.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (`pub mod rewrite;`)
- Test: `crates/kvm-proto/src/h264/rewrite.rs` (`tests`)

**Interfaces:**
- Consumes: `SpsSyntax` and friends (Task 2.3); `kvm_proto::h264::{SpsSummary, SpsSummaryError, parse_sps}` (Plan A); `h264_reader::nal::{RefNal, WritableNal, NalHeader}`, `h264_reader::nal::sps::SeqParameterSet`.
- Produces (`kvm_proto::h264::rewrite`):
  - `pub struct RewriteConfig { level: bool, vui: bool, restriction: bool, max_fps: u32 }` with `pub const ES3: RewriteConfig` (all three, 30 fps)
  - `pub struct RewriteFields { level: bool, vui: bool, restriction: bool }` (`Copy`, `Default`, `Eq`) — which rewrites changed the SPS (the `sps_rewrites{field}` metric)
  - `pub enum RewriteError { Unreadable(SpsSyntaxError), NoLevel { width_mbs: u32, height_mbs: u32 }, SelfCheck, H264Reader(String), Disagrees, Summary(String) }` (`Eq`)
  - `pub struct RewrittenSps { nal: Vec<u8>, syntax: SpsSyntax, parsed: SeqParameterSet, summary: SpsSummary, changed: RewriteFields }`
  - `pub fn required_level_idc(width_mbs: u32, height_mbs: u32, fps: u32) -> Option<u8>` (Table A-1 and the rest of A.3.1's frame-size rules — deviation D9)
  - `pub fn apply_rewrites(s: &mut SpsSyntax, cfg: &RewriteConfig) -> Result<RewriteFields, RewriteError>`
  - `pub fn rewrite_sps(nal: &[u8], cfg: &RewriteConfig) -> Result<RewrittenSps, RewriteError>` — rewrite, re-serialise, verify; Task 4.5 calls it on every SPS

- [ ] **Step 1: Write the failing tests.** Add `pub mod rewrite;` to `crates/kvm-proto/src/h264/mod.rs` and create `crates/kvm-proto/src/h264/rewrite.rs` with the test module. The ES3 golden below was checked bit by bit while writing this plan (level byte `1f`→`28`; VUI `dc 14 18 14 08` → `d4 04 04 04` with full-range 0 and 1/1/1; then `1b 41 00 85 40`: no chroma-loc/timing/HRD, `bitstream_restriction_flag` 1, `motion_vectors_over_pic_boundaries` 1, `ue(2) ue(1) ue(15) ue(15) ue(0) ue(1)`, stop bit), and h264-reader's own writer reproduces it:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::h264::sps_syntax::TimingInfo;
    use crate::h264::test_support::SpsCfg;

    /// `census.md` `sps_hex`: the ES3's SPS as sent.
    const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn fixture_sps(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        let data = std::fs::read(p).unwrap();
        crate::h264::split_annex_b(&data)
            .find(|n| n[0] & 0x1F == 7)
            .unwrap()
            .to_vec()
    }

    /// The L0 golden (§11.2): level 31 → 40, VUI limited-range BT.709,
    /// bitstream_restriction 0/1 added — hand-checked bit by bit in Plan B;
    /// `scripts/gen-fixtures.sh es3like` (Task 6.1) re-reads this hex and the
    /// level+VUI one below with ffmpeg's trace_headers on every run.
    #[test]
    fn es3_sps_golden() {
        assert!(
            crate::h264::parse_sps(&ES3_SPS).is_err(),
            "h264-reader refuses it as sent"
        );
        let r = rewrite_sps(&ES3_SPS, &RewriteConfig::ES3).unwrap();
        assert_eq!(hex(&r.nal), "67420028965403c0112f2cd40404041b41008540");
        assert_eq!(
            r.changed,
            RewriteFields {
                level: true,
                vui: true,
                restriction: true
            }
        );
        let s = &r.summary;
        assert_eq!(
            (s.width, s.height, s.level_idc, s.profile_idc),
            (1920, 1080, 40, 66)
        );
        assert_eq!(s.video_full_range_flag, Some(false));
        assert_eq!(
            (s.colour_primaries, s.matrix_coefficients),
            (Some(1), Some(1))
        );
        assert_eq!(
            (s.max_num_reorder_frames, s.max_dec_frame_buffering),
            (Some(0), Some(1))
        );
    }

    #[test]
    fn es3_level_and_vui_only() {
        let cfg = RewriteConfig {
            restriction: false,
            ..RewriteConfig::ES3
        };
        let r = rewrite_sps(&ES3_SPS, &cfg).unwrap();
        assert_eq!(hex(&r.nal), "67420028965403c0112f2cd404040408");
        assert_eq!(r.summary.max_num_reorder_frames, None);
    }

    #[test]
    fn level_table_a1() {
        assert_eq!(required_level_idc(120, 68, 30), Some(40)); // the ES3's 1080p30
        assert_eq!(required_level_idc(120, 68, 60), Some(42)); // 60 fps needs 4.2
        assert_eq!(required_level_idc(40, 23, 30), Some(30));
        assert_eq!(required_level_idc(11, 9, 15), Some(10));
        assert_eq!(required_level_idc(1024, 1024, 30), None);
        // A.3.1 (D9): a 4096×16 strip (256 × 1 MBs) fits MaxFS from level 1.1,
        // but PicWidthInMbs² ≤ 8 × MaxFS first holds at 4.0 (256² = 8 × 8192).
        assert_eq!(required_level_idc(256, 1, 30), Some(40));
    }

    #[test]
    fn a_level_that_admits_the_size_is_never_lowered() {
        let mut c = SpsCfg::main_1080p();
        c.level_idc = 51;
        let r = rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap();
        assert_eq!(r.summary.level_idc, 51);
        assert!(!r.changed.level);
    }

    #[test]
    fn an_already_correct_sps_is_byte_identical() {
        // x264's limited-range BT.709 fixture: level 31 admits 640×360 at
        // 30 fps and bitstream_restriction is present.
        let sps = fixture_sps("360p30_main_limited.h264");
        let r = rewrite_sps(&sps, &RewriteConfig::ES3).unwrap();
        assert_eq!(r.nal, sps);
        assert_eq!(r.changed, RewriteFields::default());
    }

    #[test]
    fn an_existing_bitstream_restriction_is_kept() {
        let sps = fixture_sps("360p30_main_full.h264");
        let before = SpsSyntax::parse(&sps)
            .unwrap()
            .vui
            .unwrap()
            .bitstream_restriction;
        assert!(before.is_some());
        let r = rewrite_sps(&sps, &RewriteConfig::ES3).unwrap();
        assert_eq!(r.syntax.vui.unwrap().bitstream_restriction, before);
        assert!(r.changed.vui && !r.changed.restriction);
    }

    #[test]
    fn re_serialising_zeros_gains_emulation_prevention() {
        // num_units_in_tick = 1 puts `00 00 00 01` in the RBSP. With no
        // video_signal_type in the input, the VUI rewrite inserts 29 bits
        // ahead of that zero run, so its escapes land at new offsets.
        let mut s = SpsSyntax::parse(&ES3_SPS).unwrap();
        let vui = s.vui.as_mut().unwrap();
        vui.video_signal_type = None;
        vui.timing = Some(TimingInfo {
            num_units_in_tick: 1,
            time_scale: 60,
            fixed_frame_rate_flag: false,
        });
        let input = s.to_nal();
        let escapes = |n: &[u8]| -> Vec<usize> {
            n.windows(3)
                .enumerate()
                .filter(|(_, w)| *w == [0, 0, 3])
                .map(|(i, _)| i)
                .collect()
        };
        let r = rewrite_sps(&input, &RewriteConfig::ES3).unwrap();
        assert!(!escapes(&input).is_empty() && !escapes(&r.nal).is_empty());
        assert_ne!(escapes(&input), escapes(&r.nal), "the zero run moved");
        assert!(!crate::bits::contains_start_code(&r.nal));
        assert_eq!(SpsSyntax::parse(&r.nal).unwrap(), r.syntax);
        let t = r.parsed.vui_parameters.unwrap().timing_info.unwrap();
        assert_eq!((t.num_units_in_tick, t.time_scale), (1, 60));
    }

    #[test]
    fn what_cannot_be_read_or_levelled_is_refused() {
        assert_eq!(
            rewrite_sps(&[0x67], &RewriteConfig::ES3).unwrap_err(),
            RewriteError::Unreadable(SpsSyntaxError::Bits(crate::bits::BitError::Eof))
        );
        let mut huge = SpsCfg::main_1080p();
        huge.pic_width_in_mbs_minus1 = 1023;
        huge.pic_height_in_map_units_minus1 = 1023;
        huge.crop = None;
        assert_eq!(
            rewrite_sps(&huge.build(), &RewriteConfig::ES3).unwrap_err(),
            RewriteError::NoLevel {
                width_mbs: 1024,
                height_mbs: 1024
            }
        );
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib rewrite::`
Expected: FAIL to compile — `cannot find function rewrite_sps` / `required_level_idc`, `RewriteConfig`, `RewriteError`, `RewriteFields`.

- [ ] **Step 3: Implement.** Put this above the test module in `rewrite.rs`:

```rust
//! The §6.8 SPS rewriter: raise `level_idc` to what the coded size needs,
//! make the VUI say what the ES3's pixels measure (limited-range BT.709),
//! and add `bitstream_restriction` so a decoder never holds frames. It runs
//! on every SPS before anything parses or checks it; its output is what is
//! admitted, classified, cached and sent (§6.1, §6.3).
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::sps_syntax::{
    BitstreamRestriction, ColourDescription, SpsSyntax, SpsSyntaxError, VideoSignalType, VuiSyntax,
};
use crate::h264::{SpsSummary, SpsSummaryError};
use h264_reader::nal::WritableNal as _;
use h264_reader::nal::sps::SeqParameterSet;

/// `video.sps_rewrite` plus `video.max_fps` (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteConfig {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
    pub max_fps: u32,
}

impl RewriteConfig {
    /// `["level", "vui", "restriction"]` at 30 fps — the ES3 default.
    pub const ES3: RewriteConfig = RewriteConfig {
        level: true,
        vui: true,
        restriction: true,
        max_fps: 30,
    };
}

/// Which rewrites changed the SPS (the `sps_rewrites{field}` metric).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewriteFields {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
}

/// Why an SPS could not be rewritten. Every variant is
/// `stream_incompatible` (§6.8, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteError {
    /// kvm-proto's reader could not read it (§6.8: it reads only what §6.1 admits).
    Unreadable(SpsSyntaxError),
    /// No level in H.264 Table A-1 admits the coded size at `max_fps`.
    NoLevel { width_mbs: u32, height_mbs: u32 },
    /// Reading the output back with kvm-proto's reader gave other fields.
    SelfCheck,
    /// h264-reader refused the output.
    H264Reader(String),
    /// h264-reader parsed the output but did not re-serialise it to the same
    /// bytes, so it read different fields than were written.
    Disagrees,
    /// The parsed output has no valid summary (chroma or cropping).
    Summary(String),
}

/// A rewritten, verified SPS.
#[derive(Debug, Clone)]
pub struct RewrittenSps {
    /// The SPS NAL to admit, cache and send (header byte included).
    pub nal: Vec<u8>,
    pub syntax: SpsSyntax,
    /// h264-reader's parse of `nal`, for the PPS and slice checks.
    pub parsed: SeqParameterSet,
    pub summary: SpsSummary,
    pub changed: RewriteFields,
}

/// H.264 Table A-1: (`level_idc`, MaxMBPS, MaxFS), ascending. Level 1b is
/// left out: the lowest level that admits a size is never 1b.
const LEVELS: [(u8, u64, u64); 16] = [
    (10, 1_485, 99),
    (11, 3_000, 396),
    (12, 6_000, 396),
    (13, 11_880, 396),
    (20, 11_880, 396),
    (21, 19_800, 792),
    (22, 20_250, 1_620),
    (30, 40_500, 1_620),
    (31, 108_000, 3_600),
    (32, 216_000, 5_120),
    (40, 245_760, 8_192),
    (41, 245_760, 8_192),
    (42, 522_240, 8_704),
    (50, 589_824, 22_080),
    (51, 983_040, 36_864),
    (52, 2_073_600, 36_864),
];

/// The lowest `level_idc` whose MaxFS and MaxMBPS admit a
/// `width_mbs` × `height_mbs` frame at `fps` (A.3.1: FrameSizeInMbs ≤
/// MaxFS, PicWidthInMbs² and FrameHeightInMbs² ≤ 8 × MaxFS, and
/// FrameSizeInMbs × fps ≤ MaxMBPS — the side rule is beyond §6.8 (a)'s two
/// columns, deviation D9).
#[must_use]
pub fn required_level_idc(width_mbs: u32, height_mbs: u32, fps: u32) -> Option<u8> {
    let (w, h) = (u64::from(width_mbs), u64::from(height_mbs));
    let fs = w.saturating_mul(h);
    let mbps = fs.saturating_mul(u64::from(fps));
    LEVELS
        .iter()
        .find(|&&(_, max_mbps, max_fs)| {
            let side = max_fs.saturating_mul(8);
            fs <= max_fs
                && mbps <= max_mbps
                && w.saturating_mul(w) <= side
                && h.saturating_mul(h) <= side
        })
        .map(|&(idc, _, _)| idc)
}

/// Apply the configured rewrites to a parsed SPS, in place; returns which
/// ones changed it.
pub fn apply_rewrites(
    s: &mut SpsSyntax,
    cfg: &RewriteConfig,
) -> Result<RewriteFields, RewriteError> {
    let mut changed = RewriteFields::default();
    if cfg.level {
        let (w, h) = (s.width_in_mbs(), s.frame_height_in_mbs());
        let need = required_level_idc(w, h, cfg.max_fps).ok_or(RewriteError::NoLevel {
            width_mbs: w,
            height_mbs: h,
        })?;
        if need > s.level_idc {
            s.level_idc = need;
            changed.level = true;
        }
    }
    if cfg.vui {
        let vui = s.vui.get_or_insert_with(VuiSyntax::default);
        let video_format = vui.video_signal_type.map_or(5, |v| v.video_format);
        let want = Some(VideoSignalType {
            video_format,
            video_full_range_flag: false,
            colour_description: Some(ColourDescription {
                colour_primaries: 1,
                transfer_characteristics: 1,
                matrix_coefficients: 1,
            }),
        });
        if vui.video_signal_type != want {
            vui.video_signal_type = want;
            changed.vui = true;
        }
    }
    if cfg.restriction {
        let dpb = s.max_num_ref_frames.max(1);
        let vui = s.vui.get_or_insert_with(VuiSyntax::default);
        if vui.bitstream_restriction.is_none() {
            vui.bitstream_restriction = Some(BitstreamRestriction::inferred(0, dpb));
            changed.restriction = true;
        }
    }
    Ok(changed)
}

/// Rewrite and verify one wire SPS NAL (§6.8). The output is accepted only
/// if kvm-proto's reader reads back exactly the rewritten fields, and
/// h264-reader both parses it and re-serialises its parse to the same
/// bytes — an independent reader that saw every field as written.
pub fn rewrite_sps(nal: &[u8], cfg: &RewriteConfig) -> Result<RewrittenSps, RewriteError> {
    let mut syntax = SpsSyntax::parse(nal).map_err(RewriteError::Unreadable)?;
    let changed = apply_rewrites(&mut syntax, cfg)?;
    let out = syntax.to_nal();
    if SpsSyntax::parse(&out).as_ref() != Ok(&syntax) {
        return Err(RewriteError::SelfCheck);
    }
    let parsed = h264_reader_parse(&out)?;
    let header = h264_reader::nal::NalHeader::new(*out.first().ok_or(RewriteError::SelfCheck)?)
        .map_err(|e| RewriteError::H264Reader(format!("{e:?}")))?;
    let mut again = Vec::with_capacity(out.len());
    parsed
        .write_with_header(header, &mut again)
        .map_err(|e| RewriteError::H264Reader(e.to_string()))?;
    if again != out {
        return Err(RewriteError::Disagrees);
    }
    let summary = SpsSummary::from_sps(&parsed)
        .map_err(|e: SpsSummaryError| RewriteError::Summary(format!("{e:?}")))?;
    Ok(RewrittenSps {
        nal: out,
        syntax,
        parsed,
        summary,
        changed,
    })
}

fn h264_reader_parse(nal: &[u8]) -> Result<SeqParameterSet, RewriteError> {
    use h264_reader::nal::{Nal as _, RefNal};
    if nal.is_empty() {
        return Err(RewriteError::SelfCheck);
    }
    let refnal = RefNal::new(nal, &[], true);
    SeqParameterSet::from_bits(refnal.rbsp_bits())
        .map_err(|e| RewriteError::H264Reader(format!("{e:?}")))
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib rewrite::` — Expected: 8 passed.
Run: `cargo clippy -p kvm-proto --all-targets -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/rewrite.rs crates/kvm-proto/src/h264/mod.rs
git commit -m "kvm-proto: §6.8 SPS rewriter (level, VUI, bitstream_restriction) with goldens" \
  -m "ES3 census SPS → 67420028965403c0112f2cd40404041b41008540; verified by re-reading and by h264-reader's parser and writer." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 3 — FLV hardening and the muxer

Every §6.2 limit enforced in the demuxer before the data it bounds is collected, a poisoned demuxer after a misaligning error, and the muxer kvm-sim and the property tests are built on.

### Task 3.1: §6.2 limits in the config record and NALU parser; error kinds

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/header.rs` (`FlvLimits`, `FlvError`, `kind()`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/avc.rs` (limits threaded through `parse_avc_config`, `read_param_sets`, `parse_nalus`, `parse_video_body`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/demux.rs` (one call site)
- Test: `crates/kvm-proto/src/flv/avc.rs` (`limit_tests`), `crates/kvm-proto/src/flv/header.rs` (`every_error_kind_is_a_distinct_snake_case_label`)

**Interfaces:**
- Consumes: Plan A's demuxer internals.
- Produces: `pub struct FlvLimits { max_tag_size: u32 /* 4 MiB */, max_nals_per_tag: usize /* 128 */, max_sps: usize /* 4 */, max_pps: usize /* 16 */, max_param_set_len: usize /* 1024 */ }` (all `pub`, `Default`); `FlvError` gains `TooManyNals`, `ParamSetCount`, `ParamSetSize`; `pub fn FlvError::kind(self) -> &'static str` — the `parse_errors{kind}` label (`"oversize_tag"`, `"too_many_nals"`, …). Crate-internal: `parse_avc_config(&Bytes, usize, &FlvLimits)`, `parse_nalus(&Bytes, usize, u8, &FlvLimits)`, `parse_video_body(&Bytes, Option<u8>, &FlvLimits)`. kvm-probe keeps compiling unchanged (it uses only `FlvLimits::default()`), and its census path now gets the 128-NAL cap (Plan A m5).

- [ ] **Step 1: Write the failing tests.** Append to `crates/kvm-proto/src/flv/avc.rs`:

```rust
#[cfg(test)]
mod limit_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;

    /// A config record body with `n_sps` SPSs of `sps_len` bytes and `n_pps`
    /// 2-byte PPSs, after the 5-byte FLV AVC header.
    fn record(n_sps: u8, sps_len: usize, n_pps: u8) -> Bytes {
        let mut b = vec![0x17, 0, 0, 0, 0, 1, 0x42, 0, 0x1F, 0xFF, 0xE0 | n_sps];
        for _ in 0..n_sps {
            b.extend_from_slice(&(sps_len as u16).to_be_bytes());
            b.push(0x67);
            b.extend(std::iter::repeat_n(0x42, sps_len.saturating_sub(1)));
        }
        b.push(n_pps);
        for _ in 0..n_pps {
            b.extend_from_slice(&[0, 2, 0x68, 0xCE]);
        }
        Bytes::from(b)
    }

    #[test]
    fn config_record_counts_and_sizes_are_capped() {
        let lim = FlvLimits::default();
        assert!(parse_avc_config(&record(1, 16, 1), 5, &lim).is_ok());
        assert!(parse_avc_config(&record(4, 1024, 16), 5, &lim).is_ok());
        assert_eq!(
            parse_avc_config(&record(0, 16, 1), 5, &lim),
            Err(FlvError::ParamSetCount)
        );
        assert_eq!(
            parse_avc_config(&record(5, 16, 1), 5, &lim),
            Err(FlvError::ParamSetCount)
        );
        assert_eq!(
            parse_avc_config(&record(1, 16, 0), 5, &lim),
            Err(FlvError::ParamSetCount)
        );
        assert_eq!(
            parse_avc_config(&record(1, 16, 17), 5, &lim),
            Err(FlvError::ParamSetCount)
        );
        assert_eq!(
            parse_avc_config(&record(1, 1025, 1), 5, &lim),
            Err(FlvError::ParamSetSize)
        );
        assert_eq!(
            parse_avc_config(&record(1, 0, 1), 5, &lim),
            Err(FlvError::ParamSetSize)
        );
        // configurationVersion must be 1.
        let mut v2 = record(1, 16, 1).to_vec();
        v2[5] = 2;
        assert_eq!(
            parse_avc_config(&Bytes::from(v2), 5, &lim),
            Err(FlvError::BadConfigRecord)
        );
    }

    #[test]
    fn at_most_128_nals_per_tag() {
        let lim = FlvLimits::default();
        let tag = |n: usize| {
            let mut b = vec![0x27, 1, 0, 0, 0];
            for _ in 0..n {
                b.extend_from_slice(&[1, 0x09]);
            }
            Bytes::from(b)
        };
        assert_eq!(parse_nalus(&tag(128), 5, 1, &lim).unwrap().len(), 128);
        assert_eq!(
            parse_nalus(&tag(129), 5, 1, &lim),
            Err(FlvError::TooManyNals)
        );
    }

    #[test]
    fn a_video_tag_with_an_empty_body_is_malformed() {
        assert_eq!(
            parse_video_body(&Bytes::new(), Some(4), &FlvLimits::default()),
            Err(FlvError::MalformedVideoTag)
        );
    }
}
```

and add this test to the `tests` module in `crates/kvm-proto/src/flv/header.rs`, above `rejects_encrypted_streamid_and_oversize`:

```rust
    #[test]
    fn every_error_kind_is_a_distinct_snake_case_label() {
        let all = [
            FlvError::BadHeader,
            FlvError::BadPrevTagSize,
            FlvError::EncryptedTag,
            FlvError::BadStreamId,
            FlvError::OversizeTag,
            FlvError::BadConfigRecord,
            FlvError::BadLengthSize,
            FlvError::NalBeforeSequenceHeader,
            FlvError::MalformedVideoTag,
            FlvError::TooManyNals,
            FlvError::ParamSetCount,
            FlvError::ParamSetSize,
        ];
        let mut kinds: Vec<&str> = all.iter().map(|e| e.kind()).collect();
        assert!(
            kinds
                .iter()
                .all(|k| k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        );
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), all.len());
    }
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib flv::`
Expected: FAIL to compile — `parse_avc_config` takes 2 arguments but 3 were supplied; no variant `TooManyNals`/`ParamSetCount`/`ParamSetSize`; no method `kind`.

- [ ] **Step 3: Implement the limits and kinds.** In `header.rs`, replace the `FlvLimits` struct, its `Default` impl and the `FlvError` enum (everything from `/// Per-stream framing limits.` down to the end of `pub enum FlvError { … }`) with:

```rust
/// Per-stream framing limits (§6.2). Every one is checked before the data it
/// bounds is buffered or collected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlvLimits {
    /// `DataSize` cap: 4 MiB.
    pub max_tag_size: u32,
    /// NALs in one NALU tag (one access unit): 128.
    pub max_nals_per_tag: usize,
    /// SPSs in one `AVCDecoderConfigurationRecord`: 1..=4.
    pub max_sps: usize,
    /// PPSs in one `AVCDecoderConfigurationRecord`: 1..=16.
    pub max_pps: usize,
    /// Bytes in one SPS or PPS: 1 KiB.
    pub max_param_set_len: usize,
}
impl Default for FlvLimits {
    fn default() -> Self {
        Self {
            max_tag_size: 4_194_304,
            max_nals_per_tag: 128,
            max_sps: 4,
            max_pps: 16,
            max_param_set_len: 1024,
        }
    }
}

/// A framing violation found by the demuxer (§6.9: transient, an FLV
/// reconnect; `parse_errors{kind}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlvError {
    BadHeader,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    OversizeTag,
    BadConfigRecord,
    BadLengthSize,
    NalBeforeSequenceHeader,
    MalformedVideoTag,
    /// More than `FlvLimits::max_nals_per_tag` NALs in one tag.
    TooManyNals,
    /// A config record with 0 or more than `max_sps` SPSs, or 0 or more than
    /// `max_pps` PPSs.
    ParamSetCount,
    /// An SPS or PPS longer than `max_param_set_len`, or empty.
    ParamSetSize,
}

impl FlvError {
    /// The `parse_errors{kind}` label.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            FlvError::BadHeader => "bad_header",
            FlvError::BadPrevTagSize => "bad_prev_tag_size",
            FlvError::EncryptedTag => "encrypted_tag",
            FlvError::BadStreamId => "bad_stream_id",
            FlvError::OversizeTag => "oversize_tag",
            FlvError::BadConfigRecord => "bad_config_record",
            FlvError::BadLengthSize => "bad_length_size",
            FlvError::NalBeforeSequenceHeader => "nal_before_sequence_header",
            FlvError::MalformedVideoTag => "malformed_video_tag",
            FlvError::TooManyNals => "too_many_nals",
            FlvError::ParamSetCount => "param_set_count",
            FlvError::ParamSetSize => "param_set_size",
        }
    }
}
```

- [ ] **Step 4: Thread the limits through `avc.rs`.** Make these replacements in `crates/kvm-proto/src/flv/avc.rs`:

```rust
use crate::flv::header::{FlvError, FlvLimits};
```

(replacing `use crate::flv::header::FlvError;`), the whole three-line `AvcConfig` doc comment (its lines from `/// Parsed` through `are Plan B hardening.`) with

```rust
/// Parsed `AVCDecoderConfigurationRecord` (ISO 14496-15). SPS/PPS are
/// zero-copy slices of the tag body (§6.2), 1–4 SPS and 1–16 PPS of
/// 1..=1024 bytes each (`FlvLimits`).
```

`parse_avc_config`'s signature and its two `read_param_sets` calls with

```rust
pub(crate) fn parse_avc_config(
    body: &Bytes,
    start: usize,
    limits: &FlvLimits,
) -> Result<AvcConfig, FlvError> {
```

```rust
    let num_sps = usize::from(c.u8().ok_or(FlvError::BadConfigRecord)? & 0x1F);
    if num_sps == 0 || num_sps > limits.max_sps {
        return Err(FlvError::ParamSetCount);
    }
    let sps = read_param_sets(body, &mut c, start, num_sps, limits)?;
    let num_pps = usize::from(c.u8().ok_or(FlvError::BadConfigRecord)?);
    if num_pps == 0 || num_pps > limits.max_pps {
        return Err(FlvError::ParamSetCount);
    }
    let pps = read_param_sets(body, &mut c, start, num_pps, limits)?;
```

`read_param_sets`'s parameters and loop head with

```rust
fn read_param_sets(
    body: &Bytes,
    c: &mut Cur<'_>,
    start: usize,
    count: usize,
    limits: &FlvLimits,
) -> Result<Vec<Bytes>, FlvError> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::from(c.u16().ok_or(FlvError::BadConfigRecord)?);
        if len == 0 || len > limits.max_param_set_len {
            return Err(FlvError::ParamSetSize);
        }
```

(the rest of the loop body is unchanged), `parse_nalus` with the cap checked before each NAL is collected:

```rust
/// Split length-prefixed NALs out of an AVC NALU tag body (zero-copy).
/// `start` is past the 5-byte FLV AVC header; `length_size` is 1, 2 or 4.
/// The NAL count is capped before each NAL is collected (§6.2: 128 per AU),
/// so a 4 MiB tag of 1-byte NALs cannot amplify into a huge `Vec`.
pub(crate) fn parse_nalus(
    body: &Bytes,
    start: usize,
    length_size: u8,
    limits: &FlvLimits,
) -> Result<Vec<Nal>, FlvError> {
```

```rust
        if nal_len == 0 || body.as_ref().get(len_end..nal_end).is_none() {
            return Err(FlvError::MalformedVideoTag); // 0 < n ≤ remaining (§6.2)
        }
        if nals.len() >= limits.max_nals_per_tag {
            return Err(FlvError::TooManyNals);
        }
```

and `parse_video_body`'s signature and its two parser calls with

```rust
pub(crate) fn parse_video_body(
    body: &Bytes,
    length_size: Option<u8>,
    limits: &FlvLimits,
) -> Result<VideoBody, FlvError> {
```

```rust
        0 => Ok(VideoBody::SequenceHeader(parse_avc_config(
            body,
            AVC_HEADER_LEN,
            limits,
        )?)),
```

```rust
                nals: parse_nalus(body, AVC_HEADER_LEN, ls, limits)?,
```

. In `avc.rs`'s existing `tests` module, add `, &FlvLimits::default()` as the last argument of every `parse_avc_config(…)` and `parse_nalus(…)` call — seven calls: three `parse_avc_config` (one in `parses_avcc_and_extracts_sps_pps`, two in `rejects_bad_length_size_and_truncation`) and four `parse_nalus` (`splits_four_byte_length_nal`, `splits_two_one_byte_length_nals`, two in `rejects_overrun_and_zero_length`). In `demux.rs`, replace `parse_video_body(&raw.body, self.length_size)` with `parse_video_body(&raw.body, self.length_size, &self.limits)`.

- [ ] **Step 5: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib flv::` — Expected: all pass (3 new `limit_tests`, the new header test, Plan A's tests).
Run: `cargo test -p kvm-probe` — Expected: unchanged pass counts (88 lib + 37 stubs, 1 ignored).

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-proto/src/flv/header.rs crates/kvm-proto/src/flv/avc.rs crates/kvm-proto/src/flv/demux.rs
git commit -m "kvm-proto: §6.2 limits — 1–4 SPS, 1–16 PPS ≤ 1 KiB, 128 NALs per tag; error kinds" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3.2: Demuxer poison, `buffered_len`, and the pre-buffer test

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/demux.rs`
- Test: `crates/kvm-proto/src/flv/demux.rs` (`hardening_tests`)

**Interfaces:**
- Consumes: `FlvDemuxer` (Plan A), `FlvLimits` (Task 3.1).
- Produces: `pub fn FlvDemuxer::buffered_len(&self) -> usize`; after any error from the tag framing itself (`BadHeader`, `BadPrevTagSize`, `EncryptedTag`, `BadStreamId`, `OversizeTag`) the demuxer is poisoned — `push` discards, `next_tag` repeats the error, the buffer is freed; a body-level error (`MalformedVideoTag`, config/NAL errors) leaves the stream aligned and the next tag readable.

- [ ] **Step 1: Write the failing tests.** Append to `crates/kvm-proto/src/flv/demux.rs`:

```rust
#[cfg(test)]
mod hardening_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const HEADER: [u8; 13] = [b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0];

    /// §11.2 pre-buffer test: `DataSize = 0xFFFFFF` is refused as soon as the
    /// 11th header byte arrives, before a single body byte is buffered;
    /// nothing is reserved for the announced body on the way, and nothing is
    /// kept — not even capacity — afterwards.
    #[test]
    fn oversize_data_size_is_refused_after_eleven_header_bytes() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&HEADER);
        let tag_header = [0x09, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0];
        for b in &tag_header[..10] {
            d.push(&[*b]);
            assert_eq!(d.next_tag(), Ok(None));
            // Nothing is reserved for the body the header announces.
            assert!(d.buf.capacity() < 1024, "{}", d.buf.capacity());
        }
        d.push(&tag_header[10..]);
        assert_eq!(d.next_tag(), Err(FlvError::OversizeTag));
        assert_eq!(d.buffered_len(), 0);
        assert_eq!(d.buf.capacity(), 0, "the buffer itself is released");
    }

    #[test]
    fn a_framing_error_poisons_the_demuxer() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&HEADER);
        d.push(&[0x29, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0, 0, 0, 12]); // encrypted
        assert_eq!(d.next_tag(), Err(FlvError::EncryptedTag));
        d.push(&[0x09; 64]);
        assert_eq!(d.buffered_len(), 0, "a poisoned demuxer buffers nothing");
        assert_eq!(d.next_tag(), Err(FlvError::EncryptedTag));
    }

    #[test]
    fn a_body_error_leaves_the_stream_aligned() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&HEADER);
        // A video tag whose body is one byte (no AVC header), then an audio tag.
        d.push(&[0x09, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x17, 0, 0, 0, 12]);
        d.push(&[0x08, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xAF, 0, 0, 0, 12]);
        assert_eq!(d.next_tag(), Err(FlvError::MalformedVideoTag));
        assert!(matches!(
            d.next_tag().unwrap().unwrap().body,
            TagBody::Audio
        ));
    }

    #[test]
    fn data_offset_below_nine_is_refused_and_above_nine_skips_padding() {
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 8, 0, 0, 0, 0]);
        assert_eq!(d.next_tag(), Err(FlvError::BadHeader));
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&[
            b'F', b'L', b'V', 1, 1, 0, 0, 0, 12, 0xEE, 0xEE, 0xEE, 0, 0, 0, 0,
        ]);
        d.push(&[0x08, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xAF, 0, 0, 0, 12]);
        assert!(matches!(
            d.next_tag().unwrap().unwrap().body,
            TagBody::Audio
        ));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib hardening_tests`
Expected: FAIL to compile — no method `buffered_len` on `FlvDemuxer`.

- [ ] **Step 3: Implement.** In `demux.rs`, first rename Plan A's framing function, keeping its body exactly as it is — replace its first line

```rust
    pub(crate) fn next_raw_tag(&mut self) -> Result<Option<RawTag>, FlvError> {
```

with

```rust
    fn next_raw_tag_inner(&mut self) -> Result<Option<RawTag>, FlvError> {
```

then replace the `FlvDemuxer` struct, the `impl FlvDemuxer {` line, `new` and `push` (from `/// Incremental FLV demuxer` to the end of `push`) with the following; the new `next_raw_tag` wraps the renamed function, which stays in the same `impl` block below it:

```rust
/// Incremental FLV demuxer over an internal `BytesMut`. After a framing
/// error in the tag stream itself (header, `PrevTagSize`, `DataSize`,
/// `StreamID`, encryption) the stream is misaligned, so the demuxer is
/// poisoned: `push` discards input and `next_tag` repeats the error. A
/// body-level error (one tag's video body) leaves the stream aligned.
pub struct FlvDemuxer {
    buf: BytesMut,
    state: State,
    limits: FlvLimits,
    pub(crate) length_size: Option<u8>,
    poisoned: Option<FlvError>,
}

impl FlvDemuxer {
    pub fn new(limits: FlvLimits) -> Self {
        Self {
            buf: BytesMut::new(),
            state: State::Start,
            limits,
            length_size: None,
            poisoned: None,
        }
    }

    /// Append received bytes. One copy into the reassembly buffer; NAL/SPS
    /// slices taken from a tag body are shared without further copying.
    /// A poisoned demuxer discards them.
    pub fn push(&mut self, data: &[u8]) {
        if self.poisoned.is_none() {
            self.buf.extend_from_slice(data);
        }
    }

    /// Bytes buffered and not yet returned as tags.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn next_raw_tag(&mut self) -> Result<Option<RawTag>, FlvError> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        let r = self.next_raw_tag_inner();
        if let Err(e) = r {
            self.poisoned = Some(e);
            self.buf = BytesMut::new();
        }
        r
    }
```


- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib flv::` — Expected: all pass, including the 4 `hardening_tests`.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/flv/demux.rs
git commit -m "kvm-proto: poison the demuxer on framing errors; pre-buffer test (§11.2)" \
  -m "DataSize 0xFFFFFF is refused on the 11th header byte with nothing buffered; data_offset 8 and padding cases (Plan A 2.3/2.4)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3.3: FLV muxer and the mux→demux property test

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/mux.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/flv/mod.rs` (`pub mod mux;`)
- Test: `crates/kvm-proto/src/flv/mux.rs` (`tests`, including the proptest `mux_then_demux_round_trips`)

**Interfaces:**
- Consumes: `FlvDemuxer`, `FlvLimits`, `TagBody`, `VideoBody`, `FrameType` (for tests).
- Produces (`kvm_proto::flv::mux`): `pub enum MuxError { TagTooLarge, BadLengthSize(u8), NalLength, ParamSet, CompositionTime }`; `pub const TAG_AUDIO: u8 = 8, TAG_VIDEO: u8 = 9, TAG_SCRIPT: u8 = 18`; `pub struct RawTagHeader { type_byte: u8, timestamp_ms: u32, stream_id: u32, data_size: Option<u32>, prev_tag_size: Option<u32> }`; `pub fn write_flv_header(out: &mut Vec<u8>, has_audio: bool, has_video: bool)`; `pub fn write_tag(out: &mut Vec<u8>, tag_type: u8, timestamp_ms: u32, body: &[u8]) -> Result<(), MuxError>`; `pub fn write_raw_tag(out: &mut Vec<u8>, h: &RawTagHeader, body: &[u8]) -> Result<(), MuxError>`; `pub fn video_tag_byte(frame_type: u8, codec_id: u8) -> u8`; `pub fn avc_sequence_header_body(sps: &[&[u8]], pps: &[&[u8]], length_size: u8) -> Result<Vec<u8>, MuxError>`; `pub fn avc_nalu_body(out: &mut Vec<u8>, key: bool, composition_time_ms: i32, nals: &[&[u8]], length_size: u8) -> Result<(), MuxError>` (leaves `out` unchanged on error); `pub fn avc_end_of_sequence_body() -> [u8; 5]`. Used by Tasks 4.6, 6.2, 7.1 and kvm-sim (Tasks 8.4, 8.5).

- [ ] **Step 1: Write the failing tests.** Add `pub mod mux;` to `crates/kvm-proto/src/flv/mod.rs` (between `mod header;` and `mod reader;`) and create `crates/kvm-proto/src/flv/mux.rs` with the test module. The property test is bounded (256 cases, inputs under 1 KiB) and runs in well under a second; its seed is fixed (`PROPTEST_RNG_SEED=<n>` explores another) and it writes no `proptest-regressions/` files — a failure prints the minimal input, which the fixed seed reproduces:

```rust
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;
    use crate::flv::{FlvDemuxer, FlvLimits, FrameType, TagBody, VideoBody};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    #[test]
    fn header_and_one_tag_are_byte_exact() {
        let mut out = Vec::new();
        write_flv_header(&mut out, false, true);
        write_tag(&mut out, TAG_VIDEO, 0x0102_0304, &[0xAA, 0xBB]).unwrap();
        assert_eq!(
            out,
            [
                b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0, // header + PrevTagSize0
                9, 0, 0, 2, 0x02, 0x03, 0x04, 0x01, 0, 0, 0, // tag header, ts ext 0x01
                0xAA, 0xBB, 0, 0, 0, 13, // body + PrevTagSize = 11 + 2
            ]
        );
    }

    #[test]
    fn nalu_body_and_sequence_header_are_byte_exact() {
        let mut b = Vec::new();
        avc_nalu_body(&mut b, true, 16, &[&[0x65, 0x88], &[0x65, 0x99, 0x01]], 2).unwrap();
        assert_eq!(
            b,
            [0x17, 1, 0, 0, 16, 0, 2, 0x65, 0x88, 0, 3, 0x65, 0x99, 0x01]
        );
        let sh = avc_sequence_header_body(&[&[0x67, 0x42, 0x00, 0x1F, 0x96]], &[&[0x68, 0xCE]], 4)
            .unwrap();
        assert_eq!(
            sh,
            [
                0x17, 0, 0, 0, 0, 1, 0x42, 0x00, 0x1F, 0xFF, 0xE1, 0, 5, 0x67, 0x42, 0x00, 0x1F,
                0x96, 1, 0, 2, 0x68, 0xCE
            ]
        );
    }

    #[test]
    fn negative_composition_time_round_trips_and_out_of_range_is_refused() {
        let mut b = Vec::new();
        avc_nalu_body(&mut b, false, -1, &[&[0x41, 0x9A]], 4).unwrap();
        assert_eq!(&b[..5], &[0x27, 1, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            avc_nalu_body(&mut Vec::new(), false, 0x0080_0000, &[&[0x41]], 4),
            Err(MuxError::CompositionTime)
        );
    }

    #[test]
    fn nal_too_long_for_its_prefix_is_refused_and_leaves_out_unchanged() {
        let big = vec![0x41u8; 256];
        let mut b = vec![0xEE];
        assert_eq!(
            avc_nalu_body(&mut b, false, 0, &[&big], 1),
            Err(MuxError::NalLength)
        );
        assert_eq!(b, [0xEE]);
        assert_eq!(
            avc_nalu_body(&mut b, false, 0, &[&[0x41]], 3),
            Err(MuxError::BadLengthSize(3))
        );
    }

    /// One tag the property test muxes: `None` = a sequence header.
    #[derive(Debug, Clone)]
    enum Spec {
        Seq {
            sps: Vec<Vec<u8>>,
            pps: Vec<Vec<u8>>,
        },
        Nalus {
            key: bool,
            ct: i32,
            nals: Vec<Vec<u8>>,
        },
        Eos,
    }

    fn nal(header: u8) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(move |mut v| {
            v.insert(0, header);
            v
        })
    }

    fn spec() -> impl Strategy<Value = Spec> {
        prop_oneof![
            (
                proptest::collection::vec(nal(0x67), 1..=4),
                proptest::collection::vec(nal(0x68), 1..=16)
            )
                .prop_map(|(sps, pps)| Spec::Seq { sps, pps }),
            (
                any::<bool>(),
                -1000i32..1000,
                proptest::collection::vec(nal(0x41), 1..=8)
            )
                .prop_map(|(key, ct, nals)| Spec::Nalus { key, ct, nals }),
            Just(Spec::Eos),
        ]
    }

    proptest! {
        // A fixed seed, so a CI failure reproduces from its log (PROPTEST_RNG_SEED
        // still overrides it), and no regression files written into the tree.
        #![proptest_config(ProptestConfig {
            cases: 256,
            failure_persistence: None,
            rng_seed: match ProptestConfig::default().rng_seed {
                RngSeed::Random => RngSeed::Fixed(20_261_006),
                from_env => from_env,
            },
            ..ProptestConfig::default()
        })]

        /// mux → demux is the identity on every field the demuxer reports,
        /// whatever the length-prefix size and however the bytes are chunked.
        #[test]
        fn mux_then_demux_round_trips(
            ls in prop_oneof![Just(1u8), Just(2u8), Just(4u8)],
            body in proptest::collection::vec(spec(), 0..12),
            chunk in 1usize..64,
        ) {
            let mut flv = Vec::new();
            write_flv_header(&mut flv, false, true);
            let mut specs = vec![Spec::Seq { sps: vec![vec![0x67, 0x42]], pps: vec![vec![0x68, 0xCE]] }];
            specs.extend(body);
            for (i, s) in specs.iter().enumerate() {
                let ts = u32::try_from(i).unwrap() * 33;
                let b = match s {
                    Spec::Seq { sps, pps } => {
                        let sps: Vec<&[u8]> = sps.iter().map(Vec::as_slice).collect();
                        let pps: Vec<&[u8]> = pps.iter().map(Vec::as_slice).collect();
                        avc_sequence_header_body(&sps, &pps, ls).unwrap()
                    }
                    Spec::Nalus { key, ct, nals } => {
                        let nals: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
                        let mut b = Vec::new();
                        avc_nalu_body(&mut b, *key, *ct, &nals, ls).unwrap();
                        b
                    }
                    Spec::Eos => avc_end_of_sequence_body().to_vec(),
                };
                write_tag(&mut flv, TAG_VIDEO, ts, &b).unwrap();
            }
            let mut d = FlvDemuxer::new(FlvLimits::default());
            let mut got = Vec::new();
            for c in flv.chunks(chunk) {
                d.push(c);
                while let Some(t) = d.next_tag().unwrap() {
                    got.push(t);
                }
            }
            prop_assert_eq!(got.len(), specs.len());
            for (i, (t, s)) in got.iter().zip(&specs).enumerate() {
                prop_assert_eq!(t.timestamp, u32::try_from(i).unwrap() * 33);
                match (&t.body, s) {
                    (TagBody::Video(VideoBody::SequenceHeader(c)), Spec::Seq { sps, pps }) => {
                        prop_assert_eq!(c.length_size_minus_one + 1, ls);
                        prop_assert_eq!(c.sps.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), sps.clone());
                        prop_assert_eq!(c.pps.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), pps.clone());
                    }
                    (TagBody::Video(VideoBody::Nalus { frame_type, composition_time, nals: got }), Spec::Nalus { key, ct, nals }) => {
                        prop_assert_eq!(*frame_type, if *key { FrameType::Key } else { FrameType::Inter });
                        prop_assert_eq!(composition_time, ct);
                        prop_assert_eq!(got.iter().map(|n| n.bytes.to_vec()).collect::<Vec<_>>(), nals.clone());
                    }
                    (TagBody::Video(VideoBody::EndOfSequence), Spec::Eos) => {}
                    (other, s) => prop_assert!(false, "tag {i}: {other:?} for {s:?}"),
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib flv::mux`
Expected: FAIL to compile — `cannot find function write_flv_header` (and the other writers).

- [ ] **Step 3: Implement.** Put this above the test module in `mux.rs`:

```rust
//! FLV muxer (§4.1): the inverse of the demuxer, for kvm-sim, the
//! mux→demux property tests and the differential fuzz target. Each writer
//! appends to a caller-owned `Vec` and checks every field fits before
//! writing anything; `write_raw_tag` takes every header field explicitly so
//! a test double can also write deliberately wrong ones.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// A value that does not fit the FLV field it was meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxError {
    /// A tag body longer than `DataSize`'s 24 bits.
    TagTooLarge,
    /// `length_size` other than 1, 2 or 4.
    BadLengthSize(u8),
    /// A NAL longer than its length prefix can express, or empty.
    NalLength,
    /// A parameter set longer than 65 535 bytes, or empty, or too many.
    ParamSet,
    /// `CompositionTime` outside the signed 24-bit range.
    CompositionTime,
}

/// FLV tag types.
pub const TAG_AUDIO: u8 = 8;
pub const TAG_VIDEO: u8 = 9;
pub const TAG_SCRIPT: u8 = 18;

/// Every field of an 11-byte tag header plus the trailing `PrevTagSize`.
/// `data_size`/`prev_tag_size` of `None` mean "the correct value".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTagHeader {
    /// The whole first byte: reserved bits, filter (`0x20`) and tag type.
    pub type_byte: u8,
    pub timestamp_ms: u32,
    pub stream_id: u32,
    pub data_size: Option<u32>,
    pub prev_tag_size: Option<u32>,
}

/// The 9-byte FLV header (`DataOffset` 9) and `PrevTagSize0`.
pub fn write_flv_header(out: &mut Vec<u8>, has_audio: bool, has_video: bool) {
    let flags = (if has_audio { 0x04 } else { 0 }) | u8::from(has_video);
    out.extend_from_slice(&[b'F', b'L', b'V', 1, flags, 0, 0, 0, 9, 0, 0, 0, 0]);
}

/// One correct tag of `tag_type` carrying `body`.
pub fn write_tag(
    out: &mut Vec<u8>,
    tag_type: u8,
    timestamp_ms: u32,
    body: &[u8],
) -> Result<(), MuxError> {
    write_raw_tag(
        out,
        &RawTagHeader {
            type_byte: tag_type & 0x1F,
            timestamp_ms,
            stream_id: 0,
            data_size: None,
            prev_tag_size: None,
        },
        body,
    )
}

/// One tag with explicit header fields (kvm-sim's fault injection).
pub fn write_raw_tag(out: &mut Vec<u8>, h: &RawTagHeader, body: &[u8]) -> Result<(), MuxError> {
    let real = u32::try_from(body.len()).map_err(|_| MuxError::TagTooLarge)?;
    if real > 0x00FF_FFFF {
        return Err(MuxError::TagTooLarge);
    }
    let data_size = h.data_size.unwrap_or(real) & 0x00FF_FFFF;
    let prev = h.prev_tag_size.unwrap_or(real.saturating_add(11));
    let ds = data_size.to_be_bytes();
    let ts = h.timestamp_ms.to_be_bytes();
    let sid = (h.stream_id & 0x00FF_FFFF).to_be_bytes();
    out.push(h.type_byte);
    out.extend_from_slice(ds.get(1..).unwrap_or(&[]));
    out.extend_from_slice(ts.get(1..).unwrap_or(&[])); // low 24 bits
    out.push(ts.first().copied().unwrap_or(0)); // TimestampExtended
    out.extend_from_slice(sid.get(1..).unwrap_or(&[]));
    out.extend_from_slice(body);
    out.extend_from_slice(&prev.to_be_bytes());
    Ok(())
}

/// First byte of a classic video tag body: frame type (1 key, 2 inter) and
/// `CodecID` (7 AVC, 12 HEVC).
#[must_use]
pub fn video_tag_byte(frame_type: u8, codec_id: u8) -> u8 {
    (frame_type & 0x0F).wrapping_shl(4) | (codec_id & 0x0F)
}

/// Body of an AVC sequence-header tag: the 5-byte AVC header (packet type 0,
/// `CompositionTime` 0) and an `AVCDecoderConfigurationRecord` (version 1,
/// profile/compat/level copied from the first SPS).
pub fn avc_sequence_header_body(
    sps: &[&[u8]],
    pps: &[&[u8]],
    length_size: u8,
) -> Result<Vec<u8>, MuxError> {
    let lsm1 = length_size_minus_one(length_size)?;
    let first = sps.first().ok_or(MuxError::ParamSet)?;
    let num_sps = u8::try_from(sps.len())
        .ok()
        .filter(|n| *n <= 31)
        .ok_or(MuxError::ParamSet)?;
    let num_pps = u8::try_from(pps.len()).map_err(|_| MuxError::ParamSet)?;
    let mut b = vec![video_tag_byte(1, 7), 0, 0, 0, 0, 1];
    b.push(first.get(1).copied().unwrap_or(0));
    b.push(first.get(2).copied().unwrap_or(0));
    b.push(first.get(3).copied().unwrap_or(0));
    b.push(0xFC | lsm1);
    b.push(0xE0 | num_sps);
    for s in sps {
        push_param_set(&mut b, s)?;
    }
    b.push(num_pps);
    for p in pps {
        push_param_set(&mut b, p)?;
    }
    Ok(b)
}

/// Body of an AVC NALU tag: the 5-byte AVC header then each NAL behind a
/// `length_size`-byte big-endian length.
pub fn avc_nalu_body(
    out: &mut Vec<u8>,
    key: bool,
    composition_time_ms: i32,
    nals: &[&[u8]],
    length_size: u8,
) -> Result<(), MuxError> {
    length_size_minus_one(length_size)?;
    if !(-0x0080_0000..=0x007F_FFFF).contains(&composition_time_ms) {
        return Err(MuxError::CompositionTime);
    }
    let start = out.len();
    out.push(video_tag_byte(if key { 1 } else { 2 }, 7));
    out.push(1);
    out.extend_from_slice(composition_time_ms.to_be_bytes().get(1..).unwrap_or(&[]));
    for nal in nals {
        if let Err(e) = push_length(out, nal.len(), length_size) {
            out.truncate(start);
            return Err(e);
        }
        out.extend_from_slice(nal);
    }
    Ok(())
}

/// Body of an AVC end-of-sequence tag (packet type 2).
#[must_use]
pub fn avc_end_of_sequence_body() -> [u8; 5] {
    [video_tag_byte(1, 7), 2, 0, 0, 0]
}

fn length_size_minus_one(length_size: u8) -> Result<u8, MuxError> {
    match length_size {
        1 => Ok(0),
        2 => Ok(1),
        4 => Ok(3),
        other => Err(MuxError::BadLengthSize(other)),
    }
}

fn push_length(out: &mut Vec<u8>, len: usize, length_size: u8) -> Result<(), MuxError> {
    let len = u32::try_from(len).map_err(|_| MuxError::NalLength)?;
    let fits = match length_size {
        1 => len <= 0xFF,
        2 => len <= 0xFFFF,
        _ => true,
    };
    if len == 0 || !fits {
        return Err(MuxError::NalLength);
    }
    let be = len.to_be_bytes();
    let skip = 4_usize.saturating_sub(usize::from(length_size));
    out.extend_from_slice(be.get(skip..).unwrap_or(&[]));
    Ok(())
}

fn push_param_set(b: &mut Vec<u8>, set: &[u8]) -> Result<(), MuxError> {
    let len = u16::try_from(set.len()).map_err(|_| MuxError::ParamSet)?;
    if len == 0 {
        return Err(MuxError::ParamSet);
    }
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(set);
    Ok(())
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib flv::mux` — Expected: 5 passed.
Run: `cargo clippy -p kvm-proto --all-targets -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/flv/mux.rs crates/kvm-proto/src/flv/mod.rs
git commit -m "kvm-proto: FLV muxer and a mux→demux property test (§4.1, §11.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 4 — Admission (§6.1, §6.2)

The per-NAL sanitiser, the SPS limits and pins, PPS and slice checks with decode-order POC, the parameter-set state, and `VideoAdmission` tying them into what Plan C's KVM actor forwards.

### Task 4.1: The NAL sanitiser

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sanitize.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (`pub mod sanitize;`)
- Test: `crates/kvm-proto/src/h264/sanitize.rs` (`tests`)

**Interfaces:**
- Consumes: `kvm_proto::bits::contains_start_code` (Task 2.1); `kvm_proto::h264::{NalHeader, NalHeaderError, nal_type_allowed}` (Plan A).
- Produces (`kvm_proto::h264::sanitize`): `pub enum NalRefusal { Empty, ForbiddenBit, StartCode }` (`Copy`, `Eq`); `pub enum NalVerdict { Keep(NalHeader, Bytes), Drop(NalHeader) }`; `pub fn check_nal(nal: &Bytes) -> Result<NalVerdict, NalRefusal>` — trims trailing zero bytes (D2), refuses the forbidden bit on every NAL, drops types outside `{1,5,7,8,9}`, refuses a start-code pattern in a kept NAL; the kept `Bytes` shares `nal`'s allocation.

- [ ] **Step 1: Write the failing tests.** Add `pub mod sanitize;` to `crates/kvm-proto/src/h264/mod.rs` and create `crates/kvm-proto/src/h264/sanitize.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn b(v: &'static [u8]) -> Bytes {
        Bytes::from_static(v)
    }

    #[test]
    fn es3_pps_trailing_zeros_are_trimmed_not_refused() {
        // census.md pps_hex = 68ce31120000
        match check_nal(&b(&[0x68, 0xce, 0x31, 0x12, 0x00, 0x00])).unwrap() {
            NalVerdict::Keep(h, kept) => {
                assert_eq!(h.nal_unit_type, 8);
                assert_eq!(kept.as_ref(), &[0x68, 0xce, 0x31, 0x12]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_refusal_has_its_own_kind() {
        assert_eq!(check_nal(&b(&[0, 0])), Err(NalRefusal::Empty));
        assert_eq!(check_nal(&b(&[0xE5, 0x88])), Err(NalRefusal::ForbiddenBit));
        assert_eq!(
            check_nal(&b(&[0x65, 0x88, 0, 0, 1, 0x42])),
            Err(NalRefusal::StartCode)
        );
        assert_eq!(
            check_nal(&b(&[0x41, 0, 0, 0, 0x42])),
            Err(NalRefusal::StartCode)
        );
        assert_eq!(
            check_nal(&b(&[0x41, 0, 0, 2, 0x42])),
            Err(NalRefusal::StartCode)
        );
    }

    #[test]
    fn sei_and_filler_are_dropped_even_with_start_codes_inside() {
        assert!(matches!(
            check_nal(&b(&[0x06, 0, 0, 1, 0x80])),
            Ok(NalVerdict::Drop(_))
        ));
        assert!(matches!(
            check_nal(&b(&[0x0C, 0xFF, 0xFF])),
            Ok(NalVerdict::Drop(_))
        ));
    }

    #[test]
    fn emulation_prevented_bytes_are_fine() {
        assert!(matches!(
            check_nal(&b(&[0x65, 0, 0, 3, 0, 0, 3, 1])),
            Ok(NalVerdict::Keep(..))
        ));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib sanitize`
Expected: FAIL to compile — `cannot find function check_nal`, types `NalVerdict`, `NalRefusal`.

- [ ] **Step 3: Implement.** Put this above the test module:

```rust
//! The per-NAL §6.2 checks every NAL from the KVM passes before anything
//! else looks at it.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::bits::contains_start_code;
use crate::h264::nal::{NalHeader, nal_type_allowed};
use bytes::Bytes;

/// Why a NAL was refused. Each is a framing violation (§6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalRefusal {
    /// Nothing left once trailing zero bytes are trimmed.
    Empty,
    /// `forbidden_zero_bit` is 1.
    ForbiddenBit,
    /// The NAL contains `00 00 00`, `00 00 01` or `00 00 02`.
    StartCode,
}

/// What to do with a NAL that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NalVerdict {
    /// On the allowlist `{1, 5, 7, 8, 9}`: keep these exact bytes.
    Keep(NalHeader, Bytes),
    /// Anything else (SEI, filler, …): drop it (§6.2).
    Drop(NalHeader),
}

/// §6.2 per-NAL checks. Trailing zero bytes are trimmed first: Annex B
/// cannot tell them from `trailing_zero_8bits`, a conforming NAL never ends
/// in `00` (7.4.1), and the ES3 appends them to its SPS and PPS
/// (`census.md` `sps_hex`, `pps_hex`). Then the forbidden bit is checked on
/// every NAL, the allowlist decides keep or drop, and a kept NAL must not
/// contain a start-code pattern — or the client's start-code scanner would
/// find NALs that were never checked. The returned `Bytes` shares `nal`'s
/// allocation.
pub fn check_nal(nal: &Bytes) -> Result<NalVerdict, NalRefusal> {
    let end = nal
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let trimmed = nal.slice(..end);
    let header = NalHeader::from_nal(&trimmed).map_err(|e| match e {
        crate::h264::NalHeaderError::Empty => NalRefusal::Empty,
        crate::h264::NalHeaderError::ForbiddenBitSet => NalRefusal::ForbiddenBit,
    })?;
    if !nal_type_allowed(header.nal_unit_type) {
        return Ok(NalVerdict::Drop(header));
    }
    if contains_start_code(&trimmed) {
        return Err(NalRefusal::StartCode);
    }
    Ok(NalVerdict::Keep(header, trimmed))
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib sanitize` — Expected: 4 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/sanitize.rs crates/kvm-proto/src/h264/mod.rs
git commit -m "kvm-proto: §6.2 NAL sanitiser — allowlist, forbidden bit, start-code refusal" \
  -m "Trailing zero bytes are trimmed first: the ES3's own SPS and PPS end in them (census.md)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.2: SPS limits — one reference frame, POC type 1 refused, `SpsPins`

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (re-exports; merge the two `pub use nal` lines — Plan A 3.1 minor)
- Test: `crates/kvm-proto/src/h264/sps.rs` (`pins_tests`; updated `exact_ceiling_values_pass`, `num_ref_frames_change_only_is_other`)

**Interfaces:**
- Consumes: `SpsSummary`, `SpsLimits`, `check_sps_limits`, `classify_sps_change`, `PinnedField` (Plan A).
- Produces: `pub const NUM_REF_FRAMES_CEILING: u32 = 16`; `SpsLimits::default().max_num_ref_frames == 1` (the census value, §6.1) and `check_sps_limits` never admits more than the ceiling whatever the limit; `SpsLimitViolation::PocType1` (D1); `pub struct SpsPins { profile_idc: u8, chroma_format_idc: u8, bit_depth_luma_minus8: u8, bit_depth_chroma_minus8: u8, pic_order_cnt_type: u8 }` (`Copy`, `Eq`) with `pub fn of(s: &SpsSummary) -> SpsPins` and `pub fn check(&self, s: &SpsSummary) -> Result<(), PinnedField>` (first changed field in spec order); `classify_sps_change` (kvm-probe's `summarize` still calls it, same signature) now uses `SpsPins`. Re-exported from `kvm_proto::h264`: `SpsPins`, `NUM_REF_FRAMES_CEILING`.

- [ ] **Step 1: Write the failing tests.** Append to `crates/kvm-proto/src/h264/sps.rs`:

```rust
#[cfg(test)]
mod pins_tests {
    use super::tests::ok_summary;
    use super::*;

    #[test]
    fn several_pinned_fields_report_the_first_in_spec_order() {
        let pins = SpsPins::of(&ok_summary());
        let mut s = ok_summary();
        s.pic_order_cnt_type = 0;
        s.bit_depth_luma_minus8 = 2;
        s.chroma_format_idc = 2;
        s.profile_idc = 100;
        assert_eq!(pins.check(&s), Err(PinnedField::ProfileIdc));
        s.profile_idc = 77;
        assert_eq!(pins.check(&s), Err(PinnedField::ChromaFormat));
        s.chroma_format_idc = 1;
        assert_eq!(pins.check(&s), Err(PinnedField::BitDepth));
        s.bit_depth_luma_minus8 = 0;
        assert_eq!(pins.check(&s), Err(PinnedField::PicOrderCntType));
        s.pic_order_cnt_type = 2;
        assert_eq!(pins.check(&s), Ok(()));
    }

    #[test]
    fn poc_type_1_is_refused() {
        let mut s = ok_summary();
        s.pic_order_cnt_type = 1;
        assert_eq!(
            check_sps_limits(&s, &SpsLimits::default()),
            Err(SpsLimitViolation::PocType1)
        );
    }
}
```

and in `sps.rs`'s `tests` module replace `exact_ceiling_values_pass` with:

```rust
    #[test]
    fn exact_ceiling_values_pass() {
        // Pin the ceilings themselves, not just values beyond them —
        // width=4096, height=2304, level_idc=51 are each the exact §6.1
        // limit; num_ref_frames is 1 by default (the census value) and a
        // raised limit stops at 16.
        let mut s = ok_summary();
        s.width = 4096;
        s.height = 2304;
        s.level_idc = 51;
        assert_eq!(check_sps_limits(&s, &SpsLimits::default()), Ok(()));
        s.num_ref_frames = 2;
        assert_eq!(
            check_sps_limits(&s, &SpsLimits::default()),
            Err(SpsLimitViolation::TooManyRefFrames(2))
        );
        let raised = SpsLimits {
            max_num_ref_frames: 99,
            ..SpsLimits::default()
        };
        s.num_ref_frames = 16;
        assert_eq!(check_sps_limits(&s, &raised), Ok(()));
        s.num_ref_frames = 17;
        assert_eq!(
            check_sps_limits(&s, &raised),
            Err(SpsLimitViolation::TooManyRefFrames(17))
        );
    }
```

and in `classify_tests::num_ref_frames_change_only_is_other` replace `let lim = SpsLimits::default();` with

```rust
        let lim = SpsLimits {
            max_num_ref_frames: 16,
            ..SpsLimits::default()
        };
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib h264::sps`
Expected: FAIL to compile — `cannot find type SpsPins`, no variant `PocType1`.

- [ ] **Step 3: Implement.** In `sps.rs`:

Replace the `SpsLimits` doc comment (the three lines starting `/// The §6.1 admission limits.`) with the constant and a corrected doc (Plan A 3.7 minor):

```rust
/// §6.1: `num_ref_frames` is never admitted above 16, whatever the limit says.
pub const NUM_REF_FRAMES_CEILING: u32 = 16;

/// The §6.1 admission limits. Defaults are the spec values: the census
/// pinned `max_num_ref_frames` to 1 (`census.md`, Leg A — stream); a test
/// replaying fixtures with more reference frames may raise it, but never
/// past `NUM_REF_FRAMES_CEILING`. The ES3 uses neither scaling matrices nor
/// HRD, so both stay refusals (booleans, no pinned values).
```

In `SpsLimits::default()`, replace `max_num_ref_frames: 16,` with `max_num_ref_frames: 1,`. In `SpsLimitViolation`, after `NotFrameMbsOnly,` add:

```rust
    /// POC type 1: the decode-order POC rule (§6.1) is computed for types 0
    /// and 2 only, and no source in scope uses type 1.
    PocType1,
```

In `check_sps_limits`, after the `NotFrameMbsOnly` check add:

```rust
    if s.pic_order_cnt_type == 1 {
        return Err(SpsLimitViolation::PocType1);
    }
```

and replace `if s.num_ref_frames > limits.max_num_ref_frames {` with

```rust
    if s.num_ref_frames > limits.max_num_ref_frames.min(NUM_REF_FRAMES_CEILING) {
```

Insert `SpsPins` above the first `#[cfg(test)]` in `sps.rs`:

```rust
/// The §6.1 pinned fields: fixed by a KVM session's first SPS, persisting
/// across FLV reconnects, reset at `Start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsPins {
    pub profile_idc: u8,
    pub chroma_format_idc: u8,
    pub bit_depth_luma_minus8: u8,
    pub bit_depth_chroma_minus8: u8,
    pub pic_order_cnt_type: u8,
}

impl SpsPins {
    #[must_use]
    pub fn of(s: &SpsSummary) -> SpsPins {
        SpsPins {
            profile_idc: s.profile_idc,
            chroma_format_idc: s.chroma_format_idc,
            bit_depth_luma_minus8: s.bit_depth_luma_minus8,
            bit_depth_chroma_minus8: s.bit_depth_chroma_minus8,
            pic_order_cnt_type: s.pic_order_cnt_type,
        }
    }

    /// The first pinned field `s` changes, in spec order.
    pub fn check(&self, s: &SpsSummary) -> Result<(), PinnedField> {
        let now = SpsPins::of(s);
        if now.profile_idc != self.profile_idc {
            return Err(PinnedField::ProfileIdc);
        }
        if now.chroma_format_idc != self.chroma_format_idc {
            return Err(PinnedField::ChromaFormat);
        }
        if now.bit_depth_luma_minus8 != self.bit_depth_luma_minus8
            || now.bit_depth_chroma_minus8 != self.bit_depth_chroma_minus8
        {
            return Err(PinnedField::BitDepth);
        }
        if now.pic_order_cnt_type != self.pic_order_cnt_type {
            return Err(PinnedField::PicOrderCntType);
        }
        Ok(())
    }
}
```

In `classify_sps_change`, replace the four pinned-field `if prev.… != new.…` blocks (from `if prev.profile_idc != new.profile_idc {` to the end of the `pic_order_cnt_type` block) with:

```rust
    if let Err(f) = SpsPins::of(prev).check(new) {
        return SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(f));
    }
```

and append to its doc comment (after `/// session's first SPS.`) — it stays the one §6.1 classifier; Task 4.5's admission calls it rather than keeping a second one:

```rust
///
/// This is kvm-proto's one §6.1 classifier: admission (`video::ParamState`)
/// calls it for every SPS that differs from the active one, after D4's rule
/// that a byte-identical rewritten SPS raises nothing — so, called directly
/// (kvm-probe's census), identical summaries are `Other`.
```

In `crates/kvm-proto/src/h264/mod.rs`, replace the contiguous lines from `pub use nal::{NalHeader, NalHeaderError};` through `pub use sps::{SpsParseError, SpsSummary, SpsSummaryError, parse_sps};` — six lines, the existing `mod sps;` among them — with:

```rust
pub use nal::{
    NalHeader, NalHeaderError, is_aud, is_idr, is_parameter_set, is_vcl, nal_type_allowed,
};
mod sps;
pub use sps::{NUM_REF_FRAMES_CEILING, SpsLimitViolation, SpsLimits, check_sps_limits};
pub use sps::{PinnedField, SpsChange, SpsIncompatibleReason, SpsPins, classify_sps_change};
pub use sps::{SpsParseError, SpsSummary, SpsSummaryError, parse_sps};
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib h264::sps` — Expected: all pass.
Run: `cargo test -p kvm-probe` — Expected: unchanged (its `summarize` tests use fixtures with one reference frame).

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/sps.rs crates/kvm-proto/src/h264/mod.rs
git commit -m "kvm-proto: §6.1 limits — one reference frame by default, POC type 1 refused, SpsPins" \
  -m "Pinned-field tie-break order tested (Plan A 3.9); SpsLimits doc corrected (3.7)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.3: PPS admission

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/pps.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (`pub mod pps;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/test_support.rs` (`PpsCfg`)
- Test: `crates/kvm-proto/src/h264/pps.rs` (`tests`)

**Interfaces:**
- Consumes: `rewrite_sps`, `RewriteConfig` (Task 2.4) to build contexts in tests; h264-reader's `Context`, `PicParameterSet::from_bits`.
- Produces (`kvm_proto::h264::pps`): `pub enum PpsRefusal { UnknownSps(u8), Unparsable(String), SliceGroups, NumRefIdx(u32), ScalingMatrix }` (`Eq`); `pub fn check_pps(ctx: &h264_reader::Context, nal: &[u8]) -> Result<PicParameterSet, PpsRefusal>` (`num_ref_idx_l{0,1}_default_active_minus1` ≤ 15). Test-only `test_support::PpsCfg { pps_id, sps_id, num_ref_idx_l0_default_active_minus1, chroma_qp_index_offset, slice_groups, scaling_matrix }` (`Default`) with `build(&self) -> Vec<u8>`.

- [ ] **Step 1: Write the failing tests.** Add `pub mod pps;` to `crates/kvm-proto/src/h264/mod.rs`. In `crates/kvm-proto/src/h264/test_support.rs`, insert above its `#[cfg(test)] mod tests`:

```rust
/// A hand-built CAVLC PPS for `SpsCfg`'s SPS. The default has one slice
/// group, no weighted prediction, deblocking control present and no scaling
/// matrix; the other fields make §6.1's PPS refusals.
#[derive(Clone, Copy, Default)]
pub struct PpsCfg {
    pub pps_id: u32,
    pub sps_id: u32,
    pub num_ref_idx_l0_default_active_minus1: u32,
    pub chroma_qp_index_offset: i32,
    /// Two slice groups (map type 0, run lengths 1) instead of one.
    pub slice_groups: bool,
    /// `pic_scaling_matrix_present_flag` 1 (every list absent → fallback).
    pub scaling_matrix: bool,
}

impl PpsCfg {
    pub fn build(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.put_ue(self.pps_id);
        w.put_ue(self.sps_id);
        w.put_bit(false); // entropy_coding_mode_flag (CAVLC)
        w.put_bit(false); // bottom_field_pic_order_in_frame_present_flag
        if self.slice_groups {
            w.put_ue(1); // num_slice_groups_minus1
            w.put_ue(0); // slice_group_map_type: interleaved
            w.put_ue(0); // run_length_minus1[0]
            w.put_ue(0); // run_length_minus1[1]
        } else {
            w.put_ue(0);
        }
        w.put_ue(self.num_ref_idx_l0_default_active_minus1);
        w.put_ue(0); // num_ref_idx_l1_default_active_minus1
        w.put_bit(false); // weighted_pred_flag
        w.put_bits(0, 2); // weighted_bipred_idc
        w.put_se(0); // pic_init_qp_minus26
        w.put_se(0); // pic_init_qs_minus26
        w.put_se(self.chroma_qp_index_offset);
        w.put_bit(true); // deblocking_filter_control_present_flag
        w.put_bit(false); // constrained_intra_pred_flag
        w.put_bit(false); // redundant_pic_cnt_present_flag
        if self.scaling_matrix {
            w.put_bit(false); // transform_8x8_mode_flag
            w.put_bit(true); // pic_scaling_matrix_present_flag
            for _ in 0..6 {
                w.put_bit(false); // pic_scaling_list_present_flag[i]
            }
            w.put_se(0); // second_chroma_qp_index_offset
        }
        w.rbsp_trailing_bits();
        wrap_nal(0x68, &w.into_rbsp())
    }
}
```

and create `crates/kvm-proto/src/h264/pps.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::h264::rewrite::{RewriteConfig, rewrite_sps};
    use crate::h264::test_support::{PpsCfg, SpsCfg};

    fn ctx_for(sps: &[u8]) -> Context {
        let r = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed);
        ctx
    }

    #[test]
    fn the_es3_pps_passes_with_or_without_its_trailing_zeros() {
        // census.md sps_hex / pps_hex
        let ctx = ctx_for(&[
            0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18,
            0x14, 0x08, 0x00,
        ]);
        let p = check_pps(&ctx, &[0x68, 0xce, 0x31, 0x12, 0x00, 0x00]).unwrap();
        assert!(!p.entropy_coding_mode_flag); // CAVLC
        assert!(p.deblocking_filter_control_present_flag);
        assert_eq!(p.chroma_qp_index_offset, 4);
        check_pps(&ctx, &[0x68, 0xce, 0x31, 0x12]).unwrap();
    }

    #[test]
    fn each_pps_rule_has_its_own_refusal() {
        let ctx = ctx_for(&SpsCfg::main_1080p().build());
        assert_eq!(
            check_pps(&ctx, &PpsCfg::default().build())
                .unwrap()
                .pic_parameter_set_id
                .id(),
            0
        );
        let refused = |c: PpsCfg| check_pps(&ctx, &c.build()).unwrap_err();
        assert_eq!(
            refused(PpsCfg {
                sps_id: 1,
                ..PpsCfg::default()
            }),
            PpsRefusal::UnknownSps(1)
        );
        assert_eq!(
            refused(PpsCfg {
                slice_groups: true,
                ..PpsCfg::default()
            }),
            PpsRefusal::SliceGroups
        );
        assert_eq!(
            refused(PpsCfg {
                num_ref_idx_l0_default_active_minus1: 16,
                ..PpsCfg::default()
            }),
            PpsRefusal::NumRefIdx(16)
        );
        assert_eq!(
            refused(PpsCfg {
                scaling_matrix: true,
                ..PpsCfg::default()
            }),
            PpsRefusal::ScalingMatrix
        );
        assert!(matches!(
            check_pps(&ctx, &[0x68]),
            Err(PpsRefusal::Unparsable(_))
        ));
        assert!(matches!(
            check_pps(&ctx, &[]),
            Err(PpsRefusal::Unparsable(_))
        ));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib h264::pps`
Expected: FAIL to compile — `cannot find function check_pps`, type `PpsRefusal`.

- [ ] **Step 3: Implement.** Put this above the test module in `pps.rs`:

```rust
//! §6.1 PPS admission: parsed by h264-reader against the active (rewritten)
//! SPS, then held to the rules the ES3 meets (`census.md`: one slice group,
//! no scaling matrices).
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use h264_reader::Context;
use h264_reader::nal::pps::{PicParameterSet, PpsError};
use h264_reader::nal::{Nal as _, RefNal};

/// Why a PPS was refused (`stream_incompatible`, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpsRefusal {
    /// It names an SPS id that is not the active SPS.
    UnknownSps(u8),
    /// h264-reader could not parse it (its error, as text).
    Unparsable(String),
    /// `num_slice_groups_minus1 != 0`.
    SliceGroups,
    /// A `num_ref_idx_l{0,1}_default_active_minus1` above 15 (frames only).
    NumRefIdx(u32),
    /// `pic_scaling_matrix_present_flag == 1`.
    ScalingMatrix,
}

/// Highest `num_ref_idx_lX_default_active_minus1` for frame coding.
const MAX_NUM_REF_IDX_MINUS1: u32 = 15;

/// Parse a wire PPS NAL against `ctx` (holding the active SPS) and check it.
pub fn check_pps(ctx: &Context, nal: &[u8]) -> Result<PicParameterSet, PpsRefusal> {
    if nal.is_empty() {
        return Err(PpsRefusal::Unparsable("empty".into()));
    }
    let pps =
        PicParameterSet::from_bits(ctx, RefNal::new(nal, &[], true).rbsp_bits()).map_err(|e| {
            match e {
                PpsError::UnknownSeqParamSetId(id) => PpsRefusal::UnknownSps(id.id()),
                other => PpsRefusal::Unparsable(format!("{other:?}")),
            }
        })?;
    if pps.slice_groups.is_some() {
        return Err(PpsRefusal::SliceGroups);
    }
    for n in [
        pps.num_ref_idx_l0_default_active_minus1,
        pps.num_ref_idx_l1_default_active_minus1,
    ] {
        if n > MAX_NUM_REF_IDX_MINUS1 {
            return Err(PpsRefusal::NumRefIdx(n));
        }
    }
    if pps
        .extension
        .as_ref()
        .is_some_and(|x| x.pic_scaling_matrix.is_some())
    {
        return Err(PpsRefusal::ScalingMatrix);
    }
    Ok(pps)
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib h264::pps` — Expected: 2 passed (the ES3's own PPS — CAVLC, deblocking control, `chroma_qp_index_offset` 4 — parses against the rewritten ES3 SPS with and without its trailing zeros).

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/pps.rs crates/kvm-proto/src/h264/mod.rs crates/kvm-proto/src/h264/test_support.rs
git commit -m "kvm-proto: §6.1 PPS admission" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.4: Slice checks and decode-order POC

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/picture.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (`pub mod picture;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/test_support.rs` (`SliceCfg`)
- Test: `crates/kvm-proto/src/h264/picture.rs` (`tests`)

**Interfaces:**
- Consumes: `parse_slice_header_prefix`, `slice_type_allowed` (Plan A); `check_pps` (Task 4.3); `rewrite_sps` (Task 2.4); h264-reader's `SliceHeader::from_bits`.
- Produces (`kvm_proto::h264::picture`):
  - `pub enum SliceRefusal { Unparsable(String), SliceType(u32), FirstMb { first_mb: u32, pic_size_in_mbs: u32 }, PocNotIncreasing { previous: i64, current: i64 }, PocType1 }` (`Eq`)
  - `pub struct SliceInfo { first_mb_in_slice: u32, idr: bool, nal_ref_idc: u8, pps_id: u8, frame_num: u16, idr_pic_id: Option<u32>, pic_order_cnt_lsb: Option<u32>, delta_pic_order_cnt_bottom: i32, mmco5: bool }` (`Copy`, `Eq`) with `pub fn same_picture(&self, other: &SliceInfo) -> bool` (7.4.1.2.4)
  - `pub fn parse_slice(ctx: &h264_reader::Context, nal: &[u8]) -> Result<SliceInfo, SliceRefusal>` — slice type from the context-free prefix first (so a B slice is always `SliceType`), then h264-reader's full header, then `first_mb_in_slice < PicSizeInMbs`
  - `pub struct PocTracker` (`Default`): `reset(&mut self)`, `next(&mut self, sps: &SeqParameterSet, s: &SliceInfo) -> Result<i64, SliceRefusal>` — 8.2.1.1 (type 0) and 8.2.1.3 (type 2), frames only; an IDR or MMCO 5 starts a GOP
  - Test-only `test_support::SliceCfg { header_byte, first_mb, slice_type, pps_id, frame_num, log2_max_frame_num, idr_pic_id, poc_lsb: Option<(u32, u32)>, mmco5 }` with `idr()`, `p(frame_num)`, `build(&self) -> Vec<u8>`

- [ ] **Step 1: Write the failing tests.** Add `pub mod picture;` to `crates/kvm-proto/src/h264/mod.rs`. In `test_support.rs`, insert above its `#[cfg(test)] mod tests`:

```rust
/// A slice NAL whose header h264-reader parses against `SpsCfg` (POC type 0
/// or 2, frames only) and `PpsCfg`; the slice data is one filler byte.
pub struct SliceCfg {
    pub header_byte: u8, // 0x65 IDR, 0x41 P (ref), 0x01 non-ref
    pub first_mb: u32,
    pub slice_type: u32,
    pub pps_id: u32,
    pub frame_num: u32,
    pub log2_max_frame_num: u32,
    pub idr_pic_id: u32,
    /// `(pic_order_cnt_lsb, bits)` for POC type 0.
    pub poc_lsb: Option<(u32, u32)>,
    pub mmco5: bool,
}

impl SliceCfg {
    pub fn idr() -> Self {
        Self {
            header_byte: 0x65,
            first_mb: 0,
            slice_type: 7,
            pps_id: 0,
            frame_num: 0,
            log2_max_frame_num: 4,
            idr_pic_id: 0,
            poc_lsb: None,
            mmco5: false,
        }
    }
    pub fn p(frame_num: u32) -> Self {
        Self {
            header_byte: 0x41,
            slice_type: 5,
            frame_num,
            ..Self::idr()
        }
    }
    pub fn build(&self) -> Vec<u8> {
        let idr = self.header_byte & 0x1F == 5;
        let is_p = matches!(self.slice_type % 5, 0);
        let is_b = matches!(self.slice_type % 5, 1);
        let mut w = BitWriter::new();
        w.put_ue(self.first_mb);
        w.put_ue(self.slice_type);
        w.put_ue(self.pps_id);
        w.put_bits(self.frame_num, self.log2_max_frame_num);
        if idr {
            w.put_ue(self.idr_pic_id);
        }
        if let Some((lsb, bits)) = self.poc_lsb {
            w.put_bits(lsb, bits);
        }
        if is_b {
            w.put_bit(true); // direct_spatial_mv_pred_flag
        }
        if is_p || is_b {
            w.put_bit(false); // num_ref_idx_active_override_flag
            w.put_bit(false); // ref_pic_list_modification_flag_l0
            if is_b {
                w.put_bit(false); // ref_pic_list_modification_flag_l1
            }
        }
        if self.header_byte & 0x60 != 0 {
            if idr {
                w.put_bit(false); // no_output_of_prior_pics_flag
                w.put_bit(false); // long_term_reference_flag
            } else if self.mmco5 {
                w.put_bit(true); // adaptive_ref_pic_marking_mode_flag
                w.put_ue(5);
                w.put_ue(0);
            } else {
                w.put_bit(false);
            }
        }
        w.put_se(0); // slice_qp_delta
        w.put_ue(1); // disable_deblocking_filter_idc
        w.put_bits(0xA5, 8); // stand-in slice data
        w.rbsp_trailing_bits();
        wrap_nal(self.header_byte, &w.into_rbsp())
    }
}
```

and create `crates/kvm-proto/src/h264/picture.rs` with:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use crate::h264::rewrite::{RewriteConfig, rewrite_sps};
    use crate::h264::test_support::{PpsCfg, SliceCfg, SpsCfg};

    /// Baseline 1080p, `log2_max_frame_num` 4; POC type 2, or type 0 with
    /// a 5-bit `pic_order_cnt_lsb`.
    fn ctx(poc_type: u32) -> (Context, SeqParameterSet) {
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_order_cnt_type = poc_type;
        c.log2_max_poc_lsb_minus4 = 1;
        let r = rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap();
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed.clone());
        ctx.put_pic_param_set(
            crate::h264::pps::check_pps(&ctx, &PpsCfg::default().build()).unwrap(),
        );
        (ctx, r.parsed)
    }

    fn slice(ctx: &Context, s: &SliceCfg) -> SliceInfo {
        parse_slice(ctx, &s.build()).unwrap()
    }

    fn poc0(frame_num: u32, lsb: u32) -> SliceCfg {
        SliceCfg {
            poc_lsb: Some((lsb, 5)),
            ..SliceCfg::p(frame_num)
        }
    }

    #[test]
    fn poc_type_2_increases_across_a_frame_num_wrap() {
        let (ctx, sps) = ctx(2);
        let mut t = PocTracker::default();
        assert_eq!(t.next(&sps, &slice(&ctx, &SliceCfg::idr())), Ok(0));
        let pocs: Vec<i64> = [1, 2, 15, 0, 1]
            .iter()
            .map(|&f| t.next(&sps, &slice(&ctx, &SliceCfg::p(f))).unwrap())
            .collect();
        assert_eq!(pocs, [2, 4, 30, 32, 34]);
    }

    #[test]
    fn poc_type_0_follows_the_lsb_wrap_and_refuses_going_back() {
        let (ctx, sps) = ctx(0);
        let mut t = PocTracker::default();
        let idr = SliceCfg {
            poc_lsb: Some((0, 5)),
            ..SliceCfg::idr()
        };
        assert_eq!(t.next(&sps, &slice(&ctx, &idr)), Ok(0));
        // 8.2.1.1: a step of half MaxPicOrderCntLsb (16) or more is a wrap.
        let pocs: Vec<i64> = [(1, 10), (2, 20), (3, 30), (4, 8)]
            .iter()
            .map(|&(f, lsb)| t.next(&sps, &slice(&ctx, &poc0(f, lsb))).unwrap())
            .collect();
        assert_eq!(pocs, [10, 20, 30, 40]); // 8 after 30: the lsb wrapped
        assert_eq!(
            t.next(&sps, &slice(&ctx, &poc0(5, 30))),
            Err(SliceRefusal::PocNotIncreasing {
                previous: 40,
                current: 30
            })
        );
        // An IDR starts a new GOP: POC 0 is fine again.
        assert_eq!(t.next(&sps, &slice(&ctx, &idr)), Ok(0));
    }

    #[test]
    fn mmco5_restarts_the_order() {
        let (ctx, sps) = ctx(2);
        let mut t = PocTracker::default();
        t.next(&sps, &slice(&ctx, &SliceCfg::idr())).unwrap();
        t.next(&sps, &slice(&ctx, &SliceCfg::p(1))).unwrap();
        t.next(&sps, &slice(&ctx, &SliceCfg::p(2))).unwrap();
        let mmco5 = SliceCfg {
            mmco5: true,
            ..SliceCfg::p(3)
        };
        t.next(&sps, &slice(&ctx, &mmco5)).unwrap();
        // After MMCO 5 the next picture counts from frame_num 0 again.
        assert_eq!(t.next(&sps, &slice(&ctx, &SliceCfg::p(1))), Ok(2));
    }

    #[test]
    fn b_sp_and_si_are_refused_from_the_prefix() {
        let (ctx, _) = ctx(2);
        assert_eq!(
            parse_slice(&ctx, &[0x41, 0xAC]),
            Err(SliceRefusal::SliceType(1))
        );
        for t in [3u32, 4, 6, 8, 9] {
            let s = SliceCfg {
                slice_type: t,
                ..SliceCfg::p(1)
            };
            assert_eq!(
                parse_slice(&ctx, &s.build()),
                Err(SliceRefusal::SliceType(t))
            );
        }
    }

    #[test]
    fn first_mb_must_be_inside_the_picture() {
        let (ctx, _) = ctx(2);
        let s = SliceCfg {
            first_mb: 120 * 68 - 1,
            ..SliceCfg::p(1)
        };
        assert_eq!(slice(&ctx, &s).first_mb_in_slice, 8159);
        let s = SliceCfg {
            first_mb: 120 * 68,
            ..SliceCfg::p(1)
        };
        assert_eq!(
            parse_slice(&ctx, &s.build()),
            Err(SliceRefusal::FirstMb {
                first_mb: 8160,
                pic_size_in_mbs: 8160
            })
        );
    }

    #[test]
    fn same_picture_compares_the_7_4_1_2_4_fields() {
        let (ctx, _) = ctx(2);
        let a = slice(&ctx, &SliceCfg::p(1));
        assert!(a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                ..SliceCfg::p(1)
            }
        )));
        assert!(!a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                ..SliceCfg::p(2)
            }
        )));
        assert!(!a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                header_byte: 0x01,
                ..SliceCfg::p(1)
            }
        )));
        assert!(!a.same_picture(&slice(&ctx, &SliceCfg::idr())));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib picture`
Expected: FAIL to compile — `cannot find function parse_slice`, types `PocTracker`, `SliceInfo`, `SliceRefusal`.

- [ ] **Step 3: Implement.** Put this above the test module in `picture.rs`:

```rust
//! §6.1 slice-header checks and the decode-order POC rule, on top of
//! h264-reader's slice-header parser with the admitted SPS and PPSs.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::{parse_slice_header_prefix, slice_type_allowed};
use h264_reader::Context;
use h264_reader::nal::slice::{
    DecRefPicMarking, MemoryManagementControlOperation, PicOrderCountLsb, SliceHeader,
};
use h264_reader::nal::sps::{PicOrderCntType, SeqParameterSet};
use h264_reader::nal::{Nal as _, RefNal};

/// Why a slice was refused (`stream_incompatible`, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceRefusal {
    /// h264-reader could not parse the header (its error, as text) — this
    /// includes a `pic_parameter_set_id` with no admitted PPS.
    Unparsable(String),
    /// `slice_type` not in `{0, 2, 5, 7}`: B, SP or SI (§6.1 admits P and I).
    SliceType(u32),
    /// `first_mb_in_slice >= PicSizeInMbs`.
    FirstMb { first_mb: u32, pic_size_in_mbs: u32 },
    /// POC not strictly increasing in decode order within a GOP.
    PocNotIncreasing { previous: i64, current: i64 },
    /// POC type 1 is refused by the SPS limits; never reaches here.
    PocType1,
}

/// The slice-header fields that identify a picture (7.4.1.2.4) and its POC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceInfo {
    pub first_mb_in_slice: u32,
    pub idr: bool,
    pub nal_ref_idc: u8,
    pub pps_id: u8,
    pub frame_num: u16,
    pub idr_pic_id: Option<u32>,
    pub pic_order_cnt_lsb: Option<u32>,
    pub delta_pic_order_cnt_bottom: i32,
    /// `memory_management_control_operation == 5` in this slice.
    pub mmco5: bool,
}

impl SliceInfo {
    /// True when `other` belongs to the same picture as `self` (7.4.1.2.4:
    /// every field that starts a new primary picture is equal).
    #[must_use]
    pub fn same_picture(&self, other: &SliceInfo) -> bool {
        self.idr == other.idr
            && (self.nal_ref_idc == 0) == (other.nal_ref_idc == 0)
            && self.pps_id == other.pps_id
            && self.frame_num == other.frame_num
            && self.idr_pic_id == other.idr_pic_id
            && self.pic_order_cnt_lsb == other.pic_order_cnt_lsb
            && self.delta_pic_order_cnt_bottom == other.delta_pic_order_cnt_bottom
    }
}

/// Parse and check one slice NAL (type 1 or 5) against `ctx`.
pub fn parse_slice(ctx: &Context, nal: &[u8]) -> Result<SliceInfo, SliceRefusal> {
    let unparsable = |e: &dyn core::fmt::Debug| SliceRefusal::Unparsable(format!("{e:?}"));
    // The slice type is checked from the context-free prefix first, so a B
    // slice is refused as such whatever follows it.
    let prefix = parse_slice_header_prefix(nal).map_err(|e| unparsable(&e))?;
    if !slice_type_allowed(prefix.slice_type) {
        return Err(SliceRefusal::SliceType(prefix.slice_type));
    }
    let refnal = RefNal::new(nal, &[], true);
    let header = refnal.header().map_err(|e| unparsable(&e))?;
    let mut bits = refnal.rbsp_bits();
    let (sh, sps, pps) =
        SliceHeader::from_bits(ctx, &mut bits, header, None).map_err(|e| unparsable(&e))?;
    let pic_size_in_mbs = sps
        .pic_width_in_mbs()
        .saturating_mul(sps.pic_height_in_map_units());
    if sh.first_mb_in_slice >= pic_size_in_mbs {
        return Err(SliceRefusal::FirstMb {
            first_mb: sh.first_mb_in_slice,
            pic_size_in_mbs,
        });
    }
    let (lsb, delta_bottom) = match sh.pic_order_cnt_lsb {
        Some(PicOrderCountLsb::Frame(lsb)) => (Some(lsb), 0),
        Some(PicOrderCountLsb::FieldsAbsolute {
            pic_order_cnt_lsb,
            delta_pic_order_cnt_bottom,
        }) => (Some(pic_order_cnt_lsb), delta_pic_order_cnt_bottom),
        Some(PicOrderCountLsb::FieldsDelta(_)) => return Err(SliceRefusal::PocType1),
        None => (None, 0),
    };
    let mmco5 = matches!(
        &sh.dec_ref_pic_marking,
        Some(DecRefPicMarking::Adaptive(ops))
            if ops.iter().any(|op| matches!(op, MemoryManagementControlOperation::AllRefPicturesUnused))
    );
    Ok(SliceInfo {
        first_mb_in_slice: sh.first_mb_in_slice,
        idr: sh.idr_pic_id.is_some(),
        nal_ref_idc: header.nal_ref_idc(),
        pps_id: pps.pic_parameter_set_id.id(),
        frame_num: sh.frame_num,
        idr_pic_id: sh.idr_pic_id,
        pic_order_cnt_lsb: lsb,
        delta_pic_order_cnt_bottom: delta_bottom,
        mmco5,
    })
}

/// Decode-order picture order count (H.264 8.2.1.1 type 0 and 8.2.1.3
/// type 2, frames only) and §6.1's rule that it strictly increases within
/// a GOP. State is per FLV connection: `reset` on every open.
#[derive(Debug, Default, Clone)]
pub struct PocTracker {
    prev_msb: i64,
    prev_lsb: i64,
    prev_frame_num: i64,
    prev_frame_num_offset: i64,
    last_poc: Option<i64>,
}

impl PocTracker {
    pub fn reset(&mut self) {
        *self = PocTracker::default();
    }

    /// The POC of the picture whose first slice is `s`, refused when it does
    /// not exceed the previous picture's in this GOP. An IDR starts a GOP;
    /// so does a picture after one with MMCO 5 (its POC becomes 0).
    pub fn next(&mut self, sps: &SeqParameterSet, s: &SliceInfo) -> Result<i64, SliceRefusal> {
        if s.idr {
            *self = PocTracker::default();
        }
        let poc = match &sps.pic_order_cnt {
            PicOrderCntType::TypeZero {
                log2_max_pic_order_cnt_lsb_minus4,
            } => {
                let max_lsb = 1_i64
                    .wrapping_shl(u32::from(*log2_max_pic_order_cnt_lsb_minus4).saturating_add(4));
                let half = max_lsb.wrapping_shr(1);
                let lsb = i64::from(s.pic_order_cnt_lsb.unwrap_or(0));
                let msb = if lsb < self.prev_lsb && self.prev_lsb.saturating_sub(lsb) >= half {
                    self.prev_msb.saturating_add(max_lsb)
                } else if lsb > self.prev_lsb && lsb.saturating_sub(self.prev_lsb) > half {
                    self.prev_msb.saturating_sub(max_lsb)
                } else {
                    self.prev_msb
                };
                let top = msb.saturating_add(lsb);
                let poc = top.min(top.saturating_add(i64::from(s.delta_pic_order_cnt_bottom)));
                if s.nal_ref_idc != 0 {
                    if s.mmco5 {
                        self.prev_msb = 0;
                        self.prev_lsb = top.saturating_sub(poc);
                    } else {
                        self.prev_msb = msb;
                        self.prev_lsb = lsb;
                    }
                }
                poc
            }
            PicOrderCntType::TypeTwo => {
                let max_frame_num = 1_i64.wrapping_shl(u32::from(sps.log2_max_frame_num()));
                let frame_num = i64::from(s.frame_num);
                let offset = if s.idr {
                    0
                } else if self.prev_frame_num > frame_num {
                    self.prev_frame_num_offset.saturating_add(max_frame_num)
                } else {
                    self.prev_frame_num_offset
                };
                let base = offset.saturating_add(frame_num).saturating_mul(2);
                let poc = if s.idr {
                    0
                } else if s.nal_ref_idc == 0 {
                    base.saturating_sub(1)
                } else {
                    base
                };
                (self.prev_frame_num, self.prev_frame_num_offset) =
                    if s.mmco5 { (0, 0) } else { (frame_num, offset) };
                poc
            }
            PicOrderCntType::TypeOne { .. } => return Err(SliceRefusal::PocType1),
        };
        if let Some(previous) = self.last_poc
            && poc <= previous
        {
            return Err(SliceRefusal::PocNotIncreasing {
                previous,
                current: poc,
            });
        }
        self.last_poc = Some(if s.mmco5 { 0 } else { poc });
        Ok(poc)
    }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib picture` — Expected: 6 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/h264/picture.rs crates/kvm-proto/src/h264/mod.rs crates/kvm-proto/src/h264/test_support.rs
git commit -m "kvm-proto: §6.1 slice checks and decode-order POC (types 0 and 2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.5: Admission errors, the violation window, parameter-set state

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/error.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/violations.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/params.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/mod.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (`pub mod video;`)
- Test: the `tests` modules of `error.rs`, `violations.rs`, `params.rs`

**Interfaces:**
- Consumes: `FlvError` + `kind()` (Task 3.1); `NalRefusal` (4.1); `SpsPins`, `SpsLimits`, `check_sps_limits`, `classify_sps_change`, `SpsChange`, `SpsIncompatibleReason` (4.2 — `ParamState` classifies every changed SPS through Plan A's one classifier, adding only D4's byte-identical rule in front of it); `check_pps`, `PpsRefusal` (4.3); `SliceRefusal` (4.4); `rewrite_sps`, `RewriteConfig`, `RewriteError`, `RewriteFields`, `RewrittenSps` (2.4).
- Produces (`kvm_proto::video`):
  - `pub enum Framing { Flv(FlvError), UnknownTagType(u8), Nal(NalRefusal), ConfigNalType(u8), NotOnePicture, TooManyPps }`; `pub enum Incompatible { Codec(u8), Enhanced([u8; 4]), CompositionTime { first: i32, now: i32 }, Rewrite(RewriteError), Sps(SpsIncompatibleReason), Pps(PpsRefusal), Slice(SliceRefusal) }`; `pub enum AdmissionError { Framing(Framing), Incompatible(Incompatible) }` with `impl From<FlvError>` and `pub fn kind(&self) -> &'static str` (distinct snake_case labels for `parse_errors{kind}` and the disconnect log)
  - `pub enum ViolationVerdict { Transient, Fatal }`; `pub struct ViolationWindow` with `new(threshold: usize, window: Duration)`, `stream_corrupt()` (3 in 60 s), `record(&mut self, now: Instant) -> ViolationVerdict` — Plan C's KVM actor feeds it every `Framing` error
  - `pub enum ParamClass { Initial, Resize, Other }`; `pub struct ParamSets { sps: Bytes, pps: Vec<Bytes>, summary: SpsSummary }`; `pub struct ParamsChange { class: ParamClass, params: ParamSets, rewrites: RewriteFields }` — the payload of Plan C's `SpsChanged{class, sps, pps}`
  - crate-internal `ParamState` (`new`, `flv_opened`, `ctx`, `active_sps`, `snapshot`, `clear_pps`, `take_sps`, `take_pps`, `change`) and `strongest`, used by Task 4.6

- [ ] **Step 1: Write the failing tests.** Add `pub mod video;` to `crates/kvm-proto/src/lib.rs` (after `pub mod login;`). Create `crates/kvm-proto/src/video/mod.rs`:

```rust
//! KVM-side video admission (§6.1, §6.2, §6.8): every demuxed FLV tag goes
//! through `VideoAdmission::admit`, which applies the NAL sanitiser, the SPS
//! rewriter, the SPS/PPS/slice checks and the one-picture rule, and returns
//! what the pump may see: a parameter-set change and/or one access unit.
//! Sans-IO: the caller passes the receive time. Nothing here allocates per
//! access unit — the AU reuses the demuxer's NAL `Vec`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod error;
// `VideoAdmission` (Task 4.6) is `ParamState`'s only caller; until then only
// its unit tests use it.
#[allow(dead_code)]
mod params;
mod violations;
pub use error::{AdmissionError, Framing, Incompatible};
pub use params::{ParamClass, ParamSets, ParamsChange};
pub use violations::{ViolationVerdict, ViolationWindow};
```

(the `allow(dead_code)` is removed in Task 4.6, when `VideoAdmission` uses `ParamState`), and create the three files with their test modules only — `error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_label_is_distinct() {
        let all = [
            AdmissionError::from(FlvError::OversizeTag),
            framing(Framing::UnknownTagType(3)),
            framing(Framing::Nal(NalRefusal::Empty)),
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
            framing(Framing::Nal(NalRefusal::StartCode)),
            framing(Framing::ConfigNalType(8)),
            framing(Framing::NotOnePicture),
            framing(Framing::TooManyPps),
            incompatible(Incompatible::Codec(12)),
            incompatible(Incompatible::Enhanced(*b"hvc1")),
            incompatible(Incompatible::CompositionTime { first: 16, now: 0 }),
            incompatible(Incompatible::Rewrite(RewriteError::SelfCheck)),
            incompatible(Incompatible::Sps(
                SpsIncompatibleReason::PinnedFieldChanged(crate::h264::PinnedField::ProfileIdc),
            )),
            incompatible(Incompatible::Pps(PpsRefusal::SliceGroups)),
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(1))),
        ];
        let mut kinds: Vec<&str> = all.iter().map(AdmissionError::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), all.len());
    }
}
```

`violations.rs`:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn the_third_violation_within_sixty_seconds_is_fatal() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut w = ViolationWindow::stream_corrupt();
        assert_eq!(w.record(t0), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(30)), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(59)), ViolationVerdict::Fatal);
    }

    #[test]
    fn violations_older_than_the_window_drop_out() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut w = ViolationWindow::stream_corrupt();
        w.record(t0);
        w.record(t0 + s(30));
        // The first is 60 s old by now: only two remain in the window.
        assert_eq!(w.record(t0 + s(60)), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(61)), ViolationVerdict::Fatal);
    }
}
```

`params.rs` (the ES3's own SPS and PPS go through the whole rewrite-and-check path here):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::h264::rewrite::RewriteError;
    use crate::h264::sps_syntax::SpsSyntaxError;
    use crate::h264::test_support::{PpsCfg, SpsCfg};
    use crate::h264::{PinnedField, SpsLimitViolation};

    /// The ES3's own SPS and PPS (`census.md` `sps_hex`, `pps_hex`, the
    /// PPS's trailing zeros trimmed as `check_nal` does).
    const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];
    const ES3_PPS: [u8; 4] = [0x68, 0xce, 0x31, 0x12];

    fn state() -> ParamState {
        ParamState::new(SpsLimits::default(), RewriteConfig::ES3, 16)
    }

    fn baseline(width_mbs_minus1: u32, height_minus1: u32) -> Vec<u8> {
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = width_mbs_minus1;
        c.pic_height_in_map_units_minus1 = height_minus1;
        c.crop = None;
        c.build()
    }

    fn tag(st: &mut ParamState, sps: &[&[u8]], pps: &[&[u8]]) -> Option<ParamsChange> {
        let before = st.snapshot();
        let mut class = None;
        for s in sps {
            class = strongest(class, st.take_sps(s).unwrap());
        }
        for p in pps {
            st.take_pps(&Bytes::copy_from_slice(p)).unwrap();
        }
        st.change(class, before)
    }

    #[test]
    fn es3_sets_are_initial_rewritten_then_silent_when_repeated() {
        let mut st = state();
        let c = tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]).unwrap();
        assert_eq!(c.class, ParamClass::Initial);
        assert_eq!(c.params.summary.level_idc, 40);
        assert_eq!(c.params.pps, [Bytes::from_static(&ES3_PPS)]);
        assert!(c.rewrites.level && c.rewrites.vui && c.rewrites.restriction);
        assert_eq!(tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]), None);
        st.flv_opened();
        assert_eq!(
            tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]).unwrap().class,
            ParamClass::Initial
        );
    }

    #[test]
    fn size_change_is_resize_and_other_changes_are_other() {
        let mut st = state();
        tag(&mut st, &[&baseline(39, 22)], &[&PpsCfg::default().build()]);
        let r = tag(&mut st, &[&baseline(52, 29)], &[]).unwrap();
        assert_eq!(r.class, ParamClass::Resize);
        assert_eq!(
            (r.params.summary.width, r.params.summary.height),
            (848, 480)
        );
        // A PPS alone changing is Other.
        let pps = PpsCfg {
            chroma_qp_index_offset: 2,
            ..PpsCfg::default()
        };
        assert_eq!(
            tag(&mut st, &[], &[&pps.build()]).unwrap().class,
            ParamClass::Other
        );
        // The SPS changing only outside dimensions/level is Other.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = 52;
        c.pic_height_in_map_units_minus1 = 29;
        c.crop = None;
        c.log2_max_frame_num_minus4 = 2;
        assert_eq!(
            tag(&mut st, &[&c.build()], &[]).unwrap().class,
            ParamClass::Other
        );
    }

    #[test]
    fn pinned_fields_and_limits_refuse() {
        let mut st = state();
        tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]);
        let main = SpsCfg::main_1080p().build(); // profile 77
        // The pins outlive an FLV reconnect (§6.1) …
        st.flv_opened();
        assert_eq!(
            st.take_sps(&main),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::PinnedFieldChanged(PinnedField::ProfileIdc)
            )))
        );
        // … and only a new session (`Start`) resets them.
        assert_eq!(state().take_sps(&main), Ok(Some(ParamClass::Initial)));
        let mut two_refs = SpsCfg::main_1080p();
        two_refs.profile_idc = 66;
        two_refs.max_num_ref_frames = 2;
        assert_eq!(
            state().take_sps(&two_refs.build()),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::TooManyRefFrames(2))
            )))
        );
    }

    #[test]
    fn section_6_1s_largest_size_needs_level_5_2_and_is_refused() {
        // 4096×2304 is 36 864 MBs: at 30 fps that is past level 5.1's MaxMBPS,
        // so the rewrite raises the level to 5.2 and the §6.1 level limit
        // refuses it (D9). Level 5.1 at 30 fps admits 32 768 MBs: 4096×2048.
        assert_eq!(
            state().take_sps(&baseline(255, 143)),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::Level(52))
            )))
        );
        assert_eq!(
            state().take_sps(&baseline(255, 127)),
            Ok(Some(ParamClass::Initial))
        );
    }

    #[test]
    fn an_sps_the_rewriter_cannot_read_is_stream_incompatible() {
        // seq_parameter_set_id 32 is outside H.264's range: the rewriter
        // refuses to read it, and there is no pass-through (§6.8).
        let mut w = crate::bits::BitWriter::new();
        w.write_u8(66);
        w.write_u8(0);
        w.write_u8(30);
        w.write_ue(32);
        w.write_trailing_bits();
        let mut nal = vec![0x67];
        crate::bits::escape_rbsp_into(&w.into_rbsp(), &mut nal);
        assert_eq!(
            state().take_sps(&nal),
            Err(incompatible(Incompatible::Rewrite(
                RewriteError::Unreadable(SpsSyntaxError::OutOfRange("seq_parameter_set_id"))
            )))
        );
    }

    #[test]
    fn a_new_sps_drops_ppss_that_no_longer_parse() {
        let mut st = state();
        tag(&mut st, &[&baseline(39, 22)], &[&PpsCfg::default().build()]);
        // The PPS names SPS id 0; the new SPS has id 1, so the PPS goes.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = 39;
        c.pic_height_in_map_units_minus1 = 22;
        c.crop = None;
        c.seq_parameter_set_id = 1;
        let ch = tag(&mut st, &[&c.build()], &[]).unwrap();
        assert_eq!(ch.class, ParamClass::Other);
        assert!(ch.params.pps.is_empty());
    }

    #[test]
    fn more_than_sixteen_pps_ids_is_a_framing_violation() {
        let mut st = state();
        tag(&mut st, &[&ES3_SPS], &[]);
        for id in 0..16 {
            st.take_pps(&Bytes::from(
                PpsCfg {
                    pps_id: id,
                    ..PpsCfg::default()
                }
                .build(),
            ))
            .unwrap();
        }
        let seventeenth = Bytes::from(
            PpsCfg {
                pps_id: 16,
                ..PpsCfg::default()
            }
            .build(),
        );
        assert_eq!(st.take_pps(&seventeenth), Err(framing(Framing::TooManyPps)));
        // Replacing an existing id is fine.
        st.take_pps(&Bytes::from(
            PpsCfg {
                pps_id: 3,
                ..PpsCfg::default()
            }
            .build(),
        ))
        .unwrap();
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib video::`
Expected: FAIL to compile — `cannot find type AdmissionError`, `ViolationWindow`, `ParamState`, `ParamClass` and friends.

- [ ] **Step 3: Implement.** Above each test module put — `error.rs`:

```rust
//! Admission refusals by §6.9 class, with their metric labels.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::flv::FlvError;
use crate::h264::SpsIncompatibleReason;
use crate::h264::picture::SliceRefusal;
use crate::h264::pps::PpsRefusal;
use crate::h264::rewrite::RewriteError;
use crate::h264::sanitize::NalRefusal;

/// §6.9 framing violations found after demux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framing {
    Flv(FlvError),
    /// A tag type other than 8, 9 or 18.
    UnknownTagType(u8),
    Nal(NalRefusal),
    /// A config record entry whose own header is not an SPS (resp. PPS).
    ConfigNalType(u8),
    /// The tag is not exactly one picture (§6.2): no slice, a second
    /// picture's slice, a first slice with `first_mb_in_slice != 0`, a second
    /// AUD, or an AUD after a slice.
    NotOnePicture,
    /// More distinct PPS ids than the §6.2 limit (16) at once.
    TooManyPps,
}

/// §6.9 stream-incompatible causes: fatal at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incompatible {
    /// FLV `CodecID` other than 7 (12 is HEVC).
    Codec(u8),
    /// An Enhanced-RTMP FourCC (`hvc1`, `av01`, …).
    Enhanced([u8; 4]),
    /// `CompositionTime` differs from the first coded tag's on this FLV.
    CompositionTime {
        first: i32,
        now: i32,
    },
    Rewrite(RewriteError),
    Sps(SpsIncompatibleReason),
    Pps(PpsRefusal),
    Slice(SliceRefusal),
}

/// Why a tag was refused, by §6.9 class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// Transient: reconnect the FLV and feed a `ViolationWindow` (three
    /// within 60 s is fatal `stream_corrupt`).
    Framing(Framing),
    /// Fatal `stream_incompatible`.
    Incompatible(Incompatible),
}

impl From<FlvError> for AdmissionError {
    fn from(e: FlvError) -> Self {
        AdmissionError::Framing(Framing::Flv(e))
    }
}

impl AdmissionError {
    /// The `parse_errors{kind}` label (framing) or the `stream_incompatible`
    /// detail (incompatible), for metrics and the disconnect log line.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            AdmissionError::Framing(f) => match f {
                Framing::Flv(e) => e.kind(),
                Framing::UnknownTagType(_) => "unknown_tag_type",
                Framing::Nal(NalRefusal::Empty) => "empty_nal",
                Framing::Nal(NalRefusal::ForbiddenBit) => "forbidden_bit",
                Framing::Nal(NalRefusal::StartCode) => "start_code_in_nal",
                Framing::ConfigNalType(_) => "config_nal_type",
                Framing::NotOnePicture => "not_one_picture",
                Framing::TooManyPps => "too_many_pps",
            },
            AdmissionError::Incompatible(i) => match i {
                Incompatible::Codec(_) => "codec",
                Incompatible::Enhanced(_) => "enhanced_rtmp",
                Incompatible::CompositionTime { .. } => "composition_time",
                Incompatible::Rewrite(_) => "sps_rewrite",
                Incompatible::Sps(_) => "sps",
                Incompatible::Pps(_) => "pps",
                Incompatible::Slice(_) => "slice",
            },
        }
    }
}

pub(crate) fn framing(f: Framing) -> AdmissionError {
    AdmissionError::Framing(f)
}

pub(crate) fn incompatible(i: Incompatible) -> AdmissionError {
    AdmissionError::Incompatible(i)
}
```

`violations.rs`:

```rust
//! §6.9 framing-violation accounting: a violation is transient (FLV
//! reconnect) unless it is the third within 60 s, which is fatal
//! `stream_corrupt`. Sans-IO: the caller passes `now`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use core::time::Duration;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationVerdict {
    /// Reconnect the FLV.
    Transient,
    /// Disconnect with `stream_corrupt`.
    Fatal,
}

/// Sliding-window counter of framing violations.
#[derive(Debug, Clone)]
pub struct ViolationWindow {
    threshold: usize,
    window: Duration,
    recent: VecDeque<Instant>,
}

impl ViolationWindow {
    /// `threshold` violations within `window` are fatal (`threshold` ≥ 1).
    #[must_use]
    pub fn new(threshold: usize, window: Duration) -> Self {
        let threshold = threshold.max(1);
        ViolationWindow {
            threshold,
            window,
            recent: VecDeque::with_capacity(threshold),
        }
    }

    /// §6.9's rule: three within 60 s.
    #[must_use]
    pub fn stream_corrupt() -> Self {
        Self::new(3, Duration::from_secs(60))
    }

    /// Record one violation at `now`.
    pub fn record(&mut self, now: Instant) -> ViolationVerdict {
        while let Some(&oldest) = self.recent.front() {
            if now.saturating_duration_since(oldest) >= self.window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= self.threshold {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        if self.recent.len() >= self.threshold {
            ViolationVerdict::Fatal
        } else {
            ViolationVerdict::Transient
        }
    }
}
```

`params.rs`:

```rust
//! The parameter-set state of one KVM session (§6.1): the active rewritten
//! SPS, the admitted PPSs, the pins, and the class of each change the pump
//! must hear about as `SpsChanged`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::pps::check_pps;
use crate::h264::rewrite::{RewriteConfig, RewriteFields, RewrittenSps, rewrite_sps};
use crate::h264::{
    SpsChange, SpsIncompatibleReason, SpsLimits, SpsPins, SpsSummary, check_sps_limits,
    classify_sps_change,
};
use crate::video::error::{AdmissionError, Framing, Incompatible, framing, incompatible};
use bytes::Bytes;
use h264_reader::Context;
use h264_reader::nal::sps::SeqParameterSet;

/// §6.1's classes for the pump (`SpsChanged{class}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamClass {
    /// The first parameter sets after an FLV open (no comparison).
    Initial,
    /// Dimensions or level changed.
    Resize,
    /// Anything else changed, including a PPS alone.
    Other,
}

/// The parameter sets the pump caches and sends before every IDR (§6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSets {
    /// The rewritten SPS NAL.
    pub sps: Bytes,
    /// Every admitted PPS NAL, by ascending `pic_parameter_set_id`.
    pub pps: Vec<Bytes>,
    pub summary: SpsSummary,
}

/// `SpsChanged`: the class, the new sets, and which rewrites applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamsChange {
    pub class: ParamClass,
    pub params: ParamSets,
    pub rewrites: RewriteFields,
}

/// The sets as they were before a tag, to tell whether it changed them.
pub(crate) type Snapshot = (Option<Bytes>, Vec<Bytes>);

pub(crate) struct ParamState {
    limits: SpsLimits,
    rewrite: RewriteConfig,
    max_pps: usize,
    pins: Option<SpsPins>,
    sps: Option<(Bytes, RewrittenSps)>,
    /// `(pic_parameter_set_id, trimmed NAL)`, ascending by id.
    pps: Vec<(u8, Bytes)>,
    /// h264-reader context holding exactly the active SPS and the PPSs.
    ctx: Context,
    initial_pending: bool,
}

impl ParamState {
    pub(crate) fn new(limits: SpsLimits, rewrite: RewriteConfig, max_pps: usize) -> Self {
        ParamState {
            limits,
            rewrite,
            max_pps,
            pins: None,
            sps: None,
            pps: Vec::new(),
            ctx: Context::new(),
            initial_pending: true,
        }
    }

    /// A new FLV connection: its first sets are `Initial`. Pins persist.
    pub(crate) fn flv_opened(&mut self) {
        self.initial_pending = true;
    }

    pub(crate) fn ctx(&self) -> &Context {
        &self.ctx
    }

    pub(crate) fn active_sps(&self) -> Option<&SeqParameterSet> {
        self.sps.as_ref().map(|(_, r)| &r.parsed)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        (
            self.sps.as_ref().map(|(b, _)| b.clone()),
            self.pps.iter().map(|(_, b)| b.clone()).collect(),
        )
    }

    /// A sequence header replaces every PPS: they leave the cache and the
    /// h264-reader context, which keeps only the active SPS (so a slice can
    /// never parse against a PPS the reported sets no longer list).
    pub(crate) fn clear_pps(&mut self) {
        self.pps.clear();
        let mut ctx = Context::new();
        if let Some((_, r)) = &self.sps {
            ctx.put_seq_param_set(r.parsed.clone());
        }
        self.ctx = ctx;
    }

    /// Rewrite, check and adopt one SPS (§6.8 then §6.1); returns its class
    /// for this tag, `None` when it is byte-identical to the active one.
    pub(crate) fn take_sps(&mut self, nal: &[u8]) -> Result<Option<ParamClass>, AdmissionError> {
        let r =
            rewrite_sps(nal, &self.rewrite).map_err(|e| incompatible(Incompatible::Rewrite(e)))?;
        check_sps_limits(&r.summary, &self.limits).map_err(|v| {
            incompatible(Incompatible::Sps(SpsIncompatibleReason::OutsideLimits(v)))
        })?;
        match self.pins {
            Some(p) => p.check(&r.summary).map_err(|f| {
                incompatible(Incompatible::Sps(
                    SpsIncompatibleReason::PinnedFieldChanged(f),
                ))
            })?,
            None => self.pins = Some(SpsPins::of(&r.summary)),
        }
        let class = match &self.sps {
            _ if self.initial_pending => Some(ParamClass::Initial),
            None => Some(ParamClass::Initial),
            // D4: a byte-identical repeat (in-band sets with every IDR) is no change.
            Some((old, _)) if old.as_ref() == r.nal.as_slice() => None,
            // Any other change goes through kvm-proto's one §6.1 classifier.
            Some((_, old)) => {
                match classify_sps_change(Some(&old.summary), &r.summary, &self.limits) {
                    SpsChange::Initial => Some(ParamClass::Initial),
                    SpsChange::Resize => Some(ParamClass::Resize),
                    SpsChange::Other => Some(ParamClass::Other),
                    SpsChange::Incompatible(reason) => {
                        return Err(incompatible(Incompatible::Sps(reason)));
                    }
                }
            }
        };
        // The context holds only the active SPS; each cached PPS is checked
        // again against it and dropped if it no longer passes.
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed.clone());
        let mut kept = Vec::with_capacity(self.pps.len());
        for (id, b) in core::mem::take(&mut self.pps) {
            if let Ok(p) = check_pps(&ctx, &b) {
                ctx.put_pic_param_set(p);
                kept.push((id, b));
            }
        }
        self.pps = kept;
        self.ctx = ctx;
        self.sps = Some((Bytes::copy_from_slice(&r.nal), r));
        Ok(class)
    }

    /// Check and adopt one PPS against the active SPS.
    pub(crate) fn take_pps(&mut self, nal: &Bytes) -> Result<(), AdmissionError> {
        let pps = check_pps(&self.ctx, nal).map_err(|e| incompatible(Incompatible::Pps(e)))?;
        let id = pps.pic_parameter_set_id.id();
        match self.pps.binary_search_by_key(&id, |(i, _)| *i) {
            Ok(at) => {
                if let Some(slot) = self.pps.get_mut(at) {
                    slot.1 = nal.clone();
                }
            }
            Err(at) => {
                if self.pps.len() >= self.max_pps {
                    return Err(framing(Framing::TooManyPps));
                }
                self.pps.insert(at, (id, nal.clone()));
            }
        }
        self.ctx.put_pic_param_set(pps);
        Ok(())
    }

    /// The change a tag made, if any: `class` from its SPSs, or `Other` when
    /// only the PPSs differ from `before`.
    pub(crate) fn change(
        &mut self,
        class: Option<ParamClass>,
        before: Snapshot,
    ) -> Option<ParamsChange> {
        let (sps, r) = self.sps.as_ref()?;
        let pps: Vec<Bytes> = self.pps.iter().map(|(_, b)| b.clone()).collect();
        let class = match class {
            Some(c) => c,
            None if before.0.as_ref() != Some(sps) || before.1 != pps => ParamClass::Other,
            None => return None,
        };
        let change = ParamsChange {
            class,
            params: ParamSets {
                sps: sps.clone(),
                pps,
                summary: r.summary.clone(),
            },
            rewrites: r.changed,
        };
        if class == ParamClass::Initial {
            self.initial_pending = false;
        }
        Some(change)
    }
}

/// Initial beats Resize beats Other beats nothing.
pub(crate) fn strongest(a: Option<ParamClass>, b: Option<ParamClass>) -> Option<ParamClass> {
    let rank = |c: Option<ParamClass>| match c {
        None => 0,
        Some(ParamClass::Other) => 1,
        Some(ParamClass::Resize) => 2,
        Some(ParamClass::Initial) => 3,
    };
    if rank(b) > rank(a) { b } else { a }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib video::` — Expected: 10 passed.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/video crates/kvm-proto/src/lib.rs
git commit -m "kvm-proto: §6.9 admission classes, 3-in-60 s window, parameter-set state" \
  -m "One active rewritten SPS, PPSs re-checked on a new SPS, SpsChanged classes incl. PPS-only and silent repeats (D4)." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.6: `VideoAdmission` and the §6.3 access unit

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/mod.rs` (replace)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/video/tests.rs`
- Test: `crates/kvm-proto/src/video/tests.rs`

**Interfaces:**
- Consumes: everything in Tasks 2.2–4.5; `FlvTag`, `TagBody`, `VideoBody`, `AvcConfig`, `Nal`, `BurstMarker` (Plan A); the muxer (Task 3.3) and `PpsCfg`/`SliceCfg`/`SpsCfg` in tests.
- Produces (`kvm_proto::video`) — the API Plan C's KVM actor drives:
  - `pub struct AdmissionConfig { limits: SpsLimits, rewrite: RewriteConfig, burst_threshold: Duration, max_sps: usize, max_pps: usize }` (`Default`: spec values, `RewriteConfig::ES3`, 100 ms, 4, 16) — `max_sps`/`max_pps` also cap each NALU tag's in-band sets (D10: a fifth SPS or seventeenth PPS in one tag is `Framing::Flv(FlvError::ParamSetCount)`, before it is rewritten or parsed)
  - `pub struct VideoAdmission`: `new(cfg: AdmissionConfig) -> Self` (at `Start`), `flv_opened(&mut self)` (every FLV open), `admit(&mut self, tag: FlvTag, now: Instant) -> Result<Admitted, AdmissionError>`
  - `pub struct Admitted { params: Option<ParamsChange>, au: Option<AccessUnit>, end_of_sequence: bool, dropped_nals: usize }` (`Default`) — send `params` as `SpsChanged` before `au`
  - `pub struct AccessUnit { flv_timestamp_ms: u32, idr: bool, burst: bool, aud: Option<Bytes>, vcl: Vec<Nal> }` with `frame_id(&self) -> u64` and `write_annex_b(&self, params: &ParamSets, out: &mut Vec<u8>)` (§6.3; appends; caller clears)
  - No allocation per access unit beyond the demuxer's NAL `Vec`, which the AU reuses (§10.1's budget, measured in Plan E).

- [ ] **Step 1: Write the failing tests.** Create `crates/kvm-proto/src/video/tests.rs`. `each_admission_rule_has_its_own_refusal` is §11.2's "one hostile vector per §6.1/§6.2 rule, each asserting its specific error kind" for the rules admission owns (the framing ones are in Tasks 3.1/3.2, the SPS/PPS ones in 2.4/4.2/4.3/4.5):

```rust
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]
use super::*;
use crate::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use crate::flv::{FlvDemuxer, FlvError, FlvLimits, FrameType};
use crate::h264::picture::SliceRefusal;
use crate::h264::sanitize::NalRefusal;
use crate::h264::test_support::{PpsCfg, SliceCfg, SpsCfg};
use crate::h264::{NalHeader, PinnedField, SpsIncompatibleReason};

/// A Baseline 1080p SPS (POC type 2, `log2_max_frame_num` 4) at level 40.
fn sps() -> Vec<u8> {
    let mut c = SpsCfg::main_1080p();
    c.profile_idc = 66;
    c.level_idc = 40;
    c.build()
}

fn idr() -> Vec<u8> {
    SliceCfg::idr().build()
}

fn p(frame_num: u32) -> Vec<u8> {
    SliceCfg::p(frame_num).build()
}

fn video(body: TagBody) -> FlvTag {
    FlvTag {
        tag_type: 9,
        data_size: 0,
        timestamp: 0,
        body,
    }
}

/// Mux a sequence header (`sps()`, default PPS) then one NALU tag per entry
/// `(composition_time, nals)` 33 ms apart, demux, and admit tag by tag until
/// the first refusal. Every tag is "received" at the same instant.
fn run(tags: &[(i32, Vec<Vec<u8>>)]) -> Vec<Result<Admitted, AdmissionError>> {
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let (s, pps) = (sps(), PpsCfg::default().build());
    write_tag(
        &mut flv,
        TAG_VIDEO,
        0,
        &avc_sequence_header_body(&[&s], &[&pps], 4).unwrap(),
    )
    .unwrap();
    for (i, (ct, nals)) in tags.iter().enumerate() {
        let nals: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
        let mut b = Vec::new();
        avc_nalu_body(&mut b, false, *ct, &nals, 4).unwrap();
        write_tag(&mut flv, TAG_VIDEO, (i as u32 + 1) * 33, &b).unwrap();
    }
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let t0 = Instant::now();
    let mut out = Vec::new();
    while let Some(t) = d.next_tag().unwrap() {
        let r = a.admit(t, t0);
        let stop = r.is_err();
        out.push(r);
        if stop {
            break;
        }
    }
    out
}

fn last(r: &[Result<Admitted, AdmissionError>]) -> &Result<Admitted, AdmissionError> {
    r.last().unwrap()
}

#[test]
fn a_clean_stream_admits_with_its_parameter_sets_first() {
    let r = run(&[(16, vec![idr()]), (16, vec![p(1)]), (16, vec![p(2)])]);
    assert!(r.iter().all(Result::is_ok), "{r:?}");
    let first = r[0].as_ref().unwrap();
    assert_eq!(first.params.as_ref().unwrap().class, ParamClass::Initial);
    assert!(first.au.is_none());
    let aus: Vec<bool> = r[1..]
        .iter()
        .map(|a| a.as_ref().unwrap().au.as_ref().unwrap().idr)
        .collect();
    assert_eq!(aus, [true, false, false]);
}

#[test]
fn constant_composition_time_16_is_admitted_and_a_change_refused() {
    assert!(
        run(&[(16, vec![idr()]), (16, vec![p(1)])])
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(
        last(&run(&[(16, vec![idr()]), (17, vec![p(1)])])),
        &Err(incompatible(Incompatible::CompositionTime {
            first: 16,
            now: 17
        }))
    );
}

/// One hostile vector per §6.1/§6.2 rule, each with its own error kind.
#[test]
fn each_admission_rule_has_its_own_refusal() {
    let mut b = SliceCfg::p(1);
    b.slice_type = 6;
    b.header_byte = 0x01;
    let mut cont = SliceCfg::p(1);
    cont.first_mb = 5;
    let mut far = SliceCfg::p(1);
    far.first_mb = 120 * 68;
    let mut other_pps = SliceCfg::p(1);
    other_pps.pps_id = 3;
    let (mut nonref1, mut nonref2) = (SliceCfg::p(1), SliceCfg::p(1));
    nonref1.header_byte = 0x01;
    nonref2.header_byte = 0x01;
    let mut start_code = p(1);
    start_code.splice(2..2, [0, 0, 1]);
    let mut forbidden = p(1);
    forbidden[0] |= 0x80;
    let pps = PpsCfg::default().build();
    let mut sps_flood = vec![sps(); 5];
    sps_flood.push(idr());
    let mut pps_flood = vec![pps; 17];
    pps_flood.push(idr());
    let aud = vec![0x09, 0xF0];
    type Case = (&'static str, Vec<(i32, Vec<Vec<u8>>)>, AdmissionError);
    let cases: Vec<Case> = vec![
        (
            "B slice",
            vec![(16, vec![idr()]), (16, vec![b.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(6))),
        ),
        (
            "first_mb out of range",
            vec![(16, vec![idr()]), (16, vec![far.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::FirstMb {
                first_mb: 8160,
                pic_size_in_mbs: 8160,
            })),
        ),
        (
            "two pictures in one tag",
            vec![(16, vec![idr(), p(1)])],
            framing(Framing::NotOnePicture),
        ),
        (
            "first slice not at MB 0",
            vec![(16, vec![idr()]), (16, vec![cont.build()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "no slice at all",
            vec![(16, vec![aud.clone()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "second AUD",
            vec![(16, vec![aud.clone(), aud.clone(), idr()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "AUD after a slice",
            vec![(16, vec![idr(), aud.clone()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "start code inside a NAL",
            vec![(16, vec![idr()]), (16, vec![start_code])],
            framing(Framing::Nal(NalRefusal::StartCode)),
        ),
        (
            "forbidden bit",
            vec![(16, vec![idr()]), (16, vec![forbidden])],
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
        ),
        (
            "all-zero NAL",
            vec![(16, vec![idr()]), (16, vec![vec![0, 0]])],
            framing(Framing::Nal(NalRefusal::Empty)),
        ),
        (
            "unknown PPS id",
            vec![(16, vec![idr()]), (16, vec![other_pps.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::Unparsable(
                "UndefinedPicParamSetId(PicParamSetId(3))".into(),
            ))),
        ),
        (
            "POC not increasing",
            vec![
                (16, vec![idr()]),
                (16, vec![nonref1.build()]),
                (16, vec![nonref2.build()]),
            ],
            incompatible(Incompatible::Slice(SliceRefusal::PocNotIncreasing {
                previous: 1,
                current: 1,
            })),
        ),
        (
            "five in-band SPSs in one tag",
            vec![(16, sps_flood)],
            AdmissionError::from(FlvError::ParamSetCount),
        ),
        (
            "seventeen in-band PPSs in one tag",
            vec![(16, pps_flood)],
            AdmissionError::from(FlvError::ParamSetCount),
        ),
    ];
    for (name, tags, want) in cases {
        assert_eq!(last(&run(&tags)), &Err(want), "{name}");
    }
}

#[test]
fn tag_level_classes() {
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let now = Instant::now();
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 8,
                data_size: 1,
                timestamp: 0,
                body: TagBody::Audio
            },
            now
        ),
        Ok(Admitted::default())
    );
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 18,
                data_size: 1,
                timestamp: 0,
                body: TagBody::ScriptData
            },
            now
        ),
        Ok(Admitted::default())
    );
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 3,
                data_size: 1,
                timestamp: 0,
                body: TagBody::Other(3)
            },
            now
        ),
        Err(framing(Framing::UnknownTagType(3)))
    );
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::NonAvc {
                codec_id: 12,
                frame_type: FrameType::Key
            })),
            now
        ),
        Err(incompatible(Incompatible::Codec(12)))
    );
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::Enhanced {
                packet_type: 1,
                frame_type: FrameType::Key,
                fourcc: *b"hvc1"
            })),
            now
        ),
        Err(incompatible(Incompatible::Enhanced(*b"hvc1")))
    );
    assert!(
        a.admit(video(TagBody::Video(VideoBody::EndOfSequence)), now)
            .unwrap()
            .end_of_sequence
    );
}

#[test]
fn config_record_entries_must_be_what_they_claim() {
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let pps = Bytes::from(PpsCfg::default().build());
    let cfg = AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![pps.clone()],
        pps: vec![pps],
    };
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::SequenceHeader(cfg))),
            Instant::now()
        ),
        Err(framing(Framing::ConfigNalType(8)))
    );
}

#[test]
fn in_band_parameter_sets_are_classified_and_removed_from_the_au() {
    let mut big = SpsCfg::main_1080p();
    big.profile_idc = 66;
    big.level_idc = 40;
    big.pic_width_in_mbs_minus1 = 79; // 1280 wide
    big.pic_height_in_map_units_minus1 = 44; // 720 high
    big.crop = None;
    let pps = PpsCfg::default().build();
    let sei = vec![0x06, 0x05, 0x01, 0xAA, 0x80];
    let r = run(&[
        (16, vec![sps(), pps.clone(), idr()]), // identical in-band sets: no event
        (16, vec![sei, p(1)]),                 // SEI dropped and counted
        (16, vec![big.build(), pps, idr()]),   // a new size in-band: Resize, then the IDR
    ]);
    let r: Vec<Admitted> = r.into_iter().map(Result::unwrap).collect();
    assert_eq!(r[1].params, None);
    assert_eq!(
        r[1].au.as_ref().unwrap().vcl.len(),
        1,
        "SPS/PPS never reach the AU"
    );
    assert_eq!(r[2].dropped_nals, 1);
    let resize = r[3].params.as_ref().unwrap();
    assert_eq!(resize.class, ParamClass::Resize);
    assert_eq!(
        (resize.params.summary.width, resize.params.summary.height),
        (1280, 720)
    );
    assert!(r[3].au.as_ref().unwrap().idr);
}

#[test]
fn annex_b_output_matches_section_6_3_and_frame_id_hashes_the_vcl() {
    let aud = vec![0x09, 0xF0];
    let r = run(&[
        (16, vec![aud.clone(), idr()]),
        (16, vec![aud.clone(), p(1)]),
    ]);
    let r: Vec<Admitted> = r.into_iter().map(Result::unwrap).collect();
    let params = r[0].params.as_ref().unwrap().params.clone();
    let (idr_au, p_au) = (r[1].au.as_ref().unwrap(), r[2].au.as_ref().unwrap());
    let mut out = Vec::new();
    idr_au.write_annex_b(&params, &mut out);
    let mut want = Vec::new();
    for nal in [&aud[..], &params.sps, &params.pps[0], &idr()] {
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(nal);
    }
    assert_eq!(out, want);
    out.clear();
    p_au.write_annex_b(&params, &mut out);
    let mut want = vec![0, 0, 0, 1];
    want.extend_from_slice(&aud);
    want.extend_from_slice(&[0, 0, 0, 1]);
    want.extend_from_slice(&p(1));
    assert_eq!(out, want, "no parameter sets before a P frame");
    assert_eq!(p_au.frame_id(), crate::h264::frame_id([p(1).as_slice()]));
    assert_eq!(NalHeader::from_nal(&params.sps).unwrap().nal_unit_type, 7);
}

#[test]
fn bursts_are_marked_against_real_time() {
    // All tags "arrive" at t0 while their timestamps run 33 ms apart: the
    // fifth AU is 132 ms ahead of the first, past §6.2's 100 ms: a burst.
    let r = run(&[
        (16, vec![idr()]),
        (16, vec![p(1)]),
        (16, vec![p(2)]),
        (16, vec![p(3)]),
        (16, vec![p(4)]),
    ]);
    let bursts: Vec<bool> = r[1..]
        .iter()
        .map(|a| a.as_ref().unwrap().au.as_ref().unwrap().burst)
        .collect();
    assert_eq!(bursts, [false, false, false, false, true]);
}

/// A sequence-header tag carrying `sps` and the default PPS.
fn seq_tag(sps: Vec<u8>) -> FlvTag {
    video(TagBody::Video(VideoBody::SequenceHeader(AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![Bytes::from(sps)],
        pps: vec![Bytes::from(PpsCfg::default().build())],
    })))
}

/// A coded tag: FLV timestamp `ts`, `CompositionTime` `ct`, one NAL.
fn coded_tag(ts: u32, ct: i32, nal: Vec<u8>) -> FlvTag {
    FlvTag {
        tag_type: 9,
        data_size: 0,
        timestamp: ts,
        body: TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            composition_time: ct,
            nals: vec![Nal {
                bytes: Bytes::from(nal),
            }],
        }),
    }
}

#[test]
fn an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins() {
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(seq_tag(sps()), now).unwrap();
    for (ts, nal) in [(0, idr()), (33, p(1)), (66, p(2)), (99, p(3))] {
        let au = a.admit(coded_tag(ts, 16, nal), now).unwrap().au.unwrap();
        assert!(!au.burst);
    }
    a.flv_opened();
    // The same SPS is `Initial` again on the new connection.
    let again = a.admit(seq_tag(sps()), now).unwrap();
    assert_eq!(again.params.unwrap().class, ParamClass::Initial);
    // Its first coded tag sets a new CompositionTime (0, not 16), restarts
    // POC order (p(3) again is POC 6, which the old connection reached), and
    // is the new burst baseline although it is 5 s ahead of the old one.
    let au = a.admit(coded_tag(5_000, 0, p(3)), now).unwrap().au.unwrap();
    assert!(!au.burst);
    let au = a.admit(coded_tag(5_200, 0, p(4)), now).unwrap().au.unwrap();
    assert!(au.burst, "200 ms ahead of the new baseline");
    // The pins persist across the reconnect: a Main SPS is fatal …
    a.flv_opened();
    assert_eq!(
        a.admit(seq_tag(SpsCfg::main_1080p().build()), now),
        Err(incompatible(Incompatible::Sps(
            SpsIncompatibleReason::PinnedFieldChanged(PinnedField::ProfileIdc)
        )))
    );
    // … and only a new session (`Start`) resets them.
    let mut fresh = VideoAdmission::new(AdmissionConfig::default());
    fresh.flv_opened();
    let first = fresh.admit(seq_tag(SpsCfg::main_1080p().build()), now);
    assert_eq!(first.unwrap().params.unwrap().class, ParamClass::Initial);
}

#[test]
fn an_identical_sequence_header_mid_connection_raises_nothing() {
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    assert!(a.admit(seq_tag(sps()), now).unwrap().params.is_some());
    a.admit(coded_tag(0, 16, idr()), now).unwrap();
    assert_eq!(a.admit(seq_tag(sps()), now).unwrap().params, None);
    assert!(a.admit(coded_tag(33, 16, p(1)), now).unwrap().au.is_some());
}

#[test]
fn a_sequence_header_without_parameter_sets_leaves_no_stale_pps() {
    // The demuxer refuses an empty config record (`ParamSetCount`), but
    // `admit` is public: a hand-built one must drop every PPS from the
    // parse context too, not only from the sets it reports.
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(seq_tag(sps()), now).unwrap();
    a.admit(coded_tag(0, 16, idr()), now).unwrap();
    let empty = video(TagBody::Video(VideoBody::SequenceHeader(AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![],
        pps: vec![],
    })));
    let change = a.admit(empty, now).unwrap().params.unwrap();
    assert!(change.params.pps.is_empty());
    assert_eq!(
        a.admit(coded_tag(33, 16, p(1)), now),
        Err(incompatible(Incompatible::Slice(SliceRefusal::Unparsable(
            "UndefinedPicParamSetId(PicParamSetId(0))".into()
        ))))
    );
}

#[test]
fn in_band_parameter_sets_up_to_the_section_6_2_cap_are_admitted() {
    let mut nals = vec![sps(); 4];
    nals.extend(std::iter::repeat_n(PpsCfg::default().build(), 16));
    nals.push(idr());
    let r = run(&[(16, nals)]);
    let a = r[1].as_ref().unwrap();
    assert_eq!(a.params, None, "identical sets raise nothing");
    assert!(a.au.as_ref().unwrap().idr);
}

/// `census.md` `sps_hex` and `pps_hex`, trailing zero bytes included.
const CENSUS_SPS: [u8; 17] = [
    0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14, 0x08,
    0x00,
];
const CENSUS_PPS: [u8; 6] = [0x68, 0xce, 0x31, 0x12, 0x00, 0x00];

#[test]
fn the_es3s_own_parameter_sets_admit_through_mux_and_demux() {
    // An IDR for the census SPS: log2_max_frame_num 8, POC type 0, 8-bit lsb.
    let idr = SliceCfg {
        log2_max_frame_num: 8,
        poc_lsb: Some((0, 8)),
        ..SliceCfg::idr()
    }
    .build();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let seq = avc_sequence_header_body(&[&CENSUS_SPS], &[&CENSUS_PPS], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    let mut body = Vec::new();
    avc_nalu_body(&mut body, true, 16, &[&idr], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &body).unwrap();
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let now = Instant::now();
    let change = a
        .admit(d.next_tag().unwrap().unwrap(), now)
        .unwrap()
        .params
        .unwrap();
    assert_eq!(change.class, ParamClass::Initial);
    let hex: String = change
        .params
        .sps
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, "67420028965403c0112f2cd40404041b41008540");
    assert_eq!(change.params.pps, [Bytes::from_static(&CENSUS_PPS[..4])]);
    let au = a
        .admit(d.next_tag().unwrap().unwrap(), now)
        .unwrap()
        .au
        .unwrap();
    assert!(au.idr);
    let mut out = Vec::new();
    au.write_annex_b(&change.params, &mut out);
    let nals: Vec<&[u8]> = crate::h264::split_annex_b(&out).collect();
    assert_eq!(nals, [&change.params.sps[..], &CENSUS_PPS[..4], &idr[..]]);
}
```

and append to `crates/kvm-proto/src/video/mod.rs`:

```rust
#[cfg(test)]
mod tests;
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib video::tests`
Expected: FAIL to compile — `cannot find type VideoAdmission`, `AdmissionConfig`, `Admitted`, `AccessUnit`.

- [ ] **Step 3: Implement.** Replace everything in `crates/kvm-proto/src/video/mod.rs` above `#[cfg(test)] mod tests;` with (this removes Task 4.5's `allow(dead_code)`):

```rust
//! KVM-side video admission (§6.1, §6.2, §6.8): every demuxed FLV tag goes
//! through `VideoAdmission::admit`, which applies the NAL sanitiser, the SPS
//! rewriter, the SPS/PPS/slice checks and the one-picture rule, and returns
//! what the pump may see: a parameter-set change and/or one access unit.
//! Sans-IO: the caller passes the receive time. Nothing here allocates per
//! access unit — the AU reuses the demuxer's NAL `Vec`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod error;
mod params;
mod violations;
pub use error::{AdmissionError, Framing, Incompatible};
pub use params::{ParamClass, ParamSets, ParamsChange};
pub use violations::{ViolationVerdict, ViolationWindow};

use crate::flv::{AvcConfig, BurstMarker, FlvError, FlvTag, Nal, TagBody, VideoBody};
use crate::h264::picture::{PocTracker, SliceInfo, parse_slice};
use crate::h264::rewrite::RewriteConfig;
use crate::h264::sanitize::{NalVerdict, check_nal};
use crate::h264::{SpsLimits, frame_id};
use bytes::Bytes;
use core::time::Duration;
use error::{framing, incompatible};
use params::{ParamState, strongest};
use std::time::Instant;

/// One admitted access unit: exactly one picture (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    pub flv_timestamp_ms: u32,
    pub idr: bool,
    /// Ran more than `burst_threshold` ahead of real time on this FLV (§6.2).
    pub burst: bool,
    /// The AUD, when the source sent one.
    pub aud: Option<Bytes>,
    /// The allowlisted VCL NALs (types 1 and 5), trimmed, in order.
    pub vcl: Vec<Nal>,
}

impl AccessUnit {
    /// §10.2 FrameId of this AU.
    #[must_use]
    pub fn frame_id(&self) -> u64 {
        frame_id(self.vcl.iter().map(|n| n.bytes.as_ref()))
    }

    /// Append this AU in §6.3's output form — 4-byte start codes; [AUD] +
    /// SPS and every PPS (IDR only) + the VCL NALs — to `out`, which the
    /// caller clears and reuses.
    pub fn write_annex_b(&self, params: &ParamSets, out: &mut Vec<u8>) {
        const SC: [u8; 4] = [0, 0, 0, 1];
        if let Some(aud) = &self.aud {
            out.extend_from_slice(&SC);
            out.extend_from_slice(aud);
        }
        if self.idr {
            out.extend_from_slice(&SC);
            out.extend_from_slice(&params.sps);
            for p in &params.pps {
                out.extend_from_slice(&SC);
                out.extend_from_slice(p);
            }
        }
        for n in &self.vcl {
            out.extend_from_slice(&SC);
            out.extend_from_slice(&n.bytes);
        }
    }
}

/// What one tag produced. When both are set the caller sends `params` (as
/// `SpsChanged`) before `au`, on the one ordered stream (§4.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admitted {
    pub params: Option<ParamsChange>,
    pub au: Option<AccessUnit>,
    /// `AVCPacketType 2`: reconnect the FLV (transient, §6.9).
    pub end_of_sequence: bool,
    /// NALs dropped by the allowlist (SEI, filler, …).
    pub dropped_nals: usize,
}

/// The `video.*` settings admission needs (§4.4).
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    pub limits: SpsLimits,
    pub rewrite: RewriteConfig,
    /// §6.2 burst threshold: 100 ms.
    pub burst_threshold: Duration,
    /// §6.2 SPS limit: 4 in-band SPSs per tag (D10).
    pub max_sps: usize,
    /// §6.2 PPS limit: 16 PPS ids at once, and 16 in-band PPSs per tag (D10).
    pub max_pps: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        AdmissionConfig {
            limits: SpsLimits::default(),
            rewrite: RewriteConfig::ES3,
            burst_threshold: Duration::from_millis(100),
            max_sps: 4,
            max_pps: 16,
        }
    }
}

/// Per-KVM-session admission (§6.1): created at `Start`, told about every
/// FLV open with [`VideoAdmission::flv_opened`].
pub struct VideoAdmission {
    params: ParamState,
    composition_time: Option<i32>,
    poc: PocTracker,
    burst: BurstMarker,
    max_sps: usize,
    max_pps: usize,
}

impl VideoAdmission {
    #[must_use]
    pub fn new(cfg: AdmissionConfig) -> Self {
        VideoAdmission {
            params: ParamState::new(cfg.limits, cfg.rewrite, cfg.max_pps),
            composition_time: None,
            poc: PocTracker::default(),
            burst: BurstMarker::new(cfg.burst_threshold),
            max_sps: cfg.max_sps,
            max_pps: cfg.max_pps,
        }
    }

    /// A new FLV connection (any origin) delivers the tags from now on: its
    /// first parameter sets are `Initial`, its first coded tag sets the
    /// `CompositionTime`, and burst marking and POC order start afresh. The
    /// pins persist (§6.1).
    pub fn flv_opened(&mut self) {
        self.params.flv_opened();
        self.composition_time = None;
        self.poc.reset();
        self.burst.reset();
    }

    /// Admit one demuxed tag received at `now`.
    pub fn admit(&mut self, tag: FlvTag, now: Instant) -> Result<Admitted, AdmissionError> {
        match tag.body {
            TagBody::Audio | TagBody::ScriptData => Ok(Admitted::default()),
            TagBody::Other(t) => Err(framing(Framing::UnknownTagType(t))),
            TagBody::Video(VideoBody::NonAvc { codec_id, .. }) => {
                Err(incompatible(Incompatible::Codec(codec_id)))
            }
            TagBody::Video(VideoBody::Enhanced { fourcc, .. }) => {
                Err(incompatible(Incompatible::Enhanced(fourcc)))
            }
            TagBody::Video(VideoBody::EndOfSequence) => Ok(Admitted {
                end_of_sequence: true,
                ..Admitted::default()
            }),
            TagBody::Video(VideoBody::SequenceHeader(cfg)) => self.sequence_header(&cfg),
            TagBody::Video(VideoBody::Nalus {
                composition_time,
                nals,
                ..
            }) => self.coded(tag.timestamp, composition_time, nals, now),
        }
    }

    fn sequence_header(&mut self, cfg: &AvcConfig) -> Result<Admitted, AdmissionError> {
        let mut sps = Vec::with_capacity(cfg.sps.len());
        for nal in &cfg.sps {
            sps.push(config_nal(nal, 7)?);
        }
        let mut pps = Vec::with_capacity(cfg.pps.len());
        for nal in &cfg.pps {
            pps.push(config_nal(nal, 8)?);
        }
        let before = self.params.snapshot();
        self.params.clear_pps();
        let mut class = None;
        for nal in &sps {
            class = strongest(class, self.params.take_sps(nal)?);
        }
        for nal in &pps {
            self.params.take_pps(nal)?;
        }
        Ok(Admitted {
            params: self.params.change(class, before),
            ..Admitted::default()
        })
    }

    fn coded(
        &mut self,
        timestamp: u32,
        composition_time: i32,
        mut nals: Vec<Nal>,
        now: Instant,
    ) -> Result<Admitted, AdmissionError> {
        match self.composition_time {
            None => self.composition_time = Some(composition_time),
            Some(first) if first != composition_time => {
                return Err(incompatible(Incompatible::CompositionTime {
                    first,
                    now: composition_time,
                }));
            }
            Some(_) => {}
        }
        let mut before = None;
        let mut class = None;
        let mut aud = None;
        let mut dropped = 0_usize;
        let mut seen_vcl = false;
        let (mut sps_seen, mut pps_seen) = (0_usize, 0_usize);
        for n in &mut nals {
            let kept = match check_nal(&n.bytes).map_err(|e| framing(Framing::Nal(e)))? {
                NalVerdict::Drop(_) => {
                    dropped = dropped.saturating_add(1);
                    None
                }
                NalVerdict::Keep(h, bytes) => match h.nal_unit_type {
                    7 | 8 => {
                        // §6.2: 4 SPS and 16 PPS per tag (D10), checked before
                        // each costs a rewrite or a parse.
                        let seen = if h.nal_unit_type == 7 {
                            &mut sps_seen
                        } else {
                            &mut pps_seen
                        };
                        *seen = seen.saturating_add(1);
                        if sps_seen > self.max_sps || pps_seen > self.max_pps {
                            return Err(AdmissionError::from(FlvError::ParamSetCount));
                        }
                        if before.is_none() {
                            before = Some(self.params.snapshot());
                        }
                        if h.nal_unit_type == 7 {
                            class = strongest(class, self.params.take_sps(&bytes)?);
                        } else {
                            self.params.take_pps(&bytes)?;
                        }
                        None
                    }
                    9 => {
                        if seen_vcl || aud.is_some() {
                            return Err(framing(Framing::NotOnePicture));
                        }
                        aud = Some(bytes);
                        None
                    }
                    _ => {
                        seen_vcl = true;
                        Some(bytes)
                    }
                },
            };
            n.bytes = kept.unwrap_or_default();
        }
        nals.retain(|n| !n.bytes.is_empty());
        let params = match before {
            Some(b) => self.params.change(class, b),
            None => None,
        };
        let first = self.check_picture(&nals)?;
        let sps = self
            .params
            .active_sps()
            .ok_or(framing(Framing::NotOnePicture))?;
        self.poc
            .next(sps, &first)
            .map_err(|e| incompatible(Incompatible::Slice(e)))?;
        Ok(Admitted {
            params,
            au: Some(AccessUnit {
                flv_timestamp_ms: timestamp,
                idr: first.idr,
                burst: self.burst.mark(timestamp, now),
                aud,
                vcl: nals,
            }),
            end_of_sequence: false,
            dropped_nals: dropped,
        })
    }

    /// §6.1's slice checks and §6.2's one-picture rule; returns the first
    /// slice's fields.
    fn check_picture(&self, vcl: &[Nal]) -> Result<SliceInfo, AdmissionError> {
        let mut first: Option<SliceInfo> = None;
        for n in vcl {
            let s = parse_slice(self.params.ctx(), &n.bytes)
                .map_err(|e| incompatible(Incompatible::Slice(e)))?;
            match &first {
                None if s.first_mb_in_slice == 0 => first = Some(s),
                Some(f) if s.first_mb_in_slice != 0 && f.same_picture(&s) => {}
                _ => return Err(framing(Framing::NotOnePicture)),
            }
        }
        first.ok_or(framing(Framing::NotOnePicture))
    }
}

/// A config-record entry: §6.2's per-NAL checks, and its own header must say
/// `want` (7 for the SPS list, 8 for the PPS list).
fn config_nal(nal: &Bytes, want: u8) -> Result<Bytes, AdmissionError> {
    match check_nal(nal) {
        Ok(NalVerdict::Keep(h, b)) if h.nal_unit_type == want => Ok(b),
        Ok(NalVerdict::Keep(h, _) | NalVerdict::Drop(h)) => {
            Err(framing(Framing::ConfigNalType(h.nal_unit_type)))
        }
        Err(e) => Err(framing(Framing::Nal(e))),
    }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib video::` — Expected: 23 passed.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/video/mod.rs crates/kvm-proto/src/video/tests.rs
git commit -m "kvm-proto: VideoAdmission — §6.1/§6.2 per tag, one picture, POC order, §6.3 output" \
  -m "BurstMarker wired into the demux path (Plan A 2.8); one hostile vector per rule." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 5 — HID frames

### Task 5.1: The §3.3 HID frame codec

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/hid.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (`pub mod hid;`)
- Test: `crates/kvm-proto/src/hid.rs` (`tests`)

**Interfaces:**
- Consumes: nothing.
- Produces (`kvm_proto::hid`): `pub const ABS_MAX: u16 = 32_767`; `pub enum Wheel { Up, Down }`; `pub enum HidFrame { SetMode { hid_type: u8 }, Keyboard { modifiers: u8, keys: [u8; 5] }, AbsMouse { buttons: u8, x: u16, y: u16 }, Wheel { buttons: u8, wheel: Wheel } }` (`Copy`, `Eq`) with `abs_mouse(buttons, x, y) -> HidFrame` (clamps to `ABS_MAX`), `encode(&self, out: &mut Vec<u8>)`, `to_vec(&self) -> Vec<u8>`, `decode(msg: &[u8]) -> Result<HidFrame, HidDecodeError>`; `pub enum HidDecodeError { Unknown, BadLength, CoordinateOutOfRange }`. The encoders are what Plans C/D's HID writer sends (scancode tables, mouse scaling and the Typist stay in Plan D); the decoder is how kvm-sim's websocket tests (Task 8.6) and Plans C–E's L2 tests read what the bridge sent.

- [ ] **Step 1: Write the failing tests.** Add `pub mod hid;` to `crates/kvm-proto/src/lib.rs` (after `pub mod h264;`) and create `crates/kvm-proto/src/hid.rs` with the test module. The goldens come from §3.3's byte layouts (`kvm.js` behaviour, §11.1), not from the encoder:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Goldens from §3.3's byte layouts (independent of the encoder).
    #[test]
    fn encoders_match_section_3_3() {
        assert_eq!(
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            [0x88, 0x88, 0x01, 0x30]
        );
        // Shift + 'a' (usage 0x04) in slot 1.
        assert_eq!(
            HidFrame::Keyboard {
                modifiers: 0x02,
                keys: [0x04, 0, 0, 0, 0]
            }
            .to_vec(),
            [
                0xAA, 0xAA, 0x08, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Left button at (16384, 8192): little-endian coordinates.
        assert_eq!(
            HidFrame::abs_mouse(0x01, 16_384, 8_192).to_vec(),
            [0xAA, 0xAA, 0x05, 0x51, 0x01, 0x00, 0x40, 0x00, 0x20]
        );
        assert_eq!(
            HidFrame::abs_mouse(0, 32_767, 0).to_vec(),
            [0xAA, 0xAA, 0x05, 0x51, 0x00, 0xFF, 0x7F, 0x00, 0x00]
        );
        assert_eq!(
            HidFrame::Wheel {
                buttons: 0x01,
                wheel: Wheel::Up
            }
            .to_vec(),
            [0xAA, 0xAA, 0x04, 0x20, 0x01, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            HidFrame::Wheel {
                buttons: 0,
                wheel: Wheel::Down
            }
            .to_vec(),
            [0xAA, 0xAA, 0x04, 0x20, 0x00, 0x00, 0x00, 0xFF]
        );
    }

    #[test]
    fn coordinates_clamp_to_32767() {
        assert_eq!(
            HidFrame::abs_mouse(0, u16::MAX, 40_000),
            HidFrame::AbsMouse {
                buttons: 0,
                x: 32_767,
                y: 32_767
            }
        );
    }

    #[test]
    fn decode_inverts_encode_and_refuses_the_rest() {
        let frames = [
            HidFrame::SetMode { hid_type: 0 },
            HidFrame::Keyboard {
                modifiers: 0x08,
                keys: [0x06, 0x19, 0, 0, 0],
            },
            HidFrame::abs_mouse(0x07, 123, 32_767),
            HidFrame::Wheel {
                buttons: 0,
                wheel: Wheel::Down,
            },
        ];
        for f in frames {
            assert_eq!(HidFrame::decode(&f.to_vec()), Ok(f));
        }
        assert_eq!(
            HidFrame::decode(&[0xAA, 0xAA, 0x08]),
            Err(HidDecodeError::BadLength)
        );
        assert_eq!(
            HidFrame::decode(&[0xAA, 0xAA, 0x05, 0x51, 0, 0x00, 0x80, 0, 0]),
            Err(HidDecodeError::CoordinateOutOfRange)
        );
        assert_eq!(
            HidFrame::decode(&[0x88, 0x88, 0x03, b'h']),
            Err(HidDecodeError::Unknown)
        );
        assert_eq!(HidFrame::decode(&[]), Err(HidDecodeError::Unknown));
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib hid::`
Expected: FAIL to compile — `cannot find type HidFrame`.

- [ ] **Step 3: Implement.** Put this above the test module:

```rust
//! The ES3's websocket HID frames (§3.3), byte-exact with the vendor's
//! `kvm.js`: the encoders the bridge sends with, and the decoder kvm-sim
//! records with.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Largest absolute coordinate (§3.3: x, y in 0..=32767).
pub const ABS_MAX: u16 = 32_767;

/// Wheel direction: one notch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    Up,
    Down,
}

/// One HID frame on the control websocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidFrame {
    /// `88 88 01 <0x30 + hid_type>`; type 0 is absolute mouse.
    SetMode { hid_type: u8 },
    /// `AA AA 08 00 mod 00 00 k1 k2 k3 k4 k5` (12 bytes).
    Keyboard { modifiers: u8, keys: [u8; 5] },
    /// `AA AA 05 51 btn xLo xHi yLo yHi` (9 bytes), x and y ≤ 32767.
    AbsMouse { buttons: u8, x: u16, y: u16 },
    /// `AA AA 04 20 btn 00 00 w` (8 bytes), `w` = `01` up / `FF` down.
    Wheel { buttons: u8, wheel: Wheel },
}

/// Why a websocket message is not a §3.3 HID frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDecodeError {
    Unknown,
    BadLength,
    CoordinateOutOfRange,
}

impl HidFrame {
    /// Absolute-mouse frame with x and y clamped to `ABS_MAX`.
    #[must_use]
    pub fn abs_mouse(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse {
            buttons,
            x: x.min(ABS_MAX),
            y: y.min(ABS_MAX),
        }
    }

    /// Append the frame's bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            HidFrame::SetMode { hid_type } => {
                out.extend_from_slice(&[0x88, 0x88, 0x01, 0x30_u8.wrapping_add(hid_type)]);
            }
            HidFrame::Keyboard { modifiers, keys } => {
                out.extend_from_slice(&[0xAA, 0xAA, 0x08, 0x00, modifiers, 0x00, 0x00]);
                out.extend_from_slice(&keys);
            }
            HidFrame::AbsMouse { buttons, x, y } => {
                let [x_lo, x_hi] = x.min(ABS_MAX).to_le_bytes();
                let [y_lo, y_hi] = y.min(ABS_MAX).to_le_bytes();
                out.extend_from_slice(&[0xAA, 0xAA, 0x05, 0x51, buttons, x_lo, x_hi, y_lo, y_hi]);
            }
            HidFrame::Wheel { buttons, wheel } => {
                let w = match wheel {
                    Wheel::Up => 0x01,
                    Wheel::Down => 0xFF,
                };
                out.extend_from_slice(&[0xAA, 0xAA, 0x04, 0x20, buttons, 0x00, 0x00, w]);
            }
        }
    }

    /// The frame's bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        self.encode(&mut v);
        v
    }

    /// Decode one websocket message.
    pub fn decode(msg: &[u8]) -> Result<HidFrame, HidDecodeError> {
        match msg {
            [0x88, 0x88, 0x01, t] => t
                .checked_sub(0x30)
                .map(|hid_type| HidFrame::SetMode { hid_type })
                .ok_or(HidDecodeError::Unknown),
            [0xAA, 0xAA, 0x08, 0x00, m, 0x00, 0x00, k1, k2, k3, k4, k5] => Ok(HidFrame::Keyboard {
                modifiers: *m,
                keys: [*k1, *k2, *k3, *k4, *k5],
            }),
            [0xAA, 0xAA, 0x05, 0x51, b, x_lo, x_hi, y_lo, y_hi] => {
                let x = u16::from_le_bytes([*x_lo, *x_hi]);
                let y = u16::from_le_bytes([*y_lo, *y_hi]);
                if x > ABS_MAX || y > ABS_MAX {
                    return Err(HidDecodeError::CoordinateOutOfRange);
                }
                Ok(HidFrame::AbsMouse { buttons: *b, x, y })
            }
            [0xAA, 0xAA, 0x04, 0x20, b, 0x00, 0x00, w] => match w {
                0x01 => Ok(HidFrame::Wheel {
                    buttons: *b,
                    wheel: Wheel::Up,
                }),
                0xFF => Ok(HidFrame::Wheel {
                    buttons: *b,
                    wheel: Wheel::Down,
                }),
                _ => Err(HidDecodeError::Unknown),
            },
            [0x88, 0x88, 0x01, ..] | [0xAA, 0xAA, 0x08 | 0x05 | 0x04, ..] => {
                Err(HidDecodeError::BadLength)
            }
            _ => Err(HidDecodeError::Unknown),
        }
    }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib hid::` — Expected: 3 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/hid.rs crates/kvm-proto/src/lib.rs
git commit -m "kvm-proto: §3.3 HID frame encoders and decoder" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 6 — Fixtures

### Task 6.1: The ES3-shaped POC-type-0 fixture

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/examples/es3_fixture.rs`
- Modify: `/home/chris/Repos/kvm-rdp/scripts/gen-fixtures.sh`
- Create (generated): `/home/chris/Repos/kvm-rdp/fixtures/360p30_es3like_poc0.h264`, `/home/chris/Repos/kvm-rdp/fixtures/360p30_es3like_poc0.h264.manifest.json`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/fixtures.rs`
- Test: `tests/fixtures.rs` (`es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg`, `committed_bytes_match_their_manifests`)

**Interfaces:**
- Consumes: `SpsSyntax`, `PocSyntax`, `VideoSignalType`, `ColourDescription` (2.3), `rewrite_sps` (2.4), `bits` (2.1), `split_annex_b` (2.2).
- Produces: `fixtures/360p30_es3like_poc0.h264` — 640×360, 120 frames, two 60-frame GOPs, Baseline, POC type 0, limited-range BT.709 pixels, level 2.1 as sent (rewritten to 3.0), VUI full range 5/6/5 as sent (the ES3's mislabel, D6; rewritten to limited-range BT.709, which is then true), no `bitstream_restriction`, AUD on every AU, x264's SEI in the first — and its manifest with the extra field `ffmpeg_level_vui_sps_hex`. Used by Tasks 6.2 and 7.1 and kvm-sim's ES3 profile (Part 8). `scripts/gen-fixtures.sh es3like` regenerates it alone, and on every run re-reads Task 2.4's census goldens with ffmpeg's trace_headers.

- [ ] **Step 1: Write the failing tests.** In `crates/kvm-proto/tests/fixtures.rs`:

Replace `assert_eq!(ms.len(), 10, "expected 10 committed fixtures");` with `assert_eq!(ms.len(), 11, "expected 11 committed fixtures");`.

In `kvm_proto_sps_parser_agrees_with_ffmpeg`, replace

```rust
        let s = kvm_proto::h264::parse_sps(sps).unwrap_or_else(|e| panic!("{name}: {e:?}"));
```

with (the literal BT.709 asserts are Plan A's 4.2 minor):

```rust
        if m.get("ffmpeg_level_vui_sps_hex").is_some() {
            continue; // the ES3-like fixture: es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg
        }
        let s = kvm_proto::h264::parse_sps(sps).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // gen-fixtures asks x264 for BT.709 on every encode; a literal check
        // catches a dropped colorprim/colormatrix param the manifest would
        // simply repeat.
        assert_eq!(
            s.colour_primaries,
            Some(1),
            "{name} colour_primaries literal"
        );
        assert_eq!(
            s.matrix_coefficients,
            Some(1),
            "{name} matrix_coefficients literal"
        );
```

Append:

```rust
#[test]
fn es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg() {
    use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
    let m = manifests()
        .into_iter()
        .find(|m| m["name"] == "360p30_es3like_poc0.h264")
        .unwrap();
    // The manifest is ffmpeg's view of the stream as generated: ES3-shaped.
    assert_eq!(
        (
            m["profile_idc"].as_u64(),
            m["level_idc"].as_u64(),
            m["pic_order_cnt_type"].as_u64()
        ),
        (Some(66), Some(21), Some(0))
    );
    assert_eq!(m["bitstream_restriction_flag"].as_u64(), Some(0));
    assert_eq!(
        (
            m["colour_primaries"].as_u64(),
            m["matrix_coefficients"].as_u64()
        ),
        (Some(5), Some(5))
    );
    assert_eq!(
        (m["keyint"].as_u64(), m["key_frames"].as_u64()),
        (Some(60), Some(2))
    );
    let bytes = read("360p30_es3like_poc0.h264");
    let sps = nals(&bytes).into_iter().find(|n| nal_type(n) == 7).unwrap();
    // Like the ES3's own SPS, h264-reader refuses it as sent (§6.8).
    assert!(kvm_proto::h264::parse_sps(sps).is_err());
    // kvm-proto's level + VUI rewrite is byte-identical to ffmpeg's
    // h264_metadata doing the same (an independent serialiser).
    let lv = rewrite_sps(
        sps,
        &RewriteConfig {
            restriction: false,
            ..RewriteConfig::ES3
        },
    )
    .unwrap();
    let hex: String = lv.nal.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, m["ffmpeg_level_vui_sps_hex"].as_str().unwrap());
    // The full rewrite: level 30 for 640×368 at 30 fps, BT.709 limited,
    // bitstream_restriction 0 / 1 added (gen-fixtures checks the same with
    // trace_headers and an unchanged decode).
    let full = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
    let s = &full.summary;
    assert_eq!(
        (s.width, s.height, s.level_idc, s.pic_order_cnt_type),
        (640, 360, 30, 0)
    );
    assert_eq!(s.video_full_range_flag, Some(false));
    assert_eq!(
        (s.colour_primaries, s.matrix_coefficients),
        (Some(1), Some(1))
    );
    assert_eq!(
        (s.max_num_reorder_frames, s.max_dec_frame_buffering),
        (Some(0), Some(1))
    );
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --test fixtures`
Expected: FAIL — `committed_bytes_match_their_manifests` (`expected 11 committed fixtures`, left 10), `es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg` (`unwrap()` on `None`: no such manifest).

- [ ] **Step 3: Write the transform.** Create `crates/kvm-proto/examples/es3_fixture.rs` (trusted input only — it never runs on a KVM capture). `es3ify` rewrites each SPS into the ES3's shape and inserts `pic_order_cnt_lsb = 2 × frame_num` into each slice header, copying the rest of every slice bit for bit; `rewrite` applies the bridge's §6.8 rewrite so ffmpeg can be shown what the bridge would send:

```rust
//! Fixture tool (trusted input only — never run on a KVM capture): turn an
//! x264 Baseline stream with POC type 2 into an ES3-shaped stream (§11.5):
//! POC type 0 with `pic_order_cnt_lsb = 2 × frame_num` inserted into every
//! slice header, no `bitstream_restriction`, and the ES3's mislabels — a
//! level below the coded size (2.1 for 640×360), constraint flags 0, and a
//! VUI claiming full-range BT.601 (5/6/5). Slice data is copied bit for
//! bit, so the decoded frames are unchanged (gen-fixtures checks the md5).
//!
//! `rewrite` instead applies kvm-proto's §6.8 rewrite (`RewriteConfig::ES3`)
//! to every SPS, so gen-fixtures can show ffmpeg what the bridge would send.
//!
//! Usage: `cargo run -p kvm-proto --example es3_fixture -- es3ify|rewrite IN OUT`
use kvm_proto::bits::{BitReader, BitWriter, escape_rbsp_into, unescape_rbsp};
use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
use kvm_proto::h264::split_annex_b;
use kvm_proto::h264::sps_syntax::{ColourDescription, PocSyntax, SpsSyntax, VideoSignalType};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let [_, mode, input, output] = args.as_slice() else {
        return Err("usage: es3_fixture es3ify|rewrite IN.h264 OUT.h264".into());
    };
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let out = match mode.as_str() {
        "es3ify" => transform(&data)?,
        "rewrite" => rewrite(&data)?,
        other => return Err(format!("unknown mode {other}")),
    };
    std::fs::write(output, out).map_err(|e| format!("{output}: {e}"))
}

fn rewrite(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    for nal in split_annex_b(data) {
        out.extend_from_slice(&[0, 0, 0, 1]);
        if nal[0] & 0x1F == 7 {
            let r = rewrite_sps(nal, &RewriteConfig::ES3).map_err(|e| format!("{e:?}"))?;
            out.extend_from_slice(&r.nal);
        } else {
            out.extend_from_slice(nal);
        }
    }
    Ok(out)
}

/// `(log2_max_frame_num, log2_max_pic_order_cnt_lsb)` of the stream's SPS.
type Widths = (u32, u32);

fn transform(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut widths: Option<Widths> = None;
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);
    for nal in split_annex_b(data) {
        let nal_type = nal[0] & 0x1F;
        let new = match nal_type {
            7 => {
                let (sps, w) = es3_sps(nal)?;
                widths = Some(w);
                sps
            }
            8 => {
                check_pps(nal)?;
                nal.to_vec()
            }
            1 | 5 => insert_poc_lsb(nal, widths.ok_or("slice before SPS")?)?,
            _ => nal.to_vec(),
        };
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&new);
    }
    Ok(out)
}

fn es3_sps(nal: &[u8]) -> Result<(Vec<u8>, Widths), String> {
    let mut s = SpsSyntax::parse(nal).map_err(|e| format!("SPS: {e:?}"))?;
    if s.poc != PocSyntax::Type2 || s.profile_idc != 66 {
        return Err(format!(
            "want Baseline POC type 2, got {} {:?}",
            s.profile_idc, s.poc
        ));
    }
    let log2_fn = s.log2_max_frame_num_minus4 + 4;
    let log2_lsb = log2_fn + 1; // 2 × frame_num never wraps before frame_num does
    s.poc = PocSyntax::Type0 {
        log2_max_pic_order_cnt_lsb_minus4: log2_lsb - 4,
    };
    s.level_idc = 21; // MaxFS 792 < 920 MBs: mislabelled like the ES3 (§6.8)
    s.constraint_flags = 0;
    let vui = s.vui.get_or_insert_with(Default::default);
    vui.video_signal_type = Some(VideoSignalType {
        video_format: 5,
        video_full_range_flag: true,
        colour_description: Some(ColourDescription {
            colour_primaries: 5,
            transfer_characteristics: 6,
            matrix_coefficients: 5,
        }),
    });
    vui.bitstream_restriction = None;
    Ok((s.to_nal(), (log2_fn, log2_lsb)))
}

/// The slice-header rewrite below copies everything after the inserted
/// field bit for bit, which is only right for CAVLC slices with no
/// `delta_pic_order_cnt_bottom`.
fn check_pps(nal: &[u8]) -> Result<(), String> {
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let bits = |e| format!("PPS: {e:?}");
    r.read_ue().map_err(bits)?; // pic_parameter_set_id
    r.read_ue().map_err(bits)?; // seq_parameter_set_id
    let cabac = r.read_bit().map_err(bits)?;
    let bottom_field_poc = r.read_bit().map_err(bits)?;
    if cabac || bottom_field_poc {
        return Err("want a CAVLC PPS without bottom_field_pic_order_in_frame_present_flag".into());
    }
    Ok(())
}

fn insert_poc_lsb(nal: &[u8], (log2_fn, log2_lsb): Widths) -> Result<Vec<u8>, String> {
    let bits = |e| format!("slice: {e:?}");
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let stop = r.stop_bit_position().ok_or("slice without a stop bit")?;
    let mut w = BitWriter::new();
    for _ in 0..3 {
        w.write_ue(r.read_ue().map_err(bits)?); // first_mb_in_slice, slice_type, pps_id
    }
    let frame_num = r.read_bits(log2_fn).map_err(bits)?;
    w.write_bits(u64::from(frame_num), log2_fn);
    if nal[0] & 0x1F == 5 {
        w.write_ue(r.read_ue().map_err(bits)?); // idr_pic_id
    }
    let lsb = (2 * u64::from(frame_num)) % (1u64 << log2_lsb);
    w.write_bits(lsb, log2_lsb); // pic_order_cnt_lsb
    while r.position() < stop {
        w.write_bit(r.read_bit().map_err(bits)?);
    }
    w.write_trailing_bits();
    let mut out = vec![nal[0]];
    escape_rbsp_into(&w.into_rbsp(), &mut out);
    Ok(out)
}
```

- [ ] **Step 4: Teach gen-fixtures to make it.** In `scripts/gen-fixtures.sh`:

Add a usage line under the first `#   scripts/gen-fixtures.sh` line:

```bash
#   scripts/gen-fixtures.sh es3like    only fixtures/360p30_es3like_poc0.h264 (+ manifest)
```

Replace the comment above `sps_count()` (Plan A 4.1 minor: it is a presence check, not an exact count) with:

```bash
# Whether a stream has an in-band SPS (nal_unit_type 7): a byte-level scan for
# a 3-byte start code followed by an SPS header byte (any of the 4 nal_ref_idc
# values: 0x07/0x27/0x47/0x67). Only presence (0 vs not 0) is used; a 4-byte
# start code ends in the same 3 bytes. Not ffmpeg's trace_headers, whose
# extradata handling logs SPS lines that do not match the real NAL count.
```

Replace `    local sps_pps=$(mktemp)` (which masks a `mktemp` failure under `set -e`) with:

```bash
    local sps_pps
    sps_pps=$(mktemp)
```

Add, right below the `FP=(…)` line (§13: decodes and traces run with `-threads 4`; encodes keep their own `-threads 1`, so `FF` and every committed fixture stay as they are):

```bash
# Decode-only runs (md5, trace_headers): §13 caps ffmpeg at 4 threads. Encodes
# keep their own `-threads 1` (determinism), so FF itself is unchanged.
DEC=("${FF[@]}" -threads 4)
```

Add `  es3like` as the last line of `committed()` (after `manifest $d/slate_1080p.h264 1`), and insert these functions between `committed()` and `large()`:

```bash
es3_fixture() { cargo run -q -p kvm-proto --example es3_fixture -- "$@"; }

# check_sps_trace HEX FIELD=VALUE...: ffmpeg's trace_headers, an independent
# reader, must see every listed field of the Annex-B SPS HEX at its value.
check_sps_trace() {
  local hex=$1 f trace kv got
  shift
  f=$(mktemp)
  printf '%b' "$(printf '00000001%s' "$hex" | sed 's/../\\x&/g')" > "$f"
  trace=$("${DEC[@]}" -loglevel trace -f h264 -i "$f" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  rm -f "$f"
  for kv in "$@"; do
    got=$(tv "$trace" "${kv%%=*}")
    if [ "$got" != "${kv#*=}" ]; then
      echo "gen-fixtures: SPS $hex: ${kv%%=*} is $got, want ${kv#*=}" >&2
      return 1
    fi
  done
}

# The ES3-shaped POC-type-0 fixture (spec §11.5; Plan B deviation D6): an x264
# Baseline POC-type-2 encode of limited-range BT.709 pixels (what Leg A
# measured on the ES3) with the ES3's GOP (keyint 60, ref 1), turned by
# kvm-proto's es3_fixture example into POC type 0 (pic_order_cnt_lsb =
# 2 × frame_num) carrying the ES3's mislabels — so the §6.8 VUI rewrite makes
# its VUI true, as it does the ES3's. Checked four ways: trace_headers reads
# the L0 goldens of kvm-proto Task 2.4 (census.md's sps_hex rewritten) with
# the fields that task claims; the decode is unchanged; kvm-proto's full §6.8
# rewrite of the fixture reads back in trace_headers as level 30,
# limited-range BT.709 and bitstream_restriction 0/1, with the decode still
# unchanged; and ffmpeg's own h264_metadata level+VUI rewrite of its SPS is
# recorded in the manifest, which kvm-proto's tests compare byte for byte
# with the bridge's.
es3like() {
  local d=fixtures work md5_src trace kv got hex
  check_sps_trace 67420028965403c0112f2cd40404041b41008540 level_idc=40 \
    video_full_range_flag=0 colour_primaries=1 transfer_characteristics=1 \
    matrix_coefficients=1 bitstream_restriction_flag=1 max_num_reorder_frames=0 \
    max_dec_frame_buffering=1 pic_order_cnt_type=0
  check_sps_trace 67420028965403c0112f2cd404040408 level_idc=40 video_full_range_flag=0 \
    colour_primaries=1 transfer_characteristics=1 matrix_coefficients=1 \
    bitstream_restriction_flag=0
  work=$(mktemp -d)
  enc "$work/src.h264" 640x360 120 baseline 3.0 tv 60 600k 1 40 32 ":ref=1"
  es3_fixture es3ify "$work/src.h264" $d/360p30_es3like_poc0.h264
  md5_src=$("${DEC[@]}" -i "$work/src.h264" -fps_mode passthrough -f md5 -)
  if [ "$("${DEC[@]}" -i $d/360p30_es3like_poc0.h264 -fps_mode passthrough -f md5 -)" != "$md5_src" ]; then
    echo "es3like: decoded frames differ from the x264 source" >&2
    rm -rf "$work"
    return 1
  fi
  es3_fixture rewrite $d/360p30_es3like_poc0.h264 "$work/rewritten.h264"
  trace=$("${DEC[@]}" -loglevel trace -i "$work/rewritten.h264" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  for kv in level_idc=30 video_full_range_flag=0 colour_primaries=1 transfer_characteristics=1 \
    matrix_coefficients=1 bitstream_restriction_flag=1 max_num_reorder_frames=0 \
    max_dec_frame_buffering=1 pic_order_cnt_type=0; do
    got=$(tv "$trace" "${kv%%=*}")
    if [ "$got" != "${kv#*=}" ]; then
      echo "es3like: rewritten SPS ${kv%%=*} is $got, want ${kv#*=}" >&2
      rm -rf "$work"
      return 1
    fi
  done
  if [ "$("${DEC[@]}" -i "$work/rewritten.h264" -fps_mode passthrough -f md5 -)" != "$md5_src" ]; then
    echo "es3like: the rewrite changed the decoded frames" >&2
    rm -rf "$work"
    return 1
  fi
  "${FF[@]}" -i $d/360p30_es3like_poc0.h264 -frames:v 1 -c copy \
    -bsf:v "h264_metadata=level=3:video_full_range_flag=0:colour_primaries=1:transfer_characteristics=1:matrix_coefficients=1,filter_units=pass_types=7" \
    -f h264 "$work/meta.h264"
  hex=$(od -An -tx1 -v "$work/meta.h264" | tr -d ' \n' | sed 's/^00000001//')
  manifest $d/360p30_es3like_poc0.h264 60
  jq --arg h "$hex" '. + {ffmpeg_level_vui_sps_hex: $h}' \
    $d/360p30_es3like_poc0.h264.manifest.json > "$work/manifest.json"
  mv "$work/manifest.json" $d/360p30_es3like_poc0.h264.manifest.json
  rm -rf "$work"
}
```

Finally replace the `case` block's `committed)` and `*)` arms so it reads:

```bash
case "$MODE" in
  committed) committed ;;
  es3like) es3like ;;
  large) large ;;
  clean) rm -rf fixtures/large ;;
  *) echo "usage: $0 [committed|es3like|large|clean]" >&2; exit 2 ;;
esac
```

- [ ] **Step 5: Generate it.**

Run: `scripts/gen-fixtures.sh es3like`
Expected: exits 0 (the golden trace checks and the three fixture checks pass); then `sha256sum fixtures/360p30_es3like_poc0.h264` prints `131ea43747b288b8c1aede036645ac525c629c31100439b84c4b4128f731e091` and `stat -c %s` prints `318186`; the manifest has `"level_idc": 21`, `"pic_order_cnt_type": 0`, `"key_frames": 2` and `"ffmpeg_level_vui_sps_hex": "6742001ee901405ff2e02d40404050000003001000000303c840"`. A different hash means the flake's ffmpeg/x264 changed: stop and report, do not commit a different stream.

Run: `scripts/gen-fixtures.sh && git status --porcelain fixtures/`
Expected: only the two new `360p30_es3like_poc0.h264*` files — regenerating every committed fixture leaves the others byte-identical.

- [ ] **Step 6: Run the tests to see them pass.**

Run: `cargo test -p kvm-proto --test fixtures` — Expected: 6 passed.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean (examples included).

- [ ] **Step 7: Commit.**

```bash
git add crates/kvm-proto/examples/es3_fixture.rs scripts/gen-fixtures.sh \
  fixtures/360p30_es3like_poc0.h264 fixtures/360p30_es3like_poc0.h264.manifest.json \
  crates/kvm-proto/tests/fixtures.rs
git commit -m "fixtures: ES3-shaped POC-type-0 stream (§11.5, moved from Plan A)" \
  -m "x264 Baseline of limited-range BT.709 pixels → POC 0 with pic_order_cnt_lsb = 2 × frame_num and the ES3's level/VUI mislabels; decode unchanged; ffmpeg's h264_metadata rewrite of its SPS recorded and matched byte for byte; the census goldens re-read by trace_headers." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6.2: Every committed fixture through admission

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/admission.rs` (a module of the one `fixtures` test binary)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/fixtures.rs` (`mod admission;`)
- Test: `tests/admission.rs` (`every_fixture_admits_with_ffprobes_frame_counts`, `the_ffmpeg_muxed_flv_admits`)

**Interfaces:**
- Consumes: the muxer (3.3), `VideoAdmission` (4.6), `split_annex_b` (2.2), the ten committed `.h264` fixtures (Task 6.1's included) and the ffmpeg-muxed `360p30_main_full.flv`.
- Produces: §11.2's fixture tier for admission — every fixture muxed into FLV, demuxed and admitted with ffprobe's AU and IDR counts, every emitted AU re-split against §6.3's output contract, and an independent demux oracle (ffmpeg's own FLV muxer).

This task adds tests over code that already exists (Tasks 4.6 and 6.1), so they pass when written; a failure is an admission bug — fix the code, never the counts, which are ffprobe's.

- [ ] **Step 1: Write the tests.** Add the admission module to `crates/kvm-proto/tests/fixtures.rs`, under the file's first doc line:

```rust
#[path = "admission.rs"]
mod admission;
```

and create `crates/kvm-proto/tests/admission.rs`:

```rust
//! Every committed fixture, muxed into FLV, demuxed and admitted: the AU and
//! IDR counts match ffprobe's (the manifest), and every emitted AU meets
//! §6.3's output contract. Plus the committed ffmpeg-muxed FLV as an
//! independent demux oracle (§11.2).
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use kvm_proto::h264::split_annex_b;
use kvm_proto::video::{AdmissionConfig, ParamClass, ParamSets, VideoAdmission};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifest(name: &str) -> serde_json::Value {
    let p = dir().join(format!("{name}.manifest.json"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// Access units of an Annex-B stream: an AUD that follows a slice starts
/// the next one (every committed fixture has AUDs).
fn access_units(data: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut aus: Vec<Vec<&[u8]>> = Vec::new();
    for nal in split_annex_b(data) {
        let has_vcl = aus
            .last()
            .is_some_and(|au| au.iter().any(|n| matches!(n[0] & 0x1F, 1 | 5)));
        if aus.is_empty() || (nal[0] & 0x1F == 9 && has_vcl) {
            aus.push(Vec::new());
        }
        aus.last_mut().unwrap().push(nal);
    }
    aus
}

/// The stream as an FLV: its first SPS/PPS in the sequence header, one tag
/// per AU with `CompositionTime` 16. With 1-byte length prefixes the SEI
/// (x264's 695-byte version string) cannot be framed, so it is left out.
fn to_flv(data: &[u8], length_size: u8) -> Vec<u8> {
    let nals: Vec<&[u8]> = split_annex_b(data).collect();
    let sps = *nals.iter().find(|n| n[0] & 0x1F == 7).unwrap();
    let pps = *nals.iter().find(|n| n[0] & 0x1F == 8).unwrap();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let seq = avc_sequence_header_body(&[sps], &[pps], length_size).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    for (i, au) in access_units(data).iter().enumerate() {
        let key = au.iter().any(|n| n[0] & 0x1F == 5);
        let au: Vec<&[u8]> = au
            .iter()
            .copied()
            .filter(|n| length_size != 1 || n[0] & 0x1F != 6)
            .collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, key, 16, &au, length_size).unwrap();
        let ts = u32::try_from(i * 1000 / 30).unwrap();
        write_tag(&mut flv, TAG_VIDEO, ts, &body).unwrap();
    }
    flv
}

/// Demux and admit `flv`; check §6.3 on every AU; return (AUs, IDRs, the
/// classes of every parameter-set change, the last sets).
fn admit_all(flv: &[u8]) -> (u64, u64, Vec<ParamClass>, ParamSets) {
    let mut d = FlvDemuxer::new(FlvLimits::default());
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    d.push(flv);
    let (mut aus, mut idrs, mut classes, mut last) = (0, 0, Vec::new(), None);
    let mut out = Vec::new();
    let t0 = Instant::now();
    while let Some(tag) = d.next_tag().unwrap() {
        let ad = a.admit(tag, t0).unwrap();
        if let Some(pc) = ad.params {
            classes.push(pc.class);
            last = Some(pc.params);
        }
        if let Some(au) = ad.au {
            aus += 1;
            idrs += u64::from(au.idr);
            let ps = last.as_ref().unwrap();
            out.clear();
            au.write_annex_b(ps, &mut out);
            let mut expect: Vec<&[u8]> = Vec::new();
            expect.extend(au.aud.as_deref());
            if au.idr {
                expect.push(&ps.sps);
                expect.extend(ps.pps.iter().map(|p| p.as_ref()));
            }
            expect.extend(au.vcl.iter().map(|n| n.bytes.as_ref()));
            let resplit: Vec<&[u8]> = split_annex_b(&out).collect();
            assert_eq!(resplit, expect);
            for n in resplit {
                assert!(matches!(n[0] & 0x1F, 1 | 5 | 7 | 8 | 9));
                assert!(!n.windows(3).any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 2));
            }
        }
    }
    (aus, idrs, classes, last.unwrap())
}

#[test]
fn every_fixture_admits_with_ffprobes_frame_counts() {
    let mut seen = 0;
    for e in std::fs::read_dir(dir()).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".h264") {
            continue;
        }
        let m = manifest(&name);
        let length_size = if name.contains("slices") { 1 } else { 4 };
        let (aus, idrs, classes, last) =
            admit_all(&to_flv(&std::fs::read(&path).unwrap(), length_size));
        assert_eq!(Some(aus), m["frames"].as_u64(), "{name} AUs");
        assert_eq!(Some(idrs), m["key_frames"].as_u64(), "{name} IDRs");
        // Repeated in-band SPS/PPS (x264 repeat-headers) raise nothing new.
        assert_eq!(classes, [ParamClass::Initial], "{name}");
        // Every admitted SPS carries the rewritten VUI.
        assert_eq!(last.summary.video_full_range_flag, Some(false), "{name}");
        if name == "360p30_es3like_poc0.h264" {
            assert_eq!(
                (last.summary.level_idc, last.summary.pic_order_cnt_type),
                (30, 0)
            );
        }
        seen += 1;
    }
    assert_eq!(
        seen, 10,
        "every committed .h264 (the 11th manifest is the .flv)"
    );
}

#[test]
fn the_ffmpeg_muxed_flv_admits() {
    let flv = std::fs::read(dir().join("360p30_main_full.flv")).unwrap();
    let (aus, idrs, classes, _) = admit_all(&flv);
    assert_eq!((aus, idrs), (90, 3));
    assert_eq!(classes, [ParamClass::Initial]);
}
```

- [ ] **Step 2: Run them.**

Run: `cargo test -p kvm-proto --test fixtures admission`
Expected: 2 passed — all ten `.h264` fixtures admit with their manifest's `frames` and `key_frames`, each raising exactly one `Initial` (x264's repeated in-band sets raise nothing new), the ES3-like one at level 30 with POC type 0; the ffmpeg FLV gives 90 AUs and 3 IDRs.

- [ ] **Step 3: Run the whole binary.**

Run: `cargo test -p kvm-proto --test fixtures` — Expected: 8 passed.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 4: Commit.**

```bash
git add crates/kvm-proto/tests/fixtures.rs crates/kvm-proto/tests/admission.rs
git commit -m "kvm-proto: every committed fixture through admission (§11.2)" \
  -m "ffprobe's AU and IDR counts, §6.3's output re-split per AU, and ffmpeg's own FLV muxer as a demux oracle." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 7 — Fuzzing

§11.2's L0 fuzz tier: FLV demux, AVCC, the sanitiser and the SPS/PPS/slice checks (each directly, and all through admission), the SPS rewriter, login, and a differential mux→demux target, each with output invariants — bounded everywhere, and run only in CI (§13). On this host every target body runs over its seeds in plain `cargo test`.

### Task 7.1: `kvm_proto::fuzzing` — target bodies, invariants and seeds

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/fuzzing.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/examples/fuzz_seeds.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml`
- Test: `crates/kvm-proto/src/fuzzing.rs` (`tests`)

**Interfaces:**
- Consumes: everything public in kvm-proto; the committed fixtures (seeds).
- Produces (`kvm_proto::fuzzing`, compiled under `cfg(test)` or feature `fuzzing`; never by the bridge — D8): `pub fn flv_demux(data: &[u8])`, `admission`, `avcc`, `sps_rewrite`, `pps`, `sanitize`, `slice`, `login`, `mux_demux` — each panics only when an invariant breaks: emitted NAL types ∈ {1,5,7,8,9}; no emitted NAL contains `00 00 0[0-2]`; re-splitting the Annex-B yields exactly the emitted NALs; the emitted SPS is the admitted (rewritten) one and its pinned fields never move; for an SPS kvm-proto reads, the rewrite either succeeds or refuses for a legitimate reason (`NoLevel`, `H264Reader`, `Summary`) — `SelfCheck` or `Disagrees` (two readers disagreeing on what was written) is a finding — and its output re-reads with every field equal to the input's except `level_idc` (never lower), the VUI's signal type/colour and an added `bitstream_restriction` (= `inferred(0, max(refs, 1))`); an accepted PPS has one slice group, `num_ref_idx` defaults ≤ 15 and no scaling matrix; a NAL the sanitiser keeps is non-empty, allowlisted, start-code-free and its input minus trailing zeros; every POC the slice tracker admits exceeds the last one in its GOP; `avcc_to_annex_b` leaves `out` untouched on error; a login token is `0.` + digits; mux→demux is the identity; a demuxer with a 64 KiB tag limit, drained after every chunk as a consumer drains it (body errors leave it aligned, framing errors poison and empty it), holds less than one maximal tag — a bound `fuzz.sh`'s 256 KiB inputs can reach. Also `pub const ES3_LIKE_PARAMS`, `MAIN_360P_PARAMS: (&[u8], &[u8])`, `pub fn seeds() -> Vec<(&'static str, String, Vec<u8>)>` (FLV seeds for `flv_demux` carry a leading chunk-size selector byte; `admission` also gets an in-band parameter-set flood at D10's cap), `pub fn run(target: &str, data: &[u8])`, `pub const TARGETS: [&str; 9]`. Feature `fuzzing = []` in kvm-proto's `Cargo.toml`; example `fuzz_seeds` (requires `fuzzing`) writes the seeds under a directory it must be given.

- [ ] **Step 1: Write the failing tests.** In `crates/kvm-proto/src/lib.rs` add, after `pub mod flv;`:

```rust
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzzing;
```

In `crates/kvm-proto/Cargo.toml` add after the `[lib]` table:

```toml
[features]
# Fuzz-target bodies with output invariants (`kvm_proto::fuzzing`), for
# `fuzz/` only: the module panics by design (Plan B deviation D8), and CI
# fails if any workspace crate enables this feature.
fuzzing = []
```

and at the end:

```toml
[[example]]
name = "fuzz_seeds"
required-features = ["fuzzing"]
```

Create `crates/kvm-proto/src/fuzzing.rs` with its test module (it runs every target over every seed and three truncations of each — on stable, in every `cargo test`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_runs_clean_over_its_seeds() {
        let seeds = seeds();
        for t in TARGETS {
            assert!(seeds.iter().any(|(s, _, _)| *s == t), "no seed for {t}");
        }
        for (target, name, bytes) in &seeds {
            run(target, bytes);
            // Truncations exercise every partial-input path.
            for cut in [1, bytes.len() / 3, bytes.len() / 2] {
                run(target, &bytes[..cut.min(bytes.len())]);
            }
            let _ = name;
        }
    }

    #[test]
    fn the_es3_seed_admits_end_to_end() {
        let es3 = seeds()
            .into_iter()
            .find(|(t, n, _)| *t == "admission" && n == "es3.flv")
            .unwrap()
            .2;
        let mut d = FlvDemuxer::new(FlvLimits::default());
        let mut a = VideoAdmission::new(AdmissionConfig::default());
        a.flv_opened();
        d.push(&es3);
        let mut aus = 0;
        while let Some(tag) = d.next_tag().unwrap() {
            aus += usize::from(a.admit(tag, Instant::now()).unwrap().au.is_some());
        }
        assert_eq!(aus, 8);
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-proto --lib fuzzing`
Expected: FAIL to compile — `cannot find function seeds`, `run`, value `TARGETS`, and the target functions.

- [ ] **Step 3: Implement.** Put this above the test module in `fuzzing.rs` (test-oracle code: it allows the panicking lints on purpose, scoped to this module):

```rust
//! Fuzz-target bodies with their output invariants (§11.2 L0 fuzz). Each
//! function takes arbitrary bytes and panics only when an invariant breaks —
//! a panic is a finding. `fuzz/` calls them from libFuzzer; the unit tests
//! below run them over the committed seeds on stable, so every target is
//! exercised by plain `cargo test` too. Test-oracle code, not a parser: it
//! may panic by design, so it alone in kvm-proto opts out of the crate's
//! lint denies (deviation D8); only `fuzz/` enables its feature.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::flv::mux::{
    TAG_VIDEO, avc_end_of_sequence_body, avc_nalu_body, avc_sequence_header_body, write_flv_header,
    write_tag,
};
use crate::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
use crate::h264::rewrite::{RewriteConfig, RewriteError, rewrite_sps};
use crate::h264::sanitize::{NalVerdict, check_nal};
use crate::h264::sps_syntax::{BitstreamRestriction, ColourDescription, SpsSyntax};
use crate::h264::{SpsPins, avcc_to_annex_b, split_annex_b};
use crate::video::{AdmissionConfig, ParamSets, VideoAdmission};
use std::sync::OnceLock;
use std::time::Instant;

/// Feed the bytes after a selector byte to a demuxer with a 64 KiB tag
/// limit, in chunks of `1 + 16 × selector` bytes, draining after every chunk
/// as a consumer does: a body-level error leaves the stream aligned, a
/// framing error poisons the demuxer and empties its buffer. After each
/// drain the buffer holds less than one maximal tag — a bound that
/// `fuzz.sh`'s 256 KiB inputs can reach.
pub fn flv_demux(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let limits = FlvLimits {
        max_tag_size: 64 * 1024,
        ..FlvLimits::default()
    };
    let tag_bound = 11 + limits.max_tag_size as usize + 4;
    let mut d = FlvDemuxer::new(limits);
    for c in rest.chunks(1 + usize::from(sel) * 16) {
        d.push(c);
        loop {
            match d.next_tag() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) if d.buffered_len() == 0 => break,
                Err(_) => {}
            }
        }
        assert!(
            d.buffered_len() < tag_bound,
            "demuxer kept {} bytes after draining",
            d.buffered_len()
        );
    }
}

/// Demux and admit everything; check every emitted parameter set and access
/// unit against §6.2/§6.3's output invariants.
pub fn admission(data: &[u8]) {
    let mut d = FlvDemuxer::new(FlvLimits::default());
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    d.push(data);
    let mut params: Option<ParamSets> = None;
    let mut pins: Option<SpsPins> = None;
    let mut out = Vec::new();
    let now = Instant::now();
    while let Ok(Some(tag)) = d.next_tag() {
        let Ok(admitted) = a.admit(tag, now) else {
            return;
        };
        if let Some(change) = admitted.params {
            let p = change.params;
            // The emitted SPS is exactly the admitted (rewritten) one.
            assert_eq!(SpsSyntax::parse(&p.sps).unwrap().to_nal(), p.sps.as_ref());
            let now_pins = SpsPins::of(&p.summary);
            assert_eq!(
                *pins.get_or_insert(now_pins),
                now_pins,
                "pinned field moved"
            );
            params = Some(p);
        }
        if let Some(au) = admitted.au {
            let p = params.as_ref().expect("an AU before any parameter sets");
            out.clear();
            au.write_annex_b(p, &mut out);
            let mut expected: Vec<&[u8]> = Vec::new();
            expected.extend(au.aud.as_deref());
            if au.idr {
                expected.push(&p.sps);
                expected.extend(p.pps.iter().map(|b| b.as_ref()));
            }
            expected.extend(au.vcl.iter().map(|n| n.bytes.as_ref()));
            let resplit: Vec<&[u8]> = split_annex_b(&out).collect();
            assert_eq!(resplit, expected, "Annex-B re-split differs");
            for nal in resplit {
                assert!(
                    matches!(nal[0] & 0x1F, 1 | 5 | 7 | 8 | 9),
                    "type {}",
                    nal[0] & 0x1F
                );
                assert!(
                    !crate::bits::contains_start_code(nal),
                    "start code in {nal:02x?}"
                );
            }
            assert!(!au.vcl.is_empty());
        }
    }
}

/// `avcc_to_annex_b`: on success the output re-splits to exactly the input
/// NALs; on error `out` is untouched.
pub fn avcc(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let ls = [1usize, 2, 4][sel as usize % 3];
    let mut out = vec![0xEE];
    match avcc_to_annex_b(rest, ls, &mut out) {
        Err(_) => assert_eq!(out, [0xEE]),
        Ok(()) => {
            let mut nals = Vec::new();
            let mut r = rest;
            while !r.is_empty() {
                let (len, tail) = r.split_at(ls);
                let n = len.iter().fold(0usize, |v, b| v << 8 | *b as usize);
                nals.push(&tail[..n]);
                r = &tail[n..];
            }
            let mut want = vec![0xEE];
            for n in nals {
                want.extend_from_slice(&[0, 0, 0, 1]);
                want.extend_from_slice(n);
            }
            assert_eq!(out, want);
        }
    }
}

/// The rewriter (§6.8, §11.2): the output re-parses with every field equal to
/// the input's except `level_idc` (never lower), the VUI's video signal type
/// and colour description, and `bitstream_restriction`.
pub fn sps_rewrite(data: &[u8]) {
    let Ok(input) = SpsSyntax::parse(data) else {
        assert!(rewrite_sps(data, &RewriteConfig::ES3).is_err());
        return;
    };
    let r = match rewrite_sps(data, &RewriteConfig::ES3) {
        Ok(r) => r,
        // Legitimate refusals of an SPS kvm-proto reads: no level admits its
        // size, h264-reader refuses the output, or the output has no summary.
        Err(
            RewriteError::NoLevel { .. } | RewriteError::H264Reader(_) | RewriteError::Summary(_),
        ) => {
            return;
        }
        // Anything else is a finding: kvm-proto's own writer and reader
        // disagree (`SelfCheck`), or h264-reader read other fields than were
        // written (`Disagrees`) — an asymmetric field or an escaping bug.
        Err(e) => panic!("rewrite of {data:02x?}: {e:?}"),
    };
    let out = SpsSyntax::parse(&r.nal).unwrap();
    assert!(out.level_idc >= input.level_idc);
    let out_vui = out.vui.unwrap_or_default();
    let signal = out_vui.video_signal_type.unwrap();
    assert!(!signal.video_full_range_flag);
    assert_eq!(
        signal.colour_description,
        Some(ColourDescription {
            colour_primaries: 1,
            transfer_characteristics: 1,
            matrix_coefficients: 1,
        })
    );
    let mut expect = input.clone();
    expect.level_idc = out.level_idc;
    let ev = expect.vui.get_or_insert_with(Default::default);
    ev.video_signal_type = out_vui.video_signal_type;
    if ev.bitstream_restriction.is_none() {
        let dpb = input.max_num_ref_frames.max(1);
        assert_eq!(
            out_vui.bitstream_restriction,
            Some(BitstreamRestriction::inferred(0, dpb))
        );
        ev.bitstream_restriction = out_vui.bitstream_restriction;
    }
    assert_eq!(out, expect);
    assert!(!crate::bits::contains_start_code(&r.nal));
}

struct Ctx {
    ctx: h264_reader::Context,
    sps: h264_reader::nal::sps::SeqParameterSet,
}

fn contexts() -> &'static [Ctx] {
    static CTX: OnceLock<Vec<Ctx>> = OnceLock::new();
    CTX.get_or_init(|| {
        [ES3_LIKE_PARAMS, MAIN_360P_PARAMS]
            .into_iter()
            .map(|(sps, pps)| {
                let r = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
                let mut ctx = h264_reader::Context::new();
                ctx.put_seq_param_set(r.parsed.clone());
                let p = crate::h264::pps::check_pps(&ctx, pps).unwrap();
                ctx.put_pic_param_set(p);
                Ctx { ctx, sps: r.parsed }
            })
            .collect()
    })
}

/// The ES3-like fixture's SPS (as sent) and PPS (CAVLC Baseline, POC 0).
pub const ES3_LIKE_PARAMS: (&[u8], &[u8]) = (
    &[
        0x67, 0x42, 0x00, 0x15, 0xe9, 0x01, 0x40, 0x5f, 0xf2, 0xe0, 0x2d, 0xc1, 0x41, 0x81, 0x50,
        0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0xc8, 0x40,
    ],
    &[0x68, 0xce, 0x3c, 0x80],
);
/// `360p30_main_full`'s SPS and PPS (CABAC Main, POC 2).
pub const MAIN_360P_PARAMS: (&[u8], &[u8]) = (
    &[
        0x67, 0x4d, 0x40, 0x1f, 0xda, 0x02, 0x80, 0xbf, 0xe5, 0xc0, 0x5b, 0x80, 0x80, 0x80, 0xa0,
        0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x07, 0x91, 0xe3, 0x06, 0x54,
    ],
    &[0x68, 0xef, 0x3c, 0x80],
);

/// Slice-header checks and the POC tracker against an admitted context:
/// the first byte picks the context, the rest is a run of slice NALs
/// separated as Annex B. Every POC the tracker admits exceeds the last one
/// it admitted in that GOP (§6.1), which an IDR starts — as does the picture
/// after an MMCO 5.
pub fn slice(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let c = &contexts()[sel as usize % 2];
    let mut poc = crate::h264::picture::PocTracker::default();
    let mut last: Option<i64> = None;
    for nal in split_annex_b(rest) {
        if let Ok(info) = crate::h264::picture::parse_slice(&c.ctx, nal) {
            if info.idr {
                last = None;
            }
            if let Ok(p) = poc.next(&c.sps, &info) {
                assert!(last.is_none_or(|l| p > l), "POC {p} after {last:?}");
                last = Some(if info.mmco5 { 0 } else { p });
            }
        }
    }
}

/// PPS admission against an admitted context (the first byte picks it): an
/// accepted PPS has one slice group, `num_ref_idx` defaults of at most 15
/// and no scaling matrix (§6.1).
pub fn pps(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let c = &contexts()[sel as usize % 2];
    if let Ok(p) = crate::h264::pps::check_pps(&c.ctx, rest) {
        assert!(p.slice_groups.is_none());
        assert!(p.num_ref_idx_l0_default_active_minus1 <= 15);
        assert!(p.num_ref_idx_l1_default_active_minus1 <= 15);
        assert!(
            p.extension
                .as_ref()
                .is_none_or(|x| x.pic_scaling_matrix.is_none())
        );
    }
}

/// The §6.2 NAL sanitiser: a kept NAL is non-empty, on the allowlist, free
/// of start-code patterns, and its input with only trailing zeros trimmed.
pub fn sanitize(data: &[u8]) {
    let nal = bytes::Bytes::copy_from_slice(data);
    if let Ok(NalVerdict::Keep(h, kept)) = check_nal(&nal) {
        assert!(!kept.is_empty());
        assert!(
            matches!(h.nal_unit_type, 1 | 5 | 7 | 8 | 9),
            "type {}",
            h.nal_unit_type
        );
        assert_eq!(kept[0] & 0x1F, h.nal_unit_type);
        assert!(!crate::bits::contains_start_code(&kept));
        assert!(data.starts_with(&kept));
        assert!(data[kept.len()..].iter().all(|&b| b == 0));
    }
}

/// `parse_login_token`: a token, when returned, is `0.` and digits.
pub fn login(data: &[u8]) {
    if let Ok(t) = crate::login::parse_login_token(data) {
        let s = t.as_str();
        assert!(s.len() > 2 && s.starts_with("0.") && s[2..].bytes().all(|b| b.is_ascii_digit()));
    }
}

/// Differential mux → demux: tags generated from the bytes, muxed, then
/// demuxed, must come back field for field.
pub fn mux_demux(data: &[u8]) {
    let mut it = data.iter().copied();
    let ls = [1u8, 2, 4][it.next().unwrap_or(0) as usize % 3];
    let mut next = |n: usize| -> Vec<u8> { (0..n).map(|_| it.next().unwrap_or(0)).collect() };
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let mut want: Vec<(u32, Vec<Vec<u8>>, i32)> = Vec::new();
    let seq = avc_sequence_header_body(&[&[0x67, 0x42]], &[&[0x68, 0xce]], ls).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    for i in 1..=8u32 {
        let spec = next(2);
        if spec[0] == 0xFF {
            write_tag(&mut flv, TAG_VIDEO, i, &avc_end_of_sequence_body()).unwrap();
            want.push((i, vec![], 0));
            continue;
        }
        let count = 1 + spec[0] as usize % 4;
        let nals: Vec<Vec<u8>> = (0..count)
            .map(|_| {
                let len = 1 + next(1)[0] as usize % 40;
                let mut n = next(len);
                n[0] = 0x41;
                n
            })
            .collect();
        let ct = i32::from(spec[1] as i8);
        let refs: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, false, ct, &refs, ls).unwrap();
        write_tag(&mut flv, TAG_VIDEO, i, &body).unwrap();
        want.push((i, nals, ct));
    }
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    assert!(matches!(
        d.next_tag().unwrap().unwrap().body,
        TagBody::Video(VideoBody::SequenceHeader(_))
    ));
    for (ts, nals, ct) in want {
        let tag = d.next_tag().unwrap().unwrap();
        assert_eq!(tag.timestamp, ts);
        match tag.body {
            TagBody::Video(VideoBody::EndOfSequence) => assert!(nals.is_empty()),
            TagBody::Video(VideoBody::Nalus {
                composition_time,
                nals: got,
                ..
            }) => {
                assert_eq!(composition_time, ct);
                let got: Vec<Vec<u8>> = got.iter().map(|n| n.bytes.to_vec()).collect();
                assert_eq!(got, nals);
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(d.next_tag().unwrap().is_none());
}

/// Seed inputs for every target, derived from the committed fixtures:
/// `(target, file name, bytes)`. `scripts/fuzz.sh` writes them under
/// `target/` (they are regenerated, never committed); the unit test below
/// runs every target over them.
#[must_use]
pub fn seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
    let es3 = read("360p30_es3like_poc0.h264");
    let main = read("360p30_main_full.h264");
    let slices = read("360p30_main_slices.h264");
    let mut out = Vec::new();
    let flv = |data: &[u8], aus: usize, ls: u8, ct: i32, keep: fn(u8) -> bool| {
        let nals: Vec<&[u8]> = split_annex_b(data).collect();
        let sps = *nals.iter().find(|n| n[0] & 0x1F == 7).unwrap();
        let pps = *nals.iter().find(|n| n[0] & 0x1F == 8).unwrap();
        let mut f = Vec::new();
        write_flv_header(&mut f, false, true);
        write_tag(
            &mut f,
            TAG_VIDEO,
            0,
            &avc_sequence_header_body(&[sps], &[pps], ls).unwrap(),
        )
        .unwrap();
        for (i, au) in access_units(data).into_iter().take(aus).enumerate() {
            let au: Vec<&[u8]> = au.into_iter().filter(|n| keep(n[0] & 0x1F)).collect();
            let mut b = Vec::new();
            avc_nalu_body(&mut b, i == 0, ct, &au, ls).unwrap();
            write_tag(&mut f, TAG_VIDEO, i as u32 * 33, &b).unwrap();
        }
        f
    };
    let flvs = [
        ("es3.flv", flv(&es3, 8, 4, 16, |t| matches!(t, 1 | 5))),
        ("slices.flv", flv(&slices, 4, 1, 0, |t| t != 6)),
        (
            "ffmpeg_head.flv",
            read("360p30_main_full.flv")[..32 * 1024].to_vec(),
        ),
    ];
    for (name, bytes) in flvs {
        // flv_demux's first byte picks the chunk size: 0x10 = 257 bytes.
        out.push(("flv_demux", name.to_owned(), [&[0x10][..], &bytes].concat()));
        out.push(("admission", name.to_owned(), bytes));
    }
    // An in-band parameter-set flood at §6.2's per-tag cap (4 SPS, 16 PPS)
    // ahead of the ES3-like IDR; the fuzzer grows it past the cap (D10).
    let (es3_sps, es3_pps) = ES3_LIKE_PARAMS;
    let mut flood: Vec<&[u8]> = vec![es3_sps; 4];
    flood.extend(std::iter::repeat_n(es3_pps, 16));
    flood.extend(
        access_units(&es3)[0]
            .iter()
            .copied()
            .filter(|n| n[0] & 0x1F == 5),
    );
    let mut f = Vec::new();
    write_flv_header(&mut f, false, true);
    let seq = avc_sequence_header_body(&[es3_sps], &[es3_pps], 4).unwrap();
    write_tag(&mut f, TAG_VIDEO, 0, &seq).unwrap();
    let mut b = Vec::new();
    avc_nalu_body(&mut b, true, 16, &flood, 4).unwrap();
    write_tag(&mut f, TAG_VIDEO, 0, &b).unwrap();
    out.push(("admission", "inband_flood.flv".to_owned(), f));
    for (sel, name, pps) in [
        (0u8, "es3like", ES3_LIKE_PARAMS.1),
        (0, "es3_census", &ES3_PPS[..]),
        (1, "main", MAIN_360P_PARAMS.1),
    ] {
        out.push(("pps", name.to_owned(), [&[sel][..], pps].concat()));
    }
    out.push(("sanitize", "es3_census_pps".to_owned(), ES3_PPS.to_vec()));
    for (i, nal) in access_units(&main)[0].iter().enumerate() {
        out.push(("sanitize", format!("main_au0_{i}"), nal.to_vec()));
    }
    let first_au: Vec<u8> = access_units(&es3)[0]
        .iter()
        .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
        .flat_map(|n| [&(n.len() as u32).to_be_bytes()[..], n].concat())
        .collect();
    out.push((
        "avcc",
        "es3_idr".to_owned(),
        [&[2u8][..], &first_au].concat(),
    ));
    for (name, sps) in [
        ("es3_census", ES3_SPS.to_vec()),
        ("es3like", ES3_LIKE_PARAMS.0.to_vec()),
        ("main", MAIN_360P_PARAMS.0.to_vec()),
    ] {
        out.push(("sps_rewrite", name.to_owned(), sps));
    }
    for (sel, name, data) in [(0u8, "es3like", &es3), (1, "main", &main)] {
        let aus: Vec<u8> = access_units(data)
            .into_iter()
            .take(3)
            .flatten()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .flat_map(|n| [&[0u8, 0, 0, 1][..], n].concat())
            .collect();
        out.push(("slice", name.to_owned(), [&[sel][..], &aus].concat()));
    }
    out.push((
        "login",
        "ok".to_owned(),
        br#"{"result":0,"token":"0.123456789","role":"admin"}"#.to_vec(),
    ));
    out.push((
        "login",
        "refused".to_owned(),
        br#"{"result":"invalid password","code":200}"#.to_vec(),
    ));
    out.push((
        "mux_demux",
        "short".to_owned(),
        b"\x02\x03\x10seed".to_vec(),
    ));
    out.push(("mux_demux", "long".to_owned(), (0u8..=255).collect()));
    out
}

/// `census.md` `sps_hex`.
const ES3_SPS: [u8; 17] = [
    0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14, 0x08,
    0x00,
];
/// `census.md` `pps_hex`, trailing zeros included.
const ES3_PPS: [u8; 6] = [0x68, 0xce, 0x31, 0x12, 0x00, 0x00];

/// AUD-delimited access units (every committed fixture has AUDs).
fn access_units(data: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut aus: Vec<Vec<&[u8]>> = Vec::new();
    for nal in split_annex_b(data) {
        let has_vcl = aus
            .last()
            .is_some_and(|au| au.iter().any(|n| matches!(n[0] & 0x1F, 1 | 5)));
        if aus.is_empty() || (nal[0] & 0x1F == 9 && has_vcl) {
            aus.push(Vec::new());
        }
        aus.last_mut().unwrap().push(nal);
    }
    aus
}

/// Run `target`'s body on `data` (the fuzz binaries and the seed test).
pub fn run(target: &str, data: &[u8]) {
    match target {
        "flv_demux" => flv_demux(data),
        "admission" => admission(data),
        "avcc" => avcc(data),
        "sps_rewrite" => sps_rewrite(data),
        "pps" => pps(data),
        "sanitize" => sanitize(data),
        "slice" => slice(data),
        "login" => login(data),
        "mux_demux" => mux_demux(data),
        other => panic!("no fuzz target {other}"),
    }
}

/// Every target, for `scripts/fuzz.sh` and CI.
pub const TARGETS: [&str; 9] = [
    "flv_demux",
    "admission",
    "avcc",
    "sps_rewrite",
    "pps",
    "sanitize",
    "slice",
    "login",
    "mux_demux",
];
```

and create `crates/kvm-proto/examples/fuzz_seeds.rs`:

```rust
//! Write the fuzz seeds (`kvm_proto::fuzzing::seeds`) under DIR, one
//! subdirectory per target: `cargo run -p kvm-proto --features fuzzing
//! --example fuzz_seeds -- DIR`. DIR is required (scripts/fuzz.sh passes
//! `$CARGO_TARGET_DIR/fuzz-seeds`), so nothing lands in a per-worktree
//! `target/`.
fn main() -> std::io::Result<()> {
    let Some(dir) = std::env::args().nth(1) else {
        return Err(std::io::Error::other("usage: fuzz_seeds DIR"));
    };
    for (target, name, bytes) in kvm_proto::fuzzing::seeds() {
        let d = std::path::Path::new(&dir).join(target);
        std::fs::create_dir_all(&d)?;
        std::fs::write(d.join(name), bytes)?;
    }
    Ok(())
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-proto --lib fuzzing` — Expected: 2 passed.
Run: `cargo run -q -p kvm-proto --features fuzzing --example fuzz_seeds -- "$CARGO_TARGET_DIR/fuzz-seeds" && ls "$CARGO_TARGET_DIR/fuzz-seeds"` — Expected: nine directories, one per target (about 0.3 MB in all, in the shared target dir the devshell exports — never a per-worktree `target/`). Without a directory argument the example exits with `usage: fuzz_seeds DIR`.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-proto/src/fuzzing.rs crates/kvm-proto/src/lib.rs crates/kvm-proto/Cargo.toml crates/kvm-proto/examples/fuzz_seeds.rs
git commit -m "kvm-proto: fuzz-target bodies with §11.2 output invariants, and seeds" \
  -m "Every target runs over every seed on stable in cargo test; the libFuzzer wrappers come next." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7.2: The `fuzz/` workspace, the crash-reproduction shell and the bounded CI runner

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/fuzz/Cargo.toml`, `/home/chris/Repos/kvm-rdp/fuzz/rust-toolchain.toml`, `/home/chris/Repos/kvm-rdp/fuzz/fuzz_targets/{flv_demux,admission,avcc,sps_rewrite,pps,sanitize,slice,login,mux_demux}.rs`, `/home/chris/Repos/kvm-rdp/fuzz/Cargo.lock` (generated)
- Create: `/home/chris/Repos/kvm-rdp/scripts/fuzz.sh`
- Modify: `/home/chris/Repos/kvm-rdp/flake.nix` (the `fuzz` devshell), `/home/chris/Repos/kvm-rdp/.gitignore`

**Interfaces:**
- Consumes: `kvm_proto::fuzzing` (Task 7.1).
- Produces: `cargo fuzz` targets named as in `kvm_proto::fuzzing::TARGETS`; `nix develop .#fuzz` (nightly-2026-10-01 + cargo-fuzz 0.13.2 behind the same §13 wrapper, shared target dir) for reproducing a CI crash artifact only — no task here enters it; `scripts/fuzz.sh seeds | run [SECONDS] [TARGET…] | clean`, what CI runs — every run has `-max_total_time`, `-rss_limit_mb` and `-malloc_limit_mb` (`FUZZ_RSS_MB`, default 2048), `-max_len` (`FUZZ_MAX_LEN`, default 262144), `-timeout=10`, builds with `-a` (debug assertions and overflow checks) under ASan into `$CARGO_TARGET_DIR/fuzz-build`; it starts each target from a fresh corpus in `$CARGO_TARGET_DIR/fuzz-corpus` (`FUZZ_KEEP_CORPUS=1` keeps it, and a kept corpus over `FUZZ_CORPUS_MB`, default 64, is refused); seeds in `$CARGO_TARGET_DIR/fuzz-seeds`, generated by `seeds` with the stable toolchain only (`run` refuses to start without them, so nightly never builds kvm-proto's dev-dependencies); `clean` deletes corpus, seeds, the ASan build and `fuzz/artifacts`; `FUZZ_CARGO` overrides the cargo used for `cargo fuzz` (CI: `cargo +nightly-2026-10-01`).

- [ ] **Step 1: See the runner missing.**

Run: `FUZZ_CARGO='echo cargo' scripts/fuzz.sh run 5 login`
Expected: FAIL — the shell cannot find `scripts/fuzz.sh` (it does not exist yet).

- [ ] **Step 2: The workspace.** Create `fuzz/Cargo.toml`:

```toml
# Fuzz targets for kvm-proto (spec §4.1, §11.2): a separate cargo workspace
# on a pinned nightly (rust-toolchain.toml here), fuzzed only by
# scripts/fuzz.sh in CI (§13) — never by `cargo test`, never on a dev host.
# Each target is a one-liner over kvm_proto::fuzzing, which holds the bodies
# and their output invariants (and is exercised on stable by kvm-proto's own
# tests).
[package]
name = "kvm-proto-fuzz"
version = "0.0.0"
edition = "2024"
license = "MIT OR Apache-2.0"
publish = false

[package.metadata]
cargo-fuzz = true

[workspace]
members = ["."]

[dependencies]
libfuzzer-sys = "0.4.13"
kvm-proto = { path = "../crates/kvm-proto", features = ["fuzzing"] }

[profile.release]
debug = "line-tables-only"

[[bin]]
name = "flv_demux"
path = "fuzz_targets/flv_demux.rs"
test = false
doc = false
bench = false

[[bin]]
name = "admission"
path = "fuzz_targets/admission.rs"
test = false
doc = false
bench = false

[[bin]]
name = "avcc"
path = "fuzz_targets/avcc.rs"
test = false
doc = false
bench = false

[[bin]]
name = "sps_rewrite"
path = "fuzz_targets/sps_rewrite.rs"
test = false
doc = false
bench = false

[[bin]]
name = "pps"
path = "fuzz_targets/pps.rs"
test = false
doc = false
bench = false

[[bin]]
name = "sanitize"
path = "fuzz_targets/sanitize.rs"
test = false
doc = false
bench = false

[[bin]]
name = "slice"
path = "fuzz_targets/slice.rs"
test = false
doc = false
bench = false

[[bin]]
name = "login"
path = "fuzz_targets/login.rs"
test = false
doc = false
bench = false

[[bin]]
name = "mux_demux"
path = "fuzz_targets/mux_demux.rs"
test = false
doc = false
bench = false
```

`fuzz/rust-toolchain.toml`:

```toml
# fuzz/ only: libFuzzer + AddressSanitizer need nightly (spec §4.1). The same
# date as flake.nix's `fuzzToolchain` and CI's fuzz job.
[toolchain]
channel = "nightly-2026-10-01"
profile = "minimal"
```

and the nine targets — `fuzz/fuzz_targets/flv_demux.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::flv_demux(data));
```

`fuzz/fuzz_targets/admission.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::admission(data));
```

`fuzz/fuzz_targets/avcc.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::avcc(data));
```

`fuzz/fuzz_targets/sps_rewrite.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::sps_rewrite(data));
```

`fuzz/fuzz_targets/pps.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::pps(data));
```

`fuzz/fuzz_targets/sanitize.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::sanitize(data));
```

`fuzz/fuzz_targets/slice.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::slice(data));
```

`fuzz/fuzz_targets/login.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::login(data));
```

`fuzz/fuzz_targets/mux_demux.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::mux_demux(data));
```

- [ ] **Step 3: The crash-reproduction shell.** Replace `flake.nix` with (the `default` shell is unchanged apart from taking the wrapper as a function of its toolchain; `fuzz` is new):

```nix
{
  description = "kvm-rdp — RDP bridge for the ES3 IP-KVM (dev shell)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      rustToolchain = pkgs.rust-bin.stable."1.94.1".default.override {
        extensions = [ "rust-src" ];
      };

      # fuzz/ only (spec §4.1): libFuzzer + AddressSanitizer need nightly.
      # Pinned to a date present in flake.lock's rust-overlay, and the same
      # date as fuzz/rust-toolchain.toml.
      fuzzToolchain = pkgs.rust-bin.nightly."2026-10-01".minimal;

      # §13 cargo wrapper: cap CPU/IO/memory and nice the whole build.
      # Falls back to plain `nice` when there is no user systemd (e.g. CI).
      cargoWrapper = toolchain: pkgs.writeShellScriptBin "cargo" ''
        real=${toolchain}/bin/cargo
        if ${pkgs.systemd}/bin/systemctl --user show-environment >/dev/null 2>&1; then
          exec ${pkgs.systemd}/bin/systemd-run --user --scope -q \
            -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G \
            ${pkgs.coreutils}/bin/nice -n 19 "$real" "$@"
        else
          exec ${pkgs.coreutils}/bin/nice -n 19 "$real" "$@"
        fi
      '';

      # §13: one shared target dir for every worktree of this repo.
      sharedTarget = ''
        if [ -z "''${CARGO_TARGET_DIR:-}" ] && common=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
          export CARGO_TARGET_DIR="$(dirname "$common")/target"
        fi
      '';
    in
    {
      devShells.${system} = {
        default = pkgs.mkShell {
          # cargoWrapper first so its `cargo` shadows the toolchain's on PATH.
          packages = [
            (cargoWrapper rustToolchain)
            rustToolchain
            pkgs.cmake
            pkgs.pkg-config
            pkgs.ffmpeg-full
            pkgs.jq
            pkgs.bubblewrap
            pkgs.openssl # census step 2: `openssl s_client -brief` per TLS port
          ];

          KVM_RDP_FONT = "${pkgs.dejavu_fonts}/share/fonts/truetype/DejaVuSans.ttf";

          shellHook = ''
            ${sharedTarget}
            echo "kvm-rdp devshell: $(${rustToolchain}/bin/rustc --version)"
          '';
        };

        # `nix develop .#fuzz`: nightly + cargo-fuzz, same §13 wrapper. Only to
        # reproduce a CI fuzz crash (`cargo fuzz run --fuzz-dir fuzz --target-dir "$CARGO_TARGET_DIR/fuzz-build" -a T ARTIFACT`, the flags CI uses):
        # fuzzing itself runs in CI only (spec §13).
        fuzz = pkgs.mkShell {
          packages = [
            (cargoWrapper fuzzToolchain)
            fuzzToolchain
            pkgs.cargo-fuzz
          ];
          shellHook = ''
            ${sharedTarget}
            echo "kvm-rdp fuzz shell: $(${fuzzToolchain}/bin/rustc --version)"
          '';
        };
      };
    };
}
```

- [ ] **Step 4: The bounded runner.** Create `scripts/fuzz.sh` (then `chmod +x scripts/fuzz.sh`):

```bash
#!/usr/bin/env bash
# Bounded fuzzing of kvm-proto (spec §11.2, §13) — what CI runs. Fuzzing is
# CI-only (§13); a developer host never runs `run` as part of the build.
# Every run has a time cap, an RSS cap, an input-size cap and a per-input
# timeout, and starts from a fresh corpus (FUZZ_KEEP_CORPUS=1 keeps the last
# one, refused past FUZZ_CORPUS_MB). Corpus, seeds and the ASan build live
# under the shared target dir; `clean` deletes all three.
#   scripts/fuzz.sh seeds                     seeds from the committed fixtures
#   scripts/fuzz.sh run [SECONDS] [TARGET...] default 60 s per target, all targets
#   scripts/fuzz.sh clean                     delete corpus, seeds and fuzz build
# `run` needs nightly + cargo-fuzz: CI sets FUZZ_CARGO="cargo +nightly-2026-10-01"
# (rustup); `nix develop .#fuzz` provides both to reproduce a CI crash.
# `seeds` builds a kvm-proto example with the stable toolchain — rustup's
# rust-toolchain.toml in CI, the default devshell locally — never nightly.
set -euo pipefail
cd "$(dirname "$0")/.."
target_dir=${CARGO_TARGET_DIR:-$PWD/target}
seeds_dir=$target_dir/fuzz-seeds
corpus_dir=$target_dir/fuzz-corpus
build_dir=$target_dir/fuzz-build
all=(flv_demux admission avcc sps_rewrite pps sanitize slice login mux_demux)
read -ra fuzz_cargo <<<"${FUZZ_CARGO:-cargo}"
rss_mb=${FUZZ_RSS_MB:-2048}
max_len=${FUZZ_MAX_LEN:-262144}
corpus_mb=${FUZZ_CORPUS_MB:-64}

seeds() {
  rm -rf "$seeds_dir"
  nice -n 19 cargo run -q -p kvm-proto --features fuzzing --example fuzz_seeds -- "$seeds_dir"
}

run() {
  local secs=${1:-60}
  shift || true
  local targets=("$@")
  [ ${#targets[@]} -gt 0 ] || targets=("${all[@]}")
  if [ ! -d "$seeds_dir" ]; then
    echo "fuzz: no seeds; run scripts/fuzz.sh seeds first (stable toolchain)" >&2
    exit 1
  fi
  for t in "${targets[@]}"; do
    [ "${FUZZ_KEEP_CORPUS:-0}" = 1 ] || rm -rf "${corpus_dir:?}/$t"
    mkdir -p "$corpus_dir/$t" "$seeds_dir/$t"
    # The cap applies to a kept corpus, per target: a fresh corpus starts
    # empty, and other targets' corpora must not count against this one.
    if [ "${FUZZ_KEEP_CORPUS:-0}" = 1 ] && [ "$(du -sm "$corpus_dir/$t" | cut -f1)" -gt "$corpus_mb" ]; then
      echo "fuzz: kept corpus for $t over $corpus_mb MB; run scripts/fuzz.sh clean" >&2
      exit 1
    fi
    echo "fuzz: $t for ${secs}s (rss ${rss_mb} MB, max_len $max_len)"
    nice -n 19 "${fuzz_cargo[@]}" fuzz run --fuzz-dir fuzz --target-dir "$build_dir" -a "$t" \
      "$corpus_dir/$t" "$seeds_dir/$t" -- \
      -max_total_time="$secs" -rss_limit_mb="$rss_mb" -malloc_limit_mb="$rss_mb" \
      -max_len="$max_len" -timeout=10 -print_final_stats=1
    # A fresh corpus is scratch: drop it so later targets and the disk don't carry it.
    [ "${FUZZ_KEEP_CORPUS:-0}" = 1 ] || rm -rf "${corpus_dir:?}/$t"
  done
}

case "${1:-}" in
  seeds) seeds ;;
  run) shift; run "$@" ;;
  clean) rm -rf "$corpus_dir" "$seeds_dir" "$build_dir" fuzz/artifacts ;;
  *) echo "usage: $0 seeds | run [SECONDS] [TARGET...] | clean" >&2; exit 2 ;;
esac
```

and append to `.gitignore`:

```gitignore
# fuzzing (scripts/fuzz.sh): crash artifacts stay local until triaged; the
# corpus and seeds live under the shared target dir, never in the repo
/fuzz/artifacts/
/fuzz/corpus/
/fuzz/target/
```

- [ ] **Step 5: Check it without fuzzing** (fuzzing is CI-only, §13: nothing here downloads the nightly toolchain or builds ASan).

Run: `cargo check --manifest-path fuzz/Cargo.toml`
Expected: the nine targets check clean on the default shell's stable 1.94.1 (`fuzz/rust-toolchain.toml` only steers rustup, i.e. CI); this writes `fuzz/Cargo.lock`, and libFuzzer's C++ objects (~0.2 GB) land in the shared target dir.
Run: `FUZZ_CARGO='echo cargo' scripts/fuzz.sh run 5 login`
Expected: exit 1 with `fuzz: no seeds; run scripts/fuzz.sh seeds first (stable toolchain)`.
Run: `scripts/fuzz.sh seeds && FUZZ_CARGO='echo cargo' scripts/fuzz.sh run 5 login pps`
Expected: a dry run — for each target the line `fuzz: <target> for 5s (rss 2048 MB, max_len 262144)` and the exact command CI will run, printed instead of run: `cargo fuzz run --fuzz-dir fuzz --target-dir …/target/fuzz-build -a <target> …/target/fuzz-corpus/<target> …/target/fuzz-seeds/<target> -- -max_total_time=5 -rss_limit_mb=2048 -malloc_limit_mb=2048 -max_len=262144 -timeout=10 -print_final_stats=1`.
Run: `scripts/fuzz.sh clean && ls "$CARGO_TARGET_DIR" | grep fuzz`
Expected: nothing — corpus, seeds and the (absent) fuzz build are gone.
Run: `nix eval --raw .#devShells.x86_64-linux.fuzz.drvPath`
Expected: a `/nix/store/…-nix-shell.drv` path: the shell evaluates (instantiation only; nothing is fetched or built).
Run: `bash -n scripts/fuzz.sh && cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 6: Commit** (`fuzz/Cargo.lock` was written by Step 5's `cargo check`; commit it so CI fuzzes the same dependency versions):

```bash
git add fuzz/Cargo.toml fuzz/Cargo.lock fuzz/rust-toolchain.toml fuzz/fuzz_targets scripts/fuzz.sh flake.nix flake.lock .gitignore
git commit -m "fuzz/: nightly cargo-fuzz workspace, bounded scripts/fuzz.sh for CI, crash-reproduction shell (§11.2, §13)" \
  -m "Every run is capped in time, RSS, input size and per-input time, from a fresh, size-capped corpus; corpus, seeds and the ASan build under the shared target dir. Checked locally on stable only." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(`flake.lock` changes only if evaluating `.#fuzz` had to lock something new; it should not, since rust-overlay already carries the 2026-10-01 nightly.)

### Task 7.3: CI — 5 s per target on every PR, 300 s nightly, and the D8 gate

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (new `fuzz` job; a step in `check`)
- Create: `/home/chris/Repos/kvm-rdp/.github/workflows/fuzz-nightly.yml`

**Interfaces:**
- Consumes: `scripts/fuzz.sh` (Task 7.2), `rust-toolchain.toml` (1.94.1, which rustup uses for `scripts/fuzz.sh seeds`).
- Produces: a `fuzz` job on push to main and every PR (all nine targets, 5 s each, RSS-capped, `timeout-minutes: 30`), a scheduled `Fuzz (nightly)` workflow (300 s each, `timeout-minutes: 75`, also `workflow_dispatch`); both generate seeds on stable before fuzzing on nightly and upload `fuzz/artifacts` on failure. The `check` job gains the D8 gate: it fails if any workspace crate enables `kvm-proto/fuzzing`.

- [ ] **Step 1: Add the PR job and the D8 gate.** Append to the `jobs:` map in `.github/workflows/ci.yml`:

```yaml
  fuzz:
    # Bounded fuzzing of kvm-proto (spec §11.2, §13 — CI only): every target
    # for 5 s, RSS-capped by scripts/fuzz.sh. Longer runs are the nightly
    # workflow's.
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: nightly-2026-10-01
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: 1.94.1
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked --version 0.13.2
      - name: Seeds, on stable (rust-toolchain.toml)
        run: scripts/fuzz.sh seeds
      - name: Fuzz every target for 5 s
        env:
          FUZZ_CARGO: cargo +nightly-2026-10-01
        run: scripts/fuzz.sh run 5
      - name: Keep any crash
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts
```

and append this step to the `check` job's `steps:` (after the ring gate):

```yaml
      - name: kvm-proto/fuzzing stays out of the workspace graph (Plan B D8)
        run: |
          # kvm_proto::fuzzing panics by design; only fuzz/ (its own
          # workspace) may enable the feature. --all-features above compiles
          # it for clippy and the seed tests; this checks no crate asks for it.
          if cargo tree --workspace -e features -i kvm-proto | grep -q 'feature "fuzzing"'; then
            echo "::error::a workspace crate enables kvm-proto's fuzzing feature (Plan B D8)"
            exit 1
          fi
```

- [ ] **Step 2: Add the nightly workflow.** Create `.github/workflows/fuzz-nightly.yml`:

```yaml
name: Fuzz (nightly)

on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: "0"
  CARGO_BUILD_JOBS: "4"

jobs:
  fuzz:
    runs-on: ubuntu-latest
    # Nine targets × 300 s (45 min) plus the ASan build and the seeds.
    timeout-minutes: 75
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: nightly-2026-10-01
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: 1.94.1
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked --version 0.13.2
      - name: Seeds, on stable (rust-toolchain.toml)
        run: scripts/fuzz.sh seeds
      - name: Fuzz every target for 300 s
        env:
          FUZZ_CARGO: cargo +nightly-2026-10-01
        run: scripts/fuzz.sh run 300
      - name: Keep any crash
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts
```

- [ ] **Step 3: Check them** (statically — the first real fuzz run is CI's, on the PR that carries this task, or a `workflow_dispatch` of the nightly).

Run: `nix shell --inputs-from . nixpkgs#actionlint -c actionlint .github/workflows/ci.yml .github/workflows/fuzz-nightly.yml`
Expected: no findings (`--inputs-from .` takes actionlint from flake.lock's pinned nixpkgs, 1.7.12 — no floating registry fetch).
Run: `cargo tree --workspace -e features -i kvm-proto | grep -c 'feature "fuzzing"'`
Expected: `0` — the D8 gate passes on this workspace.

- [ ] **Step 4: Commit.**

```bash
git add .github/workflows/ci.yml .github/workflows/fuzz-nightly.yml
git commit -m "CI: fuzz every kvm-proto target 5 s per PR, 300 s nightly; gate kvm-proto/fuzzing (D8)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 8 — kvm-sim (Milestone 2)

The fake ES3 the bridge's L2/L3 tests and kvm-bench run against (§10.2, §11.3, §11.5). Plans C–E depend on exactly this API (each row's last column names the test that pins it, so a broken hook fails here, not in Plan C):

| Need (spec) | kvm-sim API | Pinned by |
|---|---|---|
| Pin and address the KVM (§3.2, §4.4) | `async KvmSim::start(SimConfig) -> io::Result<KvmSim>`, `host()`, `ports() -> SimPorts { web, video, control }`, `spki_sha256()`, `password()` | 8.3 `one_certificate_pins_all_three_ports` |
| "zero new TCP accepts on all its ports", login/logout counts, "never two concurrent websockets", "open-connection gauge reaches 0" (§11.3) | `stats() -> SimStats { accepts_web, accepts_video, accepts_control, logins_ok, logins_failed, logouts, flv_open, ws_open, ws_max_open, frames_sent, frames_dropped, events_dropped, max_flv_write_block }` | 8.3 login tests; 8.4, 8.6 |
| Exact orders ("release-all → websocket close → FLV close → login → websocket open → session-start sequence"), byte-exact HID frames, FrameId → (seq, `sim_tx`) (§10.1, §10.2, §11.3) | `events() -> Vec<SimEvent>`, `stamped_events() -> Vec<(Instant, SimEvent)>` (`FlvAu`'s instant is `sim_tx`), `wait_for(timeout, pred)` (`pred` runs on the log in place; the log keeps 1 000 000 events, then counts `events_dropped`); `SimEvent::{Accept, Login, Logout, FlvOpen, FlvRefused, FlvClose, FlvAu { conn, seq, source_index, frame_id, idr }, WsOpen, WsRefused, WsClose, Hid { conn, bytes }}` | 8.4 `sim_tx_follows_the_send_order_and_a_reader_never_blocks_a_write`; 8.6 `hid_frames_are_recorded_verbatim` |
| §10.2 "no kvm-sim FLV write blocks for more than 100 ms" | `stats().max_flv_write_block` | 8.4 `sim_tx_follows…` |
| Token expiry, another session's logout, auth failure (incl. a second consecutive one), side connections refused, HTTP 5xx, a blocked websocket write (§11.3 faults) | `expire_tokens()`, the `/cgi-bin/login.lua?logout` endpoint (global), `set_policy(f)` (`f: impl FnOnce(&mut Policy)`) with `Policy { reject_logins, flv_status, refuse_concurrent_flv, ws_status, pause_ws_reads, skip_sequence_header, blackhole }`, `SimConfig::control_recv_buffer` | 8.3 `a_rejecting_policy_fails_even_the_right_password`; 8.4 `logout_is_global_but_open_streams_survive`, `expired_tokens_are_refused_without_a_logout`, `a_policy_status_refuses_the_stream` (503, 401), `bad_tokens_and_refused_side_connections`; 8.6 `a_policy_status_refuses_the_upgrade`, `paused_reads_back_up_the_clients_writes_until_resumed` |
| KVM unreachable (disconnect at the deadline, §11.3) | `Policy::blackhole`: new TCP connections are accepted and then left silent (no TLS, no bytes) until the client gives up — the sim and its event log stay alive, and no loopback port is freed for a parallel test to reuse | 8.3 `an_unreachable_kvm_accepts_and_never_answers` |
| Framing and stream faults, end of sequence, FLV drop or silence (§11.3) | `inject(Fault::{OversizeTag, BadPrevTagSize, EncryptedTag, BadStreamId, HevcCodecId, EnhancedHevc, CompositionTime(i32), TwoPictures, BSlice, StartCodeInNal, ForbiddenBit, EndOfSequence, TooManyNals, Close, Silence})` | 8.5 `each_fault_is_its_own_section_6_9_refusal` (full `AdmissionError`s), `silence_keeps_the_flv_open_and_sends_nothing` |
| Websocket drop, 64 MiB message (§11.3) | `close_websockets()`, `send_ws_oversize(declared_len)` | 8.6 `closing_and_oversize_faults_reach_the_client` |
| Resolution change three ways (§6.4, §11.3) | `switch_source(Source, ResizeSignal::{SequenceHeader, InBandSps, CloseFlv})`. The profile is pinned (§6.1), and the only second-size fixture, `480p30_main_full`, is Main: **resize cases start from a Main source** — `360p30_main_full.h264` → `480p30_main_full.h264` under `Profile::es3()` — never from the ES3-like Baseline default, which a switch to 480p would end as `PinnedFieldChanged(ProfileIdc)` | 8.4 `resolution_change_by_each_signal` |
| A viewer that stops reading (§4.3, §10.2) | per-viewer 512-frame queues; `SimConfig::video_send_buffer` (`SO_SNDBUF` on video sockets) makes the stalled writer block after little data | 8.2 `a_full_viewer_queue_drops_only_that_viewers_frames`; 8.4 `a_viewer_that_stops_reading_does_not_stall_the_others` |
| Display sleep (§6.1) | `set_signal(false)` — the NO SIGNAL card | 8.2, 8.4 `no_signal_card_admits_without_a_params_change` |
| Deterministic tests vs real time; bench streams (§10.2) | `Pacing::{Manual, RealTime}` + `advance(frames)`; `Source::fixture(name)` / `Source::from_annex_b(name, bytes)` for on-demand `target/` streams | every test |
| The ES3 itself (`census.md` Artifacts) | `Profile::es3()` (30 fps, AVCC 4, CT 16, no burst, shared encoder whose forced IDR restarts the GOP, NAL types 1 and 5 only, a sequence header whose SPS and PPS end in the device's zero bytes), `SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264")?)` | 8.2 `a_new_viewer_forces_an_idr_into_every_open_stream`; 8.4 `es3_tag_shape_on_the_wire_and_the_bridge_admits_it`; 8.7 conformance |

### Task 8.1: The crate and `Source`

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/Cargo.toml`, `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/source.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/main.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/source.rs`
- Test: `tests/sim/source.rs`

**Interfaces:**
- Consumes: `kvm_proto::h264::{split_annex_b, parse_slice_header_prefix}`; the committed fixtures.
- Produces (`kvm_sim`): `pub struct Frame { index: usize, idr: bool, nals: Vec<Bytes> }`; `pub struct Source { name: String, sps: Bytes, pps: Bytes, frames: Vec<Frame>, gop_starts: Vec<usize> }` with `fixture(name: &str) -> Result<Source, SourceError>`, `from_annex_b(name: &str, data: &[u8]) -> Result<Source, SourceError>` (access units per H.264 7.4.1.2.3) and `next_gop_start(&self, index: usize) -> usize`; `pub enum SourceError { Io(io::Error), NoParameterSets, NotIdrFirst }`; `pub fn fixtures_dir() -> PathBuf`. The crate is a workspace member through `crates/*`; its manifest already lists every dependency Part 8 uses (aws-lc-rs only: rustls, tokio-rustls and rcgen with default features off).

- [ ] **Step 1: Write the failing tests.** Create `crates/kvm-sim/Cargo.toml`:

```toml
[package]
name = "kvm-sim"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false
autotests = false

[lib]
doctest = false

[dependencies]
kvm-proto = { path = "../kvm-proto" }
bytes = { workspace = true }
sha2 = { workspace = true }
serde_json = { workspace = true }
httparse = "1.10"
futures-util = { version = "0.3", default-features = false, features = ["sink"] }
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "macros", "time", "sync"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std"] }
tokio-tungstenite = { version = "0.24", default-features = false, features = ["handshake"] }
rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs"] }

[dev-dependencies]
kvm-probe = { path = "../kvm-probe" }
tempfile = "3"

[[test]]
name = "sim"
path = "tests/sim/main.rs"
```

`crates/kvm-sim/src/lib.rs`:

```rust
//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

mod source;

pub use source::{Frame, Source, SourceError, fixtures_dir};
```

`crates/kvm-sim/tests/sim/main.rs`:

```rust
//! kvm-sim's own tests (one binary, §13).
mod source;
```

and `crates/kvm-sim/tests/sim/source.rs`:

```rust
use kvm_sim::Source;

#[test]
fn es3like_fixture_splits_into_120_frames_in_two_gops() {
    let s = Source::fixture("360p30_es3like_poc0.h264").unwrap();
    assert_eq!(s.frames.len(), 120);
    assert_eq!(s.gop_starts, [0, 60]);
    assert_eq!(s.sps[0] & 0x1F, 7);
    assert_eq!(s.pps[0] & 0x1F, 8);
    assert!(s.frames.iter().all(|f| {
        f.nals
            .iter()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .count()
            == 1
    }));
    assert_eq!(
        (
            s.next_gop_start(0),
            s.next_gop_start(59),
            s.next_gop_start(60)
        ),
        (60, 60, 0)
    );
}

#[test]
fn multi_slice_access_units_stay_whole() {
    let s = Source::fixture("360p30_main_slices.h264").unwrap();
    assert_eq!(s.frames.len(), 90);
    assert!(s.frames.iter().any(|f| {
        f.nals
            .iter()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .count()
            > 3
    }));
    assert_eq!(s.gop_starts, [0, 30, 60]);
}

#[test]
fn a_stream_must_start_with_an_idr() {
    let data = std::fs::read(kvm_sim::fixtures_dir().join("360p30_main_full.h264")).unwrap();
    // Drop everything up to the second access unit delimiter: a P frame first.
    let second_aud = data
        .windows(5)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 0, 1, 0x09])
        .nth(1)
        .unwrap()
        .0;
    assert!(matches!(
        Source::from_annex_b("cut", &data[second_aud..]),
        Err(kvm_sim::SourceError::NotIdrFirst)
    ));
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim`
Expected: FAIL to compile — `file not found for module source` (`src/source.rs` does not exist yet).

- [ ] **Step 3: Implement.** Create `crates/kvm-sim/src/source.rs`:

```rust
//! A video source for the simulated encoder: a committed Annex-B fixture
//! split into access units (trusted input — never a KVM capture).
use bytes::Bytes;
use kvm_proto::h264::split_annex_b;
use std::path::{Path, PathBuf};

/// One access unit of the source, NALs without start codes, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Index of this frame in the source (the fixture's barcode counter).
    pub index: usize,
    pub idr: bool,
    pub nals: Vec<Bytes>,
}

/// A looping stream of frames plus the parameter sets for its sequence header.
#[derive(Debug, Clone)]
pub struct Source {
    pub name: String,
    pub sps: Bytes,
    pub pps: Bytes,
    pub frames: Vec<Frame>,
    /// Indices into `frames` of every IDR (GOP starts), ascending.
    pub gop_starts: Vec<usize>,
}

#[derive(Debug)]
pub enum SourceError {
    Io(std::io::Error),
    NoParameterSets,
    /// The stream is empty or does not start with an IDR.
    NotIdrFirst,
}

fn nal_type(n: &[u8]) -> u8 {
    n.first().map_or(0, |b| b & 0x1F)
}

/// The committed `fixtures/` directory of this repository.
#[must_use]
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

impl Source {
    /// Load `fixtures/<name>`.
    pub fn fixture(name: &str) -> Result<Source, SourceError> {
        let data = std::fs::read(fixtures_dir().join(name)).map_err(SourceError::Io)?;
        Source::from_annex_b(name, &data)
    }

    /// Split an Annex-B stream into access units (H.264 7.4.1.2.3): once the
    /// current AU has a slice, an SEI, SPS, PPS, AUD or type 14–18 NAL, or a
    /// slice with `first_mb_in_slice == 0`, starts the next one.
    pub fn from_annex_b(name: &str, data: &[u8]) -> Result<Source, SourceError> {
        let mut sps = None;
        let mut pps = None;
        let mut aus: Vec<Vec<Bytes>> = Vec::new();
        let mut current: Vec<Bytes> = Vec::new();
        let mut has_vcl = false;
        for nal in split_annex_b(data) {
            let t = nal_type(nal);
            let starts_picture = matches!(t, 1 | 5)
                && kvm_proto::h264::parse_slice_header_prefix(nal)
                    .is_ok_and(|p| p.first_mb_in_slice == 0);
            if has_vcl && (matches!(t, 6..=9 | 14..=18) || starts_picture) {
                aus.push(std::mem::take(&mut current));
                has_vcl = false;
            }
            match t {
                7 if sps.is_none() => sps = Some(Bytes::copy_from_slice(nal)),
                8 if pps.is_none() => pps = Some(Bytes::copy_from_slice(nal)),
                _ => {}
            }
            has_vcl |= matches!(t, 1 | 5);
            current.push(Bytes::copy_from_slice(nal));
        }
        if has_vcl {
            aus.push(current);
        }
        let frames: Vec<Frame> = aus
            .into_iter()
            .enumerate()
            .map(|(index, nals)| Frame {
                index,
                idr: nals.iter().any(|n| nal_type(n) == 5),
                nals,
            })
            .collect();
        if !frames.first().is_some_and(|f| f.idr) {
            return Err(SourceError::NotIdrFirst);
        }
        let gop_starts = frames.iter().filter(|f| f.idr).map(|f| f.index).collect();
        Ok(Source {
            name: name.to_owned(),
            sps: sps.ok_or(SourceError::NoParameterSets)?,
            pps: pps.ok_or(SourceError::NoParameterSets)?,
            frames,
            gop_starts,
        })
    }

    /// The first GOP start after `index`, wrapping to the first.
    #[must_use]
    pub fn next_gop_start(&self, index: usize) -> usize {
        self.gop_starts
            .iter()
            .copied()
            .find(|&s| s > index)
            .unwrap_or(0)
    }
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 3 passed.
Run: `cargo tree --workspace --target all -i ring` — Expected: nothing printed (or "did not match any packages"); CI's ring gate stays green.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-sim Cargo.lock
git commit -m "kvm-sim: crate and Source — committed fixtures as looping frames and GOPs" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.2: Shared state and the shared encoder

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/state.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/encoder.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs`
- Test: `crates/kvm-sim/src/encoder.rs` (`tests`)

**Interfaces:**
- Consumes: `Source` (Task 8.1).
- Produces: (`kvm_sim`) `pub struct Profile { fps: u32, length_size: u8, composition_time_ms: i32, burst_on_connect: bool, idr_on_new_connection: bool, inband_params: bool, aud: bool, sei: bool, padded_param_sets: bool }` with `Profile::es3()`; `pub enum Pacing { RealTime, Manual }`; `pub enum ResizeSignal { SequenceHeader, InBandSps, CloseFlv }`; `pub enum Fault { … }` (the fifteen variants in the table above); `pub enum PortKind { Web, Video, Control }`, `pub enum SimEvent`, `pub struct SimStats`, `pub struct Policy` (as in the table). Crate-internal: `Shared` (event log — events and their instants in two `Vec`s, capped at 1 000 000 then only counted in `SimStats::events_dropped` — stats, tokens, policy, websocket commands, and `wait_for`, whose predicate runs on the log under the lock so a wake-up copies nothing), `WsCmd`, `encoder::{spawn, EncoderHandle, Item, OutFrame, Subscription}` — `spawn(Source, Profile, Pacing, Arc<Shared>) -> (EncoderHandle, JoinHandle<()>)`; `EncoderHandle::{subscribe, advance, signal, switch, inject}`; each viewer gets a 512-frame queue and frames it has no room for are dropped and counted.

- [ ] **Step 1: Write the failing tests.** Replace `crates/kvm-sim/src/lib.rs` with this (the `allow(dead_code)` on `encoder` comes off in Task 8.5 and the one on `state` in Task 8.6, when av.flv's faults and the websocket are their last users):

```rust
//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

// Wired into `KvmSim` by Tasks 8.3–8.6; until then only the unit tests use them.
#[allow(dead_code)]
mod encoder;
mod source;
#[allow(dead_code)]
mod state;

pub use source::{Frame, Source, SourceError, fixtures_dir};
pub use state::{Policy, PortKind, SimEvent, SimStats};

/// The stream's shape on the wire (`census.md`, Artifacts: kvm-sim profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Nominal frame rate: FLV timestamps and real-time pacing.
    pub fps: u32,
    /// AVCC NAL length size: 1, 2 or 4.
    pub length_size: u8,
    /// `CompositionTime` on every coded tag (0 on the sequence header).
    pub composition_time_ms: i32,
    /// A new FLV connection replays the GOP so far at once (a GOP-caching
    /// source; the ES3 does not).
    pub burst_on_connect: bool,
    /// Shared encoder: any new FLV connection forces an IDR into every open
    /// stream and restarts the GOP.
    pub idr_on_new_connection: bool,
    /// Keep in-band SPS/PPS in coded tags (the ES3 sends them only in the
    /// sequence header).
    pub inband_params: bool,
    /// Keep AUDs (the ES3 sends none).
    pub aud: bool,
    /// Keep SEI (the ES3 sends none).
    pub sei: bool,
    /// Append the ES3's trailing zero bytes to the sequence header's
    /// parameter sets — one after the SPS, two after the PPS — as the device
    /// does (`census.md` `sps_hex`, `pps_hex`).
    pub padded_param_sets: bool,
}

impl Profile {
    /// The ES3 as measured (`census.md`, Leg A — stream): 30 fps, length size
    /// 4, `CompositionTime` 16, no burst, shared encoder, tag = AU carrying
    /// only NAL types 1 and 5, and a sequence header whose SPS and PPS end in
    /// zero bytes.
    #[must_use]
    pub fn es3() -> Profile {
        Profile {
            fps: 30,
            length_size: 4,
            composition_time_ms: 16,
            burst_on_connect: false,
            idr_on_new_connection: true,
            inband_params: false,
            aud: false,
            sei: false,
            padded_param_sets: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// One frame every `1 / Profile::fps`, never catching up (the ES3 sends
    /// one tag every 33 ms whether the screen moves or not).
    RealTime,
    /// Frames only on [`KvmSim::advance`]: deterministic tests.
    Manual,
}

/// How a source switch reaches viewers (§6.4, §11.3 resolution change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeSignal {
    /// A new sequence header on every open FLV.
    SequenceHeader,
    /// The new SPS/PPS in-band in the next IDR's tag.
    InBandSps,
    /// Every open FLV closes (the ES3's observed preset change); new
    /// connections get the new source.
    CloseFlv,
}

/// One-shot faults, applied by every open FLV to its next tag (§6.9 cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OversizeTag,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    HevcCodecId,
    EnhancedHevc,
    /// The next coded tag's `CompositionTime`.
    CompositionTime(i32),
    /// The next two pictures in one tag.
    TwoPictures,
    BSlice,
    StartCodeInNal,
    ForbiddenBit,
    /// An `AVCPacketType 2` tag, now.
    EndOfSequence,
    /// 129 NALs in one tag.
    TooManyNals,
    /// Close every open FLV, now.
    Close,
    /// Stop writing on every open FLV, keeping it open.
    Silence,
}
```

and create `crates/kvm-sim/src/encoder.rs` with its test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Source;

    fn es3() -> (EncoderHandle, Arc<Shared>) {
        let shared = Arc::new(Shared::default());
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let (enc, _task) = spawn(src, Profile::es3(), Pacing::Manual, shared.clone());
        (enc, shared)
    }

    /// Everything queued for a viewer right now: `(seq, idr, NAL types)`.
    async fn drain(enc: &EncoderHandle, sub: &mut Subscription) -> Vec<(u64, bool, Vec<u8>)> {
        enc.sync().await;
        let mut out = Vec::new();
        while let Ok(item) = sub.rx.try_recv() {
            if let Item::Frame(f) = item {
                out.push((f.seq, f.idr, f.nals.iter().map(|n| n[0] & 0x1F).collect()));
            }
        }
        out
    }

    #[tokio::test]
    async fn a_new_viewer_forces_an_idr_into_every_open_stream() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(10);
        let first = drain(&enc, &mut a).await;
        assert_eq!(first.len(), 10);
        assert!(first[0].1 && first[1..].iter().all(|f| !f.1));
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(2);
        let (a2, b2) = (drain(&enc, &mut a).await, drain(&enc, &mut b).await);
        assert_eq!(a2, b2, "one encoder: both viewers get the same frames");
        assert_eq!((a2[0].0, a2[0].1, a2[1].1), (10, true, false));
        // The forced IDR restarts the GOP: the next IDR is 60 frames later
        // (seq 70), not on the old cadence (seq 60).
        enc.advance(60);
        let rest = drain(&enc, &mut a).await;
        let idrs: Vec<u64> = first
            .iter()
            .chain(&a2)
            .chain(&rest)
            .filter(|f| f.1)
            .map(|f| f.0)
            .collect();
        assert_eq!(idrs, [0, 10, 70]);
    }

    #[tokio::test]
    async fn the_gop_is_the_source_gop_and_es3_frames_carry_only_slices() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(121);
        let f = drain(&enc, &mut a).await;
        let idrs: Vec<u64> = f.iter().filter(|f| f.1).map(|f| f.0).collect();
        assert_eq!(idrs, [0, 60, 120]);
        assert!(f.iter().all(|f| f.2 == [if f.1 { 5 } else { 1 }]));
    }

    #[tokio::test]
    async fn no_signal_is_all_intra_and_the_signal_returns_on_an_idr() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(5);
        enc.signal(false);
        enc.advance(4);
        enc.signal(true);
        enc.advance(2);
        let idr: Vec<bool> = drain(&enc, &mut a).await.iter().map(|f| f.1).collect();
        assert_eq!(
            idr,
            [
                true, false, false, false, false, true, true, true, true, true, false
            ]
        );
    }

    #[tokio::test]
    async fn a_gop_caching_profile_replays_the_gop_so_far_to_a_new_viewer() {
        let shared = Arc::new(Shared::default());
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let profile = Profile {
            burst_on_connect: true,
            idr_on_new_connection: false,
            ..Profile::es3()
        };
        let (enc, _task) = spawn(src, profile, Pacing::Manual, shared);
        let _a = enc.subscribe().await.unwrap();
        enc.advance(7);
        let mut b = enc.subscribe().await.unwrap();
        let replay = drain(&enc, &mut b).await;
        assert_eq!(
            replay.iter().map(|f| f.0).collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        assert!(replay[0].1);
    }

    #[tokio::test]
    async fn a_full_viewer_queue_drops_only_that_viewers_frames() {
        let (enc, shared) = es3();
        let mut a = enc.subscribe().await.unwrap();
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(512);
        assert_eq!(drain(&enc, &mut a).await.len(), 512);
        enc.advance(100); // b never drained: its queue is full
        assert_eq!(drain(&enc, &mut a).await.len(), 100);
        assert_eq!(shared.stats().frames_dropped, 100);
        assert_eq!(drain(&enc, &mut b).await.len(), 512);
    }

    #[tokio::test]
    async fn faults_and_source_switches_reach_every_viewer_in_order() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(1);
        enc.inject(Fault::Close);
        let other = Source::fixture("480p30_main_full.h264").unwrap();
        let sps = other.sps.clone();
        enc.switch(other, ResizeSignal::SequenceHeader);
        enc.advance(1);
        enc.sync().await;
        let kinds: Vec<String> = std::iter::from_fn(|| a.rx.try_recv().ok())
            .map(|i| match i {
                Item::Frame(f) => format!("frame {} idr {}", f.seq, f.idr),
                Item::Fault(f) => format!("{f:?}"),
                Item::Params { sps: s, signal, .. } => format!("params {} {signal:?}", s == sps),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "frame 0 idr true",
                "Close",
                "params true SequenceHeader",
                "frame 1 idr true"
            ]
        );
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim --lib`
Expected: FAIL to compile — `file not found for module state`, then `cannot find function spawn` / types `EncoderHandle`, `Subscription`, `Item`, `Shared`.

- [ ] **Step 3: Implement.** Create `crates/kvm-sim/src/state.rs`:

```rust
//! State shared by kvm-sim's listeners and its test-facing handle: the
//! event log, counters, live tokens and the fault policy.
use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};

/// Which of the three ES3 service ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortKind {
    /// Login/logout (443 on the ES3).
    Web,
    /// `av.flv` (8881).
    Video,
    /// The control websocket (8889).
    Control,
}

/// Everything kvm-sim observed, in order. L2 tests assert on these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEvent {
    /// A TCP connection was accepted (before TLS).
    Accept {
        port: PortKind,
    },
    Login {
        ok: bool,
    },
    /// `GET /cgi-bin/login.lua?logout`: every token was invalidated.
    Logout,
    FlvOpen {
        conn: u64,
    },
    FlvRefused {
        status: u16,
    },
    FlvClose {
        conn: u64,
    },
    /// One coded tag written; `at` of the stamped event is `sim_tx` (the
    /// moment `write_all` of its last byte returned, §10.1).
    FlvAu {
        conn: u64,
        seq: u64,
        /// The source frame's index: the fixture's barcode value.
        source_index: usize,
        frame_id: u64,
        idr: bool,
    },
    WsOpen {
        conn: u64,
    },
    WsRefused {
        status: u16,
    },
    WsClose {
        conn: u64,
    },
    /// One websocket data message, verbatim (§3.3 HID frames).
    Hid {
        conn: u64,
        bytes: Vec<u8>,
    },
}

/// Counters and gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimStats {
    pub accepts_web: u64,
    pub accepts_video: u64,
    pub accepts_control: u64,
    pub logins_ok: u64,
    pub logins_failed: u64,
    pub logouts: u64,
    pub flv_open: u64,
    pub ws_open: u64,
    pub ws_max_open: u64,
    pub frames_sent: u64,
    /// Frames a viewer's queue had no room for (it was not reading).
    pub frames_dropped: u64,
    /// Events past the log's cap (`MAX_EVENTS`): counted, not recorded.
    pub events_dropped: u64,
    /// Longest single FLV `write_all` (§10.2: never above 100 ms).
    pub max_flv_write_block: Duration,
}

/// Behaviour switches a test flips at any time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Every login answers `result` ≠ 0.
    pub reject_logins: bool,
    /// Answer `av.flv` with this HTTP status instead of a stream.
    pub flv_status: Option<u16>,
    /// A second concurrent `av.flv` gets 503 (side connections refused).
    pub refuse_concurrent_flv: bool,
    /// Answer the websocket upgrade with this HTTP status.
    pub ws_status: Option<u16>,
    /// Stop reading websockets (the bridge's writes back up).
    pub pause_ws_reads: bool,
    /// New FLV connections start with a NALU tag, no sequence header.
    pub skip_sequence_header: bool,
    /// New TCP connections are accepted, then left silent — no TLS, no
    /// bytes — until the client gives up: an unreachable KVM (§11.3).
    pub blackhole: bool,
}

/// A command for every open websocket.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WsCmd {
    Close,
    /// Write a frame header declaring this payload length, then 4 KiB.
    Oversize(u64),
}

#[derive(Default)]
struct Inner {
    events: Vec<SimEvent>,
    /// When each of `events` was recorded (`FlvAu`: `sim_tx`).
    stamps: Vec<Instant>,
    stats: SimStats,
    tokens: HashSet<String>,
    next_token: u64,
    policy: Policy,
    ws: Vec<mpsc::UnboundedSender<WsCmd>>,
}

/// Cap on recorded events (a 1 h soak at 30 fps is ~110 k; the cap is at
/// most ~70 MB of log). Past it, events are only counted.
const MAX_EVENTS: usize = 1_000_000;

#[derive(Default)]
pub(crate) struct Shared {
    inner: Mutex<Inner>,
    changed: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn record(&self, event: SimEvent) {
        self.record_at(Instant::now(), event);
    }

    pub(crate) fn record_at(&self, at: Instant, event: SimEvent) {
        {
            let mut g = self.lock();
            let s = &mut g.stats;
            match &event {
                SimEvent::Accept { port } => match port {
                    PortKind::Web => s.accepts_web += 1,
                    PortKind::Video => s.accepts_video += 1,
                    PortKind::Control => s.accepts_control += 1,
                },
                SimEvent::Login { ok: true } => s.logins_ok += 1,
                SimEvent::Login { ok: false } => s.logins_failed += 1,
                SimEvent::Logout => s.logouts += 1,
                SimEvent::FlvOpen { .. } => s.flv_open += 1,
                SimEvent::FlvClose { .. } => s.flv_open = s.flv_open.saturating_sub(1),
                SimEvent::FlvAu { .. } => s.frames_sent += 1,
                SimEvent::WsOpen { .. } => {
                    s.ws_open += 1;
                    s.ws_max_open = s.ws_max_open.max(s.ws_open);
                }
                SimEvent::WsClose { .. } => s.ws_open = s.ws_open.saturating_sub(1),
                _ => {}
            }
            if g.events.len() < MAX_EVENTS {
                g.events.push(event);
                g.stamps.push(at);
            } else {
                g.stats.events_dropped += 1;
            }
        }
        self.changed.notify_waiters();
    }

    pub(crate) fn frame_dropped(&self) {
        self.lock().stats.frames_dropped += 1;
    }

    pub(crate) fn write_blocked(&self, d: Duration) {
        let mut g = self.lock();
        g.stats.max_flv_write_block = g.stats.max_flv_write_block.max(d);
    }

    pub(crate) fn events(&self) -> Vec<SimEvent> {
        self.lock().events.clone()
    }

    pub(crate) fn stamped_events(&self) -> Vec<(Instant, SimEvent)> {
        let g = self.lock();
        g.stamps
            .iter()
            .copied()
            .zip(g.events.iter().cloned())
            .collect()
    }

    pub(crate) fn stats(&self) -> SimStats {
        self.lock().stats.clone()
    }

    pub(crate) fn policy(&self) -> Policy {
        self.lock().policy.clone()
    }

    pub(crate) fn set_policy(&self, f: impl FnOnce(&mut Policy)) {
        f(&mut self.lock().policy);
    }

    /// Mint a `0.<digits>` token (§3.1); logins coexist (§3.2).
    pub(crate) fn mint_token(&self) -> String {
        let mut g = self.lock();
        g.next_token += 1;
        let t = format!("0.{}", 100_000_000 + g.next_token);
        g.tokens.insert(t.clone());
        t
    }

    pub(crate) fn token_valid(&self, token: &str) -> bool {
        self.lock().tokens.contains(token)
    }

    /// Logout is global on the ES3 (§3.2): every token dies at once.
    pub(crate) fn clear_tokens(&self) {
        self.lock().tokens.clear();
    }

    pub(crate) fn add_ws(&self, tx: mpsc::UnboundedSender<WsCmd>) {
        self.lock().ws.push(tx);
    }

    pub(crate) fn ws_broadcast(&self, cmd: WsCmd) {
        self.lock().ws.retain(|tx| tx.send(cmd).is_ok());
    }

    /// Wait until `pred` holds over the event log, or `timeout`. `pred` runs
    /// on the log under the lock, so a wake-up copies nothing; the log is
    /// cloned once, for the result.
    pub(crate) async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&[SimEvent]) -> bool,
    ) -> Result<Vec<SimEvent>, Vec<SimEvent>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            {
                let g = self.lock();
                if pred(&g.events) {
                    return Ok(g.events.clone());
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(self.lock().events.clone());
            }
        }
    }
}
```

and put this above the test module in `encoder.rs`:

```rust
//! The ES3's one shared encoder (§6.5, `census.md`): every viewer gets the
//! same frames; a new FLV connection forces an IDR into every open stream
//! and restarts the GOP; with no HDMI signal it sends its NO SIGNAL card
//! (every frame an IDR, same SPS).
use crate::source::{Frame, Source};
use crate::state::Shared;
use crate::{Fault, Pacing, Profile, ResizeSignal};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

/// Frames a viewer may fall behind before kvm-sim drops frames for it.
const VIEWER_QUEUE: usize = 512;

/// A frame as every viewer receives it: the source frame's NALs filtered by
/// the profile, and the encoder's running sequence number.
#[derive(Debug)]
pub(crate) struct OutFrame {
    pub seq: u64,
    pub source_index: usize,
    pub idr: bool,
    pub nals: Vec<Bytes>,
}

#[derive(Debug, Clone)]
pub(crate) enum Item {
    Frame(Arc<OutFrame>),
    Params {
        sps: Bytes,
        pps: Bytes,
        signal: ResizeSignal,
    },
    Fault(Fault),
}

pub(crate) struct Subscription {
    pub rx: mpsc::Receiver<Item>,
    pub sps: Bytes,
    pub pps: Bytes,
}

enum Cmd {
    Subscribe(oneshot::Sender<Subscription>),
    /// Tests: answered once every earlier command is done.
    #[cfg(test)]
    Sync(oneshot::Sender<()>),
    Advance(u32),
    Signal(bool),
    Switch(Source, ResizeSignal),
    Inject(Fault),
}

#[derive(Clone)]
pub(crate) struct EncoderHandle {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl EncoderHandle {
    pub(crate) async fn subscribe(&self) -> Option<Subscription> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Subscribe(tx)).ok()?;
        rx.await.ok()
    }
    #[cfg(test)]
    async fn sync(&self) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(Cmd::Sync(tx));
        let _ = rx.await;
    }
    pub(crate) fn advance(&self, frames: u32) {
        let _ = self.tx.send(Cmd::Advance(frames));
    }
    pub(crate) fn signal(&self, present: bool) {
        let _ = self.tx.send(Cmd::Signal(present));
    }
    pub(crate) fn switch(&self, source: Source, signal: ResizeSignal) {
        let _ = self.tx.send(Cmd::Switch(source, signal));
    }
    pub(crate) fn inject(&self, fault: Fault) {
        let _ = self.tx.send(Cmd::Inject(fault));
    }
}

struct Encoder {
    source: Source,
    profile: Profile,
    shared: Arc<Shared>,
    pos: usize,
    seq: u64,
    force_idr: bool,
    signal: bool,
    no_signal_k: usize,
    gop_cache: Vec<Arc<OutFrame>>,
    viewers: Vec<mpsc::Sender<Item>>,
}

fn nal_type(n: &[u8]) -> u8 {
    n.first().map_or(0, |b| b & 0x1F)
}

impl Encoder {
    fn subscribe(&mut self) -> Subscription {
        let (tx, rx) = mpsc::channel(VIEWER_QUEUE);
        if self.profile.idr_on_new_connection {
            self.force_idr = true;
        }
        if self.profile.burst_on_connect {
            for f in &self.gop_cache {
                let _ = tx.try_send(Item::Frame(f.clone()));
            }
        }
        self.viewers.push(tx);
        Subscription {
            rx,
            sps: self.source.sps.clone(),
            pps: self.source.pps.clone(),
        }
    }

    fn filter(&self, f: &Frame) -> Vec<Bytes> {
        f.nals
            .iter()
            .filter(|n| match nal_type(n) {
                1 | 5 => true,
                9 => self.profile.aud,
                7 | 8 => self.profile.inband_params,
                6 => self.profile.sei,
                _ => false,
            })
            .cloned()
            .collect()
    }

    fn tick(&mut self) {
        let frames_len = self.source.frames.len().max(1);
        let index = if self.signal {
            let at_idr = self.source.frames.get(self.pos).is_some_and(|f| f.idr);
            if self.force_idr && !at_idr {
                self.pos = self.source.next_gop_start(self.pos);
            }
            self.force_idr = false;
            let i = self.pos;
            self.pos = (self.pos + 1) % frames_len;
            i
        } else {
            let starts = &self.source.gop_starts;
            let i = starts
                .get(self.no_signal_k % starts.len().max(1))
                .copied()
                .unwrap_or(0);
            self.no_signal_k += 1;
            i
        };
        let Some(frame) = self.source.frames.get(index) else {
            return;
        };
        let out = Arc::new(OutFrame {
            seq: self.seq,
            source_index: frame.index,
            idr: frame.idr,
            nals: self.filter(frame),
        });
        self.seq += 1;
        if out.idr {
            self.gop_cache.clear();
        }
        self.gop_cache.push(out.clone());
        self.broadcast(&Item::Frame(out));
    }

    fn broadcast(&mut self, item: &Item) {
        let shared = &self.shared;
        self.viewers.retain(|tx| match tx.try_send(item.clone()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                shared.frame_dropped();
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        });
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Subscribe(reply) => {
                let sub = self.subscribe();
                let _ = reply.send(sub);
            }
            #[cfg(test)]
            Cmd::Sync(done) => {
                let _ = done.send(());
            }
            Cmd::Advance(n) => (0..n).for_each(|_| self.tick()),
            Cmd::Signal(present) => {
                // Signal coming back is a new input: the encoder restarts at an IDR.
                if present && !self.signal {
                    self.force_idr = true;
                }
                self.signal = present;
            }
            Cmd::Switch(source, signal) => {
                self.source = source;
                self.pos = 0;
                self.force_idr = false;
                self.gop_cache.clear();
                let item = Item::Params {
                    sps: self.source.sps.clone(),
                    pps: self.source.pps.clone(),
                    signal,
                };
                self.broadcast(&item);
            }
            Cmd::Inject(fault) => self.broadcast(&Item::Fault(fault)),
        }
    }
}

pub(crate) fn spawn(
    source: Source,
    profile: Profile,
    pacing: Pacing,
    shared: Arc<Shared>,
) -> (EncoderHandle, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut enc = Encoder {
        source,
        profile,
        shared,
        pos: 0,
        seq: 0,
        force_idr: false,
        signal: true,
        no_signal_k: 0,
        gop_cache: Vec::new(),
        viewers: Vec::new(),
    };
    let task = tokio::spawn(async move {
        let mut ticker = match pacing {
            Pacing::RealTime => {
                let period = Duration::from_secs(1) / profile.fps.max(1);
                let mut t = tokio::time::interval(period);
                t.set_missed_tick_behavior(MissedTickBehavior::Skip);
                Some(t)
            }
            Pacing::Manual => None,
        };
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(c) => enc.handle(c),
                    None => break,
                },
                () = async {
                    match ticker.as_mut() {
                        Some(t) => { t.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => enc.tick(),
            }
        }
    });
    (EncoderHandle { tx }, task)
}
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 3 integration passed.
Run: `cargo clippy -p kvm-sim --all-targets -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-sim/src
git commit -m "kvm-sim: the ES3's shared encoder — forced IDR on every new viewer, NO SIGNAL card, per-viewer queues" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.3: `KvmSim`, one certificate, and `login.lua`

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/{tls,http,web}.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs` (replace)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/{support,login}.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/main.rs`
- Test: `tests/sim/login.rs`

**Interfaces:**
- Consumes: Tasks 8.1–8.2; in tests, `kvm_probe::{kvm, request, fingerprint}` (the client proven against the ES3).
- Produces: the whole public `KvmSim` API of Part 8's table — `pub struct SimConfig { password: String, profile: Profile, pacing: Pacing, source: Source, control_recv_buffer: Option<u32>, video_send_buffer: Option<u32> }` with `SimConfig::es3(Source)`; `pub struct SimPorts { web: u16, video: u16, control: u16 }`; `pub struct KvmSim` with `async start`, `host`, `ports`, `spki_sha256`, `password`, `events`, `stamped_events`, `stats`, `wait_for`, `set_policy`, `expire_tokens`, `advance`, `set_signal`, `inject`, `switch_source`, `close_websockets`, `send_ws_oversize`, and `Drop` aborting every task. Wire behaviour so far: one rcgen certificate on all three ports; login is `POST /cgi-bin/login.lua` with JSON `pass`, answering `{"result":0,"token":"0.<digits>",…}` or `{"result":"invalid password",…}` (always the latter under `Policy::reject_logins`); `GET /cgi-bin/login.lua?logout` clears every token; under `Policy::blackhole` every new connection is accepted, counted and then never answered. The video and control ports answer 404 until Tasks 8.4 and 8.6. Test support: `support::{T, sim_with, es3_sim, target, login}`.

- [ ] **Step 1: Write the failing tests.** Replace `crates/kvm-sim/tests/sim/main.rs` with:

```rust
//! kvm-sim's own tests (one binary, §13).
mod support;

mod login;
mod source;
```

create `tests/sim/support.rs`:

```rust
//! Clients for kvm-sim built on kvm-probe — the tool proven against the real
//! ES3 in the census — so kvm-sim is held to what the device does.
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_sim::{KvmSim, Pacing, SimConfig, Source};
use std::time::Duration;

pub const T: Duration = Duration::from_secs(5);

/// kvm-sim in the ES3 profile over the ES3-like fixture, `f` adjusting its
/// config first.
pub async fn sim_with(f: impl FnOnce(&mut SimConfig)) -> KvmSim {
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    f(&mut cfg);
    KvmSim::start(cfg).await.unwrap()
}

pub async fn es3_sim(pacing: Pacing) -> KvmSim {
    sim_with(|c| c.pacing = pacing).await
}

pub fn target(sim: &KvmSim) -> KvmTarget {
    let p = sim.ports();
    KvmTarget {
        scheme: Scheme::Https,
        host: sim.host().to_owned(),
        login_port: p.web,
        video_port: p.video,
        control_port: p.control,
    }
}

pub async fn login(sim: &KvmSim) -> String {
    kvm_probe::kvm::login(
        &target(sim),
        Some(sim.spki_sha256()),
        sim.password(),
        0,
        "UTC",
    )
    .await
    .unwrap()
}
```

and `tests/sim/login.rs`:

```rust
use crate::support::{T, es3_sim, login, target};
use kvm_sim::{Pacing, PortKind, SimEvent};
use std::time::Duration;

#[tokio::test]
async fn one_certificate_pins_all_three_ports() {
    let sim = es3_sim(Pacing::Manual).await;
    let p = sim.ports();
    for port in [p.web, p.video, p.control] {
        let seen = kvm_probe::fingerprint::observe(&target(&sim), port)
            .await
            .unwrap();
        assert_eq!(seen, sim.spki_sha256(), "port {port}");
    }
}

#[tokio::test]
async fn logins_coexist_and_a_wrong_password_is_refused() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let b = login(&sim).await;
    assert_ne!(a, b);
    assert!(a.starts_with("0.") && a[2..].bytes().all(|c| c.is_ascii_digit()));
    let bad = kvm_probe::kvm::login(&target(&sim), Some(sim.spki_sha256()), "nope", 0, "UTC").await;
    assert!(bad.is_err());
    let s = sim.stats();
    assert_eq!((s.logins_ok, s.logins_failed, s.logouts), (2, 1, 0));
}

#[tokio::test]
async fn a_rejecting_policy_fails_even_the_right_password() {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.reject_logins = true);
    let refused = kvm_probe::kvm::login(
        &target(&sim),
        Some(sim.spki_sha256()),
        sim.password(),
        0,
        "UTC",
    )
    .await;
    assert!(refused.is_err());
    assert_eq!((sim.stats().logins_ok, sim.stats().logins_failed), (0, 1));
    sim.set_policy(|p| p.reject_logins = false);
    login(&sim).await;
}

#[tokio::test]
async fn a_logout_is_recorded_and_counted() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &a)
        .await
        .unwrap();
    sim.wait_for(T, |e| e.contains(&SimEvent::Logout))
        .await
        .unwrap();
    assert_eq!(sim.stats().logouts, 1);
}

#[tokio::test]
async fn an_unreachable_kvm_accepts_and_never_answers() {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.blackhole = true);
    let kvm = target(&sim);
    let tls = kvm_probe::kvm::connect_to(&kvm, sim.ports().web, Some(sim.spki_sha256()));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), tls)
            .await
            .is_err(),
        "no TLS handshake ever completes"
    );
    sim.wait_for(T, |e| {
        e.contains(&SimEvent::Accept {
            port: PortKind::Web,
        })
    })
    .await
    .unwrap();
    assert_eq!(sim.stats().accepts_web, 1);
    sim.set_policy(|p| p.blackhole = false);
    login(&sim).await;
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim --test sim`
Expected: FAIL to compile — `unresolved imports kvm_sim::KvmSim`, `SimConfig`.

- [ ] **Step 3: TLS and HTTP.** Create `crates/kvm-sim/src/tls.rs`:

```rust
//! One self-signed certificate on all three ports, as on the ES3 (§3.2), and
//! the SHA-256 of its SPKI that a test config pins.
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub(crate) struct Identity {
    pub acceptor: TlsAcceptor,
    /// Lowercase hex SHA-256 of the certificate's SubjectPublicKeyInfo.
    pub spki_sha256: String,
}

pub(crate) fn identity() -> std::io::Result<Identity> {
    let err = |e: &dyn std::fmt::Display| std::io::Error::other(e.to_string());
    let ck =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
            .map_err(|e| err(&e))?;
    let spki_sha256 = Sha256::digest(ck.key_pair.public_key_der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).map_err(|e| err(&e))?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| err(&e))?;
    Ok(Identity {
        acceptor: TlsAcceptor::from(Arc::new(cfg)),
        spki_sha256,
    })
}
```

and `crates/kvm-sim/src/http.rs` (its av.flv helpers — `query_token`, the cookie, `FLV_HEAD` — get their first user in Task 8.4):

```rust
//! Just enough HTTP/1.1 for the ES3's three request shapes, parsed with
//! httparse (hyper's own parser). kvm-sim writes responses itself so every
//! FLV byte write is observable (`sim_tx`, back-pressure) and corruptible.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Request heads and bodies are small on the ES3; refuse anything bigger.
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 4 * 1024;

pub(crate) struct Request {
    pub method: String,
    /// Path and query, as sent.
    pub target: String,
    pub cookie_token: Option<String>,
    pub body: Vec<u8>,
}

impl Request {
    pub(crate) fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    pub(crate) fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    /// The `token` query parameter.
    pub(crate) fn query_token(&self) -> Option<&str> {
        self.query()
            .split('&')
            .find_map(|kv| kv.strip_prefix("token="))
    }
}

/// `token=<value>` from a `Cookie` header.
pub(crate) fn cookie_token(value: &str) -> Option<String> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("token="))
        .map(str::to_owned)
}

/// Read one request head (and a `Content-Length` body) from `io`.
pub(crate) async fn read_request<S: AsyncRead + Unpin>(io: &mut S) -> Option<Request> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = io.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let mut content_length = 0usize;
                let mut cookie = None;
                for h in req.headers.iter() {
                    let v = std::str::from_utf8(h.value).unwrap_or("");
                    if h.name.eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().ok()?;
                    } else if h.name.eq_ignore_ascii_case("cookie") {
                        cookie = cookie_token(v);
                    }
                }
                if content_length > MAX_BODY {
                    return None;
                }
                let method = req.method?.to_owned();
                let target = req.path?.to_owned();
                let mut body = buf.get(head_len..)?.to_vec();
                while body.len() < content_length {
                    let n = io.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    body.extend_from_slice(chunk.get(..n)?);
                }
                body.truncate(content_length);
                return Some(Request {
                    method,
                    target,
                    cookie_token: cookie,
                    body,
                });
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            _ => return None,
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A complete response with a `Content-Length` body; the connection closes.
pub(crate) async fn respond<S: AsyncWrite + Unpin>(
    io: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    io.write_all(head.as_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    io.shutdown().await
}

/// The head of a close-delimited streaming FLV response.
pub(crate) const FLV_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
```

- [ ] **Step 4: Login.** Create `crates/kvm-sim/src/web.rs`:

```rust
//! `/cgi-bin/login.lua` on the web port (§3.1, §3.2): logins coexist and
//! each gets a `0.<digits>` token; `?logout` is global — every token dies,
//! open FLVs keep streaming.
use crate::http::{Request, respond};
use crate::state::{Shared, SimEvent};
use tokio::io::AsyncWrite;

pub(crate) async fn serve<S: AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    shared: &Shared,
    password: &str,
) {
    let json = "application/json";
    match (req.method.as_str(), req.path()) {
        ("POST", "/cgi-bin/login.lua") => {
            let pass = serde_json::from_slice::<serde_json::Value>(&req.body)
                .ok()
                .and_then(|v| v.get("pass").and_then(|p| p.as_str()).map(str::to_owned));
            let ok = !shared.policy().reject_logins && pass.as_deref() == Some(password);
            shared.record(SimEvent::Login { ok });
            let body = if ok {
                format!(
                    "{{\"result\":0,\"token\":\"{}\",\"role\":\"admin\"}}",
                    shared.mint_token()
                )
            } else {
                "{\"result\":\"invalid password\",\"code\":200}".to_owned()
            };
            let _ = respond(&mut io, 200, json, body.as_bytes()).await;
        }
        ("GET", "/cgi-bin/login.lua") if req.query() == "logout" => {
            shared.clear_tokens();
            shared.record(SimEvent::Logout);
            let _ = respond(&mut io, 200, json, b"{\"result\":0}").await;
        }
        _ => {
            let _ = respond(&mut io, 404, "text/plain", b"not found").await;
        }
    }
}
```

- [ ] **Step 5: `KvmSim`.** Replace `crates/kvm-sim/src/lib.rs` with the following. Every connection runs `serve_connection` with a shared `ConnCtx`; Tasks 8.4–8.6 add `av.flv` and the websocket to it and take the staged `allow(dead_code)`s off:

```rust
//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

// av.flv (Tasks 8.4, 8.5) and the websocket (Task 8.6) are the remaining
// users of `encoder`, `http`'s av.flv helpers and `state`.
#[allow(dead_code)]
mod encoder;
#[allow(dead_code)]
mod http;
mod source;
#[allow(dead_code)]
mod state;
mod tls;
mod web;

pub use source::{Frame, Source, SourceError, fixtures_dir};
pub use state::{Policy, PortKind, SimEvent, SimStats};

use encoder::EncoderHandle;
use state::{Shared, WsCmd};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;

/// The stream's shape on the wire (`census.md`, Artifacts: kvm-sim profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Nominal frame rate: FLV timestamps and real-time pacing.
    pub fps: u32,
    /// AVCC NAL length size: 1, 2 or 4.
    pub length_size: u8,
    /// `CompositionTime` on every coded tag (0 on the sequence header).
    pub composition_time_ms: i32,
    /// A new FLV connection replays the GOP so far at once (a GOP-caching
    /// source; the ES3 does not).
    pub burst_on_connect: bool,
    /// Shared encoder: any new FLV connection forces an IDR into every open
    /// stream and restarts the GOP.
    pub idr_on_new_connection: bool,
    /// Keep in-band SPS/PPS in coded tags (the ES3 sends them only in the
    /// sequence header).
    pub inband_params: bool,
    /// Keep AUDs (the ES3 sends none).
    pub aud: bool,
    /// Keep SEI (the ES3 sends none).
    pub sei: bool,
    /// Append the ES3's trailing zero bytes to the sequence header's
    /// parameter sets — one after the SPS, two after the PPS — as the device
    /// does (`census.md` `sps_hex`, `pps_hex`).
    pub padded_param_sets: bool,
}

impl Profile {
    /// The ES3 as measured (`census.md`, Leg A — stream): 30 fps, length size
    /// 4, `CompositionTime` 16, no burst, shared encoder, tag = AU carrying
    /// only NAL types 1 and 5, and a sequence header whose SPS and PPS end in
    /// zero bytes.
    #[must_use]
    pub fn es3() -> Profile {
        Profile {
            fps: 30,
            length_size: 4,
            composition_time_ms: 16,
            burst_on_connect: false,
            idr_on_new_connection: true,
            inband_params: false,
            aud: false,
            sei: false,
            padded_param_sets: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// One frame every `1 / Profile::fps`, never catching up (the ES3 sends
    /// one tag every 33 ms whether the screen moves or not).
    RealTime,
    /// Frames only on [`KvmSim::advance`]: deterministic tests.
    Manual,
}

/// How a source switch reaches viewers (§6.4, §11.3 resolution change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeSignal {
    /// A new sequence header on every open FLV.
    SequenceHeader,
    /// The new SPS/PPS in-band in the next IDR's tag.
    InBandSps,
    /// Every open FLV closes (the ES3's observed preset change); new
    /// connections get the new source.
    CloseFlv,
}

/// One-shot faults, applied by every open FLV to its next tag (§6.9 cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OversizeTag,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    HevcCodecId,
    EnhancedHevc,
    /// The next coded tag's `CompositionTime`.
    CompositionTime(i32),
    /// The next two pictures in one tag.
    TwoPictures,
    BSlice,
    StartCodeInNal,
    ForbiddenBit,
    /// An `AVCPacketType 2` tag, now.
    EndOfSequence,
    /// 129 NALs in one tag.
    TooManyNals,
    /// Close every open FLV, now.
    Close,
    /// Stop writing on every open FLV, keeping it open.
    Silence,
}

pub struct SimConfig {
    pub password: String,
    pub profile: Profile,
    pub pacing: Pacing,
    pub source: Source,
    /// `SO_RCVBUF` for control-port sockets, so a test can make the
    /// bridge's websocket writes block quickly.
    pub control_recv_buffer: Option<u32>,
    /// `SO_SNDBUF` for video-port sockets, so a viewer that stops reading
    /// blocks its writer after little data.
    pub video_send_buffer: Option<u32>,
}

impl SimConfig {
    /// The ES3 profile, real-time, over `source`.
    #[must_use]
    pub fn es3(source: Source) -> SimConfig {
        SimConfig {
            password: "kvm-sim-password".to_owned(),
            profile: Profile::es3(),
            pacing: Pacing::RealTime,
            source,
            control_recv_buffer: None,
            video_send_buffer: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimPorts {
    pub web: u16,
    pub video: u16,
    pub control: u16,
}

/// A running simulated KVM. Dropping it stops everything.
pub struct KvmSim {
    ports: SimPorts,
    spki_sha256: String,
    password: String,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    tasks: Arc<std::sync::Mutex<Vec<AbortHandle>>>,
}

async fn bind(recv_buffer: Option<u32>, send_buffer: Option<u32>) -> std::io::Result<TcpListener> {
    let sock = TcpSocket::new_v4()?;
    // Accepted sockets inherit the listener's buffer sizes.
    if let Some(n) = recv_buffer {
        sock.set_recv_buffer_size(n)?;
    }
    if let Some(n) = send_buffer {
        sock.set_send_buffer_size(n)?;
    }
    sock.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    sock.listen(64)
}

/// Bound on TLS accept and request-head read for one connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// What every connection task shares.
struct ConnCtx {
    shared: Arc<Shared>,
    acceptor: TlsAcceptor,
    password: String,
}

/// One accepted connection: TLS, then its port's service. `av.flv` is Task
/// 8.4's and the websocket Task 8.6's; until then both ports answer 404.
async fn serve_connection(kind: PortKind, tcp: TcpStream, _conn: u64, ctx: Arc<ConnCtx>) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(tcp)).await
    else {
        return;
    };
    let Ok(Some(req)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, http::read_request(&mut tls)).await
    else {
        return;
    };
    match kind {
        PortKind::Web => web::serve(tls, req, &ctx.shared, &ctx.password).await,
        PortKind::Video | PortKind::Control => {
            let _ = http::respond(&mut tls, 404, "text/plain", b"not yet").await;
        }
    }
}

/// `Policy::blackhole`: an unreachable KVM (§11.3). The connection stays
/// open and silent — no TLS, no bytes — until the client gives up.
async fn hold_silent(mut tcp: TcpStream) {
    let mut sink = [0u8; 1024];
    while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
}

impl KvmSim {
    pub async fn start(cfg: SimConfig) -> std::io::Result<KvmSim> {
        let id = tls::identity()?;
        let shared = Arc::new(Shared::default());
        let (enc, enc_task) = encoder::spawn(cfg.source, cfg.profile, cfg.pacing, shared.clone());
        let tasks = Arc::new(std::sync::Mutex::new(vec![enc_task.abort_handle()]));
        let (web, video, control) = (
            bind(None, None).await?,
            bind(None, cfg.video_send_buffer).await?,
            bind(cfg.control_recv_buffer, None).await?,
        );
        let ports = SimPorts {
            web: web.local_addr()?.port(),
            video: video.local_addr()?.port(),
            control: control.local_addr()?.port(),
        };
        let ctx = Arc::new(ConnCtx {
            shared: shared.clone(),
            acceptor: id.acceptor,
            password: cfg.password.clone(),
        });
        let next_conn = Arc::new(AtomicU64::new(1));
        for (listener, kind) in [
            (web, PortKind::Web),
            (video, PortKind::Video),
            (control, PortKind::Control),
        ] {
            let (ctx, tasks2, next_conn) = (ctx.clone(), tasks.clone(), next_conn.clone());
            let accept = tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    ctx.shared.record(SimEvent::Accept { port: kind });
                    let _ = tcp.set_nodelay(true);
                    let conn = next_conn.fetch_add(1, Ordering::Relaxed);
                    let task = if ctx.shared.policy().blackhole {
                        tokio::spawn(hold_silent(tcp))
                    } else {
                        tokio::spawn(serve_connection(kind, tcp, conn, ctx.clone()))
                    };
                    if let Ok(mut t) = tasks2.lock() {
                        t.retain(|h| !h.is_finished());
                        t.push(task.abort_handle());
                    }
                }
            });
            if let Ok(mut t) = tasks.lock() {
                t.push(accept.abort_handle());
            }
        }
        Ok(KvmSim {
            ports,
            spki_sha256: id.spki_sha256,
            password: cfg.password,
            shared,
            enc,
            tasks,
        })
    }

    /// Always loopback.
    #[must_use]
    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }
    #[must_use]
    pub fn ports(&self) -> SimPorts {
        self.ports
    }
    /// The pin for the bridge's `kvm.spki_sha256` (one cert, all ports).
    #[must_use]
    pub fn spki_sha256(&self) -> &str {
        &self.spki_sha256
    }
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
    #[must_use]
    pub fn events(&self) -> Vec<SimEvent> {
        self.shared.events()
    }
    /// Events with the instant each was recorded (`FlvAu`: `sim_tx`).
    #[must_use]
    pub fn stamped_events(&self) -> Vec<(Instant, SimEvent)> {
        self.shared.stamped_events()
    }
    #[must_use]
    pub fn stats(&self) -> SimStats {
        self.shared.stats()
    }
    /// Wait until `pred` holds over the event log; `Err` carries the log at
    /// the timeout.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&[SimEvent]) -> bool,
    ) -> Result<Vec<SimEvent>, Vec<SimEvent>> {
        self.shared.wait_for(timeout, pred).await
    }
    pub fn set_policy(&self, f: impl FnOnce(&mut Policy)) {
        self.shared.set_policy(f);
    }
    /// Invalidate every token without a logout request (token expiry).
    pub fn expire_tokens(&self) {
        self.shared.clear_tokens();
    }
    /// `Pacing::Manual`: encode `frames` frames now.
    pub fn advance(&self, frames: u32) {
        self.enc.advance(frames);
    }
    /// HDMI signal present (`false`: the NO SIGNAL card, every frame an IDR).
    pub fn set_signal(&self, present: bool) {
        self.enc.signal(present);
    }
    pub fn inject(&self, fault: Fault) {
        self.enc.inject(fault);
    }
    pub fn switch_source(&self, source: Source, signal: ResizeSignal) {
        self.enc.switch(source, signal);
    }
    pub fn close_websockets(&self) {
        self.shared.ws_broadcast(WsCmd::Close);
    }
    /// Send every open websocket a frame header declaring `declared_len`
    /// bytes (§3.2: the bridge closes at 4 KiB without buffering).
    pub fn send_ws_oversize(&self, declared_len: u64) {
        self.shared.ws_broadcast(WsCmd::Oversize(declared_len));
    }
}

impl Drop for KvmSim {
    fn drop(&mut self) {
        if let Ok(t) = self.tasks.lock() {
            t.iter().for_each(AbortHandle::abort);
        }
    }
}
```

- [ ] **Step 6: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 8 integration passed (`source` 3, `login` 5).
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.
Run: `cargo tree --workspace --target all -i ring` — Expected: nothing printed; CI's ring gate stays green.

- [ ] **Step 7: Commit.**

```bash
git add crates/kvm-sim
git commit -m "kvm-sim: KvmSim — one certificate on three ports, login.lua with global logout, a blackhole policy" \
  -m "The public API Plans C–E use (§11.3, §10.2); av.flv and the websocket follow." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.4: `av.flv` — the ES3 tag shape, the shared encoder, resize

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/flv.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/{support,main}.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/flv.rs`
- Test: `tests/sim/flv.rs`

**Interfaces:**
- Consumes: Task 8.3; `kvm_proto::flv::mux::*` (3.3), `kvm_proto::h264::frame_id` (2.2); in tests, `kvm_proto::video` (4.6) as the admission oracle and kvm-probe's `kvm::{connect_to, logout}`.
- Produces: `GET /av.flv?token=T` with `Cookie: token=T` (both required, equal and live; else 403; `Policy::flv_status` answers with its status instead, `Policy::refuse_concurrent_flv` answers a second open with 503) answers a close-delimited `video/x-flv` stream: the sequence header (its SPS and PPS padded with the ES3's zero bytes under `Profile::padded_param_sets`), then one tag per access unit from the first IDR on, `CompositionTime` and NAL length size per profile; source switches by the three `ResizeSignal`s; every write timed (`max_flv_write_block`) and every coded tag stamped (`FlvAu` at `sim_tx`); `SimConfig::video_send_buffer` sizes video sockets' `SO_SNDBUF`. `advance(n)` with `n` ≤ 512 keeps every reading viewer whole (the per-viewer queue). Test support gains `support::FlvClient`. One-shot faults are Task 8.5's: until then `inject` reaches the FLV writers and is ignored there.

- [ ] **Step 1: Write the failing tests.** Replace `crates/kvm-sim/tests/sim/support.rs` with (it adds `FlvClient`, a raw `av.flv` reader on kvm-probe's TLS client and kvm-proto's demuxer):

```rust
//! Clients for kvm-sim built on kvm-probe — the tool proven against the real
//! ES3 in the census — so kvm-sim is held to what the device does.
use kvm_probe::kvm::{BoxedIo, connect_to};
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag};
use kvm_sim::{KvmSim, Pacing, SimConfig, Source};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const T: Duration = Duration::from_secs(5);

/// kvm-sim in the ES3 profile over the ES3-like fixture, `f` adjusting its
/// config first.
pub async fn sim_with(f: impl FnOnce(&mut SimConfig)) -> KvmSim {
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    f(&mut cfg);
    KvmSim::start(cfg).await.unwrap()
}

pub async fn es3_sim(pacing: Pacing) -> KvmSim {
    sim_with(|c| c.pacing = pacing).await
}

pub fn target(sim: &KvmSim) -> KvmTarget {
    let p = sim.ports();
    KvmTarget {
        scheme: Scheme::Https,
        host: sim.host().to_owned(),
        login_port: p.web,
        video_port: p.video,
        control_port: p.control,
    }
}

pub async fn login(sim: &KvmSim) -> String {
    kvm_probe::kvm::login(
        &target(sim),
        Some(sim.spki_sha256()),
        sim.password(),
        0,
        "UTC",
    )
    .await
    .unwrap()
}

/// A raw `av.flv` reader: request with the token in the query and the
/// cookie, as the bridge sends it (§3.2), then kvm-proto's demuxer.
pub struct FlvClient {
    io: BoxedIo,
    pub demux: FlvDemuxer,
}

impl FlvClient {
    /// `Err(status)` when kvm-sim refuses the stream.
    pub async fn open(sim: &KvmSim, token: &str) -> Result<FlvClient, u16> {
        let mut io = connect_to(&target(sim), sim.ports().video, Some(sim.spki_sha256()))
            .await
            .unwrap();
        let req = format!(
            "GET /av.flv?token={token} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: token={token}\r\n\r\n"
        );
        io.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 4096, "response head too long");
            if io.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let status: u16 = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if status != 200 {
            return Err(status);
        }
        Ok(FlvClient {
            io,
            demux: FlvDemuxer::new(FlvLimits::default()),
        })
    }

    /// The next demuxed tag, `Ok(None)` on EOF or timeout.
    pub async fn next(&mut self) -> Result<Option<FlvTag>, kvm_proto::flv::FlvError> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            if let Some(tag) = self.demux.next_tag()? {
                return Ok(Some(tag));
            }
            match tokio::time::timeout(T, self.io.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => self.demux.push(&buf[..n]),
                _ => return Ok(None),
            }
        }
    }
}
```

add `mod flv;` to `tests/sim/main.rs` (above `mod login;`), and create `tests/sim/flv.rs` — the ES3 tag shape on the wire (padding included) admitted end to end by the bridge's own admission; the shared encoder seen from two connections, its forced IDR restarting the GOP; token rules and global logout; the policy statuses; `sim_tx` and write blocking; the NO SIGNAL card and a stalled viewer (Review Focus 2 and 4); resolution change by each signal, from a Main source:

```rust
use crate::support::{FlvClient, T, es3_sim, login, sim_with, target};
use kvm_proto::flv::{FrameType, TagBody, VideoBody};
use kvm_proto::video::{AdmissionConfig, ParamClass, VideoAdmission};
use kvm_sim::{KvmSim, Pacing, Profile, ResizeSignal, SimConfig, SimEvent, Source};
use std::time::{Duration, Instant};

fn nal_types(body: &TagBody) -> Vec<u8> {
    match body {
        TagBody::Video(VideoBody::Nalus { nals, .. }) => {
            nals.iter().map(|n| n.unit_type().unwrap()).collect()
        }
        _ => vec![],
    }
}

#[tokio::test]
async fn es3_tag_shape_on_the_wire_and_the_bridge_admits_it() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(3);
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    let seq = c.next().await.unwrap().unwrap();
    match &seq.body {
        TagBody::Video(VideoBody::SequenceHeader(cfg)) => {
            assert_eq!(cfg.length_size_minus_one, 3); // AVCC length size 4
            assert_eq!(cfg.sps.len(), 1);
            assert_eq!(cfg.pps.len(), 1);
            // Padded like the device's own (census.md: sps_hex …08 00,
            // pps_hex …12 00 00).
            assert!(cfg.sps[0].ends_with(&[0]) && cfg.pps[0].ends_with(&[0, 0]));
        }
        other => panic!("{other:?}"),
    }
    let params = adm.admit(seq, Instant::now()).unwrap().params.unwrap();
    assert_eq!(params.class, ParamClass::Initial);
    assert_eq!(params.params.summary.level_idc, 30); // mislabelled 21 → rewritten
    // Admission trims the padding (D2).
    assert!(!params.params.sps.ends_with(&[0]) && !params.params.pps[0].ends_with(&[0]));
    for (i, want) in [(0u32, vec![5u8]), (33, vec![1]), (66, vec![1])] {
        let tag = c.next().await.unwrap().unwrap();
        assert_eq!(tag.timestamp, i);
        assert_eq!(nal_types(&tag.body), want, "only NAL types 1 and 5 (ES3)");
        if let TagBody::Video(VideoBody::Nalus {
            composition_time,
            frame_type,
            ..
        }) = &tag.body
        {
            assert_eq!(*composition_time, 16);
            assert_eq!(*frame_type == FrameType::Key, want == [5]);
        }
        let au = adm.admit(tag, Instant::now()).unwrap().au.unwrap();
        assert_eq!(au.idr, want == [5]);
    }
}

#[tokio::test]
async fn a_new_connection_forces_an_idr_into_every_open_stream() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut a = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(10);
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
            .count()
            == 10
    })
    .await
    .unwrap();
    let b = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(2);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 14
        })
        .await
        .unwrap();
    let aus: Vec<(u64, u64, bool)> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { conn, seq, idr, .. } => Some((*conn, *seq, *idr)),
            _ => None,
        })
        .collect();
    // The 11th frame (seq 10) is an IDR on both streams: off the 60-frame cadence.
    assert!(
        aus.iter()
            .filter(|(_, s, _)| *s == 10)
            .all(|(_, _, idr)| *idr)
    );
    assert_eq!(aus.iter().filter(|(_, s, _)| *s == 10).count(), 2);
    for _ in 0..11 {
        a.next().await.unwrap().unwrap();
    }
    let tag = a.next().await.unwrap().unwrap();
    assert!(matches!(
        tag.body,
        TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            ..
        })
    ));
    // The forced IDR restarted the GOP: the next IDR comes 60 frames later
    // (seq 70), not on the old cadence (seq 60).
    drop(b);
    sim.advance(60);
    let mut keys = vec![];
    for seq in 11..72 {
        let tag = a.next().await.unwrap().unwrap();
        if matches!(
            tag.body,
            TagBody::Video(VideoBody::Nalus {
                frame_type: FrameType::Key,
                ..
            })
        ) {
            keys.push(seq);
        }
    }
    assert_eq!(keys, [70]);
}

#[tokio::test]
async fn gop_is_sixty_frames_and_no_signal_is_all_intra() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let _c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(121);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 121
        })
        .await
        .unwrap();
    let idrs: Vec<u64> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { seq, idr: true, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(idrs, [0, 60, 120]);
    sim.set_signal(false);
    sim.advance(5);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 126
        })
        .await
        .unwrap();
    let last: Vec<bool> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { idr, .. } => Some(*idr),
            _ => None,
        })
        .skip(121)
        .collect();
    assert_eq!(last, [true; 5]);
}

#[tokio::test]
async fn bad_tokens_and_refused_side_connections() {
    let sim = es3_sim(Pacing::Manual).await;
    assert_eq!(FlvClient::open(&sim, "0.123").await.err(), Some(403));
    let token = login(&sim).await;
    sim.set_policy(|p| p.refuse_concurrent_flv = true);
    let _first = FlvClient::open(&sim, &token).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::FlvOpen { .. }))
    })
    .await
    .unwrap();
    assert_eq!(FlvClient::open(&sim, &token).await.err(), Some(503));
    assert!(sim.events().contains(&SimEvent::FlvRefused { status: 503 }));
}

async fn main_sim() -> KvmSim {
    let mut cfg = SimConfig::es3(Source::fixture("360p30_main_full.h264").unwrap());
    cfg.pacing = Pacing::Manual;
    cfg.profile = Profile {
        aud: true,
        ..Profile::es3()
    };
    KvmSim::start(cfg).await.unwrap()
}

#[tokio::test]
async fn resolution_change_by_each_signal() {
    for signal in [
        ResizeSignal::SequenceHeader,
        ResizeSignal::InBandSps,
        ResizeSignal::CloseFlv,
    ] {
        let sim = main_sim().await;
        let token = login(&sim).await;
        let mut c = FlvClient::open(&sim, &token).await.unwrap();
        let mut adm = VideoAdmission::new(AdmissionConfig::default());
        adm.flv_opened();
        sim.advance(2);
        for _ in 0..3 {
            adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
                .unwrap();
        }
        sim.switch_source(Source::fixture("480p30_main_full.h264").unwrap(), signal);
        sim.advance(1);
        let mut classes = vec![];
        if signal == ResizeSignal::CloseFlv {
            assert!(c.next().await.unwrap().is_none(), "the FLV closes");
            c = FlvClient::open(&sim, &token).await.unwrap();
            adm.flv_opened();
            sim.advance(1);
        }
        while classes.is_empty() {
            let a = adm
                .admit(c.next().await.unwrap().unwrap(), Instant::now())
                .unwrap();
            if let Some(p) = a.params {
                assert_eq!(
                    (p.params.summary.width, p.params.summary.height),
                    (854, 480)
                );
                classes.push(p.class);
            }
        }
        let want = if signal == ResizeSignal::CloseFlv {
            ParamClass::Initial
        } else {
            ParamClass::Resize
        };
        assert_eq!(classes, [want], "{signal:?}");
    }
}

#[tokio::test]
async fn no_signal_card_admits_without_a_params_change() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    sim.advance(3);
    for _ in 0..4 {
        adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
    }
    sim.set_signal(false); // display sleep: every frame an IDR, same SPS
    sim.advance(6);
    for _ in 0..6 {
        let a = adm
            .admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
        assert_eq!(a.params, None);
        assert!(a.au.unwrap().idr);
    }
    sim.set_signal(true); // wake: the encoder restarts at an IDR
    sim.advance(2);
    let a = adm
        .admit(c.next().await.unwrap().unwrap(), Instant::now())
        .unwrap();
    assert!(a.au.unwrap().idr);
    let a = adm
        .admit(c.next().await.unwrap().unwrap(), Instant::now())
        .unwrap();
    assert!(!a.au.unwrap().idr);
}

#[tokio::test]
async fn a_viewer_that_stops_reading_does_not_stall_the_others() {
    // A 64 KiB send buffer: the stalled viewer's writer blocks after a few
    // dozen frames, so its 512-frame queue overflows well before 2000.
    let sim = sim_with(|c| {
        c.pacing = Pacing::Manual;
        c.video_send_buffer = Some(64 * 1024);
    })
    .await;
    let token = login(&sim).await;
    let mut reader = FlvClient::open(&sim, &token).await.unwrap();
    let _stalled = FlvClient::open(&sim, &token).await.unwrap(); // never read
    reader.next().await.unwrap().unwrap(); // sequence header
    // ~5 MB of video: the viewer that never reads blocks its writer and
    // overflows its queue — the reading one must not notice.
    for _ in 0..20 {
        sim.advance(100);
        for _ in 0..100 {
            reader
                .next()
                .await
                .unwrap()
                .expect("the reading viewer keeps getting tags");
        }
    }
    let events = sim.events();
    let reader_conn = events
        .iter()
        .find_map(|e| match e {
            SimEvent::FlvOpen { conn } => Some(*conn),
            _ => None,
        })
        .unwrap();
    let reader_seqs: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { conn, seq, .. } if *conn == reader_conn => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(
        sim.stats().frames_dropped > 0,
        "the stalled viewer's queue never overflowed"
    );
    assert_eq!(reader_seqs, (0..2000).collect::<Vec<u64>>());
}

#[tokio::test]
async fn a_second_login_leaves_the_first_token_valid() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let _b = login(&sim).await;
    assert!(FlvClient::open(&sim, &a).await.is_ok());
}

#[tokio::test]
async fn logout_is_global_but_open_streams_survive() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let b = login(&sim).await;
    let mut open = FlvClient::open(&sim, &a).await.unwrap();
    kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &b)
        .await
        .unwrap();
    // Every token died, including the one that did not log out …
    assert_eq!(FlvClient::open(&sim, &a).await.err(), Some(403));
    // … but the FLV opened before the logout keeps streaming.
    sim.advance(2);
    assert!(open.next().await.unwrap().is_some()); // sequence header
    assert!(open.next().await.unwrap().is_some()); // IDR
    assert_eq!(sim.stats().logouts, 1);
}

#[tokio::test]
async fn expired_tokens_are_refused_without_a_logout() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    sim.expire_tokens();
    assert_eq!(FlvClient::open(&sim, &a).await.err(), Some(403));
    assert_eq!(sim.stats().logouts, 0);
}

#[tokio::test]
async fn a_policy_status_refuses_the_stream() {
    // HTTP 5xx, and the 401 a second consecutive auth failure (§11.3) needs.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    for status in [503u16, 401] {
        sim.set_policy(|p| p.flv_status = Some(status));
        assert_eq!(FlvClient::open(&sim, &token).await.err(), Some(status));
        assert!(sim.events().contains(&SimEvent::FlvRefused { status }));
    }
    sim.set_policy(|p| p.flv_status = None);
    assert!(FlvClient::open(&sim, &token).await.is_ok());
}

#[tokio::test]
async fn sim_tx_follows_the_send_order_and_a_reader_never_blocks_a_write() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(30);
    for _ in 0..31 {
        c.next().await.unwrap().unwrap();
    }
    let sent: Vec<(Instant, u64)> = sim
        .stamped_events()
        .into_iter()
        .filter_map(|(at, e)| match e {
            SimEvent::FlvAu { seq, .. } => Some((at, seq)),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent.iter().map(|s| s.1).collect::<Vec<u64>>(),
        (0..30).collect::<Vec<u64>>()
    );
    assert!(
        sent.windows(2).all(|w| w[0].0 <= w[1].0),
        "sim_tx in send order"
    );
    // §10.2: no FLV write blocks for 100 ms (kvm-bench asserts it under load).
    let block = sim.stats().max_flv_write_block;
    assert!(
        block > Duration::ZERO && block < Duration::from_millis(100),
        "{block:?}"
    );
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim --test sim flv::`
Expected: FAIL — every `flv::` test: `FlvClient::open` returns `Err(404)` (the video port does not serve `av.flv` yet), or a `403`/`503` assertion sees 404.

- [ ] **Step 3: `av.flv`.** Create `crates/kvm-sim/src/flv.rs`. Every write is timed (`max_flv_write_block`) and each coded tag's is stamped (`FlvAu`'s instant is `sim_tx`):

```rust
//! `GET /av.flv?token=…` (§3.1): a close-delimited HTTP-FLV stream in the
//! profile's tag shape — one tag per access unit, `CompositionTime` per the
//! profile on coded tags (0 on the sequence header), the profile's NAL
//! length size. Every write is timed (`max_flv_write_block`) and each coded
//! tag's is stamped (`FlvAu`'s instant is `sim_tx`).
use crate::encoder::{EncoderHandle, Item, OutFrame};
use crate::http::{FLV_HEAD, Request, respond};
use crate::state::{Shared, SimEvent};
use crate::{Profile, ResizeSignal};
use bytes::Bytes;
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::h264::frame_id;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Writer<W> {
    out: W,
    profile: Profile,
    conn: u64,
    shared: Arc<Shared>,
    frames_written: u64,
    seen_idr: bool,
    inband_next: Option<(Bytes, Bytes)>,
}

fn nal_type(n: &[u8]) -> u8 {
    n.first().map_or(0, |b| b & 0x1F)
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn timestamp(&self) -> u32 {
        let ms = self.frames_written * 1000 / u64::from(self.profile.fps.max(1));
        u32::try_from(ms).unwrap_or(u32::MAX)
    }

    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<Instant> {
        let start = Instant::now();
        self.out.write_all(bytes).await?;
        self.out.flush().await?;
        let done = Instant::now();
        self.shared.write_blocked(done - start);
        Ok(done)
    }

    async fn sequence_header(&mut self, sps: &[u8], pps: &[u8]) -> std::io::Result<()> {
        // The ES3 pads its config record's SPS with one zero byte and its PPS
        // with two (`census.md`); admission trims them (D2).
        let (sps, pps) = if self.profile.padded_param_sets {
            ([sps, &[0]].concat(), [pps, &[0, 0]].concat())
        } else {
            (sps.to_vec(), pps.to_vec())
        };
        let body = avc_sequence_header_body(&[&sps], &[&pps], self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut tag = Vec::new();
        write_tag(&mut tag, TAG_VIDEO, self.timestamp(), &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.write(&tag).await.map(|_| ())
    }

    /// Returns false when the connection should close.
    async fn item(&mut self, item: Item) -> std::io::Result<bool> {
        match item {
            // One-shot faults are Task 8.5's.
            Item::Fault(_) => {}
            Item::Params {
                signal: ResizeSignal::CloseFlv,
                ..
            } => return Ok(false),
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::SequenceHeader,
            } => {
                self.sequence_header(&sps, &pps).await?;
            }
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::InBandSps,
            } => {
                self.inband_next = Some((sps, pps));
            }
            Item::Frame(f) => self.frame(f).await?,
        }
        Ok(true)
    }

    async fn frame(&mut self, f: Arc<OutFrame>) -> std::io::Result<()> {
        if !self.seen_idr && !f.idr {
            return Ok(());
        }
        self.seen_idr = true;
        let mut nals: Vec<Bytes> = Vec::new();
        if f.idr
            && let Some((sps, pps)) = self.inband_next.take()
        {
            nals.push(sps);
            nals.push(pps);
        }
        nals.extend(f.nals.iter().cloned());
        let refs: Vec<&[u8]> = nals.iter().map(|n| n.as_ref()).collect();
        let mut body = Vec::new();
        let ct = self.profile.composition_time_ms;
        avc_nalu_body(&mut body, f.idr, ct, &refs, self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut tag = Vec::with_capacity(body.len() + 15);
        write_tag(&mut tag, TAG_VIDEO, self.timestamp(), &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let sim_tx = self.write(&tag).await?;
        self.frames_written += 1;
        let vcl = nals
            .iter()
            .filter(|n| matches!(nal_type(n), 1 | 5))
            .map(|n| n.as_ref());
        self.shared.record_at(
            sim_tx,
            SimEvent::FlvAu {
                conn: self.conn,
                seq: f.seq,
                source_index: f.source_index,
                frame_id: frame_id(vcl),
                idr: f.idr,
            },
        );
        Ok(())
    }
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    conn: u64,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    profile: Profile,
) {
    let policy = shared.policy();
    let token_ok = match (req.query_token(), req.cookie_token.as_deref()) {
        (Some(q), Some(c)) => q == c && shared.token_valid(q),
        _ => false,
    };
    let status = if req.method != "GET" || req.path() != "/av.flv" {
        Some(404)
    } else if !token_ok {
        Some(403)
    } else if let Some(s) = policy.flv_status {
        Some(s)
    } else if policy.refuse_concurrent_flv && shared.stats().flv_open > 0 {
        Some(503)
    } else {
        None
    };
    if let Some(status) = status {
        shared.record(SimEvent::FlvRefused { status });
        let _ = respond(&mut io, status, "application/json", b"{\"result\":403}").await;
        return;
    }
    let Some(mut sub) = enc.subscribe().await else {
        return;
    };
    shared.record(SimEvent::FlvOpen { conn });
    let (mut rd, wr) = tokio::io::split(io);
    let mut w = Writer {
        out: wr,
        profile,
        conn,
        shared: shared.clone(),
        frames_written: 0,
        seen_idr: false,
        inband_next: None,
    };
    let mut head = FLV_HEAD.to_vec();
    write_flv_header(&mut head, false, true);
    let mut ok = w.write(&head).await.is_ok();
    if ok && !policy.skip_sequence_header {
        ok = w.sequence_header(&sub.sps, &sub.pps).await.is_ok();
    }
    let mut scratch = [0u8; 256];
    while ok {
        tokio::select! {
            item = sub.rx.recv() => match item {
                Some(item) => ok = w.item(item).await.unwrap_or(false),
                None => ok = false,
            },
            n = rd.read(&mut scratch) => ok = matches!(n, Ok(n) if n > 0),
        }
    }
    let _ = w.out.shutdown().await;
    shared.record(SimEvent::FlvClose { conn });
}
```

- [ ] **Step 4: Serve it.** In `crates/kvm-sim/src/lib.rs`:

replace the module list (from the `// av.flv (Tasks 8.4, 8.5) …` comment through `mod web;`) with

```rust
// av.flv's faults (Task 8.5) read `encoder::Item::Fault`; the websocket
// (Task 8.6) is the last user of `state`.
#[allow(dead_code)]
mod encoder;
mod flv;
mod http;
mod source;
#[allow(dead_code)]
mod state;
mod tls;
mod web;
```

add the encoder handle and the profile to `ConnCtx`:

```rust
/// What every connection task shares.
struct ConnCtx {
    shared: Arc<Shared>,
    acceptor: TlsAcceptor,
    password: String,
    enc: EncoderHandle,
    profile: Profile,
}
```

replace `serve_connection` with

```rust
/// One accepted connection: TLS, then its port's service. The websocket is
/// Task 8.6's; until then the control port answers 404.
async fn serve_connection(kind: PortKind, tcp: TcpStream, conn: u64, ctx: Arc<ConnCtx>) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(tcp)).await
    else {
        return;
    };
    let Ok(Some(req)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, http::read_request(&mut tls)).await
    else {
        return;
    };
    match kind {
        PortKind::Web => web::serve(tls, req, &ctx.shared, &ctx.password).await,
        PortKind::Video => {
            let (shared, enc) = (ctx.shared.clone(), ctx.enc.clone());
            flv::serve(tls, req, conn, shared, enc, ctx.profile).await;
        }
        PortKind::Control => {
            let _ = http::respond(&mut tls, 404, "text/plain", b"not yet").await;
        }
    }
}
```

and in `KvmSim::start` replace the `ConnCtx` literal with

```rust
        let ctx = Arc::new(ConnCtx {
            shared: shared.clone(),
            acceptor: id.acceptor,
            password: cfg.password.clone(),
            enc: enc.clone(),
            profile: cfg.profile,
        });
```

- [ ] **Step 5: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 20 integration passed (`flv` 12).
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-sim
git commit -m "kvm-sim: av.flv in the ES3 profile — padded sequence header, tag = AU, shared encoder, resize" \
  -m "Every write timed and stamped (sim_tx); a stalled viewer drops only its own frames." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.5: One-shot faults on `av.flv`

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/flv.rs` (replace), `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/faults.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/main.rs`
- Test: `tests/sim/faults.rs`

**Interfaces:**
- Consumes: Task 8.4; in tests, `kvm_proto::video` (4.6) as the oracle and `kvm_proto::{flv::FlvError, h264::picture::SliceRefusal, h264::sanitize::NalRefusal}` for the expected refusals.
- Produces: every `Fault` applied by each open FLV to its next tag on the wire — `OversizeTag`, `BadPrevTagSize`, `EncryptedTag`, `BadStreamId` in the tag header; `HevcCodecId`, `EnhancedHevc`, `CompositionTime(i32)`, `TwoPictures`, `BSlice`, `StartCodeInNal`, `ForbiddenBit`, `TooManyNals` in the body; `EndOfSequence` now; `Close` closes; `Silence` keeps the FLV open and sends nothing more (§11.3's `flv_idle_timeout` case). A faulted tag records no `FlvAu`.

- [ ] **Step 1: Write the failing tests.** Add `mod faults;` to `tests/sim/main.rs` (above `mod flv;`) and create `tests/sim/faults.rs` — every fault reaches kvm-proto's admission as exactly its §6.9 refusal, compared whole (a malformed B slice h264-reader cannot parse would be `Unparsable`, not `SliceType(1)`):

```rust
//! Every one-shot fault reaches the bridge's admission as exactly its §6.9
//! refusal (kvm-proto is the oracle).
use crate::support::{FlvClient, es3_sim, login};
use kvm_proto::flv::FlvError;
use kvm_proto::h264::picture::SliceRefusal;
use kvm_proto::h264::sanitize::NalRefusal;
use kvm_proto::video::{AdmissionConfig, AdmissionError, Framing, Incompatible, VideoAdmission};
use kvm_sim::{Fault, Pacing, SimEvent};
use std::time::{Duration, Instant};

/// How a stream ended for the bridge's admission.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Refused(AdmissionError),
    EndOfSequence,
    Eof,
}

/// Stream an IDR and a P frame, inject `fault`, stream two more, and return
/// the first refusal (or the end of the stream).
async fn first_refusal(fault: Option<Fault>, skip_sequence_header: bool) -> Outcome {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.skip_sequence_header = skip_sequence_header);
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    sim.advance(2);
    let skip = if skip_sequence_header { 0 } else { 3 };
    for _ in 0..skip {
        adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
    }
    if let Some(f) = fault {
        sim.inject(f);
    }
    sim.advance(2);
    loop {
        let tag = match c.next().await {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::Eof,
            Err(e) => return Outcome::Refused(AdmissionError::from(e)),
        };
        match adm.admit(tag, Instant::now()) {
            Ok(a) if a.end_of_sequence => return Outcome::EndOfSequence,
            Ok(_) => {}
            Err(e) => return Outcome::Refused(e),
        }
    }
}

#[tokio::test]
async fn each_fault_is_its_own_section_6_9_refusal() {
    use Outcome::{EndOfSequence, Eof, Refused};
    let flv = |e: FlvError| Refused(AdmissionError::from(e));
    let framing = |f: Framing| Refused(AdmissionError::Framing(f));
    let incompatible = |i: Incompatible| Refused(AdmissionError::Incompatible(i));
    let cases = [
        (Fault::OversizeTag, flv(FlvError::OversizeTag)),
        (Fault::BadPrevTagSize, flv(FlvError::BadPrevTagSize)),
        (Fault::EncryptedTag, flv(FlvError::EncryptedTag)),
        (Fault::BadStreamId, flv(FlvError::BadStreamId)),
        (Fault::HevcCodecId, incompatible(Incompatible::Codec(12))),
        (
            Fault::EnhancedHevc,
            incompatible(Incompatible::Enhanced(*b"hvc1")),
        ),
        (
            Fault::CompositionTime(17),
            incompatible(Incompatible::CompositionTime { first: 16, now: 17 }),
        ),
        (Fault::TwoPictures, framing(Framing::NotOnePicture)),
        (
            Fault::BSlice,
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(1))),
        ),
        (
            Fault::StartCodeInNal,
            framing(Framing::Nal(NalRefusal::StartCode)),
        ),
        (
            Fault::ForbiddenBit,
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
        ),
        (Fault::TooManyNals, flv(FlvError::TooManyNals)),
        (Fault::EndOfSequence, EndOfSequence),
        (Fault::Close, Eof),
    ];
    for (fault, want) in cases {
        assert_eq!(first_refusal(Some(fault), false).await, want, "{fault:?}");
    }
    assert_eq!(
        first_refusal(None, true).await,
        flv(FlvError::NalBeforeSequenceHeader)
    );
}

#[tokio::test]
async fn silence_keeps_the_flv_open_and_sends_nothing() {
    // §11.3's `flv_idle_timeout` case: no byte and no EOF.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(2);
    for _ in 0..3 {
        c.next().await.unwrap().unwrap(); // sequence header, IDR, P
    }
    sim.inject(Fault::Silence);
    sim.advance(3);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), c.next())
            .await
            .is_err(),
        "nothing arrives and the connection stays open"
    );
    assert_eq!(sim.stats().flv_open, 1);
    let aus = sim
        .events()
        .iter()
        .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
        .count();
    assert_eq!(aus, 2);
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim --test sim faults::`
Expected: FAIL — `each_fault_is_its_own_section_6_9_refusal`: `OversizeTag`: left `Eof`, right `Refused(Framing(Flv(OversizeTag)))` (the fault is ignored, the stream goes quiet, and the client's 5 s read times out); `silence_keeps_the_flv_open_and_sends_nothing`: the next tag arrives inside the 300 ms window.

- [ ] **Step 3: Apply the faults.** Replace `crates/kvm-sim/src/flv.rs` with the following. Relative to Task 8.4's file: the module doc, the imports and the `B_SLICE`/`AUD` constants; `Writer`'s `silenced`, `pending` and `held`; `item`'s fault arms; `frame`'s fault handling (a held picture for `TwoPictures`, the body and header corruptions, no `FlvAu` for a faulted tag); `corrupt_first_vcl`; and `serve`'s `Writer` literal. `timestamp`, `write`, `sequence_header` and the rest of `serve` are unchanged:

```rust
//! `GET /av.flv?token=…` (§3.1): a close-delimited HTTP-FLV stream in the
//! profile's tag shape — one tag per access unit, `CompositionTime` per the
//! profile on coded tags (0 on the sequence header), the profile's NAL
//! length size — with one-shot faults applied on the wire.
use crate::encoder::{EncoderHandle, Item, OutFrame};
use crate::http::{FLV_HEAD, Request, respond};
use crate::state::{Shared, SimEvent};
use crate::{Fault, Profile, ResizeSignal};
use bytes::Bytes;
use kvm_proto::flv::mux::{
    RawTagHeader, TAG_VIDEO, avc_end_of_sequence_body, avc_nalu_body, avc_sequence_header_body,
    video_tag_byte, write_flv_header, write_raw_tag, write_tag,
};
use kvm_proto::h264::frame_id;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A slice NAL whose header prefix is `first_mb 0, slice_type 1 (B), pps 0`.
const B_SLICE: [u8; 2] = [0x41, 0xAC];
/// A tiny AUD, repeated to exceed §6.2's 128 NALs per tag.
const AUD: [u8; 2] = [0x09, 0xF0];

struct Writer<W> {
    out: W,
    profile: Profile,
    conn: u64,
    shared: Arc<Shared>,
    frames_written: u64,
    seen_idr: bool,
    silenced: bool,
    pending: Option<Fault>,
    held: Option<Arc<OutFrame>>,
    inband_next: Option<(Bytes, Bytes)>,
}

fn nal_type(n: &[u8]) -> u8 {
    n.first().map_or(0, |b| b & 0x1F)
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn timestamp(&self) -> u32 {
        let ms = self.frames_written * 1000 / u64::from(self.profile.fps.max(1));
        u32::try_from(ms).unwrap_or(u32::MAX)
    }

    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<Instant> {
        let start = Instant::now();
        self.out.write_all(bytes).await?;
        self.out.flush().await?;
        let done = Instant::now();
        self.shared.write_blocked(done - start);
        Ok(done)
    }

    async fn sequence_header(&mut self, sps: &[u8], pps: &[u8]) -> std::io::Result<()> {
        // The ES3 pads its config record's SPS with one zero byte and its PPS
        // with two (`census.md`); admission trims them (D2).
        let (sps, pps) = if self.profile.padded_param_sets {
            ([sps, &[0]].concat(), [pps, &[0, 0]].concat())
        } else {
            (sps.to_vec(), pps.to_vec())
        };
        let body = avc_sequence_header_body(&[&sps], &[&pps], self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut tag = Vec::new();
        write_tag(&mut tag, TAG_VIDEO, self.timestamp(), &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.write(&tag).await.map(|_| ())
    }

    /// Returns false when the connection should close.
    async fn item(&mut self, item: Item) -> std::io::Result<bool> {
        match item {
            Item::Fault(Fault::Close) => return Ok(false),
            Item::Fault(Fault::Silence) => self.silenced = true,
            Item::Fault(Fault::EndOfSequence) => {
                let mut tag = Vec::new();
                let _ = write_tag(
                    &mut tag,
                    TAG_VIDEO,
                    self.timestamp(),
                    &avc_end_of_sequence_body(),
                );
                self.write(&tag).await?;
            }
            Item::Fault(f) => self.pending = Some(f),
            Item::Params {
                signal: ResizeSignal::CloseFlv,
                ..
            } => return Ok(false),
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::SequenceHeader,
            } => {
                self.sequence_header(&sps, &pps).await?;
            }
            Item::Params {
                sps,
                pps,
                signal: ResizeSignal::InBandSps,
            } => {
                self.inband_next = Some((sps, pps));
            }
            Item::Frame(f) => self.frame(f).await?,
        }
        Ok(true)
    }

    async fn frame(&mut self, f: Arc<OutFrame>) -> std::io::Result<()> {
        if self.silenced || (!self.seen_idr && !f.idr) {
            return Ok(());
        }
        self.seen_idr = true;
        if matches!(self.pending, Some(Fault::TwoPictures)) && self.held.is_none() {
            self.held = Some(f);
            return Ok(());
        }
        let mut nals: Vec<Bytes> = Vec::new();
        let mut fault = None;
        if let Some(h) = self.held.take() {
            nals.extend(h.nals.iter().cloned());
            fault = self.pending.take();
        }
        if f.idr
            && let Some((sps, pps)) = self.inband_next.take()
        {
            nals.push(sps);
            nals.push(pps);
        }
        nals.extend(f.nals.iter().cloned());
        if fault.is_none() {
            fault = self.pending.take();
        }
        let mut ct = self.profile.composition_time_ms;
        match &fault {
            Some(Fault::CompositionTime(c)) => ct = *c,
            Some(Fault::BSlice) => nals = vec![Bytes::from_static(&B_SLICE)],
            Some(Fault::StartCodeInNal) => corrupt_first_vcl(&mut nals, |v| {
                v.splice(1..1, [0, 0, 1]);
            }),
            Some(Fault::ForbiddenBit) => corrupt_first_vcl(&mut nals, |v| {
                if let Some(b) = v.first_mut() {
                    *b |= 0x80;
                }
            }),
            Some(Fault::TooManyNals) => nals = vec![Bytes::from_static(&AUD); 129],
            _ => {}
        }
        let refs: Vec<&[u8]> = nals.iter().map(|n| n.as_ref()).collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, f.idr, ct, &refs, self.profile.length_size)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let mut header = RawTagHeader {
            type_byte: TAG_VIDEO,
            timestamp_ms: self.timestamp(),
            stream_id: 0,
            data_size: None,
            prev_tag_size: None,
        };
        match &fault {
            Some(Fault::OversizeTag) => header.data_size = Some(0x00FF_FFFF),
            Some(Fault::BadPrevTagSize) => {
                header.prev_tag_size = Some(u32::try_from(body.len() + 12).unwrap_or(0));
            }
            Some(Fault::EncryptedTag) => header.type_byte = 0x20 | TAG_VIDEO,
            Some(Fault::BadStreamId) => header.stream_id = 1,
            Some(Fault::HevcCodecId) => {
                if let Some(b) = body.first_mut() {
                    *b = video_tag_byte(if f.idr { 1 } else { 2 }, 12);
                }
            }
            Some(Fault::EnhancedHevc) => body = vec![0x80 | 0x10 | 1, b'h', b'v', b'c', b'1'],
            _ => {}
        }
        let mut tag = Vec::with_capacity(body.len() + 15);
        write_raw_tag(&mut tag, &header, &body)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let sim_tx = self.write(&tag).await?;
        self.frames_written += 1;
        if fault.is_none() {
            let vcl = nals
                .iter()
                .filter(|n| matches!(nal_type(n), 1 | 5))
                .map(|n| n.as_ref());
            self.shared.record_at(
                sim_tx,
                SimEvent::FlvAu {
                    conn: self.conn,
                    seq: f.seq,
                    source_index: f.source_index,
                    frame_id: frame_id(vcl),
                    idr: f.idr,
                },
            );
        }
        Ok(())
    }
}

fn corrupt_first_vcl(nals: &mut [Bytes], f: impl FnOnce(&mut Vec<u8>)) {
    if let Some(n) = nals.iter_mut().find(|n| matches!(nal_type(n), 1 | 5)) {
        let mut v = n.to_vec();
        f(&mut v);
        *n = Bytes::from(v);
    }
}

pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    conn: u64,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    profile: Profile,
) {
    let policy = shared.policy();
    let token_ok = match (req.query_token(), req.cookie_token.as_deref()) {
        (Some(q), Some(c)) => q == c && shared.token_valid(q),
        _ => false,
    };
    let status = if req.method != "GET" || req.path() != "/av.flv" {
        Some(404)
    } else if !token_ok {
        Some(403)
    } else if let Some(s) = policy.flv_status {
        Some(s)
    } else if policy.refuse_concurrent_flv && shared.stats().flv_open > 0 {
        Some(503)
    } else {
        None
    };
    if let Some(status) = status {
        shared.record(SimEvent::FlvRefused { status });
        let _ = respond(&mut io, status, "application/json", b"{\"result\":403}").await;
        return;
    }
    let Some(mut sub) = enc.subscribe().await else {
        return;
    };
    shared.record(SimEvent::FlvOpen { conn });
    let (mut rd, wr) = tokio::io::split(io);
    let mut w = Writer {
        out: wr,
        profile,
        conn,
        shared: shared.clone(),
        frames_written: 0,
        seen_idr: false,
        silenced: false,
        pending: None,
        held: None,
        inband_next: None,
    };
    let mut head = FLV_HEAD.to_vec();
    write_flv_header(&mut head, false, true);
    let mut ok = w.write(&head).await.is_ok();
    if ok && !policy.skip_sequence_header {
        ok = w.sequence_header(&sub.sps, &sub.pps).await.is_ok();
    }
    let mut scratch = [0u8; 256];
    while ok {
        tokio::select! {
            item = sub.rx.recv() => match item {
                Some(item) => ok = w.item(item).await.unwrap_or(false),
                None => ok = false,
            },
            n = rd.read(&mut scratch) => ok = matches!(n, Ok(n) if n > 0),
        }
    }
    let _ = w.out.shutdown().await;
    shared.record(SimEvent::FlvClose { conn });
}
```

In `crates/kvm-sim/src/lib.rs`, replace the module list (from the `// av.flv's faults (Task 8.5) …` comment through `mod web;`) with

```rust
mod encoder;
mod flv;
mod http;
mod source;
// The websocket (Task 8.6) is the last user of `state`.
#[allow(dead_code)]
mod state;
mod tls;
mod web;
```

- [ ] **Step 4: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 22 integration passed (`faults` 2).
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/kvm-sim
git commit -m "kvm-sim: one-shot av.flv faults, each reaching admission as its own §6.9 refusal" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.6: The control websocket

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/ws.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/src/lib.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/websocket.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/main.rs`
- Test: `tests/sim/websocket.rs`

**Interfaces:**
- Consumes: Task 8.3; `kvm_proto::hid::HidFrame` (5.1) in tests; tokio-tungstenite.
- Produces: the websocket upgrade on `/websocket` needs a live token cookie (else 403; `Policy::ws_status` answers with its status instead); every data message becomes `SimEvent::Hid` verbatim; `Policy::pause_ws_reads` stops reading (with `SimConfig::control_recv_buffer`, the client's writes back up); `close_websockets()` and `send_ws_oversize(len)` act on every open websocket.

- [ ] **Step 1: Write the failing tests.** Add `mod websocket;` to `tests/sim/main.rs` (after `mod source;`) and create `tests/sim/websocket.rs`:

```rust
use crate::support::{T, es3_sim, login, sim_with, target};
use futures_util::{SinkExt, StreamExt};
use kvm_proto::hid::HidFrame;
use kvm_sim::{KvmSim, Pacing, SimEvent};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

async fn ws(
    sim: &KvmSim,
    token: &str,
    limit: Option<usize>,
) -> Result<
    tokio_tungstenite::WebSocketStream<kvm_probe::kvm::BoxedIo>,
    tokio_tungstenite::tungstenite::Error,
> {
    let io = kvm_probe::kvm::connect_to(&target(sim), sim.ports().control, Some(sim.spki_sha256()))
        .await
        .unwrap();
    let mut req = format!("wss://127.0.0.1:{}/websocket", sim.ports().control)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Cookie", format!("token={token}").parse().unwrap());
    let cfg = WebSocketConfig {
        max_message_size: limit,
        max_frame_size: limit,
        ..WebSocketConfig::default()
    };
    tokio_tungstenite::client_async_with_config(req, io, Some(cfg))
        .await
        .map(|(w, _)| w)
}

#[tokio::test]
async fn hid_frames_are_recorded_verbatim() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, None).await.unwrap();
    let frames = [
        HidFrame::SetMode { hid_type: 0 },
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        },
        HidFrame::abs_mouse(0, 100, 200),
    ];
    for f in frames {
        w.send(Message::Binary(f.to_vec())).await.unwrap();
    }
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::Hid { .. }))
                .count()
                == 3
        })
        .await
        .unwrap();
    let got: Vec<HidFrame> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::Hid { bytes, .. } => HidFrame::decode(bytes).ok(),
            _ => None,
        })
        .collect();
    assert_eq!(got, frames);
    assert_eq!(sim.stats().ws_open, 1);
}

#[tokio::test]
async fn upgrade_needs_a_live_token() {
    let sim = es3_sim(Pacing::Manual).await;
    assert!(ws(&sim, "0.1", None).await.is_err());
    sim.wait_for(T, |e| e.contains(&SimEvent::WsRefused { status: 403 }))
        .await
        .unwrap();
}

#[tokio::test]
async fn closing_and_oversize_faults_reach_the_client() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, Some(4096)).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsOpen { .. }))
    })
    .await
    .unwrap();
    sim.send_ws_oversize(64 << 20);
    let r = tokio::time::timeout(T, w.next()).await.unwrap();
    assert!(matches!(r, Some(Err(_))), "{r:?}");
    let mut w2 = ws(&sim, &token, None).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::WsOpen { .. }))
            .count()
            == 2
    })
    .await
    .unwrap();
    sim.close_websockets();
    let r = tokio::time::timeout(T, w2.next()).await.unwrap();
    assert!(matches!(r, Some(Ok(Message::Close(_))) | None), "{r:?}");
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::WsClose { .. }))
            .count()
            == 2
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_policy_status_refuses_the_upgrade() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.ws_status = Some(503));
    assert!(ws(&sim, &token, None).await.is_err());
    sim.wait_for(T, |e| e.contains(&SimEvent::WsRefused { status: 503 }))
        .await
        .unwrap();
}

#[tokio::test]
async fn paused_reads_back_up_the_clients_writes_until_resumed() {
    // §11.3's blocked websocket write: kvm-sim stops reading and its control
    // sockets have a 4 KiB receive buffer, so 16 MB of writes (past any
    // loopback send buffer) cannot drain until reads resume.
    const N: usize = 256;
    let sim = sim_with(|c| {
        c.pacing = Pacing::Manual;
        c.control_recv_buffer = Some(4096);
    })
    .await;
    let token = login(&sim).await;
    let mut w = ws(&sim, &token, None).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::WsOpen { .. }))
    })
    .await
    .unwrap();
    sim.set_policy(|p| p.pause_ws_reads = true);
    let mut flood = tokio::spawn(async move {
        for _ in 0..N {
            w.send(Message::Binary(vec![0x5A; 64_000])).await.unwrap();
        }
        w
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut flood)
            .await
            .is_err(),
        "the writes back up while kvm-sim is not reading"
    );
    sim.set_policy(|p| p.pause_ws_reads = false);
    let _w = tokio::time::timeout(T, flood).await.unwrap().unwrap();
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::Hid { .. }))
            .count()
            == N
    })
    .await
    .unwrap();
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `cargo test -p kvm-sim --test sim websocket::`
Expected: FAIL — every upgrade gets 404 (the control port is not a websocket yet): `ws(…).await.unwrap()` panics with an HTTP error, and `upgrade_needs_a_live_token`/`a_policy_status_refuses_the_upgrade` time out waiting for `WsRefused`.

- [ ] **Step 3: The websocket.** Create `crates/kvm-sim/src/ws.rs`:

```rust
//! The control websocket (`/websocket`, §3.1): the upgrade must carry a live
//! `Cookie: token=…`; every data message is recorded verbatim (§3.3 HID
//! frames). Tests can pause reads, close every websocket, or send the
//! client an oversize message.
use crate::http::cookie_token;
use crate::state::{Shared, SimEvent, WsCmd};
use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

// `result_large_err`: the handshake callback's `Err` type is fixed by
// tungstenite's `Callback` trait (a whole `http::Response`).
#[allow(clippy::result_large_err)]
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    conn: u64,
    shared: Arc<Shared>,
) {
    let refused = Arc::new(Mutex::new(None::<u16>));
    let (sh, rf) = (shared.clone(), refused.clone());
    let policy = shared.policy();
    let callback = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let token_ok = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(cookie_token)
            .is_some_and(|t| sh.token_valid(&t));
        let status = if req.uri().path() != "/websocket" {
            Some(404)
        } else if let Some(s) = policy.ws_status {
            Some(s)
        } else if !token_ok {
            Some(403)
        } else {
            None
        };
        match status {
            None => Ok(resp),
            Some(s) => {
                if let Ok(mut g) = rf.lock() {
                    *g = Some(s);
                }
                let mut r = ErrorResponse::new(None);
                *r.status_mut() = StatusCode::from_u16(s).unwrap_or(StatusCode::FORBIDDEN);
                Err(r)
            }
        }
    };
    let cfg = WebSocketConfig {
        max_message_size: Some(64 * 1024),
        max_frame_size: Some(64 * 1024),
        ..WebSocketConfig::default()
    };
    let mut ws =
        match tokio_tungstenite::accept_hdr_async_with_config(io, callback, Some(cfg)).await {
            Ok(ws) => ws,
            Err(_) => {
                let status = refused.lock().ok().and_then(|g| *g).unwrap_or(400);
                shared.record(SimEvent::WsRefused { status });
                return;
            }
        };
    shared.record(SimEvent::WsOpen { conn });
    let (tx, mut cmds) = mpsc::unbounded_channel();
    shared.add_ws(tx);
    loop {
        if shared.policy().pause_ws_reads {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(10)) => continue,
                cmd = cmds.recv() => if !handle(&mut ws, cmd).await { break },
            }
        }
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(b))) => shared.record(SimEvent::Hid { conn, bytes: b }),
                Some(Ok(Message::Text(t))) => shared.record(SimEvent::Hid { conn, bytes: t.into_bytes() }),
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            cmd = cmds.recv() => if !handle(&mut ws, cmd).await { break },
        }
    }
    shared.record(SimEvent::WsClose { conn });
}

/// Returns false when the websocket should end.
async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    cmd: Option<WsCmd>,
) -> bool {
    match cmd {
        Some(WsCmd::Close) | None => {
            let _ = ws.close(None).await;
            false
        }
        Some(WsCmd::Oversize(len)) => {
            // A binary frame header declaring `len` payload bytes, then 4 KiB
            // of it: the client must close at its limit without buffering.
            let mut raw = vec![0x82, 127];
            raw.extend_from_slice(&len.to_be_bytes());
            raw.extend_from_slice(&[0u8; 4096]);
            let io = ws.get_mut();
            io.write_all(&raw).await.is_ok() && io.flush().await.is_ok()
        }
    }
}
```

- [ ] **Step 4: Serve it.** In `crates/kvm-sim/src/lib.rs`, replace the module list (from the `mod encoder;` line through `mod web;`) with

```rust
mod encoder;
mod flv;
mod http;
mod source;
mod state;
mod tls;
mod web;
mod ws;
```

and replace `serve_connection` with

```rust
/// One accepted connection: TLS, then its port's service.
async fn serve_connection(kind: PortKind, tcp: TcpStream, conn: u64, ctx: Arc<ConnCtx>) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(tcp)).await
    else {
        return;
    };
    if kind == PortKind::Control {
        ws::serve(tls, conn, ctx.shared.clone()).await;
        return;
    }
    let Ok(Some(req)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, http::read_request(&mut tls)).await
    else {
        return;
    };
    match kind {
        PortKind::Web => web::serve(tls, req, &ctx.shared, &ctx.password).await,
        _ => {
            let (shared, enc) = (ctx.shared.clone(), ctx.enc.clone());
            flv::serve(tls, req, conn, shared, enc, ctx.profile).await;
        }
    }
}
```

No `allow(dead_code)` is left in `lib.rs`.

- [ ] **Step 5: Run them to see them pass.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 27 integration passed, in about 1 s (no test here uses real-time pacing).
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.
Run the binary twice more (`cargo test -p kvm-sim --test sim`) — Expected: identical results (no timing flakiness: every wait is `wait_for` with a 5 s bound; the only short windows — 300 ms in `silence_…` and `an_unreachable_kvm_…`, 500 ms in `paused_reads_…` — assert that something does *not* happen).

- [ ] **Step 6: Commit.**

```bash
git add crates/kvm-sim
git commit -m "kvm-sim: the HID-recording control websocket, with pause, close and oversize faults" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8.7: Conformance — kvm-probe measures kvm-sim the way it measured the ES3

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/conformance.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-sim/tests/sim/main.rs` (`mod conformance;`)
- Test: `tests/sim/conformance.rs`

**Interfaces:**
- Consumes: `KvmSim` (8.3–8.6); kvm-probe's census path — `capture::{run, StopAt}`, `captures::CaptureDir`, `record::TagRecord`, `report::summarize`, `trial::first_idr_latency`, `wsprobe::open_control_websocket`, `kvm::login` — the code that produced `census.md`'s Leg A.
- Produces: the fidelity gate for Plans C–E: under kvm-probe, kvm-sim's ES3 profile shows `census.md`'s stream — codec 7 only; tag = AU (`multi_picture_tags`, `continuation_tags`, `non_vcl_picture_tags` all 0); GOP 60; CT 16 on every coded tag; only NAL types 1 and 5; an SPS h264-reader refuses as sent; SPS and PPS ending in zero bytes; the first-IDR trial and the websocket open succeed; no HID frame and no logout.

This task adds only a test: kvm-sim already exists. If it fails, kvm-sim diverges from the device — fix kvm-sim (Tasks 8.2–8.6 code), never the expectations, which are `census.md`'s.

- [ ] **Step 1: Write the test.** Add `mod conformance;` to `crates/kvm-sim/tests/sim/main.rs` (after `mod support;`) and create `tests/sim/conformance.rs`. The capture is paced by hand, not by the clock: once kvm-probe's FLV is open, kvm-sim sends exactly 130 frames and then closes it, so a loaded host (tests run niced at `CPUWeight=20`) changes how long it takes, never what is captured; only the first-IDR trial uses real-time pacing, and it waits for one IDR with a 5 s bound:

```rust
//! kvm-probe, the census tool proven against the real ES3, measures kvm-sim
//! the way it measured the device (`census.md`, Leg A — stream).
use crate::support::{T, es3_sim, login, target};
use kvm_probe::capture::{StopAt, run};
use kvm_probe::captures::CaptureDir;
use kvm_probe::record::TagRecord;
use kvm_probe::report::summarize;
use kvm_sim::{Fault, KvmSim, Pacing, Profile, SimConfig, SimEvent, Source};

fn coded_aus(e: &[SimEvent]) -> usize {
    e.iter()
        .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
        .count()
}

#[tokio::test]
async fn census_capture_sees_the_es3_profile() {
    // Manual pacing: once kvm-probe's FLV is open, kvm-sim sends exactly 130
    // frames (two whole GOPs and the start of a third) and then closes it, so
    // what is captured never depends on how loaded the host is.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stop = StopAt {
        max_bytes: 8 << 20,
        max_duration: T,
    };
    let drive = async {
        sim.wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::FlvOpen { .. }))
        })
        .await
        .unwrap();
        sim.advance(130);
        sim.wait_for(T, |e| coded_aus(e) == 130).await.unwrap();
        sim.inject(Fault::Close);
    };
    let kvm = target(&sim);
    let capture = run(
        &kvm,
        Some(sim.spki_sha256()),
        &token,
        &dir,
        "sim.flv",
        &mut jsonl,
        stop,
    );
    let (stats, ()) = tokio::join!(capture, drive);
    assert_eq!(stats.unwrap().parse_errors, 0);
    let records: Vec<TagRecord> = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let s = summarize(&records);
    assert_eq!(s.codecs, [7]);
    assert_eq!(
        (
            s.multi_picture_tags,
            s.continuation_tags,
            s.non_vcl_picture_tags,
            s.bad_header_nals
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(s.gop_len, Some(60));
    // Like the real ES3, the SPS as sent is refused by h264-reader (level),
    // and both parameter sets end in zero bytes (census.md sps_hex, pps_hex).
    assert!(s.sps[0].summary.is_err());
    assert!(s.sps[0].hex.ends_with("00") && s.pps_hex[0].ends_with("0000"));
    let coded: Vec<&TagRecord> = records
        .iter()
        .filter(|r| r.avc_packet_type == Some(1))
        .collect();
    assert_eq!(coded.len(), 130);
    for r in coded {
        assert_eq!(r.composition_time, 16);
        assert!(r.nal_types.iter().all(|t| matches!(t, 1 | 5)));
    }
    assert_eq!(sim.stats().logouts, 0);
}

#[tokio::test]
async fn first_idr_and_websocket_open_work_and_send_nothing() {
    // Real-time pacing at 120 fps: the first-IDR trial waits on frames.
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    cfg.profile = Profile {
        fps: 120,
        ..Profile::es3()
    };
    let sim = KvmSim::start(cfg).await.unwrap();
    let token = login(&sim).await;
    let latency =
        kvm_probe::trial::first_idr_latency(&target(&sim), Some(sim.spki_sha256()), &token, T)
            .await
            .unwrap();
    assert!(latency < T);
    kvm_probe::wsprobe::open_control_websocket(&target(&sim), Some(sim.spki_sha256()), &token)
        .await
        .unwrap();
    let ev = sim
        .wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::WsClose { .. }))
        })
        .await
        .unwrap();
    assert!(!ev.iter().any(|e| matches!(e, SimEvent::Hid { .. })));
}
```

- [ ] **Step 2: Run it.**

Run: `cargo test -p kvm-sim --test sim conformance`
Expected: 2 passed (well under a second).

- [ ] **Step 3: Run the whole crate once more.**

Run: `cargo test -p kvm-sim` — Expected: 6 unit + 29 integration passed.

- [ ] **Step 4: Commit.**

```bash
git add crates/kvm-sim/tests/sim/conformance.rs crates/kvm-sim/tests/sim/main.rs
git commit -m "kvm-sim: conformance — kvm-probe sees the census.md ES3 stream in kvm-sim" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part 9 — Close-out

### Task 9.1: Record the deviations (spec rev 6.1), README, final gates

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`
- Modify: `/home/chris/Repos/kvm-rdp/README.md`

**Interfaces:**
- Consumes: deviations D1–D10 (header of this plan), everything built in Parts 1–8.
- Produces: spec Draft rev 6.1 — the binding authority now says what Plan B built; a README that says what runs, how to test it, and that fuzzing is CI's.

- [ ] **Step 1: Check the spec does not yet carry rev 6.1.**

Run: `grep -c 'rev 6.1' docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`
Expected: `0`.

- [ ] **Step 2: Edit the spec.** Make these exact replacements in `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`:

In the header table, replace `| Status | Draft rev 6 — census-filled.` with `| Status | Draft rev 6.1 — Plan B's deviations recorded (2026-10-06); rev 6: census-filled.`

Insert above the line `**Rev 6 — census-filled (2026-10-06).** Fills every census-dependent value`:

```markdown
**Rev 6.1 — Plan B (2026-10-06).** Records what building Milestones 1 and 2
settled: POC type 1 is refused (§6.1); trailing zero bytes are trimmed from
every NAL before the §6.2 checks, at most one AUD per tag comes before any
slice, unknown FLV tag types are framing violations, and the 4 SPS / 16 PPS
limits also bound each tag's in-band sets (§6.2); one active SPS and a
sequence header that replaces every PPS, with a PPS-only change classed
`other` and byte-identical repeats raising nothing (§6.1); the level rewrite
applies H.264 A.3.1's frame-size rules in full, and with level ≤ 5.1 admits
at most 32 768 MBs per frame at 30 fps (§6.8 (a)); the fuzz-oracle module is
the one `kvm-proto` module outside the parser lint denies (§6.2); kvm-sim
speaks HTTP through httparse rather than hyper (§4.1); the POC-type-0 fixture
is ES3-shaped — limited-range BT.709 pixels under the ES3's mislabels
(§11.5).

```

In §4.1's table, replace

```markdown
| `kvm-sim` | `kvm-proto`, tokio, hyper, tokio-tungstenite, rustls (aws-lc) | Fake ES3 for tests and benches (§11.5), served over TLS |
```

with

```markdown
| `kvm-sim` | `kvm-proto`, tokio, httparse (hyper's parser), tokio-tungstenite, rustls (aws-lc) | Fake ES3 for tests and benches (§11.5), served over TLS; it writes HTTP itself so every FLV byte is observable and corruptible (rev 6.1) |
```

In §6.1, insert above the line beginning `- **PPS**: `num_slice_groups_minus1 == 0``:

```markdown
- **POC type 1 is refused** (rev 6.1): the POC rule below is computed for
  types 0 (the ES3) and 2 (x264), and no source in scope uses type 1.
```

In §6.1, insert between the SPS-change table's `| other | … |` row and `### 6.2 FLV demux and NAL sanitiser (`kvm-proto`)`:

```markdown

Parameter-set model (rev 6.1): one active SPS, the latest admitted; a
sequence header replaces every PPS, and cached PPSs that no longer parse
against a new SPS are dropped; a PPS-only change is `other`; a byte-identical
repeat (in-band SPS/PPS with every IDR) raises nothing.
```

In §6.2, replace `  8 and 18 skipped. `DataSize` is checked against the limit **before** anything` with `  8 and 18 skipped; any other tag type is a framing violation (rev 6.1). `DataSize` is checked against the limit **before** anything`, and insert after the line `  the client's start-code scanner would find NALs we never checked.`:

```markdown
- Trailing zero bytes are trimmed from every NAL before these checks (rev
  6.1): Annex B cannot tell them from `trailing_zero_8bits`, a conforming NAL
  never ends in `00`, and the ES3 appends them to its SPS and PPS
  (`census.md` `sps_hex`, `pps_hex`).
- At most one AUD per tag, before any slice (rev 6.1); §6.3 sends it first.
```

In §6.2, replace `- Limits: tag 4 MiB, 128 NALs per AU, 4 SPS, 16 PPS.` with

```markdown
- Limits: tag 4 MiB, 128 NALs per AU, 4 SPS, 16 PPS — the SPS/PPS limits
  bound a config record and, separately, each NALU tag's in-band sets: a
  fifth SPS or seventeenth PPS in one tag is a framing violation, refused
  before it is rewritten or parsed (rev 6.1).
```

and replace

```markdown
- Parser modules deny `clippy::{indexing_slicing, unwrap_used, expect_used,
  panic, arithmetic_side_effects, as_conversions}`.
```

with

```markdown
- Parser modules deny `clippy::{indexing_slicing, unwrap_used, expect_used,
  panic, arithmetic_side_effects, as_conversions}`. The one exception is
  `kvm_proto::fuzzing` (rev 6.1): the fuzz targets' bodies, whose panics are
  findings, compiled only for tests and for `fuzz/` (feature `fuzzing`, which
  CI forbids any workspace crate to enable). It parses nothing the bridge
  receives.
```

In §6.8, replace

```markdown
- (a) `"level"`: `level_idc` is raised to the lowest level whose MaxFS and
  MaxMBPS (H.264 Table A-1) admit the coded size at `video.max_fps`, and never
  lowered — **31 → 40** for the ES3's 1080p30 (MaxFS 8192 ≥ 8160 MBs; MaxMBPS
```

with

```markdown
- (a) `"level"`: `level_idc` is raised to the lowest level whose MaxFS and
  MaxMBPS (H.264 Table A-1) admit the coded size at `video.max_fps` — with
  A.3.1's `PicWidthInMbs²` and `FrameHeightInMbs²` ≤ 8 × MaxFS as well (rev
  6.1), which matters only for extreme aspect ratios — and never lowered. With
  §6.1's level ≤ 5.1 this admits at most 32 768 MBs per frame at 30 fps (e.g.
  4096×2048): 4096×2304 needs level 5.2 and is refused after the rewrite.
  **31 → 40** for the ES3's 1080p30 (MaxFS 8192 ≥ 8160 MBs; MaxMBPS
```

In §11.5, replace

```markdown
    the same bit-level SPS re-serialisation as the rewriter (§6.8), so Plan B
    builds both together;
```

with

```markdown
    the same bit-level SPS re-serialisation as the rewriter (§6.8), so Plan B
    builds both together. Built as `360p30_es3like_poc0.h264` (rev 6.1):
    Baseline, keyint 60, ref 1, limited-range BT.709 pixels as the ES3's
    measure, under the ES3's mislabels (level 2.1 for 640×360, VUI full
    range 5/6/5, constraint flags 0), and a decode md5 equal to its x264
    source's — kvm-sim's ES3 profile streams it;
```

- [ ] **Step 3: Edit the README.** In `README.md`, replace `**Status:** design. Nothing runs yet.` with:

```markdown
**Status:** in development. `kvm-proto` (hardened FLV/H.264 admission, the
SPS rewriter, HID frames) and `kvm-sim` (a fake ES3 for tests) are built and
tested; the bridge itself does not run yet.

## Development

`nix develop` provides the pinned toolchain; its `cargo` is niced and
memory-capped, and every worktree shares one target dir.

- `cargo test --workspace --all-features` — unit, property, fixture and
  kvm-sim tests (every fuzz target's body also runs over its seeds here).
- `scripts/gen-fixtures.sh` — regenerate the committed synthetic fixtures.
  Fixtures never come from a real KVM.
- Fuzzing runs in CI only (spec §13): every kvm-proto target for 5 s on each
  PR and 300 s nightly, through `scripts/fuzz.sh`, which caps time, memory,
  input size and corpus size. To replay a crash CI uploaded:
  `nix develop .#fuzz -c sh -c 'cargo fuzz run --fuzz-dir fuzz --target-dir "$CARGO_TARGET_DIR/fuzz-build" -a <target> <artifact>'` (the same `-a` build CI uses, inside the dir `scripts/fuzz.sh clean` removes).
```

- [ ] **Step 4: Final gates** (no fuzz run: that is CI's, §13).

Run: `cargo fmt --all -- --check` — Expected: clean.
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean.
Run: `cargo test --workspace --all-features` — Expected: all pass, twice in a row with identical counts (kvm-probe 88 + 37 with 1 ignored; kvm-proto 146 unit + 8 fixture; kvm-sim 6 + 29).
Run: `cargo tree --workspace --target all -i ring` — Expected: no tree printed.
Run: `cargo check --manifest-path fuzz/Cargo.toml` — Expected: the nine fuzz targets check clean on stable.
Run: `cargo tree --workspace -e features -i kvm-proto | grep -c 'feature "fuzzing"'` — Expected: `0` (D8).
Run: `git status --porcelain` — Expected: only the two files of this task; nothing under `captures/`, `fuzz/artifacts/` or `target/` tracked.

- [ ] **Step 5: Commit.**

```bash
git add docs/superpowers/specs/2026-10-05-kvm-rdp-design.md README.md
git commit -m "spec rev 6.1: record Plan B's deviations; README status and development commands" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Planning notes

Revision 2 of this plan (2026-10-06) answers four independent critiques (spec coverage, code truth, tests and hostile input, format and budget). Every code change was rebuilt in a scratch copy of the workspace inside the repo's devshell before it was written here: `cargo clippy --workspace --all-targets --all-features -D warnings` is clean, kvm-proto passes 146 unit + 8 fixture tests, kvm-sim 6 unit + 29 integration (stable over three runs), kvm-probe is unchanged at 88 + 37 with 1 ignored, the intermediate states after Tasks 8.3, 8.4 and 8.5 are clippy-clean and pass on their own (and Task 8.4–8.6's `lib.rs` edits applied in order reproduce the final file byte for byte), `fuzz/` checks on stable, and `scripts/fuzz.sh` was exercised only as a dry run. Mutation checks: dropping any one of `flv_opened`'s three resets, clearing the pins on a reconnect, or leaving PPSs in the parse context after `clear_pps` each fails the new tests. The ES3-like fixture was regenerated twice with the limited-range source and hashes the same both times; `ffmpeg_level_vui_sps_hex` did not change (the transform replaces the whole VUI signal type).

**Rejected findings:** none. Where a finding offered alternatives, the choice was:

- Fuzzing on the host (spec-coverage, format-budget): local `scripts/fuzz.sh run` calls were removed rather than adding a deviation — §4.1, §11.2 and §13 all say CI-only, and the stable seed tests already run every target body. `.#fuzz` stays, for replaying a CI crash artifact only.
- `kvm_proto::fuzzing` lint exception (three findings): recorded as D8 and gated in CI, rather than moved behind a `--cfg` — the feature keeps `cargo test --all-features` exercising the bodies with no extra build flags.
- Two SPS-change classifiers: `ParamState` now classifies through Plan A's `classify_sps_change`, keeping only D4's byte-identical rule in front of it; `classify_sps_change` keeps its census semantics (identical summaries are `Other`) and stays exported for kvm-probe.
- In-band parameter-set floods: the per-tag 4 SPS / 16 PPS cap (D10) rather than recording the per-config-record reading as a deviation — it bounds the rewrite cost per tag and is the safe direction.
- `clear_pps`: the h264-reader context is rebuilt from the active SPS (with a test for a hand-built empty sequence header), rather than refusing empty lists in `sequence_header` — the demuxer already refuses those, and the context fix closes the stale-PPS path whatever builds the tag.
- Stalled-viewer determinism: `SimConfig::video_send_buffer` (64 KiB in the test) plus `assert!(frames_dropped > 0)`, rather than streaming more frames.
- Conformance pacing: `Pacing::Manual` driven by a helper future that sends exactly 130 frames once kvm-probe's FLV is open and then injects `Fault::Close`, rather than a tag-count stop in kvm-probe (whose `StopAt` has none).
- Unreachable KVM: a `Policy::blackhole` switch (accept, then silence) rather than documentation, so Plan C keeps the event log and no loopback port is freed for a parallel test.
- `wait_for` cost: the predicate borrows the log under the lock and the cap drops from 2 000 000 to 1 000 000 events with `SimStats::events_dropped`, rather than a configurable cap (no new API).
- Task 8.3 was split into 8.3 (`KvmSim`, TLS, login), 8.4 (`av.flv`), 8.5 (faults) and 8.6 (websocket); the old 8.4 is now 8.7. Task 6.1 was also split (6.2: every fixture through admission), so the old "Task 6.2" reference in Task 3.3 is now correct rather than renumbered.

**Deferred minors** (optional parts of findings, each cheap to add later, none blocking):

- The `admission` fuzz target could call `flv_opened()` on a selector byte to fuzz reconnects (tests lens, optional part of the reconnect finding). Deferred: it would change every `admission` seed's format and `the_es3_seed_admits_end_to_end`; the reconnect resets are now pinned by `an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins`.
- kvm-sim could emit an identical sequence header on `set_signal` behind a `Profile` flag (tests lens, optional part of the NO SIGNAL finding). Deferred: the ES3 was not seen to do it (`census.md`), and `an_identical_sequence_header_mid_connection_raises_nothing` pins the admission side.
- The `sps_rewrite` fuzz target could also treat `RewriteError::H264Reader` as a finding when h264-reader accepts the input as sent (tests lens, optional). Deferred: h264-reader may legitimately refuse a rewritten SPS the input never exercised (e.g. a `max_dec_frame_buffering` above the raised level's DPB for an input with many reference frames, which §6.1 refuses anyway), so it would raise false findings; `SelfCheck` and `Disagrees` — the real serialiser bugs — are now findings.
- Found while revising, outside the findings: Plan A's `manifest()` decodes every fixture with `ffprobe -count_frames` and no thread cap (§13's `-threads 4`). Left as is: it is Plan A's committed code, `-count_frames` on ≤ 330-frame 360p streams is brief, and changing the fixture tool's ffprobe arguments is a separate, testable change for whichever plan next touches `scripts/gen-fixtures.sh`.
