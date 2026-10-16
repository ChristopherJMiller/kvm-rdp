# kvm-rdp Plan E — L3 interop, CI, the container image and the perf pass (Milestones 5 + 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the bridge for deployment: close every item carried to Plan E, add the L3 FreeRDP interop tier, harden CI (SHA-pinned actions, cargo-deny, a nightly), publish a minimal, non-root, reproducible, signed image to `ghcr.io/christopherjmiller/kvm-rdp` that a deployment plan can pin as `:sha-<short>@sha256:…`, and build `kvm-bench` to prove §10.1's targets.

**Architecture:** Five strands, each landing as small tasks with their own tests. (1) Bridge carries — a non-default `test-hooks` feature removes the test seams from the release binary, a KVM-runtime watch releases held input when the RDP thread stalls and a queue resync ends a typing paste (spec rev 6.3's m3 and m4), a 200 px floor joins §6.1's SPS limits, third-party log lines are rate-limited per callsite, and a counting allocator (`alloc_stats`, exported by `alloc-stats` builds) measures §10.1's allocation budgets. (2) CI — every action pinned by SHA and checked by a script, cargo-deny over the production graph, every non-Rust CI tool pinned through the flake (except in `publish`, which evaluates no repository code), the fuzz nightly's false positive fixed, and a nightly workflow. (3) L3 — `#[ignore]` cases in the L2 binary drive the bridge binary with the flake's FreeRDP under Xvfb and read the decoded picture back from Xvfb's framebuffer. (4) The image — a Dockerfile on distroless `cc-debian12:nonroot`, both bases pinned by digest, built reproducibly by BuildKit, smoke-tested, and pushed from main only as the exact tested OCI archive, then signed. (5) The perf pass — `kvm-bench`, a new crate whose pure library holds the statistics and whose binary runs kvm-sim and a lean IronRDP client in one process against the bridge as a subprocess.

**Tech Stack:** Rust 1.94.1 (edition 2024); IronRDP fork `ChristopherJMiller/IronRDP` @ `c99eece22338e26ee6839ee89c29617bbcadbb65` (unchanged pin; kvm-bench uses the client crates L2 already compiles, plus `ironrdp-server` for the null bridge, all at that rev); tokio 1, rustls 0.23 on aws-lc-rs (0.23.46 from Task 2.2, for RUSTSEC-2026-0346..0349); tracing-subscriber 0.3.23 (`Filter::event_enabled`); FreeRDP 3.32.1 and `xvfb-run` from the flake's nixpkgs (OpenH264 on); Docker BuildKit with a pinned `moby/buildkit` image; `gcr.io/distroless/cc-debian12:nonroot`; skopeo and cosign on GitHub's `ubuntu-24.04` runners; cargo-deny, actionlint, shellcheck and yq-go from the flake.

**Spec:** `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (Draft rev 6.3, on branch `plan-d`) — the binding authority — with `docs/census.md`. This plan is §12's planning unit **E**: "M5 + M6: L3, CI, image, perf pass (rev 6.2: CI's job timeout, tracked-secrets gate and target-budget step landed with Plan C, DC19; rev 6.3: also the carries below)". The ledgers it carries from are binding inputs: `.superpowers/sdd/2026-10-07-kvm-rdp-plan-c/{progress,final-review}.md` (Recommendations, "Plan E") and `.superpowers/sdd/2026-10-14-kvm-rdp-plan-d/progress.md`. For the image's contract only, the companion deployment design in luma-homeops (`docs/superpowers/specs/2026-10-07-kvm-rdp-deployment-design.md` §4.2, §4.6, §11 "What this spec asks of kvm-rdp in return", §13 decisions 1 and 8) — Plan E changes nothing in luma-homeops or the cluster.

**Scope:** in — every "Carried to Plan E" item of spec §12 and every "Plan E" line of the ledgers (the "Carries into Plan E" table below); §10 (targets, the kvm-bench harness, §10.4's allocations-per-frame metric); §11.4 L3 with its 11-set ladder fixture (DC8); the container image and its CI (§4.1, §9.1's "CI checks the published image rejects any other mode"); a nightly workflow; spec rev 6.4. Out — Plan D's hardware run (Task 1.6, Leg D) and the owner's Windows App acceptance run (both stay owner items; Plan E only adds L5 checklist items); every luma-homeops or cluster change; multi-arch images (galaxy is amd64); an upstream IronRDP PR; trimming IronRDP's dependency graph.

**Design decisions** (one line each, with why):

1. **`test-hooks`, a non-default feature, holds every test seam the binary would otherwise ship** — the RDP-runtime stall (`RdpInput::Stall`) and a `[test] panic_after` key that panics the pump shell; the lib's dev-dependency on itself turns it on for every test build and never for `cargo build --release` — because the final review asked for the stall off the release binary, and §5.2's panic path needs a trigger the release binary can be tested with (Task 5.3) but the image must refuse (Task 4.1).
2. **One counting allocator, two readers** — `kvm_rdp::alloc_stats::Counting` counts process-wide (an `alloc-stats` build exports it on `/metrics`, §10.4) and per thread (the lib's own tests measure a region) — because §10.1 has both a whole-process and a bridge-owned budget, and one implementation keeps them comparable.
3. **The pump core appends into the shell's reused `Vec`** (`Pump::step_into`) and the KVM side demuxes into a reused tag buffer — because PC14 n4 and the per-chunk `Vec<FlvTag>` are exactly the allocations that would put the bridge-owned count over 2 per frame.
4. **Third-party log lines are limited per callsite** (the first, then at most one per 10 s, the rest counted) on top of §4.5's level caps — because a level cap cannot stop an authenticated client making IronRDP warn once per PDU (PD8 m4), and per-callsite memory is bounded by the binary's callsites.
5. **CI's tools come from the flake; Rust comes from rustup** — `nix build .#lint-tools|l3-tools|bench-tools` gives cargo-deny, actionlint, shellcheck, yq, FreeRDP 3.32.1, `xvfb-run`, ffmpeg and jq at flake.lock's versions, while the existing jobs keep the runner's rustup reading `rust-toolchain.toml` (dtolnay/rust-toolchain dropped) — because §11.4 requires the flake's FreeRDP, pinning by lock file beats pinning a dozen versions in YAML, and the cache-friendly Rust jobs need no rework.
6. **Every action is pinned to a commit SHA, enforced by `scripts/check-workflows.sh`**, which also refuses `pull_request_target` and `workflow_run`, a top-level permission other than `contents: read`, a job that writes anywhere but on a push to main, a job with no `timeout-minutes`, a rust-cache that saves outside main, a `secrets.` reference outside the publishing job, a checkout that persists its token, one action pinned to two SHAs, and an unpinned image in the Dockerfile — because a compromised action could poison main's cache today (final review Minor 7) and a rule nobody checks decays. GitHub's own "require actions pinned to a full-length commit SHA" setting is the owner's to turn on once Task 2.1 is on main (a script inside a workflow cannot stop the edit that removes it).
7. **L3 lives in the L2 test binary as `#[ignore]` cases (`l3::`)** and runs in CI's existing `check` job with `nix build .#l3-tools` on `PATH` — because §11.2 names L3 an `#[ignore]` test, §13 forbids a third IronRDP-linked test executable without cause, and the `check` job has already built the binary.
8. **The picture oracle is Xvfb's own framebuffer** (`-fbdir`, XWD format) read by a 60-line parser, and the 16-bit barcode every fixture carries (§11.5) — because §11.4 names that oracle and it needs no screenshot tool.
9. **The image is a Dockerfile on distroless `cc-debian12:nonroot`, built reproducibly**: builder `rust:1.94.1-slim-bookworm` and runtime pinned by digest, `--locked`, build paths remapped, a pinned BuildKit, `SOURCE_DATE_EPOCH` = the commit time with `rewrite-timestamp=true`, no provenance or SBOM attestations inside the image index — because the image must be minimal, shell-free, non-root and reproducible, and the deployment's sibling rdpgw image follows the same distroless pattern.
10. **`publish` pushes the tested OCI archive, never a rebuild** — the `image` job builds, smoke-tests and uploads the archive; `publish` (push to main only, the only job with write permissions) copies it with `skopeo --preserve-digests`, checks the pushed digest equals the tested one, signs it keyless with cosign and attests its provenance — because the digest a deployment pins must be the image that passed the smoke test.
11. **"The published image rejects any other mode" is checked on the wire** — the smoke test sends X.224 Connection Requests asking for TLS only and for standard RDP security (refused) and for NLA (`HYBRID` selected), and runs the image with `[test]` hooks configured (refused, exit 2) — because since rev 6.2 no other mode exists in any build, so the check proves the negotiation, not a feature flag.
12. **kvm-bench: a pure `kvm_bench` library and an IO binary** — statistics, the Prometheus parser, report thresholds and the frame/input matchers are library code with unit tests; the client, kvm-sim, the bridge subprocess and the null bridge live in the binary (`test = false`) — because the library's test binary then links no IronRDP (§13), and the logic that decides pass/fail is the part worth testing.
13. **Absolute targets on a dedicated runner, loose ones per PR** — `kvm-bench --thresholds strict` on GitHub's runner through the nightly's `workflow_dispatch`, `taskset`-pinned to CPUs 2,3 at nice 0, `--thresholds ci` (10×) in every PR's `bench` job and the nightly — because §10.2 wants the absolute numbers serially "on a quiet host or dedicated runner" and the development host is shared and loaded (§13).

## Global Constraints

Copied from the spec, the ledgers and the owner's rules; every task's requirements include these.

- "Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1" (§4.2).
- §4.2: "**IronRDP is git-pinned**: one rev … for every `ironrdp-*` crate used … — no `[patch.crates-io]`"; "CI fails if `cargo tree -d` shows a duplicate `ironrdp-*` crate"; "`ironrdp-server` with `default-features = false, features = ["egfx"]` … Never the `ironrdp` meta-crate. `ironrdp-egfx` without `openh264`."; "**One crypto provider, aws-lc-rs** … Nothing may pull in `ring`."
- §4.1: "Every hostile-input parser lives in `kvm-proto`"; `kvm-proto` has no IronRDP, no tokio, no TLS, and its parser lints deny `indexing_slicing`, `unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`, `as_conversions`; `kvm-rdp`'s crate root denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `as_conversions` and `#![deny(clippy::await_holding_lock, clippy::await_holding_refcell_ref)]` (§4.3). New non-test code in those crates obeys them.
- §4.4: "Environment variables other than that path (including `RUST_LOG`) are not read" — `MALLOC_ARENA_MAX` is glibc's, read by the allocator, never by bridge code; a config error never echoes the file; every new config key gets a `leak_shapes` shape (final review: "keep `leak_shapes` the single list every new config key is added to").
- §4.5 / §9.2: "Bridge code never logs keystrokes, HID frames, pasted text, the KVM token or passwords"; "No per-frame events above `trace`".
- §9.1: "The release binary only ever calls `with_hybrid` … no-security is never compiled in. CI checks the published image rejects any other mode."
- §10.2, verbatim: "Absolute targets are measured serially, on a quiet host or dedicated runner, pinned with `taskset`, at nice 0 (nice 19 is for builds only). CI runs the harness with loose thresholds that catch 10× regressions."; "`dhat` only in a dedicated single-test binary. No tokio-console".
- §11.1: L2 asserts are one-sided — "*happens within 5× the configured value* and *does not happen before 0.5× of it*"; "Each L2 test client binds its own loopback source address".
- §11.5: "**Real captures from the KVM are never committed**"; the bench streams are "generated on demand into `target/`" and never committed.
- §13, verbatim: "`.cargo/config.toml` commits `[build] jobs = 4` and `[env] RUST_TEST_THREADS = "4"`"; "The devshell wraps `cargo` as `systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`"; "One shared `CARGO_TARGET_DIR` across long-lived worktrees"; the target budget is `scripts/target-budget.sh` at 8 GiB; "Fuzzing and the 1-hour soak run in CI only"; "ffmpeg runs under `nice -n 19` with `-threads 4`".
- CI (the brief): fork-PR safe — `pull_request` only, never `pull_request_target`; no secret is readable by a PR job; the top-level token is `contents: read`; every action pinned by commit SHA (one SHA per action); publishing to ghcr only from a push to main, by the one job that asks for `packages: write`, `id-token: write` and `attestations: write`; every job has `timeout-minutes`; caches are written by main only; no checkout leaves the job token on disk (`persist-credentials: false`). `scripts/check-workflows.sh` checks every one of these (Task 2.1).
- The image (the brief, the deployment design §4.2/§11): minimal (distroless), non-root by number (`65532:65532`, so `runAsNonRoot` can verify it), no shell and no package manager, runs on a read-only root filesystem with no writable path, reproducible, amd64 only, tagged `sha-<7-hex short commit>` and identified by its digest, `/livez` and `/readyz` unauthenticated on 9464.
- Owner: the bridge and every tool never log out of the KVM (§3.2); no secrets, tokens or captures committed; licence MIT OR Apache-2.0; every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no luma-homeops or cluster change; Plan D Task 1.6 and the Windows App acceptance run stay owner items.

## Review Focus

Five inputs or conditions the spec implies but no §11 case names, most likely to bite first; each line's test is in the owning task.

1. **A Kubernetes Secret renewal** — the kubelet mounts `tls.crt -> ..data/tls.crt` and renews by swapping the `..data` symlink with one rename → the certificate watcher sees a renewal and exits 0 once idle, exactly as for a rewritten file (Task 4.1 `a_kubernetes_secret_swap_is_a_renewal`).
2. **The restricted Pod Security profile** — a read-only root filesystem, an arbitrary non-root UID (not only 65532), no capabilities, `no-new-privileges` → the image starts, answers `/readyz`, refuses non-NLA negotiation and exits 0 on SIGTERM within 5 s under each (Task 4.1 `scripts/image-smoke.sh`, runs as 65532 and as 4242).
3. **The digest a deployment pins is not the image that was tested** (a rebuild, a recompression, an attestation manifest in the index) → `image-build.sh` fails unless the loaded image's layers and creation time equal the archive's (and, on the classic image store, its config digest), and `publish` fails unless the pushed manifest digest equals the archive's (Task 4.1 `image-build.sh`; Task 4.2's publish step).
4. **An authenticated client that makes IronRDP log per PDU, or offers an enormous clipboard format list** (PD8 m3, m4) → the log grows by one line per callsite per 10 s with the rest counted on `/metrics`, and a 20 000-format list neither panics nor ends the session, and the paste still types (Task 1.3 `a_third_party_callsite_logs_once_per_interval_and_counts_the_rest`, `a_twenty_thousand_format_list_still_pastes`).
5. **An L3 subprocess that hangs or outlives its test** (FreeRDP stuck in NLA, Xvfb left behind by `xvfb-run`) → every L3 wait is bounded, and dropping the case kills FreeRDP's whole process group, so a failed case never leaves an X server or a client running in CI (Task 3.1 `a_dropped_group_leaves_no_process_behind`).

## Recorded deviations from the spec

Task 6.1 writes these into the spec as rev 6.4. None admits anything the spec refuses.

- **DE1 — the image's build** (the spec says only that the image ships `kvm-rdp` and `kvm-probe`, §4.1): a Dockerfile, builder `docker.io/library/rust:1.94.1-slim-bookworm` and runtime `gcr.io/distroless/cc-debian12:nonroot`, both pinned by digest; `cargo build --release --locked -p kvm-rdp -p kvm-probe`; `--remap-path-prefix` for `CARGO_HOME` and the source tree; DWARF stripped (`CARGO_PROFILE_RELEASE_STRIP=debuginfo`, symbols kept); `MALLOC_ARENA_MAX=2` in the image's environment (the soak's condition, §10.1); user `65532:65532`; amd64 only; built by a pinned BuildKit with `SOURCE_DATE_EPOCH` and `rewrite-timestamp=true`; pushed as `ghcr.io/christopherjmiller/kvm-rdp:sha-<short>`, signed keyless with cosign and attested with GitHub build provenance.
- **DE2 — "CI checks the published image rejects any other mode"** (§9.1; rev 6.2 left no other mode in any build): the smoke test checks the negotiation itself — an X.224 Connection Request for TLS only or standard RDP security is closed with no protocol selected (IronRDP at the pinned rev closes without an RDP_NEG_FAILURE PDU, §9.1), one for NLA gets `PROTOCOL_HYBRID` — and that the image refuses `[test]` keys (`test-hooks` absent) at load, exit 2.
- **DE3 — "bridge-owned allocations ≤ 2 per frame"** (§10.1 names the stages, not how IronRDP's own allocations inside the pump's step are excluded): bridge-owned = (A) kvm-proto's demux → admission → Annex-B per access unit, at most 1.5, + (B) the KVM side's per-chunk wrapper, 0, + (C) `Pump::step_into` for the shell's three inputs and the frame's ack, minus a twin `GraphicsPipelineServer`'s `send_avc420_frame` + `drain_output` for the same Annex-B, at most 0.5; measured on the committed ES3-shaped and 480p fixtures. tokio's channel blocks and IronRDP's encode in the shell are outside it. (A) is the steady state, each AU released before the next read; under a burst the demuxer may reallocate per read, which the whole-process metric covers.
- **DE4 — four metrics join §10.4's registry**: `kvm_rdp_log_lines_suppressed_total` (counter, DE5), `kvm_rdp_egfx_client_frames_decoded` (gauge, the client's last `totalFramesDecoded`, §11.4's "decode count"), `kvm_rdp_need_idr_total` (counter, entries into NeedIdr, §10.2's "NeedIdr entries per minute"), and in `alloc-stats` builds only `kvm_rdp_allocations_total` and `kvm_rdp_allocated_bytes_total` — rev 6.3's 44 plus three (47), plus two in an `alloc-stats` build. Task 1.5's two release triggers (`rdp_stale`, `paste_resync`) and the paste label `aborted_resync` are labels on existing families, not families.
- **DE5 — third-party log lines are rate-limited per callsite** (§4.5 caps them by level): every event from a target outside `kvm_rdp` that passes the level filters logs if its callsite has not logged in the last 10 s (`logging::THIRD_PARTY_INTERVAL`), and is otherwise counted; bridge lines are never limited.
- **DE6 — `test-hooks`** (final review Minor 5): a non-default cargo feature gating `RdpInput::Stall`, `BridgeHandle::block_rdp_runtime_for`, `RdpInput::InjectedPanic` outside unit tests, and the `[test] panic_after` key; enabled for every test build by `kvm-rdp`'s dev-dependency on itself; absent from the image, which refuses `[test]` as an unknown key.
- **DE7 — release builds are `panic = "abort"` by construction**: `main.rs` fails to compile any build without debug assertions whose panic strategy is not abort (`cfg(panic = "abort")`).
- **DE8 — a minimum frame size** (spec §12's carry): §6.1's SPS limits gain width ≥ 200 and height ≥ 200 after cropping (RDP's 200-pixel minimum desktop: MS-RDPEDISP 2.2.2.2.1, which IronRDP's displaycontrol enforces as 200..=8192; spec §12 says MS-RDPBCGR), `stream_incompatible` otherwise; `video.default_size`'s own 16-pixel floor (operator-set, not hostile) is unchanged.
- **DE9 — L3 as built** (§11.4): `#[ignore]` cases `l3::*` in the L2 test binary, run by CI's `check` job; the FreeRDP 11-set ladder fixture (DC8) is captured from the flake's FreeRDP (3.32.1; the census ran 3.31.1) into `fixtures/freerdp-gfx-ladder.txt`, whose first header line is the recording's `xfreerdp /version` and is checked against the running FreeRDP, and the `/gfx:AVC420` pair it advertises is re-checked equal to `census.md`'s; a case also checks FreeRDP without NLA is refused before any KVM traffic.
- **DE10 — kvm-bench as built** (§10.2): its client is its own lean one, not L2's (L2's records every PDU for its oracles — at 1080p60 that would be the measurement); bench streams are 20 s each (≥ 10 s loops, under §10.2's 60 s), IDR every second, `-threads 4`, not deterministic and not committed; 60 fps scenarios configure `video.max_fps = 60`; the stalled-client timing bounds loosen 1.5×, not 10×, under `--thresholds ci` (a 10× bound would be a 155 s case). kvm-bench's bridge is the release profile with `alloc-stats,test-hooks`; its CPU and latency figures are an upper bound for the image's build. kvm-bench and the bridge it spawns share the pinned CPUs (results err high).
- **DE11 — "dedicated runner"** (§10.2): the absolute targets are measured by the nightly workflow's `workflow_dispatch` with `thresholds = strict` on a GitHub-hosted runner, taskset-pinned to CPUs 2,3 of the runner's four, at nice 0; a `taskset`-pinned run on the shared development host is a development check, recorded with its load average.
- **DE12 — the `hid.lua?type=text` comparison** (§8, controller ruling 2, deferred to Plan E's perf pass): nothing in the repo records the endpoint's request format, and guessing a write path into a hostile device's typing endpoint is not a test; it becomes an L5 / Leg D owner item — the owner pastes L4's 200-character pattern through the vendor web UI's own text box into the committed HID test page, three times, and compares the page's `rate` and text hash with `kvm-probe hid-type` at `paste.pace`.
- **DE13 — CI's provenance**: rustup (on the runner image) replaces `dtolnay/rust-toolchain`; runners are `ubuntu-24.04`, not `ubuntu-latest`; every non-Rust tool comes from the flake's pinned nixpkgs — except `publish`, which evaluates no repository code: skopeo and docker from the runner image, cosign from the SHA-pinned cosign-installer; and the image jobs (`image`, the nightly `image-build`/`reproducible`), whose host tools — docker and buildx, jq, curl, openssl, coreutils — are the runner image's, the build itself running in the digest-pinned BuildKit and builder images.
- **DE14 — the soak's churn** (§10.1: "a preempting reconnect, FLV drop, websocket drop, re-advertise, resize and 1 KiB paste" every 5 minutes): the preempting client alternates between `127.0.0.2` and `127.0.0.3`, so a reconnect never depends on Preempt's evicted-address bar (5 s, at most 30 s; §5.1), whatever `--churn-every` is, and the resize alternates the 1080p and 720p bench streams.
- **DE15 — cargo-deny's advisories** (§12 bullet 2 asks for licences and advisories): `bans`, `licenses` and `sources` block every PR; `advisories` blocks on main (so `publish` never ships a known-vulnerable image) and is reported, not blocking, on PRs and by a nightly `deny-advisories` job — the advisory database moves daily, so a blocking PR gate fails PRs that changed nothing. `rustls` moves to 0.23.46 (RUSTSEC-2026-0346..0349); RUSTSEC-2023-0071 (`rsa`, Marvin, no fix upstream) is ignored in `deny.toml` with its reachability reading, **pending the owner's sign-off**.
- **DE16 — m3's stale bound** (§12: "once the RDP heartbeat is about 1 s old"; controller ruling 11): Task 1.5's watch releases held input once the heartbeat is older than 3 s (`hid::stale::RDP_STALE_RELEASE`, three periods of §4.5's heartbeat, which stays every quarter of `admin.liveness_timeout`, capped at 1 s — idle CPU stays at PC15 m2's measured ~21 wakeups per 10 s). A single late beat can never trip it; a key held through a stalled RDP thread is released at 3 s, not about 1 s. `/livez`'s bound (`admin.liveness_timeout`, 10 s) is unchanged.

## Carries into Plan E

Every spec §12 "Carried to Plan E" bullet, every ledger line naming Plan E, every Plan E item in Plan C's final review ("Recommendations — Plan E" and "Declined to judge … Plan E"), and the deployment design's asks of kvm-rdp.

| Carry (source) | Where in Plan E |
|---|---|
| `--remap-path-prefix` (or `trim-paths`) in the image build, so no build-host source path reaches an error message (PC15; final review parked #9; spec §12 bullet 1) | Task 4.1 (Dockerfile `RUSTFLAGS`; the smoke test greps both binaries) |
| Actions pinned by SHA (final review Minor 7, ledger PC fix-wave ruling; spec §12 bullet 2) | Task 2.1 (`scripts/pin-action.sh`, `scripts/check-workflows.sh`) |
| `cargo deny` (licences and advisories) over the production graph (final review Recs and "Declined"; spec §12 bullet 2) | Task 2.2 |
| §10.1's allocation budget, including PC14 n4 (one extra `Vec` per AU in the shell's `step`) and the per-chunk `Vec<FlvTag>` (final review parked #8; spec §12 bullet 3) | Task 1.4 (bridge-owned, DE3); Task 5.1 (whole-process, `alloc-stats`) |
| A minimum frame size in admission (final review Minor 8; spec §12 bullet 4) | Task 1.2 (DE8) |
| Gating the `RdpInput::Stall` test hook behind a non-default feature (final review Minor 5; spec §12 bullet 5) | Task 1.1 (DE6) |
| IronRDP's format-list amplification, PD8 m3 (Plan D ledger l.85; spec §12 bullet 6) | Task 1.3 (`a_twenty_thousand_format_list_still_pastes`); Task 6.1 (the pin-review checklist's upstream-cap note) |
| Milestone 4's comparison with `hid.lua?type=text`, in the perf pass (controller ruling 2; spec §8, §12 bullet 7) | Task 6.1 (L5 / Leg D owner item, DE12) |
| A nightly L2 run under a CPU stressor at the wrapper's nice 19 (final review Recs; spec §12 bullet 8) | Task 2.3 |
| The disk pass: pruning the stale incremental cache (Plan C ledger l.155, minor 4; spec §12 bullet 9) | Task 2.1 (`scripts/target-budget.sh --prune`) |
| kvm-bench measuring how often the KVM → pump channel fills (PC17 m2, parked #11; spec §12 bullet 10) | Task 5.1 (`channel_full` drops per minute in every report); Task 5.2 (the input-latency run with source bursts) |
| Rate limiting IronRDP's per-PDU WARNs past the INFO cap (PD8 m4; spec §12 bullet 11) | Task 1.3 (DE5) |
| A KVM-runtime watch that calls release-all once the RDP heartbeat is about 1 s old while the queue's newest state holds something (Plan D final review m3; spec §12 bullet 12, §7.4) | Task 1.5 (`hid::stale`, `release_all{trigger="rdp_stale"}`; at 3 s, three heartbeat periods: DE16, controller ruling 11) |
| Ending a paste as aborted when the queue resyncs while it types (Plan D final review m4; spec §8, §12 bullet 13) | Task 1.5 (`paste_events{outcome="aborted_resync"}`, `release_all{trigger="paste_resync"}`) |
| The fuzz nightly red 7 nights of 8 on `sps_rewrite`'s level-1b oracle (Plan B PB12's recorded limitation; pre-flight E7) | Task 2.4 |
| Release-build behaviour, `panic = "abort"` (final review "Declined to judge … Plan E") | Task 1.1 (DE7, the debug path's L2 case); Task 5.3 (`panic-abort`: the release binary dies by SIGABRT) |
| The container image; CI's "image rejects other modes" (§4.1, §9.1; final review "Declined") | Tasks 4.1, 4.2 (DE1, DE2) |
| kvm-bench and §10.1's perf targets — CPU, allocations per frame, enqueue latency (final review "Declined") | Tasks 5.1–5.4; Task 6.1 (the run and its record) |
| Soak memory (final review "Declined"; §10.1) | Task 5.5 (nightly soak); Task 6.1 (records it, and the memory limit it implies) |
| L3 FreeRDP interop and the 11-set ladder fixture (DC8; final review "Declined") | Tasks 3.1, 3.2 (DE9) |
| The production graph's size (345 crates (cargo-deny, `7bdcf15`); final review "Declined") | Task 2.2 audits it (licences, advisories, bans, sources; DE15); not trimmed — not ours without a fork patch |
| Bound the admin response write before `/metrics` grows (final review Recs) | Not carried: Plan C did it (spec §12 "Not carried"); Task 1.3's and 1.4's new families are rendered inside that bound |
| Deployment design §11 (1): the certificate poll follows symlinks | Task 4.1 (`a_kubernetes_secret_swap_is_a_renewal`) |
| Deployment design §11 (2): `sha-<commit>` with a digest; non-root; read-only root filesystem; no writable path | Tasks 4.1 (smoke), 4.2 (publish) |
| Deployment design §11 (3): `/livez` and `/readyz` stay unauthenticated | Task 4.1 (smoke) |
| Deployment design §13 decision 1: kvm-rdp's CI builds and signs the image | Task 4.2 |
| Deployment design §4.2: the memory limit from Plan E's soak; `MALLOC_ARENA_MAX=2` on a glibc image | Task 4.1 (image environment); Task 5.5; Task 6.1 |
| Deployment design §13 decision 8 / risk 9: defer the restart on rotation until idle | Not carried: done in Plan C (DC21) |

## Execution notes

- Repo `/home/chris/Repos/kvm-rdp`, branch `plan-e`, cut from `plan-d` @ `7bdcf15` (Plan D complete plus its final fix wave). Task numbers are `Part.N`; parts and tasks run in order, with one exception: Task 2.4 sits, and runs, between Tasks 2.2 and 2.3 (it fixes the fuzz nightly before Task 2.3 adds a second nightly beside it).
- Every command runs inside `nix develop` from the repo root (the §13 cargo wrapper). Run `cargo fmt --all` before every commit; `git add` exact paths, never `-A`; never commit anything under `.superpowers/`, `target/` or `captures/`.
- **The per-task gate** (Plans C and D): `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, then `scripts/target-budget.sh`; a task that edits `crates/kvm-rdp/src` also runs `cargo clippy -p kvm-rdp --lib --bins -- -D warnings` (a named exception: the image's feature set, so an item gated on `alloc-stats` or `test-hooks` cannot leave an unused import in the build that ships). **Never `-p`** for the gate or a TDD step: unit tests run as `cargo test --workspace --all-features --lib -- <filter>`, L2 and L3 as `cargo test --workspace --all-features --test l2 -- <filter>`, kvm-proto's allocation binary as `cargo test --workspace --all-features --test alloc`. The three **named exceptions** build what ships, in the feature resolution that ships it, and nothing else: the image (`cargo build --release --locked -p kvm-rdp -p kvm-probe`, inside the Dockerfile), the bench's bridge (`cargo build --release --locked -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp`) and the bench itself (`cargo build --release --locked -p kvm-bench --bin kvm-bench`); the image's feature-set clippy above (`cargo clippy -p kvm-rdp --lib --bins -- -D warnings`); and Task 1.1's guard build (`cargo build --release --locked -p kvm-rdp --features test-hooks --bin kvm-rdp`, whose units Part 5 reuses).
- Expected counts in "Expected: N passed" lines are minimums: the gate is "0 failed and every named test exists and passes".
- **Docker** is on the host (29.x, buildx 0.31); `scripts/image-build.sh` makes its own `docker-container` builder capped at CPU shares 205 (≈ §13's CPUWeight 20) and 8 GiB, so an image build is as polite as the cargo wrapper, and prunes that builder's cache to 8 GB after each build. An image build's disk is outside target-budget.sh; check `df /` has ≥ 20 GiB free before one (the root filesystem filled on 2026-10-11).
- **GitHub Actions runs only on GitHub.** Pushing `plan-e` and opening a PR needs the owner's approval (as for `plan-c` and `plan-d`). Tasks 2.1–2.4, 3.2, 4.2 and 5.5 verify locally (`scripts/check-workflows.sh`, actionlint, shellcheck, the scripts themselves; `act` is not available, so a workflow itself runs only once the owner pushes) and end with a **CI check** line the owner's first push exercises; no task blocks on it, and Task 6.1 records which CI runs have happened.
- §13: the 1-hour soak runs in CI only; locally the soak scenario runs only as `--soak-duration 3m --churn-every 1m`. kvm-bench's strict run on this host is a development check (DE11).
- Scratch worktrees (reviewers) set their own `CARGO_TARGET_DIR` under the session scratchpad and delete it when done.

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `crates/kvm-rdp/Cargo.toml`, `src/{msg,main,bridge,config}.rs`, `src/pump/shell.rs`, `tests/l2/admin.rs` | `test-hooks`; the `panic = "abort"` guard; `[test] panic_after` | 1.1 |
| `crates/kvm-proto/src/h264/sps.rs`, `src/video/tests.rs` | The 200 px floor in §6.1's limits | 1.2 |
| `crates/kvm-rdp/src/logging.rs`, `src/metrics.rs`, `tests/l2/{client,paste}.rs` | Per-callsite limit, `log_lines_suppressed`; the 20 000-format L2 case | 1.3 |
| `crates/kvm-rdp/src/alloc_stats.rs`, `src/{lib,main,testkit,metrics}.rs`, `src/pump/{core,shell}.rs`, `src/kvm/video.rs`, `Cargo.toml`; `crates/kvm-proto/tests/alloc.rs`, `crates/kvm-proto/Cargo.toml` | The counting allocator, `alloc-stats`, `step_into`, the reused buffers, the budget tests | 1.4 |
| `crates/kvm-rdp/src/hid/{stale,queue,mod}.rs`, `src/{admin,bridge,metrics}.rs`, `src/input/core.rs`, `src/rdp/input.rs`, `tests/l2/{admin,input,paste}.rs` | The stale-heartbeat release (m3); the abort on resync (m4) | 1.5 |
| `flake.nix`, `.github/workflows/{ci,fuzz-nightly}.yml`, `scripts/{pin-action,check-workflows,test-check-workflows,target-budget,test-target-budget}.sh` | CI tools from the flake; SHA pins; the `lint` job; the disk pass | 2.1 |
| `deny.toml`, `.github/workflows/ci.yml` | cargo-deny | 2.2 |
| `crates/kvm-proto/src/h264/rewrite.rs`, `src/fuzzing.rs` | The fuzz oracle's level-1b raise; its seed (in `fuzzing::seeds()`) | 2.4 |
| `.github/workflows/nightly.yml`, `scripts/l2-under-load.sh` | Nightly L2 under a CPU stressor; the nightly advisories job | 2.3 |
| `crates/kvm-rdp/src/rdp/gfx.rs`, `src/metrics.rs`, `tests/l2/{main,admin,xwd,l3}.rs` | The decode gauge and the advertised-caps line; the L3 harness; FreeRDP decodes the ES3 stream | 3.1 |
| `crates/kvm-rdp/tests/l2/l3.rs`, `src/pump/{rig,core}.rs`, `fixtures/freerdp-gfx-ladder.txt`, `.github/workflows/ci.yml` | Ack suspension, the ladder fixture (DC8), no-NLA refusal; L3 in CI | 3.2 |
| `Dockerfile`, `.dockerignore`, `scripts/{pin-image,image-build,image-smoke}.sh`, `flake.nix`, `crates/kvm-rdp/src/bridge.rs`, `README.md` | The image, its smoke test, the Secret-swap test | 4.1 |
| `.github/workflows/{ci,nightly}.yml`, `README.md` | `image` and `publish` jobs; nightly reproducibility | 4.2 |
| `crates/kvm-bench/{Cargo.toml,src/{lib,stats,prom,report,frames,main,bridge,client,scenarios,streams}.rs}`, `scripts/gen-fixtures.sh` | kvm-bench: library, client, bridge subprocess, bench streams, `unshaped` | 5.1 |
| `crates/kvm-bench/src/scenarios.rs`, `crates/kvm-rdp/src/{pump/core,metrics}.rs` | Input latency, shaped links, RTT spike, idle → motion; `need_idr` | 5.2 |
| `crates/kvm-bench/src/scenarios.rs` | Stalled clients; the release `panic-abort` check | 5.3 |
| `crates/kvm-bench/src/{null_bridge,scenarios,main}.rs` | The null bridge and the end-to-end comparison | 5.4 |
| `crates/kvm-bench/src/{soak,main}.rs`, `.github/workflows/{ci,nightly}.yml` | The soak; the `bench` CI job; the nightly bench and soak | 5.5 |
| `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`, `README.md` | The perf pass's record, rev 6.4, the L5 items | 6.1 |

---
## Part 1 — The bridge's carries

Code changes inside the bridge that later parts measure or rely on: the release binary loses its test seams (Task 1.1), admission gains a floor (Task 1.2), IronRDP's chatter is bounded (Task 1.3), the allocation budget becomes measurable and met (Task 1.4), and a stalled RDP thread or a queue overflow can no longer leave input held or a paste with a hole in it (Task 1.5, which uses Task 1.1's stall).

### Task 1.1: `test-hooks` — the release binary carries no test seam; release builds abort on a panic

The final review's Minor 5: `RdpInput::Stall` (a `std::thread::sleep` on the RDP runtime, reachable through the `doc(hidden)` `BridgeHandle::block_rdp_runtime_for`) ships in the release binary. Gate it, and every other test seam the binary has, behind a non-default `test-hooks` feature. Add the one seam §5.2's release behaviour needs — `[test] panic_after`, which makes the pump shell panic — so Task 5.3 can show a release build dies by SIGABRT, and Task 4.1 can show the image refuses the key. Make `panic = "abort"` a compile-time property of every build without debug assertions (DE7).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/Cargo.toml` (`[features]`; the self dev-dependency)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/msg.rs` (`RdpInput::Stall`, `RdpInput::InjectedPanic`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/shell.rs` (their arms; `MAX_STALL`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/bridge.rs` (`block_rdp_runtime_for`; the `panic_after` timer)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/config.rs` (`[test] panic_after`; its `leak_shapes` shape)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/main.rs` (the guard)
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.lock` (the self dev-dependency's edge)
- Test: `crates/kvm-rdp/src/config.rs` (`tests`), `crates/kvm-rdp/tests/l2/admin.rs`

**Interfaces:**
- Consumes: Plan C's `PumpShell::rdp_input`, `RdpParts`, `rdp_main`; L2's `Bin` (`tests/l2/admin.rs`), `harness::{es3, write_files, T}`.
- Produces:
  - Cargo feature `kvm-rdp/test-hooks` (non-default). Every `cargo test`/`clippy --all-targets` build has it (dev-dependency); `cargo build --release -p kvm-rdp` never does.
  - `config::TestConfig { pub panic_after: Option<Duration> }` and `Config::test: TestConfig`, both `#[cfg(feature = "test-hooks")]`; TOML `[test]` with `panic_after = "<duration>"`. Without the feature `[test]` is an unknown key: exit 2 (Task 4.1 relies on it).
  - `RdpInput::Stall(Duration)` and `BridgeHandle::block_rdp_runtime_for` under `#[cfg(feature = "test-hooks")]`; `RdpInput::InjectedPanic` under `#[cfg(any(test, feature = "test-hooks"))]`.
  - Task 5.3 runs a release binary built `--features alloc-stats,test-hooks` with `[test]\npanic_after = "1s"` and expects SIGABRT.

- [ ] **Step 1: Write the failing tests.** In `crates/kvm-rdp/src/config.rs`'s `tests` module, after `defaults_match_the_spec_table`:

```rust
    /// Plan E Task 1.1 (DE6): `[test] panic_after` is a `test-hooks` key —
    /// off by default, a duration when set, its key named when it is not.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn test_panic_after_parses_and_is_off_by_default() {
        let d = tempfile::tempdir().unwrap();
        let base = minimal(d.path());
        assert_eq!(load(d.path(), &base).unwrap().test.panic_after, None);
        let c = load(d.path(), &format!("{base}[test]\npanic_after = \"750ms\"\n")).unwrap();
        assert_eq!(c.test.panic_after, Some(Duration::from_millis(750)));
        let e = load(d.path(), &format!("{base}[test]\npanic_after = \"soon\"\n"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("test.panic_after"), "{e}");
        assert!(!e.contains("soon"), "a config error never echoes the file: {e}");
    }
```

In `crates/kvm-rdp/tests/l2/admin.rs`, after `shutdown_completes_with_the_kvm_unreachable`:

```rust
/// Plan E Task 1.1 (spec §5.2): a panic in a task the bridge cannot run
/// without — the pump shell, through `test-hooks`' `[test] panic_after` —
/// ends the binary. This is the test profile (`panic = "unwind"`): the RDP
/// server stops, the binary exits 1, and the log names the dead task.
/// Release's `panic = "abort"` is Task 5.3's `panic-abort` scenario.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicked_pump_shell_ends_the_binary_with_exit_1() {
    let sim = KvmSim::start(es3()).await.unwrap();
    let d = tempfile::tempdir().unwrap();
    write_files(&sim, d.path());
    let toml = d.path().join("kvm-rdp.toml");
    let text = std::fs::read_to_string(&toml).unwrap();
    std::fs::write(&toml, format!("{text}[test]\npanic_after = \"500ms\"\n")).unwrap();
    let mut bin = Bin::spawn(d.path(), &[]);
    bin.ready().await;
    let status = bin.wait(T).await;
    assert_eq!(status.code(), Some(1), "{status:?}");
    let out = bin.output();
    assert!(
        out.iter().any(|l| l.contains("a task the bridge needs panicked")),
        "no essential-task line: {out:?}"
    );
    assert_eq!(sim.stats().logouts, 0);
}
```

(`KvmSim`, `T`, `es3` and `write_files` are imported at admin.rs's top.)

- [ ] **Step 2: The feature and the self dev-dependency** (first, so the `#[cfg(feature = "test-hooks")]` test above is compiled in when Step 3 runs it). In `crates/kvm-rdp/Cargo.toml`, after `[[bin]]`:

```toml
[features]
# Test seams the release image must not carry (Plan E Task 1.1, DE6): the
# RDP-runtime stall behind `BridgeHandle::block_rdp_runtime_for` (L2's
# /livez case), the pump shell's injected panic, and the `[test]
# panic_after` key that fires it (§5.2's panic path, in debug and in
# release). Every test build turns it on through the dev-dependency on this
# package below; `cargo build --release -p kvm-rdp` (the image) never does.
test-hooks = []
```

and at the end of `[dev-dependencies]`:

```toml
# Turns `test-hooks` on for the lib's unit tests, L2 and the binary L2
# spawns. Dev-dependency features never reach a non-test build (resolver 3).
kvm-rdp = { path = ".", features = ["test-hooks"] }
```

With it, a `--lib`-only run also compiles kvm-rdp's rlib — accepted: it is what makes a plain `cargo test` build L2.

- [ ] **Step 3: Run them to see them fail.** `cargo test --workspace --all-features --lib -- config::tests::test_panic_after` — Expected: FAIL to compile (no field `test` on type `Config`). `cargo test --workspace --all-features --test l2 -- admin::a_panicked_pump_shell_ends` — Expected: FAIL (the config is refused: `[test]` is an unknown key, so the bridge never gets ready).

- [ ] **Step 4: Gate the seams.** In `crates/kvm-rdp/src/msg.rs`, replace the two test-hook variants of `RdpInput` and their `Debug` arms:

```rust
    /// Test hook: block the RDP runtime (L2 `/livez`; DE6).
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    Stall(Duration),
    /// Test hook: the pump shell panics, as a bug would — the lib's unit
    /// tests (PC15 review m5) and `[test] panic_after` (Plan E, §5.2).
    #[cfg(any(test, feature = "test-hooks"))]
    InjectedPanic,
```

```rust
            #[cfg(feature = "test-hooks")]
            RdpInput::Stall(_) => "Stall",
            #[cfg(any(test, feature = "test-hooks"))]
            RdpInput::InjectedPanic => "InjectedPanic",
```

`Stall` is `Duration`'s only use in `msg.rs`, so replace its `use std::time::{Duration, Instant};` with:

```rust
use std::time::Instant;
#[cfg(feature = "test-hooks")]
use std::time::Duration;
```

In `crates/kvm-rdp/src/pump/shell.rs`, gate `MAX_STALL` with `#[cfg(feature = "test-hooks")]` and replace the two arms of `rdp_input`:

```rust
            // Test hook (L2 `/livez`): block this runtime's thread.
            #[cfg(feature = "test-hooks")]
            RdpInput::Stall(d) => std::thread::sleep(d.min(MAX_STALL)),
            // Test hook: a bug in the shell (unit tests; `[test] panic_after`).
            #[cfg(any(test, feature = "test-hooks"))]
            #[allow(clippy::panic)]
            RdpInput::InjectedPanic => panic!("injected: the pump shell panics"),
```

In `crates/kvm-rdp/src/bridge.rs`, gate `block_rdp_runtime_for` with `#[cfg(feature = "test-hooks")]` (keep `#[doc(hidden)]`).

- [ ] **Step 5: `[test] panic_after`.** In `crates/kvm-rdp/src/config.rs`:

```rust
/// `[test]` (DE6): test seams, only in `test-hooks` builds — the image
/// refuses the table as an unknown key.
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone, Default)]
pub struct TestConfig {
    /// Make the pump shell panic this long after startup (§5.2's path).
    pub panic_after: Option<Duration>,
}
```

Add `#[cfg(feature = "test-hooks")] pub test: TestConfig,` as the last field of `Config`; the raw table, after `RawLog`:

```rust
#[cfg(feature = "test-hooks")]
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawTest {
    panic_after: Option<String>,
}
```

`#[cfg(feature = "test-hooks")] test: RawTest,` as the last field of `Raw`; and in `build`, before `Ok(Config {`:

```rust
    #[cfg(feature = "test-hooks")]
    let test = TestConfig {
        panic_after: raw
            .test
            .panic_after
            .as_ref()
            .map(|s| dur(Some(s), Duration::ZERO, "test.panic_after"))
            .transpose()?,
    };
```

with `#[cfg(feature = "test-hooks")] test,` as the last field of the returned `Config`. In `leak_shapes`, turn the `vec![…]` into `let mut shapes = vec![…];`, then before returning it:

```rust
        // DE6: `[test] panic_after`'s rule never echoes its value either.
        #[cfg(feature = "test-hooks")]
        shapes.push(t(
            format!("{base}[test]\npanic_after = \"{s}\"\n"),
            "a secret as test.panic_after",
        ));
        shapes
```

- [ ] **Step 6: Fire it.** In `bridge.rs`, add to `RdpParts`:

```rust
    /// `[test] panic_after` (DE6): when, and the channel the panic goes on.
    #[cfg(feature = "test-hooks")]
    panic_after: Option<(Duration, mpsc::UnboundedSender<RdpInput>)>,
```

fill it in `spawn_with_grace` where `RdpParts` is built (`panic_after: cfg.test.panic_after.map(|d| (d, to_pump.clone())),` under the same `cfg`), take it in `rdp_main`'s destructuring (`#[cfg(feature = "test-hooks")] panic_after,`), and right after the pump shell is spawned and pushed to `essential`:

```rust
        // DE6: the pump shell panics on cue — §5.2's path, testable in a
        // release build (Task 5.3) and absent from the image.
        #[cfg(feature = "test-hooks")]
        if let Some((after, to_pump)) = panic_after {
            tokio::task::spawn_local(async move {
                tokio::time::sleep(after).await;
                let _ = to_pump.send(RdpInput::InjectedPanic);
            });
        }
```

- [ ] **Step 7: The guard.** At the top of `crates/kvm-rdp/src/main.rs`, after the module doc:

```rust
// Spec §5.2 (DE7): release builds abort on a panic. A crash cannot release
// keys either way, but an unwinding release build could keep serving NLA
// with a task it cannot run without gone. Every build without debug
// assertions — the release profile, the image, kvm-bench's bridge — must
// use the release profile's `panic = "abort"`. (`cargo test --release`
// still builds — test harnesses unwind and the binary L2 spawns aborts —
// but `a_panicked_pump_shell_ends_the_binary_with_exit_1` then sees
// SIGABRT; only the debug profile is a supported test invocation.)
#[cfg(all(not(debug_assertions), not(panic = "abort")))]
compile_error!("kvm-rdp: a build without debug assertions must use panic = \"abort\" (spec §5.2)");
```

- [ ] **Step 8: Run the tests.** `cargo test --workspace --all-features --lib -- config::tests cli::tests` — Expected: PASS, including `test_panic_after_parses_and_is_off_by_default`, `config_errors_never_echo_the_file` and `the_binarys_stderr_never_echoes_the_config_file` (both now also run the new shape). `cargo test --workspace --all-features --test l2 -- admin::` — Expected: PASS, including `livez_goes_stale_while_the_rdp_runtime_is_blocked` (the stall still reaches L2 through the dev-dependency) and `a_panicked_pump_shell_ends_the_binary_with_exit_1`.

- [ ] **Step 9: The feature-off build.** The image's feature resolution (the named exceptions in the Execution notes): `cargo clippy -p kvm-rdp --lib --bins -- -D warnings` — Expected: clean, no unused import or dead code left by the gating. `cargo build --release --locked -p kvm-rdp --features test-hooks --bin kvm-rdp` (the bench bridge's exception less `alloc-stats`: it proves the guard — `cfg(panic = "abort")` and `debug_assertions` in the release profile — and Part 5 reuses its units) — Expected: builds, and `scripts/target-budget.sh` passes. That the release binary *refuses* `[test]` at run time is Task 4.1's smoke test (on the image) and Task 5.3's `panic-abort` is the hooks build's release behaviour.

- [ ] **Step 10: Gate and commit.** The per-task gate. Then:

```bash
git add crates/kvm-rdp/Cargo.toml crates/kvm-rdp/src/msg.rs crates/kvm-rdp/src/pump/shell.rs \
  crates/kvm-rdp/src/bridge.rs crates/kvm-rdp/src/config.rs crates/kvm-rdp/src/main.rs \
  crates/kvm-rdp/tests/l2/admin.rs Cargo.lock
git commit -m "kvm-rdp: test-hooks gates the Stall seam and adds [test] panic_after; release builds must abort on a panic (Plan E Task 1.1, final review Minor 5)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 1.2: a minimum frame size in admission

The final review's Minor 8: a hostile SPS can make the bridge resize the client to a 16×16 desktop. Refuse a picture under 200 pixels either way, after cropping — RDP's 200-pixel minimum desktop (MS-RDPEDISP 2.2.2.2.1; IronRDP's displaycontrol enforces 200..=8192; spec §12 says MS-RDPBCGR) — as `stream_incompatible`, the class every other §6.1 limit has (DE8).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps.rs` (`SpsLimits`, `SpsLimitViolation`, `check_sps_limits`, its tests)
- Test: `crates/kvm-proto/src/h264/sps.rs`, `crates/kvm-proto/src/video/tests.rs`

**Interfaces:**
- Consumes: `SpsSummary { width, height, .. }` (cropped size), `check_sps_limits`.
- Produces: `SpsLimits { …, pub min_width: u32, pub min_height: u32 }` (defaults 200, 200); `SpsLimitViolation::WidthTooSmall(u32)`, `SpsLimitViolation::HeightTooSmall(u32)`, checked right after the two `…TooLarge` rules. A refused SPS surfaces as `AdmissionError::Incompatible(Incompatible::Sps(SpsIncompatibleReason::OutsideLimits(…)))`, kind `sps` — fatal `stream_incompatible` (§6.9), as before.

- [ ] **Step 1: Write the failing tests.** In `sps.rs`'s tests, in the test that walks every `SpsLimitViolation` (the one asserting `WidthTooLarge(4098)`), after the `HeightTooLarge` block:

```rust
        // Plan E Task 1.2 (DE8): RDP's 200-pixel minimum desktop.
        let mut s = ok_summary();
        s.width = 198;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::WidthTooSmall(198))
        );

        let mut s = ok_summary();
        s.height = 198;
        assert_eq!(
            check_sps_limits(&s, &lim),
            Err(SpsLimitViolation::HeightTooSmall(198))
        );

        let mut s = ok_summary();
        (s.width, s.height) = (200, 200);
        assert_eq!(check_sps_limits(&s, &lim), Ok(()), "200×200 is the floor, admitted");
```

In `crates/kvm-proto/src/video/tests.rs` (add `SpsLimitViolation` to the `use crate::h264::{…}` line):

```rust
/// Plan E Task 1.2 (DE8): a sequence header whose SPS codes a picture
/// under 200 pixels either way is stream_incompatible before it can resize
/// anything; one at 208×208 (13 macroblocks) is admitted.
#[test]
fn a_tiny_frame_is_stream_incompatible() {
    let tiny = |mbs_minus1: u32| {
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.level_idc = 40;
        c.pic_width_in_mbs_minus1 = mbs_minus1;
        c.pic_height_in_map_units_minus1 = mbs_minus1;
        c.crop = None;
        c.build()
    };
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    assert_eq!(
        a.admit(seq_tag(tiny(0)), Instant::now()),
        Err(incompatible(Incompatible::Sps(
            SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::WidthTooSmall(16))
        )))
    );
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let ok = a.admit(seq_tag(tiny(12)), Instant::now()).unwrap();
    assert_eq!(ok.params.map(|p| p.class), Some(ParamClass::Initial));
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- h264::sps video::tests::a_tiny_frame` — Expected: FAIL to compile (`WidthTooSmall`, `HeightTooSmall` not found).

- [ ] **Step 3: Implement.** In `sps.rs`, add to `SpsLimits` (after `max_height`):

```rust
    /// Plan E (DE8): RDP's 200-pixel minimum desktop (MS-RDPEDISP
    /// 2.2.2.2.1; IronRDP's displaycontrol enforces 200..=8192) — a hostile
    /// SPS must not shrink the client to a postage stamp.
    pub min_width: u32,
    pub min_height: u32,
```

`min_width: 200, min_height: 200,` in `Default`; the two variants after `HeightTooLarge(u32)`:

```rust
    WidthTooSmall(u32),
    HeightTooSmall(u32),
```

and in `check_sps_limits`, right after the `HeightTooLarge` check:

```rust
    if s.width < limits.min_width {
        return Err(SpsLimitViolation::WidthTooSmall(s.width));
    }
    if s.height < limits.min_height {
        return Err(SpsLimitViolation::HeightTooSmall(s.height));
    }
```

Both literals already take the floor's defaults through `..SpsLimits::default()`; there is no other literal in the workspace or fuzz/.

- [ ] **Step 4: Run the tests, then the whole of kvm-proto.** `cargo test --workspace --all-features --lib -- h264::sps video::tests` — Expected: PASS. `cargo test --workspace --all-features` — Expected: 0 failed. If a pre-existing test admits a deliberately tiny SPS through `SpsLimits::default()` (a rewriter or level-1b test at QCIF, say), keep its intent by giving that test's limits `min_width: 0, min_height: 0` — never by lowering the default — and name each such test in the commit body. The fuzz targets need no change (refusing more cannot break an output invariant); `scripts/fuzz.sh seeds` — Expected: passes.

- [ ] **Step 5: Gate and commit.**

```bash
git add crates/kvm-proto/src/h264/sps.rs crates/kvm-proto/src/video/tests.rs
git commit -m "kvm-proto: a picture under 200 px either way is stream_incompatible (Plan E Task 1.2, final review Minor 8)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 1.3: IronRDP under an authenticated flood — third-party lines limited per callsite, an oversized format list survives

PD8 m4: `ironrdp_server`'s "Unexpected channel received" lets an authenticated client cause one WARN per PDU, and a level cap cannot bound that. Limit every third-party callsite to its first line, then one per 10 s, and count the rest on `/metrics` (DE5). PD8 m3: IronRDP builds a client's whole format list, 5–10× its wire size, before the bridge's backend runs — an accepted residual (§8); pin that a 20 000-format list neither panics nor ends the session (Review Focus 4). Task 6.1 adds the format-count cap to the pin review's upstream-cap note.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/logging.rs` (the per-callsite filter, `suppressed()`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/metrics.rs` (`kvm_rdp_log_lines_suppressed_total`; the family count)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/client.rs` (`Opts::extra_formats`)
- Test: `crates/kvm-rdp/src/logging.rs`, `crates/kvm-rdp/src/metrics.rs`, `crates/kvm-rdp/tests/l2/paste.rs`

**Interfaces:**
- Consumes: `logging::subscriber`, `CAPPED_TARGETS`, `ERROR_CAPPED_TARGETS`; `Metrics::render`; L2's `Opts::clipboard`, `ClientClip::on_request_format_list`.
- Produces:
  - `pub const logging::THIRD_PARTY_INTERVAL: Duration` (10 s); `pub fn logging::suppressed() -> u64` (process-wide count of dropped third-party lines).
  - `metrics::render_value_counter(out: &mut String, name: &str, help: &str, value: u64)` (crate-private helper; Task 1.4 reuses it); the counter `kvm_rdp_log_lines_suppressed_total`. Family count: the base's 44 + 1 = **45** (19 counters, 13 families, 8 gauges, 5 histograms).
  - L2: `Opts::extra_formats(n: usize) -> Opts` — the client also offers `n` registered formats (ids `0xC000..`, long names).

- [ ] **Step 1: Write the failing tests.** In `logging.rs`'s tests (add `use std::sync::atomic::AtomicU64; use std::time::Duration;`):

```rust
    /// One third-party callsite (each macro call is its own).
    fn unexpected_channel() {
        tracing::warn!(target: "ironrdp_server::server", "unexpected-channel");
    }

    /// DE5 (PD8 m4): a third-party callsite logs its first event, then at
    /// most one per interval, and every dropped line is counted. Events the
    /// level filters already drop are never counted (they never reach the
    /// limit), other callsites keep their own allowance, and bridge lines
    /// are never limited.
    #[test]
    fn a_third_party_callsite_logs_once_per_interval_and_counts_the_rest() {
        let buf = Buf::default();
        let dropped: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));
        let sub = subscriber_limited("trace", buf.clone(), Duration::from_millis(300), dropped)
            .unwrap();
        tracing::subscriber::with_default(sub, || {
            for _ in 0..1000 {
                unexpected_channel();
            }
            for _ in 0..1000 {
                tracing::debug!(target: "ironrdp_server::server", "capped-debug");
            }
            tracing::warn!(target: "ironrdp_server::other", "another-callsite");
            for _ in 0..50 {
                tracing::info!(target: "kvm_rdp::bridge", "bridge-line");
            }
            std::thread::sleep(Duration::from_millis(400));
            unexpected_channel();
        });
        let out = buf.text();
        // Timing-robust (§13's loaded host): a deschedule past the 300 ms
        // interval inside the first loop lets one more line through, and
        // every line is either logged or counted.
        let logged = u64::try_from(out.matches("unexpected-channel").count()).unwrap();
        let dropped = dropped.load(std::sync::atomic::Ordering::Relaxed);
        assert!((2..=4).contains(&logged), "{logged} logged: {out}");
        assert_eq!(logged + dropped, 1001, "{logged} logged, {dropped} dropped");
        assert_eq!(out.matches("another-callsite").count(), 1, "{out}");
        assert_eq!(out.matches("bridge-line").count(), 50, "{out}");
        assert_eq!(out.matches("capped-debug").count(), 0, "{out}");
    }

    /// The production subscriber uses the 10 s interval and the
    /// process-wide counter `/metrics` reads.
    #[test]
    fn the_interval_is_ten_seconds() {
        assert_eq!(THIRD_PARTY_INTERVAL, Duration::from_secs(10));
    }
```

In `metrics.rs`'s tests, in `every_metric_name_is_unique_and_well_formed`, change the count and add the name:

```rust
        assert_eq!(
            names.len(),
            45,
            "19 counters, 13 families, 8 gauges, 5 histograms"
        );
        assert!(t.contains("# TYPE kvm_rdp_log_lines_suppressed_total counter\n"));
```

In `crates/kvm-rdp/tests/l2/paste.rs`:

```rust
/// Plan E Task 1.3 (PD8 m3, Review Focus 4): IronRDP builds a client's
/// whole format list — here CF_UNICODETEXT and 20 000 registered formats
/// with long names, about 1 MiB on the wire — before the bridge sees it.
/// The session survives it, keeps streaming, and the paste still types
/// exactly what `a_paste_types_the_exact_report_list` would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_twenty_thousand_format_list_still_pastes() {
    let env = env(es3(), |c| {
        sized(c);
        c.paste.pace = ms(0);
        c.paste.modifier_wait = ms(300);
    })
    .await;
    let c = env.client(Opts::new(2).clipboard("abc").extra_formats(20_000));
    ready(&c).await;
    let ws = env.hid_ready().await;
    paste_chord(&c, true);
    counted(&env, "done", 1).await;
    let mut want = chord_frames(true);
    want.extend(typed("abc"));
    assert_eq!(settled(until_mark(&env, &c, ws).await), want);
    let before = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= before + 5).await;
    assert_eq!(env.sim.stats().logouts, 0);
}
```

It uses paste.rs's own pattern and helpers: `env`, `es3`, `sized`, `ms`, `paste_chord`, `typed`, `until_mark`, `T` (imported from the harness), `Opts`, `pictures` (from the client), and the module's `ready`, `counted`, `chord_frames` and `settled`. (`after_start` would return on the chord's own six frames, before the Typist types: typing waits for the CLIPRDR round trip.)

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- logging::tests metrics::tests` — Expected: FAIL to compile (`subscriber_limited`, `THIRD_PARTY_INTERVAL` not found). `cargo test --workspace --all-features --test l2 -- paste::a_twenty_thousand` — Expected: FAIL to compile (`extra_formats` not found).

- [ ] **Step 3: The per-callsite filter.** In `logging.rs`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::callsite::Identifier;
use tracing_subscriber::layer::{Context, Filter};

/// Rev 6.4 (PD8 m4, DE5): a third-party callsite logs its first event, then
/// at most one per this interval; the rest are counted in
/// `kvm_rdp_log_lines_suppressed_total`. IronRDP warns once per PDU where
/// an authenticated client chooses the PDUs ("Unexpected channel
/// received"), so a level cap alone still lets a client flood the log.
pub const THIRD_PARTY_INTERVAL: Duration = Duration::from_secs(10);

/// Lines the per-callsite limit dropped, process-wide (`/metrics`).
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Third-party lines dropped so far by the per-callsite limit.
#[must_use]
pub fn suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// Bridge code is never limited: where a peer drives its lines they are
/// already bounded (DC15's refusal line, §4.5).
fn third_party(target: &str) -> bool {
    !(target == "kvm_rdp" || target.starts_with("kvm_rdp::"))
}

/// The limit: one `Instant` per third-party callsite that has logged — a
/// map bounded by the binary's callsites, not by what a peer sends.
struct PerCallsite {
    interval: Duration,
    last: Mutex<HashMap<Identifier, Instant>>,
    dropped: &'static AtomicU64,
}

impl<S> Filter<S> for PerCallsite {
    /// Every callsite stays eligible; the level filters it is `and`ed
    /// after decide what reaches `event_enabled`.
    fn enabled(&self, _: &tracing::Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    /// No level opinion of its own: `And` takes the minimum of the hints,
    /// in which `None` wins, so `None` here would raise
    /// `LevelFilter::current()` to TRACE and make every skipped `trace!`
    /// pay an interest check.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    /// Called for an event the level filters let through, just before it
    /// is written: the per-callsite decision, and the count.
    fn event_enabled(&self, event: &tracing::Event<'_>, _: &Context<'_, S>) -> bool {
        let meta = event.metadata();
        if !third_party(meta.target()) {
            return true;
        }
        let now = Instant::now();
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match last.get(&meta.callsite()) {
            Some(t) if now.saturating_duration_since(*t) < self.interval => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            _ => {
                last.insert(meta.callsite(), now);
                true
            }
        }
    }
}
```

Make `subscriber` delegate to a new `subscriber_limited(filter, writer, interval, dropped)` that holds today's body with one change — the layer's filter becomes:

```rust
        .with_filter(user.and(cap).and(PerCallsite {
            interval,
            last: Mutex::default(),
            dropped,
        }));
```

and `subscriber` is `subscriber_limited(filter, writer, THIRD_PARTY_INTERVAL, &SUPPRESSED)`. (`LevelFilter` is already imported from `tracing_subscriber::filter`.) The limit comes last in the `and` chain so an event a level filter drops never reaches it. Extend the module doc by one sentence: "Third-party lines are also limited per callsite (rev 6.4, DE5)." If `tracing-subscriber` 0.3.23's `Filter` lacks `event_enabled` (it has had it since 0.3.18), stop and report: do not move the decision into `enabled`, which runs before the level filters' verdict is known.

- [ ] **Step 4: The metric.** In `metrics.rs`:

```rust
/// One counter whose value lives outside `Metrics` (a process-wide static):
/// rendered like `Counter`.
pub(crate) fn render_value_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = write!(
        out,
        "# HELP {name}_total {help}\n# TYPE {name}_total counter\n{name}_total {value}\n"
    );
}
```

and in `render`, after the counters loop:

```rust
        render_value_counter(
            &mut out,
            "kvm_rdp_log_lines_suppressed",
            "Third-party log lines past their callsite's limit (§4.5, rev 6.4)",
            crate::logging::suppressed(),
        );
```

- [ ] **Step 5: The L2 client's format list.** In `tests/l2/client.rs`: add `extra_formats: usize` to `Opts` (0 in `Opts::new`), the builder

```rust
    /// Offer `n` more registered formats (ids 0xC000.., long names) beside
    /// CF_UNICODETEXT: a format list about 56 bytes a format on the wire.
    pub fn extra_formats(mut self, n: usize) -> Opts {
        self.extra_formats = n;
        self
    }
```

carry `extra_formats` into `ClientClip`, and build its list in `on_request_format_list`:

```rust
        let mut formats = vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
        formats.extend((0..self.extra_formats).map(|i| {
            let id = 0xC000 + u32::try_from(i % 0x3FFF).unwrap();
            ClipboardFormat::new(ClipboardFormatId::new(id))
                .with_name(ClipboardFormatName::new(format!("kvm-rdp-l2-format-{i:05}")))
        }));
        self.proxy
            .send_clipboard_message(ClipboardMessage::SendInitiateCopy(formats));
```

Add `ClipboardFormatName` to client.rs's `use ironrdp_cliprdr::pdu::{…}` import (beside `ClipboardFormat, ClipboardFormatId`). If the pinned rev spells the constructor or the builder differently, use its spelling — the case needs only "a registered id with a long name".

- [ ] **Step 6: Run the tests.** `cargo test --workspace --all-features --lib -- logging::tests metrics::tests` — Expected: PASS. `cargo test --workspace --all-features --test l2 -- paste::` — Expected: PASS, including `a_twenty_thousand_format_list_still_pastes`. If IronRDP refuses a list this large and the session survives without typing, that is a better outcome than the residual: drop the case's `counted` and `until_mark` lines (and `want`), turn `let ws = env.hid_ready().await;` into `env.hid_ready().await;` (`ws` is then unused, which the clippy gate refuses), keep its streaming and logout asserts, record the refusal (and the size it starts at) in the commit body for Task 6.1, and carry on. A panic or a dropped session is a finding: stop and report.

- [ ] **Step 7: Gate and commit.** The per-task gate, with the image's feature-set clippy (`cargo clippy -p kvm-rdp --lib --bins -- -D warnings`).

```bash
git add crates/kvm-rdp/src/logging.rs crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/tests/l2/client.rs crates/kvm-rdp/tests/l2/paste.rs
git commit -m "kvm-rdp: third-party log lines limited per callsite and counted; a 20 000-format list still pastes (Plan E Task 1.3, PD8 m3 m4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 1.4: allocations — the counting allocator, `alloc-stats`, and the bridge-owned budget

§10.1: "Bridge-owned allocations ≤ 2 per frame" (an in-process microbench of kvm-proto's demux → sanitise → Annex-B, plus the pump, under a counting allocator) and "Whole-process allocations ≤ 40 + bytes/1590 per frame" (a subprocess, exported via `/metrics` in `alloc-stats` builds, §10.4). Build the allocator once (design decision 2), export it, measure the bridge-owned share as DE3 defines it, and remove the two allocations the ledgers carried (PC14 n4: the shell's own `Vec` per step; the per-chunk `Vec<FlvTag>`). Task 5.1 reads the whole-process count.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/alloc_stats.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/Cargo.toml` (`alloc-stats = []`), `src/lib.rs`, `src/main.rs`, `src/testkit.rs`, `src/metrics.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/core.rs` (`step_into`; `surface()` for tests), `src/pump/shell.rs` (the reused `Vec`), `src/kvm/video.rs` (the reused tag buffer)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/alloc.rs`; Modify: `crates/kvm-proto/Cargo.toml` (`[[test]] alloc`)
- Test: `crates/kvm-rdp/src/pump/core.rs`, `crates/kvm-rdp/src/kvm/video.rs`, `crates/kvm-rdp/src/metrics.rs`, `crates/kvm-proto/tests/alloc.rs`

**Interfaces:**
- Consumes: `Pump::step`, the L1 rig (`Rig::new`, `live`, `params`, `au`, `pdus`, `CHAN`, `cfg`), `FlvDemuxer`, `VideoAdmission`, `AccessUnit::write_annex_b`, `metrics::render_value_counter` (Task 1.3).
- Produces:
  - `kvm_rdp::alloc_stats` (`#[cfg(any(test, feature = "alloc-stats"))]`): `pub struct Counting;` (a `GlobalAlloc` over `System`), `pub fn totals() -> (u64, u64)` (allocations, bytes requested, process-wide), `pub fn this_thread() -> u64` (allocations on the calling thread).
  - Cargo feature `kvm-rdp/alloc-stats` (non-default): `main.rs` installs `Counting`; `/metrics` gains `kvm_rdp_allocations_total`, `kvm_rdp_allocated_bytes_total`. Task 5.1's whole-process check reads them.
  - `Pump::step_into(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, input: Input, out: &mut Vec<Command>)` — `step` becomes a wrapper; `#[cfg(test)] pub(crate) fn Pump::surface(&self) -> Option<(u16, u16, u16)>`.

- [ ] **Step 1: Write the failing tests.**

`crates/kvm-proto/tests/alloc.rs`:

```rust
//! §10.1's bridge-owned allocation budget, kvm-proto's share (Plan E Task
//! 1.4, DE3 A): a committed fixture muxed as the ES3 sends it — the FLV
//! header and sequence header, then one tag per access unit, each tag one
//! network read — through `FlvDemuxer` → `VideoAdmission` →
//! `AccessUnit::write_annex_b` into one reused buffer, under a counting
//! allocator. Its own binary with `harness = false`: the global allocator
//! is this file's, and nothing else runs while it counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::as_conversions)]
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use kvm_proto::h264::{is_vcl, split_annex_b};
use kvm_proto::video::{AdmissionConfig, VideoAdmission};
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards to `System` unchanged; counting touches
// one atomic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// kvm-proto's share of §10.1's ≤ 2 per frame (DE3): the per-tag NAL
/// `Vec` and the demuxer buffer's amortised growth.
const BUDGET: f64 = 1.5;
const WARM_UP: usize = 30;

fn main() {
    for name in ["360p30_es3like_poc0.h264", "480p30_main_full.h264"] {
        let per_au = measure(name);
        println!("alloc: {name}: {per_au:.3} allocations per access unit (budget {BUDGET})");
        assert!(per_au <= BUDGET, "{name}: {per_au:.3} > {BUDGET} allocations per AU (§10.1, DE3)");
    }
}

/// The fixture's SPS, PPS and access units (VCL NALs only; an AU starts at
/// a VCL NAL whose `first_mb_in_slice` is 0 — the slice header's first
/// bit set).
fn split(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<Vec<Vec<u8>>>) {
    let (mut sps, mut pps, mut aus) = (None, None, Vec::<Vec<Vec<u8>>>::new());
    for nal in split_annex_b(data) {
        match nal[0] & 0x1F {
            7 => sps = sps.or_else(|| Some(nal.to_vec())),
            8 => pps = pps.or_else(|| Some(nal.to_vec())),
            t if is_vcl(t) => {
                if nal[1] & 0x80 != 0 || aus.is_empty() {
                    aus.push(Vec::new());
                }
                aus.last_mut().unwrap().push(nal.to_vec());
            }
            _ => {}
        }
    }
    (sps.unwrap(), pps.unwrap(), aus)
}

/// Mean allocations per access unit once warm.
fn measure(name: &str) -> f64 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name);
    let (sps, pps, aus) = split(&std::fs::read(path).unwrap());
    // The network reads, built before anything is counted.
    let mut head = Vec::new();
    write_flv_header(&mut head, false, true);
    write_tag(&mut head, TAG_VIDEO, 0, &avc_sequence_header_body(&[&sps], &[&pps], 4).unwrap())
        .unwrap();
    let mut chunks = vec![head];
    for (i, au) in aus.iter().enumerate() {
        let nals: Vec<&[u8]> = au.iter().map(Vec::as_slice).collect();
        let idr = au.iter().any(|n| n[0] & 0x1F == 5);
        let mut body = Vec::new();
        avc_nalu_body(&mut body, idr, 16, &nals, 4).unwrap();
        let mut tag = Vec::new();
        write_tag(&mut tag, TAG_VIDEO, (i as u32 + 1) * 33, &body).unwrap();
        chunks.push(tag);
    }
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut admission = VideoAdmission::new(AdmissionConfig::default());
    admission.flv_opened();
    let mut params = None;
    let mut annexb = Vec::with_capacity(1 << 20);
    let (mut counted, mut n) = (0u64, 0usize);
    for (i, chunk) in chunks.iter().enumerate() {
        let before = ALLOCS.load(Ordering::Relaxed);
        demux.push(chunk);
        while let Some(tag) = demux.next_tag().unwrap() {
            let a = admission.admit(tag, Instant::now()).unwrap();
            if let Some(p) = a.params {
                params = Some(p.params);
            }
            if let (Some(au), Some(p)) = (a.au, params.as_ref()) {
                annexb.clear();
                au.write_annex_b(p, &mut annexb);
            }
        }
        let after = ALLOCS.load(Ordering::Relaxed);
        if i > WARM_UP {
            counted += after - before;
            n += 1;
        }
    }
    counted as f64 / n as f64
}
```

Register it in `crates/kvm-proto/Cargo.toml`:

```toml
# Plan E Task 1.4: kvm-proto's share of §10.1's allocation budget, under
# this binary's own counting allocator — hence no libtest harness.
[[test]]
name = "alloc"
path = "tests/alloc.rs"
harness = false
```

In `crates/kvm-rdp/src/pump/core.rs`'s tests (they already `use` the rig):

```rust
    /// §10.1 (Plan E Task 1.4, DE3 C): the pump's share of the bridge-owned
    /// budget. Per live frame: the shell's three inputs (DC6: suppression,
    /// backlog, the AU) and the frame's ack, stepped into one reused
    /// `Vec` — minus what IronRDP's `send_avc420_frame` + `drain_output`
    /// allocate for the same Annex-B on a twin `GraphicsPipelineServer` in
    /// the same state. At most 0.5 once warm.
    #[test]
    fn the_pumps_own_allocations_per_frame_are_within_its_share() {
        use crate::alloc_stats::this_thread;
        use ironrdp_core::encode_vec;
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::{Avc420Region, FrameAcknowledgePdu, GfxPdu, QueueDepth};
        let (mut r, mut twin) = (Rig::new(cfg()), Rig::new(cfg()));
        let first = r.live();
        twin.live();
        // The session's first IDR, acknowledged: the soft gate sees a live
        // client, as it would once the first frame is acked.
        let id0 = pdus(&first)
            .iter()
            .find_map(|p| match p {
                GfxPdu::EndFrame(e) => Some(e.frame_id),
                _ => None,
            })
            .unwrap();
        r.ack(id0, QueueDepth::Unavailable);
        let (sid, w, h) = twin.pump.surface().unwrap();
        let params = params(ES3);
        let mut out = Vec::with_capacity(16);
        let mut annexb = Vec::with_capacity(1 << 16);
        let ack = |id: u32| {
            encode_vec(&GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
                queue_depth: QueueDepth::Unavailable,
                frame_id: id,
                total_frames_decoded: 0,
            }))
            .unwrap()
        };
        let (mut pump, mut ironrdp, mut frames) = (0u64, 0u64, 0u64);
        for i in 1..=400u32 {
            r.at(u64::from(i) * 33);
            let idr = i % 60 == 0;
            let (Input::Au(a), Input::Au(b)) = (au(idr, false), au(idr, false)) else {
                unreachable!()
            };
            out.clear();
            let t0 = this_thread();
            r.pump.step_into(&mut r.gfx, r.now, Input::Suppress(false), &mut out);
            r.pump.step_into(&mut r.gfx, r.now, Input::Backlog { written: 0 }, &mut out);
            r.pump.step_into(&mut r.gfx, r.now, Input::Au(a), &mut out);
            let t1 = this_thread();
            // The frame's ack: IronRDP's part (decoding the PDU) is not
            // the pump's, so it runs outside the count on both sides.
            let id = pdus(&out)
                .iter()
                .find_map(|p| match p {
                    GfxPdu::EndFrame(e) => Some(e.frame_id),
                    _ => None,
                })
                .expect("the frame was sent");
            r.gfx.process(CHAN, &ack(id)).unwrap();
            let t2 = this_thread();
            r.pump.step_into(
                &mut r.gfx,
                r.now,
                Input::FrameAck { frame_id: id, queue_depth: QueueDepth::Unavailable.to_u32() },
                &mut out,
            );
            let t3 = this_thread();
            annexb.clear();
            b.au.write_annex_b(&params, &mut annexb);
            let region = Avc420Region::full_frame(w, h, 22);
            let t4 = this_thread();
            let tid = twin.gfx.send_avc420_frame(sid, &annexb, &[region], 0);
            let msgs = twin.gfx.drain_output();
            let t5 = this_thread();
            drop(msgs);
            twin.gfx.process(CHAN, &ack(tid.expect("the twin sent it"))).unwrap();
            if i > 30 {
                pump += (t1 - t0) + (t3 - t2);
                ironrdp += t5 - t4;
                frames += 1;
            }
        }
        let net = (pump as f64 - ironrdp as f64) / frames as f64;
        println!("pump: {net:.3} own allocations per frame ({pump} − IronRDP's {ironrdp}, {frames} frames)");
        assert!(net <= 0.5, "the pump allocates {net:.3} per frame of its own (budget 0.5, DE3)");
    }
```

In `crates/kvm-rdp/src/kvm/video.rs`'s tests:

```rust
    /// Plan E Task 1.4 (the per-chunk `Vec<FlvTag>`): `drain` demuxes into
    /// the caller's buffer and never replaces it — once it holds a chunk's
    /// tags, its allocation is reused for every later chunk.
    #[test]
    fn drain_reuses_the_tag_buffer() {
        use kvm_proto::flv::mux::{
            TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
        };
        // `drain` only demuxes: the ES3 fixture's admitted parameter sets
        // (the L1 rig's) make a well-formed sequence header.
        let p = crate::pump::rig::params(crate::pump::rig::ES3);
        let pps: Vec<&[u8]> = p.pps.iter().map(|b| b.as_ref()).collect();
        let mut head = Vec::new();
        write_flv_header(&mut head, false, true);
        write_tag(&mut head, TAG_VIDEO, 0, &avc_sequence_header_body(&[&p.sps], &pps, 4).unwrap())
            .unwrap();
        let mut chunks = vec![head];
        for i in 0..64u32 {
            let mut body = Vec::new();
            avc_nalu_body(&mut body, i == 0, 16, &[&[0x65, 0x88, 0x84, 0x21][..]], 4).unwrap();
            let mut tag = Vec::new();
            write_tag(&mut tag, TAG_VIDEO, (i + 1) * 33, &body).unwrap();
            chunks.push(tag);
        }
        let mut demux = FlvDemuxer::new(FlvLimits::default());
        let mut tags = Vec::with_capacity(8);
        let (ptr, cap) = (tags.as_ptr(), tags.capacity());
        for c in &chunks {
            tags.clear();
            assert!(drain(&mut demux, c, &mut tags).is_none());
            assert_eq!((tags.as_ptr(), tags.capacity()), (ptr, cap), "drain replaced the buffer");
        }
    }
```

(`avc_sequence_header_body`'s parameter types are whatever the mux takes — `&[&[u8]]` for both lists in `video/tests.rs`; adapt the two bindings if it takes `Bytes`.) The assertion is the point: the buffer's pointer and capacity never change.

In `metrics.rs`'s tests:

```rust
    /// Plan E Task 1.4 (§10.4): an alloc-stats build exports the process's
    /// allocation counters, and they move.
    #[cfg(feature = "alloc-stats")]
    #[test]
    fn alloc_stats_builds_export_the_allocation_counters() {
        let first = Metrics::default().render();
        let _keep: Vec<Vec<u8>> = (0..64).map(|i| vec![0u8; 64 + i]).collect();
        let second = Metrics::default().render();
        let value = |t: &str| -> u64 {
            t.lines()
                .find_map(|l| l.strip_prefix("kvm_rdp_allocations_total "))
                .unwrap()
                .parse()
                .unwrap()
        };
        assert!(value(&second) >= value(&first) + 64, "{first}\n{second}");
        assert!(second.contains("# TYPE kvm_rdp_allocated_bytes_total counter\n"));
    }
```

and, in the same commit that declares `alloc-stats = []` (Step 3), edit Task 1.3's count assertion in `every_metric_name_is_unique_and_well_formed` to:

```rust
        assert_eq!(
            names.len(),
            45 + if cfg!(feature = "alloc-stats") { 2 } else { 0 },
            "19 counters, 13 families, 8 gauges, 5 histograms (+2 counters in alloc-stats builds)"
        );
```

(Written before the feature is declared, the `cfg!` would warn `unexpected cfg condition value` and fail the clippy gate.)

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --test alloc` — Expected: it builds and either passes or fails on the budget; record the two "allocations per access unit" lines (this is A's baseline, before any change). `cargo test --workspace --all-features --lib -- pump::core::tests::the_pumps_own kvm::video::tests::drain_reuses metrics::tests::alloc_stats` — Expected: FAIL to compile (`alloc_stats`, `step_into`, `surface`, the new `drain` signature).

- [ ] **Step 3: The allocator.** `crates/kvm-rdp/src/alloc_stats.rs`:

```rust
//! Allocation counting (§10.1, §10.4; Plan E Task 1.4): one `GlobalAlloc`
//! over `System` that counts every allocation process-wide — what an
//! `alloc-stats` build exports on `/metrics` — and per thread, which the
//! lib's own tests read around a measured region. A `realloc` counts as an
//! allocation (it may move); a free counts nothing.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// `const`-initialised and drop-free: reading it never allocates.
    static THREAD: Cell<u64> = const { Cell::new(0) };
}

fn note(size: usize) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(u64::try_from(size).unwrap_or(u64::MAX), Ordering::Relaxed);
    // During this thread's TLS teardown the thread count is gone: the
    // allocation is counted process-wide only.
    let _ = THREAD.try_with(|c| c.set(c.get().wrapping_add(1)));
}

// SAFETY: every method forwards its arguments to `System` unchanged, so
// `System`'s guarantees are this allocator's; counting touches only atomics
// and a thread-local `Cell`, neither of which allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's `GlobalAlloc::alloc` contract, forwarded.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: `ptr` came from this allocator, i.e. from `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as `realloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Allocations and bytes requested since the process started (0 unless
/// this allocator is installed).
#[must_use]
pub fn totals() -> (u64, u64) {
    (ALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed))
}

/// Allocations on the calling thread so far: a test reads it before and
/// after the region it measures.
#[must_use]
pub fn this_thread() -> u64 {
    THREAD.try_with(Cell::get).unwrap_or(0)
}
```

`crates/kvm-rdp/src/lib.rs`: `#[cfg(any(test, feature = "alloc-stats"))] pub mod alloc_stats;`. `Cargo.toml` `[features]`:

```toml
# §10.4's allocations per frame (Plan E Task 1.4): the binary installs
# `alloc_stats::Counting` and /metrics exports its counters. kvm-bench's
# bridge is built with it; the image never is.
alloc-stats = []
```

`main.rs`:

```rust
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: kvm_rdp::alloc_stats::Counting = kvm_rdp::alloc_stats::Counting;
```

`testkit.rs` (a `cfg(test)` module):

```rust
/// Plan E Task 1.4: the lib's tests count allocations per thread
/// (`alloc_stats::this_thread`). The count costs one TLS add per
/// allocation; nothing else changes.
#[global_allocator]
static ALLOC: crate::alloc_stats::Counting = crate::alloc_stats::Counting;
```

`metrics.rs`, in `render` after Task 1.3's counter:

```rust
        #[cfg(feature = "alloc-stats")]
        {
            let (allocations, bytes) = crate::alloc_stats::totals();
            render_value_counter(
                &mut out,
                "kvm_rdp_allocations",
                "Heap allocations since start (alloc-stats builds, §10.4)",
                allocations,
            );
            render_value_counter(
                &mut out,
                "kvm_rdp_allocated_bytes",
                "Bytes requested from the allocator since start (alloc-stats builds)",
                bytes,
            );
        }
```

- [ ] **Step 4: `Pump::step_into`.** In `core.rs`, move `step`'s body into

```rust
    /// `step`, appending to `out` (Plan E Task 1.4, PC14 n4: the shell
    /// steps every input into one reused `Vec`). Commands already in `out`
    /// stay where they are, before this step's.
    pub fn step_into(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        input: Input,
        out: &mut Vec<Command>,
    ) {
        let base = out.len();
        // … the body of `step`, with `out` the parameter …
    }

    pub fn step(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, input: Input) -> Vec<Command> {
        let mut out = Vec::new();
        self.step_into(gfx, now, input, &mut out);
        out
    }
```

The body's one positional use — the burst chunk sent ahead of a state change, `out.insert(0, Command::SendDvc(b))` — becomes `out.insert(base, Command::SendDvc(b))`. Check there is no other: `grep -n 'out\.\(insert\|is_empty\|len\|clear\|retain\|first\|truncate\)' crates/kvm-rdp/src/pump/core.rs` — every hit above the `#[cfg(test)]` line must be relative to `base` (the `out.last()` hits are in tests). Add for the tests:

```rust
    #[cfg(test)]
    pub(crate) fn surface(&self) -> Option<(u16, u16, u16)> {
        self.surface
    }
```

- [ ] **Step 5: The shell reuses one `Vec` (PC14 n4).** In `shell.rs`, add a field `scratch: Vec<Command>` to `PumpShell` (`Vec::new()` in its constructor; doc: "Every step's commands, one allocation reused (PC14 n4)."). `step` becomes:

```rust
    /// Step `inputs` in order under one GFX lock hold (§4.3), into the
    /// shell's reused `Vec` (PC14 n4) — `exec` hands it back.
    fn step(&mut self, inputs: impl IntoIterator<Item = Input>) -> Vec<Command> {
        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        let Some(gfx) = self.link.as_ref().map(|l| l.gfx.clone()) else {
            self.scratch = out;
            return Vec::new();
        };
        let now = Instant::now();
        let mut g = lock(&gfx);
        for i in inputs {
            self.pump.step_into(&mut g, now, i, &mut out);
        }
        out
    }
```

and `exec` returns the buffer whatever path it ends by — rename today's `exec` to `exec_queue(&mut self, queue: &mut VecDeque<Command>)` with its body unchanged (its `return`s now return from `exec_queue`), and:

```rust
    async fn exec(&mut self, cmds: Vec<Command>) {
        let mut queue: VecDeque<Command> = cmds.into();
        self.exec_queue(&mut queue).await;
        queue.clear();
        // The capacity, for the next step; a nested step meanwhile took a
        // fresh, empty one.
        let back = Vec::from(queue);
        if back.capacity() > self.scratch.capacity() {
            self.scratch = back;
        }
    }
```

- [ ] **Step 6: The KVM side's tag buffer.** In `kvm/video.rs`, `drain` becomes:

```rust
/// Demux `bytes` into `tags`, the caller's reused buffer (Plan E Task 1.4:
/// no `Vec` per chunk).
fn drain(demux: &mut FlvDemuxer, bytes: &[u8], tags: &mut Vec<FlvTag>) -> Option<FlvError> {
    demux.push(bytes);
    loop {
        match demux.next_tag() {
            Ok(Some(t)) => tags.push(t),
            Ok(None) => return None,
            Err(e) => return Some(e),
        }
    }
}
```

Add `tags: Vec<FlvTag>` to the struct that owns `main`/`pending` (`Vec::with_capacity(8)` where it is built). The buffer is taken only after each function's `as_mut()?` — an early return before the take keeps it — and put back before every return after it. `main_chunk`'s tail, from `let s = self.main.as_mut()?;`:

```rust
        let s = self.main.as_mut()?;
        let mut tags = std::mem::take(&mut self.tags);
        tags.clear();
        let err = drain(&mut s.demux, &bytes, &mut tags);
        let outcome = self.admit_all(&mut tags, err, now).await;
        self.tags = tags;
        outcome
```

`pending_chunk`'s tail, from `let p = self.pending.as_mut()?;` (the error branch's body below the restore is today's, unchanged):

```rust
        let p = self.pending.as_mut()?;
        let mut tags = std::mem::take(&mut self.tags);
        tags.clear();
        let err = drain(&mut p.demux, &bytes, &mut tags);
        if tags.is_empty() {
            // No first tag: a header-only chunk waits; an error means the
            // candidate failed and the old FLV keeps flowing (§6.5). It is
            // still the KVM's framing violation (§6.9): counted, and toward
            // the 3-in-60 s `stream_corrupt` rule.
            let Some(e) = err else {
                self.tags = tags;
                return None;
            };
            self.tags = tags;
            self.pending = None;
            self.metrics.upstream_reconnects.inc("commanded_failed");
            let e = AdmissionError::from(e);
            self.metrics.parse_errors.inc(e.kind());
            if matches!(self.violations.record(now), ViolationVerdict::Fatal) {
                self.close();
                return Some(Outcome::Fatal(Cause::StreamCorrupt));
            }
            return None;
        }
        // Its first tag: the old FLV closes now (make-before-break, §6.5).
        self.main = self.pending.take();
        self.became_main(FlvOrigin::Commanded, now).await;
        let outcome = self.admit_all(&mut tags, err, now).await;
        self.tags = tags;
        outcome
```

`admit_all` takes `tags: &mut Vec<FlvTag>` and iterates `for tag in tags.drain(..)` — an early return drops the rest, as before.

- [ ] **Step 7: Run the tests.** `cargo test --workspace --all-features --lib -- pump:: kvm::video:: metrics::` — Expected: PASS, including `the_pumps_own_allocations_per_frame_are_within_its_share` (record its printed number), `drain_reuses_the_tag_buffer`, `alloc_stats_builds_export_the_allocation_counters`, and every existing pump and shell case (the reuse must not change a single command). `cargo test --workspace --all-features --test alloc` — Expected: PASS, both fixtures ≤ 1.5 (record the numbers). If A or C is over its share after these changes, stop and report the measured numbers per stage: the allowed remedies (reusing the demuxer's NAL `Vec`, a larger initial `BytesMut`) change kvm-proto's API or memory profile and need a ruling.

- [ ] **Step 8: Gate and commit.** The per-task gate (the target budget too: no new IronRDP-linked binary — `alloc` is kvm-proto's), with the image's feature-set clippy: `cargo clippy -p kvm-rdp --lib --bins -- -D warnings` — Expected: clean (nothing gated on `alloc-stats` leaves an unused import in the build that ships).

```bash
git add crates/kvm-rdp/Cargo.toml crates/kvm-rdp/src/alloc_stats.rs crates/kvm-rdp/src/lib.rs crates/kvm-rdp/src/main.rs \
  crates/kvm-rdp/src/testkit.rs crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/src/pump/core.rs crates/kvm-rdp/src/pump/shell.rs \
  crates/kvm-rdp/src/kvm/video.rs crates/kvm-proto/tests/alloc.rs crates/kvm-proto/Cargo.toml
git commit -m "kvm-rdp: counting allocator and alloc-stats; the pump steps into one reused Vec, the KVM side demuxes into one tag buffer; bridge-owned allocations within §10.1's budget (Plan E Task 1.4, PC14 n4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Put Step 7's two printed numbers in the commit body (`git commit` opens the editor if you drop the first `-m`, or add a `-m "Measured per frame: A … (kvm-proto, 360p / 480p), C … (pump, net of IronRDP)."` line with the real values) — Task 6.1 copies them into §10.1.

### Task 1.5: spec rev 6.3's last two carries — a stalled RDP thread releases held input (m3); a resync mid-paste aborts it (m4)

Spec rev 6.3 §12 carries two items to Plan E from Plan D's final review, and the owner's rule is that a key never stays stuck and a paste never types a different text:

- **m3** — "A KVM-runtime watch that calls release-all once the RDP heartbeat is about 1 s old while the queue's newest state holds something: a stalled RDP thread is otherwise healed only by `/livez`'s restart (§7.4)." The input core, its driver and both §7.4 timers run on the RDP thread (§4.3); stalled, nothing steps them, and what the KVM holds stays held — a Typist press auto-repeating on the Mac — until `/livez` (10 s) and the supervisor's restart. The watch runs on the KVM runtime, which the stall does not reach.
- **m4** — "Ending a paste as aborted when the queue resyncs while it types (§8), so an overflow never drops characters from the middle of a paste." The Typist is room-bounded (DD6), but pointer reports share the queue; a resync (§7.3) clears the queued typed reports and sends the final state, and the Typist then carries on — the KVM types the text with a hole in it. The shell sees the resync (`Push::Resync`) and steps the core with it; the core ends the paste `aborted_resync` and releases all. While the Typist types, the shell pushes with `HidControl::push_typing_at`, which drops the resync's state under the queue lock — as `discard_queued` does (Plan D I1) — and the step's later pushes are not made, so the writer, woken by the push, finds nothing to write before the release's zeros: nothing after the hole is ever typed. Residual (recorded in rev 6.4): a resync after the Typist's last report but before the queue has drained drops the paste's last ≤ 8 reports — the KVM keeps a prefix, no key held — and the paste stays counted `done` (keep `input.queue` at 256).

The heartbeat beats every quarter of `admin.liveness_timeout`, capped at 1 s (§4.5), and stays so (idle CPU: PC15 m2's ~21 wakeups per 10 s). At the default one late beat would already be "about 1 s old", so the bound is 3 s — three periods — and a single late beat can never trip it (DE16, controller ruling 11): a key held through a stalled RDP thread is released at 3 s. Both triggers are labels on `kvm_rdp_release_all{trigger}` and the abort a label on `paste_events{outcome}`: the family count is unchanged. Run after Task 1.1 (the L2 case needs `test-hooks`' stall).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/stale.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/hid/mod.rs` (`pub mod stale;`), `src/hid/queue.rs` (`ReleaseTrigger::{RdpStale, PasteResync}`; `HidControl::{newest_holds, push_typing_at}`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/admin.rs` (`Health::rdp_age`), `src/bridge.rs` (the watch as an essential KVM-runtime task; the heartbeat's 1 s cap named `HEARTBEAT_MAX`, its value unchanged)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/input/core.rs` (`Event::QueueResynced`; `InputCore::typing`), `src/rdp/input.rs` (`carry_out` pushes with `push_typing_at` while typing and reports a resync; `abort_label("resync")`), `src/metrics.rs` (`PASTE_ABORTS`: nine)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/admin.rs` (`INPUT_LINES`: the watch's line)
- Test: `crates/kvm-rdp/src/hid/stale.rs`, `src/hid/queue.rs`, `src/admin.rs`, `src/bridge.rs`, `src/input/core.rs`, `src/rdp/input.rs` (`tests`); `crates/kvm-rdp/tests/l2/input.rs`, `tests/l2/paste.rs`

**Interfaces:**
- Consumes: `admin::Health` (`beat`, `live`), `hid::{HidControl, ReleaseTrigger, Push}` (`release_all`, `push_at`, `queued`), Task 1.1's `BridgeHandle::block_rdp_runtime_for` (`test-hooks`), bridge.rs's `fault_point`, `Essential` and `dies_and_stops_the_bridge`, the core's `paste_filter`, `release_marked` and `State::Typing`; L2's `streaming`, `hid_ready`, `hid_stamped`, `until`, `until_mark`, paste.rs's `ready`, `counted`, `pasted`, `settled`, `chord_frames`, `typed`, and kvm-sim's `control_recv_buffer` / `pause_ws_reads`.
- Produces:
  - `pub mod kvm_rdp::hid::stale`: `pub const RDP_STALE_RELEASE: Duration` (3 s), `pub const HEARTBEAT_MAX: Duration` (1 s, §4.5's cap), `pub const WATCH_EVERY: Duration` (100 ms), `pub struct StaleWatch` with `step(&mut self, age: Duration, held: impl FnOnce() -> bool) -> bool`, `pub async fn run(health: Arc<Health>, hid: Arc<HidControl>)` (never returns); WARN `the RDP runtime stopped with input held: released all` (target `kvm_rdp::hid::stale`, no fields).
  - `ReleaseTrigger::RdpStale` (`"rdp_stale"`), `ReleaseTrigger::PasteResync` (`"paste_resync"`); `pub fn HidControl::newest_holds(&self) -> bool` (the queue's newest keyboard or pointer state holds a key or a button); `pub(crate) fn HidControl::push_typing_at(&self, stamp: u64, frame: HidFrame, motion_only: bool) -> Push` (`push_at`, but a resync leaves nothing for the writer), both over a private `push_inner(…, typing: bool)`.
  - `pub fn Health::rdp_age(&self) -> Duration`; the essential KVM-runtime task `"stale watch"`.
  - `Event::QueueResynced`; `pub fn InputCore::typing(&self) -> bool`; `PasteOutcome::Aborted("resync")`, counted `paste_events{outcome="aborted_resync"}`; `metrics::PASTE_ABORTS: [&str; 9]`.

- [ ] **Step 1: Write the failing unit tests (m3).** `crates/kvm-rdp/src/hid/stale.rs`, its tests first (the module body comes in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// m3: a stale episode releases once, and only while something is
    /// held; a fresh heartbeat re-arms it. The bound itself is not stale.
    #[test]
    fn a_stale_episode_releases_once_and_only_while_held() {
        let mut w = StaleWatch::default();
        let fresh = Duration::from_millis(300);
        let stale = RDP_STALE_RELEASE + Duration::from_millis(1);
        assert!(!w.step(fresh, || true), "fresh: never");
        assert!(!w.step(RDP_STALE_RELEASE, || true), "at the bound: not yet");
        assert!(!w.step(stale, || false), "stale, nothing held: nothing to release");
        assert!(w.step(stale, || true), "stale and held: release");
        assert!(!w.step(stale * 3, || true), "once per episode");
        assert!(!w.step(fresh, || true), "fresh again: re-armed");
        assert!(w.step(stale, || true), "the next episode releases again");
    }

    /// `held` is read only once the heartbeat is stale: the watch takes no
    /// queue lock every 100 ms on a healthy bridge.
    #[test]
    fn held_is_read_only_when_stale() {
        let mut w = StaleWatch::default();
        let mut reads = 0;
        let _ = w.step(Duration::from_millis(10), || {
            reads += 1;
            true
        });
        assert_eq!(reads, 0);
    }

    /// DE16 (controller ruling 11): the bound is three heartbeats at
    /// §4.5's 1 s cap, so one late beat never reads as a stall.
    #[test]
    fn the_bound_is_three_heartbeats() {
        assert_eq!(RDP_STALE_RELEASE, Duration::from_secs(3));
        assert_eq!(HEARTBEAT_MAX, Duration::from_secs(1));
        assert!(RDP_STALE_RELEASE >= HEARTBEAT_MAX * 3);
        assert!(WATCH_EVERY < RDP_STALE_RELEASE / 5);
    }
}
```

In `crates/kvm-rdp/src/hid/queue.rs`'s tests, after `the_input_cores_triggers_are_counted_under_their_labels`:

```rust
    /// Plan E Task 1.5: the stale watch's trigger (m3) and the resync
    /// abort's (m4), each under its own `release_all{trigger}` label.
    #[test]
    fn the_stale_watch_and_the_resync_abort_are_counted_under_their_labels() {
        let c = ctl(4);
        for (t, label) in [
            (ReleaseTrigger::RdpStale, "rdp_stale"),
            (ReleaseTrigger::PasteResync, "paste_resync"),
        ] {
            assert_eq!(t.label(), label);
            c.release_all(t);
            assert_eq!(c.metrics.release_all.get(label), 1);
        }
    }

    /// m3's condition: the queue's newest state holds a key or a button.
    #[test]
    fn newest_holds_follows_the_newest_state() {
        let c = ctl(4);
        assert!(!c.newest_holds());
        c.push(kbd(4), false);
        assert!(c.newest_holds(), "a key down");
        c.push(kbd(0), false);
        assert!(!c.newest_holds(), "all up");
        c.push(mouse(1, 5, 5), false);
        assert!(c.newest_holds(), "a button down");
        c.release_all(ReleaseTrigger::RdpStale);
        assert!(!c.newest_holds(), "a release zeroes it");
    }
```

(`ctl(capacity)`, `kbd(usage)` and `mouse(buttons, x, y)` are the module's own test helpers.) In `crates/kvm-rdp/src/admin.rs`'s tests, after `livez_goes_stale_without_heartbeats`:

```rust
    /// Plan E Task 1.5: the heartbeat's age, which `/livez` and the stale
    /// watch both read. Generous bounds (§13's loaded host).
    #[test]
    fn the_rdp_age_is_the_time_since_the_last_beat() {
        let h = Health::new(Duration::from_secs(10));
        h.beat();
        assert!(h.rdp_age() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(300));
        let age = h.rdp_age();
        assert!(age >= Duration::from_millis(299) && age < Duration::from_secs(5), "{age:?}");
        h.beat();
        assert!(h.rdp_age() < Duration::from_secs(1));
    }
```

In `crates/kvm-rdp/src/bridge.rs`'s tests, after `a_panicked_certificate_watcher_stops_the_bridge`:

```rust
    /// Plan E Task 1.5: the stale watch is an essential KVM-runtime task —
    /// without it a stalled RDP thread keeps a key held until `/livez`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicked_stale_watch_stops_the_bridge() {
        dies_and_stops_the_bridge("stale watch", |h| {
            h.faults.send_replace(Some("stale watch"));
        })
        .await;
    }
```

- [ ] **Step 2: The failing L2 case (m3).** In `crates/kvm-rdp/tests/l2/input.rs` (add `use kvm_rdp::hid::stale::RDP_STALE_RELEASE;`), after the key-repeat cases:

```rust
/// Plan E Task 1.5 (spec §7.4, Plan D final review m3): the RDP runtime
/// stalls with a key held. Nothing on that thread runs — no timer, no core
/// step — so only the KVM-runtime watch can release it: kvm-sim sees the
/// all-zero report within 5× `RDP_STALE_RELEASE` (3 s) of the stall and
/// not before 0.5× (§11.1), during the stall, counted
/// `release_all{rdp_stale}` once, and the key is not pressed again once
/// the thread runs again. (`key_repeat_timeout` is raised to 60 s, past
/// the 5× bound: only the watch can pass this case.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_rdp_runtime_with_a_key_held_is_released_by_the_kvm_runtime() {
    // Longer than the bound plus a heartbeat period, so the release comes
    // inside the stall.
    const STALL: Duration = Duration::from_secs(6);
    let (env, c) = streaming(|c| c.input.key_repeat_timeout = Duration::from_secs(60)).await;
    let ws = env.hid_ready().await;
    c.key(A, true);
    let press = kbd(0, 0x04);
    env.sim
        .wait_for(T, |l| hid_on(l, ws).contains(&press))
        .await
        .unwrap_or_else(|l| panic!("the press never reached kvm-sim: {:02x?}", hid_on(&l, ws)));
    let t0 = Instant::now();
    env.bridge().block_rdp_runtime_for(STALL);
    // The first all-zero keyboard report after the press: its stamp.
    let released = || {
        let s = hid_stamped(&env.sim, ws);
        let p = s.iter().position(|(_, f)| *f == press)?;
        s[p..].iter().find(|(_, f)| *f == zero()).map(|(t, _)| *t)
    };
    assert!(
        until(RDP_STALE_RELEASE * 5, || released().is_some()).await,
        "no all-zero report within 5× RDP_STALE_RELEASE of the stall"
    );
    let at = released().unwrap().duration_since(t0);
    assert!(at >= RDP_STALE_RELEASE / 2, "released {at:?} into the stall, before 0.5× the bound");
    assert!(at < STALL, "released {at:?} in, after the stall: not the watch");
    assert_eq!(env.metrics().release_all.get("rdp_stale"), 1);
    // After the stall: the core's next step sees the moved epoch and
    // releases its own state (the key is released by the bridge), so the
    // key never goes down again on its own.
    let frames = until_mark(&env, &c, ws).await;
    let p = frames.iter().position(|f| *f == press).unwrap();
    let z = p + frames[p..].iter().position(|f| *f == zero()).unwrap();
    assert!(!frames[z..].contains(&press), "pressed again after the release: {frames:02x?}");
    c.key(A, false);
    assert_eq!(env.metrics().release_all.get("rdp_stale"), 1, "one release per stall");
}
```

**Re-check after Plan D's residual fix lands** (the writer's re-assert becomes pong-gated and its backoff is skipped once until the session start; `plan-e` is cut after it): this case observes the writer's re-asserts of the held press before the stale release; its oracle — no press after the first zero — tolerates either behaviour, but run it again then (pre-flight X1).

In `crates/kvm-rdp/tests/l2/admin.rs`, `INPUT_LINES` becomes `[Line; 10]` with, after the two release-websocket lines:

```rust
    // Plan E Task 1.5 (m3): the KVM-runtime watch released held input
    // because the RDP runtime stopped; once per stall, no fields.
    (
        "kvm_rdp::hid::stale",
        "the RDP runtime stopped with input held: released all",
        &[],
    ),
```

- [ ] **Step 3: Run them to see them fail.** `cargo test --workspace --all-features --lib -- hid::stale hid::queue::tests::the_stale_watch hid::queue::tests::newest_holds admin::tests::the_rdp_age bridge::tests::a_panicked_stale_watch` — Expected: FAIL to compile (no `hid::stale`, `RdpStale`, `PasteResync`, `newest_holds`, `rdp_age`). `cargo test --workspace --all-features --test l2 -- input::a_stalled_rdp_runtime` — Expected: FAIL to compile (`kvm_rdp::hid::stale` not found).

- [ ] **Step 4: The watch (m3).** `crates/kvm-rdp/src/hid/stale.rs`, above its tests:

```rust
//! Plan E Task 1.5 (spec §7.4 rev 6.3, Plan D final review m3): a stalled
//! RDP runtime must not leave a key held. The input core, its driver and
//! both §7.4 timers run on the RDP thread (§4.3); stalled, nothing steps
//! them, and only `/livez`'s restart would heal it. This task runs on the
//! KVM runtime, which the stall does not reach: once the RDP heartbeat is
//! older than `RDP_STALE_RELEASE` while the queue's newest state holds a
//! key or a button, it calls release-all — once per stale episode.
use crate::admin::Health;
use crate::hid::{HidControl, ReleaseTrigger};
use std::sync::Arc;
use std::time::Duration;

/// How old the RDP heartbeat may be before held input is released: three
/// heartbeat periods (DE16, controller ruling 11; §12 said "about 1 s"), so
/// a single late beat never reads as a stall.
pub const RDP_STALE_RELEASE: Duration = Duration::from_secs(3);
/// The heartbeat's longest period, §4.5's cap (bridge.rs's clamp; idle CPU
/// rests on it: PC15 m2's ~21 wakeups per 10 s).
pub const HEARTBEAT_MAX: Duration = Duration::from_secs(1);
/// How often the watch reads the heartbeat's age.
pub const WATCH_EVERY: Duration = Duration::from_millis(100);

const _: () = assert!(RDP_STALE_RELEASE.as_millis() >= 3 * HEARTBEAT_MAX.as_millis());

/// The decision, apart from the clock and the queue: release once per
/// stale episode, re-armed when the heartbeat is fresh again.
#[derive(Debug, Default)]
pub struct StaleWatch {
    fired: bool,
}

impl StaleWatch {
    /// Whether to release now, given the heartbeat's `age`; `held` (the
    /// queue's newest state holds something) is read only when stale.
    pub fn step(&mut self, age: Duration, held: impl FnOnce() -> bool) -> bool {
        if age <= RDP_STALE_RELEASE {
            self.fired = false;
            return false;
        }
        if self.fired || !held() {
            return false;
        }
        self.fired = true;
        true
    }
}

/// The watch, an essential KVM-runtime task (bridge.rs): every
/// `WATCH_EVERY`, the heartbeat's age and, when stale, whether input is
/// held. Never returns.
pub async fn run(health: Arc<Health>, hid: Arc<HidControl>) {
    let mut watch = StaleWatch::default();
    let mut tick = tokio::time::interval(WATCH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if watch.step(health.rdp_age(), || hid.newest_holds()) {
            tracing::warn!("the RDP runtime stopped with input held: released all");
            hid.release_all(ReleaseTrigger::RdpStale);
        }
    }
}
```

`crates/kvm-rdp/src/hid/mod.rs`: `pub mod stale;` after `pub mod release;`. In `hid/queue.rs`, `ReleaseTrigger` gains, after `ModifierIdle`:

```rust
    /// The KVM-runtime stale watch: the RDP heartbeat stopped with input
    /// held (§7.4; Plan E Task 1.5, m3).
    RdpStale,
    /// A queue resync while the Typist typed ended the paste (§8; Plan E
    /// Task 1.5, m4).
    PasteResync,
```

with `ReleaseTrigger::RdpStale => "rdp_stale",` and `ReleaseTrigger::PasteResync => "paste_resync",` in `label`; and `HidControl` gains, after `input_held`:

```rust
    /// m3 (Plan E Task 1.5): the queue's newest keyboard or pointer state
    /// holds a key or a button — what the input core last asked for.
    #[must_use]
    pub fn newest_holds(&self) -> bool {
        self.q().state_holds()
    }
```

In `admin.rs`, `Health` gains

```rust
    /// How long since the RDP runtime's last heartbeat: `/livez` and the
    /// stale watch (`hid::stale`) both read it.
    #[must_use]
    pub fn rdp_age(&self) -> Duration {
        let last = Duration::from_millis(self.last_beat_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last)
    }
```

`live` becomes `self.rdp_age() <= self.liveness_timeout`, and `beat`'s doc reads "(a `LocalSet` task, every quarter of `admin.liveness_timeout`, at most `hid::stale::HEARTBEAT_MAX`, 1 s)". In `bridge.rs`: the heartbeat period's clamp names its cap, `.clamp(Duration::from_millis(10), crate::hid::stale::HEARTBEAT_MAX)` — the same 1 s (§4.5 unchanged), so the const assert above binds the cap the bridge uses; after `watcher_task`:

```rust
    // Plan E Task 1.5 (§7.4, m3): on the KVM runtime, which a stalled RDP
    // thread does not reach.
    let stale_task = kvm_rt.spawn(fault_point(
        "stale watch",
        crate::hid::stale::run(health.clone(), hid.clone()),
        &seam,
    ));
```

and `("stale watch", stale_task),` after `("certificate watcher", watcher_task),` in `essential`.

- [ ] **Step 5: Run the m3 tests.** The Step 3 commands — Expected: PASS, the L2 case included (its release lands between about 2 s and 3 s into the 6 s stall: 3 s after the last beat, which L2's 1 s `liveness_timeout` makes at most 250 ms old when the stall begins). Then `cargo test --workspace --all-features --test l2 -- admin:: input::` — Expected: PASS (the secrets case reviews the new line only if it fires; `livez_goes_stale_while_the_rdp_runtime_is_blocked` still sees `/livez` stale and recover).

- [ ] **Step 6: The failing tests (m4).** In `crates/kvm-rdp/src/input/core.rs`'s tests, after `every_paste_outcome_leaves_nothing_held`, and — in that test — a sixteenth case (the array's type becomes `[(&str, PasteOutcome, Drive); 16]`):

```rust
            (
                "resync typing",
                PasteOutcome::Aborted("resync"),
                |w| {
                    w.typing("abcdef");
                    w.step(Event::QueueResynced);
                    vec![]
                },
            ),
```

```rust
    /// Plan E Task 1.5 (m4, §8): a queue resync while the Typist types ends
    /// the paste as aborted ("resync") and releases all — the resync cleared
    /// typed reports, so typing on would leave a hole — and nothing more is
    /// typed. Idle or Pending, a resync changes nothing (the shell steps it
    /// only while typing, but the core does not rely on that).
    #[test]
    fn a_queue_resync_while_typing_aborts_the_paste_and_releases_all() {
        let mut w = Wired::new();
        w.typing("abcdef");
        assert!(w.core.typing());
        let out = w.step(Event::QueueResynced);
        assert_eq!(outcomes(&out), [&PasteOutcome::Aborted("resync")]);
        assert_eq!(releases(&out), [ReleaseTrigger::PasteResync]);
        assert!(!w.core.typing() && !w.core.paste.is_active());
        for _ in 0..16 {
            w.now += w.pace;
            let out = w.step(Event::Tick);
            assert!(
                !pushes(&out).iter().any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] != 0)),
                "typed after the abort: {}",
                show(&out)
            );
        }
        let mut idle = Wired::new();
        let out = idle.step(Event::QueueResynced);
        assert!(outcomes(&out).is_empty() && releases(&out).is_empty(), "{}", show(&out));
        let mut pending = Wired::new();
        pending.chord();
        let out = pending.step(Event::QueueResynced);
        assert!(outcomes(&out).is_empty() && releases(&out).is_empty(), "{}", show(&out));
        assert!(pending.core.paste.is_active(), "a Pending paste is not typing");
    }
```

In `crates/kvm-rdp/src/rdp/input.rs`'s tests: `a_paste_abort_is_counted_under_its_reason`'s reasons gain `"resync"` (last) and its doc's "the eight" becomes "the nine"; and after `the_driver_types_a_paste_as_the_queue_drains`:

```rust
    /// Plan E Task 1.5 (m4, §8): through the shell. The writer stands still
    /// (no `write`), so the Typist fills its room; wheel notches — pointer
    /// reports share the queue — then find it full: a resync. The paste
    /// ends `aborted_resync` with `release_all{paste_resync}`, and after the
    /// release's zeros nothing is typed.
    #[tokio::test(flavor = "current_thread")]
    async fn a_queue_resync_while_typing_ends_the_paste() {
        let mut r = rig_with_queue(TYPIST_ROOM + 1);
        r.start();
        let _ = r.write();
        r.s.clipboard_available(true);
        r.chord();
        r.s.clipboard_text(utf16("abcdefghijklmnopqrstuvwxyz"));
        r.unchord();
        let resyncs = r.metrics.hid_resyncs.get();
        for _ in 0..=TYPIST_ROOM + 1 {
            if r.metrics.hid_resyncs.get() > resyncs {
                break;
            }
            r.s.mouse(MouseEvent::VerticalScroll { value: -120 });
        }
        assert_eq!(r.metrics.hid_resyncs.get(), resyncs + 1, "the wheel never filled the queue");
        assert_eq!(r.metrics.paste_events.get("aborted_resync"), 1);
        assert_eq!(r.metrics.release_all.get("paste_resync"), 1);
        assert_eq!(r.metrics.paste_events.get("done"), 0);
        r.s.feed(Event::Tick);
        let after = r.write();
        assert!(
            !after.iter().any(|f| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] != 0)),
            "typed after the resync: {after:?}"
        );
        assert!(r.holds_nothing());
    }
```

In `crates/kvm-rdp/src/hid/queue.rs`'s tests, after `newest_holds_follows_the_newest_state`:

```rust
    /// Plan E Task 1.5 (m4; pre-flight R1): while the Typist types, a push
    /// that finds the queue full drops the resync's state under the queue
    /// lock, as `discard_queued` does (Plan D I1): the writer — which the
    /// push wakes — has nothing to write, never the Typist's newest
    /// character, until the release's zeros. `push_at` keeps it (§7.3).
    #[test]
    fn a_resync_while_typing_leaves_nothing_to_write_before_the_release() {
        let c = ctl(4);
        let e = c.epoch();
        for k in 4..8 {
            assert_eq!(c.push_typing_at(e, kbd(k), false), Push::Queued);
        }
        assert_eq!(c.push_typing_at(e, kbd(8), false), Push::Resync);
        assert_eq!(c.next_frame(), None, "the resync's state is dropped under the lock");
        c.release_all(ReleaseTrigger::PasteResync);
        assert!(c.take_release());
        assert_eq!(c.release_frames(), [KBD_ZERO]);
        assert_eq!(c.next_frame(), None);
        // Not typing, a resync still sends the final state (§7.3).
        let d = ctl(4);
        let e = d.epoch();
        for k in 4..8 {
            assert_eq!(d.push_at(e, kbd(k), false), Push::Queued);
        }
        assert_eq!(d.push_at(e, kbd(8), false), Push::Resync);
        assert_eq!(d.next_frame(), Some(kbd(8)));
    }
```

In `crates/kvm-rdp/tests/l2/paste.rs` (add `Duration` to its `std::time` import):

```rust
/// Plan E Task 1.5 (Plan D final review m4, §8): a queue resync while the
/// Typist types ends the paste as `aborted_resync` and releases all, so an
/// overflow never drops characters from the middle of a paste. kvm-sim
/// stops reading with a small receive buffer, so the writer blocks and the
/// Typist fills its room (8 of the least queue, 9); a pointer move takes
/// the ninth slot and a wheel notch finds the queue full. What kvm-sim then
/// receives is a prefix of the text — never a text with a hole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queue_resync_while_typing_aborts_the_paste_with_no_hole() {
    // Long enough to outlast kvm-sim's 4 KiB receive buffer and the bridge's
    // 16 KiB send cap (about 18 bytes a report on the wire, two a character).
    let text = "abcdefghij".repeat(300);
    let mut sim = es3();
    sim.control_recv_buffer = Some(4096);
    let env = env(sim, |c| {
        sized(c);
        c.paste.pace = ms(0);
        c.paste.modifier_wait = ms(300);
        c.input.queue = 9;
        c.input.hid_write_timeout = Duration::from_secs(30);
    })
    .await;
    let c = env.client(Opts::new(2).clipboard(&text));
    ready(&c).await;
    let ws = env.hid_ready().await;
    let hid = env.bridge().hid().clone();
    env.sim.set_policy(|p| p.pause_ws_reads = true);
    paste_chord(&c, true);
    counted(&env, "started", 1).await;
    // Blocked: nothing written for 300 ms with the Typist at its room.
    let written = || env.metrics().hid_reports_sent.get();
    let t0 = Instant::now();
    loop {
        let w = written();
        if !until(ms(300), || written() != w).await && hid.queued() >= 8 {
            break;
        }
        assert!(t0.elapsed() < T, "the writer never blocked within {T:?}: {} written", written());
    }
    c.mouse_move(5, 5);
    c.wheel(-1);
    counted(&env, "aborted_resync", 1).await;
    assert_eq!(env.metrics().release_all.get("paste_resync"), 1);
    assert_eq!(pasted(&env, "done"), 0);
    env.sim.set_policy(|p| p.pause_ws_reads = false);
    // The keyboard reports kvm-sim received, less the release's zeros at
    // the end: the chord, then a prefix of the typed text.
    let mut kbd: Vec<Vec<u8>> = settled(until_mark(&env, &c, ws).await)
        .into_iter()
        .filter(|f| f.len() == 12 && f[2] == 0x08)
        .collect();
    while kbd.last() == Some(&KBD_ZERO.to_vec()) {
        kbd.pop();
    }
    let mut want = chord_frames(true);
    want.extend(typed(&text));
    assert!(kbd.len() > chord_frames(true).len(), "nothing was typed");
    assert!(kbd.len() < want.len(), "the whole text was typed: the resync never landed mid-paste");
    assert!(want.starts_with(&kbd), "a hole in the paste: {} reports typed, not a prefix of the text", kbd.len());
    assert_eq!(env.sim.stats().logouts, 0);
}
```

**Re-check after Plan D's residual fix lands** (the writer's re-assert becomes pong-gated and its backoff is skipped once until the session start; `plan-e` is cut after it): with kvm-sim's reads paused and `reassert_after` at 600 s (`sized`) the writer's pings go unanswered; the case must still see the abort if the pong-gated writer acts on a missing pong — run it again then (pre-flight X2).

- [ ] **Step 7: Run them to see them fail.** `cargo test --workspace --all-features --lib -- input::core::tests rdp::input::tests` — Expected: FAIL to compile (`Event::QueueResynced`, `InputCore::typing` not found). `cargo test --workspace --all-features --lib -- hid::queue::tests::a_resync_while_typing` — Expected: FAIL to compile (`push_typing_at` not found). `cargo test --workspace --all-features --test l2 -- paste::a_queue_resync` — Expected: FAIL (`paste_events{aborted_resync} never reached 1`: today the paste types on past the resync).

- [ ] **Step 8: The abort (m4).** In `core.rs`, `Event` gains, after `ClipboardAvailable(bool)`:

```rust
    /// The shell's word that a push it carried out found the HID queue full
    /// and resynced it (§7.3) — while the Typist types, typed reports were
    /// cleared (Plan E Task 1.5, m4).
    QueueResynced,
```

Every exhaustive `match` on `Event` gains its arm — the compiler lists them; `rg -n 'Event::Tick =>' crates/kvm-rdp/src` finds the three: `Debug` (`Event::QueueResynced => "QueueResynced",`), `handle` (`Event::QueueResynced => {}` — `paste_filter` never passes it on), and the tests' event formatter (`Event::QueueResynced => "QueueResynced".to_owned(),`). In `paste_filter`, before the `// Typing: every client press is swallowed` arm:

```rust
            // Plan E Task 1.5 (m4, §8): the queue resynced while typing —
            // the reports it cleared were typed characters, so typing on
            // would leave a hole. The paste ends as aborted, and everything
            // is released: the resync's state goes with the queue, so no
            // character after the hole is typed either. The outcome comes
            // first, so `release_marked` adds none of its own.
            Event::QueueResynced => {
                if typing {
                    self.paste = State::Idle;
                    out.push(Out::Paste(PasteOutcome::Aborted("resync")));
                    let _ = self.release_marked(out);
                    out.push(Out::Release(ReleaseTrigger::PasteResync));
                }
                None
            }
```

and `InputCore` gains, after `holds_input`:

```rust
    /// Whether a paste is typing (§8): a queue resync now would have
    /// cleared typed reports (Plan E Task 1.5, m4).
    #[must_use]
    pub fn typing(&self) -> bool {
        matches!(self.paste, State::Typing { .. })
    }
```

In `hid/queue.rs`, `push_at`'s body moves into a private `push_inner`, and `HidControl` gains `push_typing_at` beside it — the resync's state dropped under the queue lock, so no `resync` is left set for the writer:

```rust
    pub(crate) fn push_at(&self, stamp: u64, frame: HidFrame, motion_only: bool) -> Push {
        self.push_inner(stamp, frame, motion_only, false)
    }

    /// m4: a resync while the Typist types — the input core ends the paste
    /// and releases all, so the resync's state is dropped under the same
    /// queue lock, as `discard_queued` does (Plan D I1). The writer, woken
    /// below, finds nothing to write — never the Typist's newest character —
    /// until the release's zeros (Plan E Task 1.5).
    pub(crate) fn push_typing_at(&self, stamp: u64, frame: HidFrame, motion_only: bool) -> Push {
        self.push_inner(stamp, frame, motion_only, true)
    }

    fn push_inner(&self, stamp: u64, frame: HidFrame, motion_only: bool, typing: bool) -> Push {
        let r = {
            let mut q = self.q();
            if self.epoch() == stamp {
                let r = q.push(Report {
                    epoch: stamp,
                    frame,
                    motion_only,
                });
                if typing && r == Push::Resync {
                    q.clear();
                }
                r
            } else {
                Push::Discarded
            }
        };
        match r {
            Push::Coalesced => self.metrics.hid_reports_coalesced.inc(),
            Push::Resync => self.metrics.hid_resyncs.inc(),
            Push::Discarded => {
                // Nothing new to write: no wake-up.
                self.metrics.hid_epoch_discards.inc();
                return r;
            }
            Push::Queued => {}
        }
        self.notify.notify_one();
        r
    }
```

(`push_at`'s doc comment stays on `push_at`; below the `let r` block the body is today's.) In `rdp/input.rs`: the import becomes `use crate::hid::{HidControl, Push, ReleaseTrigger};`; `carry_out` takes whether the core is typing, pushes with `push_typing_at` then, and returns whether a push resynced the queue — once one has while typing, the step's later pushes (the Typist's next characters among them) are not made: the abort's release-all would discard them anyway, and queued meanwhile the writer could send them first:

```rust
    /// Carry out the core's `Out`s; whether a push found the queue full and
    /// resynced it (§7.3; Plan E Task 1.5, m4). `typing`: the core is
    /// typing a paste after this step — pushes then use `push_typing_at`,
    /// and after a resync no further report is pushed before the abort.
    fn carry_out(&self, generation: Gen, outs: Vec<Out>, typing: bool) -> bool {
        let mut resynced = false;
        for out in outs {
            match out {
                Out::Push {
                    frame,
                    motion_only,
                    stamp,
                } => {
                    if typing && resynced {
                        continue;
                    }
                    let push = if typing {
                        self.hid.push_typing_at(stamp, frame, motion_only)
                    } else {
                        self.hid.push_at(stamp, frame, motion_only)
                    };
                    resynced |= push == Push::Resync;
                }
                Out::Release(trigger) => self.hid.release_all(trigger),
                Out::Ignored => self.metrics.input_events_ignored.inc(), // DD7, DD9 (D8f)
                Out::RequestClipboard => self.request_clipboard(generation),
                Out::Paste(outcome) => self.count_paste(&outcome),
                Out::ClipboardDiscarded(why) => self.metrics.clipboard_discarded.inc(why),
            }
        }
        resynced
    }
```

`sync_generation`'s call becomes `self.carry_out(generation, outs, false);`, and `step`'s last line, `self.carry_out(generation, outs);`, becomes:

```rust
        // m4 (§8): a push that resynced the queue while the Typist types
        // cleared typed reports, and `push_typing_at` dropped the resync's
        // state. The core ends the paste — under the same core lock (I1),
        // before any other event can step it.
        let typing = core.typing();
        if self.carry_out(generation, outs, typing) && typing {
            let mut outs = Vec::new();
            core.step(&self.ctx(now, generation), Event::QueueResynced, &mut outs);
            self.carry_out(generation, outs, false);
        }
```

`abort_label` gains `"resync" => "aborted_resync",` after `"session"`; `metrics.rs`'s `PASTE_ABORTS` becomes `[&str; 9]` with `"aborted_resync"` last.

- [ ] **Step 9: Run every input test.** `cargo test --workspace --all-features --lib -- input:: rdp::input:: hid:: metrics::` — Expected: PASS, including the three new cases (`a_resync_while_typing_leaves_nothing_to_write_before_the_release` among them), the sixteen-case outcome table, the core's property test (it never steps `QueueResynced`: its outcome list is unchanged) and `a_paste_abort_is_counted_under_its_reason` (nine labels). `cargo test --workspace --all-features --test l2 -- paste:: input:: hid:: admin::` — Expected: PASS, including `a_queue_resync_while_typing_aborts_the_paste_with_no_hole`. Under Task 2.3's stressor, an L2 case that sees a `release_all{rdp_stale}` it did not cause is a finding for Task 6.1 (the bound is 3 s, three heartbeat periods: DE16).

- [ ] **Step 10: Gate and commit.** The per-task gate, with the image's feature-set clippy.

```bash
git add crates/kvm-rdp/src/hid/stale.rs crates/kvm-rdp/src/hid/mod.rs crates/kvm-rdp/src/hid/queue.rs \
  crates/kvm-rdp/src/admin.rs crates/kvm-rdp/src/bridge.rs crates/kvm-rdp/src/input/core.rs \
  crates/kvm-rdp/src/rdp/input.rs crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/tests/l2/admin.rs \
  crates/kvm-rdp/tests/l2/input.rs crates/kvm-rdp/tests/l2/paste.rs
git commit -m "kvm-rdp: a stalled RDP runtime's held input is released from the KVM runtime; a queue resync mid-paste aborts it (Plan E Task 1.5, Plan D final review m3 m4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Part 2 — CI's supply chain

Every action pinned and the pins checked (Task 2.1), the production graph audited (Task 2.2), the fuzz nightly's false positive fixed (Task 2.4, which sits and runs before 2.3), and a nightly that runs what a PR cannot afford (Task 2.3). Parts 3–5 add their jobs to these workflows.

### Task 2.1: the flake's CI tools, SHA-pinned actions, the workflow rules, the disk pass

The final review's Minor 7: CI's actions are pinned to tags or a branch, and pushes to main write the shared cache, so a compromised action could poison it. Pin every action to a commit SHA, write the rule down as a script CI runs against itself (design decision 6), take every non-Rust CI tool from the flake (design decision 5), and do the disk pass the Plan C ledger carried (`target/*/incremental` is stale since `incremental = false`).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/flake.nix` (`packages.x86_64-linux.{lint-tools,l3-tools,bench-tools}`; the devshell's tools)
- Create: `/home/chris/Repos/kvm-rdp/scripts/pin-action.sh`, `scripts/check-workflows.sh`, `scripts/test-check-workflows.sh`, `scripts/test-target-budget.sh`
- Modify: `/home/chris/Repos/kvm-rdp/scripts/target-budget.sh` (`--prune`)
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml`, `.github/workflows/fuzz-nightly.yml`
- Test: `scripts/test-check-workflows.sh`, `scripts/test-target-budget.sh`

**Interfaces:**
- Consumes: the flake's pinned `nixpkgs` (FreeRDP 3.32.1 built with OpenH264, checked at drafting with `nix eval --inputs-from . nixpkgs#freerdp.version`).
- Produces:
  - `nix build .#lint-tools` (cargo-deny, actionlint, shellcheck, yq-go), `.#l3-tools` (freerdp, xvfb-run), `.#bench-tools` (ffmpeg-headless, jq) — each a `buildEnv` whose `bin/` a CI job puts on `PATH`; the default devshell has all of them (with ffmpeg-full, for the committed fixtures).
  - `scripts/check-workflows.sh` — exit 0 iff its eleven rules hold (design decision 6); reads `WORKFLOWS_DIR` (default `.github/workflows`), `DOCKERFILE` (default `Dockerfile`, skipped while absent) and `IMAGE_BUILD` (default `scripts/image-build.sh`, skipped while absent). Tasks 2.3, 3.2, 4.1–4.2 and 5.5 must keep it green: every job with `timeout-minutes`, every checkout with `persist-credentials: false`, every rust-cache with a main-only `save-if`, and every write permission or `secrets.` only in a job whose `if:` is exactly `github.event_name == 'push' && github.ref == 'refs/heads/main'`.
  - `scripts/pin-action.sh OWNER/REPO` prints `OWNER/REPO@<sha> # <tag>`; `scripts/pin-action.sh --rewrite FILE…` replaces every `uses: OWNER/REPO@release` with that pin, or with the pin a workflow already has for OWNER/REPO, verbatim; `scripts/pin-action.sh --verify FILE…` checks each pin's tag comment against its SHA (the monthly pin review runs it). Workflow text in this plan writes `@release` for "pin me"; for an action a workflow already pins, `--rewrite` copies that `uses:` line's pin verbatim instead of resolving it again (rule 11: one SHA per action), so a later task's `--rewrite` re-resolves only the actions new to the workflows. Nothing with `@release` survives the rewrite or the check.
  - `scripts/target-budget.sh --prune` deletes stale `incremental/` directories, then gates as before.
  - The `lint` job in `ci.yml`. Task 2.2 adds `cargo deny` to it.

- [ ] **Step 1: Write the failing tests.** `scripts/test-check-workflows.sh`:

```bash
#!/usr/bin/env bash
# Tests for scripts/check-workflows.sh (Plan E Task 2.1): the real tree
# passes; each rule fails on a workflow, Dockerfile or build script that
# breaks it. Needs yq (the flake's lint-tools).
set -euo pipefail
cd "$(dirname "$0")/.."
check=scripts/check-workflows.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
expect() { # $1 = pass|fail, $2 = what, then env assignments for the check
  local want=$1 what=$2
  shift 2
  if env "$@" "$check" >"$work/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "test-check-workflows: $what: expected $want, got $got" >&2
    cat "$work/out" >&2
    fails=$((fails + 1))
  fi
}
good() { # a minimal workflow that keeps every rule
  cat <<'YAML'
name: t
# pull_request_target is refused (a comment is not a trigger)
on: { push: { branches: [main] }, pull_request: {} }
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v9.9.9
        with:
          persist-credentials: false
      - uses: Swatinem/rust-cache@0123456789abcdef0123456789abcdef01234567 # v9.9.9
        with:
          save-if: ${{ github.ref == 'refs/heads/main' }}
  publish:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: read
      packages: write
    steps:
      - run: true
YAML
}
case_dir() { mkdir -p "$work/$1"; good >"$work/$1/w.yml"; echo "$work/$1"; }
# The workflow-only cases: no Dockerfile, no build script.
wf() { expect "$1" "$2" WORKFLOWS_DIR="$3" DOCKERFILE=/nonexistent IMAGE_BUILD=/nonexistent; }

expect pass "the repository's own workflows" WORKFLOWS_DIR=.github/workflows
d=$(case_dir ok); wf pass "a workflow that keeps every rule" "$d"
d=$(case_dir tag); sed -i 's|@0123456789abcdef0123456789abcdef01234567 # v9.9.9|@v4|' "$d/w.yml"
wf fail "an action pinned to a tag" "$d"
d=$(case_dir nocomment); sed -i '0,/ # v9.9.9/s///' "$d/w.yml"
wf fail "a SHA with no tag comment" "$d"
d=$(case_dir prt); sed -i 's|pull_request: {}|pull_request_target: {}|' "$d/w.yml"
wf fail "pull_request_target" "$d"
d=$(case_dir wfrun); yq -i '.on.workflow_run = {"workflows": ["CI"]}' "$d/w.yml"
wf fail "workflow_run" "$d"
d=$(case_dir toplevel); sed -i '0,/contents: read/s//contents: write/' "$d/w.yml"
wf fail "a writable top-level token" "$d"
d=$(case_dir unguarded); yq -i 'del(.jobs.publish.if)' "$d/w.yml"
wf fail "a write permission without the push-to-main guard" "$d"
d=$(case_dir writeall); yq -i '.jobs.a.permissions = "write-all"' "$d/w.yml"
wf fail "permissions: write-all without the guard" "$d"
d=$(case_dir orguard); yq -i ".jobs.publish.if = \"github.event_name == 'push' && github.ref == 'refs/heads/main' || true\"" "$d/w.yml"
wf fail "a guard widened with ||" "$d"
d=$(case_dir braced)
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
yq -i '.jobs.publish.if = "${{ github.event_name == '"'push'"' && github.ref == '"'refs/heads/main'"' }}"' "$d/w.yml"
wf pass "the guard inside \${{ }}" "$d"
d=$(case_dir notimeout); yq -i 'del(.jobs.a."timeout-minutes")' "$d/w.yml"
wf fail "a job with no timeout-minutes" "$d"
d=$(case_dir nosaveif); yq -i 'del(.jobs.a.steps[1].with."save-if")' "$d/w.yml"
wf fail "a rust-cache with no save-if" "$d"
d=$(case_dir saveiftrue); yq -i '.jobs.a.steps[1].with."save-if" = true' "$d/w.yml"
wf fail "a rust-cache that saves on every ref" "$d"
d=$(case_dir prsecret)
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
yq -i '.jobs.a.env.T = "${{ secrets.X }}"' "$d/w.yml"
wf fail "a secret in a pull-request job" "$d"
d=$(case_dir mainsecret)
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
yq -i '.jobs.publish.env.T = "${{ secrets.X }}"' "$d/w.yml"
wf pass "a secret in the guarded job" "$d"
d=$(case_dir persist); yq -i 'del(.jobs.a.steps[0].with)' "$d/w.yml"
wf fail "a checkout that persists its token" "$d"
d=$(case_dir oneshatwofiles); good >"$d/w2.yml"
wf pass "two workflows, one SHA per action" "$d"
d=$(case_dir twoshas)
good | sed 's|actions/checkout@0123456789abcdef0123456789abcdef01234567|actions/checkout@89abcdef0123456789abcdef0123456789abcdef|' >"$d/w2.yml"
wf fail "one action pinned to two SHAs" "$d"
d=$(case_dir dockerfile)
printf 'FROM docker.io/library/debian:bookworm\n' >"$d/Dockerfile"
expect fail "an unpinned FROM" WORKFLOWS_DIR="$d" DOCKERFILE="$d/Dockerfile" IMAGE_BUILD=/nonexistent
# shellcheck disable=SC2016  # the Dockerfile's literal ${…}
printf 'ARG B=docker.io/library/rust:1.94.1-slim-bookworm\nFROM ${B} AS build\nFROM scratch\n' >"$d/Dockerfile"
expect fail "an unpinned image ARG" WORKFLOWS_DIR="$d" DOCKERFILE="$d/Dockerfile" IMAGE_BUILD=/nonexistent
# shellcheck disable=SC2016  # the Dockerfile's literal ${…}
printf 'ARG B=docker.io/library/rust:1.94.1-slim-bookworm@sha256:%s\nFROM ${B} AS build\nFROM build\n' "$(printf 'a%.0s' $(seq 64))" >"$d/Dockerfile"
expect pass "pinned ARGs, a stage reference" WORKFLOWS_DIR="$d" DOCKERFILE="$d/Dockerfile" IMAGE_BUILD=/nonexistent
printf 'BUILDKIT_IMAGE=moby/buildkit:v0.20.0\n' >"$d/build.sh"
expect fail "an unpinned BuildKit image" WORKFLOWS_DIR="$d" DOCKERFILE="$d/Dockerfile" IMAGE_BUILD="$d/build.sh"
[ "$fails" -eq 0 ] || { echo "test-check-workflows: $fails failed" >&2; exit 1; }
echo "test-check-workflows: all cases pass"
```

`scripts/test-target-budget.sh`:

```bash
#!/usr/bin/env bash
# Tests for scripts/target-budget.sh (Plan E Task 2.1, the disk pass).
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/t/debug/incremental/kvm_rdp-1" "$work/t/release/incremental/x" "$work/t/debug/deps"
head -c 1048576 /dev/zero >"$work/t/debug/incremental/kvm_rdp-1/blob"
head -c 4096 /dev/zero >"$work/t/debug/deps/keep"
CARGO_TARGET_DIR="$work/t" scripts/target-budget.sh --prune >"$work/out"
[ ! -e "$work/t/debug/incremental" ] && [ ! -e "$work/t/release/incremental" ] \
  || { echo "test-target-budget: an incremental dir survived --prune" >&2; exit 1; }
[ -e "$work/t/debug/deps/keep" ] || { echo "test-target-budget: --prune removed a non-incremental file" >&2; exit 1; }
grep -q "pruned" "$work/out" || { echo "test-target-budget: --prune said nothing" >&2; exit 1; }
if KVM_RDP_TARGET_BUDGET_GIB=abc CARGO_TARGET_DIR="$work/t" scripts/target-budget.sh 2>/dev/null; then
  echo "test-target-budget: a non-integer budget passed" >&2; exit 1
fi
CARGO_TARGET_DIR="$work/t" KVM_RDP_TARGET_BUDGET_GIB=1 scripts/target-budget.sh >/dev/null
echo "test-target-budget: all cases pass"
```

`chmod +x` both.

- [ ] **Step 2: Run them to see them fail.** `nix develop --command scripts/test-check-workflows.sh` — Expected: FAIL (`scripts/check-workflows.sh: No such file or directory`, or `yq: command not found` until Step 3). `nix develop --command scripts/test-target-budget.sh` — Expected: FAIL (`--prune` is not understood: the dirs survive).

- [ ] **Step 3: The flake's tools.** In `flake.nix`'s `let`, after `sharedTarget`:

```nix
      # CI's tools at flake.lock's versions (Plan E Task 2.1, DE13): a CI job
      # runs `nix build .#<name>` and puts result/bin on PATH. Rust stays
      # rustup's in CI (rust-toolchain.toml), the same 1.94.1 as below.
      ciTools = name: paths: pkgs.buildEnv {
        name = "kvm-rdp-${name}";
        inherit paths;
      };
```

and in `outputs`, beside `devShells`:

```nix
      packages.${system} = {
        lint-tools = ciTools "lint-tools" [ pkgs.cargo-deny pkgs.actionlint pkgs.shellcheck pkgs.yq-go ];
        # §11.4: FreeRDP 3 built with OpenH264 (nixpkgs 3.32.1), under Xvfb.
        l3-tools = ciTools "l3-tools" [ pkgs.freerdp pkgs.xvfb-run ];
        # §10.2's bench streams (scripts/gen-fixtures.sh bench).
        # ffmpeg-headless (305 MiB) has ffmpeg-full's libx264, freetype and
        # fontconfig at a fifth of its closure; the devshell keeps
        # ffmpeg-full for the committed fixtures.
        bench-tools = ciTools "bench-tools" [ pkgs.ffmpeg-headless pkgs.jq ];
      };
```

Add to the default devshell's `packages` (§4.2 lists FreeRDP 3 and Xvfb in the devshell): `pkgs.freerdp pkgs.xvfb-run pkgs.cargo-deny pkgs.actionlint pkgs.shellcheck pkgs.yq-go`. Then `nix build .#lint-tools .#l3-tools .#bench-tools --no-link` — Expected: builds from the binary cache; `nix develop --command xfreerdp /version` — Expected: `3.32.1`.

- [ ] **Step 4: `scripts/pin-action.sh`.**

```bash
#!/usr/bin/env bash
# Pin GitHub Actions to commit SHAs (Plan E Task 2.1; final review Minor 7).
#   scripts/pin-action.sh OWNER/REPO       print `OWNER/REPO@<sha> # <tag>`: the
#                                          newest non-draft, non-prerelease
#                                          release published at least 14 days ago
#   scripts/pin-action.sh --rewrite FILE…  replace every `uses: OWNER/REPO@release`
#                                          in FILE with that pin — or, when a
#                                          workflow already pins OWNER/REPO, with
#                                          that pin, verbatim
#   scripts/pin-action.sh --verify FILE…   check every `uses: X@<sha> # <tag>`:
#                                          the tag's commit is that SHA
# Bump pins, and run --verify, with the monthly IronRDP pin review (spec §4.2).
# An action already pinned in a workflow (WORKFLOWS_DIR, default
# .github/workflows) is copied verbatim into the next one, never re-resolved:
# one action, one SHA (check-workflows.sh rule 11). Needs gh and jq.
set -euo pipefail
min_age_days=14
resolve() {
  local action=$1 repo cutoff tag sha
  repo=$(cut -d/ -f1-2 <<<"$action")
  cutoff=$(date -u -d "-${min_age_days} days" +%Y-%m-%dT%H:%M:%SZ)
  tag=$(gh api --paginate "repos/$repo/releases?per_page=100" \
    --jq ".[] | select(.draft | not) | select(.prerelease | not)
          | select(.published_at <= \"$cutoff\") | .tag_name" | sort -V | tail -n 1)
  if [ -z "$tag" ]; then
    echo "pin-action: $repo has no release at least $min_age_days days old" >&2
    return 1
  fi
  sha=$(gh api "repos/$repo/commits/$tag" --jq .sha)
  printf '%s@%s # %s\n' "$action" "$sha" "$tag"
}
existing() { # $1 = OWNER/REPO: its pin in a workflow already, if any
  { grep -hoE "uses: $1@[0-9a-f]{40} # [^[:space:]]+" "${WORKFLOWS_DIR:-.github/workflows}"/*.yml || true; } |
    sed 's/^uses: //' | sort -u | sed -n 1p
}
verify() {
  local f=$1 bad=0 action sha tag repo want
  while read -r action sha tag; do
    repo=$(cut -d/ -f1-2 <<<"$action")
    want=$(gh api "repos/$repo/commits/$tag" --jq .sha)
    if [ "$want" != "$sha" ]; then
      echo "pin-action: $f: $action@$sha says $tag, whose commit is $want" >&2
      bad=1
    else
      echo "pin-action: $f: $action $tag = $sha"
    fi
  done < <({ grep -oE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40} # [^[:space:]]+' "$f" || true; } |
    sed -E 's/^uses: //; s/@/ /; s/ # / /' | sort -u)
  return "$bad"
}
case "${1:-}" in
  --rewrite)
    shift
    for f in "$@"; do
      { grep -oE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@release' "$f" || true; } |
        sed 's/^uses: //; s/@release$//' | sort -u |
        while IFS= read -r action; do
          pin=$(existing "$action")
          [ -n "$pin" ] || pin=$(resolve "$action")
          sed -i "s|uses: ${action}@release|uses: ${pin}|" "$f"
          echo "pin-action: $f: $pin"
        done
    done
    ;;
  --verify)
    shift
    status=0
    for f in "$@"; do verify "$f" || status=1; done
    exit "$status"
    ;;
  *)
    resolve "${1:?usage: pin-action.sh OWNER/REPO | --rewrite FILE... | --verify FILE...}"
    ;;
esac
```

- [ ] **Step 5: `scripts/check-workflows.sh`.**

```bash
#!/usr/bin/env bash
# The rules CI's workflows keep (Plan E Task 2.1; spec §12's carries). CI
# runs this against itself in the `lint` job; scripts/test-check-workflows.sh
# is its test. Every yq or grep reads a variable, never a pipe a `grep -q`
# could cut short: under pipefail a SIGPIPE'd writer would make a match
# read as no match.
#  1. Every `uses:` names its action by a full commit SHA, its tag in a comment.
#  2. No workflow runs on pull_request_target or workflow_run (a fork's code
#     with a write token).
#  3. Each workflow's top-level permissions are exactly `contents: read`.
#  4. A job that asks for any write permission (`write`, `write-all`) runs
#     only on a push to main: its `if:` is exactly GUARD below.
#  5. Every image the Dockerfile names is pinned by digest (stages excepted).
#  6. The BuildKit image scripts/image-build.sh uses is pinned by digest.
#  7. Every job has `timeout-minutes`.
#  8. Every Swatinem/rust-cache step saves only on main: its `save-if` is
#     `${{ github.ref == 'refs/heads/main' }}` or `false`.
#  9. `secrets.` appears only in a job that keeps rule 4's guard.
# 10. Every actions/checkout step sets `persist-credentials: false`.
# (yq's `//` treats `false` as absent, so rules 8 and 10 read the bare value:
# an absent key prints `null`.)
# 11. One action, one SHA, across every workflow.
set -euo pipefail
wf=${WORKFLOWS_DIR:-.github/workflows}
dockerfile=${DOCKERFILE:-Dockerfile}
image_build=${IMAGE_BUILD:-scripts/image-build.sh}
fail=0
err() { echo "check-workflows: $*" >&2; fail=1; }
digest='@sha256:[0-9a-f]{64}'
guard="github.event_name == 'push' && github.ref == 'refs/heads/main'"
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
main_only='${{ github.ref == '"'refs/heads/main'"' }}'
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
# Whether job $2 of workflow $1 runs only on a push to main (rule 4's guard,
# with any `${{ }}` around it stripped).
guarded() {
  local c
  c=$(yq ".jobs.\"$2\".if // \"\"" "$1")
  c=$(trim "$c")
  c=${c#\$\{\{}
  c=${c%\}\}}
  [ "$(trim "$c")" = "$guard" ]
}
pins=
shopt -s nullglob
for f in "$wf"/*.yml "$wf"/*.yaml; do
  while IFS= read -r line; do
    ref=$(sed -E 's/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]].*$//' <<<"$line")
    case $ref in ./*) continue ;; esac
    if ! grep -qE '^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$' <<<"$ref" ||
      ! grep -qE '#[[:space:]]*[vV]?[0-9]' <<<"$line"; then
      err "$f: not a commit SHA with its tag in a comment: $(printf '%s' "${line#"${line%%[![:space:]]*}"}")"
    else
      pins+="$ref"$'\n'
    fi
  done < <(grep -E '^[[:space:]-]*uses:' "$f" || true)
  on=$(yq -o=json -I=0 '.on' "$f")
  if grep -qE '"(pull_request_target|workflow_run)"' <<<"$on"; then
    err "$f: pull_request_target and workflow_run are not allowed"
  fi
  top=$(yq -o=json -I=0 '.permissions' "$f")
  [ "$top" = '{"contents":"read"}' ] || err "$f: top-level permissions must be exactly contents: read (got $top)"
  outside=$(yq -o=json -I=0 'del(.jobs)' "$f")
  if grep -qF 'secrets.' <<<"$outside"; then
    err "$f: secrets. outside a job (every job would read it)"
  fi
  for job in $(yq '.jobs | keys | .[]' "$f"); do
    perms=$(yq -o=json -I=0 ".jobs.\"$job\".permissions // {}" "$f")
    if grep -qE '"write(-all)?"' <<<"$perms" && ! guarded "$f" "$job"; then
      err "$f: job $job asks for write permissions but its if: is not exactly: $guard"
    fi
    timeout=$(yq ".jobs.\"$job\".\"timeout-minutes\" // \"\"" "$f")
    [ -n "$timeout" ] || err "$f: job $job has no timeout-minutes"
    body=$(yq -o=json -I=0 ".jobs.\"$job\"" "$f")
    if grep -qF 'secrets.' <<<"$body" && ! guarded "$f" "$job"; then
      err "$f: job $job reads a secret but does not run only on a push to main"
    fi
    while IFS= read -r v; do
      [ "$v" = "$main_only" ] || [ "$v" = false ] ||
        err "$f: job $job: a rust-cache step must save only on main (save-if: $v)"
    done < <(yq ".jobs.\"$job\".steps[]? | select((.uses // \"\") | test(\"^Swatinem/rust-cache@\")) | .with.\"save-if\"" "$f")
    while IFS= read -r v; do
      [ "$v" = false ] || err "$f: job $job: a checkout must set persist-credentials: false (got $v)"
    done < <(yq ".jobs.\"$job\".steps[]? | select((.uses // \"\") | test(\"^actions/checkout@\")) | .with.\"persist-credentials\"" "$f")
  done
done
twice=$(printf '%s' "$pins" | LC_ALL=C sort -u | cut -d@ -f1 | uniq -d)
[ -z "$twice" ] || err "one action pinned to two SHAs: $(tr '\n' ' ' <<<"$twice")"
if [ -f "$dockerfile" ]; then
  stages=$(grep -oiE '^FROM[[:space:]]+[^[:space:]]+[[:space:]]+AS[[:space:]]+[^[:space:]]+' "$dockerfile" | awk '{print $NF}' || true)
  while IFS= read -r line; do
    img=$(awk '{print $2}' <<<"$line")
    # shellcheck disable=SC2016  # the Dockerfile's literal ${…}
    case $img in '${'*|scratch) continue ;; esac
    grep -qxF "$img" <<<"$stages" && continue
    grep -qE "$digest" <<<"$img" || err "$dockerfile: FROM not pinned by digest: $line"
  done < <(grep -iE '^FROM[[:space:]]' "$dockerfile")
  while IFS= read -r line; do
    val=${line#*=}
    if grep -qE '^[a-z0-9.-]+(\.[a-z]+)?/[^[:space:]]+:' <<<"$val" && ! grep -qE "$digest" <<<"$val"; then
      err "$dockerfile: image ARG not pinned by digest: $line"
    fi
  done < <(grep -E '^ARG[[:space:]]+[A-Za-z_]+=' "$dockerfile")
fi
if [ -f "$image_build" ]; then
  while IFS= read -r line; do
    grep -qE "$digest" <<<"$line" || err "$image_build: BuildKit image not pinned by digest: $line"
  done < <(grep -E '^[[:space:]]*BUILDKIT_IMAGE=' "$image_build")
fi
[ "$fail" -eq 0 ] && echo "check-workflows: every rule holds"
exit "$fail"
```

- [ ] **Step 6: The disk pass.** In `scripts/target-budget.sh`, after `dir=…` and its existence check:

```bash
# The disk pass (Plan E Task 2.1; Plan C ledger, minor 4): `[build]
# incremental = false` since Plan C leaves every `incremental/` directory
# stale, so deleting them is always safe.
if [ "${1:-}" = "--prune" ]; then
  pruned_kib=0
  for inc in "$dir"/*/incremental "$dir"/*/*/incremental; do
    [ -d "$inc" ] || continue
    kib=$(du -sk "$inc" | cut -f1)
    rm -rf -- "$inc"
    pruned_kib=$((pruned_kib + kib))
    echo "target-budget: pruned $inc (${kib} KiB)"
  done
  echo "target-budget: pruned $(awk -v k="$pruned_kib" 'BEGIN { printf "%.2f", k / 1048576 }') GiB of stale incremental caches"
fi
```

and in the over-budget message, before the `cargo clean` line: `echo "target-budget: run 'scripts/target-budget.sh --prune' first; if still over," >&2`. (The budget-validity `case` already precedes `dir=`, so a bad budget fails before anything is deleted.)

- [ ] **Step 7: The workflows.** Replace `.github/workflows/ci.yml` with:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

# Read-only for every job but `publish` (Plan E Task 4.2), which asks for its
# own permissions and runs only on a push to main; no job reads a secret on a
# pull request, so a fork's PR runs every gate safely. Every action is pinned
# to a commit SHA with its tag beside it (scripts/check-workflows.sh; bump
# with scripts/pin-action.sh). Rust comes from rustup on the runner image,
# reading rust-toolchain.toml; every other tool from the flake (DE13).
permissions:
  contents: read

# A newer push to the same PR supersedes the run in flight: IronRDP's graph
# is too heavy to build twice for nothing (§13). Runs on main always finish.
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: "0"
  # ubuntu-24.04 has 4 vCPUs; .cargo/config.toml's RUST_TEST_THREADS = 4
  # matches it, and L2's one-sided timing asserts are sized for that.
  CARGO_BUILD_JOBS: "4"

jobs:
  check:
    runs-on: ubuntu-24.04
    # IronRDP's graph plus L2 (§13): a hung L2 case must not hold a runner.
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@release
        with:
          # No job pushes git: the token is not left on disk while the
          # repository's own code runs (check-workflows.sh rule 10).
          persist-credentials: false
      - name: Rust from rust-toolchain.toml (1.94.1 with clippy and rustfmt)
        run: rustup toolchain install && cargo --version
      - uses: Swatinem/rust-cache@release
        with:
          # One dependency cache, written by main only: pull requests
          # restore it and never save their own (the nightly reads it too).
          shared-key: check
          save-if: ${{ github.ref == 'refs/heads/main' }}
```

followed by every step of today's `check` job from `- name: Format` to `- name: Target budget (spec §13, DC10)`, verbatim, with one step inserted right after `- name: Clippy`:

```yaml
      - name: Clippy — the image's feature set
        # The build that ships has neither test-hooks nor alloc-stats: an
        # item gated on them must leave no unused import behind (Docker
        # does not deny warnings).
        run: cargo clippy -p kvm-rdp --lib --bins -- -D warnings
```

then:

```yaml
  fuzz:
    # Bounded fuzzing of kvm-proto (spec §11.2, §13 — CI only): every target
    # for 5 s, RSS-capped by scripts/fuzz.sh. Longer runs are the nightly's.
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: Rust (stable from rust-toolchain.toml; the fuzz nightly)
        run: |
          rustup toolchain install
          rustup toolchain install nightly-2026-10-01 --profile minimal
      - uses: Swatinem/rust-cache@release
        with:
          shared-key: fuzz
          save-if: ${{ github.ref == 'refs/heads/main' }}
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
        uses: actions/upload-artifact@release
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts

  lint:
    # Plan E Task 2.1: the workflows' own rules (check-workflows.sh), the
    # scripts, the disk pass; Task 2.2 adds cargo deny.
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - uses: cachix/install-nix-action@release
        with:
          extra_nix_config: "experimental-features = nix-command flakes"
      - name: The flake's lint tools (cargo-deny, actionlint, shellcheck, yq)
        run: |
          nix build .#lint-tools --out-link "$RUNNER_TEMP/lint-tools"
          echo "$RUNNER_TEMP/lint-tools/bin" >> "$GITHUB_PATH"
      - name: Workflow and image-pin rules
        run: scripts/test-check-workflows.sh && scripts/check-workflows.sh
      - name: actionlint
        run: actionlint
      - name: shellcheck
        run: shellcheck scripts/*.sh
      - name: The target-budget script (the disk pass)
        run: scripts/test-target-budget.sh
```

In `.github/workflows/fuzz-nightly.yml`: `runs-on: ubuntu-24.04`; replace both `dtolnay/rust-toolchain@master` steps with one `run:` step (`rustup toolchain install && rustup toolchain install nightly-2026-10-01 --profile minimal`); `actions/checkout@release` with `with: { persist-credentials: false }`, `Swatinem/rust-cache@release` (with `shared-key: fuzz` and `save-if: false` — the nightly reads main's cache, never writes it), `actions/upload-artifact@release`; keep its `timeout-minutes: 75`; and rewrite the comment above `permissions:` to say the actions are SHA-pinned (the `dtolnay` sentence goes).

Then pin: `nix develop --command scripts/pin-action.sh --rewrite .github/workflows/ci.yml .github/workflows/fuzz-nightly.yml` — Expected: one `pin-action:` line per distinct action in each file — fuzz-nightly's three repeat ci.yml's pins verbatim (rule 11) — and `grep -n '@release' .github/workflows/*.yml` prints nothing. Both files are rewritten in one run, so an action used in both resolves once (rule 11); `nix develop --command scripts/pin-action.sh --verify .github/workflows/*.yml` — Expected: every pin's tag is its SHA. If the runner's rustup predates `rustup toolchain install` reading `rust-toolchain.toml` (rustup 1.28), CI's first run will say so; the fix is `rustup show` in that step — note it for the CI check.

- [ ] **Step 8: Run the tests and the linters.** `nix develop --command scripts/test-target-budget.sh` — Expected: `all cases pass`. `nix develop --command scripts/test-check-workflows.sh` — Expected: `all cases pass` (its first case is the real tree). `nix develop --command actionlint` — Expected: clean. `nix develop --command shellcheck scripts/*.sh` — Expected: clean (shellcheck 0.11.0; the new scripts' deliberate literals carry their one-line `# shellcheck disable=SC2016  # …` directives); fix any finding in a pre-existing script at its cause (quoting, `read -r`), or, where the construct is deliberate (`printf` with a variable format, say), add a one-line `# shellcheck disable=SCnnnn  # why` above it. `nix develop --command scripts/target-budget.sh --prune` — Expected: prunes whatever stale `incremental/` the shared target holds, then passes the budget; record "pruned N GiB (0 is expected: Plan C's stale caches are already gone)" in the commit body.

- [ ] **Step 9: Gate and commit.** The per-task gate. Then:

```bash
git add flake.nix flake.lock scripts/pin-action.sh scripts/check-workflows.sh scripts/test-check-workflows.sh \
  scripts/target-budget.sh scripts/test-target-budget.sh .github/workflows/ci.yml .github/workflows/fuzz-nightly.yml
git commit -m "ci: every action pinned by SHA and checked; CI tools from the flake; the lint job; target-budget --prune (Plan E Task 2.1, final review Minor 7)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(`flake.lock` changes only if `nix build` had to lock something new; it should not — no input is added.) **CI check** (owner's first push): `check`, `fuzz` and `lint` green on the PR. **Owner item** (after this task is on main): set the repository's Actions setting "Require actions to be pinned to a full-length commit SHA", and optionally restrict `allowed_actions` to the seven the workflows use (today `allowed_actions: "all"`, `sha_pinning_required: false`); Task 6.1 records whether it was set.

### Task 2.2: cargo-deny — licences, advisories, bans and sources over the production graph

Plan C's final review: "licence and advisory auditing (cargo-deny): Plan E", over the production graph — what the image ships, `kvm-rdp` and `kvm-probe` with their normal and build dependencies (345 crates (cargo-deny, `7bdcf15`), most through `ironrdp-server`'s own graph; audited, not trimmed). Bans encode §4.2's rules as a second line behind the existing CI gates. At `7bdcf15` the advisories class fails on five (measured with cargo-deny 0.20.2): RUSTSEC-2026-0346..0349 in `rustls 0.23.45` — the bridge's TLS for both RDP and the KVM — fixed in 0.23.46 (2026-10-14), and RUSTSEC-2023-0071 in `rsa 0.10.0-rc.18`, which has no fix. This task bumps rustls, drafts the `rsa` ignore with its reachability reading for the owner's sign-off, and makes advisories block on main only (DE15): the database moves daily, so as a PR gate it would redden PRs that changed nothing.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/deny.toml`
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.lock` (`rustls` 0.23.45 → 0.23.46)
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (`lint` job)
- Test: `cargo deny check` itself, plus the injected-violation check in Step 3

**Interfaces:**
- Consumes: Task 2.1's `lint` job and `lint-tools` (cargo-deny at flake.lock's version).
- Produces: `deny.toml` (its one `ignore`, RUSTSEC-2023-0071, marked **PENDING OWNER SIGN-OFF**); `cargo deny --locked check bans licenses sources` blocking in the `lint` job, `cargo deny --locked check advisories` blocking on main and `continue-on-error` on pull requests. Task 2.3's nightly adds a read-only `deny-advisories` job that reports the advisories every night.

- [ ] **Step 1: Write `deny.toml`.**

```toml
# cargo-deny over the production graph (spec §4.2; Plan E Task 2.2): what the
# image ships — kvm-rdp and kvm-probe, with their normal and build
# dependencies — on the one target the image runs on.
[graph]
targets = ["x86_64-unknown-linux-gnu"]
exclude-dev = true
# Test and benchmark tools: never in the image.
exclude = ["kvm-sim", "kvm-bench"]

[advisories]
version = 2
yanked = "deny"
# Each ignore names the advisory, the dependency path that brings it in, and
# why it is unreachable here — and needs the owner's sign-off (Task 2.2).
# Step 2 fills this in; it starts empty so the first run shows every finding.
ignore = []

[licenses]
version = 2
# The licences the production graph needs and nothing more: every crate
# offers at least one of these (the other OR alternatives need not be
# listed), and aws-lc-sys needs ISC and BSD-3-Clause as well. Unicode-3.0 is
# ICU's permissive licence (the icu_* and zerovec crates). Measured at
# drafting from `cargo metadata`; Step 2 is the check.
allow = ["Apache-2.0", "BSD-3-Clause", "ISC", "MIT", "Unicode-3.0"]
confidence-threshold = 0.93

[licenses.private]
# The workspace's own crates are MIT OR Apache-2.0 and unpublished.
ignore = true

[bans]
# Duplicate versions come with IronRDP's graph and are not ours to trim
# (Plan C final review); duplicate ironrdp-* crates have their own CI gate.
multiple-versions = "allow"
wildcards = "deny"
allow-wildcard-paths = true
deny = [
    { crate = "ring", reason = "spec §4.2: aws-lc-rs is the one crypto provider" },
    { crate = "ironrdp", reason = "spec §4.2: never the ironrdp meta-crate" },
    { crate = "openssl-sys", reason = "spec §4.2: rustls on aws-lc-rs only" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
# The IronRDP fork the workspace git-pins (§4.2), and nothing else.
allow-git = ["https://github.com/ChristopherJMiller/IronRDP"]
```

- [ ] **Step 2: Run it.** `nix develop --command cargo deny --locked check` — Expected: `bans ok, licenses ok, sources ok`, and advisories FAIL on exactly five: RUSTSEC-2023-0071 (`rsa 0.10.0-rc.18`), and RUSTSEC-2026-0346, -0347, -0348 and -0349 (`rustls 0.23.45`, fixed in 0.23.46). Then:

1. `nix develop --command cargo update -p rustls --precise 0.23.46` — Expected: `Updating rustls v0.23.45 -> v0.23.46`, and nothing else moves (if anything else does, list it in the commit body). The full per-task gate covers the bump: L2 runs both TLS roles (the RDP listener and the KVM client).
2. `rsa` has no fixed release. Re-read the reachability below against the code (the paths are at the pinned IronRDP rev `c99eece2`, in `~/.cargo/git/checkouts/ironrdp-*/c99eece`, and sspi 0.21.3 / picky 7.0.0-rc.25 in `~/.cargo/registry/src/`), and replace `ignore = []` and its last comment line with the entry — changing the reading only where the code says otherwise, and saying so in the commit body:

```toml
# RUSTSEC-2023-0071 — PENDING OWNER SIGN-OFF (before the first push; Plan E
# owner items). rsa: the Marvin attack — rsa's private-key operations are
# not constant-time (PKCS#1 v1.5 decryption padding; no default blinding,
# which signing shares); no fixed release exists.
# Where it is: rsa 0.10.0-rc.18, reached only through IronRDP — picky
#   7.0.0-rc.25 (via ironrdp-connector, which ironrdp-acceptor and
#   ironrdp-server use), sspi 0.21.3 and winscard 0.3.3 (`cargo tree -i rsa
#   -e normal --target x86_64-unknown-linux-gnu -p kvm-rdp -p kvm-probe`:
#   kvm-rdp is the only root).
# Whether the bridge runs the vulnerable operation: no. Its NLA is
#   ironrdp-server's `accept_credssp(…, None)` — no Kerberos config
#   (ironrdp-server server.rs:1342–1349 at c99eece2) — so sspi's
#   CredSspServer runs `ServerMode::Ntlm` (ironrdp-acceptor credssp.rs:
#   113–121), and NTLM performs no RSA operation. The TLS private key is
#   loaded and used by rustls on aws-lc-rs, and its public key (CredSSP's
#   pubKeyAuth binding) is read with x509-parser (kvm-rdp rdp/tls.rs); no
#   bridge code and no server path of IronRDP at that rev hands an RSA
#   private key to rsa or picky. The rsa private-key code in the graph is
#   winscard's emulated smart card (signing: scard.rs:432–454), picky's
#   signer as sspi's PKINIT and PKU2U use it, and picky's JWE RSA
#   decryption (jose/jwe.rs), which nothing in the graph calls. It is
#   compiled in (sspi's `scard`, picky's `jose`) and never on the bridge's
#   server path: IronRDP's acceptor builds only ServerMode::Ntlm or
#   ::Negotiate, never ::Pku2u, and NTLM refuses smart-card credentials.
# Mitigation: none needed — at c99eece2 ironrdp-server has no Kerberos (or
#   PKU2U) option at all (accept_credssp(…, None) is a literal), and kvm-rdp
#   calls only with_hybrid. Re-read at every IronRDP pin bump (Task 6.1's
#   pin-review checklist), and drop this entry when rsa ships a fixed
#   release.
ignore = [
    { id = "RUSTSEC-2023-0071", reason = "rsa (Marvin) via IronRDP's picky/sspi/winscard: the bridge's NTLM-only CredSSP and its rustls/aws-lc TLS key perform no rsa private-key operation — PENDING OWNER SIGN-OFF" },
]
```

3. `nix develop --command cargo deny --locked check` — Expected: `advisories ok, bans ok, licenses ok, sources ok`.

By class, for anything else Step 2 reports:
  - **licenses**: a licence outside `allow` is a finding — if it is permissive (MIT-0, BSD-2-Clause, Zlib, 0BSD, BSL-1.0, CC0-1.0, Unicode-DFS-2016) and it is the crate's only option, add it with a comment naming the crate; anything copyleft (GPL, LGPL, AGPL, MPL, EPL, CDDL) or unknown: stop and report — the image's licence is MIT OR Apache-2.0. A `license-not-encountered` warning for one of the five means the measurement was wrong: drop it.
  - **advisories** (beyond the five above, if the database has moved): for each one, run `cargo tree -i <crate> -e normal --target x86_64-unknown-linux-gnu` and try `cargo update -p <crate>` within semver (never an `ironrdp-*` crate: §4.2's pin). If a fixed version resolves, keep the `Cargo.lock` change and rerun the gate. If none does, **stop and report** it with its ID, the dependency path, whether the bridge can reach the vulnerable code (read where the crate is called and say what the code shows, not what is likely), and a proposed `ignore` entry in RUSTSEC-2023-0071's shape. Every `ignore` is marked PENDING OWNER SIGN-OFF in `deny.toml` and in the task report, and joins the owner items.
  - **bans**: `ring` reported as present contradicts CI's `cargo tree -i ring` gate. That gate is the authority (it reads the activated graph); if cargo-deny flags `ring` only as an inactive optional dependency of `rustls-webpki`, drop the `ring` ban here with a comment pointing to the CI gate, and record it in the commit body.
  - **sources**: if cargo-deny spells the fork's URL differently (`.git` suffix), match its spelling.

- [ ] **Step 3: Prove it fails when it should.** Temporarily add `ring = "0.17"` under `[dependencies]` in `crates/kvm-probe/Cargo.toml` and run `nix develop --command cargo deny --offline check bans` (`--offline`, not `--locked`: the new edge changes the lockfile, which `--locked` refuses inside `cargo metadata` before any ban is read; ring 0.17.14 is already in the local registry) — Expected: FAIL with `error[banned]: crate 'ring = 0.17.14'` (unless Step 2 dropped the ban — then use `openssl-sys = "0.9"` and expect it named). Revert with `git checkout crates/kvm-probe/Cargo.toml Cargo.lock`.

- [ ] **Step 4: CI.** In `ci.yml`'s `lint` job, after the shellcheck step:

```yaml
      - name: Rust for cargo deny (cargo metadata; rust-toolchain.toml)
        run: rustup toolchain install
      - name: cargo deny — licences, bans, sources (the production graph)
        run: cargo deny --locked check bans licenses sources
      - name: cargo deny — advisories (blocking on main; reported on PRs, DE15)
        # The advisory database moves daily: on a PR a new advisory is
        # reported, not a red gate on a change that did not cause it. On
        # main it blocks, so `publish` (which needs `lint`) never ships a
        # known-vulnerable image. The nightly's deny-advisories job reports
        # it every night (Task 2.3).
        continue-on-error: ${{ github.event_name == 'pull_request' }}
        run: cargo deny --locked check advisories
```

`nix develop --command scripts/check-workflows.sh && nix develop --command actionlint` — Expected: clean.

- [ ] **Step 5: Gate and commit.** The per-task gate. Then:

```bash
git add deny.toml .github/workflows/ci.yml Cargo.lock
git commit -m "ci: cargo deny over the production graph — licences, bans, sources blocking, advisories blocking on main; rustls 0.23.46 (Plan E Task 2.2)" \
  -m "rustls 0.23.45 -> 0.23.46 (cargo update -p rustls --precise 0.23.46): RUSTSEC-2026-0346..0349. RUSTSEC-2023-0071 (rsa) ignored PENDING OWNER SIGN-OFF, reachability in deny.toml. The production graph: 345 crates; release-candidate crypto in it, all via IronRDP's sspi/picky: rsa 0.10.0-rc.18, picky 7.0.0-rc.25, curve25519-dalek 5.0.0-rc.1, ed25519-dalek 3.0.0-rc.1." \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(List any further `cargo update -p` in the body, and correct the crate count and the release-candidate list if Step 2's run says otherwise.) The task report states: "RUSTSEC-2023-0071 ignore — PENDING OWNER SIGN-OFF". **CI check**: the `lint` job's three deny steps green on main (the advisories step may report on a PR without failing it).

### Task 2.4: the fuzz nightly's `sps_rewrite` oracle reads a level raise by rank (runs before Task 2.3)

Main's fuzz nightly has been red 7 nights of 8 (2026-10-08 to 10-15): every failing run stops in `sps_rewrite` at `fuzzing.rs:271`, constraint_flags 75 against an expected 91 at `level_idc` 11, `profile_idc` 66. It is Plan B PB12's recorded limitation, a false positive of the oracle, not of the rewriter: `level_raised = out.level_idc != input.level_idc` misses a raise from level 1b to 1.1, whose number stays 11 while the rewriter correctly clears `constraint_set3_flag`. The PR job's 5-second fuzz can hit the same input, `publish` needs `fuzz`, and Task 2.3 would add a second nightly beside one nobody can read. Compare levels by rank — the rewriter's own `level_rank`, which places 1b between 1 and 1.1 — and seed the fuzzer with the case. Fuzzing itself stays in CI (§13); locally only the seeds run. This task sits, and runs, between Tasks 2.2 and 2.3.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/rewrite.rs` (`level_rank`, `is_level_1b` become `pub(crate)`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/fuzzing.rs` (`sps_rewrite`'s `level_raised`; `level_1b_needing_1_1`; the seed; its test)
- Test: `crates/kvm-proto/src/fuzzing.rs` (`tests`)

**Interfaces:**
- Consumes: `h264::rewrite::{level_rank, is_level_1b, rewrite_sps, RewriteConfig::ES3}`, `bits::{BitWriter, escape_rbsp_into}`, `fuzzing::{sps_rewrite, seeds}`.
- Produces: `pub(crate) fn h264::rewrite::level_rank(profile_idc: u8, level_idc: u8, constraint_flags: u8) -> Option<u16>` and `pub(crate) fn h264::rewrite::is_level_1b(…) -> bool` (unchanged bodies); `fn fuzzing::level_1b_needing_1_1() -> Vec<u8>`; the `sps_rewrite` seed `level_1b_needs_1_1`.

- [ ] **Step 1: Write the failing test.** In `crates/kvm-proto/src/fuzzing.rs`'s `tests`, after `every_target_runs_clean_over_its_seeds`:

```rust
    /// Plan E Task 2.4 (pre-flight E7; Plan B PB12's recorded limitation):
    /// a Baseline level-1b SPS (level_idc 11 with constraint_set3_flag) at
    /// a size that needs 1.1 is raised with cs3 cleared while level_idc's
    /// number stays 11. The oracle must read that as a raise — by rank —
    /// and pass; read by number it saw no raise, expected cs3 kept, and
    /// failed (the fuzz nightly's constraint_flags 75 vs 91 at level_idc 11,
    /// profile 66). The case is also a seed, so the fuzzer starts from it.
    #[test]
    fn the_oracle_reads_a_level_1b_to_1_1_raise_by_rank() {
        let sps = level_1b_needing_1_1();
        let r = rewrite_sps(&sps, &RewriteConfig::ES3).unwrap();
        assert_eq!(
            (r.syntax.level_idc, r.syntax.constraint_flags & 0x10),
            (11, 0),
            "1b -> 1.1: level_idc's number unchanged, cs3 cleared"
        );
        sps_rewrite(&sps);
        assert!(
            seeds()
                .iter()
                .any(|(t, n, s)| *t == "sps_rewrite" && n == "level_1b_needs_1_1" && *s == sps),
            "the case is an sps_rewrite seed"
        );
    }
```

- [ ] **Step 2: Run it to see it fail.** `cargo test --workspace --all-features --lib -- fuzzing::tests::the_oracle_reads` — Expected: FAIL to compile (`level_1b_needing_1_1` not found).

- [ ] **Step 3: The case and its seed.** In `fuzzing.rs`, after `p_slice_with_lists`:

```rust
/// A Baseline level-1b SPS (`level_idc` 11, `constraint_set3_flag` set) at
/// 10×9 macroblocks: 2,700 MB/s at 30 fps is past 1b's MaxMBPS of 1,485, so
/// the rewriter raises it to 1.1 — `level_idc`'s number unchanged, cs3
/// cleared (`rewrite.rs`'s `level_1b_is_ranked_between_level_1_and_level_1_1`,
/// case 1). POC type 2, no VUI. Plan E Task 2.4: the `sps_rewrite` seed
/// that keeps the oracle's raise-by-rank honest.
fn level_1b_needing_1_1() -> Vec<u8> {
    use crate::bits::{BitWriter, escape_rbsp_into};
    let mut w = BitWriter::new();
    w.write_u8(66); // profile_idc: Baseline
    w.write_u8(0x10); // constraint_set3_flag: with level_idc 11, level 1b
    w.write_u8(11); // level_idc
    w.write_ue(0); // seq_parameter_set_id
    w.write_ue(0); // log2_max_frame_num_minus4
    w.write_ue(2); // pic_order_cnt_type
    w.write_ue(1); // max_num_ref_frames
    w.write_flag(false); // gaps_in_frame_num_value_allowed_flag
    w.write_ue(9); // pic_width_in_mbs_minus1: 10 MBs
    w.write_ue(8); // pic_height_in_map_units_minus1: 9 MBs
    w.write_flag(true); // frame_mbs_only_flag
    w.write_flag(true); // direct_8x8_inference_flag
    w.write_flag(false); // frame_cropping_flag
    w.write_flag(false); // vui_parameters_present_flag
    w.write_trailing_bits();
    let mut nal = vec![0x67];
    escape_rbsp_into(&w.into_rbsp(), &mut nal);
    nal
}
```

and in `seeds()`, in the `sps_rewrite` loop's list, after `("main", MAIN_360P_PARAMS.0.to_vec()),`:

```rust
        ("level_1b_needs_1_1", level_1b_needing_1_1()),
```

Run the test again — Expected: FAIL, now inside `sps_rewrite`'s `assert_eq!(out, expect)` with `constraint_flags: 0` against `constraint_flags: 16`: the PB12 limitation, reproduced on a committed input.

- [ ] **Step 4: Compare by rank.** In `crates/kvm-proto/src/h264/rewrite.rs`, `fn is_level_1b` and `fn level_rank` become `pub(crate) fn` (bodies and docs unchanged; `level_rank` keeps `#[must_use]`). In `fuzzing.rs`, the import becomes `use crate::h264::rewrite::{RewriteConfig, RewriteError, RewriteFields, level_rank, rewrite_sps};`, and in `sps_rewrite` the comment block from `// Preflight I1/m5:` through `let level_raised = out.level_idc != input.level_idc;` becomes:

```rust
    // Preflight I1/m5: key this off an independently observed raise (input
    // vs output) rather than trusting the rewriter's own `r.changed.level`
    // report — a rewriter that mis-reports `changed.level` while clearing
    // cs3 without an actual raise must not be excused by believing its own
    // flag (M18b2). Plan E Task 2.4 (pre-flight E7): observed by rank, not
    // by number — level 1b -> 1.1 keeps `level_idc` 11 and is a raise
    // (`level_rank` places 1b between 1 and 1.1). An unranked level was
    // refused above as `UnknownLevel`.
    let rank = |s: &SpsSyntax| level_rank(s.profile_idc, s.level_idc, s.constraint_flags);
    let level_raised = rank(&out) > rank(&input);
```

The RB3 lines that follow (`if matches!(input.profile_idc, 66 | 77 | 88) && level_raised { expect.constraint_flags &= !0x10; }`) are unchanged.

- [ ] **Step 5: Run the tests and the seeds.** `cargo test --workspace --all-features --lib -- fuzzing::tests h264::rewrite` — Expected: PASS, including `the_oracle_reads_a_level_1b_to_1_1_raise_by_rank` and `every_target_runs_clean_over_its_seeds` (which now also runs the new seed and its truncations). `nix develop --command scripts/fuzz.sh seeds` — Expected: passes (stable toolchain; seeds only — fuzzing itself is CI's, §13).

- [ ] **Step 6: Gate and commit.** The per-task gate. Then:

```bash
git add crates/kvm-proto/src/h264/rewrite.rs crates/kvm-proto/src/fuzzing.rs
git commit -m "kvm-proto: the sps_rewrite oracle reads a level raise by rank, so level 1b -> 1.1 is a raise; the case is a seed (Plan E Task 2.4, Plan B PB12's limitation; the fuzz nightly's false positive)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**CI check**: `fuzz` green on the PR, and the fuzz nightly green on main (the owner dispatches it once after the push, or reads the next scheduled run); Task 6.1 records it.

### Task 2.3: a nightly workflow — L2 under a CPU stressor at nice 19

The final review: "A nightly L2 run under a CPU stressor at the wrapper's nice 19, so load-sensitive cases surface in CI rather than on the shared host". The review measured the failure mode: 16 busy loops on 16 cores at nice 5 with L2 at nice 19 (a CFS weight ratio of 335:15) broke a case 7 runs in 10. Reproduce that condition on the runner — one busy loop per CPU at nice 5 (the review's measured condition), L2 at nice 19 — three times a night. The nightly also reports cargo-deny's advisories (Task 2.2, DE15). Tasks 4.2 and 5.5 add jobs to this workflow.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/.github/workflows/nightly.yml`, `/home/chris/Repos/kvm-rdp/scripts/l2-under-load.sh`
- Test: a local run of the script with one loop and one case (Step 3)

**Interfaces:**
- Consumes: the `check` job's cache (`shared-key: check`), Task 2.1's pins and rules, Task 2.2's `deny.toml` and `lint-tools`.
- Produces: `.github/workflows/nightly.yml` (`schedule` + `workflow_dispatch` with input `thresholds: ci|strict`, read by Task 5.5's jobs; jobs `l2-under-load` and `deny-advisories`); `scripts/l2-under-load.sh RUNS [FILTER]` with env `L2_LOAD_LOOPS` (default: `nproc`) — exit 0 iff every run passed; logs in `$L2_LOAD_LOGS` (default `target/l2-under-load`).

- [ ] **Step 1: The script.**

```bash
#!/usr/bin/env bash
# L2 under a CPU stressor (Plan E Task 2.3; Plan C final review): one busy
# loop per CPU at nice 5 (the review's measured condition) while L2 runs at
# the §13 wrapper's nice 19 — the shared host's worst case, where
# load-sensitive cases fail first.
#   scripts/l2-under-load.sh RUNS [FILTER]
# L2_LOAD_LOOPS overrides the number of busy loops (default: every CPU) —
# only CI runs the default: on the shared host use 1 (§13).
set -euo pipefail
cd "$(dirname "$0")/.."
runs=${1:?usage: l2-under-load.sh RUNS [FILTER]}
filter=${2:-}
loops=${L2_LOAD_LOOPS:-$(nproc)}
logs=${L2_LOAD_LOGS:-target/l2-under-load}
mkdir -p "$logs"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for _ in $(seq "$loops"); do
  nice -n 5 sh -c 'while :; do :; done' &
  pids+=("$!")
done
echo "l2-under-load: $loops busy loops at nice 5; L2 at nice 19, $runs run(s)"
failed=0
for i in $(seq "$runs"); do
  if nice -n 19 cargo test --workspace --all-features --test l2 -- ${filter:+"$filter"} >"$logs/run-$i.log" 2>&1; then
    echo "l2-under-load: run $i passed ($(grep -E '^test result' "$logs/run-$i.log" | tail -n 1))"
  else
    failed=$((failed + 1))
    echo "l2-under-load: run $i FAILED:"
    grep -E '^(test .* FAILED|failures:|    [a-z_:]+$)' "$logs/run-$i.log" || tail -n 40 "$logs/run-$i.log"
  fi
done
[ "$failed" -eq 0 ] || { echo "l2-under-load: $failed of $runs runs failed (logs in $logs)"; exit 1; }
```

- [ ] **Step 2: The workflow.** `.github/workflows/nightly.yml`:

```yaml
name: Nightly

on:
  schedule:
    - cron: "43 2 * * *"
  workflow_dispatch:
    inputs:
      thresholds:
        description: "kvm-bench thresholds — strict is §10.1's absolute targets on this runner (DE11)"
        type: choice
        options: [ci, strict]
        default: ci

# Read-only: the nightly writes nothing back, reads no secret, and restores
# main's caches without saving its own.
permissions:
  contents: read

concurrency:
  group: nightly
  cancel-in-progress: false

env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: "0"
  CARGO_BUILD_JOBS: "4"

jobs:
  l2-under-load:
    # Plan C final review: load-sensitive L2 cases surface here, not on the
    # shared host — one busy loop per CPU at nice 5 (the review's measured
    # condition), L2 at nice 19, 3 runs.
    runs-on: ubuntu-24.04
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: Rust from rust-toolchain.toml
        run: rustup toolchain install && cargo --version
      - uses: Swatinem/rust-cache@release
        with:
          shared-key: check
          save-if: false
      - name: Build L2, unloaded
        run: cargo test --workspace --all-features --test l2 --no-run
      - name: L2 at nice 19 under a CPU stressor, three runs
        env:
          L2_LOAD_LOGS: ${{ runner.temp }}/l2-under-load
        run: scripts/l2-under-load.sh 3
      - name: Keep the logs
        if: failure()
        uses: actions/upload-artifact@release
        with:
          name: l2-under-load-logs
          path: ${{ runner.temp }}/l2-under-load
          retention-days: 14

  deny-advisories:
    # DE15 (Task 2.2): the advisory database moves daily, and a PR only
    # reports it; the nightly reads it against main every night. Read-only,
    # like every job here.
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - uses: cachix/install-nix-action@release
        with:
          extra_nix_config: "experimental-features = nix-command flakes"
      - name: The flake's lint tools (cargo-deny)
        run: |
          nix build .#lint-tools --out-link "$RUNNER_TEMP/lint-tools"
          echo "$RUNNER_TEMP/lint-tools/bin" >> "$GITHUB_PATH"
      - name: Rust for cargo deny (cargo metadata; rust-toolchain.toml)
        run: rustup toolchain install
      - name: cargo deny — advisories
        run: cargo deny --locked check advisories
```

Pin it: `nix develop --command scripts/pin-action.sh --rewrite .github/workflows/nightly.yml` — Expected: every action here is already pinned in `ci.yml`, so each `pin-action:` line is ci.yml's pin, verbatim, and `scripts/check-workflows.sh` (rule 11) agrees.

- [ ] **Step 3: Run it locally, politely.** One busy loop and one case (§13 — never the default `nproc` loops on the shared host): `nix develop --command env L2_LOAD_LOOPS=1 L2_LOAD_LOGS=$PWD/target/l2-under-load scripts/l2-under-load.sh 1 admin::readyz` — Expected: `run 1 passed`, and its log in `target/l2-under-load/run-1.log`. The failure path: `nix develop --command env L2_LOAD_LOOPS=1 PATH="$PWD/target/l2-fake:$PATH" scripts/l2-under-load.sh 1` after `mkdir -p target/l2-fake && printf '#!/bin/sh\necho "test admin::x ... FAILED"; exit 101\n' > target/l2-fake/cargo && chmod +x target/l2-fake/cargo` — Expected: `run 1 FAILED`, the `FAILED` line, exit 1; then `rm -rf target/l2-fake`. After either: `pgrep -fc 'while :; do :; done'` — Expected: `0` (the trap killed the loops).

- [ ] **Step 4: The rules and linters.** `nix develop --command scripts/check-workflows.sh`, `nix develop --command actionlint`, `nix develop --command shellcheck scripts/l2-under-load.sh` — Expected: clean.

- [ ] **Step 5: Commit.** (The gate is unchanged by a workflow; run `scripts/target-budget.sh`.)

```bash
git add .github/workflows/nightly.yml scripts/l2-under-load.sh
git commit -m "ci: nightly L2 at nice 19 under one nice-5 busy loop per CPU, three runs; nightly cargo-deny advisories (Plan E Task 2.3, Plan C final review)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**CI check**: the owner runs the nightly once by hand (`workflow_dispatch`) after the first push; `l2-under-load` green, or its failures are load-sensitive cases to fix (each a finding for Task 6.1's record, with the pass rate), and `deny-advisories` green (or naming a new advisory: Task 2.2's procedure).

---
## Part 3 — L3: FreeRDP interop (§11.4, Milestone 5)

"Bridge and `xfreerdp /gfx:AVC420 /log-level:WARN` as subprocesses, kvm-sim in process, under `xvfb-run` with `-fbdir`. FreeRDP comes from the flake (nixpkgs 3.32.1, built with OpenH264 …). Oracles: 1. No log line matches `avc420_decompress failure|rdpgfx_decode failed|h264`. 2. The Xvfb framebuffer read at two instants ≥ 1 s apart shows the fixture's barcode advancing and equal to a counter kvm-sim sent. 3. Bridge metrics: negotiated version, AVC420 frames acked, decode count advancing. A second run uses `/gfx:frame-ack:off` to exercise ack suspension." Plus DC8's ladder fixture. Task 3.1 builds the harness and the first run; Task 3.2 the rest and CI.

### Task 3.1: the L3 harness — Xvfb's framebuffer, FreeRDP's process group — and FreeRDP decoding the ES3 stream

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/rdp/gfx.rs` (the advertised-sets DEBUG line; the decode gauge), `src/metrics.rs` (`egfx_client_frames_decoded`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/xwd.rs`, `tests/l2/l3.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/main.rs` (`mod xwd; mod l3;`), `tests/l2/admin.rs` (`Bin`, `http_get` visible to `l3`; `Bin::lines`)
- Test: `crates/kvm-rdp/src/rdp/gfx.rs`, `tests/l2/xwd.rs` (unit cases, run in every L2), `tests/l2/l3.rs` (`#[ignore]`)

**Interfaces:**
- Consumes: L2's `Bin` (spawn, ready, admin, wait, output), `harness::{write_files, edit_toml, es3, NLA, USER, T, ms}`, kvm-sim's `stamped_events()` (`SimEvent::FlvAu { source_index, .. }`), Task 2.1's `l3-tools`.
- Produces:
  - Metric gauge `kvm_rdp_egfx_client_frames_decoded` (`Metrics::egfx_client_frames_decoded`), set from every `on_frame_ack`'s `total_frames_decoded`. Family count **46** (19 counters, 13 families, 9 gauges, 5 histograms), +2 counters in an `alloc-stats` build.
  - Log line `EGFX capabilities advertised` (target `kvm_rdp::rdp::gfx`, DEBUG, fields `slot` and `sets` — the advertised sets in census notation, `vvvvvvvv:hex`, comma-joined, bounded by `caps_hex`).
  - `tests/l2/xwd.rs`: `Framebuffer::{read(&Path) -> Option<Framebuffer>, parse(Vec<u8>) -> Option<Framebuffer>, rgb(x, y) -> Option<[u8; 3]>}`; `barcode(&Framebuffer, x0, y0, block_w, block_h) -> Option<u16>`; `Group::{spawn(Command) -> io::Result<Group>, running(&mut self) -> bool, wait_exit(&mut self, Duration) -> Option<ExitStatus>}` (drop kills the group).
  - `tests/l2/l3.rs`: `L3::{start(video_toml: &str), freerdp(&mut self, args: &[&str]), streaming(&self, limit), barcode_within, sim_sent, metrics, advertised, freerdp_log, xvfb_log, freerdp_running, stop_and_check_freerdp_log}`, `sample(body, series) -> Option<f64>`, `V8_1`. Task 3.2 adds `V10_7`, `L3::freerdp_exit` and its cases (each item lands with its first user, so Task 3.1's clippy gate sees no dead code).

- [ ] **Step 1: Write the failing unit tests.** `crates/kvm-rdp/tests/l2/xwd.rs`, its tests module first (the module body comes in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// An XWD image as Xvfb 21.1.24's -fbdir writes one: a big-endian
    /// header with a 60-byte window name (`header_size` 160), 256 colormap
    /// entries (`ncolors` 256, each a zeroed 12-byte XWDColor), so the
    /// pixels start at 3232 as on a live Xvfb; 32-bit LSBFirst TrueColor.
    fn xwd(w: u32, h: u32, px: impl Fn(u32, u32) -> [u8; 3]) -> Vec<u8> {
        let mut name = b"Xvfb main window".to_vec();
        name.resize(60, 0);
        let header = 100 + u32::try_from(name.len()).unwrap();
        let words = [
            header, 7, 2, 24, w, h, 0, 0, 32, 0, 32, 32, w * 4, 4, 0x00FF_0000, 0x0000_FF00,
            0x0000_00FF, 8, 256, 256, w, h, 0, 0, 0,
        ];
        let mut out: Vec<u8> = words.iter().flat_map(|v| v.to_be_bytes()).collect();
        out.extend_from_slice(&name);
        out.resize(out.len() + 256 * 12, 0);
        assert_eq!(out.len(), 3232, "Xvfb's pixel offset");
        for y in 0..h {
            for x in 0..w {
                let [r, g, b] = px(x, y);
                out.extend_from_slice(&[b, g, r, 0]);
            }
        }
        out
    }

    #[test]
    fn a_synthetic_framebuffer_reads_back_its_pixels() {
        let fb = Framebuffer::parse(xwd(8, 4, |x, y| [x as u8 * 10, y as u8 * 20, 7])).unwrap();
        assert_eq!(fb.rgb(3, 2), Some([30, 40, 7]));
        assert_eq!(fb.rgb(8, 0), None, "outside the image");
        assert!(Framebuffer::parse(vec![0; 50]).is_none(), "a short file");
    }

    /// §11.5's barcode: block k white when bit k of the frame index is set.
    #[test]
    fn the_barcode_decodes_and_an_unclean_one_does_not() {
        let value = 0xA5C3u16;
        let fb = Framebuffer::parse(xwd(640, 40, |x, y| {
            let on = y < 32 && value >> (x / 40) & 1 == 1;
            if on { [235, 235, 235] } else { [16, 16, 16] }
        }))
        .unwrap();
        assert_eq!(barcode(&fb, 0, 0, 40, 32), Some(value));
        let grey = Framebuffer::parse(xwd(640, 40, |_, _| [128, 128, 128])).unwrap();
        assert_eq!(barcode(&grey, 0, 0, 40, 32), None, "neither black nor white");
        // Black is a clean reading of 0 — and Xvfb's root and FreeRDP's
        // empty window are black: why `L3::barcode_within` skips 0.
        let black = Framebuffer::parse(xwd(640, 40, |_, _| [0, 0, 0])).unwrap();
        assert_eq!(barcode(&black, 0, 0, 40, 32), Some(0));
    }

    /// Review Focus 5: dropping a group kills every process in it — the
    /// leader and what it started (Xvfb under xvfb-run, here two sleeps).
    #[test]
    fn a_dropped_group_leaves_no_process_behind() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 60 & sleep 60"]);
        let g = Group::spawn(cmd).unwrap();
        let pgid = g.pgid;
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: signal 0 probes our own process group.
        assert_eq!(unsafe { libc::kill(-pgid, 0) }, 0, "the group runs");
        drop(g);
        let gone = (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            // SAFETY: as above.
            unsafe { libc::kill(-pgid, 0) } == -1
        });
        assert!(gone, "a process of the group outlived its drop");
    }
}
```

In `crates/kvm-rdp/src/rdp/gfx.rs`'s tests (add `use crate::msg::RdpInput; use ironrdp_egfx::pdu::CapabilitiesAdvertisePdu; use std::sync::Mutex;` as needed):

```rust
    /// A `MakeWriter` into a shared buffer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    /// Plan E Task 3.1 (§11.4 oracle 3, DE4): an ack sets the client's
    /// decode gauge; an advertise is logged at DEBUG in census notation
    /// (what L3 reads FreeRDP's ladder from) and still reaches the pump.
    #[test]
    fn an_ack_sets_the_decode_gauge_and_an_advertise_is_logged_at_debug() {
        let metrics = Arc::new(Metrics::default());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut cb = GfxCallbacks { slot: 3, tx, hard_cap: 60, metrics: metrics.clone() };
        cb.on_frame_ack(7, 0, 41);
        assert_eq!(metrics.egfx_client_frames_decoded.get(), 41);
        let buf = Buf::default();
        let sub = crate::logging::subscriber("kvm_rdp=debug", buf.clone()).unwrap();
        let pdu = CapabilitiesAdvertisePdu(vec![
            RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
            RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
        ]);
        tracing::subscriber::with_default(sub, || cb.capabilities_advertise(&pdu));
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("EGFX capabilities advertised"), "{text}");
        assert!(text.contains("00080004:02000000,00080105:12000000"), "{text}");
        // The ack still reaches the pump, first: it was sent first.
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::FrameAck { slot: 3, frame_id: 7, queue_depth: 0 })
        ));
        assert!(matches!(rx.try_recv(), Ok(RdpInput::CapsAdvertised { slot: 3, .. })));
    }
```

Bump `metrics.rs`'s count by one: `46 + if cfg!(feature = "alloc-stats") { 2 } else { 0 }`, "19 counters, 13 families, 9 gauges, 5 histograms (+2 counters in alloc-stats builds)", and add `assert!(t.contains("# TYPE kvm_rdp_egfx_client_frames_decoded gauge\n"));`.

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- rdp::gfx metrics::tests` — Expected: FAIL to compile (`egfx_client_frames_decoded` not found). `cargo test --workspace --all-features --test l2 -- xwd::` — Expected: FAIL to compile (`Framebuffer`, `barcode`, `Group` not found; add `mod xwd;` to `main.rs` first).

- [ ] **Step 3: The gauge and the line.** `metrics.rs`: a field `pub egfx_client_frames_decoded: Gauge` (after `egfx_capability_version`), built as `Gauge::new("kvm_rdp_egfx_client_frames_decoded", "The client's last totalFramesDecoded, from its FrameAcknowledge (§11.4)")`, rendered in the gauges loop. `gfx.rs`:

```rust
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        let sets = caps_hex(pdu);
        // Once per negotiation, bounded by `caps_hex`; L3 reads FreeRDP's
        // ladder from it (Plan E Task 3.1, DC8). Client-chosen bytes, as
        // hex: never text the client typed.
        tracing::debug!(slot = self.slot, sets = %sets.join(","), "EGFX capabilities advertised");
        let _ = self.tx.send(RdpInput::CapsAdvertised { slot: self.slot, sets });
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        // §11.4 oracle 3: the client's own decode count (a metric only).
        self.metrics
            .egfx_client_frames_decoded
            .set(i64::from(total_frames_decoded));
        let _ = self.tx.send(RdpInput::FrameAck { slot: self.slot, frame_id, queue_depth });
    }
```

The secrets case (`admin::secrets_never_reach_the_logs`) runs at TRACE and will now see this line under `kvm_rdp::rdp::gfx`, already a `KNOWN_TARGETS` entry: it faces every encoding and fragment check (the L2 client's two sets are hex digits; the sentinel's and canary's letters `g`–`l`, `w`–`z` are not hex, so no fragment can match). It must stay green in Step 6.

- [ ] **Step 4: `xwd.rs`.** Above its tests:

```rust
//! L3's oracles (Plan E Task 3.1): the picture FreeRDP decoded, read back
//! from Xvfb's `-fbdir` framebuffer (an XWD file, the X server's own
//! pixels), §11.5's 16-bit barcode in it, and FreeRDP's process group,
//! killed whole when a case ends however it ends (Review Focus 5).
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// A ZPixmap XWD image with 32-bit pixels (Xvfb's at depth 24).
pub struct Framebuffer {
    width: u32,
    height: u32,
    bytes_per_line: usize,
    lsb_first: bool,
    masks: [u32; 3],
    start: usize,
    data: Vec<u8>,
}

impl Framebuffer {
    pub fn read(path: &Path) -> Option<Framebuffer> {
        Framebuffer::parse(std::fs::read(path).ok()?)
    }

    /// XWDFileHeader: 25 big-endian CARD32s (X11's XWDFile.h), then the
    /// window name (to `header_size`), `ncolors` 12-byte XWDColors, then
    /// `height` lines of `bytes_per_line`.
    pub fn parse(data: Vec<u8>) -> Option<Framebuffer> {
        let word = |i: usize| -> Option<u32> {
            let b = data.get(i * 4..i * 4 + 4)?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        };
        if word(1)? != 7 || word(11)? != 32 {
            return None; // XWD_FILE_VERSION 7; 32 bits per pixel only
        }
        let (width, height) = (word(4)?, word(5)?);
        let bytes_per_line = usize::try_from(word(12)?).ok()?;
        let start = usize::try_from(word(0)?).ok()? + usize::try_from(word(19)?).ok()? * 12;
        if data.len() < start + bytes_per_line * usize::try_from(height).ok()? {
            return None;
        }
        Some(Framebuffer {
            width,
            height,
            bytes_per_line,
            lsb_first: word(7)? == 0,
            masks: [word(14)?, word(15)?, word(16)?],
            start,
            data,
        })
    }

    pub fn rgb(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let off = self.start + usize::try_from(y).ok()? * self.bytes_per_line + usize::try_from(x).ok()? * 4;
        let b = self.data.get(off..off + 4)?;
        let px = if self.lsb_first {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        };
        let channel = |mask: u32| -> u8 {
            if mask == 0 {
                return 0;
            }
            let shift = mask.trailing_zeros();
            let max = mask >> shift;
            u8::try_from(((px & mask) >> shift) * 255 / max).unwrap_or(255)
        };
        Some([channel(self.masks[0]), channel(self.masks[1]), channel(self.masks[2])])
    }
}

/// §11.5's barcode at `(x0, y0)`: block k white when bit k is set, read at
/// three points per block; `None` unless every point is clean black
/// (luma < 64) or white (> 192) and a block's points agree — a torn or
/// half-decoded picture never reads as a frame number.
pub fn barcode(fb: &Framebuffer, x0: u32, y0: u32, bw: u32, bh: u32) -> Option<u16> {
    let mut value = 0u16;
    for k in 0..16u32 {
        let mut white = None;
        for (dx, dy) in [(bw / 2, bh / 2), (bw / 4, bh / 4), (3 * bw / 4, 3 * bh / 4)] {
            let [r, g, b] = fb.rgb(x0 + k * bw + dx, y0 + dy)?;
            let luma = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            let w = match luma {
                0..=63 => false,
                193..=255 => true,
                _ => return None,
            };
            if *white.get_or_insert(w) != w {
                return None;
            }
        }
        if white == Some(true) {
            value |= 1 << k;
        }
    }
    Some(value)
}

/// A child in its own process group; dropping it ends the whole group.
pub struct Group {
    child: Child,
    pub pgid: libc::pid_t,
}

impl Group {
    pub fn spawn(mut cmd: Command) -> std::io::Result<Group> {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        let child = cmd.spawn()?;
        let pgid = libc::pid_t::try_from(child.id()).map_err(std::io::Error::other)?;
        Ok(Group { child, pgid })
    }

    pub fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// The leader's exit, if it comes within `limit`.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let t0 = Instant::now();
        loop {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            if t0.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // SAFETY: signalling our own process group.
        unsafe { libc::kill(-self.pgid, libc::SIGTERM) };
        let _ = self.wait_exit(Duration::from_secs(2));
        // SAFETY: as above; whatever outlived the TERM (Xvfb under a dead
        // xvfb-run) is still in the group.
        unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
        let _ = self.child.wait();
    }
}
```

- [ ] **Step 5: Run the unit tests.** `cargo test --workspace --all-features --lib -- rdp::gfx metrics::tests` and `cargo test --workspace --all-features --test l2 -- xwd::` — Expected: PASS.

- [ ] **Step 6: The L3 harness and its first case.** In `admin.rs`: `pub(crate) struct Bin`, `pub(crate)` on `spawn`, `ready`, `admin`, `wait`, `output`, and `http_get`, and

```rust
    /// What the child has written so far (a live snapshot; `output` is the
    /// complete log once it has exited).
    pub(crate) fn lines(&self) -> Vec<String> {
        self.out.lock().unwrap().clone()
    }
```

`crates/kvm-rdp/tests/l2/l3.rs`:

```rust
//! L3 interop (spec §11.4; Plan E Tasks 3.1–3.2): the bridge binary and
//! FreeRDP 3 (the flake's, built with OpenH264) as subprocesses, kvm-sim in
//! process; FreeRDP under `xvfb-run` with `-fbdir`, so a case reads back
//! the picture FreeRDP decoded. `#[ignore]`d — they need the flake's tools:
//!   nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1
//! CI's `check` job puts `nix build .#l3-tools` on PATH (Task 3.2).
//! Oracles (§11.4): no H.264 error in FreeRDP's log at WARN; the
//! framebuffer's barcode advancing and equal to a frame kvm-sim sent; the
//! bridge's metrics.
use crate::admin::{Bin, http_get};
use crate::harness::{NLA, T, USER, edit_toml, es3, ms, write_files};
use crate::xwd::{Framebuffer, Group, barcode};
use kvm_sim::{KvmSim, SimEvent};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The ES3-shaped fixture's barcode: 16 blocks of 40×32 across the top
/// (scripts/gen-fixtures.sh `es3like`).
const BLOCK: (u32, u32) = (40, 32);
/// §11.4 oracle 1, matched case-insensitively.
const FORBIDDEN: [&str; 3] = ["avc420_decompress failure", "rdpgfx_decode failed", "h264"];
/// MS-RDPEGFX's CAPVERSION_81.
pub const V8_1: f64 = 524_549.0;

/// One L3 case's processes and files. Fields drop in declaration order:
/// FreeRDP's group (and the Xvfb under it) first, so a failing case never
/// leaves FreeRDP and Xvfb running for up to 2 s after the bridge, kvm-sim
/// and the directories holding their logs are gone.
pub struct L3 {
    freerdp: Option<Group>,
    pub sim: KvmSim,
    dir: tempfile::TempDir,
    fb: tempfile::TempDir,
    pub bin: Bin,
    pub rdp: SocketAddr,
}

/// §11.4's tools on PATH, or a message saying how to get them.
fn require_tools() {
    for tool in ["xvfb-run", "xfreerdp"] {
        let found = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()));
        assert!(
            found,
            "L3 needs {tool} on PATH: run it in `nix develop`, or put `nix build .#l3-tools`'s bin/ first"
        );
    }
}

impl L3 {
    /// kvm-sim (the ES3 profile over the ES3-shaped fixture, real time) and
    /// the bridge binary over it: a 640×360 desktop, the advertised-sets
    /// line on, and `video` TOML lines added to `[video]`.
    pub async fn start(video: &str) -> L3 {
        require_tools();
        let sim = KvmSim::start(es3()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_files(&sim, dir.path());
        edit_toml(
            dir.path(),
            "[video]\n",
            &format!("[video]\ndefault_size = \"640x360\"\n{video}"),
        );
        let toml = dir.path().join("kvm-rdp.toml");
        let text = std::fs::read_to_string(&toml).unwrap();
        std::fs::write(&toml, format!("{text}[log]\nfilter = \"info,kvm_rdp::rdp::gfx=debug\"\n"))
            .unwrap();
        let mut bin = Bin::spawn(dir.path(), &[]);
        let rdp = bin.ready().await;
        L3 { freerdp: None, sim, dir, fb: tempfile::tempdir().unwrap(), bin, rdp }
    }

    /// FreeRDP against the bridge, under Xvfb, in its own process group,
    /// stdout and stderr to `freerdp.log`, its config in a throwaway HOME.
    /// `xvfb-run -d` lets Xvfb pick a free display itself (`-displayfd`; the
    /// deprecated `-a` scans lock files and races a concurrent run), and the
    /// display is ready when xvfb-run resumes, so `-w 0` drops its 3 s
    /// sleep; Xvfb's own output goes to `xvfb.log` (`-e`).
    pub fn freerdp(&mut self, args: &[&str]) {
        let log = std::fs::File::create(self.dir.path().join("freerdp.log")).unwrap();
        let home = self.dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let mut cmd = Command::new("xvfb-run");
        cmd.arg("-d")
            .arg("-e")
            .arg(self.dir.path().join("xvfb.log"))
            .args(["-w", "0"])
            .arg("-s")
            .arg(format!("-screen 0 1280x720x24 -fbdir {}", self.fb.path().display()))
            .arg("xfreerdp")
            .arg(format!("/v:{}:{}", self.rdp.ip(), self.rdp.port()))
            .arg(format!("/u:{USER}"))
            .arg(format!("/p:{NLA}"))
            .args(["/cert:ignore", "/log-level:WARN"])
            .args(args)
            // A session's LD_LIBRARY_PATH can carry an alsa-lib FreeRDP
            // cannot load (spikes/legb-winapp/README.md).
            .env_remove("LD_LIBRARY_PATH")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        self.freerdp = Some(Group::spawn(cmd).unwrap());
    }

    /// The bridge is sending FreeRDP pictures: `kvm_rdp_egfx_frames_sent_total`
    /// at least 1, polled every 200 ms within `limit` (the slate is not
    /// counted, only KVM frames). Every picture wait comes after it: before
    /// it, the framebuffer is Xvfb's root or FreeRDP's empty window. On a
    /// timeout, FreeRDP's and Xvfb's logs.
    pub async fn streaming(&self, limit: Duration) {
        let t0 = Instant::now();
        loop {
            let sent = sample(&self.metrics().await, "kvm_rdp_egfx_frames_sent_total");
            if sent.is_some_and(|n| n >= 1.0) {
                return;
            }
            assert!(
                t0.elapsed() <= limit,
                "the bridge sent FreeRDP no frame within {limit:?}; FreeRDP said:\n{}\nXvfb said:\n{}",
                self.freerdp_log(),
                self.xvfb_log()
            );
            tokio::time::sleep(ms(200)).await;
        }
    }

    /// The framebuffer's barcode, once it reads clean and non-zero, within
    /// `limit`; on a timeout the framebuffer is kept beside FreeRDP's and
    /// Xvfb's logs for diagnosis. A reading of 0 is skipped: black is
    /// Xvfb's root, FreeRDP's empty window and frame 0 alike (`xwd.rs`'s
    /// barcode test), and frame 0 recurs every 4 s, so skipping it costs at
    /// most one frame.
    pub async fn barcode_within(&self, limit: Duration) -> (u16, Instant) {
        let path = self.fb.path().join("Xvfb_screen0");
        let t0 = Instant::now();
        loop {
            let at = Instant::now();
            if let Some(b) = Framebuffer::read(&path)
                .and_then(|f| barcode(&f, 0, 0, BLOCK.0, BLOCK.1))
                .filter(|b| *b != 0)
            {
                return (b, at);
            }
            if t0.elapsed() > limit {
                let kept = std::env::temp_dir()
                    .join(format!("kvm-rdp-l3-framebuffer-{}.xwd", std::process::id()));
                let _ = std::fs::copy(&path, &kept);
                panic!(
                    "no clean non-zero barcode within {limit:?}; framebuffer kept at {}; FreeRDP said:\n{}\nXvfb said:\n{}",
                    kept.display(),
                    self.freerdp_log(),
                    self.xvfb_log()
                );
            }
            tokio::time::sleep(ms(200)).await;
        }
    }

    /// kvm-sim sent the frame whose barcode is `b` in the `window` before `at`.
    pub fn sim_sent(&self, b: u16, at: Instant, window: Duration) -> bool {
        self.sim.stamped_events().iter().any(|(t, e)| {
            matches!(e, SimEvent::FlvAu { source_index, .. } if *source_index == usize::from(b))
                && *t <= at
                && at.saturating_duration_since(*t) <= window
        })
    }

    pub async fn metrics(&self) -> String {
        http_get(self.bin.admin(), "/metrics").await
    }

    /// The sets the bridge last logged a client advertising (census notation).
    pub fn advertised(&self) -> Vec<String> {
        self.bin
            .lines()
            .iter()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v["fields"]["message"] != "EGFX capabilities advertised" {
                    return None;
                }
                v["fields"]["sets"].as_str().map(str::to_owned)
            })
            .last()
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    }

    pub fn freerdp_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("freerdp.log")).unwrap_or_default()
    }

    /// Xvfb's own output (`xvfb-run -e`): kept while xvfb-run runs;
    /// xvfb-run's cleanup truncates it when the command exits by itself —
    /// FreeRDP's log then names a display failure (`failed to open display`).
    pub fn xvfb_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("xvfb.log")).unwrap_or_default()
    }

    pub fn freerdp_running(&mut self) -> bool {
        self.freerdp.as_mut().is_some_and(Group::running)
    }

    /// End FreeRDP's group, then §11.4 oracle 1 over everything it logged.
    pub fn stop_and_check_freerdp_log(&mut self) {
        self.freerdp = None;
        let log = self.freerdp_log().to_lowercase();
        for f in FORBIDDEN {
            assert!(!log.contains(f), "FreeRDP logged {f:?}:\n{log}");
        }
    }
}

/// A series' value in a `/metrics` body.
pub fn sample(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.trim().parse().ok())
}

/// §11.4 oracles 1–3 with `/gfx:AVC420`, and the advertise equal to
/// `census.md`'s FreeRDP pair (Legs B and C ran 3.31.1; the flake has
/// 3.32.1, DE9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_decodes_the_es3_stream_through_the_bridge() {
    let mut l3 = L3::start("").await;
    l3.freerdp(&["/sec:nla", "/gfx:AVC420"]);
    l3.streaming(Duration::from_secs(20)).await;
    let (b1, t1) = l3.barcode_within(T).await;
    let m1 = l3.metrics().await;
    tokio::time::sleep(ms(1100)).await;
    let (b2, t2) = l3.barcode_within(T).await;
    let m2 = l3.metrics().await;
    assert_ne!(b1, b2, "the picture did not advance in {:?}", t2 - t1);
    for (b, at) in [(b1, t1), (b2, t2)] {
        assert!(l3.sim_sent(b, at, ms(1500)), "barcode {b} is no frame kvm-sim sent in the 1.5 s before");
    }
    assert_eq!(sample(&m2, "kvm_rdp_egfx_capability_version"), Some(V8_1));
    for series in ["kvm_rdp_egfx_frames_acked_total", "kvm_rdp_egfx_client_frames_decoded"] {
        assert!(sample(&m2, series) > sample(&m1, series), "{series} did not advance");
    }
    assert_eq!(l3.advertised(), ["00080004:02000000", "00080105:12000000"]);
    assert!(l3.freerdp_running(), "FreeRDP exited:\n{}", l3.freerdp_log());
    l3.stop_and_check_freerdp_log();
    assert_eq!(l3.sim.stats().logouts, 0);
}
```

Add `mod l3;` to `tests/l2/main.rs`. A failed case leaves the picture it saw in the system temp dir (`kvm-rdp-l3-framebuffer-<pid>.xwd`).

- [ ] **Step 7: Run L3.** `nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1` — Expected: PASS (`freerdp_decodes_the_es3_stream_through_the_bridge`, about 7 s: no xvfb-run sleep). If the barcode never reads clean, look at the kept framebuffer (`ffmpeg -i framebuffer.xwd framebuffer.png`, in the devshell) before changing anything: a picture not at (0, 0) means FreeRDP placed its window elsewhere — then locate the barcode by scanning row 16 for the first 40-pixel run of clean black or white, and say so in the commit; anything else is a finding. Then the whole suite (the secrets case included): `cargo test --workspace --all-features --test l2` — Expected: 0 failed; the L3 case is listed as ignored.

- [ ] **Step 8: Gate and commit.** The per-task gate, with the image's feature-set clippy (this task edits `crates/kvm-rdp/src`).

```bash
git add crates/kvm-rdp/src/rdp/gfx.rs crates/kvm-rdp/src/metrics.rs crates/kvm-rdp/tests/l2/xwd.rs \
  crates/kvm-rdp/tests/l2/l3.rs crates/kvm-rdp/tests/l2/main.rs crates/kvm-rdp/tests/l2/admin.rs
git commit -m "kvm-rdp: L3 harness — Xvfb's framebuffer, FreeRDP's process group — and FreeRDP decoding the ES3 stream; the client decode gauge (Plan E Task 3.1, §11.4)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3.2: L3 — ack suspension, FreeRDP's 11-set ladder fixture (DC8), no NLA refused; L3 in CI

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/tests/l2/l3.rs` (`V10_7`, `L3::freerdp_exit`, `freerdp_version`; three cases)
- Create: `/home/chris/Repos/kvm-rdp/fixtures/freerdp-gfx-ladder.txt` (recorded by the ladder case)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/rig.rs` (`freerdp_ladder`), `src/pump/core.rs` (the L1 case uses it)
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (`check` runs L3)
- Test: `tests/l2/l3.rs`, `pump::core::tests::capability_replays_confirm_what_the_census_recorded`

**Interfaces:**
- Consumes: Task 3.1's `L3` (`streaming`, `barcode_within`, …), `sample`, `V8_1`; Task 2.1's `l3-tools`.
- Produces: `pub const V10_7: f64`, `L3::freerdp_exit(&mut self, limit) -> Option<ExitStatus>`, `fn freerdp_version() -> String` (the first line of `xfreerdp /version`); `fixtures/freerdp-gfx-ladder.txt` — a comment header whose first line is `# <xfreerdp /version>` as recorded, then one advertised set per line in census notation (`vvvvvvvv:hex`); `rig::freerdp_ladder() -> Vec<RawCapabilitySet>` parsing it; env `KVM_RDP_L3_RECORD=1` makes the ladder case write the fixture instead of comparing.

- [ ] **Step 1: The items the cases need, and the three cases.** In `l3.rs`, after `V8_1`:

```rust
/// MS-RDPEGFX's CAPVERSION_107.
pub const V10_7: f64 = 657_153.0;

/// The first line `xfreerdp /version` prints: the ladder fixture's header
/// names the FreeRDP that recorded it.
fn freerdp_version() -> String {
    let out = Command::new("xfreerdp")
        .arg("/version")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}
```

in `impl L3`, after `freerdp_running`:

```rust
    /// FreeRDP's leader's own exit (a refused connection), within `limit`.
    pub fn freerdp_exit(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        self.freerdp.as_mut().and_then(|g| g.wait_exit(limit))
    }
```

and the three cases:

```rust
/// §11.4's second run: `/gfx:frame-ack:off` suspends acks (§6.6). Frames
/// keep flowing and the picture keeps moving, with the stall timer scaled
/// to 2 s, for three times that once acks are suspended — a bridge that
/// waited for acks would close the session as client_stalled inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_suspending_acks_keeps_the_picture_moving() {
    let mut l3 = L3::start("stall_timeout = \"2s\"\n").await;
    l3.freerdp(&["/sec:nla", "/gfx:AVC420,frame-ack:off"]);
    l3.streaming(Duration::from_secs(20)).await;
    // The 6 s window starts once the suspension is in force, not before.
    let t0 = Instant::now();
    while sample(&l3.metrics().await, "kvm_rdp_egfx_ack_suspended") != Some(1.0) {
        assert!(t0.elapsed() < T, "acks never suspended:\n{}", l3.freerdp_log());
        tokio::time::sleep(ms(200)).await;
    }
    let m1 = l3.metrics().await;
    let (b1, _) = l3.barcode_within(T).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (b2, t2) = l3.barcode_within(T).await;
    let m2 = l3.metrics().await;
    assert_eq!(sample(&m2, "kvm_rdp_egfx_ack_suspended"), Some(1.0), "acks never suspended");
    assert!(sample(&m2, "kvm_rdp_egfx_frames_sent_total") > sample(&m1, "kvm_rdp_egfx_frames_sent_total"));
    assert_ne!(b1, b2, "the picture froze");
    assert!(l3.sim_sent(b2, t2, ms(1500)));
    assert!(l3.freerdp_running(), "the session ended:\n{}", l3.freerdp_log());
    assert!(!m2.contains("kvm_rdp_disconnects_total{cause=\"client_stalled\"}"), "{m2}");
    l3.stop_and_check_freerdp_log();
}

/// DC8: FreeRDP's full ladder — `/gfx` with no codec option advertises
/// eleven sets, V8 to V10_7 (census.md, Leg C) — byte for byte the
/// committed fixture, which the bridge confirms at V10_7 and serves AVC420
/// under. `KVM_RDP_L3_RECORD=1` writes the fixture instead (a new FreeRDP
/// in flake.lock: record, review the diff, commit).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdps_full_ladder_is_the_committed_fixture() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/freerdp-gfx-ladder.txt");
    let mut l3 = L3::start("").await; // require_tools first: its message, not "os error 2"
    let version = format!("# {}", freerdp_version());
    l3.freerdp(&["/sec:nla", "/gfx"]);
    l3.streaming(Duration::from_secs(20)).await;
    l3.barcode_within(T).await;
    let sets = l3.advertised();
    assert_eq!(sets.len(), 11, "{sets:?}");
    if std::env::var_os("KVM_RDP_L3_RECORD").is_some() {
        // The first line names the recording FreeRDP (`xfreerdp /version`),
        // so a re-record after a flake.lock bump labels itself.
        let mut text = format!(
            "{version}\n\
             # The flake's FreeRDP, `/gfx` with no codec option: the 11-set\n\
             # capability ladder it advertises (census.md, Leg C; DC8), one set per\n\
             # line in census notation (version:data, hex). Recorded by L3's\n\
             # freerdps_full_ladder_is_the_committed_fixture with KVM_RDP_L3_RECORD=1.\n",
        );
        for s in &sets {
            text.push_str(s);
            text.push('\n');
        }
        std::fs::write(&fixture, text).unwrap();
    } else {
        let text = std::fs::read_to_string(&fixture).unwrap();
        assert_eq!(
            text.lines().next(),
            Some(version.as_str()),
            "FreeRDP changed: re-record (KVM_RDP_L3_RECORD=1) and review"
        );
        let want: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(sets, want, "FreeRDP's ladder changed: re-record (KVM_RDP_L3_RECORD=1) and review");
    }
    let m = l3.metrics().await;
    assert_eq!(sample(&m, "kvm_rdp_egfx_capability_version"), Some(V10_7));
    l3.stop_and_check_freerdp_log();
}

/// §9.1 and §5.1 with a real client: FreeRDP offering TLS without NLA is
/// refused at negotiation, before any KVM traffic — kvm-sim sees no
/// connection at all — and the bridge keeps serving. IronRDP at the pinned
/// rev sends no RDP_NEG_FAILURE (it returns before the write), so FreeRDP
/// sees a plain close: the refusal's one trace is the bridge's own
/// "Connection error" line, which names the mismatch — asserted, so a
/// FreeRDP that failed for any other reason (no display, a bad flag, a
/// missing library) cannot pass for a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "L3: needs xfreerdp and xvfb-run on PATH (nix build .#l3-tools)"]
async fn freerdp_without_nla_is_refused_before_any_kvm_traffic() {
    let mut l3 = L3::start("").await;
    l3.freerdp(&["/sec:tls", "/gfx:AVC420"]);
    let status = l3.freerdp_exit(Duration::from_secs(20)).expect("FreeRDP kept running");
    assert!(!status.success(), "FreeRDP connected without NLA:\n{}", l3.freerdp_log());
    assert!(
        l3.bin
            .lines()
            .iter()
            .any(|l| l.contains("Connection error") && l.contains("security protocol mismatch")),
        "the bridge logged no refusal; FreeRDP said:\n{}\nXvfb said:\n{}",
        l3.freerdp_log(),
        l3.xvfb_log()
    );
    // FreeRDP 3.32.1 logs `[xf_setup_x11]: failed to open display: :N`,
    // then ERRCONNECT_PRE_CONNECT_FAILED, when it never got a display.
    let log = l3.freerdp_log();
    let lower = log.to_lowercase();
    for no_display in ["failed to open display", "errconnect_pre_connect_failed"] {
        assert!(!lower.contains(no_display), "FreeRDP never ran against the bridge:\n{log}");
    }
    let s = l3.sim.stats();
    assert_eq!((s.accepts_web, s.accepts_video, s.accepts_control), (0, 0, 0), "{s:?}");
    http_get(l3.bin.admin(), "/readyz").await; // asserts the 200 itself
    l3.stop_and_check_freerdp_log();
}
```

- [ ] **Step 2: Record the fixture, then run all four.** `nix develop --command env KVM_RDP_L3_RECORD=1 cargo test --workspace --all-features --test l2 -- --ignored l3::freerdps_full_ladder --test-threads 1` — Expected: PASS, and `fixtures/freerdp-gfx-ladder.txt` starts with `# ` and `xfreerdp /version`'s line (3.32.1), and holds eleven sets, the first two `00080004:` and `00080105:`, the last `000a0701:`. Read it against census.md's Leg C description (V8…V10_7); a different count or order is a finding to report, not to commit. Then without the variable: `nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1` — Expected: 4 passed. If FreeRDP 3.32.1 spells the suspension sub-option differently, `xfreerdp /help` names it (`frame-ack[:on|off]` under `/gfx` at drafting); if it advertises no suspension at all, the first case's `ack_suspended` assert fails — report it, since §6.6 rests on this run. Record in the commit body the exact lines the no-NLA case saw: the bridge's `Connection error` line and FreeRDP 3.32.1's last lines in `freerdp.log` (the ERROR passes §4.5's cap, and passes Task 1.3's per-callsite limit as its callsite's first line).

- [ ] **Step 3: The L1 replay uses the real ladder.** In `rig.rs`:

```rust
/// FreeRDP's 11-set ladder, as L3 recorded it (DC8; the fixture's first
/// line names the FreeRDP version).
pub(crate) fn freerdp_ladder() -> Vec<RawCapabilitySet> {
    include_str!("../../../../fixtures/freerdp-gfx-ladder.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (v, hex) = l.split_once(':').unwrap();
            let data = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            RawCapabilitySet::new(CapabilityVersion(u32::from_str_radix(v, 16).unwrap()), data)
        })
        .collect()
}
```

and in `core.rs`'s `capability_replays_confirm_what_the_census_recorded`, after the `full_ladder()` block:

```rust
        // DC8: FreeRDP's own ladder, as L3 recorded it, confirms V10_7 with
        // AVC420 — the confirm census.md records for it (Leg C).
        let mut r = Rig::new(cfg());
        let c = r.advertise(freerdp_ladder());
        let [GfxPdu::CapabilitiesConfirm(c)] = c.as_slice() else {
            panic!("{c:?}")
        };
        assert_eq!(c.0.version, CapabilityVersion::V10_7);
        assert!(r.gfx.supports_avc420());
```

`cargo test --workspace --all-features --lib -- pump::core::tests::capability_replays` — Expected: PASS.

- [ ] **Step 4: L3 in CI.** In `ci.yml`'s `check` job, after the `Test` step:

```yaml
      - uses: cachix/install-nix-action@release
        with:
          extra_nix_config: "experimental-features = nix-command flakes"
      - name: L3 tools from the flake (FreeRDP 3.32.1 with OpenH264, xvfb-run)
        run: |
          nix build .#l3-tools --out-link "$RUNNER_TEMP/l3-tools"
          "$RUNNER_TEMP/l3-tools/bin/xfreerdp" /version
      - name: L3 interop (spec §11.4) — FreeRDP against the bridge, one case at a time
        # Four cases of well under a minute each: a hung FreeRDP or Xvfb
        # must not spend the job's 45 minutes.
        timeout-minutes: 10
        run: |
          export PATH="$RUNNER_TEMP/l3-tools/bin:$PATH"
          cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1
```

The `Target budget` step stays last. `nix develop --command scripts/pin-action.sh --rewrite .github/workflows/ci.yml` — Expected: `cachix/install-nix-action` takes the `lint` job's pin, verbatim — then `nix develop --command scripts/check-workflows.sh && nix develop --command actionlint` — Expected: clean.

- [ ] **Step 5: Gate and commit.**

```bash
git add crates/kvm-rdp/tests/l2/l3.rs fixtures/freerdp-gfx-ladder.txt crates/kvm-rdp/src/pump/rig.rs \
  crates/kvm-rdp/src/pump/core.rs .github/workflows/ci.yml
git commit -m "kvm-rdp: L3 — ack suspension, FreeRDP's 11-set ladder fixture (DC8), no NLA refused; L3 runs in CI's check job (Plan E Task 3.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**CI check**: the `check` job's L3 step green (4 passed) on the PR; Task 6.1 records the `nix build .#l3-tools` time and closure size and the four cases' time from that run (E50).

---
## Part 4 — The container image (Milestone 5)

An image a deployment plan can pin (the deployment design §4.6: "pinned here as `ghcr.io/christopherjmiller/kvm-rdp:sha-<commit>@sha256:…`"): Task 4.1 builds and smoke-tests it locally and pins the behaviour the deployment relies on; Task 4.2 builds it in CI and publishes the tested archive from main only.

### Task 4.1: the Dockerfile, a reproducible build, the smoke test, and the Secret-swap test

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/Dockerfile`, `/home/chris/Repos/kvm-rdp/.dockerignore`
- Create: `/home/chris/Repos/kvm-rdp/scripts/pin-image.sh`, `scripts/image-build.sh`, `scripts/image-smoke.sh`
- Modify: `/home/chris/Repos/kvm-rdp/flake.nix` (the devshell gains `curl` for the smoke test)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/bridge.rs` (tests: the Secret swap)
- Modify: `/home/chris/Repos/kvm-rdp/README.md` (`## Container image`)
- Test: `scripts/image-smoke.sh` against the built image; `bridge::tests::a_kubernetes_secret_swap_is_a_renewal`; `scripts/check-workflows.sh` (rules 5–6 now see a Dockerfile and a BuildKit pin)

**Interfaces:**
- Consumes: Task 1.1 (`[test]` refused without `test-hooks`), Task 2.1's `check-workflows.sh` rules 5–6, the bridge's `watch_certificate` / `tls::fingerprint` (`std::fs::metadata`, which follows symlinks).
- Produces:
  - `Dockerfile`: `/usr/local/bin/kvm-rdp` (entrypoint) and `/usr/local/bin/kvm-probe`, user `65532:65532`, `MALLOC_ARENA_MAX=2`, ports 3389 and 9464, OCI labels `source`, `licenses`, `revision`.
  - `scripts/image-build.sh OUT.oci.tar [buildx args…]`: the OCI archive at `OUT` and the same image loaded as `kvm-rdp:ci`; fails unless the loaded image's `RootFS.Layers` and `Created` equal the archive config's `rootfs.diff_ids` and `created` (and, in the classic image store only, its `.Id` equals the config digest); prints `manifest <digest>, config <digest>, layers <json>`. Extra args (Task 4.2's `--no-cache`) apply to the archive's build only. Refuses a dirty build context unless `IMAGE_BUILD_DIRTY=1` (then `REVISION` is `<HEAD>-dirty`); remakes its builder when `BUILDKIT_IMAGE` changed; prunes the builder's cache to 8 GB after each build.
  - `scripts/image-smoke.sh IMAGE`: exit 0 iff every check passes; `scripts/image-smoke.sh --paths-only FILE…` runs only the build-path check (its own negative test). Task 4.2 runs both scripts in CI.
  - `scripts/pin-image.sh REF` prints `REF@sha256:<index digest>`; `--rewrite FILE…` replaces every `REF@pin` with that. This plan writes `@pin` for "pin me"; check-workflows rules 5–6 fail any left.

- [ ] **Step 1: Write the failing tests.** In `bridge.rs`'s tests, beside `a_changed_certificate_requests_an_exit`:

```rust
    /// Review Focus 1, the deployment design §11 (1): Kubernetes mounts a
    /// Secret as `tls.crt -> ..data/tls.crt` with `..data -> ..<stamp>`,
    /// and renews it by writing a new `..<stamp>` and swapping `..data` in
    /// one rename. The watcher follows the links (`metadata`, not
    /// `symlink_metadata`), so the swap is a renewal like any other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kubernetes_secret_swap_is_a_renewal() {
        use std::os::unix::fs::symlink;
        let sim = sim().await;
        let d = tempfile::tempdir().unwrap();
        let mut cfg = config_for(&sim, d.path(), |_| {});
        let secret = d.path().join("tls");
        let generation = |stamp: &str| {
            let g = secret.join(stamp);
            std::fs::create_dir_all(&g).unwrap();
            let (cert, key) = pair_in(&g);
            std::fs::rename(cert, g.join("tls.crt")).unwrap();
            std::fs::rename(key, g.join("tls.key")).unwrap();
        };
        generation("..2026_10_15_00_00_00.1");
        symlink("..2026_10_15_00_00_00.1", secret.join("..data")).unwrap();
        symlink("..data/tls.crt", secret.join("tls.crt")).unwrap();
        symlink("..data/tls.key", secret.join("tls.key")).unwrap();
        cfg.rdp.tls_cert_file = secret.join("tls.crt");
        cfg.rdp.tls_key_file = secret.join("tls.key");
        let mut h = start(cfg).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), h.exit_requested())
                .await
                .is_err(),
            "an exit before any renewal"
        );
        generation("..2026_10_15_00_01_00.2");
        symlink("..2026_10_15_00_01_00.2", secret.join("..data_tmp")).unwrap();
        std::fs::rename(secret.join("..data_tmp"), secret.join("..data")).unwrap();
        tokio::time::timeout(Duration::from_secs(1), h.exit_requested())
            .await
            .expect("the ..data swap was not seen as a renewal");
        stop(h).await;
    }
```

`scripts/image-smoke.sh` is the image's test, and it cannot pass before the image exists: write it now (Step 2), run it in Step 6.

- [ ] **Step 2: `scripts/image-smoke.sh`.**

```bash
#!/usr/bin/env bash
# Smoke-test kvm-rdp's image (Plan E Task 4.1): scripts/image-smoke.sh IMAGE
#  1. what it is: user 65532:65532, entrypoint kvm-rdp, MALLOC_ARENA_MAX=2,
#     at most MAX_MIB, no shell;
#  2. its binaries: no build-host path (PC15), kvm-probe runs;
#  3. under the restricted Pod Security profile (read-only root, no
#     capabilities, no-new-privileges), as 65532 and as an arbitrary UID,
#     with its secrets mounted the way the kubelet mounts a Secret
#     (`..<stamp>/`, a `..data` link, one link per file) at the deployment's
#     /run/secrets/kvm-rdp: /readyz and /livez answer unauthenticated; X.224
#     negotiation selects HYBRID for an NLA client and closes TLS-only and
#     standard security with no protocol (§9.1, DE2); SIGTERM exits 0 within
#     5 s (§5.2);
#  4. a config with `[test]` hooks or a security-mode key is refused, exit 2.
#   scripts/image-smoke.sh --paths-only FILE…   only check 2's build-path
#                                               rule, on FILE (its own test)
# Every grep reads a file or a variable, never a pipe a `grep -q` or `head`
# could cut short: under pipefail a SIGPIPE'd writer reads as a clean result.
set -euo pipefail
MAX_MIB=64
work=$(mktemp -d)
name=kvm-rdp-smoke-$$
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() {
  echo "image-smoke: FAIL: $*" >&2
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" 2>&1 | tail -n 40 >&2 || true
  fi
  exit 1
}
ok() { echo "image-smoke: ok — $*"; }

# PC15: no build-host source path in a binary.
paths_clean() {
  local pat='/usr/local/cargo/[[:print:]]{1,80}|/src/crates/[[:print:]]{1,80}|/home/[a-z][[:print:]]{1,80}'
  local b
  for b in "$@"; do
    [ -f "$b" ] || fail "no such binary: $b"
    if grep -aqE "$pat" "$b"; then
      grep -aoE "$pat" "$b" | head -n 3 || true
      fail "$(basename "$b") carries a build-host path (PC15: --remap-path-prefix)"
    fi
  done
}
if [ "${1:-}" = "--paths-only" ]; then
  shift
  paths_clean "$@"
  ok "no build-host path in $*"
  exit 0
fi
image=${1:?usage: image-smoke.sh IMAGE | --paths-only FILE...}

# 1. What the image is.
[ "$(docker image inspect -f '{{.Config.User}}' "$image")" = 65532:65532 ] || fail "the user is not 65532:65532"
[ "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$image")" = '["/usr/local/bin/kvm-rdp"]' ] ||
  fail "the entrypoint is not /usr/local/bin/kvm-rdp"
env_json=$(docker image inspect -f '{{json .Config.Env}}' "$image")
grep -qF '"MALLOC_ARENA_MAX=2"' <<<"$env_json" || fail "MALLOC_ARENA_MAX=2 is not set: $env_json"
size=$(docker image inspect -f '{{.Size}}' "$image")
[ "$size" -le $((MAX_MIB * 1024 * 1024)) ] || fail "the image is $((size / 1048576)) MiB, over $MAX_MIB MiB"
ok "user 65532:65532, entrypoint kvm-rdp, MALLOC_ARENA_MAX=2, $((size / 1048576)) MiB"
for sh in /bin/sh /bin/bash /busybox/sh; do
  if docker run --rm --entrypoint "$sh" "$image" -c true >/dev/null 2>&1; then
    fail "the image has a shell: $sh"
  fi
done
ok "no shell"

# 2. The binaries.
cid=$(docker create "$image")
docker cp "$cid:/usr/local/bin/kvm-rdp" "$work/kvm-rdp" >/dev/null
docker cp "$cid:/usr/local/bin/kvm-probe" "$work/kvm-probe" >/dev/null
docker rm "$cid" >/dev/null
paths_clean "$work/kvm-rdp" "$work/kvm-probe"
ok "no build-host path in either binary ($(stat -c %s "$work/kvm-rdp") and $(stat -c %s "$work/kvm-probe") bytes)"
docker run --rm --entrypoint /usr/local/bin/kvm-probe "$image" --help >/dev/null || fail "kvm-probe does not run"
ok "kvm-probe runs"

# 3. Running. The KVM is TEST-NET-1: nothing is sent to it before an
# authenticated client (§5.1), so the bridge must start and serve without it.
# The secrets as the kubelet mounts a Secret volume: the files in a
# `..<stamp>` directory, `..data` linking to it, and one link per file
# through `..data` (deployment design §4.2) — the renewal path the bridge's
# watcher follows (bridge::tests::a_kubernetes_secret_swap_is_a_renewal).
sec=$work/secrets
stamp=..2026_10_15_00_00_00.1
mkdir -p "$sec/$stamp" "$work/etc"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$sec/$stamp/tls.key" -out "$sec/$stamp/tls.crt" 2>/dev/null
printf 'image-smoke-nla-password-0123456789\n' >"$sec/$stamp/nla.pass"
printf 'image-smoke-kvm-password\n' >"$sec/$stamp/kvm.pass"
ln -s "$stamp" "$sec/..data"
for f in tls.crt tls.key nla.pass kvm.pass; do
  ln -s "..data/$f" "$sec/$f"
done
config() {
  cat <<EOF
[rdp]
listen = "0.0.0.0:3389"
nla_password_file = "/run/secrets/kvm-rdp/nla.pass"
tls_cert_file = "/run/secrets/kvm-rdp/tls.crt"
tls_key_file = "/run/secrets/kvm-rdp/tls.key"
[admin]
listen = "0.0.0.0:9464"
[kvm]
host = "192.0.2.1"
spki_sha256 = "$(printf '0%.0s' $(seq 64))"
password_file = "/run/secrets/kvm-rdp/kvm.pass"
EOF
}
config >"$work/etc/kvm-rdp.toml"
{ config; printf '[test]\npanic_after = "1s"\n'; } >"$work/etc/hooks.toml"
config | sed 's/^\[rdp\]$/[rdp]\nsecurity = "tls"/' >"$work/etc/mode.toml"
chmod 0755 "$work" "$work/etc" "$sec" "$sec/$stamp"
chmod 0644 "$work"/etc/* "$sec/$stamp"/*
mounts=(-v "$work/etc:/etc/kvm-rdp:ro" -v "$sec:/run/secrets/kvm-rdp:ro")

start() { # $1 = uid:gid
  docker run -d --name "$name" --read-only --user "$1" --cap-drop ALL --security-opt no-new-privileges \
    "${mounts[@]}" -p 127.0.0.1::3389 -p 127.0.0.1::9464 \
    "$image" --config /etc/kvm-rdp/kvm-rdp.toml >/dev/null
  rdp_port=$(docker port "$name" 3389/tcp | sed -n '1s/.*://p')
  admin_port=$(docker port "$name" 9464/tcp | sed -n '1s/.*://p')
  for _ in $(seq 100); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$admin_port/readyz")" = 200 ]; then
      return 0
    fi
    sleep 0.1
  done
  fail "not ready within 10 s as $1"
}

# An X.224 Connection Request carrying an RDP_NEG_REQ for $1
# (requestedProtocols, little-endian hex). Sets `reply` to what came back as
# hex — the 19-byte Connection Confirm, or less when the bridge closes — and
# `reply_status` to head's exit: 0 at 19 bytes or at the bridge's close, 124
# when neither came within 5 s.
negotiate() {
  local esc='' i
  for ((i = 0; i < ${#1}; i += 2)); do esc+="\\x${1:i:2}"; done
  exec 3<>"/dev/tcp/127.0.0.1/$rdp_port"
  # shellcheck disable=SC2059  # the format carries the request's own escapes
  printf "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00$esc" >&3
  reply_status=0
  timeout 5 head -c 19 <&3 >"$work/reply" || reply_status=$?
  exec 3<&- 3>&-
  reply=$(od -An -tx1 -v "$work/reply" | tr -d ' \n')
}

# A full Connection Confirm (status 0, 19 bytes) whose RDP_NEG_RSP selects $2.
selected() { # $1 = what, then the accepted protocols (hex, little-endian)
  local what=$1
  shift
  [ "$reply_status" = 0 ] && [ "${#reply}" = 38 ] || fail "$what: no Connection Confirm (status $reply_status): '$reply'"
  # Offsets in the hex reply: byte 11 is the RDP_NEG type (02 RSP, 03
  # FAILURE), bytes 15..18 the selected protocol.
  [ "${reply:22:2}" = 02 ] || fail "$what: not an RDP_NEG_RSP: '$reply'"
  local p
  for p in "$@"; do [ "${reply:30:8}" = "$p" ] && return 0; done
  fail "$what: selected ${reply:30:8}, want one of $*: '$reply'"
}

running_checks() { # $1 = uid:gid
  for path in /readyz /livez; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$admin_port$path")" = 200 ] ||
      fail "$path is not 200 unauthenticated as $1"
  done
  negotiate 03000000 # TLS | HYBRID: an NLA client
  selected "TLS|HYBRID as $1" 02000000
  negotiate 0b000000 # TLS | HYBRID | HYBRID_EX: Windows App's request
  selected "TLS|HYBRID|HYBRID_EX as $1" 02000000 08000000
  # TLS alone; standard RDP security. IronRDP at the pinned rev answers
  # neither with an RDP_NEG_FAILURE PDU: it returns before the write and
  # closes the connection (§9.1). A close is the refusal; a hang is not.
  for req in 01000000 00000000; do
    negotiate "$req"
    case $reply_status in
      0) ;;
      124) fail "requestedProtocols $req as $1: no answer and no close within 5 s" ;;
      *) fail "requestedProtocols $req as $1: reading the reply failed (status $reply_status)" ;;
    esac
    if [ "${#reply}" -ge 38 ]; then
      [ "${reply:22:2}" != 03 ] ||
        fail "requestedProtocols $req: IronRDP now answers RDP_NEG_FAILURE: update spec §9.1 ('$reply')"
      fail "requestedProtocols $req was answered with a protocol: '$reply'"
    fi
  done
  ok "as $1: /readyz and /livez 200; HYBRID selected; TLS-only and standard security closed unselected"
  local t0 t1 code logs
  t0=$(date +%s%N)
  docker stop -t 10 "$name" >/dev/null
  t1=$(date +%s%N)
  code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
  [ "$code" = 0 ] || fail "exit $code after SIGTERM as $1"
  [ $(((t1 - t0) / 1000000)) -le 6000 ] || fail "SIGTERM took $(((t1 - t0) / 1000000)) ms as $1"
  logs=$(docker logs "$name" 2>&1)
  grep -qF '"shutting down"' <<<"$logs" || fail "no shutdown line as $1"
  docker rm "$name" >/dev/null
  ok "as $1: SIGTERM → exit 0 in $(((t1 - t0) / 1000000)) ms"
}

for uid in 65532:65532 4242:4242; do
  start "$uid"
  running_checks "$uid"
done

# 4. Refused at load.
for f in hooks.toml mode.toml; do
  set +e
  out=$(docker run --rm --read-only --user 65532:65532 "${mounts[@]}" \
    "$image" --config "/etc/kvm-rdp/$f" 2>&1)
  code=$?
  set -e
  [ "$code" = 2 ] || fail "$f: exit $code, want 2: $out"
  grep -qF 'unknown key' <<<"$out" || fail "$f: the error does not say unknown key: $out"
done
ok "[test] hooks and a security-mode key are unknown keys (exit 2): no test-hooks, no other mode"
echo "image-smoke: every check passes"
```

`chmod +x scripts/image-smoke.sh`.

- [ ] **Step 3: Run the tests to see them fail.** `cargo test --workspace --all-features --lib -- bridge::tests::a_kubernetes_secret_swap` — Expected: PASS already (it pins behaviour the deployment relies on; `fingerprint` uses `std::fs::metadata`). If it fails, the watcher does not follow symlinks: fix `tls::fingerprint` to `std::fs::metadata` (never `symlink_metadata`) and say so in the commit. `scripts/image-smoke.sh kvm-rdp:ci` — Expected: FAIL (no such image).

- [ ] **Step 4: The Dockerfile and its context.** `.dockerignore` — an allowlist, so nothing else (captures, `.superpowers/`, `target/`, secrets) can enter the build context:

```gitignore
# Only what `cargo build -p kvm-rdp -p kvm-probe` reads (Plan E Task 4.1).
# An allowlist: captures/, .superpowers/, target/, spikes/ never enter the
# build context.
*
!Cargo.toml
!Cargo.lock
!rust-toolchain.toml
!.cargo/config.toml
!crates/
!fixtures/slate_1080p.h264
crates/**/target
```

`Dockerfile`:

```dockerfile
# kvm-rdp's container image (spec §4.1: it ships kvm-rdp and kvm-probe;
# Plan E Task 4.1, DE1). Build it with scripts/image-build.sh, which passes
# SOURCE_DATE_EPOCH (the commit time) and rewrite-timestamp=true on a
# pinned BuildKit, so one commit builds one image.
#
# Both bases are pinned by digest (scripts/check-workflows.sh refuses an
# unpinned one); bump them with scripts/pin-image.sh at the monthly IronRDP
# pin review (§4.2).
ARG BUILDER=docker.io/library/rust:1.94.1-slim-bookworm@pin
ARG RUNTIME=gcr.io/distroless/cc-debian12:nonroot@pin

FROM ${BUILDER} AS build
# The builder's 1.94.1, named so rustup ignores rust-toolchain.toml's extra
# components (no download in the build). CARGO_HOME is the image's.
ENV RUSTUP_TOOLCHAIN=1.94.1 \
    CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/target \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=false \
    CARGO_PROFILE_RELEASE_STRIP=debuginfo
# PC15 (Plan C final review, parked #9): no build path reaches an error
# message — IronRDP's errors render a source `Location` — so the registry
# and git checkouts read as /cargo, this tree as /kvm-rdp.
ENV RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/src=/kvm-rdp"
WORKDIR /src
COPY . .
# The release target, the registry and the git checkouts are deleted in the
# same RUN: BuildKit's cached layer then holds only /out, not several GiB of
# IronRDP's build on the host's root filesystem (§13; the image and its
# reproducibility are unchanged).
RUN cargo build --release --locked -p kvm-rdp -p kvm-probe --bins \
 && install -D -m 0755 /target/release/kvm-rdp /out/usr/local/bin/kvm-rdp \
 && install -D -m 0755 /target/release/kvm-probe /out/usr/local/bin/kvm-probe \
 && rm -rf /target /usr/local/cargo/registry /usr/local/cargo/git

FROM ${RUNTIME}
ARG REVISION=unknown
COPY --from=build /out/ /
# The condition §10.1's soak runs under; glibc reads it — the bridge itself
# reads no environment but KVM_RDP_CONFIG (§4.4).
ENV MALLOC_ARENA_MAX=2
# distroless's nonroot user, by number, so runAsNonRoot can verify it.
USER 65532:65532
EXPOSE 3389/tcp 9464/tcp
LABEL org.opencontainers.image.source="https://github.com/ChristopherJMiller/kvm-rdp" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.description="RDP bridge for the ES3 IP-KVM: kvm-rdp, with kvm-probe"
ENTRYPOINT ["/usr/local/bin/kvm-rdp"]
```

If the build reports that aws-lc-sys wants CMake, add `ENV AWS_LC_SYS_CMAKE_BUILDER=0` to the build stage (aws-lc-sys 0.45 builds with `cc` by default for x86_64-linux-gnu); never `apt-get install` anything — an unpinned package breaks reproducibility.

- [ ] **Step 5: The pins and the build script.** `scripts/pin-image.sh`:

```bash
#!/usr/bin/env bash
# Pin container images by digest (Plan E Task 4.1):
#   scripts/pin-image.sh REF             print REF@sha256:<index digest>
#   scripts/pin-image.sh --rewrite FILE… replace every `REF@pin` in FILE
# Bump with the monthly IronRDP pin review (spec §4.2). Needs docker buildx and jq.
set -euo pipefail
pin() {
  local digest
  digest=$(docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r .digest)
  grep -qE '^sha256:[0-9a-f]{64}$' <<<"$digest" || { echo "pin-image: no digest for $1" >&2; return 1; }
  printf '%s@%s\n' "$1" "$digest"
}
if [ "${1:-}" = "--rewrite" ]; then
  shift
  for f in "$@"; do
    { grep -oE '[a-z0-9.-]+\.[a-z]+/[A-Za-z0-9_./-]+:[A-Za-z0-9_.-]+@pin' "$f" || true; } | sort -u |
      while IFS= read -r ref; do
        p=$(pin "${ref%@pin}")
        sed -i "s|${ref}|${p}|" "$f"
        echo "pin-image: $f: $p"
      done
  done
else
  pin "${1:?usage: pin-image.sh REF | --rewrite FILE...}"
fi
```

`scripts/image-build.sh`:

```bash
#!/usr/bin/env bash
# Build kvm-rdp's image reproducibly (Plan E Task 4.1, DE1):
#   scripts/image-build.sh OUT.oci.tar [buildx args for the archive's build]
# writes the OCI archive CI's `publish` pushes and loads the same image as
# kvm-rdp:ci for scripts/image-smoke.sh. One commit builds one image: the
# Dockerfile's pinned bases, this BuildKit, SOURCE_DATE_EPOCH = the commit
# time, rewrite-timestamp, and no attestation manifests in the index. A tree
# with uncommitted changes in the build context is refused (it would ship
# under HEAD's revision and time) unless IMAGE_BUILD_DIRTY=1, which labels
# the image `<HEAD>-dirty`.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: image-build.sh OUT.oci.tar [buildx args...]}
shift
# moby/buildkit's buildx-stable channel, pinned by digest (check-workflows rule 6).
BUILDKIT_IMAGE=docker.io/moby/buildkit:buildx-stable-1@pin
builder=kvm-rdp-image
# What the build reads: .dockerignore's allowlist, and the two files that
# define the build.
context=(Dockerfile .dockerignore Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml
  crates fixtures/slate_1080p.h264)
revision=$(git rev-parse HEAD)
dirty=$(git status --porcelain -- "${context[@]}")
if [ -n "$dirty" ]; then
  if [ "${IMAGE_BUILD_DIRTY:-}" != 1 ]; then
    echo "image-build: uncommitted changes in the build context (IMAGE_BUILD_DIRTY=1 to build anyway, labelled -dirty):" >&2
    echo "$dirty" >&2
    exit 1
  fi
  revision=$revision-dirty
fi
# A builder made before a BUILDKIT_IMAGE bump keeps the old BuildKit: remake it.
info=$(docker buildx inspect "$builder" 2>/dev/null || true)
if [ -n "$info" ] && ! grep -qF "image=\"$BUILDKIT_IMAGE\"" <<<"$info"; then
  docker buildx rm "$builder" >/dev/null
  info=
fi
if [ -z "$info" ]; then
  # §13's politeness on the shared host: CPU shares 205 of 1024 (≈ the cargo
  # wrapper's CPUWeight 20) and 8 GiB, like `cargo` there.
  docker buildx create --name "$builder" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" --driver-opt cpu-shares=205 --driver-opt memory=8g >/dev/null
fi
common=(--builder "$builder" --platform linux/amd64 --provenance=false --sbom=false
  --build-arg "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)"
  --build-arg "REVISION=$revision")
docker buildx build "${common[@]}" "$@" --output "type=oci,dest=$out,rewrite-timestamp=true" .
docker buildx build "${common[@]}" --output "type=docker,name=kvm-rdp:ci,rewrite-timestamp=true" .
# The builder's cache lives on the host's root filesystem, outside
# target-budget.sh: keep it to 8 GB (the Dockerfile's RUN already drops the
# release target, the registry and git checkouts).
docker buildx prune --builder "$builder" --force --max-used-space 8gb >/dev/null
manifest=$(tar -xOf "$out" index.json | jq -r '.manifests[0].digest')
config=$(tar -xOf "$out" "blobs/sha256/${manifest#sha256:}" | jq -r '.config.digest')
config_json=$(tar -xOf "$out" "blobs/sha256/${config#sha256:}")
# The loaded image is the archive's: the same layers and creation time —
# what both image stores report alike. `.Id` is the config digest only in
# the classic store (under containerd's it is the manifest's), so it is
# compared only there.
want_layers=$(jq -c '.rootfs.diff_ids' <<<"$config_json")
want_created=$(jq -r '.created' <<<"$config_json")
got_layers=$(docker image inspect -f '{{json .RootFS.Layers}}' kvm-rdp:ci)
got_created=$(docker image inspect -f '{{.Created}}' kvm-rdp:ci)
if [ "$got_layers" != "$want_layers" ] || [ "$got_created" != "$want_created" ]; then
  echo "image-build: the loaded image is not the archive's: layers $got_layers vs $want_layers, created $got_created vs $want_created" >&2
  exit 1
fi
store=$(docker info 2>/dev/null || true)
if ! grep -qF io.containerd.snapshotter <<<"$store"; then
  loaded=$(docker image inspect -f '{{.Id}}' kvm-rdp:ci)
  if [ "$config" != "$loaded" ]; then
    echo "image-build: the loaded image ($loaded) is not the archive's ($config)" >&2
    exit 1
  fi
fi
echo "image-build: manifest $manifest, config $config, layers $got_layers"
```

Pin both files: `scripts/pin-image.sh --rewrite Dockerfile scripts/image-build.sh` — Expected: three `pin-image:` lines; `grep -n '@pin' Dockerfile scripts/image-build.sh` prints nothing; `nix develop --command scripts/check-workflows.sh` — Expected: `every rule holds` (rules 5–6 now see both files). Add `pkgs.curl` to the devshell's packages in `flake.nix` (the smoke test's HTTP client).

- [ ] **Step 6: Build and smoke-test.** First `df -h /` — Expected: ≥ 20 GiB free (an image build's disk is outside `target-budget.sh`; the root filesystem filled on 2026-10-11) — and `docker system df` (record it). `chmod +x scripts/pin-image.sh scripts/image-build.sh`. The task's own files are uncommitted until Step 8, so Step 6 builds with `IMAGE_BUILD_DIRTY=1` (both labels read `<HEAD>-dirty`, which the reproducibility comparison ignores); CI's checkouts are clean and never set it. First the refusal: `scripts/image-build.sh "$CARGO_TARGET_DIR/kvm-rdp.oci.tar"` without the variable — Expected: exit 1 with `image-build: uncommitted changes in the build context`, listing `Dockerfile`, `.dockerignore` and `crates/kvm-rdp/src/bridge.rs`, and no archive written. Then `IMAGE_BUILD_DIRTY=1 scripts/image-build.sh "$CARGO_TARGET_DIR/kvm-rdp.oci.tar"` (inside `nix develop`, for `jq`) — Expected: `image-build: manifest sha256:…, config sha256:…, layers [...]` (a cold build compiles the release graph inside BuildKit: allow 15–30 minutes on this host's 205 shares). `nix develop --command scripts/image-smoke.sh kvm-rdp:ci` — Expected: every `ok` line, then `image-smoke: every check passes`. Record in the commit body the image's `.Size` (`docker image inspect -f '{{.Size}}' kvm-rdp:ci`) and both binaries' sizes (the smoke test's "no build-host path" line prints them): the 64 MiB cap rests on no measurement yet. On a failure:
  - over `MAX_MIB`: do not stop the task. Report the three sizes; the controller rules a cap (proposed: the measured size × 1.25, rounded up to a multiple of 8 MiB), and the task continues with it. Thereafter the cap is the regression bound DE1 states;
  - a build path found: extend `RUSTFLAGS`' remaps to the prefix the grep printed;
  - a negotiation reply that is not what the spec says (for example IronRDP selecting `HYBRID_EX` for `03000000`, or an `03` RDP_NEG_FAILURE for TLS-only): stop and report the hex.
  The path check's own negative case (it must not fail open — under `pipefail` a `grep | head` would have): `cid=$(docker create kvm-rdp:ci) && docker cp "$cid:/usr/local/bin/kvm-probe" "$CARGO_TARGET_DIR/kvm-probe-copy" && docker rm "$cid"`, `printf '/usr/local/cargo/x' >>"$CARGO_TARGET_DIR/kvm-probe-copy"`, `nix develop --command scripts/image-smoke.sh --paths-only "$CARGO_TARGET_DIR/kvm-probe-copy"` — Expected: FAIL, printing `/usr/local/cargo/x` and naming the file; then `rm "$CARGO_TARGET_DIR/kvm-probe-copy"`.
  Then reproducibility, locally: `IMAGE_BUILD_DIRTY=1 scripts/image-build.sh "$CARGO_TARGET_DIR/kvm-rdp-2.oci.tar" --no-cache` and compare its printed manifest digest with the first build's — Expected: equal. A difference is a finding: find the differing layer (`tar -tvf` of both archives' layer blobs) before Task 4.2. Then delete both archives (`rm "$CARGO_TARGET_DIR"/kvm-rdp.oci.tar "$CARGO_TARGET_DIR"/kvm-rdp-2.oci.tar`), and record `docker system df` again beside the first one in the commit body (the builder's cache, pruned to 8 GB).

- [ ] **Step 7: README.** Add after `## Running`:

````markdown
## Container image

CI publishes the image from `main` only, as
`ghcr.io/christopherjmiller/kvm-rdp:sha-<commit>` — pin it with its digest,
`…:sha-<commit>@sha256:<digest>`. It is distroless (no shell, no package
manager), amd64, and runs as `65532:65532` on a read-only root filesystem
with no capabilities; it writes nothing.

    docker run --read-only --cap-drop ALL -v /etc/kvm-rdp:/etc/kvm-rdp:ro \
      -p 3389:3389 -p 9464:9464 \
      ghcr.io/christopherjmiller/kvm-rdp:sha-<commit>@sha256:<digest> \
      --config /etc/kvm-rdp/kvm-rdp.toml

- The entrypoint is `kvm-rdp`; `kvm-probe` is at `/usr/local/bin/kvm-probe`
  (its `capture` and `snapshot` decodes need ffmpeg and bubblewrap, which the
  image does not have).
- Mount the secrets as files and point the `*_file` keys at them by
  absolute path. A Kubernetes Secret volume works as mounted — no `subPath`
  — since a renewed certificate is seen through the `..data` symlink and the
  bridge exits 0 to be restarted once no client is connected (the smoke test
  runs the image with exactly that layout at `/run/secrets/kvm-rdp`). A
  Secret with `defaultMode: 0400` needs `fsGroup: 65532` (or the run's UID
  as owner) for the non-root process to read it.
- `MALLOC_ARENA_MAX=2` is set in the image: the condition its memory figures
  were measured under.
- One commit builds one image (`scripts/image-build.sh`); the nightly checks it.
````

(Task 4.2 adds how to verify the signature.)

- [ ] **Step 8: Gate and commit.** The per-task gate (the Secret-swap test is a lib test), with the image's feature-set clippy. `nix develop --command shellcheck scripts/*.sh && nix develop --command scripts/test-check-workflows.sh` — Expected: clean (the smoke test's `printf` format carries its one `# shellcheck disable=SC2059` directive; its request-escaping loop needs none).

```bash
git add Dockerfile .dockerignore scripts/pin-image.sh scripts/image-build.sh scripts/image-smoke.sh flake.nix \
  crates/kvm-rdp/src/bridge.rs README.md
git commit -m "image: distroless, non-root, reproducible, path-remapped; its smoke test; a Kubernetes Secret swap is a renewal (Plan E Task 4.1, PC15)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4.2: the image in CI — build and smoke on every PR, publish the tested archive from main, nightly reproducibility

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (`image`, `publish`), `.github/workflows/nightly.yml` (`image-build`, `reproducible`)
- Modify: `/home/chris/Repos/kvm-rdp/README.md` (verifying the signature)
- Test: `scripts/check-workflows.sh`, `scripts/test-check-workflows.sh`, actionlint; the owner's first push (CI check)

**Interfaces:**
- Consumes: Task 4.1's `scripts/image-build.sh`, `scripts/image-smoke.sh`; Task 2.1's rules (the write-permission guard).
- Produces: on every PR and push, the job `image` (read-only); on a push to main only, `publish`: `ghcr.io/christopherjmiller/kvm-rdp:sha-<first 7 of GITHUB_SHA>`, its digest in the job summary and the step output `digest`, a keyless cosign signature (cosign v3.0.6, the new bundle format) and a GitHub build-provenance attestation for that digest. Nightly: `image-build` ×2 (each keeping its archive and build log as `image-<run>` for 3 days) and `reproducible` (manifest, config and layer digests equal).

- [ ] **Step 1: The `image` job.** In `ci.yml`:

```yaml
  image:
    # Plan E Task 4.2: this commit's image, built reproducibly and smoke-tested
    # (scripts/image-build.sh, scripts/image-smoke.sh). On main its OCI
    # archive is what `publish` pushes — the tested bytes, never a rebuild.
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: Build (an OCI archive, and the same image loaded as kvm-rdp:ci)
        run: scripts/image-build.sh "$RUNNER_TEMP/kvm-rdp.oci.tar"
      - name: Smoke test
        run: scripts/image-smoke.sh kvm-rdp:ci
      - name: Keep the tested archive for publish
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@release
        with:
          name: kvm-rdp-image
          path: ${{ runner.temp }}/kvm-rdp.oci.tar
          retention-days: 3
          if-no-files-found: error
```

- [ ] **Step 2: The `publish` job.**

```yaml
  publish:
    # The one job with write permissions (design decision 10): a push to main,
    # after every gate. It runs no repository code — no checkout, no flake
    # (DE13's exception): only pinned actions, and the runner image's skopeo
    # and docker, on the archive the `image` job tested.
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [check, fuzz, lint, image]
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    env:
      IMAGE: ghcr.io/christopherjmiller/kvm-rdp
    steps:
      - uses: actions/download-artifact@release
        with:
          name: kvm-rdp-image
          path: ${{ runner.temp }}
      - name: Push the tested archive as sha-<short>, digests preserved
        id: push
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          archive="$RUNNER_TEMP/kvm-rdp.oci.tar"
          tag="$IMAGE:sha-${GITHUB_SHA::7}"
          # One login for skopeo, cosign and attest: attest reads only
          # ~/.docker/config.json, and skopeo falls back to it.
          printf '%s' "$TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
          skopeo copy --preserve-digests --format oci --digestfile "$RUNNER_TEMP/digest" \
            "oci-archive:$archive" "docker://$tag"
          pushed=$(cat "$RUNNER_TEMP/digest")
          tested=$(tar -xOf "$archive" index.json | jq -r '.manifests[0].digest')
          if [ "$pushed" != "$tested" ]; then
            echo "::error::pushed $pushed, but the image job tested $tested"
            exit 1
          fi
          echo "digest=$pushed" >> "$GITHUB_OUTPUT"
          {
            echo "### Published"
            echo
            echo "\`$tag@$pushed\`"
          } >> "$GITHUB_STEP_SUMMARY"
      - uses: sigstore/cosign-installer@release
        with:
          # Explicit: v3 signs in the new bundle format, which a v2 verifier
          # cannot find (the README says "cosign v3 or later").
          cosign-release: v3.0.6
      # Quoted: a plain YAML scalar cannot hold ": " (the colon after keyless).
      - name: "Sign the digest (keyless: this workflow's identity on main)"
        env:
          # A step output reaches the script as data, never as script text.
          DIGEST: ${{ steps.push.outputs.digest }}
        run: cosign sign --yes "$IMAGE@$DIGEST"
      - uses: actions/attest-build-provenance@release
        with:
          subject-name: ghcr.io/christopherjmiller/kvm-rdp
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
          # A user-owned repository: no artifact-metadata storage record
          # (which would need a fifth permission).
          create-storage-record: false
```

- [ ] **Step 3: Nightly reproducibility.** In `nightly.yml`:

```yaml
  image-build:
    # Two clean builds of the same commit on two runners (DE1): the digests
    # must match, or the image is not reproducible.
    strategy:
      matrix:
        run: [first, second]
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: A clean build
        run: |
          scripts/image-build.sh "$RUNNER_TEMP/i.oci.tar" --no-cache | tee "$RUNNER_TEMP/build.txt"
          mkdir -p "$RUNNER_TEMP/digests"
          manifest=$(tar -xOf "$RUNNER_TEMP/i.oci.tar" index.json | jq -r '.manifests[0].digest')
          echo "$manifest" > "$RUNNER_TEMP/digests/manifest"
          # The config digest from the archive, not the loaded image's .Id
          # (which is the manifest's under the containerd image store).
          tar -xOf "$RUNNER_TEMP/i.oci.tar" "blobs/sha256/${manifest#sha256:}" | jq -r '.config.digest' > "$RUNNER_TEMP/digests/config"
          docker image inspect -f '{{json .RootFS.Layers}}' kvm-rdp:ci > "$RUNNER_TEMP/digests/layers"
      - uses: actions/upload-artifact@release
        with:
          name: digests-${{ matrix.run }}
          path: ${{ runner.temp }}/digests
          retention-days: 14
      - name: Keep the archive and the build log (a mismatch needs both to diff)
        uses: actions/upload-artifact@release
        with:
          name: image-${{ matrix.run }}
          path: |
            ${{ runner.temp }}/i.oci.tar
            ${{ runner.temp }}/build.txt
          retention-days: 3

  reproducible:
    needs: image-build
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/download-artifact@release
        with:
          pattern: digests-*
          path: ${{ runner.temp }}/d
      - name: The two builds are one image
        run: |
          cd "$RUNNER_TEMP/d"
          for f in config manifest layers; do
            echo "$f: $(cat digests-first/$f) / $(cat digests-second/$f)"
            diff digests-first/$f digests-second/$f
          done
```

- [ ] **Step 4: Pin and check.** `nix develop --command scripts/pin-action.sh --rewrite .github/workflows/ci.yml .github/workflows/nightly.yml` — Expected: `actions/checkout` and `actions/upload-artifact` take ci.yml's existing pins verbatim, and only `actions/download-artifact`, `sigstore/cosign-installer` and `actions/attest-build-provenance` are resolved — then `nix develop --command scripts/check-workflows.sh`, `nix develop --command scripts/test-check-workflows.sh`, `nix develop --command actionlint` — Expected: clean (`publish` asks for write permissions and reads `secrets.GITHUB_TOKEN` under exactly the push-to-main guard: rules 4 and 9 hold; actionlint parses the quoted step name, and its shellcheck passes every `run:`).

- [ ] **Step 5: README.** Under `## Container image`, add:

````markdown
Each published image is signed keyless by this repository's CI on `main`, with
a build-provenance attestation (verify with cosign v3 or later; the signature
is in the new bundle format):

    cosign verify ghcr.io/christopherjmiller/kvm-rdp@sha256:<digest> \
      --certificate-identity-regexp '^https://github.com/ChristopherJMiller/kvm-rdp/\.github/workflows/ci\.yml@refs/heads/main$' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify oci://ghcr.io/christopherjmiller/kvm-rdp@sha256:<digest> \
      --repo ChristopherJMiller/kvm-rdp

A commit whose CI run was superseded while queued (GitHub keeps one pending
run per concurrency group) has no image; pin a published one.
````

- [ ] **Step 6: Commit.**

```bash
git add .github/workflows/ci.yml .github/workflows/nightly.yml README.md
git commit -m "ci: build and smoke-test the image on every PR; publish the tested archive from main, signed and attested; nightly reproducibility (Plan E Task 4.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**CI check** (owner): on the PR, `image` green; after the merge to main, `publish` green with `ghcr.io/christopherjmiller/kvm-rdp:sha-<short>@sha256:…` in its summary, `cosign verify` (above, with cosign v3) run once by the owner and passing, `gh attestation verify` passing, and the package's visibility public in its GitHub package settings (a new package is private by default; the cluster pulls anonymously unless luma-homeops adds a pull secret). The nightly's `reproducible` green.

---
## Part 5 — kvm-bench and the perf pass (§10, Milestone 6)

§10.2's harness: "kvm-sim and the measuring client in one process (shared `Instant` epoch); the bridge as a subprocess", FrameIds, a lean EGFX client with shaping, bench streams generated on demand, absolute targets serially on a dedicated runner and loose ones per PR. Task 5.1 builds the crate and the unshaped run that measures most of §10.1; Tasks 5.2–5.4 add the scenarios; Task 5.5 the soak and CI.

### Task 5.1: kvm-bench — the pure library, the bench streams, the client, the bridge subprocess, and the unshaped run

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-bench/Cargo.toml`
- Create: `crates/kvm-bench/src/lib.rs`, `src/stats.rs`, `src/prom.rs`, `src/report.rs`, `src/frames.rs` (pure, unit-tested)
- Create: `crates/kvm-bench/src/main.rs`, `src/bridge.rs`, `src/client.rs`, `src/streams.rs`, `src/scenarios.rs` (IO)
- Modify: `/home/chris/Repos/kvm-rdp/scripts/gen-fixtures.sh` (`bench` mode)
- Test: the library's unit tests; the `unshaped` run (Step 9)

**Interfaces:**
- Consumes: kvm-sim (`KvmSim::start`, `SimConfig::es3`, `Source::from_annex_b`, `stamped_events`, `stats`, `ports`, `host`, `spki_sha256`, `password`, `inject(Fault::Silence)`); kvm-proto (`h264::{frame_id, is_vcl, split_annex_b}`); the bridge binary's ready line (`{"fields":{"message":"kvm-rdp ready","rdp":…,"admin":…}}`) and `/metrics` (Task 1.4's `kvm_rdp_allocations_total` in an `alloc-stats` build).
- Produces (later tasks build on these names):
  - `kvm_bench::stats::{percentile(&[f64], f64) -> Option<f64>, Summary { n, p50, p99, max }, summarize(&[f64]) -> Option<Summary>, slope(&[(f64, f64)]) -> Option<f64>}`.
  - `kvm_bench::prom::Scrape` — `parse(&str)`, `get(&str) -> f64`, `has(&str) -> bool`, `delta(&Scrape, &str) -> f64`, `fraction_le(&Scrape, histogram, le) -> Option<f64>`, `family_delta(&Scrape, family, label) -> BTreeMap<String, f64>`.
  - `kvm_bench::report::{Thresholds::{Strict, Ci}, Thresholds::{factor, timing_factor}, Report}` — `Report::{new, perf_at_most, timing_at_most, at_most, at_least, within, holds, number, note, passed}`; a report serialises to JSON.
  - `kvm_bench::frames::{latencies, unique_loop, input_latencies}`.
  - Binary: `bridge::{Bridge, NLA_PASSWORD, USER, clk_tck, rss_kib_of}` — `Bridge::spawn(bin, &KvmSim, extra_toml) -> Result<Bridge, String>` (the child dies with kvm-bench and dumps no core), `rdp`, `admin`, `pid()`, `scrape().await`, `cpu_ticks()`, `rss_kib()`, `lines()`, `sigterm()`, `wait(Duration).await -> Option<ExitStatus>`; `pub fn rss_kib_of(pid: u32) -> Option<u64>` (`VmRSS`, for Task 5.5's sampler thread); `client::{BenchClient, Opts, Shape, AckMode, Rx, Log}` — `BenchClient::connect(addr, Opts)`, `shape(|&mut Shape|)`, `with_log(|&Log|)`, `until(limit, pred).await -> bool`, `key(scancode, pressed)`, `readvertise()`, `close()`; `streams::{dir() -> PathBuf, load(name) -> Result<Source, String>}`; `scenarios::{Ctx, run(name, &Ctx), CI, ALL, Session, session(..), Mark, mark(&Session).await, window_checks(&mut Report, &Session, &Mark, &Mark), source_ids(&Source) -> Vec<u64>, sim_sent(&KvmSim) -> Vec<(u64, Instant)>}`. Task 5.2 adds `kvm_proto::keymap::usage_for_scancode` to its own imports (its first user).
  - Bench streams in `${CARGO_TARGET_DIR:-target}/bench-streams/`: `bench_1080p30.h264`, `bench_1080p60.h264`, `bench_720p30.h264`, `bench_720p60.h264` (§10.2's four; nothing reads the last yet), `idle_motion_1080p30.h264`.
  - CLI: `kvm-bench --bridge PATH [--thresholds ci|strict] [--out DIR] [--soak-duration D] [--churn-every D] SCENARIO…` (`ci`, `all` are sets); exit 0 iff every report passed.

- [ ] **Step 1: The crate, and the library's failing tests.** `crates/kvm-bench/Cargo.toml`:

```toml
[package]
name = "kvm-bench"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false
autotests = false
autobins = false
autoexamples = false

# The pure half — statistics, the /metrics parser, thresholds, the matchers
# — with its unit tests; it uses no IronRDP, so its test binary links none
# (§13, design decision 12).
[lib]
name = "kvm_bench"
path = "src/lib.rs"
doctest = false

# The IO half: kvm-sim, the client, the bridge subprocess, the null bridge.
# No unit tests: it would be a third IronRDP-linked test executable (§13).
[[bin]]
name = "kvm-bench"
path = "src/main.rs"
test = false
bench = false

[dependencies]
kvm-proto = { path = "../kvm-proto" }
kvm-sim = { path = "../kvm-sim" }
# The client crates L2 already compiles, at the workspace pin (§4.2), and
# ironrdp-server for the null bridge (Task 5.4) — egfx only.
ironrdp-async = { workspace = true }
ironrdp-cliprdr = { workspace = true }
ironrdp-connector = { workspace = true }
ironrdp-core = { workspace = true }
ironrdp-dvc = { workspace = true }
ironrdp-egfx = { workspace = true }
ironrdp-graphics = { workspace = true }
ironrdp-pdu = { workspace = true }
ironrdp-server = { workspace = true }
ironrdp-session = { workspace = true }
ironrdp-svc = { workspace = true }
ironrdp-tls = { workspace = true, features = ["rustls"] }
ironrdp-tokio = { workspace = true, features = ["reqwest"] }
async-trait = "0.1"
clap = { version = "4", features = ["derive"] }
libc = "0.2"
# default features would pull in ring (§4.2)
rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs", "pem"] }
# `logging` and tokio's `signal` as the bridge (`-p kvm-rdp`) resolves them,
# so tokio, rustls and aws-lc-sys build once for both release binaries
# (§13's 8 GiB); kvm-bench's client crates still turn on `bitflags/std`,
# `ironrdp-tls/rustls` and the like, so about 50 units — most `ironrdp-*`
# crates — build twice (measured at drafting).
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12", "logging"] }
serde = { version = "1", features = ["derive"] }
serde_json = { workspace = true }
tempfile = "3"
tokio = { version = "1", features = ["rt", "rt-multi-thread", "net", "io-util", "macros", "time", "sync", "signal"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
x509-parser = "0.16"
```

`src/lib.rs`:

```rust
//! kvm-bench's pure half (spec §10.2; Plan E design decision 12): the
//! statistics, the `/metrics` parser, a scenario's report and its
//! thresholds, and the frame and input matchers. The binary does the IO.
pub mod frames;
pub mod prom;
pub mod report;
pub mod stats;
```

Each module below is written with its tests first; the bodies come in Step 3.

`src/stats.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_nearest_rank_in_any_order() {
        let xs: Vec<f64> = (1..=100).rev().map(f64::from).collect();
        assert_eq!(percentile(&xs, 50.0), Some(50.0));
        assert_eq!(percentile(&xs, 99.0), Some(99.0));
        assert_eq!(percentile(&xs, 100.0), Some(100.0));
        assert_eq!(percentile(&[7.0], 99.0), Some(7.0));
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&xs, 0.0), None);
        let s = summarize(&xs).unwrap();
        assert_eq!((s.n, s.p50, s.p99, s.max), (100, 50.0, 99.0, 100.0));
    }

    #[test]
    fn the_slope_of_a_line_is_its_gradient() {
        let pts: Vec<(f64, f64)> = (0..10).map(|i| (f64::from(i), 2.0 * f64::from(i) + 1.0)).collect();
        assert!((slope(&pts).unwrap() - 2.0).abs() < 1e-9);
        assert_eq!(slope(&[(1.0, 1.0)]), None);
        assert_eq!(slope(&[(1.0, 1.0), (1.0, 2.0)]), None, "no spread in x");
    }
}
```

`src/prom.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "# HELP kvm_rdp_sessions_total s\n# TYPE kvm_rdp_sessions_total counter\n\
        kvm_rdp_sessions_total 1\nkvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 2\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 90\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"+Inf\"} 100\n\
        kvm_rdp_enqueue_latency_seconds_count 100\nkvm_rdp_egfx_in_flight 7\n";
    const TWO: &str = "kvm_rdp_sessions_total 1\nkvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 5\n\
        kvm_rdp_frames_dropped_total{reason=\"paused\"} 1\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 289\n\
        kvm_rdp_enqueue_latency_seconds_count 300\n";

    #[test]
    fn a_scrape_parses_its_series_and_skips_comments() {
        let s = Scrape::parse(ONE);
        assert_eq!(s.get("kvm_rdp_sessions_total"), 1.0);
        assert_eq!(s.get("kvm_rdp_egfx_in_flight"), 7.0);
        assert_eq!(s.get("kvm_rdp_absent_total"), 0.0);
        assert!(!s.has("kvm_rdp_absent_total"));
        assert_eq!(s.get("kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"), 2.0);
    }

    #[test]
    fn deltas_fractions_and_families_are_between_two_scrapes() {
        let (a, b) = (Scrape::parse(ONE), Scrape::parse(TWO));
        assert_eq!(b.delta(&a, "kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"), 3.0);
        let f = b.fraction_le(&a, "kvm_rdp_enqueue_latency_seconds", "0.005").unwrap();
        assert!((f - 199.0 / 200.0).abs() < 1e-9);
        assert_eq!(a.fraction_le(&a, "kvm_rdp_enqueue_latency_seconds", "0.005"), None);
        let d = b.family_delta(&a, "kvm_rdp_frames_dropped_total", "reason");
        assert_eq!(d.get("soft_gate"), Some(&3.0));
        assert_eq!(d.get("paused"), Some(&1.0));
    }
}
```

`src/report.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_loosens_performance_bounds_tenfold_and_timing_bounds_by_half() {
        let mut r = Report::new("t", Thresholds::Ci);
        r.perf_at_most("cpu percent", 40.0, 5.0);
        r.timing_at_most("ended within s", 20.0, 15.5);
        r.at_most("unmatched fraction", 0.5, 0.01);
        assert_eq!(r.checks.iter().map(|c| c.pass).collect::<Vec<_>>(), [true, true, false]);
        assert!(!r.passed());
        let mut s = Report::new("t", Thresholds::Strict);
        s.perf_at_most("cpu percent", 4.0, 5.0);
        s.within("bitrate", 8.4e6, 8e6, 0.10);
        s.at_least("fraction under 5 ms", 0.995, 0.99);
        s.holds("alive", true);
        s.number("p50 ms", 1.5);
        assert!(s.passed());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"thresholds\":\"strict\"") && json.contains("\"p50 ms\":1.5"), "{json}");
    }
}
```

`src/frames.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn a_frame_matches_the_latest_send_of_its_id_before_it_arrived() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        // A two-frame loop sent twice; the client got the second loop's.
        let sent = [(1, ms(0)), (2, ms(33)), (1, ms(66)), (2, ms(99))];
        let received = [(1, ms(70)), (2, ms(104)), (9, ms(110))];
        let (lat, unmatched) = latencies(&sent, &received);
        assert_eq!(lat, [4.0, 5.0]);
        assert_eq!(unmatched, 1);
    }

    #[test]
    fn a_loop_needs_unique_ids_and_ten_seconds() {
        let ids: Vec<u64> = (0..300).collect();
        assert!(unique_loop(&ids, 30, 10.0).is_ok());
        assert!(unique_loop(&ids[..299], 30, 10.0).is_err(), "9.97 s");
        let mut dup = ids.clone();
        dup[150] = 3;
        assert!(unique_loop(&dup, 30, 10.0).is_err());
    }

    #[test]
    fn each_press_meets_the_first_report_of_its_key_after_it() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        let kbd = |usage: u8| vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, usage, 0, 0, 0, 0];
        let zero = kbd(0);
        let presses = [(0x04, ms(10)), (0x05, ms(60)), (0x06, ms(110))];
        let reports = vec![
            (ms(5), kbd(0x04)), // before its press: not it
            (ms(12), kbd(0x04)),
            (ms(13), zero.clone()),
            (ms(63), kbd(0x05)),
            (ms(64), zero),
        ];
        let (lat, missed) = input_latencies(&presses, &reports);
        assert_eq!(lat, [2.0, 3.0]);
        assert_eq!(missed, 1);
    }
}
```

- [ ] **Step 2: Run them to see them fail.** `cargo test --workspace --all-features --lib -- stats:: prom:: report:: frames::` — Expected: FAIL to compile (the functions do not exist). (The binary does not exist yet: give `src/main.rs` a one-line `fn main() {}` so the crate builds.)

- [ ] **Step 3: The library.** `src/stats.rs`:

```rust
//! Percentiles and the soak's slope (§10.1).
use serde::Serialize;

/// The nearest-rank `p`th percentile (0 < p ≤ 100) of `xs`, in any order.
#[must_use]
pub fn percentile(xs: &[f64], p: f64) -> Option<f64> {
    if xs.is_empty() || !(p > 0.0 && p <= 100.0) {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let rank = (p / 100.0 * v.len() as f64).ceil() as usize;
    v.get(rank.clamp(1, v.len()) - 1).copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    pub n: usize,
    pub p50: f64,
    pub p99: f64,
    pub max: f64,
}

#[must_use]
pub fn summarize(xs: &[f64]) -> Option<Summary> {
    Some(Summary {
        n: xs.len(),
        p50: percentile(xs, 50.0)?,
        p99: percentile(xs, 99.0)?,
        max: percentile(xs, 100.0)?,
    })
}

/// The least-squares slope of `(x, y)`; `None` without two distinct x.
#[must_use]
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let (sx, sy) = points.iter().fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let (num, den) = points.iter().fold((0.0, 0.0), |(a, b), (x, y)| {
        (a + (x - mx) * (y - my), b + (x - mx) * (x - mx))
    });
    (den > 0.0).then(|| num / den)
}
```

`src/prom.rs`:

```rust
//! One `/metrics` scrape — §4.5's Prometheus text as the bridge renders it.
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scrape(pub BTreeMap<String, f64>);

impl Scrape {
    /// Every `series value` line; comments and unparsable lines skipped.
    #[must_use]
    pub fn parse(text: &str) -> Scrape {
        Scrape(
            text.lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| {
                    let (series, value) = l.rsplit_once(' ')?;
                    Some((series.to_owned(), value.trim().parse().ok()?))
                })
                .collect(),
        )
    }

    /// A series' value; 0 when absent — a family renders a label only once
    /// it is counted, and a counter starts at 0.
    #[must_use]
    pub fn get(&self, series: &str) -> f64 {
        self.0.get(series).copied().unwrap_or(0.0)
    }

    #[must_use]
    pub fn has(&self, series: &str) -> bool {
        self.0.contains_key(series)
    }

    #[must_use]
    pub fn delta(&self, earlier: &Scrape, series: &str) -> f64 {
        self.get(series) - earlier.get(series)
    }

    /// Of a histogram's observations between `earlier` and this scrape, the
    /// fraction at or under `le` (written as the bridge renders it, "0.005").
    #[must_use]
    pub fn fraction_le(&self, earlier: &Scrape, histogram: &str, le: &str) -> Option<f64> {
        let count = self.delta(earlier, &format!("{histogram}_count"));
        let under = self.delta(earlier, &format!("{histogram}_bucket{{le=\"{le}\"}}"));
        (count > 0.0).then(|| under / count)
    }

    /// A labelled counter's moves between `earlier` and now: label value → delta.
    #[must_use]
    pub fn family_delta(&self, earlier: &Scrape, family: &str, label: &str) -> BTreeMap<String, f64> {
        let prefix = format!("{family}{{{label}=\"");
        self.0
            .keys()
            .filter_map(|k| {
                let v = k.strip_prefix(&prefix)?.strip_suffix("\"}")?;
                let d = self.delta(earlier, k);
                (d != 0.0).then(|| (v.to_owned(), d))
            })
            .collect()
    }
}
```

`src/report.rs`:

```rust
//! A scenario's report, and §10.2's thresholds: absolute (`strict`) on a
//! dedicated runner, 10× looser (`ci`) per PR.
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Thresholds {
    Strict,
    Ci,
}

impl Thresholds {
    /// §10.2: "CI runs the harness with loose thresholds that catch 10×
    /// regressions."
    #[must_use]
    pub fn factor(self) -> f64 {
        match self {
            Thresholds::Strict => 1.0,
            Thresholds::Ci => 10.0,
        }
    }

    /// DE10: a stalled-client timing bound loosens 1.5× under `ci`.
    #[must_use]
    pub fn timing_factor(self) -> f64 {
        match self {
            Thresholds::Strict => 1.0,
            Thresholds::Ci => 1.5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub value: f64,
    pub bound: String,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub scenario: String,
    pub thresholds: Thresholds,
    pub checks: Vec<Check>,
    pub numbers: BTreeMap<String, f64>,
    pub notes: Vec<String>,
}

impl Report {
    #[must_use]
    pub fn new(scenario: &str, thresholds: Thresholds) -> Report {
        Report {
            scenario: scenario.to_owned(),
            thresholds,
            checks: Vec::new(),
            numbers: BTreeMap::new(),
            notes: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, value: f64, bound: String, pass: bool) {
        self.checks.push(Check { name: name.to_owned(), value, bound, pass });
    }

    /// A §10.1 performance bound, loosened by `factor`.
    pub fn perf_at_most(&mut self, name: &str, value: f64, bound: f64) {
        let b = bound * self.thresholds.factor();
        self.push(name, value, format!("<= {b}"), value <= b);
    }

    /// A stalled-client timing bound, loosened by `timing_factor` (DE10).
    pub fn timing_at_most(&mut self, name: &str, value: f64, bound: f64) {
        let b = bound * self.thresholds.timing_factor();
        self.push(name, value, format!("<= {b}"), value <= b);
    }

    /// Exact bounds no threshold loosens: delivery, bitrate, uniqueness, survival.
    pub fn at_most(&mut self, name: &str, value: f64, bound: f64) {
        self.push(name, value, format!("<= {bound}"), value <= bound);
    }

    pub fn at_least(&mut self, name: &str, value: f64, bound: f64) {
        self.push(name, value, format!(">= {bound}"), value >= bound);
    }

    pub fn within(&mut self, name: &str, value: f64, target: f64, fraction: f64) {
        let pass = (value - target).abs() <= target * fraction;
        self.push(name, value, format!("{target} ± {}%", fraction * 100.0), pass);
    }

    pub fn holds(&mut self, name: &str, ok: bool) {
        self.push(name, if ok { 1.0 } else { 0.0 }, "true".to_owned(), ok);
    }

    pub fn number(&mut self, name: &str, value: f64) {
        self.numbers.insert(name.to_owned(), value);
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
}
```

`src/frames.rs`:

```rust
//! §10.2's matchers: received frames to kvm-sim's sends by FrameId, and
//! client key presses to the HID reports kvm-sim read.
use std::collections::HashMap;
use std::time::Instant;

/// End-to-end latencies in ms: each received `(frame_id, arrival)` minus
/// the latest send of that id at or before the arrival (a looped source
/// sends each id once per loop); and how many arrivals matched no send.
#[must_use]
pub fn latencies(sent: &[(u64, Instant)], received: &[(u64, Instant)]) -> (Vec<f64>, usize) {
    let mut by_id: HashMap<u64, Vec<Instant>> = HashMap::new();
    for (id, at) in sent {
        by_id.entry(*id).or_default().push(*at);
    }
    for v in by_id.values_mut() {
        v.sort();
    }
    let (mut out, mut unmatched) = (Vec::with_capacity(received.len()), 0);
    for (id, at) in received {
        let tx = by_id.get(id).and_then(|v| {
            let i = v.partition_point(|t| t <= at);
            i.checked_sub(1).and_then(|j| v.get(j))
        });
        match tx {
            Some(tx) => out.push(at.duration_since(*tx).as_secs_f64() * 1000.0),
            None => unmatched += 1,
        }
    }
    (out, unmatched)
}

/// §10.2's load check: FrameIds unique within one loop, the loop at least
/// `min_secs` long at `fps`.
pub fn unique_loop(ids: &[u64], fps: u32, min_secs: f64) -> Result<(), String> {
    let secs = ids.len() as f64 / f64::from(fps);
    if secs < min_secs {
        return Err(format!("the loop is {secs:.2} s, under {min_secs} s"));
    }
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    match ids.iter().position(|id| !seen.insert(*id)) {
        Some(i) => Err(format!("frame {i}'s FrameId repeats within the loop")),
        None => Ok(()),
    }
}

/// Input latencies in ms (§10.1): each press `(usage, written)` against the
/// first keyboard report (§3.3: `AA AA 08 …`, first key slot at byte 7) at
/// or after it carrying that usage, each report used once, in order; and
/// how many presses met none.
#[must_use]
pub fn input_latencies(presses: &[(u8, Instant)], reports: &[(Instant, Vec<u8>)]) -> (Vec<f64>, usize) {
    let (mut out, mut missed, mut cursor) = (Vec::new(), 0, 0);
    for (usage, sent) in presses {
        let hit = reports[cursor..].iter().position(|(at, b)| {
            at >= sent && b.len() >= 8 && b[2] == 0x08 && b[7] == *usage
        });
        match hit {
            Some(i) => {
                out.push(reports[cursor + i].0.duration_since(*sent).as_secs_f64() * 1000.0);
                cursor += i + 1;
            }
            None => missed += 1,
        }
    }
    (out, missed)
}
```

- [ ] **Step 4: Run the library's tests.** `cargo test --workspace --all-features --lib -- stats:: prom:: report:: frames::` — Expected: PASS (8 tests in `kvm_bench`).

- [ ] **Step 5: The bench streams.** In `scripts/gen-fixtures.sh`, before the `case`:

```bash
# §10.2's bench streams (Plan E Task 5.1, DE10): testsrc2 under full-frame
# noise at 8 Mbit/s capped (no filler), the barcode drawn over the noise,
# an IDR every second, 20 s each — loops of at least 10 s — into the shared
# target dir. -threads 4 (§13), so not deterministic: nothing pins their
# bytes, and kvm-bench checks what it needs (unique FrameIds, the bitrate).
# sliced-threads=0, as every other fixture: -tune zerolatency with -threads 4
# would cut each AU into four slices, which no ES3 stream does; and
# -filter_threads 4, or the lavfi graph takes one thread per CPU (§13).
bench_enc() { # OUT SIZE FPS BLOCK_W BLOCK_H SOURCE NOISE — SOURCE ends in = or : (its options follow)
  "${FF[@]}" -filter_threads 4 -f lavfi -i "${6}size=$2:rate=$3" \
    -vf "$7,$(barcode "$4" "$5"),scale=out_color_matrix=bt709:out_range=pc,format=yuv420p" \
    -t 20 -an -c:v libx264 -preset veryfast -tune zerolatency -profile:v main -level:v 4.2 \
    -bf 0 -threads 4 \
    -x264-params "sliced-threads=0:keyint=$3:min-keyint=$3:scenecut=0:aud=1:repeat-headers=1:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=pc" \
    -b:v 8M -maxrate 8M -bufsize 8M -f h264 "$1"
}
bench() {
  local d=${CARGO_TARGET_DIR:-target}/bench-streams
  mkdir -p "$d"
  # 30 and 60 fps at two resolutions (§10.2; 720p for resize churn).
  bench_enc "$d/bench_1080p30.h264" 1920x1080 30 120 64 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_1080p60.h264" 1920x1080 60 120 64 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_720p30.h264" 1280x720 30 80 48 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_720p60.h264" 1280x720 60 80 48 "testsrc2=" "noise=alls=60:allf=t"
  # Idle → motion (§10.2): 10 s of a still grey screen (only the barcode
  # changes), then 10 s of noise.
  bench_enc "$d/idle_motion_1080p30.h264" 1920x1080 30 120 64 "color=c=0x404040:" \
    "noise=alls=60:allf=t:enable='gte(t,10)'"
}
```

add `bench) bench ;;` to the `case` and `bench` to the usage line and the header comment. `nix develop --command scripts/gen-fixtures.sh bench` — Expected: five files of about 20 MB each (the idle-motion one smaller) in `$CARGO_TARGET_DIR/bench-streams/`, in under five minutes.

- [ ] **Step 6: The bridge subprocess and the streams.** `src/bridge.rs`:

```rust
//! The bridge under test as a subprocess (§10.2): its config and secrets in
//! a temp dir pointed at kvm-sim; its ready line, `/metrics` and
//! `/proc/<pid>`. Its environment is cleared but for MALLOC_ARENA_MAX=2 —
//! §10.1's soak condition, and the image's.
use kvm_bench::prom::Scrape;
use kvm_sim::KvmSim;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const USER: &str = "kvm";
pub const NLA_PASSWORD: &str = "kvm-bench-nla-password-0123456789";

pub struct Bridge {
    child: Child,
    _dir: tempfile::TempDir,
    pub rdp: SocketAddr,
    pub admin: SocketAddr,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Bridge {
    /// `extra` is TOML appended to the config (whole tables: `[video]`, …).
    pub fn spawn(bin: &Path, sim: &KvmSim, extra: &str) -> Result<Bridge, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(|e| e.to_string())?;
        let write = |name: &str, text: String| std::fs::write(dir.path().join(name), text).map_err(|e| e.to_string());
        write("cert.pem", ck.cert.pem())?;
        write("key.pem", ck.key_pair.serialize_pem())?;
        write("nla.pass", format!("{NLA_PASSWORD}\n"))?;
        write("kvm.pass", format!("{}\n", sim.password()))?;
        let p = sim.ports();
        write(
            "kvm-rdp.toml",
            format!(
                "[rdp]\nlisten = \"127.0.0.1:0\"\nusername = \"{USER}\"\nnla_password_file = \"nla.pass\"\n\
                 tls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\n[admin]\nlisten = \"127.0.0.1:0\"\n\
                 [kvm]\nhost = \"{}\"\nspki_sha256 = \"{}\"\npassword_file = \"kvm.pass\"\n\
                 web_port = {}\nvideo_port = {}\ncontrol_port = {}\n{extra}",
                sim.host(),
                sim.spki_sha256(),
                p.web,
                p.video,
                p.control
            ),
        )?;
        let mut cmd = Command::new(bin);
        cmd.arg("--config")
            .arg(dir.path().join("kvm-rdp.toml"))
            .env_clear()
            .env("MALLOC_ARENA_MAX", "2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure runs in the forked child before exec and calls
        // only prctl(2) and setrlimit(2), both async-signal-safe; it touches
        // nothing of the parent's but its own stack.
        unsafe {
            cmd.pre_exec(|| {
                // kvm-bench is release, `panic = "abort"`: a panic never runs
                // `Drop for Bridge`. The bridge gets SIGTERM when the thread
                // that spawned it dies (a runtime worker or the main thread
                // — never call this from a blocking-pool thread), so none is
                // left running at nice 0 on the shared host.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // No core dump of Task 5.3's deliberate SIGABRT on a root
                // filesystem that has filled before (systemd-coredump).
                let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", bin.display()))?;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (out, l) = (child.stdout.take().ok_or("no stdout")?, lines.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(a) = ready_addrs(&line) {
                    let _ = tx.send(a);
                }
                l.lock().unwrap().push(line);
            }
        });
        let (err, l) = (child.stderr.take().ok_or("no stderr")?, lines.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                l.lock().unwrap().push(line);
            }
        });
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok((rdp, admin)) => Ok(Bridge { child, _dir: dir, rdp, admin, lines }),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(format!("the bridge never got ready: {:?}", lines.lock().unwrap()))
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// utime + stime of the process, in clock ticks (`/proc/<pid>/stat`).
    pub fn cpu_ticks(&self) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid())).ok()?;
        let after = stat.rsplit_once(')')?.1;
        let f: Vec<&str> = after.split_whitespace().collect();
        // Fields 14 and 15 of proc(5); `after` starts at field 3.
        Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
    }

    /// `VmRSS` in KiB.
    pub fn rss_kib(&self) -> Option<u64> {
        rss_kib_of(self.pid())
    }

    pub async fn scrape(&self) -> Result<Scrape, String> {
        let admin = self.admin;
        let get = async move {
            let mut s = tokio::net::TcpStream::connect(admin).await.map_err(|e| e.to_string())?;
            s.write_all(b"GET /metrics HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            let (_, body) = text.split_once("\r\n\r\n").ok_or("no /metrics body")?;
            Ok::<_, String>(Scrape::parse(body))
        };
        tokio::time::timeout(Duration::from_secs(3), get)
            .await
            .map_err(|_| "/metrics timed out".to_owned())?
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    pub fn sigterm(&self) {
        if let Ok(pid) = libc::pid_t::try_from(self.pid()) {
            // SAFETY: kill(2) on our own child.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }

    /// The child's exit, if it comes within `limit` (polled; never blocks
    /// the runtime).
    pub async fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
        let t0 = Instant::now();
        loop {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            if t0.elapsed() > limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `VmRSS` of `pid` in KiB (`/proc/<pid>/status`): a free function, so
/// Task 5.5's sampler thread can read it without the `Bridge`.
pub fn rss_kib_of(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().strip_suffix("kB")?.trim().parse().ok())
}

fn ready_addrs(line: &str) -> Option<(SocketAddr, SocketAddr)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["fields"]["message"] != "kvm-rdp ready" {
        return None;
    }
    Some((v["fields"]["rdp"].as_str()?.parse().ok()?, v["fields"]["admin"].as_str()?.parse().ok()?))
}

/// Clock ticks per second (`sysconf(_SC_CLK_TCK)`).
pub fn clk_tck() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as f64 } else { 100.0 }
}
```

`src/streams.rs`:

```rust
//! §10.2's bench streams, generated on demand by `scripts/gen-fixtures.sh
//! bench` into the shared target dir and never committed.
use kvm_sim::Source;
use std::path::{Path, PathBuf};

pub fn dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("bench-streams")
}

pub fn load(name: &str) -> Result<Source, String> {
    let path = dir().join(name);
    let data = std::fs::read(&path).map_err(|e| {
        format!("{}: {e} — generate the bench streams: scripts/gen-fixtures.sh bench", path.display())
    })?;
    Source::from_annex_b(name, &data).map_err(|e| format!("{name}: {e:?}"))
}
```

- [ ] **Step 7: The client.** `src/client.rs` (its connection code follows L2's `tests/l2/client.rs`, which compiles against the same pin — keep the two in step on a pin bump):

```rust
//! kvm-bench's RDP client (§10.2; DE10): IronRDP's connector with NLA over
//! TLS and a lean EGFX `DvcProcessor` — ZGFX, decode, one `Rx` per frame at
//! its EndFrame (FrameId, arrival, IDR, VCL bytes), acks per `Shape` —
//! plus fast-path keys and, for the soak's paste, a CLIPRDR text holder.
//! Not L2's client: that one records every PDU for its oracles, which at
//! 1080p60 would be the measurement. Each client has its own thread and
//! runtime and binds `127.0.0.<source>` (Preempt's per-address cooldown).
use crate::bridge::{NLA_PASSWORD, USER};
use ironrdp_async::FramedWrite as _;
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use ironrdp_connector::connection_activation::{ConnectionActivationFactory, ConnectionActivationState};
use ironrdp_connector::{ClientConnector, ConnectionResult, Credentials, DesktopSize};
use ironrdp_core::{ReadCursor, WriteBuf, decode, decode_cursor, impl_as_any};
use ironrdp_dvc::{DrdynvcClient, DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, CapabilitiesAdvertisePdu, CapabilityVersion, FrameAcknowledgePdu, GfxPdu,
    QueueDepth, RawCapabilitySet,
};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::zgfx::Decompressor;
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::{PduResult, gcc};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::ChannelFlags;
use kvm_proto::h264::{frame_id, is_vcl, split_annex_b};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

type Upgraded = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;
type Acks = Arc<Mutex<VecDeque<(Instant, FrameAcknowledgePdu)>>>;

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckMode {
    Normal,
    /// Never acknowledge (a stalled client).
    Withhold,
    /// Acknowledge with `queue_depth = SUSPEND` (MS-RDPEGFX 2.2.2.13).
    Suspend,
}

/// §10.2's in-process shaping, changeable while connected.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    pub ack: AckMode,
    pub ack_delay: Duration,
    /// Read at most this many bits per second.
    pub read_bps: Option<u64>,
    pub reading: bool,
}

impl Default for Shape {
    fn default() -> Shape {
        Shape { ack: AckMode::Normal, ack_delay: Duration::ZERO, read_bps: None, reading: true }
    }
}

/// One frame, at its EndFrame.
#[derive(Debug, Clone, Copy)]
pub struct Rx {
    pub frame_id: u64,
    pub at: Instant,
    pub idr: bool,
    pub vcl_bytes: usize,
}

#[derive(Debug, Default)]
pub struct Log {
    pub connected: Option<Instant>,
    pub ended: Option<(Instant, String)>,
    pub rx: Vec<Rx>,
    /// Each key press, `(scancode, written)` — when its PDU's write returned.
    pub keys: Vec<(u8, Instant)>,
    pub last_read: Option<Instant>,
}

pub struct Opts {
    pub source: u8,
    pub caps: Vec<RawCapabilitySet>,
    pub clipboard: Option<String>,
}

impl Opts {
    pub fn new(source: u8) -> Opts {
        Opts { source, caps: census_caps(), clipboard: None }
    }
}

/// FreeRDP's `/gfx:AVC420` pair (census.md, Legs B and C).
pub fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

enum Ctl {
    Key(u8, bool),
    Readvertise,
    Close,
}

pub struct BenchClient {
    log: Arc<Mutex<Log>>,
    shape: Arc<Mutex<Shape>>,
    ctl: mpsc::UnboundedSender<Ctl>,
}

impl BenchClient {
    pub fn connect(server: SocketAddr, opts: Opts) -> BenchClient {
        let (log, shape) = (Arc::new(Mutex::new(Log::default())), Arc::new(Mutex::new(Shape::default())));
        let (ctl, rx) = mpsc::unbounded_channel();
        let (l, s) = (log.clone(), shape.clone());
        let source = opts.source;
        std::thread::Builder::new()
            .name(format!("bench-client-{source}"))
            .spawn(move || run(server, opts, l, s, rx))
            .expect("spawn the client thread");
        BenchClient { log, shape, ctl }
    }

    pub fn shape(&self, f: impl FnOnce(&mut Shape)) {
        f(&mut lock(&self.shape));
    }

    pub fn with_log<R>(&self, f: impl FnOnce(&Log) -> R) -> R {
        f(&lock(&self.log))
    }

    /// Until `pred` holds over the log (polled every 20 ms), or `limit`.
    pub async fn until(&self, limit: Duration, pred: impl Fn(&Log) -> bool) -> bool {
        let t0 = Instant::now();
        loop {
            if self.with_log(&pred) {
                return true;
            }
            if t0.elapsed() > limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn key(&self, scancode: u8, pressed: bool) {
        let _ = self.ctl.send(Ctl::Key(scancode, pressed));
    }

    pub fn readvertise(&self) {
        let _ = self.ctl.send(Ctl::Readvertise);
    }

    pub fn close(&self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

impl Drop for BenchClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn end(log: &Arc<Mutex<Log>>, why: String) {
    let mut l = lock(log);
    if l.ended.is_none() {
        l.ended = Some((Instant::now(), why));
    }
}

fn config() -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size: DesktopSize { width: 1920, height: 1080 },
        monitor_layout: None,
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword { username: USER.to_owned(), password: NLA_PASSWORD.to_owned() },
        domain: None,
        client_build: 0,
        client_name: "kvm-bench".to_owned(),
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
        support_dyn_vc_gfx_protocol: true,
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::SUPPORTED,
    }
}

async fn connect(
    server: SocketAddr,
    opts: &Opts,
    capture: Capture,
    clip: mpsc::UnboundedSender<ClipboardMessage>,
) -> Result<(Upgraded, ConnectionResult), String> {
    let socket = TcpSocket::new_v4().map_err(|e| e.to_string())?;
    socket
        .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, opts.source), 0)))
        .map_err(|e| format!("bind: {e}"))?;
    let tcp = socket.connect(server).await.map_err(|e| format!("connect: {e}"))?;
    tcp.set_nodelay(true).map_err(|e| e.to_string())?;
    let client_addr = tcp.local_addr().map_err(|e| e.to_string())?;
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config(), client_addr)
        .with_static_channel(DrdynvcClient::new().with_dynamic_channel(capture));
    if let Some(text) = &opts.clipboard {
        let backend = ClientClip { text: text.clone(), proxy: ClipProxy(clip) };
        connector = connector.with_static_channel(CliprdrClient::new(Box::new(backend)));
    }
    let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| format!("begin: {e}"))?;
    let (upgraded, cert) = ironrdp_tls::upgrade_with_certificate_validation(
        framed.into_inner_no_leftover(),
        "localhost",
        ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate,
    )
    .await
    .map_err(|e| format!("tls: {e}"))?;
    let marked = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
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

/// The Deactivation-Reactivation Sequence (a server resize), as L2's client.
async fn reactivate(framed: &mut Upgraded, factory: &ConnectionActivationFactory, stage: &mut ActiveStage) -> Result<(), String> {
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
            return Ok(());
        }
    }
}

async fn sleep_until(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t.into()).await,
        None => std::future::pending().await,
    }
}

fn run(server: SocketAddr, opts: Opts, log: Arc<Mutex<Log>>, shape: Arc<Mutex<Shape>>, mut ctl: mpsc::UnboundedReceiver<Ctl>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("client runtime");
    rt.block_on(async move {
        let acks: Acks = Arc::default();
        let capture = Capture {
            caps: opts.caps.clone(),
            log: log.clone(),
            shape: shape.clone(),
            acks: acks.clone(),
            zgfx: Decompressor::new(),
            decoded: 0,
            pending: None,
        };
        let (clip_tx, mut clip_rx) = mpsc::unbounded_channel();
        let (mut framed, result) =
            match tokio::time::timeout(Duration::from_secs(10), connect(server, &opts, capture, clip_tx)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return end(&log, e),
                Err(_) => return end(&log, "connect timeout".to_owned()),
            };
        lock(&log).connected = Some(Instant::now());
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
        // EGFX only: no bitmap update ever lands here.
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 1920, 1080);
        // §10.2's shaped link (pre-flight E62): a link of `read_bps` the
        // client reads through. Each PDU holds the link for len·8/bps after
        // it arrives, so an IDR serialises as on a real link, and no credit
        // accumulates while the source is quiet; a change of rate starts
        // the link afresh. While the link is busy the read arm is off and a
        // wake arm waits for it, so acks still fall due and go out.
        let (mut link_free, mut link_bps) = (Instant::now(), None::<u64>);
        let mut clip_open = true;
        loop {
            let s = *lock(&shape);
            if s.read_bps != link_bps {
                (link_free, link_bps) = (Instant::now(), s.read_bps);
            }
            let link_open = link_bps.is_none() || Instant::now() >= link_free;
            let next_ack = lock(&acks).front().map(|(t, _)| *t);
            tokio::select! {
                c = ctl.recv() => match c {
                    Some(Ctl::Key(code, pressed)) => {
                        let flags = if pressed { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
                        let out = match stage.process_fastpath_input(&mut image, &[FastPathInputEvent::KeyboardEvent(flags, code)]) {
                            Ok(o) => o,
                            Err(e) => return end(&log, format!("input: {e}")),
                        };
                        for o in out {
                            if let ActiveStageOutput::ResponseFrame(f) = o
                                && framed.write_all(&f).await.is_err()
                            {
                                return end(&log, "write".to_owned());
                            }
                        }
                        if pressed {
                            lock(&log).keys.push((code, Instant::now()));
                        }
                    }
                    Some(Ctl::Readvertise) => {
                        let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                        let msg: DvcMessage = Box::new(GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(opts.caps.clone())));
                        match ironrdp_dvc::encode_dvc_messages(cid, vec![msg], ChannelFlags::empty())
                            .map_err(|e| e.to_string())
                            .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()))
                        {
                            Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                            Err(e) => return end(&log, format!("readvertise: {e}")),
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
                        return end(&log, "client".to_owned());
                    }
                },
                // Delayed acks (§10.2's ack delay): each sent when due, in order.
                () = sleep_until(next_ack) => {
                    let now = Instant::now();
                    let mut due: Vec<DvcMessage> = Vec::new();
                    {
                        let mut q = lock(&acks);
                        while q.front().is_some_and(|(t, _)| *t <= now) {
                            if let Some((_, a)) = q.pop_front() {
                                due.push(Box::new(GfxPdu::FrameAcknowledge(a)));
                            }
                        }
                    }
                    let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                    match ironrdp_dvc::encode_dvc_messages(cid, due, ChannelFlags::empty())
                        .map_err(|e| e.to_string())
                        .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()))
                    {
                        Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                        Err(e) => return end(&log, format!("ack: {e}")),
                    }
                }
                m = clip_rx.recv(), if clip_open => {
                    let Some(m) = m else { clip_open = false; continue };
                    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                    let msgs = match m {
                        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
                        ClipboardMessage::SendFormatData(r) => cliprdr.submit_format_data(r),
                        _ => continue,
                    };
                    match msgs.map_err(|e| e.to_string()).and_then(|m| stage.process_svc_processor_messages(m).map_err(|e| e.to_string())) {
                        Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                        Err(e) => return end(&log, format!("cliprdr: {e}")),
                    }
                }
                () = tokio::time::sleep_until(link_free.into()), if s.reading && !link_open => {}
                pdu = framed.read_pdu(), if s.reading && link_open => {
                    let (action, frame) = match pdu {
                        Ok(v) => v,
                        Err(e) => return end(&log, format!("read: {e}")),
                    };
                    lock(&log).last_read = Some(Instant::now());
                    if let Some(bps) = link_bps {
                        link_free = Instant::now() + Duration::from_secs_f64(frame.len() as f64 * 8.0 / bps as f64);
                    }
                    let outputs = match stage.process(&mut image, action, &frame) {
                        Ok(o) => o,
                        Err(e) => return end(&log, format!("process: {e}")),
                    };
                    for o in outputs {
                        match o {
                            ActiveStageOutput::ResponseFrame(f) => {
                                if framed.write_all(&f).await.is_err() {
                                    return end(&log, "write".to_owned());
                                }
                            }
                            ActiveStageOutput::DeactivateAll => {
                                if let Err(e) = reactivate(&mut framed, &factory, &mut stage).await {
                                    return end(&log, e);
                                }
                            }
                            ActiveStageOutput::Terminate(reason) => return end(&log, reason.description()),
                            _ => {}
                        }
                    }
                }
            }
        }
    });
}

/// EGFX's client side: one `Rx` per frame, acks per `Shape`.
struct Capture {
    caps: Vec<RawCapabilitySet>,
    log: Arc<Mutex<Log>>,
    shape: Arc<Mutex<Shape>>,
    acks: Acks,
    zgfx: Decompressor,
    decoded: u32,
    /// The frame between its WireToSurface1 and its EndFrame.
    pending: Option<(u64, bool, usize)>,
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
        if self.zgfx.decompress(payload, &mut plain).is_err() {
            return Ok(Vec::new());
        }
        let mut cur = ReadCursor::new(&plain);
        let mut replies: Vec<DvcMessage> = Vec::new();
        while !cur.is_empty() {
            let Ok(pdu) = decode_cursor::<GfxPdu>(&mut cur) else { break };
            match pdu {
                GfxPdu::WireToSurface1(w) => {
                    if let Ok(s) = decode::<Avc420BitmapStream<'_>>(&w.bitmap_data) {
                        let vcl = || split_annex_b(s.data).filter(|n| n.first().is_some_and(|b| is_vcl(b & 0x1F)));
                        let idr = vcl().any(|n| n.first().is_some_and(|b| b & 0x1F == 5));
                        let bytes = vcl().map(<[u8]>::len).sum();
                        self.pending = Some((frame_id(vcl()), idr, bytes));
                    }
                }
                GfxPdu::EndFrame(end) => {
                    let at = Instant::now();
                    if let Some((frame_id, idr, vcl_bytes)) = self.pending.take() {
                        lock(&self.log).rx.push(Rx { frame_id, at, idr, vcl_bytes });
                    }
                    self.decoded = self.decoded.wrapping_add(1);
                    let s = *lock(&self.shape);
                    let depth = match s.ack {
                        AckMode::Normal => Some(QueueDepth::Unavailable),
                        AckMode::Suspend => Some(QueueDepth::Suspend),
                        AckMode::Withhold => None,
                    };
                    if let Some(queue_depth) = depth {
                        let ack = FrameAcknowledgePdu { queue_depth, frame_id: end.frame_id, total_frames_decoded: self.decoded };
                        if s.ack_delay.is_zero() {
                            replies.push(Box::new(GfxPdu::FrameAcknowledge(ack)));
                        } else {
                            lock(&self.acks).push_back((at + s.ack_delay, ack));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(replies)
    }
}

impl DvcClientProcessor for Capture {}

#[derive(Debug)]
struct ClipProxy(mpsc::UnboundedSender<ClipboardMessage>);

impl ClipboardMessageProxy for ClipProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let _ = self.0.send(message);
    }
}

/// The soak's clipboard (Task 5.5): offers CF_UNICODETEXT, answers with
/// its text — as L2's `ClientClip`, without the log.
struct ClientClip {
    text: String,
    proxy: ClipProxy,
}

impl_as_any!(ClientClip);

impl std::fmt::Debug for ClientClip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientClip").field("text_len", &self.text.len()).finish_non_exhaustive()
    }
}

impl CliprdrBackend for ClientClip {
    fn temporary_directory(&self) -> &str {
        "."
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }
    fn on_ready(&mut self) {}
    fn on_request_format_list(&mut self) {
        self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(
            ClipboardFormatId::CF_UNICODETEXT,
        )]));
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {}
    fn on_format_data_request(&mut self, req: FormatDataRequest) {
        let answer = if req.format == ClipboardFormatId::CF_UNICODETEXT {
            OwnedFormatDataResponse::new_unicode_string(&self.text)
        } else {
            OwnedFormatDataResponse::new_error()
        };
        self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(answer));
    }
    fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}
```

- [ ] **Step 8: The scenario runner, `unshaped`, and the CLI.** `src/scenarios.rs`:

```rust
//! §10.2's scenarios. Each returns a `Report`; `run` picks one by name.
use crate::bridge::{Bridge, clk_tck};
use crate::client::{BenchClient, Opts};
use crate::streams;
use kvm_bench::frames::{latencies, unique_loop};
use kvm_bench::prom::Scrape;
use kvm_bench::report::{Report, Thresholds};
use kvm_bench::stats::summarize;
use kvm_proto::h264::{frame_id, is_vcl};
use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Ctx {
    pub bridge: PathBuf,
    pub thresholds: Thresholds,
    pub soak_duration: Duration,
    pub churn_every: Duration,
}

/// The per-PR set and every scenario but the soak (§10.2). Tasks 5.2–5.4
/// add their names.
pub const CI: &[&str] = &["unshaped"];
pub const ALL: &[&str] = &["unshaped"];

pub async fn run(name: &str, cx: &Ctx) -> Result<Report, String> {
    match name {
        "unshaped" => unshaped(cx).await,
        other => Err(format!("no scenario {other:?}")),
    }
}

/// A live session: kvm-sim over `cfg`, the bridge with `extra`, one client
/// with a picture.
pub struct Session {
    pub client: BenchClient,
    pub bridge: Bridge,
    pub sim: KvmSim,
}

pub async fn session(cx: &Ctx, cfg: SimConfig, extra: &str, opts: Opts) -> Result<Session, String> {
    // A KVM picture, not the "Connecting…" slate (an AVC420 frame too): a
    // frame whose FrameId is the source's, so a broken KVM leg fails here.
    let ids: std::collections::HashSet<u64> = source_ids(&cfg.source).into_iter().collect();
    let sim = KvmSim::start(cfg).await.map_err(|e| e.to_string())?;
    let bridge = Bridge::spawn(&cx.bridge, &sim, extra)?;
    let client = BenchClient::connect(bridge.rdp, opts);
    if !client.until(Duration::from_secs(15), |l| l.rx.iter().any(|x| ids.contains(&x.frame_id))).await {
        return Err(format!("no KVM picture within 15 s: {:?}", client.with_log(|l| l.ended.clone())));
    }
    Ok(Session { client, bridge, sim })
}

/// A source's FrameIds over the VCL NALs kvm-sim sends (§10.2).
pub fn source_ids(src: &Source) -> Vec<u64> {
    src.frames
        .iter()
        .map(|f| frame_id(f.nals.iter().filter(|n| n.first().is_some_and(|b| is_vcl(b & 0x1F))).map(|n| n.as_ref())))
        .collect()
}

/// What kvm-sim sent, `(frame_id, sim_tx)`.
pub fn sim_sent(sim: &KvmSim) -> Vec<(u64, Instant)> {
    sim.stamped_events()
        .into_iter()
        .filter_map(|(t, e)| match e {
            SimEvent::FlvAu { frame_id, .. } => Some((frame_id, t)),
            _ => None,
        })
        .collect()
}

/// One point of a measured window.
pub struct Mark {
    pub m: Scrape,
    pub cpu: u64,
    pub at: Instant,
    pub rx: usize,
}

pub async fn mark(s: &Session) -> Result<Mark, String> {
    Ok(Mark {
        m: s.bridge.scrape().await?,
        cpu: s.bridge.cpu_ticks().ok_or("no /proc stat")?,
        at: Instant::now(),
        rx: s.client.with_log(|l| l.rx.len()),
    })
}

/// The checks every live window carries (§10.1, §10.2, PC17 m2).
pub fn window_checks(r: &mut Report, s: &Session, a: &Mark, b: &Mark) {
    // Counters and histograms always render, so a missing series is a
    // rename — which would read as 0, a silent pass or a misleading fail.
    for series in [
        "kvm_rdp_egfx_frames_sent_total",
        "kvm_rdp_egfx_frames_acked_total",
        "kvm_rdp_enqueue_latency_seconds_count",
        "kvm_rdp_kvm_frame_bytes_count",
    ] {
        r.holds(&format!("the bridge exports {series}"), b.m.has(series));
    }
    let secs = b.at.duration_since(a.at).as_secs_f64();
    let frames = b.m.delta(&a.m, "kvm_rdp_egfx_frames_sent_total");
    r.number("frames sent", frames);
    r.number("window s", secs);
    r.number(
        "channel_full drops per minute (PC17 m2)",
        b.m.delta(&a.m, "kvm_rdp_frames_dropped_total{reason=\"channel_full\"}") / secs * 60.0,
    );
    for (reason, n) in b.m.family_delta(&a.m, "kvm_rdp_frames_dropped_total", "reason") {
        r.number(&format!("dropped {reason}"), n);
    }
    let block = s.sim.stats().max_flv_write_block.as_secs_f64() * 1000.0;
    r.at_most("max kvm-sim FLV write block, ms (§10.2: the KVM never sees back-pressure)", block, 100.0);
    r.holds("the session is alive", s.client.with_log(|l| l.ended.is_none()));
}

/// §10.1's unshaped targets on the 1080p30 8 Mbit/s bench stream: video
/// latency, CPU, allocations per frame, delivery, the forwarded bitrate,
/// FrameId uniqueness, and the end-to-end latency (for information).
async fn unshaped(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("unshaped", cx.thresholds);
    let src = streams::load("bench_1080p30.h264")?;
    let loop_ok = unique_loop(&source_ids(&src), 30, 10.0);
    r.holds("FrameIds unique within a loop of ≥ 10 s (§10.2)", loop_ok.is_ok());
    if let Err(e) = loop_ok {
        r.note(e);
    }
    let s = session(cx, SimConfig::es3(src), "", Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(20)).await;
    let b = mark(&s).await?;
    // The source stops (the FLV stays open: 3 s is well under
    // flv_idle_timeout's 10 s), so 3 s on, every frame sent has been acked
    // or is lost: §10.1's "Delivery 1.0" reads as nothing left in flight.
    s.sim.inject(kvm_sim::Fault::Silence);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let c = s.bridge.scrape().await?;
    window_checks(&mut r, &s, &a, &b);
    let secs = b.at.duration_since(a.at).as_secs_f64();
    let frames = b.m.delta(&a.m, "kvm_rdp_egfx_frames_sent_total");
    // Bridge video latency p99 < 5 ms: the enqueue-latency histogram (§10.1).
    let le = if cx.thresholds == Thresholds::Strict { "0.005" } else { "0.05" };
    let under = b.m.fraction_le(&a.m, "kvm_rdp_enqueue_latency_seconds", le).unwrap_or(0.0);
    r.at_least(&format!("enqueue latency: fraction ≤ {le} s (p99 < {le} s)"), under, 0.99);
    // CPU < 5 % of one core at 1080p30, 8 Mbit/s; and per Mbit/s.
    let cpu = (b.cpu - a.cpu) as f64 / clk_tck() / secs * 100.0;
    r.perf_at_most("CPU, % of one core", cpu, 5.0);
    // Whole-process allocations ≤ 40 + bytes/1590 per frame (alloc-stats).
    let bytes = b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_sum") / b.m.delta(&a.m, "kvm_rdp_kvm_frame_bytes_count").max(1.0);
    if b.m.has("kvm_rdp_allocations_total") {
        let per_frame = b.m.delta(&a.m, "kvm_rdp_allocations_total") / frames.max(1.0);
        r.perf_at_most("allocations per frame (whole process)", per_frame, 40.0 + bytes / 1590.0);
    } else {
        r.holds("the bridge is an alloc-stats build", false);
    }
    // Delivery 1.0: 3 s after the source stopped, no frame is in flight —
    // every frame the bridge sent was acked (the gauge refreshes after every
    // step). The ratio is information: the slate's ack is counted in acked,
    // never in sent.
    r.holds(
        "delivery 1.0: no frame in flight 3 s after the source stops",
        c.has("kvm_rdp_egfx_in_flight") && c.get("kvm_rdp_egfx_in_flight") == 0.0,
    );
    r.number(
        "frames acked / frames sent, window start to 3 s after the source stopped",
        c.delta(&a.m, "kvm_rdp_egfx_frames_acked_total") / c.delta(&a.m, "kvm_rdp_egfx_frames_sent_total").max(1.0),
    );
    // The forwarded VCL bitrate within ±10 % of 8 Mbit/s (§10.2).
    let (rx, vcl_bits) = s.client.with_log(|l| {
        let w: Vec<_> = l.rx.iter().filter(|x| x.at >= a.at && x.at <= b.at).copied().collect();
        let bits: f64 = w.iter().map(|x| x.vcl_bytes as f64 * 8.0).sum();
        (w, bits)
    });
    r.within("forwarded VCL bit/s", vcl_bits / secs, 8e6, 0.10);
    r.number("CPU % per Mbit/s", cpu / (vcl_bits / secs / 1e6));
    // End to end, sim_tx → EndFrame parsed (information, §10.1).
    let got: Vec<(u64, Instant)> = rx.iter().map(|x| (x.frame_id, x.at)).collect();
    let (lat, unmatched) = latencies(&sim_sent(&s.sim), &got);
    r.at_most("frames matching no kvm-sim send, fraction", unmatched as f64 / got.len().max(1) as f64, 0.01);
    if let Some(e) = summarize(&lat) {
        r.number("end-to-end p50 ms", e.p50);
        r.number("end-to-end p99 ms", e.p99);
    }
    Ok(r)
}
```

`src/main.rs`:

```rust
//! kvm-bench (spec §10.2): kvm-sim and a lean IronRDP client in this
//! process, the bridge under test as a subprocess — a release build with
//! `--features alloc-stats,test-hooks`:
//!   kvm-bench --bridge target/release/kvm-rdp [--thresholds ci|strict] [--out DIR] SCENARIO...
//! `ci` and `all` name scenario sets. Each scenario writes `<name>.json`;
//! the exit status is 0 only if every check of every report passed.
// The harness's API: Tasks 5.2–5.5's scenarios use what `unshaped` does not
// (as tests/l2/client.rs). `allow`, not `expect`: an `expect` would warn as
// unfulfilled once Task 5.5 uses everything.
#[allow(dead_code)]
mod bridge;
#[allow(dead_code)]
mod client;
#[allow(dead_code)]
mod scenarios;
mod streams;

use clap::{Parser, ValueEnum};
use kvm_bench::report::Thresholds;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Ci,
    Strict,
}

#[derive(Parser)]
#[command(about = "kvm-rdp's perf harness (spec §10.2)")]
struct Args {
    /// The bridge under test: built --release --features alloc-stats,test-hooks.
    #[arg(long)]
    bridge: PathBuf,
    /// strict: §10.1's absolute targets; ci: 10× looser (§10.2).
    #[arg(long, value_enum, default_value = "ci")]
    thresholds: Mode,
    /// Where each report goes, as <scenario>.json.
    #[arg(long, default_value = "target/kvm-bench")]
    out: PathBuf,
    /// The soak's length (Task 5.5; CI only at 60m, §13).
    #[arg(long, default_value = "60m", value_parser = duration)]
    soak_duration: Duration,
    /// The soak's churn period (§10.1: every 5 minutes).
    #[arg(long, default_value = "5m", value_parser = duration)]
    churn_every: Duration,
    /// Scenario names, or `ci` (the per-PR set) or `all` (all but the soak).
    #[arg(required = true)]
    scenarios: Vec<String>,
}

fn duration(s: &str) -> Result<Duration, String> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().map_err(|_| format!("{s:?} is not a duration like 90s or 60m"))?;
    match unit {
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        _ => Err(format!("{s:?} is not a duration like 90s or 60m")),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let cx = scenarios::Ctx {
        bridge: args.bridge,
        thresholds: match args.thresholds {
            Mode::Ci => Thresholds::Ci,
            Mode::Strict => Thresholds::Strict,
        },
        soak_duration: args.soak_duration,
        churn_every: args.churn_every,
    };
    let names: Vec<String> = args
        .scenarios
        .iter()
        .flat_map(|n| match n.as_str() {
            "ci" => scenarios::CI.iter().map(|s| (*s).to_owned()).collect(),
            "all" => scenarios::ALL.iter().map(|s| (*s).to_owned()).collect(),
            other => vec![other.to_owned()],
        })
        .collect();
    if std::fs::create_dir_all(&args.out).is_err() {
        eprintln!("kvm-bench: cannot create {}", args.out.display());
        return ExitCode::FAILURE;
    }
    let mut all_passed = true;
    for name in names {
        let t0 = std::time::Instant::now();
        let report = match scenarios::run(&name, &cx).await {
            Ok(r) => r,
            Err(e) => {
                let mut r = kvm_bench::report::Report::new(&name, cx.thresholds);
                r.holds("the scenario ran", false);
                r.note(e);
                r
            }
        };
        let path = args.out.join(format!("{name}.json"));
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap_or_default());
        let failed: Vec<&str> = report.checks.iter().filter(|c| !c.pass).map(|c| c.name.as_str()).collect();
        println!(
            "kvm-bench: {name}: {} in {:.0} s{} ({})",
            if report.passed() { "PASS" } else { "FAIL" },
            t0.elapsed().as_secs_f64(),
            if failed.is_empty() { String::new() } else { format!(" — {}", failed.join("; ")) },
            path.display()
        );
        all_passed &= report.passed();
    }
    if all_passed { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
```

- [ ] **Step 9: Build and run it.** `cargo clippy --workspace --all-targets --all-features -- -D warnings` — Expected: clean (kvm-bench included). The two release builds (named exceptions): `nix develop --command cargo build --release --locked -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp` and `nix develop --command cargo build --release --locked -p kvm-bench --bin kvm-bench`. Then, at nice 0 pinned to two CPUs (§10.2), recording the load first:

```bash
uptime
nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" \
  --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci --out "$CARGO_TARGET_DIR/kvm-bench" unshaped'
```

Expected: `kvm-bench: unshaped: PASS`, and `$CARGO_TARGET_DIR/kvm-bench/unshaped.json` with every number filled. (The devshell's `cargo` is the niced wrapper; the bench binary itself runs at the shell's nice 0.) A FAIL is read before it is fixed: the forwarded bitrate outside ±10 % means the bench stream is not what §10.2 asks (regenerate, or report the encoder's rate); unmatched FrameIds over 1 % means the client and kvm-sim disagree on which NALs a FrameId covers (compare `source_ids` with one received frame's NAL types); a performance check over even the `ci` bound is a finding to report with the JSON.

- [ ] **Step 10: The budget, then commit.** `scripts/target-budget.sh` — the release artifacts are new: Expected: under 8 GiB; record the size in the commit body, with `du -sh "$CARGO_TARGET_DIR/debug" "$CARGO_TARGET_DIR/release"` separately (kvm-bench's `signal` and `logging` features make tokio, rustls and aws-lc-sys build once for both release binaries; about 50 units — most `ironrdp-*` crates — still build twice, since kvm-bench's client crates turn on `bitflags/std`, `ironrdp-tls/rustls` and the like). If over: `scripts/target-budget.sh --prune`, then report the size before anything else (never raise the budget).

```bash
git add crates/kvm-bench scripts/gen-fixtures.sh Cargo.lock
git commit -m "kvm-bench: the pure library, bench streams, the lean client, the bridge subprocess, and the unshaped run (Plan E Task 5.1, §10.1, §10.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5.2: input latency under 1080p60 with bursts; shaped links, the RTT spike, idle → motion; NeedIdr entries

§10.1's input target ("Client writes an input PDU → kvm-sim reads the HID frame (same-process epoch), while 1080p60 video with IDRs and a source burst is flowing") and §10.2's scenarios ("unshaped; 50 ms / 20 Mbit/s; 150 ms / 5 Mbit/s; a 2 s RTT spike; an idle → motion transition. Reports NeedIdr entries per minute, drops by reason and time-to-picture after each spike"). NeedIdr entries need a counter (DE4).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-rdp/src/pump/core.rs` (`need_idr` on entry), `src/metrics.rs` (`kvm_rdp_need_idr_total`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-bench/src/scenarios.rs` (five scenarios)
- Test: `pump::core::tests::entries_into_need_idr_are_counted_once_each`, `metrics::tests`; the five runs (Step 5)

**Interfaces:**
- Consumes: Task 5.1's `Session`, `session`, `mark`, `window_checks`, `sim_sent`, `streams::load`, `BenchClient::{key, shape}`, `frames::{latencies, input_latencies}`; kvm-proto's `keymap::usage_for_scancode` (first used here); kvm-sim's `Profile { fps, burst_on_connect, .. }`, `Fault::Close`, `SimEvent::Hid`.
- Produces: metric `kvm_rdp_need_idr_total` (`Metrics::need_idr`), counted on each entry into `State::NeedIdr` — family count **47** (20 counters, 13 families, 9 gauges, 5 histograms), +2 counters in an `alloc-stats` build (49 under `--all-features`). Scenarios `input-latency`, `shaped-50ms-20mbit`, `shaped-150ms-5mbit`, `rtt-spike`, `idle-motion`; `CI` becomes `["unshaped", "input-latency"]`, `ALL` gains all five.

- [ ] **Step 1: Write the failing test.** In `core.rs`'s tests (`FlvOrigin` comes in with the rig's imports; add `use crate::msg::FlvOrigin;` if not):

```rust
    /// Plan E Task 5.2 (DE4, §10.2's NeedIdr entries per minute): each
    /// entry into NeedIdr counts once — staying there counts nothing, and a
    /// transient FLV reconnect from Live is one more.
    #[test]
    fn entries_into_need_idr_are_counted_once_each() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        let n0 = r.metrics.need_idr.get();
        assert!(n0 >= 1, "the session's first wait for an IDR is an entry");
        r.step(au(false, false)); // a P frame while waiting
        assert_eq!(r.metrics.need_idr.get(), n0);
        r.step(au(true, false));
        assert_eq!(r.pump.state(), State::Live);
        r.step(Input::FlvOpened { origin: FlvOrigin::Transient });
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(r.metrics.need_idr.get(), n0 + 1);
    }
```

Bump `metrics.rs`'s count by one: `47 + if cfg!(feature = "alloc-stats") { 2 } else { 0 }`, "20 counters, 13 families, 9 gauges, 5 histograms (+2 counters in alloc-stats builds)", and assert `# TYPE kvm_rdp_need_idr_total counter`.

- [ ] **Step 2: Run it to see it fail.** `cargo test --workspace --all-features --lib -- pump::core::tests::entries_into_need_idr metrics::tests` — Expected: FAIL to compile (`need_idr` not found).

- [ ] **Step 3: The counter.** `metrics.rs`: `pub need_idr: Counter` built as `Counter::new("kvm_rdp_need_idr", "Entries into NeedIdr (§6.4; §10.2's NeedIdr entries per minute)")`, rendered in the counters loop. In `core.rs`'s `set_state`, after the early `if self.state == new { return; }`:

```rust
        if new == State::NeedIdr {
            self.metrics.need_idr.inc();
        }
```

`cargo test --workspace --all-features --lib -- pump:: metrics::` — Expected: PASS (every pump case too: the counter changes no command).

- [ ] **Step 4: The scenarios.** In `crates/kvm-bench/src/scenarios.rs`, extend the imports (`use crate::client::{AckMode, Rx}; use kvm_bench::frames::input_latencies; use kvm_proto::keymap::usage_for_scancode; use kvm_sim::Fault;`), set

```rust
pub const CI: &[&str] = &["unshaped", "input-latency"];
pub const ALL: &[&str] = &[
    "unshaped", "input-latency", "shaped-50ms-20mbit", "shaped-150ms-5mbit", "rtt-spike", "idle-motion",
];
```

the `run` arms

```rust
        "input-latency" => input_latency(cx).await,
        "shaped-50ms-20mbit" => shaped(cx, "shaped-50ms-20mbit", 50, 20).await,
        "shaped-150ms-5mbit" => shaped(cx, "shaped-150ms-5mbit", 150, 5).await,
        "rtt-spike" => rtt_spike(cx).await,
        "idle-motion" => idle_motion(cx).await,
```

and the functions:

```rust
/// Set-1 make codes for a–z, cycled so consecutive presses differ.
const LETTERS: [u8; 26] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
    0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
];

/// §10.1: bridge input latency p99 < 5 ms — the client's input PDU written
/// → kvm-sim's HID frame read, on this process's one clock — while 1080p60
/// video with an IDR every second flows and a source burst replays every
/// 5 s (an FLV dropped under `burst_on_connect` replays the GOP so far).
async fn input_latency(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("input-latency", cx.thresholds);
    let mut cfg = SimConfig::es3(streams::load("bench_1080p60.h264")?);
    cfg.profile.fps = 60;
    cfg.profile.burst_on_connect = true;
    // No re-assert within the run (D10a). Re-check after Plan D's residual
    // fix lands (the re-assert pong-gated, the backoff skipped once until the
    // session start): 600 s must still mean "none within the run"
    // (pre-flight X3).
    let extra = "[video]\nmax_fps = 60\n[input]\nreassert_after = \"600s\"\n";
    let s = session(cx, cfg, extra, Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let a = mark(&s).await?;
    let t0 = Instant::now();
    let mut i = 0usize;
    while t0.elapsed() < Duration::from_secs(20) {
        let code = LETTERS[i % LETTERS.len()];
        s.client.key(code, true);
        tokio::time::sleep(Duration::from_millis(25)).await;
        s.client.key(code, false);
        tokio::time::sleep(Duration::from_millis(25)).await;
        if i % 100 == 99 {
            s.sim.inject(Fault::Close);
        }
        i += 1;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let presses: Vec<(u8, Instant)> = s.client.with_log(|l| {
        l.keys.iter().filter_map(|(code, at)| Some((usage_for_scancode(*code, false)?, *at))).collect()
    });
    let reports: Vec<(Instant, Vec<u8>)> = s
        .sim
        .stamped_events()
        .into_iter()
        .filter_map(|(t, e)| match e {
            SimEvent::Hid { bytes, .. } => Some((t, bytes)),
            _ => None,
        })
        .collect();
    let (lat, missed) = input_latencies(&presses, &reports);
    r.at_most("presses with no HID report", missed as f64, 0.0);
    match summarize(&lat) {
        Some(x) => {
            r.perf_at_most("input latency p99, ms", x.p99, 5.0);
            r.number("input latency p50 ms", x.p50);
            r.number("presses", x.n as f64);
        }
        None => r.holds("input latencies measured", false),
    }
    r.number("burst frames", b.m.delta(&a.m, "kvm_rdp_burst_frames_total"));
    Ok(r)
}

/// The longest gap between pictures in `[from, to]`, in ms.
fn longest_gap(rx: &[Rx], from: Instant, to: Instant) -> f64 {
    let (mut last, mut gap) = (from, 0.0f64);
    for x in rx.iter().filter(|x| x.at >= from && x.at <= to) {
        gap = gap.max(x.at.duration_since(last).as_secs_f64() * 1000.0);
        last = x.at;
    }
    gap.max(to.duration_since(last).as_secs_f64() * 1000.0)
}

/// §10.2's shaped links: acks delayed `delay_ms` and reads throttled to
/// `mbit` Mbit/s. Reported: NeedIdr entries per minute, drops by reason,
/// the longest picture gap. Checked: the session survives and kvm-sim never
/// sees back-pressure. (Task 6.1 records these numbers in rev 6.4; no default changes from them — controller ruling b.)
async fn shaped(cx: &Ctx, name: &str, delay_ms: u64, mbit: u64) -> Result<Report, String> {
    let mut r = Report::new(name, cx.thresholds);
    let s = session(cx, SimConfig::es3(streams::load("bench_1080p30.h264")?), "", Opts::new(2)).await?;
    s.client.shape(|sh| {
        sh.ack_delay = Duration::from_millis(delay_ms);
        sh.read_bps = Some(mbit * 1_000_000);
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let minutes = b.at.duration_since(a.at).as_secs_f64() / 60.0;
    r.number("NeedIdr entries per minute", b.m.delta(&a.m, "kvm_rdp_need_idr_total") / minutes);
    r.number("longest picture gap, ms", s.client.with_log(|l| longest_gap(&l.rx, a.at, b.at)));
    Ok(r)
}

/// §10.2's 2 s RTT spike: acks delayed 2 s for 3 s, then prompt again.
/// Reported: the time from the spike's end to the first picture kvm-sim
/// sent after it (time-to-picture), NeedIdr entries and drops. Checked:
/// the session survives.
async fn rtt_spike(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("rtt-spike", cx.thresholds);
    let s = session(cx, SimConfig::es3(streams::load("bench_1080p30.h264")?), "", Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let a = mark(&s).await?;
    s.client.shape(|sh| sh.ack_delay = Duration::from_secs(2));
    tokio::time::sleep(Duration::from_secs(3)).await;
    s.client.shape(|sh| sh.ack_delay = Duration::ZERO);
    let spike_end = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    let sent = sim_sent(&s.sim);
    let after: Vec<(u64, Instant)> =
        s.client.with_log(|l| l.rx.iter().filter(|x| x.at >= spike_end).map(|x| (x.frame_id, x.at)).collect());
    let ttp = after.iter().find_map(|(id, at)| {
        let (lat, _) = latencies(&sent, &[(*id, *at)]);
        let tx = *at - Duration::from_secs_f64(lat.first()? / 1000.0);
        (tx >= spike_end).then(|| at.duration_since(spike_end).as_secs_f64() * 1000.0)
    });
    match ttp {
        Some(ms) => r.number("time to picture after the spike, ms", ms),
        None => r.holds("a picture sent after the spike arrived", false),
    }
    r.number("NeedIdr entries", b.m.delta(&a.m, "kvm_rdp_need_idr_total"));
    Ok(r)
}

/// §10.2's idle → motion: the idle_motion stream's still 10 s, then 10 s of
/// noise, looped. The soft gate is an age gate (§14: not a frame count), so
/// the bitrate's jump must close nothing: no soft-gate drop and no NeedIdr
/// entry over two transitions.
async fn idle_motion(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("idle-motion", cx.thresholds);
    let s = session(cx, SimConfig::es3(streams::load("idle_motion_1080p30.h264")?), "", Opts::new(2)).await?;
    let a = mark(&s).await?;
    tokio::time::sleep(Duration::from_secs(22)).await;
    let b = mark(&s).await?;
    window_checks(&mut r, &s, &a, &b);
    r.at_most(
        "soft_gate drops across idle → motion",
        b.m.delta(&a.m, "kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"),
        0.0,
    );
    r.at_most("NeedIdr entries across idle → motion", b.m.delta(&a.m, "kvm_rdp_need_idr_total"), 0.0);
    Ok(r)
}
```

(`AckMode` is Task 5.3's; drop it from the import if clippy calls it unused here.)

- [ ] **Step 5: Run them.** Rebuild both release binaries (Task 5.1 Step 9's two commands; the bridge changed). Then, recording `uptime` first:

```bash
nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" \
  --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci --out "$CARGO_TARGET_DIR/kvm-bench" \
  input-latency shaped-50ms-20mbit shaped-150ms-5mbit rtt-spike idle-motion'
```

Expected: five PASS lines. Read the numbers: NeedIdr per minute and drops by reason under each shaped link, the time to picture after the spike, the input p50/p99, and `channel_full drops per minute` in `input-latency` (PC17 m2's question: how often the KVM → pump channel fills while bursts replay). A failing `idle-motion` is a finding against §6.6's soft gate: report it with the JSON, do not tune.

- [ ] **Step 6: Gate and commit.** The per-task gate, with the image's feature-set clippy (this task edits `crates/kvm-rdp/src`).

```bash
git add crates/kvm-rdp/src/pump/core.rs crates/kvm-rdp/src/metrics.rs crates/kvm-bench/src/scenarios.rs
git commit -m "kvm-bench: input latency under 1080p60 with bursts, shaped links, the RTT spike, idle → motion; kvm-rdp counts NeedIdr entries (Plan E Task 5.2, §10.1, §10.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5.3: stalled clients, and the release build's `panic = "abort"`

§10.1's stalled-client row — "RSS growth ≤ `backlog_limit` + 16 MiB. Withheld acks or stopped reading: ended within `soft_gate` + `stall_timeout` + `disconnect_watchdog` (+ one RTT) of the first withheld ack or last read. Suspended and not reading: ended within `stall_timeout` + `disconnect_watchdog` of the backlog first reaching `backlog_limit`. Suspended and reading: never ended" — and §10.2's "While the client withholds acks, no kvm-sim FLV write blocks for more than 100 ms". Then the release half of Task 1.1: a release `test-hooks` build dies by SIGABRT.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-bench/src/scenarios.rs`
- Test: the five runs (Step 2)

**Interfaces:**
- Consumes: Task 5.1's `session`, `sim_sent`, `Bridge::{rss_kib, wait, lines}` (its `pre_exec` sets `RLIMIT_CORE` 0, so `panic-abort` leaves no core dump), `BenchClient::shape`, `Report::timing_at_most`, `Scrape::family_delta`; kvm-sim's `SimEvent::WsClose` (the KVM side's `Stop`, which ends a session whether or not the client still reads); Task 1.1's `[test] panic_after`.
- Produces: scenarios `withhold`, `stop-reading`, `suspended-not-reading`, `suspended-reading`, `panic-abort`; `CI` becomes `["unshaped", "input-latency", "withhold", "suspended-reading", "panic-abort"]`; `ALL` gains all five.

- [ ] **Step 1: The scenarios.** In `scenarios.rs`, extend `CI` and `ALL` as above, add the `run` arms

```rust
        "withhold" => stalled(cx, Stall::Withhold).await,
        "stop-reading" => stalled(cx, Stall::StopReading).await,
        "suspended-not-reading" => stalled(cx, Stall::SuspendedNotReading).await,
        "suspended-reading" => stalled(cx, Stall::SuspendedReading).await,
        "panic-abort" => panic_abort(cx).await,
```

and:

```rust
/// The bridge's defaults these bounds are written in (§4.4).
const SOFT_GATE: f64 = 0.5;
const STALL_TIMEOUT: f64 = 10.0;
const WATCHDOG: f64 = 5.0;
const BACKLOG_LIMIT_MIB: f64 = 4.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stall {
    Withhold,
    StopReading,
    SuspendedNotReading,
    SuspendedReading,
}

/// When kvm-sim saw the session's websocket close after `from` — the KVM
/// side's `Stop`, which comes with the session's end (Closing's
/// `Disconnect`, or the watchdog's abort for a client that stopped reading).
fn ended_after(sim: &KvmSim, from: Instant) -> Option<Instant> {
    sim.stamped_events()
        .into_iter()
        .find_map(|(t, e)| (matches!(e, SimEvent::WsClose { .. }) && t >= from).then_some(t))
}

/// §10.1's stalled-client row, one way of stalling per run.
async fn stalled(cx: &Ctx, how: Stall) -> Result<Report, String> {
    let name = match how {
        Stall::Withhold => "withhold",
        Stall::StopReading => "stop-reading",
        Stall::SuspendedNotReading => "suspended-not-reading",
        Stall::SuspendedReading => "suspended-reading",
    };
    let mut r = Report::new(name, cx.thresholds);
    let s = session(cx, SimConfig::es3(streams::load("bench_1080p30.h264")?), "", Opts::new(2)).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let m0 = s.bridge.scrape().await?;
    let t_m0 = Instant::now();
    let rss0 = s.bridge.rss_kib().ok_or("no VmRSS")?;
    let mut peak = rss0;
    // The reference instant each bound is measured from.
    let mut from = Instant::now();
    match how {
        Stall::Withhold => s.client.shape(|sh| sh.ack = AckMode::Withhold),
        Stall::StopReading => s.client.shape(|sh| sh.reading = false),
        Stall::SuspendedNotReading | Stall::SuspendedReading => s.client.shape(|sh| sh.ack = AckMode::Suspend),
    }
    if how == Stall::SuspendedNotReading {
        tokio::time::sleep(Duration::from_secs(2)).await;
        s.client.shape(|sh| sh.reading = false);
        // §10.1: from the backlog first reaching backlog_limit.
        let limit = BACKLOG_LIMIT_MIB * 1024.0 * 1024.0;
        let t0 = Instant::now();
        loop {
            // The instant before the scrape that shows the limit: taken
            // after it, the bound would lean toward passing by a scrape.
            let t = Instant::now();
            if s.bridge.scrape().await?.get("kvm_rdp_egfx_backlog_bytes") >= limit {
                from = t;
                break;
            }
            if t0.elapsed() > Duration::from_secs(30) {
                r.holds("the backlog reached backlog_limit", false);
                return Ok(r);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let (bound, horizon) = match how {
        Stall::Withhold | Stall::StopReading => (SOFT_GATE + STALL_TIMEOUT + WATCHDOG + 0.25, 40.0),
        Stall::SuspendedNotReading => (STALL_TIMEOUT + WATCHDOG + 0.25, 40.0),
        Stall::SuspendedReading => (f64::INFINITY, 2.0 * (STALL_TIMEOUT + WATCHDOG)),
    };
    let t0 = Instant::now();
    let mut ended = None;
    while t0.elapsed().as_secs_f64() < horizon {
        peak = peak.max(s.bridge.rss_kib().unwrap_or(peak));
        if let Some(t) = ended_after(&s.sim, from) {
            ended = Some(t);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    r.at_most(
        "RSS growth, MiB (≤ backlog_limit + 16 MiB)",
        (peak.saturating_sub(rss0)) as f64 / 1024.0,
        BACKLOG_LIMIT_MIB + 16.0,
    );
    let block = s.sim.stats().max_flv_write_block.as_secs_f64() * 1000.0;
    r.at_most("max kvm-sim FLV write block, ms", block, 100.0);
    if how == Stall::SuspendedReading {
        r.holds("a client that suspends acks and keeps reading is never ended", ended.is_none());
        // §10.1's delivery row: "suspended runs are matched by FrameId".
        // Over the closed window [m0 + 0.5 s, m1 − 0.5 s] — a margin for a
        // frame in flight at either end — the bridge dropped no frame for
        // any reason, and every frame kvm-sim sent reached the client.
        let t_m1 = Instant::now();
        let m1 = s.bridge.scrape().await?;
        let drops = m1.family_delta(&m0, "kvm_rdp_frames_dropped_total", "reason");
        for (reason, n) in &drops {
            r.number(&format!("dropped {reason} while suspended"), *n);
        }
        r.holds("no frame dropped while suspended, for any reason", drops.values().all(|n| *n == 0.0));
        // The window stays under one 20 s loop of the bench stream, so a
        // FrameId names one frame: a lost frame cannot hide behind its copy
        // in another loop.
        let lo = t_m0 + Duration::from_millis(500);
        let hi = (t_m1 - Duration::from_millis(500)).min(lo + Duration::from_secs(15));
        let got: std::collections::HashSet<u64> = s.client.with_log(|l| {
            l.rx.iter().filter(|x| x.at >= lo && x.at <= hi + Duration::from_secs(1)).map(|x| x.frame_id).collect()
        });
        let missing = sim_sent(&s.sim)
            .iter()
            .filter(|(id, t)| *t >= lo && *t <= hi && !got.contains(id))
            .count();
        r.at_most("kvm-sim frames in the window never received", missing as f64, 0.0);
        return Ok(r);
    }
    match ended {
        Some(t) => {
            r.timing_at_most("ended after the stall began, s", t.duration_since(from).as_secs_f64(), bound);
            let m1 = s.bridge.scrape().await?;
            r.at_least(
                "disconnects{client_stalled}",
                m1.delta(&m0, "kvm_rdp_disconnects_total{cause=\"client_stalled\"}"),
                1.0,
            );
        }
        None => r.holds(&format!("the session ended within {horizon} s"), false),
    }
    Ok(r)
}

/// §5.2, DE7: a release build aborts on a panic. A test-hooks build's pump
/// shell panics on `[test] panic_after`, and the process dies by SIGABRT
/// with no orderly shutdown (in a debug build it would exit 1 — Task 1.1's
/// L2 case).
async fn panic_abort(cx: &Ctx) -> Result<Report, String> {
    use std::os::unix::process::ExitStatusExt as _;
    let mut r = Report::new("panic-abort", cx.thresholds);
    let src = Source::fixture("360p30_es3like_poc0.h264").map_err(|e| format!("{e:?}"))?;
    let sim = KvmSim::start(SimConfig::es3(src)).await.map_err(|e| e.to_string())?;
    let mut b = Bridge::spawn(&cx.bridge, &sim, "[test]\npanic_after = \"1s\"\n")
        .map_err(|e| format!("{e} — is the bridge a release build with --features test-hooks?"))?;
    let status = b.wait(Duration::from_secs(10)).await;
    r.holds("the release bridge died by SIGABRT (panic = \"abort\")", status.and_then(|s| s.signal()) == Some(libc::SIGABRT));
    r.holds("no orderly shutdown ran", !b.lines().iter().any(|l| l.contains("\"shutting down\"")));
    Ok(r)
}
```

- [ ] **Step 2: Run them.** (The bridge did not change; reuse Task 5.2's release builds.)

```bash
nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" \
  --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci --out "$CARGO_TARGET_DIR/kvm-bench" \
  withhold stop-reading suspended-not-reading suspended-reading panic-abort'
```

Expected: five PASS lines (about two minutes). A stalled case that never ends, or one that ends past its bound, is a finding against §6.6/§6.9 — report it with the JSON; `suspended-reading` ending is the same. If `panic-abort` reports exit 1 instead of SIGABRT, the binary was not built with the release profile: check `cargo build --release` was used (Task 1.1's guard would have refused an unwinding release build). `coredumpctl list 2>/dev/null | tail -n 3` — Expected: no new `kvm-rdp` entry (`RLIMIT_CORE` 0).

- [ ] **Step 3: Gate and commit.**

```bash
git add crates/kvm-bench/src/scenarios.rs
git commit -m "kvm-bench: stalled clients four ways, and a release build dies by SIGABRT on a panic (Plan E Task 5.3, §10.1, §5.2)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5.4: the null bridge — the end-to-end comparison

§10.1: "End-to-end latency (`sim_tx` … → client `EndFrame` parsed, TLS on both legs) is reported for information **alongside** a null bridge's distribution — the same client against a minimal IronRDP server sending kvm-sim's pre-converted AUs from memory on the same schedule — p50 and p99 of each, never subtracted."

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-bench/src/null_bridge.rs`
- Modify: `crates/kvm-bench/src/main.rs` (`mod null_bridge;`), `src/scenarios.rs` (`e2e-null`)
- Test: the `e2e-null` run (Step 3)

**Interfaces:**
- Consumes: kvm-sim's `Source { sps, pps, frames: Vec<Frame { idr, nals, .. }> }`; kvm-proto's `h264::{frame_id, is_vcl, parse_sps}`; `ironrdp-server` at the workspace pin (the bridge's own `server::build` is the reference for the builder calls); Task 5.1's `BenchClient`, `frames::latencies`, `stats::summarize`.
- Produces: `null_bridge::NullBridge::{start(&Source, fps: u32) -> Result<NullBridge, String>, addr, sent() -> Vec<(u64, Instant)>}` (drop stops it); scenario `e2e-null` in `ALL`.

- [ ] **Step 1: `null_bridge.rs`.**

```rust
//! The null bridge (§10.1): a minimal IronRDP server — NLA, EGFX AVC420 —
//! sending a source's access units from memory on kvm-sim's schedule (one
//! every 1/fps from the first IDR, looped), so kvm-bench can report the
//! same client's end-to-end latency against it beside the bridge's: p50 and
//! p99 of each, never subtracted. One client at a time; information only.
use crate::bridge::{NLA_PASSWORD, USER};
use ironrdp_dvc::{DvcMessage, encode_dvc_messages};
use ironrdp_egfx::pdu::{Avc420Region, CapabilitiesAdvertisePdu, CapabilitySet};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_server::{
    Credentials, DesktopSize, DisplayUpdate, EgfxServerMessage, GfxDvcBridge, GfxServerFactory,
    GfxServerHandle, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler, ServerEvent, ServerEventSender, ServerResult,
};
use ironrdp_svc::ChannelFlags;
use kvm_proto::h264::{frame_id, is_vcl, parse_sps};
use kvm_sim::Source;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

type Sent = Arc<Mutex<Vec<(u64, Instant)>>>;
type Slot = Arc<Mutex<Option<GfxServerHandle>>>;

pub struct NullBridge {
    pub addr: SocketAddr,
    sent: Sent,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl NullBridge {
    pub fn start(source: &Source, fps: u32) -> Result<NullBridge, String> {
        let sps = parse_sps(&source.sps).map_err(|e| format!("the source's SPS: {e:?}"))?;
        let size = (
            u16::try_from(sps.width).map_err(|_| "width".to_owned())?,
            u16::try_from(sps.height).map_err(|_| "height".to_owned())?,
        );
        let frames = annex_b(source);
        let sent: Sent = Arc::default();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = oneshot::channel();
        let s = sent.clone();
        let thread = std::thread::Builder::new()
            .name("null-bridge".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("null-bridge runtime");
                tokio::task::LocalSet::new().block_on(&rt, serve(frames, size, fps, s, addr_tx, stopped));
            })
            .map_err(|e| e.to_string())?;
        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "the null bridge did not start".to_owned())??;
        Ok(NullBridge { addr, sent, stop: Some(stop), thread: Some(thread) })
    }

    pub fn sent(&self) -> Vec<(u64, Instant)> {
        self.sent.lock().unwrap().clone()
    }
}

impl Drop for NullBridge {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Each frame's FrameId and §6.3's Annex-B: SPS and PPS before an IDR, the
/// VCL NALs, 4-byte start codes — pre-converted, as §10.1 says.
fn annex_b(source: &Source) -> Vec<(u64, Vec<u8>)> {
    source
        .frames
        .iter()
        .map(|f| {
            let vcl: Vec<&[u8]> = f
                .nals
                .iter()
                .map(|n| n.as_ref())
                .filter(|n: &&[u8]| n.first().is_some_and(|b| is_vcl(b & 0x1F)))
                .collect();
            let mut out = Vec::new();
            let mut nals: Vec<&[u8]> = Vec::new();
            if f.idr {
                nals.push(&source.sps);
                nals.push(&source.pps);
            }
            nals.extend(vcl.iter().copied());
            for n in nals {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(n);
            }
            (frame_id(vcl.iter().copied()), out)
        })
        .collect()
}

fn tls() -> Result<(tokio_rustls::TlsAcceptor, Vec<u8>), String> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(|e| e.to_string())?;
    let der = ck.cert.der().to_vec();
    let public_key = {
        let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| e.to_string())?;
        cert.tbs_certificate.subject_pki.subject_public_key.data.to_vec()
    };
    let key = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der()).map_err(|e| e.to_string())?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(der)], key)
        .map_err(|e| e.to_string())?;
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), public_key))
}

struct Fixed(u16, u16);

#[async_trait::async_trait]
impl RdpServerDisplay for Fixed {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: self.0, height: self.1 }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Never))
    }
}

struct Never;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Never {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        std::future::pending().await
    }
}

struct NoInput;

impl RdpServerInputHandler for NoInput {
    fn keyboard(&mut self, _: KeyboardEvent) {}
    fn mouse(&mut self, _: MouseEvent) {}
}

/// Tells the shipper a connection's EGFX is ready.
struct Ready(mpsc::UnboundedSender<()>);

impl GraphicsPipelineHandler for Ready {
    fn capabilities_advertise(&mut self, _: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _: &CapabilitySet) {
        let _ = self.0.send(());
    }
    fn max_frames_in_flight(&self) -> u32 {
        120
    }
}

struct NullGfx {
    slot: Slot,
    ready: mpsc::UnboundedSender<()>,
}

impl ServerEventSender for NullGfx {
    fn set_sender(&mut self, _: mpsc::UnboundedSender<ServerEvent>) {}
}

impl GfxServerFactory for NullGfx {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        Box::new(Ready(self.ready.clone()))
    }
    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let handle: GfxServerHandle =
            Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(Ready(self.ready.clone())))));
        *self.slot.lock().unwrap() = Some(handle.clone());
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

async fn serve(
    frames: Vec<(u64, Vec<u8>)>,
    size: (u16, u16),
    fps: u32,
    sent: Sent,
    addr: std::sync::mpsc::Sender<Result<SocketAddr, String>>,
    stop: oneshot::Receiver<()>,
) {
    let (acceptor, public_key) = match tls() {
        Ok(t) => t,
        Err(e) => {
            let _ = addr.send(Err(e));
            return;
        }
    };
    let slot: Slot = Arc::default();
    let (ready_tx, ready_rx) = mpsc::unbounded_channel();
    let mut server = RdpServer::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_hybrid(acceptor, public_key)
        .with_input_handler(NoInput)
        .with_display_handler(Fixed(size.0, size.1))
        .with_gfx_factory(Some(Box::new(NullGfx { slot: slot.clone(), ready: ready_tx })))
        .build();
    server.set_credentials(Some(Credentials {
        username: USER.to_owned(),
        password: NLA_PASSWORD.to_owned(),
        domain: None,
    }));
    let events = server.event_sender().clone();
    let (tx, rx) = oneshot::channel();
    let _ = events.send(ServerEvent::GetLocalAddr(tx));
    tokio::task::spawn_local(async move {
        let got = rx.await.ok().flatten().ok_or_else(|| "no local address".to_owned());
        let _ = addr.send(got);
    });
    tokio::task::spawn_local(ship(frames, size, fps, slot, ready_rx, events, sent));
    tokio::select! {
        r = server.run() => if let Err(e) = r { eprintln!("null bridge: {e:#}") },
        _ = stop => {}
    }
}

fn send(events: &mpsc::UnboundedSender<ServerEvent>, channel_id: u32, msgs: Vec<DvcMessage>) -> bool {
    if msgs.is_empty() {
        return true;
    }
    match encode_dvc_messages(channel_id, msgs, ChannelFlags::SHOW_PROTOCOL) {
        Ok(svc) => events.send(ServerEvent::Egfx(EgfxServerMessage::send_messages(svc))).is_ok(),
        Err(_) => true,
    }
}

/// Per ready connection: the bridge's Setup (§6.4: ResetGraphics with one
/// primary monitor, CreateSurface, MapSurfaceToOutput), then one AU every
/// 1/fps from frame 0 (the source's first IDR), recording each FrameId's
/// hand-off to IronRDP's event queue.
async fn ship(
    frames: Vec<(u64, Vec<u8>)>,
    (w, h): (u16, u16),
    fps: u32,
    slot: Slot,
    mut ready: mpsc::UnboundedReceiver<()>,
    events: mpsc::UnboundedSender<ServerEvent>,
    sent: Sent,
) {
    while ready.recv().await.is_some() {
        let Some(handle) = slot.lock().unwrap().clone() else { continue };
        let setup = {
            let mut g = handle.lock().unwrap();
            let monitor = Monitor {
                left: 0,
                top: 0,
                right: i32::from(w) - 1,
                bottom: i32::from(h) - 1,
                flags: MonitorFlags::PRIMARY,
            };
            g.resize_with_monitors(w, h, vec![monitor]);
            let sid = g.create_surface(w, h).filter(|s| g.map_surface_to_output(*s, 0, 0));
            g.set_max_frames_in_flight(120);
            (sid, g.channel_id(), g.drain_output())
        };
        let (Some(sid), Some(cid), msgs) = setup else { continue };
        if !send(&events, cid, msgs) {
            return;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1) / fps);
        // kvm-sim's schedule (encoder.rs): a late tick is skipped, never
        // caught up in a burst — §10.1's "on the same schedule".
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let t0 = Instant::now();
        for (id, annexb) in frames.iter().cycle() {
            tick.tick().await;
            if !ready.is_empty() {
                break; // a new connection: set it up
            }
            let ts = u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX);
            let msgs = {
                let mut g = handle.lock().unwrap();
                if g.send_avc420_frame(sid, annexb, &[Avc420Region::full_frame(w, h, 22)], ts).is_none() {
                    continue;
                }
                g.drain_output()
            };
            if !send(&events, cid, msgs) {
                return;
            }
            sent.lock().unwrap().push((*id, Instant::now()));
        }
    }
}
```

If the pinned rev's builder wants its calls in another order, or a trait method above has another signature, follow `crates/kvm-rdp/src/rdp/server.rs` (`build`), `src/rdp/display.rs` and `src/rdp/gfx.rs`, which compile against the same rev; the behaviour is the contract, not the spelling.

- [ ] **Step 2: The scenario.** `mod null_bridge;` in `main.rs`; in `scenarios.rs` add `"e2e-null"` to `ALL`, the arm `"e2e-null" => e2e_null(cx).await,`, and:

```rust
/// §10.1's end-to-end latency, for information: the bridge's distribution
/// and the null bridge's, the same client, source and schedule — p50 and
/// p99 of each, never subtracted.
async fn e2e_null(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("e2e-null", cx.thresholds);
    let window = Duration::from_secs(20);
    let through_bridge = {
        let s = session(cx, SimConfig::es3(streams::load("bench_1080p30.h264")?), "", Opts::new(2)).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let from = Instant::now();
        tokio::time::sleep(window).await;
        let got: Vec<(u64, Instant)> = s.client.with_log(|l| {
            l.rx.iter().filter(|x| x.at >= from).map(|x| (x.frame_id, x.at)).collect()
        });
        latencies(&sim_sent(&s.sim), &got)
    };
    let through_null = {
        let null = crate::null_bridge::NullBridge::start(&streams::load("bench_1080p30.h264")?, 30)?;
        let c = BenchClient::connect(null.addr, Opts::new(3));
        if !c.until(Duration::from_secs(15), |l| !l.rx.is_empty()).await {
            return Err(format!("no picture from the null bridge: {:?}", c.with_log(|l| l.ended.clone())));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let from = Instant::now();
        tokio::time::sleep(window).await;
        let got: Vec<(u64, Instant)> =
            c.with_log(|l| l.rx.iter().filter(|x| x.at >= from).map(|x| (x.frame_id, x.at)).collect());
        latencies(&null.sent(), &got)
    };
    for (who, (lat, unmatched)) in [("bridge", through_bridge), ("null bridge", through_null)] {
        match summarize(&lat) {
            Some(x) => {
                r.number(&format!("{who} end-to-end p50 ms"), x.p50);
                r.number(&format!("{who} end-to-end p99 ms"), x.p99);
                r.number(&format!("{who} frames"), x.n as f64);
            }
            None => r.holds(&format!("{who}: latencies measured"), false),
        }
        r.number(&format!("{who} unmatched frames"), unmatched as f64);
    }
    r.note("the two distributions are reported side by side and never subtracted (§10.1)");
    Ok(r)
}
```

- [ ] **Step 3: Run it.** Rebuild `kvm-bench` (release), then `nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci --out "$CARGO_TARGET_DIR/kvm-bench" e2e-null'` — Expected: PASS, with both p50s and p99s in `e2e-null.json`. The bridge's numbers above the null's are expected (it adds the KVM leg's TLS and FLV); the gap is information only.

- [ ] **Step 4: Gate and commit.** The gate (clippy covers the new module).

```bash
git add crates/kvm-bench/src/null_bridge.rs crates/kvm-bench/src/main.rs crates/kvm-bench/src/scenarios.rs
git commit -m "kvm-bench: the null bridge, and end-to-end latency beside it, never subtracted (Plan E Task 5.4, §10.1)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5.5: the soak, the per-PR `bench` job, and the nightly bench and soak

§10.1's memory row: "Over minutes 5–60, RSS least-squares slope < 2 MiB/h and max − min < 16 MiB. `VmRSS` sampled every 10 s, `MALLOC_ARENA_MAX=2`. Every 5 minutes a churn cycle: a preempting reconnect, FLV drop, websocket drop, re-advertise, resize and 1 KiB paste. Nightly, not per PR." Then CI: the `ci` set on every PR at loose thresholds, and nightly `all` (strict on demand, DE11) and the soak.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-bench/src/soak.rs`
- Modify: `crates/kvm-bench/src/main.rs` (`mod soak;`), `src/scenarios.rs` (the `soak` arm)
- Modify: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml` (`bench`; `publish` needs it), `.github/workflows/nightly.yml` (`bench`)
- Test: a 3-minute local soak (Step 3; §13 keeps the hour in CI), `scripts/check-workflows.sh`, actionlint

**Interfaces:**
- Consumes: Task 5.1's `Bridge` (`pid`, `scrape`), `rss_kib_of`, `BenchClient` (`Opts::clipboard`, `key`, `readvertise`), `streams::load`, `stats::slope`, `Scrape::{delta, family_delta}`; kvm-sim's `switch_source(Source, ResizeSignal)`, `inject(Fault::Close)`, `close_websockets()`; `Ctx::{soak_duration, churn_every}`.
- Produces: scenario `soak` (not in `ALL`); its report's numbers `steady RSS MiB` and `memory limit MiB (RSS + 4 + 16, + 50 %)` — the deployment design §4.2's formula, which Task 6.1 records — and, under 30 minutes, the slope and range as numbers with a "short soak" note instead of checks; CI's `bench` job; the nightly's `bench` job (taskset-pinned, DE11).

- [ ] **Step 1: `soak.rs`.**

```rust
//! §10.1's memory soak (nightly; §13: the full hour in CI only). RSS every
//! 10 s under MALLOC_ARENA_MAX=2, on its own thread; every `churn_every` a
//! churn cycle — a preempting reconnect (from the other loopback address,
//! DE14), an FLV drop, a websocket drop, a re-advertise, a resize (1080p ↔
//! 720p) and a 1 KiB paste; over minutes 5 to the end, the RSS slope
//! < 2 MiB/h and max − min < 16 MiB. The steady RSS sizes the deployment's
//! memory limit.
use crate::bridge::{Bridge, rss_kib_of};
use crate::client::{BenchClient, Opts};
use crate::scenarios::Ctx;
use crate::streams;
use kvm_bench::report::Report;
use kvm_bench::stats::{percentile, slope};
use kvm_sim::{Fault, KvmSim, ResizeSignal, SimConfig, SimEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The paste chord's make codes (`ctrl+option+shift+v`, §8) and V.
const CHORD: [u8; 3] = [0x1D, 0x38, 0x2A];
const V: u8 = 0x2F;

async fn picture(c: &BenchClient, since: usize) -> bool {
    c.until(Duration::from_secs(15), |l| l.rx.len() > since + 2).await
}

async fn connect(bridge: &Bridge, source: u8, text: &str) -> Result<BenchClient, String> {
    let mut o = Opts::new(source);
    o.clipboard = Some(text.to_owned());
    let c = BenchClient::connect(bridge.rdp, o);
    if !picture(&c, 0).await {
        return Err(format!("no picture from 127.0.0.{source}: {:?}", c.with_log(|l| l.ended.clone())));
    }
    Ok(c)
}

fn hid_reports(sim: &KvmSim) -> usize {
    sim.stamped_events().iter().filter(|(_, e)| matches!(e, SimEvent::Hid { .. })).count()
}

/// §10.1's "VmRSS sampled every 10 s", on its own thread: a churn cycle's
/// awaits (30–90 s of connects, picture waits and the paste) never pause
/// it, so the peaks the churn causes are in the samples the memory limit
/// is sized from. Stopped and joined on `finish`, or on drop whatever path
/// `soak` leaves by.
struct Sampler {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(f64, f64)>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start(pid: u32, t0: Instant) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let (s, v) = (stop.clone(), samples.clone());
        let thread = std::thread::spawn(move || {
            let mut next = t0;
            while !s.load(Ordering::Relaxed) {
                if Instant::now() >= next {
                    if let Some(kib) = rss_kib_of(pid) {
                        v.lock().unwrap().push((t0.elapsed().as_secs_f64() / 60.0, kib as f64 / 1024.0));
                    }
                    next += Duration::from_secs(10);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Sampler { stop, samples, thread: Some(thread) }
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Stop, join, and every sample: (minutes, MiB).
    fn finish(mut self) -> Vec<(f64, f64)> {
        self.halt();
        std::mem::take(&mut *self.samples.lock().unwrap())
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.halt();
    }
}

/// `paste_events{outcome}`'s rises between two scrapes: the `done` count,
/// and every abort reason's together (`aborted_*`, whatever
/// `PASTE_ABORTS` holds).
fn paste_outcomes(before: &kvm_bench::prom::Scrape, after: &kvm_bench::prom::Scrape) -> (f64, f64) {
    let d = after.family_delta(before, "kvm_rdp_paste_events_total", "outcome");
    let done = d.get("done").copied().unwrap_or(0.0);
    let aborted = d.iter().filter(|(k, _)| k.starts_with("aborted")).map(|(_, n)| *n).sum();
    (done, aborted)
}

pub async fn soak(cx: &Ctx) -> Result<Report, String> {
    let mut r = Report::new("soak", cx.thresholds);
    let sim = KvmSim::start(SimConfig::es3(streams::load("bench_1080p30.h264")?))
        .await
        .map_err(|e| e.to_string())?;
    // No re-assert within the run. Re-check after Plan D's residual fix
    // lands (pong-gated re-assert; backoff skipped once until the session
    // start): 600 s must still mean "none within the run" (pre-flight X3).
    let bridge = Bridge::spawn(&cx.bridge, &sim, "[input]\nreassert_after = \"600s\"\n")?;
    // 1 KiB of typeable text, no line break (§8).
    let text: String = "abcdefghij".chars().cycle().take(1024).collect();
    let mut source = 2u8;
    let mut client = connect(&bridge, source, &text).await?;
    let (t0, mut big, mut failed_steps, mut cycles) = (Instant::now(), true, 0u32, 0u32);
    let sampler = Sampler::start(bridge.pid(), t0);
    let mut next_churn = t0 + cx.churn_every;
    let mut paste_reports: Vec<f64> = Vec::new();
    while t0.elapsed() < cx.soak_duration {
        if Instant::now() >= next_churn {
            cycles += 1;
            next_churn += cx.churn_every;
            // 1. A preempting reconnect from the other address (DE14).
            source = if source == 2 { 3 } else { 2 };
            client = match connect(&bridge, source, &text).await {
                Ok(c) => c,
                Err(e) => {
                    r.note(format!("cycle {cycles}: reconnect: {e}"));
                    failed_steps += 1;
                    continue;
                }
            };
            // 2–4. An FLV drop, a websocket drop, a re-advertise: a picture after each.
            let steps: [(&str, Box<dyn Fn()>); 3] = [
                ("FLV drop", Box::new(|| sim.inject(Fault::Close))),
                ("websocket drop", Box::new(|| sim.close_websockets())),
                ("re-advertise", Box::new(|| client.readvertise())),
            ];
            for (what, act) in steps {
                let n = client.with_log(|l| l.rx.len());
                act();
                if !picture(&client, n).await {
                    r.note(format!("cycle {cycles}: no picture after the {what}"));
                    failed_steps += 1;
                }
            }
            // 5. A resize, 1080p ↔ 720p, as a new sequence header (§6.4).
            big = !big;
            let next = streams::load(if big { "bench_1080p30.h264" } else { "bench_720p30.h264" })?;
            let n = client.with_log(|l| l.rx.len());
            sim.switch_source(next, ResizeSignal::SequenceHeader);
            if !picture(&client, n).await {
                r.note(format!("cycle {cycles}: no picture after the resize"));
                failed_steps += 1;
            }
            // 6. A 1 KiB paste (§8). Its oracle is the bridge's own outcome —
            // exactly one more `done` and no abort of any reason — not a
            // count of HID reports, which also holds the modifiers, the
            // re-asserts and the releases (kept as a number).
            let p0 = bridge.scrape().await?;
            let hid0 = hid_reports(&sim);
            for m in CHORD {
                client.key(m, true);
            }
            client.key(V, true);
            client.key(V, false);
            for m in CHORD {
                client.key(m, false);
            }
            let t = Instant::now();
            let (done, aborted) = loop {
                let (done, aborted) = paste_outcomes(&p0, &bridge.scrape().await?);
                if done >= 1.0 || aborted > 0.0 || t.elapsed() > Duration::from_secs(60) {
                    break (done, aborted);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            };
            paste_reports.push((hid_reports(&sim) - hid0) as f64);
            if done != 1.0 || aborted != 0.0 {
                r.note(format!("cycle {cycles}: the 1 KiB paste: {done} done, {aborted} aborted within 60 s (want 1, 0)"));
                failed_steps += 1;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let samples = sampler.finish();
    // §10.1: minutes 5 to the end (a short local run: its last 11/12).
    let from = (cx.soak_duration.as_secs_f64() / 60.0 / 12.0).min(5.0);
    let steady: Vec<(f64, f64)> = samples.iter().copied().filter(|(m, _)| *m >= from).collect();
    let mib: Vec<f64> = steady.iter().map(|(_, y)| *y).collect();
    let per_hour = slope(&steady).map(|s| s * 60.0).ok_or("too few RSS samples")?;
    let range = mib.iter().copied().fold(f64::MIN, f64::max) - mib.iter().copied().fold(f64::MAX, f64::min);
    if cx.soak_duration < Duration::from_secs(30 * 60) {
        // Over a few minutes a 0.1 MiB drift is already 2 MiB/h, and one
        // churn cycle moves RSS by more: the bounds are the hour's.
        r.number("RSS slope, MiB/h (minutes 5 on)", per_hour);
        r.number("RSS max − min, MiB (minutes 5 on)", range);
        r.note("short soak: slope and range are reported, not checked (§10.1's hour is the nightly's)".to_owned());
    } else {
        r.at_most("RSS slope, MiB/h (minutes 5 on)", per_hour, 2.0);
        r.at_most("RSS max − min, MiB (minutes 5 on)", range, 16.0);
    }
    r.number("RSS samples", samples.len() as f64);
    if let Some(n) = paste_reports.iter().copied().reduce(f64::max) {
        r.number("HID reports per 1 KiB paste, most", n);
    }
    r.at_most("churn steps that did not recover", f64::from(failed_steps), 0.0);
    r.holds("the session is alive at the end", client.with_log(|l| l.ended.is_none()));
    r.number("churn cycles", f64::from(cycles));
    let median = percentile(&mib, 50.0).unwrap_or(0.0);
    r.number("steady RSS MiB", median);
    r.number("memory limit MiB (RSS + 4 + 16, + 50 %)", (median + 4.0 + 16.0) * 1.5);
    Ok(r)
}
```

`mod soak;` in `main.rs`; in `scenarios::run`: `"soak" => crate::soak::soak(cx).await,`.

- [ ] **Step 2: CI.** In `ci.yml`, after `image`:

```yaml
  bench:
    # §10.2: kvm-bench on every PR at loose (10×) thresholds — release builds
    # of the bridge under test (alloc-stats, test-hooks) and of kvm-bench,
    # the bench streams from the flake's ffmpeg, and the `ci` set.
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: Rust from rust-toolchain.toml
        run: rustup toolchain install && cargo --version
      - uses: Swatinem/rust-cache@release
        with:
          shared-key: bench
          save-if: ${{ github.ref == 'refs/heads/main' }}
      - uses: cachix/install-nix-action@release
        with:
          extra_nix_config: "experimental-features = nix-command flakes"
      - name: Bench tools from the flake (ffmpeg, jq)
        run: |
          nix build .#bench-tools --out-link "$RUNNER_TEMP/bench-tools"
          echo "$RUNNER_TEMP/bench-tools/bin" >> "$GITHUB_PATH"
      - name: Bench streams (§10.2 — generated, never committed)
        run: scripts/gen-fixtures.sh bench
      - name: Release builds — the bridge under test, and kvm-bench
        run: |
          cargo build --release --locked -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp
          cargo build --release --locked -p kvm-bench --bin kvm-bench
      - name: kvm-bench — the ci set, loose thresholds
        run: target/release/kvm-bench --bridge target/release/kvm-rdp --thresholds ci --out "$RUNNER_TEMP/kvm-bench" ci
      - name: Keep the reports
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@release
        with:
          name: kvm-bench-reports
          path: ${{ runner.temp }}/kvm-bench
          retention-days: 14
```

and `publish`'s `needs: [check, fuzz, lint, image, bench]`. In `nightly.yml`:

```yaml
  bench:
    # §10.2, DE11: every scenario (strict on demand: workflow_dispatch with
    # thresholds=strict is the perf pass's dedicated runner), then §10.1's
    # one-hour soak, strict — §13 keeps the hour in CI.
    runs-on: ubuntu-24.04
    timeout-minutes: 150
    steps:
      - uses: actions/checkout@release
        with:
          persist-credentials: false
      - name: Rust from rust-toolchain.toml
        run: rustup toolchain install && cargo --version
      - uses: Swatinem/rust-cache@release
        with:
          shared-key: bench
          save-if: false
      - uses: cachix/install-nix-action@release
        with:
          extra_nix_config: "experimental-features = nix-command flakes"
      - name: Bench tools and streams
        run: |
          nix build .#bench-tools --out-link "$RUNNER_TEMP/bench-tools"
          export PATH="$RUNNER_TEMP/bench-tools/bin:$PATH"
          scripts/gen-fixtures.sh bench
      - name: Release builds
        run: |
          cargo build --release --locked -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp
          cargo build --release --locked -p kvm-bench --bin kvm-bench
      # §10.2: absolute targets "pinned with taskset, at nice 0" — CPUs 2,3
      # of the runner's four (DE11); kvm-bench and the bridge it spawns
      # share them (results err high, DE10).
      - name: Every scenario
        env:
          THRESHOLDS: ${{ inputs.thresholds || 'ci' }}
        run: taskset -c 2,3 target/release/kvm-bench --bridge target/release/kvm-rdp --thresholds "$THRESHOLDS" --out "$RUNNER_TEMP/kvm-bench" all
      - name: The one-hour soak (§10.1)
        # Not always(): a cancelled nightly must not soak for an hour.
        if: ${{ !cancelled() }}
        run: taskset -c 2,3 target/release/kvm-bench --bridge target/release/kvm-rdp --thresholds strict --out "$RUNNER_TEMP/kvm-bench" soak
      - name: Keep the reports
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@release
        with:
          name: kvm-bench-nightly
          path: ${{ runner.temp }}/kvm-bench
          retention-days: 30
```

Pin and check: `nix develop --command scripts/pin-action.sh --rewrite .github/workflows/ci.yml .github/workflows/nightly.yml` — Expected: every action here is already pinned, so each line takes the existing pin verbatim (rule 11) — then `nix develop --command scripts/check-workflows.sh`, `nix develop --command actionlint` — Expected: clean.

- [ ] **Step 3: A short soak, locally.** Rebuild `kvm-bench` (release). `nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci --out "$CARGO_TARGET_DIR/kvm-bench" --soak-duration 3m --churn-every 1m soak'` — Expected: PASS with `churn cycles` 2, no unrecovered step (no cycle note), the slope and the range as numbers beside the "short soak" note (on 3 minutes they are noise: the checks that matter are the nightly hour's), about 18 `RSS samples` taken through both churn cycles, and the paste's HID-report count. A step that never recovers its picture is a finding (§6.4/§6.5's recovery) — report it.

- [ ] **Step 4: Gate and commit.**

```bash
git add crates/kvm-bench/src/soak.rs crates/kvm-bench/src/main.rs crates/kvm-bench/src/scenarios.rs \
  .github/workflows/ci.yml .github/workflows/nightly.yml
git commit -m "kvm-bench: the memory soak with its churn cycle; the bench job on every PR, and the nightly bench and soak (Plan E Task 5.5, §10.1)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**CI check** (owner): `bench` green on the PR; the nightly's `bench` green, its `soak.json` carrying `steady RSS MiB` and the memory limit; once, `workflow_dispatch` with `thresholds = strict` (the perf pass's absolute run, DE11). Task 6.1 records the cold and warm `bench` durations and `gh cache list`'s sizes per key from these runs (E50): a warm `bench` over 30 minutes, or caches past about 8 GB, go to the owner.

---
## Part 6 — Close-out

### Task 6.1: the perf pass's record, spec rev 6.4, and the README

Run the perf pass (the strict scenario set), apply its decision rules, and write Plan E into the spec as rev 6.4 — the deviations, the carries closed, the results, the new L5 items — then the README. The last task; it reads every report Part 5 wrote and whatever CI runs the owner has triggered.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`
- Modify: `/home/chris/Repos/kvm-rdp/README.md`
- Test: the strict run (Step 1); the per-task gate; the docs read against the code (Step 6)

**Interfaces:**
- Consumes: every `kvm-bench` report (`$CARGO_TARGET_DIR/kvm-bench/*.json`, and the nightly's artifacts if the owner has run it), Task 1.4's two allocation numbers, the target budget's size, Task 4.1's image and binary sizes and `docker system df`, and whatever CI runs the owner has triggered (their timings, cache sizes and verdicts).
- Produces: spec rev 6.4; the README's status, `## Container image` (Tasks 4.1–4.2) and `## Benchmarks`.

- [ ] **Step 1: The strict run.** Rebuild both release binaries (Task 5.1 Step 9), regenerate the streams if `target/` was cleaned, then:

```bash
uptime | tee "$CARGO_TARGET_DIR/kvm-bench/load.txt"
nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" \
  --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds strict --out "$CARGO_TARGET_DIR/kvm-bench/strict" all'
```

(nice 0, two pinned CPUs, serially — §10.2; about six minutes). Keep every JSON.

- [ ] **Step 2: Apply the decision rules.** For each §10.1 target — bridge video latency (`unshaped`'s enqueue fraction), bridge input latency (`input-latency`), delivery, CPU, whole-process allocations per frame (`unshaped`), the stalled-client bounds (`withhold`, `stop-reading`, `suspended-not-reading`, `suspended-reading`):
  - **met** under `strict`: record the value, the host and its load average. CPU and latency figures are the `alloc-stats,test-hooks` release build's: an upper bound for the image's build (DE10), and kvm-bench shares the pinned CPUs with the bridge (results err high);
  - **missed** under `strict` but met under `ci`, with a 1-minute load average above 2 on this 16-core host: record "not met on the shared host (load L)"; the absolute verdict is the nightly's `workflow_dispatch` with `thresholds = strict` on GitHub's runner (DE11, an owner trigger) — if it has run, record its numbers instead;
  - **missed** under `strict` on a quiet host (load ≤ 2) or on the runner: **stop and report** the JSON — optimising the bridge or amending a target needs a ruling.
  - Bridge-owned allocations: Task 1.4's A and C (both under their shares). (A) is the steady state, each AU released before the next read; under a burst the demuxer may reallocate per read, which the whole-process metric covers.
  - Memory: from the nightly soak's `soak.json` if it has run — `steady RSS MiB` and `memory limit MiB` (of the `alloc-stats,test-hooks` release build, sampled on its own thread through every churn cycle), which the deployment design §4.2 takes in place of its interim 128 Mi; if not, "pending the first nightly soak" and the 128 Mi stands.
  - The gates (§10.2: "The soft gate, backlog limit and standing delay limit are tuned from these"): change no default. Record each shaped run's NeedIdr entries per minute and drops by reason. If `unshaped` or `shaped-50ms-20mbit` shows a `soft_gate`, `backlog_gate` or `standing_delay` drop after its warm-up, report it for a ruling — the spec gives no rule that turns those numbers into a new default.
  - PC17 m2: record `channel_full drops per minute` from `unshaped` and `input-latency`.
  - CI, from the runs the owner has triggered (each "not yet run" otherwise): the `l2-under-load` pass rate (Task 2.3, nice-5 loops); the fuzz nightly green since Task 2.4; the `nix build .#l3-tools` time and closure size and the four L3 cases' time; the cold and warm `bench` durations and `gh cache list`'s sizes per key — a warm `bench` over 30 minutes or caches past about 8 GB go to the owner (E50); whether the owner set "Require actions to be pinned to a full-length commit SHA" (E80); the image's size against its cap (E81) and the image builder's size beside the 8 GiB target budget (E13).

- [ ] **Step 3: Spec rev 6.4.** In the status table, replace the span `Draft rev 6.3 — Plan D's deviations recorded (2026-10-15)` (not the token alone: the cell's tail would repeat) with `Draft rev 6.4 — Plan E's deviations recorded (<this commit's date>); rev 6.3: Plan D's (2026-10-15)`; then a leading paragraph like rev 6.3's: "**Rev 6.4 — Plan E (<dates>).** Records what building Milestones 5 and 6 settled, against the code as built. DE*n* are Plan E's recorded deviations (`docs/superpowers/plans/2026-10-15-kvm-rdp-plan-e.md`); every amended passage below is marked "rev 6.4". The owner's hardware run (Plan D Task 1.6) and Windows App acceptance run have not happened yet, so every value they would retune keeps its written default. One line per change:", then one line per DE1–DE16 (this plan's "Recorded deviations"), and one line per later-§ change, each marked "rev 6.4" in its section:
  - §4.1: `kvm-bench` as built — a pure `kvm_bench` library (statistics, the `/metrics` parser, thresholds, matchers) and an IO binary (kvm-sim, the lean client, the bridge as a subprocess, the null bridge, which uses `ironrdp-server`).
  - §4.2, a **pin review checklist** (rev 6.4), monthly and on every IronRDP pin bump: the pin goldens; `cargo tree -d`; the fork's three patches; the upstream caps still missing — an SVC/DVC reassembly cap (§8), a CLIPRDR format-count cap (PD8 m3: `get_formats` builds a client's whole format list, about 5–10× its wire size, before the backend runs; L2 pins that a 20 000-format list survives), and per-PDU WARNs past the INFO cap ("Unexpected channel received"; limited per callsite since rev 6.4); IronRDP's picky/sspi release-candidate crypto (`rsa 0.10.0-rc.18`, `picky 7.0.0-rc.25`, `curve25519-dalek 5.0.0-rc.1`, `ed25519-dalek 3.0.0-rc.1`): re-check at each pin bump, and re-read RUSTSEC-2023-0071's reachability in `deny.toml`; L3 (a FreeRDP bump in `flake.lock` re-records the ladder fixture, whose first line names the FreeRDP); `kvm-bench ci`. With it: Actions pins (`scripts/pin-action.sh`, and `--verify` on every workflow), the image's base and BuildKit pins (`scripts/pin-image.sh`), `cargo deny` advisories (DE15).
  - §4.4: `[test] panic_after` exists only in `test-hooks` builds; the image refuses `[test]` as an unknown key.
  - §4.5: third-party lines limited per callsite (DE5); `kvm_rdp_log_lines_suppressed_total`.
  - §7.4: the KVM-runtime stale watch as built (Task 1.5, m3): `hid::stale`, release-all once the RDP heartbeat is older than `RDP_STALE_RELEASE` — 3 s, three periods of the unchanged 1 s-capped heartbeat, where §12 said "about 1 s" (DE16) — while input is held, once per stale episode, counted `release_all{trigger="rdp_stale"}`; rev 6.3's "carried to Plan E" sentence becomes the built behaviour.
  - §5.2: DE7 — and that the release build's abort is shown by `kvm-bench panic-abort`, the debug build's exit 1 by L2.
  - §6.1: DE8's floor beside the other SPS limits — RDP's 200-pixel minimum desktop, citing MS-RDPEDISP 2.2.2.2.1 (IronRDP's displaycontrol enforces 200..=8192), where §12 had said MS-RDPBCGR.
  - §8: the `hid.lua?type=text` comparison is an L5 / Leg D owner item (DE12); ours stays the default. Rev 6.3's m4 residual bullet ("aborting the paste on a resync is carried to Plan E") is *replaced* by the built behaviour: a queue resync while the Typist types ends the paste `aborted_resync` and releases all (`release_all{trigger="paste_resync"}`; Task 1.5, m4), the resync's state dropped under the queue lock (`push_typing_at`), so an overflow never drops characters from the middle of a paste; `PASTE_ABORTS` has nine labels. Its residual: a resync after the Typist's last report but before the queue has drained drops the paste's last ≤ 8 reports — the KVM keeps a prefix, no key held — and the paste stays counted `done` (keep `input.queue` at 256).
  - §9.1: "CI checks the published image rejects any other mode" as built (DE2): the negotiation probe and the `[test]` refusal in `scripts/image-smoke.sh`, run on every PR's image before `publish` pushes those bytes.
  - §10.1: add a column "Result (rev 6.4)" holding Step 2's value or status per row — the CPU row's value marked "the `alloc-stats,test-hooks` release build: an upper bound for the image's" — and the bridge-owned split (DE3: A, C, measured on the committed fixtures; A is the steady state, each AU released before the next read, and a burst's per-read reallocation is the whole-process metric's). The soak's memory line names the build it measured.
  - §10.2: the harness as built (DE10, DE11): the scenario names, `ci` and `all`, the bench streams, the null bridge, the reports; the absolute run taskset-pinned to CPUs 2,3 of the runner's four at nice 0, and kvm-bench and the bridge it spawns share the pinned CPUs (results err high).
  - §10.4: the registry as built — 47 families — 20 counters, 13 labelled families, 9 gauges, 5 histograms — 49 in an `alloc-stats` build (the count `metrics.rs`'s test asserts); the `kvm_rdp_release_all_total` row gains `rdp_stale` (the stale watch, §7.4) and `paste_resync` (a resync while typing, §8), and the `kvm_rdp_paste_events_total` row gains `aborted_resync` — with rows for `kvm_rdp_log_lines_suppressed_total`, `kvm_rdp_egfx_client_frames_decoded`, `kvm_rdp_need_idr_total` and the two `alloc-stats` counters; "allocations per frame (`alloc-stats` builds)" is now built.
  - §11.2 and §11.4: L3 as built (DE9) — the four `l3::` cases, `fixtures/freerdp-gfx-ladder.txt` (its first line the recording FreeRDP's `/version`, and its re-record rule), and the L1 case that replays it; L3 runs in CI's `check` job.
  - §11.6, the L5 checklist gains: the `hid.lua?type=text` comparison (DE12's method); the deployed bridge's CPU at 1080p30 on the real ES3 against §10.1's 5 % (the pod's CPU usage while the owner works; kvm-bench cannot reach the real KVM); the memory limit holds over a working day (no OOM kill) once the soak has sized it.
  - §12: planning unit E's row gets its status ("rev 6.4: built"); every bullet of "Carried to Plan E" gets the task that closed it — the stale-heartbeat release (m3) and the abort on resync (m4) closed by Task 1.5 — and the fuzz nightly's level-1b oracle fix (Task 2.4); the CI DC19 note gains the SHA pins, cargo-deny (advisories blocking on main, reported on PRs and nightly, DE15; RUSTSEC-2023-0071's ignore and its owner sign-off, or "pending" if not yet given), the lint job, the nightly, L3, the image and `publish`; "Owner acceptance checklist": a note that acceptance runs against the published image (`ghcr.io/christopherjmiller/kvm-rdp:sha-<short>@sha256:…`), no new item.
  - §13: the target budget re-measured with the release artifacts (the size Task 5.1 and this task's run recorded, `debug/` and `release/` apart); the 1-hour soak runs in the nightly; image builds run in Docker at CPU shares 205 and 8 GiB (`scripts/image-build.sh`), their cache pruned to 8 GB outside the target budget (its measured size beside it); the nightly L2 stressor runs at nice 5.
  - §15: "Watched" gains the image's base and BuildKit digests, the Actions pins, and `flake.lock`'s FreeRDP (the L3 ladder fixture follows it).
  The change log supersedes nothing in rev 6.3's; it is added to it.

- [ ] **Step 4: README.** The status paragraph: Milestones 5 and 6 — L3 interop with FreeRDP, CI's supply-chain gates, the published image, and `kvm-bench` — keeping the caveat that the real device and Windows App are still unrun (the owner's checks). Add after `## Container image`:

````markdown
## Benchmarks

`kvm-bench` (spec §10.2) runs kvm-sim and an IronRDP client in one process
against the bridge as a subprocess, and checks §10.1's targets:

    scripts/gen-fixtures.sh bench   # the bench streams, into target/ (never committed)
    cargo build --release -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp
    cargo build --release -p kvm-bench --bin kvm-bench
    target/release/kvm-bench --bridge target/release/kvm-rdp --thresholds strict all

`--thresholds ci` loosens §10.1's performance bounds 10× and the stalled-client
timings 1.5×; delivery, bitrate and survival checks are exact (what every PR
runs, scenario set `ci`). `strict` is meant for a quiet machine (pin it with
`taskset`, at nice 0). The
one-hour memory soak (`soak`) runs nightly in CI. Each scenario writes a JSON
report to `target/kvm-bench/`.
````

- [ ] **Step 5: Verify.** The per-task gate. `nix develop --command scripts/check-workflows.sh`, `nix develop --command actionlint`, `nix develop --command shellcheck scripts/*.sh`, `nix develop --command scripts/test-check-workflows.sh`, `nix develop --command scripts/test-target-budget.sh` — Expected: clean. `nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1` — Expected: 4 passed. `nix develop --command cargo deny --locked check` — Expected: ok (RUSTSEC-2023-0071 ignored, its sign-off recorded or still pending).

- [ ] **Step 6: Read the docs against the code.** Every "rev 6.4" claim names something that exists: grep each metric name in `crates/kvm-rdp/src/metrics.rs`, each scenario name in `crates/kvm-bench/src/scenarios.rs`, each script in `scripts/`; the §10.4 family count equals `metrics.rs`'s test; nothing still says Plan E "will" do what it did.

- [ ] **Step 7: Commit.**

```bash
git add docs/superpowers/specs/2026-10-05-kvm-rdp-design.md README.md
git commit -m "docs: spec rev 6.4 (Plan E's deviations, the carries closed, the perf pass's results, new L5 items), README (Plan E Task 6.1)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Running Plan E's tools

```bash
# L3 (the flake's FreeRDP and xvfb-run are in the devshell):
nix develop --command cargo test --workspace --all-features --test l2 -- --ignored l3:: --test-threads 1
# …and re-recording FreeRDP's ladder after a flake.lock bump (review the diff):
nix develop --command env KVM_RDP_L3_RECORD=1 cargo test --workspace --all-features --test l2 -- --ignored l3::freerdps_full_ladder --test-threads 1

# The image, locally (reproducible; its own polite BuildKit builder):
nix develop --command scripts/image-build.sh "$CARGO_TARGET_DIR/kvm-rdp.oci.tar"
nix develop --command scripts/image-smoke.sh kvm-rdp:ci

# kvm-bench (release builds; the named -p exceptions):
nix develop --command scripts/gen-fixtures.sh bench
nix develop --command cargo build --release --locked -p kvm-rdp --features alloc-stats,test-hooks --bin kvm-rdp
nix develop --command cargo build --release --locked -p kvm-bench --bin kvm-bench
nix develop --command bash -c 'taskset -c 2,3 "$CARGO_TARGET_DIR/release/kvm-bench" --bridge "$CARGO_TARGET_DIR/release/kvm-rdp" --thresholds ci ci'

# The workflow rules, and re-pinning (monthly, with the IronRDP pin review):
nix develop --command scripts/check-workflows.sh
nix develop --command scripts/pin-action.sh actions/checkout   # prints the pin to paste
nix develop --command scripts/pin-image.sh gcr.io/distroless/cc-debian12:nonroot
```

## Planning notes

- Parts run in order, and tasks in order within them, except that Task 2.4 sits and runs between Tasks 2.2 and 2.3. Within Part 1 Task 1.3's family count precedes Task 1.4's (`alloc-stats` adds to it), Task 1.4's allocator precedes Part 5, and Task 1.5 needs Task 1.1's `test-hooks` stall (it adds no family). Part 2 precedes every later workflow edit (its pin and rule scripts). Task 3.1 precedes 3.2 (the harness; the ladder fixture). Task 4.1 precedes 4.2. Part 5's tasks build on 5.1 in order; 5.5's `ci` set needs 5.3's scenarios.
- The metric family count moves +1 (Task 1.3), +1 (Task 3.1), +1 (Task 5.2) from the base's — 44 → 47 — plus 2 in `alloc-stats` builds (Task 1.4; 49 under `--all-features`); Task 1.5's triggers and abort label are labels, not families. Each task updates `metrics.rs`'s count test and its description, and Task 6.1's §10.4 line quotes the final count.
- IronRDP-linked test executables stay two (the lib's and L2): kvm-bench's library test binary links no IronRDP, its binary has no tests, and kvm-proto's `alloc` binary links only kvm-proto. New release artifacts (the bench's bridge, kvm-bench) count against the 8 GiB target budget; Tasks 5.1 and 6.1 measure it.
- Owner-gated, none blocking a task (controller ruling 6; Plan E's code is completed and verified locally, and every workflow passes actionlint and shellcheck and runs locally where it can — act is not available — so the workflows themselves wait on these):
  - approving the pushes of `plan-e` (every **CI check** line);
  - **RUSTSEC-2023-0071's ignore in `deny.toml` — PENDING OWNER SIGN-OFF, before the first push** (Task 2.2; its reachability reading is in the entry), and any further cargo-deny ignore;
  - the merge that runs the first `publish`, then running the README's `cosign verify` (cosign v3) once on its digest;
  - making the ghcr package public;
  - the nightly's runs: the scheduled ones (L2 under load, advisories, reproducibility, `bench` and the one-hour soak) and one `workflow_dispatch` with `thresholds = strict` (DE11), plus one dispatch of the fuzz nightly after Task 2.4;
  - setting "Require actions to be pinned to a full-length commit SHA" in the repository's Actions settings once Task 2.1 is on main, and optionally restricting `allowed_actions` to the seven used (E80);
  - the L5 items (DE12's comparison among them).
  Plan D's Task 1.6 and the Windows App acceptance run stay as they were.
- Plan D's final fix wave is in the base: `hid/release.rs`, the `release_websockets` family (44 families), `PASTE_ABORTS`, the ping/pong release proof and the no-backoff reopen; Task 1.3's L2 case uses paste.rs's helpers (E5).

## Pre-flight resolutions

Every finding of the pre-flight scan (`.superpowers/sdd/plan-e-draft/preflight.md` §5, E1–E81) is applied with its proposed ruling (controller rulings 8–10). One line each: the finding, the task that applies it, and the plan line(s) where it lands.

- **E1** (Critical) — Tasks 3.1, 3.2: `barcode_within` skips a 0 reading; `L3::streaming`; every picture wait after it; the suspension window starts once suspended; xwd's black test — l.3494, 3464, 3674.
- **E2** (Critical) — Task 4.2: the cosign step's name quoted — l.4479.
- **E3** (Important) — Task 1.5 (Carries table, DE16): m3 stale-heartbeat release-all (at 3 s, three heartbeat periods: DE16, ruling 11) and m4 abort on resync with release-all (ruling 12), with tests — l.1373, 98, 78.
- **E4** (Important) — Tasks 1.3, 1.4: literal 45 in Task 1.3; the `alloc-stats` term added with the feature — l.583, 1096.
- **E5** (Important) — Task 1.3: the 20 000-format case on paste.rs's pattern; `ClipboardFormatName` import; the fallback — l.597, 763.
- **E6** (Important) — Task 2.1: rules 2 and 4 exact; rules 7–9; their tests — l.2329, 2136.
- **E7** (Important) — Task 2.4: the fuzz oracle compares levels by rank; the 1b→1.1 seed and test — l.2741, 2838.
- **E8** (Important) — Tasks 2.2, 2.3: five advisories named; rustls 0.23.46; RUSTSEC-2023-0071 ignore PENDING OWNER SIGN-OFF; advisories non-blocking on PRs; nightly `deny-advisories` — l.2697, 2724, 2967.
- **E9** (Important) — Task 3.1: the FrameAck is received before the advertise — l.3152.
- **E10** (Important) — Tasks 3.1, 3.2: `V10_7` and `freerdp_exit` land in Task 3.2 — l.3632, 3655.
- **E11** (Important) — Task 3.2: the no-NLA case asserts the bridge's refusal line and a display — l.3764.
- **E12** (Important) — Task 4.1: build-path check without a pipe; logs and Env read whole; `--paths-only` negative check — l.3966, 4341.
- **E13** (Important) — Task 4.1 (Execution notes, 6.1): the RUN deletes the target; builder pruned to 8 GB; second archive in the target dir, both deleted; `df /` check — l.4204, 4308, 121.
- **E14** (Important) — Task 4.2: one `docker login`; `create-storage-record: false` — l.4458, 4491.
- **E15** (Important) — Task 5.1: `#[allow(dead_code)]` on the binary's harness modules — l.6215.
- **E16** (Important) — Task 5.1: the source silenced; delivery is nothing in flight; the ratio a number — l.6179.
- **E17** (Important) — Task 5.3: suspended-reading matched by FrameId over a closed window; no drops — l.6722.
- **E18** (Important) — Tasks 5.1, 5.5: `rss_kib_of`; the soak's sampler thread — l.5363, 7207.
- **E19** (Important) — Task 5.5: a soak under 30 min reports slope and range as numbers — l.7359.
- **E20** (Important) — Task 5.5 (DE11, decision 13): both nightly kvm-bench runs taskset-pinned — l.7460, 73.
- **E21** (Minor) — Task 1.1: the feature first, then the failing run — l.229, 252.
- **E22** (Minor) — Task 1.1: `config::tests cli::tests`; `config_errors_never_echo_the_file` — l.383.
- **E23** (Minor) — Task 1.1: the exact msg.rs import edit — l.274.
- **E24** (Minor) — Task 1.1: the guard's comment on `cargo test --release` — l.376.
- **E25** (Minor) — Execution notes, 1.1, 1.3, 1.4, 1.5, 2.1, 3.1, 4.1, 5.2: the image's feature-set clippy in the gate and in CI — l.119, 2509.
- **E26** (Minor) — Task 1.1: the rlib sentence — l.250.
- **E27** (Minor) — Task 1.1: Step 9 builds the release guard with `test-hooks` — l.385.
- **E28** (Minor) — Task 1.1: no redundant `use`; `Cargo.lock` in Files — l.227, 166.
- **E29** (Minor) — Task 1.2: the struct-literal sentence — l.494.
- **E30** (Minor) — Task 1.2 (DE8, 6.1): the floor cites MS-RDPEDISP 2.2.2.2.1 and IronRDP's 200..=8192 — l.399.
- **E31** (Minor) — DE4, 1.3, 1.4, 3.1, 5.2, 6.1, Planning notes: 45 → 46 → 47 (+2 under alloc-stats, 49) — l.66, 3022, 6354, 7537, 7607.
- **E32** (Minor) — Task 1.3: timing-robust per-callsite asserts — l.562.
- **E33** (Minor) — Task 1.3: `max_level_hint` is TRACE — l.673.
- **E34** (Minor) — Task 1.4: the tag buffer taken after `as_mut()?`, restored before each return — l.1334.
- **E35** (Minor) — DE3, 6.1: what the microbench cannot see — l.65.
- **E36** (Minor) — Tasks 2.1, 4.1: shellcheck-clean scripts: printf trim, escape loop, SC2016 directives — l.2370, 4067, 2168.
- **E37** (Minor) — Task 2.2: `--offline` for the injected ban — l.2709.
- **E38** (Minor) — Task 2.3 (6.1): busy loops at nice 5 — l.2889.
- **E39** (Minor) — Task 2.1: `--rewrite` on a file with no `@release` — l.2294.
- **E40** (Minor) — Task 2.1: no moot move; the prune recorded — l.2451, 2581.
- **E41** (Minor) — DE13, 4.2: `publish`'s exception — l.75.
- **E42** (Minor) — Task 2.1: `bench-tools` uses ffmpeg-headless — l.2231.
- **E43** (Minor) — Tasks 2.1, 2.3, 4.2, 5.5: `persist-credentials: false` on every checkout; rule 10 — l.2337.
- **E44** (Minor) — Task 4.2: `cosign-release: v3.0.6`; README "cosign v3 or later" — l.4477, 4557.
- **E45** (Minor) — Task 2.1 (and every later `--rewrite`): existing pins copied verbatim; rule 11; `--verify` — l.2340, 2271.
- **E46** (Minor) — Task 4.2: the digest reaches the script through `env` — l.4482.
- **E47** (Minor) — Carries table, 2.2, 6.1: 345 crates; the release-candidate crypto listed and on the pin review — l.106, 7527.
- **E48** (Minor) — Task 3.1: `xvfb-run -d -e xvfb.log -w 0`; Xvfb's log in failures — l.3436.
- **E49** (Minor) — Task 3.1: the synthetic XWD as Xvfb writes it (header 160, 256 colors) — l.3040.
- **E50** (Minor) — Tasks 3.2, 5.5, 6.1: the L3 step's own timeout; CI timings and caches recorded; owner decides past 30 min / 8 GB — l.3833, 7523.
- **E51** (Minor) — Task 3.2 (DE9, 6.1): `fixtures/freerdp-gfx-ladder.txt` with the recording's `/version` line — l.3705.
- **E52** (Minor) — Task 3.1: `freerdp` declared first in `L3` — l.3377.
- **E53** (Minor) — Tasks 4.1, 4.2: layers and creation time compared; `.Id` only in the classic store; the nightly records layers — l.4316, 4518.
- **E54** (Minor) — Task 4.1 (DE2): refusal = EOF under 19 bytes; `03` and a hang fail — l.4111.
- **E55** (Minor) — Task 4.1: the kubelet's Secret layout at /run/secrets/kvm-rdp; README fsGroup note — l.4013, 4368.
- **E56** (Minor) — Task 4.1: a dirty build context refused unless `IMAGE_BUILD_DIRTY=1` (`-dirty`) — l.4281.
- **E57** (Minor) — File structure: the 4.1, 5.4 and 6.1 rows — l.141.
- **E58** (Minor) — Task 4.2: each nightly leg keeps its archive and build log — l.4527.
- **E59** (Minor) — Task 4.1: the builder remade on a BuildKit pin bump — l.4288.
- **E60** (Minor) — Task 4.2: README: a superseded run has no image — l.4566.
- **E61** (Minor) — Task 5.1: `sliced-threads=0`, `-filter_threads 4` — l.5156.
- **E62** (Minor) — Task 5.1: the read throttle is a link (serialise per PDU, a wake arm) — l.5768.
- **E63** (Minor) — Task 5.1: `session` waits for a KVM picture — l.6065.
- **E64** (Minor) — Task 5.1: `PR_SET_PDEATHSIG`; the timeout arm reaps — l.5251.
- **E65** (Minor) — Tasks 5.1, 5.2: Produces and Consumes completed; `bytes` dropped — l.4601.
- **E66** (Minor) — DE10, 6.1: CPU and latency are the alloc-stats build's upper bound — l.72.
- **E67** (Minor) — Task 5.1: `window_checks` asserts the four series exist — l.6116.
- **E68** (Minor) — Task 5.5: `if: ${{ !cancelled() }}` on the soak and both report uploads — l.7462.
- **E69** (Minor) — Task 5.2: the `shaped` docstring — l.6492.
- **E70** (Minor) — Task 5.5: the soak's paste oracle is the outcome counters — l.7256.
- **E71** (Minor) — Task 5.4: the null bridge skips missed ticks — l.7059.
- **E72** (Minor) — Task 5.1 (5.3): `RLIMIT_CORE` 0 in `pre_exec` — l.5257.
- **E73** (Minor) — DE14: the alternating addresses' reason — l.76.
- **E74** (Minor) — Task 6.1: the status-table span replaced — l.7525.
- **E75** (Minor) — Task 5.3: the reference instant before the scrape — l.6661.
- **E76** (Minor) — Task 6.1: the README's `--thresholds ci` wording — l.7558.
- **E77** (Minor) — Task 5.1: kvm-bench's tokio `signal` and rustls `logging`; `debug/` and `release/` sizes — l.4664, 6335.
- **E78** (Minor) — DE10, 5.5, 6.1: bench and bridge share the pinned CPUs — l.72.
- **E79** (Minor) — Execution notes, Planning notes: the base `7bdcf15`; the fix-wave note — l.117, 7618.
- **E80** (Minor) — Task 2.1 (Planning notes, 6.1): owner item: GitHub's SHA-pinning setting — l.2592.
- **E81** (Minor) — Task 4.1: sizes recorded; over 64 MiB the controller rules a cap — l.4338.

### Verification re-scan resolutions

The re-scan's new findings (`preflight.md` "Verification re-scan", R1–R19) are applied as proposed (controller ruling 13); X1–X3 are re-check notes for after Plan D's residual fix lands (the writer's pong-gated re-assert and its backoff skip), from which `plan-e` is cut.

- **R1** (Important) — Task 1.5: `HidControl::push_typing_at` drops the resync's state under the queue lock; the shell pushes with it while typing and makes no later push before the abort; its queue test — l.1938, 1793, 1990.
- **R2** (Important) — Task 4.1: Step 6 builds with `IMAGE_BUILD_DIRTY=1`; one negative check without it — l.4337.
- **R3** (Minor) — Task 1.3: the fallback keeps `env.hid_ready().await;` without `ws` — l.765.
- **R4** (Minor) — Tasks 1.5, 6.1: the drained-tail residual recorded — l.1378, 7533.
- **R5** (Minor) — Task 6.1: §10.4's label rows; §8's m4 bullet replaced — l.7537, 7533.
- **R6** (Minor) — Task 1.5: the step reference — l.1398.
- **R7** (Minor) — File structure: Task 2.4's row — l.137.
- **R8** (Minor) — Task 2.1: the rewrite's Expected per file — l.2579.
- **R9** (Minor) — Task 2.2: the advisory covers private-key operations; the rsa code in the graph; the reason — l.2669, 2684.
- **R10** (Minor) — Task 2.2: `cargo tree … -p kvm-rdp -p kvm-probe` — l.2674.
- **R11** (Minor) — Task 2.2: the mitigation states what the code guarantees — l.2691.
- **R12** (Minor) — Task 3.2: `require_tools` before `freerdp_version` — l.3704.
- **R13** (Minor) — Task 3.2: the no-display guard matches FreeRDP 3.32.1's text — l.3773.
- **R14** (Minor) — Task 3.1: `xvfb_log`'s doc on xvfb-run's truncation — l.3548.
- **R15** (Minor) — DE13: the image jobs' runner tools — l.75.
- **R16** (Minor) — Task 5.1: what the shared release units are (about 50 still build twice) — l.4660, 6335.
- **R17** (Minor) — Task 5.3: the FrameId window under one stream loop — l.6714.
- **R18** (Minor) — File structure: Task 1.5's row names `tests/l2/input.rs` — l.134.
- **R19** (Minor) — Review Focus 3: the identity check as E53 built it — l.55.
- **X1** (re-check) — Task 1.5: the m3 L2 case, after Plan D's residual fix — l.1564.
- **X2** (re-check) — Task 1.5: the m4 L2 case, after Plan D's residual fix — l.1882.
- **X3** (re-check) — Tasks 5.2, 5.5: `reassert_after = "600s"` in `input-latency` and the soak, after Plan D's residual fix — l.6430, 7269.
