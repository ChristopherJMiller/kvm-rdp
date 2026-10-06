# kvm-rdp Plan A — Milestone 0 (census and spikes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide, with measurements instead of assumptions, whether the ES3's own H.264 can be passed straight through to Windows App over RDP — and leave behind the parsers, fixtures and census tool the rest of kvm-rdp builds on.

**Architecture:** A cargo workspace with `kvm-proto` (pure, hostile-input-safe FLV/login/H.264 parsing; no IronRDP, tokio or TLS) and `kvm-probe` (a census CLI that logs in, captures the video stream, and measures it, decoding only inside a bubblewrap sandbox). Synthetic, deterministic fixtures from `scripts/gen-fixtures.sh` feed tests and two throwaway spikes: Leg B replays fixtures from a stock IronRDP server to Windows App; Leg C puts rdpgw in front of it on the LAN. A four-patch upstream IronRDP PR is opened in parallel. The milestone ends with `docs/census.md` and a spec revision that fills every census-dependent value — the go/no-go for passthrough.

**Tech Stack:** Rust 1.94.1 (edition 2024), `bytes`, `h264-reader`, tokio, hyper 1, tokio-rustls/rustls 0.23 (aws-lc-rs only), tokio-tungstenite, clap; nix flake devshell (rust-overlay, ffmpeg-full, jq, bubblewrap); IronRDP git `38b074e` (spikes and upstream PR only); rdpgw `16cdaaf` (Leg C spike only).

**Spec:** `docs/superpowers/specs/2026-10-05-kvm-rdp-design.md` (rev 5). This plan is **Plan A** of §12's planning units: Milestone 0 plus the `kvm-proto` subset, fixtures, `kvm-probe`, the spikes and the upstream PR. No later plan is written before `docs/census.md` is committed.

## Global Constraints

- Edition 2024, `rust-version = "1.94"`, `rust-toolchain.toml` 1.94.1 (§4.2).
- `kvm-proto` depends only on `bytes` and `h264-reader` — no IronRDP, no tokio, no TLS (§4.1).
- One crypto provider: aws-lc-rs. Nothing may pull in `ring`; `cargo tree -p kvm-probe -i ring` must report no match (§4.2).
- kvm-proto parser code denies `clippy::{indexing_slicing, unwrap_used, expect_used, panic, arithmetic_side_effects, as_conversions}` and uses checked access; full fuzzing and the remaining admission limits are Plan B (§6.2, §12).
- Build budget (§13): `[build] jobs = 4`, `RUST_TEST_THREADS = "4"`; cargo through the devshell wrapper (`systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19`); one shared `CARGO_TARGET_DIR`; `[profile.dev] debug = "line-tables-only"`, dependencies `debug = false`; `[profile.release] lto = "thin", codegen-units = 16, debug = "line-tables-only", panic = "abort"`; no fat-LTO profile; ffmpeg under `nice -n 19`.
- Real KVM captures are never committed: `captures/` is 0700, gitignored, and wiped after each session (§11.5, §12).
- Every ffmpeg/ffprobe run on a capture happens inside the bubblewrap sandbox: no network, no home directory, no SSH agent, no repo checkout, `/nix` read-only (§12).
- `kvm-probe` sends no keyboard or mouse input to the KVM; the KVM password is read only from a file and never logged (§9.2).
- IronRDP for the spikes is git `38b074e`, `ironrdp-server` with `default-features = false, features = ["egfx", "helper"]`, never the `ironrdp` meta-crate (§4.2).
- Licence MIT OR Apache-2.0; every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

These are the inputs most likely to bite during the live census that the spec implies but does not spell out; each has a test in the owning task.

1. **The KVM sends HEVC through Enhanced-RTMP (`IsExHeader`, FourCC `hvc1`)** → surfaced as `VideoBody::Enhanced` and recorded with its FourCC, never misread as AVC (Task 2.7 `enhanced_rtmp_hevc_tag_is_surfaced_not_misread_as_avc`; Task 5.9 `enhanced_rtmp_records_fourcc_not_avc`).
2. **The KVM answers login with a redirect, an error page, or a rejected-password body** → a clean `KvmError::Login`, no panic, no token (Task 5.8 `non_200_login_is_a_clean_login_error`, `rejected_password_body_is_a_clean_login_error`).
3. **The KVM's certificate changes (factory reset, firmware update)** → the pinned connection is refused and the error names the fingerprint actually seen, so re-pinning is one copy-paste (Task 5.8 `correct_pin_connects_wrong_pin_names_observed_fingerprint`).
4. **bubblewrap is missing or cannot start** → the sample-range run fails; ffmpeg never runs unsandboxed on a capture (Task 5.12 `missing_sandbox_binary_fails_closed`).
5. **A capture ends mid-tag, the FLV request is refused, or a run is forgotten** → a partial trailing tag is not a parse error, a non-200 FLV is a clean error, and every capture is bounded by bytes and time (Task 5.9 `byte_cap_mid_tag_stops_cleanly`, `non_200_flv_is_an_http_error`, `StopAt::default`).

## Execution notes

- Repo: `/home/chris/Repos/kvm-rdp`. Work on a branch `plan-a` created from `main` before Task 1.1 (`git -C /home/chris/Repos/kvm-rdp checkout -b plan-a`); merge to `main` when the plan completes.
- Every command runs inside `nix develop` from the repo root (before Task 1.6 lands the flake, use a rustup 1.94.1 toolchain and prefix cargo with `nice -n 19`).
- Task numbers are `Part.N`. Inside a part, a bare "Task N" means Task `<this part>.N`.
- **Live tasks need Chris present** and are not to be run unattended: Task 6.2 (the census against the real KVM), the Leg B and Leg C runs in Part 7 (Windows App on the laptop), and the fork creation in Part 8 (a public repo under his account).
- **Disk:** the spikes and the IronRDP checkout each build IronRDP (a few GB of `target/`). Run `cargo clean` in `spikes/legb-winapp` and `~/Repos/IronRDP` once their results are recorded, and `scripts/gen-fixtures.sh clean` after the spikes.
- Plan A's exit gate is Task 9.1: census gates pass → passthrough is a go and Plans B–E may be written; Leg C fails → revisit the §14 VNC fallback first.

---

## Part 1 — Workspace and toolchain

The cargo workspace, `kvm-proto` crate root, pinned dependencies, the §13 build budget, the nix devshell and CI.

_Component preamble (not a task): all crates live under `crates/<name>/`; the repo root holds `Cargo.toml`, `flake.nix`, `.cargo/`, `.github/`, `rust-toolchain.toml` and (later) `fuzz/`. Until Task 6 lands the flake, run cargo with any toolchain 1.94.1 (`rustup toolchain install 1.94.1 && rustup override set 1.94.1`); afterwards the canonical path is `nix develop -c cargo …`, where `cargo` is the §13 wrapper. The six `clippy::` denies are tool lints: `cargo test` (plain rustc) silently ignores them, `cargo clippy` enforces them — that is why Task 1 is green under `cargo test` and the deny-lints are first exercised by the clippy gate in Task 7. Run `cargo fmt --all` before every commit so the committed tree passes CI's `fmt --check`._

### Task 1.1: Cargo workspace + kvm-proto crate root

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/Cargo.toml`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (unit test `tests::name_is_stable`)

**Interfaces:**
- Consumes: nothing (root of the dependency DAG; everything else consumes this workspace).
- Produces: the virtual workspace manifest with `members = ["crates/*"]`; `pub const fn kvm_proto::name() -> &'static str`; the crate-root `#![deny(...)]` posture.

**Steps:**

1. Write the failing test first. Create `crates/kvm-proto/src/lib.rs` referencing a `name()` that does not exist yet, plus the crate-root denies and a crate doc:
   ```rust
   //! `kvm-proto`: sans-IO parsers and encoders for the kvm-rdp bridge.
   //!
   //! This crate faces hostile input from the KVM (spec §2, §4.1) and must
   //! never panic, index out of bounds, or overflow. The crate-root lints
   //! below are denied crate-wide (the Milestone-0 hardening posture; full
   //! fuzzing and the remaining byte-limits are Plan B). Test modules that
   //! legitimately need `unwrap`/`panic` opt out locally with a scoped
   //! `#![allow(...)]`.
   #![deny(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   #[cfg(test)]
   mod tests {
       use super::name;

       #[test]
       fn name_is_stable() {
           assert_eq!(name(), "kvm-proto");
       }
   }
   ```

2. Create the two manifests so cargo can resolve the workspace. Root `Cargo.toml`:
   ```toml
   [workspace]
   resolver = "3"
   members = ["crates/*"]
   # Plan A resolves to kvm-proto + kvm-probe (crates/*). kvm-rdp, kvm-sim and
   # kvm-bench arrive in later plans as new crate dirs; fuzz/ is its own
   # workspace at the repo root (spec §4.1, §12).
   ```
   `crates/kvm-proto/Cargo.toml` (concrete `edition` for now — Task 2 flips it to workspace inheritance):
   ```toml
   [package]
   name = "kvm-proto"
   version = "0.0.0"
   edition = "2024"
   rust-version = "1.94"
   license = "MIT OR Apache-2.0"
   repository = "https://github.com/ChristopherJMiller/kvm-rdp"
   publish = false
   autotests = false
   ```

3. Run the test and watch it fail for a real reason:
   ```
   cargo test -p kvm-proto
   ```
   Expected failure: `error[E0425]: cannot find function `name` in module `super`` (compile error, 0 tests run).

4. Minimal implementation — add `name()` above the `tests` module in `lib.rs`:
   ```rust
   /// Crate name; the first link/smoke anchor until the parsers land.
   #[must_use]
   pub const fn name() -> &'static str {
       "kvm-proto"
   }
   ```

5. Format and run to pass:
   ```
   cargo fmt --all
   cargo test -p kvm-proto
   ```
   Expected: `test tests::name_is_stable ... ok` — `1 passed`.

6. Commit (Cargo.lock is generated by the build above):
   ```
   git add Cargo.toml crates/kvm-proto/Cargo.toml crates/kvm-proto/src/lib.rs Cargo.lock
   git commit -m "Workspace skeleton and the kvm-proto crate root" \
     -m "Virtual workspace (crates/*), kvm-proto with the §4.1 hostile-input deny lints and a trivial unit test." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.2: workspace profiles + shared package metadata

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.toml`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml`
- Test: shell assertions (no test file — infra task)

**Interfaces:**
- Consumes: the Task 1 workspace.
- Produces: `[workspace.package]` (edition 2024, rust-version 1.94, license, repository) inherited by members; the `[profile.*]` blocks from §13.

**Steps:**

1. Write the failing check first — assert the profiles and shared metadata exist (they do not yet):
   ```
   python3 - <<'PY'
   import tomllib
   d = tomllib.load(open("Cargo.toml", "rb"))
   assert d["profile"]["release"]["lto"] == "thin", "release lto"
   assert d["profile"]["release"]["panic"] == "abort", "release panic"
   assert d["profile"]["dev"]["debug"] == "line-tables-only", "dev debug"
   assert d["profile"]["dev"]["package"]["*"]["debug"] is False, "dep debug"
   assert d["workspace"]["package"]["edition"] == "2024", "ws edition"
   print("ok")
   PY
   ```
   Expected failure: `KeyError: 'profile'`.

2. Minimal implementation — append to the root `Cargo.toml`:
   ```toml
   [workspace.package]
   edition = "2024"
   rust-version = "1.94"
   license = "MIT OR Apache-2.0"
   repository = "https://github.com/ChristopherJMiller/kvm-rdp"

   [profile.dev]
   debug = "line-tables-only"

   [profile.dev.package."*"]
   debug = false

   [profile.release]
   lto = "thin"
   codegen-units = 16
   debug = "line-tables-only"
   panic = "abort"

   # profile.bench inherits profile.release (Cargo default); there is
   # deliberately no fat-LTO profile (spec §13).
   ```
   Then make `crates/kvm-proto/Cargo.toml` inherit the shared metadata — replace the four concrete lines with workspace references:
   ```toml
   [package]
   name = "kvm-proto"
   version = "0.0.0"
   edition.workspace = true
   rust-version.workspace = true
   license.workspace = true
   repository.workspace = true
   publish = false
   autotests = false
   ```

3. Run to pass — the TOML check, then prove inheritance and the release profile both resolve in cargo:
   ```
   python3 - <<'PY'
   import tomllib
   d = tomllib.load(open("Cargo.toml", "rb"))
   assert d["profile"]["release"]["lto"] == "thin"
   assert d["profile"]["release"]["panic"] == "abort"
   assert d["profile"]["dev"]["debug"] == "line-tables-only"
   assert d["profile"]["dev"]["package"]["*"]["debug"] is False
   assert d["workspace"]["package"]["edition"] == "2024"
   print("ok")
   PY
   cargo metadata --format-version 1 --no-deps \
     | python3 -c 'import sys,json; p=[x for x in json.load(sys.stdin)["packages"] if x["name"]=="kvm-proto"][0]; assert p["edition"]=="2024"; print("edition inherited ok")'
   cargo build --release -p kvm-proto
   ```
   Expected: `ok`, `edition inherited ok`, and a clean release build.

4. Commit:
   ```
   git add Cargo.toml crates/kvm-proto/Cargo.toml Cargo.lock
   git commit -m "Workspace profiles and shared package metadata (spec §13)" \
     -m "thin-LTO release with panic=abort and line-tables debug; deps debug=false; shared edition/rust-version/license inherited by members." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.3: pin the shared dependencies in `[workspace.dependencies]` (bytes, h264-reader)

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.toml`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs`
- Modify: `/home/chris/Repos/kvm-rdp/Cargo.lock`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs` (unit test `tests::bytes_dependency_links`)

**Interfaces:**
- Consumes: crates.io `bytes` 1.12.1, `h264-reader` 0.9.0 (latest stable, confirmed 2026-10-05).
- Produces: root `[workspace.dependencies]` with `bytes = "1.12.1"` and `h264-reader = "0.9.0"`; kvm-proto depends on both via `{ workspace = true }`. Every later crate (kvm-probe in this plan; kvm-rdp/kvm-sim in later plans) takes these two through the workspace table, never with its own version string.

**Steps:**

1. Write the failing test first — add a smoke test to the `tests` module in `crates/kvm-proto/src/lib.rs` that touches `bytes`:
   ```rust
       #[test]
       fn bytes_dependency_links() {
           let buf = bytes::BytesMut::with_capacity(16);
           assert!(buf.is_empty());
       }
   ```

2. Run it and watch it fail because the crate is not yet a dependency:
   ```
   cargo test -p kvm-proto
   ```
   Expected failure: `error[E0433]: failed to resolve: use of unresolved module or unlinked crate `bytes``.

3. Minimal implementation. Append to the root `Cargo.toml`:
   ```toml
   [workspace.dependencies]
   bytes = "1.12.1"
   h264-reader = "0.9.0"
   ```
   and add to `crates/kvm-proto/Cargo.toml`:
   ```toml
   [dependencies]
   bytes = { workspace = true }
   h264-reader = { workspace = true }
   ```
   (`h264-reader` is declared now for the SPS/slice inspection added in the H.264 tasks; `unused_crate_dependencies` is allow-by-default, so the declared-but-unused dep raises nothing under `-D warnings`, and building it now proves the pin compiles on this toolchain.)

4. Run to pass and confirm the pins resolved:
   ```
   cargo fmt --all
   cargo test -p kvm-proto
   cargo tree -p kvm-proto | grep -E 'bytes v1\.12|h264-reader v0\.9'
   ```
   Expected: `test tests::bytes_dependency_links ... ok`; the grep prints `bytes v1.12.1` and `h264-reader v0.9.0`.

5. Commit:
   ```
   git add Cargo.toml crates/kvm-proto/Cargo.toml crates/kvm-proto/src/lib.rs Cargo.lock
   git commit -m "Pin bytes 1.12.1 and h264-reader 0.9.0 in workspace.dependencies" \
     -m "The two §4.1 kvm-proto dependencies, shared through the workspace table so later crates cannot drift. A bytes link smoke-test guards the pin." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.4: resource-budget build config (.cargo/config.toml + rust-analyzer)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/.cargo/config.toml`
- Create: `/home/chris/Repos/kvm-rdp/.vscode/settings.json`
- Test: shell assertions (no test file — infra task)

**Interfaces:**
- Consumes: the Task 1 workspace.
- Produces: `[build] jobs = 4`, `[env] RUST_TEST_THREADS = "4"`, the shared-`CARGO_TARGET_DIR` note; committed rust-analyzer `check.extraArgs = ["--jobs=2"]` on the shared target dir (§13).

**Steps:**

1. Write the failing checks first:
   ```
   python3 - <<'PY'
   import tomllib, json
   c = tomllib.load(open(".cargo/config.toml", "rb"))
   assert c["build"]["jobs"] == 4
   assert c["env"]["RUST_TEST_THREADS"] == "4"
   s = json.load(open(".vscode/settings.json"))
   assert s["rust-analyzer.check.extraArgs"] == ["--jobs=2"]
   print("ok")
   PY
   ```
   Expected failure: `FileNotFoundError: ... '.cargo/config.toml'`.

2. Minimal implementation. `.cargo/config.toml`:
   ```toml
   # Development resource budget (spec §13): the host is shared and loaded.
   [build]
   jobs = 4

   [env]
   RUST_TEST_THREADS = "4"

   # CARGO_TARGET_DIR: keep ONE shared target dir across all git worktrees
   # (spec §13) — never one per worktree. The devshell/operator exports an
   # absolute CARGO_TARGET_DIR at the shared tree; it is intentionally NOT
   # hard-coded here (the path is machine-specific). CI overrides build
   # parallelism with the CARGO_BUILD_JOBS env var.
   ```
   `.vscode/settings.json` (strict JSON; `cargo.targetDir = false` keeps rust-analyzer on the shared target dir — no second build tree):
   ```json
   {
     "rust-analyzer.check.extraArgs": ["--jobs=2"],
     "rust-analyzer.cargo.targetDir": false
   }
   ```

3. Run to pass — the assertions above, then prove cargo still reads the config cleanly (an unknown key would warn/error):
   ```
   python3 - <<'PY'
   import tomllib, json
   c = tomllib.load(open(".cargo/config.toml", "rb"))
   assert c["build"]["jobs"] == 4 and c["env"]["RUST_TEST_THREADS"] == "4"
   assert json.load(open(".vscode/settings.json"))["rust-analyzer.check.extraArgs"] == ["--jobs=2"]
   print("ok")
   PY
   cargo build -p kvm-proto
   ```
   Expected: `ok` and a clean build with no cargo config warnings.

4. Commit:
   ```
   git add .cargo/config.toml .vscode/settings.json
   git commit -m "Resource-budget build config (spec §13)" \
     -m "jobs=4, RUST_TEST_THREADS=4, shared CARGO_TARGET_DIR note; rust-analyzer check at --jobs=2 on the shared target dir." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.5: pin the toolchain (rust-toolchain.toml 1.94.1)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/rust-toolchain.toml`
- Test: shell assertions (no test file — infra task)

**Interfaces:**
- Consumes: nothing.
- Produces: `rust-toolchain.toml` pinning channel 1.94.1 with clippy/rustfmt/rust-src — the rustup/CI pin that matches the flake's nix pin (§4.2).

**Steps:**

1. Write the failing check first:
   ```
   python3 - <<'PY'
   import tomllib
   t = tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]
   assert t["channel"] == "1.94.1"
   assert {"rustfmt", "clippy"}.issubset(set(t["components"]))
   print("ok")
   PY
   ```
   Expected failure: `FileNotFoundError: ... 'rust-toolchain.toml'`.

2. Minimal implementation — `rust-toolchain.toml`:
   ```toml
   # Pins the toolchain for rustup and CI. In the nix devshell (flake.nix) the
   # toolchain is supplied by rust-overlay and this file is advisory; the two
   # are kept at the same version on purpose (spec §4.2).
   [toolchain]
   channel = "1.94.1"
   components = ["rustfmt", "clippy", "rust-src"]
   profile = "minimal"
   ```

3. Run to pass:
   ```
   python3 - <<'PY'
   import tomllib
   t = tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]
   assert t["channel"] == "1.94.1"
   assert {"rustfmt", "clippy"}.issubset(set(t["components"]))
   print("ok")
   PY
   ```
   Expected: `ok`. (On a rustup host, `rustc --version` from the repo root now prints `rustc 1.94.1`.)

4. Commit:
   ```
   git add rust-toolchain.toml
   git commit -m "Pin the toolchain with rust-toolchain.toml 1.94.1" \
     -m "Matches the nix flake pin; components rustfmt, clippy, rust-src." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.6: nix flake devshell

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/flake.nix`
- Create: `/home/chris/Repos/kvm-rdp/flake.lock`
- Modify: `/home/chris/Repos/kvm-rdp/.gitignore`
- Test: shell assertion via `nix develop` (no test file — infra task)

**Interfaces:**
- Consumes: nixpkgs nixos-unstable; `github:oxalica/rust-overlay`; nixpkgs attrs `ffmpeg-full` (includes libx264 and drawtext), `jq`, `dejavu_fonts`, `bubblewrap`, `cmake`, `pkg-config`, `systemd`, `coreutils`.
- Produces: `devShells.x86_64-linux.default` providing rust 1.94.1, the §13 `cargo` wrapper, ffmpeg/ffprobe, `jq`, `bwrap`, and the environment variable `KVM_RDP_FONT` (absolute path to `DejaVuSans.ttf`, used by `scripts/gen-fixtures.sh` for the slate); the pinned `flake.lock`; `.gitignore` entries for `/captures/` and `/fixtures/large/`.

FreeRDP is deliberately **not** in this devshell: nothing in Plan A uses it, and an OpenH264-enabled FreeRDP override builds from source (CPU and disk the §13 budget does not want spent yet). Plan E adds it for L3 interop.

**Steps:**

1. Write the failing check first — before `flake.nix` exists this errors:
   ```
   nix develop -c rustc --version
   ```
   Expected failure: `error: path '/home/chris/Repos/kvm-rdp' does not contain a 'flake.nix', searching up`.

2. Minimal implementation — `flake.nix`:
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

         # §13 cargo wrapper: cap CPU/IO/memory and nice the whole build.
         # Falls back to plain `nice` when there is no user systemd (e.g. CI).
         cargoWrapper = pkgs.writeShellScriptBin "cargo" ''
           real=${rustToolchain}/bin/cargo
           if ${pkgs.systemd}/bin/systemctl --user show-environment >/dev/null 2>&1; then
             exec ${pkgs.systemd}/bin/systemd-run --user --scope -q \
               -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G \
               ${pkgs.coreutils}/bin/nice -n 19 "$real" "$@"
           else
             exec ${pkgs.coreutils}/bin/nice -n 19 "$real" "$@"
           fi
         '';
       in
       {
         devShells.${system}.default = pkgs.mkShell {
           # cargoWrapper first so its `cargo` shadows the toolchain's on PATH.
           packages = [
             cargoWrapper
             rustToolchain
             pkgs.cmake
             pkgs.pkg-config
             pkgs.ffmpeg-full
             pkgs.jq
             pkgs.bubblewrap
           ];

           KVM_RDP_FONT = "${pkgs.dejavu_fonts}/share/fonts/truetype/DejaVuSans.ttf";

           shellHook = ''
             echo "kvm-rdp devshell: $(${rustToolchain}/bin/rustc --version)"
           '';
         };
       };
   }
   ```
   Extend `.gitignore` (append):
   ```
   # nix
   /result
   /result-*
   .direnv/

   # census captures (0700, wiped each session; never committed — spec §11.5, §12)
   /captures/

   # on-demand large fixtures (1080p spike/bench streams; regenerate with scripts/gen-fixtures.sh large)
   /fixtures/large/
   ```

3. Generate the lock and make the flake visible to nix (flakes only read git-tracked files):
   ```
   git add flake.nix .gitignore
   nix flake lock
   git add flake.lock
   ```

4. Run to pass (`ffmpeg-full` comes from the binary cache; expect a download, not a build):
   ```
   nix develop -c rustc --version
   nix develop -c sh -c 'command -v cargo && cargo --version'
   nix develop -c sh -c 'ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libx264 && echo x264-ok'
   nix develop -c sh -c 'test -f "$KVM_RDP_FONT" && echo font-ok && command -v bwrap jq'
   ```
   Expected: `rustc 1.94.1`; `command -v cargo` resolves to the `cargoWrapper` store path and `cargo --version` prints the 1.94.1 cargo (the wrapper execs the real binary without recursion); `x264-ok`; `font-ok` followed by the `bwrap` and `jq` paths.

5. Commit:
   ```
   git add flake.nix flake.lock .gitignore
   git commit -m "Nix flake devshell with the pinned toolchain and media tools" \
     -m "rust 1.94.1 via rust-overlay, the §13 systemd-run/nice cargo wrapper, ffmpeg-full (libx264, drawtext), jq, bubblewrap and the slate font. FreeRDP arrives with Plan E." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

### Task 1.7: GitHub Actions CI (fmt, clippy, test)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/.github/workflows/ci.yml`
- Test: the three gate commands run locally + file-existence check (no test file — infra task)

**Interfaces:**
- Consumes: `actions/checkout@v4`, `dtolnay/rust-toolchain@master` (1.94.1), `Swatinem/rust-cache@v2`.
- Produces: a CI workflow enforcing `fmt --check`, `clippy -D warnings` (which is where the crate-root `clippy::` denies first bite) and `test`; an informational duplicate-dependency step whose hard ironrdp-\* form arrives in Plan C.

**Steps:**

1. Write the failing checks first — the workflow is absent, and confirm the repo already passes the gates it will enforce:
   ```
   test -f .github/workflows/ci.yml && echo exists
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```
   Expected: the first line prints nothing and exits non-zero (file absent — RED); the three cargo gates already pass on the Task 1–3 tree (so CI will be green once wired).

2. Minimal implementation — `.github/workflows/ci.yml`:
   ```yaml
   name: CI

   on:
     push:
       branches: [main]
     pull_request:

   env:
     CARGO_TERM_COLOR: always
     CARGO_INCREMENTAL: "0"
     CARGO_BUILD_JOBS: "4"

   jobs:
     check:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: dtolnay/rust-toolchain@master
           with:
             toolchain: 1.94.1
             components: clippy, rustfmt
         - uses: Swatinem/rust-cache@v2
         - name: Format
           run: cargo fmt --all -- --check
         - name: Clippy
           run: cargo clippy --workspace --all-targets --all-features -- -D warnings
         - name: Test
           run: cargo test --workspace --all-features
         - name: Duplicate-dependency check (informational in Plan A)
           run: |
             # Plan A has no IronRDP dependency, so this only prints duplicates.
             # Plan C turns it into a hard gate that fails on a duplicate
             # ironrdp-* crate (spec §4.2). Until then it must not fail CI.
             cargo tree --workspace --duplicates || true
   ```

3. Run to pass — confirm the file exists and the gates CI runs are green locally:
   ```
   test -f .github/workflows/ci.yml && echo exists
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```
   Expected: `exists`; `fmt --check` silent (exit 0); clippy `0 warnings` under `-D warnings` (the six crate-root denies confirmed clean on the skeleton); `test --workspace` all green. (The YAML is validated by GitHub on push; run `actionlint .github/workflows/ci.yml` too if it is available.)

4. Commit:
   ```
   git add .github/workflows/ci.yml
   git commit -m "CI: fmt, clippy -D warnings, and test" \
     -m "CARGO_INCREMENTAL=0 and CARGO_BUILD_JOBS=4 per §13; an informational cargo-tree duplicates step whose hard ironrdp-* gate lands in Plan C." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```
## Part 2 — kvm-proto: login and FLV demux

The login-response parser and the incremental FLV demuxer (Milestone-0 subset; hardening and fuzzing are Plan B).

> **Scope & assumptions.** This covers the Milestone-0 unhardened subset of `kvm-proto`: the FLV demux (§6.2 framing, AVCC config, NALU split, burst marking) and the login-response parser (§3.1). It does **not** cover the §6.1 admission checks, SPS/PPS field validation or classification, the NAL allowlist `{1,5,7,8,9}`, the start-code-in-NAL refusal, the forbidden-bit check, or the per-AU/parameter-set count caps — those are **Plan B** hardening (M1) and live in sibling components. `kvm-proto` uses only `bytes` here (no IronRDP/tokio/TLS, per §4.1; `h264-reader` belongs to the SPS component, not this one).
>
> **Commands.** Every `cargo`/`git` command runs inside the nix devshell (`nix develop`), where `cargo` is the §13-wrapped form (`systemd-run … nice -n 19 cargo`) and `.cargo/config.toml` pins `[build] jobs = 4` / `[env] RUST_TEST_THREADS = "4"`. Crate layout is `crates/kvm-proto/`.
>
> **Prerequisite (consumed from the workspace/foundation component):** root `Cargo.toml` (`[workspace] members = ["crates/kvm-proto", …]`, `[workspace.dependencies] bytes = "1"`), `crates/kvm-proto/Cargo.toml` (`edition = "2024"`, `rust-version = "1.94"`, `bytes.workspace = true`), a possibly-empty `crates/kvm-proto/src/lib.rs`, `.cargo/config.toml`, `rust-toolchain.toml` (1.94.1). If no such component runs first, prepend a task that `cargo new --lib crates/kvm-proto` and wires the workspace.

### Task 2.1: Login-response token parser

**Files:**
- Create: `crates/kvm-proto/src/login.rs`
- Modify: `crates/kvm-proto/src/lib.rs`
- Test: in-file `#[cfg(test)] mod tests` in `login.rs`

**Interfaces:**
- Consumes: nothing beyond `std`/`core`.
- Produces: `kvm_proto::login::{Token, LoginError, parse_login_token}`; `Token::as_str(&self) -> &str`; `Token::into_string(self) -> String`; `parse_login_token(body: &[u8]) -> Result<Token, LoginError>`.

**Steps:**

1. **Write the failing test.** Create `crates/kvm-proto/src/login.rs` with only a test module, and add `pub mod login;` + `pub use login::{parse_login_token, LoginError, Token};` to `crates/kvm-proto/src/lib.rs`.
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;

       #[test]
       fn extracts_token_from_success_body() {
           let body = br#"{"result":0,"token":"0.123456789","role":"admin"}"#;
           assert_eq!(parse_login_token(body).unwrap().as_str(), "0.123456789");
       }

       #[test]
       fn rejects_missing_bad_and_failed() {
           assert_eq!(parse_login_token(br#"{"result":0,"role":"x"}"#), Err(LoginError::NoToken));
           assert_eq!(parse_login_token(br#"{"result":0,"token":"0.12a"}"#), Err(LoginError::BadTokenFormat));
           assert_eq!(parse_login_token(br#"{"result":0,"token":"1.5"}"#), Err(LoginError::BadTokenFormat));
           assert_eq!(parse_login_token(br#"{"result":0,"token":"0."}"#), Err(LoginError::BadTokenFormat));
           assert_eq!(parse_login_token(br#"{"result":"invalid password","code":200}"#), Err(LoginError::ResultNotOk));
           assert_eq!(parse_login_token(&[0xFFu8, 0xFE]), Err(LoginError::NotUtf8));
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto login::tests` — expect a compile error: `E0425: cannot find function \`parse_login_token\`` / `E0433: failed to resolve: … \`Token\``.
3. **Minimal implementation.** Prepend to `login.rs`, above the test module:
   ```rust
   //! Login-response parsing for the ES3 KVM (§3.1). The vendor UI posts
   //! `{"pass","timezone","time"}` to `/cgi-bin/login.lua` and reads back
   //! `{"result":0,"token":"0.<digits>",...}` (login.html:129, kvm.js:191).
   #![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used,
           clippy::panic, clippy::arithmetic_side_effects, clippy::as_conversions)]

   use core::str;

   /// A validated session token of the form `0.<digits>` (the vendor matches
   /// `/token=0\.\d+/`), sent back as `Cookie: token=<token>` and `?token=`.
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub struct Token(String);

   impl Token {
       pub fn as_str(&self) -> &str { &self.0 }
       pub fn into_string(self) -> String { self.0 }
   }

   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
   pub enum LoginError { NotUtf8, ResultNotOk, NoToken, BadTokenFormat }

   /// Parse the JSON body of `POST /cgi-bin/login.lua`. Success is
   /// `"result":0` plus a `"token"` string matching `0.<digits>`.
   pub fn parse_login_token(body: &[u8]) -> Result<Token, LoginError> {
       let text = str::from_utf8(body).map_err(|_| LoginError::NotUtf8)?;
       if !result_is_zero(text) {
           return Err(LoginError::ResultNotOk);
       }
       let raw = json_string_value(text, "token").ok_or(LoginError::NoToken)?;
       if is_valid_token(raw) {
           Ok(Token(raw.to_owned()))
       } else {
           Err(LoginError::BadTokenFormat)
       }
   }

   /// `0.` followed by one or more ASCII digits and nothing else.
   fn is_valid_token(s: &str) -> bool {
       match s.strip_prefix("0.") {
           Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
           None => false,
       }
   }

   /// Raw inner text of the first `"key":"..."` string value. No escape
   /// processing — adequate for the fixed, tiny login body (M0).
   fn json_string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
       let needle = ["\"", key, "\""].concat();
       let key_at = text.find(&needle)?;
       let after_key = key_at.checked_add(needle.len())?;
       let tail = text.get(after_key..)?;
       let colon = tail.find(':')?;
       let after_colon = colon.checked_add(1)?;
       let vtail = tail.get(after_colon..)?.trim_start();
       let inner = vtail.strip_prefix('"')?;
       let end = inner.find('"')?;
       inner.get(..end)
   }

   /// True when a numeric `"result"` value is exactly `0` (a string result is
   /// a failure message and is rejected).
   fn result_is_zero(text: &str) -> bool {
       let needle = "\"result\"";
       let Some(key_at) = text.find(needle) else { return false };
       let Some(after_key) = key_at.checked_add(needle.len()) else { return false };
       let Some(tail) = text.get(after_key..) else { return false };
       let Some(colon) = tail.find(':') else { return false };
       let Some(after_colon) = colon.checked_add(1) else { return false };
       let Some(vtail) = tail.get(after_colon..).map(str::trim_start) else { return false };
       let num: String = vtail.chars()
           .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
           .collect();
       num == "0"
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto login::tests` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean (parser denies honoured; test module overrides them locally).
5. **Commit.** `git add crates/kvm-proto/src/login.rs crates/kvm-proto/src/lib.rs && git commit -m "kvm-proto: login-response token parser (§3.1)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.2: Checked byte-reader cursor

**Files:**
- Create: `crates/kvm-proto/src/flv/mod.rs`, `crates/kvm-proto/src/flv/reader.rs`
- Modify: `crates/kvm-proto/src/lib.rs`
- Test: in-file `#[cfg(test)] mod tests` in `reader.rs`

**Interfaces:**
- Consumes: nothing beyond `core`.
- Produces (crate-internal): `flv::reader::Cur<'a>` with `new(&'a [u8])`, `pos()`, `remaining()`, `take(usize) -> Option<&'a [u8]>`, `u8/u16/u24/u32() -> Option<…>`, `i24() -> Option<i32>`.

**Steps:**

1. **Write the failing test.** Create `crates/kvm-proto/src/flv/mod.rs`:
   ```rust
   //! FLV demux for the ES3 KVM video stream (§6.2). Hand-rolled incremental
   //! state machine over a `BytesMut`; no AMF0 parsing, no resync scanning.
   #![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used,
           clippy::panic, clippy::arithmetic_side_effects, clippy::as_conversions)]

   mod reader;
   ```
   Add `pub mod flv;` to `crates/kvm-proto/src/lib.rs`. Create `crates/kvm-proto/src/flv/reader.rs` with only this test module:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;

       #[test]
       fn reads_be_integers_and_stops_at_end() {
           let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
           let mut c = Cur::new(&data);
           assert_eq!(c.u8(), Some(0x01));
           assert_eq!(c.u16(), Some(0x0203));
           assert_eq!(c.u24(), Some(0x0004_0506));
           assert_eq!(c.u32(), Some(0x0708_090A));
           assert_eq!(c.u8(), None);
       }

       #[test]
       fn i24_sign_extends_and_bounds_check() {
           assert_eq!(Cur::new(&[0xFFu8, 0xFF, 0xFF]).i24(), Some(-1));
           assert_eq!(Cur::new(&[0x00u8, 0x00, 0x2A]).i24(), Some(42));
           assert_eq!(Cur::new(&[0x00u8, 0x01]).i24(), None);
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::reader` — expect `E0433`/`E0599`: cannot find `Cur`.
3. **Minimal implementation.** Prepend to `reader.rs`:
   ```rust
   //! Forward-only, panic-free reads over a byte slice. Every bounds and
   //! arithmetic operation is checked so parser modules can deny the
   //! panicking clippy lints (§6.2).

   pub(crate) struct Cur<'a> {
       buf: &'a [u8],
       pos: usize,
   }

   impl<'a> Cur<'a> {
       pub(crate) fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
       pub(crate) fn pos(&self) -> usize { self.pos }
       pub(crate) fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }

       pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
           let end = self.pos.checked_add(n)?;
           let s = self.buf.get(self.pos..end)?;
           self.pos = end;
           Some(s)
       }

       pub(crate) fn u8(&mut self) -> Option<u8> {
           self.take(1).and_then(|s| s.first().copied())
       }
       pub(crate) fn u16(&mut self) -> Option<u16> {
           let a: [u8; 2] = self.take(2)?.try_into().ok()?;
           Some(u16::from_be_bytes(a))
       }
       pub(crate) fn u24(&mut self) -> Option<u32> {
           let s = self.take(3)?;
           Some(u32::from_be_bytes([0, *s.first()?, *s.get(1)?, *s.get(2)?]))
       }
       pub(crate) fn u32(&mut self) -> Option<u32> {
           let a: [u8; 4] = self.take(4)?.try_into().ok()?;
           Some(u32::from_be_bytes(a))
       }
       pub(crate) fn i24(&mut self) -> Option<i32> {
           let s = self.take(3)?;
           let (b0, b1, b2) = (*s.first()?, *s.get(1)?, *s.get(2)?);
           let ext = if b0 & 0x80 != 0 { 0xFF } else { 0x00 };
           Some(i32::from_be_bytes([ext, b0, b1, b2]))
       }
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::reader` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/mod.rs crates/kvm-proto/src/flv/reader.rs crates/kvm-proto/src/lib.rs && git commit -m "kvm-proto: checked byte-reader cursor for FLV parsing" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.3: FLV header and tag header

**Files:**
- Create: `crates/kvm-proto/src/flv/header.rs`
- Modify: `crates/kvm-proto/src/flv/mod.rs`
- Test: in-file `#[cfg(test)] mod tests` in `header.rs`

**Interfaces:**
- Consumes: `flv::reader::Cur`.
- Produces: `flv::{FlvHeader, FlvLimits, FlvError}` (public); `flv::header::{TagHeader, parse_flv_header, parse_tag_header, HEADER_LEN, TAG_HEADER_LEN, PREV_TAG_SIZE_LEN}` (crate-internal). `parse_tag_header(buf: &[u8], limits: FlvLimits) -> Result<TagHeader, FlvError>` validates the filter bit, StreamID, and `data_size ≤ limit` **before** the body is buffered (§6.2).

**Steps:**

1. **Write the failing test.** In `flv/mod.rs` add `mod header;` and `pub use header::{FlvError, FlvHeader, FlvLimits};`. Create `crates/kvm-proto/src/flv/header.rs` with only:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;

       #[test]
       fn parses_video_only_header() {
           let hdr = [b'F', b'L', b'V', 0x01, 0x01, 0x00, 0x00, 0x00, 0x09];
           let h = parse_flv_header(&hdr).unwrap();
           assert_eq!(h.version, 1);
           assert!(h.has_video && !h.has_audio);
           assert_eq!(h.data_offset, 9);
       }

       #[test]
       fn rejects_bad_signature_and_offset() {
           assert_eq!(parse_flv_header(&[b'X', b'L', b'V', 1, 1, 0, 0, 0, 9]), Err(FlvError::BadHeader));
           assert_eq!(parse_flv_header(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 65]), Err(FlvError::BadHeader));
       }

       #[test]
       fn parses_tag_header_and_timestamp() {
           let th = [0x09, 0x00, 0x00, 0x19, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00];
           let t = parse_tag_header(&th, FlvLimits::default()).unwrap();
           assert_eq!(t.tag_type, 9);
           assert_eq!(t.data_size, 25);
           assert_eq!(t.timestamp, 0x21);
           assert_eq!(t.stream_id, 0);
       }

       #[test]
       fn rejects_encrypted_streamid_and_oversize() {
           let enc = [0x29, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
           assert_eq!(parse_tag_header(&enc, FlvLimits::default()), Err(FlvError::EncryptedTag));
           let sid = [0x09, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1];
           assert_eq!(parse_tag_header(&sid, FlvLimits::default()), Err(FlvError::BadStreamId));
           let big = [0x09, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0];
           assert_eq!(parse_tag_header(&big, FlvLimits::default()), Err(FlvError::OversizeTag));
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::header` — expect `E0425`/`E0433`: cannot find `parse_flv_header`, `FlvError`, `FlvLimits`.
3. **Minimal implementation.** Prepend to `header.rs`:
   ```rust
   use crate::flv::reader::Cur;

   pub(crate) const HEADER_LEN: usize = 9;
   pub(crate) const TAG_HEADER_LEN: usize = 11;
   pub(crate) const PREV_TAG_SIZE_LEN: usize = 4;

   /// Per-stream framing limits. `max_tag_size` is §6.2's 4 MiB tag cap; the
   /// remaining size-limit hardening is Plan B.
   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
   pub struct FlvLimits { pub max_tag_size: u32 }
   impl Default for FlvLimits {
       fn default() -> Self { Self { max_tag_size: 4_194_304 } }
   }

   /// A framing violation (§6.9, `parse_errors{kind}`). The M0 subset surfaces
   /// only the kinds reachable from demux; §6.1 admission kinds are Plan B.
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
   }

   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
   pub struct FlvHeader {
       pub version: u8,
       pub has_audio: bool,
       pub has_video: bool,
       pub data_offset: u32,
   }

   /// Parse the 9-byte FLV header; `DataOffset` must be 9 (≤ 64 tolerated).
   pub(crate) fn parse_flv_header(buf: &[u8]) -> Result<FlvHeader, FlvError> {
       let mut c = Cur::new(buf);
       if c.take(3).ok_or(FlvError::BadHeader)? != b"FLV" {
           return Err(FlvError::BadHeader);
       }
       let version = c.u8().ok_or(FlvError::BadHeader)?;
       let flags = c.u8().ok_or(FlvError::BadHeader)?;
       let data_offset = c.u32().ok_or(FlvError::BadHeader)?;
       if version != 1 || data_offset < 9 || data_offset > 64 {
           return Err(FlvError::BadHeader);
       }
       Ok(FlvHeader {
           version,
           has_audio: flags & 0x04 != 0,
           has_video: flags & 0x01 != 0,
           data_offset,
       })
   }

   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
   pub(crate) struct TagHeader {
       pub(crate) tag_type: u8,
       pub(crate) data_size: u32,
       pub(crate) timestamp: u32,
       pub(crate) stream_id: u32,
   }

   /// Parse an 11-byte tag header. `data_size` is checked against the limit
   /// here, before the body is buffered (§6.2).
   pub(crate) fn parse_tag_header(buf: &[u8], limits: FlvLimits) -> Result<TagHeader, FlvError> {
       let mut c = Cur::new(buf);
       let type_byte = c.u8().ok_or(FlvError::BadHeader)?;
       let data_size = c.u24().ok_or(FlvError::BadHeader)?;
       let ts_low = c.u24().ok_or(FlvError::BadHeader)?;
       let ts_ext = c.u8().ok_or(FlvError::BadHeader)?;
       let stream_id = c.u24().ok_or(FlvError::BadHeader)?;
       if type_byte & 0x20 != 0 {
           return Err(FlvError::EncryptedTag);
       }
       if stream_id != 0 {
           return Err(FlvError::BadStreamId);
       }
       if data_size > limits.max_tag_size {
           return Err(FlvError::OversizeTag);
       }
       let timestamp = u32::from(ts_ext).wrapping_shl(24) | ts_low;
       Ok(TagHeader { tag_type: type_byte & 0x1F, data_size, timestamp, stream_id })
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::header` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/header.rs crates/kvm-proto/src/flv/mod.rs && git commit -m "kvm-proto: FLV + tag headers, DataSize-before-buffering check (§6.2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.4: Incremental demux state machine (framing)

**Files:**
- Create: `crates/kvm-proto/src/flv/demux.rs`
- Modify: `crates/kvm-proto/src/flv/mod.rs`
- Test: in-file `#[cfg(test)] mod tests` in `demux.rs`

**Interfaces:**
- Consumes: `flv::header::{parse_flv_header, parse_tag_header, TagHeader, FlvError, FlvLimits, HEADER_LEN, TAG_HEADER_LEN, PREV_TAG_SIZE_LEN}`, `flv::reader::Cur`, `bytes::{Bytes, BytesMut}`.
- Produces: `flv::FlvDemuxer` with `new(FlvLimits) -> Self` and `push(&mut self, &[u8])` (public); `FlvDemuxer::next_raw_tag(&mut self) -> Result<Option<RawTag>, FlvError>` and `RawTag { tag_type: u8, data_size: u32, timestamp: u32, body: bytes::Bytes }` (crate-internal); `FlvDemuxer::length_size: Option<u8>` (crate-visible field, set by the AVC layer in Task 7). Validates `PrevTagSize0 == 0` and each `PrevTagSize == 11 + data_size`; skips the DataOffset gap; frames every tag type with a zero-copy body `Bytes`.

**Steps:**

1. **Write the failing test.** In `flv/mod.rs` add `mod demux;` and `pub use demux::FlvDemuxer;`. Create `crates/kvm-proto/src/flv/demux.rs` with only:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;
       use crate::flv::header::FlvLimits;

       /// Hand-built FLV: header + a video sequence-header tag + a video NALU
       /// (IDR) tag. No real capture is used.
       fn build_flv() -> Vec<u8> {
           let mut v = Vec::new();
           v.extend_from_slice(&[b'F', b'L', b'V', 0x01, 0x01, 0x00, 0x00, 0x00, 0x09]);
           v.extend_from_slice(&[0, 0, 0, 0]); // PrevTagSize0
           // Tag1: type 9, data_size 25, ts 0
           v.extend_from_slice(&[0x09, 0x00, 0x00, 0x19, 0, 0, 0, 0, 0, 0, 0]);
           v.extend_from_slice(&[0x17, 0x00, 0x00, 0x00, 0x00]); // key/AVC, seq header, CT 0
           v.extend_from_slice(&[0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05,
                                 0x67, 0x42, 0x00, 0x1E, 0x88, 0x01, 0x00, 0x04,
                                 0x68, 0xCE, 0x3C, 0x80]); // AVCDecoderConfigurationRecord
           v.extend_from_slice(&[0, 0, 0, 36]); // PrevTagSize1 = 11 + 25
           // Tag2: type 9, data_size 13, ts 0x21
           v.extend_from_slice(&[0x09, 0x00, 0x00, 0x0D, 0, 0, 0x21, 0, 0, 0, 0]);
           v.extend_from_slice(&[0x17, 0x01, 0x00, 0x00, 0x00]); // key/AVC, NALU, CT 0
           v.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x65, 0x88, 0x80, 0x10]); // 4-byte len + IDR NAL
           v.extend_from_slice(&[0, 0, 0, 24]); // PrevTagSize2 = 11 + 13
           v
       }

       #[test]
       fn frames_two_video_tags() {
           let mut d = FlvDemuxer::new(FlvLimits::default());
           d.push(&build_flv());
           let t1 = d.next_raw_tag().unwrap().unwrap();
           assert_eq!((t1.tag_type, t1.data_size, t1.timestamp, t1.body.len()), (9, 25, 0, 25));
           let t2 = d.next_raw_tag().unwrap().unwrap();
           assert_eq!((t2.tag_type, t2.data_size, t2.timestamp, t2.body.len()), (9, 13, 0x21, 13));
           assert!(d.next_raw_tag().unwrap().is_none());
       }

       #[test]
       fn is_incremental_across_pushes() {
           let flv = build_flv();
           let mut d = FlvDemuxer::new(FlvLimits::default());
           d.push(&flv[..20]);
           assert!(d.next_raw_tag().unwrap().is_none()); // first tag not yet complete
           d.push(&flv[20..]);
           assert!(d.next_raw_tag().unwrap().is_some());
           assert!(d.next_raw_tag().unwrap().is_some());
       }

       #[test]
       fn rejects_bad_prev_tag_size() {
           let mut flv = build_flv();
           let n = flv.len();
           flv[n - 1] = 0xFF; // corrupt PrevTagSize2
           let mut d = FlvDemuxer::new(FlvLimits::default());
           d.push(&flv);
           assert!(d.next_raw_tag().unwrap().is_some());
           assert_eq!(d.next_raw_tag(), Err(FlvError::BadPrevTagSize));
       }

       #[test]
       fn oversize_data_size_rejected_before_buffering() {
           let mut d = FlvDemuxer::new(FlvLimits::default());
           // header + PrevTagSize0 + tag header only, data_size = 0xFFFFFF
           d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0,
                    0x09, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0]);
           assert_eq!(d.next_raw_tag(), Err(FlvError::OversizeTag));
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::demux` — expect `E0433`/`E0599`: cannot find `FlvDemuxer`, `RawTag`, `next_raw_tag`.
3. **Minimal implementation.** Prepend to `demux.rs`:
   ```rust
   use bytes::{Bytes, BytesMut};
   use crate::flv::header::{
       parse_flv_header, parse_tag_header, FlvError, FlvLimits,
       HEADER_LEN, PREV_TAG_SIZE_LEN, TAG_HEADER_LEN,
   };
   use crate::flv::reader::Cur;

   /// A framed FLV tag with its body as a zero-copy `Bytes` slice of the
   /// reassembly buffer (§6.2 ownership note).
   #[derive(Clone, Debug)]
   pub(crate) struct RawTag {
       pub(crate) tag_type: u8,
       pub(crate) data_size: u32,
       pub(crate) timestamp: u32,
       pub(crate) body: Bytes,
   }

   #[derive(Clone, Copy, PartialEq, Eq)]
   enum State { Start, FirstPrev, Tag }

   /// Incremental FLV demuxer over an internal `BytesMut`.
   pub struct FlvDemuxer {
       buf: BytesMut,
       state: State,
       limits: FlvLimits,
       pub(crate) length_size: Option<u8>,
   }

   impl FlvDemuxer {
       pub fn new(limits: FlvLimits) -> Self {
           Self { buf: BytesMut::new(), state: State::Start, limits, length_size: None }
       }

       /// Append received bytes. One copy into the reassembly buffer; NAL/SPS
       /// slices taken from a tag body are shared without further copying.
       pub fn push(&mut self, data: &[u8]) {
           self.buf.extend_from_slice(data);
       }

       pub(crate) fn next_raw_tag(&mut self) -> Result<Option<RawTag>, FlvError> {
           loop {
               match self.state {
                   State::Start => {
                       let Some(head) = self.buf.as_ref().get(..HEADER_LEN) else {
                           return Ok(None);
                       };
                       let hdr = parse_flv_header(head)?;
                       let skip = usize::try_from(hdr.data_offset).unwrap_or(HEADER_LEN);
                       if self.buf.len() < skip {
                           return Ok(None);
                       }
                       let _ = self.buf.split_to(skip);
                       self.state = State::FirstPrev;
                   }
                   State::FirstPrev => {
                       let Some(pv) = self.buf.as_ref().get(..PREV_TAG_SIZE_LEN) else {
                           return Ok(None);
                       };
                       if Cur::new(pv).u32().ok_or(FlvError::BadPrevTagSize)? != 0 {
                           return Err(FlvError::BadPrevTagSize);
                       }
                       let _ = self.buf.split_to(PREV_TAG_SIZE_LEN);
                       self.state = State::Tag;
                   }
                   State::Tag => {
                       let Some(head) = self.buf.as_ref().get(..TAG_HEADER_LEN) else {
                           return Ok(None);
                       };
                       // data_size validated here, before buffering the body.
                       let th = parse_tag_header(head, self.limits)?;
                       let body_len = usize::try_from(th.data_size).unwrap_or(usize::MAX);
                       let total = TAG_HEADER_LEN
                           .checked_add(body_len)
                           .and_then(|n| n.checked_add(PREV_TAG_SIZE_LEN))
                           .ok_or(FlvError::OversizeTag)?;
                       if self.buf.len() < total {
                           return Ok(None);
                       }
                       let _ = self.buf.split_to(TAG_HEADER_LEN);
                       let body = self.buf.split_to(body_len).freeze();
                       let trailer = self.buf.split_to(PREV_TAG_SIZE_LEN);
                       let prev = Cur::new(trailer.as_ref()).u32().ok_or(FlvError::BadPrevTagSize)?;
                       let expected = u32::try_from(total.saturating_sub(PREV_TAG_SIZE_LEN))
                           .unwrap_or(u32::MAX);
                       if prev != expected {
                           return Err(FlvError::BadPrevTagSize);
                       }
                       return Ok(Some(RawTag {
                           tag_type: th.tag_type,
                           data_size: th.data_size,
                           timestamp: th.timestamp,
                           body,
                       }));
                   }
               }
           }
       }
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::demux` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/demux.rs crates/kvm-proto/src/flv/mod.rs && git commit -m "kvm-proto: incremental FLV demux framing (PrevTagSize, zero-copy body)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.5: AVCDecoderConfigurationRecord parser + Nal

**Files:**
- Create: `crates/kvm-proto/src/flv/avc.rs`
- Modify: `crates/kvm-proto/src/flv/mod.rs`
- Test: in-file `#[cfg(test)] mod tests` in `avc.rs`

**Interfaces:**
- Consumes: `flv::header::FlvError`, `flv::reader::Cur`, `bytes::Bytes`.
- Produces: `flv::{Nal, AvcConfig}` (public); `Nal { bytes: bytes::Bytes }` with `unit_type(&self) -> Option<u8>` and `ref_idc(&self) -> Option<u8>`; `AvcConfig { length_size_minus_one: u8, profile_idc: u8, level_idc: u8, sps: Vec<bytes::Bytes>, pps: Vec<bytes::Bytes> }`; `flv::avc::parse_avc_config(body: &bytes::Bytes, start: usize) -> Result<AvcConfig, FlvError>` (crate-internal), SPS/PPS extracted as zero-copy slices; `length_size_minus_one == 2` → `FlvError::BadLengthSize` (§6.2 `{0,1,3}`).

**Steps:**

1. **Write the failing test.** In `flv/mod.rs` add `mod avc;` and `pub use avc::{AvcConfig, Nal};`. Create `crates/kvm-proto/src/flv/avc.rs` with only:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;
       use bytes::Bytes;

       #[test]
       fn nal_header_fields() {
           let n = Nal { bytes: Bytes::from_static(&[0x65, 0x88]) };
           assert_eq!(n.unit_type(), Some(5));
           assert_eq!(n.ref_idc(), Some(3));
           assert_eq!(Nal { bytes: Bytes::new() }.unit_type(), None);
       }

       #[test]
       fn parses_avcc_and_extracts_sps_pps() {
           let body = Bytes::from_static(&[
               0x17, 0x00, 0x00, 0x00, 0x00, // 5-byte FLV AVC header
               0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05,
               0x67, 0x42, 0x00, 0x1E, 0x88, 0x01, 0x00, 0x04,
               0x68, 0xCE, 0x3C, 0x80,
           ]);
           let cfg = parse_avc_config(&body, 5).unwrap();
           assert_eq!(cfg.length_size_minus_one, 3);
           assert_eq!((cfg.profile_idc, cfg.level_idc), (0x42, 0x1E));
           assert_eq!(cfg.sps, vec![Bytes::from_static(&[0x67, 0x42, 0x00, 0x1E, 0x88])]);
           assert_eq!(cfg.pps, vec![Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])]);
       }

       #[test]
       fn rejects_bad_length_size_and_truncation() {
           // lengthSizeMinusOne = 2 (0xFE & 0x03)
           let bad_ls = Bytes::from_static(&[0x17, 0, 0, 0, 0, 0x01, 0x42, 0x00, 0x1E, 0xFE, 0xE0]);
           assert_eq!(parse_avc_config(&bad_ls, 5), Err(FlvError::BadLengthSize));
           // SPS length 0x0005 but only 1 byte present
           let short = Bytes::from_static(&[0x17, 0, 0, 0, 0, 0x01, 0x42, 0x00, 0x1E, 0xFF, 0xE1, 0x00, 0x05, 0x67]);
           assert_eq!(parse_avc_config(&short, 5), Err(FlvError::BadConfigRecord));
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::avc` — expect `E0425`/`E0433`: cannot find `Nal`, `parse_avc_config`.
3. **Minimal implementation.** Prepend to `avc.rs`:
   ```rust
   use bytes::Bytes;
   use crate::flv::header::FlvError;
   use crate::flv::reader::Cur;

   /// A raw H.264 NAL unit (no start code, no length prefix), shared with the
   /// FLV buffer without copying.
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub struct Nal { pub bytes: Bytes }

   impl Nal {
       /// `nal_unit_type` (header byte & 0x1F).
       pub fn unit_type(&self) -> Option<u8> { self.bytes.first().map(|b| b & 0x1F) }
       /// `nal_ref_idc` ((header byte >> 5) & 0x3).
       pub fn ref_idc(&self) -> Option<u8> { self.bytes.first().map(|b| b.wrapping_shr(5) & 0x3) }
   }

   /// Parsed `AVCDecoderConfigurationRecord` (ISO 14496-15). SPS/PPS are
   /// zero-copy slices of the tag body (§6.2). Count/size caps (1–4 SPS,
   /// 1–16 PPS, ≤ 1 KiB each) are Plan B hardening.
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub struct AvcConfig {
       pub length_size_minus_one: u8,
       pub profile_idc: u8,
       pub level_idc: u8,
       pub sps: Vec<Bytes>,
       pub pps: Vec<Bytes>,
   }

   /// Parse the config record starting at `start` (past the 5-byte FLV AVC
   /// header). `body` is the whole tag body so slices share its allocation.
   pub(crate) fn parse_avc_config(body: &Bytes, start: usize) -> Result<AvcConfig, FlvError> {
       let region = body.as_ref().get(start..).ok_or(FlvError::BadConfigRecord)?;
       let mut c = Cur::new(region);
       if c.u8().ok_or(FlvError::BadConfigRecord)? != 1 {
           return Err(FlvError::BadConfigRecord);
       }
       let profile_idc = c.u8().ok_or(FlvError::BadConfigRecord)?;
       let _compat = c.u8().ok_or(FlvError::BadConfigRecord)?;
       let level_idc = c.u8().ok_or(FlvError::BadConfigRecord)?;
       let length_size_minus_one = c.u8().ok_or(FlvError::BadConfigRecord)? & 0x03;
       if length_size_minus_one == 2 {
           return Err(FlvError::BadLengthSize);
       }
       let num_sps = c.u8().ok_or(FlvError::BadConfigRecord)? & 0x1F;
       let sps = read_param_sets(body, &mut c, start, num_sps)?;
       let num_pps = c.u8().ok_or(FlvError::BadConfigRecord)?;
       let pps = read_param_sets(body, &mut c, start, num_pps)?;
       Ok(AvcConfig { length_size_minus_one, profile_idc, level_idc, sps, pps })
   }

   fn read_param_sets(body: &Bytes, c: &mut Cur<'_>, start: usize, count: u8) -> Result<Vec<Bytes>, FlvError> {
       let mut out = Vec::new();
       for _ in 0..count {
           let len = usize::from(c.u16().ok_or(FlvError::BadConfigRecord)?);
           let at = start.checked_add(c.pos()).ok_or(FlvError::BadConfigRecord)?;
           let end = at.checked_add(len).ok_or(FlvError::BadConfigRecord)?;
           if body.as_ref().get(at..end).is_none() {
               return Err(FlvError::BadConfigRecord);
           }
           let _ = c.take(len).ok_or(FlvError::BadConfigRecord)?;
           out.push(body.slice(at..end));
       }
       Ok(out)
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::avc` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/avc.rs crates/kvm-proto/src/flv/mod.rs && git commit -m "kvm-proto: AVCDecoderConfigurationRecord parse + zero-copy SPS/PPS (§6.2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.6: NALU splitter (length-prefixed)

**Files:**
- Modify: `crates/kvm-proto/src/flv/avc.rs`
- Test: add cases to the `#[cfg(test)] mod tests` in `avc.rs`

**Interfaces:**
- Consumes: `flv::avc::Nal`, `flv::header::FlvError`, `bytes::Bytes`.
- Produces: `flv::avc::parse_nalus(body: &bytes::Bytes, start: usize, length_size: u8) -> Result<Vec<Nal>, FlvError>` (crate-internal). Zero-copy NAL slices; `0 < n ≤ remaining` enforced (§6.2) → `FlvError::MalformedVideoTag` otherwise. The NAL allowlist, forbidden-bit and start-code refusal are Plan B.

**Steps:**

1. **Write the failing test.** Append to the test module in `avc.rs`:
   ```rust
   #[test]
   fn splits_four_byte_length_nal() {
       let body = Bytes::from_static(&[0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x04, 0x65, 0x88, 0x80, 0x10]);
       let nals = parse_nalus(&body, 5, 4).unwrap();
       assert_eq!(nals.len(), 1);
       assert_eq!(nals[0].bytes, Bytes::from_static(&[0x65, 0x88, 0x80, 0x10]));
       assert_eq!(nals[0].unit_type(), Some(5));
   }

   #[test]
   fn splits_two_one_byte_length_nals() {
       let body = Bytes::from_static(&[0x27, 0x01, 0, 0, 0, 0x02, 0x67, 0x88, 0x03, 0x68, 0xCE, 0x3C]);
       let nals = parse_nalus(&body, 5, 1).unwrap();
       assert_eq!(nals.len(), 2);
       assert_eq!(nals[0].bytes, Bytes::from_static(&[0x67, 0x88]));
       assert_eq!(nals[1].bytes, Bytes::from_static(&[0x68, 0xCE, 0x3C]));
   }

   #[test]
   fn rejects_overrun_and_zero_length() {
       let overrun = Bytes::from_static(&[0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x09, 0x65, 0x88]);
       assert_eq!(parse_nalus(&overrun, 5, 4), Err(FlvError::MalformedVideoTag));
       let zero = Bytes::from_static(&[0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x00]);
       assert_eq!(parse_nalus(&zero, 5, 4), Err(FlvError::MalformedVideoTag));
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::avc` — expect `E0425`: cannot find `parse_nalus`.
3. **Minimal implementation.** Append to `avc.rs` (above the test module):
   ```rust
   /// Split length-prefixed NALs out of an AVC NALU tag body (zero-copy).
   /// `start` is past the 5-byte FLV AVC header; `length_size` is 1, 2 or 4.
   pub(crate) fn parse_nalus(body: &Bytes, start: usize, length_size: u8) -> Result<Vec<Nal>, FlvError> {
       let mut nals = Vec::new();
       let mut at = start;
       let ls = usize::from(length_size);
       loop {
           if body.len().saturating_sub(at) == 0 {
               break;
           }
           let len_end = at.checked_add(ls).ok_or(FlvError::MalformedVideoTag)?;
           let len_bytes = body.as_ref().get(at..len_end).ok_or(FlvError::MalformedVideoTag)?;
           let nal_len = read_len(len_bytes);
           let nal_end = len_end.checked_add(nal_len).ok_or(FlvError::MalformedVideoTag)?;
           if nal_len == 0 || body.as_ref().get(len_end..nal_end).is_none() {
               return Err(FlvError::MalformedVideoTag); // 0 < n ≤ remaining (§6.2)
           }
           nals.push(Nal { bytes: body.slice(len_end..nal_end) });
           at = nal_end;
       }
       Ok(nals)
   }

   /// Big-endian NAL length of 1–4 bytes.
   fn read_len(bytes: &[u8]) -> usize {
       let mut v: usize = 0;
       for b in bytes {
           v = v.wrapping_shl(8).wrapping_add(usize::from(*b));
       }
       v
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::avc` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/avc.rs && git commit -m "kvm-proto: zero-copy NALU splitter with checked lengths (§6.2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.7: Video-body dispatch + public `next_tag`

**Files:**
- Modify: `crates/kvm-proto/src/flv/avc.rs`, `crates/kvm-proto/src/flv/demux.rs`, `crates/kvm-proto/src/flv/mod.rs`
- Test: add cases to the `#[cfg(test)] mod tests` in `demux.rs`

**Interfaces:**
- Consumes: `flv::avc::{AvcConfig, Nal, parse_avc_config, parse_nalus}`, `flv::demux::{FlvDemuxer, RawTag}`, `flv::header::FlvError`, `flv::reader::Cur`, `bytes::Bytes`.
- Produces: `flv::{FrameType, VideoBody, TagBody, FlvTag}` (public); `FrameType` = `Key | Inter | Other(u8)`; `VideoBody` = `SequenceHeader(AvcConfig) | Nalus { frame_type: FrameType, composition_time: i32, nals: Vec<Nal> } | EndOfSequence | NonAvc { codec_id: u8, frame_type: FrameType } | Enhanced { packet_type: u8, frame_type: FrameType, fourcc: [u8; 4] }` (Enhanced-RTMP `IsExHeader` tags — e.g. HEVC as `hvc1` — are surfaced, never misread as AVC; §6.1 refuses them in Plan C, the census records them); `TagBody` = `Audio | ScriptData | Video(VideoBody) | Other(u8)`; `FlvTag { tag_type: u8, data_size: u32, timestamp: u32, body: TagBody }`; `FlvDemuxer::next_tag(&mut self) -> Result<Option<FlvTag>, FlvError>`. A NALU tag before any sequence header → `FlvError::NalBeforeSequenceHeader` (§6.9).

**Steps:**

1. **Write the failing test.** In `flv/mod.rs` add `pub use avc::{FrameType, VideoBody};` and `pub use demux::{FlvTag, TagBody};`. Append to the test module in `demux.rs`:
   ```rust
   use crate::flv::{FrameType, TagBody, VideoBody};

   #[test]
   fn next_tag_parses_seqheader_then_idr() {
       let mut d = FlvDemuxer::new(FlvLimits::default());
       d.push(&build_flv());
       let t1 = d.next_tag().unwrap().unwrap();
       match t1.body {
           TagBody::Video(VideoBody::SequenceHeader(cfg)) => {
               assert_eq!(cfg.length_size_minus_one, 3);
               assert_eq!(cfg.sps.len(), 1);
               assert_eq!(cfg.pps.len(), 1);
           }
           other => panic!("expected seq header, got {other:?}"),
       }
       let t2 = d.next_tag().unwrap().unwrap();
       match t2.body {
           TagBody::Video(VideoBody::Nalus { frame_type, composition_time, nals }) => {
               assert_eq!(frame_type, FrameType::Key);
               assert_eq!(composition_time, 0);
               assert_eq!(nals.len(), 1);
               assert_eq!(nals[0].unit_type(), Some(5));
           }
           other => panic!("expected NALU AU, got {other:?}"),
       }
       assert!(d.next_tag().unwrap().is_none());
   }

   #[test]
   fn nalu_before_sequence_header_is_fatal() {
       let mut d = FlvDemuxer::new(FlvLimits::default());
       d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0]);
       // a video NALU tag (data_size 13) with no prior seq header
       d.push(&[0x09, 0x00, 0x00, 0x0D, 0, 0, 0, 0, 0, 0, 0,
                0x17, 0x01, 0, 0, 0, 0x00, 0x00, 0x00, 0x04, 0x65, 0x88, 0x80, 0x10,
                0, 0, 0, 24]);
       assert_eq!(d.next_tag(), Err(FlvError::NalBeforeSequenceHeader));
   }

   #[test]
   fn audio_and_script_tags_surface_without_body_parse() {
       let mut d = FlvDemuxer::new(FlvLimits::default());
       d.push(&[b'F', b'L', b'V', 1, 0x05, 0, 0, 0, 9, 0, 0, 0, 0]);
       // one audio tag (type 8, data_size 1), then one script tag (type 18, data_size 1)
       d.push(&[0x08, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0xAF, 0, 0, 0, 12]);
       d.push(&[0x12, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 12]);
       assert!(matches!(d.next_tag().unwrap().unwrap().body, TagBody::Audio));
       assert!(matches!(d.next_tag().unwrap().unwrap().body, TagBody::ScriptData));
   }

   #[test]
   fn enhanced_rtmp_hevc_tag_is_surfaced_not_misread_as_avc() {
       let mut d = FlvDemuxer::new(FlvLimits::default());
       d.push(&[b'F', b'L', b'V', 1, 1, 0, 0, 0, 9, 0, 0, 0, 0]);
       // video tag, data_size 5: IsExHeader|FrameType=1(key)|PacketType=0, FourCC "hvc1"
       d.push(&[0x09, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0,
                0x90, b'h', b'v', b'c', b'1',
                0, 0, 0, 16]);
       match d.next_tag().unwrap().unwrap().body {
           TagBody::Video(VideoBody::Enhanced { packet_type, frame_type, fourcc }) => {
               assert_eq!(packet_type, 0);
               assert_eq!(frame_type, FrameType::Key);
               assert_eq!(&fourcc, b"hvc1");
           }
           other => panic!("expected Enhanced, got {other:?}"),
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::demux` — expect `E0599`/`E0433`: cannot find `next_tag`, `TagBody`, `VideoBody`.
3. **Minimal implementation.** Append to `avc.rs` (above the test module):
   ```rust
   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
   pub enum FrameType { Key, Inter, Other(u8) }

   #[derive(Clone, Debug, PartialEq, Eq)]
   pub enum VideoBody {
       SequenceHeader(AvcConfig),
       Nalus { frame_type: FrameType, composition_time: i32, nals: Vec<Nal> },
       EndOfSequence,
       NonAvc { codec_id: u8, frame_type: FrameType },
       /// Enhanced-RTMP `IsExHeader` tag: bits 6..4 frame type, bits 3..0
       /// packet type, then a 4-byte FourCC (`hvc1`, `av01`, …).
       Enhanced { packet_type: u8, frame_type: FrameType, fourcc: [u8; 4] },
   }

   const AVC_HEADER_LEN: usize = 5;
   const CODEC_AVC: u8 = 7;
   const IS_EX_HEADER: u8 = 0x80;

   /// Parse an FLV video tag body (§6.2). `length_size` is the current
   /// `lengthSizeMinusOne + 1`, needed for NALU tags.
   pub(crate) fn parse_video_body(body: &Bytes, length_size: Option<u8>) -> Result<VideoBody, FlvError> {
       let mut c = Cur::new(body.as_ref());
       let b0 = c.u8().ok_or(FlvError::MalformedVideoTag)?;
       if b0 & IS_EX_HEADER != 0 {
           let frame_type = match b0.wrapping_shr(4) & 0x07 {
               1 => FrameType::Key,
               2 => FrameType::Inter,
               other => FrameType::Other(other),
           };
           let fourcc = [
               c.u8().ok_or(FlvError::MalformedVideoTag)?,
               c.u8().ok_or(FlvError::MalformedVideoTag)?,
               c.u8().ok_or(FlvError::MalformedVideoTag)?,
               c.u8().ok_or(FlvError::MalformedVideoTag)?,
           ];
           return Ok(VideoBody::Enhanced { packet_type: b0 & 0x0F, frame_type, fourcc });
       }
       let frame_type = match b0.wrapping_shr(4) {
           1 => FrameType::Key,
           2 => FrameType::Inter,
           other => FrameType::Other(other),
       };
       let codec_id = b0 & 0x0F;
       if codec_id != CODEC_AVC {
           return Ok(VideoBody::NonAvc { codec_id, frame_type });
       }
       let packet_type = c.u8().ok_or(FlvError::MalformedVideoTag)?;
       let composition_time = c.i24().ok_or(FlvError::MalformedVideoTag)?;
       match packet_type {
           0 => Ok(VideoBody::SequenceHeader(parse_avc_config(body, AVC_HEADER_LEN)?)),
           1 => {
               let ls = length_size.ok_or(FlvError::NalBeforeSequenceHeader)?;
               Ok(VideoBody::Nalus { frame_type, composition_time, nals: parse_nalus(body, AVC_HEADER_LEN, ls)? })
           }
           2 => Ok(VideoBody::EndOfSequence),
           _ => Err(FlvError::MalformedVideoTag),
       }
   }
   ```
   Append to `demux.rs` (above the test module), extending the `use` line to `use crate::flv::avc::{parse_video_body, VideoBody};`:
   ```rust
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub enum TagBody { Audio, ScriptData, Video(VideoBody), Other(u8) }

   #[derive(Clone, Debug, PartialEq, Eq)]
   pub struct FlvTag {
       pub tag_type: u8,
       pub data_size: u32,
       pub timestamp: u32,
       pub body: TagBody,
   }

   impl FlvDemuxer {
       /// Parsed next tag (§6.2). Video tags decode into `VideoBody` with
       /// zero-copy NAL/SPS/PPS slices; audio (8) and script-data (18) tags are
       /// framed and surfaced but their bodies are not parsed.
       pub fn next_tag(&mut self) -> Result<Option<FlvTag>, FlvError> {
           let Some(raw) = self.next_raw_tag()? else { return Ok(None) };
           let body = match raw.tag_type {
               8 => TagBody::Audio,
               18 => TagBody::ScriptData,
               9 => {
                   let vb = parse_video_body(&raw.body, self.length_size)?;
                   if let VideoBody::SequenceHeader(ref cfg) = vb {
                       self.length_size = Some(cfg.length_size_minus_one.wrapping_add(1));
                   }
                   TagBody::Video(vb)
               }
               other => TagBody::Other(other),
           };
           Ok(Some(FlvTag { tag_type: raw.tag_type, data_size: raw.data_size, timestamp: raw.timestamp, body }))
       }
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::demux flv::avc` → passes. `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/avc.rs crates/kvm-proto/src/flv/demux.rs crates/kvm-proto/src/flv/mod.rs && git commit -m "kvm-proto: FLV video-body dispatch and public next_tag (§6.2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

### Task 2.8: Burst marking (FLV-timestamp vs receive-time)

**Files:**
- Create: `crates/kvm-proto/src/flv/burst.rs`
- Modify: `crates/kvm-proto/src/flv/mod.rs`
- Test: in-file `#[cfg(test)] mod tests` in `burst.rs`

**Interfaces:**
- Consumes: `core::time::Duration`, `std::time::Instant`.
- Produces: `flv::BurstMarker` with `new(threshold: core::time::Duration) -> Self`, `mark(&mut self, flv_ts_ms: u32, now: std::time::Instant) -> bool`, `reset(&mut self)`. A tag whose FLV timestamp runs > threshold (default 100 ms) ahead of its receive time since the FLV connection's first tag is a burst (§6.2); `reset` re-baselines on a new FLV connection.

**Steps:**

1. **Write the failing test.** In `flv/mod.rs` add `mod burst;` and `pub use burst::BurstMarker;`. Create `crates/kvm-proto/src/flv/burst.rs` with only:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,
                clippy::indexing_slicing, clippy::arithmetic_side_effects,
                clippy::as_conversions)]
       use super::*;
       use core::time::Duration;
       use std::time::Instant;

       #[test]
       fn first_is_never_burst_then_detects_replay() {
           let t0 = Instant::now();
           let mut m = BurstMarker::new(Duration::from_millis(100));
           assert!(!m.mark(1000, t0));                               // baseline
           assert!(m.mark(1500, t0 + Duration::from_millis(300)));   // 200 ms ahead > 100 ms
           assert!(!m.mark(1200, t0 + Duration::from_millis(300)));  // behind real time
       }

       #[test]
       fn reset_rebaselines_on_new_connection() {
           let t0 = Instant::now();
           let mut m = BurstMarker::new(Duration::from_millis(100));
           assert!(!m.mark(1000, t0));
           m.reset();
           assert!(!m.mark(9999, t0 + Duration::from_millis(50)));   // new baseline, not a burst
       }
   }
   ```
2. **Run it (red).** `cargo test -p kvm-proto flv::burst` — expect `E0433`: cannot find `BurstMarker`.
3. **Minimal implementation.** Prepend to `burst.rs`:
   ```rust
   use core::time::Duration;
   use std::time::Instant;

   /// Marks access units that arrive faster than real time — a GOP-caching
   /// source replaying on connect (§6.2). State is per FLV connection; `reset`
   /// re-baselines from the next connection's first tag.
   pub struct BurstMarker {
       baseline: Option<(u32, Instant)>,
       threshold: Duration,
   }

   impl BurstMarker {
       pub fn new(threshold: Duration) -> Self {
           Self { baseline: None, threshold }
       }

       pub fn reset(&mut self) {
           self.baseline = None;
       }

       /// Record a tag's FLV timestamp (ms) and receive time; returns whether
       /// it is a burst. The first tag of a connection sets the baseline and is
       /// never a burst.
       pub fn mark(&mut self, flv_ts_ms: u32, now: Instant) -> bool {
           match self.baseline {
               None => {
                   self.baseline = Some((flv_ts_ms, now));
                   false
               }
               Some((ts0, recv0)) => {
                   let flv_elapsed = u128::from(flv_ts_ms.saturating_sub(ts0));
                   let recv_elapsed = now.saturating_duration_since(recv0).as_millis();
                   let bound = recv_elapsed.saturating_add(self.threshold.as_millis());
                   flv_elapsed > bound
               }
           }
       }
   }
   ```
4. **Run to pass (green).** `cargo test -p kvm-proto flv::burst` → passes. Full crate: `cargo test -p kvm-proto` and `cargo clippy -p kvm-proto --all-targets -- -D warnings` → clean.
5. **Commit.** `git add crates/kvm-proto/src/flv/burst.rs crates/kvm-proto/src/flv/mod.rs && git commit -m "kvm-proto: FLV burst marking (timestamp vs receive-time, §6.2)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`
## Part 3 — kvm-proto: H.264 helpers

AVCC→Annex-B, NAL headers, SPS inspection, admission limits, slice-header prefix and SPS-change classification.

> **House conventions for every task below.** Crate layout mirrors IronRDP: crates live under `crates/<name>/`. Edition 2024, `rust-version = "1.94"`. The nix devshell (owned by the repo-scaffold/devshell component, §4.2/§13 — not authored here) wraps cargo as `systemd-run --user --scope -p CPUWeight=20 -p IOWeight=20 -p MemoryMax=8G nice -n 19 cargo …`, with `CARGO_TARGET_DIR` (one shared dir across worktrees) and `jobs = 4` from `.cargo/config.toml`. Every `cargo …` below runs through that wrapper; outside the devshell, prefix `nice -n 19`. All git commands target the `/home/chris/Repos/kvm-rdp` repo and commit to the `plan-a` branch. This is the *unhardened* M0 subset (§12): full fuzzing and the remaining admission limits are Plan B — but per the task brief these parsers already face hostile input, so every parser module denies the panicking clippy lints (§6.2) and uses checked access.

---

### Task 3.1: the `h264` module namespace in kvm-proto

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/lib.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs` (unit test `tests::module_is_reachable`)

**Interfaces:**
- Consumes: the workspace and kvm-proto crate from the scaffolding tasks (`h264-reader` already declared through `[workspace.dependencies]`).
- Produces: `kvm_proto::h264` — the namespace every later H.264 task adds a submodule and `pub use` line to.

**Steps:**

1. Write the failing test. Create `crates/kvm-proto/src/h264/mod.rs`:
   ```rust
   //! H.264 helpers: AVCC→Annex-B, NAL header/allowlist, SPS inspection and
   //! change classification, slice-header prefix. Parsers face attacker input
   //! (spec §2, §6.1, §6.2); the crate-root deny lints apply here too.

   #[cfg(test)]
   mod tests {
       #[test]
       fn module_is_reachable() {
           assert_eq!(module_path!(), "kvm_proto::h264::tests");
       }
   }
   ```

2. Run it — it fails to compile into the crate because nothing declares the module yet, so the test does not exist:
   ```
   cargo test -p kvm-proto h264::tests::module_is_reachable
   ```
   Expected: `running 0 tests` (filter matches nothing).

3. Minimal implementation — add to `crates/kvm-proto/src/lib.rs`, next to the other `pub mod` lines:
   ```rust
   pub mod h264;
   ```

4. Run to pass:
   ```
   cargo test -p kvm-proto h264::tests::module_is_reachable
   ```
   Expected: `test h264::tests::module_is_reachable ... ok`.

5. Commit:
   ```
   git add crates/kvm-proto/src/h264/mod.rs crates/kvm-proto/src/lib.rs
   git commit -m "kvm-proto: h264 module namespace" \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.2: AVCC → Annex-B conversion honoring NAL length-prefix width {1,2,4}

> **Reconciliation note.** The brief says "lengthSizeMinusOne ∈ {1,2,4}"; spec §6.2 says the `AVCDecoderConfigurationRecord` carries `lengthSizeMinusOne ∈ {0,1,3}`, and §11.5 says kvm-sim controls "length-prefix size 1/2/4". These are the same quantity: the function takes the length-prefix **width in bytes** (1, 2 or 4) = `lengthSizeMinusOne + 1`. Output is Annex-B with 4-byte start codes (§6.3).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/annexb.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: inline `#[cfg(test)] mod tests` in `annexb.rs`

**Interfaces:**
- Consumes: `std` slices only.
- Produces:
  - `pub fn avcc_to_annex_b(data: &[u8], nal_length_size: usize, out: &mut Vec<u8>) -> Result<(), AvccError>`
  - `pub enum AvccError { BadLengthSize(usize), TruncatedPrefix, NalLengthZero, NalExceedsBuffer { nal_len: usize, remaining: usize } }`

**Steps:**

1. Add the module + re-export to `h264/mod.rs`:
   ```rust
   mod annexb;
   pub use annexb::{avcc_to_annex_b, AvccError};
   ```

2. Write the failing test block at the bottom of a new `annexb.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(
           clippy::indexing_slicing,
           clippy::unwrap_used,
           clippy::arithmetic_side_effects,
           clippy::as_conversions
       )]
       use super::*;

       #[test]
       fn four_byte_prefix_two_nals() {
           // len=3 [67 42 00], len=2 [68 ce]
           let avcc = [0, 0, 0, 3, 0x67, 0x42, 0x00, 0, 0, 0, 2, 0x68, 0xce];
           let mut out = Vec::new();
           avcc_to_annex_b(&avcc, 4, &mut out).unwrap();
           assert_eq!(
               out,
               [0, 0, 0, 1, 0x67, 0x42, 0x00, 0, 0, 0, 1, 0x68, 0xce]
           );
       }

       #[test]
       fn one_byte_prefix() {
           let avcc = [3, 0x65, 0x11, 0x22];
           let mut out = Vec::new();
           avcc_to_annex_b(&avcc, 1, &mut out).unwrap();
           assert_eq!(out, [0, 0, 0, 1, 0x65, 0x11, 0x22]);
       }

       #[test]
       fn two_byte_prefix_appends_not_clears() {
           let avcc = [0, 1, 0xaa];
           let mut out = vec![0xff]; // pre-existing content is preserved
           avcc_to_annex_b(&avcc, 2, &mut out).unwrap();
           assert_eq!(out, [0xff, 0, 0, 0, 1, 0xaa]);
       }

       #[test]
       fn bad_length_size_rejected() {
           let mut out = Vec::new();
           assert_eq!(
               avcc_to_annex_b(&[0, 0, 0, 1, 0xaa], 3, &mut out),
               Err(AvccError::BadLengthSize(3))
           );
       }

       #[test]
       fn zero_length_nal_rejected() {
           let mut out = Vec::new();
           assert_eq!(
               avcc_to_annex_b(&[0, 0, 0, 0], 4, &mut out),
               Err(AvccError::NalLengthZero)
           );
       }

       #[test]
       fn nal_exceeds_buffer_rejected() {
           let mut out = Vec::new();
           // claims 5 bytes, only 2 remain
           assert_eq!(
               avcc_to_annex_b(&[0, 0, 0, 5, 0xaa, 0xbb], 4, &mut out),
               Err(AvccError::NalExceedsBuffer { nal_len: 5, remaining: 2 })
           );
       }

       #[test]
       fn truncated_prefix_rejected() {
           let mut out = Vec::new();
           assert_eq!(
               avcc_to_annex_b(&[0, 0], 4, &mut out),
               Err(AvccError::TruncatedPrefix)
           );
       }
   }
   ```

3. Run:
   ```bash
   cargo test -p kvm-proto h264::annexb
   ```
   Expected: fails to compile — `cannot find function 'avcc_to_annex_b'` and `cannot find type 'AvccError'` (E0425/E0412).

4. Write the implementation at the top of `annexb.rs`:
   ```rust
   //! AVCC (length-prefixed) → Annex-B conversion (spec §6.3 output contract).
   //! Hostile input: no panics, checked access, saturating/checked arithmetic.
   #![deny(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   /// Why an AVCC buffer could not be converted. Maps to a framing violation
   /// (spec §6.9) in the demuxer.
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub enum AvccError {
       /// `nal_length_size` was not 1, 2 or 4.
       BadLengthSize(usize),
       /// The buffer ended inside a length prefix.
       TruncatedPrefix,
       /// A NAL declared length 0 (spec §6.2: `0 < n`).
       NalLengthZero,
       /// A NAL length ran past the end of the buffer (spec §6.2: `n <= remaining`).
       NalExceedsBuffer { nal_len: usize, remaining: usize },
   }

   /// Convert one AVCC buffer into Annex-B with 4-byte start codes, **appending**
   /// into `out` (the caller owns clearing/reuse — spec §6.2/§6.3 build an AU by
   /// concatenating cached SPS/PPS and VCL NALs into one reused buffer).
   ///
   /// `nal_length_size` is the NAL length-prefix width in bytes: 1, 2 or 4
   /// (= `AVCDecoderConfigurationRecord.lengthSizeMinusOne + 1`; §6.2 admits
   /// `lengthSizeMinusOne ∈ {0,1,3}`).
   pub fn avcc_to_annex_b(
       data: &[u8],
       nal_length_size: usize,
       out: &mut Vec<u8>,
   ) -> Result<(), AvccError> {
       if !matches!(nal_length_size, 1 | 2 | 4) {
           return Err(AvccError::BadLengthSize(nal_length_size));
       }
       let mut rest = data;
       while !rest.is_empty() {
           let (prefix, after_prefix) = rest
               .split_at_checked(nal_length_size)
               .ok_or(AvccError::TruncatedPrefix)?;
           let mut nal_len: usize = 0;
           for &b in prefix {
               // nal_length_size <= 4 so at most a 32-bit value; wrapping_shl
               // keeps us clear of clippy::arithmetic_side_effects.
               nal_len = nal_len.wrapping_shl(8) | usize::from(b);
           }
           if nal_len == 0 {
               return Err(AvccError::NalLengthZero);
           }
           let (nal, tail) =
               after_prefix
                   .split_at_checked(nal_len)
                   .ok_or(AvccError::NalExceedsBuffer {
                       nal_len,
                       remaining: after_prefix.len(),
                   })?;
           out.extend_from_slice(&[0, 0, 0, 1]);
           out.extend_from_slice(nal);
           rest = tail;
       }
       Ok(())
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::annexb
   ```
   Expected: 7 passed.

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: AVCC->Annex-B conversion (prefix width 1/2/4)

   Appends 4-byte-start-code Annex-B into a caller-owned buffer (reuse per
   §6.3). Checked access, no panics; rejects bad prefix width, zero-length and
   over-long NALs as framing violations (§6.2).

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.3: NAL header parse (forbidden bit, `nal_ref_idc`, type)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/nal.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: inline `#[cfg(test)] mod tests` in `nal.rs`

**Interfaces:**
- Consumes: `std` only (hand-rolled; does not use h264-reader's `NalHeader`, so its error kinds map to §6.9 framing violations).
- Produces:
  - `pub struct NalHeader { pub nal_ref_idc: u8, pub nal_unit_type: u8 }`
  - `pub fn NalHeader::parse(byte: u8) -> Result<NalHeader, NalHeaderError>`
  - `pub fn NalHeader::from_nal(nal: &[u8]) -> Result<NalHeader, NalHeaderError>`
  - `pub enum NalHeaderError { ForbiddenBitSet, Empty }`

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   mod nal;
   pub use nal::{NalHeader, NalHeaderError};
   ```

2. Write the failing test at the bottom of `nal.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn sps_header_byte() {
           // 0x67 = forbidden 0, nal_ref_idc 3, type 7
           assert_eq!(
               NalHeader::parse(0x67),
               Ok(NalHeader { nal_ref_idc: 3, nal_unit_type: 7 })
           );
       }

       #[test]
       fn idr_slice_header_byte() {
           // 0x65 = forbidden 0, nal_ref_idc 3, type 5
           assert_eq!(
               NalHeader::parse(0x65),
               Ok(NalHeader { nal_ref_idc: 3, nal_unit_type: 5 })
           );
       }

       #[test]
       fn non_ref_slice_header_byte() {
           // 0x01 = forbidden 0, nal_ref_idc 0, type 1
           assert_eq!(
               NalHeader::parse(0x01),
               Ok(NalHeader { nal_ref_idc: 0, nal_unit_type: 1 })
           );
       }

       #[test]
       fn forbidden_bit_set_rejected() {
           // 0xE7 = forbidden bit set
           assert_eq!(NalHeader::parse(0xE7), Err(NalHeaderError::ForbiddenBitSet));
       }

       #[test]
       fn from_nal_reads_first_byte() {
           assert_eq!(
               NalHeader::from_nal(&[0x68, 0xaa, 0xbb]),
               Ok(NalHeader { nal_ref_idc: 3, nal_unit_type: 8 })
           );
       }

       #[test]
       fn from_empty_nal_rejected() {
           assert_eq!(NalHeader::from_nal(&[]), Err(NalHeaderError::Empty));
       }
   }
   ```

3. Run:
   ```bash
   cargo test -p kvm-proto h264::nal
   ```
   Expected: fails to compile — `cannot find type 'NalHeader'` / `NalHeaderError`.

4. Write the implementation at the top of `nal.rs`:
   ```rust
   //! NAL header parse and NAL-type helpers (spec §6.2). Hostile input.
   #![deny(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   /// A parsed one-byte H.264 NAL unit header (forbidden bit already checked 0).
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub struct NalHeader {
       /// `nal_ref_idc` (0..=3).
       pub nal_ref_idc: u8,
       /// `nal_unit_type` (0..=31).
       pub nal_unit_type: u8,
   }

   /// Why a NAL header could not be accepted (a framing violation, spec §6.9).
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub enum NalHeaderError {
       /// `forbidden_zero_bit` was 1 (spec §6.2 refuses it).
       ForbiddenBitSet,
       /// The NAL was empty, so there is no header byte.
       Empty,
   }

   impl NalHeader {
       /// Parse the single NAL header byte.
       pub fn parse(byte: u8) -> Result<NalHeader, NalHeaderError> {
           if byte & 0b1000_0000 != 0 {
               return Err(NalHeaderError::ForbiddenBitSet);
           }
           Ok(NalHeader {
               nal_ref_idc: (byte & 0b0110_0000).wrapping_shr(5),
               nal_unit_type: byte & 0b0001_1111,
           })
       }

       /// Parse the header from the first byte of a NAL unit.
       pub fn from_nal(nal: &[u8]) -> Result<NalHeader, NalHeaderError> {
           let first = nal.first().copied().ok_or(NalHeaderError::Empty)?;
           Self::parse(first)
       }
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::nal
   ```
   Expected: 6 passed.

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: NAL header parse with forbidden-bit check

   Hand-rolled one-byte parse (forbidden bit -> framing violation, nal_ref_idc,
   nal_unit_type). Checked access; no panics (§6.2).

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.4: NAL-type allowlist helpers

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/nal.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: extend `#[cfg(test)] mod tests` in `nal.rs`

**Interfaces:**
- Consumes: `std` only.
- Produces (all `pub fn … -> bool`, taking a `nal_unit_type: u8`):
  - `pub fn nal_type_allowed(nal_unit_type: u8) -> bool` (allowlist `{1,5,7,8,9}`, spec §6.2)
  - `pub fn is_vcl(nal_unit_type: u8) -> bool` (`{1,5}`)
  - `pub fn is_idr(nal_unit_type: u8) -> bool` (`5`)
  - `pub fn is_parameter_set(nal_unit_type: u8) -> bool` (`{7,8}`)
  - `pub fn is_aud(nal_unit_type: u8) -> bool` (`9`)

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   pub use nal::{is_aud, is_idr, is_parameter_set, is_vcl, nal_type_allowed};
   ```

2. Add the failing tests to the existing `mod tests` in `nal.rs`:
   ```rust
   #[test]
   fn allowlist_matches_spec_6_2() {
       for t in [1u8, 5, 7, 8, 9] {
           assert!(nal_type_allowed(t), "type {t} should be allowed");
       }
       // SEI(6), filler(12), end-of-seq(10), reserved/unspecified all dropped.
       for t in [0u8, 2, 3, 4, 6, 10, 11, 12, 20, 31] {
           assert!(!nal_type_allowed(t), "type {t} should be dropped");
       }
   }

   #[test]
   fn vcl_idr_pps_aud_classifiers() {
       assert!(is_vcl(1) && is_vcl(5));
       assert!(!is_vcl(7) && !is_vcl(8) && !is_vcl(9));
       assert!(is_idr(5) && !is_idr(1));
       assert!(is_parameter_set(7) && is_parameter_set(8) && !is_parameter_set(9));
       assert!(is_aud(9) && !is_aud(1));
   }
   ```

3. Run:
   ```bash
   cargo test -p kvm-proto h264::nal
   ```
   Expected: fails to compile — `cannot find function 'nal_type_allowed'` (and the four siblings).

4. Append the implementation to `nal.rs` (below the `impl NalHeader` block, still inside the module whose denies are set):
   ```rust
   /// The spec §6.2 allowlist: slices (1), IDR (5), SPS (7), PPS (8), AUD (9).
   /// Everything else (SEI, filler, …) is dropped.
   #[must_use]
   pub fn nal_type_allowed(nal_unit_type: u8) -> bool {
       matches!(nal_unit_type, 1 | 5 | 7 | 8 | 9)
   }

   /// A VCL (slice) NAL: non-IDR coded slice (1) or IDR coded slice (5).
   /// Spec §6.3: only AUs containing a VCL NAL are sent.
   #[must_use]
   pub fn is_vcl(nal_unit_type: u8) -> bool {
       matches!(nal_unit_type, 1 | 5)
   }

   /// An IDR coded slice (5).
   #[must_use]
   pub fn is_idr(nal_unit_type: u8) -> bool {
       nal_unit_type == 5
   }

   /// A parameter set: SPS (7) or PPS (8).
   #[must_use]
   pub fn is_parameter_set(nal_unit_type: u8) -> bool {
       matches!(nal_unit_type, 7 | 8)
   }

   /// An access unit delimiter (9).
   #[must_use]
   pub fn is_aud(nal_unit_type: u8) -> bool {
       nal_unit_type == 9
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::nal
   ```
   Expected: 8 passed.

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: NAL-type allowlist and classifier helpers

   Allowlist {1,5,7,8,9} plus is_vcl/is_idr/is_parameter_set/is_aud (§6.2/§6.3).

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.5: Test-only H.264 bit writer and SPS builder

> The fixtures component owns `gen-fixtures.sh` and the committed Annex-B fixtures (§11.5). Per the brief, this component builds SPS bytes **inline** so its tests carry no cross-dependency on fixtures. This task introduces the shared `#[cfg(test)]` builder; Tasks 6 and 8 import it.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/test_support.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: inline `#[cfg(test)] mod tests` in `test_support.rs` that round-trips a built SPS through h264-reader

**Interfaces:**
- Consumes: `h264_reader::nal::{RefNal, Nal}`, `h264_reader::nal::sps::SeqParameterSet`.
- Produces (crate-internal, `#[cfg(test)]`):
  - `pub struct BitWriter` with `new`, `put_bit(bool)`, `put_bits(u32, u32)`, `put_ue(u32)`, `put_se(i32)`, `rbsp_trailing_bits()`, `into_rbsp() -> Vec<u8>`
  - `pub fn escape_rbsp(rbsp: &[u8]) -> Vec<u8>`
  - `pub fn wrap_nal(header_byte: u8, rbsp: &[u8]) -> Vec<u8>`
  - `pub struct SpsCfg { … }` with `pub fn main_1080p() -> SpsCfg` and `pub fn build(&self) -> Vec<u8>` (returns a complete wire NAL)

**Steps:**

1. Ensure `h264/mod.rs` has the test-support module line (added in Task 1 step 7 or add now):
   ```rust
   #[cfg(test)]
   pub(crate) mod test_support;
   ```

2. Write the failing round-trip test at the bottom of `test_support.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use h264_reader::nal::sps::SeqParameterSet;
       use h264_reader::nal::{Nal, RefNal};

       fn parse(nal: &[u8]) -> SeqParameterSet {
           let refnal = RefNal::new(nal, &[], true);
           SeqParameterSet::from_bits(refnal.rbsp_bits()).unwrap()
       }

       #[test]
       fn ue_roundtrips_through_reader() {
           // Build a NAL whose RBSP is a single ue(v) and read it back via the
           // same reader h264-reader uses (rbsp_bits strips header + emulation).
           let mut w = BitWriter::new();
           w.put_ue(300);
           w.rbsp_trailing_bits();
           let nal = wrap_nal(0x68, &w.into_rbsp());
           let refnal = RefNal::new(&nal, &[], true);
           let mut r = refnal.rbsp_bits();
           use h264_reader::rbsp::BitRead;
           assert_eq!(r.read_ue("v").unwrap(), 300);
       }

       #[test]
       fn main_1080p_parses_to_expected_dimensions() {
           let sps = parse(&SpsCfg::main_1080p().build());
           assert_eq!(sps.pixel_dimensions().unwrap(), (1920, 1080));
           assert_eq!(u8::from(sps.profile_idc), 77);
       }

       #[test]
       fn escape_inserts_emulation_byte() {
           assert_eq!(escape_rbsp(&[0, 0, 0]), [0, 0, 3, 0]);
           assert_eq!(escape_rbsp(&[0, 0, 1]), [0, 0, 3, 1]);
           assert_eq!(escape_rbsp(&[0, 0, 4]), [0, 0, 4]); // >0x03: no insert
       }
   }
   ```

3. Run:
   ```bash
   cargo test -p kvm-proto h264::test_support
   ```
   Expected: fails to compile — `cannot find type 'BitWriter'` / `SpsCfg` / functions.

4. Write the implementation at the top of `test_support.rs`:
   ```rust
   //! Test-only H.264 bit writer and SPS/slice NAL builders. Never compiled into
   //! normal builds. Lets this component's tests hand-build bitstreams without a
   //! fixture dependency (the fixtures component owns gen-fixtures, §11.5).
   #![allow(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   /// Big-endian bit writer with Exp-Golomb support.
   #[derive(Default)]
   pub struct BitWriter {
       bytes: Vec<u8>,
       cur: u8,
       nbits: u8, // bits currently buffered in `cur` (0..8)
   }

   impl BitWriter {
       pub fn new() -> Self {
           Self::default()
       }

       pub fn put_bit(&mut self, bit: bool) {
           self.cur = (self.cur << 1) | u8::from(bit);
           self.nbits += 1;
           if self.nbits == 8 {
               self.bytes.push(self.cur);
               self.cur = 0;
               self.nbits = 0;
           }
       }

       pub fn put_bits(&mut self, value: u32, count: u32) {
           for i in (0..count).rev() {
               self.put_bit((value >> i) & 1 == 1);
           }
       }

       /// ue(v), unsigned Exp-Golomb.
       pub fn put_ue(&mut self, value: u32) {
           let code = value + 1;
           let nbits = 32 - code.leading_zeros(); // >= 1
           for _ in 0..(nbits - 1) {
               self.put_bit(false);
           }
           self.put_bits(code, nbits);
       }

       /// se(v), signed Exp-Golomb.
       pub fn put_se(&mut self, value: i32) {
           let mapped = if value <= 0 {
               (-value as u32) * 2
           } else {
               (value as u32) * 2 - 1
           };
           self.put_ue(mapped);
       }

       /// rbsp_trailing_bits(): a stop-one bit then zero-pad to a byte boundary.
       pub fn rbsp_trailing_bits(&mut self) {
           self.put_bit(true);
           while self.nbits != 0 {
               self.put_bit(false);
           }
       }

       /// Flush and return the raw (un-escaped) RBSP bytes.
       pub fn into_rbsp(mut self) -> Vec<u8> {
           if self.nbits != 0 {
               self.cur <<= 8 - self.nbits;
               self.bytes.push(self.cur);
               self.nbits = 0;
           }
           self.bytes
       }
   }

   /// Emulation-prevention-encode an RBSP so `RefNal::rbsp_bits` reconstructs it
   /// byte-for-byte: insert 0x03 after any `00 00` followed by a byte <= 0x03.
   pub fn escape_rbsp(rbsp: &[u8]) -> Vec<u8> {
       let mut out = Vec::with_capacity(rbsp.len());
       let mut zeros = 0u32;
       for &b in rbsp {
           if zeros >= 2 && b <= 0x03 {
               out.push(0x03);
               zeros = 0;
           }
           out.push(b);
           if b == 0 {
               zeros += 1;
           } else {
               zeros = 0;
           }
       }
       out
   }

   /// Prepend the 1-byte NAL header and emulation-encode the RBSP into a wire NAL.
   pub fn wrap_nal(header_byte: u8, rbsp: &[u8]) -> Vec<u8> {
       let mut nal = Vec::with_capacity(rbsp.len() + 1);
       nal.push(header_byte);
       nal.extend_from_slice(&escape_rbsp(rbsp));
       nal
   }

   /// A hand-built SPS. Fields map 1:1 to H.264 SPS syntax; the chroma block is
   /// emitted only for high profiles (profile_idc with chroma info).
   pub struct SpsCfg {
       pub profile_idc: u8,
       pub level_idc: u8,
       pub seq_parameter_set_id: u32,
       pub chroma_format_idc: u32,       // emitted only for high profiles
       pub bit_depth_luma_minus8: u32,   // emitted only for high profiles
       pub bit_depth_chroma_minus8: u32, // emitted only for high profiles
       pub log2_max_frame_num_minus4: u32,
       pub pic_order_cnt_type: u32,
       pub log2_max_poc_lsb_minus4: u32, // used only for POC type 0
       pub max_num_ref_frames: u32,
       pub pic_width_in_mbs_minus1: u32,
       pub pic_height_in_map_units_minus1: u32,
       pub frame_mbs_only_flag: bool,
       pub crop: Option<(u32, u32, u32, u32)>, // left, right, top, bottom (crop units)
   }

   impl SpsCfg {
       /// Valid 1920x1080, Main profile, POC type 2, within §6.1 limits.
       /// Bottom crop of 4 (crop unit 2 for 4:2:0) trims 1088 -> 1080.
       pub fn main_1080p() -> Self {
           Self {
               profile_idc: 77,
               level_idc: 42,
               seq_parameter_set_id: 0,
               chroma_format_idc: 1,
               bit_depth_luma_minus8: 0,
               bit_depth_chroma_minus8: 0,
               log2_max_frame_num_minus4: 0,
               pic_order_cnt_type: 2,
               log2_max_poc_lsb_minus4: 0,
               max_num_ref_frames: 1,
               pic_width_in_mbs_minus1: 119,       // 120 * 16 = 1920
               pic_height_in_map_units_minus1: 67, // 68 * 16 = 1088
               frame_mbs_only_flag: true,
               crop: Some((0, 0, 0, 4)),
           }
       }

       fn has_chroma_block(&self) -> bool {
           matches!(
               self.profile_idc,
               100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 134 | 135 | 138 | 139
           )
       }

       /// Emit a complete wire SPS NAL (header 0x67 + emulation-encoded RBSP).
       pub fn build(&self) -> Vec<u8> {
           let mut w = BitWriter::new();
           w.put_bits(u32::from(self.profile_idc), 8);
           w.put_bits(0, 8); // constraint_set flags + reserved_zero_2bits
           w.put_bits(u32::from(self.level_idc), 8);
           w.put_ue(self.seq_parameter_set_id);
           if self.has_chroma_block() {
               w.put_ue(self.chroma_format_idc);
               if self.chroma_format_idc == 3 {
                   w.put_bit(false); // separate_colour_plane_flag
               }
               w.put_ue(self.bit_depth_luma_minus8);
               w.put_ue(self.bit_depth_chroma_minus8);
               w.put_bit(false); // qpprime_y_zero_transform_bypass_flag
               w.put_bit(false); // seq_scaling_matrix_present_flag
           }
           w.put_ue(self.log2_max_frame_num_minus4);
           w.put_ue(self.pic_order_cnt_type);
           match self.pic_order_cnt_type {
               0 => w.put_ue(self.log2_max_poc_lsb_minus4),
               1 => {
                   w.put_bit(false); // delta_pic_order_always_zero_flag
                   w.put_se(0); // offset_for_non_ref_pic
                   w.put_se(0); // offset_for_top_to_bottom_field
                   w.put_ue(0); // num_ref_frames_in_pic_order_cnt_cycle
               }
               _ => {}
           }
           w.put_ue(self.max_num_ref_frames);
           w.put_bit(false); // gaps_in_frame_num_value_allowed_flag
           w.put_ue(self.pic_width_in_mbs_minus1);
           w.put_ue(self.pic_height_in_map_units_minus1);
           w.put_bit(self.frame_mbs_only_flag);
           if !self.frame_mbs_only_flag {
               w.put_bit(false); // mb_adaptive_frame_field_flag
           }
           w.put_bit(true); // direct_8x8_inference_flag
           match self.crop {
               Some((l, r, t, b)) => {
                   w.put_bit(true); // frame_cropping_flag
                   w.put_ue(l);
                   w.put_ue(r);
                   w.put_ue(t);
                   w.put_ue(b);
               }
               None => w.put_bit(false),
           }
           w.put_bit(false); // vui_parameters_present_flag
           w.rbsp_trailing_bits();
           wrap_nal(0x67, &w.into_rbsp()) // SPS: forbidden 0, nal_ref_idc 3, type 7
       }
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::test_support
   ```
   Expected: 3 passed. (If `main_1080p_parses_to_expected_dimensions` yields a height other than 1080, adjust `crop.3` — the oracle is h264-reader's `pixel_dimensions`.)

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: test-only bit writer and SPS builder

   Exp-Golomb BitWriter + emulation-prevention escaping + SpsCfg builder,
   validated by round-tripping through h264-reader (oracle). No fixture
   dependency at test time (§11.5).

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.6: SPS inspection → `SpsSummary`

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: inline `#[cfg(test)] mod tests` in `sps.rs` (uses `crate::h264::test_support::SpsCfg`)

**Interfaces:**
- Consumes:
  - `h264_reader::nal::sps::{SeqParameterSet, ChromaFormat, FrameMbsFlags, PicOrderCntType, SpsError}`
  - `h264_reader::nal::{RefNal, Nal, UnitType}` (via `RefNal::header()` / `rbsp_bits()`)
  - `kvm_proto::h264::test_support::SpsCfg` (tests only)
- Produces:
  - `pub struct SpsSummary { pub profile_idc: u8, pub level_idc: u8, pub chroma_format_idc: u8, pub bit_depth_luma_minus8: u8, pub bit_depth_chroma_minus8: u8, pub pic_order_cnt_type: u8, pub width: u32, pub height: u32, pub num_ref_frames: u32, pub frame_mbs_only_flag: bool, pub seq_scaling_matrix_present: bool, pub nal_hrd_present: bool, pub vcl_hrd_present: bool, pub video_full_range_flag: Option<bool>, pub colour_primaries: Option<u8>, pub matrix_coefficients: Option<u8>, pub max_num_reorder_frames: Option<u32>, pub max_dec_frame_buffering: Option<u32>, pub log2_max_frame_num: u8, pub sps_id: u8, pub frame_cropping: bool }`
  - `pub fn SpsSummary::from_sps(sps: &SeqParameterSet) -> Result<SpsSummary, SpsSummaryError>`
  - `pub fn parse_sps(nal: &[u8]) -> Result<SpsSummary, SpsParseError>`
  - `pub enum SpsSummaryError { Dimensions(SpsError), InvalidChroma(u32) }`
  - `pub enum SpsParseError { BadNalHeader, NotSps(u8), Sps(SpsError), Summary(SpsSummaryError) }`

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   mod sps;
   pub use sps::{parse_sps, SpsParseError, SpsSummary, SpsSummaryError};
   ```

2. Write the failing test at the bottom of `sps.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used)]
       use super::*;
       use crate::h264::test_support::SpsCfg;

       #[test]
       fn main_1080p_summary_fields() {
           let s = parse_sps(&SpsCfg::main_1080p().build()).unwrap();
           assert_eq!(s.profile_idc, 77);
           assert_eq!(s.level_idc, 42);
           assert_eq!(s.chroma_format_idc, 1);
           assert_eq!(s.bit_depth_luma_minus8, 0);
           assert_eq!(s.bit_depth_chroma_minus8, 0);
           assert_eq!(s.pic_order_cnt_type, 2);
           assert_eq!((s.width, s.height), (1920, 1080));
           assert_eq!(s.num_ref_frames, 1);
           assert!(s.frame_mbs_only_flag);
           assert!(!s.seq_scaling_matrix_present);
           assert!(!s.nal_hrd_present && !s.vcl_hrd_present);
           assert_eq!(s.log2_max_frame_num, 4);
           assert_eq!(s.sps_id, 0);
           assert!(s.frame_cropping);
           // No VUI in the builder => colour/reorder fields are None.
           assert_eq!(s.video_full_range_flag, None);
           assert_eq!(s.max_num_reorder_frames, None);
       }

       #[test]
       fn high_profile_10bit_422_extracted() {
           let mut cfg = SpsCfg::main_1080p();
           cfg.profile_idc = 100;
           cfg.chroma_format_idc = 2; // 4:2:2
           cfg.bit_depth_luma_minus8 = 2; // 10-bit
           cfg.bit_depth_chroma_minus8 = 2;
           cfg.crop = None; // avoid 4:2:2 crop-unit arithmetic in this check
           let s = parse_sps(&cfg.build()).unwrap();
           assert_eq!(s.profile_idc, 100);
           assert_eq!(s.chroma_format_idc, 2);
           assert_eq!(s.bit_depth_luma_minus8, 2);
           assert_eq!(s.bit_depth_chroma_minus8, 2);
       }

       #[test]
       fn parse_sps_rejects_non_sps_nal() {
           // PPS header byte 0x68 (type 8)
           assert!(matches!(
               parse_sps(&[0x68, 0x00]),
               Err(SpsParseError::NotSps(8))
           ));
       }

       #[test]
       fn parse_sps_rejects_empty() {
           assert!(matches!(parse_sps(&[]), Err(SpsParseError::BadNalHeader)));
       }
   }
   ```

3. Run:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: fails to compile — `cannot find function 'parse_sps'` / types.

4. Write the implementation at the top of `sps.rs`:
   ```rust
   //! SPS inspection into a flat `SpsSummary` (spec §6.1). Uses h264-reader for
   //! the bit-level parse; this layer is total and panic-free over its output.
   #![deny(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   use h264_reader::nal::sps::{ChromaFormat, FrameMbsFlags, PicOrderCntType, SeqParameterSet, SpsError};
   use h264_reader::nal::{Nal, RefNal};

   /// A flat, comparable summary of the SPS fields the bridge reasons about
   /// (spec §6.1). `Eq` so change classification (Task 9) can compare summaries.
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub struct SpsSummary {
       pub profile_idc: u8,
       pub level_idc: u8,
       pub chroma_format_idc: u8, // 0 mono, 1 4:2:0, 2 4:2:2, 3 4:4:4
       pub bit_depth_luma_minus8: u8,
       pub bit_depth_chroma_minus8: u8,
       pub pic_order_cnt_type: u8, // 0, 1 or 2
       pub width: u32,
       pub height: u32,
       pub num_ref_frames: u32,
       pub frame_mbs_only_flag: bool,
       pub seq_scaling_matrix_present: bool,
       pub nal_hrd_present: bool,
       pub vcl_hrd_present: bool,
       pub video_full_range_flag: Option<bool>,
       pub colour_primaries: Option<u8>,
       pub matrix_coefficients: Option<u8>,
       pub max_num_reorder_frames: Option<u32>,
       pub max_dec_frame_buffering: Option<u32>,
       pub log2_max_frame_num: u8,
       pub sps_id: u8,
       pub frame_cropping: bool,
   }

   /// Why an `SpsSummary` could not be built from a parsed SPS.
   #[derive(Debug)]
   pub enum SpsSummaryError {
       /// `pixel_dimensions()` failed (cropping overflow, etc.).
       Dimensions(SpsError),
       /// The SPS declared an invalid chroma_format_idc.
       InvalidChroma(u32),
   }

   /// Why a wire NAL could not be parsed into an `SpsSummary`.
   #[derive(Debug)]
   pub enum SpsParseError {
       /// The NAL was empty or its forbidden bit was set.
       BadNalHeader,
       /// The NAL was not an SPS (carries the actual nal_unit_type).
       NotSps(u8),
       /// h264-reader rejected the SPS bitstream.
       Sps(SpsError),
       /// The SPS parsed but a summary field could not be derived.
       Summary(SpsSummaryError),
   }

   impl SpsSummary {
       /// Extract a summary from an already-parsed SPS.
       pub fn from_sps(sps: &SeqParameterSet) -> Result<SpsSummary, SpsSummaryError> {
           let chroma_format_idc: u8 = match sps.chroma_info.chroma_format {
               ChromaFormat::Monochrome => 0,
               ChromaFormat::YUV420 => 1,
               ChromaFormat::YUV422 => 2,
               ChromaFormat::YUV444 => 3,
               ChromaFormat::Invalid(n) => return Err(SpsSummaryError::InvalidChroma(n)),
           };
           let pic_order_cnt_type: u8 = match sps.pic_order_cnt_type {
               PicOrderCntType::TypeZero { .. } => 0,
               PicOrderCntType::TypeOne { .. } => 1,
               PicOrderCntType::TypeTwo => 2,
           };
           let (width, height) = sps
               .pixel_dimensions()
               .map_err(SpsSummaryError::Dimensions)?;

           let vui = sps.vui_parameters.as_ref();
           let vst = vui.and_then(|v| v.video_signal_type.as_ref());
           let colour = vst.and_then(|v| v.colour_description.as_ref());
           let br = vui.and_then(|v| v.bitstream_restrictions.as_ref());

           Ok(SpsSummary {
               profile_idc: u8::from(sps.profile_idc),
               level_idc: sps.level_idc,
               chroma_format_idc,
               bit_depth_luma_minus8: sps.chroma_info.bit_depth_luma_minus8,
               bit_depth_chroma_minus8: sps.chroma_info.bit_depth_chroma_minus8,
               pic_order_cnt_type,
               width,
               height,
               num_ref_frames: sps.num_ref_frames,
               frame_mbs_only_flag: matches!(sps.frame_mbs_flags, FrameMbsFlags::Frames),
               seq_scaling_matrix_present: sps.chroma_info.scaling_matrix.is_some(),
               nal_hrd_present: vui.map(|v| v.nal_hrd_parameters.is_some()).unwrap_or(false),
               vcl_hrd_present: vui.map(|v| v.vcl_hrd_parameters.is_some()).unwrap_or(false),
               video_full_range_flag: vst.map(|v| v.video_full_range_flag),
               colour_primaries: colour.map(|c| c.colour_primaries),
               matrix_coefficients: colour.map(|c| c.matrix_coefficients),
               max_num_reorder_frames: br.map(|b| b.max_num_reorder_frames),
               max_dec_frame_buffering: br.map(|b| b.max_dec_frame_buffering),
               log2_max_frame_num: sps.log2_max_frame_num_minus4.saturating_add(4),
               sps_id: sps.seq_parameter_set_id.id(),
               frame_cropping: sps.frame_cropping.is_some(),
           })
       }
   }

   /// Parse a wire SPS NAL (header byte + emulation-prevention bytes) into a
   /// summary. `RefNal::rbsp_bits` skips the header and strips emulation bytes.
   pub fn parse_sps(nal: &[u8]) -> Result<SpsSummary, SpsParseError> {
       let refnal = RefNal::new(nal, &[], true);
       let header = refnal.header().map_err(|_| SpsParseError::BadNalHeader)?;
       let unit_type = header.nal_unit_type().id();
       if unit_type != 7 {
           return Err(SpsParseError::NotSps(unit_type));
       }
       let sps = SeqParameterSet::from_bits(refnal.rbsp_bits()).map_err(SpsParseError::Sps)?;
       SpsSummary::from_sps(&sps).map_err(SpsParseError::Summary)
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: 4 passed.

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: SPS inspection into SpsSummary

   from_sps maps the §6.1 fields (dims w/ cropping, profile/level, chroma/bit
   depth, POC type, num_ref_frames, frame_mbs_only, scaling matrix, HRD, VUI
   range/colour, bitstream_restriction) via h264-reader; parse_sps wraps a wire
   NAL through RefNal. Total, panic-free.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.7: SPS admission limits (`check_sps_limits`)

> One hostile vector per §6.1 SPS rule, each asserting its specific error kind (§11.2). Tests construct `SpsSummary` literals directly, so each rule is exercised in isolation (including the defensive even-width/height check, which real 4:2:0 SPS cannot violate through h264-reader).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: extend `#[cfg(test)] mod tests` in `sps.rs`

**Interfaces:**
- Consumes: `SpsSummary` (Task 6).
- Produces:
  - `pub struct SpsLimits { pub allowed_profiles: &'static [u8], pub max_level_idc: u8, pub max_width: u32, pub max_height: u32, pub max_num_ref_frames: u32, pub require_no_scaling_matrix: bool, pub require_no_hrd: bool }` with `impl Default` = the §6.1 ceilings `{66,77,100}` / 51 / 4096 / 2304 / 16 / true / true
  - `pub enum SpsLimitViolation { Profile(u8), ChromaNot420(u8), BitDepthNot8 { luma_minus8: u8, chroma_minus8: u8 }, NotFrameMbsOnly, Level(u8), WidthTooLarge(u32), HeightTooLarge(u32), WidthNotEven(u32), HeightNotEven(u32), TooManyRefFrames(u32), ScalingMatrixPresent, HrdPresent }`
  - `pub fn check_sps_limits(s: &SpsSummary, limits: &SpsLimits) -> Result<(), SpsLimitViolation>`

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   pub use sps::{check_sps_limits, SpsLimitViolation, SpsLimits};
   ```

2. Add the failing tests to the existing `mod tests` in `sps.rs` (add a within-limits constructor helper and one vector per rule):
   ```rust
   fn ok_summary() -> SpsSummary {
       SpsSummary {
           profile_idc: 77,
           level_idc: 42,
           chroma_format_idc: 1,
           bit_depth_luma_minus8: 0,
           bit_depth_chroma_minus8: 0,
           pic_order_cnt_type: 2,
           width: 1920,
           height: 1080,
           num_ref_frames: 1,
           frame_mbs_only_flag: true,
           seq_scaling_matrix_present: false,
           nal_hrd_present: false,
           vcl_hrd_present: false,
           video_full_range_flag: None,
           colour_primaries: None,
           matrix_coefficients: None,
           max_num_reorder_frames: None,
           max_dec_frame_buffering: None,
           log2_max_frame_num: 4,
           sps_id: 0,
           frame_cropping: true,
       }
   }

   #[test]
   fn within_limits_ok() {
       assert_eq!(check_sps_limits(&ok_summary(), &SpsLimits::default()), Ok(()));
   }

   #[test]
   fn each_rule_has_its_own_violation() {
       let lim = SpsLimits::default();
       let mut s = ok_summary();
       s.profile_idc = 244;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::Profile(244)));

       let mut s = ok_summary();
       s.chroma_format_idc = 2;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::ChromaNot420(2)));

       let mut s = ok_summary();
       s.bit_depth_luma_minus8 = 2;
       assert_eq!(
           check_sps_limits(&s, &lim),
           Err(SpsLimitViolation::BitDepthNot8 { luma_minus8: 2, chroma_minus8: 0 })
       );

       let mut s = ok_summary();
       s.frame_mbs_only_flag = false;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::NotFrameMbsOnly));

       let mut s = ok_summary();
       s.level_idc = 52;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::Level(52)));

       let mut s = ok_summary();
       s.width = 4112;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::WidthTooLarge(4112)));

       let mut s = ok_summary();
       s.height = 2320;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::HeightTooLarge(2320)));

       let mut s = ok_summary();
       s.width = 1921;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::WidthNotEven(1921)));

       let mut s = ok_summary();
       s.height = 1081;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::HeightNotEven(1081)));

       let mut s = ok_summary();
       s.num_ref_frames = 17;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::TooManyRefFrames(17)));

       let mut s = ok_summary();
       s.seq_scaling_matrix_present = true;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::ScalingMatrixPresent));

       let mut s = ok_summary();
       s.vcl_hrd_present = true;
       assert_eq!(check_sps_limits(&s, &lim), Err(SpsLimitViolation::HrdPresent));
   }
   ```
   (Make `ok_summary` visible to Task 9's tests by leaving it in this `mod tests`; Task 9 adds its own test module in the same file and can call it.)

3. Run:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: fails to compile — `cannot find type 'SpsLimits'` / `SpsLimitViolation` / function `check_sps_limits`.

4. Append the implementation to `sps.rs` (inside the module whose denies are already set):
   ```rust
   /// The §6.1 admission limits. Defaults are the spec ceilings; the census may
   /// tighten `max_num_ref_frames` or (if the KVM uses them) relax the scaling
   /// matrix / HRD requirements with pinned values.
   #[derive(Debug, Clone)]
   pub struct SpsLimits {
       pub allowed_profiles: &'static [u8],
       pub max_level_idc: u8,
       pub max_width: u32,
       pub max_height: u32,
       pub max_num_ref_frames: u32,
       pub require_no_scaling_matrix: bool,
       pub require_no_hrd: bool,
   }

   impl Default for SpsLimits {
       fn default() -> Self {
           Self {
               allowed_profiles: &[66, 77, 100],
               max_level_idc: 51, // level 5.1
               max_width: 4096,
               max_height: 2304,
               max_num_ref_frames: 16,
               require_no_scaling_matrix: true,
               require_no_hrd: true,
           }
       }
   }

   /// A specific §6.1 SPS limit that was exceeded.
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub enum SpsLimitViolation {
       Profile(u8),
       ChromaNot420(u8),
       BitDepthNot8 { luma_minus8: u8, chroma_minus8: u8 },
       NotFrameMbsOnly,
       Level(u8),
       WidthTooLarge(u32),
       HeightTooLarge(u32),
       WidthNotEven(u32),
       HeightNotEven(u32),
       TooManyRefFrames(u32),
       ScalingMatrixPresent,
       HrdPresent,
   }

   /// Check an SPS summary against the §6.1 admission limits. The first failing
   /// rule wins, in spec order.
   pub fn check_sps_limits(
       s: &SpsSummary,
       limits: &SpsLimits,
   ) -> Result<(), SpsLimitViolation> {
       if !limits.allowed_profiles.contains(&s.profile_idc) {
           return Err(SpsLimitViolation::Profile(s.profile_idc));
       }
       if s.chroma_format_idc != 1 {
           return Err(SpsLimitViolation::ChromaNot420(s.chroma_format_idc));
       }
       if s.bit_depth_luma_minus8 != 0 || s.bit_depth_chroma_minus8 != 0 {
           return Err(SpsLimitViolation::BitDepthNot8 {
               luma_minus8: s.bit_depth_luma_minus8,
               chroma_minus8: s.bit_depth_chroma_minus8,
           });
       }
       if !s.frame_mbs_only_flag {
           return Err(SpsLimitViolation::NotFrameMbsOnly);
       }
       if s.level_idc > limits.max_level_idc {
           return Err(SpsLimitViolation::Level(s.level_idc));
       }
       if s.width > limits.max_width {
           return Err(SpsLimitViolation::WidthTooLarge(s.width));
       }
       if s.height > limits.max_height {
           return Err(SpsLimitViolation::HeightTooLarge(s.height));
       }
       // Bitwise `& 1` avoids clippy::arithmetic_side_effects on `%`.
       if s.width & 1 == 1 {
           return Err(SpsLimitViolation::WidthNotEven(s.width));
       }
       if s.height & 1 == 1 {
           return Err(SpsLimitViolation::HeightNotEven(s.height));
       }
       if s.num_ref_frames > limits.max_num_ref_frames {
           return Err(SpsLimitViolation::TooManyRefFrames(s.num_ref_frames));
       }
       if limits.require_no_scaling_matrix && s.seq_scaling_matrix_present {
           return Err(SpsLimitViolation::ScalingMatrixPresent);
       }
       if limits.require_no_hrd && (s.nal_hrd_present || s.vcl_hrd_present) {
           return Err(SpsLimitViolation::HrdPresent);
       }
       Ok(())
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: 6 passed (4 from Task 6 + 2 new).

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: SPS admission limits (check_sps_limits)

   SpsLimits (census-tunable; defaults = §6.1 ceilings) + one SpsLimitViolation
   per rule: profile {66,77,100}, 4:2:0/8-bit, frame_mbs_only, level<=5.1,
   4096x2304, even dims, num_ref_frames<=16, no scaling matrix, no HRD.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.8: Slice-header prefix parse

> §6.1's full slice checks (`pps_id` refers to a validated PPS; `first_mb_in_slice < PicSizeInMbs`; POC strictly increasing) are admission/sequencing that needs PPS/SPS context and the decode-order stream — that lives in the demuxer/pump (Plan B/C), not here. This component provides the **context-free prefix** the census logs: `first_mb_in_slice`, `slice_type`, `pic_parameter_set_id` (the three leading `ue(v)` fields of a non-IDR/IDR slice header), plus the P/I slice-type allowlist helper.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/slice.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/test_support.rs` (add `build_slice_nal`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: inline `#[cfg(test)] mod tests` in `slice.rs`

**Interfaces:**
- Consumes:
  - `h264_reader::nal::{RefNal, Nal, UnitType}` and `h264_reader::rbsp::{BitRead, BitReaderError}`
  - `kvm_proto::h264::test_support::build_slice_nal` (tests only)
- Produces:
  - `pub struct SliceHeaderPrefix { pub first_mb_in_slice: u32, pub slice_type: u32, pub pic_parameter_set_id: u32 }`
  - `pub fn parse_slice_header_prefix(nal: &[u8]) -> Result<SliceHeaderPrefix, SliceParseError>`
  - `pub enum SliceParseError { BadNalHeader, NotSlice(u8), Bits(BitReaderError) }`
  - `pub fn slice_type_allowed(slice_type: u32) -> bool` (P and I only: `{0,2,5,7}`, spec §6.1)
  - (test support) `pub fn build_slice_nal(header_byte: u8, first_mb_in_slice: u32, slice_type: u32, pps_id: u32) -> Vec<u8>`

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   mod slice;
   pub use slice::{parse_slice_header_prefix, slice_type_allowed, SliceHeaderPrefix, SliceParseError};
   ```

2. Add `build_slice_nal` to `test_support.rs` (below `SpsCfg`):
   ```rust
   /// Build a wire slice NAL carrying only the three leading header fields
   /// (first_mb_in_slice, slice_type, pic_parameter_set_id) + trailing bits.
   /// `header_byte` e.g. 0x41 (type 1, non-IDR) or 0x65 (type 5, IDR).
   pub fn build_slice_nal(
       header_byte: u8,
       first_mb_in_slice: u32,
       slice_type: u32,
       pps_id: u32,
   ) -> Vec<u8> {
       let mut w = BitWriter::new();
       w.put_ue(first_mb_in_slice);
       w.put_ue(slice_type);
       w.put_ue(pps_id);
       w.rbsp_trailing_bits();
       wrap_nal(header_byte, &w.into_rbsp())
   }
   ```

3. Write the failing test at the bottom of `slice.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used)]
       use super::*;
       use crate::h264::test_support::build_slice_nal;

       #[test]
       fn non_idr_prefix_fields() {
           // header 0x41 = type 1; first_mb 0, slice_type 7 (I, all), pps_id 0
           let nal = build_slice_nal(0x41, 0, 7, 0);
           assert_eq!(
               parse_slice_header_prefix(&nal).unwrap(),
               SliceHeaderPrefix { first_mb_in_slice: 0, slice_type: 7, pic_parameter_set_id: 0 }
           );
       }

       #[test]
       fn idr_prefix_fields_with_nonzero_values() {
           // header 0x65 = type 5 (IDR); first_mb 99, slice_type 2 (I), pps_id 1
           let nal = build_slice_nal(0x65, 99, 2, 1);
           assert_eq!(
               parse_slice_header_prefix(&nal).unwrap(),
               SliceHeaderPrefix { first_mb_in_slice: 99, slice_type: 2, pic_parameter_set_id: 1 }
           );
       }

       #[test]
       fn non_slice_nal_rejected() {
           // SPS header byte 0x67 (type 7)
           assert!(matches!(
               parse_slice_header_prefix(&[0x67, 0x00]),
               Err(SliceParseError::NotSlice(7))
           ));
       }

       #[test]
       fn empty_nal_rejected() {
           assert!(matches!(
               parse_slice_header_prefix(&[]),
               Err(SliceParseError::BadNalHeader)
           ));
       }

       #[test]
       fn p_and_i_slice_types_allowed_only() {
           for t in [0u32, 2, 5, 7] {
               assert!(slice_type_allowed(t), "slice_type {t} (P/I) should pass");
           }
           for t in [1u32, 3, 4, 6, 8, 9] {
               assert!(!slice_type_allowed(t), "slice_type {t} (B/SP/SI) should fail");
           }
       }
   }
   ```

4. Run:
   ```bash
   cargo test -p kvm-proto h264::slice
   ```
   Expected: fails to compile — `cannot find function 'parse_slice_header_prefix'` / types / `build_slice_nal`.

5. Write the implementation at the top of `slice.rs`:
   ```rust
   //! Context-free slice-header prefix (spec §6.1 census fields). The first three
   //! ue(v) fields of a coded slice header need no SPS/PPS context. Full slice
   //! validation (PicSizeInMbs, POC order, validated pps_id) is Plan B/C.
   #![deny(
       clippy::indexing_slicing,
       clippy::unwrap_used,
       clippy::expect_used,
       clippy::panic,
       clippy::arithmetic_side_effects,
       clippy::as_conversions
   )]

   use h264_reader::nal::{Nal, RefNal};
   use h264_reader::rbsp::{BitRead, BitReaderError};

   /// The leading, context-free fields of a coded slice header.
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub struct SliceHeaderPrefix {
       pub first_mb_in_slice: u32,
       pub slice_type: u32,
       pub pic_parameter_set_id: u32,
   }

   /// Why a slice-header prefix could not be parsed.
   #[derive(Debug)]
   pub enum SliceParseError {
       /// The NAL was empty or its forbidden bit was set.
       BadNalHeader,
       /// The NAL was not a coded slice (type 1 or 5); carries the actual type.
       NotSlice(u8),
       /// The bit reader failed (truncated Exp-Golomb, etc.).
       Bits(BitReaderError),
   }

   /// Parse the first three ue(v) fields of a type-1/5 slice NAL.
   pub fn parse_slice_header_prefix(nal: &[u8]) -> Result<SliceHeaderPrefix, SliceParseError> {
       let refnal = RefNal::new(nal, &[], true);
       let header = refnal.header().map_err(|_| SliceParseError::BadNalHeader)?;
       let unit_type = header.nal_unit_type().id();
       if !matches!(unit_type, 1 | 5) {
           return Err(SliceParseError::NotSlice(unit_type));
       }
       let mut r = refnal.rbsp_bits();
       let first_mb_in_slice = r.read_ue("first_mb_in_slice").map_err(SliceParseError::Bits)?;
       let slice_type = r.read_ue("slice_type").map_err(SliceParseError::Bits)?;
       let pic_parameter_set_id =
           r.read_ue("pic_parameter_set_id").map_err(SliceParseError::Bits)?;
       Ok(SliceHeaderPrefix {
           first_mb_in_slice,
           slice_type,
           pic_parameter_set_id,
       })
   }

   /// Spec §6.1 slice-type allowlist: P and I only (`{0,2,5,7}`); B/SP/SI refused.
   #[must_use]
   pub fn slice_type_allowed(slice_type: u32) -> bool {
       matches!(slice_type, 0 | 2 | 5 | 7)
   }
   ```

6. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::slice
   ```
   Expected: 5 passed.

7. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: context-free slice-header prefix + type allowlist

   parse_slice_header_prefix reads first_mb_in_slice/slice_type/pps_id via
   h264-reader's bit reader (census fields, §6.1); slice_type_allowed gates P/I
   only {0,2,5,7}. Full slice validation is Plan B/C.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 3.9: SPS-change classification (§6.1 table)

> Pure function over `(previous, new)` plus the census-tunable `SpsLimits`, returning `initial | resize | other | incompatible` (§6.1). The pump consumes it in Plan C; the probe and these tests need it now. **Scope note on `initial`:** §6.1's "`initial` = first SPS after each FLV open" and "pins persist across FLV reconnects" are KVM-actor sequencing (Plan C) — the caller forces `Initial` by passing `previous = None` at a session's first SPS and after each FLV (re)open, while still enforcing limits here. Carrying/clearing `previous` and persisting pins across reconnects is out of scope for this component; the pure classifier is total over its two summaries.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/sps.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/src/h264/mod.rs`
- Test: add a second `#[cfg(test)] mod classify_tests` in `sps.rs`

**Interfaces:**
- Consumes: `SpsSummary` (Task 6), `SpsLimits` / `check_sps_limits` / `SpsLimitViolation` (Task 7).
- Produces:
  - `pub enum SpsChange { Initial, Resize, Other, Incompatible(SpsIncompatibleReason) }`
  - `pub enum SpsIncompatibleReason { OutsideLimits(SpsLimitViolation), PinnedFieldChanged(PinnedField) }`
  - `pub enum PinnedField { ProfileIdc, ChromaFormat, BitDepth, PicOrderCntType }`
  - `pub fn classify_sps_change(previous: Option<&SpsSummary>, new: &SpsSummary, limits: &SpsLimits) -> SpsChange`

**Steps:**

1. Add to `h264/mod.rs`:
   ```rust
   pub use sps::{classify_sps_change, PinnedField, SpsChange, SpsIncompatibleReason};
   ```

2. Add a second test module at the bottom of `sps.rs` (reusing `tests::ok_summary`):
   ```rust
   #[cfg(test)]
   mod classify_tests {
       use super::tests::ok_summary;
       use super::*;

       #[test]
       fn no_previous_is_initial() {
           let lim = SpsLimits::default();
           assert_eq!(classify_sps_change(None, &ok_summary(), &lim), SpsChange::Initial);
       }

       #[test]
       fn new_outside_limits_is_incompatible() {
           let lim = SpsLimits::default();
           let mut new = ok_summary();
           new.profile_idc = 244;
           assert_eq!(
               classify_sps_change(Some(&ok_summary()), &new, &lim),
               SpsChange::Incompatible(SpsIncompatibleReason::OutsideLimits(
                   SpsLimitViolation::Profile(244)
               ))
           );
       }

       #[test]
       fn pinned_profile_change_is_incompatible() {
           let lim = SpsLimits::default();
           let prev = ok_summary(); // profile 77
           let mut new = ok_summary();
           new.profile_idc = 100; // still within limits, but pinned
           assert_eq!(
               classify_sps_change(Some(&prev), &new, &lim),
               SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
                   PinnedField::ProfileIdc
               ))
           );
       }

       #[test]
       fn pinned_poc_type_change_is_incompatible() {
           let lim = SpsLimits::default();
           let prev = ok_summary(); // poc type 2
           let mut new = ok_summary();
           new.pic_order_cnt_type = 0;
           assert_eq!(
               classify_sps_change(Some(&prev), &new, &lim),
               SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
                   PinnedField::PicOrderCntType
               ))
           );
       }

       #[test]
       fn dimension_change_is_resize() {
           let lim = SpsLimits::default();
           let prev = ok_summary();
           let mut new = ok_summary();
           new.width = 1280;
           new.height = 720;
           assert_eq!(classify_sps_change(Some(&prev), &new, &lim), SpsChange::Resize);
       }

       #[test]
       fn level_change_is_resize() {
           let lim = SpsLimits::default();
           let prev = ok_summary();
           let mut new = ok_summary();
           new.level_idc = 40;
           assert_eq!(classify_sps_change(Some(&prev), &new, &lim), SpsChange::Resize);
       }

       #[test]
       fn num_ref_frames_change_only_is_other() {
           let lim = SpsLimits::default();
           let prev = ok_summary();
           let mut new = ok_summary();
           new.num_ref_frames = 3; // still <= 16; not a pinned field, not dims/level
           assert_eq!(classify_sps_change(Some(&prev), &new, &lim), SpsChange::Other);
       }

       #[test]
       fn identical_sps_is_other() {
           let lim = SpsLimits::default();
           let prev = ok_summary();
           assert_eq!(classify_sps_change(Some(&prev), &ok_summary(), &lim), SpsChange::Other);
       }
   }
   ```
   Also change the Task 7 test module declaration so the classifier tests can reuse `ok_summary`: ensure `mod tests` is visible to `classify_tests` (both are siblings under `sps.rs`; `super::tests::ok_summary` works because they share the parent module).

3. Run:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: fails to compile — `cannot find type 'SpsChange'` / `classify_sps_change`.

4. Append the implementation to `sps.rs`:
   ```rust
   /// A pinned SPS field (spec §6.1): fixed after the first SPS of a KVM session.
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub enum PinnedField {
       ProfileIdc,
       ChromaFormat,
       BitDepth,
       PicOrderCntType,
   }

   /// Why an SPS change is incompatible (fatal `stream_incompatible`, §6.9).
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub enum SpsIncompatibleReason {
       /// The new SPS is outside the §6.1 limits.
       OutsideLimits(SpsLimitViolation),
       /// A pinned field changed from the previous SPS.
       PinnedFieldChanged(PinnedField),
   }

   /// Classification of an SPS relative to the previous one (spec §6.1 table).
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub enum SpsChange {
       /// No previous SPS (first of the session / forced after an FLV (re)open).
       Initial,
       /// Dimensions or level changed, within limits.
       Resize,
       /// Any other within-limits change (num_ref_frames, VUI, cropping, …).
       Other,
       /// Fatal: a pinned field changed or the SPS is outside the limits.
       Incompatible(SpsIncompatibleReason),
   }

   /// Classify a new SPS against the previous one (spec §6.1). `previous = None`
   /// yields `Initial` (still after a limits check). Pinned-field comparison is
   /// against `previous`; because any earlier out-of-pin SPS would already have
   /// been `Incompatible` and ended the session, that equals comparing to the
   /// session's first SPS.
   pub fn classify_sps_change(
       previous: Option<&SpsSummary>,
       new: &SpsSummary,
       limits: &SpsLimits,
   ) -> SpsChange {
       if let Err(v) = check_sps_limits(new, limits) {
           return SpsChange::Incompatible(SpsIncompatibleReason::OutsideLimits(v));
       }
       let Some(prev) = previous else {
           return SpsChange::Initial;
       };
       if prev.profile_idc != new.profile_idc {
           return SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
               PinnedField::ProfileIdc,
           ));
       }
       if prev.chroma_format_idc != new.chroma_format_idc {
           return SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
               PinnedField::ChromaFormat,
           ));
       }
       if prev.bit_depth_luma_minus8 != new.bit_depth_luma_minus8
           || prev.bit_depth_chroma_minus8 != new.bit_depth_chroma_minus8
       {
           return SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
               PinnedField::BitDepth,
           ));
       }
       if prev.pic_order_cnt_type != new.pic_order_cnt_type {
           return SpsChange::Incompatible(SpsIncompatibleReason::PinnedFieldChanged(
               PinnedField::PicOrderCntType,
           ));
       }
       if prev.width != new.width || prev.height != new.height || prev.level_idc != new.level_idc {
           return SpsChange::Resize;
       }
       SpsChange::Other
   }
   ```

5. Run to pass:
   ```bash
   cargo test -p kvm-proto h264::sps
   ```
   Expected: 14 passed (6 from Tasks 6–7 + 8 classification). Then run the whole component once:
   ```bash
   cargo test -p kvm-proto
   ```
   Expected: all green. Optionally confirm the parser denies hold:
   ```bash
   cargo clippy -p kvm-proto --all-targets -- -D warnings
   ```

6. Commit:
   ```bash
   git -C /home/chris/Repos/kvm-rdp add -A
   git -C /home/chris/Repos/kvm-rdp commit -m "kvm-proto/h264: SPS-change classification (§6.1 table)

   Pure classify_sps_change(previous, new, limits) -> initial/resize/other/
   incompatible, with pinned-field (profile/chroma/bit-depth/POC-type) and
   limits checks. Initial-after-FLV-open + cross-reconnect pin persistence is
   Plan C sequencing (caller passes previous=None); noted in rustdoc.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

## Part 4 — Synthetic fixtures

Deterministic test streams and their manifests, checked against kvm-proto's parser.

_Component preamble (not a task): synthetic H.264 fixtures (spec §11.5). Everything here is generated from `ffmpeg`'s `testsrc2`/`color` sources by `scripts/gen-fixtures.sh` with the flake's pinned ffmpeg/x264, deterministically (`-threads 1`, `sliced-threads=0`, fixed GOP, no scene-cut), so a regeneration on the same `flake.lock` is byte-identical and a manifest test catches drift. **No fixture ever comes from the real KVM** — real captures show the work Mac's screen and stay in the gitignored `captures/`. Two outputs: small committed fixtures in `fixtures/` (tests, kvm-sim later) and larger on-demand streams in `fixtures/large/` (gitignored; Leg B spike now, benches in Plan E). Deviation from §11.5, recorded for the spec revision: the POC-type-0-without-`bitstream_restriction` fixture is produced in Plan B alongside the SPS rewriter it exists to test; Plan A's §6.8 decision uses the census and, if needed, a local capture (census tasks)._

### Task 4.1: `scripts/gen-fixtures.sh` and the committed fixture set

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/scripts/gen-fixtures.sh`
- Create (generated, committed): `/home/chris/Repos/kvm-rdp/fixtures/{360p30_baseline_full,360p30_main_full,360p30_main_norepeat,360p30_main_longgop,360p30_main_slices,360p30_main_limited,360p30_main_limited_flagfull,480p30_main_full,slate_1080p}.h264`, `/home/chris/Repos/kvm-rdp/fixtures/360p30_main_full.flv`, and one `<name>.manifest.json` per file
- Test: the script's own self-checks (step 3) — the Rust oracle test is Task 4.2

**Interfaces:**
- Consumes: the devshell (`ffmpeg`/`ffprobe` with libx264 and drawtext, `jq`, `KVM_RDP_FONT`).
- Produces: the fixture paths above (consumed by kvm-proto's fixture test, kvm-probe's capture test `fixtures/360p30_main_full.flv`, and the Leg B spike) and, via `scripts/gen-fixtures.sh large`, `fixtures/large/{1080p30_main_full,720p30_main_full,1080p30_main_limited,1080p30_main_limited_flagfull}.h264`. Manifest schema: `{"name","sha256","bytes","width","height","profile_idc","level_idc","pic_order_cnt_type","video_full_range_flag","bitstream_restriction_flag","frames","key_frames","keyint","slices_per_au"}` (absent VUI fields are `null`).

**Steps:**

1. Write `scripts/gen-fixtures.sh` (mode `committed` is the default):
   ```bash
   #!/usr/bin/env bash
   # Synthetic H.264 fixtures for kvm-rdp (spec §11.5). Deterministic for a pinned
   # ffmpeg/x264 (flake.lock): encoder -threads 1, sliced-threads=0, fixed GOP,
   # scenecut=0. Never fed from the real KVM.
   #   scripts/gen-fixtures.sh            fixtures/*.h264|.flv + *.manifest.json (committed)
   #   scripts/gen-fixtures.sh large      fixtures/large/*.h264 (gitignored; spikes, benches)
   #   scripts/gen-fixtures.sh clean      rm -rf fixtures/large
   set -euo pipefail
   cd "$(dirname "$0")/.."
   MODE=${1:-committed}
   FF=(nice -n 19 ffmpeg -hide_banner -nostdin -loglevel error -y)
   FP=(nice -n 19 ffprobe -v error)

   # 16-bit frame-counter barcode across the top: block k is white when bit k of
   # the frame number n is set. $1/$2 = block width/height.
   barcode() {
     local f="drawbox=x=0:y=0:w=iw:h=$2:color=black:t=fill" k
     for k in $(seq 0 15); do
       f="$f,drawbox=x=$((k * $1)):y=0:w=$1:h=$2:color=white:t=fill:enable='eq(mod(floor(n/$((1 << k))),2),1)'"
     done
     printf '%s' "$f"
   }

   # enc OUT WxH FRAMES PROFILE LEVEL RANGE(pc|tv) KEYINT BITRATE REPEAT_HEADERS BLOCK_W BLOCK_H [EXTRA_X264]
   enc() {
     local out=$1 size=$2 frames=$3 profile=$4 level=$5 range=$6 keyint=$7 br=$8 rh=$9 bw=${10} bh=${11} extra=${12:-}
     "${FF[@]}" -f lavfi -i "testsrc2=size=${size}:rate=30" \
       -vf "$(barcode "$bw" "$bh"),scale=out_color_matrix=bt709:out_range=${range},format=yuv420p" \
       -frames:v "$frames" -an -c:v libx264 -preset veryfast -tune zerolatency \
       -profile:v "$profile" -level:v "$level" -bf 0 -threads 1 \
       -x264-params "sliced-threads=0:keyint=${keyint}:min-keyint=${keyint}:scenecut=0:aud=1:repeat-headers=${rh}:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=${range}${extra}" \
       -b:v "$br" -maxrate "$br" -bufsize "$br" -f h264 "$out"
   }

   # First value of a trace_headers field, or null when the field is absent.
   tv() { awk -v k=" $2 " 'index($0, k) { print $NF; found = 1; exit } END { if (!found) print "null" }' <<<"$1"; }

   manifest() { # $1 = fixture path, $2 = configured keyint
     local f=$1 keyint=$2 probe trace frames keys slices
     probe=$("${FP[@]}" -count_frames -select_streams v:0 \
       -show_entries stream=width,height,nb_read_frames -of json "$f")
     trace=$("${FF[@]}" -loglevel trace -i "$f" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
     frames=$(jq '.streams[0].nb_read_frames | tonumber' <<<"$probe")
     keys=$("${FP[@]}" -select_streams v:0 -show_entries frame=key_frame -of csv=p=0 "$f" | grep -c '^1' || true)
     slices=$(grep -c ' first_mb_in_slice ' <<<"$trace" || true)
     jq -n \
       --arg name "$(basename "$f")" \
       --arg sha "$(sha256sum "$f" | cut -d' ' -f1)" \
       --argjson bytes "$(stat -c %s "$f")" \
       --argjson probe "$probe" \
       --argjson profile "$(tv "$trace" profile_idc)" \
       --argjson level "$(tv "$trace" level_idc)" \
       --argjson poc "$(tv "$trace" pic_order_cnt_type)" \
       --argjson full "$(tv "$trace" video_full_range_flag)" \
       --argjson br "$(tv "$trace" bitstream_restriction_flag)" \
       --argjson frames "$frames" --argjson keys "$keys" --argjson keyint "$keyint" \
       --argjson slices "$slices" \
       '{name: $name, sha256: $sha, bytes: $bytes,
         width: $probe.streams[0].width, height: $probe.streams[0].height,
         profile_idc: $profile, level_idc: $level, pic_order_cnt_type: $poc,
         video_full_range_flag: $full, bitstream_restriction_flag: $br,
         frames: $frames, key_frames: $keys, keyint: $keyint,
         slices_per_au: (if $frames > 0 then ($slices / $frames | floor) else 0 end)}' \
       > "${f}.manifest.json"
   }

   committed() {
     mkdir -p fixtures
     local d=fixtures
     #   OUT                                  SIZE     FRAMES PROFILE  LEVEL RANGE KEYINT BR    RH BW BH  EXTRA
     enc $d/360p30_baseline_full.h264         640x360  90     baseline 3.1   pc    30     600k  1  40 32
     enc $d/360p30_main_full.h264             640x360  90     main     3.1   pc    30     600k  1  40 32
     enc $d/360p30_main_norepeat.h264         640x360  90     main     3.1   pc    30     600k  0  40 32
     enc $d/360p30_main_longgop.h264          640x360  330    main     3.1   pc    300    300k  1  40 32
     enc $d/360p30_main_slices.h264           640x360  90     main     3.1   pc    30     600k  1  40 32  ":slice-max-size=250"
     enc $d/360p30_main_limited.h264          640x360  90     main     3.1   tv    30     600k  1  40 32
     enc $d/480p30_main_full.h264             854x480  90     main     3.1   pc    30     800k  1  40 32
     # Colour A/B twin: identical slices, only the SPS VUI range flag flipped.
     "${FF[@]}" -i $d/360p30_main_limited.h264 -c copy \
       -bsf:v h264_metadata=video_full_range_flag=1 -f h264 $d/360p30_main_limited_flagfull.h264
     # Demux oracle: the main stream muxed by ffmpeg's own FLV muxer.
     "${FF[@]}" -i $d/360p30_main_full.h264 -c copy -f flv $d/360p30_main_full.flv
     # "Connecting to KVM…" slate: one 1080p IDR (spec §6.4).
     "${FF[@]}" -f lavfi -i "color=c=0x202020:size=1920x1080:rate=30" \
       -vf "drawtext=fontfile=${KVM_RDP_FONT}:text='Connecting to KVM...':fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2,scale=out_color_matrix=bt709:out_range=pc,format=yuv420p" \
       -frames:v 1 -an -c:v libx264 -preset veryfast -profile:v main -level:v 4.0 -threads 1 \
       -x264-params "sliced-threads=0:keyint=1:min-keyint=1:scenecut=0:aud=1:repeat-headers=1:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=pc" \
       -f h264 $d/slate_1080p.h264

     manifest $d/360p30_baseline_full.h264 30
     manifest $d/360p30_main_full.h264 30
     manifest $d/360p30_main_norepeat.h264 30
     manifest $d/360p30_main_longgop.h264 300
     manifest $d/360p30_main_slices.h264 30
     manifest $d/360p30_main_limited.h264 30
     manifest $d/360p30_main_limited_flagfull.h264 30
     manifest $d/480p30_main_full.h264 30
     manifest $d/360p30_main_full.flv 30
     manifest $d/slate_1080p.h264 1
   }

   large() {
     mkdir -p fixtures/large
     local d=fixtures/large
     enc $d/1080p30_main_full.h264      1920x1080 300 main 4.0 pc 30 4M 1 120 64
     enc $d/720p30_main_full.h264       1280x720  300 main 4.0 pc 30 2500k 1 80 48
     enc $d/1080p30_main_limited.h264   1920x1080 300 main 4.0 tv 30 4M 1 120 64
     "${FF[@]}" -i $d/1080p30_main_limited.h264 -c copy \
       -bsf:v h264_metadata=video_full_range_flag=1 -f h264 $d/1080p30_main_limited_flagfull.h264
   }

   case "$MODE" in
     committed) committed ;;
     large) large ;;
     clean) rm -rf fixtures/large ;;
     *) echo "usage: $0 [committed|large|clean]" >&2; exit 2 ;;
   esac
   ```
   Then `chmod +x scripts/gen-fixtures.sh`.

2. Run it inside the devshell:
   ```
   nix develop -c scripts/gen-fixtures.sh
   ```
   Expected: 10 fixture files and 10 `.manifest.json` files under `fixtures/`, no errors.

3. Self-check the generation contract before committing (each line must print `ok`):
   ```
   du -b fixtures/*.h264 fixtures/*.flv | awk '{ if ($1 > 524288) bad = 1 } END { print (bad ? "TOO BIG" : "ok") }'
   jq -e '.video_full_range_flag == 1' fixtures/360p30_main_full.h264.manifest.json >/dev/null && echo ok
   jq -e '.video_full_range_flag == 0' fixtures/360p30_main_limited.h264.manifest.json >/dev/null && echo ok
   jq -e '.video_full_range_flag == 1' fixtures/360p30_main_limited_flagfull.h264.manifest.json >/dev/null && echo ok
   jq -e '.profile_idc == 66 and .key_frames == 3' fixtures/360p30_baseline_full.h264.manifest.json >/dev/null && echo ok
   jq -e '.slices_per_au > 1' fixtures/360p30_main_slices.h264.manifest.json >/dev/null && echo ok
   jq -e '.width == 854 and .height == 480' fixtures/480p30_main_full.h264.manifest.json >/dev/null && echo ok
   jq -e '.width == 1920 and .height == 1080 and .frames == 1' fixtures/slate_1080p.h264.manifest.json >/dev/null && echo ok
   nix develop -c scripts/gen-fixtures.sh && git status --porcelain fixtures/ | grep -q . && echo "NOT DETERMINISTIC" || echo ok
   ```
   The last line regenerates and asserts nothing changed (determinism). If it prints `NOT DETERMINISTIC`, find the nondeterministic stream (`git diff --stat fixtures/`) before going on.

4. Commit:
   ```
   git add scripts/gen-fixtures.sh fixtures/
   git commit -m "Synthetic H.264 fixtures and manifests (spec §11.5)" \
     -m "Deterministic testsrc2 streams with a 16-bit frame barcode: baseline/main full range, no-repeat-headers, long GOP, multi-slice, limited range + flag-flipped twin, 480p, an ffmpeg-muxed FLV and the 1080p slate. Large 1080p/720p streams come from 'gen-fixtures.sh large' into the gitignored fixtures/large/." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 4.2: fixture oracle test in kvm-proto (manifest + ffmpeg's view vs kvm-proto's parser)

The manifests carry what ffmpeg's `trace_headers` and `ffprobe` saw — an oracle independent of our code. This test pins three things: the committed bytes match their manifests (catches drift and corruption); kvm-proto's `parse_sps` agrees with ffmpeg on every fixture; and the generation contract holds (the A/B twin differs **only** in the SPS, `repeat-headers=0` really has one SPS, the slice fixture stays within §6.2's 128-NAL-per-AU limit).

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/Cargo.toml` (`[[test]] name = "fixtures"`, dev-deps `sha2`, `serde_json`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/fixtures.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-proto/tests/fixtures.rs`

**Interfaces:**
- Consumes: `fixtures/*.manifest.json` and the fixture files (Task 4.1); `kvm_proto::h264::{parse_sps, SpsSummary}` (H.264 tasks).
- Produces: the `fixtures` integration-test binary — kvm-proto's single integration-test binary (§13: `autotests = false`, one `[[test]]`).

**Steps:**

1. Declare the test binary and dev-deps in `crates/kvm-proto/Cargo.toml`:
   ```toml
   [[test]]
   name = "fixtures"
   path = "tests/fixtures.rs"

   [dev-dependencies]
   sha2 = "0.10"
   serde_json = "1"
   ```

2. Write the test `crates/kvm-proto/tests/fixtures.rs`:
   ```rust
   //! Oracle: ffmpeg's view of each committed fixture (its manifest) vs kvm-proto.
   use sha2::{Digest, Sha256};
   use std::path::{Path, PathBuf};

   fn root() -> PathBuf {
       Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
   }

   fn manifests() -> Vec<serde_json::Value> {
       let mut v: Vec<_> = std::fs::read_dir(root()).unwrap()
           .map(|e| e.unwrap().path())
           .filter(|p| p.to_string_lossy().ends_with(".manifest.json"))
           .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
           .collect();
       v.sort_by_key(|m: &serde_json::Value| m["name"].as_str().unwrap().to_owned());
       v
   }

   fn read(name: &str) -> Vec<u8> {
       std::fs::read(root().join(name)).unwrap()
   }

   /// NAL payloads of an Annex-B stream (3- or 4-byte start codes).
   fn nals(b: &[u8]) -> Vec<&[u8]> {
       let mut starts = Vec::new(); // (start-code begin, payload begin)
       let mut i = 0;
       while i + 3 <= b.len() {
           if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
               let begin = if i > 0 && b[i - 1] == 0 { i - 1 } else { i };
               starts.push((begin, i + 3));
               i += 3;
           } else {
               i += 1;
           }
       }
       starts.iter().enumerate().map(|(k, &(_, p))| {
           let end = starts.get(k + 1).map_or(b.len(), |&(s, _)| s);
           &b[p..end]
       }).collect()
   }

   fn nal_type(n: &[u8]) -> u8 { n[0] & 0x1F }

   #[test]
   fn committed_bytes_match_their_manifests() {
       let ms = manifests();
       assert_eq!(ms.len(), 10, "expected 10 committed fixtures");
       for m in &ms {
           let name = m["name"].as_str().unwrap();
           let bytes = read(name);
           assert_eq!(bytes.len() as u64, m["bytes"].as_u64().unwrap(), "{name} size");
           assert_eq!(format!("{:x}", Sha256::digest(&bytes)), m["sha256"].as_str().unwrap(),
               "{name} sha256 — regenerate with scripts/gen-fixtures.sh on the locked flake");
       }
   }

   #[test]
   fn kvm_proto_sps_parser_agrees_with_ffmpeg() {
       for m in manifests() {
           let name = m["name"].as_str().unwrap();
           if !name.ends_with(".h264") { continue; }
           let bytes = read(name);
           let sps = nals(&bytes).into_iter().find(|n| nal_type(n) == 7)
               .unwrap_or_else(|| panic!("{name}: no SPS"));
           let s = kvm_proto::h264::parse_sps(sps).unwrap_or_else(|e| panic!("{name}: {e:?}"));
           assert_eq!(u64::from(s.width), m["width"].as_u64().unwrap(), "{name} width");
           assert_eq!(u64::from(s.height), m["height"].as_u64().unwrap(), "{name} height");
           assert_eq!(u64::from(s.profile_idc), m["profile_idc"].as_u64().unwrap(), "{name} profile");
           assert_eq!(u64::from(s.level_idc), m["level_idc"].as_u64().unwrap(), "{name} level");
           assert_eq!(u64::from(s.pic_order_cnt_type), m["pic_order_cnt_type"].as_u64().unwrap(), "{name} poc");
           let full = m["video_full_range_flag"].as_u64().map(|v| v == 1);
           assert_eq!(s.video_full_range_flag, full, "{name} full range");
           let restriction = m["bitstream_restriction_flag"].as_u64() == Some(1);
           assert_eq!(s.max_num_reorder_frames.is_some(), restriction, "{name} bitstream_restriction");
       }
   }

   #[test]
   fn colour_twin_differs_only_in_the_sps() {
       let a = read("360p30_main_limited.h264");
       let b = read("360p30_main_limited_flagfull.h264");
       let (na, nb) = (nals(&a), nals(&b));
       assert_eq!(na.len(), nb.len());
       for (x, y) in na.iter().zip(nb.iter()) {
           if nal_type(x) == 7 { continue; }
           assert_eq!(x, y, "non-SPS NAL differs between the A/B twins");
       }
   }

   #[test]
   fn norepeat_has_one_sps_and_main_repeats_per_idr() {
       let one = nals(&read("360p30_main_norepeat.h264")).into_iter().filter(|n| nal_type(n) == 7).count();
       assert_eq!(one, 1);
       let main = nals(&read("360p30_main_full.h264")).into_iter().filter(|n| nal_type(n) == 7).count();
       assert_eq!(main, 3, "repeat-headers=1 with keyint 30 over 90 frames");
   }

   #[test]
   fn slice_fixture_stays_within_the_per_au_nal_limit() {
       // AUs are AUD-delimited (aud=1); §6.2 caps 128 NALs per AU.
       let mut per_au = 0usize;
       let mut max = 0usize;
       for n in nals(&read("360p30_main_slices.h264")) {
           if nal_type(n) == 9 { per_au = 0; }
           per_au += 1;
           max = max.max(per_au);
       }
       assert!(max > 3, "expected several slices per AU, got {max}");
       assert!(max <= 128, "slice fixture exceeds §6.2's 128 NALs/AU: {max}");
   }
   ```

3. Run it:
   ```
   cargo test -p kvm-proto --test fixtures
   ```
   Expected: `test result: ok. 5 passed`. A failure in `kvm_proto_sps_parser_agrees_with_ffmpeg` is a real finding about the parser (or the manifest extraction) — fix the cause; do not edit a manifest by hand.

4. Commit:
   ```
   git add crates/kvm-proto/Cargo.toml crates/kvm-proto/tests/fixtures.rs Cargo.lock
   git commit -m "kvm-proto: fixture oracle test (manifests and ffmpeg's view vs parse_sps)" \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

## Part 5 — kvm-probe: the census tool

Login, bounded stream capture with per-tag JSONL, first-IDR trials, the control-websocket open check and the sandboxed sample-range measurement.

### Task 5.1: Scaffold `kvm-probe` crate and the SPKI fingerprint formatter

All `cargo` commands run inside the devshell (`nix develop --command …` or `nix-shell shell.nix --run '…'`), so §13's `systemd-run … nice -n 19 cargo` wrapper, `jobs = 4` and `RUST_TEST_THREADS = 4` apply automatically. The crate lives at the repo root as `kvm-probe/` (member path `kvm-probe`, per §4.1).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/main.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/fingerprint.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/clippy.toml`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/fingerprint.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: workspace root `Cargo.toml`, `.cargo/config.toml`, `rust-toolchain.toml` (workspace-scaffold component).
- Produces: crate `kvm-probe`; `pub fn kvm_probe::fingerprint::spki_sha256_hex(spki_der: &[u8]) -> String`.

**Steps:**

1. Scaffold the crate (setup, not the unit under test). `crates/kvm-probe/Cargo.toml`:
   ```toml
   [package]
   name = "kvm-probe"
   version = "0.0.0"
   edition = "2024"
   rust-version = "1.94"
   license = "MIT OR Apache-2.0"
   publish = false

   [lib]
   name = "kvm_probe"
   path = "src/lib.rs"

   [[bin]]
   name = "kvm-probe"
   path = "src/main.rs"

   [dependencies]
   sha2 = "0.10"

   [lints.clippy]
   indexing_slicing = "deny"
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   arithmetic_side_effects = "deny"
   as_conversions = "deny"
   ```
   `clippy.toml`:
   ```toml
   allow-unwrap-in-tests = true
   allow-expect-in-tests = true
   allow-panic-in-tests = true
   ```
   `src/lib.rs`:
   ```rust
   pub mod fingerprint;
   ```
   `src/main.rs`:
   ```rust
   fn main() {
       eprintln!("kvm-probe {}", env!("CARGO_PKG_VERSION"));
   }
   ```
   (No root-manifest edit: the workspace's `crates/*` glob picks the crate up.)

2. Write the failing test in `src/fingerprint.rs` (module has no body yet):
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn abc_matches_known_sha256() {
           // SHA-256("abc") is a fixed, independently known value.
           assert_eq!(
               spki_sha256_hex(b"abc"),
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
           );
       }

       #[test]
       fn empty_is_64_hex_chars() {
           let s = spki_sha256_hex(b"");
           assert_eq!(s.len(), 64);
           assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
       }
   }
   ```

3. Run it, expect a compile failure (function missing):
   ```
   cargo test -p kvm-probe --lib fingerprint::
   ```
   Expect: `error[E0425]: cannot find function `spki_sha256_hex` in this scope` (or `E0433`).

4. Minimal implementation at the top of `src/fingerprint.rs`:
   ```rust
   use sha2::{Digest, Sha256};

   /// Lowercase hex of the SHA-256 of a DER-encoded SubjectPublicKeyInfo (§3.2).
   pub fn spki_sha256_hex(spki_der: &[u8]) -> String {
       let digest = Sha256::digest(spki_der);
       let mut out = String::with_capacity(64);
       for byte in digest {
           // {:02x} cannot overflow; no arithmetic on `byte`.
           out.push_str(&format!("{byte:02x}"));
       }
       out
   }
   ```

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib fingerprint::
   ```
   Expect: `test result: ok. 2 passed`.

6. Commit:
   ```
   git add crates/kvm-probe/ Cargo.toml && git commit -m "kvm-probe: scaffold crate and SPKI fingerprint hex formatter

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.2: KVM request builders (login body, FLV/logout/websocket URLs, token cookie)

These are pure functions grounded byte-for-byte in the ES3 web UI: login body from `login.html` (`field.pass` + `field.timezone = Intl…timeZone` + `field.time = ceil(Date.now()/1000)`, `JSON.stringify`); `av.flv?…token=0.<n>` from `kvm.js:363`; logout `GET /cgi-bin/login.lua?logout` from `index.js:625`; `/websocket` from `kvm.js:195`; cookie name `token` from `login.html` `$.cookie("token", …)`.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/request.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod request;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml` (`serde`, `serde_json`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/request.rs`

**Interfaces:**
- Produces: `pub enum request::Scheme { Http, Https }`; `pub struct request::KvmTarget { scheme, host, login_port, video_port, control_port }`; `pub fn build_login_body(password: &str, timezone: &str, now_unix: i64) -> String`; `pub fn flv_url(&KvmTarget, token: &str) -> String`; `pub fn logout_url(&KvmTarget) -> String`; `pub fn websocket_url(&KvmTarget) -> String`; `pub fn token_cookie_header(token: &str) -> String`.
- Consumes: nothing.

**Steps:**

1. Add deps to `crates/kvm-probe/Cargo.toml`:
   ```toml
   serde = { version = "1", features = ["derive"] }
   serde_json = "1"
   ```
   and `pub mod request;` to `src/lib.rs`.

2. Write the failing test in `src/request.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       fn https_target() -> KvmTarget {
           KvmTarget {
               scheme: Scheme::Https,
               host: "192.168.0.50".to_string(),
               login_port: 443,
               video_port: 8881,
               control_port: 8889,
           }
       }

       #[test]
       fn login_body_is_pass_timezone_time_in_order() {
           assert_eq!(
               build_login_body("s3cret", "America/Chicago", 1_759_680_000),
               r#"{"pass":"s3cret","timezone":"America/Chicago","time":1759680000}"#
           );
       }

       #[test]
       fn urls_and_cookie_match_the_web_ui() {
           let t = https_target();
           assert_eq!(flv_url(&t, "0.12345"), "https://192.168.0.50:8881/av.flv?token=0.12345");
           assert_eq!(logout_url(&t), "https://192.168.0.50:443/cgi-bin/login.lua?logout");
           assert_eq!(websocket_url(&t), "wss://192.168.0.50:8889/websocket");
           assert_eq!(token_cookie_header("0.12345"), "token=0.12345");
       }

       #[test]
       fn http_scheme_uses_ws_not_wss() {
           let t = KvmTarget { scheme: Scheme::Http, host: "h".into(),
               login_port: 80, video_port: 8880, control_port: 8888 };
           assert_eq!(websocket_url(&t), "ws://h:8888/websocket");
           assert_eq!(flv_url(&t, "0.1"), "http://h:8880/av.flv?token=0.1");
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib request::
   ```
   Expect: `error[E0433]: failed to resolve: use of undeclared type `KvmTarget``.

4. Minimal implementation at the top of `src/request.rs`:
   ```rust
   use serde::Serialize;

   #[derive(Clone, Copy, Debug)]
   pub enum Scheme { Http, Https }

   impl Scheme {
       pub fn http(self) -> &'static str { match self { Scheme::Http => "http", Scheme::Https => "https" } }
       pub fn ws(self) -> &'static str { match self { Scheme::Http => "ws", Scheme::Https => "wss" } }
   }

   #[derive(Clone, Debug)]
   pub struct KvmTarget {
       pub scheme: Scheme,
       pub host: String,
       pub login_port: u16,
       pub video_port: u16,
       pub control_port: u16,
   }

   #[derive(Serialize)]
   struct LoginBody<'a> { pass: &'a str, timezone: &'a str, time: i64 }

   /// Body of `POST /cgi-bin/login.lua` (login.html). Infallible: the struct has no maps.
   pub fn build_login_body(password: &str, timezone: &str, now_unix: i64) -> String {
       let body = LoginBody { pass: password, timezone, time: now_unix };
       serde_json::to_string(&body).unwrap_or_else(|_| String::new())
   }

   pub fn flv_url(t: &KvmTarget, token: &str) -> String {
       format!("{}://{}:{}/av.flv?token={}", t.scheme.http(), t.host, t.video_port, token)
   }
   pub fn logout_url(t: &KvmTarget) -> String {
       format!("{}://{}:{}/cgi-bin/login.lua?logout", t.scheme.http(), t.host, t.login_port)
   }
   pub fn websocket_url(t: &KvmTarget) -> String {
       format!("{}://{}:{}/websocket", t.scheme.ws(), t.host, t.control_port)
   }
   pub fn token_cookie_header(token: &str) -> String { format!("token={token}") }
   ```
   (The `unwrap_or_else` keeps `unwrap_used` satisfied without a panic path; a fixed-shape struct never fails to serialize.)

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib request::
   ```
   Expect: `test result: ok. 3 passed`.

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: KVM request builders grounded in the ES3 web UI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.3: `TagRecord` JSONL formatting (one line per FLV tag)

One JSONL line per FLV tag with the §12 Leg A fields: receive time, tag type, timestamp, CompositionTime, frame type, codec, packet type, NAL types, `nal_ref_idc`, slice type, size. `TagRecord` is owned by kvm-probe with plain fields so this formatting is independent of the kvm-proto parser (Task 9 populates it from parsed tags). The probe never decodes — it only records framing fields.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/record.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod record;`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/record.rs`

**Interfaces:**
- Produces: `pub struct record::TagRecord { pub recv_ms: u64, pub tag_type: u8, pub timestamp_ms: u32, pub composition_time: i32, pub frame_type: Option<u8>, pub codec_id: Option<u8>, pub avc_packet_type: Option<u8>, pub fourcc: Option<String>, pub nal_types: Vec<u8>, pub nal_ref_idc: Vec<u8>, pub slice_types: Vec<Option<u8>>, pub first_mb: Vec<Option<u32>>, pub size: usize }` (`fourcc` is set only for Enhanced-RTMP tags, e.g. `"hvc1"`; `first_mb` is `first_mb_in_slice` per VCL NAL — `Some(0)` starts a picture, so a tag holding more than one `Some(0)`, or a picture split across tags, answers the census's "tag = AU?"); `pub fn TagRecord::to_jsonl(&self) -> Result<String, serde_json::Error>`.
- Consumes: nothing.

**Steps:**

1. Add `pub mod record;` to `src/lib.rs`.

2. Write the failing test in `src/record.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn video_idr_tag_serialises_exactly() {
           let r = TagRecord {
               recv_ms: 1234,
               tag_type: 9,
               timestamp_ms: 40,
               composition_time: 0,
               frame_type: Some(1),
               codec_id: Some(7),
               avc_packet_type: Some(1),
               fourcc: None,
               nal_types: vec![7, 8, 5],
               nal_ref_idc: vec![3, 3, 3],
               slice_types: vec![None, None, Some(7)],
               first_mb: vec![None, None, Some(0)],
               size: 4096,
           };
           assert_eq!(
               r.to_jsonl().unwrap(),
               r#"{"recv_ms":1234,"tag_type":9,"timestamp_ms":40,"composition_time":0,"frame_type":1,"codec_id":7,"avc_packet_type":1,"fourcc":null,"nal_types":[7,8,5],"nal_ref_idc":[3,3,3],"slice_types":[null,null,7],"first_mb":[null,null,0],"size":4096}"#
           );
       }

       #[test]
       fn non_video_tag_has_null_video_fields() {
           let r = TagRecord {
               recv_ms: 5, tag_type: 18, timestamp_ms: 0, composition_time: 0,
               frame_type: None, codec_id: None, avc_packet_type: None, fourcc: None,
               nal_types: vec![], nal_ref_idc: vec![], slice_types: vec![], first_mb: vec![],
               size: 11,
           };
           let line = r.to_jsonl().unwrap();
           assert!(line.contains(r#""frame_type":null"#));
           assert!(!line.contains('\n'));
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib record::
   ```
   Expect: `error[E0422]: cannot find struct `TagRecord``.

4. Minimal implementation at the top of `src/record.rs`:
   ```rust
   use serde::Serialize;

   /// One census JSONL line (§12 Leg A). Field order below is the emitted order.
   #[derive(Serialize, Clone, Debug)]
   pub struct TagRecord {
       pub recv_ms: u64,
       pub tag_type: u8,
       pub timestamp_ms: u32,
       pub composition_time: i32,
       pub frame_type: Option<u8>,
       pub codec_id: Option<u8>,
       pub avc_packet_type: Option<u8>,
       pub fourcc: Option<String>,
       pub nal_types: Vec<u8>,
       pub nal_ref_idc: Vec<u8>,
       pub slice_types: Vec<Option<u8>>,
       pub first_mb: Vec<Option<u32>>,
       pub size: usize,
   }

   impl TagRecord {
       /// Serialize to a single JSON line (no trailing newline; the writer adds it).
       pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
           serde_json::to_string(self)
       }
   }
   ```

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib record::
   ```
   Expect: `test result: ok. 2 passed`.

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: TagRecord JSONL record for census (§12 Leg A fields)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.4: `captures/` directory discipline (0700, refuse non-captures paths)

§11.5/§12: the probe writes **only** under a 0700 `captures/` directory and refuses any other path (real captures show the Mac's screen and are gitignored + wiped). `resolve` accepts exactly one safe filename component; everything else is `Unsafe`.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/captures.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod captures;`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/captures.rs`

**Interfaces:**
- Produces: `pub struct captures::CaptureDir`; `pub enum captures::CaptureError { Unsafe(String), Io(std::io::Error) }`; `pub fn CaptureDir::create(root: &std::path::Path) -> Result<CaptureDir, CaptureError>`; `pub fn CaptureDir::resolve(&self, name: &str) -> Result<std::path::PathBuf, CaptureError>`.
- Consumes: nothing.

**Steps:**

1. Add `pub mod captures;` to `src/lib.rs`.

2. Write the failing test in `src/captures.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use std::os::unix::fs::PermissionsExt;

       fn tmp_root() -> std::path::PathBuf {
           let mut p = std::env::temp_dir();
           p.push(format!("kvm-probe-cap-{}", std::process::id()));
           p.push("captures");
           p
       }

       #[test]
       fn create_is_0700_and_resolves_only_simple_names() {
           let root = tmp_root();
           let _ = std::fs::remove_dir_all(root.parent().unwrap());
           let dir = CaptureDir::create(&root).unwrap();

           let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
           assert_eq!(mode, 0o700);

           assert_eq!(dir.resolve("capture-001.flv").unwrap(), root.join("capture-001.flv"));

           for bad in ["../x", "/etc/passwd", "a/b", "", ".", "..", "with\0null"] {
               assert!(matches!(dir.resolve(bad), Err(CaptureError::Unsafe(_))), "accepted {bad:?}");
           }
           let _ = std::fs::remove_dir_all(root.parent().unwrap());
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib captures::
   ```
   Expect: `error[E0433]: ... CaptureDir`.

4. Minimal implementation at the top of `src/captures.rs`:
   ```rust
   use std::path::{Component, Path, PathBuf};

   #[derive(Debug)]
   pub enum CaptureError { Unsafe(String), Io(std::io::Error) }

   impl From<std::io::Error> for CaptureError {
       fn from(e: std::io::Error) -> Self { CaptureError::Io(e) }
   }

   pub struct CaptureDir { root: PathBuf }

   fn is_safe_name(name: &str) -> bool {
       if name.is_empty() || name.contains('\0') { return false; }
       let mut comps = Path::new(name).components();
       match (comps.next(), comps.next()) {
           (Some(Component::Normal(c)), None) => c == std::ffi::OsStr::new(name),
           _ => false,
       }
   }

   impl CaptureDir {
       /// Create `root` (and parents) with mode 0700; tighten if it already exists.
       pub fn create(root: &Path) -> Result<CaptureDir, CaptureError> {
           use std::os::unix::fs::DirBuilderExt;
           if let Some(parent) = root.parent() {
               std::fs::create_dir_all(parent)?;
           }
           let mut b = std::fs::DirBuilder::new();
           b.mode(0o700);
           match b.create(root) {
               Ok(()) => {}
               Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
               Err(e) => return Err(CaptureError::Io(e)),
           }
           std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
           Ok(CaptureDir { root: root.to_path_buf() })
       }

       /// Join a single safe filename under the capture root; refuse anything else.
       pub fn resolve(&self, name: &str) -> Result<PathBuf, CaptureError> {
           if !is_safe_name(name) {
               return Err(CaptureError::Unsafe(name.to_string()));
           }
           Ok(self.root.join(name))
       }
   }
   ```

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib captures::
   ```
   Expect: `test result: ok. 1 passed`.

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: 0700 captures dir with single-component path refusal (§11.5)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.5: bubblewrap+ffmpeg sandbox command builder (sample-range decode)

§12: the decoded-sample-range measurement runs ffmpeg in a disposable sandbox — `bwrap --unshare-all --die-with-parent --ro-bind /nix /nix --bind $CAPDIR /cap …` — and reads the **decoder-native Y plane** with `ffmpeg -f rawvideo` in the decoder's own pix_fmt, **no `-vf`/scale**. The builder emits the exact argv; it passes no `-pix_fmt` (so ffmpeg emits the native plane and inserts no scaler) and adds `--clearenv`/`--chdir /cap` as census-hygiene hardening (§9.3: no home, no SSH agent, no repo). ffmpeg is addressed by absolute /nix store path (caller resolves it from the devshell).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod sandbox;`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`

**Interfaces:**
- Produces: `pub fn sandbox::build_ffmpeg_sandbox_argv(ffmpeg: &std::path::Path, cap_host_dir: &std::path::Path, capture_name: &str, out_name: &str) -> Vec<String>`.
- Consumes: nothing.

**Steps:**

1. Add `pub mod sandbox;` to `src/lib.rs`.

2. Write the failing test in `src/sandbox.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use std::path::Path;

       #[test]
       fn argv_is_exact_and_has_no_scaler() {
           let argv = build_ffmpeg_sandbox_argv(
               Path::new("/nix/store/abc-ffmpeg/bin/ffmpeg"),
               Path::new("/home/chris/Repos/kvm-rdp/captures"),
               "ramp-1080p60.flv",
               "ramp-1080p60.y",
           );
           assert_eq!(argv, vec![
               "bwrap",
               "--unshare-all", "--die-with-parent", "--clearenv",
               "--dev", "/dev", "--proc", "/proc",
               "--ro-bind", "/nix", "/nix",
               "--bind", "/home/chris/Repos/kvm-rdp/captures", "/cap",
               "--chdir", "/cap",
               "--",
               "/nix/store/abc-ffmpeg/bin/ffmpeg",
               "-hide_banner", "-nostdin", "-loglevel", "verbose",
               "-i", "/cap/ramp-1080p60.flv",
               "-map", "0:v:0", "-frames:v", "1",
               "-f", "rawvideo", "/cap/ramp-1080p60.y",
           ]);
           // No scaler, no explicit pixel format, no filtergraph.
           assert!(!argv.iter().any(|a| a == "-vf" || a == "-pix_fmt" || a.contains("scale")));
           // Network namespace is unshared.
           assert!(argv.contains(&"--unshare-all".to_string()));
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expect: `error[E0425]: cannot find function `build_ffmpeg_sandbox_argv``.

4. Minimal implementation at the top of `src/sandbox.rs`:
   ```rust
   use std::path::Path;

   /// Build the `bwrap … ffmpeg …` argv that decodes a capture's first frame to a
   /// raw Y/UV plane in the decoder's native pix_fmt, with no scaler (§12).
   /// `capture_name`/`out_name` must already be CaptureDir-validated simple names.
   pub fn build_ffmpeg_sandbox_argv(
       ffmpeg: &Path,
       cap_host_dir: &Path,
       capture_name: &str,
       out_name: &str,
   ) -> Vec<String> {
       let cap_in = format!("/cap/{capture_name}");
       let cap_out = format!("/cap/{out_name}");
       vec![
           "bwrap".to_string(),
           "--unshare-all".to_string(),
           "--die-with-parent".to_string(),
           "--clearenv".to_string(),
           "--dev".to_string(), "/dev".to_string(), "--proc".to_string(), "/proc".to_string(),
           "--ro-bind".to_string(), "/nix".to_string(), "/nix".to_string(),
           "--bind".to_string(), cap_host_dir.to_string_lossy().into_owned(), "/cap".to_string(),
           "--chdir".to_string(), "/cap".to_string(),
           "--".to_string(),
           ffmpeg.to_string_lossy().into_owned(),
           "-hide_banner".to_string(), "-nostdin".to_string(),
           "-loglevel".to_string(), "verbose".to_string(),
           "-i".to_string(), cap_in,
           "-map".to_string(), "0:v:0".to_string(),
           "-frames:v".to_string(), "1".to_string(),
           "-f".to_string(), "rawvideo".to_string(), cap_out,
       ]
   }
   ```

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expect: `test result: ok. 1 passed`.

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: bwrap+ffmpeg sandbox argv for decoded sample-range (§12)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.6: scaler-insertion detector and native Y-plane min/max

§12: the sample-range run **fails if ffmpeg logs an auto-inserted scaler**, and Y min/max is read from the decoder's native Y plane (never RGB). `ffmpeg_inserted_scaler` scans ffmpeg's verbose stderr for the swscale log tag and the auto-scale filter name; `y_plane_range` reads the first `width*height` bytes (the Y plane of a planar rawvideo frame) with fully checked access — this is semi-trusted sandbox output, so no indexing/arithmetic that can panic.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`

**Interfaces:**
- Produces: `pub fn sandbox::ffmpeg_inserted_scaler(stderr: &str) -> bool`; `pub fn sandbox::y_plane_range(frame: &[u8], width: usize, height: usize) -> Option<(u8, u8)>`.
- Consumes: nothing.

**Steps:**

1. Add tests to the `mod tests` in `src/sandbox.rs`:
   ```rust
   #[test]
   fn scaler_detected_from_swscale_tags() {
       assert!(ffmpeg_inserted_scaler("[swscaler @ 0x5563] deprecated pixel format used"));
       assert!(ffmpeg_inserted_scaler("Stream mapping:\n  auto_scale_0 (scale)"));
       assert!(!ffmpeg_inserted_scaler(
           "Input #0, flv\nStream #0:0: Video: h264 (High), yuv420p\nframe=    1 fps=0.0"
       ));
   }

   #[test]
   fn y_plane_min_max_over_first_frame() {
       // width=4 height=2 -> 8 Y bytes, rest is chroma we ignore.
       let frame = [0u8, 255, 10, 20, 30, 40, 50, 16, 128, 128, 128, 128];
       assert_eq!(y_plane_range(&frame, 4, 2), Some((0, 255)));
       // too short -> None, never panics.
       assert_eq!(y_plane_range(&[0, 1, 2], 4, 2), None);
       // zero-size -> None.
       assert_eq!(y_plane_range(&frame, 0, 2), None);
   }
   ```

2. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expect: `error[E0425]: cannot find function `ffmpeg_inserted_scaler``.

3. Minimal implementation appended to `src/sandbox.rs`:
   ```rust
   /// True if ffmpeg's verbose log shows swscale or an auto-inserted scale filter.
   pub fn ffmpeg_inserted_scaler(stderr: &str) -> bool {
       let s = stderr.to_ascii_lowercase();
       s.contains("swscaler") || s.contains("auto_scale")
   }

   /// Min/max of the Y plane (first `width*height` bytes) of a planar rawvideo frame.
   /// Returns None if the buffer is too short or the plane is empty. Checked throughout.
   pub fn y_plane_range(frame: &[u8], width: usize, height: usize) -> Option<(u8, u8)> {
       let plane_len = width.checked_mul(height)?;
       if plane_len == 0 { return None; }
       let plane = frame.get(..plane_len)?;
       let mut min = u8::MAX;
       let mut max = u8::MIN;
       for &y in plane {
           if y < min { min = y; }
           if y > max { max = y; }
       }
       Some((min, max))
   }
   ```

4. Run to pass:
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expect: `test result: ok. 3 passed`.

5. Verify the hostile-input lints hold on this module:
   ```
   cargo clippy -p kvm-probe --lib -- -D warnings
   ```
   Expect: no warnings (no indexing, `checked_mul`, `.get(..)`).

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: scaler-insertion guard and checked native Y-plane range

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.7: SPKI pin TLS verifier and `--print-fingerprint` extraction

§3.2: the KVM cert is self-signed and pinned by SHA-256 of its SPKI; a mismatch refuses the connection; **there is no accept-any verifier**. `SpkiPinVerifier` implements rustls' `ServerCertVerifier` over the aws-lc provider: it extracts the end-entity SPKI, hashes it with Task 1's formatter, and compares to the configured pin (constant-time-ish string compare). In `--print-fingerprint` mode (`pin = None`) it records the SPKI hash and accepts, so the pin can be captured once. Tested without a network using an rcgen self-signed cert as the oracle (rcgen's `KeyPair::public_key_der()` is the SPKI DER).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/pin.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod pin;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml` (`rustls`, `rustls-pki-types`, `x509-parser`; dev `rcgen`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/pin.rs`

**Interfaces:**
- Produces: `pub fn pin::extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, pin::PinError>`; `pub struct pin::SpkiPinVerifier { expected_hex: Option<String>, provider: std::sync::Arc<rustls::crypto::CryptoProvider> }`; `pub fn SpkiPinVerifier::new(expected_hex: Option<String>) -> SpkiPinVerifier` (uses aws-lc-rs provider).
- Consumes: `kvm_probe::fingerprint::spki_sha256_hex` (Task 1).

**Steps:**

1. Add deps to `crates/kvm-probe/Cargo.toml`:
   ```toml
   rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "tls12", "logging"] }
   rustls-pki-types = "1"
   x509-parser = "0.16"

   [dev-dependencies]
   rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs", "pem"] }  # default features would pull in ring (§4.2)
   ```
   and `pub mod pin;` to `src/lib.rs`. (No `ring`: rustls `default-features = false` + `aws_lc_rs` only, per §4.2.)

2. Write the failing test in `src/pin.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn extract_spki_matches_rcgen_public_key_der() {
           let ck = rcgen::generate_simple_self_signed(vec!["kvm.test".to_string()]).unwrap();
           let cert_der = ck.cert.der().to_vec();
           let spki = extract_spki(&cert_der).unwrap();
           assert_eq!(spki, ck.key_pair.public_key_der());
       }

       #[test]
       fn pin_hex_round_trips_through_fingerprint() {
           let ck = rcgen::generate_simple_self_signed(vec!["kvm.test".to_string()]).unwrap();
           let spki = extract_spki(&ck.cert.der().to_vec()).unwrap();
           let pinned = crate::fingerprint::spki_sha256_hex(&spki);
           // A verifier built with the right pin considers this SPKI a match.
           let v = SpkiPinVerifier::new(Some(pinned.clone()));
           assert!(v.spki_matches(&spki));
           // A one-char-off pin does not.
           let mut wrong = pinned.clone();
           wrong.replace_range(0..1, if pinned.starts_with('a') { "b" } else { "a" });
           assert!(!SpkiPinVerifier::new(Some(wrong)).spki_matches(&spki));
           // print-fingerprint mode (no pin) accepts anything.
           assert!(SpkiPinVerifier::new(None).spki_matches(&spki));
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib pin::
   ```
   Expect: `error[E0433]: ... extract_spki`.

4. Minimal implementation in `src/pin.rs`:
   ```rust
   use std::sync::Arc;
   use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
   use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
   use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
   use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

   #[derive(Debug)]
   pub enum PinError { Parse, Mismatch }

   /// Extract the DER-encoded SubjectPublicKeyInfo from an X.509 certificate.
   pub fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, PinError> {
       let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|_| PinError::Parse)?;
       Ok(cert.public_key().raw.to_vec())
   }

   #[derive(Debug)]
   pub struct SpkiPinVerifier {
       expected_hex: Option<String>,
       provider: Arc<CryptoProvider>,
   }

   impl SpkiPinVerifier {
       pub fn new(expected_hex: Option<String>) -> SpkiPinVerifier {
           SpkiPinVerifier {
               expected_hex: expected_hex.map(|h| h.to_ascii_lowercase()),
               provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
           }
       }
       /// True if this SPKI is accepted: either no pin (record mode) or hash equals pin.
       pub fn spki_matches(&self, spki_der: &[u8]) -> bool {
           match &self.expected_hex {
               None => true,
               Some(want) => &crate::fingerprint::spki_sha256_hex(spki_der) == want,
           }
       }
   }

   impl ServerCertVerifier for SpkiPinVerifier {
       fn verify_server_cert(
           &self,
           end_entity: &CertificateDer<'_>,
           _intermediates: &[CertificateDer<'_>],
           _server_name: &ServerName<'_>,
           _ocsp: &[u8],
           _now: UnixTime,
       ) -> Result<ServerCertVerified, TlsError> {
           let spki = extract_spki(end_entity.as_ref())
               .map_err(|_| TlsError::General("SPKI parse failed".into()))?;
           if self.spki_matches(&spki) {
               Ok(ServerCertVerified::assertion())
           } else {
               Err(TlsError::General("kvm_cert_mismatch".into()))
           }
       }
       fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
           -> Result<HandshakeSignatureValid, TlsError> {
           verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
       }
       fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
           -> Result<HandshakeSignatureValid, TlsError> {
           verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
       }
       fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
           self.provider.signature_verification_algorithms.supported_schemes()
       }
   }
   ```

5. Run to pass:
   ```
   cargo test -p kvm-probe --lib pin::
   ```
   Expect: `test result: ok. 2 passed`. Then confirm no `ring` is pulled: `cargo tree -p kvm-probe -i ring` → `error: package ID specification `ring` did not match` (i.e. absent).

6. Commit:
   ```
   git add crates/kvm-probe/ && git commit -m "kvm-probe: SPKI-pinning rustls verifier (aws-lc) + --print-fingerprint extraction

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.8: KVM connection (pinned TLS or plain) + login, tested against an in-test stub

Because tests cannot reach the real KVM, this builds a loopback stub with an rcgen certificate and drives the connection path against it: a matching pin connects, a wrong pin is refused with an error that **names the fingerprint actually observed** (so a re-pin after a KVM reset is one copy-paste), a non-200 login response is a clean `KvmError::Login`, and a good login returns the token. `connect_to` speaks TLS when `target.scheme` is `Https` (pinned, §3.2) and plain TCP when it is `Http` — the census compares the two (§12 Leg A), and the bridge may use either (§3.2). `TCP_NODELAY` is set on every socket. The live run is `#[ignore]`.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/kvm.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/support/mod.rs` (loopback stubs, reused by Tasks 9 and 10)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_login.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod kvm;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/pin.rs` (mismatch error names the observed fingerprint)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_login.rs`

**Interfaces:**
- Consumes: `pin::SpkiPinVerifier` (Task 7); `request::{KvmTarget, Scheme, build_login_body}` (Task 2); `fingerprint::spki_sha256_hex` (Task 1); `kvm_proto::login::{parse_login_token, Token, LoginError}` (kvm-proto login task).
- Produces:
  - `pub trait kvm::IoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}` (blanket-implemented) and `pub type kvm::BoxedIo = Box<dyn kvm::IoStream>`
  - `pub enum kvm::KvmError { Connect(String), Tls(String), Http(String), Login(String), Io(String) }`
  - `pub async fn kvm::connect_to(target: &request::KvmTarget, port: u16, pin_sha256_hex: Option<&str>) -> Result<kvm::BoxedIo, kvm::KvmError>`
  - `pub async fn kvm::login(target: &request::KvmTarget, pin: Option<&str>, password: &str, now_unix: i64, timezone: &str) -> Result<String, kvm::KvmError>` (returns the `0.<digits>` token)
  - test support: `support::tls_acceptor_and_pin() -> (tokio_rustls::TlsAcceptor, String)`, `support::start_http_stub(response: Vec<u8>) -> support::Stub`, `support::start_login_stub() -> support::Stub`, `pub struct support::Stub { pub port: u16, pub pin_hex: String }`

**Steps:**

1. Add dependencies to `crates/kvm-probe/Cargo.toml` (aws-lc only — `rcgen`'s default features would pull in `ring`, which §4.2 forbids):
   ```toml
   [dependencies]
   tokio = { version = "1", features = ["rt", "net", "io-util", "macros", "time"] }
   tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
   hyper = { version = "1", features = ["client", "http1"] }
   hyper-util = { version = "0.1", features = ["tokio"] }
   http-body-util = "0.1"
   kvm-proto = { path = "../kvm-proto" }

   [dev-dependencies]
   rcgen = { version = "0.13", default-features = false, features = ["aws_lc_rs", "pem"] }
   tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "time"] }
   ```
   and `pub mod kvm;` to `src/lib.rs`.

2. Make the pin mismatch name what it saw. In `src/pin.rs`, replace the mismatch arm of `verify_server_cert`:
   ```rust
           if self.spki_matches(&spki) {
               Ok(ServerCertVerified::assertion())
           } else {
               Err(TlsError::General(format!(
                   "kvm_cert_mismatch: observed spki_sha256={}",
                   crate::fingerprint::spki_sha256_hex(&spki)
               )))
           }
   ```

3. Write the stubs in `tests/support/mod.rs`:
   ```rust
   #![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::as_conversions)]
   use std::sync::Arc;
   use tokio::io::{AsyncReadExt, AsyncWriteExt};
   use tokio::net::TcpListener;
   use tokio_rustls::TlsAcceptor;

   pub struct Stub { pub port: u16, pub pin_hex: String }

   /// A self-signed loopback TLS identity and the SHA-256(SPKI) hex pin of it.
   pub fn tls_acceptor_and_pin() -> (TlsAcceptor, String) {
       let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
       let cert = tokio_rustls::rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
       let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
           ck.key_pair.serialize_der()).unwrap();
       let pin_hex = kvm_probe::fingerprint::spki_sha256_hex(&ck.key_pair.public_key_der());
       let cfg = tokio_rustls::rustls::ServerConfig::builder()
           .with_no_client_auth()
           .with_single_cert(vec![cert], key).unwrap();
       (TlsAcceptor::from(Arc::new(cfg)), pin_hex)
   }

   /// Serve `response` verbatim (status line, headers, body) to every TLS
   /// connection after reading the request, then close.
   pub async fn start_http_stub(response: Vec<u8>) -> Stub {
       let (acceptor, pin_hex) = tls_acceptor_and_pin();
       let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
       let port = listener.local_addr().unwrap().port();
       let response = Arc::new(response);
       tokio::spawn(async move {
           loop {
               let (tcp, _) = match listener.accept().await { Ok(v) => v, Err(_) => break };
               let (acceptor, response) = (acceptor.clone(), response.clone());
               tokio::spawn(async move {
                   let mut tls = match acceptor.accept(tcp).await { Ok(v) => v, Err(_) => return };
                   let mut buf = [0u8; 4096];
                   let _ = tls.read(&mut buf).await; // consume the request head
                   let _ = tls.write_all(&response).await;
                   let _ = tls.shutdown().await;
               });
           }
       });
       Stub { port, pin_hex }
   }

   pub fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
       let mut r = format!(
           "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
           body.len()
       ).into_bytes();
       r.extend_from_slice(body);
       r
   }

   pub async fn start_login_stub() -> Stub {
       start_http_stub(http_response(
           "200 OK",
           "application/json",
           br#"{"result":0,"token":"0.987654","role":"admin"}"#,
       )).await
   }
   ```

4. Write the failing tests in `tests/stub_login.rs`:
   ```rust
   #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::as_conversions)]
   mod support;
   use kvm_probe::request::{KvmTarget, Scheme};

   fn target(port: u16) -> KvmTarget {
       KvmTarget { scheme: Scheme::Https, host: "127.0.0.1".into(),
           login_port: port, video_port: port, control_port: port }
   }

   #[tokio::test]
   async fn correct_pin_connects_wrong_pin_names_observed_fingerprint() {
       let stub = support::start_login_stub().await;
       let t = target(stub.port);
       assert!(kvm_probe::kvm::connect_to(&t, stub.port, Some(&stub.pin_hex)).await.is_ok());

       let wrong = "0".repeat(64);
       let err = match kvm_probe::kvm::connect_to(&t, stub.port, Some(&wrong)).await {
           Ok(_) => panic!("wrong pin must refuse the connection"),
           Err(e) => format!("{e:?}"),
       };
       assert!(err.contains("kvm_cert_mismatch"), "{err}");
       assert!(err.contains(&stub.pin_hex), "error must name the observed pin: {err}");
   }

   #[tokio::test]
   async fn login_returns_token_from_response() {
       let stub = support::start_login_stub().await;
       let token = kvm_probe::kvm::login(&target(stub.port), Some(&stub.pin_hex),
           "pw", 1_759_680_000, "UTC").await.unwrap();
       assert_eq!(token, "0.987654");
   }

   #[tokio::test]
   async fn non_200_login_is_a_clean_login_error() {
       let stub = support::start_http_stub(support::http_response(
           "302 Found", "text/html", b"<a href=\"./login.html\">moved</a>",
       )).await;
       match kvm_probe::kvm::login(&target(stub.port), Some(&stub.pin_hex),
           "pw", 1_759_680_000, "UTC").await {
           Err(kvm_probe::kvm::KvmError::Login(msg)) => assert!(msg.contains("302"), "{msg}"),
           other => panic!("expected KvmError::Login, got {other:?}"),
       }
   }

   #[tokio::test]
   async fn rejected_password_body_is_a_clean_login_error() {
       let stub = support::start_http_stub(support::http_response(
           "200 OK", "application/json", br#"{"result":403}"#,
       )).await;
       assert!(matches!(
           kvm_probe::kvm::login(&target(stub.port), Some(&stub.pin_hex), "pw", 1_759_680_000, "UTC").await,
           Err(kvm_probe::kvm::KvmError::Login(_))
       ));
   }
   ```

5. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --test stub_login
   ```
   Expected: `error[E0425]: cannot find function `connect_to` in module `kvm_probe::kvm``.

6. Minimal implementation in `src/kvm.rs`:
   ```rust
   use std::sync::Arc;
   use http_body_util::{BodyExt, Full};
   use hyper::Request;
   use hyper_util::rt::TokioIo;
   use tokio::io::{AsyncRead, AsyncWrite};
   use tokio::net::TcpStream;
   use tokio_rustls::TlsConnector;
   use tokio_rustls::rustls::pki_types::ServerName;
   use crate::pin::SpkiPinVerifier;
   use crate::request::{self, KvmTarget, Scheme};

   pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
   impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
   pub type BoxedIo = Box<dyn IoStream>;

   #[derive(Debug)]
   pub enum KvmError { Connect(String), Tls(String), Http(String), Login(String), Io(String) }

   fn client_config(pin: Option<&str>) -> tokio_rustls::rustls::ClientConfig {
       let verifier = Arc::new(SpkiPinVerifier::new(pin.map(str::to_string)));
       tokio_rustls::rustls::ClientConfig::builder()
           .dangerous()
           .with_custom_certificate_verifier(verifier)
           .with_no_client_auth()
   }

   /// Connect to `port` on the KVM: pinned TLS for `Https`, plain TCP for
   /// `Http` (§3.2). `TCP_NODELAY` on every socket.
   pub async fn connect_to(
       target: &KvmTarget,
       port: u16,
       pin_sha256_hex: Option<&str>,
   ) -> Result<BoxedIo, KvmError> {
       let tcp = TcpStream::connect((target.host.as_str(), port))
           .await
           .map_err(|e| KvmError::Connect(e.to_string()))?;
       tcp.set_nodelay(true).map_err(|e| KvmError::Connect(e.to_string()))?;
       match target.scheme {
           Scheme::Http => Ok(Box::new(tcp)),
           Scheme::Https => {
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

   pub async fn login(
       target: &KvmTarget,
       pin: Option<&str>,
       password: &str,
       now_unix: i64,
       timezone: &str,
   ) -> Result<String, KvmError> {
       let io = connect_to(target, target.login_port, pin).await?;
       let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
           .await
           .map_err(|e| KvmError::Http(e.to_string()))?;
       tokio::spawn(async move {
           let _ = conn.await;
       });

       let body = request::build_login_body(password, timezone, now_unix);
       let req = Request::builder()
           .method("POST")
           .uri("/cgi-bin/login.lua")
           .header("Host", &target.host)
           .header("Content-Type", "application/json")
           .body(Full::new(hyper::body::Bytes::from(body)))
           .map_err(|e| KvmError::Http(e.to_string()))?;
       let resp = sender.send_request(req).await.map_err(|e| KvmError::Http(e.to_string()))?;
       let status = resp.status();
       if status != hyper::StatusCode::OK {
           return Err(KvmError::Login(format!("http status {}", status.as_u16())));
       }
       let bytes = resp
           .into_body()
           .collect()
           .await
           .map_err(|e| KvmError::Http(e.to_string()))?
           .to_bytes();
       let token = kvm_proto::login::parse_login_token(&bytes)
           .map_err(|e| KvmError::Login(format!("{e:?}")))?;
       Ok(token.into_string())
   }
   ```
   (The `{e}` formatting of the TLS error carries rustls' `General` message, so the observed fingerprint from step 2 reaches the operator.)

7. Run to pass:
   ```
   cargo test -p kvm-probe --test stub_login
   cargo tree -p kvm-probe -i ring
   ```
   Expected: `test result: ok. 4 passed`; `ring` absent (`did not match any packages`).

8. Commit:
   ```
   git add crates/kvm-probe/ Cargo.lock
   git commit -m "kvm-probe: pinned-TLS or plain KVM connection and login, against loopback stubs" \
     -m "A pin mismatch names the observed SPKI fingerprint; non-200 and rejected-password logins are clean errors." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.9: `av.flv` capture to the 0700 dir with per-tag JSONL

The `capture` subcommand opens `GET /av.flv?token=…` on the **video port** with the token cookie (§3.2), streams the raw bytes into a `CaptureDir` file (Task 4), and feeds them to the kvm-proto FLV demuxer, writing one `TagRecord` JSONL line per tag (§12 Leg A) stamped with the real receive time (the census computes cadence, bursts and reconnect→first-IDR from it). **The probe never decodes H.264**: it records framing, NAL-header and slice-header-prefix fields only. A parse error stops parsing but not saving — the raw bytes still land on disk for sandboxed analysis — and is counted, never swallowed. Every capture is bounded by bytes and by duration so a forgotten run cannot fill the disk (§13).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/capture.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod capture;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/support/mod.rs` (add `start_flv_stub`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_capture.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/capture.rs` (unit), `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_capture.rs` (against the committed fixture `fixtures/360p30_main_full.flv` from the fixtures tasks)

**Interfaces:**
- Consumes: `kvm::{connect_to, KvmError, BoxedIo}` (Task 8); `request::{KvmTarget, flv_url, token_cookie_header}` (Task 2); `captures::CaptureDir` (Task 4); `record::TagRecord` (Task 3); `kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, TagBody, VideoBody, FrameType}` and `kvm_proto::h264::parse_slice_header_prefix` (kvm-proto tasks).
- Produces:
  - `pub fn capture::record_for(tag: &kvm_proto::flv::FlvTag, recv_ms: u64) -> record::TagRecord`
  - `pub struct capture::StopAt { pub max_bytes: u64, pub max_duration: std::time::Duration }` with `impl Default` = 64 MiB / 60 s
  - `pub struct capture::Stats { pub tags: u64, pub bytes: u64, pub parse_errors: u64, pub first_error: Option<String> }`
  - `pub async fn capture::run(target: &request::KvmTarget, pin: Option<&str>, token: &str, dir: &captures::CaptureDir, name: &str, jsonl: &mut impl std::io::Write, stop: capture::StopAt) -> Result<capture::Stats, kvm::KvmError>`

**Steps:**

1. Add `pub mod capture;` to `src/lib.rs`. Write the failing unit tests at the bottom of a new `src/capture.rs` (they build kvm-proto values directly, no network):
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use bytes::Bytes;
       use kvm_proto::flv::{FlvTag, FrameType, Nal, TagBody, VideoBody};

       fn tag(body: TagBody) -> FlvTag {
           FlvTag { tag_type: 9, data_size: 20, timestamp: 33, body }
       }

       #[test]
       fn idr_nalus_map_types_ref_idc_slice_type_and_first_mb() {
           // 0x65 = ref_idc 3, type 5 (IDR). 0x88 0x80 = ue(0) first_mb, ue(7) I-slice, ue(0) pps.
           let t = tag(TagBody::Video(VideoBody::Nalus {
               frame_type: FrameType::Key,
               composition_time: 0,
               nals: vec![
                   Nal { bytes: Bytes::from_static(&[0x09, 0x10]) },        // AUD
                   Nal { bytes: Bytes::from_static(&[0x65, 0x88, 0x80]) },  // IDR slice
               ],
           }));
           let r = record_for(&t, 1500);
           assert_eq!((r.recv_ms, r.tag_type, r.timestamp_ms, r.size), (1500, 9, 33, 20));
           assert_eq!((r.codec_id, r.avc_packet_type, r.frame_type), (Some(7), Some(1), Some(1)));
           assert_eq!(r.nal_types, vec![9, 5]);
           assert_eq!(r.nal_ref_idc, vec![0, 3]);
           assert_eq!(r.slice_types, vec![None, Some(7)]);
           assert_eq!(r.first_mb, vec![None, Some(0)]);
           assert_eq!(r.fourcc, None);
       }

       #[test]
       fn sequence_header_lists_its_parameter_sets() {
           let cfg = kvm_proto::flv::AvcConfig {
               length_size_minus_one: 3, profile_idc: 77, level_idc: 31,
               sps: vec![Bytes::from_static(&[0x67, 0x4D, 0x00, 0x1F])],
               pps: vec![Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])],
           };
           let r = record_for(&tag(TagBody::Video(VideoBody::SequenceHeader(cfg))), 0);
           assert_eq!((r.codec_id, r.avc_packet_type), (Some(7), Some(0)));
           assert_eq!(r.nal_types, vec![7, 8]);
       }

       #[test]
       fn enhanced_rtmp_records_fourcc_not_avc() {
           let r = record_for(&tag(TagBody::Video(VideoBody::Enhanced {
               packet_type: 1, frame_type: FrameType::Inter, fourcc: *b"hvc1",
           })), 0);
           assert_eq!(r.fourcc.as_deref(), Some("hvc1"));
           assert_eq!(r.codec_id, None);
           assert_eq!(r.frame_type, Some(2));
       }

       #[test]
       fn script_tag_has_no_video_fields() {
           let mut t = tag(TagBody::ScriptData);
           t.tag_type = 18;
           let r = record_for(&t, 0);
           assert_eq!((r.tag_type, r.codec_id, r.frame_type), (18, None, None));
           assert!(r.nal_types.is_empty());
       }
   }
   ```

2. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib capture::
   ```
   Expected: `error[E0425]: cannot find function `record_for` in this scope`.

3. Minimal implementation above the test module in `src/capture.rs`:
   ```rust
   use std::io::Write;
   use std::time::{Duration, Instant};
   use http_body_util::BodyExt;
   use hyper_util::rt::TokioIo;
   use kvm_proto::flv::{FlvDemuxer, FlvLimits, FlvTag, FrameType, TagBody, VideoBody};
   use crate::captures::CaptureDir;
   use crate::kvm::{self, KvmError};
   use crate::record::TagRecord;
   use crate::request::{self, KvmTarget};

   /// Every capture is bounded (§13: captures are 15–60 MB and wiped).
   pub struct StopAt { pub max_bytes: u64, pub max_duration: Duration }
   impl Default for StopAt {
       fn default() -> Self { Self { max_bytes: 64 * 1024 * 1024, max_duration: Duration::from_secs(60) } }
   }

   #[derive(Debug, Default)]
   pub struct Stats { pub tags: u64, pub bytes: u64, pub parse_errors: u64, pub first_error: Option<String> }

   fn frame_type_code(f: FrameType) -> u8 {
       match f { FrameType::Key => 1, FrameType::Inter => 2, FrameType::Other(x) => x }
   }

   fn push_nal(r: &mut TagRecord, nal: &[u8]) {
       let Some(&h) = nal.first() else { return };
       let ty = h & 0x1F;
       r.nal_types.push(ty);
       r.nal_ref_idc.push(h.wrapping_shr(5) & 0x03);
       let (slice_type, first_mb) = if ty == 1 || ty == 5 {
           match kvm_proto::h264::parse_slice_header_prefix(nal) {
               Ok(p) => (u8::try_from(p.slice_type).ok(), Some(p.first_mb_in_slice)),
               Err(_) => (None, None),
           }
       } else {
           (None, None)
       };
       r.slice_types.push(slice_type);
       r.first_mb.push(first_mb);
   }

   /// One census record for one FLV tag (§12 Leg A). Framing fields only.
   pub fn record_for(tag: &FlvTag, recv_ms: u64) -> TagRecord {
       let mut r = TagRecord {
           recv_ms,
           tag_type: tag.tag_type,
           timestamp_ms: tag.timestamp,
           composition_time: 0,
           frame_type: None,
           codec_id: None,
           avc_packet_type: None,
           fourcc: None,
           nal_types: Vec::new(),
           nal_ref_idc: Vec::new(),
           slice_types: Vec::new(),
           first_mb: Vec::new(),
           size: usize::try_from(tag.data_size).unwrap_or(usize::MAX),
       };
       if let TagBody::Video(v) = &tag.body {
           match v {
               VideoBody::SequenceHeader(cfg) => {
                   r.codec_id = Some(7);
                   r.avc_packet_type = Some(0);
                   for ps in cfg.sps.iter().chain(cfg.pps.iter()) {
                       push_nal(&mut r, ps);
                   }
               }
               VideoBody::Nalus { frame_type, composition_time, nals } => {
                   r.codec_id = Some(7);
                   r.avc_packet_type = Some(1);
                   r.frame_type = Some(frame_type_code(*frame_type));
                   r.composition_time = *composition_time;
                   for n in nals {
                       push_nal(&mut r, &n.bytes);
                   }
               }
               VideoBody::EndOfSequence => {
                   r.codec_id = Some(7);
                   r.avc_packet_type = Some(2);
               }
               VideoBody::NonAvc { codec_id, frame_type } => {
                   r.codec_id = Some(*codec_id);
                   r.frame_type = Some(frame_type_code(*frame_type));
               }
               VideoBody::Enhanced { packet_type, frame_type, fourcc } => {
                   r.avc_packet_type = Some(*packet_type);
                   r.frame_type = Some(frame_type_code(*frame_type));
                   r.fourcc = Some(String::from_utf8_lossy(fourcc).into_owned());
               }
           }
       }
       r
   }

   pub async fn run(
       target: &KvmTarget,
       pin: Option<&str>,
       token: &str,
       dir: &CaptureDir,
       name: &str,
       jsonl: &mut impl Write,
       stop: StopAt,
   ) -> Result<Stats, KvmError> {
       let path = dir.resolve(name).map_err(|e| KvmError::Io(format!("{e:?}")))?;
       let mut file = std::fs::File::create(&path).map_err(|e| KvmError::Io(e.to_string()))?;

       let io = kvm::connect_to(target, target.video_port, pin).await?;
       let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
           .await
           .map_err(|e| KvmError::Http(e.to_string()))?;
       tokio::spawn(async move {
           let _ = conn.await;
       });
       // The browser sends the token as the ?token= query and as the cookie (§3.2).
       let req = hyper::Request::builder()
           .method("GET")
           .uri(format!("/av.flv?token={token}")) // origin-form; Host header names the KVM
           .header("Host", &target.host)
           .header("Cookie", request::token_cookie_header(token))
           .body(http_body_util::Empty::<hyper::body::Bytes>::new())
           .map_err(|e| KvmError::Http(e.to_string()))?;
       let resp = sender.send_request(req).await.map_err(|e| KvmError::Http(e.to_string()))?;
       if resp.status() != hyper::StatusCode::OK {
           return Err(KvmError::Http(format!("av.flv http status {}", resp.status().as_u16())));
       }
       let mut body = resp.into_body();

       let started = Instant::now();
       let mut demux = FlvDemuxer::new(FlvLimits::default());
       let mut parsing = true;
       let mut stats = Stats::default();
       loop {
           let remaining = stop.max_duration.saturating_sub(started.elapsed());
           if remaining.is_zero() {
               break;
           }
           let frame = match tokio::time::timeout(remaining, body.frame()).await {
               Err(_) | Ok(None) => break, // duration cap, or the KVM closed the stream
               Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
           };
           let Some(chunk) = frame.data_ref() else { continue };
           let recv_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
           file.write_all(chunk).map_err(|e| KvmError::Io(e.to_string()))?;
           stats.bytes = stats.bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
           if parsing {
               demux.push(chunk);
               loop {
                   match demux.next_tag() {
                       Ok(Some(tag)) => {
                           let line = record_for(&tag, recv_ms)
                               .to_jsonl()
                               .map_err(|e| KvmError::Io(e.to_string()))?;
                           writeln!(jsonl, "{line}").map_err(|e| KvmError::Io(e.to_string()))?;
                           stats.tags = stats.tags.saturating_add(1);
                       }
                       Ok(None) => break,
                       Err(e) => {
                           // Keep saving raw bytes for sandboxed analysis; stop parsing.
                           stats.parse_errors = stats.parse_errors.saturating_add(1);
                           stats.first_error.get_or_insert_with(|| format!("{e:?}"));
                           parsing = false;
                           break;
                       }
                   }
               }
           }
           if stats.bytes >= stop.max_bytes {
               break;
           }
       }
       file.flush().map_err(|e| KvmError::Io(e.to_string()))?;
       Ok(stats)
   }
   ```
   (`kvm-probe` already depends on `bytes` transitively through `kvm-proto`; add `bytes = { workspace = true }` to its `[dev-dependencies]` for the unit tests' `Bytes::from_static`.)

4. Run the unit tests to pass:
   ```
   cargo test -p kvm-probe --lib capture::
   ```
   Expected: `test result: ok. 4 passed`.

5. Add `start_flv_stub` to `tests/support/mod.rs` — it serves the committed fixture with a close-delimited body, exactly as a streaming FLV endpoint does:
   ```rust
   pub fn flv_fixture() -> Vec<u8> {
       std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/360p30_main_full.flv")).unwrap()
   }

   pub async fn start_flv_stub() -> Stub {
       let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nConnection: close\r\n\r\n".to_vec();
       resp.extend_from_slice(&flv_fixture());
       start_http_stub(resp).await
   }
   ```
   Write the failing integration test `tests/stub_capture.rs`:
   ```rust
   #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::as_conversions)]
   mod support;
   use kvm_probe::capture::{run, StopAt};
   use kvm_probe::captures::CaptureDir;
   use kvm_probe::request::{KvmTarget, Scheme};

   fn target(port: u16) -> KvmTarget {
       // login/control ports deliberately wrong: capture must use video_port.
       KvmTarget { scheme: Scheme::Https, host: "127.0.0.1".into(),
           login_port: 1, video_port: port, control_port: 1 }
   }

   #[tokio::test]
   async fn whole_fixture_is_saved_and_every_tag_recorded() {
       let stub = support::start_flv_stub().await;
       let tmp = tempfile::tempdir().unwrap();
       let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
       let mut jsonl = Vec::new();
       let stats = run(&target(stub.port), Some(&stub.pin_hex), "0.987654",
           &dir, "a.flv", &mut jsonl, StopAt::default()).await.unwrap();

       let fixture = support::flv_fixture();
       assert_eq!(stats.bytes, u64::try_from(fixture.len()).unwrap());
       assert_eq!(std::fs::read(dir.resolve("a.flv").unwrap()).unwrap(), fixture);
       assert_eq!(stats.parse_errors, 0, "{:?}", stats.first_error);
       let lines: Vec<serde_json::Value> = String::from_utf8(jsonl).unwrap()
           .lines().map(|l| serde_json::from_str(l).unwrap()).collect();
       assert_eq!(u64::try_from(lines.len()).unwrap(), stats.tags);
       assert!(lines.iter().any(|l| l["avc_packet_type"] == 0 && l["nal_types"] == serde_json::json!([7, 8])));
       assert!(lines.iter().any(|l| l["nal_types"].as_array().unwrap().contains(&serde_json::json!(5))));
       assert!(lines.iter().all(|l| l["recv_ms"].is_u64()));
   }

   #[tokio::test]
   async fn byte_cap_mid_tag_stops_cleanly() {
       let stub = support::start_flv_stub().await;
       let tmp = tempfile::tempdir().unwrap();
       let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
       let mut jsonl = Vec::new();
       let stop = StopAt { max_bytes: 1000, max_duration: std::time::Duration::from_secs(10) };
       let stats = run(&target(stub.port), Some(&stub.pin_hex), "0.987654",
           &dir, "b.flv", &mut jsonl, stop).await.unwrap();
       assert!(stats.bytes >= 1000);
       assert_eq!(stats.parse_errors, 0, "a partial trailing tag is not an error");
   }

   #[tokio::test]
   async fn non_200_flv_is_an_http_error() {
       let stub = support::start_http_stub(support::http_response("403 Forbidden", "text/plain", b"no")).await;
       let tmp = tempfile::tempdir().unwrap();
       let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
       let mut jsonl = Vec::new();
       let err = run(&target(stub.port), Some(&stub.pin_hex), "0.987654",
           &dir, "c.flv", &mut jsonl, StopAt::default()).await.unwrap_err();
       assert!(format!("{err:?}").contains("403"));
   }
   ```
   Add to `[dev-dependencies]`: `tempfile = "3"` and `serde_json = "1"`.

6. Run, expect failure until `start_flv_stub` and the dev-deps exist, then pass:
   ```
   cargo test -p kvm-probe --test stub_capture
   ```
   Expected: `test result: ok. 3 passed`.

7. Commit:
   ```
   git add crates/kvm-probe/ Cargo.lock
   git commit -m "kvm-probe: bounded av.flv capture to the 0700 dir with per-tag JSONL" \
     -m "Video port, token cookie, real receive times, counted parse errors (raw bytes keep saving), byte and duration caps. No in-process decode." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.10: control-websocket open check (token cookie, no HID frames)

§3.2: the token rides as `Cookie: token=<token>` on the websocket upgrade (`kvm.js` opens `/websocket` with no in-URL token; the browser attaches the cookie). The bridge will always send that cookie. This probe confirms the control websocket opens on the configured control port with the pinned certificate and the cookie — the way the bridge will open it — and then closes **without sending a single frame** (no HID traffic reaches the Mac). Tested against a stub that records the upgrade headers and any frames received.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/wsprobe.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod wsprobe;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml` (`tokio-tungstenite`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/support/mod.rs` (add `start_ws_stub`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_ws.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_ws.rs`

**Interfaces:**
- Produces: `pub async fn wsprobe::open_control_websocket(target: &request::KvmTarget, pin: Option<&str>, token: &str) -> Result<std::time::Duration, kvm::KvmError>` — returns the upgrade latency; never sends a data frame.
- Consumes: `request::{websocket_url, token_cookie_header}` (Task 2); `pin::SpkiPinVerifier` (Task 7); `kvm::KvmError` (Task 8).

**Steps:**

1. Add the dependency (TLS through our own pinned `ClientConfig`; no bundled roots, no `ring`):
   ```toml
   tokio-tungstenite = { version = "0.24", default-features = false, features = ["connect", "__rustls-tls"] }
   ```
   and `pub mod wsprobe;` in `src/lib.rs`. Gate the one-crypto-provider rule (§4.2) right away:
   ```
   cargo tree -p kvm-probe -i ring
   ```
   Expected: `error: package ID specification `ring` did not match any packages` (i.e. `ring` is absent). If it prints a tree, change the feature selection until it does not; do not proceed with `ring` in the graph.

2. Add `start_ws_stub` to `tests/support/mod.rs`. It reuses the login stub's rcgen TLS setup, accepts one connection with `tokio_tungstenite::accept_hdr_async`, records whether the upgrade request carried `Cookie: token=0.987654`, then counts every data frame received until the client closes:
   ```rust
   pub struct WsStub { pub port: u16, pub pin_hex: String,
       pub saw_cookie: std::sync::Arc<std::sync::atomic::AtomicBool>,
       pub data_frames: std::sync::Arc<std::sync::atomic::AtomicUsize> }

   pub async fn start_ws_stub() -> WsStub {
       use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
       use futures_util::StreamExt;
       use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
       let (acceptor, pin_hex) = tls_acceptor_and_pin();
       let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
       let port = listener.local_addr().unwrap().port();
       let saw_cookie = Arc::new(AtomicBool::new(false));
       let data_frames = Arc::new(AtomicUsize::new(0));
       let (sc, df) = (saw_cookie.clone(), data_frames.clone());
       tokio::spawn(async move {
           let (tcp, _) = listener.accept().await.unwrap();
           let tls = acceptor.accept(tcp).await.unwrap();
           let cb = |req: &Request, resp: Response| {
               let ok = req.headers().get("cookie")
                   .and_then(|v| v.to_str().ok())
                   .is_some_and(|v| v.contains("token=0.987654"));
               sc.store(ok, Ordering::SeqCst);
               Ok(resp)
           };
           let mut ws = tokio_tungstenite::accept_hdr_async(tls, cb).await.unwrap();
           while let Some(Ok(msg)) = ws.next().await {
               if msg.is_binary() || msg.is_text() { df.fetch_add(1, Ordering::SeqCst); }
               if msg.is_close() { break; }
           }
       });
       WsStub { port, pin_hex, saw_cookie, data_frames }
   }
   ```
   (`tls_acceptor_and_pin()` is the helper Task 8 factored out of `start_login_stub`; add `futures-util = "0.3"` to `[dev-dependencies]`.)

   Write the failing test `tests/stub_ws.rs`:
   ```rust
   #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::as_conversions)]
   mod support;
   use std::sync::atomic::Ordering;
   use kvm_probe::request::{KvmTarget, Scheme};

   #[tokio::test]
   async fn opens_with_cookie_and_sends_no_frames() {
       let stub = support::start_ws_stub().await;
       let t = KvmTarget { scheme: Scheme::Https, host: "127.0.0.1".into(),
           login_port: 1, video_port: 1, control_port: stub.port };
       let latency = kvm_probe::wsprobe::open_control_websocket(&t, Some(&stub.pin_hex), "0.987654")
           .await.unwrap();
       assert!(latency < std::time::Duration::from_secs(5));
       tokio::time::sleep(std::time::Duration::from_millis(100)).await;
       assert!(stub.saw_cookie.load(Ordering::SeqCst), "upgrade must carry the token cookie");
       assert_eq!(stub.data_frames.load(Ordering::SeqCst), 0, "probe must never send HID frames");
   }
   ```
   (`login_port`/`video_port` are deliberately bogus: the probe must use `control_port`.)

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --test stub_ws
   ```
   Expected: `error[E0425]: cannot find function `open_control_websocket``.

4. Minimal implementation in `src/wsprobe.rs`:
   ```rust
   use std::sync::Arc;
   use std::time::{Duration, Instant};
   use futures_util::SinkExt;
   use tokio_tungstenite::Connector;
   use tokio_tungstenite::tungstenite::client::IntoClientRequest;
   use crate::kvm::KvmError;
   use crate::pin::SpkiPinVerifier;
   use crate::request::{self, KvmTarget};

   /// Open the KVM control websocket exactly as the bridge will (§3.2): pinned
   /// TLS, `Cookie: token=…`, control port. Close immediately; send nothing.
   pub async fn open_control_websocket(
       target: &KvmTarget,
       pin: Option<&str>,
       token: &str,
   ) -> Result<Duration, KvmError> {
       let mut req = request::websocket_url(target)
           .as_str()
           .into_client_request()
           .map_err(|e| KvmError::Http(e.to_string()))?;
       let cookie = request::token_cookie_header(token)
           .parse()
           .map_err(|_| KvmError::Http("bad cookie header".into()))?;
       req.headers_mut().insert("Cookie", cookie);
       let cfg = tokio_rustls::rustls::ClientConfig::builder()
           .dangerous()
           .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier::new(pin.map(str::to_string))))
           .with_no_client_auth();
       let started = Instant::now();
       let (mut ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
           req, None, true, Some(Connector::Rustls(Arc::new(cfg))),
       )
       .await
       .map_err(|e| KvmError::Tls(e.to_string()))?;
       let latency = started.elapsed();
       ws.close(None).await.map_err(|e| KvmError::Http(e.to_string()))?;
       Ok(latency)
   }
   ```
   (`disable_nagle = true` — §3.2's `TCP_NODELAY`. Add `futures-util = "0.3"` to `[dependencies]` for `SinkExt`.)

5. Run to pass, and re-check the crypto graph:
   ```
   cargo test -p kvm-probe --test stub_ws
   cargo tree -p kvm-probe -i ring
   ```
   Expected: `test result: ok. 1 passed`; `ring` still absent.

6. Commit:
   ```
   git add crates/kvm-probe/ Cargo.lock
   git commit -m "kvm-probe: control-websocket open check (token cookie, pinned TLS, no frames sent)" \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.11: first-IDR latency trials and the percentile stat

§12 Leg A needs FLV-open→first-IDR latency over 20 trials (census gate: p95 ≤ 1.5 s for the `reconnect` policy), and the same measurement with `http` and `https` (§3.2's scheme decision). This task adds the pure nearest-rank `percentile` and a `first_idr_latency` function that opens `av.flv` on the video port and returns the time until the first tag carrying an IDR NAL. Tested against the Task 9 FLV stub; the 20-trial live loop is driven by the CLI (Task 13).

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/stats.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/trial.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod stats; pub mod trial;`)
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_trial.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/stats.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-probe/tests/stub_trial.rs`

**Interfaces:**
- Consumes: `kvm::{connect_to, KvmError}` (Task 8); `request::{KvmTarget, flv_url, token_cookie_header}` (Task 2); `capture::record_for` (Task 9); `kvm_proto::flv::{FlvDemuxer, FlvLimits}`; `support::start_flv_stub` (Task 9).
- Produces: `pub fn stats::percentile(samples: &[std::time::Duration], p: u32) -> Option<std::time::Duration>`; `pub async fn trial::first_idr_latency(target: &request::KvmTarget, pin: Option<&str>, token: &str, timeout: std::time::Duration) -> Result<std::time::Duration, kvm::KvmError>`.

**Steps:**

1. Add `pub mod stats; pub mod trial;` to `src/lib.rs`. Write the failing unit tests in `src/stats.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use std::time::Duration;

       fn ms(v: &[u64]) -> Vec<Duration> { v.iter().map(|&x| Duration::from_millis(x)).collect() }

       #[test]
       fn nearest_rank_percentiles() {
           let s = ms(&[500, 100, 300, 200, 400]);
           assert_eq!(percentile(&s, 50), Some(Duration::from_millis(300)));
           assert_eq!(percentile(&s, 95), Some(Duration::from_millis(500)));
           assert_eq!(percentile(&s, 0), Some(Duration::from_millis(100)));
           assert_eq!(percentile(&s, 100), Some(Duration::from_millis(500)));
       }

       #[test]
       fn empty_or_out_of_range_is_none() {
           assert_eq!(percentile(&[], 50), None);
           assert_eq!(percentile(&ms(&[1]), 101), None);
       }
   }
   ```

2. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib stats::
   ```
   Expected: `error[E0425]: cannot find function `percentile``.

3. Minimal implementation above the tests in `src/stats.rs` (integer math, no floats, no `as`):
   ```rust
   use std::time::Duration;

   /// Nearest-rank percentile: the smallest sample with at least p% of samples ≤ it.
   pub fn percentile(samples: &[Duration], p: u32) -> Option<Duration> {
       if samples.is_empty() || p > 100 {
           return None;
       }
       let mut sorted = samples.to_vec();
       sorted.sort_unstable();
       let n = u64::try_from(sorted.len()).ok()?;
       // rank = ceil(p/100 * n), at least 1
       let rank = u64::from(p).checked_mul(n)?.div_ceil(100).max(1);
       let idx = usize::try_from(rank.checked_sub(1)?).ok()?;
       sorted.get(idx).copied()
   }
   ```

4. Run to pass:
   ```
   cargo test -p kvm-probe --lib stats::
   ```
   Expected: `test result: ok. 2 passed`.

5. Write the failing integration test `tests/stub_trial.rs`:
   ```rust
   #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::as_conversions)]
   mod support;
   use kvm_probe::request::{KvmTarget, Scheme};
   use std::time::Duration;

   #[tokio::test]
   async fn first_idr_latency_is_measured_on_the_video_port() {
       let stub = support::start_flv_stub().await;
       let t = KvmTarget { scheme: Scheme::Https, host: "127.0.0.1".into(),
           login_port: 1, video_port: stub.port, control_port: 1 };
       let d = kvm_probe::trial::first_idr_latency(&t, Some(&stub.pin_hex), "0.987654",
           Duration::from_secs(5)).await.unwrap();
       assert!(d < Duration::from_secs(5));
   }
   ```

6. Run, expect compile failure (`cannot find function `first_idr_latency``), then implement `src/trial.rs`:
   ```rust
   use std::time::{Duration, Instant};
   use http_body_util::BodyExt;
   use hyper_util::rt::TokioIo;
   use kvm_proto::flv::{FlvDemuxer, FlvLimits};
   use crate::capture::record_for;
   use crate::kvm::{self, KvmError};
   use crate::request::{self, KvmTarget};

   /// Time from opening `av.flv` to the first tag that carries an IDR NAL (type 5).
   pub async fn first_idr_latency(
       target: &KvmTarget,
       pin: Option<&str>,
       token: &str,
       timeout: Duration,
   ) -> Result<Duration, KvmError> {
       let started = Instant::now();
       let io = kvm::connect_to(target, target.video_port, pin).await?;
       let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
           .await
           .map_err(|e| KvmError::Http(e.to_string()))?;
       tokio::spawn(async move {
           let _ = conn.await;
       });
       let req = hyper::Request::builder()
           .method("GET")
           .uri(format!("/av.flv?token={token}")) // origin-form; Host header names the KVM
           .header("Host", &target.host)
           .header("Cookie", request::token_cookie_header(token))
           .body(http_body_util::Empty::<hyper::body::Bytes>::new())
           .map_err(|e| KvmError::Http(e.to_string()))?;
       let resp = sender.send_request(req).await.map_err(|e| KvmError::Http(e.to_string()))?;
       if resp.status() != hyper::StatusCode::OK {
           return Err(KvmError::Http(format!("av.flv http status {}", resp.status().as_u16())));
       }
       let mut body = resp.into_body();
       let mut demux = FlvDemuxer::new(FlvLimits::default());
       loop {
           let remaining = timeout.saturating_sub(started.elapsed());
           let frame = match tokio::time::timeout(remaining, body.frame()).await {
               Err(_) => return Err(KvmError::Http("no IDR before timeout".into())),
               Ok(None) => return Err(KvmError::Http("stream ended before an IDR".into())),
               Ok(Some(f)) => f.map_err(|e| KvmError::Http(e.to_string()))?,
           };
           let Some(chunk) = frame.data_ref() else { continue };
           demux.push(chunk);
           while let Some(tag) = demux.next_tag().map_err(|e| KvmError::Http(format!("{e:?}")))? {
               if record_for(&tag, 0).nal_types.contains(&5) {
                   return Ok(started.elapsed());
               }
           }
       }
   }
   ```

7. Run to pass:
   ```
   cargo test -p kvm-probe --test stub_trial
   ```
   Expected: `test result: ok. 1 passed`.

8. Commit:
   ```
   git add crates/kvm-probe/
   git commit -m "kvm-probe: first-IDR latency trial and nearest-rank percentile" \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.12: sample-range runner (execute the sandbox, enforce no scaler, fail closed)

Wire Task 5's argv and Task 6's guards into a runner that spawns `bwrap`, fails if ffmpeg logged an auto-inserted scaler, and reads the native Y-plane min/max (§12 Leg A sample range). The decision logic is a pure function (`sample_range_outcome`) unit-tested on synthetic stderr and bytes. The spawn goes through a single `run_argv` seam so a test can prove the failure mode that matters: **if `bwrap` cannot start, the run fails — ffmpeg is never run unsandboxed.** The real spawn is an `#[ignore]` live test.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/sandbox.rs`

**Interfaces:**
- Consumes: `build_ffmpeg_sandbox_argv`, `ffmpeg_inserted_scaler`, `y_plane_range` (Tasks 5–6); `captures::CaptureDir` (Task 4).
- Produces:
  - `pub enum sandbox::SampleOutcome { ScalerInserted, Decoded { y_min: u8, y_max: u8 }, NoPlane }`
  - `pub fn sandbox::sample_range_outcome(ffmpeg_stderr: &str, y_frame: &[u8], width: usize, height: usize) -> SampleOutcome`
  - `pub fn sandbox::resolve_ffmpeg() -> std::io::Result<std::path::PathBuf>` (the canonical `/nix/store/…/bin/ffmpeg` behind `ffmpeg` on `PATH`; must live under `/nix` because the sandbox binds only `/nix`)
  - `pub fn sandbox::run_sample_range(ffmpeg: &std::path::Path, dir: &crate::captures::CaptureDir, capture_name: &str, width: usize, height: usize) -> std::io::Result<SampleOutcome>`

**Steps:**

1. Add tests to `mod tests` in `src/sandbox.rs`:
   ```rust
   #[test]
   fn outcome_fails_closed_on_scaler_even_with_bytes() {
       let frame = [10u8, 240, 10, 240, 10, 240, 10, 240];
       assert!(matches!(
           sample_range_outcome("[swscaler @ 0x1] converting", &frame, 4, 2),
           SampleOutcome::ScalerInserted));
   }

   #[test]
   fn outcome_reports_range_when_clean() {
       let frame = [16u8, 235, 16, 235, 16, 235, 16, 235];
       assert!(matches!(
           sample_range_outcome("clean verbose log", &frame, 4, 2),
           SampleOutcome::Decoded { y_min: 16, y_max: 235 }));
       assert!(matches!(
           sample_range_outcome("clean", &[0, 1], 4, 2),
           SampleOutcome::NoPlane));
   }

   #[test]
   fn missing_sandbox_binary_fails_closed() {
       let argv = vec!["/nonexistent/bwrap".to_string(), "--".to_string(), "ffmpeg".to_string()];
       let err = run_argv(&argv).unwrap_err();
       assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
   }

   #[test]
   fn empty_argv_is_an_error_not_a_panic() {
       assert!(run_argv(&[]).is_err());
   }
   ```

2. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expected: `error[E0433]: failed to resolve: use of undeclared type `SampleOutcome``.

3. Minimal implementation appended to `src/sandbox.rs`:
   ```rust
   use std::path::{Path, PathBuf};
   use std::process::{Command, Output};
   use crate::captures::CaptureDir;

   #[derive(Debug)]
   pub enum SampleOutcome { ScalerInserted, Decoded { y_min: u8, y_max: u8 }, NoPlane }

   /// A scaler in the log fails the measurement (§12); otherwise report min/max.
   pub fn sample_range_outcome(ffmpeg_stderr: &str, y_frame: &[u8], width: usize, height: usize) -> SampleOutcome {
       if ffmpeg_inserted_scaler(ffmpeg_stderr) {
           return SampleOutcome::ScalerInserted;
       }
       match y_plane_range(y_frame, width, height) {
           Some((y_min, y_max)) => SampleOutcome::Decoded { y_min, y_max },
           None => SampleOutcome::NoPlane,
       }
   }

   /// The only process spawn in this module: argv[0] is the sandbox. A spawn
   /// failure is returned as-is; there is no unsandboxed fallback.
   fn run_argv(argv: &[String]) -> std::io::Result<Output> {
       let (head, tail) = argv
           .split_first()
           .ok_or_else(|| std::io::Error::other("empty argv"))?;
       Command::new(head).args(tail).output()
   }

   /// Resolve `ffmpeg` on PATH to its canonical store path (the sandbox binds only /nix).
   pub fn resolve_ffmpeg() -> std::io::Result<PathBuf> {
       let path = std::env::var_os("PATH").ok_or_else(|| std::io::Error::other("PATH unset"))?;
       for dir in std::env::split_paths(&path) {
           let candidate = dir.join("ffmpeg");
           if candidate.is_file() {
               let real = std::fs::canonicalize(&candidate)?;
               if real.starts_with("/nix/") {
                   return Ok(real);
               }
               return Err(std::io::Error::other(format!(
                   "ffmpeg at {} is outside /nix; run inside the devshell", real.display()
               )));
           }
       }
       Err(std::io::Error::new(std::io::ErrorKind::NotFound, "ffmpeg not on PATH"))
   }

   /// Spawn the sandbox, enforce no scaler, read the native Y-plane range. Live only.
   pub fn run_sample_range(
       ffmpeg: &Path,
       dir: &CaptureDir,
       capture_name: &str,
       width: usize,
       height: usize,
   ) -> std::io::Result<SampleOutcome> {
       let out_name = format!("{capture_name}.y");
       let cap_host_dir = dir
           .resolve(capture_name)?
           .parent()
           .map(Path::to_path_buf)
           .ok_or_else(|| std::io::Error::other("no capture dir"))?;
       let argv = build_ffmpeg_sandbox_argv(ffmpeg, &cap_host_dir, capture_name, &out_name);
       let output = run_argv(&argv)?;
       let stderr = String::from_utf8_lossy(&output.stderr);
       if !output.status.success() {
           return Err(std::io::Error::other(format!("sandboxed ffmpeg failed: {stderr}")));
       }
       let frame = std::fs::read(dir.resolve(&out_name)?)?;
       Ok(sample_range_outcome(&stderr, &frame, width, height))
   }
   ```
   And an `#[ignore]` live test documenting the exact command:
   ```rust
   #[test]
   #[ignore = "live: needs bwrap+ffmpeg from the devshell and a real capture under captures/"]
   fn live_sample_range() {
       // Run (inside `nix develop`):
       //   cargo test -p kvm-probe --lib sandbox::tests::live_sample_range -- --ignored --nocapture
       // Precondition: captures/ramp.flv recorded by `kvm-probe capture` with the ramp on screen.
       let ffmpeg = resolve_ffmpeg().unwrap();
       let dir = CaptureDir::create(Path::new("captures")).unwrap();
       let outcome = run_sample_range(&ffmpeg, &dir, "ramp.flv", 1920, 1080).unwrap();
       eprintln!("sample-range: {outcome:?}");
       assert!(!matches!(outcome, SampleOutcome::ScalerInserted));
   }
   ```

4. Run the unit tests to pass (the live one stays ignored):
   ```
   cargo test -p kvm-probe --lib sandbox::
   ```
   Expected: `test result: ok.` with `live_sample_range` listed as ignored.

5. Commit:
   ```
   git add crates/kvm-probe/
   git commit -m "kvm-probe: sample-range runner, fail-closed on scaler or missing sandbox (§12)" \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 5.13: census summary and the `kvm-probe` CLI

A pure `summarize` rolls JSONL `TagRecord`s into a `TagSummary` (IDR/P counts, codec set, size range, GOP length, and how many tags hold more than one picture start) for the census. The clap CLI exposes the measurement subcommands the Leg A run uses: `fingerprint`, `capture`, `first-idr`, `ws-open`, `sample-range`, `summarize`. The KVM password is read from a file (`--password-file`), never from argv or the environment; every output lands under `captures/` (Task 4). `docs/census.md` is **not** created here — the census tasks own it.

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/report.rs`
- Create: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/cli.rs`
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/fingerprint.rs` (add `observe`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/lib.rs` (`pub mod report; pub mod cli;`)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/main.rs` (dispatch)
- Modify: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/Cargo.toml` (`clap`, `serde_json`, tokio `rt-multi-thread`)
- Test: `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/report.rs`, `/home/chris/Repos/kvm-rdp/crates/kvm-probe/src/cli.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–12.
- Produces:
  - `pub struct report::TagSummary { pub total: usize, pub idr: usize, pub p_slices: usize, pub codecs: Vec<u8>, pub fourccs: Vec<String>, pub min_size: usize, pub max_size: usize, pub gop_len: Option<usize>, pub multi_picture_tags: usize }`; `pub fn report::summarize(records: &[record::TagRecord]) -> report::TagSummary`
  - `pub async fn fingerprint::observe(target: &request::KvmTarget, port: u16) -> Result<String, kvm::KvmError>` (TLS connect in record mode; returns the observed SPKI SHA-256 hex)
  - `pub struct cli::Cli` / `pub enum cli::Cmd` (clap)

**Steps:**

1. Add to `crates/kvm-probe/Cargo.toml`:
   ```toml
   clap = { version = "4", features = ["derive"] }
   serde_json = "1"
   tokio = { version = "1", features = ["rt-multi-thread", "rt", "net", "io-util", "macros", "time"] }
   ```
   and `pub mod report; pub mod cli;` to `src/lib.rs`.

2. Write the failing tests in `src/report.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use crate::record::TagRecord;

       fn vid(frame_type: u8, slice: Option<u8>, first_mb: Vec<Option<u32>>, size: usize) -> TagRecord {
           TagRecord { recv_ms: 0, tag_type: 9, timestamp_ms: 0, composition_time: 0,
               frame_type: Some(frame_type), codec_id: Some(7), avc_packet_type: Some(1), fourcc: None,
               nal_types: vec![], nal_ref_idc: vec![], slice_types: vec![slice], first_mb, size }
       }

       #[test]
       fn summary_counts_idrs_codecs_gop_and_multi_picture_tags() {
           // IDR, P, P, P, IDR -> 5 tags, 2 IDRs, GOP 4; one P tag holds two picture starts.
           let recs = vec![
               vid(1, Some(7), vec![Some(0)], 5000),
               vid(2, Some(5), vec![Some(0)], 900),
               vid(2, Some(5), vec![Some(0), Some(0)], 850),
               vid(2, Some(5), vec![Some(0)], 870),
               vid(1, Some(7), vec![Some(0)], 4800),
           ];
           let s = summarize(&recs);
           assert_eq!(s.total, 5);
           assert_eq!(s.idr, 2);
           assert_eq!(s.p_slices, 3);
           assert_eq!(s.codecs, vec![7]);
           assert_eq!((s.min_size, s.max_size), (850, 5000));
           assert_eq!(s.gop_len, Some(4));
           assert_eq!(s.multi_picture_tags, 1);
       }

       #[test]
       fn empty_input_summarises_to_zeroes() {
           let s = summarize(&[]);
           assert_eq!((s.total, s.min_size, s.max_size, s.gop_len), (0, 0, 0, None));
       }
   }
   ```

3. Run, expect compile failure:
   ```
   cargo test -p kvm-probe --lib report::
   ```
   Expected: `error[E0422]: cannot find struct, variant or union type `TagSummary``.

4. Minimal implementation in `src/report.rs`:
   ```rust
   use crate::record::TagRecord;

   #[derive(Debug, Default)]
   pub struct TagSummary {
       pub total: usize,
       pub idr: usize,
       pub p_slices: usize,
       pub codecs: Vec<u8>,
       pub fourccs: Vec<String>,
       pub min_size: usize,
       pub max_size: usize,
       pub gop_len: Option<usize>,
       /// Tags holding more than one `first_mb_in_slice == 0` (more than one picture): tag ≠ AU.
       pub multi_picture_tags: usize,
   }

   pub fn summarize(records: &[TagRecord]) -> TagSummary {
       let mut s = TagSummary { min_size: usize::MAX, ..TagSummary::default() };
       let mut idr_positions: Vec<usize> = Vec::new();
       for (i, r) in records.iter().enumerate() {
           s.total = s.total.saturating_add(1);
           if let Some(c) = r.codec_id {
               if !s.codecs.contains(&c) { s.codecs.push(c); }
           }
           if let Some(f) = &r.fourcc {
               if !s.fourccs.contains(f) { s.fourccs.push(f.clone()); }
           }
           s.min_size = s.min_size.min(r.size);
           s.max_size = s.max_size.max(r.size);
           match r.frame_type {
               Some(1) => { s.idr = s.idr.saturating_add(1); idr_positions.push(i); }
               Some(2) => { s.p_slices = s.p_slices.saturating_add(1); }
               _ => {}
           }
           if r.first_mb.iter().filter(|m| **m == Some(0)).count() > 1 {
               s.multi_picture_tags = s.multi_picture_tags.saturating_add(1);
           }
       }
       if s.total == 0 { s.min_size = 0; }
       s.codecs.sort_unstable();
       if let (Some(a), Some(b)) = (idr_positions.first(), idr_positions.get(1)) {
           s.gop_len = Some(b.saturating_sub(*a));
       }
       s
   }
   ```
   Run to pass: `cargo test -p kvm-probe --lib report::` → `test result: ok. 2 passed`.

5. Add `observe` to `src/fingerprint.rs` (record mode: no pin, accept, report what was seen):
   ```rust
   use std::sync::Arc;
   use tokio_rustls::TlsConnector;
   use tokio_rustls::rustls::pki_types::ServerName;
   use crate::kvm::KvmError;
   use crate::pin::{extract_spki, SpkiPinVerifier};
   use crate::request::KvmTarget;

   /// Connect once without a pin and return the KVM certificate's SPKI SHA-256 hex,
   /// for recording into config (`kvm.spki_sha256`, §3.2).
   pub async fn observe(target: &KvmTarget, port: u16) -> Result<String, KvmError> {
       let tcp = tokio::net::TcpStream::connect((target.host.as_str(), port))
           .await
           .map_err(|e| KvmError::Connect(e.to_string()))?;
       let cfg = tokio_rustls::rustls::ClientConfig::builder()
           .dangerous()
           .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier::new(None)))
           .with_no_client_auth();
       let name = ServerName::try_from(target.host.clone())
           .map_err(|_| KvmError::Tls("bad server name".into()))?;
       let tls = TlsConnector::from(Arc::new(cfg))
           .connect(name, tcp)
           .await
           .map_err(|e| KvmError::Tls(e.to_string()))?;
       let cert = tls
           .get_ref()
           .1
           .peer_certificates()
           .and_then(|c| c.first())
           .ok_or_else(|| KvmError::Tls("no peer certificate".into()))?;
       let spki = extract_spki(cert.as_ref()).map_err(|e| KvmError::Tls(format!("{e:?}")))?;
       Ok(spki_sha256_hex(&spki))
   }
   ```
   Add a test to `tests/stub_login.rs`:
   ```rust
   #[tokio::test]
   async fn observe_reports_the_stub_pin() {
       let stub = support::start_login_stub().await;
       let seen = kvm_probe::fingerprint::observe(&target(stub.port), stub.port).await.unwrap();
       assert_eq!(seen, stub.pin_hex);
   }
   ```
   Run: `cargo test -p kvm-probe --test stub_login` → `test result: ok. 5 passed`.

6. Write `src/cli.rs` with its parser tests first:
   ```rust
   use std::path::PathBuf;
   use clap::{Parser, Subcommand, ValueEnum};

   #[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
   pub enum SchemeArg { Https, Http }

   #[derive(Parser, Debug)]
   #[command(name = "kvm-probe", about = "Milestone-0 census tool for the ES3 KVM (spec §12)")]
   pub struct Cli {
       #[command(subcommand)]
       pub cmd: Cmd,
   }

   #[derive(clap::Args, Debug, Clone)]
   pub struct Conn {
       #[arg(long)]
       pub host: String,
       #[arg(long, value_enum, default_value_t = SchemeArg::Https)]
       pub scheme: SchemeArg,
       /// SPKI SHA-256 hex recorded by `fingerprint` (required for https).
       #[arg(long)]
       pub pin: Option<String>,
       /// File holding the KVM password (never pass it on the command line).
       #[arg(long)]
       pub password_file: PathBuf,
   }

   #[derive(Subcommand, Debug)]
   pub enum Cmd {
       /// Record the KVM certificate's SPKI SHA-256 (connects once without a pin).
       Fingerprint { #[arg(long)] host: String, #[arg(long, default_value_t = 443)] port: u16 },
       /// Capture av.flv to captures/<name> plus captures/<name>.jsonl.
       Capture {
           #[command(flatten)] conn: Conn,
           #[arg(long)] name: String,
           #[arg(long, default_value_t = 60)] seconds: u64,
           #[arg(long, default_value_t = 64)] max_mb: u64,
       },
       /// FLV-open → first-IDR latency over N trials; prints p50/p95.
       FirstIdr {
           #[command(flatten)] conn: Conn,
           #[arg(long, default_value_t = 20)] trials: u32,
       },
       /// Open the control websocket with the token cookie, then close (no frames sent).
       WsOpen { #[command(flatten)] conn: Conn },
       /// Decode one frame of captures/<name> in the sandbox; report native Y min/max.
       SampleRange {
           #[arg(long)] name: String,
           #[arg(long)] width: usize,
           #[arg(long)] height: usize,
       },
       /// Summarise captures/<name>.jsonl.
       Summarize { #[arg(long)] name: String },
   }

   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn parses_fingerprint_and_capture() {
           let c = Cli::try_parse_from(["kvm-probe", "fingerprint", "--host", "h"]).unwrap();
           assert!(matches!(c.cmd, Cmd::Fingerprint { port: 443, .. }));
           let c = Cli::try_parse_from(["kvm-probe", "capture", "--host", "h", "--pin", "ab",
               "--password-file", "/tmp/pw", "--name", "c.flv"]).unwrap();
           assert!(matches!(c.cmd, Cmd::Capture { seconds: 60, max_mb: 64, .. }));
       }

       #[test]
       fn password_is_never_an_argument() {
           assert!(Cli::try_parse_from(["kvm-probe", "ws-open", "--host", "h",
               "--password", "x"]).is_err());
       }

       #[test]
       fn http_scheme_is_selectable() {
           let c = Cli::try_parse_from(["kvm-probe", "first-idr", "--host", "h", "--scheme", "http",
               "--password-file", "/tmp/pw"]).unwrap();
           match c.cmd { Cmd::FirstIdr { conn, trials } => {
               assert_eq!(conn.scheme, SchemeArg::Http);
               assert_eq!(trials, 20);
           } other => panic!("{other:?}") }
       }
   }
   ```
   Run: `cargo test -p kvm-probe --lib cli::` → first a compile failure until the file is complete, then `test result: ok. 3 passed`.

7. Wire `src/main.rs`:
   ```rust
   use std::path::Path;
   use std::time::{Duration, SystemTime, UNIX_EPOCH};
   use clap::Parser;
   use kvm_probe::captures::CaptureDir;
   use kvm_probe::cli::{Cli, Cmd, Conn, SchemeArg};
   use kvm_probe::request::{KvmTarget, Scheme};
   use kvm_probe::{capture, fingerprint, kvm, report, sandbox, stats, trial, wsprobe};

   fn target(conn: &Conn) -> KvmTarget {
       match conn.scheme {
           SchemeArg::Https => KvmTarget { scheme: Scheme::Https, host: conn.host.clone(),
               login_port: 443, video_port: 8881, control_port: 8889 },
           SchemeArg::Http => KvmTarget { scheme: Scheme::Http, host: conn.host.clone(),
               login_port: 80, video_port: 8880, control_port: 8888 },
       }
   }

   async fn token(conn: &Conn) -> Result<String, String> {
       let pw = std::fs::read_to_string(&conn.password_file).map_err(|e| e.to_string())?;
       let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
       let now = i64::try_from(now.as_secs()).map_err(|e| e.to_string())?;
       kvm::login(&target(conn), conn.pin.as_deref(), pw.trim_end(), now, "UTC")
           .await
           .map_err(|e| format!("{e:?}"))
   }

   async fn run(cli: Cli) -> Result<(), String> {
       let dir = || CaptureDir::create(Path::new("captures")).map_err(|e| format!("{e:?}"));
       match cli.cmd {
           Cmd::Fingerprint { host, port } => {
               let t = KvmTarget { scheme: Scheme::Https, host, login_port: port, video_port: port, control_port: port };
               println!("{}", fingerprint::observe(&t, port).await.map_err(|e| format!("{e:?}"))?);
           }
           Cmd::Capture { conn, name, seconds, max_mb } => {
               let tok = token(&conn).await?;
               let dir = dir()?;
               let jsonl_path = dir.resolve(&format!("{name}.jsonl")).map_err(|e| format!("{e:?}"))?;
               let mut jsonl = std::io::BufWriter::new(
                   std::fs::File::create(jsonl_path).map_err(|e| e.to_string())?);
               let stop = capture::StopAt {
                   max_bytes: max_mb.saturating_mul(1024 * 1024),
                   max_duration: Duration::from_secs(seconds),
               };
               let s = capture::run(&target(&conn), conn.pin.as_deref(), &tok, &dir, &name, &mut jsonl, stop)
                   .await.map_err(|e| format!("{e:?}"))?;
               println!("tags={} bytes={} parse_errors={} first_error={:?}",
                   s.tags, s.bytes, s.parse_errors, s.first_error);
           }
           Cmd::FirstIdr { conn, trials } => {
               let tok = token(&conn).await?;
               let t = target(&conn);
               let mut samples = Vec::new();
               for _ in 0..trials {
                   let d = trial::first_idr_latency(&t, conn.pin.as_deref(), &tok, Duration::from_secs(10))
                       .await.map_err(|e| format!("{e:?}"))?;
                   println!("trial: {} ms", d.as_millis());
                   samples.push(d);
                   tokio::time::sleep(Duration::from_secs(1)).await;
               }
               println!("p50={:?} p95={:?}", stats::percentile(&samples, 50), stats::percentile(&samples, 95));
           }
           Cmd::WsOpen { conn } => {
               let tok = token(&conn).await?;
               let d = wsprobe::open_control_websocket(&target(&conn), conn.pin.as_deref(), &tok)
                   .await.map_err(|e| format!("{e:?}"))?;
               println!("websocket upgrade: {} ms", d.as_millis());
           }
           Cmd::SampleRange { name, width, height } => {
               let ffmpeg = sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?;
               let out = sandbox::run_sample_range(&ffmpeg, &dir()?, &name, width, height)
                   .map_err(|e| e.to_string())?;
               println!("{out:?}");
           }
           Cmd::Summarize { name } => {
               let path = dir()?.resolve(&format!("{name}.jsonl")).map_err(|e| format!("{e:?}"))?;
               let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
               let recs: Vec<kvm_probe::record::TagRecord> = text.lines()
                   .map(serde_json::from_str).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
               println!("{:#?}", report::summarize(&recs));
           }
       }
       Ok(())
   }

   #[tokio::main(flavor = "current_thread")]
   async fn main() {
       if let Err(e) = run(Cli::parse()).await {
           eprintln!("kvm-probe: {e}");
           std::process::exit(1);
       }
   }
   ```
   `TagRecord` needs `Deserialize` for `summarize`: change its derive in `src/record.rs` to `#[derive(Serialize, serde::Deserialize, Clone, Debug)]`.

8. Run the whole crate, clippy, and the crypto-graph gate:
   ```
   cargo test -p kvm-probe
   cargo clippy -p kvm-probe --all-targets -- -D warnings
   cargo tree -p kvm-probe -i ring
   ```
   Expected: all tests pass (ignored live tests listed as ignored); clippy clean; `ring` absent.

9. Commit:
   ```
   git add crates/kvm-probe/ Cargo.lock
   git commit -m "kvm-probe: census summary and CLI (fingerprint, capture, first-idr, ws-open, sample-range, summarize)" \
     -m "Password only from a file; outputs only under captures/." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

## Part 6 — Census

The census template, then the live Leg A run against the real KVM.

### Task 6.1: census.md template (checklist/doc — not TDD)

**Files:**
- Create: `/home/chris/Repos/kvm-rdp/docs/census.md`

**Interfaces:**
- Consumes: `kvm-probe` Leg A JSONL + raw FLV (parsed via kvm-proto's Rust flag fields, §12 sandboxing), Leg B Windows-App-direct spike logs, Leg C gateway spike logs.
- Produces: `docs/census.md` — the single committed source of every census-dependent value, read by the spec revision (Task 9.1) and by Plans B and C. **Derived parameters only — no screen content** (real captures live in gitignored, 0700 `captures/`, wiped per session).

**Steps (fill every field §12 Output enumerates; mark each pass/fail or value):**

1. Create `docs/census.md` with a header (date, ES3 firmware/`Server` header, presets covered: 1920×1080 vs auto × 30/60 fps) and these sections, each a table with the measured value and how it was obtained:
   - **Leg A — stream (kvm-probe):** codec (expect AVC/`CodecID==7`); profile_idc + level; POC type; VUI present + fields; `bitstream_restriction` present + `max_num_reorder_frames`/`max_dec_frame_buffering`; `seq_scaling_matrix_present_flag`/`pic_scaling_matrix_present_flag`; HRD (`nal/vcl_hrd_parameters_present_flag`); `num_ref_frames`; GOP length; static-screen vs typing cadence; **tag == AU?**; **FLV-reconnect→first-IDR p95 over 20 trials**; **burst length in frames on connect** (GOP-cache replay); **does a second connection trigger an IDR?**; resolution-change signalling (new sequence header vs in-band SPS).
   - **Leg A — transport:** the KVM's documented service ports (web 80/443, video 8880/8881, control 8888/8889, WebRTC 1988 — from the vendor UI) and which offer TLS; per TLS port the version/cipher/key and **whether rustls negotiates**; **`http` vs `https`** FLV-open→first-IDR (`kvm-probe first-idr`, 20 trials each), inter-tag jitter (from the capture JSONL), and control-websocket open latency (`kvm-probe ws-open`).
   - **Leg A — colour (decoded Y only):** black/white/grey ramp (codes 0–15, 236–255) Y min/max from the decoder's native pix_fmt (no scaler); limited-range vs BT.709 verdict.
   - **Leg A — crash behaviour:** moved to Plan C's L4 hardware checks (it needs HID input, which `kvm-probe` never sends); leave a one-line pointer here.
   - **Leg B — Windows App (direct) gates:** NLA completes (P/F); confirmed capability set has AVC420 (P/F); **first-frame ack p95 within 1 s** (P/F → sets `first_ack_grace`); picture returns **within N (§6.5)** after a server resize (P/F) and after a re-advertise (P/F); colour A/B (P/F); barcode stranding (P/F). Plus raw data: every advertised capability set + the confirmed one (+ FreeRDP's), ack latency, every `queue_depth` (does it suspend acks? re-send a suspend ack after its own re-advertise / after a server resize?), auto-detect negotiated + answers RTT probes (Y/N), QoE present, re-advertise occurrences, key-matrix capture + typematic initial delay and repeat interval (≥20 samples, default macOS), each ErrorInfo's dialog + auto-reconnect behaviour.
   - **Leg C — gateway gates:** Windows App connects with a gateway-token `.rdp` (P/F); NLA with pre-filled username (P/F); CLIPRDR channel opens (P/F); Leg B video gates hold through the gateway (P/F). Plus: capability bytes (initial + re-advertise), every `queue_depth`, auto-detect through the gateway (Y/N).
   - **Census gates (go/no-go):** max burst length ≤ the resulting hard cap **and** ≤ the KVM→pump channel capacity (P/F); **N ≤ 3 s for the chosen policy** (for `reconnect`: reconnect→first-IDR p95 ≤ 1.5 s) (P/F).
   - **Derived decisions (the handoff to Task 9.1):** §3.2 scheme + ports; §6.1 pinned values; §6.5 `idr_policy` + N; `first_ack_grace`; hard-cap burst term; §6.8 `sps_rewrite`; §6.9 ErrorInfo table (confirm/revise); `flv_idle_timeout`; §7.4 `key_repeat_timeout` + `modifier_idle_timeout`; `video.default_size` preset.
   - **Artifacts:** paths to the kvm-sim profile (a TOML block inside census.md: AVCC length size, fps, GOP length, burst length on connect, tag = AU, and the hex of the KVM's own SPS/PPS — parameter sets only, never frame data), the capability fixture, and the key-matrix fixture; note `captures/` is gitignored/0700/wiped.

2. Add a one-line hygiene assertion at the top: "Derived parameters only — no frame bytes, no screen content, no secrets." Confirm by inspection before commit.

3. Commit:
   ```
   cd /home/chris/Repos/kvm-rdp && git add docs/census.md
   git commit -m "docs: census.md template for Milestone 0 (every §12 field)

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```
   (Leg A/B/C fill the values as the spikes run; this task lands the skeleton so no field is forgotten.)

---

### Task 6.2: run the Leg A census (live, with Chris)

Checklist task, not TDD: it uses the finished `kvm-probe` against the real ES3 and fills the Leg A sections of `docs/census.md`. Rules for the whole session (spec §12): the Mac shows **only** the test patterns below or its lock screen; every capture stays in `captures/` (0700, gitignored); any ffmpeg run on a capture goes through `kvm-probe sample-range` or the optional sandboxed cross-check in step 3 (bubblewrap, new session); **`summarize` every capture before any ffmpeg run** — the sandbox can write the whole `captures/` directory, so a decoder exploited by one capture could otherwise tamper with another capture's JSONL; `captures/` is deleted at the end. The probe only logs in, reads the video stream, and opens/closes the control websocket — it sends no keyboard or mouse input. Every logged-in run leaves its session open when it ends unless `--logout` is given: logout is global on this KVM — one session logging out ends every other open session too, including an operator's own vendor web UI session — so only pass `--logout` when no one else could be using the KVM. With `--logout`, logout is best effort and bounded at 5 s (a failed logout prints one line and is otherwise ignored), and `first-idr` logs in once per run (every trial reopens `av.flv` on that session) and logs out once at the end rather than per trial, also when trials failed.

Deviation recorded for the spec revision: §12's "what the Mac sees when the websocket TCP connection is killed with a key held" needs HID input, which the probe deliberately never sends; it moves to Plan C's L4 hardware checks, where the bridge exists.

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/census.md` (Leg A sections and the kvm-sim profile block)

**Interfaces:**
- Consumes: `kvm-probe` subcommands (`fingerprint`, `capture`, `first-idr`, `ws-open`, `sample-range`, `summarize` — Task 5.13); the census template (Task 6.1).
- Produces: filled Leg A sections of `docs/census.md`.

**Steps:**

1. Prepare (inside `nix develop`, from the repo root):
   ```
   cargo build -p kvm-probe --release
   install -m 0600 /dev/null ~/.config/kvm-rdp-census.pw && $EDITOR ~/.config/kvm-rdp-census.pw   # KVM password, outside the repo
   KVM=<kvm-lan-ip>
   P=target/release/kvm-probe
   ```
   On the Mac, open a full-screen page that can show, one at a time: solid black, solid white, a grey ramp including codes 0–15 and 236–255, and a moving pattern (a ticking millisecond clock). Nothing else on screen during captures.

2. Record the certificate pin for each TLS port and note whether rustls negotiated:
   ```
   $P fingerprint --host $KVM --port 443
   $P fingerprint --host $KVM --port 8881
   $P fingerprint --host $KVM --port 8889
   for p in 443 8881 8889; do openssl s_client -connect $KVM:$p -brief </dev/null 2>&1 | grep -E 'Protocol version|Ciphersuite|Peer signature|Server Temp Key'; done
   ```
   Census → *Leg A — transport*: the pin (not secret), TLS version, cipher and key per port, and whether `fingerprint` succeeded (rustls negotiates). Each port's pin feeds its own flag: 443 → `--pin` (web port: login and logout), 8881 → `--video-pin` (`av.flv`), 8889 → `--control-pin` (websocket). The last two default to `--pin`, so if all three pins are equal `--pin` alone is enough; if they differ, note it for Task 9.1 (§3.2 assumes a single `kvm.spki_sha256`). Set the flags once for the steps below (an array, so it expands the same in bash and zsh):
   ```
   PINS=(--pin <443-pin> --video-pin <8881-pin> --control-pin <8889-pin>)
   ```
   Also record the video server's identity (SRS or the vendor daemon — SRS implies a GOP cache and merged writes, §15): `curl -sk -D - -o /dev/null --max-time 2 "https://$KVM:8881/av.flv" | grep -i '^server:'`.

3. Captures at each preset the bridge might ship (change the preset in the KVM web UI between rows: 1920×1080 vs auto; 30 vs 60 fps). For each preset, with the moving clock on screen, then with a static screen:
   ```
   $P capture --host $KVM "${PINS[@]}" --password-file ~/.config/kvm-rdp-census.pw --name moving-1080p30.flv --seconds 30
   $P capture --host $KVM "${PINS[@]}" --password-file ~/.config/kvm-rdp-census.pw --name static-1080p30.flv --seconds 30
   $P summarize --name moving-1080p30.flv
   $P summarize --name static-1080p30.flv
   ```
   Run `summarize` on every capture as soon as it is taken — before any `sample-range` run or the cross-check below (see the session rules). From each summary and JSONL, fill *Leg A — stream shape*:
   - codec (`codecs`/`fourccs`): any `hvc1` FourCC, or `12` in `codecs` (classic-FLV HEVC), means stop — passthrough is impossible;
   - the SPS fields, from summarize's `sps` list (kvm-proto's own parser and §6.1 checks run on the KVM's own SPS): each distinct SPS's `summary` gives `profile_idc`, `level_idc`, `pic_order_cnt_type`, `num_ref_frames`, `seq_scaling_matrix_present`, `nal_hrd_present`/`vcl_hrd_present`, the VUI's `video_full_range_flag`/`colour_primaries`/`matrix_coefficients`, and `bitstream_restriction`'s `max_num_reorder_frames`/`max_dec_frame_buffering` (`None` = absent); `limits` is the §6.1 verdict (anything but `Ok(())` is a finding); `change_vs_first` classifies every later SPS (`Resize`, `Other`, or a fatal `Incompatible`). `param_sets_skipped` and `param_sets_unreported` should be 0;
   - GOP length (`gop_len`, in pictures);
   - **tag = AU** only if `multi_picture_tags`, `continuation_tags` and `non_vcl_picture_tags` are **all 0** — a picture split across tags, or an AUD/SEI/SPS-only tag, means Plan B needs the AU assembler;
   - and cadence:
   ```
   jq -s '[.[] | select(.tag_type == 9) | .recv_ms] | [range(1; length) as $i | .[$i] - .[$i-1]] | sort | .[length/2|floor]' captures/static-1080p30.flv.jsonl   # median inter-tag ms, static
   jq -s '[.[] | select(.tag_type == 9) | .recv_ms] | [range(1; length) as $i | .[$i] - .[$i-1]] | sort | .[length/2|floor]' captures/moving-1080p30.flv.jsonl   # median inter-tag ms, moving
   ```
   Optional cross-check, and the only source of the PPS's `pic_scaling_matrix_present_flag` and of `vui_parameters_present_flag` (kvm-proto parses only the SPS until Plan B): ffmpeg's `trace_headers` in the same sandbox `sample-range` uses (new session, no network, no home, read-only /nix, niced, 4 threads; `captures/` is bound **read-only** here because `-f null` writes nothing, so this run cannot touch any JSONL), with control bytes in its output made visible:
   ```
   nice -n 19 bwrap --new-session --unshare-all --die-with-parent --clearenv --dev /dev --proc /proc --ro-bind /nix /nix \
     --ro-bind "$PWD/captures" /cap --chdir /cap -- "$(readlink -f "$(command -v ffmpeg)")" \
     -hide_banner -nostdin -threads 4 -i /cap/moving-1080p30.flv -c copy -bsf:v trace_headers -frames:v 1 -f null - 2>&1 \
     | grep -E ' (profile_idc|level_idc|pic_order_cnt_type|max_num_ref_frames|seq_scaling_matrix_present_flag|vui_parameters_present_flag|video_full_range_flag|colour_primaries|matrix_coefficients|bitstream_restriction_flag|max_num_reorder_frames|max_dec_frame_buffering|nal_hrd_parameters_present_flag|vcl_hrd_parameters_present_flag|pic_scaling_matrix_present_flag|frame_cropping_flag) ' \
     | head -n 100 | cat -v
   ```

4. IDR behaviour (*Leg A — IDR behaviour*):
   ```
   $P first-idr --host $KVM "${PINS[@]}" --password-file ~/.config/kvm-rdp-census.pw --trials 20
   $P first-idr --host $KVM --scheme http --password-file ~/.config/kvm-rdp-census.pw --trials 20
   ```
   The run logs in once; every trial reopens `av.flv` with that one token — the bridge's reconnect-on-the-same-session path — and times FLV open → first IDR; one best-effort logout at the end, also when trials failed. A failed trial (a timeout, or the KVM refusing the token) prints its reason and the run goes on; the last line is `ok=… failed=… p50=… p95=…`, with p50/p95 over the successful trials only, and the command exits non-zero only if the login fails or every trial failed. Record ok/failed and p50/p95 for both schemes (gate for `reconnect`: p95 ≤ 1.5 s — a failed trial, no IDR within 10 s, is far over that, so p95 over the successes alone cannot pass a run that had failures; record `failed=` beside it). **Burst on connect** — from a fresh capture's first second, count the video tags whose FLV timestamp runs more than 100 ms ahead of their receive time:
   ```
   jq -s '[.[] | select(.tag_type == 9)] as $t | ($t[0].timestamp_ms - $t[0].recv_ms) as $o | [$t[] | select(.recv_ms < 1000 and (.timestamp_ms - .recv_ms - $o) > 100)] | length' captures/moving-1080p30.flv.jsonl
   ```
   **Second connection triggers an IDR?** Start a 30 s capture `a.flv`; ten seconds in, start a 5 s capture `b.flv --logout` in a second terminal (so `b`'s session logs out when it ends — the default leaves it open); check whether `a.flv.jsonl` shows an IDR (`nal_types` containing 5) within 200 ms of `b`'s start that is off the regular GOP cadence. If `a.flv` stops at that moment, a logout on one session ends the other session's stream — record that in the census (it constrains the bridge's reconnect and the break-glass UI) and rerun with `b` ending after `a`. **Resolution-change signalling:** during a capture, switch the KVM preset from 1920×1080 to auto (or another size); in the JSONL, a new `avc_packet_type: 0` line means a new sequence header, an in-band `7` in a `avc_packet_type: 1` line means an in-band SPS.

5. Transport latency (*Leg A — transport*):
   ```
   $P ws-open --host $KVM "${PINS[@]}" --password-file ~/.config/kvm-rdp-census.pw
   $P ws-open --host $KVM --scheme http --password-file ~/.config/kvm-rdp-census.pw
   ```
   With step 4's two `first-idr` runs and the moving captures' inter-tag jitter, decide §3.2's scheme (`https` unless rustls failed in step 2 or TLS costs measurable latency).

6. Decoded sample range (*Leg A — colour*): for each of black, white and the grey ramp, capture 5 s, summarize it, then decode one frame in the sandbox with `--width`/`--height` set to that summary's SPS `width`/`height`:
   ```
   $P capture --host $KVM "${PINS[@]}" --password-file ~/.config/kvm-rdp-census.pw --name ramp.flv --seconds 5
   $P summarize --name ramp.flv
   $P sample-range --name ramp.flv --width 1920 --height 1080
   ```
   Every capture of the session must already be summarized before the first `sample-range`. `sample-range` takes 16..=8192 for each dimension and refuses a decoded frame that is not exactly one 8-bit 4:2:0 frame of `--width`×`--height`: a size that fits no layout means the dimensions are wrong; another known layout means the stream is outside §6.1 (the summary's `limits` already says so). Record Y min/max; `ScalerInserted` fails the measurement (rerun after checking the native pix_fmt). Limited range shows black ≈ 16 and white ≈ 235.

7. Fill the kvm-sim profile block in `docs/census.md` (derived numbers only): AVCC length size (from the sequence header), fps, GOP length (`gop_len`), burst length, tag = AU (all three counts 0, step 3), and the hex of the KVM's SPS and PPS — summarize's `sps[].hex` and `pps_hex` (parameter sets only: the probe hexes nothing else, never slice data or frames).

8. Wipe and commit:
   ```
   rm -rf captures/
   git diff --stat docs/census.md
   git add docs/census.md
   git commit -m "census: Leg A results (stream shape, transport, IDR behaviour, sample range)" \
     -m "Derived parameters only; captures wiped." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```
   Before committing, read the diff once: no screen content, no password, no token.

---

## Part 7 — Spikes: Windows App (Leg B) and the gateway (Leg C)

Throwaway code under `spikes/`, outside the workspace and CI. Leg B replays fixtures from stock IronRDP HEAD to Windows App; Leg C puts rdpgw in front of it on the LAN.

### Task 7.1: Scaffold `spikes/legb-winapp` as a throwaway, workspace-excluded crate

These are **throwaway spikes**. They live under `spikes/`, are **not** members of the (future) `kvm-rdp` cargo workspace, carry their own `Cargo.toml`, and are excluded from CI. We keep them out of any parent workspace by giving each spike crate an **empty `[workspace]` table** (Cargo then treats the crate as its own workspace root, so a root `Cargo.toml` added later by Plan C never absorbs it). None of the §13 "deny panicking clippy lints / checked access" rules apply here: the spike replays a *committed, trusted* Annex-B fixture, not hostile KVM input — the hardened parsers are `kvm-proto` (Plan A subset / Plan B), out of scope for this component.

**Build cost note:** the first build compiles the whole git-pinned IronRDP dependency subtree plus the `aws-lc-rs` C build — expect several minutes and ~2–3 GB of `target/` on the shared, loaded host. The IronRDP source is already cloned locally at `/tmp/claude-1000/-home-chris-Repos-luma-homeops/91548cbb-215a-4256-90ee-40bf394f5dff/scratchpad/src/ironrdp` at exactly `38b074e`; to skip the network clone, point the git deps at `git = "file:///tmp/claude-1000/-home-chris-Repos-luma-homeops/91548cbb-215a-4256-90ee-40bf394f5dff/scratchpad/src/ironrdp"` with the same `rev` (canonical pin is the GitHub URL below; the `file://` form is a throwaway convenience only).

**Files:**
- Create `spikes/README.md` (one paragraph: "Throwaway Milestone-0 spikes. Not a workspace member, not built in CI. Delete after `census.md` is committed.")
- Create `spikes/legb-winapp/Cargo.toml`
- Create `spikes/legb-winapp/.cargo/config.toml`
- Create `spikes/legb-winapp/src/main.rs` (skeleton only this task)
- Modify `.gitignore` (append `spikes/**/target/`, `spikes/legb-winapp/certs/`, `spikes/legc-rdpgw/state/`, `spikes/legc-rdpgw/src/`, `spikes/legc-rdpgw/bin/`, `spikes/legc-rdpgw/gomod/`)

**Interfaces:**
- Consumes (git-pinned IronRDP HEAD `38b074e`): `ironrdp_server` with `default-features = false, features = ["egfx", "helper"]`; `ironrdp_egfx` (no `openh264`); `ironrdp_dvc`; `ironrdp_svc`; `ironrdp_pdu`. Crypto: `rustls 0.23` with feature `aws_lc_rs` only (never `ring`).
- Produces: `fn main()` that installs the aws-lc provider idempotently and initialises JSON tracing; a `mod cfg` with the spike constants.

**Steps:**

1. Write `spikes/legb-winapp/Cargo.toml`:
```toml
[package]
name = "legb-winapp"
version = "0.0.0"
edition = "2024"
rust-version = "1.94"
publish = false
license = "MIT OR Apache-2.0"

# Empty workspace table: keeps this crate OUT of any parent workspace.
[workspace]

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "net", "macros", "sync", "time", "io-std", "io-util"] }
tokio-rustls = "0.26"
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12", "logging"] }
rcgen = "0.13"
x509-cert = "0.3"
bytes = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

ironrdp-server = { git = "https://github.com/Devolutions/IronRDP.git", rev = "38b074e", default-features = false, features = ["egfx", "helper"] }
ironrdp-egfx   = { git = "https://github.com/Devolutions/IronRDP.git", rev = "38b074e" }
ironrdp-dvc    = { git = "https://github.com/Devolutions/IronRDP.git", rev = "38b074e" }
ironrdp-svc    = { git = "https://github.com/Devolutions/IronRDP.git", rev = "38b074e" }
ironrdp-pdu    = { git = "https://github.com/Devolutions/IronRDP.git", rev = "38b074e" }
```
2. Write `spikes/legb-winapp/.cargo/config.toml` (§13 good-citizen build limits for the shared host):
```toml
[build]
jobs = 4
```
3. Write `spikes/legb-winapp/src/main.rs` skeleton:
```rust
//! THROWAWAY Milestone-0 Leg B spike: stock IronRDP HEAD (38b074e) vs Microsoft
//! Windows App. Replays a committed Annex-B fixture over EGFX AVC420 with
//! Hybrid/NLA. Logs every capability set, the confirmed set, every frame ack,
//! QoE, re-advertises and whether auto-detect is negotiated. NOT production code.

mod cfg {
    pub const RDP_LISTEN: &str = "0.0.0.0:3389";
    pub const NLA_USERNAME: &str = "kvm"; // must equal rdpgw's pre-filled username (Leg C)
    pub const NLA_PASSWORD: &str = "legb-spike-pw"; // throwaway; NLA needs it recoverable
    pub const FIXTURE_ENV: &str = "LEGB_FIXTURE"; // path to a committed Annex-B .h264 stream
    pub const HARD_CAP: u32 = 120; // ceil(2s * 60fps); static memory backstop (spec §6.6)
    pub const REGION_QP: u8 = 22; // spec §6.3 video.region_qp
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One crypto provider, aws-lc-rs, installed idempotently (spec §4.2).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,legb_winapp=debug")),
        )
        .init();

    tracing::info!("legb-winapp spike starting (placeholder main — wired up in later tasks)");
    Ok(())
}
```
4. Build it (honouring §13 on the shared host):
```
nice -n 19 cargo build --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```
Expected: the first run fetches and compiles the IronRDP git subtree + aws-lc-rs (minutes); it finishes with `Compiling legb-winapp v0.0.0` and no errors. This confirms the pin, the feature set (`egfx` + `helper`, no `openh264`) and the aws-lc provider all resolve.
5. Append those six lines to `.gitignore`, then commit:
```
git add spikes/legb-winapp/Cargo.toml spikes/legb-winapp/.cargo/config.toml spikes/legb-winapp/src/main.rs spikes/README.md .gitignore
git commit -m "spikes/legb: scaffold throwaway Windows App spike (IronRDP 38b074e, egfx+helper, aws-lc)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.2: Leg B — self-signed `rcgen` cert and the `with_hybrid` public-key material

CredSSP/NLA channel-binding hashes the **raw `subjectPublicKey` BIT STRING contents** of the server cert (the DER-encoded public key itself), **not** the full `SubjectPublicKeyInfo` wrapper — passing the SPKI sequence makes the server/client hashes disagree (grounded in `macrdp/src/main.rs::make_tls_acceptor`, which cites sspi's `raw_peer_public_key()`). `rcgen::generate_simple_self_signed` yields a P-256/ECDSA key; whether Windows App's NLA accepts ECDSA or demands RSA is itself a Leg B census finding (recorded in Task 6's checklist — fall back to an `openssl`-minted RSA cert if NLA fails).

**Files:**
- Create `spikes/legb-winapp/src/tls.rs`
- Modify `spikes/legb-winapp/src/main.rs` (add `mod tls;`)

**Interfaces:**
- Consumes: `rcgen::generate_simple_self_signed(Vec<String>) -> Result<rcgen::CertifiedKey>` where `CertifiedKey { cert, key_pair }`, `cert.der() -> &CertificateDer`, `key_pair.serialize_der() -> Vec<u8>`; `x509_cert::Certificate::from_der(&[u8])` → `.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes() -> &[u8]`; `rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)`; `tokio_rustls::TlsAcceptor::from(Arc<ServerConfig>)`.
- Produces: `pub struct TlsMaterial { pub acceptor: tokio_rustls::TlsAcceptor, pub spki_pub_key: Vec<u8> }` and `pub fn self_signed(san: &str) -> anyhow::Result<TlsMaterial>`.

**Steps:**

1. Write `spikes/legb-winapp/src/tls.rs`:
```rust
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

pub struct TlsMaterial {
    pub acceptor: TlsAcceptor,
    /// Raw subjectPublicKey BIT STRING contents — what `with_hybrid` wants.
    pub spki_pub_key: Vec<u8>,
}

pub fn self_signed(san: &str) -> anyhow::Result<TlsMaterial> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![san.to_owned()]).context("gen self-signed cert")?;

    let cert_der_bytes = cert.der().to_vec();
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow!("convert key DER: {e}"))?;

    // Extract the inner public-key bytes (NOT the SPKI wrapper) for CredSSP.
    let parsed = x509_cert::Certificate::from_der(&cert_der_bytes)
        .context("parse cert DER for SPKI")?;
    let spki_pub_key = parsed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    anyhow::ensure!(!spki_pub_key.is_empty(), "empty subjectPublicKey");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der_bytes)], key_der)
        .context("build rustls ServerConfig")?;

    Ok(TlsMaterial {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        spki_pub_key,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_signed_yields_nonempty_pubkey_and_acceptor() {
        let m = super::self_signed("kvm-bridge.spike").expect("tls material");
        assert!(!m.spki_pub_key.is_empty(), "pub key must be the raw BIT STRING, non-empty");
    }
}
```
2. Add `mod tls;` to `main.rs` (under the existing `mod cfg;`).
3. Run the unit test (this one is a real red→green: it fails to compile until `tls.rs` exists, then passes):
```
nice -n 19 cargo test --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4 tls:: -- --nocapture
```
Expected: `test tls::tests::self_signed_yields_nonempty_pubkey_and_acceptor ... ok`.
4. Commit:
```
git add spikes/legb-winapp/src/tls.rs spikes/legb-winapp/src/main.rs
git commit -m "spikes/legb: rcgen self-signed cert + raw-SPKI pub key for with_hybrid

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.3: Leg B — committed Annex-B fixture loader and access-unit splitter

The spike replays a *committed, trusted* fixture produced by `gen-fixtures.sh` (a sibling Plan-A component). It is read from `$LEGB_FIXTURE`. `send_avc420_frame` takes an Annex-B elementary stream for one access unit (grounded: `GraphicsPipelineServer::send_avc420_frame(surface_id, h264_data, regions, timestamp_ms)` calls `encode_avc420_bitmap_stream(regions, h264_data)` internally). We split the fixture on 4-byte start codes into NALs, group them into AUs (one AU per AUD/`type 9`, or per fixture record if no AUD), and flag an AU as an IDR when it contains a type-5 NAL. SPS/PPS (types 7/8) are retained and re-prepended on IDR AUs. This is deliberately simple start-code scanning on trusted bytes — not the hardened `kvm-proto` demux.

**Files:**
- Create `spikes/legb-winapp/src/replay.rs`
- Modify `spikes/legb-winapp/src/main.rs` (add `mod replay;`)

**Interfaces:**
- Produces: `pub struct AccessUnit { pub annex_b: bytes::Bytes, pub is_idr: bool }` and `pub fn load_fixture(path: &std::path::Path) -> anyhow::Result<Vec<AccessUnit>>`.
- Consumes: nothing from IronRDP; `bytes::Bytes`.

**Steps:**

1. Write `spikes/legb-winapp/src/replay.rs`:
```rust
use std::path::Path;

use anyhow::Context as _;
use bytes::Bytes;

pub struct AccessUnit {
    pub annex_b: Bytes,
    pub is_idr: bool,
}

/// Split a trusted Annex-B fixture (4-byte start codes) into access units.
/// An AU boundary is the start of an AUD (NAL type 9) or an SPS (type 7) that
/// follows at least one VCL NAL. IDR = the AU contains a type-5 NAL.
pub fn load_fixture(path: &Path) -> anyhow::Result<Vec<AccessUnit>> {
    let raw = std::fs::read(path).with_context(|| format!("read fixture {}", path.display()))?;
    let starts = start_code_offsets(&raw);
    anyhow::ensure!(!starts.is_empty(), "no 4-byte start codes in fixture");

    let mut units: Vec<AccessUnit> = Vec::new();
    let mut cur_start = starts[0];
    let mut cur_has_vcl = false;
    let mut cur_is_idr = false;

    let push = |units: &mut Vec<AccessUnit>, data: &[u8], idr: bool| {
        units.push(AccessUnit { annex_b: Bytes::copy_from_slice(data), is_idr: idr });
    };

    for (i, &off) in starts.iter().enumerate() {
        let nal_type = raw.get(off + 4).map(|b| b & 0x1f).unwrap_or(0);
        let boundary = (nal_type == 9 || nal_type == 7) && cur_has_vcl;
        if boundary && off > cur_start {
            push(&mut units, &raw[cur_start..off], cur_is_idr);
            cur_start = off;
            cur_has_vcl = false;
            cur_is_idr = false;
        }
        if nal_type == 1 || nal_type == 5 {
            cur_has_vcl = true;
            if nal_type == 5 {
                cur_is_idr = true;
            }
        }
        if i + 1 == starts.len() {
            push(&mut units, &raw[cur_start..], cur_is_idr);
        }
    }

    anyhow::ensure!(!units.is_empty(), "fixture produced no access units");
    Ok(units)
}

fn start_code_offsets(buf: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1 {
            v.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_idr_then_p() {
        // SPS, PPS, IDR slice, then a P slice — two AUs, first is an IDR.
        let mut f = Vec::new();
        for (ty, body) in [(7u8, &[0x42u8][..]), (8, &[0x00]), (5, &[0x11]), (1, &[0x22])] {
            f.extend_from_slice(&[0, 0, 0, 1]);
            f.push(0x60 | ty); // nal_ref_idc set + type
            f.extend_from_slice(body);
        }
        let aus = load_fixture_from_bytes(&f);
        assert_eq!(aus.len(), 2);
        assert!(aus[0].is_idr);
        assert!(!aus[1].is_idr);
    }

    // Test seam so we don't touch the filesystem in a unit test.
    fn load_fixture_from_bytes(raw: &[u8]) -> Vec<AccessUnit> {
        let path = std::env::temp_dir().join("legb_fixture_test.h264");
        std::fs::write(&path, raw).unwrap();
        let r = super::load_fixture(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        r
    }
}
```
2. Add `mod replay;` to `main.rs`.
3. Run the unit test (real red→green):
```
nice -n 19 cargo test --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4 replay:: -- --nocapture
```
Expected: `test replay::tests::splits_idr_then_p ... ok`.
4. Commit:
```
git add spikes/legb-winapp/src/replay.rs spikes/legb-winapp/src/main.rs
git commit -m "spikes/legb: Annex-B fixture loader + AU splitter (trusted committed input)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.4: Leg B — the EGFX factory and handler (caps / ack / QoE / re-advertise / auto-detect logging), with the preferred-capabilities ladder and `max_frames_in_flight` overrides

This is the observation core of Leg B: it logs **every** advertised `RawCapabilitySet` (version + hex + parsed), the confirmed/negotiated set and whether it carries AVC420, **every** `on_frame_ack` `queue_depth` (including the `0xFFFFFFFF` suspend sentinel), QoE metrics, and distinguishes the first `on_ready` from a mid-session re-advertise. It overrides `preferred_capabilities()` with the full ladder (pinned so the spike logs exactly what we offer) and `max_frames_in_flight()` to the static hard cap.

Grounded against `ironrdp-egfx/src/server.rs` (`GraphicsPipelineHandler`, default `preferred_capabilities` ladder lines 932–968, `max_frames_in_flight` line 970) and `ironrdp-server/src/gfx.rs` (`GfxServerFactory`, `GfxDvcBridge::new`, `GfxServerHandle`, `build_server_with_handle`) and the `macrdp/src/h264.rs` factory/handler pattern (`impl ServerEventSender for Gfx`, `build_server_with_handle`, `caps_indicate_avc`).

**Files:**
- Create `spikes/legb-winapp/src/gfx.rs`
- Modify `spikes/legb-winapp/src/main.rs` (add `mod gfx;`)

**Interfaces:**
- Consumes: `ironrdp_server::{GfxServerFactory, GfxDvcBridge, GfxServerHandle, ServerEventSender, ServerEvent}`; `ironrdp_egfx::server::{GraphicsPipelineServer, GraphicsPipelineHandler, QoeMetrics}`; `ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, CapabilitySet, RawCapabilitySet, CapabilitiesV8Flags, CapabilitiesV81Flags, CapabilitiesV10Flags, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags}`. Signatures relied on: `fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu)`, `fn on_ready(&mut self, negotiated: &CapabilitySet)`, `fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32)`, `fn on_qoe_metrics(&mut self, metrics: QoeMetrics)`, `RawCapabilitySet{version, data}` + `RawCapabilitySet::parsed() -> DecodeResult<Option<CapabilitySet>>`, `GraphicsPipelineServer::new(Box<dyn GraphicsPipelineHandler>)`, `GraphicsPipelineServer::supports_avc420(&self) -> bool`.
- Produces: `pub struct SpikeCtx { pub handle: GfxServerHandle, pub ready: bool, pub avc420: bool, pub ready_count: u32, pub surface_id: Option<u16> }`, `pub struct Gfx { ... }` with `Gfx::new()`, and the readiness snapshot `Gfx::snapshot(&self) -> Option<(GfxServerHandle, bool, Option<u16>)>` + `Gfx::set_surface(&self, u16)`.

**Steps:**

1. Write `spikes/legb-winapp/src/gfx.rs`:
```rust
use std::sync::{Arc, Mutex};

use ironrdp_egfx::pdu::{
    CapabilitiesAdvertisePdu, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags,
    CapabilitiesV10Flags, CapabilitiesV81Flags, CapabilitiesV8Flags, CapabilitySet,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer, QoeMetrics};
use ironrdp_server::{GfxDvcBridge, GfxServerFactory, GfxServerHandle, ServerEvent, ServerEventSender};
use tokio::sync::mpsc::UnboundedSender;

pub struct SpikeCtx {
    pub handle: GfxServerHandle,
    pub ready: bool,
    pub avc420: bool,
    pub ready_count: u32,
    pub surface_id: Option<u16>,
}

#[derive(Clone)]
pub struct Gfx {
    hard_cap: u32,
    sender: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
    ctx: Arc<Mutex<Option<SpikeCtx>>>,
}

impl Gfx {
    pub fn new(hard_cap: u32) -> Self {
        Self {
            hard_cap,
            sender: Arc::new(Mutex::new(None)),
            ctx: Arc::new(Mutex::new(None)),
        }
    }

    pub fn sender(&self) -> Option<UnboundedSender<ServerEvent>> {
        self.sender.lock().expect("sender mutex").clone()
    }

    /// (handle, avc420-ready, surface_id) once on_ready has fired with AVC420.
    pub fn snapshot(&self) -> Option<(GfxServerHandle, bool, Option<u16>)> {
        let g = self.ctx.lock().expect("ctx mutex");
        g.as_ref()
            .filter(|c| c.ready && c.avc420)
            .map(|c| (c.handle.clone(), c.avc420, c.surface_id))
    }

    pub fn set_surface(&self, id: u16) {
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.surface_id = Some(id);
        }
    }
}

impl ServerEventSender for Gfx {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.sender.lock().expect("sender mutex") = Some(sender);
    }
}

impl GfxServerFactory for Gfx {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        // We override build_server_with_handle, so this is only a safety stub.
        Box::new(SpikeHandler { ctx: Arc::new(Mutex::new(None)), hard_cap: self.hard_cap })
    }

    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let handler = Box::new(SpikeHandler { ctx: self.ctx.clone(), hard_cap: self.hard_cap });
        let server = GraphicsPipelineServer::new(handler);
        let handle: GfxServerHandle = Arc::new(Mutex::new(server));
        *self.ctx.lock().expect("ctx mutex") = Some(SpikeCtx {
            handle: handle.clone(),
            ready: false,
            avc420: false,
            ready_count: 0,
            surface_id: None,
        });
        tracing::info!("EGFX: fresh GraphicsPipelineServer for new connection");
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

struct SpikeHandler {
    ctx: Arc<Mutex<Option<SpikeCtx>>>,
    hard_cap: u32,
}

impl GraphicsPipelineHandler for SpikeHandler {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        // pdu.0: Vec<RawCapabilitySet>. Log EACH raw set verbatim + parsed.
        for (i, raw) in pdu.0.iter().enumerate() {
            let parsed = raw.parsed().ok().flatten();
            tracing::info!(
                idx = i,
                version = ?raw.version,
                data_hex = %hex(&raw.data),
                parsed = ?parsed,
                "LEGB_CAP advertise entry"
            );
        }
        let avc = pdu
            .0
            .iter()
            .filter_map(|r| r.parsed().ok().flatten())
            .any(caps_indicate_avc);
        tracing::info!(count = pdu.0.len(), advertises_avc = avc, "LEGB_CAP advertise summary");
    }

    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        let avc = caps_indicate_avc(negotiated);
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.ready = true;
            c.avc420 = avc;
            c.ready_count += 1;
            let is_readvertise = c.ready_count > 1;
            // Confirm against the server's own view too.
            let server_avc = c.handle.lock().expect("gfx handle").supports_avc420();
            tracing::info!(
                confirmed = ?negotiated,
                confirmed_has_avc = avc,
                server_supports_avc420 = server_avc,
                ready_count = c.ready_count,
                re_advertise = is_readvertise,
                "LEGB_READY on_ready (negotiated/confirmed capability set)"
            );
            if is_readvertise {
                // A re-advertise invalidates surfaces: force a fresh Setup.
                c.surface_id = None;
            }
        }
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        let suspended = queue_depth == 0xFFFF_FFFF;
        tracing::info!(
            frame_id,
            queue_depth,
            suspended,
            total_frames_decoded,
            "LEGB_ACK on_frame_ack"
        );
    }

    fn on_qoe_metrics(&mut self, metrics: QoeMetrics) {
        tracing::info!(
            frame_id = metrics.frame_id,
            time_diff_se_us = metrics.time_diff_se,
            time_diff_dr_us = metrics.time_diff_dr,
            "LEGB_QOE on_qoe_metrics"
        );
    }

    /// Full capability ladder, pinned so the spike logs exactly what it offers
    /// (byte-identical to IronRDP HEAD's default at 38b074e — pinned on purpose).
    fn preferred_capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::SMALL_CACHE },
            CapabilitySet::V10_6Err { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_6 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_5 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_4 { flags: CapabilitiesV104Flags::SMALL_CACHE },
            CapabilitySet::V10_3 { flags: CapabilitiesV103Flags::empty() },
            CapabilitySet::V10_2 { flags: CapabilitiesV10Flags::SMALL_CACHE },
            CapabilitySet::V10_1,
            CapabilitySet::V10 { flags: CapabilitiesV10Flags::SMALL_CACHE },
            CapabilitySet::V8_1 {
                flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
            },
            CapabilitySet::V8 { flags: CapabilitiesV8Flags::SMALL_CACHE },
        ]
    }

    fn max_frames_in_flight(&self) -> u32 {
        self.hard_cap
    }
}

/// Positive AVC420 signal only (mirrors macrdp's verified `caps_indicate_avc`).
fn caps_indicate_avc(c: &CapabilitySet) -> bool {
    match c {
        CapabilitySet::V8_1 { flags } => flags.contains(CapabilitiesV81Flags::AVC420_ENABLED),
        CapabilitySet::V10 { flags } | CapabilitySet::V10_2 { flags } => {
            !flags.contains(CapabilitiesV10Flags::AVC_DISABLED)
        }
        CapabilitySet::V10_3 { flags } => !flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
        CapabilitySet::V10_4 { flags }
        | CapabilitySet::V10_5 { flags }
        | CapabilitySet::V10_6 { flags }
        | CapabilitySet::V10_6Err { flags } => !flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
        CapabilitySet::V10_7 { flags } => !flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
        CapabilitySet::V8 { .. } | CapabilitySet::V10_1 => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
```
2. Add `mod gfx;` to `main.rs`.
3. Build:
```
nice -n 19 cargo build --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```
Expected: compiles clean. (If `on_qoe_metrics`'s `QoeMetrics` field names drift on a later pin, the compile error names them — fix against `ironrdp-egfx/src/server.rs`'s `QoeMetrics { frame_id, timestamp, time_diff_se, time_diff_dr }`.)
4. Commit:
```
git add spikes/legb-winapp/src/gfx.rs spikes/legb-winapp/src/main.rs
git commit -m "spikes/legb: EGFX factory+handler logging caps/ack/QoE/re-advertise; pinned ladder

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.5: Leg B — the frame-ship loop (Setup + `send_avc420_frame` + drain + `ServerEvent::Egfx`) with manual census triggers and the auto-detect probe

This wires the observed pieces into a running replay: once `on_ready` reports AVC420, a background task does the Setup (`resize_with_monitors` with one explicit PRIMARY monitor → `create_surface` → `map_surface_to_output` → `set_max_frames_in_flight(HARD_CAP)`), then ships fixture AUs at the fixture's cadence via `send_avc420_frame`, drains with `drain_output()`, wraps with `encode_dvc_messages(channel_id, msgs, ChannelFlags::SHOW_PROTOCOL)` and emits `ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages })`. It periodically issues `ServerEvent::AutoDetectRttRequest` and logs whether the RTT handle leaves `u32::MAX` (auto-detect negotiated). Stdin commands drive the census: `resize`, `strand`, `resume` (the colour A/B swap is driving the spike twice with different fixtures — simpler than hot-swapping).

Grounded against `macrdp/src/h264.rs` setup_locked (lines 2320–2360) and the ship path (2687–2770): lock the handle, `send_avc420_frame` + `drain_output` under one hold, release, then `encode_dvc_messages` + `sender.send(ServerEvent::Egfx(...))`; `server.channel_id()` gives the EGFX DVC id.

**Files:**
- Create `spikes/legb-winapp/src/ship.rs`
- Modify `spikes/legb-winapp/src/main.rs` (add `mod ship;`)

**Interfaces:**
- Consumes: `GraphicsPipelineServer::{resize_with_monitors(u16,u16,Vec<ironrdp_pdu::gcc::Monitor>), create_surface(u16,u16)->Option<u16>, map_surface_to_output(u16,u32,u32)->bool, set_max_frames_in_flight(u32), channel_id()->Option<u32>, send_avc420_frame(u16,&[u8],&[Avc420Region],u32)->Option<u32>, drain_output()->Vec<DvcMessage>}`; `ironrdp_egfx::pdu::{Avc420Region::full_frame(u16,u16,u8), PixelFormat::XRgb}`; `ironrdp_pdu::gcc::{Monitor, MonitorFlags}`; `ironrdp_dvc::encode_dvc_messages(u32, Vec<DvcMessage>, ironrdp_svc::ChannelFlags) -> EncodeResult<Vec<SvcMessage>>`; `ironrdp_svc::ChannelFlags::SHOW_PROTOCOL`; `ironrdp_server::{ServerEvent, EgfxServerMessage}`; `ServerEvent::AutoDetectRttRequest`.
- Produces: `pub async fn run_ship(gfx: crate::gfx::Gfx, aus: Vec<crate::replay::AccessUnit>, w: u16, h: u16, hard_cap: u32, rtt_handle: Arc<AtomicU32>, mut cmd_rx: tokio::sync::mpsc::Receiver<ShipCmd>)` and `pub enum ShipCmd { Resize(u16,u16), Strand, Resume }`.

**Steps:**

1. Write `spikes/legb-winapp/src/ship.rs`:
```rust
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp_dvc::encode_dvc_messages;
use ironrdp_egfx::pdu::{Avc420Region, PixelFormat};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_server::{EgfxServerMessage, ServerEvent};
use ironrdp_svc::ChannelFlags;

use crate::gfx::Gfx;
use crate::replay::AccessUnit;

pub enum ShipCmd {
    Resize(u16, u16),
    Strand,
    Resume,
}

pub async fn run_ship(
    gfx: Gfx,
    aus: Vec<AccessUnit>,
    mut w: u16,
    mut h: u16,
    hard_cap: u32,
    rtt_handle: Arc<AtomicU32>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<ShipCmd>,
) {
    // Wait for the connection to become AVC420-ready.
    let (handle, _avc, _sid) = loop {
        if let Some(s) = gfx.snapshot() {
            break s;
        }
        if let Ok(cmd) = cmd_rx.try_recv() {
            drain_cmd(cmd); // discard pre-ready commands
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let sender = match gfx.sender() {
        Some(s) => s,
        None => {
            tracing::error!("LEGB_SHIP: no server-event sender");
            return;
        }
    };

    // ---- Setup (spec §6.4): resize_with_monitors -> create_surface -> map ----
    if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
        tracing::error!(error = %e, "LEGB_SHIP: setup failed");
        return;
    }

    let epoch = Instant::now();
    let frame_dt = Duration::from_millis(1000 / 30); // fixture cadence (30 fps)
    let mut stranded = false;
    let mut rtt_tick = Instant::now();

    loop {
        for au in &aus {
            // Drain stdin-driven census commands between frames.
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    ShipCmd::Strand => {
                        stranded = true;
                        tracing::warn!("LEGB_SHIP: STRAND — stopped sending (observe last-frame hold)");
                    }
                    ShipCmd::Resume => {
                        stranded = false;
                        tracing::warn!("LEGB_SHIP: RESUME");
                    }
                    ShipCmd::Resize(nw, nh) => {
                        w = nw;
                        h = nh;
                        tracing::warn!(nw, nh, "LEGB_SHIP: server-initiated RESIZE (§6.4 Setup cause)");
                        if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                            tracing::error!(error = %e, "LEGB_SHIP: re-setup failed");
                        }
                    }
                }
            }

            // Periodic auto-detect probe + log whether the client answers.
            if rtt_tick.elapsed() >= Duration::from_millis(250) {
                let _ = sender.send(ServerEvent::AutoDetectRttRequest);
                let rtt = rtt_handle.load(Ordering::Relaxed);
                tracing::info!(
                    rtt_ms = rtt,
                    autodetect_answered = (rtt != u32::MAX),
                    "LEGB_AUTODETECT probe"
                );
                rtt_tick = Instant::now();
            }

            if !stranded {
                if let Err(e) = ship_one(&gfx, &handle, &sender, au, w, h, &epoch) {
                    tracing::error!(error = %e, "LEGB_SHIP: ship failed");
                }
            }
            tokio::time::sleep(frame_dt).await;
        }
    }
}

fn setup(
    gfx: &Gfx,
    handle: &ironrdp_server::GfxServerHandle,
    sender: &tokio::sync::mpsc::UnboundedSender<ServerEvent>,
    w: u16,
    h: u16,
    hard_cap: u32,
) -> anyhow::Result<()> {
    let (dvc, chan) = {
        let mut server = handle.lock().expect("gfx handle");
        server.set_output_dimensions(w, h);
        // Explicit single-monitor PRIMARY layout, inclusive bounds (spec §6.4).
        let monitor = Monitor {
            left: 0,
            top: 0,
            right: i32::from(w).saturating_sub(1),
            bottom: i32::from(h).saturating_sub(1),
            flags: MonitorFlags::PRIMARY,
        };
        server.resize_with_monitors(w, h, vec![monitor]);
        let sid = server
            .create_surface_with_format(w, h, PixelFormat::XRgb)
            .ok_or_else(|| anyhow::anyhow!("create_surface failed (not ready?)"))?;
        anyhow::ensure!(server.map_surface_to_output(sid, 0, 0), "map_surface_to_output failed");
        server.set_max_frames_in_flight(hard_cap);
        gfx.set_surface(sid);
        let chan = server.channel_id().ok_or_else(|| anyhow::anyhow!("no EGFX channel id"))?;
        (server.drain_output(), chan)
    };
    if !dvc.is_empty() {
        let msgs = encode_dvc_messages(chan, dvc, ChannelFlags::SHOW_PROTOCOL)?;
        sender.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages: msgs }))
            .map_err(|_| anyhow::anyhow!("event loop closed"))?;
    }
    tracing::info!(w, h, hard_cap, "LEGB_SHIP: Setup emitted (ResetGraphics+CreateSurface+Map)");
    Ok(())
}

fn ship_one(
    gfx: &Gfx,
    handle: &ironrdp_server::GfxServerHandle,
    sender: &tokio::sync::mpsc::UnboundedSender<ServerEvent>,
    au: &AccessUnit,
    w: u16,
    h: u16,
    epoch: &Instant,
) -> anyhow::Result<()> {
    let (dvc, chan, sid) = {
        let mut server = handle.lock().expect("gfx handle");
        let sid = match gfx.snapshot().and_then(|(_, _, s)| s) {
            Some(s) => s,
            None => return Ok(()), // no surface yet
        };
        let region = Avc420Region::full_frame(w, h, crate::cfg::REGION_QP);
        let ts = u32::try_from(epoch.elapsed().as_millis() % u128::from(u32::MAX)).unwrap_or(0);
        let sent = server.send_avc420_frame(sid, &au.annex_b, &[region], ts);
        match sent {
            Some(id) if au.is_idr => tracing::info!(frame_id = id, "LEGB_SHIP shipped IDR"),
            Some(id) => tracing::trace!(frame_id = id, "LEGB_SHIP shipped P"),
            None => tracing::warn!(idr = au.is_idr, "LEGB_SHIP send_avc420_frame returned None"),
        }
        let chan = server.channel_id().ok_or_else(|| anyhow::anyhow!("no EGFX channel id"))?;
        (server.drain_output(), chan, sid)
    };
    let _ = sid;
    if dvc.is_empty() {
        return Ok(());
    }
    let msgs = encode_dvc_messages(chan, dvc, ChannelFlags::SHOW_PROTOCOL)?;
    sender.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages: msgs }))
        .map_err(|_| anyhow::anyhow!("event loop closed"))?;
    Ok(())
}

fn drain_cmd(_c: ShipCmd) {}
```
2. Add `mod ship;` to `main.rs`. (The surface helper uses `create_surface_with_format`; both it and `create_surface` exist on HEAD — the `_with_format` form lets us pin `XRgb` as macrdp does.)
3. Build:
```
nice -n 19 cargo build --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```
Expected: compiles clean (no running client yet — this task only proves the ship module type-checks against HEAD's signatures).
4. Commit:
```
git add spikes/legb-winapp/src/ship.rs spikes/legb-winapp/src/main.rs
git commit -m "spikes/legb: EGFX ship loop (Setup/send_avc420/drain/Egfx) + autodetect probe + census triggers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.6: Leg B — assemble and run the server (`with_hybrid` NLA, Preempt, `enable_autodetect`, `set_credentials`, connection logging), the exact run command, and the `census.md` gate checklist

This wires `main.rs` into a running server, spawns the ship task and a stdin command reader, and documents how to run it against Windows App and what to capture. The server uses `with_hybrid` (NLA/CredSSP over TLS), `ConnectionPolicy::Preempt`, `enable_autodetect()` (so RTT probes work when the client negotiates the message channel), `set_credentials` with the static `kvm`/password, and a `ConnectionHandler` that logs `ConnectionInfo` and disconnect causes (so we can exercise each ErrorInfo dialog by disconnecting via `error_info_disconnect_handle()`).

Grounded against `ironrdp-server/src/builder.rs` (`with_hybrid(acceptor, pub_key)`, `with_gfx_factory`, `with_connection_policy`, `with_connection_handler`), `server.rs` (`RdpServer::builder()`, `set_credentials(Some(Credentials{username,password,domain}))`, `enable_autodetect()`, `autodetect_rtt_handle() -> Arc<AtomicU32>`, `run()`, `error_info_disconnect_handle() -> ErrorInfoDisconnectHandle`), and the macrdp builder chain in `main.rs` (3438–3450).

**Files:**
- Modify `spikes/legb-winapp/src/main.rs` (full wiring)
- Create `spikes/legb-winapp/src/display.rs` (minimal `RdpServerDisplay` + `RdpServerInputHandler`)
- Modify `docs/census.md`: replace the template's `## Leg B — Windows App (direct) gates` section with the checklist in step 4

**Interfaces:**
- Consumes: `ironrdp_server::{RdpServer, Credentials, ConnectionHandler, ConnectionInfo, PostConnectionAction, RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, KeyboardEvent, MouseEvent, DesktopSize, DisplayUpdate, ServerResult}`; `RdpServer::builder().with_addr(SocketAddr).with_hybrid(TlsAcceptor, Vec<u8>).with_input_handler(_).with_display_handler(_).with_gfx_factory(Some(Box<dyn GfxServerFactory>)).with_connection_policy(ConnectionPolicy::Preempt).with_connection_handler(Some(_)).build()`.
- Produces: a runnable `legb-winapp` binary; `src/display.rs` with `pub struct SpikeDisplay { w: u16, h: u16 }` and `pub struct SpikeInput;`.

**Steps:**

1. Write `spikes/legb-winapp/src/display.rs`:
```rust
use ironrdp_server::{
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServerDisplay,
    RdpServerDisplayUpdates, RdpServerInputHandler, ServerResult,
};

pub struct SpikeDisplay {
    pub w: u16,
    pub h: u16,
}

struct Pending;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Pending {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // Frames are pushed proactively via the gfx handle; never via updates().
        let () = core::future::pending().await;
        unreachable!()
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for SpikeDisplay {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: self.w, height: self.h }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Pending))
    }
}

/// Logs every input event — this IS the Leg B key-matrix capture.
pub struct SpikeInput;

impl RdpServerInputHandler for SpikeInput {
    fn keyboard(&mut self, e: KeyboardEvent) {
        tracing::info!(event = ?e, "LEGB_INPUT keyboard");
    }
    fn mouse(&mut self, e: MouseEvent) {
        tracing::debug!(event = ?e, "LEGB_INPUT mouse");
    }
}
```
Add `async-trait = "0.1"` to `spikes/legb-winapp/Cargo.toml` `[dependencies]` (the display trait is `#[async_trait]`).
2. Replace `main.rs`'s body with the full wiring:
```rust
mod cfg;
mod display;
mod gfx;
mod replay;
mod ship;
mod tls;

use std::net::SocketAddr;
use std::time::Duration;

use ironrdp_server::{
    ConnectionHandler, ConnectionInfo, Credentials, PostConnectionAction, RdpServer, ServerError,
};

struct LogHandler;
impl ConnectionHandler for LogHandler {
    fn on_accept(&mut self, peer: std::net::SocketAddr) -> bool {
        tracing::info!(%peer, "LEGB_CONN on_accept");
        true
    }
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        tracing::info!(
            keyboard_layout = info.keyboard_layout,
            keyboard_type = ?info.keyboard_type,
            "LEGB_CONN on_connection_info"
        );
    }
    fn on_disconnected(
        &mut self,
        peer: std::net::SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        tracing::warn!(%peer, ?duration, error = ?error.map(|e| e.to_string()), "LEGB_CONN on_disconnected");
        PostConnectionAction::Continue
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,legb_winapp=debug")),
        )
        .init();

    let fixture = std::env::var(cfg::FIXTURE_ENV)
        .map_err(|_| anyhow::anyhow!("set {} to a committed Annex-B fixture", cfg::FIXTURE_ENV))?;
    let aus = replay::load_fixture(std::path::Path::new(&fixture))?;
    tracing::info!(fixture = %fixture, aus = aus.len(), "LEGB loaded fixture");

    // Dimensions: 1920x1080 default; override with LEGB_W/LEGB_H for a resize fixture.
    let w: u16 = std::env::var("LEGB_W").ok().and_then(|s| s.parse().ok()).unwrap_or(1920);
    let h: u16 = std::env::var("LEGB_H").ok().and_then(|s| s.parse().ok()).unwrap_or(1080);

    let tls = tls::self_signed("kvm-bridge.spike")?;
    let gfx = gfx::Gfx::new(cfg::HARD_CAP);

    let addr: SocketAddr = cfg::RDP_LISTEN.parse()?;
    let mut server = RdpServer::builder()
        .with_addr(addr)
        .with_hybrid(tls.acceptor, tls.spki_pub_key)
        .with_input_handler(display::SpikeInput)
        .with_display_handler(display::SpikeDisplay { w, h })
        .with_gfx_factory(Some(Box::new(gfx.clone())))
        .with_connection_policy(ironrdp_server::ConnectionPolicy::Preempt)
        .with_connection_handler(Some(Box::new(LogHandler)))
        .build();

    server.set_credentials(Some(Credentials {
        username: cfg::NLA_USERNAME.to_owned(),
        password: cfg::NLA_PASSWORD.to_owned(),
        domain: None,
    }));
    server.enable_autodetect(); // RTT probes available if the client negotiates the channel

    let rtt_handle = server.autodetect_rtt_handle();

    // stdin command reader -> ship task.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ship::ShipCmd>(8);
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let cmd = match line.trim() {
                "resize" => Some(ship::ShipCmd::Resize(1280, 720)),
                "strand" => Some(ship::ShipCmd::Strand),
                "resume" => Some(ship::ShipCmd::Resume),
                other => {
                    tracing::warn!(%other, "unknown command (resize|strand|resume)");
                    None
                }
            };
            if let Some(c) = cmd {
                let _ = cmd_tx.send(c).await;
            }
        }
    });

    tokio::spawn(ship::run_ship(gfx, aus, w, h, cfg::HARD_CAP, rtt_handle, cmd_rx));

    tracing::info!(%addr, "LEGB listening (Hybrid/NLA, Preempt, autodetect on)");
    server.run().await?;
    Ok(())
}
```
3. Run it against a committed fixture (point `LEGB_FIXTURE` at the gen-fixtures output; the full-range BT.709 main-profile stream for the baseline run):
```
LEGB_FIXTURE=$PWD/fixtures/large/1080p30_main_full.h264 \
RUST_LOG=info,legb_winapp=debug \
nice -n 19 cargo run --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```
Then from the laptop (macOS), open Microsoft Windows App → add a PC → host `kvm-bridge.spike` (or the dev host's LAN IP):3389, username `kvm`, password `legb-spike-pw`, **trust the certificate** when prompted. Expected log sequence: `LEGB_CONN on_accept` → NLA completes → `LEGB_CAP advertise entry` (one per set) → `LEGB_READY ... confirmed_has_avc=true` → `LEGB_SHIP: Setup emitted` → `LEGB_SHIP shipped IDR` → `LEGB_ACK` lines with `queue_depth`. Type/click in the window to fill the key-matrix log; type `strand` / `resume` at the spike's stdin to drive the stranding gate. The resize gate runs after Task 6b (it needs the real resize path and a second-size fixture).
4. Fill the Leg B section of `docs/census.md`: replace the template's `## Leg B — Windows App (direct) gates` section with this checklist (it is the pass/fail record Plan A's spec revision reads):
```markdown
## Leg B — Windows App (direct), stock IronRDP HEAD 38b074e

Run: `legb-winapp` with a committed fixture; Windows App on macOS, default settings.

Capture (one row per observation; raw log line id in brackets):
- [ ] NLA completes with the rcgen **ECDSA** cert. If NLA fails, mint an RSA
      cert (`openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out
      cert.pem -subj /CN=kvm-bridge.spike -days 2`, load via
      `ironrdp_server::TlsIdentityCtx::init_from_paths` for the pub key) and
      retry. RECORD which key type Windows App requires. [LEGB_CONN/handshake]
- [ ] Confirmed capability set contains AVC420 (`confirmed_has_avc=true`,
      `server_supports_avc420=true`). RECORD the exact confirmed version. [LEGB_READY]
- [ ] Full advertised ladder (every `LEGB_CAP advertise entry`: version + hex +
      parsed). Commit as the capability fixture for the L1 golden (§11.2). Repeat
      for FreeRDP (L3) and record the diff.
- [ ] First-frame ack p95 over ≥20 reconnects (time first `LEGB_SHIP shipped IDR`
      → its matching `LEGB_ACK`). This sets `video.first_ack_grace`. GATE ≤ 1 s.
- [ ] Picture returns within N (§6.5, ≤ 3 s) after a server-initiated resize
      (Task 6b; stdin `resize` with `LEGB_FIXTURE_RESIZE=$PWD/fixtures/large/720p30_main_full.h264`): picture-return time = first ack after "new-size stream starts at IDR" − "RESIZE emitted". Also record `resize-channel` (channel-only swap): does it blink?
- [ ] Picture returns within N after a client re-advertise (`re_advertise=true`
      in LEGB_READY): same measurement.
- [ ] Does Windows App SUSPEND acks? (`LEGB_ACK suspended=true`,
      queue_depth=0xFFFFFFFF). Does it re-send a suspend ack AFTER its own
      re-advertise and AFTER a server resize? (Decides §4.2 patch-1 fallback.)
- [ ] Auto-detect: does `LEGB_AUTODETECT autodetect_answered` ever become true?
      (Decides the standing-delay gate, §6.6.)
- [ ] QoE: does `LEGB_QOE` ever fire? Record `time_diff_dr_us`.
- [ ] Key matrix: every physical key/chord → the `LEGB_INPUT keyboard` scancode
      + extended flag + Cmd-rewrite behaviour. ≥ 20 typematic samples: initial
      delay + repeat interval (sets §7.4 `key_repeat_timeout`; feeds §7.1 Mac
      remap decision). Commit as the remap-table fixture.
- [ ] Each ErrorInfo dialog + auto-reconnect behaviour: trigger 0x1, 0x5, 0x7,
      0x9 via `error_info_disconnect_handle().disconnect(...)`. Revise §6.9 if
      0x19 SERVER_SHUTDOWN suits `shutdown` better.
- [ ] Colour A/B: run twice — `LEGB_FIXTURE=$PWD/fixtures/large/1080p30_main_limited.h264`, then `…/1080p30_main_limited_flagfull.h264` (identical slices, only the VUI range flag differs);
      eyeball black level in Windows App; record whether the two differ (does it honour the VUI?).
- [ ] Barcode stranding (stdin `strand`): does the last frame appear without
      further input? Sets §6.8's idle-encoder decision + `flv_idle_timeout`.
```
5. Commit:
```
git add spikes/legb-winapp/src/main.rs spikes/legb-winapp/src/display.rs spikes/legb-winapp/Cargo.toml docs/census.md
git commit -m "spikes/legb: run (Hybrid/Preempt/autodetect) + Leg B census gate checklist

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7.6b: Leg B — the real resize path (`DisplayUpdate::Resize` → reactivation → Setup) with a second-size fixture

The Leg B resize gate must exercise the mechanism the bridge will use (spec §6.4): emit `DisplayUpdate::Resize` on the current display-updates stream, wait for IronRDP's next `updates()` call (reactivation complete), then Setup at the new size and send a stream **of that size** starting at its IDR. Task 5's `resize` re-ran Setup on the EGFX channel only (a channel-level swap, which the research saw blink on Windows App) and kept sending the old-size stream. This task makes `resize` the real path and keeps the channel-only swap as `resize-channel`, so the census records both. API grounded at IronRDP `38b074e`: `ironrdp_server::DisplayUpdate::Resize(DesktopSize)` (`display.rs:21-22`); `RdpServerDisplayUpdates::next_update` must be cancellation-safe (`display.rs:275-281`) — `tokio::sync::mpsc::UnboundedReceiver::recv` is.

**Files:**
- Modify: `spikes/legb-winapp/src/display.rs` (shared size + a resize channel + an `updates()` call counter)
- Modify: `spikes/legb-winapp/src/ship.rs` (index-based replay that can switch fixtures; `Resize` = real path, `ResizeChannel` = old path)
- Modify: `spikes/legb-winapp/src/main.rs` (wire `DisplayCtl`; load `LEGB_FIXTURE_RESIZE`; stdin `resize` / `resize-channel`)

**Interfaces:**
- Consumes: Tasks 3–6 (`replay::{AccessUnit, load_fixture}`, `gfx::Gfx`, `ship::setup`, `ship::ship_one`).
- Produces: `pub struct display::DisplayCtl` (Clone) with `pub fn new(w: u16, h: u16) -> Self`, `pub fn set_size(&self, w: u16, h: u16)`, `pub fn send_resize(&self, w: u16, h: u16) -> bool`, `pub fn updates_calls(&self) -> u64`; `ShipCmd::{Resize, ResizeChannel(u16, u16), Strand, Resume}`; env `LEGB_FIXTURE_RESIZE`, `LEGB_RESIZE_W`, `LEGB_RESIZE_H`.

**Steps:**

1. Replace the display part of `spikes/legb-winapp/src/display.rs` (keep `SpikeInput` as it is):
   ```rust
   use std::sync::atomic::{AtomicU64, Ordering};
   use std::sync::{Arc, Mutex};
   use ironrdp_server::{DesktopSize, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult};
   use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

   /// Shared between the display handler and the ship loop.
   #[derive(Clone)]
   pub struct DisplayCtl {
       size: Arc<Mutex<(u16, u16)>>,
       tx: Arc<Mutex<Option<UnboundedSender<DisplayUpdate>>>>,
       updates_calls: Arc<AtomicU64>,
   }

   impl DisplayCtl {
       pub fn new(w: u16, h: u16) -> Self {
           Self { size: Arc::new(Mutex::new((w, h))), tx: Arc::new(Mutex::new(None)),
                  updates_calls: Arc::new(AtomicU64::new(0)) }
       }
       pub fn set_size(&self, w: u16, h: u16) {
           *self.size.lock().expect("size") = (w, h);
       }
       /// Emit DisplayUpdate::Resize on the current updates stream. False if none yet.
       pub fn send_resize(&self, w: u16, h: u16) -> bool {
           self.tx.lock().expect("tx").as_ref()
               .is_some_and(|tx| tx.send(DisplayUpdate::Resize(DesktopSize { width: w, height: h })).is_ok())
       }
       /// IronRDP calls updates() once per (re)activation; a bump = reactivation complete.
       pub fn updates_calls(&self) -> u64 {
           self.updates_calls.load(Ordering::SeqCst)
       }
   }

   pub struct SpikeDisplay { pub ctl: DisplayCtl }

   struct ChanUpdates(UnboundedReceiver<DisplayUpdate>);

   #[async_trait::async_trait]
   impl RdpServerDisplayUpdates for ChanUpdates {
       async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
           // recv() is cancellation-safe, as the trait requires.
           Ok(self.0.recv().await)
       }
   }

   #[async_trait::async_trait]
   impl RdpServerDisplay for SpikeDisplay {
       async fn size(&mut self) -> DesktopSize {
           let (width, height) = *self.ctl.size.lock().expect("size");
           DesktopSize { width, height }
       }
       async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
           let (tx, rx) = unbounded_channel();
           *self.ctl.tx.lock().expect("tx") = Some(tx);
           let n = self.ctl.updates_calls.fetch_add(1, Ordering::SeqCst) + 1;
           tracing::info!(updates_calls = n, "LEGB_DISPLAY updates() (activation/reactivation)");
           Ok(Box::new(ChanUpdates(rx)))
       }
   }
   ```

2. In `spikes/legb-winapp/src/ship.rs`, extend the command enum and the `run_ship` signature, and replace the replay loop with an index-based one that can switch fixtures:
   ```rust
   pub enum ShipCmd { Resize, ResizeChannel(u16, u16), Strand, Resume }

   pub async fn run_ship(
       gfx: crate::gfx::Gfx,
       aus: Vec<crate::replay::AccessUnit>,
       mut w: u16,
       mut h: u16,
       hard_cap: u32,
       rtt_handle: Arc<AtomicU32>,
       mut cmd_rx: tokio::sync::mpsc::Receiver<ShipCmd>,
       ctl: crate::display::DisplayCtl,
       resize_to: Option<(Vec<crate::replay::AccessUnit>, u16, u16)>,
   ) {
   ```
   Keep everything up to and including the first `setup(...)` call unchanged. Replace the `loop { for au in &aus { … } }` block with:
   ```rust
       let epoch = Instant::now();
       let frame_dt = Duration::from_millis(1000 / 30); // fixture cadence (30 fps)
       let mut stranded = false;
       let mut rtt_tick = Instant::now();
       let mut current = aus;
       let mut resize_to = resize_to;
       let mut i: usize = 0;

       loop {
           while let Ok(cmd) = cmd_rx.try_recv() {
               match cmd {
                   ShipCmd::Strand => { stranded = true; tracing::warn!("LEGB_SHIP: STRAND"); }
                   ShipCmd::Resume => { stranded = false; tracing::warn!("LEGB_SHIP: RESUME"); }
                   ShipCmd::ResizeChannel(nw, nh) => {
                       // Old path, kept for comparison: channel-level re-Setup, same stream.
                       w = nw; h = nh;
                       tracing::warn!(nw, nh, "LEGB_SHIP: RESIZE-CHANNEL (channel-only Setup, same stream)");
                       if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                           tracing::error!(error = %e, "LEGB_SHIP: re-setup failed");
                       }
                   }
                   ShipCmd::Resize => {
                       let Some((next, nw, nh)) = resize_to.take() else {
                           tracing::error!("LEGB_SHIP: RESIZE needs LEGB_FIXTURE_RESIZE");
                           continue;
                       };
                       let t0 = Instant::now();
                       let before = ctl.updates_calls();
                       ctl.set_size(nw, nh);
                       if !ctl.send_resize(nw, nh) {
                           tracing::error!("LEGB_SHIP: no updates stream to send Resize on");
                           continue;
                       }
                       tracing::warn!(nw, nh, "LEGB_SHIP: RESIZE emitted (DisplayUpdate::Resize); awaiting reactivation");
                       let deadline = Instant::now() + Duration::from_secs(10);
                       while ctl.updates_calls() == before && Instant::now() < deadline {
                           tokio::time::sleep(Duration::from_millis(20)).await;
                       }
                       tracing::warn!(reactivated = ctl.updates_calls() != before,
                           ms = t0.elapsed().as_millis(), "LEGB_SHIP: reactivation");
                       w = nw; h = nh;
                       if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                           tracing::error!(error = %e, "LEGB_SHIP: post-resize setup failed");
                       }
                       current = next;
                       i = current.iter().position(|au| au.is_idr).unwrap_or(0);
                       tracing::warn!(ms = t0.elapsed().as_millis(), "LEGB_SHIP: new-size stream starts at IDR");
                   }
               }
           }

           if rtt_tick.elapsed() >= Duration::from_millis(250) {
               let _ = sender.send(ServerEvent::AutoDetectRttRequest);
               let rtt = rtt_handle.load(Ordering::Relaxed);
               tracing::info!(rtt_ms = rtt, autodetect_answered = (rtt != u32::MAX), "LEGB_AUTODETECT probe");
               rtt_tick = Instant::now();
           }

           if !stranded {
               if let Some(au) = current.get(i % current.len().max(1)) {
                   if let Err(e) = ship_one(&gfx, &handle, &sender, au, w, h, &epoch) {
                       tracing::error!(error = %e, "LEGB_SHIP: ship failed");
                   }
               }
               i = i.wrapping_add(1);
           }
           tokio::time::sleep(frame_dt).await;
       }
   }
   ```
   (The first `LEGB_ACK` after "new-size stream starts at IDR" closes the measurement: picture-return time = that ack's timestamp − the `RESIZE emitted` timestamp.)

3. In `spikes/legb-winapp/src/main.rs`: create `let ctl = display::DisplayCtl::new(w, h);`, pass `display::SpikeDisplay { ctl: ctl.clone() }` to `.with_display_handler(..)`, load the optional second fixture, and pass both to `run_ship`:
   ```rust
   let resize_to = match std::env::var("LEGB_FIXTURE_RESIZE") {
       Ok(p) => {
           let rw: u16 = std::env::var("LEGB_RESIZE_W").ok().and_then(|v| v.parse().ok()).unwrap_or(1280);
           let rh: u16 = std::env::var("LEGB_RESIZE_H").ok().and_then(|v| v.parse().ok()).unwrap_or(720);
           Some((replay::load_fixture(std::path::Path::new(&p))?, rw, rh))
       }
       Err(_) => None,
   };
   tokio::spawn(ship::run_ship(gfx, aus, w, h, cfg::HARD_CAP, rtt_handle, cmd_rx, ctl.clone(), resize_to));
   ```
   and map stdin lines: `"resize" => Some(ship::ShipCmd::Resize)`, `"resize-channel" => Some(ship::ShipCmd::ResizeChannel(1280, 720))`.

4. Build:
   ```
   nice -n 19 cargo build --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
   ```
   Expected: compiles with no errors.

5. Commit:
   ```
   git add spikes/legb-winapp/src/display.rs spikes/legb-winapp/src/ship.rs spikes/legb-winapp/src/main.rs
   git commit -m "spikes/legb: real resize path (DisplayUpdate::Resize → reactivation → Setup) with a second-size fixture" \
     -m "resize-channel keeps the channel-only swap for comparison." \
     -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 7.7: Leg C — rdpgw on the LAN in header mode behind a header-injecting stub, the generated `.rdp`, Windows App steps, and the Leg C gate checklist

Leg C runs **rdpgw on the LAN only** (never internet-facing; the Dex part belongs to the companion spec). We use **header auth** behind a throwaway loopback header-injecting proxy (standing in for the oauth2-proxy admin tier). The proxy fronts `/connect` on the LAN, injects `X-Forwarded-User`, and forwards to rdpgw bound to `127.0.0.1`; rdpgw's `Header.TrustedProxies` lists `127.0.0.1/32`, so only the local proxy can mint the user header (grounded: `docs/header-authentication.md`, `main.go:259` refuses an empty `Header.TrustedProxies`). rdpgw tunnels to the Leg B server via `Server.Hosts` (operator-curated → unaffected by the Unreleased `hostselection: any` private-address block in the CHANGELOG; `roundrobin` over a single host always picks it — `rdpgw_web.go:getHost`). The generated `.rdp` carries `full address`, `gatewayhostname`, a PAA `gatewayaccesstoken`, `username:s:kvm`, and `redirectclipboard:i:1` (default `true` in `rdpgw_rdp.go` `RdpSettings`). No TDD — these are write/run/record steps.

**Files:**
- Create `spikes/legc-rdpgw/rdpgw.yaml`
- Create `spikes/legc-rdpgw/header-proxy.py`
- Create `spikes/legc-rdpgw/run.sh`
- Modify `docs/census.md`: replace the template's `## Leg C — gateway (rdpgw) gates` section with the checklist in step 6

**Interfaces:**
- Consumes: rdpgw `16cdaaf` config keys `Server.{CertFile,KeyFile,GatewayAddress,Port,BindAddress,Hosts,HostSelection,Authentication}`, `Header.{UserHeader,TrustedProxies}`, `Security.{PAATokenSigningKey,VerifyClientIp}`, `Caps.TokenAuth`; the generated `.rdp` settings written by `rdpgw_web.go` `HandleDownload`. Leg B's `legb-winapp` listening on `:3389` (Task 6) as `Server.Hosts[0]`.
- Produces: a runnable LAN gateway + the `.rdp` fetched from `/connect`; the Leg C gate record in `docs/census.md`.

**Steps:**

1. Generate a self-signed cert and a random 32-char PAA key (the CHANGELOG + `configuration.go:273` require a 32-char key that is **not** a published placeholder), then write `spikes/legc-rdpgw/rdpgw.yaml`. Fill `<LEGB_HOST>` with the dev host's LAN IP (where `legb-winapp` listens) and `<GW_LAN_HOST>` with the gateway's own LAN name/IP that the Mac will reach:
```yaml
Server:
  # LAN cert; self-signed is fine for the spike (Windows App trusts on first use).
  CertFile: spikes/legc-rdpgw/state/server.pem
  KeyFile: spikes/legc-rdpgw/state/key.pem
  # GatewayAddress is what ends up in the .rdp as `gatewayhostname`: Windows App
  # tunnels straight to rdpgw on the LAN. Only /connect goes through the proxy.
  GatewayAddress: <GW_LAN_HOST>:9443
  Port: 9443
  # LAN-reachable for the tunnel. The user header is trusted only from the
  # loopback proxy (Header.TrustedProxies), so /connect still requires the proxy,
  # and the tunnel requires the token /connect hands out (Caps.TokenAuth).
  BindAddress: 0.0.0.0
  Authentication:
    - header
  # Operator-curated single host: roundrobin always picks it, so we avoid the
  # `any` mode that the Unreleased CHANGELOG blocks for RFC1918 destinations.
  HostSelection: roundrobin
  Hosts:
    - <LEGB_HOST>:3389
Header:
  UserHeader: X-Forwarded-User
  # Only the loopback header-proxy may stamp the user header.
  TrustedProxies:
    - 127.0.0.1/32
Security:
  # 32 chars, random, NOT a README placeholder (rdpgw refuses placeholders).
  PAATokenSigningKey: <PASTE_32_RANDOM_CHARS_HERE>
  # /connect is seen from the loopback proxy's IP while the tunnel is seen from
  # the Mac's IP, so the two never match — disable IP pinning for the spike.
  VerifyClientIp: false
Caps:
  TokenAuth: true
```
2. Write `spikes/legc-rdpgw/header-proxy.py` (dependency-free stdlib reverse proxy; injects the user header, strips any client-supplied copy, forwards to loopback rdpgw):
```python
#!/usr/bin/env python3
"""THROWAWAY Leg C stub: stands in for the oauth2-proxy admin tier.
Listens on the LAN, injects X-Forwarded-User, forwards to rdpgw on 127.0.0.1:9443.
NOT an authenticator — it unconditionally asserts one identity for the spike."""
import http.server
import ssl
import urllib.request

RDPGW = "https://127.0.0.1:9443"
USER = "kvm-admin@example.test"  # the one allowlisted identity for the spike
LISTEN = ("0.0.0.0", 8443)

# rdpgw uses a self-signed cert on loopback; the spike does not verify it.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class Proxy(http.server.BaseHTTPRequestHandler):
    def _forward(self):
        body_len = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(body_len) if body_len else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "x-forwarded-user", "content-length")}
        headers["X-Forwarded-User"] = USER  # strip-then-inject: client cannot smuggle one
        req = urllib.request.Request(RDPGW + self.path, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(req, context=_CTX) as r:
                self.send_response(r.status)
                for k, v in r.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(r.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())

    do_GET = _forward
    do_POST = _forward


if __name__ == "__main__":
    httpd = http.server.ThreadingHTTPServer(LISTEN, Proxy)
    # Serve HTTPS on the LAN so Windows App / the browser trust the download page.
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain("spikes/legc-rdpgw/state/server.pem", "spikes/legc-rdpgw/state/key.pem")
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    print(f"header-proxy on https://{LISTEN[0]}:{LISTEN[1]} -> {RDPGW} as {USER}")
    httpd.serve_forever()
```
3. Write `spikes/legc-rdpgw/run.sh`:
```bash
#!/usr/bin/env bash
# THROWAWAY Leg C runner — LAN only, run from the repo root. Requires
# legb-winapp already listening on <LEGB_HOST>:3389 (Task 6). No sudo: all
# state lives in spikes/legc-rdpgw/{state,src,bin,gomod}/ (gitignored).
set -euo pipefail
S=spikes/legc-rdpgw
mkdir -p "$S/state" "$S/bin" "$S/gomod"
chmod 0700 "$S/state"

# 1. Self-signed LAN cert (shared by rdpgw and the header proxy), 2-day lifetime.
[ -f "$S/state/server.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$S/state/key.pem" -out "$S/state/server.pem" \
  -subj "/CN=$(hostname -f)" -days 2

# 2. A fresh 32-char PAA key if the config still has the placeholder.
if grep -q '<PASTE_32_RANDOM_CHARS_HERE>' "$S/rdpgw.yaml"; then
  KEY="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
  sed -i "s/<PASTE_32_RANDOM_CHARS_HERE>/${KEY}/" "$S/rdpgw.yaml"
fi

# 3. rdpgw built from source at the commit this spike was grounded on (16cdaaf),
#    module cache kept inside the spike dir so cleanup is one rm -rf.
if [ ! -x "$S/bin/rdpgw" ]; then
  [ -d "$S/src" ] || git clone --quiet https://github.com/bolkedebruin/rdpgw "$S/src"
  git -C "$S/src" checkout --quiet 16cdaaf
  ( cd "$S/src" && GOMODCACHE="$PWD/../gomod" GOFLAGS=-p=4 \
      nice -n 19 nix shell nixpkgs#go --command go build -o ../bin/rdpgw ./cmd/rdpgw )
fi
"$S/bin/rdpgw" -c "$PWD/$S/rdpgw.yaml" &
RDPGW_PID=$!
trap 'kill $RDPGW_PID 2>/dev/null || true' EXIT

# 4. The header-injecting proxy for /connect on the LAN (:8443 → 127.0.0.1:9443).
nix shell nixpkgs#python3 --command python3 "$S/header-proxy.py"
```
4. Run it and fetch the `.rdp` (the download path exercises `/connect` → header auth → `HandleDownload`):
```
bash spikes/legc-rdpgw/run.sh &
# From the Mac (or dev host), download the .rdp through the LAN proxy:
curl -k -o legc.rdp https://<GW_LAN_HOST>:8443/connect
```
Expected `legc.rdp` contents include: `full address:s:<LEGB_HOST>:3389`, `gatewayhostname:s:<GW_LAN_HOST>:9443`, `gatewaycredentialssource:i:` cookie, a non-empty `gatewayaccesstoken:s:…`, `gatewayusagemethod:i:1`, `username:s:kvm`, `redirectclipboard:i:1`, `networkautodetect:i:1`, `enablecredsspsupport:i:1`. Confirm the header is only honoured from the loopback proxy — from **another** LAN host, a `/connect` sent straight to rdpgw (not through :8443) must not yield an `.rdp`:
```
curl -k -o /dev/null -w '%{http_code}\n' https://<GW_LAN_HOST>:9443/connect
# expect: 401 (no trusted proxy in front of this request, so no user identity)
```
5. Open `legc.rdp` in Microsoft Windows App on the laptop. Expected: Windows App dials the gateway at `<GW_LAN_HOST>:9443` over `/remoteDesktopGateway/`, presents the PAA token (TokenAuth validates it — `rdpgw_process.go` `CheckPAACookie`), tunnels to the Leg B server, completes NLA with pre-filled `kvm`, and the Leg B fixture plays. Watch the Leg B logs for `LEGB_CAP`/`LEGB_READY`/`LEGB_ACK` arriving **through the gateway**, and that CLIPRDR opens (copy text on the laptop → the Leg B clipboard channel registers).
6. Fill the Leg C section of `docs/census.md` (replace the template's `## Leg C — gateway (rdpgw) gates` section with this checklist), then commit:
```markdown
## Leg C — gateway (rdpgw on the LAN, header mode behind a loopback stub)

- [ ] Windows App connects with the gateway-token `.rdp` (end to end through
      `/remoteDesktopGateway/`; PAA token validated by TokenAuth).
- [ ] NLA completes with the pre-filled username `kvm` (== `rdp.username`).
- [ ] CLIPRDR channel opens (`redirectclipboard:i:1` present; Leg B logs the
      clipboard channel registering).
- [ ] The Leg B video gates (AVC420 confirmed; first-frame ack p95; picture
      within N after resize + re-advertise) HOLD through the gateway.
- [ ] Capability bytes captured through the gateway (initial + any
      re-advertise) — compare to the direct Leg B ladder; record any diff.
- [ ] Every `queue_depth` captured through the gateway (does gatewaying change
      ack-suspension behaviour?).
- [ ] Auto-detect through the gateway: does `LEGB_AUTODETECT autodetect_answered`
      ever become true when tunnelled? (`.rdp` sets `networkautodetect:i:1`.)
- [ ] Exploit guard: a `/connect` request reaching rdpgw from outside
      `Header.TrustedProxies` (i.e. not via the loopback proxy) is refused.
- If Leg C fails: revisit the VNC fallback (§14) before Milestone 1.
```
```
git add spikes/legc-rdpgw/rdpgw.yaml spikes/legc-rdpgw/header-proxy.py spikes/legc-rdpgw/run.sh docs/census.md
git commit -m "spikes/legc: LAN rdpgw (header mode + loopback stub), .rdp + Leg C census gates

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
## Part 8 — Upstream IronRDP PR

The four §4.2 patches, on a branch of Chris's IronRDP fork, opened as one PR to Devolutions/IronRDP.

> **Working trees.** Tasks 1–4 patch the git-pinned IronRDP checkout, NOT `kvm-rdp`.
> Let `$IRONRDP = ~/Repos/IronRDP` — Chris's fork of Devolutions/IronRDP, created once with `gh repo fork Devolutions/IronRDP --clone -- --filter=blob:none ~/Repos/IronRDP` (a blob-less partial clone keeps disk use low; confirm with Chris before creating the fork, it is public). The IronRDP build is large: run `cargo clean` in `$IRONRDP` once the PR is open to give the disk back.
> All patches branch from `38b074e` (the rev the spec and research were grounded on). All four patches land on one local branch `kvm-rdp-egfx-patches` off `38b074e`; they become PRs to **Devolutions/IronRDP**. Until merged, Plan C's `[workspace.dependencies]` git-pins every `ironrdp-*` crate at this branch's HEAD (a documented, temporary fork exception per §4.2; reverted when upstream merges — Patch 1 alone may instead be replaced by its shadow-flag fallback in the pump). Tasks 5–6 are checklist/doc tasks in `/home/chris/Repos/kvm-rdp`.
>
> **Build budget (§13).** Every `cargo` runs from the IronRDP root under `nice -n 19` with `--jobs 4`, scoped to one crate/test, so the shared loaded host is not swamped. These are upstream server/EGFX patches, not parsers: the §6.1/§6.2 panicking-clippy denies and checked-access rules (and all fuzzing) are kvm-proto concerns in Plan B and do not apply here.
> **Attribution.** IronRDP commits are signed off (`-s`, Devolutions DCO) and carry the Co-Authored-By trailer; kvm-rdp commits carry the trailer.

### Task 8.1: IronRDP Patch 1 — ack suspension survives `FrameTracker::clear()`

**Files:**
- Modify: `$IRONRDP/crates/ironrdp-egfx/src/server.rs` (`FrameTracker::clear` @703–707; `GraphicsPipelineServer` flow-control passthroughs @1332–1352)
- Test: `$IRONRDP/crates/ironrdp-testsuite-core/tests/egfx/server.rs` (append next to the existing suspension tests @704–855)

**Interfaces:**
- Consumes: `pub fn FrameTracker::is_ack_suspended(&self) -> bool` (exists, server.rs:688); `GraphicsPipelineServer::{resize(&mut self, u16, u16), create_surface(&mut self, u16, u16) -> Option<u16>, send_avc420_frame(&mut self, u16, &[u8], &[Avc420Region], u32) -> Option<u32>, process(&mut self, u32, &[u8]) -> PduResult<Vec<DvcMessage>>, drain_output(&mut self) -> Vec<DvcMessage>}`. The two production callers of `clear()` are `resize_with_monitors` (server.rs:1312, every Setup) and the re-advertise branch of `handle_capabilities_advertise` (server.rs:2061).
- Produces: `pub fn GraphicsPipelineServer::is_ack_suspended(&self) -> bool`; behaviour change — `FrameTracker::clear(&mut self)` preserves `self.ack_suspended`.

**Steps:**

1. Create the branch:
   ```
   git -C $IRONRDP checkout -b kvm-rdp-egfx-patches 38b074e
   ```

2. Write the failing test. Append to `$IRONRDP/crates/ironrdp-testsuite-core/tests/egfx/server.rs`:
   ```rust
   /// A client that suspended frame acknowledgement must stay suspended across
   /// a server-driven resize and a mid-session capability re-advertise: both run
   /// `FrameTracker::clear()`, and clearing the suspension there wedges video for
   /// good — the client sends no acknowledgement to resume, so backpressure would
   /// never lift. MS-RDPEGFX's ResetGraphics says nothing about acknowledgement;
   /// keeping the flag is the deliberate, lower-risk choice (kvm-rdp §4.2 patch 1).
   #[test]
   fn ack_suspension_survives_a_resize_and_a_readvertise() {
       let handler = Box::new(TestHandler::new());
       let mut server = GraphicsPipelineServer::new(handler);
       server.set_max_frames_in_flight(2);

       let advertise = GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu::from_typed(&[
           CapabilitySet::V8_1 { flags: CapabilitiesV81Flags::AVC420_ENABLED },
       ]));
       let _ = server.process(0, &encode_pdu(&advertise)).expect("initial advertise");

       let surface_id = server.create_surface(640, 360).unwrap();
       server.drain_output();

       let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65];
       let regions = vec![Avc420Region::full_frame(640, 360, 22)];

       // One frame out, then the client suspends acknowledgement for it.
       let first = server.send_avc420_frame(surface_id, &idr, &regions, 0).expect("first frame");
       let suspend = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
           queue_depth: QueueDepth::Suspend,
           frame_id: first,
           total_frames_decoded: 1,
       });
       let _ = server.process(0, &encode_pdu(&suspend)).expect("suspend ack");
       assert!(server.is_ack_suspended(), "the client just suspended acknowledgement");

       // A server-initiated resize runs FrameTracker::clear().
       server.resize(1280, 720);
       assert!(server.is_ack_suspended(), "a resize must not resume a suspended client");

       // A mid-session re-advertise (mstsc/Windows App decoder-recovery) runs it again.
       let readvertise = GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu::from_typed(&[
           CapabilitySet::V8_1 { flags: CapabilitiesV81Flags::AVC420_ENABLED },
       ]));
       let _ = server.process(0, &encode_pdu(&readvertise)).expect("re-advertise");
       assert!(server.is_ack_suspended(), "a re-advertise must not resume a suspended client");

       // With suspension intact the encoder is never throttled: every frame goes
       // out though none is acknowledged. max_frames_in_flight is 2, so a tracker
       // that forgot the suspension would return None on the third frame.
       let surface_id = server.create_surface(1280, 720).unwrap();
       server.drain_output();
       let regions = vec![Avc420Region::full_frame(1280, 720, 22)];
       for i in 0..4u32 {
           assert!(
               server.send_avc420_frame(surface_id, &idr, &regions, (i + 1) * 16).is_some(),
               "frame {i} was throttled -- the suspension was lost across clear()",
           );
       }
       assert!(server.is_ack_suspended(), "still suspended after sending");
   }
   ```

3. Run it — expect a **compile error** (no method `is_ack_suspended` on `GraphicsPipelineServer`):
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-testsuite-core --test main -- egfx::server::ack_suspension_survives_a_resize_and_a_readvertise --exact
   ```
   Expected: `error[E0599]: no method named `is_ack_suspended` found for struct `GraphicsPipelineServer``.

4. Add the passthrough (minimal, so the test compiles). In `$IRONRDP/crates/ironrdp-egfx/src/server.rs`, after `client_queue_depth` (@1347):
   ```rust
   /// Whether the client has suspended frame acknowledgement
   /// ([MS-RDPEGFX] 2.2.2.13, `queue_depth == 0xFFFFFFFF`). The bridge's flow
   /// control reads this to bypass the soft gate and disable the stall timer
   /// while suspended (kvm-rdp §6.6).
   #[must_use]
   pub fn is_ack_suspended(&self) -> bool {
       self.frames.is_ack_suspended()
   }
   ```

5. Re-run the same command — expect it to **compile but fail an assertion**: `clear()` still zeroes `ack_suspended`, so `assert!(server.is_ack_suspended())` fails after `resize`, and the third `send_avc420_frame` returns `None`.

6. Fix `FrameTracker::clear` (@703–707) — drop the suspension reset:
   ```rust
   /// Clear per-reset tracking state.
   ///
   /// Deliberately keeps `ack_suspended`. This runs on every Setup
   /// (`resize_with_monitors`) and on a mid-session re-advertise; MS-RDPEGFX's
   /// ResetGraphics (3.2.5.18) says nothing about acknowledgement, and the risk
   /// is asymmetric — wrongly keeping it costs ~one RTT of untracked frames,
   /// wrongly clearing it wedges video for good (the client resumes only by
   /// acknowledging an EndFrame it received).
   pub fn clear(&mut self) {
       self.unacknowledged.clear();
       self.client_queue_depth = 0;
       // `ack_suspended` intentionally preserved — see the doc comment.
   }
   ```

7. Run to pass:
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-testsuite-core --test main -- egfx::server::
   ```
   Expected: the new test and every existing suspension test (`test_frames_sent_while_acknowledgement_is_suspended_do_not_hold_backpressure`, `test_suspension_does_not_shrink_the_window_for_the_rest_of_the_connection`, `test_a_suspending_acknowledgement_still_acknowledges_its_frame`, `test_resize`, `test_frame_flow_control`) pass.

8. Commit:
   ```
   git -C $IRONRDP add crates/ironrdp-egfx/src/server.rs crates/ironrdp-testsuite-core/tests/egfx/server.rs
   git -C $IRONRDP commit -s -m "fix(egfx): keep ack suspension across FrameTracker::clear

   clear() runs on every Setup (resize_with_monitors) and on a mid-session
   re-advertise. Zeroing ack_suspended there resumes a client that is still
   suspended, and since it resumes only by acknowledging a frame it received,
   backpressure never lifts and video wedges. Preserve the flag and expose
   GraphicsPipelineServer::is_ack_suspended().

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 8.2: IronRDP Patch 2 — optional per-event write-completion counter on `EgfxServerMessage::SendMessages`

**Files:**
- Modify: `$IRONRDP/crates/ironrdp-server/src/gfx.rs` (`EgfxServerMessage` enum @95–98; `Display` impl @100–107)
- Modify: `$IRONRDP/crates/ironrdp-server/src/server.rs` (match arm @3412–3417; `dispatch_egfx_messages` @3480–3560; `write_egfx_over_tcp` @3562–3576; add `note_egfx_written` free fn)
- Modify: `$IRONRDP/crates/ironrdp-testsuite-extra/tests/e2e.rs` (two construction sites @1206, @1296)
- Test: inline `#[cfg(all(test, feature = "egfx"))] mod egfx_write_counter_tests` in `$IRONRDP/crates/ironrdp-server/src/server.rs`

**Interfaces:**
- Consumes: `dispatch_egfx_messages(&mut self, Vec<SvcMessage>, &mut impl FramedWrite, u16, Option<&multitransport::UdpTransportHandle>) -> ServerResult<()>`; `write_egfx_over_tcp(&mut self, Vec<SvcMessage>, &mut impl FramedWrite, u16, u16) -> ServerResult<()>`; `multitransport::UdpTransportHandle::send`. `Arc`, `AtomicU64`, `Ordering` already imported in server.rs:4; gfx.rs imports `std::sync::{Arc, Mutex}` — add `use core::sync::atomic::AtomicU64;`.
- Produces: `EgfxServerMessage::SendMessages { messages: Vec<SvcMessage>, write_counter: Option<(Arc<AtomicU64>, u64)> }` with `#[non_exhaustive]` on the enum; `fn note_egfx_written(counter: &Option<(Arc<AtomicU64>, u64)>)` (cfg `egfx`). The bridge (Plan C, §6.6 backlog gate) sets `weight = Σ DvcMessage::size()` of the drained batch and owns one counter per connection generation (§4.3); `written = counter.load()` is the backlog gate's lower bound.

**Steps:**

1. Write the failing test. Append to `$IRONRDP/crates/ironrdp-server/src/server.rs`:
   ```rust
   #[cfg(all(test, feature = "egfx"))]
   mod egfx_write_counter_tests {
       use super::*;

       /// Once every byte of an EGFX event has reached the transport, the
       /// per-generation counter advances by exactly the weight the embedder
       /// attached — never more, never twice, and never for an absent counter.
       /// This is the write-side half of the §6.6 backlog gate: handed − written.
       #[test]
       fn a_completed_write_advances_the_counter_by_its_weight_once() {
           let counter = Arc::new(AtomicU64::new(0));

           note_egfx_written(&Some((Arc::clone(&counter), 1590)));
           assert_eq!(counter.load(Ordering::Relaxed), 1590);

           note_egfx_written(&Some((Arc::clone(&counter), 10)));
           assert_eq!(counter.load(Ordering::Relaxed), 1600, "weights accumulate across events");

           note_egfx_written(&None);
           assert_eq!(counter.load(Ordering::Relaxed), 1600, "an absent counter is a no-op");
       }
   }
   ```

2. Run it — expect a **compile error** (no `note_egfx_written` in scope):
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server --features egfx -- egfx_write_counter_tests::a_completed_write_advances_the_counter_by_its_weight_once --exact
   ```
   Expected: `error[E0425]: cannot find function `note_egfx_written` in this scope`.

3. Add the helper near `write_egfx_over_tcp` in `server.rs`:
   ```rust
   /// Record that every byte of an EGFX event reached the transport, advancing
   /// the embedder-owned per-generation outbound counter by the weight attached
   /// to the event. A `None` counter (the default) is a no-op, so callers that
   /// do not opt in are unaffected. See [`crate::gfx::EgfxServerMessage::SendMessages`].
   #[cfg(feature = "egfx")]
   fn note_egfx_written(counter: &Option<(Arc<AtomicU64>, u64)>) {
       if let Some((counter, weight)) = counter {
           counter.fetch_add(*weight, Ordering::Relaxed);
       }
   }
   ```

4. Run to pass:
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server --features egfx -- egfx_write_counter_tests::a_completed_write_advances_the_counter_by_its_weight_once --exact
   ```
   Expected: `test egfx_write_counter_tests::a_completed_write_advances_the_counter_by_its_weight_once ... ok`.

5. Wire the field and the call sites (the mechanical threading the helper test anchors):
   - `gfx.rs` — mark the enum `#[non_exhaustive]`, add the field, fix `Display`:
     ```rust
     #[derive(Debug)]
     #[non_exhaustive]
     pub enum EgfxServerMessage {
         /// Pre-encoded DVC messages from `GraphicsPipelineServer::drain_output()`.
         SendMessages {
             messages: Vec<SvcMessage>,
             /// Once every byte of this event is written (TCP `write_all`
             /// returned, or each UDP send returned), `weight` is added to the
             /// counter. Lets an embedder observe wire progress per connection
             /// generation without re-encoding. `None` keeps the prior behaviour.
             write_counter: Option<(Arc<AtomicU64>, u64)>,
         },
     }
     ```
     and `write!(f, "SendMessages(count={})", messages.len())` → match `Self::SendMessages { messages, .. }`. Add `use core::sync::atomic::AtomicU64;`.
   - `server.rs` match arm @3413: `EgfxServerMessage::SendMessages { messages, write_counter } => { self.dispatch_egfx_messages(messages, writer, user_channel_id, udp_transport, write_counter).await?; }`
   - `dispatch_egfx_messages` gains `write_counter: Option<(Arc<AtomicU64>, u64)>`; after the UDP `for message in &messages { … udp_transport.send(payload).await; }` loop and before `return Ok(());` (the `route_over_udp` true path), call `note_egfx_written(&write_counter);`; pass `write_counter` into `write_egfx_over_tcp` on the TCP path.
   - `write_egfx_over_tcp` gains `write_counter: Option<(Arc<AtomicU64>, u64)>`; change its tail to:
     ```rust
     writer.write_all(&data).await.map_err(|e| ServerError::io("write_all", e))?;
     note_egfx_written(&write_counter);
     Ok(())
     ```
   - `e2e.rs` @1206 and @1296: add `write_counter: None,` to each `SendMessages { … }`.

6. Re-run to confirm nothing regressed (enum consumers, e2e):
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server --features egfx -- egfx_write_counter_tests::
   cd $IRONRDP && nice -n 19 cargo build --jobs 4 -p ironrdp-testsuite-extra --tests
   ```
   Expected: test ok; `ironrdp-testsuite-extra` builds (the `#[non_exhaustive]` enum and new field compile at both construction sites).

7. Commit:
   ```
   git -C $IRONRDP add crates/ironrdp-server/src/gfx.rs crates/ironrdp-server/src/server.rs crates/ironrdp-testsuite-extra/tests/e2e.rs
   git -C $IRONRDP commit -s -m "feat(server): optional write-completion counter for EGFX events

   EgfxServerMessage::SendMessages gains an optional (Arc<AtomicU64>, weight).
   Once every byte of the event is on the transport (TCP write_all returned, or
   each UDP send returned), weight is added to the counter, letting an embedder
   measure outbound progress per connection without re-encoding. Enum is now
   #[non_exhaustive].

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 8.3: IronRDP Patch 3 — discard stale session events before serving a *fresh* connection

**Files:**
- Modify: `$IRONRDP/crates/ironrdp-server/src/server.rs` (`discard_stale_session_events` @2075–2108; accept loop @2420–2479 — the `Negotiated` arm's call @2433 and the serve point @2481)
- Test: inline `#[cfg(test)] mod stale_event_tests` in `$IRONRDP/crates/ironrdp-server/src/server.rs`

**Interfaces:**
- Consumes: `RdpServer::{ev_sender: mpsc::UnboundedSender<ServerEvent>, ev_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ServerEvent>>>}`; the keep-list (`Quit | GetLocalAddr | SetCredentials | SetAutoReconnectCookie`). `RdpServer::builder()` as in `cliprdr_error_tests` (server.rs:5835).
- Produces: `async fn RdpServer::discard_stale_session_events(&mut self) -> usize` (was `-> ()`), returning the count discarded; the call now runs once before serving **every** entry (Fresh and Negotiated), closing the gap where a fresh connection inherited a leftover per-session event (e.g. an unconsumed `Disconnect`/`EvictedByOtherConnection`) and disconnected itself with a bogus code. End-to-end this backs the kvm-rdp L2 "Generations" case (§11.3) and §4.3's "events already queued when a connection ends are dropped by IronRDP, not the bridge."

**Steps:**

1. Write the failing test. Append to `$IRONRDP/crates/ironrdp-server/src/server.rs`:
   ```rust
   #[cfg(test)]
   mod stale_event_tests {
       use core::net::Ipv4Addr;

       use super::*;

       /// Per-session events left on the server-global channel by a connection
       /// that ended must be dropped before the next connection is served, while
       /// the handful of control events that outlive a connection survive. The
       /// returned count makes the drop observable; the fresh-path call site
       /// (patch 3) relies on exactly this contract.
       #[tokio::test]
       async fn stale_session_events_are_dropped_and_control_events_survive() {
           let mut server = RdpServer::builder()
               .with_addr((Ipv4Addr::LOCALHOST, 0))
               .with_no_security()
               .with_no_input()
               .with_no_display()
               .build();

           // Two per-session leftovers (must go) around one control event (must stay).
           server.ev_sender.send(ServerEvent::AutoDetectRttRequest).unwrap();
           server
               .ev_sender
               .send(ServerEvent::SetAutoReconnectCookie(None))
               .unwrap();
           server
               .ev_sender
               .send(ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                   ProtocolIndependentCode::DisconnectedByOtherconnection,
               )))
               .unwrap();

           let dropped = server.discard_stale_session_events().await;
           assert_eq!(dropped, 2, "the RttRequest and the stale Disconnect must be discarded");

           let ev_receiver = Arc::clone(&server.ev_receiver);
           let mut ev_receiver = ev_receiver.lock().await;
           assert!(
               matches!(ev_receiver.try_recv(), Ok(ServerEvent::SetAutoReconnectCookie(None))),
               "the control event must be put back in order",
           );
           assert!(
               ev_receiver.try_recv().is_err(),
               "nothing else may remain for the next connection to inherit",
           );
       }
   }
   ```

2. Run it — expect a **compile error** (`discard_stale_session_events` returns `()`, so `assert_eq!(dropped, 2)` is a type mismatch):
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server -- stale_event_tests::stale_session_events_are_dropped_and_control_events_survive --exact
   ```
   Expected: `error[E0308]: mismatched types ... expected integer, found `()``.

3. Change the method to return the count. In `discard_stale_session_events` (@2075): signature `async fn discard_stale_session_events(&mut self) -> usize {`, and after the re-send loop (@2105–2107) add the trailing expression:
   ```rust
       for event in keep {
           let _ = self.ev_sender.send(event);
       }

       discarded
   }
   ```

4. Make the fresh path call it (the behavioural fix). Remove the call from the `Negotiated` arm (@2433 — `self.discard_stale_session_events().await;`) and insert one unified call immediately after the `let entry = match pending.take() { … };` block (just before `let peer = match &entry` @2481), so both Fresh and Negotiated discard exactly once before serving:
   ```rust
       // Before serving ANY entry — the fresh path as well as a preemption
       // winner — drop per-session events the previous session never consumed,
       // so this connection cannot inherit, e.g., a stale Disconnect and tear
       // itself down with a bogus reason.
       let dropped = self.discard_stale_session_events().await;
       if dropped > 0 {
           debug!(dropped, "discarded stale per-session events before serving a new connection");
       }
   ```

5. Run to pass, and confirm the preemption tests still pass:
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server -- stale_event_tests:: preempt_tests::
   ```
   Expected: the new test and `preempt_tests` all pass.

6. Commit:
   ```
   git -C $IRONRDP add crates/ironrdp-server/src/server.rs
   git -C $IRONRDP commit -s -m "fix(server): discard stale session events before every connection

   discard_stale_session_events ran only for a preemption winner. A fresh
   connection could inherit a per-session event the previous session never
   consumed (e.g. a leftover Disconnect) and tear itself down with the wrong
   reason. Run it once before serving any entry, Fresh or Negotiated, and
   return the discarded count so the behaviour is testable.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```

---

### Task 8.4: IronRDP Patch 4 — per-connection abort handle + bounded SetErrorInfo write

**Files:**
- Modify: `$IRONRDP/crates/ironrdp-server/src/server.rs` (near `ErrorInfoDisconnectHandle` @888/1637; `EVICTION_GRACE` @1237; the `ServerEvent::Disconnect` arm @2920–2935; add `ConnectionAbortHandle`, `serve_with_abort`, `SET_ERROR_INFO_WRITE_GRACE`)
- Test: inline `#[cfg(test)] mod hard_close_tests` in `$IRONRDP/crates/ironrdp-server/src/server.rs`

**Interfaces:**
- Consumes: `RdpServer::error_info_disconnect_handle(&self) -> ErrorInfoDisconnectHandle` and `ErrorInfoDisconnectHandle::disconnect(&self, ErrorInfo) -> Result<(), SendError<ServerEvent>>` (@904); `dispatch_server_events(&mut self, &mut Vec<ServerEvent>, &mut impl FramedWrite, u16, u16, Option<u16>, Option<&UdpTransportHandle>) -> ServerResult<RunState>` (@2851); `encode_share_data_pdu`; `RunState::Disconnect`; the `tokio::time::timeout(EVICTION_GRACE, &mut conn)` cancel pattern (@2655) — dropping `conn` runs the same teardown a client disconnect does.
- Produces: `pub fn RdpServer::connection_abort_handle(&self) -> ConnectionAbortHandle`; `pub struct ConnectionAbortHandle` with `pub fn abort(&self)`; `async fn serve_with_abort<F>(conn: F, abort: Arc<tokio::sync::Notify>) -> ServerResult<()> where F: Future<Output = ServerResult<()>>`; `const SET_ERROR_INFO_WRITE_GRACE: Duration`. The kvm-rdp disconnect watchdog (§6.9) holds a `ConnectionAbortHandle` and triggers it when `on_disconnected` has not fired, so a client that stopped reading cannot pin the session or the KVM login.

**Steps:**

1. Write the failing test for the abort core. Append to `$IRONRDP/crates/ironrdp-server/src/server.rs`:
   ```rust
   #[cfg(test)]
   mod hard_close_tests {
       use core::net::Ipv4Addr;

       use super::*;

       /// The abort handle must drop a connection future that will never resolve
       /// on its own — the writer blocked on a peer that stopped reading — so the
       /// drop runs the same per-connection teardown a client disconnect does.
       #[tokio::test]
       async fn an_abort_drops_a_wedged_connection_future() {
           let abort = Arc::new(tokio::sync::Notify::new());
           let trigger = Arc::clone(&abort);
           tokio::spawn(async move {
               tokio::time::sleep(Duration::from_millis(10)).await;
               trigger.notify_waiters();
           });

           // Never completes on its own.
           let wedged = core::future::pending::<ServerResult<()>>();
           let outcome = tokio::time::timeout(Duration::from_secs(5), serve_with_abort(wedged, abort)).await;
           assert!(
               matches!(outcome, Ok(Ok(()))),
               "the abort must make the serve future resolve so teardown can run",
           );
       }

       struct WedgedWriter;

       impl FramedWrite for WedgedWriter {
           type WriteAllFut<'write>
               = core::future::Pending<std::io::Result<()>>
           where
               Self: 'write;

           fn write_all<'a>(&'a mut self, _buf: &'a [u8]) -> Self::WriteAllFut<'a> {
               core::future::pending()
           }
       }

       /// A bridge-initiated disconnect must put the reason on the wire on a
       /// bounded write and then return Disconnect even if the peer never reads,
       /// so a stalled client cannot wedge the dispatch loop.
       #[tokio::test]
       async fn a_bridge_disconnect_is_bounded_when_the_peer_stops_reading() {
           let mut server = RdpServer::builder()
               .with_addr((Ipv4Addr::LOCALHOST, 0))
               .with_no_security()
               .with_no_input()
               .with_no_display()
               .build();

           let mut events = vec![ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
               ProtocolIndependentCode::ServerDeniedConnection,
           ))];
           let mut writer = WedgedWriter;

           let state = tokio::time::timeout(
               Duration::from_secs(2),
               server.dispatch_server_events(&mut events, &mut writer, 1003, 1002, None, None),
           )
           .await
           .expect("the bounded SetErrorInfo write must return even when the peer never reads")
           .expect("a bounded disconnect write must not surface as a session error");

           assert!(matches!(state, RunState::Disconnect));
       }
   }
   ```

2. Run it — expect a **compile error** (no `serve_with_abort`); the bounded-write test would otherwise **hang** past the 2 s outer timeout:
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server -- hard_close_tests::
   ```
   Expected: `error[E0425]: cannot find function `serve_with_abort` in this scope`.

3. Add the abort core and handle. Near `ErrorInfoDisconnectHandle` in `server.rs`:
   ```rust
   /// Drops the active connection future even while its writer is blocked on a
   /// peer that stopped reading, so `on_disconnected` runs and the session and
   /// any upstream login are released. The embedder holds one per connection
   /// (see [`RdpServer::connection_abort_handle`]) and triggers it from a
   /// watchdog when a graceful `ErrorInfoDisconnectHandle::disconnect` has not
   /// landed in time.
   #[derive(Clone)]
   pub struct ConnectionAbortHandle {
       notify: Arc<tokio::sync::Notify>,
   }

   impl ConnectionAbortHandle {
       /// Abort the active connection; a no-op if none is being served.
       pub fn abort(&self) {
           self.notify.notify_waiters();
       }
   }

   /// Serve `conn`, but drop it if `abort` fires first. Dropping the future
   /// runs the same per-connection teardown a client-side disconnect does
   /// (identical to the `EVICTION_GRACE` cancel of the preemption race).
   async fn serve_with_abort<F>(conn: F, abort: Arc<tokio::sync::Notify>) -> ServerResult<()>
   where
       F: Future<Output = ServerResult<()>>,
   {
       tokio::pin!(conn);
       tokio::select! {
           res = &mut conn => res,
           () = abort.notified() => {
               debug!("connection aborted by handle; dropping the connection future so teardown runs");
               Ok(())
           }
       }
   }
   ```
   Add a field `connection_abort: Arc<tokio::sync::Notify>` to `RdpServer` (init `Arc::new(tokio::sync::Notify::new())` in the builder/`new`, re-created per connection in the accept loop), and the accessor next to `error_info_disconnect_handle` (@1637):
   ```rust
   /// A handle that aborts the active connection outright. See
   /// [`ConnectionAbortHandle`].
   pub fn connection_abort_handle(&self) -> ConnectionAbortHandle {
       ConnectionAbortHandle { notify: Arc::clone(&self.connection_abort) }
   }
   ```
   (Plan C wraps the served future with `serve_with_abort(conn, Arc::clone(&self.connection_abort))` in the accept loop; the kvm-rdp pump's §6.9 watchdog calls `ConnectionAbortHandle::abort()`.) Ensure `use core::future::Future;` is in scope (or fully-qualify).

4. Bound the SetErrorInfo write. Add near `EVICTION_GRACE` (@1237):
   ```rust
   /// How long the `ServerSetErrorInfo` write on a bridge-initiated disconnect
   /// may take before the client loop gives up and tears down anyway. A peer
   /// that has stopped reading must not hold the dispatch loop open.
   const SET_ERROR_INFO_WRITE_GRACE: Duration = Duration::from_millis(500);
   ```
   Replace the body of the `ServerEvent::Disconnect(error)` arm (@2921–2934) with a bounded write:
   ```rust
   ServerEvent::Disconnect(error) => {
       debug!(?error, "Got disconnect event");
       let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error));
       // pduSource=0 per MS-RDPBCGR 2.2.5.1.1 for TS_SET_ERROR_INFO_PDU.
       let data = encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id)?;
       // Bounded: a client that stopped reading must not wedge the loop. Put the
       // reason on the wire best-effort, then disconnect regardless.
       match tokio::time::timeout(SET_ERROR_INFO_WRITE_GRACE, writer.write_all(&data)).await {
           Ok(Ok(())) => {}
           Ok(Err(error)) => debug!(%error, "could not send the disconnect reason; disconnecting anyway"),
           Err(_) => debug!("disconnect reason write timed out; disconnecting anyway"),
       }
       return Ok(RunState::Disconnect);
   }
   ```

5. Run to pass:
   ```
   cd $IRONRDP && nice -n 19 cargo test --jobs 4 -p ironrdp-server -- hard_close_tests::
   ```
   Expected: `an_abort_drops_a_wedged_connection_future ... ok` and `a_bridge_disconnect_is_bounded_when_the_peer_stops_reading ... ok` (returns in ~0.5 s via the internal grace, not the 2 s outer bound).

6. Commit:
   ```
   git -C $IRONRDP add crates/ironrdp-server/src/server.rs
   git -C $IRONRDP commit -s -m "feat(server): connection abort handle and bounded SetErrorInfo write

   Add ConnectionAbortHandle + serve_with_abort so an embedder can drop a
   connection whose writer is blocked on a peer that stopped reading, running
   on_disconnected teardown. Bound the ServerEvent::Disconnect write with
   SET_ERROR_INFO_WRITE_GRACE so a stalled peer cannot wedge the dispatch loop.

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```
   Then push the branch and open the PR against Devolutions/IronRDP:
   ```
   git -C $IRONRDP push -u origin kvm-rdp-egfx-patches
   gh pr create --repo Devolutions/IronRDP --head kvm-rdp-egfx-patches --title "egfx/server: ack-suspend survival, write counter, stale-event discard, hard close" --body "Four small, independent patches (kvm-rdp passthrough bridge, design §4.2): keep ack suspension across FrameTracker::clear; optional per-event write-completion counter on EgfxServerMessage::SendMessages; discard stale session events before every connection; per-connection abort handle + bounded SetErrorInfo write. Each with a test."
   ```
   Record the resulting commit as the rev Plan C git-pins (and note the no-fork fallback: Patch 1 may instead be replaced by the pump's shadow-suspension flag + `InjectSuspendAck`, §4.2).

---

## Part 9 — Spec revision and the Plan A exit gate

Fill every census-dependent value in the spec and record the go/no-go.

### Task 9.1: spec revision + Plan A exit gate (checklist/doc — not TDD)

**Files:**
- Modify: `/home/chris/Repos/kvm-rdp/docs/superpowers/specs/2026-10-05-kvm-rdp-design.md`

**Interfaces:**
- Consumes: `/home/chris/Repos/kvm-rdp/docs/census.md` (Task 6.1, all fields filled by the three legs).
- Produces: the revised spec — every `*(census)*` marker replaced by a concrete value with a one-line "from census.md §X" citation; Status bumped to rev 6; the Plan A exit-gate decision recorded. This is the gate that lets any post-A plan be written (§12: "no plan after A is written before `census.md` is committed").

**Steps (a checklist mapping each census result to the spec default it fills — edit, don't rewrite):**

1. **§3.2 scheme / ports** — set `kvm.scheme` and the 443/8881/8889 vs 80/8880/8888 ports from census transport (rustls-negotiates + TLS-latency vs `http` request→first-IDR). `http` only if rustls cannot negotiate or TLS costs measurable latency, and note "isolated segment only."
2. **§6.1 pinned values** — fix `profile_idc` set, `num_ref_frames` bound (≤ census, ≤ 16), and the `seq_scaling_matrix`/`pic_scaling_matrix`/VUI/HRD present-flag expectations; if the KVM uses any, pin the exact values rather than refusing.
3. **§6.5 policy + N** — set `video.idr_policy` (`reconnect`|`wait`) to the faster census result; write N from the §6.5 formula (`reconnect`: `flv_reconnect_interval_setup` + census reconnect→first-IDR p95 + 0.5 s; `wait`: census GOP length + 0.5 s). **If neither policy gives N ≤ 3 s, stop and design a bridge-side GOP cache before Plan C** (§6.5 / §14 rejected-alternatives note) — do not proceed.
4. **`first_ack_grace`** — set `video.first_ack_grace` to census first-frame ack p95 + `soft_gate` (default 1.5 s if the gate passed at ≤ 1 s).
5. **Hard-cap burst term** — set the census-max-burst addend in `video.hard_cap`'s formula (`ceil(2 s × max_fps) + census max burst`); assert the census gate held (max burst ≤ hard cap and ≤ channel capacity).
6. **§6.8 rewrite** — set `video.sps_rewrite` from the census POC type and `bitstream_restriction`. If the KVM sends POC type 0 without `bitstream_restriction`, decide with a Leg B presentation-hold check: convert a local capture (Mac showing the barcode test pattern only) to Annex-B inside the sandbox (`ffmpeg -c copy -bsf:v h264_mp4toannexb -f h264`), replay it with `LEGB_FIXTURE` pointing into `captures/`, and run the stranding procedure; the capture stays in `captures/` and is wiped. The synthetic POC-0 fixture and the rewriter itself are Plan B.
7. **§6.9 ErrorInfo table** — confirm each code against Leg B's observed dialog + auto-reconnect behaviour; apply any revision the census justifies (e.g. `0x19 SERVER_SHUTDOWN` for `shutdown`).
8. **`flv_idle_timeout`** — set `video.flv_idle_timeout` above the measured static-screen cadence (default 10 s if cadence is faster).
9. **§7.4 timeout** — set `input.key_repeat_timeout` from Leg B's typematic initial delay + 2 × repeat interval + 250 ms (floor 1 s; 10 s if repeats were not confirmed); confirm `modifier_idle_timeout`. Also set `video.default_size` to the shipped preset (1920×1080 expected).
10. **Mac remap** — record whether Leg B's key-matrix capture shows the Cmd-rewrite is distinguishable from a real Ctrl+key, and set `input.mac_remap` accordingly (ships off until shown).
11. **Plan A exit gate** — add a short "Milestone 0 verdict" subsection: if all census gates pass (AVC420 confirmed, N ≤ 3 s, burst ≤ hard cap & channel capacity, Leg C video gates hold through the gateway) → **go for passthrough**, Plans B–E may be written. If **Leg C fails** → revisit the §14 VNC-bridge (neatvnc through a Pomerium tunnel) fallback before Milestone 1. Record each as pass/fail with the census citation.
12. Bump the Status line to "Draft rev 6 — census-filled" and update any `*(census)*` strings remaining in the config-defaults table (§4.4) to concrete values.
13. **Record Plan A's deviations from the spec** so the revision matches what was built: §11.5 — the POC-type-0 fixture moves to Plan B with the SPS rewriter; §12 Leg A — "every open TCP port" became the KVM's documented service ports, "HID round trip" became control-websocket open latency (`kvm-probe ws-open`), and "what the Mac sees when the websocket dies with a key held" moves to Plan C's L4 hardware checks (it needs HID input, which the probe never sends); §4.2 — the upstream PR's branch lives in `~/Repos/IronRDP`.
14. Commit:
   ```
   cd /home/chris/Repos/kvm-rdp && git add docs/superpowers/specs/2026-10-05-kvm-rdp-design.md
   git commit -m "spec: fill census-dependent values from census.md; record Plan A exit gate

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
   ```
