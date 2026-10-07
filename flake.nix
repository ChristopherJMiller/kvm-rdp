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
        # reproduce a CI fuzz crash (`cargo fuzz run --fuzz-dir fuzz --target-dir "$CARGO_TARGET_DIR/fuzz-build" -a T ARTIFACT -- -timeout=10`, the flags CI uses — `-timeout` defaults to 1200 s, so a timeout artifact needs it to replay as a timeout rather than a 20-minute hang, fix round 1 m4):
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
