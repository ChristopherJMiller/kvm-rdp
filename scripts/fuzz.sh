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
