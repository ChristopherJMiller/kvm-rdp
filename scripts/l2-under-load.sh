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
cleanup() {
  trap - EXIT INT TERM HUP
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
}
# Every exit path kills the loops: normal exit, a failing run (set -e), and
# Ctrl-C / TERM / HUP (which exit, so the EXIT trap's work runs once).
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
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
