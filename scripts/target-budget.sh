#!/usr/bin/env bash
# Spec §13 / Plan C design decision 8: fail when the shared target dir grows
# past the budget. The one cleanup that is always safe is `cargo clean`; the
# next gate rebuilds (jobs = 4, niced).
# Default: Task 2.1's 8 GiB floor. Task 6.1 re-measured with every
# IronRDP-linked unit built (the lib tests, the binary and L2): 3.31 GiB,
# x 1.3 = 4.3 GiB, under the floor, so the floor stands (DC10).
set -euo pipefail
budget_gib=${KVM_RDP_TARGET_BUDGET_GIB:-8}
case "$budget_gib" in
  ''|*[!0-9]*|0) echo "target-budget: KVM_RDP_TARGET_BUDGET_GIB must be a positive integer" >&2; exit 2 ;;
esac
dir=${CARGO_TARGET_DIR:-$(git rev-parse --show-toplevel)/target}
if [ ! -d "$dir" ]; then
  echo "target-budget: $dir does not exist (nothing built yet)"
  exit 0
fi
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
used_kib=$(du -sk "$dir" | cut -f1)
budget_kib=$(( budget_gib * 1024 * 1024 ))
used_gib=$(awk -v k="$used_kib" 'BEGIN { printf "%.2f", k / 1048576 }')
if [ "$used_kib" -gt "$budget_kib" ]; then
  echo "target-budget: $dir is ${used_gib} GiB, over the ${budget_gib} GiB budget." >&2
  echo "target-budget: run 'scripts/target-budget.sh --prune' first; if still over," >&2
  echo "target-budget: run 'cargo clean', then the per-task gate again. If it is over" >&2
  echo "target-budget: budget again straight after that, stop and report the size;" >&2
  echo "target-budget: never raise KVM_RDP_TARGET_BUDGET_GIB to get past this gate." >&2
  exit 1
fi
echo "target-budget: $dir is ${used_gib} GiB of ${budget_gib} GiB"
