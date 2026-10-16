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
