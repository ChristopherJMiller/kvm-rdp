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
