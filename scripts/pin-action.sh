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
