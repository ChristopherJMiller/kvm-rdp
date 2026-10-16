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
