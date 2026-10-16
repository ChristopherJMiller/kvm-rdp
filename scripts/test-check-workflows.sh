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
d=$(case_dir topsecret)
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
yq -i '.env.T = "${{ secrets.X }}"' "$d/w.yml"
wf fail "a secret outside any job" "$d"
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
