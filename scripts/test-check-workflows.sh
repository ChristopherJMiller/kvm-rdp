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
  if timeout 10 env "$@" "$check" >"$work/out" 2>&1; then got=pass; else [ $? -eq 124 ] && got=timeout || got=fail; fi
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

# --- Fix round 1: the evading spellings (PE5 review I1-I6, m2-m4, m7) ---
sha=0123456789abcdef0123456789abcdef01234567
sha2=89abcdef0123456789abcdef0123456789abcdef
# A pull-request workflow whose job `a` has the steps (and extra env) given.
mkwf() { # $1 = case name, $2 = steps text (6-space indented lines), $3 = optional job-level text
  mkdir -p "$work/$1"
  {
    printf 'name: t\non: { pull_request: {} }\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n'
    [ -z "${3:-}" ] || printf '%s\n' "$3"
    printf '    steps:\n%s\n' "$2"
  } >"$work/$1/w.yml"
  echo "$work/$1"
}
ckout="      - uses: actions/checkout@$sha # v9.9.9
        with:
          persist-credentials: false"
d=$(mkwf basecase "$ckout"); wf pass "the variant skeleton itself" "$d"
# I1: uses that a line grep never sees
d=$(mkwf flowstep "      - {uses: evil/act@main}"); wf fail "I1: a flow-style step" "$d"
d=$(mkwf flowsteps "" ""); printf '    steps: [ {uses: evil/act@main} ]\n' >"$work/x"; sed -i '/^    steps:/d' "$d/w.yml"; cat "$work/x" >>"$d/w.yml"
wf fail "I1: a flow-style steps list" "$d"
d=$(mkwf quotedkey '      - "uses": evil/act@main'); wf fail "I1: a quoted uses key" "$d"
d=$(mkwf spacecolon '      - uses : evil/act@main'); wf fail "I1: a space before the colon" "$d"
d=$(mkwf localact '      - uses: ./.github/actions/x'); wf fail "I1: a local action" "$d"
# I2: secrets by other spellings, in an unguarded job
for spelling in "\${{ secrets['X'] }}" "\${{ toJSON(secrets) }}" "\${{ SECRETS.X }}"; do
  d=$(mkwf "sec$RANDOM" "$ckout" "    env: { T: \"$spelling\" }"); wf fail "I2: $spelling" "$d"
done
d=$(mkwf secif "      - run: true
        if: secrets.X != ''" ""); wf fail "I2: secrets in a step if:" "$d"
d=$(mkwf secname "      - name: No secrets or captures tracked
        run: true"); wf pass "I2: the word in a step name is fine" "$d"
# I3: owner/repo case
d=$(mkwf lowcache "$ckout
      - uses: swatinem/rust-cache@$sha # v9.9.9
        with:
          save-if: true"); wf fail "I3: lowercase rust-cache saving everywhere" "$d"
d=$(mkwf upco "      - uses: Actions/Checkout@$sha # v9.9.9"); wf fail "I3: Actions/Checkout persisting" "$d"
d=$(mkwf casetwo "$ckout"); mkdir -p "$d"
sed "s|actions/checkout@$sha|Actions/Checkout@$sha2|" "$d/w.yml" >"$d/w2.yml"
wf fail "I3: one action, two SHAs, two spellings" "$d"
# m2: one repository, two sub-actions, two SHAs
d=$(mkwf codeql "      - uses: github/codeql-action/init@$sha # v9.9.9
      - uses: github/codeql-action/analyze@$sha2 # v9.9.9"); wf fail "m2: one repository, two SHAs" "$d"
# I4: the trigger allowlist
d=$(case_dir issuecomment); sed -i 's|pull_request: {}|issue_comment: {}|' "$d/w.yml"
wf fail "I4: issue_comment" "$d"
d=$(case_dir schedule); sed -i 's|pull_request: {}|schedule: [{cron: "1 2 * * *"}], workflow_dispatch: {}|' "$d/w.yml"
wf pass "I4: schedule and workflow_dispatch" "$d"
d=$(case_dir onstr); sed -i 's|^on: .*|on: issues|' "$d/w.yml"
wf fail "I4: a bare string trigger outside the list" "$d"
# m3: a reusable-workflow call
d=$(case_dir reuse); printf "  call:\n    uses: org/repo/.github/workflows/x.yml@%s # v1.0.0\n    secrets: inherit\n    timeout-minutes: 5\n" "$sha" >>"$d/w.yml"
wf fail "m3: job-level uses and secrets: inherit" "$d"
# I5 / m7: the Dockerfile and the build script
pinned="@sha256:$(printf 'b%.0s' $(seq 64))"
df() { # $1 = case name, $2 = Dockerfile text, expect $3; build script optional $4
  local dd; dd=$(case_dir "$1"); printf '%s\n' "$2" >"$dd/Dockerfile"
  if [ -n "${4:-}" ]; then printf '%s\n' "$4" >"$dd/build.sh"; fi
  expect "$3" "$1" WORKFLOWS_DIR="$dd" DOCKERFILE="$dd/Dockerfile" IMAGE_BUILD="$([ -n "${4:-}" ] && echo "$dd/build.sh" || echo /nonexistent)"
}
# shellcheck disable=SC2016  # the Dockerfile's literal ${…}
{
df i5argunused "ARG B=rust:1.94
FROM scratch" fail
df i5short 'ARG B=rust:1.94.1-slim-bookworm
FROM ${B} AS build' fail
df i5quoted 'ARG B="docker.io/library/rust:1.94.1"
FROM ${B}' fail
df i5digit 'ARG B2=docker.io/library/rust:1.94.1
FROM ${B2}' fail
df i5lower 'arg B=docker.io/library/rust:1.94.1
from ${B}' fail
df i5nodef 'ARG B
FROM ${B}' fail
df i5indent '  FROM debian:bookworm' fail
df i5copy "FROM scratch
COPY --from=docker.io/library/busybox:latest /a /a" fail
df i5mount "FROM docker.io/library/rust:1${pinned} AS build
RUN --mount=type=bind,from=busybox:latest,target=/m true" fail
df m7platform "FROM --platform=linux/amd64 docker.io/library/rust:1${pinned} AS build
COPY --from=build /a /a
RUN --mount=type=bind,from=build,target=/m true" pass
df i5shortpinned "ARG B=rust:1.94${pinned}
FROM \${B}" pass
}
df i5export 'FROM scratch' fail 'export BUILDKIT_IMAGE=moby/buildkit:v0.20.0'
df i5readonly 'FROM scratch' fail 'readonly BUILDKIT_IMAGE=moby/buildkit:v0.20.0'
df i5driveropt 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt image=moby/buildkit:latest"
df i5noassign 'FROM scratch' fail 'echo no image here'
df i5exportok 'FROM scratch' pass "export BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}"
# I6, m4: pin-action.sh
pa=scripts/pin-action.sh
d=$(case_dir verifynocomment); sed -i "s|@$sha # v9.9.9|@$sha|" "$d/w.yml"
if WORKFLOWS_DIR="$d" $pa --verify "$d/w.yml" >/dev/null 2>&1; then
  echo "test-check-workflows: I6: --verify passed a pin with no tag comment" >&2; fails=$((fails + 1)); fi
d=$(case_dir verifyflow); printf 'jobs:\n  a:\n    steps:\n      - {uses: "x/y@%s"}\n' "$sha" >"$d/w.yml"
if WORKFLOWS_DIR="$d" $pa --verify "$d/w.yml" >/dev/null 2>&1; then
  echo "test-check-workflows: I6: --verify passed a flow-style pin it cannot read" >&2; fails=$((fails + 1)); fi
# m4 / I6: --rewrite copies a pin from a .yaml file with any spacing (offline: no resolve happens)
d=$(case_dir rewrite); rm "$d/w.yml"
printf 'jobs:\n  a:\n    steps:\n      - uses: Foo.Bar/baz@%s  #   v1.2.3\n' "$sha" >"$d/old.yaml"
printf 'jobs:\n  a:\n    steps:\n      - uses: Foo.Bar/baz@release\n' >"$d/new.yml"
if WORKFLOWS_DIR="$d" $pa --rewrite "$d/new.yml" >/dev/null 2>&1; then
  grep -qF "uses: Foo.Bar/baz@$sha # v1.2.3" "$d/new.yml" ||
    { echo "test-check-workflows: m4: --rewrite did not copy the existing pin" >&2; fails=$((fails + 1)); }
else
  echo "test-check-workflows: m4: --rewrite tried the network for a pinned action" >&2; fails=$((fails + 1))
fi
expect fail "an unpinned BuildKit image" WORKFLOWS_DIR="$d" DOCKERFILE="$d/Dockerfile" IMAGE_BUILD="$d/build.sh"

# --- Fix round 2 (PE5 re-review N1, N2, ARG cycles, --verify on bad YAML) ---
# N1: Task 4.1's own image-build.sh line must not trip the literal-image check
df n1task41 'FROM scratch' pass "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt \"image=\$BUILDKIT_IMAGE\"
docker buildx inspect | grep -qF \"image=\\\"\$BUILDKIT_IMAGE\\\"\""
df n1unpinned 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt 'image=moby/buildkit:latest'"
df n1unpinnedeq 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt=image=moby/buildkit:latest"
df n1quoted 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt image=\"moby/buildkit:latest\""
df n1comma 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt cpu-shares=205,image=moby/buildkit:latest"
df n1literalpinned 'FROM scratch' fail "BUILDKIT_IMAGE=moby/buildkit:v0.20.0${pinned}
docker buildx create --driver-opt image=moby/buildkit:v0.20.0${pinned}"
# N2: a parser directive names an image too
df n2unpinned '# syntax=docker/dockerfile:1.7
FROM scratch' fail
df n2pinned "# syntax=docker/dockerfile:1.7${pinned}
FROM scratch" pass
df n2spaced "#  Syntax = docker/dockerfile:1.7
FROM scratch" fail
df n2late 'FROM scratch
# syntax=docker/dockerfile:1.7' pass
# ARG cycles must end (expect() bounds each case at 10 s and counts a timeout as a failure)
# shellcheck disable=SC2016  # the Dockerfile's literal ${…}
{
df cycleself 'ARG B=${B}
FROM ${B}' fail
df cycletwo 'ARG A=${C}
ARG C=${A}
FROM ${A}' fail
}
# --verify on YAML yq cannot parse must not read as "no pins"
d=$(case_dir verifybadyaml); printf 'jobs: [unclosed\n  a: {\n' >"$d/w.yml"
if $pa --verify "$d/w.yml" >/dev/null 2>&1; then
  echo "test-check-workflows: --verify passed YAML yq cannot parse" >&2; fails=$((fails + 1)); fi
[ "$fails" -eq 0 ] || { echo "test-check-workflows: $fails failed" >&2; exit 1; }
echo "test-check-workflows: all cases pass"
