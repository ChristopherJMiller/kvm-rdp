#!/usr/bin/env bash
# Smoke-test kvm-rdp's image (Plan E Task 4.1): scripts/image-smoke.sh IMAGE
#  1. what it is: user 65532:65532, entrypoint kvm-rdp, MALLOC_ARENA_MAX=2,
#     at most MAX_MIB, no shell;
#  2. its binaries: no build-host path (PC15), kvm-probe runs;
#  3. under the restricted Pod Security profile (read-only root, no
#     capabilities, no-new-privileges), as 65532 and as an arbitrary UID,
#     with its secrets mounted the way the kubelet mounts a Secret
#     (`..<stamp>/`, a `..data` link, one link per file) at the deployment's
#     /run/secrets/kvm-rdp: /readyz and /livez answer unauthenticated; X.224
#     negotiation selects HYBRID for an NLA client and closes TLS-only and
#     standard security with no protocol (§9.1, DE2); SIGTERM exits 0 within
#     5 s (§5.2);
#  4. a config with either `[test]` hook (`panic_after`, `stall_on_sigusr1`)
#     or a security-mode key is refused, exit 2, and the error echoes no value.
#   scripts/image-smoke.sh --paths-only FILE…   only check 2's build-path
#                                               rule, on FILE (its own test)
# Every grep reads a file or a variable, never a pipe a `grep -q` or `head`
# could cut short: under pipefail a SIGPIPE'd writer reads as a clean result.
set -euo pipefail
MAX_MIB=64
work=$(mktemp -d)
name=kvm-rdp-smoke-$$
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() {
  echo "image-smoke: FAIL: $*" >&2
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" 2>&1 | tail -n 40 >&2 || true
  fi
  exit 1
}
ok() { echo "image-smoke: ok — $*"; }

# PC15: no build-host source path in a binary.
paths_clean() {
  local pat='/usr/local/cargo/[[:print:]]{1,80}|/src/crates/[[:print:]]{1,80}|/home/[a-z][[:print:]]{1,80}'
  local b
  for b in "$@"; do
    [ -f "$b" ] || fail "no such binary: $b"
    if grep -aqE "$pat" "$b"; then
      grep -aoE "$pat" "$b" | head -n 3 || true
      fail "$(basename "$b") carries a build-host path (PC15: --remap-path-prefix)"
    fi
  done
}
if [ "${1:-}" = "--paths-only" ]; then
  shift
  paths_clean "$@"
  ok "no build-host path in $*"
  exit 0
fi
image=${1:?usage: image-smoke.sh IMAGE | --paths-only FILE...}

# 1. What the image is.
[ "$(docker image inspect -f '{{.Config.User}}' "$image")" = 65532:65532 ] || fail "the user is not 65532:65532"
[ "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$image")" = '["/usr/local/bin/kvm-rdp"]' ] ||
  fail "the entrypoint is not /usr/local/bin/kvm-rdp"
env_json=$(docker image inspect -f '{{json .Config.Env}}' "$image")
grep -qF '"MALLOC_ARENA_MAX=2"' <<<"$env_json" || fail "MALLOC_ARENA_MAX=2 is not set: $env_json"
size=$(docker image inspect -f '{{.Size}}' "$image")
[ "$size" -le $((MAX_MIB * 1024 * 1024)) ] || fail "the image is $((size / 1048576)) MiB, over $MAX_MIB MiB"
ok "user 65532:65532, entrypoint kvm-rdp, MALLOC_ARENA_MAX=2, $((size / 1048576)) MiB"
for sh in /bin/sh /bin/bash /busybox/sh; do
  if docker run --rm --entrypoint "$sh" "$image" -c true >/dev/null 2>&1; then
    fail "the image has a shell: $sh"
  fi
done
ok "no shell"

# 2. The binaries.
cid=$(docker create "$image")
docker cp "$cid:/usr/local/bin/kvm-rdp" "$work/kvm-rdp" >/dev/null
docker cp "$cid:/usr/local/bin/kvm-probe" "$work/kvm-probe" >/dev/null
docker rm "$cid" >/dev/null
paths_clean "$work/kvm-rdp" "$work/kvm-probe"
ok "no build-host path in either binary ($(stat -c %s "$work/kvm-rdp") and $(stat -c %s "$work/kvm-probe") bytes)"
docker run --rm --entrypoint /usr/local/bin/kvm-probe "$image" --help >/dev/null || fail "kvm-probe does not run"
ok "kvm-probe runs"

# 3. Running. The KVM is TEST-NET-1: nothing is sent to it before an
# authenticated client (§5.1), so the bridge must start and serve without it.
# The secrets as the kubelet mounts a Secret volume: the files in a
# `..<stamp>` directory, `..data` linking to it, and one link per file
# through `..data` (deployment design §4.2) — the renewal path the bridge's
# watcher follows (bridge::tests::a_kubernetes_secret_swap_is_a_renewal).
sec=$work/secrets
stamp=..2026_10_15_00_00_00.1
mkdir -p "$sec/$stamp" "$work/etc"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$sec/$stamp/tls.key" -out "$sec/$stamp/tls.crt" 2>/dev/null
printf 'image-smoke-nla-password-0123456789\n' >"$sec/$stamp/nla.pass"
printf 'image-smoke-kvm-password\n' >"$sec/$stamp/kvm.pass"
ln -s "$stamp" "$sec/..data"
for f in tls.crt tls.key nla.pass kvm.pass; do
  ln -s "..data/$f" "$sec/$f"
done
config() {
  cat <<EOF
[rdp]
listen = "0.0.0.0:3389"
nla_password_file = "/run/secrets/kvm-rdp/nla.pass"
tls_cert_file = "/run/secrets/kvm-rdp/tls.crt"
tls_key_file = "/run/secrets/kvm-rdp/tls.key"
[admin]
listen = "0.0.0.0:9464"
[kvm]
host = "192.0.2.1"
spki_sha256 = "$(printf '0%.0s' $(seq 64))"
password_file = "/run/secrets/kvm-rdp/kvm.pass"
EOF
}
config >"$work/etc/kvm-rdp.toml"
# The two test-hooks keys (DE6), each with a value check 4 must not see echoed.
{ config; printf '[test]\npanic_after = "4711ms"\n'; } >"$work/etc/hooks.toml"
{ config; printf '[test]\nstall_on_sigusr1 = "4713ms"\n'; } >"$work/etc/stall.toml"
config | sed 's/^\[rdp\]$/[rdp]\nsecurity = "tls"/' >"$work/etc/mode.toml"
chmod 0755 "$work" "$work/etc" "$sec" "$sec/$stamp"
chmod 0644 "$work"/etc/* "$sec/$stamp"/*
mounts=(-v "$work/etc:/etc/kvm-rdp:ro" -v "$sec:/run/secrets/kvm-rdp:ro")

start() { # $1 = uid:gid
  docker run -d --name "$name" --read-only --user "$1" --cap-drop ALL --security-opt no-new-privileges \
    "${mounts[@]}" -p 127.0.0.1::3389 -p 127.0.0.1::9464 \
    "$image" --config /etc/kvm-rdp/kvm-rdp.toml >/dev/null
  rdp_port=$(docker port "$name" 3389/tcp | sed -n '1s/.*://p')
  admin_port=$(docker port "$name" 9464/tcp | sed -n '1s/.*://p')
  for _ in $(seq 100); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$admin_port/readyz")" = 200 ]; then
      return 0
    fi
    sleep 0.1
  done
  fail "not ready within 10 s as $1"
}

# An X.224 Connection Request carrying an RDP_NEG_REQ for $1
# (requestedProtocols, little-endian hex). Sets `reply` to what came back as
# hex — the 19-byte Connection Confirm, or less when the bridge closes — and
# `reply_status` to head's exit: 0 at 19 bytes or at the bridge's close, 124
# when neither came within 5 s.
negotiate() {
  local esc='' i
  for ((i = 0; i < ${#1}; i += 2)); do esc+="\\x${1:i:2}"; done
  exec 3<>"/dev/tcp/127.0.0.1/$rdp_port"
  # shellcheck disable=SC2059  # the format carries the request's own escapes
  printf "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00$esc" >&3
  reply_status=0
  timeout 5 head -c 19 <&3 >"$work/reply" || reply_status=$?
  exec 3<&- 3>&-
  reply=$(od -An -tx1 -v "$work/reply" | tr -d ' \n')
}

# A full Connection Confirm (status 0, 19 bytes) whose RDP_NEG_RSP selects $2.
selected() { # $1 = what, then the accepted protocols (hex, little-endian)
  local what=$1
  shift
  [ "$reply_status" = 0 ] && [ "${#reply}" = 38 ] || fail "$what: no Connection Confirm (status $reply_status): '$reply'"
  # Offsets in the hex reply: byte 11 is the RDP_NEG type (02 RSP, 03
  # FAILURE), bytes 15..18 the selected protocol.
  [ "${reply:22:2}" = 02 ] || fail "$what: not an RDP_NEG_RSP: '$reply'"
  local p
  for p in "$@"; do [ "${reply:30:8}" = "$p" ] && return 0; done
  fail "$what: selected ${reply:30:8}, want one of $*: '$reply'"
}

running_checks() { # $1 = uid:gid
  for path in /readyz /livez; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$admin_port$path")" = 200 ] ||
      fail "$path is not 200 unauthenticated as $1"
  done
  negotiate 03000000 # TLS | HYBRID: an NLA client
  selected "TLS|HYBRID as $1" 02000000
  negotiate 0b000000 # TLS | HYBRID | HYBRID_EX: Windows App's request
  selected "TLS|HYBRID|HYBRID_EX as $1" 02000000 08000000
  # TLS alone; standard RDP security. IronRDP at the pinned rev answers
  # neither with an RDP_NEG_FAILURE PDU: it returns before the write and
  # closes the connection (§9.1). A close is the refusal; a hang is not.
  for req in 01000000 00000000; do
    negotiate "$req"
    case $reply_status in
      0) ;;
      124) fail "requestedProtocols $req as $1: no answer and no close within 5 s" ;;
      *) fail "requestedProtocols $req as $1: reading the reply failed (status $reply_status)" ;;
    esac
    if [ "${#reply}" -ge 38 ]; then
      [ "${reply:22:2}" != 03 ] ||
        fail "requestedProtocols $req: IronRDP now answers RDP_NEG_FAILURE: update spec §9.1 ('$reply')"
      fail "requestedProtocols $req was answered with a protocol: '$reply'"
    fi
  done
  ok "as $1: /readyz and /livez 200; HYBRID selected; TLS-only and standard security closed unselected"
  local t0 t1 code logs
  t0=$(date +%s%N)
  docker stop -t 10 "$name" >/dev/null
  t1=$(date +%s%N)
  code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
  [ "$code" = 0 ] || fail "exit $code after SIGTERM as $1"
  [ $(((t1 - t0) / 1000000)) -le 6000 ] || fail "SIGTERM took $(((t1 - t0) / 1000000)) ms as $1"
  logs=$(docker logs "$name" 2>&1)
  grep -qF '"shutting down"' <<<"$logs" || fail "no shutdown line as $1"
  docker rm "$name" >/dev/null
  ok "as $1: SIGTERM → exit 0 in $(((t1 - t0) / 1000000)) ms"
}

for uid in 65532:65532 4242:4242; do
  start "$uid"
  running_checks "$uid"
done

# 4. Refused at load: each file, and the value its error must not echo (I1).
for check in hooks.toml:4711 stall.toml:4713 mode.toml:'"tls"'; do
  f=${check%%:*}
  value=${check#*:}
  set +e
  out=$(docker run --rm --read-only --user 65532:65532 "${mounts[@]}" \
    "$image" --config "/etc/kvm-rdp/$f" 2>&1)
  code=$?
  set -e
  [ "$code" = 2 ] || fail "$f: exit $code, want 2: $out"
  grep -qF 'unknown key' <<<"$out" || fail "$f: the error does not say unknown key: $out"
  if grep -qF -- "$value" <<<"$out"; then
    fail "$f: the error echoes the value $value: $out"
  fi
done
ok "[test] panic_after, [test] stall_on_sigusr1 and a security-mode key are unknown keys (exit 2, no value echoed): no test-hooks, no other mode"
echo "image-smoke: every check passes"
