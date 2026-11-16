#!/usr/bin/env bash
# Smoke-test kvm-rdp's image (Plan E Task 4.1): scripts/image-smoke.sh IMAGE
#  1. what it is: user 65532:65532, entrypoint kvm-rdp, MALLOC_ARENA_MAX=2,
#     at most MAX_MIB, no shell;
#  2. its binaries: no build-host path (PC15), kvm-probe runs;
#  3. under the restricted Pod Security profile (read-only root, no
#     capabilities, no-new-privileges), as 65532 and as an arbitrary UID,
#     with the deployment's ConfigMap and two Secrets mounted the way the
#     kubelet mounts them (`..<stamp>/`, a `..data` link, one link per file)
#     at /etc/kvm-rdp, /run/secrets/kvm-rdp and /run/secrets/kvm-rdp-tls:
#     /readyz and /livez answer unauthenticated; X.224 negotiation selects
#     HYBRID for an NLA client and closes TLS-only, standard security and a
#     legacy request with no RDP_NEG_REQ without a byte (§9.1, DE2); SIGTERM
#     exits 0 within 5 s (§5.2);
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
# The deployment's three volumes (deployment design §4.2, §4.5), each laid out
# as the kubelet's AtomicWriter lays out a ConfigMap or Secret volume: the
# files in a `..<stamp>` directory, `..data` linking to it, and one link per
# file through `..data` — the renewal path the bridge's watcher follows
# (bridge::tests::a_kubernetes_secret_swap_is_a_renewal):
#   /etc/kvm-rdp              the ConfigMap: config.toml (and check 4's files)
#   /run/secrets/kvm-rdp      Secret kvm-rdp-mac: kvm-password, nla-password
#   /run/secrets/kvm-rdp-tls  Secret kvm-rdp-mac-tls (cert-manager's): tls.crt, tls.key
stamp=..2026_10_15_00_00_00.1
cm=$work/configmap
sec=$work/secret
tls=$work/tls
mkdir -p "$cm/$stamp" "$sec/$stamp" "$tls/$stamp"
# A volume's links, once its files are in $1/$stamp.
atomic_dir() {
  local f
  ln -s "$stamp" "$1/..data"
  for f in "$1/$stamp"/*; do
    ln -s "..data/${f##*/}" "$1/${f##*/}"
  done
  chmod 0755 "$1" "$1/$stamp"
  chmod 0644 "$1/$stamp"/*
}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$tls/$stamp/tls.key" -out "$tls/$stamp/tls.crt" 2>/dev/null
printf 'image-smoke-nla-password-0123456789\n' >"$sec/$stamp/nla-password"
printf 'image-smoke-kvm-password\n' >"$sec/$stamp/kvm-password"
config() {
  cat <<EOF
[rdp]
listen = "0.0.0.0:3389"
username = "kvm"
nla_password_file = "/run/secrets/kvm-rdp/nla-password"
tls_cert_file = "/run/secrets/kvm-rdp-tls/tls.crt"
tls_key_file = "/run/secrets/kvm-rdp-tls/tls.key"
[admin]
listen = "0.0.0.0:9464"
[kvm]
host = "192.0.2.1"
spki_sha256 = "$(printf '0%.0s' $(seq 64))"
scheme = "https"
password_file = "/run/secrets/kvm-rdp/kvm-password"
EOF
}
config >"$cm/$stamp/config.toml"
# The two test-hooks keys (DE6), each with a value check 4 must not see echoed.
{ config; printf '[test]\npanic_after = "4711ms"\n'; } >"$cm/$stamp/hooks.toml"
{ config; printf '[test]\nstall_on_sigusr1 = "4713ms"\n'; } >"$cm/$stamp/stall.toml"
config | sed 's/^\[rdp\]$/[rdp]\nsecurity = "tls"/' >"$cm/$stamp/mode.toml"
for d in "$cm" "$sec" "$tls"; do atomic_dir "$d"; done
chmod 0755 "$work"
mounts=(-v "$cm:/etc/kvm-rdp:ro" -v "$sec:/run/secrets/kvm-rdp:ro" -v "$tls:/run/secrets/kvm-rdp-tls:ro")

start() { # $1 = uid:gid
  docker run -d --name "$name" --read-only --user "$1" --cap-drop ALL --security-opt no-new-privileges \
    "${mounts[@]}" -p 127.0.0.1::3389 -p 127.0.0.1::9464 \
    "$image" --config /etc/kvm-rdp/config.toml >/dev/null
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

# Sends $1 (hex) as one request on a fresh connection. Sets `reply` to what
# came back as hex — at most the 19 bytes of a Connection Confirm with an
# RDP_NEG_RSP — and `reply_status` to head's exit: 0 at 19 bytes or at the
# bridge's close, 124 when neither came within 5 s.
exchange() {
  local esc='' i
  for ((i = 0; i < ${#1}; i += 2)); do esc+="\\x${1:i:2}"; done
  exec 3<>"/dev/tcp/127.0.0.1/$rdp_port"
  # shellcheck disable=SC2059  # the format is the request's own escapes
  printf "$esc" >&3
  reply_status=0
  timeout 5 head -c 19 <&3 >"$work/reply" || reply_status=$?
  exec 3<&- 3>&-
  reply=$(od -An -tx1 -v "$work/reply" | tr -d ' \n')
}

# An X.224 Connection Request carrying an RDP_NEG_REQ for $1
# (requestedProtocols, little-endian hex).
negotiate() { exchange "030000130ee0000000000001000800$1"; }

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

# Refused as the wire shows it: closed at once with not one byte (no
# Connection Confirm at all, so no protocol — not even a legacy one).
refused() { # $1 = what
  case $reply_status in
    0) ;;
    124) fail "$1: no answer and no close within 5 s" ;;
    *) fail "$1: reading the reply failed (status $reply_status)" ;;
  esac
  [ -n "$reply" ] || return 0
  if [ "${#reply}" -ge 38 ] && [ "${reply:22:2}" = 03 ]; then
    fail "$1: IronRDP now answers RDP_NEG_FAILURE: update spec §9.1 ('$reply')"
  fi
  fail "$1: answered with $((${#reply} / 2)) bytes, want a close with none: '$reply'"
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
  # TLS alone; standard RDP security; and the legacy request with no
  # RDP_NEG_REQ, which asks for standard security. IronRDP at the pinned rev
  # answers none with an RDP_NEG_FAILURE PDU: it returns before the write and
  # closes the connection (§9.1). A close with nothing sent is the refusal; a
  # hang, or any Connection Confirm, is not.
  local req
  for req in 01000000 00000000; do
    negotiate "$req"
    refused "requestedProtocols $req as $1"
  done
  exchange 0300000b06e00000000000
  refused "a Connection Request with no RDP_NEG_REQ as $1"
  ok "as $1: /readyz and /livez 200; HYBRID selected; TLS-only, standard and legacy security closed with no reply"
  local t0 t1 finished fin code logs bridge_ms docker_ms
  t0=$(date +%s%N)
  docker stop -t 10 "$name" >/dev/null
  t1=$(date +%s%N)
  code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
  [ "$code" = 0 ] || fail "exit $code after SIGTERM as $1"
  # The bound is on the bridge's exit, by containerd's timestamp: `docker
  # stop`'s own time is mostly dockerd's work before the signal and after
  # the exit (ADV3 review: up to 13 s on a loaded host, against the
  # bridge's ≤ 50 ms), so it is printed, not bounded.
  finished=$(docker inspect -f '{{.State.FinishedAt}}' "$name")
  fin=$(date -d "$finished" +%s%N) || fail "cannot read FinishedAt '$finished' as $1"
  bridge_ms=$(((fin - t0) / 1000000))
  docker_ms=$(((t1 - t0) / 1000000))
  [ "$bridge_ms" -le 5000 ] || fail "SIGTERM took $bridge_ms ms as $1 (docker stop: $docker_ms ms)"
  logs=$(docker logs "$name" 2>&1)
  grep -qF '"shutting down"' <<<"$logs" || fail "no shutdown line as $1"
  docker rm "$name" >/dev/null
  ok "as $1: SIGTERM → exit 0 in $bridge_ms ms (docker stop: $docker_ms ms)"
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
