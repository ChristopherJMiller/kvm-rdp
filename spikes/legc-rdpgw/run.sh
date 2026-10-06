#!/usr/bin/env bash
# THROWAWAY Leg C runner (Task 7.7) — loopback only, run from the repo root.
# Expects legb-winapp listening on 127.0.0.1:${LEGB_PORT:-23389} by the time a
# client connects (Task 6; LEGB_LISTEN=127.0.0.1:23389). No sudo: all state lives in
# spikes/legc-rdpgw/{state,src,bin,gomod}/ (gitignored); cleanup is one rm -rf
# (chmod -R u+w gomod first — Go's module cache is read-only).
#
#   bash spikes/legc-rdpgw/run.sh            # rdpgw :9443 + header proxy :8443
#   LEGC_CLIPBOARD=false bash spikes/...     # reproduce the brief's config (no
#                                            # Caps.EnableClipboard → client
#                                            # told to disable clipboard)
#   LEGC_VERIFY_IP=true bash spikes/...      # pin the token to the client IP
#                                            # (works via the proxy's XFF)
# Then fetch the .rdp through the proxy (exercises /connect → header auth →
# HandleDownload) and open it with the client:
#   curl -sk -o spikes/legc-rdpgw/state/legc.rdp https://127.0.0.1:8443/connect
set -euo pipefail
S=spikes/legc-rdpgw
GW_PORT=9443
PROXY_PORT=8443
LEGB_PORT=${LEGB_PORT:-23389}
GO=${GO:-nix shell nixpkgs#go --command go}
PY=${PY:-nix shell nixpkgs#python3 --command python3}
OPENSSL=${OPENSSL:-nix shell nixpkgs#openssl --command openssl}

[ -f "$S/rdpgw.yaml" ] || { echo "run from the repo root" >&2; exit 1; }
mkdir -p "$S/state" "$S/bin" "$S/gomod"
chmod 0700 "$S/state"

listening() { ss -Hltn "sport = :$1" | grep -q .; }
for p in "$GW_PORT" "$PROXY_PORT"; do
  if listening "$p"; then echo "port $p is already in use" >&2; exit 1; fi
done
listening "$LEGB_PORT" || echo "warning: legb-winapp is not listening on :$LEGB_PORT yet" >&2

# 1. Self-signed loopback cert (shared by rdpgw and the header proxy), 2 days.
[ -f "$S/state/server.pem" ] || $OPENSSL req -x509 -newkey rsa:2048 -nodes \
  -keyout "$S/state/key.pem" -out "$S/state/server.pem" \
  -subj "/CN=legc-rdpgw.spike" -addext "subjectAltName=IP:127.0.0.1" -days 2 2>/dev/null
chmod 0600 "$S/state/key.pem"

# 2. Render the config with a fresh 32-char PAA key into the gitignored state
#    dir. The committed template keeps its placeholder — never sed the key into
#    a tracked file.
KEY="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 || true)"
[ "${#KEY}" -eq 32 ] || { echo "PAA key generation failed" >&2; exit 1; }
umask 077
sed -e "s/__PAA_SIGNING_KEY__/${KEY}/" \
    -e "s/__LEGB_PORT__/${LEGB_PORT}/" \
    -e "s/__LEGC_CLIPBOARD__/${LEGC_CLIPBOARD:-true}/" \
    -e "s/__LEGC_VERIFY_IP__/${LEGC_VERIFY_IP:-false}/" \
    "$S/rdpgw.yaml" > "$S/state/rdpgw.yaml"
unset KEY
# .rdp defaults: the fixed RDP user of the bridge (rdpgw.yaml Client.NoUsername).
printf 'username:s:kvm\r\n' > "$S/state/defaults.rdp"

# 3. rdpgw built from source at the commit this spike was grounded on (16cdaaf).
#    rdpgw does not commit go.sum; its Makefile's `mod` target runs
#    `go mod tidy` first. Module + build caches stay inside the spike dir.
if [ ! -x "$S/bin/rdpgw" ]; then
  [ -d "$S/src" ] || git clone --quiet https://github.com/bolkedebruin/rdpgw "$S/src"
  git -C "$S/src" checkout --quiet 16cdaaf
  ( cd "$S/src" && export GOMODCACHE="$PWD/../gomod/mod" GOCACHE="$PWD/../gomod/build-cache" \
      GOTOOLCHAIN=local GOMAXPROCS=4 GOFLAGS=-p=4 CGO_ENABLED=0 \
    && nice -n 19 $GO mod tidy -compat=1.22 \
    && nice -n 19 $GO build -trimpath -o ../bin/rdpgw ./cmd/rdpgw )
fi

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

"$S/bin/rdpgw" -c "$PWD/$S/state/rdpgw.yaml" >"$S/state/rdpgw.log" 2>&1 &
PIDS+=($!)

# 4. The header-injecting proxy for /connect (:8443 → 127.0.0.1:9443, from
#    127.0.0.2 = Header.TrustedProxies).
LEGC_STATE="$S/state" $PY "$S/header-proxy.py" >"$S/state/proxy.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 150); do   # first `nix shell` evaluation can take seconds
  listening "$GW_PORT" && listening "$PROXY_PORT" && break
  sleep 0.2
done
listening "$GW_PORT" || { echo "rdpgw did not start; see $S/state/rdpgw.log" >&2; exit 1; }
listening "$PROXY_PORT" || { echo "proxy did not start; see $S/state/proxy.log" >&2; exit 1; }
echo "rdpgw https://127.0.0.1:$GW_PORT, header proxy https://127.0.0.1:$PROXY_PORT/connect" >&2
wait -n "${PIDS[@]}" || true   # either one exiting tears both down
