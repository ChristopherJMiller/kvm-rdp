#!/usr/bin/env bash
# Build kvm-rdp's image reproducibly (Plan E Task 4.1, DE1):
#   scripts/image-build.sh OUT.oci.tar [buildx args for the archive's build]
# writes the OCI archive CI's `publish` pushes and loads the same image as
# kvm-rdp:ci for scripts/image-smoke.sh. One commit builds one image: the
# Dockerfile's pinned bases, this BuildKit, SOURCE_DATE_EPOCH = the commit
# time, rewrite-timestamp, and no attestation manifests in the index. A tree
# with uncommitted changes in the build context is refused (it would ship
# under HEAD's revision and time) unless IMAGE_BUILD_DIRTY=1, which labels
# the image `<HEAD>-dirty`.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: image-build.sh OUT.oci.tar [buildx args...]}
shift
# moby/buildkit's buildx-stable channel, pinned by digest (check-workflows rule 6).
BUILDKIT_IMAGE=docker.io/moby/buildkit:buildx-stable-1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea
builder=kvm-rdp-image
# What the build reads: .dockerignore's allowlist, and the two files that
# define the build.
context=(Dockerfile .dockerignore Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml
  crates fixtures/slate_1080p.h264)
revision=$(git rev-parse HEAD)
dirty=$(git status --porcelain -- "${context[@]}")
if [ -n "$dirty" ]; then
  if [ "${IMAGE_BUILD_DIRTY:-}" != 1 ]; then
    echo "image-build: uncommitted changes in the build context (IMAGE_BUILD_DIRTY=1 to build anyway, labelled -dirty):" >&2
    echo "$dirty" >&2
    exit 1
  fi
  revision=$revision-dirty
fi
# A builder made before a BUILDKIT_IMAGE bump keeps the old BuildKit: remake it.
info=$(docker buildx inspect "$builder" 2>/dev/null || true)
if [ -n "$info" ] && ! grep -qF "image=\"$BUILDKIT_IMAGE\"" <<<"$info"; then
  docker buildx rm "$builder" >/dev/null
  info=
fi
if [ -z "$info" ]; then
  # §13's politeness on the shared host: CPU shares 205 of 1024 (≈ the cargo
  # wrapper's CPUWeight 20) and 8 GiB, like `cargo` there.
  docker buildx create --name "$builder" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" --driver-opt cpu-shares=205 --driver-opt memory=8g >/dev/null
fi
common=(--builder "$builder" --platform linux/amd64 --provenance=false --sbom=false
  --build-arg "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)"
  --build-arg "REVISION=$revision")
docker buildx build "${common[@]}" "$@" --output "type=oci,dest=$out,rewrite-timestamp=true" .
docker buildx build "${common[@]}" --output "type=docker,name=kvm-rdp:ci,rewrite-timestamp=true" .
# The builder's cache lives on the host's root filesystem, outside
# target-budget.sh: keep it to 8 GB (the Dockerfile's RUN already drops the
# release target, the registry and git checkouts).
docker buildx prune --builder "$builder" --force --max-used-space 8gb >/dev/null
manifest=$(tar -xOf "$out" index.json | jq -r '.manifests[0].digest')
config=$(tar -xOf "$out" "blobs/sha256/${manifest#sha256:}" | jq -r '.config.digest')
config_json=$(tar -xOf "$out" "blobs/sha256/${config#sha256:}")
# The loaded image is the archive's: the same layers and creation time —
# what both image stores report alike. `.Id` is the config digest only in
# the classic store (under containerd's it is the manifest's), so it is
# compared only there.
want_layers=$(jq -c '.rootfs.diff_ids' <<<"$config_json")
want_created=$(jq -r '.created' <<<"$config_json")
got_layers=$(docker image inspect -f '{{json .RootFS.Layers}}' kvm-rdp:ci)
got_created=$(docker image inspect -f '{{.Created}}' kvm-rdp:ci)
if [ "$got_layers" != "$want_layers" ] || [ "$got_created" != "$want_created" ]; then
  echo "image-build: the loaded image is not the archive's: layers $got_layers vs $want_layers, created $got_created vs $want_created" >&2
  exit 1
fi
store=$(docker info 2>/dev/null || true)
if ! grep -qF io.containerd.snapshotter <<<"$store"; then
  loaded=$(docker image inspect -f '{{.Id}}' kvm-rdp:ci)
  if [ "$config" != "$loaded" ]; then
    echo "image-build: the loaded image ($loaded) is not the archive's ($config)" >&2
    exit 1
  fi
fi
echo "image-build: manifest $manifest, config $config, layers $got_layers"
