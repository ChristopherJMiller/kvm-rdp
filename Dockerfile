# kvm-rdp's container image (spec §4.1: it ships kvm-rdp and kvm-probe;
# Plan E Task 4.1, DE1). Build it with scripts/image-build.sh, which passes
# SOURCE_DATE_EPOCH (the commit time) and rewrite-timestamp=true on a
# pinned BuildKit, so one commit builds one image.
#
# Both bases are pinned by digest (scripts/check-workflows.sh refuses an
# unpinned one); bump them with scripts/pin-image.sh at the monthly IronRDP
# pin review (§4.2).
ARG BUILDER=docker.io/library/rust:1.94.1-slim-trixie@sha256:cf09adf8c3ebaba10779e5c23ff7fe4df4cccdab8a91f199b0c142c53fef3e1a
ARG RUNTIME=gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2

FROM ${BUILDER} AS build
# The builder's 1.94.1, named so rustup ignores rust-toolchain.toml's extra
# components (no download in the build). CARGO_HOME is the image's.
ENV RUSTUP_TOOLCHAIN=1.94.1 \
    CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/target \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=false \
    CARGO_PROFILE_RELEASE_STRIP=debuginfo
# PC15 (Plan C final review, parked #9): no build path reaches an error
# message — IronRDP's errors render a source `Location` — so the registry
# and git checkouts read as /cargo, this tree as /kvm-rdp.
ENV RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/src=/kvm-rdp"
# The remap does not reach an `env!` string: kvm-probe's captures directory
# (anchored at CARGO_MANIFEST_DIR in a checkout) is named outright, so no
# build path ships in it either (PC15). rustc reads it; nothing does at run
# time.
ENV KVM_PROBE_CAPTURES_DIR=/captures
WORKDIR /src
COPY . .
# The release target, the registry and the git checkouts are deleted in the
# same RUN: BuildKit's cached layer then holds only /out, not several GiB of
# IronRDP's build on the host's root filesystem (§13; the image and its
# reproducibility are unchanged).
RUN cargo build --release --locked -p kvm-rdp -p kvm-probe --bins \
 && install -D -m 0755 /target/release/kvm-rdp /out/usr/local/bin/kvm-rdp \
 && install -D -m 0755 /target/release/kvm-probe /out/usr/local/bin/kvm-probe \
 && rm -rf /target /usr/local/cargo/registry /usr/local/cargo/git
# One commit, one image, whatever the builder's cache holds (PE10 review
# I1): rewrite-timestamp only clamps times newer than SOURCE_DATE_EPOCH, and
# BuildKit keys a COPY on content, not times — so a cached /out (or a cached
# copy of it) from a build before the commit would ship that build's clock.
# The binaries are stamped with the epoch in a directory named for it, which
# no other commit's copy can match; image-build.sh checks the layer.
ARG SOURCE_DATE_EPOCH
RUN : "${SOURCE_DATE_EPOCH:?build with scripts/image-build.sh}" \
 && mkdir "/out-${SOURCE_DATE_EPOCH}" && cp -a /out/. "/out-${SOURCE_DATE_EPOCH}/" \
 && find "/out-${SOURCE_DATE_EPOCH}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM ${RUNTIME}
ARG REVISION=unknown
ARG SOURCE_DATE_EPOCH
COPY --from=build /out-${SOURCE_DATE_EPOCH}/ /
# The condition §10.1's soak runs under; glibc reads it — the bridge itself
# reads no environment but KVM_RDP_CONFIG (§4.4).
ENV MALLOC_ARENA_MAX=2
# distroless's nonroot user, by number, so runAsNonRoot can verify it.
USER 65532:65532
EXPOSE 3389/tcp 9464/tcp
LABEL org.opencontainers.image.source="https://github.com/ChristopherJMiller/kvm-rdp" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.description="RDP bridge for the ES3 IP-KVM: kvm-rdp, with kvm-probe"
ENTRYPOINT ["/usr/local/bin/kvm-rdp"]
