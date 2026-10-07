# kvm-rdp

An RDP server for a commodity IP-KVM. It logs in to the KVM, passes the KVM's
H.264 video through to the RDP client untouched (EGFX AVC420, via
[IronRDP](https://github.com/Devolutions/IronRDP)), and turns the client's
keyboard and mouse into the KVM's USB-HID frames. Any RDP client — Windows
App on macOS included — can then drive whatever machine the KVM is plugged
into, with no browser and no re-encode.

The first target is the Angeet/Yeeso ES3 ("ONE KVM").

**Status:** in development. `kvm-proto` (hardened FLV/H.264 admission, the
SPS rewriter, HID frames) and `kvm-sim` (a fake ES3 for tests) are built and
tested; the bridge itself does not run yet.

## Development

`nix develop` provides the pinned toolchain; its `cargo` is niced and
memory-capped, and every worktree shares one target dir.

- `cargo test --workspace --all-features` — unit, property, fixture and
  kvm-sim tests (every fuzz target's body also runs over its seeds here).
- `scripts/gen-fixtures.sh` — regenerate the committed synthetic fixtures.
  Fixtures never come from a real KVM.
- Fuzzing runs in CI only (spec §13): every kvm-proto target for 5 s on each
  PR and 300 s nightly, through `scripts/fuzz.sh`, which validates its own
  arguments and caps time, memory, input size and corpus size. To replay a
  crash CI uploaded:
  `nix develop .#fuzz -c sh -c 'cargo fuzz run --fuzz-dir fuzz --target-dir "$CARGO_TARGET_DIR/fuzz-build" -a <target> <artifact>'` (the same `-a` build CI uses, inside the dir `scripts/fuzz.sh clean` removes).

> **Security note.** The ES3 has an unpatched pre-auth root RCE
> (CVE-2026-32297 / CVE-2026-32298). Never expose it to a network anything
> untrusted can reach; put it on an isolated segment that only this bridge
> can talk to, and treat its video stream as hostile input.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
