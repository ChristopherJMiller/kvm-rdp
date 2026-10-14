# kvm-rdp

An RDP server for a commodity IP-KVM. It logs in to the KVM, passes the KVM's
H.264 video through to the RDP client untouched (EGFX AVC420, via
[IronRDP](https://github.com/Devolutions/IronRDP)), and turns the client's
keyboard and mouse into the KVM's USB-HID frames. Any RDP client — Windows
App on macOS included — can then drive whatever machine the KVM is plugged
into, with no browser and no re-encode.

The first target is the Angeet/Yeeso ES3 ("ONE KVM").

**Status:** in development (Milestone 3a). The bridge runs: NLA-only RDP
with EGFX AVC420 passthrough of the KVM's H.264, one session at a time (a
new authenticated client takes over), the KVM's control websocket and HID
writer, admin endpoints and a graceful shutdown — tested against `kvm-sim`
with an in-process IronRDP client. Keyboard and mouse mapping, paste and
clipboard come next (Milestone 3b), after the hardware checks they depend
on; the bridge has not yet driven the real device.

The design, and every decision behind it, is
[the spec](docs/superpowers/specs/2026-10-05-kvm-rdp-design.md).

## Security model

> **The KVM is hostile.** The ES3 has an unpatched pre-auth root RCE
> (CVE-2026-32297 / CVE-2026-32298). Never expose it to a network anything
> untrusted can reach; put it on an isolated segment that only this bridge
> can talk to, and treat its video stream as hostile input.

- **Everything from the KVM is untrusted input.** The FLV and H.264 it sends
  go through hardened, fuzzed parsers (`kvm-proto`) with every size checked
  before anything is buffered; only allowlisted NAL types reach the client.
  The KVM's TLS certificate is pinned by the SHA-256 of its public key, and
  there is no accept-any mode. Slice data cannot be sanitised without
  decoding, so a compromised KVM could still target the client's video
  decoder — containment is the answer.
- **A compromised KVM sees every keystroke** sent through the bridge,
  passwords typed into the target machine included. Don't paste secrets
  through it.
- **NLA (CredSSP) is the only mode.** The bridge is built with Hybrid
  security only — no TLS-only or plain RDP security exists in any build. A
  client that does not offer NLA is refused during negotiation with a plain
  disconnect, not a "CredSSP required" message, so it reports a generic
  connection failure.
- **One user, one password.** RDP clients log in as `rdp.username`
  (default `kvm`, compared exactly; a `DOMAIN\` prefix is ignored) with the
  NLA password. NTLM needs the password stored recoverably: generate at
  least 128 random bits (the bridge refuses one under 22 characters).
- **TLS** uses the bridge's own rustls configuration on aws-lc-rs;
  `SSLKEYLOGFILE` is never honoured. The certificate's key type and size are
  logged when the bridge starts (`TLS identity loaded`). Neither RSA nor
  ECDSA is refused — which one Windows App accepts for NLA is an open
  acceptance check, and the spec ships RSA until then; a key aws-lc-rs
  cannot sign with (RSA under 2048 bits) is refused at startup.
- **The bridge never logs out of the KVM.** The ES3's logout is global: one
  session's logout invalidates every token, including the vendor web UI's
  break-glass session. The bridge closes its websocket and video streams
  and lets its token lapse instead.
- **Secrets come only from files** named in the config, and are never
  logged; nor are tokens, keystrokes or HID frames. The bridge reads no
  environment variable but `KVM_RDP_CONFIG` — not even `RUST_LOG`; the
  libraries that log credentials or payloads at debug level are capped at
  INFO whatever `log.filter` says.
- **A config error never echoes the file.** It names the path and either a
  line and column with a fixed category such as `unknown key` or `wrong value
  type`, or — for a value that parses but breaks a rule — the key and the
  rule. That is on purpose: pointed at a secret by mistake (`--config nla.pass`), or
  given a config with an inline password, the bridge must not print it.
  Open the file at the reported position. Nor does any error, log line or
  debug output show a `*_file` key's value — a password written where the
  file name goes, or a pasted PEM, stays unprinted: a file that cannot be
  read is named by its key (`rdp.nla_password_file: cannot read the file:
  entity not found`).
- **One session at a time.** A new authenticated client takes the session
  over; connection attempts are rate-limited (30 admitted per 60 s by
  default).
- **The admin endpoints are unauthenticated.** Expose them to your
  monitoring only (a NetworkPolicy or a host firewall). Requests are
  bounded in size and time, and at most 32 connections are served at once.

## Running

    kvm-rdp --config /etc/kvm-rdp/kvm-rdp.toml

(or `KVM_RDP_CONFIG`; no other environment variable is read). A minimal
config — every other key has the spec's default (§4.4):

```toml
[rdp]
nla_password_file = "nla.pass"   # at least 22 characters
tls_cert_file = "tls.crt"
tls_key_file = "tls.key"

[kvm]
host = "192.0.2.10"
# The KVM certificate's SPKI SHA-256 (64 hex digits):
# `kvm-probe fingerprint --host 192.0.2.10 --port 443` prints it; this one is an example.
spki_sha256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
password_file = "kvm.pass"
```

Secret files are read relative to the config's directory (the password
files at most 4 KiB with one trailing line ending trimmed, the PEM files at
most 64 KiB) and are never logged.

- The RDP listener defaults to `0.0.0.0:3389`; `/metrics`, `/livez` and
  `/readyz` listen on `0.0.0.0:9464` (`admin.listen`). `/readyz` never
  checks the KVM; `/livez` fails when the RDP side stops making progress.
- Logs are JSON lines on stdout, filtered by `log.filter` (default `info`).
  A config or logging error is one line on stderr, before anything binds.
- On SIGTERM or SIGINT the bridge stops accepting, releases every key on the
  KVM, disconnects the client (ErrorInfo 0x1), closes the KVM connections —
  never logging out — and exits 0 within 5 s.
- A renewed TLS certificate (polled every 60 s) runs the same shutdown once
  no client is connected — a live session is never cut for a renewal — so
  the supervisor restarts the bridge on the new pair.
- Exit codes: 0 after a signal or a certificate change, 1 if startup failed
  or the RDP server stopped on its own, 2 on a config or logging error.

## Development

`nix develop` provides the pinned toolchain; its `cargo` is niced and
memory-capped, and every long-lived worktree shares one target dir
(disposable scratch worktrees use their own and delete it).

- `cargo test --workspace --all-features` — unit, property, fixture and
  kvm-sim tests, the bridge's sans-IO state-machine tests, and its full-stack
  tests: the bridge, `kvm-sim` and an in-process IronRDP client on private
  loopback addresses, plus the real binary under SIGTERM (every fuzz
  target's body also runs over its seeds here).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
  `scripts/target-budget.sh` fails above 8 GiB of target (IronRDP's graph
  is large; `cargo clean` is always safe).
- `scripts/gen-fixtures.sh` — regenerate the committed synthetic fixtures.
  Fixtures never come from a real KVM.
- Fuzzing runs in CI only (spec §13): every kvm-proto target for 5 s on each
  PR and 300 s nightly, through `scripts/fuzz.sh`, which validates its own
  arguments and caps time, memory, input size and corpus size. To replay a
  crash CI uploaded:
  `nix develop .#fuzz -c sh -c 'cargo fuzz run --fuzz-dir fuzz --target-dir "$CARGO_TARGET_DIR/fuzz-build" -a <target> <artifact>'` (the same `-a` build CI uses, inside the dir `scripts/fuzz.sh clean` removes).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
