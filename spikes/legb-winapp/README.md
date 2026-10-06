# legb-winapp — Leg B spike (stock IronRDP vs a real RDP client)

THROWAWAY Milestone-0 spike. Not a workspace member, not built in CI (see
`spikes/README.md`). Replays a committed Annex-B H.264 fixture over EGFX
AVC420 against stock IronRDP HEAD (`38b074e`), with Hybrid/NLA,
`ConnectionPolicy::Preempt`, and `enable_autodetect()`.

**Client: FreeRDP 3.31.1, not Microsoft Windows App** (ruling R22, 2026-10-06
— Windows App is hard to test from this host, so every Windows-App run step
in Plan A's Part 7 becomes a FreeRDP run instead; see `docs/census.md`'s
Leg B section for which gates that defers to a later Windows App session).

## Run the server

```bash
LEGB_FIXTURE=$PWD/fixtures/large/1080p30_main_full.h264 \
RUST_LOG=info,legb_winapp=debug \
nice -n 19 cargo run --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```

Env vars:

| Var | Default | Meaning |
|---|---|---|
| `LEGB_FIXTURE` | *(required)* | Path to a committed Annex-B `.h264` fixture to replay. |
| `LEGB_W` / `LEGB_H` | `1920` / `1080` | Initial desktop size (should match `LEGB_FIXTURE`'s own resolution). |
| `LEGB_FIXTURE_RESIZE` | *(unset)* | Path to a second Annex-B fixture, at a different size, for the **real** resize path (stdin `resize`). Unset = `resize` logs an error and no-ops. |
| `LEGB_RESIZE_W` / `LEGB_RESIZE_H` | `1280` / `720` | Target size for `resize` (paired with `LEGB_FIXTURE_RESIZE`) **and** for `resize-channel` (the old, channel-only path — no second fixture, same stream, size change only). |

Example exercising both resize paths:

```bash
LEGB_FIXTURE=$PWD/fixtures/large/1080p30_main_full.h264 \
LEGB_W=1920 LEGB_H=1080 \
LEGB_FIXTURE_RESIZE=$PWD/fixtures/large/720p30_main_full.h264 \
LEGB_RESIZE_W=1280 LEGB_RESIZE_H=720 \
RUST_LOG=info,legb_winapp=debug \
nice -n 19 cargo run --manifest-path spikes/legb-winapp/Cargo.toml --jobs 4
```

The server listens on `0.0.0.0:3389` (`cfg::RDP_LISTEN` in `main.rs`), NLA
credentials `kvm` / `legb-spike-pw` (`cfg::NLA_USERNAME` / `NLA_PASSWORD`),
against a self-signed rcgen ECDSA certificate minted fresh each run (SAN
`kvm-bridge.spike`).

## Run the client (FreeRDP)

From the same host (or any host that can reach the server's port 3389),
with `nixpkgs#freerdp` and `nixpkgs#xvfb-run` (there's no display attached,
and the session's own `LD_LIBRARY_PATH` carries an incompatible `alsa-lib`,
hence the `-u`):

```bash
env -u LD_LIBRARY_PATH xvfb-run -a xfreerdp \
  /v:127.0.0.1:3389 /u:kvm /p:legb-spike-pw /sec:nla /gfx:AVC420 \
  /cert:ignore /log-level:INFO
```

`/cert:ignore` is safe here only because the cert is the spike's own
throwaway self-signed one. Swap the IP for the dev host's LAN address to
connect from a different machine.

## stdin commands

The server reads commands, one per line, from its own stdin while it is
running (type into the same terminal it's running in, then Enter):

| Command | Effect |
|---|---|
| `resize` | The **real** resize path (spec §6.4): emits `DisplayUpdate::Resize` on the active display-updates stream, waits for IronRDP's reactivation (its next `updates()` call, up to 10s), re-runs Setup at the new size, then switches the replayed stream to `LEGB_FIXTURE_RESIZE` starting at its first IDR. Needs `LEGB_FIXTURE_RESIZE` set at startup — without it, logs an error and no-ops. |
| `resize-channel` | The old path, kept for comparison: a channel-level Setup swap to `LEGB_RESIZE_W`×`LEGB_RESIZE_H` with **no** reactivation wait and **no** stream switch (same fixture keeps replaying at the new advertised size). This is what Task 5's `resize` did; the research saw it blink on Windows App. |
| `strand` | Stop sending frames (barcode-stranding gate — does the client just hold the last frame?). |
| `resume` | Resume sending frames after a `strand`. |

Any other line is logged as an unknown command and ignored.

## Census capture

`docs/census.md`'s "Leg B — FreeRDP 3.31.1 (direct)" section is the
pass/fail checklist this run is meant to fill in. Items marked "deferred —
Chris's acceptance" (key matrix/typematic, ErrorInfo dialogs, Windows App
colour/VUI handling) have no FreeRDP equivalent and wait for a real Windows
App session.
