# Live integration (audit L3 / wave 6)

keystore has no third-party network peers; its "real systems" are the OS and the tools it touches.
This tier runs the suite and the interop checks against those, on a real Linux kernel (Apple
`container`, arm64) and a real OpenSSL 3.5. It complements the hermetic suite and never replaces it.

## What each tier proves, and what it does not reach

| Tier | Proves | Does not reach |
|---|---|---|
| Linux containers (alpine 3.23, debian 13 trixie-slim; kernel 6.18.15, arm64), each as root and as uid 1000 | the whole test suite (20 packages incl. the six `examples/*` scripts) passes on Linux/arm64 with `CGO_ENABLED=0`; peercred on the real `SO_PEERCRED` path; file modes under umask 000; `flock` contention on ext4 (0xef53) and tmpfs (0x1021994) | `-race` (needs cgo); amd64; a real host's systemd or a real multi-user machine; macOS-only paths |
| `integration/linuxlive` (inside the containers) | modes of ring / default dir / exported key / agent socket; a held ring lock blocks `add` for about `LockTimeout` and then releases; same-uid agent signing; as root, an agent owned by uid 1000 is refused by the root client ("served by uid 1000") and the agent drops a root peer without answering (root passes the socket's mode bits, so only the peer-uid check can have done it) | agent under contention, crash loops, TTL at scale (wave 7) |
| `integration/interop` (OpenSSL 3.5.x; skips on the host's LibreSSL 3.3.6) | keystore signature verified by `openssl pkeyutl -verify`, and a tampered message rejected; OpenSSL signature verified by `keystore verify` (exit 0; tampered gives exit 3); an OpenSSL key imported into a ring signs byte-identical signatures (Ed25519 is deterministic); export-pub / export-priv parse in `openssl pkey` and describe the same key; ring fingerprint equals SHA-256 of the SPKI DER OpenSSL emits; `kdf.Derive` equals `openssl kdf ARGON2ID` | other OpenSSL versions, other implementations |
| Classifier (`integration/container_test.go`, hermetic) | no `container` binary, system not running, image missing, the container never reaching our script, package install failure: SKIP with reason. Failing test, build error, run that ends without the final marker, deadline after start: FAIL. A run also FAILs unless it reports exactly one `rc=0` result per staged test binary for each of uid 0 and uid 1000 (so an empty manifest, a missing leg or a test that eats manifest lines cannot pass by omission) and every package passed at least one test (all-skipped is not a pass). Test binaries run with `</dev/null` and the manifest is read on fd 3 | whether a real runtime fault is mislabelled outside those cases |
| macOS login keychain (`integration/keychain`) | designed, double-gated, **not executed** | everything: see `untestable-without-x.md` |

## How to run

```
integration/run.sh        # = GOWORK=off KEYSTORE_LIVE=1 go test -tags integration -count=1 -v -timeout 60m ./integration/ ./integration/interop/
```

Needs `container` running (`container system start`), images `alpine:latest` and `debian:trixie-slim`
pulled (never pulled for you), and network in the container (installs bash, openssl, setpriv; no Go
toolchain is in the image, so a `go` shim in the staging dir copies the prebuilt binaries for
the example scripts). The tier is excluded from `go test ./...` and the gate: every file carries
`//go:build integration`, each test also needs `KEYSTORE_LIVE=1` and refuses `-short`.
`go vet -tags integration ./...` and staticcheck with the tag are clean.

## Results (2026-10-19, this Mac: container 1.5.0, Go 1.27.2)

Alpine run (final):

```
KSL3 BEGIN Alpine Linux v3.23 aarch64 kernel 6.18.15
KSL3 INFO OpenSSL 3.5.9 29 Sep 2026 ... setpriv=/bin/setpriv
--- PASS: TestLinuxTier/alpine_latest (108.96s)
ok  github.com/netstar-labs/keystore/integration  116.861s
```

Debian run: `KSL3 BEGIN Debian GNU/Linux 13 (trixie)`, OpenSSL 3.5.7, `--- PASS: TestLinuxTier/debian_trixie-slim (129.15s)`.
In both, 40 of 40 (package x uid) results had `rc=0`; `integration/interop` ran 4 tests with 0 skipped, as root and as uid 1000;
`integration/linuxlive` 3/3 at root and 2 pass + 1 skip at uid 1000 (`TestPeerCredAcrossUIDs` runs its same-uid half, then skips the cross-uid half by design; the root leg runs it).
After review the runs were repeated with the exact-count classifier and stdin isolation: 80 of 80 `rc=0` (40 per image), also with a temporary test that drains stdin planted in `cmd/keystore` (it no longer shortens the run).
Skips recorded by the runner: `cmd/keystore` 2 (root), `internal/term` 1, `internal/passphrase` 1 (uid 1000), `pkg/agent` 1 (root): hermetic tests' own skips.

Host (macOS): classifier tests pass; interop skips ("need OpenSSL 3.x, have LibreSSL"); keychain skips (gate).

The first runs failed for reasons in the harness, not keystore (recorded so a reader does not think they hid something):
busybox `setpriv` has no `--reuid` (uid 1000 leg never started: alpine needs the `setpriv` package), a root-owned
`a.sock.lock` left by my own test blocked the uid-1000 agent, and a `sed` delimiter bug in the runner's skip report.

## Defects found

None in keystore. No production code is touched on this branch. (So no live-found-to-hermetic regression test is owed.)
The classifier and harness bugs above are covered by the final runs, and the classifier by its hermetic table.

## Limits worth knowing

* The Linux suite runs without `-race` (static, cgo off). Run it on a Linux host for that.
* An in-container hang or VM crash after the script began is classified FAIL, not skip: a hang hides a keystore bug more often than it hides an environment one.
* Both images install packages at run time from public mirrors; a mirror outage skips, it does not fail.
* uid 1000 is dropped with `setpriv` inside a root container, not `--uid`, so the container's rootfs and mounts are the same for both legs.
