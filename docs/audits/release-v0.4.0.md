# Release v0.4.0 — prepared, not yet tagged

*Status: pre-flight complete on `feat/v0.4.0-release` at `3beadf0`. Tagging, pushing and
publishing need sign-off and a remote; neither exists yet.*

## Version rationale

First tag. The roadmap and user guide number the feature sets v0.1.0–v0.3.0, which were
built and merged locally but never tagged; tagging the complete set as **v0.4.0** keeps the
docs' "Release" column true. v0-forever policy: no v1, no `/vN` module path. The ring format
is separately versioned (`keystore/v1`) and is the compatibility contract.

## Release notes

**Additions**

- Encrypted ring (`keystore/v1`): Ed25519 signing keys and opaque secrets, argon2id
  (64 MiB, t=3, p=1) → AES-256-GCM, associated data binding format, kind, id, public key and
  every KDF parameter. Locked, re-read-under-lock, atomic and durable writes.
- CLI `keystore`: `init keygen add import list use rm export-pub export-priv add-secret
  import-secret export-secret passwd keychain-set sign verify`. No passphrase flag; sources
  are env → keychain → passfile → no-echo prompt; 12-character minimum when establishing.
- `keystore-agent` and `pkg/agent`: one key in memory, owner-only socket, peer-uid check both
  ways, TTL/idle expiry, exclusive ownership of the socket path.
- Six machine-to-machine examples, each run by `go test`.
- Release tooling: `build/keystore --release` (four platforms, SHA256SUMS, SPDX SBOM,
  THIRD-PARTY-NOTICES); CI on Linux and macOS with pinned analyzers and a fuzz budget.

**Fixes from the pre-release adversarial review** (each with a regression test that failed
before the fix)

| # | Severity | Fix | Commit |
|---|---|---|---|
| F1 | high | Agent stop closes open connections; a busy connection no longer keeps the key alive past TTL/idle/SIGTERM | 6b9113f |
| F2 | medium | Out-of-range `created` rejected; `Marshal` refuses output `Parse` would reject | 92ab347 |
| F3 | medium | Symlinked ring paths resolved before lock and write | cb06370 |
| F4 | low | Socket path owned by an exclusive lock; racing agents cannot orphan one another | f757f48 |
| minors | low | Bounded key-file reads, FIFO passfile cannot block, failed exports leave no partial file, no passphrase buffer regrowth | 8d062a9 |

Documented, not fixed (SECURITY.md "Known limits"): keychain hex for non-ASCII passphrases,
CPU cost of a crafted ring, case-insensitive/duplicate JSON keys, CLI-only length minimum.

**Breaking:** none (first release).

## Pre-flight results (all run on macOS arm64, Go 1.27.2)

| Gate | Result |
|---|---|
| `gofmt -l .` | empty |
| `go build ./...`, `go vet ./...` | clean |
| `GOOS=linux go vet ./...`, `GOOS=linux GOARCH=arm64 go build ./...` | clean |
| staticcheck v0.8.2 | clean |
| deadcode (x/tools v0.52.0) | only `Keystore.Path` (public library API) |
| `go mod tidy` | no diff |
| govulncheck v1.9.0 | 0 affecting; module-level `x/crypto/openpgp` (not imported, no fix) |
| `go test -race -count=1 ./...` | 18/18 packages ok, including the six examples |
| golden fixture (`testdata/golden.ks`, written in v0.1.0) | opens, unlocks, signs, secret matches |
| fuzz `FuzzParse` 30 s, `FuzzReadFrame` 30 s | pass |
| reproducible binaries | byte-identical across two clean-cache builds (linux/amd64, darwin/arm64) |
| adversarial review | done; findings above |
| private-name screen (tracked files + all commit messages) | clean; only `@zxdev` (owner) in CODEOWNERS |

**Not run:** Linux runtime (peer credentials, examples) — CI `ci` job covers it on first
push; real cross-uid agent rejection (needs a second account); `systemd-analyze verify`
(not installed; CI runs it); an SPDX validator (structure checked by script only); OpenSSL 3
interop on exported PEM (system LibreSSL lacks Ed25519).

## Build

```sh
build/keystore --release
# = GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=true \
#     -ldflags "-s -w -X main.version=v0.4.0 -X main.build=<rev>" ./cmd/keystore ./cmd/keystore-agent
#   for linux/{amd64,arm64} darwin/{amd64,arm64}; toolchain go1.27.2 (pinned in go.mod)
```

## Third-party notices shipped

`THIRD-PARTY-NOTICES` (BSD-3-Clause: Go standard library, golang.org/x/crypto v0.56.0,
golang.org/x/sys v0.47.0) inside every install package and release archive, installed to
`/usr/local/share/doc/keystore/`.

## To publish (needs sign-off)

1. Create the GitHub repo `netstar-labs/keystore` (private), push `main`, let CI go green.
2. `git tag -a v0.4.0 <sha> -m "keystore v0.4.0"` and push the tag.
3. `build/keystore --release`; `gh release create v0.4.0 --latest` with the archives,
   SHA256SUMS and these notes.
4. Verify from a clean environment: `go install github.com/netstar-labs/keystore/cmd/keystore@v0.4.0`.
5. Going public: add Apache-2.0 `LICENSE` (copyright holder per house policy), re-run the
   private-name screen, set description, topics (`go`, `cryptography`, `security`, `cli`,
   `library`) and homepage `https://pkg.go.dev/github.com/netstar-labs/keystore`.

## Rollback

Delete the GitHub release and the tag (`gh release delete v0.4.0 && git push --delete
origin v0.4.0`); if the module proxy has already fetched it, add a `retract v0.4.0` line to
`go.mod` in a v0.4.1 release.
