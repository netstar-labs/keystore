# keystore

An encrypted, single-file keyring for Ed25519 signing keys and opaque secrets — with a CLI,
a Go library and a signing agent, so a private key never has to sit in a plaintext file or be
handed to the process that uses it.

```
   operator                      ring file (0600, JSON)                    workload
 ┌──────────┐  keygen/add   ┌──────────────────────────────┐   Signer()   ┌──────────────┐
 │ keystore ├──────────────►│ id · kind · pub (cleartext)  ├─────────────►│ your Go code │
 │   CLI    │  passphrase   │ argon2id → AES-256-GCM(priv) │  passphrase  └──────────────┘
 └────┬─────┘               └──────────────┬───────────────┘
      │ export-pub                         │ unlock once at start
      ▼                                    ▼
  verifiers pin the            ┌──────────────────────┐  sign over 0600   ┌──────────────┐
  public key (PEM)             │   keystore-agent     │◄──── unix socket ─┤ any process  │
                               │ key in memory only   ├──────────────────►│ (no key, no  │
                               └──────────────────────┘   64-byte sig     │  passphrase) │
                                                                          └──────────────┘
```

## Start here

- [Introduction](docs/introduction.md) — what it is, in one page
- [Executive summary](docs/executive-summary.md) — why it exists

## Deep dive

- [Architecture](docs/architecture.md) — packages, data flow, trade-offs
- [Ring format](docs/format.md) — the normative on-disk format
- [Agent protocol](docs/agent-protocol.md) — the normative socket protocol
- [Design: scope & roadmap](docs/design/scope.md) · [review of the reference design](docs/design/review.md) · [decisions](docs/design/decisions.md)

## Operations

- [User guide](docs/userguide.md) — verbs, passphrase sources, rotation, backup
- [Verb reference](docs/reference.md) — generated from the command table
- [Security policy](SECURITY.md) · [third-party notices](THIRD-PARTY-NOTICES)

## Install

```sh
go install github.com/netstar-labs/keystore/cmd/keystore@latest
go install github.com/netstar-labs/keystore/cmd/keystore-agent@latest
```

Requires Go 1.27 or newer; macOS and Linux. Release builds (`build/keystore --release`) use
`-trimpath`, `CGO_ENABLED=0` and the toolchain pinned in `go.mod`, so the binaries come out
byte-identical from the same clean git checkout; `--release` refuses a dirty tree, and a dev
build from one is stamped `-dirty`. The archives and the SBOM embed timestamps, so their
checksums differ from run to run. The archives carry this README without the `docs/` tree; the
documentation lives in the repository.

## Examples

- [examples/](examples/README.md) — machine-to-machine integration scenarios

## Layout

| Path | Purpose |
|---|---|
| `pkg/keystore/` | public library: open/create a ring, keys and secrets, `Signer`, `ChangePassphrase`, PEM helpers |
| `pkg/agent/` | public library: the signing agent server and its `crypto.Signer` client |
| `internal/kdf/` | argon2id parameters, bounds and key derivation |
| `internal/seal/` | AES-256-GCM seal/open and the associated-data encoding |
| `internal/ringfile/` | JSON schema, validation, locking, atomic durable writes |
| `internal/ids/` | entry-id validation |
| `internal/passphrase/` | passphrase sources and the establishment policy |
| `internal/term/` | no-echo prompt, terminal detection and output cleaning |
| `internal/keychain/` | macOS Keychain passphrase source |
| `internal/peercred/` | unix-socket peer credentials |
| `cmd/keystore/` | the CLI |
| `cmd/keystore-agent/` | the signing agent daemon |
| `examples/` | runnable integration scenarios |
| `testdata/` | golden ring fixtures that pin the format |
| `build/keystore` | build and packaging: `build/keystore` (linux/amd64 install package) or `build/keystore --release` (all platforms, SHA256SUMS, SPDX SBOM, notices) |
