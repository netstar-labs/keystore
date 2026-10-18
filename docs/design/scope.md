# Keystore — scope and roadmap

## One-line purpose

An encrypted, single-file keyring for Ed25519 signing keys and opaque secrets, with a CLI,
a Go library and a small signing agent — so a private key never has to sit in a plaintext
file or be handed to the process that uses it.

## Users

- **Operators and CI** that need to sign things without a plaintext key on disk.
- **Go programs** that need a `crypto.Signer` or a secret from an encrypted store.

## Scope — v0.1.0

### Entries
- `ed25519` signing keys (generated or imported), public half readable without a passphrase.
- `secret`: opaque bytes (32 random by default, or imported), encrypted identically.
- A `current` pointer naming the default signing key.

### Verbs (CLI `keystore`)

| Verb | Purpose |
|---|---|
| `init` | create an empty ring (mode 0600, never overwrites) |
| `keygen` | `init` if needed, then mint a key — the one-step path |
| `add` | mint another signing key |
| `import` | encrypt an existing PKCS#8/PEM private key into the ring |
| `list` | id, kind, current marker, created time, public-key fingerprint; no passphrase |
| `use` | set the current signing key |
| `rm` | remove an entry; if it was current, move current to another signing key; refuse to remove the last signing key without `-force` |
| `export-pub` | public key as SPKI PEM; no passphrase |
| `export-priv` | PKCS#8 PEM for backup/migration; guarded (see below) |
| `add-secret` | mint a random 32-byte secret |
| `import-secret` | store a supplied secret (base64) |
| `export-secret` | print or write a secret (base64); guarded |
| `passwd` | change the ring passphrase and re-encrypt every entry at current KDF cost |
| `keychain-set` | store the ring passphrase in the macOS login keychain |
| `sign` | sign a file or stdin with a ring key, or via an agent; outputs raw or base64 signature |
| `verify` | verify a signature with a public key (convenience; no ring needed) |

### Agent (`keystore-agent`)
Unlocks one key, holds it only in memory, serves `P` (public key) and `S` (sign) over an
owner-only unix socket. Peer-uid checked, lifetime- and idle-limited, refuses to steal a
live socket.

### Library (`github.com/netstar-labs/keystore/pkg/keystore`, agent in `/pkg/agent`)
`Create`, `Open`, `OpenOrCreate`; `Add`, `Import`, `AddSecret`, `ImportSecret`, `Signer`,
`Secret`, `Public`, `List`, `Use`, `Remove`, `ExportPrivate`, `ChangePassphrase`;
`DialAgent`, `Serve`; PEM helpers; `ResolveSigner`; passphrase resolution.

### Passphrase sources (never a flag)
`KEYSTORE_PASSPHRASE` → macOS Keychain (`KEYSTORE_KEYCHAIN=<service>`) → `-passfile` →
no-echo prompt. A **12-character minimum** applies whenever a passphrase is established.

### Security properties every release must meet
1. A copy of the ring file alone reveals no private material (argon2id 64 MiB/t=3/p=1,
   AES-256-GCM, per-entry salt and nonce).
2. Any modification of an entry — id, kind, public key, KDF parameters, ciphertext — fails
   authentication with one named error.
3. A crash at any point leaves either the old ring or the new ring, never a torn one, and
   the new one is durable once the command returns.
4. Concurrent processes cannot lose each other's writes.
5. One passphrase per ring, enforced.
6. No secret material on argv, and none written to a terminal or an existing file by
   accident.
7. A crafted ring cannot cause an unbounded allocation or a zero-cost KDF.

### Platforms
macOS and Linux (arm64, amd64). Keychain features are macOS-only and degrade with a clear
message elsewhere. Windows is out of scope.

## Examples — machine-to-machine integration

An `examples/` folder ships with the first release and demonstrates **unattended** use: no prompts, no
humans, no plaintext private key on any disk the workload can read. Each example is runnable
end to end by a script, uses only the standard library plus `pkg/keystore` and `pkg/agent`,
and is exercised by a test in CI so it cannot rot.

| Example | Shows |
|---|---|
| `examples/provision/` | One-time setup by an operator: `init`, `keygen`, `export-pub`, `add-secret`; passfile at 0600; the public key published to the verifying side |
| `examples/agent-service/` | Running `keystore-agent` as a service — a `systemd` unit (Linux) and a `launchd` plist (macOS), owner-only socket directory, passphrase from a 0600 passfile, `-ttl`/`-idle` and restart behaviour |
| `examples/signed-requests/` | Service A signs outbound HTTP requests (method, path, body hash, timestamp, nonce) through `DialAgent`; service B verifies with only the public key; replay and clock-skew rejection shown |
| `examples/ci-release/` | A CI job signs a build artifact via the agent socket (`keystore sign -agent`), publishes `artifact.sig`; a deploy host verifies (`keystore verify`) before installing; the CI job never sees the key or the passphrase |
| `examples/rotation/` | Zero-downtime key rotation: add the next key, publish its public half, verifiers accept both, `use` switches the signer, `rm` retires the old one |
| `examples/secrets/` | A workload fetching an opaque secret (an HMAC or API key) from the ring at start-up, then dropping it from memory; contrast with the env-var anti-pattern |

Each folder has a `README.md` stating the threat it addresses and what it does **not**
protect against (for example: any process running as the same user can use the agent), plus a
`run.sh` that stands the scenario up in a temp directory and tears it down.

Acceptance: `go test ./examples/...` runs every scenario in-process or with the built
binaries; each verifies the happy path, a tampered message, a wrong key, and an expired or
absent agent.

## Non-goals

- A network service, multi-user access control, or remote key management.
- Key types other than Ed25519 for signing (other types are roadmap).
- Encryption/decryption API for arbitrary user data (the ring protects keys, it is not an
  encryption service).
- Hardware backends before the backends milestone — only the `crypto.Signer` seam that makes them possible.
- Compatibility with other keyring formats; import/export is via standard PEM.
- Being a password manager.

## Versioning

Under a v0-forever policy: tags start at `v0.1.0` and **never advance off `v0`** — no `v1`, no `/vN` module suffix.
Patch (`v0.y.Z+1`) for fixes; minor (`v0.Y+1.0`) for everything else, breaking changes
included, each called out in the release notes with a migration step.

Two things must not be confused:

- the **module version** (`v0.y.z`) — the Go API and CLI; no stability promise;
- the **ring format** (`"magic": "keystore/v1"`) — the on-disk contract, versioned
  independently. A format bump is a coordinated event: binaries recognise one format ahead
  (`ErrFutureVersion`) so a migration is not a cliff. The module stays on `v0` regardless.

## Roadmap

| Release | Theme | Contents |
|---|---|---|
| **v0.1.0** | First release, built in four phases | **Core:** ring format `keystore/v1`, library, `init/keygen/add/import/list/use/rm/export-pub/export-priv`, locking, durable writes, id validation, golden-vector and fuzz tests. **Secrets & custody:** `add-secret/import-secret/export-secret`, `passwd`, passphrase sources incl. Keychain, TTY guards. **Agent & integration:** `keystore-agent`, `agent.Dial`, peer credentials, TTL/idle, `ResolveSigner`, `sign`/`verify`, the six examples. **Release readiness:** CI (Linux + macOS, race, fuzz budget, govulncheck, deadcode), reproducible build, SBOM, notices, adversarial review and its fixes |
| **v0.2.0+** | Hardening | `mlock`/no-swap options, memory-zeroing audit, agent re-lock with re-prompt, key labels/metadata |
| **later (still v0.x)** | Backends & algorithms | PKCS#11 / cloud-KMS `Signer` providers as separate sub-modules, additional key types, post-quantum signing kind, ring format `keystore/v2` with the one-ahead rule |

Each release is gated on: all tests green, fuzz target run for a fixed budget, `go vet`,
`staticcheck` and `govulncheck` clean, the verb reference regenerated from the command
table, and a diff of the exported surface against the previous tag so any break is listed
in the notes. A "stable" milestone is expressed as a frozen **ring format**, not a `v1` tag.

## Open questions

1. ~~Module path and repo name~~ — **accepted:** `github.com/netstar-labs/keystore`.
2. ~~License~~ — **accepted:** Apache-2.0.
3. ~~`sign`/`verify`~~ — **accepted:** ship in v0.1.0 (agent phase). The agent signs any bytes a same-uid peer sends; documented as a trust trade-off in SECURITY.md.
4. ~~Dependencies~~ — **accepted:** `golang.org/x/crypto` (argon2id) and `golang.org/x/sys` only; everything else stdlib. No `x/term` — the no-echo prompt uses `x/sys/unix` directly.
5. ~~Default ring path~~ — **accepted:** `~/.config/keystore/default.ks`, overridable by
   `-keystore` and `KEYSTORE_FILE`.
