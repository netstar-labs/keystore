# Keystore — build prompt

*A prompt for a Claude Code session that builds this repository from scratch. Read
[../design/scope.md](../design/scope.md) (what to build) and
[../design/review.md](../design/review.md) (which flaws to avoid) first; this file says how.*

---

## Role and ground rules

You are building `github.com/netstar-labs/keystore`: a small, security-sensitive Go module and
CLI — an encrypted single-file keyring for Ed25519 signing keys and opaque secrets, plus a
signing agent. It will be a public repository. Optimise for **small, readable, auditable**
code, not features.

- Standard library plus exactly `golang.org/x/crypto` (argon2id) and `golang.org/x/sys` (`unix` for the no-echo prompt and peer credentials; `cpu` arrives via argon2). No `x/term`. Adding
  any other dependency requires a written reason in the PR/commit and a stop to ask.
- Go: latest stable. `go vet`, `gofmt`, and `govulncheck` clean at every commit.
- Write tests first for every security property in scope.md ("Security properties every release must
  meet"). A property without a test is not done.
- Commit in small steps with conventional messages. **Do not push, tag, or create a remote**
  unless asked.
- Do not copy or reference any outside project in code, comments, docs, env var names or
  file magic. Everything is named `keystore`.
- When something is ambiguous, prefer the smaller, safer behaviour and record the choice in
  `docs/design/decisions.md`.

## Repository layout

Keep the root thin: module files and docs only. Public library code goes under `pkg/`,
private helpers under `internal/`, binaries under `cmd/`. No Go source in the root.

```
keystore/
  go.mod  LICENSE  README.md  SECURITY.md
  cmd/
    keystore/            main.go  verbs.go            (CLI; verb table drives help + reference)
    keystore-agent/      main.go
  pkg/
    keystore/            ring.go  entry.go  errors.go  pem.go  signer.go   (public API)
    agent/               server.go  client.go  frame.go                    (public API)
  internal/
    kdf/                 argon2id parameters, bounds, key derivation
    seal/                AES-256-GCM seal/open and the associated-data encoding
    ringfile/            JSON schema, validation, atomic durable save, flock, golden tests
    passphrase/          source resolution and the establishment policy
    term/                no-echo prompt, isatty
    keychain/            keychain_darwin.go  keychain_other.go
    peercred/            peercred_linux.go  peercred_darwin.go
    ids/                 entry-id validation
  examples/              provision/  agent-service/  signed-requests/  ci-release/  rotation/  secrets/
  testdata/              golden.ks  golden.md
  docs/                  design/  plan/  format.md  agent-protocol.md  reference.md (generated)
```

Import paths: `github.com/netstar-labs/keystore/pkg/keystore` and `.../pkg/agent`. `internal/`
packages are imported only by `pkg/` and `cmd/`; `pkg/agent` may import `pkg/keystore` but
not the reverse. Each package has one responsibility, a doc comment, and its own tests.

## On-disk format (ring format v1, normative — write it into `docs/format.md`)

JSON, UTF-8, mode 0600:

```json
{ "magic": "keystore/v1", "current": "id-or-empty", "entries": [ Entry… ] }
```

Entry: `id`, `kind` (`"ed25519"` | `"secret"`), `pub` (base64 SPKI DER, ed25519 only),
`kdf` `{algo:"argon2id", mem:65536, time:3, par:1, salt:<16B b64>}`, `nonce` (12B b64),
`ct` (b64), `created` (RFC 3339 UTC).

Encryption: key = argon2id(passphrase, salt, time, mem, par) → 32 bytes; AES-256-GCM, random
12-byte nonce. Plaintext: PKCS#8 DER for `ed25519`, raw bytes for `secret`.

**Associated data** (length-prefixed, big-endian uint32 lengths, no separators):
`"keystore/v1" ‖ kind ‖ id ‖ pub ‖ algo ‖ mem ‖ time ‖ par ‖ salt` — every field that
changes meaning is authenticated.

Validation on open and on every entry: ids match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and are
unique; `kind` known; KDF bounds `mem ∈ [8 MiB, 1 GiB]`, `time ∈ [1,64]`, `par ∈ [1,16]`
(reject, do not clamp); salt and nonce exact length; `current` is empty or names an
`ed25519` entry. Unknown `magic` → `ErrBadFormat`. Newer `keystore/vN` → distinct
`ErrFutureVersion` ("upgrade this binary").

Errors are sentinel values: `ErrNoKey`, `ErrBadPass` (wrong passphrase *or* tampered entry —
deliberately indistinguishable), `ErrExists`, `ErrBadFormat`, `ErrFutureVersion`,
`ErrBadID`, `ErrPassphraseMismatch`, `ErrLocked`.

## Write path (every mutation, no exceptions)

1. Take an exclusive `flock` on `<ring>.lock` (0600, created if missing).
2. **Re-read** the ring from disk under the lock; apply the mutation to that fresh copy.
3. `CreateTemp` in the ring's directory (O_EXCL, random name); `chmod 0600` before writing;
   write; `fsync` file; `rename` over the ring; `fsync` the directory.
4. Release the lock. Remove the temp file on any failure.

`Create` must not replace an existing file (use `O_EXCL`/`link`, not stat-then-write).
**One passphrase per ring:** before adding any encrypted entry to a non-empty ring, unlock an
existing encrypted entry with the supplied passphrase and return `ErrPassphraseMismatch` on
failure — before generating anything.

## Verbs

Implement the verb table in scope.md. Rules common to all:

- Global flags: `-keystore FILE` (default `$KEYSTORE_FILE`, else
  `~/.config/keystore/default.ks`), `-passfile FILE`. **No passphrase flag.**
- Passphrase order: `KEYSTORE_PASSPHRASE` → macOS Keychain (`KEYSTORE_KEYCHAIN=<service>`) →
  `-passfile` (must be mode 0600 or stricter, owned by the user; else refuse) → no-echo prompt
  (twice, matching, when establishing). 12-character minimum whenever establishing, from any
  source. Unlocking an existing ring is never length-checked.
- `list`, `export-pub`, `verify` need no passphrase and must not prompt.
- `export-priv`, `export-secret` write to `-o FILE` (created `O_EXCL`, 0600, no symlink
  follow; refuse existing unless `-force`, which replaces via temp-and-rename). Without
  `-o`, refuse when stdout is a terminal unless `-force`.
- `rm` of the last signing key requires `-force`; of the `current` key moves `current` to
  the first remaining signing key.
- `passwd`: prompt old, then new twice; unlock **all** entries first, fail with nothing
  written if any fails, then re-encrypt every entry (fresh salts, nonces, current KDF
  parameters) in one atomic write.
- Output for humans on stderr, data on stdout; non-zero exit and one-line error on failure;
  never print a passphrase or key except by an explicit export verb.
- Generate `docs/reference.md` from the command table (verb, flags, one-line purpose) and add
  a test that fails if a verb exists in code but not in the reference or the reverse.

## Agent

`keystore-agent -keystore K [-id ID] -sock PATH [-passfile P] [-ttl 8h] [-idle 30m]`

- Passphrase from env or passfile only (a daemon does not prompt).
- Socket's parent directory must be owned by the user and not group/world-accessible; create
  the socket under `umask 0177`, then `chmod 0600`.
- If something answers on `PATH`, exit with an error; remove only a stale socket.
- Per connection: verify peer uid equals the agent's uid (`SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on Darwin) before reading; set read/write deadlines.
- Protocol: frame `[op:1][len:4 BE][payload]`, `len ≤ 1 MiB`; op `'P'` → 32-byte public key,
  `'S'` → 64-byte signature over payload; reply status byte `0` ok / `1` error with message.
  Write this into `docs/agent-protocol.md`.
- On `-ttl` expiry or `-idle` expiry: drop the key, close the listener, remove the socket,
  exit 0. SIGINT/SIGTERM do the same.
- Client `DialAgent` returns a `crypto.Signer`; dial and call timeouts default to 5 s.

## Tests (required)

- Round trip for each kind; wrong passphrase → `ErrBadPass`.
- **Tamper matrix:** flip a byte in each of `id`, `kind`, `pub`, each KDF field, `salt`,
  `nonce`, `ct`, and `magic`; each must fail, none may panic.
- **Golden vector:** `testdata/golden.ks` with a fixed passphrase opens and yields known
  public key and secret bytes — pins the format.
- **Fuzz** `Open` and the entry decoder (no panics, no allocation above the KDF cap).
- **Concurrency:** N goroutines *and* N child processes each `add` a distinct id; all N are
  present afterwards.
- **Crash safety:** inject failure after temp write, after file sync, after rename, before
  directory sync; ring is always either old or new and always opens.
- **Passphrase invariant:** adding with a different passphrase → `ErrPassphraseMismatch`,
  ring unchanged.
- **Permissions:** ring 0600; `export-priv -o` onto a pre-existing 0644 file is refused (and
  with `-force` ends 0600); symlink target refused.
- **Agent:** sign over socket verifies with `ed25519.Verify`; wrong-uid peer rejected
  (where testable); TTL and idle expiry; refuses a live socket; oversize frame rejected.
- **Verb/reference parity** test (above).
- Run with `-race`. Report the commands and their output.

## Versioning

v0-forever policy: tags start at `v0.1.0` and never advance off `v0`; the four phases
below together make the first release, tagged once as `v0.1.0` (phases are not tagged); never cut `v1` or a
`/vN` module path. Patch for fixes, minor for everything else including breaking changes
(called out in notes with a migration step). The ring format magic `keystore/v1` is a
separate, on-disk version and does not affect the module version.

## Phased execution

Stop and report at the end of each phase; start the next only when told.

1. **Phase 1 — Core** — module, format, validation, locking, durable writes, library API for
   signing keys, verbs `init keygen add import list use rm export-pub export-priv`, golden
   vector, fuzz, tamper, concurrency and crash tests.
2. **Phase 2 — Secrets & custody** — secrets in library and CLI, `passwd`, Keychain
   (`internal/term` and build-tagged files), TTY guards, passphrase source tests.
3. **Phase 3 — Agent** — `agent` package and `keystore-agent`, peer credentials, TTL/idle,
   `sign`/`verify` verbs, `ResolveSigner`.
   Also build `examples/` per the "Examples — machine-to-machine integration" section of
   scope.md: each folder gets a `README.md` (threat addressed, what it does not protect
   against), a `run.sh` that builds in a temp dir and cleans up, stdlib-only Go where code is
   needed, and a test under `go test ./examples/...` covering the happy path, a tampered
   message, a wrong key, and an absent or expired agent. Include a `systemd` unit and a
   `launchd` plist for the agent; do not enable or load either on the host.
4. **Phase 4 — Release readiness** — README, SECURITY.md, generated reference, examples, CI config (vet, race,
   fuzz budget, govulncheck), LICENSE (confirm which first).

## What to hand back at each stop

Lead with the verdict and any caveat that changes a decision. Then: what changed; what
passed (command and output); what was not run, with the command; the strongest argument
that the design is wrong; open questions. Do not claim a property holds unless a test shows
it.

## Out of scope — do not build

Network service; other key types; data-encryption API; hardware backends (leave only the
`crypto.Signer` seam); a cleartext "credential" entry kind; legacy KDFs; Windows support;
anything not in scope.md.
