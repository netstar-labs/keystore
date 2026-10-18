# Architecture

## Packages and dependencies

```
cmd/keystore        ──► pkg/keystore, pkg/agent,
                        internal/passphrase, internal/keychain, internal/term
cmd/keystore-agent  ──► pkg/keystore, pkg/agent, internal/passphrase
pkg/agent           ──► pkg/keystore, internal/peercred
pkg/keystore        ──► internal/ringfile, internal/seal, internal/kdf, internal/ids
internal/ringfile   ──► internal/ids, internal/kdf, internal/seal
internal/seal       ──► internal/kdf
internal/passphrase ──► internal/keychain, internal/term
internal/keychain   ──► internal/ids
internal/kdf        ──► golang.org/x/crypto/argon2
internal/term, internal/peercred ──► golang.org/x/sys/unix
internal/ids        imports nothing from this module
```

Rules: `pkg/agent` may import `pkg/keystore`, never the reverse. `internal/` packages are
used only by `pkg/` and `cmd/`. Each package has one job.

| Package | Responsibility |
|---|---|
| `internal/ids` | Which strings are valid entry ids. |
| `internal/kdf` | argon2id parameters, their bounds, fresh salts, key derivation. |
| `internal/seal` | AES-256-GCM seal/open and the length-prefixed associated data that binds an entry's meaning to its ciphertext. |
| `internal/ringfile` | The JSON schema, strict validation, the advisory lock, and the atomic durable write. Knows nothing about keys. |
| `pkg/keystore` | The ring as a library: create, open, add, import, use, remove, unlock (`Signer`), export; PEM helpers. Enforces the one-passphrase-per-ring invariant. |
| `pkg/agent` | Signing agent server and `crypto.Signer` client over a unix socket. |
| `internal/passphrase` | Where a passphrase comes from (env, Keychain, passfile, prompt) and the rules for establishing a new one. |
| `cmd/keystore` | Thin CLI; a verb table drives dispatch, help and the generated reference. |

## Data flow

**Add a key.** CLI resolves the passphrase → `pkg/keystore` takes the ring lock → re-reads the
file → if the ring already has encrypted entries, unlocks one to prove the passphrase matches →
generates the key → `kdf` derives an AES key from a fresh salt → `seal` encrypts the PKCS#8
bytes with associated data covering format, kind, id, public key and KDF parameters →
`ringfile` writes a temp file, syncs it, renames it over the ring, syncs the directory →
lock released.

**Use a key.** Open (no lock, read-only) → `Signer(id, passphrase)` → derive, open, parse
PKCS#8 → an `ed25519.PrivateKey`, which is a `crypto.Signer`.

**Use a key without holding it.** The agent does the "use a key" step once at start, then
answers `sign` requests on a unix socket after checking the caller's uid. Clients get a
`crypto.Signer` whose `Sign` is a socket round trip.

## Trade-offs

- **One file, whole-file rewrites.** Simple, atomic and easy to back up; not designed for
  thousands of entries or high write rates. A ring holds a handful of keys.
- **Per-entry salts and KDF runs.** Unlocking one entry costs one argon2id run (64 MiB, ~0.1–
  0.3 s). Adding an entry costs two (check the passphrase, then encrypt). Deliberate.
- **Advisory locking.** `flock` on a sidecar file protects cooperating writers. A process
  that ignores the lock can still race; nothing short of a server prevents that.
- **No legacy formats.** One KDF, one cipher, one format version — less code to audit.
- **Wrong passphrase and entry tampering are indistinguishable.** Both are an AEAD failure
  when the entry is unlocked; telling them apart would leak information to an attacker. A
  field that is out of range or malformed is different: it fails at parse, for the whole
  ring, as "not a keystore file".
- **Entries are authenticated, the ring is not.** The AEAD covers each entry's own fields;
  nothing covers `current`, entry order, which entries exist, or which version of the file
  this is. A key that authenticated the whole file would need the passphrase for `use`, `rm`
  and listing, and a rollback check needs state outside the file. See
  [format.md](format.md#what-is-authenticated) and decision 39.
