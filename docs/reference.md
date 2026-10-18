# Verb reference

*Generated from the command table in `cmd/keystore/verbs.go` — do not edit by hand.
Regenerate with `go test ./cmd/keystore -run TestReference -args -update`.*

`keystore <verb> [flags]`. There is no passphrase flag; see the user guide for
passphrase sources.

## `init`

create an empty ring (mode 0600); never overwrites

| Flag | Meaning | Default |
|---|---|---|
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |

## `keygen`

create the ring if missing, then mint a signing key

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `add`

mint another signing key in an existing ring

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `import`

encrypt an existing PKCS#8 PEM Ed25519 private key into the ring

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-key` | PKCS#8 PEM private key file to import (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `list`

list entries: current marker, id, kind, created, fingerprint (no passphrase)

| Flag | Meaning | Default |
|---|---|---|
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |

## `use`

make an entry the current signing key

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |

## `rm`

remove an entry; the last signing key needs -force

| Flag | Meaning | Default |
|---|---|---|
| `-force` | allow removing the last signing key | — |
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |

## `export-pub`

write a public key as SPKI PEM (no passphrase)

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (default: the current signing key) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |

## `export-priv`

write a private key as PKCS#8 PEM, for backup or migration (guarded)

| Flag | Meaning | Default |
|---|---|---|
| `-force` | replace an existing -o file, or allow writing to a terminal | — |
| `-id` | entry id (default: the current signing key) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-o` | write to this new file (0600); default stdout | — |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `add-secret`

mint a random 32-byte secret (never printed; use export-secret)

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `import-secret`

store a base64 secret read from -in FILE or stdin (prompted without echo on a terminal)

| Flag | Meaning | Default |
|---|---|---|
| `-id` | entry id (required) | — |
| `-in` | file holding the base64 secret; - for stdin | - |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `export-secret`

write a secret as base64 (guarded)

| Flag | Meaning | Default |
|---|---|---|
| `-force` | replace an existing -o file, or allow writing to a terminal | — |
| `-id` | entry id (required) | — |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-o` | write to this new file (0600); default stdout | — |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `passwd`

change the ring passphrase and re-encrypt every entry

| Flag | Meaning | Default |
|---|---|---|
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-new-passfile` | read the NEW passphrase from this file (0600, owned by you); env KEYSTORE_NEW_PASSPHRASE | — |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |

## `keychain-set`

store the ring passphrase in the macOS login keychain (security prompts for it)

| Flag | Meaning | Default |
|---|---|---|
| `-service` | keychain service name (use it as KEYSTORE_KEYCHAIN) | keystore |

## `sign`

sign up to 1 MiB from -in FILE or stdin with a ring key or an agent; prints a base64 signature

| Flag | Meaning | Default |
|---|---|---|
| `-agent` | sign through the agent at this socket instead of unlocking the ring | — |
| `-force` | replace an existing -o file | — |
| `-id` | entry id (default: the current signing key) | — |
| `-in` | message file; - for stdin | - |
| `-keystore` | ring file (env KEYSTORE_FILE) | $KEYSTORE_FILE, else ~/.config/keystore/default.ks |
| `-o` | write the signature to this new file; default stdout | — |
| `-passfile` | read the passphrase from this file (0600, owned by you) | — |
| `-raw` | write the 64 raw signature bytes instead of base64 | — |

## `verify`

verify a signature over -in FILE or stdin with a public key PEM; no ring needed

| Flag | Meaning | Default |
|---|---|---|
| `-in` | message file; - for stdin | - |
| `-pub` | public key, SPKI PEM (required) | — |
| `-sig` | signature file, base64 or 64 raw bytes (required) | — |
