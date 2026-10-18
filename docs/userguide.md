# User guide

`keystore <verb> [flags]`. Every verb accepts `-keystore FILE` (default `$KEYSTORE_FILE`, else
`~/.config/keystore/default.ks`). Verbs that need the passphrase also accept `-passfile FILE`.
There is **no passphrase flag** — argv is visible to other users in `ps`.

Data (keys, PEM) goes to stdout; messages go to stderr; failure is a non-zero exit with one
line of error. The full flag list per verb is in the generated [reference](reference.md).

## Verbs

| Verb | What it does | Passphrase | Release |
|---|---|---|---|
| `init` | create an empty ring; never overwrites | no | v0.1.0 |
| `keygen -id ID` | create the ring if missing, then mint a key | yes (new) | v0.1.0 |
| `add -id ID` | mint another signing key | yes | v0.1.0 |
| `import -id ID -key FILE` | encrypt an existing PKCS#8 PEM private key | yes | v0.1.0 |
| `list` | id, kind, current marker, created, fingerprint | no | v0.1.0 |
| `use -id ID` | make ID the current signing key | no | v0.1.0 |
| `rm -id ID [-force]` | remove an entry; last signing key needs `-force` | no | v0.1.0 |
| `export-pub [-id ID]` | SPKI PEM public key | no | v0.1.0 |
| `export-priv [-id ID] [-o FILE] [-force]` | PKCS#8 PEM private key, guarded | yes | v0.1.0 |
| `add-secret`, `import-secret`, `export-secret` | opaque secrets | yes | v0.2.0 |
| `passwd` | change the ring passphrase | yes | v0.2.0 |
| `keychain-set` | store the passphrase in the macOS Keychain | — | v0.2.0 |
| `sign`, `verify` | sign with a ring key or agent; verify with a public key | sign: yes | v0.3.0 |

## Getting started

```sh
keystore keygen -keystore prod.ks -id 2026-prod      # creates prod.ks, prompts for a passphrase twice
keystore export-pub -keystore prod.ks > prod.pub     # publish this
keystore list -keystore prod.ks
# *  2026-prod  ed25519  2026-10-18T19:02:11Z  SHA256:…
```

## Passphrases

Resolved in this order:

1. `KEYSTORE_PASSPHRASE` — convenient for automation, but visible in the process environment.
2. `-passfile FILE` — must be owned by you and mode 0600 or stricter, or it is refused.
3. A no-echo prompt on the terminal (asked twice when setting a new passphrase).

From v0.2.0 the macOS Keychain (`KEYSTORE_KEYCHAIN=<service>`) slots in between 1 and 2.

A **new** passphrase — the one given when the first key goes into an empty ring — must be at least 12 characters, from any source. Unlocking is never
length-checked. One ring has one passphrase: adding an entry with a different passphrase is
refused (`passphrase does not match this ring`).

## Rotation

Consumers pin public keys, so rotate by overlap:

1. `keystore add -id 2027-prod`
2. `keystore export-pub -id 2027-prod` → consumers add it to their trusted set
3. `keystore use -id 2027-prod` — new signatures use it
4. `keystore rm -id 2026-prod` once nothing needs the old key

## Exporting private keys

`export-priv` exists for backup and migration. It writes PKCS#8 PEM to `-o FILE`, which is
created new with mode 0600 and never follows a symlink. An existing file is refused unless
`-force`, which replaces it atomically. Without `-o`, it refuses to print to a terminal unless
`-force`.

## Files

| File | Mode | Notes |
|---|---|---|
| `prod.ks` | 0600 | the ring; safe to back up (encrypted), but never alongside its passphrase |
| `prod.ks.lock` | 0600 | lock file; empty; safe to delete when nothing is running |
| passfile | 0600 | the ring's ceiling — keep it out of the ring's backups |

## Errors

| Message | Meaning |
|---|---|
| `wrong passphrase or corrupt entry` | AEAD check failed — wrong passphrase, or the entry was modified |
| `passphrase does not match this ring` | the passphrase differs from the one the ring's entries use |
| `not a keystore file` | wrong file, or a field fails validation |
| `ring format is newer than this binary` | upgrade the binary |
| `ring is locked by another process` | another writer held the lock past the timeout |
| `invalid entry id` | ids are 1–64 chars of `A–Z a–z 0–9 . _ -`, starting alphanumeric |
