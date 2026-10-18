# User guide

`keystore <verb> [flags]`. Every verb that reads a ring accepts `-keystore FILE` (default
`$KEYSTORE_FILE`, else `~/.config/keystore/default.ks`); `verify` and `keychain-set` read no ring
and take no `-keystore`. Verbs that need the passphrase also accept `-passfile FILE`.
There is **no passphrase flag** — argv is visible to other users in `ps`.

Data (keys, PEM) goes to stdout; messages go to stderr; failure is a non-zero exit with one
line of error. The full flag list per verb is in the generated [reference](reference.md).

## Verbs

| Verb | What it does | Passphrase |
|---|---|---|
| `init` | create an empty ring; never overwrites | no |
| `keygen -id ID` | create the ring if missing, then mint a key | yes (new) |
| `add -id ID` | mint another signing key | yes |
| `import -id ID -key FILE` | encrypt an existing PKCS#8 PEM private key into an existing ring (`init` or `keygen` first) | yes |
| `list` | id, kind, current marker, created, fingerprint | no |
| `use -id ID` | make ID the current signing key | no |
| `rm -id ID [-force]` | remove an entry; last signing key needs `-force` | no |
| `export-pub [-id ID]` | SPKI PEM public key | no |
| `export-priv [-id ID] [-o FILE] [-force]` | PKCS#8 PEM private key, guarded | yes |
| `add-secret`, `import-secret`, `export-secret` | opaque secrets | yes |
| `passwd` | change the ring passphrase | yes |
| `keychain-set` | store the passphrase in the macOS Keychain | — |
| `sign`, `verify` | sign with a ring key or agent; verify with a public key | sign: yes |

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
   When it is set it silently wins over `-passfile`: `KEYSTORE_PASSPHRASE=old keystore keygen
   -passfile strong` establishes the ring under `old`.
2. `-passfile FILE` — must be owned by you and mode 0600 or stricter, or it is refused.
3. A no-echo prompt on the terminal (asked twice when setting a new passphrase).

On macOS, `keystore keychain-set -service prod` stores the passphrase in the login keychain
(the `security` tool prompts for it, so it never touches argv); then `export
KEYSTORE_KEYCHAIN=prod` and the keychain is consulted after `KEYSTORE_PASSPHRASE` and before
`-passfile`. If `KEYSTORE_KEYCHAIN` is set and the lookup fails, the command fails rather than
falling through to a prompt.

A **new** passphrase — the one given when the first key goes into an empty ring — must be at least 12 characters, from any source. Unlocking is never
length-checked. If `keygen` is refused for a short passphrase it has already created the ring
file, empty (the state `init` leaves); run it again. Upper bounds: the terminal prompt takes up
to 1024 bytes and a passfile up to 4096 bytes; `KEYSTORE_PASSPHRASE` has no cap. One ring has one passphrase: adding an entry with a different passphrase is
refused (`passphrase does not match this ring`).

## Secrets

Opaque secrets — API tokens, HMAC keys — live in the same ring under the same passphrase.

```sh
keystore add-secret    -keystore prod.ks -id hmac          # 32 random bytes, never printed
printf %s "$TOKEN_B64" | keystore import-secret -keystore prod.ks -id api   # base64 on stdin
keystore import-secret -keystore prod.ks -id api -in token.b64             # or from a file
keystore export-secret -keystore prod.ks -id api -o api.b64                # base64, 0600
```

On a terminal, `import-secret` prompts for the value without echo; the terminal's line
buffer limits what you can type (on macOS about 1000 base64 characters — longer input is
silently ignored and the prompt keeps waiting), so for larger values use `-in FILE` or stdin.
A secret is never accepted as a command-line argument. `export-secret` follows the same output rules as
`export-priv` (below).

## Changing the passphrase

```sh
keystore passwd -keystore prod.ks
```

It asks for the current passphrase, then the new one twice. Every entry is unlocked first;
if any fails, nothing is written. Then every entry is re-encrypted with fresh salts at the
current KDF cost in one atomic write. For automation, the new passphrase can come from
`KEYSTORE_NEW_PASSPHRASE` or `-new-passfile FILE` (never from the keychain). Update the
keychain item afterwards if you use one.

`passwd` and `rm` rewrite the ring; they do not reach copies that already exist. A backup, a
snapshot, or a temporary file left by a crashed write still holds the old entries and unlocks
under the old passphrase. `passwd` also does not rotate the private keys, so after a
passphrase may have been exposed, rotate the keys themselves (below) and see
[SECURITY.md](../SECURITY.md).

## Rotation

Consumers pin public keys, so rotate by overlap:

1. `keystore add -id 2027-prod`
2. `keystore export-pub -id 2027-prod` → consumers add it to their trusted set
3. `keystore use -id 2027-prod` — new signatures use it
4. `keystore rm -id 2026-prod` once nothing needs the old key

`rm` only removes the entry from the current ring (see above); if the old key may have leaked,
consumers must stop trusting its public key too. For rotation after a suspected compromise of
the ring or its passphrase, see [SECURITY.md](../SECURITY.md).

In scripts, always pass `-id` rather than relying on the ring's current key: the current
marker is stored in the ring file unauthenticated, so anything that can write the ring can
change which key a bare `sign` uses (and `sign` still exits 0). Take each public key from the
output of `keygen` or `add` when the key is created: both print the public key PEM on stdout,
whereas `export-pub` reads the copy stored in the ring, which is only checked when the entry
is unlocked.

## Signing and verifying

```sh
keystore sign   -keystore prod.ks -in msg > msg.sig            # unlocks the current key
keystore sign   -agent /run/user/1000/keystore/agent.sock -in msg > msg.sig   # no passphrase
keystore verify -pub prod.pub -sig msg.sig -in msg              # exit 0 = valid
```

Signatures are pure Ed25519, written as base64 (or 64 raw bytes with `-raw`). Messages are
limited to 1 MiB on both paths; for artifacts, sign a digest manifest
(`sha256sum app.tgz > SHA256SUMS`) — see [examples/ci-release](../examples/ci-release/).

## The agent

```sh
keystore-agent -keystore prod.ks -id 2026-prod -sock "$XDG_RUNTIME_DIR/keystore/agent.sock" \
               -passfile ~/.config/keystore/pass -ttl 8h -idle 30m
```

The agent unlocks one key at start, holds it only in memory, and signs for processes running
as the same user over an owner-only socket. Its passphrase comes from `-passfile` or
`KEYSTORE_PASSPHRASE`; it never prompts and never reads the keychain (it refuses to start if
`KEYSTORE_KEYCHAIN` is set). Prefer `-passfile`: the agent unsets the variable in its own
environment once read, but the copy in the environment block it was started with remains
readable by the same user (`ps eww`, `/proc/PID/environ`). The agent has no default ring:
`-keystore` (or `$KEYSTORE_FILE`) and `-sock` are required. The socket's directory must
already exist, be yours and mode 0700, and the whole socket path must fit the operating system's
limit (about 104 bytes on macOS, 108 on Linux) or the agent exits with `bind: invalid argument`.
It stops — removing the socket — on SIGINT/SIGTERM, after `-ttl` (a hard stop), or after
`-idle` without a successful request (any successful request counts, including a public-key
fetch); `0` disables either and a negative value is refused. A second agent will not take
over a live socket. Wire format: [agent-protocol.md](agent-protocol.md).
Service definitions: [examples/agent-service](../examples/agent-service/).

Go programs use the agent as a `crypto.Signer`:

```go
s, err := agent.Dial(sock)                  // or agent.ResolveSigner(sock, ring, id, passFn)
sig, err := s.Sign(nil, msg, crypto.Hash(0))
```

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
| passfile | 0600 | anyone holding both this and the ring can unlock it — keep it out of the ring's backups |
| `agent.sock` | 0600 | the agent's socket; removed when the agent stops |
| `agent.sock.lock` | 0600 | the agent's path lock; empty; stays after the agent exits, safe to delete when no agent runs |
| `sig` from `sign -o` | 0644 | signatures are public; `export-*` with `-o` write 0600, but a shell `>` redirect gets the umask's mode |

## Errors

| Message | Meaning |
|---|---|
| `wrong passphrase or corrupt entry` | AEAD check failed — wrong passphrase, or the entry was modified |
| `passphrase does not match this ring` | the passphrase differs from the one the ring's entries use |
| `not a keystore file` | wrong file, or a field fails validation |
| `ring format is newer than this binary` | upgrade the binary |
| `ring is locked by another process` | another writer held the lock past the timeout |
| `invalid entry id` | ids are 1–64 chars of `A–Z a–z 0–9 . _ -`, starting alphanumeric |

## Exit status

`0` success (and `-h`/`help`); `2` usage error; `1` every other failure, including a signature
that does not verify; `130` interrupted at a prompt.
