# Keystore — review of the reference design

*Review of an existing, working private encrypted-keyring implementation (about 530 lines of Go
plus CLI and a signing agent) that this project starts from. Read from source and docs; the
package's own tests were run and pass. Findings below are inputs to [scope.md](scope.md) and
the [build prompt](../plan/build-prompt.md); each says what to keep, change or add.*

## What it is

One JSON file (the *ring*, mode 0600) holding named entries:

| Kind | Holds | At rest |
|---|---|---|
| `ed25519` | signing key | PKCS#8 DER encrypted; SPKI public key in cleartext |
| `secret` | 32 random (or imported) bytes | encrypted |

Each entry is sealed with AES-256-GCM under a key derived from the passphrase by argon2id
(64 MiB, t=3, p=1, per-entry 16-byte salt). The entry id and public key are bound into the
AEAD as associated data. A `current` pointer names the default signing key. Writes go through
temp-file + rename. A companion agent holds one unlocked key in memory and signs over a 0600
unix socket with a tiny framed protocol (`P` = public key, `S` = sign).

CLI verbs: `init`, `add`, `import`, `list`, `use`, `rm`, `export-pub`, `export-priv`,
`add-secret`, `import-secret`, `export-secret`, `keychain-set`, plus `keygen` as an alias
for init+add. Passphrase sources, in order: env var, macOS Keychain, `-passfile`, no-echo
prompt; never a flag. A 12-character minimum applies when a passphrase is *established*.

## What is good — keep

- **Right primitive choices.** argon2id plus AES-256-GCM, parameters stored per entry, and a
  ceiling on accepted KDF cost so a crafted ring cannot force an out-of-memory open.
- **Public data is public.** `list` and `export-pub` need no passphrase.
- **Failure is loud.** A wrong passphrase and a tampered entry both surface as one named
  error from the AEAD check; there is no silent mis-decrypt.
- **Safe writes.** `CreateTemp` (O_EXCL, random name) instead of a predictable `.tmp`, chmod
  0600 before writing, fsync of the file, then atomic rename. The comment explaining why is
  worth carrying over verbatim in spirit.
- **Passphrase never on argv.** Four sources, a documented order, and a minimum length
  enforced at establishment, not at unlock.
- **Standard formats on the way out.** PKCS#8 and SPKI PEM, readable by `openssl`.
- **Signer seam.** The library returns a `crypto.Signer`; an in-process key, an agent client
  and any future hardware backend are interchangeable.
- **Agent hygiene.** Socket created under a restrictive umask, then chmod; removed on
  SIGINT/SIGTERM; frame length capped at 1 MiB; the private key never crosses the socket.

## Findings — change or add

Severity: **H** fix before `v0.1.0`, **M** fix before the first tagged release, **L** hardening or polish.

| # | Sev | Finding | Why it matters | Resolution |
|---|---|---|---|---|
| 1 | H | **No cross-process locking.** Every mutation is load → modify → rename of the whole file. Two concurrent `add` calls each rename a ring that lacks the other's entry. | Silent lost update of a key — the worst possible failure for a key store. | Exclusive `flock` on a sidecar lock file around every read-modify-write; re-read the ring *after* taking the lock. Test with parallel adds. |
| 2 | H | **One passphrase per ring is assumed but not enforced.** Each entry is encrypted independently with whatever passphrase the caller supplies, and `add` never checks it against existing entries. | A typo, or a differing passphrase, creates an entry that cannot be unlocked with the others. The docs promise "one unlock covers both". | Before writing a new encrypted entry into a non-empty ring, decrypt an existing entry with the supplied passphrase and refuse on mismatch. |
| 3 | H | **`export-priv -o` uses `os.WriteFile(…, 0600)`.** That applies the mode only when it *creates* the file; an existing, wider-mode file keeps its mode and is overwritten in place. | The exact bug class the ring's own save path was written to avoid, on the one verb that writes a plaintext private key. | Create with `O_EXCL`, mode 0600; refuse to overwrite unless `-force`, and then via temp-and-rename. Never follow a symlink. |
| 4 | M | **AEAD binds id and public key only.** The entry `kind`, the KDF parameters and the format version are not authenticated. | An attacker with write access can relabel an entry's kind or rewrite KDF parameters. Today that mostly yields a failed decrypt, but it is a footgun for every future kind or parameter. | Authenticate `magic ‖ kind ‖ id ‖ pub ‖ kdf-params` as associated data, with unambiguous length-prefixed encoding rather than a NUL separator. |
| 5 | M | **Entry ids are only checked non-empty.** A NUL separator joins id and public key in the AAD; ids may contain it, newlines, path separators or terminal escapes. | Ambiguous AAD encoding; ids are printed by `list` and used in file and shell contexts. | Restrict ids to `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; reject others on every entry point including import of a ring. |
| 6 | M | **No way to change the passphrase or KDF cost.** There is no `passwd`/re-key verb, and nothing to upgrade an entry written under older parameters. | A leaked or weak passphrase cannot be rotated without exporting every key in plaintext and re-importing. | Add `passwd`: unlock every entry with the old passphrase, re-encrypt all under the new one with current KDF parameters, one atomic write. |
| 7 | M | **Directory not fsynced after rename.** The file is synced; the rename itself is not made durable. | After a crash the old ring can reappear, undoing a rotation or a removal. | fsync the parent directory after `rename`. |
| 8 | M | **Agent trusts the socket mode alone.** The code comment says the 0600 socket "limits that to same-uid callers", but there is no peer-credential check; and the socket path is `os.Remove`d unconditionally before listening. | Mode 0600 is bypassed by root and, if the parent directory is writable by others, the pre-remove is a symlink/race hazard. A second agent started on a live socket silently steals it. | Check peer uid (`SO_PEERCRED` / `LOCAL_PEERCRED`) on every connection; require the socket's parent directory to be owner-only; refuse to start if a live agent answers on the path; remove only a stale socket. |
| 9 | M | **Agent has no lifetime and no client timeouts.** Once unlocked, the key stays resident until the process dies; `DialAgent` round-trips have no deadline. | Unbounded exposure window; a stuck agent hangs every signer. | `-ttl` (max lifetime) and `-idle` (idle expiry) flags; per-connection read/write deadlines; client dial and call timeouts. |
| 10 | M | **`Create` checks existence then writes.** `Stat` then rename: a file created in between is replaced. | Overwrites an existing ring in a race. | Create with `O_EXCL` (link/rename-no-replace), not stat-then-write. |
| 11 | L | **Export path leaves plaintext in memory and argv-adjacent places.** Passphrase and key bytes are never zeroed; the interactive prompt shells out to `stty`. | Best-effort hygiene only (Go cannot guarantee it), but cheap. | Zero passphrase and key buffers after use where practical; use the terminal ioctl via `golang.org/x/term` or syscalls rather than spawning `stty`; keep `mlock`/swap discussion in the roadmap. |
| 12 | L | **`export-secret` prints base64 to stdout with no guard.** Same for `export-priv` without `-o`. | Easy to leak into shell history, logs or a terminal scrollback. | Refuse to write secret material to a TTY unless `-force`; prefer `-o FILE`. |
| 13 | L | **Platform coupling.** Keychain integration shells out to `security`; `stty` for prompts; unix sockets only. | Fine for macOS/Linux, undefined elsewhere. | Put each behind a small interface with a build-tagged implementation and a clear "unsupported" error elsewhere. |
| 14 | L | **Test gaps.** Round-trip, wrong passphrase, one tamper, multi-key and secrets are covered; there is no fuzzing of `Open`, no crash/fault-injection of `save`, no concurrency test, no golden vector pinning the on-disk format. | A format that cannot be pinned cannot be kept compatible. | Golden ring file in `testdata/`, fuzz target for `Open`, concurrency test, injected-failure test around the write path. |
| 15 | L | **Docs drift.** The guide and the CLI disagree in places (the guide describes some entry types and verbs as moved elsewhere while the code still carries them; `-service` default differs from the documented one). | Users follow the doc and get surprised. | One source of truth: generate the verb reference from the command table; test that every documented verb exists. |

## Things deliberately **not** carried over

- A third entry kind that stores cleartext armored credentials. It is a different job from
  protecting key material, drags in a naming scheme from another system, and the ring's
  confidentiality story is cleaner without a cleartext kind. A generic *opaque secret* kind
  already covers "store some bytes".
- The legacy PBKDF2 path. A new project has no legacy rings; carrying the code only adds
  attack surface and a second parameter validator.
- Product-specific names in the file magic, environment variables and defaults. They become
  `keystore`-prefixed.

## Verdict

The cryptographic core is sound and small enough to rewrite cleanly. The three **H**
findings are all *operational* — lost updates, an unenforced passphrase invariant, and an
unsafe plaintext export — not cryptographic, which is the better kind to have. Build it
fresh as a standalone module using this design as the spec, with findings 1–10 resolved by
`v0.1.0`, and 11–15 as hardening tracked on the roadmap.
