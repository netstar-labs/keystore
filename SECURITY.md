# Security policy

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" (security
advisories) on this repository. Do not open a public issue. Expect an acknowledgement within
five working days.

## What keystore protects

- A copy of the ring file alone reveals no private key or secret.
- Each entry is authenticated: changing its kind, id, public key, KDF parameters, salt, nonce
  or ciphertext is detected when that entry is unlocked. (The ring as a whole is not; see
  below.)
- A person or process that can write the ring but does not know the passphrase cannot read a
  key or forge a signature under a key you did not create.
- Cooperating writers (processes that take `<ring>.lock`) and crashes cannot lose or corrupt
  entries.
- Secret material is never accepted on the command line and never written to a terminal or an
  existing file by accident.

## What it does not protect

- **Weak passphrases.** argon2id slows guessing; it cannot rescue a short passphrase. The
  12-character minimum is a length check only: `aaaaaaaaaaaa` and twelve spaces pass.
- **A compromised user account.** Anything running as the ring's owner can read the
  passphrase source you configured, or ask a running agent to sign.
- **The agent signs whatever a permitted caller sends.** It checks *who* is calling (same
  uid), not *what* is being signed. Use a dedicated key per purpose, and domain-separate the
  messages your protocol signs.
- **Memory.** Go cannot guarantee that key bytes are erased from memory or kept out of swap.
- **Root.** File modes and socket permissions do not constrain the superuser.
- **The ring as a whole.** Authentication covers each entry, not the file. Someone who can
  write the ring can change `current` (so `keystore sign` without `-id`, or an agent started
  without `-id`, uses a different key of yours), reorder or delete entries (deleting the
  `current` entry also needs `current` edited, or the ring no longer loads), edit `created`,
  or put back an older copy of the file, which brings back removed keys *and* the passphrase
  in force when it was taken (restoring a backup undoes a `passwd`). An entry copied from
  another ring that shares the passphrase unlocks in place of the entry with the same id
  and kind. None of this yields a key or a signature under a key you did not choose, but
  it can make a command sign with the wrong one of your keys, resurrect a retired key, or
  deny service. Always pass `-id` in scripts, pin public keys in verifiers, and after a
  suspected ring-write compromise create a new key and passphrase rather than running `rm` or
  `passwd` on the old ring.
- **`pub` is readable without the passphrase but authenticated only at unlock.** A ring
  writer can swap it, and `export-pub` and the fingerprints `list` shows will then be theirs
  (signing still fails closed).
  Take the public key from the output of `keygen`/`add` when you create the key, or check a
  test signature against the key you publish.
- **Revocation.** `rm` and `passwd` change the ring, not its earlier copies: backups, old
  snapshots and the `.<ring>.<random>.tmp` file a hard kill (SIGKILL, power loss) can leave
  beside the ring (mode 0600, a full encrypted copy; nothing sweeps it) keep the old entries
  and the old passphrase. `passwd` does not rotate private keys. After a passphrase
  compromise, treat every key as compromised and rotate the keys.

## Known limits

- **The keychain source needs a printable-ASCII passphrase.** macOS `security … -w` prints
  other values as hex, which then fails to unlock (or, on an empty ring, would be
  established as the passphrase). Use a passfile for non-ASCII passphrases. Any failure of
  `security`, such as a locked keychain, is reported as "no keychain item". The item has
  the default access control, so assume any process running as you can read it with
  `security find-generic-password -w` (inferred, not tested); it is no stronger than a 0600
  passfile.
- **The agent's environment passphrase stays readable.** With `KEYSTORE_PASSPHRASE` the agent
  clears its own copy (children and `os.Environ` no longer see it), but the initial
  environment block stays readable by the same user and root (`ps eww` on macOS,
  `/proc/PID/environ` on Linux). Use `-passfile`. This concerns where the launcher kept the
  value (unit `Environment=` lines, shell history), not a new capability: the same user can
  read a 0600 passfile too.
- **Anyone who can write the ring can make it slow or unusable.** One forged entry can make a
  single command that unlocks it spend one maximal derivation (1 GiB, 64 passes: roughly
  a minute or two and 1.1 GB on an Apple-silicon Mac, more on slower hardware). `add`
  unlocks only the first entry, `passwd` stops at the first entry that fails, and `list`,
  `export-pub`, `use` and `rm` run no KDF. A single malformed entry makes the whole ring
  unreadable. This is no worse than deleting the file; write access to the ring is the
  boundary.
- **Ring JSON is decoded with Go's `encoding/json`**, which matches keys case-insensitively
  and lets a duplicate key win. Every entry field that protects a key is authenticated, so
  this cannot bypass the encryption; `current`, entry order and `created` are not, and anyone
  who can write the ring can change them anyway. Another tool might read a different value
  than this one does.
- **Locking is advisory and held across the KDF.** A process that ignores `<ring>.lock` can
  race. `add` and `passwd` hold the lock while they derive keys (roughly 0.1–0.3 s per derivation at
  the default cost; `passwd` does two per entry), so with a large ring a concurrent writer
  gets `ErrLocked` after the 10 s wait; nothing is lost.
- **Where the ring lives matters.** Keep it in a directory only you can write: another user
  could pre-create `<ring>.lock` (permanent "permission denied"), hold the lock, or replace
  the ring. Do not hardlink a ring (the alias takes a different lock and the rename breaks
  the link); use a symlink. The ring file must not itself be a mount point (the rename fails),
  and `init`/`keygen` need a filesystem that supports hard links (exFAT does not; `add` works
  on a ring copied there). Every rewrite sets mode 0600.
- **The library's `*Keystore` is not safe for concurrent use** (it is a snapshot with no
  internal locking; `-race` reports it). Open one per goroutine. Cross-process safety is
  unaffected.
- **No Unicode normalisation.** The minimum counts characters, and a passphrase is used as
  its exact bytes: a composed é and a decomposed e + U+0301 derive different keys. `add` does
  not upgrade an older entry to a newer KDF cost; `passwd` does.
- **The 12-character minimum is a CLI policy.** The library accepts any non-empty passphrase,
  and a ring emptied by another process between `keygen` opening it and its write can be
  re-established without the minimum. The window lasts as long as you take to type the
  passphrase, because the CLI decides from the ring as it was at open.

## Supported versions

Only the latest `v0.x` release receives fixes.
