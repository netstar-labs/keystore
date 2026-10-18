# Security policy

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" (security
advisories) on this repository. Do not open a public issue. Expect an acknowledgement within
five working days.

## What keystore protects

- A copy of the ring file alone reveals no private key or secret.
- Any modification of an entry is detected when it is unlocked.
- Concurrent writers and crashes cannot lose or corrupt entries.
- Secret material is never accepted on the command line and never written to a terminal or an
  existing file by accident.

## What it does not protect

- **Weak passphrases.** argon2id slows guessing; it cannot rescue a short passphrase.
- **A compromised user account.** Anything running as the ring's owner can read the
  passphrase source you configured, or ask a running agent to sign.
- **The agent signs whatever a permitted caller sends.** It checks *who* is calling (same
  uid), not *what* is being signed. Use a dedicated key per purpose, and domain-separate the
  messages your protocol signs.
- **Memory.** Go cannot guarantee that key bytes are erased from memory or kept out of swap.
- **Root.** File modes and socket permissions do not constrain the superuser.

## Known limits

- **The keychain source needs a printable-ASCII passphrase.** macOS `security … -w` prints
  other values as hex, which then fails to unlock (or, on an empty ring, would be
  established as the passphrase). Use a passfile for non-ASCII passphrases.
- **Anyone who can write the ring can make it slow or unusable.** Per-entry KDF costs are
  bounded (≤ 1 GiB, ≤ 64 passes), but a crafted ring with many maximal entries can make
  `passwd` take hours — as deleting the file would also deny service. Write access to the
  ring is the boundary.
- **Ring JSON is decoded with Go's `encoding/json`**, which matches keys case-insensitively
  and lets a duplicate key win. Every value that is used is authenticated, so this cannot
  bypass the encryption, but another tool might read a different value than this one does.
- **The 12-character minimum is a CLI policy.** The library accepts any non-empty passphrase,
  and a ring emptied by another process between `keygen`'s read and its write can be
  re-established without the minimum.

## Supported versions

Only the latest `v0.x` release receives fixes.
