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

## Supported versions

Only the latest `v0.x` release receives fixes.
