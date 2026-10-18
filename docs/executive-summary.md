# Executive summary

## What it is

`keystore` is a small, auditable tool and Go library that keeps signing keys and secrets
encrypted at rest in one file, and lets programs use those keys without holding them.

## Why it exists

Systems that sign things — releases, requests between services, tokens — need a private key
available without a human present. The common answer is a plaintext key file, which turns
every backup, every log of a CI variable and every compromised dependency into a key leak.
`keystore` replaces that file with:

- **Encryption at rest** using current, memory-hard password hashing (argon2id) and
  authenticated encryption (AES-256-GCM).
- **Tamper evidence** — any edit to an entry is detected, never silently accepted.
- **Crash and concurrency safety** — a ring is never left half-written and two writers can
  never lose each other's changes.
- **A signing agent** that holds one key in memory so the program doing the work needs
  neither the key nor the passphrase.
- **Standard formats out** (PKCS#8 / SPKI PEM), so there is no lock-in.

## What it costs

Two dependencies, both maintained by the Go project (`golang.org/x/crypto` for argon2id,
`golang.org/x/sys` for terminal and socket credentials). macOS and Linux only.

## Risks and limits

- Security is bounded by passphrase strength; a 12-character minimum is enforced when a
  passphrase is set.
- Anyone running as the same OS user can request signatures from the agent.
- No hardware-backed storage in early releases; the `crypto.Signer` seam allows it later.

## Status

Pre-release (`v0.x`, which carries no API-stability promise). The ring **file format** is
versioned separately (`keystore/v1`) and is the compatibility contract. See the
[roadmap](design/scope.md#roadmap).
