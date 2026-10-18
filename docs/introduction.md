# keystore — a locked drawer for the keys that sign your work

*The key stays in the drawer; the drawer stays shut; the work still gets signed.*

Every signature a machine makes is only as trustworthy as the place its private key lives.
Too often that place is a file called `prod.key` in a deploy directory, readable by whatever
runs there, copied into backups, pasted into CI variables. A keystore is the drawer that file
should have been in: a place where key material is kept *closed* by default, and opened only
for as long as it takes to do one job.

What it actually is: a single JSON file, mode 0600, holding named entries — Ed25519 signing
keys and opaque secrets. Each private part is encrypted with AES-256-GCM under a key derived
from a passphrase with argon2id, a deliberately memory-hungry function that makes guessing
expensive. Public keys sit in the clear so anyone can list the ring or export a public key
without unlocking anything. Every field that gives an entry its meaning is authenticated, so
a tampered entry fails loudly instead of decrypting into something wrong. Every change is
locked, written to a temporary file, synced, and swapped in atomically.

The part most keyrings leave out is the agent. `keystore-agent` opens one key once, holds it
only in memory, and signs on request over an owner-only unix socket. The service that needs
signatures never sees the key or the passphrase — it asks, and gets 64 bytes back. That is the
difference between a key that is *stored* safely and a key that is *used* safely.

What it does not pretend to do: it is not a network service, a password manager or a hardware
security module. The passphrase is the ceiling — a short one is a short one, whatever the KDF.
Any process running as the same user can ask the agent to sign. Those limits are stated where
they apply, and the operator keeps control of every one of them: which key is current, when it
rotates, where the ring is backed up, and whether the agent runs at all.

**Read next:** [Executive summary](executive-summary.md) · [Architecture](architecture.md) · [User guide](userguide.md)
