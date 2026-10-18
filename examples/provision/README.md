# provision — one-time operator setup

**Threat addressed:** a signing key that lives as a plaintext file in a deploy directory,
backup or CI variable. Here the key is generated inside the encrypted ring and never exists
in plaintext on disk; the public half is what gets distributed.

**Steps:** write a 0600 passfile → `keygen` into the ring → `export-pub` to verifiers →
`add-secret` for the workload → `list` (no passphrase needed). The script then proves the
guard rails: a world-readable passfile, a short new passphrase, a second passphrase in the
same ring, and re-initialising an existing ring are all refused.

**Does not protect against:** anyone who can read *both* the ring and the passfile — keep the
passfile out of the ring's backups, or use the agent so services never need it. Root.

```sh
examples/provision/run.sh
```
