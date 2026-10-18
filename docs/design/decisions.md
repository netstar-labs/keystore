# Decisions

Choices made where the design left room. Newest last.

| # | Decision | Why |
|---|---|---|
| 1 | Layout: no Go in the root; public API in `pkg/`, helpers in `internal/`, both binaries in `cmd/`, scenarios in `examples/`. | Keeps the root thin and the public surface explicit. |
| 2 | No `LICENSE` while the repository is private; Apache-2.0 is added when it goes public. | Unlicensed means all rights reserved until release. |
| 3 | `.gitignore` ignores `testdata/` dirs except the root `/testdata/`. | Golden fixtures must be committed to pin the ring format. |
| 4 | Sentinel errors are defined in `internal/` and re-exported from `pkg/keystore`. | `internal/` cannot import `pkg/`; callers match on `pkg/keystore.Err…` with `errors.Is`. |
| 5 | `ErrLocked` after a 10 s wait for the ring lock. | Fails rather than hanging forever behind a stuck writer. |
| 6 | The ring file is read with a 16 MiB size cap. | Bounds memory on a crafted or wrong file; a real ring is a few KiB. |
| 7 | Fingerprints are `SHA256:` + unpadded base64 of SHA-256 over the SPKI DER. | Same shape operators already know from SSH. |
| 8 | The passphrase prompt reads from `/dev/tty`, not stdin; with no terminal and no other source the verb fails. | Piped stdin is easy to leak into logs; failing is the safer default. |
| 9 | `internal/term` and the passfile/env sources land in v0.1.0 (the core verbs need a passphrase); Keychain stays in v0.2.0. | Phase 1 cannot run without a passphrase source. |
| 10 | `rm` needs no passphrase. | Removal reveals nothing; requiring the passphrase would block cleaning up a ring whose passphrase is lost. Matches the reference design. |
