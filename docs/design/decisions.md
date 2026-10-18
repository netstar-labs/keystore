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
| 11 | The CLI's terminal check is a package variable so the "refuse to print a key to a terminal" guard is tested without a TTY; the real check is tested on a regular file. | CI has no terminal; the guard must still be covered. |
| 12 | `golang.org/x/sys` stays at v0.47.0 (the minimum `x/crypto` requires) rather than `@latest`; `x/crypto` is v0.56.0 and the toolchain is pinned `go1.27.2`, both to clear govulncheck findings. The remaining module-level finding is `x/crypto/openpgp` (unmaintained, no fix), which is not imported. | Smallest change to the module graph; bump deliberately. |
| 13 | The argon2id known-answer test checks `Derive` against a direct `argon2.IDKey` call plus a recorded value. | The published reference vectors use 8-byte salts and sub-MiB memory, outside this package's bounds; `x/crypto` validates argon2id against them itself. |
| 14 | `created` is not authenticated. | It is display metadata; binding it would make a clock change look like tampering. The tamper test asserts it stays editable. |
| 15 | Adding to an empty ring establishes the passphrase (confirmed when prompted, 12-character minimum); adding to a non-empty ring unlocks with the existing one. | The minimum applies to establishing, not to unlocking. |
