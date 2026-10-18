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
| 16 | If `KEYSTORE_KEYCHAIN` is set and the keychain lookup fails, the command fails; it does not fall through to the passfile or prompt. | An explicitly configured source that silently degrades hides misconfiguration. |
| 17 | The keychain is driven via `/usr/bin/security` by absolute path; service names use the entry-id alphabet. | No `PATH` hijack; a service name can never be parsed as an option. |
| 18 | Imported secrets are 1 byte to 64 KiB. | Secrets are keys and tokens; the bound keeps a ring small and parse-safe. |
| 19 | `passwd` takes the new passphrase from `KEYSTORE_NEW_PASSPHRASE`, `-new-passfile` or the prompt — never from the keychain or `KEYSTORE_PASSPHRASE` — and refuses a new passphrase equal to the old. | The current and new values must come from distinct places, or automation would "change" to the same value. |
| 20 | `import-secret` reads base64 from `-in FILE`, piped stdin, or a no-echo prompt when stdin is a terminal. | Never argv; a terminal user should not see the value echoed. |
| 21 | The golden fixture gained a `secret` entry by appending to the existing file; the original entry is byte-identical. | Proves the v1 entry written in v0.1.0 still opens, while pinning the secret kind. |
| 22 | `ResolveSigner` lives in `pkg/agent`, not `pkg/keystore`, and the client is `agent.Dial` (not `DialAgent`). | `pkg/agent` may import `pkg/keystore` but not the reverse; the package name already says "agent". |
| 23 | `sign` and `verify` accept messages up to 1 MiB on both the ring and agent paths. | The agent frame limit; one limit keeps scripts portable between paths. Large artifacts are covered by signing a digest manifest. |
| 24 | The agent client checks the agent's peer uid and verifies every signature it returns; it refuses prehash and context options. | A squatted socket or a misbehaving agent cannot hand back a signature under the wrong key. |
| 25 | The agent removes `KEYSTORE_PASSPHRASE` from its environment after reading it and refuses `KEYSTORE_KEYCHAIN`. | A daemon must not keep the passphrase in its environment or trigger keychain UI. On Linux the initial environment stays visible in `/proc/PID/environ` to the same user; prefer `-passfile`. |
| 26 | `Server.Close` is safe before `Serve`; found by a hanging test where `Close` ran first and `Serve` then blocked forever. | Regression test `TestCloseBeforeServe`. |
| 27 | Shell examples are tested by running their `run.sh` from `go test`; refusals are checked against the expected error text, not just a non-zero exit. | A refusal for the wrong reason would otherwise pass. |
