# Defects log

Every real defect the audit found in the code, scripts or CI (not documentation drift, which is in
[audit-findings.md](audit-findings.md)): how it was found, how it was confirmed, the fix, and where the
test that pins it lives. "Real" means a skeptic reproduced it. Severity is the skeptic's.

**None of these was a break of the cryptography.** Every pass that looked at the AEAD construction, the KDF
and the key lifecycle (A3-1, A3-2, the blind implementer, the OpenSSL and RFC 8032 known answers) found them
sound. Properties 3 and 4 held under every crash and contention test, including real `SIGKILL` loops
([topology-integration.md](topology-integration.md): "No production defect was found").

Labels: **[R]** reported by the ledger or a merge message, not re-run while writing this page; **[V]** checked
while writing this page. Merge hashes are on `main`.

## Defects in the product

| # | Sev | Defect | Found by | How confirmed | Fix (merge) | Pinned by |
|---|---|---|---|---|---|---|
| 1 | MEDIUM | A negative `-ttl`/`-idle` silently disabled agent expiry | auditor C (correctness); reproduced with an agent still signing after 3 s | skeptic S1 on the base binary: alive and signing after 3-4 s, both flags | `ffe9c9c`: refused in `Serve` and in the CLI before the passphrase is read; adds `agent.ErrNegativeLifetime` | the two tests added in that merge; 4 of 4 mutants killed |
| 2 | LOW | `export-priv`/`export-secret > file` created a key file at the umask mode (0644) | A3-5 (operator surface) | `ls -l` on the base; the fix skeptic showed in a Linux container that a second uid (`nobody`) could read the base file and nothing was in the fixed one | `96d0b98`: refused when stdout is a regular file others can read | `TestExportRefusesRedirectToAFileOthersCanRead` and the cases added after review |
| 3 | LOW | `verify` exited 1 for a bad signature, the same code as "could not check" | A3-5 | observed | `2793e3c`: exit 3 | exit-status table test |
| 4 | LOW-MED | `Parse` decoded the whole `entries` array before validating: a 16 MiB ring of `{}` took about 3.7 GB RSS in `list` | A3-4 (ring file lens), `/usr/bin/time -l` on the real binary | skeptic S2: 3.85 GB, 2.89 s; fix: 67 MB, 0.57 s | `dafd3f6`: incremental decode, no entry-count cap | `FuzzOpenRing` allocation check, `TestParseEntriesShapes` |
| 5 | LOW | A second `entries` key made `Parse` allocate about 640 B per occurrence: 16 MiB accepted at 1.93 s and 786 MiB | L1 (verification) | measured in a test copy | `b04b179`: a second `entries` key rejects the ring; owner-accepted (decision 41) | repeated-key rejection test (replaced the old last-wins test) |
| 6 | LOW | The agent allocated the claimed frame length from a 5-byte header: 697 stalled connections gave +698 MiB | L1 | measured in a test copy | `d4be234`: read the body incrementally; 700 stalled claims: +642 MiB to +9 MiB | `frame_alloc_test.go`, `FuzzFrameRoundTrip` |
| 7 | LOW | `Serve` stopped on any non-closed `Accept` error (EMFILE included) without closing the listener; a stuck "zombie" variant | auditor C, then A3-3 | `ulimit -n` flood on the real binary: exit 1 and a stale socket | `a859214`: EMFILE retried, anything else a clean stop | deterministic `RLIMIT` test |
| 8 | LOW | Two findings in the agent's `Listen`: a socket path over the OS limit gave a cryptic bind error and left `.lock` behind; concurrent `Listen` calls left the process umask at 0177 in 166 of 200 rounds | auditor C | skeptic S1: a 142-byte path; 4 concurrent `Listen` calls | `22a2a19` (path limit named), `8b32c90` (umask serialised) | max and max+1 tests; 8 goroutines x 50 rounds |
| 9 | LOW | `verify -pub` and the signature file were read uncapped (a 1 GiB sparse file was about 2 GB RSS) | auditor B | skeptic S3 | `db9d151`: 64 KiB cap | boundary test at 64 KiB and +1 |
| 10 | LOW | The library accepted an empty passphrase in `Add`, `AddSecret`, `Import`, `ImportSecret` | auditor C | `Add("a", nil)` returned nil | `a2003af` | five-method probe, legacy-ring recovery |
| 11 | LOW | `Import` accepted a 64-byte key whose public half was not its seed's, bricking the entry with a misleading error | A3-1, A3-2 | proof-of-concept program | `78e19fa` | one-bit flips at bytes 0, 31, 32, 63 |
| 12 | LOW | SIGQUIT and SIGHUP at the passphrase prompt left echo off (and SIGQUIT dumped a 16 KB traceback, exit 2) | A3-5, pty tests | python `pty.fork` on the base binary | `389c386` | real-pty tests in `internal/term` |
| 13 | LOW | Echoed paths and flag names reached the terminal raw: escape and carriage-return injection could forge `verified:` lines | A3-5, `od -c` | skeptic: four rounds; 4,427 built-binary runs, 0 flagged after; the harness flagged 816 on the base | `44076e8` (one sanitiser, `term.Clean`) | `clean_test.go`, `kill_clean_test.go`, per-channel tests |
| 14 | LOW | An ambient `KEYSTORE_PASSPHRASE` silently overrode an explicit `-passfile`, including when establishing a passphrase | A3-2, A3-5 | `keygen -passfile strong` established under the stale value | `2e39346`: announced when unlocking, refused when establishing (decision 40) | the shadowing tests |
| 15 | INFO | The lock file was created 0400 under umask 0277, so every later open failed | A3-4 | macOS repro and a Linux non-root container | `ce8c582`: 0600 whatever the umask (ring and agent lock) | umask test, ring and agent |
| 16 | LOW (cosmetic) | Agent rejection log ended with a literal `<nil>`; a directory error printed `-rwxrwxrwx`; PEM errors for an encrypted or wrong-type key said "exactly one PEM block of the right type" | A3 interop agent | real Linux binaries | `49b2ec1`, `29e9973` | message tests; a 6,010-input differential on the PEM change |
| 17 | HIGH as worded (doc), LOW as code | `sign` could be silently redirected to another key by editing the unauthenticated `current` | W1-D1 doc auditor, A3-1 | `sed` on a ring, then `sign` exit 0 with the other key | `43811fd`: `sign` names its key, `-expect-fp` pins it; no format change (decision 39) | fingerprint and pin tests |
| 18 | LOW | A running agent kept holding a key after its socket file was removed: no log, never exits (A5-L2) | A5 | `rm` the socket; agent alive | `ebf5897`: the agent stops with exit 1; a first version was rejected for a false stop when `Close` raced the check | the three tests in that merge; 1500+4000 race probes |
| 19 | LOW | A ring verb with no home directory silently created `default.ks` in the working directory (A5-L4) | A5 | `env -i keystore keygen` exit 0 | `49a29bf` (first version rejected: it broke `sign -agent`) | exit-2 test |
| 20 | INFO | SIGHUP killed the agent leaving the socket and lock (exit 129) | L1 | `kill -HUP` on the real binary | `58408dc` | clean-stop and inherited-ignore tests |
| 21 | LOW | A typed-nil `crypto.Signer` came back on the error path of `Signer`/`ResolveSigner`: `s != nil` was true and a naive caller panicked | **mutation testing** (L2), not any review | the skeptic's base program shows `s != nil` | `5075321`: `return nil, err` (not the typed value) | `typednil_test.go` and three restore-mutants |
| 22 | LOW | The agent's socket-lost log line printed the path unsanitised (ESC and CR raw) (A7 M1) | A7 skeptic | `od -c` | `0632c47`: cleaned at the log sink | forged-line test (a newline in the path) |
| 23 | LOW | `keystore-agent -h` printed an error line and exited 1 (A7 M3) | A7 skeptic | `echo $?` | `bc08d87` | `-h` exit test, and an unknown flag still exits 1 |
| 24 | INFO | `verify`'s help and the generated reference did not say exit 3 (A7 M14) | A7 skeptic | `grep exit docs/reference.md` empty | `07c6d65` | reference regenerated; `TestReference` |

## Defects in scripts, CI and tests

| # | Sev | Defect | Found by | Fix (merge) |
|---|---|---|---|---|
| 25 | MEDIUM (CI) | The CI systemd step could never fail: it ended in an unconditional `true`, its filter did not match systemd 257's wording, and an unknown key or bad value only warns at rc 0 (A4-1). The workflow token was also read-write by default (A4-2) | A4, reproduced in a Debian container | `43655ff` |
| 26 | LOW | `build/keystore --release` stamped a dirty tree like a clean one while the binary embedded `vcs.modified=true` (A7 M6) | A7 skeptic | `8a90392`: refuses a dirty tree; dev builds stamped `-dirty`; the script now has a test |
| 27 | LOW | The tagged tiers were never type-checked or linted in CI, and CI fuzzed 2 of 10 targets (A7 G8) | A7 | `1d06882` (unproven on a hosted runner) |
| 28 | LOW-MOD | `keychain_other.go` (the off-macOS stub) had no test: a stub returning `nil, nil` would have kept Linux CI green while "degrades with a clear message" became an empty passphrase (A7 M2) | A7 skeptic | `1d06882`: red against that mutant in a container |
| 29 | LOW | `TestGetMissing` ran the real `/usr/bin/security` in the default macOS suite and asserted nothing, because `Get` maps every failure to `ErrNotFound` (A7 G15) | A7 skeptic | `1d06882`: deleted |
| 30 | test | Several tests were wrong or racy and were fixed in review, not hidden: a wrong-uid test failed 10/10 on linux/arm64 (the server closes with the request unread; Linux reports `ECONNRESET`); an idle-not-reset probe survived about 21 % of runs; `TestCloseBeforeExpiry` failed 33 times under `-race -count=50`; mutation runs initially excluded `docs/` so `TestReference` failed every mutant that reached `cmd/keystore` (those runs were discarded and redone) | the skeptics, `-race -count=50`, the runner's own summary | `963ab93`, `3f059ac` (see [mutation-hardening.md](mutation-hardening.md) "Method") |

## Found in the audit's own reports (corrections, not defects)

The audit also corrected itself in the open: the A7 auditor's "pipes and `>>` unchecked" was wrong for `>>`
(M11); its "keep `TestGetMissing`" premise was wrong (G15); its "`retract v0.1.0`" advice cannot work for an
unpublished version (G1); the ledger's "CLI rejects `pub` of `""`" was wrong at parse time; an earlier draft
of the topology page said `fsync` ordering "is exercised" and withdrew it. See [gap-audit.md](gap-audit.md).

## Not defects (refuted by the skeptic, kept for the record)

Connection-count cap (W2-3-1, REFUTED as a defect); core-dump hardening (W2-3-3, REFUTED: Go does not dump
core by default); the library `Server` retaining the signer after `Close` (W2-3-4); idle timer reset by `P`
(W2-3-I, documented behaviour); a foreign `<ring>.lock` (W2-4-2, downgraded: an attacker can equally block
via the ring path).
