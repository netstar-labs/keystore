# Audit findings (A1 to A4, with the later passes cross-referenced)

Every finding the 2026-10 audit raised in its first four passes, what an independent skeptic made of
it, and what became of it. The later passes have their own pages: A5 [silent-degradation.md](silent-degradation.md),
A6 [format-compatibility.md](format-compatibility.md), L1 [verification-optimization.md](verification-optimization.md),
L2 [test-ledger.md](test-ledger.md) and [mutation-hardening.md](mutation-hardening.md), L3 and L3b
[live-integration.md](live-integration.md) and [topology-integration.md](topology-integration.md), A7
[gap-audit.md](gap-audit.md). Defects with how they were found: [defects-log.md](defects-log.md).

Source: the audit's running ledger ([audit-ledger.md](audit-ledger.md)) and the merge commits on `main`
(`git log --merges --oneline main`), each of which carries the fix skeptic's verdict in its message.
Labels: **[R]** reported by the ledger or a merge message and not re-run while writing this page;
**[V]** checked while writing this page; **[I]** inferred. IDs are the ledger's: `W1-nn` from wave 1
(four auditors: A simplify, B dedup, C correctness, D doc drift), `W2-<lens>-n` from wave 2 (the five
security lenses and the blind implementer), `S1-S5` the finding skeptics.

## How a finding was processed

Candidate (auditor claim, unverified) -> a fresh **finding skeptic** (CONFIRMED / PLAUSIBLE / REFUTED) ->
for a confirmed one a branch `fix/<ID>-<slug>`: failing test first, fix, gate, then a **fix skeptic** with
seven lenses (the new test fails without the fix; root cause not reproduction; behaviour preserved,
golden file byte-identical, exported-surface diff; no new gap; reachable in the real binary; least-code
rung; for crypto and trust boundaries an independent route) -> **FIXED-VERIFIED**, **FIXED-UNPROVEN**
(say which lens could not run) or REJECTED -> `git merge --no-ff` with the verdict in the message.
A rejected first version was reworked, never merged. Anything that would change the ring format, the
agent wire protocol, the default KDF cost or a documented guarantee was a stop-and-ask item; none was
changed (decision 39).

Severities are the skeptic's where there is one. "Merge" is the commit on `main`; the fix commit is
inside it.

## Verdicts at a glance

Counted from the merge messages [V: `git log --merges main`, ignoring the "Merge main into ..." sync
merges]: 42 merge commits. 38 say FIXED-VERIFIED; one says FIXED-UNPROVEN (`1d06882`, A7 CI and keychain:
every claim reproduced locally, unproven only on a hosted runner because CI has never run); one says
"Skeptic-Verified" for the CI systemd step without the verb (`43655ff`); one is a docs-and-config merge
recorded as "docs skeptic pending" when it landed (`addf124`, A5 operating notes); one is the rework
commit of the shadowed passfile (`c39085b`), whose two-round verification is on `2e39346`. Findings the
skeptics REFUTED or downgraded are marked in the tables, and findings that were documented rather than
fixed say so.

## Wave 1: A1 / A2 (four auditors)

| ID | Sev | Claim | Skeptic | Outcome |
|---|---|---|---|---|
| W1-01 | MEDIUM | A negative `-ttl`/`-idle` silently disables agent expiry (timers armed only if `> 0`) | CONFIRMED (both flags; agent alive and signing after 3-4 s) | **Fixed**, merge `ffe9c9c`: refused in `Serve` and before the passphrase is read; adds `agent.ErrNegativeLifetime` |
| W1-02 | LOW | `Add`/`AddSecret`/`Import`/`ImportSecret` accept an empty passphrase while `ChangePassphrase` refuses it; SECURITY.md said "non-empty" | CONFIRMED | **Fixed**, `a2003af` (a legacy ring made with an empty passphrase still unlocks and can be recovered with `ChangePassphrase`) |
| W1-03 | LOW (availability) | `passwd` holds the ring lock for 2N argon2 runs; about 40 entries is 10.8 s, over the 10 s lock timeout, and a concurrent writer gets `ErrLocked` | CONFIRMED | **Documented**, not fixed (an optimistic scheme costs 25-40 lines; the KDF cost is not lowered): SECURITY "Locking is advisory and held across the KDF" |
| W1-04 | LOW (embedders) | `Listen` flips the process-wide umask without serialisation; 166 of 200 rounds left umask 0177 | CONFIRMED | **Fixed**, `8b32c90`: serialised with a mutex. The skeptic measured why the umask change stays (without it the socket is briefly observable at 0755: 17/40 on darwin, 39/40 on Linux) |
| W1-05 | MINOR | `*Keystore` data race on its file handle | CONFIRMED | **Documented**: "not safe for concurrent use" (SECURITY, scope.md) |
| W1-06 | LOW | A socket path over the OS limit gives a cryptic bind error and leaves `.lock` behind | CONFIRMED | **Fixed**, `22a2a19`: up-front length check naming the limit (103 on macOS, 107 on Linux) |
| W1-07 | INFO (was MINOR) | `keygen` leaves an empty ring when passphrase establishment fails | CONFIRMED, downgraded (same state `init` leaves) | **Documented**, not fixed (userguide Passphrases). The ledger first said "fix"; see [open-items.md](open-items.md) |
| W1-08 | INFO | `len([]rune(string(pw)))` copies the passphrase into an uncleared string | CONFIRMED | **Fixed**, `af60243` (`utf8.RuneCount`; 0 mismatches over 3.2 M inputs) |
| W1-09 / W2-3-1 | LOW (was MED) | `Serve` returns on any non-closed `Accept` error, including EMFILE, without closing the listener; a "zombie" variant | CONFIRMED (exit and stale files; zombie plausible, not run) | **Fixed**, `a859214`: EMFILE/ENFILE logged and retried, any other error stops the agent cleanly, exit 1. The "connection cap" part of W2-3-1 was REFUTED as a defect |
| W1-10 | INFO | `readSecret` on a terminal is capped at 1024 B though secrets are 64 KiB; example readPassfile follows symlinks | CONFIRMED (UX hang) | **Documented**: userguide Secrets (use `-in` or stdin) |
| W1-11 | LOW | `verify -pub` and `readSignature` read uncapped (a 1 GiB sparse file is about 2 GB RSS) | CONFIRMED | **Fixed**, `db9d151`: 64 KiB cap |
| W1-12 | optional | six byte-identical `examples/*/run_test.go` | skipped (loses per-example `go test` selectivity; -105 lines) | Not done |
| W1-13 | | constants that must agree (ring magic, frame-limit text, keychain id-rule text) | only (c), the keychain error text, worth doing | **Fixed (c)**, `af60243`; (a), (b), (d) skipped |
| W1-14 | | agent builds a `crypto.Signer` then type-asserts to `ed25519.PrivateKey` | DO | **Fixed**, `af60243` (calls `ExportPrivate`; signatures byte-identical) |
| W1-15 | | dead error branches after `crypto/rand.Read` | SKIP (fail-closed; the signature change is not worth it) | Not done |
| W1-16 | | repeated write/sync/close and capped-read idiom | SKIP | Not done |
| W1-17 | | redundant `LOCK_UN` before `Close` | SKIP (harmless margin) | Not done |
| W1-18 | | `examples/signed-requests/rand.go` seam | DO (-5 lines) | **Done**, `af60243` |
| W1-19 | | `Keystore.Path` unreachable | DELIBERATE keep (public API) | Kept |
| W1-D1 | HIGH as worded; LOW as code, MED as doc falsehood | Docs said any modification is detected and every value authenticated; actually `current`, entry order, the entry set and whole-ring rollback are not. Editing `current` then `sign` signs with another key, exit 0 | CONFIRMED. Ring-format change would be needed to authenticate: stop-and-ask | **Resolved without a format change**, decision 39: docs say exactly what is authenticated (`7b66068`), and `sign` names the key it used and takes `-expect-fp` (`43811fd`). A `v2` was costed and does not pay (skeptic: `ring_id` about 30-50 lines, keyed MAC about 150-250 lines, rollback needs external state) |
| W1-D2 | MOD | docs omit "cooperating" for the lock | CONFIRMED | **Documented**, `7b66068` |
| W1-D3 | LOW (was MOD) | "agent environment variable removed once read": still visible in `ps eww` (macOS) and `/proc/PID/environ` | CONFIRMED on both; `-passfile` avoids it | **Documented** (userguide, SECURITY, decision 25) |
| W1-D4 | MOD | release archives are not reproducible (binaries are; SBOM date, tar mtimes, gzip header differ) | CONFIRMED | README reworded at the time (binaries are reproducible, archives are not); the stamp itself was changed later by A7 M6 (decision 43) |
| W1-D5 | MOD | userguide said every verb accepts `-keystore`; false for `verify`, `keychain-set` | CONFIRMED | **Fixed**, `50370f9` |
| W1-D6..10 | LOW | agent has no default ring; format.md `created` rule; architecture dependency edges; scope.md stale API names and "one named error"; socket-path length; passphrase length caps | CONFIRMED | **Fixed**, `50370f9` (scope property 2 now distinguishes parse-time `ErrBadFormat` from unlock-time `ErrBadPass`) |

Simplify and dedup (auditors A and B): the skeptic S5 ran the full suite on the batch (18/18 `-race`
packages at the time, golden SHA-256 unchanged, staticcheck and deadcode clean) and chose the four DO
items above. Their considered-and-rejected lists are in [the ledger](audit-ledger.md).

## Wave 2: blind implementer and interop (independent routes)

| ID | Result |
|---|---|
| W2-B0 | **Spec equals code.** An agent given only `docs/format.md` (never the code) wrote a standalone decrypter that opened both entries of `testdata/golden.ks`; a round trip with the real CLI worked both ways; every authenticated field fails as specified; `created` and `current` are unauthenticated as documented [R: ledger]. |
| W2-B1 | `format.md` was underspecified (JSON `null`, duplicate keys, missing fields, empty `entries`, secret `pub` absent versus `""`, base64 canonical form, the "newer vN" rule, `current` naming a secret). None changed the AAD or KDF. Fixed in the format documentation and pinned by the A6 golden tests (`77f56c7`) [I: attribution of each wording change not traced]. |
| Interop | Linux arm64 (alpine, kernel 6.18), 17/17 test binaries pass as root and as uid 1000 including the six examples; OpenSSL 3.5.9 interop both directions; RFC 8032 TEST 1/2/3/1024/SHA(abc); NIST GCM TC16; `kdf.Derive` equals `argon2.IDKey` equals OpenSSL argon2id at 64 MiB / t=3 / p=1; cross-uid agent rejection by the peer-uid check; `systemd-analyze verify` rc 0 [R: ledger]. Promoted into the repository by the L2 and L3 passes. |
| W2-B2 | The blind implementer did not test duplicate JSON keys, `null`, non-canonical base64, duplicate entry ids or the 16 MiB limit [R: ledger] | Covered since by the A6 goldens (`77f56c7`) and the A7 skeptic's format run (17 crafted rings) [R] |
| W2-I1 | cosmetic: agent rejection log ended with a literal `<nil>` | **Fixed**, `49b2ec1` |
| W2-I2 | PEM import errors for encrypted or wrong-type keys said "expected exactly one PEM block of the right type" | **Fixed**, `29e9973`: names what was found; an encrypted key gets the `openssl pkey` hint (a 6,010-input differential left accept/reject unchanged) |
| W2-I3 | import accepts text before the BEGIN line | **Left as is**: the skeptic's reason is that tightening would break `openssl pkcs12` "Bag Attributes" output; the ledger says "doc", the wording was not traced |
| W2-I4 | `import` does not create the ring | **Documented** (userguide verbs table) |
| W2-I5 | agent directory error printed `-rwxrwxrwx` | **Fixed**, `49b2ec1` (`mode 0755`) |

## Wave 2: A3 security lenses

### A3-1 format and AEAD binding (no CRITICAL or HIGH; AEAD construction sound)

| ID | Sev | Claim | Skeptic | Outcome |
|---|---|---|---|---|
| W2-1-F1 | LOW code / MED doc gap | `pub` is readable without the passphrase but authenticated only on unlock; a ring writer can swap it and `export-pub` then hands out the attacker's key | CONFIRMED, doc-only (signing still fails closed) | **Documented**, `7b66068`: take each public key from `keygen`/`add` output; `export-pub` reads the stored copy |
| W2-1-F2 | LOW | no ring binding in the AAD: a same-id, same-kind entry from ring A unlocks in ring B sharing the passphrase | CONFIRMED | **No format change** (decision 39); mitigated by `sign` naming its key and `-expect-fp` (`43811fd`) |
| W2-1-F3 | LOW | rollback and replay undetectable | CONFIRMED | **Documented** as a known limit |
| W2-1-F4 (= W2-2-4) | LOW | `Import` accepts a 64-byte key whose public half is not its seed's, bricking the entry | CONFIRMED | **Fixed**, `78e19fa` (1000 random valid keys import; 1000 single-bit-corrupted keys all refused) |
| W2-1-F5 | INFO | SECURITY said `passwd` can take "hours"; measured maximum is about 56 s and 1.1 GB per command | CONFIRMED overstatement | **Documented**, `7b66068` |
| W2-1-F6 | INFO | non-canonical base64 and trailing PKCS#8 bytes accepted | CONFIRMED | **Documented** in format.md |

Verified sound by the lens [R]: AAD injective (352,947 tuples and a 300k fuzz, no collisions); no
nonce or key reuse (66 unique salts and nonces over 20 `passwd` rounds; one `Seal` call site); one
indistinguishable `ErrOpen`; KDF parameters authenticated.

### A3-2 KDF, passphrase and key lifecycle (no flaw in the crypto core)

| ID | Sev | Claim | Skeptic | Outcome |
|---|---|---|---|---|
| W2-2-1 (= W1-D3) | LOW (was MED) | agent `Unsetenv` does not hide the passphrase from `ps eww` on macOS | CONFIRMED | **Documented**; use `-passfile`; all shipped units use it |
| W2-2-2 | LOW | an ambient `KEYSTORE_PASSPHRASE` silently overrides an explicit `-passfile`, including when establishing | CONFIRMED | **Fixed**, `2e39346` after two rounds: announced when unlocking, refused when establishing (decision 40) |
| W2-2-3 | LOW | a hard kill leaves `.RING.*.tmp` (a full encrypted copy, 0600); `rm` and `passwd` do not revoke earlier copies | CONFIRMED | **Documented**, `7b66068` (SECURITY "Revocation"); no sweep (deleting files in a user's directory is worse) |
| W2-2-5 | INFO | keychain item has no per-app isolation [I]; PKCS#8 import lenient; no quality floor or Unicode normalisation; `Save` reports a directory-sync error after the rename; `add` never upgrades an older entry's cost | | Directory-sync-after-rename: recorded in [silent-degradation.md](silent-degradation.md) L7, not in the user docs; the rest documented where stated |

### A3-3 agent and IPC (nothing CRITICAL or HIGH)

| ID | Skeptic | Outcome |
|---|---|---|
| W2-3-1 | see W1-09 | **Fixed**, `a859214` |
| W2-3-2 | = W1-D3 (third independent confirmation) | **Documented** |
| W2-3-3 core-dump hardening | REFUTED (Go does not dump core by default: 0 cores on macOS; Linux not run) | none; units set `LimitCORE=0` |
| W2-3-4 library `Server` keeps the signer after Close | REFUTED (the command clears it; nil-ing zeroes nothing) | none |
| W2-3-I | idle timer postponed by `P` pings: REFUTED (documented); euid versus real uid: INFO; raw agent error bytes printed by the client: PLAUSIBLE LOW | The `%q` change landed in `49b2ec1` (hostile agent reply printed quoted) |

### A3-4 ring file, locking and filesystem (properties 3 and 4 held under every test)

| ID | Sev | Claim | Skeptic | Outcome |
|---|---|---|---|---|
| W2-4-1 | LOW-MED | `Parse` decodes the whole `entries` array before validating: a 16 MiB ring of `{}` (5.59 M elements) took 3.7 GB RSS in `list` | CONFIRMED (the fix skeptic measured RSS 2248 -> 65 MiB and TotalAlloc 7050 -> 32 MiB on a 16 MiB ring of `{}`) | **Fixed**, `dafd3f6`: incremental decode; **no entry-count cap** (the largest valid ring is about 48,661 entries; a cap would reject rings accepted today) |
| W2-4-2 | INFO (was LOW) | a foreign `<ring>.lock` blocks writers | DOWNGRADED: an attacker can equally block via the ring path | **Documented**: keep the ring in a directory only you can write |
| W2-4-3 | INFO | umask 0277 creates the lock 0400, so later opens fail | CONFIRMED | **Fixed**, `ce8c582`: 0600 whatever the umask, ring and agent lock |
| W2-4-4 | INFO | a hardlink alias takes a different lock | CONFIRMED (inherent to atomic rename) | **Documented**: use a symlink |
| W2-4-5 | LOW/INFO | stale temp files after SIGKILL (288 kills -> 8 stray temps; ring intact) | CONFIRMED | **Documented** (see W2-2-3) |
| W2-4-6 | LOW/INFO | exFAT `Create` fails (`os.Link`); a bind-mounted ring file gives `EBUSY`; a rewrite resets mode to 0600; a **FIFO at the ring path blocks forever**; a directory-fsync error after the rename is reported as failure | CONFIRMED each | exFAT, mount point and mode are documented in SECURITY "Where the ring lives". **FIFO: open** ([open-items.md](open-items.md) O4). Directory-fsync wording: not changed |
| W2-4-7 / W2-4-8 | INFO | base64 non-strict; no warning for a world-writable ring directory | | **Documented** |

Verified sound [R: ledger]: temp `O_EXCL` 0600, every write/sync/close error checked, `fsync` file -> rename ->
`fsync` directory; on macOS durability is `F_FULLFSYNC`; ENOSPC leaves the ring intact; property 3 held
across per-stage `SIGKILL` and 600 random kills with 0 violations; property 4 held over 150 rounds of 8
concurrent `add` (1200/1200).

### A3-5 CLI and operator surface (no CRITICAL, HIGH or MEDIUM)

| ID | Sev | Claim | Skeptic | Outcome |
|---|---|---|---|---|
| W2-5-1 | LOW | SIGQUIT and SIGHUP at the passphrase prompt leave echo off (and SIGQUIT dumps a 16 KB traceback, exit 2) | CONFIRMED | **Fixed**, `389c386`: all four signals restore echo, exit 130; tested on a real pty on macOS, Linux inferred from a clean cross-vet |
| W2-5-2 | LOW | terminal escape and CR injection through echoed paths forge output such as `verified:` | CONFIRMED | **Fixed**, `44076e8` after **four** rounds (1-3 rejected as incomplete: failure messages only; success lines and bidi; `init`/`passwd`/usage/agent; newline in an unknown flag name). One sanitiser, `internal/term.Clean`; 4,427 built-binary runs, 0 flagged |
| W2-5-3 | LOW | `verify` exits 1 for a bad signature, the same as I/O errors | CONFIRMED | **Fixed**, `2793e3c`: exit 3 (a documented exit-status contract changed, owner-accepted in decision 42) |
| W2-5-4 | LOW | `export-priv > file` creates the key file at the umask mode (0644) | CONFIRMED | **Fixed**, `96d0b98`: refused when stdout is a regular file others can read (refuse, not `fchmod`, so the user's file mode is never silently changed); `-o`, `chmod 600` and `-force` are the ways out; a pipe is not covered |
| W2-5-5 | INFO | the `security` child inherits `KEYSTORE_PASSPHRASE` | CONFIRMED, downgraded (Apple binary, same uid, no new attacker position) | none |
| W2-5-I | INFO | various: keychain `Get` maps any failure to `ErrNotFound`; `-T ""` ACL speculation not tested; passfile bare CR stripped | partly confirmed | documented or deliberate |

## Wave 1b: A4 supply chain

| ID | Skeptic | Outcome |
|---|---|---|
| A4-1 | CONFIRMED: the CI systemd step ended in an unconditional `true` and its filter did not match systemd 257's wording, so it could never fail; unknown keys and bad values only warn at rc 0 | **Fixed**, `43655ff`: the step checks the output; reproduced in a Debian container (good unit rc 0; unknown key, bad value, bad section, syntax error all fail). Not run: GitHub Actions itself |
| A4-2 | DOWNGRADED: add `permissions: contents: read` rather than pinning action SHAs | **Fixed**, `43655ff` |
| A4-4 | DOWNGRADED | none |
| `dependency-audit.md` | **Not produced**: the A4 report (module hygiene, `go mod verify`, license matrix, `openpgp` reachability) was not kept; see [README.md](README.md). What survives: `govulncheck` reports 0 affecting and one module-level advisory (`x/crypto/openpgp`, not imported, no fix) [R: L1, release record]; decisions 12, 28, 30, 31 |

## Fix pipeline summary (merges on `main`, in the order they landed)

| Merge | Branch | Finding |
|---|---|---|
| `ffe9c9c` | fix/W1-01-negative-lifetime | W1-01 |
| `a859214` | fix/W1-09-accept-errors | W1-09, W2-3-1 |
| `389c386` | fix/W2-5-1-term-signals | W2-5-1 |
| `a2003af` | fix/W1-02-empty-passphrase | W1-02 |
| `dafd3f6` | fix/W2-4-1-parse-amplification | W2-4-1 |
| `db9d151` | fix/W1-11-capped-verify-inputs | W1-11 |
| `7b66068` | docs/W1-D1-trust-model-and-limits | W1-D1, D2, W2-1-F1, F3, F5, W2-2-3, W2-4-x docs |
| `50370f9` | docs/W1-D-userguide-drift | W1-D5, D6-10, W1-10, W2-I4 |
| `78e19fa` | fix/W2-1-F4-import-consistency | W2-1-F4, W2-2-4 |
| `af60243` | fix/W1-s5-small-cleanups | W1-08, W1-13c, W1-14, W1-18 |
| `8b32c90` | fix/W1-04-listen-umask | W1-04 |
| `44076e8` | fix/W2-5-2-control-chars | W2-5-2 |
| `96d0b98` | fix/W2-5-4-redirected-export | W2-5-4 |
| `22a2a19` | fix/W1-06-socket-path-length | W1-06 |
| `49b2ec1` | fix/W2-I-agent-messages | W2-I1, W2-I5, W2-3-I |
| `2793e3c` | fix/W2-5-3-badsig-exit-code | W2-5-3 |
| `2e39346` | fix/W2-2-2-shadowed-passfile | W2-2-2 |
| `43811fd` | fix/W1-D1-sign-fingerprint | W1-D1, W2-1-F2 |
| `43655ff` | fix/A4-1-ci-systemd-gate | A4-1, A4-2 |
| `29e9973` | fix/W2-I2-pem-error-text | W2-I2 |
| `ce8c582` | fix/W2-4-3-lock-file-mode | W2-4-3 |
| `49a29bf` | fix/A5-L4-ring-path-without-home | A5-L4 |
| `addf124` | docs/A5-agent-operations | A5 L1, L3, L5, L6 (docs and unit rate limits) |
| `77f56c7` | test/A6-golden-formats | A6 |
| `ebf5897` | fix/A5-L2-orphaned-agent | A5-L2 |
| `d4be234` | fix/L1-readframe-incremental | L1 |
| `0670225` | test/L2-known-answers | L2 |
| `58408dc` | fix/L1-agent-sighup | L1 |
| `f33cecf` | test/L2-fuzz-targets | L2 |
| `963ab93` | test/L2-harnesses | L2 |
| `bf89ccc` | test/L2-benchmarks | L2 |
| `5075321` | fix/L2-signer-typed-nil | L2 (found by mutation testing) |
| `3f059ac` | test/L2-mutation-hardening | L2 |
| `a35b07a` | test/L3-live | L3 |
| `7dd11c1` | test/L3b-topology | L3b |
| `b04b179` | fix/L1-dup-entries-amplification | L1 |
| `8a90392`, `07c6d65`, `0632c47`, `bc08d87`, `1d06882` | fix/A7-build-dirty, fix/A7-verify-exit-in-help, fix/A7-agent-log-sanitize, fix/A7-agent-help, test/A7-ci-and-keychain-unsupported | A7 M6/M7, M14, M1, M3, M2/G8/G15 |

A7 findings that remain are in [open-items.md](open-items.md).
