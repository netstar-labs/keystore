# Test ledger

What tests the audit added, by wave, what each group guards, and where the test suite stands now.
Companion pages: [mutation-hardening.md](mutation-hardening.md) (the 417 mutants),
[benchmark-baselines.md](benchmark-baselines.md), [harness-inventory.md](harness-inventory.md) (the seams
the tests need), [defects-log.md](defects-log.md) (what the tests found).

Labels: **[V]** counted or run while writing this page (commands below); **[R]** reported by a merge
message or another audit page, not re-run; **[I]** inferred. Everything here is from `main` plus the
docs-only changes of the branch that adds this page: no test or production logic differs.

## Totals [V]

| Measure | At tag `v0.1.0` | Now | How |
|---|---|---|---|
| top-level `func Test*` in all `.go` files | 113 | 351 | `git grep -h -E '^func Test' <rev> -- '*.go'`, lines counted (includes each package's `TestMain`) |
| test names listed under default tags | n/a | 319 `Test`, 10 `Fuzz`, 24 `Benchmark` | `go test -list '.*' ./...` |
| extra `Test` names with a build tag | n/a | +11 with `integration`, +10 with `topology` | same command with `-tags` |
| packages with tests | 18 (release record: "18/18") | 19 | `go test ./...` (the new one is `build`, the release script's test) |
| Go files named `*_test.go` | 26 | 86 | `git ls-tree` / `git ls-files` |
| `Fuzz` targets | 2 | 10 | `git grep -E '^func Fuzz'` |
| `Benchmark` functions | 0 | 24 | `git grep -E '^func Benchmark'` |
| mutants killed / run (security tests) | 263 / 417 (63.1 %) | 379 / 417 (90.9 %) | [R] [mutation-hardening.md](mutation-hardening.md) |

`golden.ks` is unchanged: SHA-256 `bf2462491e501a051e81f5a73ea4687eba30567dfdd2f6e12cd81352938d03f6`
[V: `shasum -a 256 testdata/golden.ks`].

## Coverage by package [V: `go test -count=1 -cover ./...` on macOS arm64, default tags]

"Before" is the figure the audit recorded at the start (plan baseline, or L1 where the plan did not list
the package) [R]; blank where none was recorded.

| Package | Test, fuzz and benchmark names now | Before | Now | Kinds |
|---|---|---|---|---|
| `internal/ids` | 4 | 100.0 | 100.0 | unit, differential fuzz against an independent regexp |
| `internal/kdf` | 13 | 90.0 | 90.0 | known-answer, bounds table, production default, bench |
| `internal/seal` | 18 | 86.8 | 94.7 | known-answer (GCM), AAD golden, tamper, fuzz, bench |
| `internal/ringfile` | 36 | 88.4 | 88.6 | unit, golden, crash hook, `FuzzParse`, mutation kills, bench |
| `internal/passphrase` | 24 | 91.5 | 95.8 | unit, fuzz, shadowing matrix |
| `internal/keychain` | 12 | 70.6 | 100.0 | shim-driven argv/env/error tests, off-darwin stub test |
| `internal/peercred` | 4 | 75.0 | 100.0 | error paths of the credential lookup |
| `internal/term` | 15 | 33.3 | 96.4 | pty end-to-end, signals, `Clean` |
| `pkg/keystore` | 56 | 90.2 | 93.1 | unit, RFC 8032 known-answer, goldens, tamper matrix, fuzz, bench |
| `pkg/agent` | 76 | 88.5 | 93.5 | fake-clock expiry, wire goldens, framing, fuzz, bench |
| `cmd/keystore` | 63 | 79.1 | 93.4 | verb tables, goldens, exit codes, fuzz, bench |
| `cmd/keystore-agent` | 16 | 91.2 | 93.2 | flags, signals, log sink |
| `build` | 3 | n/a | no statements | the release script, run in a temporary git repository |
| `examples/secrets`, `examples/signed-requests` | 4, 5 | 65.7, 79.8 | 71.4, 79.8 | unit + `run.sh` |
| other `examples/*` | 1 each | n/a | no statements | `go test` runs the `run.sh` |
| `integration/topology` | tagged only | n/a | no test files under default tags | see [topology-integration.md](topology-integration.md) |

## Tests added, by wave

"+n Test" is the number of top-level `Test` functions the merge added [V: `git diff <merge>^1 <merge>`
counting `+func Test` lines; a merge that rewrote a test counts the new one]. Fuzz and benchmark
functions are counted separately. Merges that add only a regression test for a fix are grouped.

### Wave 2 (A3 findings): regression tests that came with the fixes (red first, then green)

Each fix branch wrote its test before the fix; the fix skeptic reverted the fix on a copy and required the
test to fail. Counts are per merge [V].

| Merge | Fix | +Test | What the tests guard |
|---|---|---|---|
| `ffe9c9c` | W1-01 negative ttl/idle | 2 | both `Serve` and the CLI refuse a negative lifetime |
| `a859214` | W1-09 accept errors | 2 | EMFILE is retried; any other accept error stops the agent cleanly |
| `389c386` | W2-5-1 prompt signals | 2 | echo restored after SIGQUIT and SIGHUP (exit 130) |
| `a2003af` | W1-02 empty passphrase | 4 | all five library entry points refuse empty; a legacy empty-passphrase ring still unlocks |
| `dafd3f6` | W2-4-1 Parse amplification | 4 | allocation budget on a 16 MiB ring of `{}`; check order preserved |
| `db9d151` | W1-11 verify inputs | 1 | 64 KiB cap and its boundary |
| `78e19fa` | W2-1-F4 Import | 2 | inconsistent 64-byte keys refused, ring byte-identical |
| `af60243` | W1-08, 13c, 14, 18 | 3 | rune counting in place; keychain error text |
| `8b32c90` | W1-04 umask | 1 | concurrent `Listen` does not leak umask 0177 |
| `44076e8` | W2-5-2 control characters | 9 | no raw control byte on any channel (messages, success lines, usage, agent) |
| `96d0b98` | W2-5-4 redirected export | 1 | refusal under a loose redirect, allowed for 0600, pipe, FIFO, `/dev/null` |
| `c39085b` / `2e39346` | W2-2-2 shadowed passfile | 18 / 2 | a shadowed passfile is announced when unlocking and refused when establishing; an empty variable is not a source |
| `22a2a19` | W1-06 socket path | 1 | limit and limit+1 |
| `49b2ec1` | W2-I messages | 4 | no `<nil>`, `%04o` mode, quoted remote text, uid-lookup failure line |
| `2793e3c` | W2-5-3 exit 3 | 1 | 0 / 1 / 2 / 3 table |
| `43811fd` | W1-D1 sign fingerprint | 2 | `signing with`, `-expect-fp` match, mismatch, empty |
| `29e9973` | W2-I2 PEM text | 2 | found/expected text, encrypted-key hint |
| `ce8c582` | W2-4-3 lock mode | 2 | 0600 under umask 0277, ring and agent |
| `49a29bf` | A5-L4 no home | 1 | exit 2, `sign -agent` exempt |
| `ebf5897` | A5-L2 orphaned agent | 3 | socket removed or replaced; Close racing the check |
| `d4be234` | L1 readFrame | 3 | stalled claims allocate little |
| `58408dc` | L1 SIGHUP | 2 | clean stop; inherited-ignore respected |
| `5075321` | L2 typed nil Signer | 2 | `s == nil` on every error path |
| `b04b179` | L1 duplicate `entries` | 0 added, 1 replaced | the old last-wins test was retired (commit `760afdf`) and replaced by a rejection test |

### Wave 3 (A6): golden formats (`77f56c7`, +14 Test) [R: [format-compatibility.md](format-compatibility.md)]

Every encoded artifact has fixed bytes in a test, built independently of the code (Python scripts from
`docs/format.md` and RFC 8410; PEM, SPKI hash and a signature cross-checked with OpenSSL 3.5.9): ring bytes,
four edge-case fixtures in `testdata/` (`ring-minimal.ks`, `ring-empty.ks`, `ring-secret-only.ks`,
`ring-two-entries.ks`), AAD for both entry kinds, PKCS#8 plaintext, the production KDF cost, agent frames and
the raw bytes on a real socket, the agent lock-file name, PEM text, fingerprint format, `sign` output, the
keychain argv. 30 mutants by the skeptic.

### Wave 5 (L2)

| Merge | +Test | Fuzz | Bench | What it guards |
|---|---|---|---|---|
| `0670225` known answers | 13 | | | below |
| `f33cecf` fuzz targets | 0 | 8 | | below |
| `963ab93` harnesses and error paths | 44 | | | below; coverage term 33.3 -> 96.4, keychain 70.6 -> 100, peercred 75.0 -> 100, cmd/keystore 79.1 -> 93.4 |
| `bf89ccc` benchmarks | 0 | | 24 | [benchmark-baselines.md](benchmark-baselines.md) |
| `3f059ac` mutation hardening | 80 | | | 116 of 154 old survivors now die; no production change |

**Known-answer vectors** [R: commit `5dcfb7f`; the skeptic re-derived the constants with OpenSSL, Python and
the RFC]: AES-256-GCM vectors from McGrew-Viega (test cases 13, 14, 16) plus two AAD-only vectors from OpenSSL,
through `seal.Open`; single-bit tamper of key, nonce, ciphertext, tag and AAD; `Seal` output equals
`crypto/aes` + `cipher.NewGCM`; the AAD hand-derived from `format.md` for an ed25519 and a secret entry.
`kdf.Derive` at the production cost and at the bounds against OpenSSL 3.5.9 values (commands are in the file;
the published argon2 vectors use 8-byte salts and sub-MiB memory, outside this package's bounds, decision
13). RFC 8032 section 7.1 TEST 1, 2, 3, 1024 and SHA(abc) through `Import`, `Signer`, `ExportPrivate` and
PEM; `Fingerprint` against SHA-256 of the SPKI and OpenSSL. A written entry carries argon2id 65536 / 3 / 1, a
16-byte salt and a 12-byte nonce. 28 mutants by the skeptic, all killed counting existing tests (23 by the new
tests alone).

**Fuzz targets** (10; seeds are inline `f.Add` because package `testdata/` directories are not committed
[R: commit `41f5633`]):

| Target | Package | What must hold (from the target's own comment [V]) |
|---|---|---|
| `FuzzParse` | `internal/ringfile` | no panic on arbitrary ring bytes (pre-existing) |
| `FuzzReadFrame` | `pkg/agent` | no panic on arbitrary frame bytes (pre-existing) |
| `FuzzFrameRoundTrip` | `pkg/agent` | write then read returns the same status and payload and consumes exactly the frame; the payload limit is refused on both sides; `readFrame` allocates no more than the declared length |
| `FuzzOpenRing` | `pkg/keystore` | an accepted ring re-marshals and re-parses equal; `List`/`Public`/`Signer` never panic; allocation is proportional to the input (the guard for W2-4-1) |
| `FuzzParsePEM` | `pkg/keystore` | no panic; accepted input re-encodes to the same key; accept/reject agrees with a reference built on `encoding/pem` and `crypto/x509` |
| `FuzzAAD` | `internal/seal` | the AAD decodes back to its tuple; two tuples encode equal if and only if they are equal |
| `FuzzSealOpen` | `internal/seal` | `Open` never panics; wrong sizes are refused by name; what `Seal` makes opens and stops opening on a one-bit change |
| `FuzzValid` | `internal/ids` | `Valid` agrees with an independent regexp, including NUL, newline, invalid UTF-8 and the length boundary |
| `FuzzReadPassfile` | `internal/passphrase` | the 4096-byte cap is exact; exactly one trailing LF then one CR removed |
| `FuzzRun` | `cmd/keystore` | arbitrary argv to every verb (keychain-set skipped): nothing written outside the working directory, and everything printed is inert on a terminal |

Budgets: the fix skeptic ran 70 s per target without a crash [R: merge `f33cecf`]; earlier long runs of
`FuzzParse` were 4 m 34 s / 34.6 M execs (A3-4) and 4 m 10 s / 53.9 M execs plus a 3 m 10 s differential run of
21.1 M execs (W2-4-1) [R]. CI now runs every target 20 s, and `FuzzParse` and `FuzzReadFrame` 60 s (decision
44; unproven on a hosted runner). Two known survivors the fuzz skeptic named (trailing data, a 13-byte nonce)
went to mutation hardening [R].

### Waves 6 and 7 (L3, L3b): live and topology tiers (tagged, not part of `go test ./...`)

| Merge | +Test | What it guards |
|---|---|---|
| `a35b07a` L3 | 14 | the Linux container tier (whole suite as cross-compiled binaries, as root and as uid 1000), OpenSSL interop (4 tests), the skip-versus-fail classifier (hermetic), the keychain tier (written, double-gated, never executed). See [live-integration.md](live-integration.md). 40/40 on alpine 3.23 and debian 13 as root and uid 1000; 11 production mutants make the live tests fail [R: merge message] |
| `7dd11c1` L3b | 11 | contention, SIGKILL crash loop, cross-uid, agent chaos (hammer/restart, TTL, idle, racing starts, stale socket, socket removed), fleet. See [topology-integration.md](topology-integration.md); 5 hardening mutants killed, no false failures on unmutated code (3 seeds on macOS, a container crash loop, the fleet) [R: merge message] |

### Wave 8 (A7) (`8a90392`, `07c6d65`, `0632c47`, `bc08d87`, `1d06882`)

+3 (release script in a temporary repo), +1 (verify help), +1 (forged log line), +2 (agent `-h`, an unknown
flag still exits 1), +1 -1 (off-darwin keychain stub added, `TestGetMissing` deleted). Plus one CI job that
fuzzes every target and fails if the count differs from a grep of the sources.

## What the suite does not guard

Listed with their reasons in [untestable-without-x.md](untestable-without-x.md) and
[open-items.md](open-items.md) section 2: that `fsync` runs (a killed process cannot lose the page cache);
the real macOS keychain; a second real uid on macOS; a real systemd or launchd start; linux/amd64 and
darwin/amd64 execution; Linux `-race`; GitHub Actions itself. Coverage was measured on macOS only, so
`*_linux.go` and `*_other.go` files do not count there.

## Commands

    GOWORK=off go test -race -count=1 ./...                          # the gate's test step
    GOWORK=off go test -count=1 -cover ./...                          # the coverage column
    GOWORK=off go test -list '.*' ./...                               # the name counts
    GOWORK=off go test -run '^$' -fuzz='^FuzzParse$' -fuzztime=60s ./internal/ringfile
    GOWORK=off go test -p 1 -bench . -benchmem -count=10 -run '^$' ./...   # benchmark-baselines.md
