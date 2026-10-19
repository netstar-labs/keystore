# Harness inventory

The seams, harnesses and runners the audit added or relied on so that behaviour could be tested without
a terminal, a second user, a real clock, a real keychain or a cluster. For each: what it is, where it is,
how to run it, what it proves and what it cannot reach. Companion pages: [test-ledger.md](test-ledger.md),
[untestable-without-x.md](untestable-without-x.md).

Labels: **[V]** read in the source or run while writing this page; **[R]** reported by a merge message or
audit page. Least-code rule that governed every seam: no new exported symbol, flag or dependency; a
production change must be one unexported line or variable with a stated reason.

## Production seams (unexported; each added for a test)

| Seam | Where | Added by | Replaces | Used by |
|---|---|---|---|---|
| `afterFunc` (a two-method timer interface) | `pkg/agent/server.go:56-57,76` [V] | `963ab93` (L2 harnesses, commit `c063c00`), +13/-15 lines, behaviour unchanged | `time.AfterFunc` for the TTL and idle timers | `clock_test.go`: expiry exactly at TTL/idle (deadline minus 1 ns still serves), idle reset only by a successful request, TTL not extended by a busy connection, simultaneous expiry reports `ErrExpired` once, negative and zero lifetimes arm nothing |
| `security` (package variable, was a `const`) | `internal/keychain/keychain_darwin.go:10` [V] | `963ab93` (commit `188cac8`), 1 line | the absolute path `/usr/bin/security` | `shim_darwin_test.go`; `TestRealSecurityIsTheDefault` pins the real path |
| `checkEvery` | `pkg/agent/server.go:53` [V] | `ebf5897` (A5-L2, commit `b50e90f`) | the 10 s socket check | socket-removed tests shorten it |
| `uidOf` | `pkg/agent/server.go:54` [V] | present at `v0.1.0` [V: `git show v0.1.0:pkg/agent/server.go`] | peer-uid lookup | refusal and uid-lookup-failure tests |
| `accept` | `pkg/agent/server.go:75` [V] | `a859214` (W1-09, commit `4195ca2`) | `AcceptUnix` | the EMFILE and accept-error tests |
| `hook` (per write stage) | `internal/ringfile/ringfile.go:342` [V] | present at `v0.1.0` [V] | nothing (fires at each stage of `Save`) | `TestSaveCrashSafety` (3 stages). It fires per stage, not per `fsync`, so it cannot see a dropped `fsync` |
| `isTerminal` | `cmd/keystore/output.go:15` [V] | decision 11; present at `v0.1.0` [V] | `term.IsTerminal` | the terminal-refusal guard tests |

**Considered and not added:** `testing/synctest` for the agent clock (the agent blocks in unix-socket
`accept` and `read`, which are not durably blocking, so its fake clock would never advance [R: commit
`c063c00`]); a `var syncFile = (*os.File).Sync` seam (it would prove the call, not durability; decision
recorded in [untestable-without-x.md](untestable-without-x.md)); a build-tag or environment override for the
`security` path (more surface than a variable).

## Test harnesses

| Harness | Where | What it does | Proves | Cannot reach |
|---|---|---|---|---|
| **Fake clock** | `pkg/agent/clock_test.go`, `idle_probe_test.go` | drives the two timers by hand; can freeze the watcher inside `Reset` so an "idle was not reset" check reads the queue with the watcher parked (no timing) | the lifetime rules above, with no sleeps; run `-race -count=50` | the OS timer and suspend behaviour (a laptop that sleeps) |
| **Fake `security(1)` shim** | `internal/keychain/shim_darwin_test.go` | a shell script in `t.TempDir()` that records argv, environment and stdin and replays a configured stdout and exit code | exact argv for `Get` and `Set` (bare trailing `-w`), the passphrase reaches `security` only on stdin, one trailing newline trimmed, invalid service names never exec, a missing binary names itself; observations pinned as "current behaviour": every `Get` failure is `ErrNotFound` | the real keychain |
| **pty harness** | `internal/term/pty_test.go`, `pty_darwin_test.go`, `pty_linux_test.go` | opens `/dev/ptmx` with `x/sys/unix` (no third-party code), re-execs the test binary as a `setsid` child whose controlling terminal is the slave while the test plays the user on the master; the child's coverage counts via `-test.gocoverdir` | echo off while prompting and never echoed, line handling and `MaxLen` boundaries, `ErrNoTTY`, terminal state restored after a normal return and after SIGINT, SIGTERM, SIGQUIT, SIGHUP (exit 130, no traceback) | the Linux files are compile-checked (`GOOS=linux go vet`) but were not run in that pass [R]; macOS drops input past 1024 bytes with a bell, so two cases skip there |
| **Release-script harness** | `build/keystore_test.go` | runs the real script in a temporary git repository with a stub CLI | a clean release works and has no `-dirty` in its names; untracked and modified trees are refused; a dev build is stamped | the installer (needs root: A7 M8) |
| **Container runner and classifier** | `integration/container.go`, `integration/container/inside.sh`, `integration/run.sh`, `integration/internal/livetest/livetest.go` (tag `integration`) | cross-compiles every package's `go test -c`, runs the binaries inside an Apple `container` (alpine 3.23, debian 13 trixie-slim) as root and as uid 1000, reads a manifest on fd 3. A fake `runner` interface tests the classifier hermetically | environment problems SKIP with a reason (no runtime, image missing, install failed, the container never reached the code); only a failing test, build error, hang, or a run that does not report exactly one `rc=0` per test binary per uid FAILs | a real second machine; the classifier cannot tell a runtime fault outside the listed cases from a keystore fault |
| **Interop** | `integration/interop/openssl_test.go` (tag `integration`) | OpenSSL 3.5.x in the container: signature and key round trips both ways, `kdf.Derive` against `openssl kdf ARGON2ID` | agreement with an independent implementation; skips on a host without Ed25519 | other OpenSSL versions |
| **Keychain tier** | `integration/keychain/keychain_test.go` | a unique throwaway service name, deleted in `t.Cleanup`, double-gated by `KEYSTORE_LIVE=1` and `KEYSTORE_LIVE_KEYCHAIN=1` | would exercise the real `security(1)` | **never executed**; see [untestable-without-x.md](untestable-without-x.md) |
| **Topology tier** | `integration/topology/` (tag `topology` and `KEYSTORE_TOPOLOGY=1`), driver `scripts/topology.sh` | the built binaries as real processes on a real filesystem and real sockets, on macOS and in the container: contention, `SIGKILL` crash loop, cross-uid, agent chaos, fleet | properties 3 and 4 and the agent lifetime rules at process level; every child gets a clean environment (throwaway `HOME`, no `KEYSTORE_KEYCHAIN`) so the keychain is unreachable | `fsync` and power loss; a second machine; a non-root macOS uid |
| **Mutation runner** | not committed | a throwaway Python script (about 80 lines) that copies the repository, applies one textual mutation, builds, runs the affected packages with `-race -timeout 150s`, and records killed, survived or timeout [R: mutation-hardening.md "Method"]. The 417 mutants are described in that page, the kill tests are `kill_*_test.go` and `property_test.go` | the security-test mutation score | it is not reproducible from the repository: the runner and mutant list were not kept |
| **Sandbox profiles** | not committed | skeptics used macOS `sandbox-exec` to show that the default suite never execs `/usr/bin/security` [R: merge messages `963ab93`, `1d06882`] | that claim, once | nothing in the repository re-checks it |
| **Golden fixtures** | `testdata/` (`golden.ks`, `ring-minimal.ks`, `ring-empty.ks`, `ring-secret-only.ks`, `ring-two-entries.ks`, `golden.md`) | rings that pin `keystore/v1`; `golden.ks` must stay byte-identical | the reader accepts every shipped shape; the AAD and plaintext encodings | writer output in the old format; AAD at other parameter shapes (covered by the A6 tests) |

## Running them

    GOWORK=off go test -race -count=1 ./...                         # default suite (all seams above except tagged tiers)
    integration/run.sh                                              # Linux containers + OpenSSL interop (needs `container`)
    KEYSTORE_LIVE=1 KEYSTORE_LIVE_KEYCHAIN=1 go test -tags integration -count=1 -v ./integration/keychain/   # writes the login keychain: read untestable-without-x.md first
    scripts/topology.sh mac | container | all                       # topology tier

Every tagged file carries a build tag, so plain `go test ./...` and `go vet ./...` do not see them; CI runs
`go vet` and staticcheck with `-tags integration,topology` (decision 44).
