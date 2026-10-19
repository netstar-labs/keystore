# Silent-degradation audit (A5)

Scope: `keystore` `main` as of 2026-10-19 (CLI `keystore`, signing agent `keystore-agent`, library). The
audit changed no repository files; experiments ran on a throwaway copy with a RAM disk for the ENOSPC case.
This page is the report as written, plus the status table below, which says what happened to each row
afterwards. Rows are as of the audit date: a later fix changes the status, not the row.

Operator's view: keystore has no metrics, so the signals are **exit status**, **stderr text** and **the agent's `log.Printf` stream** (journal / `StandardErrorPath`).
Marks: ACTIONABLE = a nonzero exit or stderr line a script or alert can act on; LOG-ONLY = log-only or exit-0-with-a-line (discoverable, not alertable); SILENT = nothing.
Evidence tags: **V** = the auditor ran it and saw it; **I** = inferred from code and docs, not exercised.

## Status after the audit

Fixed means a merge on `main` with a fix skeptic's verdict in its message; documented means the stated
limit is now in a committed document; "not fixed" rows are in [open-items.md](open-items.md) section 3 with
their reason. Status was checked against the repository while writing this page [V: grep of the cited
document for the stated text], not by re-running the lapse.

| # | Lapse | Status |
|---|---|---|
| L1 | ttl and idle use monotonic timers (no suspend time) | Documented: SECURITY "Known limits" (says "not tested by suspending a machine"); agent-service README. Not fixed |
| L2 | orphaned agent: socket unlinked, key still held | **Fixed**, merge `ebf5897`: the agent checks its socket about every 10 s and stops with exit 1 when it is removed or replaced |
| L3 | agent outlives `rm`/`passwd` of its key | Documented (userguide agent paragraph, SECURITY "Revocation", agent-service README), merge `addf124`. Not fixed |
| L4 | `$HOME` unset: ring silently created in the working directory | **Fixed**, merge `49a29bf`: no ring path and no home is a usage error, exit 2 (`sign -agent` is exempt); `keygen` still does not print the ring path |
| L5 | clean-exit expiry is "success" to a service manager | Documented: agent-service README; both units use `-ttl 0 -idle 0`. Not fixed |
| L6 | restart loops bounded only by manager defaults | Units now rate-limit (`StartLimitIntervalSec`, `StartLimitBurst`, `RestartSec`; plist `ThrottleInterval`), merge `addf124` |
| L7 | directory fsync fails after the rename: exit 1, ring changed | Not fixed (reports failure, never false success) |
| L8 | post-commit stdout write fails | Documented (A7 G12) in the userguide "Exit status", including the SIGPIPE status 141 a closed pipe gives |
| L9 | stale `.<ring>.*.tmp` after a hard kill | Documented (SECURITY "Revocation"). Not fixed on purpose |
| L10 | lock timeout text does not name the lock file | Not fixed (loud, nothing lost) |
| L11 | `keygen` leaves an empty ring after a failed passphrase step | Documented (userguide Passphrases). Not fixed |
| L12 | `passwd` aborts on one corrupt entry without naming it | Not fixed (loud, no partial state) |
| L13 | any `security` failure reported as "no keychain item" | Documented (SECURITY "Known limits"). Not fixed |
| L14 | empty `KEYSTORE_PASSPHRASE=` treated as unset | Documented (A7 G13), userguide Passphrases. Not fixed |
| L15 | the ring's directory is never checked | Documented (SECURITY "Where the ring lives"). Not fixed |
| L16 | library embedders get no escalation for signer errors | Not fixed (unreachable from the CLI agent) |
| L17 | `Server.Log` is nil by default | Not fixed; the field comment says "if set"; the CLI sets it |
| L18 | EMFILE log line every 50 ms | Not fixed (no stated guarantee) |
| L19 | `guardTerminal` is fail-open; pipes unchecked | Documented. A7 M11 corrected the row: `>>` onto a loose regular file **is** refused |
| L20 | KDF cost not shown | Not fixed (latent: one default cost exists) |
| L21 | `restore()` ignores the ioctl error | Not fixed (interactive only) |

## Phase 0: guarantees

| # | Guarantee | Stated in | Mechanism |
|---|---|---|---|
| G1 | durable once the command returns | scope.md sec.prop 3; format.md Invariants | temp file `Sync` (F_FULLFSYNC on darwin, verified in Go 1.27.2 `poll/fd_fsync_darwin.go`), rename, dir `Sync` |
| G2 | a crash leaves old-or-new, never torn | scope 3; SECURITY | write-temp + rename |
| G3 | cooperating writers lose nothing | scope 4; SECURITY; format.md | `flock(<ring>.lock)`, re-read under lock, 10 s `LockTimeout` then `ErrLocked` |
| G4 | one passphrase per ring, enforced | scope 5 | `checkPassphrase` unlocks `Entries[0]` on add; `passwd` unlocks all |
| G5 | no secret on argv / terminal / existing file / readable redirect | scope 6; SECURITY; `-o` and `-force` help text | `guardTerminal`, `writeNew` O_EXCL, passphrase never a flag |
| G6 | `-passfile` is 0600, owned by you; explicit source never degrades invisibly | flag help; decisions 16, 40 | `readPassfile`, `shadowed` |
| G7 | Parse is memory-bounded, no zero-cost KDF | scope 7 | `MaxSize`, incremental entry decode, `kdf.Check` |
| G8 | wrong passphrase and tamper are indistinguishable | scope 2 | one `ErrBadPass` |
| G9 | agent: key not held past `-ttl` / `-idle` / Close | `-ttl`, `-idle` help; agent-protocol Lifetime; userguide ("so an unlocked key does not outlive the session") | timers in `Server.watch`, `Close` closes listener and conns, `defer clear(priv)` |
| G10 | agent exits (and drops key) when accept fails; EMFILE retried | agent-protocol Lifetime | `Serve` loop |
| G11 | one agent per socket path; no stealing a live socket | agent-protocol Socket | `flock(<sock>.lock)` + dial probe |
| G12 | peer uid checked both ways; client verifies every signature | agent-protocol | `peercred`, `Client.Sign` verifies |
| G13 | socket dir must be 0700 and yours | `-sock` help | `checkDir` |
| G14 | `rm`/`use`/`passwd` change the ring (rotation: "retire the old one") | userguide Rotation step 4; scope verbs | `Update` |
| G15 | keychain source: configured source never falls through | decision 16; passphrase.go | `Keychain(svc)` error is returned |
| G16 | exit codes 0/1/2/3/130 mean what the guide says | userguide Exit status | `report()` |
| G17 | default ring is `~/.config/keystore/default.ks` | scope Open questions 5; `-keystore` help | `defaultRing()` |
| G18 | unattended modes: `-passfile`, `KEYSTORE_PASSPHRASE`, `-new-passfile`, never a prompt in the agent | userguide; agent main | `passphrase.resolve` |
| G19 | shipped units: restart on crash, no core dumps, owner-only socket dir | examples/agent-service | `Restart=on-failure`, `LimitCORE=0`, `RuntimeDirectory`; launchd `KeepAlive.SuccessfulExit=false` |

## 1. Ledger

| # | Guarantee | The lapse (program keeps running/answering) | Signal | Mark | Evidence |
|---|---|---|---|---|---|
| L1 | G9 `-ttl`/`-idle` bound how long the key is held | Timers run on Go's monotonic clock, which does not advance while the machine is suspended (mach_absolute_time on darwin, CLOCK_MONOTONIC on Linux). A laptop that sleeps overnight holds the key far past `-ttl 8h` wall-clock. Agent is healthy and answering after wake. | none: no log, no wall-clock deadline check | SILENT | **I**. `server.go` `watch` uses `time.NewTimer`; `runtime/sys_darwin.go:286 nanotime1` = `mach_absolute_time`. Not exercised (needs suspend). |
| L2 | G9/G10/G11 socket and agent lifetimes | Socket file unlinked while agent runs (tmp cleaner, `rm`, `systemd-tmpfiles`). Agent stays alive with the key in memory, serves nobody, logs nothing, never exits (accept never fails). With `-ttl 0 -idle 0` (what both shipped units use) the key is held indefinitely. A replacement agent is refused with "another agent is already listening" (flock still held), which is misleading. systemd/launchd see a healthy running unit. | client: `connect: no such file` (clients loud); agent/manager: nothing | SILENT | **V**: `rm $R/a.sock`; client exit 1 ENOENT; `kill -0 $AP` alive; agent log has only the "serving" line; second agent `exit=1 ... already listening`. |
| L3 | G14 `rm`/`passwd` retire a key | Running agent never re-reads the ring. After `keystore rm -id k1 -force` and after `passwd`, `sign -agent` still signs with k1 (exit 0, "signing with <k1 fp>"). Rotation step 4 ("rm the old one") does not retire it where an agent holds it; with `-ttl 0` never. | none | SILENT | **V**: agent on k1; `keystore rm -id k1 -force` ("removed k1"); `keystore list` shows only k2; `sign -agent` exit 0 with k1's fingerprint. Same after `passwd`. Docs: no mention (grep of SECURITY/userguide/rotation README). |
| L4 | G17 default ring path | `$HOME` unset (cron, system-level unit, `env -i`): `defaultRing()` silently falls back to `default.ks` in the CWD. `keygen` exits 0 and creates the ring there; output never names the path (only `init` prints it). | exit 0; no path printed | LOG-ONLY (loud only later, from another cwd: `open default.ks: no such file`) | **V**: `env -i keystore keygen -id a -passfile pass` -> exit 0, `default.ks` in cwd; next command from another dir exit 1. |
| L5 | G9/G19 agent lifetime under a service manager | Expiry (`-ttl`/`-idle`) and SIGTERM both exit 0. `Restart=on-failure` / `KeepAlive.SuccessfulExit=false` never restart a clean exit, so a unit given a nonzero `-ttl`/`-idle` (as the userguide example does) goes inactive "successfully" and every client fails until a human restarts it. | one agent log line "ttl or idle limit reached; stopping"; exit 0 | LOG-ONLY | **V**: `-idle 2s` -> `agent exit=0`, log line, socket removed, client ENOENT. Restart-policy consequence **I** (unit text). |
| L6 | G19 restart on failure | Agent exits 1 for a stale passfile/passphrase (e.g. after `passwd`, L3-adjacent) or any startup error. launchd: relaunch every ~10 s forever (default ThrottleInterval), one stderr line per try, log file unbounded. systemd: default `Restart` 100 ms x `StartLimitBurst=5/10 s` then `failed` (start-limit-hit); no key is ever served; clients ENOENT. | stderr/journal line each try; manager state | LOG-ONLY | **V** for the failing start (`keystore-agent: keystore: wrong passphrase or corrupt entry`, exit 1); loop/limit behaviour **I** (manager defaults). |
| L7 | G1/G2 durable and atomic | Dir `Sync` fails after the rename committed (EIO, FS that rejects dir fsync): `Save` returns the error. Command exits 1 while the ring HAS changed. For `keygen`/`add` the new public key is never printed (`addKey` returns before the PEM write), so a retry hits `ErrExists`. | exit 1 + stderr (`sync dir...`); state is not named | ACTIONABLE (safe direction: reports failure, never false success) | Simulated: test hook returning at stage `renamed` -> `Update err = sync dir ...`, ring file present. Code: `Save`, `addKey`. Message does not say "committed". |
| L8 | G1/G5 post-commit output | Ring committed, then the PEM write to stdout fails (ENOSPC, closed fd): exit 1, "added full1 ..." already printed to stderr. | exit 1 + `write /dev/stdout: no space left on device` | ACTIONABLE | **V** on full HFS RAM disk: `keystore add ... >> out` -> exit 1; `list` shows `full1`. |
| L9 | G2 temp files | `kill -9`/power loss between temp write and rename leaves `.<ring>.<rand>.tmp` (0600, a full encrypted ring) forever; nothing sweeps it; `list` and the agent never mention it. It is an older snapshot after later `rm`/`passwd` (SECURITY "Revocation"). | none (documented in SECURITY.md) | SILENT (documented) | **V**: child process `os.Exit(9)` at stage `synced` leaves `.r.ks.1573305667.tmp -rw-------`. |
| L10 | G3 lock timeout | Holder alive past 10 s (large ring `passwd`, hung process): writer fails `ErrLocked`. Stale lock cannot exist (flock dies with holder). | exit 1, "ring is locked by another process" (names neither lock file nor holder) | ACTIONABLE (loud; text could name `<ring>.lock`) | **V**: python holds flock 13 s; `use` -> exit 1 after 10.014 s. Holder `kill -9` -> next `use` succeeds. |
| L11 | G3/G14 partial effects | `keygen` into a missing ring creates the empty ring first; if the passphrase step then fails (no tty, too short, mismatch, empty) the ring file is left behind and the error does not say so. | exit 1 + passphrase error; ring creation unreported | LOG-ONLY | **V**: `keygen -keystore n.ks` with no tty -> exit 1, `n.ks` 63 bytes exists, `list` empty. Retry works (`OpenOrCreate`). |
| L12 | G4/G8 `passwd` | One corrupt or foreign-passphrase entry makes `passwd` abort at that entry with nothing written. The error is the generic "wrong passphrase or corrupt entry" and names no entry; an operator with the right passphrase cannot tell which entry, so cannot repair short of editing the file. | exit 1 + generic text | ACTIONABLE (loud; no partial state) | **V**: flipped one ct byte in entry 3 of 4: `passwd` exit 1, `cmp` shows ring unchanged, other entries still sign. |
| L13 | G15 keychain | `Get` maps every `security` failure (locked keychain/errSecInteractionNotAllowed, user denied, `security` missing) to `ErrNotFound` "no keychain item for that service"; `security`'s stderr is discarded by `.Output()`. | exit 1, mislabelled text (documented in SECURITY "Known limits") | ACTIONABLE (loud, but misdiagnoses; operator will recreate the item) | **V** for a missing item (`security` exit 44 -> message); **I** for other codes (code: `if err != nil { return nil, ErrNotFound }`). |
| L14 | G6/G18 explicit source | `KEYSTORE_PASSPHRASE=` (set but empty, e.g. an unset CI secret expanded) is treated as unset (`ok && v != ""`). With `-passfile` present the passfile is used with no `shadowed` note; with none the error says "set KEYSTORE_PASSPHRASE" although it is set. Same for `KEYSTORE_NEW_PASSPHRASE`. | nothing when a passfile exists; misleading text otherwise | LOG-ONLY (low) | **V**: `KEYSTORE_PASSPHRASE= keystore sign -id a -passfile pass` -> signs, no note. Without passfile: error text above, exit 1. |
| L15 | G13 / SECURITY "Where the ring lives" | The ring's directory is never checked (the agent checks its socket dir). Ring in a 0777 dir: `keygen` exit 0, no warning. Another user could pre-create `<ring>.lock` or swap the ring. | none (advice in SECURITY only) | SILENT (low; documented advice, not a promise) | **V**: `keygen -keystore open777/r.ks` exit 0, dir 0777. |
| L16 | G9 agent failure visibility | Signer errors: agent keeps answering `P`, returns `sign failed` and logs `sign: <err>` per request, never exits. Unreachable from the CLI agent (an in-memory `ed25519.PrivateKey` cannot fail), reachable for library embedders with a hardware `crypto.Signer`. | agent `Log` line per failure; client `"sign failed"` | LOG-ONLY (log-only; no escalation; `P` still succeeds so a Dial-based health check passes and also resets `-idle`) | **V** (injected failing signer): 5 sign failures, 5 log lines, `Dial` still succeeds, `Serve` keeps running. |
| L17 | G9 library default | `Server.Log` is nil by default: library embedders get no rejected-connection, oversize-frame, sign-failure or EMFILE lines unless they set it. The CLI agent sets `log.Printf`. | none by default | LOG-ONLY (never-ran shape: absent, not zero) | **I**: `server.go logf`; `cmd/keystore-agent/main.go` sets `srv.Log = log.Printf`. |
| L18 | G10 EMFILE | EMFILE/ENFILE on accept: agent logs `accept: ...; retrying` every 50 ms (20 lines/s) while serving nothing new; no escalation, no exit. | log flood line | LOG-ONLY | **I** (code `server.go:205-209`; test injection exists). |
| L19 | G5 guard | `guardTerminal` is fail-open if `Stat` on stdout errors and only checks terminal/regular-file mode; pipes and `>>` onto an existing 0600 file are unchecked (documented). | none | SILENT (documented; excluded below as a stated limit) | Code `output.go:24-27`; SECURITY states pipes unchecked. |
| L20 | G1 KDF cost | Entries written at a lower KDF cost (any value in `kdf` bounds, min 8 MiB/t=1) keep it; only `passwd` upgrades; `list`/unlock say nothing about cost. Not reachable today (single default cost in v0.1.0). | none | LOG-ONLY (latent) | **I**: `kdf.go` bounds; SECURITY "add does not upgrade". |
| L21 | G5 terminal | `restore()` ignores the `IoctlSetTermios` error; a failed restore leaves echo off with no message. Interactive only. | none | SILENT (low) | **I**: `term.go:51`. |

No exit-0-after-failure path found in the CLI verbs (L4, L11 are exit-0 successes whose effect is unannounced, not failures). Stderr writes after commit are unchecked (`fmt.Fprintf(s.err, ...)`) by design.

## 2. Sections per SILENT and LOG-ONLY

### L1 (SILENT) TTL/idle measured in awake time
Guarantee: "stop after this long" / "an unlocked key does not outlive the session". State: machine suspended; Go timers are monotonic-clock and pause with it, so wall-clock lifetime exceeds `-ttl`. Invisible because nothing compares against wall time and nothing logs the actual elapsed time at expiry. Signal should be: record `start := time.Now().Round(0)` and have `watch` also check `time.Since`-on-wall every N seconds (or compare after each wake), and log "ttl reached (wall elapsed X)" at stop. Confidence in mechanism: moderate (not exercised).

### L2 (SILENT) Orphaned agent: socket gone, key still held
Guarantee: key served only via the owner-only socket, agent exits when it cannot serve. State: socket path unlinked externally. Accept on an unlinked listener never errors. Invisible: process alive, no log, service manager green; with the shipped `-ttl 0 -idle 0` it never ends. Signal should be: periodic `Lstat`/dial self-check on the socket path (every minute), `log` + exit nonzero when it is not the socket this agent created; and the second-agent refusal text should say "lock held by pid N (no socket)".

### L3 (SILENT) Agent outlives `rm` / `passwd` of its key
Guarantee: rotation step 4 / `rm` "retire the old one". State: agent keeps signing a key that is no longer in the ring. Invisible: `sign -agent` prints `signing with <fp>` (the retired key's) and exits 0; the ring and the agent never reconcile. Signal should be: document in SECURITY/rotation ("restart or stop the agent after `rm`/`passwd`"), and/or have the agent stat the ring at start and on each request (or a timer) and log+exit when the entry for its id is gone or the ring changed.

### L4 (LOG-ONLY) `$HOME` unset: ring silently created in CWD
Guarantee: default ring `~/.config/keystore/default.ks`. Signal should be: fail ("no -keystore, KEYSTORE_FILE or home directory") instead of `default.ks`; and `keygen`/`add` should print the ring path on stderr as `init` does.

### L5 (LOG-ONLY) Clean-exit expiry is "success" to service managers
State: agent stopped by TTL/idle, exit 0, one log line. Under `Restart=on-failure` / `SuccessfulExit=false` it stays down. Signal should be: the units/README should state that a nonzero `-ttl`/`-idle` under a manager means "inactive until restarted"; optionally an exit code distinct from 0 for expiry (e.g. 0 for signal, a documented code for expiry) so `Restart=on-failure` policies and alerts can choose.

### L6 (LOG-ONLY) Restart loops are bounded only by manager defaults
launchd retries forever every ~10 s with one stderr line each; systemd gives up after 5 and goes `failed`. Neither is alerted on by keystore. Signal: add `ThrottleInterval`/`StartLimit*` and `RestartSec` to the example units, and say where the failure shows (`launchctl print`, `systemctl --user status`).

### L9 (SILENT, documented) Stale `.tmp` ring copies
Guarantee: revocation story in SECURITY. State: crash residue, never swept, never reported. Signal should be: `list`/`Open` (or the next `Update`, which holds the lock) removing or warning about `.<ring>.*.tmp` files older than the lock holder.

### L11 (LOG-ONLY) `keygen` leaves an empty ring on a failed passphrase step
Signal should be: on failure after creation, say "created empty ring PATH" (or create the ring only after the passphrase is known).

### L13 (ACTIONABLE, mislabel) and L14 (LOG-ONLY), L15 (SILENT), L16-L18, L20, L21
- L13: should surface `security`'s stderr / exit status in the error (`security exited 36: ...`) while keeping "no keychain item" only for exit 44.
- L14: treat set-but-empty as an explicit-but-empty source: error "KEYSTORE_PASSPHRASE is set but empty".
- L15: warn (stderr) when the ring's directory is group/world-writable, as the agent does for its socket dir.
- L16/L17: embedders should be given a default `Log` (stderr) or a counter accessor; `Server.Log` documented as the only signal.
- L18: rate-limit the EMFILE line or exit after N consecutive.
- L20: show KDF cost in `list` (or a warning below `kdf.Default`) once a second cost exists.
- L21: log restore failure.

## 3. Deliberate exclusions (decided, with reason)

- **Successful sign requests are not logged by the agent.** No stated guarantee of an audit trail; SECURITY says any same-uid process can sign. Noted, not a lapse.
- **`-idle` is reset by a successful `P` (health checks keep the agent alive).** Documented in userguide and agent-protocol.
- **Wrong passphrase vs tamper indistinguishable (G8).** By design; message is loud.
- **Pipes unchecked (`export-priv | tee`) and `>>` onto an existing file.** Documented limit.
- **Keychain hex output for non-ASCII passphrases.** Documented limit; fails loudly at unlock.
- **Core dumps.** Units set `LimitCORE=0` / `Core 0`; the agent itself sets no rlimit/dumpable, but Go does not dump core without `GOTRACEBACK=crash`. Docs claim only "in both definitions".
- **Filesystem that lies about fsync, NFS flock semantics.** Outside what a user-space tool can observe.
- **Ring-wide unauthenticated state (`current`, order, rollback).** SECURITY/decision 39 name it; `sign` names the key it used (decision, W1-D1).
- **`examples/signed-requests` verifier: nonce cache is in memory.** An example; README line 21 says so (a restart also empties it, which the README does not say).
- **`deadcode -test ./...` is clean (exit 0, no output).** Without `-test`, the only report is `Keystore.Path` (library accessor, used by tests); not a signal accessor. Grep for `Dropped|Failed|Stale|Degraded|Truncated|Oversize` in non-test Go: no hits.
- **EINTR/ECONNABORTED on accept.** Go's `net` retries ECONNABORTED internally; others stop the agent (exit 1, logged) by design.

## 4. The rule this pass produced

**A long-lived process that holds something must watch the thing that makes holding it legitimate, not only its own timers.** The agent's three promises (bounded lifetime, reachable via its socket, key still belongs to the ring) each depend on something outside the process (wall clock, the socket path, the ring entry), and the process checks none of them: it only waits on its own monotonic timers and accept loop. Whenever a daemon's guarantee is relative to an external object, give it a self-check that compares against that object and exits nonzero with a log line when it no longer matches. A clean exit 0 should mean "I was told to stop", never "my premise lapsed".

Secondary rule: where a command commits state and then fails a later step (L7, L8, L11), the error text must say what was committed.
