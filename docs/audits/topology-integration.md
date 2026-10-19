# Real-topology integration tier (audit wave L3b)

keystore is not a cluster, but in production it is many processes sharing one ring file and
one agent socket. An in-process test stubs the three things that matter there: the disk
(fsync, rename, `flock`), the process boundary (a real `SIGKILL`, a real exit) and the
kernel's peer credentials. This tier runs the **built binaries** (`keystore`,
`keystore-agent`) as real processes, on a real filesystem, over real unix sockets, on macOS
and inside a Linux container.

Status: every scenario below ran and passed on both platforms (cross-uid on Linux only).
**No production defect was found.** Labels used throughout: *verified* = I ran it and saw
the output recorded here; *inferred* = reasoned, not executed.

## What it proves, and how it is built

Code: `integration/topology/` (Go tests, build tag `topology` and `KEYSTORE_TOPOLOGY=1`;
plain `go test ./...` does not see them). Driver: `scripts/topology.sh`. Every child gets a
clean environment (throwaway `HOME`, no `KEYSTORE_KEYCHAIN`, passphrase only via
`KEYSTORE_PASSPHRASE`), so the macOS keychain and `security(1)` are unreachable.

| # | Scenario | Test | Asserted (a violation fails the test) |
|---|---|---|---|
| 1 | Cross-process ring contention | `TestContention` | N worker loops spawn real `keystore add`/`rm`/`use` processes on one ring while one loop rotates the passphrase with `passwd`. Final ring equals the model exactly (seed + successful adds - successful rms: no lost write, no phantom); every entry unlocks under the one final passphrase (#5); ring mode 0600; no `.tmp` or other debris; `current` names an entry. Live: a checker snapshots the ring about every 0.7 s, it must parse (#3) and the seed plus two sampled entries must unlock under the same passphrase generation (#5). Adds with a wrong passphrase must never succeed. Outcomes are classified: ok, `ErrLocked`, stale passphrase (tolerated only while a `passwd` was in flight), anything else is a violation. |
| 2 | Real `SIGKILL` crash loop | `TestCrashLoop` | A writer (`add`/`rm`/`use`/`passwd`) is killed with `SIGKILL` at a random delay (uniform over 0..1.25x the calibrated op time; 40 % of kills aimed at the last stretch, where the temp file is written, renamed and the directory synced). Afterwards the ring parses and equals exactly the model's old state or its new state (ids, current, passphrase generation); all entries unlock under one generation (all of them after `passwd`, seed plus a sample otherwise); a probe writer (`use`) succeeds within 3 s (lock not wedged); at most one `.tmp` per kill, none after a process that exited first, each mode 0600, counted and removed. |
| 3 | Cross-uid agent rejection | `TestCrossUID` | Linux container, root. Agent runs as uid 1000. Control: with default modes uid 1001 gets `EACCES`. Then dir 0755 / socket 0666 on purpose. A raw client (bypassing the library's own client-side check) as uid 1000 gets the 37-byte public-key reply; as uid 1001 and as root it **connects** (so mode is not what stops it), gets no reply byte, and the agent logs `rejected connection: peer uid 1001 (want 1000)` / `peer uid 0 (want 1000)`. `keystore sign -agent` as 1000 succeeds, as 1001 and root is refused client-side ("not the current user"). |
| 4a | Concurrent clients, SIGTERM and restart under load | `TestAgentHammerRestart` | 48 client goroutines (library `Dial`+`Sign`, each verifies) while the agent gets SIGTERM: exit 0, socket gone, no signature after exit, a fresh agent on the same path takes over and the clients recover, zero wrong-key/bad-signature results. |
| 4b | TTL with live connections | `TestAgentTTL` | `-ttl 3s`, 8 held-open connections and 16 hammering clients: the last successful signature is no later than the deadline (first dialable moment + ttl) + 300 ms, every held connection sees EOF at the deadline, exit 0, socket removed, a dial after expiry fails. Observed from outside only. |
| 4c | Idle expiry | `TestAgentIdle` | Traffic every 0.7 s keeps a 2 s idle agent alive past 4 s; a silent held connection does not; expiry lands about idle after the last request; the held connection sees EOF. |
| 4d | Racing starts | `TestAgentRaceStart` | 10 agents released at the same instant on one socket path: exactly one survives, nine exit 1 with "already listening", the winner answers afterwards (losers did not unlink its socket). |
| 4e | Stale socket after SIGKILL | `TestAgentStaleSocket` | SIGKILL leaves the socket file; dial gives `ECONNREFUSED`; a new agent takes over and signs; repeated. |
| 4f | Socket removed or replaced (the A5-L2 stop) | `TestAgentSocketRemoved` | Agent stops with exit 1 about 10 s after its socket vanishes, logs why, drops held connections; a regular file put in its place is left byte-identical. |
| 5 | Simulated fleet | `TestFleet` | 24 (and 32) concurrent client processes (`keystore sign -agent` on three agents, plus `keystore sign -keystore` straight from the ring) while the operator runs add k2, `passwd`, `use k2`, start agent 2 on k2, `rm k1`, add k3, `passwd`, `use k3`, start agent 3. Every signature verifies under the key its process reports; agent 1 keeps signing k1 after k1 is gone from the ring and the passphrase changed twice (documented semantics: a running agent keeps the key it loaded); a final cross-check shows no agent's signature verifies under a key it was not started with. |

### Can the tier fail? Production mutants (verified by the skeptic review and by me)

Each mutant was applied to production code, the binaries rebuilt, and the tier run against
them; production was reverted afterwards. "Killed" means a tier test failed.

**Killed (skeptic review):** `flock` removed from the ring lock (contention, 8 workers /
120 ops); `Save` truncating and writing the ring in place (see the iteration caveat
below); TTL timer never armed; TTL extended by traffic; idle timer never reset; socket not
unlinked on close; connections not closed at stop; stale-socket takeover removed; second
agent steals a live socket (flock and dial check removed); the A5-L2 socket-lost check
removed; peer-uid check removed or inverted (container); `passwd` writing entries one at a
time; `add` not re-reading the ring after taking the lock; `add`'s `checkPassphrase` a
no-op; `passwd` setting current to the last entry; `use` duplicating an entry (killed by
the library's invalid-ring refusal, not by the old-or-new comparison).

**Killed after the hardening in this revision (verified by me, red against the mutant,
green against production):**

| Mutant | Killed by |
|---|---|
| ring-direct `sign` picks the first entry instead of `current` (and reports its own fingerprint) | `TestFleet`: "signed under ... but current is k2" |
| `Remove` does not move `current` when the current entry is removed | `TestCrashLoop` (the `rm` exits 1, "refusing to write an invalid ring"), found at lane iteration 21-48 of a 300-iteration run |
| `Remove` always resets `current` to the first signing key | `TestCrashLoop`: "neither old nor new", lane iteration 18-30 |
| ring entries reversed on every write | `TestCrashLoop`: "neither old nor new", at iteration 0-1 of every lane |

The new live check in `TestContention` ("`current` names an existing signing entry") did
**not** kill the `Remove` mutant at 8 workers / 120 operations: the ring parser already
refuses a dangling `current`, so that check is belt and braces, and a worker rarely removes
the entry that is current. I report it as added, not as a proven killer.

**Survived, and why that is expected:**

* `fsync` and directory sync removed. `SIGKILL` cannot lose the page cache, so **this tier
  cannot detect a missing fsync**; durability across power loss is simply not tested here.
  (An earlier draft of this document said the fsync "ordering is exercised"; that was
  too strong and is withdrawn.)
* `flock` ignored while the dial check is kept in `Listen`: near-equivalent, because the
  socket bind itself is exclusive.

**Survived the first revision, now killed:** `Remove` not moving `current`, `Remove`
always resetting `current`, entries reversed on every write, and the ring-direct signer
choosing the first entry (table above).

#### The in-place-write mutant needs many iterations

`Save` truncating and writing in place is caught only when a kill lands in the short window
between truncate and write, which is rare. The default `TOPO_ITERS=60` cannot catch it,
and 200 iterations with seed 7 passed with 87 kills (skeptic). I re-ran it against the
revised model: with seed 7 and 1500 iterations over 4 lanes it failed ("ring does not
parse") in 2 of 4 lanes, at lane iterations 98 and 138, and the other two lanes
(375 iterations each) did not hit it. That is about one hit per 100-150 iterations in the
lanes that hit, and none in roughly 750 lane-iterations in the others, so plan on **500 or
more iterations per run** and expect a run that large to still miss it occasionally:

    TOPO_RUN=TestCrashLoop TOPO_ITERS=1500 TOPO_LANES=4 TOPO_SEED=7 scripts/topology.sh mac

(the 3000- and 1000-iteration runs reported below used other seeds and passed against
production).

## Platforms and constraints (phase 0, verified)

* macOS: Darwin 25.6, arm64, 8 CPUs, host filesystem (APFS, from the OS temp dir).
* Container: Apple `container` 1.5.0, `alpine:latest` arm64, Linux 6.18.15, 5 vCPU, 4 GiB,
  root. Rings, locks and sockets live on the container's **own ext4 root filesystem**
  (`/dev/vdb`); only the binaries and the result file cross the virtiofs mount.
* Containers started with `--rm` and a name; the driver removes the container on exit or
  signal. No container was left behind.
* Not available: a second physical machine, `NET_ADMIN`/partition injection (not needed:
  the transport is a local unix socket), a non-root macOS uid (needs sudo, not used).
* The distributed-systems "above RF" rule has no analogue here; the equivalent was running
  contention at 8, 16 and 32 concurrent processes, and the fleet at 24 and 32.

## Exact commands

    scripts/topology.sh mac          # build, then run the tier on this machine
    scripts/topology.sh container    # cross-build linux/arm64, run in an alpine container
    # scale and subset via the environment, e.g. what produced the numbers below:
    TOPO_RUN=TestContention TOPO_WORKERS=16 TOPO_OPS=2000 scripts/topology.sh mac
    TOPO_RUN=TestCrashLoop  TOPO_ITERS=3000 TOPO_LANES=4 TOPO_SEED=20261021 scripts/topology.sh mac
    TOPO_RUN=TestCrashLoop  TOPO_ITERS=1000 TOPO_LANES=4 TOPO_SEED=20261022 scripts/topology.sh container
    TOPO_RUN='TestAgent|TestFleet|TestCrossUID' TOPO_TTL_ROUNDS=20 TOPO_RACE_ROUNDS=20 \
        TOPO_STALE_ROUNDS=50 scripts/topology.sh container

Defaults (no variables) are small enough to finish in a few minutes. Result lines are
appended as JSON to `$TOPO_OUTDIR/results-*.jsonl`. `TOPO_SEED` reproduces the kill-delay
sequence, not the kernel's scheduling, so a failure is re-runnable but not bit-replayable.

## Results (verified; one run each unless stated)

### 1. Contention (violations: 0 in every run)

Each worker op is one real process. "Ops" counts launched processes, including those that
ended in `ErrLocked`.

| Platform | Workers | Ops | Wall time | add ok / locked / stale-pass | rm ok / locked | use ok / locked | passwd ok / locked | wrong-pass adds (all refused) | live checks | final entries |
|---|---|---|---|---|---|---|---|---|---|---|
| macOS | 8 | 1000 | 11 m 10 s | 206 / 172 / 113 | 134 / 102 | 118 / 64 | 35 / 0 | 91 | 473 | 73 |
| macOS | 16 | 2000 | 14 m 42 s | 323 / 531 / 136 | 209 / 263 | 157 / 217 | 30 / 3 | 164 | 608 | 115 |
| macOS | 32 | 1500 | 6 m 06 s | 220 / 487 / 68 | 111 / 231 | 90 / 182 | 10 / 5 | 111 | 263 | 110 |
| Linux ct | 16 | 1500 | 8 m 58 s | 308 / 359 / 73 | 189 / 168 | 139 / 143 | 18 / 0 | 121 | 424 | 120 |
| Linux ct | 32 | 1000 | 3 m 56 s | 214 / 316 / 16 | 82 / 125 | 59 / 106 | 5 / 5 | 82 | 179 | 133 |

Reading it:

* No lost write, no phantom entry, never a torn or non-parsing ring, never two
  passphrases in one ring, in 7 111 launched processes (worker operations plus `passwd` runs).
* `ErrLocked` is common and every one is accounted for: the model treats it as "nothing
  written", and the final ring agrees. One denominator throughout: **all launched
  processes** (worker operations, including wrong-passphrase adds, plus `passwd` runs);
  numerator: every process that ended in `ErrLocked`. macOS: 375/1035 = 36 % (8 workers),
  1106/2033 = 54 % (16), 977/1515 = 64 % (32). Linux container: 738/1518 = 49 % (16),
  602/1010 = 60 % (32). (The skeptic's review counts the same data without the
  wrong-passphrase adds and per worker operations, giving 34/51/60 % and 45/55 %; the
  difference is only the denominator and those adds.)
* Cause of the high `ErrLocked` rate (*verified* measurement, *inferred* link): `passwd`
  re-derives every entry, about 0.33 s each (`passwd` of a 40-entry ring took 13 s on this
  Mac, measured twice, whole-second resolution, longer than the 10 s lock wait), and the test's ring grows to 70-130 entries
  because adds outnumber removes. Past roughly 30 entries a `passwd` holds the lock longer
  than `LockTimeout`, so every concurrent writer gets `ErrLocked`. This is documented
  behaviour (SECURITY.md: "gets `ErrLocked` after the 10 s wait; nothing is lost"), not a
  defect; it is an operational fact worth knowing for large rings.

### 2. SIGKILL crash loop (violations: 0 in every run)

Revised model (entries compared in file order with public key, nonce and ciphertext;
`current` compared exactly; the probe sets a random `current` each iteration and `rm`
sometimes removes the current entry):

| Platform | Iterations | Killed by SIGKILL | Exited before the kill | Stale `.tmp` left | Kill landed after the rename (state = new) |
|---|---|---|---|---|---|
| macOS (seed 20261031) | 3000 | 1327 | 1673 | 97 | add 14, passwd 2, rm 51, use 39 |
| Linux ct (seed 20261032) | 1000 | 697 | 303 | 153 | add 7, passwd 0, rm 20, use 16 |

Earlier model (ids compared as a sorted set, `current` reset to the seed each iteration,
current never removed), kept because it is real evidence for the same properties:

| Platform | Iterations | Killed | Stale `.tmp` | Kill landed after the rename |
|---|---|---|---|---|
| macOS, run A (uniform delay) | 3000 | 2007 | 127 | add 18, passwd 1, rm 91, use 38 |
| macOS, run B (40 % tail-aimed) | 3000 | 1438 | 118 | add 14, passwd 2, rm 55, use 23 |
| Linux ct, run A | 1000 | 632 | 70 | add 0, passwd 0, rm 15, use 16 |
| Linux ct, run B | 1000 | 640 | 126 | add 7, passwd 1, rm 22, use 13 |

* After every one of the 12 000 iterations (4 000 revised, 8 000 earlier) the ring parsed,
  equalled exactly the old or the new model state, and the next writer succeeded at once.
  Both outcomes were observed for every op type, except that `passwd` was caught after its
  rename only 0-2 times per run: the window between the rename and the process exit is
  milliseconds wide, and `passwd`'s time is almost all key derivation. So the "new state
  after a kill" side is well covered for `rm`/`use`/`add` and thinly covered for `passwd`.
* Stale `.tmp` files: never more than one per kill, always mode 0600, never after a
  writer that exited by itself (asserted each iteration); 441 in the earlier runs, 250 in
  the revised ones. This is the documented leftover (SECURITY.md).
* SIGKILL leaves the page cache intact, so this tests process death, not power loss.

### 3. Cross-uid (Linux container, verified)

    control, default modes: uid 1001: connect-error=EACCES
    permissive: dir drwxr-xr-x socket Srw-rw-rw-
    uid 1000 (agent's own):  connected reply-bytes=37
    uid 1001 (other user):   connected reply-bytes=0 err=ECONNRESET
    uid 0    (root):         connected reply-bytes=0 err=ECONNRESET
    agent log: rejected connection: peer uid 1001 (want 1000)  /  peer uid 0 (want 1000)

The two refused clients got through `connect(2)` on a 0666 socket in a 0755 directory, so
file mode did not stop them; the agent's peer-uid check did. The "not run" item in the
release record is closed for Linux (`SO_PEERCRED`). macOS (`LOCAL_PEERCRED`) was not run
cross-uid (needs root); only same-uid paths run there.

### 4. Agent chaos (macOS / Linux container)

| Test | Result |
|---|---|
| Hammer + SIGTERM + restart (48 clients) | mac: 58 444 signatures before SIGTERM, 37 928 after restart; Linux: 77 532 / 54 862. Exit 0, socket removed, 0 wrong-key or bad-signature results. |
| TTL 3 s, 20 rounds each | worst last-successful-sign vs deadline: mac +1 ms, Linux +1 ms (limit 300 ms); worst process exit vs deadline: mac +5 ms, Linux +1 ms. All 160 held connections per platform saw EOF at the deadline; all post-expiry dials failed. |
| Idle 2 s | expiry 2.003 s (mac), 2.008 s (Linux) after the last request, with a silent connection held open and traffic having kept it alive past 4 s. |
| Racing starts, 20 rounds x 10 agents | exactly one winner in 20/20 rounds on both platforms; 180 losers per platform exited 1 with "already listening". |
| Stale socket after SIGKILL, 50 rounds | `ECONNREFUSED` on the stale socket and a successful takeover every time, both platforms. |
| Socket removed / replaced | agent stopped 10.0 s later, exit 1, held connection closed; the replacement file untouched (both platforms). |

The TTL numbers are the F1 regression at scale: from the outside, the key does not answer
after the deadline, to within a few milliseconds.

### 5. Fleet (verified)

| Platform | Client processes | Signatures verified | Peak concurrent client processes | Agent-1 signs after k1 removed from the ring | Violations |
|---|---|---|---|---|---|
| macOS | 24 | 8 248 (also 8 348 in an earlier run) | 24 | 2 272 | 0 |
| macOS | 32 | 9 121 | 32 | 2 837 | 0 |
| Linux ct | 24 | 35 466 | 24 | 9 105 | 0 |

The first macOS run at 32 failed with 5 "violations". That was a bug in the test (it
compared a counter shared by all ring-signing workers, so one worker's legitimate
stale-passphrase refusal during a rotation was blamed on another); I fixed the test to
judge each process on its own outcome and re-ran, and the earlier line is superseded.
It was not a product defect: the refusals themselves were "stale passphrase while a
`passwd` was in flight".

## Flakiness observed

* One: `TestAgentHammerRestart` under `-race` on a busy machine flagged a signature
  stamped 2.7 ms after the agent's recorded exit. The timestamp is taken by the client
  goroutine after the reply arrives, so scheduling delay explains it (*inferred*; a real
  post-exit signature is impossible, and the test separately attempts one and requires it
  to fail). The check now allows 250 ms. After that, the five tests re-run under `-race`
  (small scale) passed.
* No other flake in the runs above. The timing-sensitive assertions (TTL +300 ms slack,
  idle window, 10 s socket-lost stop) held with 1-5 ms observed error over 40 rounds.

## What this tier does not reach

* Power loss and torn writes below the page cache: `SIGKILL` cannot lose cached data, so
  a missing `fsync` or directory sync is **undetectable** here (an fsync-removed mutant
  survived).
* Network or exotic filesystems: no NFS/SMB; `flock` and `rename` were tested on APFS and
  ext4 only. (The container's virtiofs host mount was deliberately not used for rings.)
* More than one machine, partitions, clock jumps, suspend/resume (the documented
  "TTL elapses while asleep" caveat is not exercised), `SIGSTOP`.
* Resource faults: `ENOSPC`, `EIO`, descriptor exhaustion, OOM kill.
* Other platforms: Linux x86-64, other distributions, user-namespace uid mapping, macOS
  cross-uid (root required).
* The model: contention workers own disjoint ids, so same-id add races are not part of the
  model (the library's own tests cover `ErrExists`); `passwd` is a single loop, so two
  concurrent `passwd` calls are not exercised. The fleet's "right key" for ring-direct
  signing is the fingerprint the process reports plus a verifying signature under it; I
  do not independently assert which key was current at that instant.
* The client in the hammer test is the Go library, not the CLI; the fleet uses the CLI.
* Kill timing coverage of `passwd` after its rename is thin (see section 2).
* `current` integrity: in the revised crash model `current` is compared exactly (old or
  new), but in `TestContention` it is only checked as "names an existing signing entry"
  (live and at the end). The contention and fleet numbers in sections 1 and 5 come from the
  first revision of those tests; after hardening, a reduced run passed on both platforms
  (contention 16 workers / 400 ops: macOS 2 m 33 s, 102 live checks, 40 final entries;
  Linux 2 m 29 s, 94 live checks, 69 entries; fleet 32 processes: macOS 5 185 signatures
  verified, Linux 21 715; agent suite at 5/5/10 rounds and cross-uid unchanged), but the
  full-scale contention and fleet runs were not repeated.
* Entry contents and order: the revised crash model compares file order and each entry's
  public key, nonce and ciphertext (byte-identical for untouched entries, all different
  after `passwd`); the contention and fleet tests compare only the set of ids.
* Ring-direct signing is asserted to use `current` only when no `use` was in flight, and
  only for the three keys the fleet creates.

## Hermetic regression proposals

None: no defect was found. (Had the cross-uid check been missing, the hermetic analogue
already exists as the `uidOf` seam in `pkg/agent`; the mutant run above shows the tier
would catch its removal.)
