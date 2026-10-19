# keystore — audit & hardening plan (A-series, L1–L3b; L4 held)

*The audit's plan of record, kept as written while the audit ran (status at the end, section 10). The
outputs are the reports in this directory and the fixes on `main`; [README.md](README.md) is the index.
Method: the house audit prompts A1–A7 and L1–L3b, in the suggested order.*

Labels: **[V]** verified in this session · **[R]** reported by a repo doc · **[I]** inferred.

## 0. The request, read

- **Asked:** audit keystore with A1 then the L series (L4 held); build whatever is needed to run,
  test and prove; audit the crypto carefully; fix everything found, one branch per fix, committed
  and merged; "verified" means a skeptic signed off the fix; plan tasks/agents/subagents.
- **Underneath:** keystore is a small, security-sensitive module that has had one pre-release
  review (F1–F8) and a local `v0.1.0` tag [R: `docs/audits/release-v0.1.0.md`]. The aim is to find
  what that review and the 18 green packages did *not* assert, before it goes public.
- **Next hour:** the plan is read, then waves 0–1 start. Nothing here ships; L4 is untouched.

## 1. Baseline (all [V], macOS arm64, go1.27.2, 2026-10-18)

| Check | Result |
|---|---|
| `go build`, `go vet`, `gofmt -l` | clean |
| `staticcheck`, `deadcode -test` | clean (no output) |
| `govulncheck` | 0 reachable; 1 module-level finding in `x/crypto` (openpgp, not imported) |
| `go mod tidy -diff` | no diff |
| `go test -race -count=1 -cover ./...` | 18/18 ok |
| Coverage (weakest) | `internal/term` 33.3 · `examples/secrets` 65.7 · `internal/keychain` 70.6 · `internal/peercred` 75.0 · `cmd/keystore` 79.1 · `cmd/keystore-agent` 82.3 |
| Git | branch `main`, clean tree, 23 commits, tag `v0.1.0` (local), **no remote** |
| Source size | ~6.3k Go lines incl. tests; deps: `x/crypto v0.56.0`, `x/sys v0.47.0` |
| Container runtime | Apple `container` 1.5.0 running; runs linux/arm64 binaries; network + `apk` work; OpenSSL 3.5.9 installable; image `alpine` cached |

**Not covered by the v0.1.0 record** [R], now runnable here [V]: Linux runtime (peercred, examples),
real cross-uid agent rejection (second uid in a container), OpenSSL 3 interop on exported PEM,
`systemd-analyze verify`, an SPDX validator.

## 2. Ground rules

1. **No push, no tag changes, no L4.** There is no remote; "merge" is a local `--no-ff` merge to
   `main`. The existing `v0.1.0` tag is never moved; fixes land after it, and L4 (later) decides
   `v0.1.1` vs retag. *No issues can be filed (no tracker); findings live in the ledgers and
   `open-items.md`.*
2. **No new third-party dependency** (house rule; the L2 prompt's rule 1). Test-only tooling that needs
   one (OpenSSL, python, ssh-keygen) runs **outside the Go module**, in containers or scratch dirs.
3. **Report-only until a finding is CONFIRMED.** Auditors edit nothing. Throwaway PoCs live in the
   session scratch area against a *copy*, never the repo source.
4. **One finding = one branch** `fix/<ID>-<slug>`: failing test first → fix → full gate → fix-skeptic
   sign-off → `git merge --no-ff` → delete branch. The merge commit carries
   `Skeptic-Verified:` with the lens results. A fix the skeptic rejects is reworked or reverted,
   never merged.
5. **Stop-and-ask triggers** (A3 requires confirming before changing a security boundary): any fix
   that changes the **ring format** (`keystore/v1`), the **agent wire protocol**, a **default KDF
   cost**, or **removes a documented guarantee**. Format-preserving validation/hardening fixes
   proceed without asking. Everything else the user pre-authorised ("fix everything").
6. **Least-code ladder on every fix** (the least-code agent's ladder): a gap is not answered with a new
   abstraction, flag or dependency; withdrawing an over-claim in docs is a valid fix.
7. **Re-validation gate after every merge:** `gofmt` · `vet` · `staticcheck` · `deadcode -test` ·
   `go test -race -count=1 ./...` · golden fixture · `go mod tidy` no-diff · `govulncheck`.
   Linux cross-vet after anything platform-touching.

## 3. Where the risk actually lives (effort allocation)

Risk = chance wrong × cost × silence.

| Rank | Surface | Why |
|---|---|---|
| 1 | `internal/seal`, `internal/kdf`, `pkg/keystore` (AAD binding, passphrase invariant, `ChangePassphrase`) | Silent failure = plaintext/forgery with every test still green. Cut-and-paste of entries across rings, rollback, unauthenticated ring-level fields (`current`) are **[I]** candidates, unproven. |
| 2 | `internal/ringfile` (lock, atomic write, symlink, size caps) | Crash/race bugs surface at 3 a.m.; the "never a torn ring" property is only asserted by single-process tests **[I]**. |
| 3 | `pkg/agent` (socket ownership, peer-uid, expiry, framing) | Key-in-memory lifetime and who can ask for a signature. Cross-uid rejection was **not run** [R]. |
| 4 | `internal/passphrase`, `cmd/keystore` secret handling (argv/env/tty/files/keychain/export guards) | Disclosure paths; many are platform-specific. |
| 5 | Docs, examples, generated reference, build/CI | Loud or cheap; starve. |

## 4. Orchestration

**Main loop (me)** is the only writer to `main`, runs the gate, owns merges and ledgers. Subagents
are launched with the `Agent` tool (parallel where independent, single message). I am not using
the `Workflow` tool (not requested).

| Role | Agent type | Isolation | Writes? | Parallelism |
|---|---|---|---|---|
| **Auditor** | `general-purpose` | none | no — report only | parallel, read-only |
| **Finding skeptic** | `general-purpose`, fresh | none; PoCs in scratch copy | no | one per candidate, parallel |
| **Harness builder** | `general-purpose` | `worktree` | yes, on a `test/<name>` branch | parallel if files disjoint |
| **Fixer** | `general-purpose` | `worktree` | yes, on `fix/<ID>-<slug>` | parallel only if files disjoint; else serial |
| **Fix skeptic** | `general-purpose`, fresh | none (reads diff + a copy) | no | one per fix |
| **Independent implementer** | `general-purpose`, **blind** | none | scratch area only | see wave 2 |
| **Container runner** | `general-purpose` | none | scratch area only | serial per container image |

**Finding form** (the house audit method): Claim · Grounds · Warrant · Backing · Rebuttal. Verdicts
CONFIRMED / PLAUSIBLE / REFUTED (kept, with reason). Correctness/security items need a
reproduction program.

**Fix-skeptic contract** (prompt: *"refute the fix; default to not-fixed if uncertain"*; sees only
claim + diff + repo). Seven lenses, each its own check:
1. new test **fails without the fix** (revert on a copy, run it) — mutation check;
2. root cause, not the reproduction (sibling inputs/paths/platforms);
3. behaviour preserved elsewhere (full gate; golden fixture byte-for-byte; exported-surface diff);
4. no new gap (unwired code, undocumented flag, doc now wrong);
5. reachable (the fix is actually called in the real binary path);
6. least-code ladder rung named;
7. for crypto/trust-boundary fixes: an **independent route** re-derives the property
   (second implementation, known-answer vector, or interop with OpenSSL), not just "the test passes".
Outcome recorded per fix: **FIXED-VERIFIED / FIXED-UNPROVEN (say which lens could not run) / REJECTED**.

## 5. Waves

Dependencies: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8. Waves 1b and 2 may overlap with 1; fix branches from
a wave merge before the next wave starts so later auditors read corrected code.

### Wave 0 — substrate (main loop) *(done: baseline above)*
Create `docs/audits/` ledgers, the container recipe (cross-compile `go test -c` binaries; alpine +
`apk add openssl`), and a scratch PoC area. Branch convention agreed above.

### Wave 1 — A1 (with A2's four dimensions)
Four **auditors** in parallel over the non-test source (+docs for D):
- **A simplify** (apply `least-code`), **B dedup**, **C correctness + optimization**,
  **D doc-vs-code drift** (README, `docs/*`, `format.md`, `agent-protocol.md`, flag help, generated
  `reference.md`, SECURITY.md claims, `decisions.md` vs code).
→ candidates → **one finding skeptic per candidate** → verdict table → `audit-findings.md` +
`audit-{simplify,dedup,correctness,docs}.md`. CONFIRMED findings go to the fix pipeline (§6).

### Wave 1b — A4 supply chain (main loop, parallel with 1)
Module hygiene, `go mod verify`, `govulncheck` reachability, license matrix (`x/crypto`, `x/sys`,
stdlib, SPDX/notices vs `THIRD-PARTY-NOTICES`), build-context hygiene, CI pinning. Output
`dependency-audit.md`. The `openpgp` module-level finding gets an explicit reachability check
and a recorded decision.

### Wave 2 — A3 security threat model + **careful crypto audit**
Boundary map first (assets: private keys, secrets, passphrase, ring file, agent socket;
boundaries: ring file, argv/env/tty/passfile/keychain, unix socket, `/usr/bin/security`; adversaries:
local other-uid, same-uid hostile process, ring-file writer, ring-file reader, supply chain).
Five **auditors** in parallel, each a crypto/security lens, each must write a PoC for HIGH+:
1. **Format & AEAD binding** — AAD completeness (every field that changes meaning), entry
   cut-and-paste across rings/ids, whole-ring rollback, unauthenticated fields (`current`, `created`,
   version), nonce handling, key/nonce reuse analysis, GCM tag/length edge cases, `ErrOpen` oracle.
2. **KDF & key lifecycle** — argon2id parameters vs RFC 9106 / OWASP, bounds (`kdf.Check`), salt
   freshness, CSPRNG-only, passphrase handling (copies, buffers, zeroisation claims), `ChangePassphrase`
   atomicity (no entry left under the old passphrase), one-passphrase invariant races.
3. **Agent & IPC** — peer-uid on both ends, socket path/dir permission checks and TOCTOU,
   stale-socket removal, lock-file symlink (`O_NOFOLLOW`), frame parsing bounds, request
   amplification/DoS, expiry timing, `Server.Close` races, signing-oracle scope.
4. **Ring file & filesystem** — lock/re-read under lock, atomic durable write order
   (temp → fsync → rename → dir fsync), symlink resolution, file modes, temp-file leakage, size caps,
   crash windows, JSON decoder surprises (duplicate/case-insensitive keys, large numbers, unknown fields).
5. **CLI/operator surface** — argv/env/`/proc` leakage, tty vs file output guards, export guards,
   passfile modes/FIFOs, keychain via `/usr/bin/security` (argv exposure of the passphrase to
   `ps`!), error-string and log leakage, prompt behaviour.

Plus two **independent-route proofs** (rule 4, re-derive not recognise):
- **Blind implementer:** an agent given *only* `docs/format.md` (not the code) writes a standalone
  Go decrypter in the scratch area; it must open `testdata/golden.ks` and a freshly made ring.
  Any disagreement is a finding in the spec or the code.
- **Interop:** in an alpine container with OpenSSL 3.5, import `export-priv` PEM, verify
  `keystore sign` signatures, and have OpenSSL sign what `keystore verify` accepts.
  Plus RFC 8032 Ed25519, NIST AES-GCM, and argon2id known-answer vectors where bounds allow.

Output: `security-review.md` (boundary map, findings CRITICAL→LOW with attack scenarios + PoCs,
the PoC-reproduced list), then the fix pipeline.

### Wave 3 — A5 silent degradation + A6 format compatibility
- **A5:** enumerate guarantees (SECURITY.md "protects", agent TTL/idle, lock timeout, durability,
  keychain behaviour, "refuses" claims). For each: does it lapse while still serving, and can an
  operator tell? Note keystore has no metrics; the signals are exit codes, stderr and the agent
  `Log`. Output `silent-degradation.md` (ledger is the artifact).
- **A6:** every encoded artifact (ring JSON, AAD encoding, agent frame, PEM, signature output).
  Check each field of each is pinned by a golden test; the golden fixture covers key+secret entries;
  add goldens where a layout change would pass silently. A6 may land golden tests (permitted).

### Wave 4 — L1 verification & optimization
Verify code against docs (D's findings consumed, not re-derived), map dead code, run unit, bench,
**fuzz (30 s each target)**, integration, race; the 3.6.x hardening validation (input boundaries,
error recovery, concurrency, resource limits, overflow/truncation, DoS). Profile hot paths — expected
to be the argon2id KDF (a deliberate cost; any "optimization" must not lower it). Output
`verification-optimization.md`; measured optimizations only.

### Wave 5 — L2 test / benchmark / fuzz / harden
- **Ledger:** every package and symbol → unit/harness/fuzz/bench/n-a with blockers. Start from the
  weak spots in §1 (term, keychain, peercred, cmd, examples).
- **Harnesses (builders, worktrees):**
  - injectable **clock** for agent TTL/idle (verify current tests don't sleep on wall time);
  - **fake `security` binary** on a controlled path for keychain tests (deterministic);
  - **pty/tty harness** for the no-echo prompt (`internal/term`);
  - **fake peer-uid** seam already exists (`uidOf`) — extend to cross-uid refusal cases;
  - **crash/fault injection** for ringfile (fail at each syscall in the write sequence).
- **Fuzz:** existing `FuzzParse`, `FuzzReadFrame`; add ring `Parse`→`Open`, AAD builder, id
  validator, passfile reader, PEM import, CLI arg parsing; crashers become seeds + fixes.
- **Hardening:** each security property in `scope.md` ("every release must meet" #1–7) gets an
  attempt to violate it. **Mutation check** of the security tests themselves: hand-mutate
  `seal`, the AAD builder, the verify gate, the constant-time path, the lock — every mutant must be
  killed by some test, else the test gap is a finding.
- **Bench:** KDF, seal/open, sign (ring vs agent), agent round trip, ring write; baselines recorded.
- Outputs: `test-ledger.md`, `defects-log.md`, `harness-inventory.md`,
  `benchmark-baselines.md`, `untestable-without-x.md`.

### Wave 6 — L3 live integration (build-tagged `integration`, `KEYSTORE_LIVE=1`)
keystore has **no third-party network peers**; the "real systems" are the OS and tools it
touches. Targets (catalog in `live-targets.md`, each with rationale and a known-bad case):
- **macOS Keychain via the real `/usr/bin/security`** — using a unique throwaway service name,
  cleaned up after. Doubly opt-in; if the OS prompts or blocks non-interactively, record as
  untestable-without-X rather than forcing it. *(Writes one item to the user's own login keychain;
  confirm before the first live run.)*
- **Linux runtime in an Apple container (alpine, arm64):** the whole test suite as cross-compiled
  test binaries; peercred (Linux path), the shell examples, file modes, `flock` on a real FS.
- **OpenSSL 3.5 interop** (wave 2 proofs, kept as a live test).
- Skip-vs-fail classifier tested (unreachable runtime → skip, keystore misbehaviour → fail).
  Every live-found defect gets a hermetic regression test.

### Wave 7 — L3b real-topology tier (scoped to what keystore actually is)
keystore is not a cluster, but it is **many processes sharing one file and one socket** — the
three layers an in-process simulator stubs (real disk, real process, real network/IPC) matter here.
Fake/simulated machine-to-machine is acceptable; in containers:
- **Cross-process ring contention:** N concurrent `keystore add` / `passwd` processes on one ring on
  a real FS → no lost write, ring always parses and unlocks (properties #3, #4, #5).
- **Real `SIGKILL` crash loop:** kill -9 a writer at random points across thousands of iterations;
  after each, ring opens and holds exactly old-or-new, lock files don't wedge.
- **Cross-uid agent rejection:** agent as uid A; client as uid B (and root) over a socket made
  reachable for the test → refused by the peer-uid check, not merely by file mode (closes the
  "not run" item).
- **Agent chaos:** concurrent clients, agent restart, TTL/idle expiry with live connections, racing
  agent starts, stale socket — the key must not outlive TTL (F1 regression at scale).
- **Simulated fleet (m2m):** a scripted fleet of client processes signing through one agent while the
  ring is rotated (`passwd`/key rotation), asserting every signature verifies under the right key.
Output `live-integration.md` (what it proves and what it does not reach).

### Wave 8 — A7 gap audit (before ship)
Yardstick = `scope.md` (verbs, 7 security properties, platforms, examples), every doc claim,
SECURITY.md, `decisions.md`, the release record's "Not run" list, and this plan's ledgers. Seven
places "done" hides gaps (promised/wired/verified/documented/operable/handed-on/closed), release
hygiene (no `LICENSE` yet by decision #2 — recorded, not an omission). Skeptic on findings, then
fix-skeptic on fixes. Output `gap-audit.md`.

### Closing (no L4)
Full gate green; ledgers consistent; `docs/audits/open-items.md` with the deliberately-not-open
table; a one-paragraph note on what L4 must still do (re-tag decision, release notes for the
post-tag fixes, public-repo checklist). **Not** done: tagging, release notes, SBOM refresh, pushing,
repo metadata.

## 6. Per-finding pipeline

```
candidate ─► finding skeptic ─► CONFIRMED/PLAUSIBLE ─┬─► stop-and-ask? (§2.5) ─► user
                                                     └─► branch fix/<ID>-<slug>
        failing test (red) ─► fix ─► gate ─► fix skeptic (7 lenses) ─► FIXED-VERIFIED
        ─► git merge --no-ff (Skeptic-Verified trailer) ─► gate on main ─► defects-log row ─► delete branch
```
ID scheme: `W<wave>-<n>` (e.g. `W2-03`). Ledger of record: [audit-ledger.md](audit-ledger.md) (the running ledger)
→ distilled into the committed `docs/audits/*` at each wave's close. Reports themselves are
committed on branches `audit/<pass>` and merged like fixes.

## 7. Output set (committed, `docs/audits/`)

`audit-findings.md` · `audit-simplify.md` · `audit-dedup.md` · `audit-correctness.md` · `audit-docs.md` ·
`dependency-audit.md` · `security-review.md` · `silent-degradation.md` · `format-compatibility.md` ·
`verification-optimization.md` · `test-ledger.md` · `defects-log.md` · `harness-inventory.md` ·
`benchmark-baselines.md` · `untestable-without-x.md` · `live-targets.md` · `live-integration.md` ·
`gap-audit.md` · `open-items.md`. (`release-v0.1.0.md` is left as written; L4 supersedes it.)

## 8. Known risks to the audit itself

- **[I] Same-agent blindness:** auditors share my model's blind spots → the blind implementer, OpenSSL
  interop and mutation tests exist to give independent routes.
- **Fixer collisions:** several fixes touching `pkg/keystore` / `ringfile` → serialise those; only
  disjoint-file fixes run in parallel worktrees.
- **Skeptic theatre:** a skeptic that only reads. The contract requires it to *run* the mutation
  check and, for crypto, an independent route; an unrun lens is FIXED-UNPROVEN, not verified.
- **Flaky concurrency tests:** every new concurrency/crash test is run `-count=50 -race` before merge.
- **Live tier touching the real keychain:** gated, throwaway service name, confirm first.
- **Runtime cost:** argon2id at 64 MiB makes ring-heavy tests slow; tests may lower `kdf.Default`
  (existing convention), real-cost runs only in waves 2, 5-bench and 7.

## 9. Open decisions for the user (none block waves 0–1)

1. **Plan filename:** `audit-plan.md` (confirmed by the owner; the request had said `addit-plan.md`).
2. **Live keychain write** on this Mac (wave 6) — OK, or skip as untestable-without-X?
3. **`v0.1.0` tag:** keep as-is and let L4 decide `v0.1.1`/retag? (assumed yes.)
4. **A7 in scope?** Included as the pre-ship gate; L4 only is held, per the request.

## 10. Status at close (2026-10-19)
All waves done and merged to main (tip 039ed2f at this note): A1-A7, L1, L2, L3, L3b. L4 not done (held by the owner).
Every merged branch carries a skeptic sign-off in its merge message (one FIXED-UNPROVEN: CI on GitHub never ran). Committed evidence:
docs/audits/ (index in README.md; open-items.md lists what is deliberately open and what L4 must do). Owner decisions accepted:
duplicate-entries rejection (decisions 41), behaviour changes (decisions 42). Plan filename confirmed by the owner: audit-plan.md.
Open for the owner: release version/tag (v0.1.0 predates every fix; never push it), LICENSE, FIFO at ring path, installer hygiene,
real systemd/launchd start, macOS cross-uid, amd64, first GitHub CI run, login-keychain live tier (unexecuted).
