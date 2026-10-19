# Gap audit (A7)

A pre-ship audit: where does "done" hide a gap? The yardstick was every promise the repository makes
(scope.md verbs, the seven security properties, platforms and examples; every sentence in the
README and `docs/`; SECURITY.md; decisions 1-42; the "Not run" list of the v0.1.0 record; the A5 and L1
reports), looked at in seven places: promised, wired, verified, documented, operable, handed on, closed.

The audit ran on `main` at `fe6e121` (149 commits after the `v0.1.0` tag; 162 on today's `main`) on
macOS arm64 with Apple `container` (alpine and debian arm64), go1.27.2, on 2026-10-19. An independent
skeptic then re-ran every finding and looked for gaps the auditor missed.

Labels: **[V]** the auditor or skeptic ran or inspected it and saw the result; **[R]** a repository
document reports it, not re-run; **[I]** inferred. The auditor and skeptic reports were not committed;
this page is their final form. Items marked "this branch" are made by the branch that adds this page
(`docs/A7-closing-deliverables`); the others are separate merges on `main`.

## Bottom line

- 21 findings from the auditor (G1-G21). The skeptic returned **17 CONFIRMED, 3 PLAUSIBLE (G11, G19,
  G21), 1 DELIBERATE-agree (G14), 0 refuted outright**, but six confirmed findings carried a wrong or
  overstated sub-claim (G1, G2, G5, G7, G15, G19) and it disagreed on five severities (G5 down, G6 down,
  G11 down, G15 up, G19 down).
- The skeptic found **19 gaps the auditor missed (M1-M19)**; none HIGH.
- Auditor severities: 1 HIGH (G1), 4 MODERATE (G2, G3, G6, G11), 11 LOW, 5 INFO.
- **The one real product risk was G1**: the one tag, pushed as it stood, would have shipped a 0644
  private-key leak, an expiry-disabling negative TTL and `verify` exit 1 for a bad signature. It is a
  release-gate item, not a code defect, and it is still open ([open-items.md](open-items.md) O1).
- Every promise in scope.md that could be run held, apart from two: the durability half of property 3
  (no test can see a dropped `fsync`: G6) and "v0.1.0" itself (G1).
- Gate on `main` at the time, run by both: gofmt, `go vet` on linux and darwin, staticcheck (also with
  `-tags integration` and `-tags topology`), `deadcode -test`, `go mod tidy -diff`, govulncheck,
  `go test -race`, `TestReference`, all six `examples/*/run.sh` [V: auditor and skeptic]. Each run used
  `-skip TestGetMissing`; that test was later deleted (G15).

## Findings G1-G21

Severity is auditor -> skeptic. "Status" is what happened afterwards.

| ID | Place | Finding | Sev | Skeptic verdict | Status |
|---|---|---|---|---|---|
| G1 | handed on | The only tag predates every audit fix; `go install ...@latest` and `--release` resolve to it. Skeptic built the tag and reproduced the 0644 export, the non-expiring negative TTL and verify exit 1. Auditor's "v0.2.0 collision" and "`retract`" advice were corrected. | HIGH -> HIGH | CONFIRMED | **Open, owner** (O1, O2) |
| G2 | closed | Audit evidence not in the repository: plan lists 19 outputs, 4 existed (auditor said 8: it counted three files that are not on the plan's list). | MOD -> MOD | CONFIRMED (count wrong) | **Closed, this branch**: the outputs listed in [README.md](README.md) |
| G3 | documented | userguide Files row still said a shell `>` redirect "gets the umask's mode" for `export-*`; behaviour is the opposite. | MOD -> MOD | CONFIRMED | **Closed, this branch**: `docs/W1-sync-after-fixes` merged and its two false sentences fixed |
| G4 | documented | `term.Clean` doc and the branch sentence said invalid UTF-8 becomes a space; it becomes U+FFFD (printable, so kept). | LOW | CONFIRMED [V: `od`] | Comment: merge `0632c47`; userguide: this branch |
| G5 | verified, undocumented | `keystore version`, `-version`, `--version` in no doc; a `go install` binary prints `keystore dev (none)`. **Half refuted:** `keystore-agent -h` does list `-version`. | LOW -> INFO | CONFIRMED for the CLI | **Closed, this branch**: README sentence |
| G6 | wired, not verified | Property 3's durability half has no test: mutants M106, M119, M121 (ringfile) and M338 (`writeNew`) survive; `topology-integration.md` already said a missing `fsync` is undetectable; `untestable-without-x.md` did not. | MOD -> LOW | CONFIRMED | **Documented, this branch**: untestable row and scope property 3 reworded. A `var syncFile` seam would prove the call, not durability: skipped |
| G7 | built, not wired | `ringfile.go` trailing-data branch is unreachable (the peek `json.Unmarshal` rejects trailing bytes first). Skeptic: 10.0 M-exec differential fuzz, 0 divergences; and the branch is the only thing keeping the trailing-data test green if the peek is ever simplified. Auditor proposed deleting it. | LOW | CONFIRMED unreachable; recommendation contested | **Kept, commented, this branch** |
| G8 | wired, not verified | CI fuzzed 2 of 10 targets; the tagged tiers were never vetted in CI. | LOW | CONFIRMED | Fixed: merge `1d06882` (decision 44). **Unproven on a hosted runner** |
| G9 | documented, stale | `untestable-without-x.md` last row said wave 7 was "not yet built"; **also** `live-integration.md:12` (the auditor missed it). | LOW | CONFIRMED (+1 place) | **Closed, this branch** |
| G10 | hygiene | Public audit text carried a local scratch path and named a private internal document (benchmark-baselines, format-compatibility x2). | LOW | CONFIRMED | **Closed, this branch** (three lines reworded) |
| G11 | documented, not operable | The systemd unit's sandbox lines in a `--user` unit may need user namespaces; never started under real systemd. `systemd-analyze verify` passes [V]. | MOD -> LOW | PLAUSIBLE ([I]: not reproduced) | **Documented, this branch**: agent-service README |
| G12 | documented | A failed stdout write after the ring commits exits 1 with the ring changed (Alpine `/dev/full`). Skeptic extension: a closed pipe kills the process with SIGPIPE, shell status **141**, in no exit table. | LOW | CONFIRMED + extension | **Documented, this branch**: userguide Exit status [V: 141 reproduced] |
| G13 | documented | `KEYSTORE_PASSPHRASE=` (empty) counts as unset, silently. | INFO | CONFIRMED | **Documented, this branch** |
| G14 | wired, not verified | SIGINT inherited-ignored is overridden by `Notify`; a signal between `Listen` and `Notify` takes the default action. | INFO | DELIBERATE-agree | Won't fix (self-healing) |
| G15 | wired, not verified | `TestGetMissing` ran the real `/usr/bin/security` in the default macOS suite. Auditor: "keep, it is the only check of the exit-code mapping". Skeptic: premise wrong, `Get` maps **every** exec error to `ErrNotFound`, so it asserts nothing. | INFO -> LOW | CONFIRMED as fact, premise wrong | Deleted: merge `1d06882` (decision 29) |
| G16 | documented | `examples/secrets` README said `run.sh` shows a world-readable passfile and a modified entry; it shows a wrong passphrase and a missing secret (the other two are in `main_test.go`). | LOW | CONFIRMED | **Closed, this branch** |
| G17 | wired, not verified | `examples/agent-service/run.sh` prints "well-formed" but the systemd branch ends in an unconditional `true`; only CI's step can fail. | INFO | CONFIRMED | **Closed, this branch**: the step is retitled "informational; CI gates the systemd check" |
| G18 | documented, not operable | README Layout omitted `integration/` and `scripts/`; no page said how to run the opt-in tiers or linked the audits. | LOW | CONFIRMED | **Closed, this branch** |
| G19 | handed on | No inventory row for keystore in the owner's internal project inventory, which is generated from GitHub; only the description and doc-index entry are manual. | LOW -> INFO | PLAUSIBLE | **Open, owner** (O6) |
| G20 | closed, hygiene | At the A7 audit, 33 merged branches and 14 `worktree-agent-*` branches remained (re-count before deleting). | INFO | CONFIRMED | **Open, owner** (O7) |
| G21 | verified (platform) | amd64 is promised and never executed. Skeptic adds: darwin/amd64 is not executed even in CI. | LOW | PLAUSIBLE | Won't fix; first CI run ([open-items.md](open-items.md) section 2) |

## Missed gaps M1-M19 (found by the skeptic)

| ID | Sev | Gap | Status |
|---|---|---|---|
| M1 | LOW | The agent's "socket was removed or replaced" log line printed the operator-supplied path unsanitised (ESC and CR raw), against decision 42 and the doc sentence G3 wanted merged. | Fixed at the log sink: merge `0632c47`. [V while writing this page: an agent in a directory named with ESC and CR, socket removed: the log contains no ESC or CR byte.] |
| M2 | LOW-MOD | "Keychain degrades with a clear message elsewhere" had no test; `keychain_other.go` was never executed or mutated. | Fixed: merge `1d06882` (red against a `nil, nil` mutant in a container) |
| M3 | LOW | `keystore-agent -h` printed an error line and exited 1; the userguide says `-h` is 0. | Fixed: merge `bc08d87` [V: rc 0, usage only; an unknown flag still exits 1] |
| M4 | LOW | The agent's defaults (`-ttl 8h`, `-idle 30m`) were documented only in `-h`. | **Closed, this branch**: agent-protocol "Lifetime", userguide |
| M5 | LOW/INFO | A FIFO at the ring path hangs the CLI forever. | **Open, owner** (O4) |
| M6 | LOW | `--release` stamped `git describe` without `-dirty` while the binary embeds `vcs.modified=true`. | Fixed: merge `8a90392` (decision 43) |
| M7 | LOW | The archive had README and SECURITY.md but not `docs/`, so the README's relative links were dead. | README sentence: merge `8a90392` |
| M8 | LOW | The generated installer does `rm -rf install` relative to the caller's directory. | **Open, owner** (O5); not executed [R] |
| M9 | INFO | architecture.md's dependency diagram omitted `cmd/keystore-agent -> internal/term` | **Closed, this branch** [V: `go list` imports] |
| M10 | INFO | A symlinked `-passfile` fails with the cryptic "too many levels of symbolic links". | **Documented, this branch** [V: reproduced] |
| M11 | INFO | The auditor's not-open row "pipes and `>>` unchecked" is wrong for `>>`: it is refused onto a loose file. | **Corrected in [open-items.md](open-items.md)** [V: rc 1, file unchanged] |
| M12 | INFO | scope.md's example acceptance was broader than what the six examples do. | **Closed, this branch**: wording aligned with the run scripts |
| M13 | INFO (L4) | No LICENSE file. | **Open, owner** (O3) |
| M14 | INFO | `reference.md` had no exit-status information; `verify` exit 3 was only in the userguide. | Fixed: merge `07c6d65` |
| M15 | INFO | Doubled prefix `keystore-agent: keystore agent:` | Won't fix (cosmetic) |
| M16 | LOW | `release-v0.1.0.md` stale in four places beyond G1. | Banner added, this branch; the supersession is **open** (O2) |
| M17 | INFO | CI correctness unproven (`go-version-file` against `go 1.27.0` plus `toolchain go1.27.2`; CI never ran). | **Open**; first CI run |
| M18 | INFO | Ledger W1-07 said "fix", final state is "documented, not fixed" (a failed `keygen` leaves an empty ring); the reason was only in the local ledger. | Recorded in [open-items.md](open-items.md) |
| M19 | INFO | Lock-file 0600 under umask 0277 and typed-nil Signer are covered only by the green suite in the auditor's closed table. | none |

## Closed since v0.1.0 (behaviour changes on `main`, re-checked by the auditor)

All [V by the auditor] unless marked; the source of each is a merge in [audit-findings.md](audit-findings.md).

| Item | Evidence |
|---|---|
| Negative `-ttl`/`-idle` refused (W1-01) | "ttl and idle must not be negative (0 means no limit)", rc 1, before the passphrase is read |
| Redirected export refusal (W2-5-4, decision 42) | `export-secret > f` and `export-priv > f` refused under umask 022; `-o` writes 0600; an existing `-o` file refused; a pipe allowed; a 0-byte stub remains (the shell made it) |
| `verify` exit 3 (W2-5-3) | bad signature rc 3; unreadable signature rc 1; missing `-pub` rc 2 |
| Passfile shadowing (W2-2-2, decision 40) | unlock prints "KEYSTORE_PASSPHRASE is set, so -passfile is ignored"; establishing is refused and leaves an empty ring |
| `sign` names its key; `-expect-fp` (W1-D1, decision 39) | stderr "signing with SHA256:..."; a wrong pin refused, also through the agent |
| No home, no ring path: exit 2 (A5-L4) | `env -i keystore list/keygen/init` rc 2 naming the cause; `verify` unaffected; `sign -agent` is exempt [V while writing this page: rc 1 from the failed dial, not 2] |
| SIGHUP stops the agent; an inherited ignore is respected | "hangup; stopping", rc 0, socket removed [V while writing this page] |
| Socket lost: exit 1 (A5-L2) | exit 1 after 9 s, log "removed or replaced" [V while writing this page: 8 s] |
| Duplicate `entries` key rejected (L1, decision 41) | `entries` twice, and case-variant `ENTRIES`, are "not a keystore file" |
| Typed-nil Signer (L2) | [R] doc diff of the exported surface plus tests in the suite |
| Control-character sanitiser (W2-5-2) | ESC and CR replaced by spaces; an invalid byte shown as U+FFFD |
| PEM errors name what was found (W2-I2) | `found a "PUBLIC KEY" PEM block, expected "PRIVATE KEY"`; an encrypted key gets the `openssl pkey` hint |
| Lock files 0600 (W2-4-3) | `ag.ks.lock` and `agent.sock.lock` are `-rw-------`; the umask 0277 case is in the suite only [R] |
| Agent socket path length | 103 bytes accepted, 104 refused on macOS, naming the limit |
| CI systemd step can fail; read-only token (A4-1, A4-2) | read; the same check passes in a container; CI itself never ran |
| `docs/reference.md` current | `TestReference` passes |

## "Not run" list from the v0.1.0 record

See [open-items.md](open-items.md) section 2 for the current status of each item.

## What the gate misses (the rule this pass produced)

A fix series that ends at "gate green" leaves three artifacts no gate reads: the tag that the install
instructions resolve to, the prose beside the code that changed (a table row, a stale "not yet built"),
and the reports that justify what was not fixed. Before closing a hardening wave, diff three things
against `main`, not against the tag: what `@latest` resolves to; every sentence the changed behaviours
touch (grep the old behaviour's words); and whether each "deliberately not" has a committed line with a
reason.

Checked and holding, no finding (auditor, by direct run): scope properties 1, 2, 4-7 and the
`format.md` read rules (empty ring valid; `v2`/`v02` "newer", `v01` not; BOM, trailing data, unknown
field and duplicate entries rejected; 16 MiB exact accepted and +1 rejected; a `current` naming nothing
rejected); library API names against scope.md; decisions 18, 19, 23, 24 and 35 where runnable.

## Coverage and disclosures

Swept: all seven places over every yardstick row; release hygiene; every Markdown document, example
and script, the CI workflow and build script, the L1 and A5 reports and the local ledger, the unmerged
sync branch, the git log since the tag. Run from the docs with a temporary `HOME`: keygen, list, sign,
verify, secrets, export guards, import, passwd, rotation, passfile modes and caps, size limits, exit
codes, the default ring path, the agent line with `-ttl 8h -idle 30m`, a second agent, SIGHUP, `nohup`,
socket loss, the socket path limit, `build/keystore` and `--release`, the examples, a keygen prompt on a
pty. **Not run, and why:** `keychain-set` and `KEYSTORE_KEYCHAIN` on macOS (it would touch the login
keychain); `go install ...@latest` (no remote); a real systemd or launchd start; macOS cross-user; the
interop and container tiers in full (reported only, `TestCrossUID` re-run); mutation and benchmarks
(reported); amd64 execution; Linux `-race`; the generated installer (needs root).

Auditor disclosures: a first gate run was killed after it had started `go test ./...` without `-skip`,
so `TestGetMissing` (a read-only `security find-generic-password` for a non-existent service) may have
run once [I]; a mistyped `cd` made four commands run in the home directory and created four small files
there, which were deleted at once; a temporary symlink and a Python virtual environment were created and
removed; one `passwd` timing of 277 s wall for 1.7 s of CPU was attributed to the machine sleeping [I].
