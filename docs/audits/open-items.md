# Open items

What the 2026-10 audit left open, what it decided not to fix and why, and what the owner (and the
release step, "L4") still has to decide or do. Read this first if you were not in the audit.

Labels: **[V]** verified by running or reading it while writing this page; **[R]** reported by a
named audit document (the source is in the row; not re-run here); **[I]** inferred, with the basis
stated. Sources: [gap-audit.md](gap-audit.md) (audit A7 and its skeptic), [silent-degradation.md](silent-degradation.md)
(A5), [verification-optimization.md](verification-optimization.md) (L1), [audit-findings.md](audit-findings.md)
(A1-A4), [decisions](../design/decisions.md).

## 1. Needs an owner decision

None of these is a code defect. The only HIGH finding left open is the first row (W1-D1 was HIGH as worded and is resolved: see [audit-findings.md](audit-findings.md)).

| # | Item | State | What the decision is |
|---|---|---|---|
| O1 | **The `v0.1.0` tag does not contain the audited code** (A7 G1, HIGH) | The local annotated tag points at `ee25732`; `main` is 162 commits ahead [V: `git rev-list --count v0.1.0..main`]. There is no remote, so the tag was never pushed or fetched by a proxy [V: `git remote -v` empty]. The A7 skeptic built the tag and reproduced three behaviours the audit later fixed: `export-priv > f` under umask 022 writes a 0644 key file, `keystore-agent -ttl -2s` never expires, `verify` of a bad signature exits 1 not 3 [R: gap-audit.md]. `build/keystore --release` on `main` stamps `v0.1.0-<n>-g<sha>` [R: gap-audit.md]. | Either **(a)** `git tag -d v0.1.0` and tag the final commit `v0.1.0` (decision 38 wants one tag; cheapest, valid only because nothing was ever published), or **(b)** a new version. The A7 auditor's worry that (b) collides with the roadmap's "v0.2.0 = hardening" row is conditional, not real: scope.md's "breaking changes are a minor" rule applies to a published version, and the roadmap row itself says v0.1.0 includes "adversarial review and its fixes" [R: gap-audit.md]. `retract v0.1.0` in `go.mod` is not an option for an unpublished version (a retract lives in a later version's `go.mod`) [R: gap-audit.md]. **Do not push the current tag.** |
| O2 | **`release-v0.1.0.md` step 2 cannot be followed** (A7 M16) | Step 2 says `git tag -a v0.1.0 <sha> -m ...`; that fails with "tag already exists" against the stale local tag [V by reading step 2 and `git tag` showing `v0.1.0`]. The file now carries a banner listing its four stale places; the history below the banner is untouched. | Superseded: the release notes are drafted in [release-v0.2.0.md](release-v0.2.0.md) (prepared, not tagged or published). Publishing is still the owner's step. |
| O3 | **LICENSE** (A7 M13) | No `LICENSE` file; README states no license; the SBOM says `PackageLicenseConcluded: NOASSERTION` for the project [R: gap-audit.md]; the release script copies a `LICENSE` if present. scope.md open question 2 and decision 2 accepted Apache-2.0 "at public". | Done when the repository went public (see the publish log in [release-v0.2.0.md](release-v0.2.0.md); decisions row 48): `LICENSE` is Apache-2.0, "Copyright 2026 NetSTAR Global, Inc.", the README names it, and the SBOM declares it. |
| O4 | **A FIFO at the ring path hangs the CLI forever** (A7 M5; ledger W2-4-6) | `mkfifo ring.fifo; keystore list -keystore ring.fifo` was still running after 3 s and was killed [R: gap-audit.md]. The same case for `-passfile` was fixed (commit `b258e75`), so treatment is inconsistent. Not in SECURITY.md or the userguide. | Either document it (a ring writer can already deny service by deleting the file) or add the 4-line regular-file `Lstat` guard the ledger estimated. Whoever can create the FIFO can already replace the ring, so the added risk is small [I]. |
| O5 | **Installer hygiene** (A7 M8) | The installer that `build/keystore` generates does `rm -rf "$INSTALL"` with `INSTALL=install` relative to the caller's directory, and `mkdir -p /usr/local/bin/version` makes a directory under `bin/` [R: gap-audit.md M8, from reading `build/keystore`; **not executed**: it needs root]. | Extract into a `mktemp -d` directory; keep the version history under `/usr/local/share/doc/keystore`. Untouched on purpose (the A7 build fix says so). |
| O6 | **Internal inventory row** (A7 G19) | The owner's internal project inventory does not mention keystore; it is generated from GitHub with a weekly drift check, so the row appears when the repository exists; only the curated description and a doc-index entry are manual [R: gap-audit.md]. No repository imports keystore [R: gap-audit.md]. | Add the description and doc-index entry at publish time. |
| O7 | **Delete the merged branches** (A7 G20) | At the A7 audit 33 merged branches and 14 `worktree-agent-*` branches remained; all were ancestors of `main` [R: gap-audit.md]. Re-counted while writing this page: 43 lines in `git branch --merged main` (including `main`), 18 of them `worktree-agent-*` [V]; re-count before deleting. `docs/W1-sync-after-fixes` was the one unmerged branch; it is merged by the branch that adds this page. | `git branch -d` them after pruning worktrees (a repository write, left to the owner). |
| O8 | **The owner-accepted behaviour changes** (decision 42) | Recorded as accepted. They are the list a release note must carry as breaking (section 4). | Nothing to decide; listed so the notes are complete. |
| O9 | **`go install ...@v0.2.0` prints `keystore dev (none)`** (found while verifying the published tag) | The version is stamped only by `build/keystore` through `-ldflags`; a binary from `go install` has no stamp, although Go records the module version in its build info (`debug.ReadBuildInfo`). Harmless to behaviour. | Fall back to `debug.ReadBuildInfo().Main.Version` (and `vcs.revision`) when the ldflags are unset: about six lines in `cmd/keystore` and `cmd/keystore-agent`, with a test. Not done: found after the tag. |

## 2. Not run, and what it needs

These were the "Not run" list of `release-v0.1.0.md`, plus what the audit added. "Closed" means a run
is on record; where the run is not in this repository's text the row says so.

| Item | Status | Evidence | Command or need |
|---|---|---|---|
| Linux runtime (peercred, the six examples) | closed | [R] [live-integration.md](live-integration.md): alpine and debian arm64, root and uid 1000, all test binaries rc=0 | `integration/run.sh` (needs Apple `container`) |
| Real cross-uid agent rejection | closed on Linux; **open on macOS** | [R] [topology-integration.md](topology-integration.md) `TestCrossUID`: peer uid 1001 and uid 0 refused by the peer-uid check, not by file mode; A7 re-ran it in a container [R: gap-audit.md]. macOS `LOCAL_PEERCRED` across users was never run. | row "A second real uid on macOS" in [untestable-without-x.md](untestable-without-x.md) |
| `systemd-analyze verify` | closed statically; **real start open** | [R] a7: systemd 257 (debian trixie container), `--user` and system mode, rc 0 and no output; `systemd-analyze security --offline` scored 7.4 MEDIUM. **This run is not otherwise recorded in the repository.** Never started under a real init. | `systemd-analyze verify` then `systemctl --user start` on a real host |
| launchd start | **open** | `plutil -lint` runs in `examples/agent-service/run.sh` on macOS; nothing was loaded [R: untestable-without-x.md] | `launchctl bootstrap gui/$(id -u) FILE` under a throwaway label |
| SPDX validator | closed (not in the repo) | [R] a7: spdx-tools 0.8.3 accepted the generated `keystore.spdx` and rejected a deliberately broken file. **Not recorded anywhere else.** | `pyspdxtools -i keystore.spdx` after `build/keystore --release` |
| OpenSSL 3 interop | closed | [R] [live-integration.md](live-integration.md) (OpenSSL 3.5.7 and 3.5.9), byte-for-byte checks in [format-compatibility.md](format-compatibility.md) | `KEYSTORE_LIVE=1 go test -tags integration ./integration/interop/` |
| **linux/amd64 and darwin/amd64 execution** | **open** | Everything ran on arm64. `go vet` for linux and darwin on amd64 and the four-target release build succeed [R: gap-audit.md]. `macos-latest` is arm64 [I], so darwin/amd64 is never executed even in CI; `ubuntu-latest` is amd64 and will be the first amd64 run [I: from the runner names, not checked]. | the first CI run; note darwin/amd64 as unverified in the release notes |
| Linux `-race` | **open** | the Linux tier is built without cgo [R: untestable-without-x.md] | `go test -race -count=1 ./...` on a Linux host (the CI `ci` job does this) |
| macOS keychain (real `/usr/bin/security`) | **open** | the live test is written, double-gated and never executed; the default suite no longer runs the real `security` (decision 29; A7 G15) | first row of [untestable-without-x.md](untestable-without-x.md) |
| `fsync` and power-loss durability | **open, untestable by kill** | [untestable-without-x.md](untestable-without-x.md) | same file |
| **CI on a hosted runner** | **proven for the four jobs, see the publish log** | The repository now has a private remote. Before the first run the workflow had been read and its steps reproduced locally (staticcheck v0.8.2, the deadcode filter, gofmt, tidy, the systemd step in a container, `actionlint` clean [R: merge 1d06882]) but whether `setup-go` honours `go 1.27.0` plus `toolchain go1.27.2` from `go.mod` on a hosted runner is **inferred** [R: gap-audit.md]. The new `fuzz-all` job and the tagged vet step (decision 44) are likewise unproven on a runner. | done: the first run failed (`deadcode` on ubuntu also reports the darwin-only `checkService`), fixed in the next commit; the second run was green for all four jobs (`ci`, `ci-macos`, `fuzz`, `fuzz-all`). |
| Reproducible release archives | **false by design** | binaries are byte-identical for a clean checkout; the archives embed timestamps and differ run to run [R: gap-audit.md; README says so] | none |

## 3. Deliberately not open: decided, with the reason and where it is stated

The corrected table from the A7 skeptic. Corrections to the A7 auditor's table are
marked.

| Item | Why it was left | Where it is said |
|---|---|---|
| A5 L1: `-ttl`/`-idle` use monotonic timers that may not advance during suspend | stated limit; a wall-clock check was not asked for; not tested by suspending a machine [R: A5] | SECURITY.md "Known limits" [V: line 88] |
| A5 L3: a running agent outlives `rm`/`passwd` of its key | documented; restart the agent | userguide agent paragraph [V], SECURITY "Revocation" [V], agent-service README [V] |
| A5 L5: expiry exits 0, so `Restart=on-failure` does not restart | documented; both units use `-ttl 0 -idle 0` | agent-service README [V] |
| A5 L6: restart loops | the units now rate-limit (`StartLimitBurst`, `ThrottleInterval`) | `keystore-agent.service`, `local.keystore-agent.plist` [V] |
| A5 L7: directory fsync fails after the rename; command exits 1 but the ring changed | reports failure, never false success (safe direction); not re-run by A7 [R: A5 simulation] | [gap-audit.md](gap-audit.md) G12; userguide "Exit status" now covers the stdout case, not this one [V] |
| A5 L8 and A7 G12: a failed stdout write after the ring committed exits 1, or is killed by SIGPIPE (141) on a closed pipe | documented here for the first time | userguide "Exit status" [V: 141 reproduced] |
| A5 L9: stale `.<ring>.*.tmp` after a hard kill | documented; deleting files in a user's directory is worse | SECURITY "Revocation" [V] |
| A5 L10: lock timeout text does not name the lock file | loud failure, nothing lost | [silent-degradation.md](silent-degradation.md) |
| A5 L11 and ledger W1-07: `keygen` leaves an empty ring when the passphrase step fails | same state `init` leaves; "run it again". The ledger first said "fix (resolve the passphrase before creating)"; the final state is "documented, not fixed" (A7 M18) | userguide Passphrases [V] |
| A5 L12: `passwd` aborts on one corrupt entry without naming it | loud, no partial state | [silent-degradation.md](silent-degradation.md) |
| A5 L13: any `security` failure is reported as "no keychain item" | documented; no stderr surfaced | SECURITY "Known limits" [V] |
| A5 L14 and A7 G13: empty `KEYSTORE_PASSPHRASE=`/`KEYSTORE_KEYCHAIN=` count as unset | stated now | userguide Passphrases [V] |
| A5 L15: the ring's directory is never checked | SECURITY says keep it private; `add` in a 0777 directory succeeds silently [R: gap-audit.md] | SECURITY "Where the ring lives" [V] |
| A5 L16/L17: `Server.Log` is nil by default | field comment says "if set"; the CLI sets it | `pkg/agent/server.go:51` [V] |
| A5 L18: EMFILE log line every 50 ms | no stated guarantee | [silent-degradation.md](silent-degradation.md) |
| A5 L19: pipes are unchecked by the redirect guard | documented. **Correction (A7 M11):** the auditor wrote "pipes and `>>` unchecked"; `>>` onto a loose regular file **is** refused [V: `export-priv >> f` on a 0644 file, rc 1, file unchanged] | SECURITY, userguide "Exporting private keys" [V] |
| A5 L20: KDF cost is not shown | latent: one default cost exists | [silent-degradation.md](silent-degradation.md) |
| A5 L21: `restore()` ignores the `ioctl` error | interactive only; unchanged (`term.go`) | [silent-degradation.md](silent-degradation.md) |
| **W2-4-6 (added by the skeptic, A7 M5): FIFO at the ring path** | see O4 above | not documented yet |
| **W1-07 (added by the skeptic, A7 M18): keygen empty ring** | see L11 row | userguide [V] |
| Unauthenticated `current`, entry order, entry set, rollback, ring identity | costed; no v2 (`ring_id` 30-50 lines, MAC 150-250 lines); `sign` names its key and takes `-expect-fp` | decision 39, format.md, SECURITY |
| `-idle` is reset by any successful request, `P` included | documented | userguide, agent-protocol |
| A7 G14: SIGINT inherited-ignored is overridden; a signal between `Listen` and `Notify` takes the default action | self-healing: the next start removes the stale socket [I]; SIGHUP inherited-ignored is respected | userguide agent paragraph [V] |
| A7 G7: unreachable trailing-data branch in `Parse` | kept as the only guard if the peek is simplified; now commented | `internal/ringfile/ringfile.go` [V]; differential fuzz 10.0 M execs, 0 divergences [R: gap-audit.md] |
| A7 G15: `TestGetMissing` | **deleted** (it asserted nothing: `Get` maps every failure to `ErrNotFound`) | decision 29 |
| A7 G21: amd64 never executed | the first CI run verifies linux/amd64 | section 2 |
| A7 M15: `keystore-agent: keystore agent:` doubled prefix | cosmetic | none |
| A7 M17: CI correctness unproven | first CI run | section 2 |
| A7 M7: release archives carry README and SECURITY but not `docs/` | one README sentence says so; copying two docs would leave the other links dead | README Install, decision 43 |
| Client peer-uid check needs a second uid | covered in a container by `TestCrossUID` and `linuxlive`, which are run by hand, not by `go test ./...` or CI | [topology-integration.md](topology-integration.md) |
| Benchmarks were recorded on a loaded host; no regression gate | the document says re-record before gating | [benchmark-baselines.md](benchmark-baselines.md) |
| `Keystore.Path` is reported by plain `deadcode` | public API; the CI filter excludes it | `ci.yml`, release record |
| 15 equivalent, 12 unobservable, 10 seam-bound and 1 root-only (the passfile owner check; it passes as root in a Linux container) of the 38 surviving mutants of 417 | each with its reason | [mutation-hardening.md](mutation-hardening.md) |
| Parse and agent allocation amplifications | fixed (W2-4-1, L1 dup entries, L1 readFrame); residual worst case about 8.6x the file for a valid 16 MiB ring | [defects-log.md](defects-log.md) |

## 4. What L4 must still do (not done here)

1. Decide the version first (O1). **Prepared:** `v0.2.0`, with the reasoning in [release-v0.2.0.md](release-v0.2.0.md); not tagged.
2. (Drafted in [release-v0.2.0.md](release-v0.2.0.md).) Write release notes that supersede `release-v0.1.0.md` (O2), grouped fixes, additions and **breaking**,
   with the decision-42 migration steps: a redirected export into a file others can read is refused;
   `verify` exits 3; a shadowed passfile is announced or refused; no home directory and no ring path exits
   2; negative `-ttl`/`-idle` refused; a nil `Signer` on the library's error paths; an empty library
   passphrase refused; the agent stops on SIGHUP and on a lost socket. Add the one new exported symbol,
   `agent.ErrNegativeLifetime` [R: gap-audit.md, `go doc -all` v0.1.0 against `main`].
3. Re-run the gate, `go vet -tags integration,topology ./...`, the private-name screen (a screen of tracked
   files for local scratch paths, private project names and personal names, run while writing this page,
   found only the owner handle in `CODEOWNERS` and `GOPRIVATE: github.com/netstar-labs` in `ci.yml` [V];
   commit messages were not re-screened here), `build/keystore --release` and an SPDX validation.
4. (Done at going public: `LICENSE` added and the SBOM refreshed, O3.)
5. Create the GitHub repository, enable private vulnerability reporting (SECURITY.md names it), set topics
   and description, add the inventory row (O6), push, and let CI go green for the first time (section 2).
6. Verify `go install github.com/netstar-labs/keystore/cmd/keystore@<tag>` from a clean environment and that
   `keystore version` is stamped (a `go install` build reports `dev (none)`).

**Not done by the audit:** tagging, release notes, SBOM refresh, pushing, repository metadata, deleting
branches, any real systemd or launchd start, the macOS cross-uid run, an amd64 run.
