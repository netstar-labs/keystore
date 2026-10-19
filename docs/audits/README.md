# Audit outputs

The 2026-10 audit and hardening pass over keystore: what was checked, what was found, what was fixed,
what was proven, and what is still open. If you were not in the audit, read [open-items.md](open-items.md)
first, then [audit-findings.md](audit-findings.md).

The audit worked in waves (A1/A2 code review, A3 security lenses with a blind re-implementation and OpenSSL
interop, A4 supply chain, A5 silent degradation, A6 format compatibility, L1 verification, L2 tests and
mutation, L3 live Linux and OpenSSL, L3b real topology, A7 gap audit). A fix was merged only after a
fresh skeptic tried to refute it (the verdict is in each merge commit's message: `git log --merges main`);
the A1 to A4 findings and the A7 gaps were each checked by a skeptic before work started. The A5 and L1
reports are single-auditor reports, and their rows say what was done about them.

| Page | What it holds |
|---|---|
| [open-items.md](open-items.md) | **Start here.** Decisions the owner still has to make (the `v0.1.0` tag), what was not run, the table of things deliberately not fixed with reasons, and what the release step must still do |
| [audit-findings.md](audit-findings.md) | Every finding of A1 to A4: claim, skeptic verdict, outcome, fix merge |
| [defects-log.md](defects-log.md) | Every real defect, how it was found, its fix and its pinning test |
| [gap-audit.md](gap-audit.md) | A7: 21 gaps and 19 more the skeptic found, with status |
| [silent-degradation.md](silent-degradation.md) | A5: 21 ways a guarantee can lapse while the program keeps serving, with what was fixed or documented |
| [verification-optimization.md](verification-optimization.md) | L1: doc-versus-code, dead code, coverage, benchmarks, fuzz, hardening checks |
| [format-compatibility.md](format-compatibility.md) | A6: every encoded artifact, its golden test and the version-skew verdict |
| [test-ledger.md](test-ledger.md) | The tests added, by wave, with counts, coverage, fuzz targets and known-answer vectors |
| [mutation-hardening.md](mutation-hardening.md) | 417 hand-written mutants of the security-critical code; 63.1 % to 90.9 % killed |
| [harness-inventory.md](harness-inventory.md) | The seams, fakes and runners the tests rely on, and how to run them |
| [benchmark-baselines.md](benchmark-baselines.md) | Recorded benchmark numbers and how far to trust them (read its first section) |
| [live-integration.md](live-integration.md) | The Linux container, OpenSSL and keychain tiers |
| [topology-integration.md](topology-integration.md) | Real processes, real filesystem: contention, SIGKILL loops, cross-uid, agent chaos, fleet |
| [untestable-without-x.md](untestable-without-x.md) | What could not be run here, and the exact command for a human to run |
| [audit-plan.md](audit-plan.md) | The audit's plan of record: waves, ground rules, orchestration, per-finding pipeline, status at close |
| [audit-ledger.md](audit-ledger.md) | The running ledger kept during the audit (candidates, skeptic verdicts as reported); the findings page is the cleaned version |
| [release-v0.2.0.md](release-v0.2.0.md) | The prepared (not tagged, not published) release: version rationale, notes with the breaking changes and their migration steps, verification block, build and publish commands, rollback |
| [release-v0.1.0.md](release-v0.1.0.md) | Historical record of the `v0.1.0` tag, with a banner listing its stale places; superseded by the release step |

## Planned outputs not produced as separate pages, and why

The audit plan ([audit-plan.md](audit-plan.md)) listed 19 outputs for this directory.

| Planned name | Why not produced | Where the content is |
|---|---|---|
| `audit-simplify.md`, `audit-dedup.md` | the auditors' considered-and-rejected lists were kept only in the running ledger ([audit-ledger.md](audit-ledger.md), as written during the audit); the skeptic's verdicts are in the findings page | [audit-findings.md](audit-findings.md) wave 1, rows W1-08 to W1-19 |
| `audit-correctness.md`, `audit-docs.md` | same: the verdicts and outcomes are recorded, the raw auditor reports were not kept | [audit-findings.md](audit-findings.md) wave 1, rows W1-01 to W1-11 and W1-D1 to W1-D10 |
| `security-review.md` | the five lens reports and their proof-of-concept programs were session scratch and were not kept; no CRITICAL or HIGH finding came out of them, and each finding's outcome is recorded | [audit-findings.md](audit-findings.md) "Wave 2: A3 security lenses" and the blind-implementer and interop rows |
| `dependency-audit.md` | the A4 supply-chain report (module hygiene, `go mod verify`, licence matrix, `openpgp` reachability) was not kept; only its two CI findings (A4-1, A4-2) survive. What can be stated: `govulncheck` reports 0 affecting and one module-level advisory in an unimported package, per the L1 report and the release record | [audit-findings.md](audit-findings.md) "Wave 1b", decisions 12, 28, 30, 31 |
| `live-targets.md` | a separate catalogue of targets with a known-bad case each was not kept; the tier table at the top of the live-integration page is the nearest equivalent | [live-integration.md](live-integration.md) |

## Conventions

IDs: `W1-nn` are wave-1 findings (auditors A simplify, B dedup, C correctness, D doc drift, written `W1-D1` etc.); `W2-<n>-<m>` are wave-2 findings, `<n>` being the A3 lens (1 format and AEAD, 2 KDF and lifecycle, 3 agent and IPC, 4 ring file, 5 CLI); `W2-B*` the blind implementer; `W2-I*` the interop and Linux run; `S1`-`S5` the finding skeptics; `A4-n` supply chain; `A5 Ln` (L1 to L21) the silent-degradation lapses; `L1`, `L2`, `L3`, `L3b` and `L4` are pipeline passes, not lapse numbers: L1 verification and optimization, L2 tests and mutation, L3 live integration, L3b real topology, **L4 the release step (tag, notes, publish), not done by the audit**; `Gn` is an A7 gap found by the auditor, `Mn` one found by the A7 skeptic, `On` an owner item in [open-items.md](open-items.md). "Wave" headings in [test-ledger.md](test-ledger.md) follow the plan's wave numbers (wave 2 = A3, 3 = A5/A6, 5 = L2, 6 = L3, 7 = L3b, 8 = A7).

Labels used throughout: **verified** (the author ran or read it and saw the result), **reported** (a named
source says it; not re-run), **inferred** (constructed from stated evidence). A "skeptic" is a separate
reviewer, started fresh, whose job was to refute. IDs: `W1-nn`, `W2-<lens>-n` (wave 1 and 2 findings),
`A5 Ln`, `L1`, `A7 Gn` and `Mn`. `decisions` means [design/decisions.md](../design/decisions.md).

The reference documents (`docs/userguide.md`, `docs/format.md`, `docs/agent-protocol.md`, SECURITY.md) are
the contract; these pages are the evidence behind them.
