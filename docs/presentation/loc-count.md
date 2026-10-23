# Keystore — size of the code and the documents

*Written for: the repo owner and whoever presents this deck. Counted on `main` at `a8f10d8`
(2026-10-23). Labels: [V] re-derived this session by a second route; [J] a judgment call.*

## Summary

- The production code is **2,711 lines of code** in 12 packages. The unit tests that guard it are **10,133**
  lines in the same packages, **3.7 : 1**. Adding the integration harness and tests, the examples' tests and
  the build test, the ratio is **4.8 : 1**. [V]
- Production code is **16 %** comments by code lines (443 / 2,711); test code is **8 %**. [V]
- The repo holds **5,412 lines of Markdown** in 37 files. The audit folder alone (3,486 lines) is about as
  long as the production code including its comments and blanks (3,443 lines). [V]

## Go code: production, tests and the rest

A *code* line has at least one Go token on it, so a trailing comment does not change the line's class.
A *comment* line has only comment text. *Blank* is empty. Lines inside a raw string count as code.

| Bucket | Files | Code | Comment | Blank | Total | Comment / code |
|---|--:|--:|--:|--:|--:|--:|
| Production (`cmd/`, `pkg/`, `internal/`, no `_test.go`) | 32 | 2,711 | 443 | 289 | 3,443 | 16.3 % |
| Unit tests (`_test.go` in the same trees) | 66 | 10,133 | 854 | 680 | 11,667 | 8.4 % |
| Integration harness and tests (`integration/`) | 14 | 2,577 | 274 | 203 | 3,054 | 10.6 % |
| Examples (`examples/`, non-test) | 2 | 253 | 31 | 19 | 303 | 12.3 % |
| Examples' tests | 8 | 253 | 12 | 27 | 292 | 4.7 % |
| Build-script test (`build/keystore_test.go`) | 1 | 152 | 14 | 10 | 176 | 9.2 % |
| **Go total** | **123** | **16,079** | **1,628** | **1,228** | **18,935** | **10.1 %** |

Shell (11 scripts: `build/keystore`, the examples' `run.sh`, `integration/`, `scripts/`): 522 code, 94
comment, 83 blank, 699 lines. `#` lines count as comments; a shebang counts as code.

### Production against tests, by package

| Package | Production code | Prod. comments | Comments / code | Test code | Test : prod. |
|---|--:|--:|--:|--:|--:|
| `cmd/keystore` | 800 | 53 | 7% | 1,877 | 2.3 : 1 |
| `pkg/agent` | 484 | 98 | 20% | 2,286 | 4.7 : 1 |
| `pkg/keystore` | 482 | 83 | 17% | 1,927 | 4.0 : 1 |
| `internal/ringfile` | 360 | 58 | 16% | 979 | 2.7 : 1 |
| `internal/passphrase` | 141 | 40 | 28% | 596 | 4.2 : 1 |
| `cmd/keystore-agent` | 116 | 20 | 17% | 490 | 4.2 : 1 |
| `internal/term` | 104 | 24 | 23% | 521 | 5.0 : 1 |
| `internal/seal` | 65 | 15 | 23% | 703 | 10.8 : 1 |
| `internal/keychain` | 52 | 20 | 38% | 234 | 4.5 : 1 |
| `internal/kdf` | 51 | 18 | 35% | 357 | 7.0 : 1 |
| `internal/peercred` | 37 | 6 | 16% | 87 | 2.4 : 1 |
| `internal/ids` | 19 | 8 | 42% | 76 | 4.0 : 1 |
| **Total** | **2,711** | **443** | **16%** | **10,133** | **3.7 : 1** |

The two small packages that do the sealing and key derivation (`internal/seal` 10.8 : 1, `internal/kdf`
7.0 : 1) carry the most test per line of production code. The command-line package `cmd/keystore` carries
among the least (2.3 : 1, with `internal/peercred` at 2.4 : 1). Comment density follows size the other way:
it is highest where the code is shortest (`internal/ids` 42 %, `internal/keychain` 38 %) and lowest in the
largest package (`cmd/keystore` 7 %).

## Documents: by location

| Location | Files | Lines | Non-blank |
|---|--:|--:|--:|
| `docs/audits/` | 19 | 3,486 | 3,015 |
| `docs/` (root: guide, specs, overview, reference) | 7 | 773 | 608 |
| `docs/design/` | 4 | 502 | 419 |
| `docs/presentation/` | 3 | 384 | 300 |
| Repo root (`README.md`, `SECURITY.md`, `THIRD-PARTY-NOTICES`) and `examples/README.md` | 4 | 267 | 228 |
| **Total** | **37** | **5,412** | **4,570** |

## Documents: by type

Types are assigned by what each file is (its title and opening lines), not by its folder. [J]

| Type | Files | Lines | Non-blank | What is in it |
|---|--:|--:|--:|---|
| Test and verification | 7 | 1,667 | 1,464 | `mutation-hardening`, `benchmark-baselines`, `topology-integration`, `test-ledger`, `live-integration`, `harness-inventory`, `untestable-without-x` |
| Review | 5 | 661 | 558 | `audit-findings`, `gap-audit`, `silent-degradation`, `format-compatibility`, and the design `review` |
| Plan | 3 | 647 | 540 | `audit-plan`, design `scope`, design `build-prompt` |
| Presentation | 3 | 384 | 300 | the practice deck, `model-selection`, `token-usage` |
| Research | 2 | 356 | 311 | `audit-ledger` (the running candidate ledger), `verification-optimization` (L1 experiments) |
| Release | 2 | 349 | 297 | `release-v0.1.0`, `release-v0.2.0` |
| Guide | 2 | 255 | 208 | `userguide`, `examples/README` |
| Overview | 4 | 235 | 190 | `README`, `architecture`, `introduction`, `executive-summary` |
| Spec (normative) | 2 | 223 | 178 | `format`, `agent-protocol` |
| Index and tracking | 2 | 174 | 147 | audit `README`, `open-items` |
| Reference (generated) | 1 | 171 | 121 | `reference` (generated from the verb table) |
| Policy | 1 | 115 | 105 | `SECURITY` |
| Fix | 1 | 80 | 65 | `defects-log` |
| Decision | 1 | 54 | 52 | design `decisions` |
| Legal | 1 | 41 | 34 | `THIRD-PARTY-NOTICES` |

### Location by type

| Location | Type | Files | Lines |
|---|---|--:|--:|
| `docs/audits/` | Test and verification | 7 | 1,667 |
| | Review | 4 | 576 |
| | Research | 2 | 356 |
| | Release | 2 | 349 |
| | Plan | 1 | 284 |
| | Index and tracking | 2 | 174 |
| | Fix | 1 | 80 |
| `docs/design/` | Plan | 2 | 363 |
| | Review | 1 | 85 |
| | Decision | 1 | 54 |
| `docs/` (root) | Guide | 1 | 233 |
| | Spec (normative) | 2 | 223 |
| | Reference (generated) | 1 | 171 |
| | Overview | 3 | 146 |
| `docs/presentation/` | Presentation | 3 | 384 |
| Repo root | Policy | 1 | 115 |
| | Overview | 1 | 89 |
| | Legal | 1 | 41 |
| | Guide (`examples/README`) | 1 | 22 |

Test and verification write-ups are the largest type (1,667 lines, 31 % of all Markdown). The whole
defects log is 80 lines and the decisions file is 54; the audit's findings are in the review documents (661
lines), not in the log.

## Method and limits

- Go was counted with `go/scanner` (comments kept as tokens), so raw strings and trailing comments classify
  correctly. Each line is code, comment or blank; the three sum to the file's line count.
- Cross-checks [V]: the Go total (18,935) equals `wc -l` over the same 123 files; the Markdown total
  (5,412) equals `wc -l` over the same 37 files; one file was also checked by hand.
- Not counted: `go.sum`, `testdata/` fixtures, `LICENSE`, YAML, the systemd unit and the launchd plist.
  `docs/presentation/` is counted as documents, so this file will add itself to the next count.
- The type column is a judgment [J]. A file that does two jobs is filed under the one in its title:
  `benchmark-baselines` is filed as test and verification although it is also a measurement record.
- The numbers move with every commit. Re-count before quoting them in a new release.
