# How I Use Claude Code
*A repeatable, audited engineering pipeline — not a chat window.*

Prepared by zxdev · Go engineering across NetSTAR Labs · Living practice, in daily use

---

## 1 · Five Things, One Pipeline
*Overview*

1. The reasoning harness — one standing operating manual, every session
2. The least-code agent — climb the ladder before a line gets written
3. The design ladder — interview → roadmap → scope → scaffold, before code
4. Build, harden, ship — L1–L4, bookended by the A1–A7 audit suite
5. **In practice** — one evening, scaffold to a public release *(case study)*

> All figures and quotes below are drawn from this account's own handbook
> (github.com/netstar-labs) and the keystore repository's own git history.

---

## 2 · The Reasoning Harness
*1 · Standing operating manual*

A **harness** is a standing operating manual, loaded into context before any work starts — it
changes how a conclusion is reached, not what the task is. This one is derived from failure, not
from principle: each of its eight stages is named for one specific, recurring way fluent output
goes wrong, built backward from the mistake toward the check that would have caught it.

1. Read the request underneath the request
2. Decompose at verification boundaries
3. Find where the risk actually lives
4. **Verify by re-derivation, not recognition** — *run it, don't recall it*
5. Label known versus guessed, at the claim
6. Attack your conclusion before it ships
7. Answer, then reasoning, then risk
8. The mistakes that look like competence

> **In practice:** before trusting an argon2id derivation this session, it was checked against
> `x/crypto`'s own `IDKey` call directly and a recorded hash was pinned — not recalled from
> memory, run.

Source: `handbook/prompts/claude-code-reasoning.md` — copied verbatim into every new Go repo's
`.claude/CLAUDE.md` by the scaffold step.

---

## 3 · The Least-Code Agent
*2 · A standing discipline*

Climb from the top, stop at the first rung that answers. No rung is passed silently — every
file, symbol or dependency in a diff names the rung that let it past.

| Rung | What it means | Where it showed up this week |
|---|---|---|
| **2 · Reuse** | Already in a codebase this account owns? | Reused an earlier keyring's AAD framing and atomic-write design. |
| **3 · Stdlib** | Standard library does it? | No KDF needed: AES-GCM, Ed25519, HMAC, SHA-256 sufficed. |
| **4 · Platform feature** | The OS, filesystem or init system already guarantees it. | Atomic write via `os.Rename`; ships as a systemd/launchd unit. |
| **5 · Installed dependency** | A labeled, costed proposal — never a silent `go.mod` edit. | `x/crypto/argon2` for the one gap stdlib can't fill: a memory-hard KDF. |
| **6 · One line** | The whole behavior is one condition — no registry, no mapper type. | One `switch` case covers the position-0 rule, not a new type. |
| **7 · Minimum that works** | No extension points; correct at nil, empty, zero, hostile input. | All 34 real-defect fixes cite this ladder in their own audit record. |

> **Rung 1 has no row here, on purpose** — a skipped feature, a YAGNI, leaves no caller, no file, nothing
> to point to, so its wins are invisible by construction. And the artifact is always the
> sentence, not the intent: "I considered reuse" doesn't count, naming the disqualifier does.

Source: `handbook/agents/least-code.md`.

---

## 4 · Prompt, Skill, Agent, Workflow
*2 · The vocabulary*

Four related words that mean four different things — what runs, how it is triggered, and who
decides to run it.

- **Prompt** — a markdown file, run once by request: the house A1–A7, L1–L4 and D0–D3 templates.
  Instructions for one pass, not a standing behavior.
- **Skill** — a prompt packaged to trigger itself: a SKILL.md Claude invokes on its own
  description match, or that is called by name as `/name`.
- **Agent** — one delegated subagent, dispatched on my own judgement for a single independent
  task. One call, one report back.
- **Workflow** — a scripted pipeline of many agents: parallel fan-out, phases, verification
  stages. Runs only with the user's explicit opt-in.

> A prompt becomes a skill when it needs to trigger itself, unasked. A skill — or a plain
> request — can then delegate to one agent, or to a whole workflow of them.

Source: `handbook/prompts/README.md` (the prompt set) and `prompt-to-skill.md`; this session's
own Agent and Workflow tool definitions.

---

## 5 · The Design Ladder
*3 · Before any code*

Funnel: **roadmap → scope → scaffold → build.** The interview develops the first two with
Claude, one question at a time, before either is written down.

0. **Interview** — Socratic elicitation: a reviewed draft, not a first guess.
1. **Roadmap** — the plan across an area: base, gaps, phased order. Commissions issues.
2. **Scope** — one buildable unit: capability, boundary, API, tests. A `type:scope` issue.
3. **Scaffold** — house skeleton: module, layout, `.github`, the ci/pr-issue-link gates.

> Same shape, two live examples this week: a from-scratch keystore module, and a Phase-A
> keystore design document under review on an upstream k3sm pull request.

Source: `handbook/prompts/D0-interview.md`, `D1-roadmap.md`, `D2-scope.md`, `D3-scaffold.md`.

---

## 6 · Build, Harden, Ship
*4 · After the scaffold*

One lifecycle, run in order, every release — bookended by the audit suite up front and again,
diff-scoped, as the pre-flight gate.

- **L1 — Refine.** Verify against docs, kill debt, run the existing suite, optimize with
  measured gains.
- **L2 — Fortify.** The exhaustive hermetic test / fuzz / bench / harden suite. Fix root causes.
- **L3 — Validate live.** Real third-party systems outward; real multi-node, real `SIGKILL`
  inward (L3b).
- **L4 — Ship.** Semver tag, reproducible build, SBOM, publish-and-verify.

> **On keystore:** L2 raised the mutation-kill rate from 63.1% to 90.9% across 417 injected
> mutants; L3/L3b added live Linux/OpenSSL interop and a real multi-process topology tier —
> contention, `SIGKILL` loops, cross-uid, a fleet run.

Source: `handbook/prompts/L1–L4`; `github.com/netstar-labs/keystore` git log, merge commits
`test/L2-mutation-hardening` and `test/L3b-topology`.

---

## 7 · The Audit Suite: A1–A7
*4 · Bookending the lifecycle*

Report-only review passes. Each finding is verified by a skeptic before it becomes a fix —
**CONFIRMED, PLAUSIBLE, or REFUTED,** never just "found."

| Pass | What it checks |
|---|---|
| **A1** adversarial audit | The driver — four dimensions, a skeptic per candidate, apply + re-validate |
| **A2** codebase audit | Simplify · dedup · correctness+perf · doc-drift — the candidates A1 verifies |
| **A3** security threat model | Assets → boundaries → STRIDE-lite → crypto / input / secrets |
| **A4** dependency supply chain | `go mod` hygiene, govulncheck reachability, license matrix |
| **A5** silent degradation | Every stated guarantee — where it quietly lapses, could an operator even tell |
| **A6** format compatibility | Every encoded artifact, pinned with golden bytes against version skew |
| **A7** gap audit | Promised-not-built, built-not-wired, unverified, undocumented — a numbered yardstick |

> **On keystore:** the first code-review wave and the security-lens wave between them found a
> negative `-ttl` that silently disabled agent expiry, a key file exported at the umask's mode
> instead of 0600, and a verify exit code indistinguishable from "could not check" — 3 of 34 real
> defects the pipeline found after the pre-tag review had already closed.

---

## 8 · One Evening to v0.1.0
*5 · In practice, part one*

A real keystore module, built end to end in a single session — the design ladder and the
reasoning harness, not a demo of either.

- **2h16m** — scaffold to tagged v0.1.0
- **4** — build phases, 23 commits
- **4** — real bugs fixed before tagging

> **An independent adversarial-review pass** — commissioned before tagging, not after —
> reproduced four defects with a failing test apiece: an agent-lifetime bypass that kept a key
> alive past its TTL, a crafted date field that bricked the ring on its next write, a symlinked
> path that silently stopped receiving writes, and a startup race that could orphan a second
> agent still holding the key. Each was fixed, then re-verified under `-race`.

Source: `github.com/netstar-labs/keystore`, tag `v0.1.0` (2026-10-18 23:20, kept local — never
pushed, per the account's own "don't ship an unaudited tag" rule).

---

## 9 · The Pipeline Kept Going
*5 · In practice, part two*

Nobody sat watching every step. New session, different model as independant revierer. The next day, the same repo had been through the full
audit-and-harden cycle and was live, public, and licensed.

- **194** — commits, v0.1.0 to v0.2.0
- **17h42m** — first fix to tagged v0.2.0
- **34** — real defects found and fixed

> One orchestrating session ran all eight audit waves (A1–A7, L1–L3b) through the Agent tool —
> parallel auditors, a fresh skeptic for every confirmed fix, nothing merged without one. 417
> hand-written mutants raised the kill rate 63.1% → 90.9%; real `SIGKILL` loops and cross-uid
> tests found no production defect. One bug — a typed-nil signer on an error path — was caught
> only by mutation testing, no review ever saw it. **None of the 34 was a break of the
> cryptography.**

Source: the repo's own `docs/audits/` (`audit-plan.md` §4 Orchestration, `defects-log.md`,
`mutation-hardening.md`) and its git log; v0.2.0 tagged 2026-10-19 17:49, public the same day.

---

## 10 · Why This Is the Standard
*Summary*

1. One reasoning harness, loaded before every session — not re-invented per repo
2. The ladder runs before the code — every dependency is a named, costed decision
3. Design is written down before it is built — interview, roadmap, scope, scaffold
4. **Layered review catches what a single pass misses — every time, provably** *(the point)*

| What the pipeline cost | What it bought |
|---|---|
| A second, independent review before tagging | 4 real bugs never reached the tag |
| A full audit suite after tagging | 34 more real defects caught before the public release |
