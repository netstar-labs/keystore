# Model selection: why Opus and Sonnet, not Fable for everything

*Written for: the repo owner and whoever presents this deck. Labels: [V] re-derived this session
from Claude Code's own model catalog and this repo's transcripts, [R] reported by a source without
independent re-derivation, [I] inferred.*

---

## Answer

**This repo never needed the most capable model, because nothing in it resisted the second-most
capable one.** [V] Claude Code's own model catalog ranks four tiers by capability and cost, and
`keystore` used exactly the two in the middle — Sonnet for well-specified, high-volume work;
Opus for the one open-ended, high-stakes pass. Fable, the tier above Opus, was never invoked,
and the evidence this repo already has (34 real defects found and fixed, mutation-kill rate
63.1%→90.9%, zero defects later traced to a reasoning gap) gives no reason it should have been.

| Model | Catalog description | Default effort | Used on this repo? |
|---|---|---|---|
| Haiku 5.5 | "Fastest for quick answers" | medium | **Never** |
| Sonnet 5.5 | "Most efficient for simpler tasks" | medium | **Yes** — plan, orchestration, packaging |
| Opus 5.5 | "For complex work and everyday tasks" | medium | **Yes** — the adversarial hardening pass |
| Fable 5.1 | "For your toughest challenges" — *"the most capable model and draws down usage much faster than Opus"* | **high** | **Never** |

The ladder is capability **and** cost, in the same direction: each tier up buys more reasoning
depth at a materially higher token cost, and Fable's own in-product notice says so explicitly
about itself, not as a general caution attached to every model.

## What each model actually did here

[V], re-derived from the Claude Code transcripts and `git log` (full cross-check method in
[token-usage.md](token-usage.md)):

- **Sonnet drafted the plan** (no commits — the first commit in the repo's history lands after
  the next model switch) **and later did the rest of the audit work and shipped v0.2.0/v0.2.1,
  in a separate session.** That second session also did almost all of its own delegation: 180
  subagent invocations, 6,802 subagent turns, every one of them Sonnet. [I] That shape — massive
  parallel fan-out of many small, independently-checkable tasks — is exactly what "efficient for
  simpler tasks" is for: once the audit is decomposed into one skeptic-verified finding per
  subagent call (the reasoning harness's own rule 2, "decompose at verification boundaries"),
  each individual call is narrow and well-specified, which is the shape a mid-tier model handles
  reliably and cheaply at volume.
- **Opus executed the plan and then kept going into the hardening wave, in one continuous
  session**, with almost no delegation: 2 subagent files, 35 subagent turns total, across roughly
  23 hours of continuous work. [I] That shape — one long, single-threaded reasoning chain over
  the whole codebase, generating the `fix/W1-*`/`fix/W2-*` list itself rather than executing a
  pre-decomposed one — is the open-ended, high-ambiguity work the account's own reasoning harness
  (rule 3, "find where the risk actually lives") says should get the deeper, more expensive model:
  the one place this repo needed something to *find* problems nobody had named yet, not verify
  problems someone already had.
- **Fable and Haiku never ran** on this repo, in either session, in any subagent. [V] — confirmed
  by scanning every `model` field in both top-level sessions and all 182 subagent transcripts.

## Strengths and weaknesses, for this repo's kind of task

This repo is security-sensitive Go systems code — an encrypted keyring, a signing agent, a wire
format an attacker controls the input to — reviewed by an adversarial audit suite (A1–A7) that is
explicitly designed to be skeptical of its own findings before they become fixes.

| Model | Where it's strong here | Where it's weak here |
|---|---|---|
| **Haiku** | Fast, cheap answers to narrow, low-ambiguity questions (a lookup, a formatting check, confirming a flag's spelling). | [I] Not exercised on this repo, but by its own "fastest for quick answers" positioning, not the tier to trust with "is this crypto input-handling path safe" — the exact failure mode the reasoning harness exists to catch is fluent, confident, wrong answers, and that risk is highest at the cheapest tier. |
| **Sonnet** | Executing a plan someone (or something) already wrote — the 4-phase build from `build-prompt.md`, merging and tagging a release, running many small, independently-verifiable subagent tasks in parallel. Cost-efficient enough to run 180 of them in one session. | Less suited, used alone, to *discovering* an unscoped set of defects across a large surface with no pre-built checklist — the task that has to decide what the checklist even is. |
| **Opus** | Sustained, single-threaded adversarial reasoning over the whole codebase: finding the shape of a problem, not just checking a named one. This is what actually ran, continuously, for the W1/W2 hardening wave. | More expensive per turn than Sonnet for work that doesn't need the extra depth — which is most of a build once the plan exists, which is why it wasn't used for Phase A or Phase C. |
| **Fable** | [R], from its own catalog notice: reserved for problems that resist Opus. | Costs materially more usage than Opus for the same task ("draws down usage much faster than Opus" — the product's own words); this repo's audit found everything it found — including a typed-nil signer bug caught only by mutation testing, not by any review pass — without ever needing it, which is the actual evidence against running it by default. |

## What this doesn't establish

- **Not a benchmark.** No controlled comparison ran Fable or Haiku against the same `keystore`
  tasks Opus and Sonnet actually did. The claim that Opus was "enough" is **inferred** from the
  audit's own outcome (34 real defects found, 63.1%→90.9% mutation-kill rate, nothing later found
  to be a model-capability gap), not from a side-by-side test.
- **Not a universal rule.** This is a Go keyring and signing agent: well-bounded, security-sensitive,
  with an explicit audit protocol already built for exactly this kind of layered review. A
  different repo's risk profile could tip the Sonnet/Opus/Fable balance differently — the reusable
  part of this analysis is the *method* (match reasoning depth to the risk in the task, per the
  account's own harness), not "always use Sonnet then Opus."
