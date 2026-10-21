# Keystore — model and token usage, v0.1.0 through v0.2.1

*Written for: the repo owner using a Claude Code Max plan. Labels: [V] re-derived this session from the Claude Code transcripts
and `git log`, [R] reported by one source without independent re-derivation, [I] inferred.*

> **Supersedes an earlier version of this file**, which misattributed the v0.1.0 build to Sonnet
> and the post-tag hardening to Opus. That version's time boundaries had a timezone bug (an
> already-UTC timestamp had `+03:00` appended to it a second time, shifting every tag boundary
> 3 hours earlier than the real cutoff — see *The bug in the first version*, below). Corrected
> here: **Sonnet drafted the plan, Opus executed it — in one session — and a second session's
> Sonnet did the rest of the audit work and shipped v0.2.0/v0.2.1.**

---

## Answer

| Phase | Model | Session | Tokens (total) | Output tokens | Assistant turns |
|---|---|---|---:|---:|---:|
| A — Draft the plan | **Sonnet 5.5** (`claude-sonnet-5-5`) | `ba7fb676…` | 5,463,184 | 83,256 | 68 |
| B — Execute the plan (scaffold → v0.1.0 tag → straight into the post-tag hardening wave) | **Opus 5.5** (`claude-opus-5-5`) | `ba7fb676…` (same session, no gap) | 122,812,445 | 717,083 | 414 |
| C — Rest of the audit work, v0.2.0/v0.2.1 shipped | **Sonnet 5.5** (`claude-sonnet-5-5`) | `288e75b9…` (new session) | 626,318,107 | 1,573,771 | 1,181 |

Phase C's own cumulative split: **591,875,937** tokens / 1,128 turns through the `v0.2.0` tag,
rising to **626,318,107** / 1,181 through `v0.2.1` (the patch itself: ~34.4M tokens, ~56K output,
53 turns).

**Total, v0.1.0 → v0.2.1: 754,593,736 tokens, 2,374,110 output tokens, 1,663 assistant turns**,
across two Claude Code sessions and three phases.

[V] Phase A made **zero commits** — the first commit in the repository's history lands 14 minutes
into Phase B, not during Phase A — which is the direct evidence that Phase A was planning and
Phase B was where the plan actually got executed, not a guess from the phase names alone.

## Methodology

- **Phase boundaries** are the `model` field Claude Code logs on every assistant turn, read
  directly from the transcripts — not inferred from topic or git activity. In session `ba7fb676…`
  the model is `claude-sonnet-5-5` from session start (2026-10-18T15:13:29.701Z) until
  2026-10-18T17:50:22.847Z, then `claude-opus-5-5` with no further switch until
  2026-10-19T16:59:52.783Z (when it moves to an unrelated model/task, outside this phase). That
  single switch point is Phase A/B's boundary.
- **The claim that Phase A did no building** is checked against `git log`, not assumed: the
  repository's first commit (`3c9bb1d2`, "chore: scaffold repository skeleton and design docs") is
  timestamped 2026-10-18T18:04:41Z — 14 minutes *after* the Sonnet→Opus switch, and every commit
  through the `v0.1.0` tag (2026-10-18T20:20:15Z) and on through the `fix/W1-*`/`fix/W2-*`
  hardening wave sits inside the Opus window, which runs uninterrupted to 2026-10-19T16:59:52Z —
  well past both the `v0.2.0` tag (2026-10-19T14:49:42Z) and the `v0.2.1` tag
  (2026-10-19T15:31:50Z). Opus's single continuous run spans the whole of v0.1.0's build and a
  large part of what became v0.2.0/v0.2.1.
- **Phase C is a separate Claude Code session** (`288e75b9…`), confirmed to run entirely on
  `claude-sonnet-5-5` (1,356 of 1,356 assistant turns in that session, no exception). It first
  engages `keystore` at 2026-10-18T20:37:26Z — while the Opus session (Phase B) is still active —
  and its own transcript contains the `v0.2.0` and `v0.2.1` tag-commit hashes far more often (8 and
  3 mentions) than the Opus session does (2 and 2, consistent with an incidental `git log` rather
  than authorship). Eight sampled commit hashes from the `fix/W1-*`/`fix/W2-*` branches show the
  opposite pattern — present in the Opus session, absent from this one — which is what separates
  "Opus wrote these fixes" from "Sonnet merged and tagged them" rather than reading that split off
  mention-counts alone.
- **The two sessions overlap in wall-clock time.** Phase C's window (2026-10-18T20:37Z through
  2026-10-19T15:31:50Z) sits entirely inside Phase B's (2026-10-18T17:50Z–2026-10-19T16:59Z), so
  some of "the rest of the audit work" happened concurrently with Opus's continued hardening, not
  strictly after it. Which session produced which commit is established by the hash cross-check
  above, not by which one ran first.
- **Only two Claude Code sessions on this machine ever mention `keystore`** — checked across every
  other local project directory, all of which show zero keystore-related sessions.
- **Token counts** are the `usage` block logged on every assistant turn
  (`input_tokens` + `cache_creation_input_tokens` + `cache_read_input_tokens` + `output_tokens`),
  summed within each phase's bounds and filtered to the stated model.
- **On-topic confidence**: within Phase A, 54.1% of transcript lines contain the literal string
  "keystore" (expected to be low — planning discussion references files and concepts more than the
  repo name); within Phase B, 96.3% do; within Phase C (bounded to the `v0.2.1` tag), 85.2% do. None
  of the three windows shows a plausible alternative task given where it sits: Phase A is the first
  task of a fresh session (first message 15:13:29Z, first "keystore" mention 15:24:10Z); Phase B is
  one continuous model run with no topic change visible in between; Phase C is cross-checked
  against commit hashes above, not mention density alone.

## The bug in the first version

The first version of this file bounded every phase by appending `+03:00` to a timestamp that had
*already* been converted to UTC — e.g. passing `2026-10-18T20:20:15+03:00` when 20:20:15 was
already the correct UTC value for the `v0.1.0` tag (`2026-10-18 23:20:15 +0300` in `git log`'s
output). That string asks for 20:20:15 in a +03:00 zone, which *is* 17:20:15 UTC — three hours
before the real cutoff. The error was the same size and direction on all three tag boundaries, so
every phase in that version was cut off 3 hours early, which is what hid Phase A's Opus work inside
what looked like a separate "post-v0.1.0" window and misattributed the models within it. Caught by
redoing the offset arithmetic in code (`datetime.strptime(...).astimezone(timezone.utc)`) instead
of trusting the hand-built ISO string, and confirmed against the git-log evidence above.

## What this doesn't establish

- **Not a cost figure.** `cache_read_input_tokens` dominates every phase's total (reading an
  already-cached, growing conversation prefix on every turn of a long session) and is billed at a
  small fraction of fresh input; the totals above are token counts as logged, not spend.
- **Not a precise per-task ledger.** Claude Code does not tag usage by milestone; phase bounds are
  reconstructed from the `model` field, tag timestamps, and the commit-hash cross-check above — the
  best available reconstruction, not an exact accounting.
