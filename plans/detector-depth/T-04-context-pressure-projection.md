# T-04: Context-pressure projection (decision task)

- Status: done (2026-09-21)
- Phase: detector-depth
- Priority: P3
- Type: decision/research + conditional feature
- Depends on: SL204 (done)
- Primary targets:
  - `src/sesslint/checks/accounting.py` (marker source)
  - decision output: new code SL207 **or** stats/report surface
  - `docs/codes/` or `docs/` accordingly
  - `tests/`, `CHANGELOG.md`

## Goal

Decide whether SessLint can honestly warn that a session is
approaching the context-deadlock state — too large to continue AND too
large to compact — and if so, ship the minimal deterministic surface.

## Verified Problem / Current Evidence

- contextspectre `docs/deadlock.md`: the context meter under-reports
  true API usage (system prompt + tool defs + framework ≈ 40-60K
  tokens beyond conversation); a session at "75%" can already exceed
  the requestable window → compaction itself gets rejected → terminal
  deadlock. Their remedy is amputation; prevention is knowing the
  margin before the boundary.
- claude-code#18720 (codex equivalent), #29890, #75759: auto-compact
  fires at high fill and loses task intent — the *risk window* is the
  useful signal.
- SL204 already normalizes `extra_fields["usage"]` slots
  (`contribution`/`cumulative` counters) from vendor records — the raw
  material for a projection exists without reading content.

## Required Design / Decisions

1. **Decision gate first.** Answer in impl notes before any code:
   (a) do enough records carry usage markers for a per-file projection
   (coverage question — use the maintainer's local corpus, never
   committed)? (b) are documented window sizes per profile stable
   enough to pin as profile constants? If either fails → ship the
   stats-surface variant (option C) and stop.
2. **Option A — SL207 `context-pressure`** (only if gate passes):
   - From the *last cumulative marker*: `headroom = window_limit -
     last_cumulative_total`; warn under a documented threshold
     (e.g. <15% or <fixed token margin) — counters are integers,
     comparison is deterministic.
   - Evidence: `{last_marker_line, cumulative_total, window_limit,
     headroom, threshold_source}` — integers + the profile constant's
     id, never estimated values.
   - Fires only where markers exist (absence-tolerant); the profile
     carries a versioned `window_limit` constant or the check stays
     silent — no hardcoded magic.
   - Severity `warning`, repairability `manual`, remediation text:
     "compact/checkpoint now; continued growth risks un-compactable
     deadlock".
3. **Option B — extend SL204 evidence** with a `pressure` sub-field on
   accounting findings (only when SL204 already fires — narrower but
   hides the signal behind an unrelated finding; weaker).
4. **Option C — stats/doctor surface**: `sesslint stats` reports
   `last_usage_total` + `window_limit` + `headroom` per file (numbers,
   no verdict) — zero claim risk, least useful for prevention.
5. Whatever ships: **no byte-size→token estimation** — bytes-per-token
   varies by content; an estimate would be guessing, violating the
   honest-verdict rule.

## Ordered Implementation Steps

1. Corpus check (local only): fraction of real files carrying usage
   markers; distribution of marker cadence. Record numbers in impl
   notes.
2. Pin profile constants: documented context windows per profile id —
   as versioned data in `profiles/` (wrong constants are worse than
   none; every constant cites its source in a comment).
3. Implement chosen option; fixtures: marker-near-limit → fires;
   marker-absent → silent + coverage note; profile-without-constant →
   silent.
4. Docs + enums + goldens; CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Impl notes record the gate outcome (coverage % + constant sources).
- If SL207 ships: near-limit fixture fires once with integer evidence;
  absent-marker fixture silent.
- If option C ships instead: stats output carries the three integers
  with no verdict wording.

## Rollback / Stop Conditions

- Marker coverage < ~half the corpus → option C only.
- Any ambiguity about which counter maps to "context window" → stop;
  wrong counter = false confidence.

## Risks

- Vendors change window sizes per model/plan → constants are per-
  profile, versioned, cited; drift is a docs problem, not a code bug.

## Out of Scope

- Token estimation, cost projection, quota tracking (observability —
  non-goal 9), live context metering.

## Implementation Notes (2026-09-21)

**Decision gate — both questions answered with the maintainer's local
corpus (799 rollout files, numbers only, corpus never committed):**

(a) *Marker coverage* — `event_msg/token_count` records present in
797/799 files (99.7%); `token_usage_record` envelopes in 484/799
(60.6%). Far above the ~half stop threshold → projection is viable.

(b) *Window source* — better than profile constants: every file's
`token_count` payload declares `info.model_context_window` (799/799;
observed values 258400, 121600 — varies per model/plan, which is why
pinning constants would have been wrong: 5 distinct model names in one
user's corpus). The window is self-declared on disk; SL207 reads it
from the same marker, so no profile table is needed at all.

**Counter disambiguation (stop-condition check)** — real values:
`total_token_usage.total_tokens` and `thread_token_usage` reach
3700-39000% of the window — cumulative *billing* totals, not occupancy.
`last_token_usage.input_tokens` is the per-request input footprint
(12.9%-94.1% of window in corpus — the correct counter; one real file
sat at 94.1%). Wrong counter = false confidence → only
`last_token_usage.input_tokens` + `model_context_window` are used.

**Shipped: Option A — SL207 `context-pressure`** (accounting family,
codex-rollout scoped, `adapter-not-applicable` elsewhere).
Threshold: `headroom * 20 < window * 3` (headroom < 15%, integer-only).
Evidence: `context_tokens`, `window_limit`, `headroom`,
`threshold_source` (`declared-window:15pct-headroom`),
`last_marker_line`. Spec deviation: the plan's `cumulative_total` field
is named `context_tokens` — the honest counter is the last request's
input footprint, not a cumulative counter (the cumulative counters are
billing totals; naming it "cumulative" would document the wrong
semantics).

Adapter: `event_msg/token_count` now surfaces
`extra_fields["codex"]["context_pressure"] = {occupancy, window}` —
isolated from SL204's `usage` slot (484 files carry both marker types;
merging them would double-count contributions).

Files: `src/sesslint/checks/context_pressure.py`,
`src/sesslint/adapters/codex_rollout.py`, `src/sesslint/checks/runner.py`,
`src/sesslint/codes.py`, `src/sesslint/repair/refusals.py`,
`src/sesslint/profiles/builtin.py`, 4 profile fixtures, 3 schemas,
`tests/checks/test_context_pressure.py` (22 tests), 4 codex fixtures,
`docs/codes/SL207.md`, README table + coverage example corrected to
real `claude-code-jsonl` detection output, CHANGELOG, bundle golden.
