# T-02: SL303 duplicate JSON keys in one record

- Status: done (2026-09-19)
- Phase: checks
- Priority: P1
- Type: feature (new detector; parse-layer)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL303)
  - `src/sesslint/io.py` / adapter parse layer (`object_pairs_hook`)
  - `docs/codes/SL303.md`
  - `fixtures/` + conformance rows + `tests/`
  - `CHANGELOG.md`

## Goal

Detect records containing duplicated JSON object keys — a spec-legal
ambiguity where parsers disagree (stdlib `json` keeps the last value;
other parsers may keep first, reject, or merge). For an integrity
checker, silent parser-disagreement is a first-class finding.

## Verified Problem / Current Evidence

- RFC 8259 permits but does not define duplicate-name handling; vendors
  and loaders genuinely diverge. A record `{"id":"a","id":"b"}` parses to
  `id=b` in Python but may mean `a` to a vendor loader — exactly the
  class of invisible divergence SessLint exists to catch.
- Current pipeline uses default `json.loads` — duplicates are silently
  collapsed with no record of occurrence.

## Required Design / Decisions

1. Detection at parse time: `json.loads(..., object_pairs_hook=...)` on
   the record-decoding path only (bounded, already-parse-needed input —
   not a second pass). Collect duplicate key paths (`$.a.b[0].id` style,
   bounded depth).
2. Severity `error` for duplicates on **critical keys** (the adapter's
   CRITICAL_KEYS set: id/parent/type/pairing fields — those change
   semantics), `warning` for duplicates elsewhere. Repairability
   `manual`.
3. Evidence (content-free): `{record_index, key_path, occurrence_count,
   critical: bool}` — key *paths* are schema positions, not values; never
   emit the duplicated values.
4. Cost bound: pairs-hook adds O(keys) per record; cap collected
   duplicates per record (e.g. 16) — count beyond cap reported as
   `truncated: true`.
5. Coverage integration: emitted as adapter/detection-stage finding —
   must respect `--select`/`--ignore` gating (Wave A2 path) and appear in
   coverage when deselected.

## Ordered Implementation Steps

1. `io.py`/load layer: pairs-hook wrapper collecting duplicate evidence;
   ensure all adapter entry points route through it.
2. `codes.py` SL303 + finding emission (critical vs non-critical split).
3. `docs/codes/SL303.md` + fixtures (critical-key dup, non-critical dup,
   deep-nested dup, cap-overflow dup).
4. Tests: parse-level unit tests; check/scan consistency; select/ignore
   gating; byte-determinism.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/io/ tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `{"id":"a","id":"b",...}` yields one SL303 error naming `$.id`;
  `{"note":1,"note":2}` on a non-critical key yields a warning; nested
  duplicates report full key paths; cap overflow marks `truncated`.

## Rollback / Stop Conditions

- Stop if pairs-hook breaks any existing parse performance contract —
  measure on perf_250k; a slowdown >5% requires a compiled-path
  alternative or gating behind a flag.

## Risks

- Perf: hook runs per-object → measure on the 250k bench; mitigation is
  limiting hook install to the record level (not nested loads) if cost
  shows.
- Some vendors legitimately emit dup keys → warning-only for
  non-critical keeps noise proportional.

## Out of Scope

- Choosing which value wins (that's a repair question — stays manual);
  YAML/other format duplicates.

## Implementation Notes (2026-09-19)

- `io.decode_json_dupaware` wraps `json.loads` with an
  `object_pairs_hook` tracking (path, count) per object position;
  last-wins semantics preserved exactly. `io.dup_key_findings` emits one
  SL303 per duplicated path, severity `error` iff the key is in the
  adapter's `CRITICAL_KEYS`, capped at 16 paths per record with
  `truncated: true` in evidence.
- Wired at every record-decode site: `canonical.py` (streaming events,
  streaming header, single-doc `$.events[i]` paths), `claude_code.py`,
  `codex_rollout.py`, `openai_agents.py`, plus repair-side
  `iter_events`/`read_header`/`load_session_source_with_findings` via
  `critical_keys`/`dup_sink` params. Honors `--select`/`--ignore`
  through the existing adapter-findings `enabled_rules` filter.
- `key_path`/`occurrence_count`/`critical` added to
  `CANONICAL_EVIDENCE_KEYS` — without them distinct paths collapsed to
  one fingerprint and dedup ate the findings.
- Refusal rationale in `repair/refusals.py` ("Conservative policy MUST
  refuse" — picking the winning occurrence invents record semantics).
- Evidence is positions/counts only; duplicated values never surface
  (asserted by `test_no_payload_values_in_evidence`).
- Registry now 22 codes; `docs/codes/README.md`, `README.md` tables
  (SL008 + SL303 rows), coverage matrix + MATRIX.md, all three schemas,
  profile snapshots, and CHANGELOG updated.
- Tests: `tests/io/test_dup_keys.py` (19 tests: decode-level, fixtures,
  single-doc paths, cap/truncation, strictness parity, select/ignore
  gating, check↔scan consistency, determinism, vendor path, privacy).
- Gates: ruff/format/mypy clean; full suite green;
  `bench/perf_250k.py` PASS — fresh-process check 14.384s vs 15.0s
  budget, peak RSS 476 MB vs 512 MB. Pairs-hook cost is measurable but
  inside the contract; no gating needed.
