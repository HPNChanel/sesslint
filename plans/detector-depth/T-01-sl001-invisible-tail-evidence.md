# T-01: SL001 vendor-invisible-tail evidence enrichment

- Status: done (2026-09-21) — implemented and reviewed
- Phase: detector-depth
- Priority: P2
- Type: enhancement (evidence enrichment — no new code)
- Depends on: —
- Primary targets:
  - `src/sesslint/io.py` / `src/sesslint/adapters/claude_code.py`
    (post-malformed-line accounting)
  - `src/sesslint/report.py` (evidence render)
  - `docs/codes/SL001.md`
  - fixtures + goldens, `tests/`
  - `CHANGELOG.md`

## Goal

When SL001 fires on a mid-file malformed record, quantify what the
vendor's stop-at-first-error loader hides: `following_complete_records`
and `following_bytes` added to the finding's evidence. Turns "line 402
is malformed" into "line 402 is malformed — the vendor may stop here
and hide 1,140 further records (11.2 MB)".

## Verified Problem / Current Evidence

- claude-code#50347: silent truncation at first malformed line left
  11 MB invisible — the user believed the session short. SessLint's
  reader already continues past malformed lines (that's why SL001 can
  fire mid-file at all) — it just doesn't report the visible-tail size.
- #24009: picker crashes on binary-embedded records — same "first bad
  line decides what loads" mechanics.
- Evidence is additive-only: `evidence` dict gains two integer fields;
  no schema-version bump needed if additive-permissive (verify against
  report schema rules; else bump per policy).

## Required Design / Decisions

1. **Where counted.** The streaming reader knows the malformed line's
   byte offset; after emitting SL001 it continues parsing anyway —
   count `following_complete_records` (lines that parsed cleanly after
   the malformed one) and `following_bytes` (bytes from malformed-line
   end to EOF, or to EOF minus a torn tail already claimed by SL002).
   Both integers; computed during the existing single pass.
2. **Multiple malformed lines.** Enrich only the *first* SL001 per file
   with tail counts ("vendor stops at the first"); subsequent SL001s
   get `following_*` omitted to avoid double-counting — document.
3. **Content-free.** Integers only; no line content, no ids.
4. **Wording.** Human render: `… malformed record at line 402
   (1,140 further records / 11.2 MB may be invisible to vendor
   loaders)`. "may be" — vendor loader behavior is version-dependent;
   never assert it as fact.
5. **Boundary cases.** Malformed-on-last-line → both counts 0 → omit
   fields. File that is *all* malformed → SL001 fires once at line 1
   with zero-tail counts omitted.

## Ordered Implementation Steps

1. io.py/adapter: carry a per-file `tail_after_first_malformed` counter
   through the parse loop; attach to the first SL001's evidence.
2. report renderers: human wording + JSON evidence passthrough
   (evidence dicts already pass through — verify).
3. docs/codes/SL001.md: evidence field table + vendor-behavior caveat.
4. Fixtures: malformed-mid-file golden with pinned counts; malformed-
   last-line control; multi-malformed control.
5. CHANGELOG Added (evidence enrichment).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "sl001 or malformed"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Golden fixture asserts exact `following_complete_records` /
  `following_bytes` values on the first SL001 only.
- No SL001 on a clean file; no evidence keys when counts are 0.
- Byte counts are exact integers across LF/CRLF and multibyte content.

## Rollback / Stop Conditions

- If counting requires buffering beyond the current stream contract,
  attach only `following_bytes` (computable from file size − offset —
  no buffering) and defer record counts.

## Risks

- Overstating vendor behavior → "may be invisible" wording and a docs
  note that loader behavior varies by vendor version.

## Out of Scope

- Per-vendor loader emulation, resumability verdicts, repair changes.

## Implementation Notes (2026-09-21)

- **Mechanism**: `MalformedTailTracker` in `io.py` — shared by the
  yield-style canonical generator (`iter_events`) and the list-style
  vendor line processors. `note_item`/`note_produced` observe produced
  items in stream order; `finalize(total_bytes, torn_tail_offset)`
  enriches the *first* SL001's evidence dict in place at EOF. Finding
  stays frozen — only the already-attached mutable evidence Mapping
  gains the two integer keys, so stream order, fingerprints
  (`following_*` is not in `CANONICAL_EVIDENCE_KEYS`), and wire shape
  are unchanged.
- **Deviation from plan targets**: tracker also wired into
  `codex_rollout.py` and `openai_agents.py` — identical machinery, same
  vendor semantics; leaving them unenriched would have made behavior
  adapter-dependent for no benefit.
- **`canonical.py` single-doc parser intentionally untouched** — its
  SL001s are document-level (no per-line malformed/tail semantics).
- **Why post-yield evidence mutation**: `iter_events` yields the SL001
  in document order and tests pin that interleaved position
  (`test_sl001_sl002`). Deferring the yield to EOF would break the
  documented stream-order contract; all real consumers materialize the
  stream before inspecting evidence.
- **Omit rule**: keys attached only when
  `following_records > 0 or following_bytes > 0` — malformed-followed-
  only-by-torn-tail yields a zero tail and stays unenriched.
- Fixture: `fixtures/claude_code/malformed-mid.jsonl` (existing dir
  PROVENANCE covers it); canonical counts pinned on the pre-existing
  `fixtures/sessions/malformed-line.jsonl`.
- Tests: `tests/test_sl001_tail.py` (16 tests: pinned counts both
  formats, boundary omission, first-only, torn exclusion, CRLF/multibyte
  byte exactness, codex/openai smoke, render suffix, determinism).
