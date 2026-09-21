# T-02: SL010 concurrent-writer evidence

- Status: done (2026-09-21) — implemented and reviewed
- Phase: detector-depth
- Priority: P2
- Type: feature (new detector)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL010 registry entry)
  - `src/sesslint/checks/` (new or existing module — writer-marker
    analysis)
  - `src/sesslint/adapters/claude_code.py` (writer-marker extraction
    into `extra_fields`)
  - `docs/codes/SL010.md`, fixtures + conformance, `tests/`
  - `CHANGELOG.md`

## Goal

Flag session files showing evidence of **multiple writers** — distinct
app-version markers or writer-instance identifiers interleaved in one
stream — the corruption precondition behind the dropped-entry class
(SL101 orphans). A warning that says "this file was written
concurrently" even before a pair breaks.

## Verified Problem / Current Evidence

- claude-code#31328: debug log shows **3 concurrent agent instances**
  (`cc_version` hashes `.7e0`, `.3ae`, `.1a9`) writing one session file;
  the dropped assistant entry left an orphan tool_result that bricked
  resume.
- claude-code#45286: ~1-in-10 sessions with parallel MCP tool calls hit
  non-atomic multi-tool writes; concurrency is the mechanism, not the
  tool count.
- The Claude adapter already recognizes `version`/`agentVersion`/
  `claude_code_version` fields (claude_code.py:827ff) and `isSidechain`
  markers — writer markers exist in the stream; nobody aggregates them.
- Distinct from SL003 (duplicate event ID) and SL106 (cross-branch
  pairing): SL010 fires on *writer identity* mixing, which precedes and
  explains those faults.

## Required Design / Decisions

1. **Writer markers (adapter-normalized).** Adapters expose
   `extra_fields["writer"] = {version: str|None, instance: str|None}`
   where the vendor records it. Claude: `version`/`agentVersion` (+ any
   process/instance discriminator found at impl — pin at fixture time).
   Other adapters populate nothing → zero findings (absence-tolerant).
2. **Firing rule.** Exactly one SL010 per file when ≥2 distinct
   *instance* markers appear interleaved (A→B→A pattern proves
   concurrent writers, not a sequential upgrade). A single ordered
   transition A*→B* (all A records precede all B) = version upgrade
   mid-session → **no finding** (legitimate); document this rule —
   interleaving is the corruption signal, not multiplicity.
   - If only `version` exists (no instance field): interleaved
     A→B→A *versions* still fire (same proof); a clean prefix switch
     does not.
3. **Evidence (content-free).**
   `{distinct_writer_count, transition_count, first_interleave_line,
   writer_hashes: sorted tuple of sha256-8 of each marker string}` —
   marker values hashed (a version string is near-public, but hashing
   keeps the content-free contract uniform and still lets users diff
   two files' writer sets).
4. **Severity `warning`, repairability `none`.** Nothing to repair —
   the finding is forensic context explaining *why* SL101/SL003 fired,
   and a process hint (don't run concurrent instances on one session).
5. **Interaction note.** When SL010 co-fires with SL101/SL102/SL003,
   reports may cross-reference by `first_interleave_line` — optional
   render nicety, not required.

## Ordered Implementation Steps

1. Pin the real marker fields: inspect claude-code's record schema for
   per-record writer identity (version is per-record; instance/process
   id may not exist — if absent, version-interleave still fires).
2. claude_code.py: populate `extra_fields["writer"]` per event.
3. `codes.py` SL010 entry; check module: per-file writer-sequence
   analysis → at most one finding.
4. `docs/codes/SL010.md` + fixtures: interleaved-writers (fires),
   sequential-upgrade (clean), single-writer (clean), missing markers
   (clean).
5. Registry/report/scan/bundle enums + goldens; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Interleaved A→B→A fixture → exactly one SL010 with correct counts.
- Sequential A*→B* fixture → zero findings (documented upgrade rule).
- Non-Claude files → zero findings, zero coverage noise.

## Rollback / Stop Conditions

- If Claude records carry no per-record writer discriminator beyond
  app version, restrict the rule to version-interleave and mark
  instance-interleave unverified in the doc.

## Risks

- Vendor could legitimately interleave versions (rolling upgrade of two
  processes on one file is still the *risk condition* — the warning is
  honest either way).

## Out of Scope

- Writer-process reconciliation, lock detection, real-time concurrency
  control.

## Implementation Notes (2025)

- Marker pinned: Claude records carry application `version` (plus
  `agentVersion`/`appVersion`/`claude_code_version` aliases) but **no
  verified per-process instance discriminator** — `instance` stays None
  and version-interleave is the firing signal (rollback condition hit,
  documented in SL010.md). `schemaVersion` is a format marker and is
  deliberately excluded from writer identity.
- `extra_fields["writer"] = {"version": str, "instance": None}` set on
  every emit path (default event, text, tool-call, tool-result);
  `source["writer_markers"] = True` is the adapter capability flag the
  runner reads from `CheckContext.source_metadata` to skip SL010 with
  `adapter-not-applicable` on adapters that emit no markers.
- Detector: `checks/writers.py`, family `writers`. Sequence deduped per
  (source_line, marker) so multi-event records count once; consecutive
  duplicates collapse; first marker reappearing after a different marker
  fires exactly one WARNING finding at that line.
- Evidence: `distinct_writer_count`, `transition_count`,
  `first_interleave_line`, sorted `writer_hashes` (sha256-8 of
  `v:<version>`/`i:<instance>` marker strings). Keys deliberately NOT in
  `CANONICAL_EVIDENCE_KEYS` — one finding per file makes
  code+line+record_id a sufficient fingerprint; no baseline churn.
- `Repairability.MANUAL` used (enum has no NONE) — forensic warning, no
  repair path; refusal rationale registered.
- Coverage rows pinned to 30 codes across schemas, profiles fixtures,
  SARIF/registry/scan-schema tests, README + codes README.
