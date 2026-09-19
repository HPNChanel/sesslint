# T-05: SL304 mid-file schema drift

- Status: done (implemented 2026-09-19)
- Phase: checks
- Priority: P2
- Type: feature (new detector; parse-layer)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL304)
  - `src/sesslint/adapters/detect.py` or a drift pass in `checks/`
  - `docs/codes/SL304.md`
  - `fixtures/` + conformance rows + `tests/`
  - `CHANGELOG.md`

## Goal

Flag files whose record schema changes mid-stream — envelope `type`
values or version markers that shift partway through, indicating format
migration during one session (vendor upgrade mid-conversation) or a
spliced file.

## Verified Problem / Current Evidence

- Vendors ship updates continuously; a session spanning an upgrade can
  legitimately mix `version:"2.0.30"` and `version:"2.1.0"` records — or
  illegitimately mix two different export formats if a tool appended to
  the wrong file.
- SL301/SL302 check version/format at detection level (first-markers);
  drift *within* the stream is unchecked.

## Required Design / Decisions

1. Per-adapter shape signature: the set of observed envelope `type`
   values + version field values is collected during parse (adapters
   already read these). Drift = a version field change beyond the
   adapter's known-compatible set, OR a second distinct format signature
   appearing after the first.
2. Severity `warning` (legitimate upgrades exist), repairability `manual`.
3. Evidence: `{record_index, drift_kind: version|signature,
   previous_marker, observed_marker}` — markers are bounded
   discriminators via `safe_discriminator`, never payloads.
4. Compatible-version transitions (same adapter's supported set, e.g.
   Claude 2.0→2.1) do NOT fire — only transitions crossing the adapter's
   own supported-version predicate or carrying foreign-format signature.
5. Cost: O(1) extra state per record during existing parse — no second
   pass.
6. Must not double-report with SL301: if the file's overall version is
   already unsupported, SL301 fires once at detection and SL304 suppresses
   itself (documented precedence).

## Ordered Implementation Steps

1. Adapter parse layer: track version/signature transitions into bounded
   evidence (first-marker record index + transition list capped at 8).
2. `codes.py` SL304 + finding emission.
3. `docs/codes/SL304.md` + fixtures (clean upgrade, foreign-format
   splice, unsupported-version control, multi-transition capped).
4. Tests: detection + check/scan consistency + precedence vs SL301 +
   determinism.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- A file switching envelope signature at record N yields one SL304 with
  correct markers/index; same-adapter-compatible version bumps stay
  clean; SL301 precedence verified on unsupported files.

## Rollback / Stop Conditions

- Stop if version-transition tracking cannot distinguish
  compatible-vs-foreign transitions per adapter — restrict to
  signature-drift only.

## Risks

- Vendor legitimately mixes record `type`s → drift fires on *format
  signature* and *version marker* transitions, never on ordinary type-set
  variation (envelope types are already heterogeneous by design).

## Out of Scope

- Per-key schema-diff (too noisy); migrat­ion assistance (repair domain).

## Implementation Notes (2026-09-19)

- New `src/sesslint/adapters/drift.py`: `DriftTracker` (per-file parse
  state) + `FOREIGN_SIGNATURE_TYPES` (envelope `type` → format label for
  types discriminative of exactly one format). Transitions dedupe by
  (kind, previous, observed), cap at 8, buffered until flush so an SL301
  anywhere in the file suppresses all SL304 output (precedence rule 6).
- `version` kind: only schema-marker fields are observed — Claude
  `schemaVersion`; Codex `rollout_version`/`format_version`/
  `schema_version`/`export_version`/`version` (envelope+payload); OpenAI
  `sdk_version`/`export_version`/`agent_sdk_version`/`version`. Claude
  app-release fields (`version`/`agentVersion`/`appVersion`/
  `claude_code_version`) never observed → "2.0.30→2.1.0" stays clean.
  Baseline = first supported marker; chain semantics on change.
- `signature` kind: fires only when `type` is discriminative for a
  different format — shared vocabulary (`user`, `assistant`, `message`,
  `compaction`, `tool_result`…) never fires; unknown types stay SL302
  territory. Wired in all four adapters; canonical events (which use
  `kind`, not `type`) observe the `type` key so foreign records surface.
- Evidence: `drift_kind`, `previous_marker`, `observed_marker`,
  `observed_format` (signature), `field`, `record_index`, byte coords —
  all through `safe_discriminator`; keys added to
  `CANONICAL_EVIDENCE_KEYS` so distinct transitions never share a
  fingerprint.
- Registry now 25 codes. Schemas ×3, profile snapshots, refusal
  rationale, golden bundle regen (parse-layer codes are absent from
  `performed` by design), coverage matrix + MATRIX.md, README tables,
  CHANGELOG.

## Verification (2026-09-19)

- `uv run pytest -q` — full suite green.
- `ruff check` / `ruff format --check` / `mypy --strict` — clean.
- `bench/perf_250k.py` — PASS: 11.638s / 15.0s, 477.3 MB / 512 MB.
- `scripts/check_release_refs.py` — OK. No CRLF artifacts.
- Fixture results: foreign splice → 1 signature SL304; schemaVersion
  1→0.1 → 1 version SL304; app bump → clean; unsupported → SL301 only;
  9 transitions → exactly 8 findings (cap).
