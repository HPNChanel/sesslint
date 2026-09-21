# T-03: `bundle` pre-share advisory + SessionEnd hook recipe

- Status: done (2026-09-21) — implemented and reviewed
- Phase: transcript-hygiene
- Priority: P2
- Type: feature (integration)
- Depends on: T-01 (SL009), plans/agent-hooks/T-01 (hook subcommand)
- Primary targets:
  - `src/sesslint/bundle.py` (advisory block)
  - `src/sesslint/hooks.py` (SessionEnd recipe via `sesslint hook`)
  - `schemas/sesslint.bundle.v1.json` (additive field)
  - `docs/INTEGRATIONS.md`, `docs/codes/SL009.md`
  - `tests/`, `CHANGELOG.md`

## Goal

Two outbound edges where persisted secrets propagate beyond the local
disk — (a) `sesslint bundle` artifacts shared to vendor issue trackers,
(b) the moment a session ends — get a content-free advisory and an
opt-in hook recipe.

## Verified Problem / Current Evidence

- The bundle is the wedge (STRATEGY §1.4): users attach it to vendor
  issues. If the *source* session contains a live secret, the bundle is
  clean (it carries no content) but the user's underlying file remains
  exposed — and the user may also paste raw transcripts alongside the
  bundle. A pre-share advisory catches both.
- #63593's remediation path required hooks + gitleaks + history rewrite;
  a `SessionEnd` recipe turns "30 days of accumulation" (#50014) into a
  per-session check at the exact moment the file stops growing.
- Claude Code `SessionEnd` hooks receive `transcript_path` in the stdin
  payload (documented) — with agent-hooks/T-01's `sesslint hook`
  resolver, the recipe needs no path substitution.

## Required Design / Decisions

1. **Bundle advisory (additive, deterministic).** When the bundled
   source file produced ≥1 SL009 finding, `bundle` output gains:
   ```json
   "share_advisory": {
     "kind": "secret-material-present",
     "finding_count": 3,
     "families": ["github-pat-classic", "aws-access-key"],
     "note": "source artifact contains secret-shaped material; rotate
              before sharing the source file or raw transcript excerpts"
   }
   ```
   - Families + counts only. No hashes needed here (bundle is about the
     *file*, not per-match verification — hashes live in the report).
   - Advisory presence must NOT fail the bundle command (exit code
     unchanged); it is a warning block, not a gate. A `--strict-share`
     opt-in flag that exits non-zero is allowed (additive).
   - Schema `sesslint.bundle/v1` gains the field additively; version
     bump per schema policy if required (check T-09 schema rules).
2. **SessionEnd hook recipe.** New `init-hooks` snippet:
   `SessionEnd` → `sesslint hook --event SessionEnd` which resolves
   `transcript_path` from stdin and runs `check --select SL009`.
   - Non-blocking by design (`|| true` documented): a session must never
     fail to *end* because a lint warned. The recipe prints a human line
     the user sees on exit.
   - Emitted only in the claude agent doc; codex still has no hook
     surface (see agent-hooks/T-03 research task).
3. **Wording discipline.** Advisory text says "secret-shaped material",
   never "credentials leaked" — detection is shape-based; remediation
   wording points to `docs/codes/SL009.md`.

## Ordered Implementation Steps

1. `bundle.py`: collect SL009 findings from the source check (bundle
   already runs the check pipeline); build `share_advisory` block;
   sanitize through the existing evidence path.
2. `hooks.py`: add SessionEnd HookFile to `_claude_doc()` emitting the
   `sesslint hook --event SessionEnd` command (depends on
   agent-hooks/T-01 existing; if landed first, recipe degrades to a
   documented `check --select SL009 "$transcript_path"` manual form —
   keep both in the doc note until T-01 ships).
3. Schema file + bundle schema test updates; golden bundle regen.
4. Docs: INTEGRATIONS.md recipe table + SL009.md "sharing" section.
5. Tests: seeded-secret fixture → bundle JSON contains advisory with
   correct families/counts and no values; init-hooks output includes
   the SessionEnd block; determinism on repeated runs.
6. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "bundle or hooks or init_hooks"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
uv run python scripts/check_release_refs.py
```

## Acceptance Criteria

- Bundle of a clean file: no `share_advisory` key (absent, not null).
- Bundle of a seeded file: advisory with exact families + count; canary
  value absent from the entire bundle JSON.
- `sesslint init-hooks --agent claude` prints a SessionEnd block whose
  command references `sesslint hook` (or the documented fallback).
- `check_release_refs.py` stays green (schema/doc consistency).

## Rollback / Stop Conditions

- If bundling the advisory requires running checks a second time (perf
  or determinism risk), source the findings from the report already in
  the bundle — never rescan.

## Risks

- Advisory fatigue if bundled files routinely contain test-fixture
  secrets → the near-miss exclusions from T-01 keep the rate low; the
  advisory is silent when absent by design.

## Out of Scope

- Blocking the share/upload (SessLint never controls what the user
  sends; advisory only).
- Pre-upload redaction of the *source* file (content mutation).
- Codex/other-runtime SessionEnd equivalents (no documented hook
  surface — tracked in agent-hooks/T-03).

## Implementation Notes (2026-09-21)

- `bundle.py`: `Bundle.share_advisory` optional field — absent (not
  null) when no SL009 findings. Advisory sourced from the report
  already embedded in the bundle (no second scan, per rollback rule).
  `kind`/`finding_count`/sorted `families`/`note` only — digests stay
  in the embedded report.
- `schemas/sesslint.bundle.v1.json`: additive optional
  `share_advisory` object (additionalProperties stays false); no
  version bump — additive optional field, consistent with prior
  in-place enum extensions.
- `cli.py`: `--strict-share` flag on `bundle`. Advisory always prints
  a one-line stderr notice when present (stdout stays pure JSON);
  strict mode exits 1 and writes nothing (fail-closed — no artifact
  leaves the gate). Exit-code convention: 1 = findings-class, same as
  check findings.
- `hooks.py`: `_CLAUDE_SESSIONEND_BLOCK` — matcher covers all
  documented SessionEnd reasons; command is the documented fallback
  (`jq -r .transcript_path | xargs -I{} sesslint check "{}" --select
  SL009 || true`) because `sesslint hook` (agent-hooks/T-01) has not
  shipped. `_CLAUDE_NOTE` documents the future replacement.
- `man/sesslint-bundle.1` regenerated via `scripts/gen_man.py`.
- Docs: REPORTING_CORRUPTION.md gains "Pre-share advisory" section;
  INTEGRATIONS.md gains SessionEnd table row + recipe; SL009.md gains
  "Sharing artifacts"; hygiene.md gains SessionEnd + bundling
  sections. Post-tag flag `--strict-share` carries `next-release`
  markers (check_release_refs green).
- Tests: `TestBundleShareAdvisory` (7 tests — advisory shape, absent
  key on clean, canary-free JSON, determinism, stderr notice + exit 0,
  strict gate exit 1 + no output, strict pass on clean); init-hooks
  tests updated for 3 files + SessionEnd assertions.
- Gates: ruff/format/mypy clean; full pytest green; fuzz 11/11;
  check_release_refs OK; golden bundle unchanged (clean fixture emits
  no advisory).
