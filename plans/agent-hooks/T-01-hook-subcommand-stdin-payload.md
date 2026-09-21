# T-01: `sesslint hook` subcommand — stdin payload → resolved check

- Status: done (2026-09-21) — implemented and reviewed
- Phase: agent-hooks
- Priority: P1
- Type: feature (new CLI surface)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (new `hook` subcommand)
  - `src/sesslint/hook_event.py` (new module: payload parse + dispatch)
  - `src/sesslint/precheck.py`, `src/sesslint/api.py` (reuse)
  - `schemas/` (optional `sesslint.hook-result/v1` if JSON output added)
  - `docs/INTEGRATIONS.md`, `tests/cli/`
  - `CHANGELOG.md`

## Goal

`sesslint hook --event <name>` reads one Claude Code hook payload from
stdin, resolves `transcript_path`, runs the appropriate integrity
operation for that event, and exits with semantics matching the event's
blocking contract. One binary entrypoint for every hook event, so
snippets never need path substitution.

## Verified Problem / Current Evidence

- 00-plan.md facts 1-5: today's snippets ship a literal
  `/path/to/session.jsonl` placeholder (PreCompact) and a
  whole-directory glob (SessionStart). Both are friction or wrong-unit
  checks; the documented stdin payload removes both problems.
- `precheck()` already provides the zero-exception gate
  (ok / reason / exit_code 0|1|2). The subcommand is a thin adapter:
  stdin JSON → path → `precheck` → content-free line + exit code.
- `cli.py` already parses `-` as stdin for `scan`; the hook payload is a
  different stdin contract (JSON control message, not session bytes) —
  a dedicated subcommand keeps the two unambiguous.

## Required Design / Decisions

1. **Invocation.**
   `sesslint hook --event {SessionStart,PreCompact,PostCompact,SessionEnd,
   UserPromptSubmit,...}` — any event name accepted; behavior differs
   only in *which check runs* and *whether exit 2 is meaningful*.
2. **Payload contract (per Claude Code docs).**
   Required fields handled: `transcript_path` (str), `session_id`,
   `cwd`, `hook_event_name`, `source` (SessionStart only). Missing or
   wrong-typed `transcript_path` → exit 0 with a content-free skip line
   (`hook: no transcript_path; skipped`) — a hook must never brick the
   agent because its own payload was thin. Malformed JSON stdin → same
   skip path. Payload read is bounded (cap stdin at e.g. 1 MB).
3. **Path handling.** `transcript_path` resolved literally (no glob, no
   shell); must be an existing regular file; the 100 MB size cap and
   format auto-detection apply as usual. A path outside known roots is
   still checked (hooks may point anywhere) — read-only always.
4. **Event → action map (v1):**
   - `SessionStart` (source=resume|compact|startup|clear|fork):
     `precheck(transcript_path)` — resume-gate verdict. Advisory
     (exit 0 always); output line states findings count + top code.
   - `PreCompact`: `precheck` — flags corruption *before* a compaction
     boundary is written on top of it (SL108/SL205 classes). Advisory.
   - `PostCompact`: `check` — post-boundary integrity verdict; the
     moment split-pair/coverage faults exist to be seen. Advisory.
   - `SessionEnd`: `check --select SL009` once transcript-hygiene/T-01
     lands; until then, `precheck`. Advisory.
   - All other events: generic `precheck` advisory, or skip with reason
     `event-not-applicable` when no transcript file is relevant
     (e.g. Notification) — decide per event-name allowlist; unknown
     event names are accepted and treated as generic (forward-compat).
5. **Output.** One line, content-free:
   `sesslint hook[SessionStart]: ok` /
   `sesslint hook[PostCompact]: findings=3 top=SL108 …` /
   `sesslint hook[*]: skipped (<reason>)`.
   `--json` emits `sesslint.hook-result/v1`
   `{schema, event, verdict, reason, findings_by_code, session_id?}` —
   `session_id` is an identifier, not content; include only if the
   content-free review accepts it (default: hash-truncate to 8 chars
   like other ID surfaces — decide at impl, document).
6. **Exit codes.** Advisory events: 0 always (even on findings) unless
   `--strict` passed (then 1 on findings). Blocking-capable events are
   out of scope for v1 — none of the events we map can block; document
   that exit 2 is never emitted by `sesslint hook` in v1 so a merge
   error can't wedge the agent.
7. **Never throws.** Every internal failure path → skip line + exit 0.
   The subcommand is on the agent's critical path; a crash is worse
   than a missed check. (Consistent with `precheck`'s zero-exception
   contract.)

## Ordered Implementation Steps

1. `hook_event.py`: `parse_hook_payload(bytes) -> HookPayload | Skip`;
   `resolve_transcript(payload) -> Path | Skip`; `run_hook(event, …) ->
   HookResult`; bounded stdin read.
2. `cli.py`: `hook` subparser (`--event` required, `--json`, `--strict`,
   `--profile`, `--format` passthrough) → `run_hook`.
3. Render line + `sesslint.hook-result/v1` JSON (schema file + test).
4. Tests: per-event stdin fixtures (valid, missing transcript_path,
   nonexistent path, malformed JSON, >1MB stdin), exit-code matrix,
   determinism, `--strict` behavior.
5. Docs: INTEGRATIONS.md section + `sesslint hook --help` text.
6. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/cli/ -k hook
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Piping a documented SessionStart payload with a corrupted transcript
  at `transcript_path` prints a findings line and exits 0.
- Piping `{}` / garbage / a payload with a missing file prints
  `skipped` and exits 0 — never a traceback, never exit 2.
- With `--strict`, findings exit 1; clean exits 0.

## Rollback / Stop Conditions

- If any event's documented payload lacks `transcript_path` on real
  Claude Code builds, that event maps to `skipped` — verify against the
  live hook docs at implementation time.

## Risks

- `transcript_path` lag (docs caveat): a PreCompact check may miss the
  in-flight turn — acceptable; the check guards *durable* state, which
  is the documented contract. Note in docs.
- Users could wire `sesslint hook` into a blocking event expecting a
  gate — exit 2 is never emitted in v1, documented; if a blocking use
  case proves out, add `--block` semantics deliberately.

## Out of Scope

- Writing/merging `settings.json` (permanent invariant: print-only).
- HTTP-hook mode, async hooks, MCP-tool hooks.
- Blocking/gating semantics (v1 is advisory-only by design).
- Codex hooks (T-03 research).

## Implementation Notes (2026-09-21)

- New module `src/sesslint/hook_event.py`: `run_hook(event, data, *,
  profile, format, fail_on)` — pure function over raw stdin bytes;
  `HookResult` carries event/verdict/reason/findings_by_code/top_code/
  hash-truncated `session_id` and renders both the one-line form and
  `sesslint.hook-result/v1` JSON.
- Payload contract: bounded 1 MiB stdin read (CLI passes
  `MAX_HOOK_PAYLOAD_BYTES + 1` so oversize is detectable);
  `transcript_path` resolved literally — must exist and be a regular
  file. Every failure path → `skipped` + exit 0; `run_hook` never
  raises (broad `except Exception` → `internal-error` skip).
- Event map v1: `SessionEnd` → `check --select SL009`; all other
  (including unknown) events → full check. `--event` is authoritative;
  the payload's `hook_event_name` is not cross-checked.
- **Deviation from plan:** the gate flag shipped as
  `--fail-on {never,error,warning}` (default `never`) instead of
  boolean `--strict`. Rationale: `--strict` collided with `mypy
  --strict` in `check_release_refs.py` (7 false-positive violations on
  existing docs) and `--fail-on` already exists at tag v0.3.0 — zero
  doc-lint friction plus identical vocabulary to `check`/`scan`.
  Semantics: `warning` exits 1 on any finding, `error` on error/fatal
  only (SL301/SL302 are error-class, so detection failures gate
  correctly), `never`/absent stays advisory.
- `cli.py`: `hook` subparser with `--event` (required, free string —
  forward-compat), `--json`, `--fail-on`, `--profile`, `--format`.
- New schema `schemas/sesslint.hook-result.v1.json` (shipped via
  shared-data glob; `session_id` is the SHA-256-truncated 8-hex form,
  consistent with other ID surfaces).
- `man/sesslint-hook.1` regenerated; `README.md` command matrix gains
  the `hook` row; `PINNED_COMMANDS` in `test_completion.py` updated.
- Docs: INTEGRATIONS.md gains a "sesslint hook — zero-config
  entrypoint" section (stdin contract, event map, exit codes,
  transcript_path trust boundary, lag caveat) — `next-release` marked.
- Tests: `tests/cli/test_hook.py` — 26 tests across payload handling,
  event map, fail-on matrix, output shape, CLI subprocess, and schema
  validation.
- Gates: ruff/format/mypy clean; full pytest green; fuzz 11/11;
  check_release_refs OK.
- Snippet switch to `sesslint hook` form is T-02's scope; the T-03
  SessionEnd jq fallback stays valid until then.
