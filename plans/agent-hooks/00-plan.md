# SessLint Agent-Hooks Plan (00)

- Status: done (2026-09-21) — implemented and reviewed
- Language: English
- Created: 2026-09-21
- Authority: execution plan for making SessLint's hook integration
  zero-config. `DEMAND.md`/`AGENTS.md` invariants apply; SessLint never
  writes agent configuration (print-only snippets is a permanent design
  invariant per `hooks.py`).
- Companion docs: `src/sesslint/hooks.py`, `src/sesslint/precheck.py`,
  `src/sesslint/cli.py`, `docs/INTEGRATIONS.md`, ROADMAP Phase B
  ("presence at the moment of pain").

## Goal

Replace placeholder-path hook snippets with a real integration:
Claude Code hooks deliver a JSON payload on **stdin** carrying
`session_id`, `transcript_path`, `cwd`, and `hook_event_name` —
documented for every event. A `sesslint hook` subcommand reads that
payload, resolves the exact session file, and runs the right check —
so the emitted snippet works with zero user editing and targets the
session actually being resumed/compacted/ended, not a glob of every
file in the project.

## Verified Facts (2026-09-21 evidence refresh)

1. Current snippets are placeholders: `hooks.py` emits
   `sesslint check "$CLAUDE_PROJECT_DIR"/*.jsonl` for SessionStart
   (checks *every* file in the project dir — wrong unit, wasteful) and
   `sesslint check /path/to/session.jsonl` for PreCompact (requires
   manual path substitution — most users will never do it).
2. Claude Code's documented stdin payload carries `transcript_path`
   (path to the conversation JSONL), `session_id`, `cwd`,
   `hook_event_name`, and per-event extras; `SessionStart` adds
   `source` ∈ {startup, resume, clear, compact, fork}. All documented
   at code.claude.com/docs/en/hooks.
3. Caveat from the same docs: `transcript_path` may lag the in-flight
   turn — checks must be framed as "state of durable history", which is
   exactly SessLint's contract.
4. Hook ecosystem grew from 4 → ~30 events in 2026; PostCompact and
   SessionEnd are first-class events. PostCompact is the ideal point to
   re-check compaction-boundary integrity (SL108/SL205 fire on exactly
   the artifacts compaction produces); SessionEnd is where
   transcript-hygiene/T-03's secret sweep attaches.
5. Exit-code contract: exit 2 blocks the action (PreToolUse-class
   events); SessionStart/SessionEnd are advisory (output shown to user,
   cannot block). Snippets must encode the correct semantics per event
   — a hard-block on SessionStart would brick `claude` startup.
6. Codex CLI: "no documented user-facing hook surface" (current
   `hooks.py` note). Re-verify at implementation time — T-03 tracks it.

## Constraints And Non-Goals

- `sesslint hook` reads stdin, prints a result line, and exits with
  documented codes. It **never** writes config — the snippets remain
  print-only; the user merges them into `settings.json`.
- Hook payload fields are *untrusted input*: `transcript_path` must be
  resolved defensively (must exist, must be a file, size limits apply)
  and never executed, shelled, or glob-expanded unsafely.
- Output inside a hook must be minimal and content-free — hook stdout
  on SessionStart can be injected into the agent's context, so
  `sesslint hook` output must satisfy the same content-free rules as
  every other surface.
- No new runtime dependencies; stdin JSON parse via stdlib `json`.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | `sesslint hook` subcommand (stdin payload → resolved check) | P1 | — |
| T-02 | init-hooks v2 snippets (SessionStart/PreCompact/PostCompact/SessionEnd) | P1 | T-01 |
| T-03 | Codex + other-runtime hook-surface research | P3 | — |

## Validation

Per task: fixture stdin payloads per event (including missing/
malformed fields, nonexistent `transcript_path`, oversized payload),
exit-code matrix tests per event semantics, snippet-render tests, and
determinism. No real agent config is ever written — tests assert the
print-only contract.
