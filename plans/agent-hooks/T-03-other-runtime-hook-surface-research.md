# T-03: Codex + other-runtime hook-surface research

- Status: done (2026-09-21) — implemented and reviewed
- Phase: agent-hooks
- Priority: P3
- Type: research (memo only — no code)
- Depends on: —
- Primary targets:
  - `docs/INTEGRATIONS.md` (capability matrix update)
  - `plans/agent-hooks/00-plan.md` (status annotation)
  - Possibly `hooks.py` `_CODEX_NOTE` wording refresh

## Goal

Re-verify which agent runtimes expose a user-facing hook/lifecycle
surface as of implementation time, so `init-hooks` coverage claims stay
honest and new runtimes get recipes the day their surface exists.

## Verified Problem / Current Evidence

- `hooks.py` states "Codex CLI has no documented user-facing hook
  surface as of this writing" — asserted 2026-09; the runtime is
  evolving (thread-store, desktop, and exec modes shipped since).
- Claude Code's hook system grew 4 → ~30 events during 2026; other
  runtimes may follow (Copilot CLI already documents `hooks/` user
  dir and `mcp-config.json` in its config-dir reference — a hooks
  directory exists even if event docs are thin).
- Gemini CLI documents a hooks/extension mechanism in its docs site;
  OpenCode has a plugin/event bus. None are verified against current
  releases from this repo's evidence.

## Required Design / Decisions

1. Output is a dated memo appended to this task file's Implementation
   Notes (or `demand-wedge-plan/MARKET_EVIDENCE.md` evidence log):
   per-runtime table of {hook surface exists? event names? stdin/JSON
   payload shape? blocking semantics? doc URL + access date}.
2. Runtimes to check, in order: Codex CLI/Desktop, GitHub Copilot CLI,
   Gemini CLI, OpenCode, Cursor agent CLI, Aider.
3. For each runtime with a surface: a proposed `sesslint hook --event`
   mapping table (event name → advisory check) — spec-level only.
4. For each runtime without one: the recommended fallback remains
   wrapper scripts + `scan --agent`, as today's `_CODEX_NOTE` states.

## Ordered Implementation Steps

1. Check each runtime's current docs/source for hook/event/extension
   surfaces; record URLs + retrieval date.
2. Update `_CODEX_NOTE`/agent notes only if the surface verifiably
   exists (never speculate in shipped text).
3. File adapter-coverage ledger note if a runtime's hook payload reveals
   a *file-based* session format we have not recorded (feeds
   adapters-coverage pack).

## Required Tests / Validation Commands

None — research deliverable. Docs diff review only.

## Acceptance Criteria

- Dated per-runtime table exists in-repo; every claim cites a URL +
  access date; `_CODEX_NOTE` updated iff warranted.

## Rollback / Stop Conditions

- If a runtime's surface is ambiguous (docs vs shipped behavior
  diverge), record "unverified" — never mark supported on doc claims
  alone.

## Risks

- Docs churn faster than re-verification → the memo must carry an
  access date and a "re-check at release time" note.

## Out of Scope

- Implementing non-Claude snippets.
- Any runtime whose hooks require a daemon/plugin install (out of
  scope for a print-only snippet generator).

## Implementation Notes — research memo (2026-09-21)

All claims below cite vendor docs accessed 2026-09-21. Re-verify at
release time — hook surfaces are the fastest-moving part of every
runtime right now.

### Per-runtime surface table

| Runtime | Hook surface? | Config location | stdin payload carries `transcript_path`? | Blocking semantics | Source (accessed 2026-09-21) |
| --- | --- | --- | --- | --- | --- |
| Codex CLI/Desktop | **Yes** (official docs) | `~/.codex/hooks.json`, `<repo>/.codex/hooks.json`, or `[hooks]` in `config.toml` — same 3-level `{"hooks": {Event: [{matcher, hooks: [{type: command, command}] }]}}` shape as Claude | **Yes** — `session_id`, `transcript_path` (string\|null), `cwd`, `hook_event_name`, `model`; identical field names to Claude | exit `2` blocks blockable events; `SessionEnd` advisory, always sync, default timeout **1 s** (max 3 s) | https://developers.openai.com/codex/hooks |
| GitHub Copilot CLI | **Yes** | `.github/hooks/*.json` (repo), `~/.copilot/hooks/*.json` (user), `hooks` field in `settings.json`; `{version: 1, hooks: {...}}`; entries use `bash`/`powershell` or `exec`+`args` (no shell) | **Partial** — present on `preCompact`, `agentStop`/`Stop`, `subagentStart`/`subagentStop`, tool events; **absent** on `sessionStart`, `sessionEnd`, `userPromptSubmitted`, `errorOccurred` | exit `2` or `permissionDecision` JSON on blockable events; `preCompact` notification-only; `sessionEnd` advisory | https://docs.github.com/en/copilot/reference/hooks-reference |
| Gemini CLI | **Yes** | `settings.json` `hooks` object; `{matcher, sequential, hooks: [{type: "command", command, name, timeout(ms)}]}` | **Yes** — base schema on **all** hooks: `session_id`, `transcript_path` (absolute path to transcript JSON), `cwd`; snake_case | exit `2` = system block; other non-zero = warning; **stdout must be JSON only** ("Silence is Mandatory") | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md |
| Cursor | **Yes** | `.cursor/hooks.json`, `~/.cursor/hooks.json`; `{version: 1, hooks: {event: [{command, timeout, matcher, failClosed}]}}` | **Yes** — common schema on all agent hooks: `transcript_path` (string\|null), `session_id`, `conversation_id`, `hook_event_name`; snake_case despite camelCase event names | exit `2` blocks (permission hooks); `sessionStart`/`sessionEnd` fire-and-forget; fail-open default | https://cursor.com/docs/hooks |
| OpenCode | Plugin API only | `.opencode/plugins/*.ts` — JS/TS module returning a hooks object over an internal event bus (`session.created`, `session.compacted`, `session.idle`, …) | n/a (in-process objects, not stdin JSON) | in-process return values | https://dev.opencode.ai/docs/plugins |
| Aider | **No** | n/a — only fixed-purpose `--lint-cmd`/`--test-cmd`/`auto-lint`; lifecycle-hook requests open (Aider-AI/aider#2045, #2557) | n/a | n/a | https://aider.chat/docs/scripting.html |

### Event-name / payload notes per runtime

- **Codex** — events: `SessionStart`, `SessionEnd`, `PreCompact`,
  `PostCompact`, `PreToolUse`, `PostToolUse`, `PermissionRequest`,
  `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`,
  `Interrupt`. Matchers: `SessionStart` → `startup|resume|clear|compact`
  (**no `fork`** — that source is Claude-only); `PreCompact`/
  `PostCompact` → `manual|auto`; `SessionEnd` → only `other` today.
  `transcript_path` points at the rollout file
  (`…/.codex/rollout.jsonl` in the docs' own example) — the format our
  `codex_rollout` adapter already parses, so `sesslint hook` works
  against Codex payloads **with zero code change**. Caveats:
  non-managed hooks need one-time `/hooks` trust review (trust is
  hash-pinned — editing the command re-prompts); `SessionEnd` default
  timeout is 1 s (set `timeout: 3`); vendor caveat that the transcript
  format "isn't a stable interface". A `commandWindows` field exists
  for Windows overrides.
- **Copilot CLI** — dual payload format keyed by event-name casing:
  configure **PascalCase** names (`SessionStart`, `PreCompact`, `Stop`)
  and the payload arrives snake_case with `transcript_path` — the exact
  contract `sesslint hook` reads. camelCase names deliver
  `transcriptPath` instead. Events where `transcript_path` is absent
  make `sesslint hook` skip cleanly (`no-transcript-path`, exit 0) —
  graceful, no crash. Copilot also reads `.claude/settings.json` hooks
  (cross-tool loading): our emitted Claude snippets may already fire
  under Copilot — **unverified** end-to-end.
- **Gemini CLI** — `transcript_path` on every hook, but stdout is
  parsed as JSON on exit 0 and plain text is invalid
  ("Silence is Mandatory"). `sesslint hook` default line output would
  need `--json`; whether Gemini tolerates an output object that doesn't
  match its response schema is **unverified**. Transcript is a single
  JSON file (not JSONL) — see adapters-coverage T-09.
- **Cursor** — `transcript_path` in the common schema for all agent
  hooks (`sessionStart`, `sessionEnd`, `preCompact` included), plus
  `CURSOR_TRANSCRIPT_PATH` env var. Session hooks are fire-and-forget —
  a natural fit for advisory recipes. Transcript is a sidecar format —
  see adapters-coverage T-08. Cursor additionally auto-maps
  `.claude/settings.json` hooks when third-party config loading is
  enabled — our Claude snippets may already run there — **unverified**.
- **OpenCode** — no shell-command hooks; subscribing to
  `session.*` events requires shipping a JS/TS plugin — outside the
  print-only snippet generator's scope (plan exclusion). Its session
  store is SQLite — see adapters-coverage T-04.
- **Aider** — no user-facing lifecycle hooks. Fallback stays wrapper
  scripts + `sesslint scan`.

### Proposed `sesslint hook --event` mapping (spec-level, not emitted)

| Runtime | Recipe | Notes |
| --- | --- | --- |
| Codex | `SessionStart` matcher `startup\|resume\|clear\|compact` → `sesslint hook --event SessionStart \|\| true` | drop `fork` (not a Codex source) |
| Codex | `PreCompact`/`PostCompact` matcher `auto\|manual` → `sesslint hook --event <X> \|\| true` | identical to Claude semantics |
| Codex | `SessionEnd` (omit matcher or `other`) → `sesslint hook --event SessionEnd \|\| true` + `timeout: 3` | default 1 s timeout is too tight; SL009 scan must fit |
| Copilot CLI | `PreCompact` + `Stop` (PascalCase) → `sesslint hook --event <X>` | only events carrying `transcript_path`; needs T-05 adapter before checks find anything — emits `skipped`/`detection` outcomes meanwhile |
| Gemini CLI | `SessionStart`/`SessionEnd`/`PreCompress` → `sesslint hook --event <X> --json` | blocked on stdout-JSON-only contract + T-09 adapter |
| Cursor | `sessionStart`/`sessionEnd`/`preCompact` → `sesslint hook --event <X>` | camelCase config key, snake_case payload; blocked on T-08 adapter; `--event` arg is authoritative so casing mismatch is harmless |
| OpenCode | — | plugin install required — out of scope |
| Aider | — | no surface |

### Actions taken

- `_CODEX_NOTE` rewritten — the "no documented user-facing hook
  surface" claim is stale (Codex hooks are officially documented);
  the note now says the surface exists and why snippets are deferred.
- `docs/INTEGRATIONS.md` "Not yet supported" Codex bullet corrected;
  a runtime hook-surface matrix added.
- Adapter-coverage cross-refs: hook payloads confirm file-based
  transcript targets for Copilot (T-05), Cursor (T-08), Gemini (T-09) —
  all DV-gated; this memo is their hook-surface evidence, not demand
  evidence.
- Follow-up recommendation: a T-04 task to emit Codex snippets is now
  cheap and safe — same config shape, same payload contract, and the
  rollout adapter already exists. Copilot/Cursor/Gemini recipes should
  wait for their adapters (DV-gated) so hooks don't fire into
  undetectable formats.
