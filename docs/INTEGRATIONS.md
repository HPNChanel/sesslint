# Agent Runtime Integrations

How to wire SessLint into agent runtimes so session corruption is caught **before**
it costs you work — not discovered after a failed resume.

All integrations are **read-only**: every command below inspects files and
exits; nothing writes to session stores, agent databases, or config files.
SessLint never installs or modifies agent configuration itself — hook snippets
are copy-paste recipes you own.

## Claude Code hooks

> Verified against the Claude Code hooks reference (SessionStart, PreCompact)
> as of 2026-09. Hook contracts can drift between releases — if a recipe here
> stops matching your runtime, treat it as community-verified and check the
> upstream docs before filing an issue.

> `sesslint init-hooks --agent claude --print` prints the
> exact JSON blocks below ready to paste — it never writes your settings.

Claude Code fires hooks at lifecycle points where SessLint adds value:

| Hook | When it fires | What SessLint adds |
| :--- | :--- | :--- |
| `SessionStart` | Session begins, is resumed, or is cleared | Warn the agent if the session file is already corrupt *before* it resumes into a broken ledger. |
| `PreCompact` | Before transcript compaction | Warn if compaction input is structurally damaged (orphan pairs, torn records) so the summary isn't built on a broken graph. |
| `PostCompact` | After transcript compaction | Catch compaction-boundary faults (SL108/SL205 classes) immediately, while the boundary is fresh. |
| `SessionEnd` | Session ends (clear, logout, prompt exit) | Flag secret-shaped material persisted in the transcript (SL009) at the exact moment the file stops growing — per-session instead of a monthly audit. |

### Exit-code contract

Hooks interpret exit codes as: `0` = success/allow, `2` = blocking error
(stderr is fed back to the model), any other code = non-blocking warning.

`sesslint check <file>` exits:

| Exit | Meaning | Hook effect |
| :--- | :--- | :--- |
| `0` | Session is clean (or warnings only) | proceed |
| `1` | Structural findings (corruption, pairing errors, detection failed) | non-blocking warning — surfaced to the agent |
| `2` | I/O or usage error | blocking — the agent sees the error message |

The recipes below use `sesslint hook`, which is **advisory-only**: it never
emits `2`, so nothing can block the agent — even if the recipe is merged
into the wrong event. To opt into gating, add `--fail-on warning` (exit
`1` on findings) and drop `|| true`.

### `sesslint hook` — zero-config entrypoint

`sesslint hook --event <name>` is the single entrypoint every recipe
below uses. It reads the hook payload from stdin, resolves the
transcript, runs the event-appropriate check, and prints a single
content-free line — no path substitution, no shell plumbing.

Contract:

- **stdin**: one JSON hook payload (`session_id`, `transcript_path`,
  `cwd`, `hook_event_name`), capped at 1 MiB. Malformed or oversized
  payloads print `skipped (<reason>)` and exit `0` — a hook must never
  brick the agent because its own payload was thin.
- **Event map**: `SessionEnd` runs `check --select SL009` (persisted
  secrets at the moment the file stops growing); every other event —
  including unknown names, for forward-compat — runs the full integrity
  check.
- **Output**: `sesslint hook[<event>]: ok` | `findings=N top=<code>` |
  `skipped (<reason>)`. `--json` emits `sesslint.hook-result/v1`
  (`schemas/sesslint.hook-result.v1.json`).
- **Exit codes**: `0` always — findings included — unless `--fail-on`
  gates them (`--fail-on warning` exits `1` on any finding, `--fail-on
  error` on error/fatal findings only; default `never`). `2` is never
  emitted in v1: none of the mapped events are blocking-capable, so a
  merge error cannot wedge the agent.
- `transcript_path` is untrusted input: resolved literally (no glob, no
  shell), must be an existing regular file. Missing/nonexistent paths
  skip cleanly.
- Caveat from the vendor docs: `transcript_path` can lag the in-flight
  turn. The check guards *durable* state — the on-disk record — which is
  exactly what a later resume reads back.

### Recipes

Add to `.claude/settings.json` (project) or `~/.claude/settings.json`
(user). `sesslint init-hooks --agent claude --print` emits exactly these
blocks — every command is `sesslint hook --event <name> || true`, so
there is nothing to substitute.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume|clear|compact|fork",
        "hooks": [
          {"type": "command", "command": "sesslint hook --event SessionStart || true"}
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "auto|manual",
        "hooks": [
          {"type": "command", "command": "sesslint hook --event PreCompact || true"}
        ]
      }
    ],
    "PostCompact": [
      {
        "hooks": [
          {"type": "command", "command": "sesslint hook --event PostCompact || true"}
        ]
      }
    ],
    "SessionEnd": [
      {
        "matcher": "clear|logout|prompt_input_exit|other",
        "hooks": [
          {"type": "command", "command": "sesslint hook --event SessionEnd || true"}
        ]
      }
    ]
  }
}
```

Notes:

- `SessionStart` matcher covers all documented sources including
  `compact` and `fork` — a post-compaction re-injection deserves the
  same integrity check as a fresh resume.
- `PostCompact` carries no `matcher` (fires unconditionally after every
  compaction).
- `|| true` is belt-and-suspenders: `sesslint hook` already exits `0` on
  findings, skips, and bad input — it can never produce the blocking `2`.
- Merge order and event choice are yours; dropping `|| true` changes
  nothing unless you add `--fail-on` (documented above).
- Requires a SessLint release carrying `sesslint hook` — check
  `sesslint version`. Older CLIs will surface a harmless shell error
  under `|| true` and the agent keeps working.

### Content-free guarantee

Hook stdout can be injected into the agent's context. `sesslint hook`
output is **content-free by design**: one status line, or a
`sesslint.hook-result/v1` object under `--json`, carrying rule codes,
severities, and counts — never message text, tool arguments, payloads,
or raw `session_id`/`transcript_path` values. The `--include-content`
flag on `sesslint check` exists for local debugging only; do not use it
in hooks.

### Latency

Hooks run synchronously — a slow check delays the lifecycle event. SessLint's
reader is bounded by `ReaderLimits` (`sesslint scan --show-limits`): file size,
line size, record count, and nesting depth are all capped, so a pathological
file fails fast rather than hanging the hook. Typical session files check in
well under a second; the 250k-event benchmark contract is ~15 s for the
absolute worst case.

## Programmatic gate: `sesslint.precheck`

For runtime integrations written in Python, `sesslint.precheck(path)` is the
one-call gate the hook recipes wrap:

```python
from sesslint import precheck

result = precheck("sessions/active.jsonl", profile="claude-strict")
if not result.ok:
    # reasons: findings-error, findings-warning, detection-failed,
    #          io-error, usage-error
    abort_or_warn(result.reason)
```

It never raises on session findings — only returns `PrecheckResult` with
`exit_code` 0/1/2 matching the CLI contract above.

## Live monitoring: `sesslint watch`

Run `sesslint watch` alongside your agent to catch corruption the moment it
is written — not at next resume:

```bash
# Watch every discovered agent root (default 2s poll)
sesslint watch --agent all

# Or watch one project directory
sesslint watch ~/.claude/projects/my-app/

# Machine-consumable transitions (NDJSON sesslint.watch-event/v1)
sesslint watch --agent all --json >> ~/.local/state/sesslint-watch.ndjson
```

Each verdict change prints one line — `healthy->invalid` with the rule codes
— and stays quiet otherwise. Watch is a pure observer: it never writes to
watched directories, never installs hooks, and Ctrl+C exits cleanly. Poll
cost scales with file count; narrow the scope with an explicit path or
`--agent` when watching large roots.

## MCP server: `sesslint mcp`

Agents that natively consume MCP servers (Claude Code, Codex) can call
SessLint checks directly. `sesslint mcp` runs a Model Context Protocol
server over **stdio** — newline-delimited JSON-RPC 2.0, protocol revision
`2025-06-18`, zero dependencies, no sockets, no threads.

Client configuration (add to the agent's MCP settings — SessLint never
writes client config):

```json
{
  "mcpServers": {
    "sesslint": {
      "command": "sesslint",
      "args": ["mcp"]
    }
  }
}
```

Tools exposed (all read-only, all content-free — findings are results, not
protocol errors):

| Tool | Returns |
| ---- | ------- |
| `sesslint_check` | `sesslint.report/v1` report (structured content) for one session file |
| `sesslint_precheck` | `{ok, reason, exit_code}` gate result plus the report |
| `sesslint_scan` | `sesslint.scan/v1` 5-bucket aggregate for a file or directory tree |

Each tool takes `path` (required), plus optional `profile` (`neutral`,
`claude-strict`, `openai-strict`) and `format` adapter override. Missing
paths and tool failures return `isError: true` results with content-free
reason strings; protocol problems return JSON-RPC error objects. The server
adds no timestamps — identical requests produce identical responses.
EOF or Ctrl+C exits cleanly.

## Editor problem-matchers

`contrib/editors/problem-matcher.json` ships a two-line problemMatcher so
`sesslint check`/`scan` human output becomes click-to-line navigation in
VS Code, Zed, and compatible editors. Setup notes per editor plus a
`tasks.json` example live in [`contrib/editors/README.md`](../contrib/editors/README.md).
Path caveat: human output minimizes paths for privacy — use
workspace-relative inputs for clickable navigation.

## Runtime hook surfaces

Which agent runtimes expose a user-facing hook surface whose stdin
payload `sesslint hook` can read (verified 2026-09 — re-checked each
release; see `plans/agent-hooks` T-03 memo):

| Runtime | Hook surface | Payload carries `transcript_path` | SessLint recipes |
| :--- | :--- | :--- | :--- |
| Claude Code | `settings.json` `hooks` | Yes — all events | Emitted (`init-hooks --agent claude`) |
| Codex | `~/.codex/hooks.json`, `config.toml [hooks]` | Yes — all events | Not yet — matcher/timeout/trust-review semantics under verification |
| Copilot CLI | `.github/hooks/*.json`, `~/.copilot/hooks/` | Only on `PreCompact`, `Stop`, `subagent*` events (PascalCase names → snake_case payload) | Not yet — needs the Copilot adapter first |
| Gemini CLI | `settings.json` `hooks` | Yes — all events, but stdout must be JSON | Not yet — needs the Gemini adapter + `--json` contract check |
| Cursor | `.cursor/hooks.json`, `~/.cursor/hooks.json` | Yes — all agent hooks | Not yet — needs the Cursor adapter first |
| OpenCode | Plugin API (JS/TS modules) | n/a | Out of scope — requires plugin install |
| Aider | None | n/a | Wrapper scripts + `sesslint scan` |

## Session-index health

Directory scans also reconcile the vendor session index against the files
on disk (SL402): sessions the picker cannot see, index entries pointing at
nothing, and malformed/truncated index files. `sesslint doctor` reports a
per-root index state (`ok`, `stale-divergent`, `malformed`, `truncated`,
`absent`, `unverified-format`) with counts only. The per-runtime index
coverage matrix — which runtimes have a verified file-readable index —
lives in [`codes/SL402.md`](codes/SL402.md#per-runtime-index-coverage).

## Not yet supported

- **Automatic hook installation** — SessLint will never edit your agent
  configuration. Recipes above are intentionally copy-paste.
- **OS-event watch backends** — `sesslint watch` polls via stdlib `scandir` snapshots (portable, no deps); inotify/FSEvents/ReadDirectoryChangesW integrations are out of scope.
