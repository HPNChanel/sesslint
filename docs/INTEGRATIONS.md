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

> `sesslint init-hooks --agent claude --print` *(next release)* prints the
> exact JSON blocks below ready to paste — it never writes your settings.

Claude Code fires hooks at lifecycle points where SessLint adds value:

| Hook | When it fires | What SessLint adds |
| :--- | :--- | :--- |
| `SessionStart` | Session begins, is resumed, or is cleared | Warn the agent if the session file is already corrupt *before* it resumes into a broken ledger. |
| `PreCompact` | Before transcript compaction | Warn if compaction input is structurally damaged (orphan pairs, torn records) so the summary isn't built on a broken graph. |

### Exit-code contract

Hooks interpret exit codes as: `0` = success/allow, `2` = blocking error
(stderr is fed back to the model), any other code = non-blocking warning.

`sesslint check <file>` exits:

| Exit | Meaning | Hook effect |
| :--- | :--- | :--- |
| `0` | Session is clean (or warnings only) | proceed |
| `1` | Structural findings (corruption, pairing errors, detection failed) | non-blocking warning — surfaced to the agent |
| `2` | I/O or usage error | blocking — the agent sees the error message |

For `SessionStart` you usually want the non-blocking warning path: a corrupt
session should *inform* the agent, not hard-block the session from opening.
For `PreCompact`, blocking (`2`) is defensible: compacting a known-broken
ledger produces a summary of garbage.

### Recipe: SessionStart corruption warning

<!-- next-release -->
Add to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume|clear",
        "hooks": [
          {
            "type": "command",
            "command": "sesslint check \"$CLAUDE_PROJECT_DIR\"/*.jsonl --json --skip-undetected || true"
          }
        ]
      }
    ]
  }
}
```

Notes:

- `|| true` keeps the hook non-blocking; drop it to hard-block on findings.
- `--skip-undetected` keeps non-session `*.jsonl` files that happen to sit in
  the glob (exports, caches, fixtures) from reporting as `SL302` invalid —
  they classify as `skipped` instead.
- Point the command at the session file(s) you actually resume. A common
  pattern is a small wrapper script that resolves the current session file
  path and runs `sesslint check` on it.

### Recipe: PreCompact gate

```json
{
  "hooks": {
    "PreCompact": [
      {
        "matcher": "auto|manual",
        "hooks": [
          {
            "type": "command",
            "command": "sesslint check /path/to/session.jsonl --json"
          }
        ]
      }
    ]
  }
}
```

With `exit 1` treated as a warning, the agent is told the ledger has structural
issues before it summarizes it.

### Content-free guarantee

Hook stdout can be injected into the agent's context. `sesslint check --json`
output is **content-free by design**: findings carry rule codes, severities,
record indices, and fingerprints — never message text, tool arguments, or
payloads. The `--include-content` flag exists for local debugging only; do not
use it in hooks.

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

## Live monitoring: `sesslint watch` *(next release)*

Run `sesslint watch` alongside your agent to catch corruption the moment it
is written — not at next resume:

```bash
# Watch every discovered agent root (default 2s poll)
sesslint watch --agent all  # next release

# Or watch one project directory
sesslint watch ~/.claude/projects/my-app/

# Machine-consumable transitions (NDJSON sesslint.watch-event/v1)
sesslint watch --agent all --json >> ~/.local/state/sesslint-watch.ndjson  # next release
```

Each verdict change prints one line — `healthy->invalid` with the rule codes
— and stays quiet otherwise. Watch is a pure observer: it never writes to
watched directories, never installs hooks, and Ctrl+C exits cleanly. Poll
cost scales with file count; narrow the scope with an explicit path or
`--agent` when watching large roots. *(next release)*

## MCP server: `sesslint mcp` *(next release)*

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
EOF or Ctrl+C exits cleanly. *(next release)*

## Editor problem-matchers *(next release)*

`contrib/editors/problem-matcher.json` ships a two-line problemMatcher so
`sesslint check`/`scan` human output becomes click-to-line navigation in
VS Code, Zed, and compatible editors. Setup notes per editor plus a
`tasks.json` example live in [`contrib/editors/README.md`](../contrib/editors/README.md).
Path caveat: human output minimizes paths for privacy — use
workspace-relative inputs for clickable navigation.

## Not yet supported

- **Codex CLI hooks** — Codex has no documented user-facing hook surface as of
  this writing. `sesslint scan --agent codex` *(next release)* covers its
  session roots; gate behavior via wrapper scripts.
- **Automatic hook installation** — SessLint will never edit your agent
  configuration. Recipes above are intentionally copy-paste.
- **OS-event watch backends** — `sesslint watch` *(next release)* polls via stdlib `scandir` snapshots (portable, no deps); inotify/FSEvents/ReadDirectoryChangesW integrations are out of scope.
