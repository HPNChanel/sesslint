# Agent Runtime Integrations

<!-- next-release -->

Claude hook recipes match `resume|compact|fork` at SessionStart and set a
five-second timeout for PostCompact and SessionEnd. `hook --format claude-json`
emits a root `systemMessage` containing only outcome and code counts. The CLI's
own JSON result remains available through `--json`; recipes stay advisory.

`hook --init --agent codex` prints Codex `hooks.json` recipes for the same four
events. They use the `systemMessage` envelope at SessionStart, PreCompact, and
PostCompact, and give SessionEnd the three-second maximum Codex allows.
`hook --init --json` prints the blocks as one `sesslint.init-hooks/v1`
document (`schemas/sesslint.init-hooks.v1.json`).

SessionStart skips transcripts above 128 KiB. SessionEnd limits its SL009 pass
to 1 MiB, and other hook checks accept at most 8 MiB. A budget skip never means
the transcript passed. Use `sesslint check --max-file-bytes N` for a larger
inspection. Hooks do not write transcripts or persist their own output. Actual
host UI presentation depends on the installed Claude Code version.

Seal ledgers retain a sibling `.lock` file to serialize competing appenders.
The OS releases the lock when a process exits. The ledger records the digest of
the checked snapshot even if the source changes before append. An uninspected
file cannot be sealed as checked.

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

> `sesslint hook --init --agent claude` prints the <!-- next-release -->
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
(user). `sesslint hook --init --agent claude` emits exactly these <!-- next-release -->
blocks — every command is `sesslint hook --event <name> || true`
(SessionStart adds `--format claude-json`), so there is nothing to
substitute.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "resume|compact|fork",
        "hooks": [
          {"type": "command", "command": "sesslint hook --event SessionStart --format claude-json || true"}
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
          {"type": "command", "command": "sesslint hook --event PostCompact || true", "timeout": 5}
        ]
      }
    ],
    "SessionEnd": [
      {
        "matcher": "clear|logout|prompt_input_exit|other",
        "hooks": [
          {"type": "command", "command": "sesslint hook --event SessionEnd || true", "timeout": 5}
        ]
      }
    ]
  }
}
```

Notes:

- `SessionStart` matches `resume|compact|fork`, the sources that load
  existing transcript state — a post-compaction re-injection deserves the
  same integrity check as a resume. `startup` and `clear` begin a new
  transcript, so there is nothing durable to check yet. With
  `--format claude-json` the result arrives as a content-free
  `systemMessage`.
- `PostCompact` and `SessionEnd` set `"timeout": 5` (seconds), so a slow
  check delays compaction or exit by at most five seconds.
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
reader is bounded by `ReaderLimits` (reported by `sesslint doctor`): file size,
line size, record count, and nesting depth are all capped, so a pathological
file fails fast rather than hanging the hook. Typical session files check in
well under a second; the 250k-event benchmark contract is ~15 s for the
absolute worst case.

## Codex hooks

> Verified on 2026-10-22 against the Codex hooks reference and the hooks
> engine source at tag `rust-v0.163.0` (Codex 0.163.0). The recipes are tested
> with synthetic Codex payloads and rollout fixtures, not yet against a live
> Codex build. The reference has no per-release hook changelog, so re-check it
> after upgrading Codex.

> `sesslint hook --init --agent codex` prints the <!-- next-release -->
> exact JSON blocks below ready to paste — it never writes your hooks file.

Codex fires the four events the Claude Code recipes use. Every hook payload
carries `session_id`, `transcript_path`, `cwd`, and `hook_event_name`.
`SessionStart` adds `model`, `permission_mode`, and `source`; `PreCompact` and
`PostCompact` add `model`, `turn_id`, `trigger`, and, inside a subagent,
`agent_id` and `agent_type`; `SessionEnd` adds `reason`. `sesslint hook`
ignores the extra fields and auto-detects the Codex rollout format, so the
`sesslint hook` contract above applies unchanged; a `null` `transcript_path`
skips cleanly.

What differs from Claude Code, and how the recipes handle it:

| Topic | Codex behavior | Recipe choice |
| :--- | :--- | :--- |
| Trust | Hooks are on by default, but new or changed hooks are skipped until you review and trust them in `/hooks`. A project `.codex/hooks.json` loads only when that project's `.codex/` layer is trusted. | Open `/hooks` after merging the blocks, and again after editing a command. |
| SessionStart output | Plain stdout is added to the model's context as developer context. | `--format claude-json` prints a content-free `systemMessage`, which Codex shows as a warning instead, even for a clean pass. |
| Compaction output | Plain stdout from `PreCompact` and `PostCompact` is ignored. A compaction also queues `SessionStart` with source `compact` for the next turn. | The same `systemMessage` envelope keeps the result visible. `SessionStart` skips `compact`, so one compaction shows two messages, not three. |
| SessionEnd | Advisory. The only end reason is currently `other`. The timeout defaults to 1 s and allows at most 3 s; a timeout or error is reported as a hook failure. | No `matcher`, `"timeout": 3`, and the SL009 pass reads at most 1 MiB. |
| Windows | `commandWindows` replaces `command` on Windows. Hooks run through the session's shell, which on Windows may be PowerShell or `cmd.exe`; without one, Codex falls back to `%COMSPEC% /C` on Windows and `$SHELL -lc` elsewhere. | `commandWindows` repeats the command without the POSIX fallback, so it runs unchanged in either Windows shell (see the notes). |
| Exit codes | For these four events, a non-zero exit is reported as a failed hook, and Codex reads stdout only on exit `0`. Nothing stops the session or the compaction except JSON `"continue": false`. | `sesslint hook` exits `0` on findings and skips, and its JSON never sets `continue`. |

### Recipes

Merge into `~/.codex/hooks.json` (user) or `.codex/hooks.json` (project).
`sesslint hook --init --agent codex` emits exactly these blocks: <!-- next-release -->

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "resume|fork",
        "hooks": [
          {
            "type": "command",
            "command": "sesslint hook --event SessionStart --format claude-json || true",
            "commandWindows": "sesslint hook --event SessionStart --format claude-json"
          }
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "auto|manual",
        "hooks": [
          {
            "type": "command",
            "command": "sesslint hook --event PreCompact --format claude-json || true",
            "commandWindows": "sesslint hook --event PreCompact --format claude-json"
          }
        ]
      }
    ],
    "PostCompact": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "sesslint hook --event PostCompact --format claude-json || true",
            "commandWindows": "sesslint hook --event PostCompact --format claude-json",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "sesslint hook --event SessionEnd || true",
            "commandWindows": "sesslint hook --event SessionEnd",
            "timeout": 3
          }
        ]
      }
    ]
  }
}
```

Notes:

- `SessionStart` matches `resume|fork`. As in the Claude Code recipe,
  `startup` and `clear` begin a new transcript. Unlike it, `compact` is left
  out: Codex shows every `systemMessage` as a warning, `PostCompact` already
  checks the compacted transcript, and the `SessionStart` check reads at most
  128 KiB. Codex matchers are regular expressions; `auto|manual` covers both
  compaction triggers.
- `SessionEnd` uses `"timeout": 3`, the most Codex allows, and checks at most
  1 MiB for SL009. If a slow host still runs past three seconds, Codex reports
  a hook failure; SessionEnd hooks are advisory, so the session still ends.
  `PostCompact` keeps the five-second timeout of the Claude Code recipe.
- `commandWindows` omits `|| true` because Windows hooks may run in PowerShell
  or `cmd.exe`, where `|| true` itself fails. `sesslint hook` exits `0` on
  findings, skips, and bad stdin, so a working setup never shows a hook error.
  A missing `sesslint`, or one older than 0.5.0, exits non-zero; Codex then
  shows a hook error instead of the `systemMessage`, and the session goes on.
- `command` keeps `|| true` and so needs a session shell that accepts POSIX
  `||`, as `sh`, `bash`, `zsh`, and `fish` do.
- `--fail-on` turns a finding into exit `1`, but that does not gate Codex:
  the hook is reported as failed, its `systemMessage` is dropped, and neither
  the session nor the compaction stops. Gate with `sesslint check` or
  `sesslint.precheck` instead.
- Codex also reads inline `[hooks]` tables from `config.toml`; these blocks
  are for `hooks.json`.
- Requires SessLint 0.5.0 or later on `PATH` — check `sesslint version`.
  Output stays content-free, as described under Content-free guarantee above.

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
— and stays quiet otherwise. With `--json` each line is a
`sesslint.watch-event/v1` object (`schemas/sesslint.watch-event.v1.json`).
Watch is a pure observer: it never writes to
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
| `sesslint_precheck` | `{ok, reason, exit_code}` gate result plus the report (`schemas/sesslint.precheck-result.v1.json`) |
| `sesslint_scan` | `sesslint.scan-report/v1` 5-bucket aggregate for a file or directory tree |
| `sesslint_triage` | `sesslint.triage/v1` diagnosis (`schemas/sesslint.triage.v1.json`) for one session file — the same document as `sesslint triage <path> -f json`; previews are never applied |

Each tool takes `path` (required), plus optional `profile` (`neutral`,
`claude-strict`, `openai-strict`) and `format` adapter override. Missing
paths and tool failures return `isError: true` results with content-free
reason strings (`sesslint_triage`, like `sesslint_check`, requires a file: a
directory is a `usage-error`, a missing path an `io-error`); protocol problems return JSON-RPC error objects. The server
adds no timestamps — identical requests produce identical responses.
EOF or Ctrl+C exits cleanly.

## Editor problem-matchers

`contrib/editors/problem-matcher.json` ships a two-line problemMatcher so
`sesslint check`/`scan` human output becomes click-to-line navigation in
VS Code, Zed, and compatible editors. Setup notes per editor plus a
`tasks.json` example live in [`contrib/editors/README.md`](https://github.com/HPNChanel/sesslint/blob/main/contrib/editors/README.md).
Path caveat: human output minimizes paths for privacy — use
workspace-relative inputs for clickable navigation.

## Runtime hook surfaces

Which agent runtimes expose a user-facing hook surface whose stdin
payload `sesslint hook` can read (verified 2026-09, Codex row 2026-10-22 —
re-checked each release):

| Runtime | Hook surface | Payload carries `transcript_path` | SessLint recipes |
| :--- | :--- | :--- | :--- |
| Claude Code | `settings.json` `hooks` | Yes — all events | Emitted (`sesslint hook --init --agent claude`) *(next release)* |
| Codex | `~/.codex/hooks.json`, `config.toml [hooks]` | Yes — all events | Emitted (`sesslint hook --init --agent codex`) *(next release)* |
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
