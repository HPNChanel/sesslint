# Editor problem-matchers *(next release)*

Reusable problem-matchers for `sesslint check`/`sesslint scan` **human**
output — click-to-line navigation in any editor that speaks the
problemMatcher convention (VS Code, Zed, forks, most CI log viewers).

## What it matches

SessLint human findings render two consecutive lines per finding:

```text
  [SL102] Dangling tool call (ERROR, manual)
    Span:        path/to/session.jsonl:2
```

`problem-matcher.json` is a two-line multiline matcher: the first pattern
captures `code` / `message` / `severity` from the `[CODE] message (SEVERITY, ...)`
header; the second captures `file` / `line` from the `Span:` line (the
optional `(bytes N-M)` suffix is ignored).

## VS Code

Reference the matcher file from a `tasks.json` task (user-pasted — SessLint
never writes editor config):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "sesslint check",
      "type": "shell",
      "command": "sesslint",
      "args": ["check", "${file}"],
      "problemMatcher": {
        "owner": "sesslint",
        "source": "sesslint",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": [
          {
            "regexp": "^\\s*\\[(SL[0-9A-Z]+)\\]\\s+(.+?)\\s*\\((ERROR|FATAL|WARNING|INFO),\\s*[^)]+\\)\\s*$",
            "code": 1,
            "message": 2,
            "severity": 3
          },
          {
            "regexp": "^\\s*Span:\\s+(.+?):(\\d+)(?:\\s+\\(bytes\\s+\\d+-\\d+\\))?\\s*$",
            "file": 1,
            "line": 2
          }
        ]
      }
    }
  ]
}
```

Or point `problemMatcher` at the JSON file directly when your editor
supports external matcher files:

```json
"problemMatcher": { "$ref": "contrib/editors/problem-matcher.json" }
```

## Generic regex (other editors / CI logs)

- Header: `^\s*\[(SL[0-9A-Z]+)\]\s+(.+?)\s*\((ERROR|FATAL|WARNING|INFO),\s*[^)]+\)\s*$`
- Location: `^\s*Span:\s+(.+?):(\d+)`

## Path caveat (by design)

Human output minimizes paths for privacy (`~/x`, `.._<hash>/name`).
Click-to-line resolves cleanly for **workspace-relative** paths and
`~/`-minimized paths under the user home; hash-minimized paths
(`.._<hash>`) are deliberately non-reversible — run the command on a
workspace-relative path, or consume `--json` output which carries the
same minimized `source.path` plus `source.line` fields for direct
mapping.

## A real VS Code extension?

A dedicated extension would wrap the CLI via `--json` output (never parse
human text) and lives in a **separate repository** — tracked as a future
integration, not part of this package.
