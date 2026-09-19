# SessLint Integrations Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for surfaces that put SessLint in front of users
  and tools. All integrations stay offline; generated artifacts are printed
  for the user to install — SessLint never writes agent configuration.
- Companion docs: `docs/INTEGRATIONS.md`, `STRATEGY.md` §2 (presence at the
  moment of pain), `plans/README.md`.

## Goal

Presence is the declared bottleneck (STRATEGY §1.2): users must encounter
the tool when corruption happens. This pack adds the surfaces: an MCP stdio
server agents can call natively, printable hook snippets, editor
integration via SchemaStore + problem matchers, and copy-paste CI templates
beyond GitHub Actions.

## Verified Facts

1. MCP is JSON-RPC 2.0 over stdio — implementable with the stdlib alone
   (`json`, `sys.stdin/stdout`); zero-dep constraint does not block it.
   Claude Code and Codex both consume MCP servers natively.
2. `docs/INTEGRATIONS.md` documents hook recipes but users must hand-edit
   `settings.json`; a `--print` generator removes transcription errors.
3. `sesslint.toml` has no published JSON Schema — editors cannot
   autocomplete or validate config.
4. GitHub Action exists (`.github/actions/sesslint-check`); GitLab CI,
   Azure Pipelines, CircleCI users have no template.
5. `completion.py` covers bash/zsh/fish; editor problem-matchers would let
   any IDE jump from findings to file:line.

## Constraints And Non-Goals

- MCP server is stdio JSON-RPC only — no HTTP transport, no network socket,
  no auth surface.
- `init-hooks` prints snippets; it never writes `settings.json`, hooks, or
  any agent-owned file (documented invariant).
- SchemaStore submission is an external manual step documented in-repo; the
  schema itself ships in `schemas/` and is tested here.
- Problem matchers are contributed files users copy; the VS Code extension,
  if ever built, is a separate repository (dev tooling, not runtime).

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | MCP stdio server (`sesslint mcp`) | P2 | — |
| T-02 | `sesslint init-hooks --print` snippet generator | P1 | — |
| T-03 | `sesslint.toml` JSON Schema + SchemaStore submission | P1 | — |
| T-04 | Editor problem-matchers + VS Code skeleton notes | P3 | — |
| T-05 | CI templates (GitLab / Azure / CircleCI) | P2 | — |

## Validation

Per task: JSON-RPC conformance tests (recorded MCP message sequences),
determinism tests for generated snippets/schemas, docs sync.
