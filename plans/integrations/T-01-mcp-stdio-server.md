# T-01: MCP stdio server (`sesslint mcp`)

- Status: done
- Phase: integrations
- Priority: P2
- Type: feature (new surface; stdio JSON-RPC; zero-dep)
- Depends on: —
- Primary targets:
  - `src/sesslint/mcp_server.py` (new)
  - `src/sesslint/cli.py` (`mcp` subcommand)
  - `tests/` (JSON-RPC conformance tests)
  - `docs/INTEGRATIONS.md`, `README.md`, `CHANGELOG.md`

## Goal

`sesslint mcp` runs a Model Context Protocol server over stdio so Claude
Code / Codex (which natively consume MCP servers) can call SessLint
checks directly — presence inside the agent loop with zero runtime
dependencies.

## Verified Problem / Current Evidence

- MCP is JSON-RPC 2.0 over stdio: `initialize` → `tools/list` →
  `tools/call` — implementable entirely with stdlib `json` +
  `sys.stdin.buffer`/`sys.stdout.buffer`. No SDK required.
- This is the single largest "presence" surface available offline: the
  agent itself becomes able to precheck sessions it writes.

## Required Design / Decisions

1. `sesslint mcp` subcommand: newline-delimited JSON-RPC 2.0 loop on
   stdio (read line → dispatch → write response). Content-Length-framed
   transport variant decided at impl against current MCP spec revision —
   pin the implemented revision in code + docs.
2. Tools exposed (v1, all read-only): `sesslint_check(path, profile?)`,
   `sesslint_precheck(path)`, `sesslint_scan(path)` — each returns the
   existing JSON report shape as structured content (no payload content,
   same content-free contract).
3. Server metadata: name `sesslint`, version = package version;
   `initialize` advertises `tools` capability only (no resources/prompts
   in v1).
4. Errors: JSON-RPC error objects for bad params; check findings are
   *results*, not errors (a corrupted file is a successful call
   reporting findings — correct MCP semantics).
5. Security posture: stdio only, no sockets, no auth surface; the server
   validates every input path exists and stays within argument-provided
   roots (no ambient directory access); the *client* decides trust —
   documented.
6. Determinism: identical requests → identical responses; server adds
   no timestamps to tool results.

## Ordered Implementation Steps

1. `mcp_server.py`: JSON-RPC dispatch, initialize handshake,
   tools/list (static tool descriptors), tools/call routing to
   `api.check_file`/`api.precheck`/`api.scan` equivalents.
2. CLI `mcp` wiring; `sesslint mcp` documented as long-running process
   (Ctrl+C/SIGTERM clean exit).
3. Conformance tests: recorded MCP message sequences (initialize,
   tools/list, tools/call success + param-error) replayed through the
   dispatcher deterministically.
4. Docs: INTEGRATIONS section — client config snippet (print example
   only; SessLint never writes client config), tool list, contract.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k mcp
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"<pinned>","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}\n' | uv run sesslint mcp
```

## Acceptance Criteria

- Recorded conformance sequence passes: initialize handshake returns
  server info + tools capability; tools/list returns the three tools;
  tools/call on a corrupted fixture returns findings in structured
  content; malformed JSON-RPC → error object, no crash.

## Rollback / Stop Conditions

- Stop if the current MCP spec revision cannot be satisfied with pure
  stdio semantics — ship only the revision that passes conformance,
  documented explicitly.

## Risks

- MCP spec churn → pin implemented `protocolVersion`; unknown-version
  clients get a spec-correct negotiate/error path.
- Tool-call path arguments are client-controlled → same filesystem
  exposure as the CLI itself (documented; the agent already runs as the
  user).

## Out of Scope

- HTTP/SSE transports, resources/prompts, notifications beyond spec
  requirements, auth, any network listener.
