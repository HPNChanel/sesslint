# SessLint Adapter & Profile Compatibility Matrix

This matrix documents the support status across SessLint format adapters and validation profiles (TASK-028, FR-037, FR-038).

---

## Compatibility Matrix

| Adapter | Description | Default Profile | `neutral` | `claude-strict` | `openai-strict` | Version / Format |
|---|---|---|---|---|---|---|
| `canonical` | Native SessLint session interchange | `neutral` | Supported | Supported | Supported | `sesslint.session/v1` |
| `claude-code-jsonl` | Anthropic Claude Code transcript streams | `neutral` | Supported | Supported | Unsupported | Multi-turn JSONL |
| `openai-agents` | OpenAI Agents SDK session JSON | `neutral` | Supported | Unsupported | Supported | Agents SDK JSON |
| `codex-rollout` | Codex CLI/Desktop `rollout-*.jsonl` streams | `neutral` | Supported | Unsupported | Supported | Envelope JSONL |

---

## Profile Definitions

### 1. `neutral`
- **Description**: Vendor-neutral baseline profile using standard generic rules and default thresholds.
- **Allowed Adapters**: `canonical`, `claude-code-jsonl`, `openai-agents`, `codex-rollout`
- **Confidence Threshold**: `0.55`, Margin: `0.15`
- **Strict Unknown Critical**: `False`
- **Checkpoint Sensitivity**: `default`

### 2. `claude-strict`
- **Description**: Strict profile for Claude Code sessions with tight format margins and strict version checks.
- **Allowed Adapters**: `claude-code-jsonl`, `canonical`
- **Confidence Threshold**: `0.55`, Margin: `0.20`
- **Strict Unknown Critical**: `True`
- **Checkpoint Sensitivity**: `default`

### 3. `openai-strict`
- **Description**: Strict profile for OpenAI Agents SDK sessions with high checkpoint sensitivity.
- **Allowed Adapters**: `openai-agents`, `codex-rollout`, `canonical`
- **Confidence Threshold**: `0.55`, Margin: `0.15`
- **Strict Unknown Critical**: `True`
- **Checkpoint Sensitivity**: `high`

---

## Codex Rollout Notes (DW-T-12)

- `codex-rollout` joins `openai-strict` because Codex is an OpenAI-ecosystem
  format; it inherits strict unknown-critical handling (`SL302`) and strict
  adjacency (`SL107` = ERROR).
- Codex rollouts interleave asynchronous tool activity (`exec` custom tool
  calls, agent-comm `send_message`/`wait` function calls) by design — call
  and result are routinely separated by many records. Non-adjacent pairings
  therefore flag `SL107` as WARNING under `neutral` and ERROR under
  `openai-strict`; this is by-design strictness, not adapter malfunction.
  The corruption-pairing signals that matter for rollouts are `SL101`
  (orphan result), `SL102` (dangling call), `SL103`/`SL104` (multiplicity),
  `SL105` (reversed order), and `SL106` (cross-branch).
