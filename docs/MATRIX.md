# SessLint Adapter & Profile Compatibility Matrix

This matrix documents the support status across SessLint format adapters and validation profiles (TASK-028, FR-037, FR-038).

---

## Compatibility Matrix

| Adapter | Description | Default Profile | `neutral` | `claude-strict` | `openai-strict` | Version / Format |
|---|---|---|---|---|---|---|
| `canonical` | Native SessLint session interchange | `neutral` | Supported | Supported | Supported | `sesslint.session/v1` |
| `claude-code-jsonl` | Anthropic Claude Code transcript streams | `neutral` | Supported | Supported | Unsupported | Multi-turn JSONL |
| `openai-agents` | OpenAI Agents SDK session JSON | `neutral` | Supported | Unsupported | Supported | Agents SDK JSON |

---

## Profile Definitions

### 1. `neutral`
- **Description**: Vendor-neutral baseline profile using standard generic rules and default thresholds.
- **Allowed Adapters**: `canonical`, `claude-code-jsonl`, `openai-agents`
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
- **Allowed Adapters**: `openai-agents`, `canonical`
- **Confidence Threshold**: `0.55`, Margin: `0.15`
- **Strict Unknown Critical**: `True`
- **Checkpoint Sensitivity**: `high`
