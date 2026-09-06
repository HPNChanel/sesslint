<![CDATA[<div align="center">

<br>

```
                         ╭─────────────────────────────────╮
                         │                                 │
                         │   ███████╗███████╗███████╗███████╗██╗     ██╗███╗   ██╗████████╗   │
                         │   ██╔════╝██╔════╝██╔════╝██╔════╝██║     ██║████╗  ██║╚══██╔══╝   │
                         │   ███████╗█████╗  ███████╗███████╗██║     ██║██╔██╗ ██║   ██║      │
                         │   ╚════██║██╔══╝  ╚════██║╚════██║██║     ██║██║╚██╗██║   ██║      │
                         │   ███████║███████╗███████║███████║███████╗██║██║ ╚████║   ██║      │
                         │   ╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝      │
                         │                                 │
                         ╰─────────────────────────────────╯
```

**Offline, vendor-neutral session-integrity checker and conservative repair tool<br>for tool-using AI agent sessions.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#requirements)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](#license)
[![Zero Dependencies](https://img.shields.io/badge/runtime_deps-zero-brightgreen?style=flat-square)](#architecture)
[![Tests](https://img.shields.io/badge/tests-600%2B_passed-success?style=flat-square)](#testing)
[![Strict Typing](https://img.shields.io/badge/mypy-strict-purple?style=flat-square)](#development)

---

*When crashes, partial appends, or context compactions corrupt tool pairing or parent links,<br>
providers return `400 errors`. A retry fails — or worse, duplicates side effects.<br>
SessLint finds those breaks and fixes what can be safely fixed.*

<br>
</div>

---

## Table of Contents

- [The Problem](#the-problem)
- [What SessLint Does](#what-sesslint-does)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Supported Formats](#supported-formats)
- [Diagnostic Codes](#diagnostic-codes)
- [Repair Engine](#repair-engine)
- [Replay Profiles](#replay-profiles)
- [Architecture](#architecture)
- [Library API](#library-api)
- [Schemas](#schemas)
- [Testing](#testing)
- [Development](#development)
- [Project Stats](#project-stats)
- [License](#license)

---

## The Problem

Tool-using AI agent sessions (Claude Code, OpenAI Agents SDK, Copilot CLI, PydanticAI, etc.) are **durable execution ledgers**. Each session records a precise sequence of user prompts, model responses, tool calls, tool results, checkpoints, and branching decisions.

When something goes wrong — a crash mid-write, a network timeout, a context compaction that splits a tool call from its result — the session file becomes structurally corrupt. The provider API rejects the malformed history with errors like:

```
tool_use ids were found without tool_result blocks
```

At that point, you face a choice: lose the session entirely, or manually edit JSON hoping you don't make things worse. **SessLint automates the "make things better without making things worse" part.**

<br>

## What SessLint Does

SessLint validates and repairs AI agent session files through **four layers of correctness**:

<table>
<tr>
<td width="25%" align="center"><strong>Syntactic Integrity</strong><br><sub>Valid JSON/JSONL records,<br>encoding, structure</sub></td>
<td width="25%" align="center"><strong>Structural Integrity</strong><br><sub>Consistent IDs, parent DAG,<br>tool call/result pairing</sub></td>
<td width="25%" align="center"><strong>Replay Integrity</strong><br><sub>Valid under a specific provider<br>profile (Anthropic / OpenAI)</sub></td>
<td width="25%" align="center"><strong>Side-Effect Truth</strong><br><sub>SessLint abstains from guessing<br>whether tools actually ran</sub></td>
</tr>
</table>

**Key guarantees:**

- **Source immutability** — `check` and `repair --dry-run` create zero files and change zero bytes.
- **No synthetic results** — Never invents tool results, approvals, or model answers.
- **No code execution** — Never executes code, shell commands, or model calls found in sessions.
- **100% offline** — No telemetry, no network calls, no remote flags.
- **Content-free reports** — No prompts, code, credentials, or tool arguments in output by default.
- **Zero runtime dependencies** — Pure Python 3.11+ standard library.

<br>

## Quick Start

### Installation

```bash
# From source (recommended during alpha)
pip install -e .

# Or with pipx for CLI-only usage
pipx install .

# Verify installation
sesslint --version
```

### Basic Usage

```bash
# Check a session file for integrity issues
sesslint check session.jsonl

# Check with a specific provider profile
sesslint check session.jsonl --profile claude-strict

# Dry-run a repair plan (writes nothing)
sesslint repair session.jsonl --dry-run

# Execute a repair with verified output
sesslint repair session.jsonl --output repaired.jsonl

# Get machine-readable output
sesslint repair session.jsonl --output repaired.jsonl --json
```

<br>

## CLI Reference

```
sesslint [--version] [--format FORMAT] [--profile PROFILE] [--policy POLICY] COMMAND
```

### Commands

<details>
<summary><strong><code>sesslint check &lt;path&gt;</code></strong> — Validate a session file</summary>

```
sesslint check <path> [--format auto|claude-code-jsonl|openai-agents|canonical]
                      [--profile neutral|claude-strict|openai-strict]
                      [--confidence-min FLOAT]
                      [--margin-min FLOAT]
```

Runs format auto-detection, canonicalization, and all 20 diagnostic rules against the session file. Reports findings to stderr (human) or stdout (`--json`).

</details>

<details>
<summary><strong><code>sesslint repair &lt;path&gt;</code></strong> — Safely repair a session file</summary>

```
sesslint repair <path> --output <new-file>
                       [--dry-run]
                       [--policy conservative|salvage]
                       [--format auto|claude-code-jsonl|openai-agents|canonical]
                       [--profile neutral|claude-strict|openai-strict]
                       [--plan <plan.json>]
                       [--acknowledge-side-effects]
                       [--json]
```

Plans and executes a repair with atomic file operations. `--output` is required (source is never modified in place). The repair engine writes to a temp file, validates the output, then atomically renames — guaranteeing either the complete repaired file or nothing.

</details>

<details>
<summary><strong><code>sesslint validate-session &lt;path&gt;</code></strong> — Schema validation</summary>

```
sesslint validate-session <path>
```

Validates a canonical session file against the `sesslint.session/v1` JSON schema.

</details>

<details>
<summary><strong><code>sesslint scan</code></strong> — Inspect reader limits</summary>

```
sesslint scan --show-limits
```

Displays the hostile-input reader limits (max line bytes, nesting depth, file size, record count).

</details>

### Exit Codes

| Code | Meaning |
|:----:|---------|
| `0`  | Success — valid session, clean check, or successful repair with verified manifest |
| `1`  | Findings exist — structural errors detected, repair refused, or no safe plan available |
| `2`  | Usage error — invalid flags, file not found, I/O error, or permission denied |

<br>

## Supported Formats

SessLint uses fail-closed automatic format detection with configurable confidence thresholds:

| Format | Adapter ID | Description |
|--------|-----------|-------------|
| **Claude Code** | `claude-code-jsonl` | Claude Code session logs (`.jsonl`) |
| **OpenAI Agents SDK** | `openai-agents` | Exported items and run state (`.json`) — read-only, never mutates live databases |
| **SessLint Canonical** | `canonical` | Vendor-neutral canonical format (`sesslint.session/v1`) |

**Safety gates in auto-detection:**
- SQLite database headers are detected and hard-refused (prevents accidental live-store mutation)
- Empty/whitespace-only files are rejected
- Ambiguous format ties fail closed with `SL302`

<br>

## Diagnostic Codes

SessLint defines **20 stable diagnostic codes** across 5 categories. Severity and repairability are independent axes — a warning can be unrepairable, and an error can be deterministically fixable.

### Syntax — `SL001`–`SL002`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL001` | Malformed record | `error` | `manual` |
| `SL002` | Torn terminal record | `error` | `deterministic` |

### Identity — `SL003`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL003` | Duplicate event ID | `warning` | `deterministic` |

### Graph — `SL004`–`SL007`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL004` | Missing parent | `error` | `manual` |
| `SL005` | Parent cycle | `fatal` | `unsupported` |
| `SL006` | Disconnected branch | `warning` | `manual` |
| `SL007` | Ambiguous session head | `warning` | `manual` |

### Tool Pairing — `SL101`–`SL108`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL101` | Orphan tool result | `error` | `manual` |
| `SL102` | Dangling tool call | `error` | `manual` |
| `SL103` | Reused tool-call ID | `error` | `manual` |
| `SL104` | Multiple tool results | `error` | `manual` |
| `SL105` | Tool result precedes call | `error` | `manual` |
| `SL106` | Cross-branch tool pairing | `error` | `manual` |
| `SL107` | Provider adjacency violation | `warning` | `manual` |
| `SL108` | Compaction split pair | `warning` | `manual` |

### Checkpoint — `SL201`–`SL203`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL201` | Checkpoint/history divergence | `error` | `manual` |
| `SL202` | Accepted terminal output not durable | `error` | `manual` |
| `SL203` | Unknown side-effect state | `error` | `manual` |

### Compatibility — `SL301`–`SL302`

| Code | Name | Severity | Repairability |
|:----:|------|:--------:|:-------------:|
| `SL301` | Unsupported format version | `error` | `unsupported` |
| `SL302` | Unknown critical record | `error` | `manual` |

<br>

## Repair Engine

The repair system is designed around **one core principle**: never make things worse.

### Two Policies

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   conservative (default)                                        │
│   ├── Only deterministic, non-lossy transformations             │
│   ├── Hard stop on SL203 (unknown side-effects)                 │
│   └── Never synthesizes tool results or approvals               │
│                                                                 │
│   salvage (explicit --policy salvage)                            │
│   ├── Accepts controlled data loss to unblock sessions          │
│   ├── Records loss accounting in plan and manifest              │
│   └── SL102 requires --acknowledge-side-effects                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Conservative Recipes

| Recipe | Handles | What it does |
|--------|---------|-------------|
| `terminal-suffix-discard` | SL002 | Drops trailing torn bytes after the last complete record |
| `identical-duplicate-collapse` | SL003 | Collapses adjacent byte-identical events |
| `proven-unique-parent-restore` | SL004 | Reattaches a missing parent when exactly one candidate exists |
| `compaction-projection-reunion` | SL108 | Reunites call/result pairs split by compaction boundaries |
| `duplicate-projection-removal` | SL104 | Drops identical duplicate tool result projections |

### Salvage Recipes

| Recipe | Handles | What it does |
|--------|---------|-------------|
| `unresolvable-branch-amputate` | SL005, SL006 | Drops unreachable or cyclical branches |
| `torn-compaction-project` | SL108 | Resolves split compaction by dropping orphaned halves |
| `side-effect-unknown-truncate` | SL102 | Truncates before unproven side-effecting call |

### Atomic Execution Protocol

Every repair follows an **8-step protocol** that guarantees either complete success or zero damage:

```
1. Re-validate     ──  Plan fingerprint, policy match, TOCTOU abstention check
2. Pre-hash        ──  SHA-256 of source; validate destination (refuse self/existing/live-store)
3. Apply           ──  Sequential recipe execution in memory
4. Validate output ──  Schema parse + multiset check + SL203 re-scan + profile revalidation
5. Atomic write    ──  temp file → fsync → os.replace (same filesystem)
6. Post-hash       ──  Verify source unchanged; record output hash
7. Cleanup         ──  Any failure unlinks temp; source untouched
8. Manifest        ──  Emit sesslint.repair-manifest/v1 with cryptographic hash bindings
```

### Assurance Levels

| Level | Name | Meaning |
|:-----:|------|---------|
| A0 | Unreadable | Adapter cannot safely parse the artifact |
| A1 | Parseable | Records decoded and canonicalized; relationships may be invalid |
| A2 | Structurally valid | Graph, identity, pairing, and ordering invariants pass |
| A3 | Profile-replay valid | History satisfies selected versioned replay profile |
| A4 | Reference-loader equivalent | Structural projection verified with reference loader |

<br>

## Replay Profiles

Profiles encode provider-specific placement, adjacency, and compaction rules:

| Profile | Allowed Adapters | Strictness | Use Case |
|---------|-----------------|:----------:|----------|
| `neutral` | All | Standard | Vendor-neutral baseline validation |
| `claude-strict` | Claude, Canonical | High | Tight format margins, strict version checks |
| `openai-strict` | OpenAI, Canonical | High | High checkpoint sensitivity |

```bash
# Validate against Claude's strict replay rules
sesslint check session.jsonl --profile claude-strict

# Validate against OpenAI's checkpoint requirements
sesslint check items.json --profile openai-strict
```

<br>

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLI  (argparse — thin flag parser, exit codes, stream routing)         │
├──────────────────────────────────────────────────────────────────────────┤
│  Library API  (same engine as CLI — full parity)                        │
├──────────────────────────────────────────────────────────────────────────┤
│  Reporting & Manifest                                                   │
│  ├── sesslint.report/v1 (human + JSON)                                  │
│  └── sesslint.repair-manifest/v1 (hash bindings + audit trail)          │
├──────────────────────────────────────────────────────────────────────────┤
│  Repair Engine                                                          │
│  ├── Executor (sole file mutator — temp → fsync → atomic rename)        │
│  ├── Planner (dry-run, fingerprinted, zero I/O)                         │
│  └── Recipes (conservative + salvage, registered, preconditioned)       │
├──────────────────────────────────────────────────────────────────────────┤
│  Validation Engine                                                      │
│  ├── Generic Rules  (SL001–SL203, vendor-free)                          │
│  ├── Adapter Rules  (SL301–SL302, format-specific)                      │
│  └── Profiles       (neutral / claude-strict / openai-strict)           │
├──────────────────────────────────────────────────────────────────────────┤
│  Canonical Model  (vendor-neutral event graph + provenance)             │
├──────────────────────────────────────────────────────────────────────────┤
│  Adapters  (Claude JSONL / OpenAI export / Canonical v1)                │
├──────────────────────────────────────────────────────────────────────────┤
│  I/O + Streaming + Hashing  (bounded, hostile-input safe, stdlib)       │
└──────────────────────────────────────────────────────────────────────────┘
```

**Dependency rule:** layers point inward only. Adapters depend on the canonical model, never the reverse. Generic rules never import adapters. Profiles are data-only. Any vendor-specific conditional outside adapters is a defect.

<br>

## Library API

SessLint exposes the same engine used by the CLI as a Python library:

```python
import sesslint

# Load and validate a session
session = sesslint.load_session_file("session.jsonl")
print(f"Session: {session.header.session_id}")
print(f"Events:  {len(session.events)}")

# Inspect diagnostic codes
for code in sorted(sesslint.ALL_CODES):
    info = sesslint.get_code_info(code)
    print(f"  {info.code}  {info.name:<40}  {info.default_severity.value}")

# Build a report
report = sesslint.build_report(
    findings=findings,
    source_path="session.jsonl",
    adapter="claude-code-jsonl",
    profile="claude-strict",
)
print(sesslint.dump_report(report))

# Source fingerprinting and guarded reads
with sesslint.guard("session.jsonl") as g:
    events = list(sesslint.guarded_iter_events(g))
    # g.verify() raises SourceChangedError if file was modified during read
```

<br>

## Schemas

SessLint defines four versioned JSON schemas:

| Schema | File | Purpose |
|--------|------|---------|
| Session | `sesslint.session.v1.json` | Canonical vendor-neutral event model |
| Finding | `sesslint.finding.v1.json` | Individual diagnostic finding |
| Report | `sesslint.report.v1.json` | Aggregated validation report |
| Repair Manifest | `sesslint.repair-manifest.v1.json` | Cryptographic hash binding of source → plan → output |

Schemas are bundled in `schemas/` and installed to `share/sesslint/schemas/`.

<br>

## Testing

The test suite is comprehensive and adversarial:

```bash
# Run all tests
pytest

# Run specific test modules
pytest tests/repair/              # Repair engine tests
pytest tests/adapters/            # Adapter conformance tests
pytest tests/checks/              # Rule detector tests

# Static analysis
ruff check .                      # Linting
ruff format --check .             # Formatting
mypy --strict src/sesslint        # Strict type checking
```

**Test matrix includes:**
- Fixture-driven golden file comparisons for every detector and recipe
- Kill-safety simulation (fault-injection before atomic rename)
- TOCTOU race condition detection
- Hostile input corpus (BOM, CRLF, deep nesting, giant lines, torn tails)
- Single-mutator compliance grep (proves only `executor.py` calls `os.replace`)
- Source immutability verification (SHA-256 before/after)
- Full-disk ENOSPC simulation
- Property-based testing via Hypothesis

<br>

## Development

### Requirements

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Setup

```bash
# Clone and install with dev dependencies
git clone https://github.com/your-org/sesslint.git
cd sesslint

# Using uv (recommended)
uv sync --extra dev

# Or using pip
pip install -e ".[dev]"
```

### Verify

```bash
# Full verification pipeline
pytest -q                         # Unit + integration tests
ruff check .                      # Lint
ruff format --check .             # Format
mypy --strict src/sesslint        # Types
```

### Code Quality Standards

| Tool | Configuration | Enforcement |
|------|--------------|-------------|
| **ruff** | `target-version = "py311"`, line-length 100 | `E`, `W`, `F`, `I`, `B`, `UP` |
| **mypy** | `--strict`, `disallow_untyped_defs = true` | All source and test files |
| **pytest** | `pytest>=8` + `hypothesis>=6` | Fixture-driven, property-based |

<br>

## Project Stats

| Metric | Value |
|--------|-------|
| Source code | ~12,000 lines |
| Test code | ~14,000 lines |
| Test-to-code ratio | 1.13:1 |
| Diagnostic codes | 20 (SL001–SL302) |
| Repair recipes | 8 (5 conservative + 3 salvage) |
| Runtime dependencies | 0 |
| JSON schemas | 4 versioned |
| Supported formats | 3 adapters |
| Replay profiles | 3 built-in |

<br>

## License

```
Copyright 2026 SessLint Maintainers

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<div align="center">
<sub>Built with pure Python. Zero dependencies. Maximum paranoia.</sub>
</div>
]]>
