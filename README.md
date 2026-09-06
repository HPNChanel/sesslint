<<<<<<< HEAD
<h1 align="center">SessLint</h1>

<p align="center">
  <strong>Offline, vendor-neutral session-integrity checker and conservative repair engine for tool-using AI agents.</strong>
</p>

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/runtime_deps-zero-brightgreen?style=flat-square" alt="Zero Runtime Dependencies"></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-600%2B_passed-success?style=flat-square" alt="Tests Passing"></a>
  <a href="#development"><img src="https://img.shields.io/badge/mypy-strict-purple?style=flat-square" alt="Strict Typing"></a>
</p>

<p align="center">
  <em>When crashes, network timeouts, or context compactions corrupt tool pairing or parent DAG links,<br>
  LLM providers return 400 errors. SessLint diagnoses session breaks and repairs them safely with zero data loss.</em>
</p>
=======
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
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70

---

## Table of Contents

- [The Problem](#the-problem)
<<<<<<< HEAD
- [Core Invariants & Guarantees](#core-invariants--guarantees)
- [Four Layers of Correctness](#four-layers-of-correctness)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [Command Matrix](#command-matrix)
  - [Exit Codes](#exit-codes)
- [Supported Formats](#supported-formats)
- [Diagnostic Reason Codes (SL001–SL302)](#diagnostic-reason-codes-sl001sl302)
- [Repair Engine](#repair-engine)
  - [Policies: Conservative vs. Salvage](#policies-conservative-vs-salvage)
  - [Recipe Catalog](#recipe-catalog)
  - [Atomic 8-Step Execution Protocol](#atomic-8-step-execution-protocol)
  - [Assurance Taxonomy (A0–A4)](#assurance-taxonomy-a0a4)
- [Replay Profiles](#replay-profiles)
- [Architecture & Anti-Leak Boundaries](#architecture--anti-leak-boundaries)
- [Python Library API](#python-library-api)
- [JSON Schemas](#json-schemas)
- [Test Suite & Verification](#test-suite--verification)
=======
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
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70
- [License](#license)

---

## The Problem

<<<<<<< HEAD
Tool-using AI agent sessions (e.g., Claude Code, OpenAI Agents SDK, Copilot CLI, PydanticAI) are **durable execution ledgers**. Every interaction records an ordered sequence of user intents, model completions, tool calls, tool results, memory compactions, and continuation checkpoints.

When a process crashes mid-append, a network stream disconnects, or context window compaction splits an atomic pair, the serialized session file becomes structurally corrupted. LLM providers reject the replayed history:

```text
anthropic.BadRequestError: 400 - tool_use ids were found without tool_result blocks
openai.BadRequestError: 400 - Invalid message sequence: tool_call_id mismatch
```

A blind retry fails or causes duplicate external side-effects (e.g., re-running database migrations or duplicate API calls). **SessLint acts as a compiler-grade linter and surgical repair tool** for agent sessions before replay.

---

## Core Invariants & Guarantees

> [!IMPORTANT]
> **The Bottom Line on Safety & Atomicity**
>
> 1. **Source Immutability**: SessLint never modifies user files in-place. `check` and `repair --dry-run` perform zero file writes.
> 2. **Single Mutator**: File mutation is strictly isolated to a single atomic executor (`repair/executor.py`) via `tempfile` &rarr; `os.fsync` &rarr; `os.replace`.
> 3. **Kill-Safety**: Any unhandled crash or `SIGKILL` at any point leaves the original source byte-identical with zero orphaned temporary files.
> 4. **No Synthetic Truth**: SessLint never fabricates tool results, approvals, or model answers.
> 5. **TOCTOU Protection**: Dual-hash SHA-256 verification ensures that changes to source files during execution immediately abort the pipeline.
> 6. **Zero Dependencies**: Pure Python 3.11+ standard library. 100% offline, zero telemetry, zero network calls.
> 7. **Privacy by Default**: Diagnostic reports and repair manifests are strictly content-free (prompts, code, keys, and tokens are scrubbed).

---

## Four Layers of Correctness

SessLint partitions session validity into four orthogonal tiers:

| Layer | Definition | SessLint Enforcement |
| :--- | :--- | :--- |
| **1. Syntactic** | Valid byte stream, valid JSON/JSONL syntax, UTF-8 adherence. | Bounded streaming parser, torn-tail detection (`SL001`, `SL002`). |
| **2. Structural** | Valid DAG parentage, unique identities, valid tool call/result pairing. | Identity checks, cycle detection, tool pairing rules (`SL003`–`SL108`). |
| **3. Replay** | Conformance to specific LLM provider turn and adjacency rules. | Provider replay profiles (`neutral`, `claude-strict`, `openai-strict`). |
| **4. Semantic & Side-Effect** | Whether an external side-effect actually executed in the real world. | **Explicit Abstention (`SL203`)**: SessLint refuses to guess unrecorded side effects. |

---
=======
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
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70

## Quick Start

### Installation

```bash
<<<<<<< HEAD
# Install with pip
pip install sesslint

# Or install in an isolated environment with pipx
pipx install sesslint
=======
# From source (recommended during alpha)
pip install -e .

# Or with pipx for CLI-only usage
pipx install .
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70

# Verify installation
sesslint --version
```

<<<<<<< HEAD
### 30-Second Workflow

```bash
# 1. Inspect and lint a session file (auto-detects format)
sesslint check session.jsonl

# 2. Check under a strict provider profile
sesslint check session.jsonl --profile claude-strict

# 3. Simulate repair plan without touching disk
sesslint repair session.jsonl --dry-run

# 4. Atomically repair and generate a cryptographically bound manifest
sesslint repair session.jsonl --output session.repaired.jsonl

# 5. Output structured machine-readable JSON for CI/CD pipelines
sesslint check session.jsonl --profile neutral > report.json
```

---

## CLI Reference

```text
sesslint [--version] COMMAND [OPTIONS]
```

### Command Matrix

#### `sesslint check`
Scan and validate session files for structural corruptions and provider rule violations.

```bash
sesslint check <path> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Session file path (`.json` or `.jsonl`). |
| `--format` | `choice` | `auto` | Force adapter: `auto`, `claude-code-jsonl`, `openai-agents`, `canonical`. |
| `--profile` | `string` | `neutral` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). |
| `--policy` | `choice` | `conservative` | Policy mode: `conservative`, `salvage`. |
| `--confidence-min` | `float` | `0.55` | Minimum auto-detection confidence threshold. |
| `--margin-min` | `float` | `0.15` | Minimum auto-detection margin above second-place format. |

#### `sesslint repair`
Plan and execute verified, atomic session repairs.

```bash
sesslint repair <path> --output <out_path> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Source session file to repair. |
| `--output` | `Path` | `None` | Distinct destination path (required unless `--dry-run`). |
| `--dry-run` | `flag` | `False` | Computes and displays plan; creates zero files on disk. |
| `--policy` | `choice` | `conservative` | `conservative` (zero data loss) or `salvage` (explicit lossy pruning). |
| `--plan` | `Path` | `None` | Path to a pre-computed plan JSON file to execute. |
| `--acknowledge-side-effects`| `flag` | `False` | Acknowledge unknown side effects (required for `SL102` salvage). |
| `--json` | `flag` | `False` | Emit machine-readable JSON plan or repair manifest. |

#### `sesslint validate-session`
Low-level canonical schema conformance check.

```bash
sesslint validate-session <path>
```

#### `sesslint scan`
Diagnostic inspector for hostile-input reader limits.

```bash
sesslint scan --show-limits
# Output: max_line_bytes=10MB, max_depth=64, max_file_bytes=500MB, max_records=250k
```

### Exit Codes

SessLint strictly implements predictable exit code semantics:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| `0` | **Success** | Clean check, or repair successfully executed, validated, and manifested. |
| `1` | **Finding / Refusal** | Diagnostic errors found, repair plan blocked, or execution refused (TOCTOU, `SL203`). |
| `2` | **Operational Error** | CLI syntax error, file not found, permission denied, or live DB path refusal. |

---

## Supported Formats

SessLint includes three production adapters with fail-closed auto-detection:

| Format Identifier | Source Description | Typical File Pattern | Live Store Policy |
| :--- | :--- | :--- | :--- |
| `claude-code-jsonl` | Anthropic Claude Code session logs | `*.jsonl` | Read-only |
| `openai-agents` | OpenAI Agents SDK export artifacts | `*.json` | SQLite live DB refused (`SQLITE_MAGIC`) |
| `canonical` | SessLint Canonical v1 standard | `*.json`, `*.jsonl` | Round-trip preserved |

> [!NOTE]
> **Live Store Protection**: If `--output` points to an active SQLite database (detected via SQLite format 3 header magic or `.sqlite`/`.db` extensions), SessLint **immediately aborts** with exit code `2` to protect live stores from corruption.

---

## Diagnostic Reason Codes (SL001–SL302)

SessLint implements **20 registered diagnostic codes**. Severity and repairability are maintained as independent dimensions.

### 1. Syntax & Framing
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL001`** | Malformed record | `error` | `manual` | Nonterminal malformed records block automated repair. |
| **`SL002`** | Torn terminal record | `error` | `deterministic` | Incomplete final append repairable via `terminal-suffix-discard`. |

### 2. Event Identity
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL003`** | Duplicate event ID | `warning` | `deterministic` | Identical duplicates are safely collapsed; conflicting duplicates escalate to `error`/`manual`. |

### 3. Graph Lineage & DAG Consistency
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL004`** | Missing parent | `error` | `manual` | Repair requires a proven, unique candidate predecessor. |
| **`SL005`** | Parent cycle | `fatal` | `unsupported` | Causal cycles invalidate DAG ordering; fatal by default. |
| **`SL006`** | Disconnected branch | `warning` | `manual` | Unreachable subtrees require manual review before pruning. |
| **`SL007`** | Ambiguous session head | `warning` | `manual` | Multiple leaf heads require operator branch selection. |

### 4. Tool Call & Result Pairing
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL101`** | Orphan tool result | `error` | `manual` | Result has no corresponding call in the active branch. |
| **`SL102`** | Dangling tool call | `error` | `manual` | Call has no result. Execution status is unknown. |
| **`SL103`** | Reused tool-call ID | `error` | `manual` | Conflicting parameters mapped to identical call IDs. |
| **`SL104`** | Multiple tool results | `error` | `manual` | Multiple results for one call (race condition or retries). |
| **`SL105`** | Result precedes call | `error` | `manual` | Temporal/causal inversion under provider profile. |
| **`SL106`** | Cross-branch pairing | `error` | `manual` | Call and result belong to incompatible interaction scopes. |
| **`SL107`** | Adjacency violation | `warning` | `manual` | Violates provider turn ordering or placement rules. |
| **`SL108`** | Compaction split pair | `warning` | `manual` | Context compaction marker separated an atomic pair. |

### 5. Checkpoints & Continuation
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL201`** | Checkpoint divergence | `error` | `manual` | Serialized continuation state disagrees with history. |
| **`SL202`** | Non-durable output | `error` | `manual` | Accepted output absent from durable session history. |
| **`SL203`** | Unknown side-effect | `error` | `manual` | **Hard Stop**: Automated repair must abstain if side effects are unknown. |

### 6. Format Compatibility
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL301`** | Unsupported version | `error` | `unsupported` | Schema version unrecognized; never guesses fallback version. |
| **`SL302`** | Unknown critical record | `error` | `manual` | Unrecognized record participates in core semantics. |

---

## Repair Engine

### Policies: Conservative vs. Salvage

```text
               ┌────────────────────────────────────────────────┐
               │              Input Session Finding             │
               └───────────────────────┬────────────────────────┘
                                       │
                         Is Side-Effect Unknown (SL203)?
                                      ╱ ╲
                                    YES  NO
                                    ╱     ╲
        ┌──────────────────────────┐       ┌────────────────────────────────┐
        │ Conservative: ABSTAIN    │       │ Check Policy Configuration     │
        │ Salvage: Explicit ACK    │       └───────────────┬────────────────┘
        └──────────────────────────┘                       │
                                           ┌───────────────┴────────────────┐
                                           ▼                                ▼
                              [--policy conservative]               [--policy salvage]
                                 Deterministic Only                 Controlled Lossy Pruning
                                 No data loss                       Prunes dead branches
```

### Recipe Catalog

#### Conservative Recipes (Default)
- **`terminal-suffix-discard`** (`SL002`): Truncates incomplete trailing bytes after the last validated record boundary.
- **`identical-duplicate-collapse`** (`SL003`): Deduplicates adjacent byte-identical events.
- **`proven-unique-parent-restore`** (`SL004`): Reattaches missing parent pointers when exactly one unambiguous ancestor exists.
- **`compaction-projection-reunion`** (`SL108`): Relocates compaction markers to reunite split tool call/result pairs.
- **`duplicate-projection-removal`** (`SL104`): Discards duplicate identical result projections.

#### Salvage Recipes (Explicit Opt-In)
- **`unresolvable-branch-amputate`** (`SL005`, `SL006`): Prunes dead-end cyclic or unreachable branches lacking checkpoints.
- **`torn-compaction-project`** (`SL108`): Resolves asymmetric compaction splits by dropping orphaned half-turns.
- **`side-effect-unknown-truncate`** (`SL102`): Truncates session immediately before an unresolvable tool call (requires `--acknowledge-side-effects`).

---

### Atomic 8-Step Execution Protocol

Repair execution is guaranteed atomic across all platforms:

```text
[Step 1] Pre-Validation ──> Fingerprint check + TOCTOU abstention scan + policy verification
[Step 2] Source Hashing ──> SHA-256 pre-hash of source + destination pre-flight checks
[Step 3] Apply Recipes  ──> Pure in-memory sequential execution of fingerprinted plan
[Step 4] Revalidation   ──> Output schema parse + multiset parity + zero SL203 check
[Step 5] Atomic Commit  ──> Write <target>.tmp.<pid>.<rand> ──> fsync ──> os.replace
[Step 6] Post-Hashing   ──> Verify source is byte-identical + compute output SHA-256
[Step 7] Error Cleanup  ──> try...finally unlinks temporary file on any failure
[Step 8] Manifest Emit  ──> Atomic write of <target>.manifest.json binding audit hashes
```

---

### Assurance Taxonomy (A0–A4)

Every SessLint report and manifest certifies an assurance score:

| Level | Tag | Meaning |
| :---: | :--- | :--- |
| **`A0`** | `unreadable` | Parsing failed; file is malformed or unreadable. |
| **`A1`** | `parseable` | Records decoded successfully; relational integrity unverified. |
| **`A2`** | `structurally-valid` | Graph DAG, event identities, and tool pairings verified. |
| **`A3`** | `profile-replay-valid` | Fully compliant with target provider replay constraints. |
| **`A4`** | `reference-loader-equivalent` | Byte-for-byte or semantic round-trip equivalence verified. |

---

## Replay Profiles

| Profile ID | Target Runtime | Adjacency Checks | Tool Boundary Rules |
| :--- | :--- | :--- | :--- |
| **`neutral`** *(default)* | Standard AI Agent Systems | Permissive | Standard call &rarr; result pairing |
| **`claude-strict`** | Anthropic Claude Code | High strictness | Turn alternation, no synthetic assistant turns |
| **`openai-strict`** | OpenAI Agents SDK / RunState | High strictness | Tool call ID matching, checkpoint parity |

```bash
sesslint check session.jsonl --profile claude-strict
sesslint repair session.jsonl --profile openai-strict --output repaired.json
```

---

## Architecture & Anti-Leak Boundaries

SessLint enforces strict inward-only dependency layering:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CLI Entry Point (cli.py)                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                  Reporting & Manifest Generation Layer                 │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
┌───────────────────▼────────────────┐   ┌───────────▼───────────────────┐
│        Repair Execution Layer      │   │       Validation Engine       │
│  (executor.py, planner.py, packs)  │   │   (generic checks, profiles)  │
└───────────────────┬────────────────┘   └───────────┬───────────────────┘
                    │                                │
┌───────────────────▼────────────────────────────────▼───────────────────┐
│               Canonical Event Model & Provenance Coordinate            │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    Adapters (Claude, OpenAI, Canonical)                │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                 Streaming I/O, Hashing & Atomic Primitives             │
└────────────────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> **The Anti-Leak Rule**: Generic rules and repair engines operate **exclusively** on canonical events. Vendor-specific concepts must never leak into generic validation rules.

---

## Python Library API

SessLint is engineered as both a standalone CLI and a high-performance Python library:

```python
from pathlib import Path
import sesslint

# 1. Load and parse a session
header, events = sesslint.load_session_source(Path("session.jsonl"))

# 2. Run validation checks under a specific profile
findings = sesslint.run_all_checks(
    events=events,
    profile="claude-strict",
    source_path="session.jsonl",
)

for finding in findings:
    print(f"[{finding.code}] ({finding.severity.value}): {finding.message}")

# 3. Generate a deterministic repair plan
plan = sesslint.plan(
    findings=findings,
    events=events,
    profile="claude-strict",
    policy="conservative",
)
print(f"Plan fingerprint: {plan.fingerprint}")

# 4. Atomically execute repair
manifest = sesslint.execute(
    source_path=Path("session.jsonl"),
    plan=plan,
    output_path=Path("session.repaired.jsonl"),
    policy="conservative",
    profile="claude-strict",
)
print(f"Repair certified at assurance level: {manifest.assurance}")
```

---

## JSON Schemas

Formal versioned JSON Schemas are maintained in `schemas/`:

| Schema Name | Version | Path | Role |
| :--- | :---: | :--- | :--- |
| **Session** | `v1` | `schemas/sesslint.session.v1.json` | Neutral canonical session model |
| **Finding** | `v1` | `schemas/sesslint.finding.v1.json` | Diagnostic finding contract |
| **Report** | `v1` | `schemas/sesslint.report.v1.json` | Aggregated analysis report |
| **Repair Manifest** | `v1` | `schemas/sesslint.repair-manifest.v1.json` | Cryptographic audit trail |

---

## Test Suite & Verification

The test suite covers unit, property-based, adversarial, and fault-injection testing:

```bash
# Run the complete test suite
uv run pytest

# Run repair tests including fault-injection kill simulations
uv run pytest tests/repair/ -v

# Verify strict type safety
uv run mypy --strict src/sesslint

# Verify code formatting and lint rules
uv run ruff check src tests
uv run ruff format --check src tests
```

### Verification Matrix Highlights
- **Crash / Kill Simulation**: Tests inject exceptions before atomic rename to prove source immutability.
- **TOCTOU Race Detection**: Modifying source files mid-flight triggers clean aborts.
- **Single-Mutator AST Grep**: Automated static analysis verifies `os.replace` is never called outside `executor.py` and `atomic.py`.
- **Property-Based Fuzzing**: Hypothesis tests validate random DAG permutations, cycles, and deep nesting.

---

## License

SessLint is licensed under the [Apache License, Version 2.0](LICENSE).

```text
=======
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
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70
Copyright 2026 SessLint Maintainers

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
<<<<<<< HEAD
```
=======

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
>>>>>>> 3ae9d86f6cdd802e3c464a6bbaa2dc3d20af8d70
