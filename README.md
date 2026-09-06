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

---

## Table of Contents

- [The Problem](#the-problem)
- [Core Invariants & Guarantees](#core-invariants--guarantees)
- [Four Layers of Correctness](#four-layers-of-correctness)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [Command Matrix](#command-matrix)
  - [Exit Codes](#exit-codes)
- [Supported Formats & Conformance Matrix](#supported-formats)
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
- [Safe Issue Reporting](#safe-issue-reporting)
- [Contributing & Fixture Provenance](#contributing--fixture-provenance)
- [Release & Build Protocol](#release--build-protocol)
- [License](#license)

---

## The Problem

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
> 8. **Safety & Minimization Boundaries**: redaction is best-effort minimization, not a completeness guarantee. Furthermore, sesslint makes no semantic or side-effect safety claims.

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

## Quick Start

### Installation

```bash
# Install with pip
pip install sesslint

# Or install in an isolated environment with pipx
pipx install sesslint

# Verify installation
sesslint --version
```

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

For comprehensive compatibility matrix across formats and validation profiles, consult the [Adapter & Profile Conformance Matrix](docs/MATRIX.md).

---

## Diagnostic Reason Codes (SL001–SL302)

SessLint implements **20 registered diagnostic codes**. Severity and repairability are maintained as independent dimensions. Detailed documentation for each code is available in [`docs/codes/`](docs/codes/).

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

## Safe Issue Reporting

> [!CAUTION]
> **Zero-Leak Issue Reporting Policy**:
> **Never paste or upload raw session transcripts.** Raw transcripts frequently contain unredacted API keys, private system prompts, confidential workspace paths, and proprietary code. Maintainers will delete raw transcript uploads immediately upon discovery.
>
> When reporting a bug or defect:
> 1. Attach only minimized, synthetic, or redacted excerpts reproducing the defect.
> 2. Run `sesslint version --json` and attach the diagnostic environment block.
> 3. Refer to our [Safe Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md).

---

## Contributing & Fixture Provenance

We welcome contributions adhering to our engineering and safety standards:
- Review the [Contributor Guide](CONTRIBUTING.md) for architectural boundaries and gate requirements.
- Review the [Fixture Provenance Policy](FIXTURES.md) for synthetic-only test data rules and schema.
- Explore the [Repair Recipe Catalog](docs/recipes/) for deterministic and salvage transformations.

---

## Release & Build Protocol

For verifiable distribution builds and checksum validation:
- Consult [RELEASING.md](RELEASING.md) for reproducible wheel and sdist procedures.
- Check [NOTICE](NOTICE) for third-party developer dependencies and licensing declarations.

---

## License

SessLint is licensed under the [Apache License, Version 2.0](LICENSE).

```text
Copyright 2026 SessLint Maintainers

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
