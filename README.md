<h1 align="center">SessLint</h1>

<p align="center">
  <strong>Offline, vendor-neutral session-integrity checker and conservative repair engine for tool-using AI agents.</strong>
</p>

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/runtime_deps-zero-brightgreen?style=flat-square" alt="Zero Runtime Dependencies"></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-1000%2B_passed-success?style=flat-square" alt="Tests Passing"></a>
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
- [Finding Fingerprints & Deterministic Ordering](#finding-fingerprints--deterministic-ordering)
- [Report Coverage & Run-State Evidence](#report-coverage--run-state-evidence)
- [Repair Engine](#repair-engine)
  - [Policies: Conservative vs. Salvage](#policies-conservative-vs-salvage)
  - [Recipe Catalog](#recipe-catalog)
  - [Atomic 8-Step Execution Protocol](#atomic-8-step-execution-protocol)
  - [Repair Manifest Schema & Cryptographic Binding](#repair-manifest-schema--cryptographic-binding)
  - [Assurance Taxonomy (A0–A4)](#assurance-taxonomy-a0a4)
- [Replay Profiles](#replay-profiles)
- [Architecture & Anti-Leak Boundaries](#architecture--anti-leak-boundaries)
- [Python Library API](#python-library-api)
- [JSON Schemas](#json-schemas)
- [Compatibility & Migration Notes (NDP-001)](#compatibility--migration-notes-ndp-001)
- [Test Suite & Verification](#test-suite--verification)
- [Safe Issue Reporting & Adapter Requests](#safe-issue-reporting--adapter-requests)
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

SessLint exposes eight CLI commands:

#### `sesslint check`
Scan and validate session files or directories for structural corruptions and provider rule violations.

```bash
sesslint check <path> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Session file path (`.json` or `.jsonl`) or directory (with `--recursive`). |
| `--recursive`, `-r` | `flag` | `False` | Recursively scan directories and report 5-bucket totals. |
| `--format` | `choice` | `auto` | Force adapter: `auto`, `claude-code-jsonl`, `openai-agents`, `canonical`. |
| `--profile` | `string` | `neutral` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). |
| `--json` | `flag` | `False` | Emit machine-readable JSON report. |
| `--confidence-min` | `float` | `0.55` | Minimum auto-detection confidence threshold. |
| `--margin-min` | `float` | `0.15` | Minimum auto-detection margin above second-place format. |
| `--max-files` | `int` | `10000` | Maximum number of files to inspect during recursive scan. |
| `--max-bytes` | `int` | `1GB` | Maximum cumulative bytes to read during recursive scan. |
| `--follow-symlinks` | `flag` | `False` | Follow directory symlinks during recursive scanning. |
| `--include-content` | `flag` | `False` | Embed raw transcript content in reports (warning: emits raw sensitive data). |
| `--color` | `choice` | `auto` | Control colored output: `auto`, `always`, `never`. |
| `--no-color` | `flag` | `False` | Disable ANSI color styling (equivalent to `NO_COLOR=1`). |

> [!NOTE]
> `--policy` is valid exclusively for `repair`, not `check`. Passing `--policy` to `check` errors immediately with exit code 2.

#### `sesslint scan`
Scan directory trees for session artifacts or display reader resource limits.

```bash
sesslint scan [path] [OPTIONS]
sesslint scan --show-limits
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *optional* | Directory path to scan recursively (required unless `--show-limits`). |
| `--show-limits` | `flag` | `False` | Display configured reader resource limits (max line length, max bytes) and exit 0. |
| `--recursive`, `-r` | `flag` | `True` | Recursively scan directory trees (default: `True`). |
| `--max-files` | `int` | `10000` | Maximum number of files to process before aborting. |
| `--max-bytes` | `int` | `1GB` | Maximum cumulative bytes to process before aborting. |
| `--format` | `choice` | `auto` | Force adapter: `auto`, `claude-code-jsonl`, `openai-agents`, `canonical`. |
| `--profile` | `string` | `neutral` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). |
| `--json` | `flag` | `False` | Emit machine-readable JSON scan report with 5-bucket totals. |
| `--follow-symlinks` | `flag` | `False` | Follow symbolic links during directory traversal. |
| `--color` | `choice` | `auto` | Control colored output: `auto`, `always`, `never`. |
| `--no-color` | `flag` | `False` | Disable ANSI color styling. |

#### `sesslint repair`
Plan and execute verified, atomic session repairs (Alpha scope: Canonical Session format).

```bash
sesslint repair <path> --output <out_path> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Source session file to repair (Canonical format). |
| `--output`, `-o` | `Path` | *required* | Distinct destination path (required unless `--dry-run`). |
| `--dry-run` | `flag` | `False` | Computes and displays plan; creates zero files on disk. |
| `--policy` | `choice` | `conservative` | `conservative` (zero data loss) or `salvage` (explicit lossy pruning). |
| `--format` | `choice` | `auto` | Force adapter: `auto`, `claude-code-jsonl`, `openai-agents`, `canonical`. |
| `--profile` | `string` | `neutral` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). |
| `--plan` | `Path` | `None` | Path to a pre-computed plan JSON file to execute. |
| `--acknowledge-side-effects`| `flag` | `False` | Acknowledge tool side-effects for salvage policy. |
| `--salvage-unsupported` | `flag` | `False` | *Deprecated*: Use `--policy salvage` instead. |
| `--include-content` | `flag` | `False` | Embed raw transcript content in manifests (warning: emits raw sensitive data). |
| `--json` | `flag` | `False` | Emit machine-readable JSON plan or repair manifest. |

> [!NOTE]
> The `--salvage-unsupported` flag is deprecated. Use `--policy salvage` instead.
>
> **Alpha Format Boundary**: Repair currently supports Canonical Session stream format (`schema_version: sesslint.session/v1`). Repair attempts on vendor formats (Claude Code / OpenAI Agents) safely refuse with Exit Code 2 and actionable instructions.

#### `sesslint verify`
Independently audit integrity, cryptographic hash bindings, manifest actions, and idempotence of a repaired session.

```bash
sesslint verify <source> <repaired> --manifest <manifest> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `source` | `Path` | *required* | Original source session file path (positional or `--source`). |
| `repaired`| `Path` | *required* | Repaired output session file path (positional or `--output`). |
| `--manifest` | `Path` | *required* | Cryptographically bound repair manifest JSON path. |
| `--plan` | `Path` | `None` | Path to repair plan JSON file (optional). |
| `--acknowledge-side-effects`| `flag` | `False` | Acknowledge tool side-effects for salvage policy during verify idempotence check. |
| `--include-content` | `flag` | `False` | Embed raw transcript content (warning: emits raw sensitive data). |
| `--json` | `flag` | `False` | Emit machine-readable JSON verdict. |
| `--color` | `choice` | `auto` | Control colored output: `auto`, `always`, `never`. |
| `--no-color` | `flag` | `False` | Disable ANSI color styling. |

#### `sesslint validate-session`
Validate a canonical session file against the official `sesslint.session/v1` JSON Schema specification.

```bash
sesslint validate-session <path>
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Path to canonical session file (`.json` or `.jsonl`). |

#### `sesslint formats`
List supported session format adapters and their schema version specifications.

```bash
sesslint formats [--json]
```

#### `sesslint version`
Display detailed component, CLI, schema, adapter, and profile version information.

```bash
sesslint version [--json]
```

#### `sesslint bundle`
Generate a privacy-safe diagnostic support bundle and fixture skeleton for troubleshooting or requesting adapter support.

```bash
sesslint bundle <path> [OPTIONS]
```

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | `Path` | *required* | Path to session file (`.json` or `.jsonl`). |
| `--output`, `--out`, `-o` | `Path` | `None` | Path to output bundle JSON file (prints to stdout if omitted). |
| `--json` | `flag` | `False` | Output bundle as JSON to stdout. |
| `--format` | `choice` | `auto` | Force adapter: `auto`, `claude-code-jsonl`, `openai-agents`, `canonical`. |
| `--profile` | `string` | `neutral` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). |

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
| **`SL002`** | Torn terminal record | `error` | `deterministic` | Incomplete final append repairable via `torn-terminal-record-discard`. |

### 2. Event Identity
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL003`** | Duplicate event ID | `warning` | `deterministic` | Identical duplicates are safely collapsed; conflicting duplicates escalate to `error`/`manual`. |

### 3. Graph Lineage & DAG Consistency
| Code | Name | Default Severity | Repairability | Action & Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **`SL004`** | Missing parent | `error` | `manual` | Repair requires proven unique predecessor (full equality, same branch, same compaction segment). |
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

## Finding Fingerprints & Deterministic Ordering

### Finding Fingerprint Scheme (FR-046)

Every diagnostic finding is assigned a deterministic 16-hex SHA-256 fingerprint computed across a normalized canonical preimage tuple:

```python
preimage = [
    code,  # Diagnostic reason code (e.g., "SL001")
    adapter_id,  # Active adapter name (e.g., "canonical", "claude-code-jsonl")
    adapter_version,  # Active adapter version (e.g., "1.0.0")
    profile_id,  # Active profile name (e.g., "neutral", "claude-strict")
    profile_version,  # Active profile version (e.g., "1.0.0")
    norm_path,  # Forward-slash normalized source path
    line,  # 1-based source line (or None)
    ordinal,  # 0-based stream record counter (or None)
    record_id,  # Canonical or vendor record identifier (or None)
    canonical_evidence_subset,  # Stable sorted subset of structural finding evidence
]
```

- **Canonical Encoding**: Preimage is serialized via SessLint's unified canonical JSON primitive (`sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=False`, `newline=False`) and hashed with SHA-256, returning the first 16 lowercase hex characters.
- **Version Pinning**: Omitted or unresolved versions default strictly to `"unknown"` (never empty string), ensuring findings are version-stable across refactors and deterministic across platforms.
- **Plan Fingerprints**: Repair plans are hashed with the identical canonical JSON primitive, guaranteeing cross-platform hash stability over UTF-8 data.

### Deterministic Finding Ordering (FR-094)

All SessLint renderers (JSON, scan summaries, and human-readable terminal reports) sort findings using a strict, position-first total ordering:

1. **`path`**: Lexicographical order (forward-slash normalized).
2. **`line`**: Source line number (`None` sorts as `-1` before line 0, followed by ascending integer).
3. **`ordinal`**: Stream record index from `evidence["record_ordinal"]` (`None` / `-1` sorts before 0).
4. **`severity_rank`**: Strict severity hierarchy (`fatal` < `error` < `warning` < `info`).
5. **`code`**: Lexicographical order of the diagnostic code (e.g. `SL001`, `SL002`).
6. **`record_id`**: Event identifier (`None` sorts as empty string before non-empty string, then lexicographical).
7. **`fingerprint`**: 16-character SHA-256 hex digest for total ordering tie-breaking.

---

## Report Coverage & Run-State Evidence

### Report Coverage Block (FR-047)

Every report emitted by `sesslint check --json` embeds a top-level `coverage` block certifying which rules and checks were executed versus skipped:

```json
"coverage": {
  "adapter": {
    "id": "canonical",
    "version": "1.0.0"
  },
  "performed": [
    "SL001", "SL002", "SL003", "SL004", "SL005", "SL006", "SL007",
    "SL101", "SL102", "SL103", "SL104", "SL105", "SL106", "SL107", "SL108",
    "SL201", "SL202", "SL203", "SL301", "SL302",
    "checkpoint", "graph", "identity", "tool_pairing_1", "tool_pairing_2"
  ],
  "profile": {
    "id": "neutral",
    "version": "1.0.0"
  },
  "skipped": []
}
```

Any skipped check must record a machine-readable reason drawn exclusively from a **closed vocabulary**:
- `profile-gated`: Rule or family disabled by the active replay profile.
- `adapter-not-applicable`: Check does not apply to the resolved format or auto-detection failed.
- `version-gated`: Format version is unsupported (`SL301`), aborting downstream checking.
- `empty-input`: Stream contains zero records, preventing graph or semantic evaluation.
- `cap-exceeded`: Stream resource limits exceeded (`max_line_bytes`, `max_file_bytes`, etc.).
- `single-doc-fallback`: Non-streaming single-document parsing fallback was used.

### Run-State & Checkpoint Evidence (FR-044, DEV-011)

- **Events-Only Verdict Boundary**: Current checkpoint rules (`SL201`, `SL202`) evaluate causal consistency strictly over durable events in the session stream.
- **Content-Free Structural Projection**: When runtime continuation state and checkpoints are provided (e.g. OpenAI Agents SDK exports), SessLint redacts state variables to structural projections (`keys`, `shapes`, `checkpoints`, `truncated`) and preserves them in `evidence["run_state"]`. Raw values, secrets, and prompts are never preserved.
- **Future Continuation Ownership**: Verifying deep continuation-step ownership between runtime state variables and historical actions requires upstream vendor semantics, tracked under research item **OPP-019**.

### Source Coordinates & Byte Offsets (FR-015, AC-003)

Streaming readers (`io.py`, Claude Code, OpenAI Agents SDK JSONL) compute exact byte boundaries:
- Finding evidence carries `byte_offset` (start byte), `byte_end` (end byte), and `record_ordinal`.
- Report spans populate `span.byte = (byte_offset, byte_end)` alongside 1-indexed line coordinates.

### Synthetic Event IDs & Namespace Isolation (DEV-007)

When source records lack native event IDs, SessLint synthesizes IDs in a reserved namespace:
- **Format**: `sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>`, where `<8-hex-hash>` is derived from SHA-256 over `{source_hint}:{ordinal}:{payload_len}`.
- **Collision Guard**: `SyntheticIdCollisionGuard` enforces at load time that no synthetic ID can collide with a vendor-supplied real ID, eliminating synthetic ID squatting and false `SL003` findings.

### Discriminator Privacy Bounding (SL302, DEV-008)

To prevent prompt or credential leaks via unknown record discriminators:
- Safe identifiers matching `^[A-Za-z0-9_.-]{1,64}$` are echoed verbatim in `evidence["type_value"]`.
- Non-matching, oversized, or multi-line strings are sanitized to `<type:len=N>` shape descriptors with `truncated: true` in evidence.

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

> [!NOTE]
> **Normative Interpretation: Global vs. Scoped Side-Effect Abstention (DEV-013)**
> Automated session repair enforces side-effect safety at two distinct layers:
> 1. **Global Gate (`SL203`)**: Unsafe continuation across loss (`SL203`) represents unresolved causal corruption. When `SL203` is present anywhere in a session, automated repair refuses all conservative and salvage transformations globally across the entire session (`SL203-refusal`).
> 2. **Scoped Gate (Conservative Recipes)**: For sessions containing side-effect-bearing tool calls without `SL203`, conservative repair does not refuse globally. Instead, each candidate repair step must prove region-disjointness: the step's affected record set (target records, relinked ancestors, and truncated spans) must have zero intersection with any event whose execution state is ambiguous (dangling calls, unknown side-effects, or unresolved results). If disjointness is proven, safe conservative repairs proceed cleanly. If the proof fails, repair fail-closes with `side-effect-scope-unproven` at both planning and execution layers.


### Recipe Catalog

SessLint registers **9 deterministic repair recipes** partitioned into conservative and salvage policies:

#### Conservative Recipes (Default)
- **`torn-terminal-record-discard`** (`SL002`): Discards incomplete or unparseable trailing bytes at the end of a session stream while preserving all validated preceding records.
- **`identical-duplicate-collapse`** (`SL003`): Deduplicates adjacent byte-identical events.
- **`proven-unique-parent-restore`** (`SL004`): Reattaches missing parent pointers when exactly one unambiguous ancestor exists in the same branch and compaction segment via full-equality match.
- **`compaction-projection-reunion`** (`SL108`): Relocates compaction markers to reunite split tool call/result pairs.
- **`duplicate-projection-removal`** (`SL104`): Discards duplicate identical result projections.

#### Salvage Recipes (Explicit Opt-In)
- **`terminal-suffix-discard`** (`SL005`): Discards trailing cyclic events after the cut point provided no durable checkpoints or safe tool results exist beyond the cut.
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
[Step 4] Revalidation   ──> Output schema parse + multiset parity + zero SL203 + revalidation summary
[Step 5] Atomic Commit  ──> Write <target>.tmp.<pid>.<rand> ──> fsync ──> os.replace
[Step 6] Post-Hashing   ──> Verify source is byte-identical + compute output SHA-256
[Step 7] Error Cleanup  ──> try...finally unlinks temporary file on any failure
[Step 8] Manifest Emit  ──> Exclusive create (O_EXCL) of <target>.manifest.json + directory fsync
```

### Repair Manifest Schema & Cryptographic Binding (FR-072)

Every successful repair writes a cryptographically bound `<target>.manifest.json` receipt conforming to `schemas/sesslint.repair-manifest.v1.json`:

| Manifest Field | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | `string` | Manifest contract version (`sesslint.repair-manifest/v1`). |
| `input_fingerprint` | `string` | SHA-256 digest of original source file before mutation. |
| `output_fingerprint` | `string` | SHA-256 digest of final repaired output file. |
| `policy` | `string` | Policy used during repair (`conservative` or `salvage`). |
| `actions` | `array` | Sequence of applied recipe actions with finding references. |
| `declared_loss` | `array` | Itemized declared loss counters (e.g. `["events_dropped:2"]`). |
| `idempotency_key` | `string` | 64-hex SHA-256 idempotency key binding input fingerprint, policy, and actions. |
| `revalidation` | `object` | Embedded post-repair verdict: `{assurance, error_count, warning_count, profile_id, profile_version, report_fingerprint}`. |
| `assurance_ceiling` | `string` | Revalidated output assurance level ceiling (`A0`–`A4`). |
| `assurance` | `string` | Repair lattice assurance (`repaired-lossless` or `repaired-salvage`). |
| `plan_fingerprint` | `string` | Deterministic SHA-256 digest of the executed repair plan. |
| `revalidate_report` | `string \| null` | Embedded post-repair revalidation report JSON string, or null. |
| `adapter_id` | `string` | Format adapter used for repair validation (e.g. `canonical`). |
| `adapter_version` | `string` | Format adapter semantic version. |
| `profile_version` | `string` | Replay validation profile semantic version. |
| `byte_counts` | `object` | Source and output byte sizes (`{source: N, output: M}`). |
| `record_counts` | `object` | Source and output event counts (`{source: N, output: M}`). |
| `recipe_versions` | `object` | Mapping of applied recipe names to implementation versions. |

> [!IMPORTANT]
> **Receipt Immutability**: Manifest publication uses `O_EXCL` creation flags. SessLint refuses to silently overwrite an existing receipt file, ensuring that repair audit trails cannot be overwritten.

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

SessLint is engineered as both a standalone CLI and a high-performance, strictly typed Python library with 1:1 parity:

### High-Level Programmatic API (`sesslint.api`)

```python
from pathlib import Path
from sesslint import api

# 1. Single-file check returning frozen Report dataclass
report = api.check_file("session.jsonl", profile="neutral")
print(f"Assurance: {report.assurance}, Findings: {len(report.findings)}")
for finding in report.findings:
    print(f"  [{finding.code}] {finding.severity.value}: {finding.message}")

# 2. Directory scan returning ScanReport with 5-bucket totals
scan_report = api.check_dir("logs/", recursive=True)
print(f"Totals: {scan_report.totals}")

# 3. Dry-run repair plan or full verified repair execution
plan, manifest = api.repair(
    source_path="corrupted.jsonl",
    output_path="repaired.jsonl",
    policy="conservative",
    profile="neutral",
)
if manifest:
    print(f"Repair certified at assurance level: {manifest.assurance}")

# 4. Independent audit and verification of repair artifacts
verdict = api.verify(
    source_path="corrupted.jsonl",
    output_path="repaired.jsonl",
    manifest_path="repaired.jsonl.manifest.json",
)
assert verdict.ok, "Verification audit failed!"
```

### Low-Level Modular Primitives

```python
from pathlib import Path
import sesslint

# 1. Load and parse canonical session events
header, events = sesslint.load_session_source(Path("session.jsonl"))

# 2. Run check suite with explicit profile
findings = sesslint.run_all_checks(
    events=events,
    profile="claude-strict",
    source_path="session.jsonl",
)

# 3. Plan and atomically execute repair
plan = sesslint.plan(
    findings=findings,
    events=events,
    profile="claude-strict",
    policy="conservative",
)
manifest = sesslint.execute(
    source_path=Path("session.jsonl"),
    plan=plan,
    output_path=Path("session.repaired.jsonl"),
    policy="conservative",
    profile="claude-strict",
)
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

## Compatibility & Migration Notes (NDP-001)

The NDP-001 "Trustworthy Alpha" program introduces several intentional behavioral changes and schema additions relative to initial 0.1.0 releases:

| Feature Area | Pre-NDP-001 Behavior | NDP-001 Code Truth | Migration & Output Diff Impact |
| :--- | :--- | :--- | :--- |
| **Finding Order** | Severity-first sorting: `(severity, code, path, line, record_id, fingerprint)`. | Position-first sorting (FR-094): `(path, line, ordinal, severity, code, record_id, fingerprint)`. | Findings in JSON and terminal outputs appear in physical stream order rather than grouped by severity. |
| **Finding Fingerprints** | Per-family hashing algorithms ignoring adapter/profile versions. | Unified 16-hex SHA-256 over canonical JSON preimage including `(adapter_id, adapter_version, profile_id, profile_version)`. | All finding `fingerprint` values differ from 0.1.0 baselines; cross-version stability is now guaranteed. |
| **Plan Fingerprints** | Canonical JSON formatted with `ensure_ascii=True`. | Unified canonical JSON with `ensure_ascii=False` and `\n` normalization. | Plan SHA-256 hashes differ for non-ASCII records; plan schemas remain backward compatible. |
| **Report Coverage** | Reports contained only finding arrays and metadata; no check coverage tracking. | Embedded `coverage` block (FR-047) enumerating performed and skipped checks with closed reason vocabulary. | Additive schema change in `schemas/sesslint.report.v1.json`. CI gates can verify full test execution. |
| **Source Coordinates** | Finding `span.byte` coordinates were always null. | Streaming readers track byte offsets and emit `byte_offset`, `byte_end`, and `record_ordinal` in evidence and `span.byte`. | Additive evidence fields; allows exact byte-range auditing. |
| **Synthetic Event IDs** | Guessable synthetic IDs (`rec_0`, `rec_1`) without namespace isolation. | Reserved collision-resistant namespace `sesslint:synthetic:<adapter>:<ordinal>:<hash>` with load-time collision guard. | Eliminates false `SL003` findings caused by synthetic ID collisions with real session IDs. |
| **SL302 Type Discriminator** | Unknown event discriminator echoed raw into `evidence.type_value`. | Allowlist echo `^[A-Za-z0-9_.-]{1,64}$`; complex or long discriminators masked to `<type:len=N>` with `truncated: true`. | Protects against secret and prompt leakage in default reports (FR-081/FR-082). |
| **Repair Manifest** | Manifests lacked revalidation proof and allowed silent file overwrite. | Embedded `revalidation` summary struct, `assurance_ceiling`, real adapter versions, `O_EXCL` exclusive create, and directory fsync. | Additive manifest fields; existing receipt files are never silently overwritten. |
| **SL004 Parent Restoration** | `proven-unique-parent-restore` matched candidate parents across the entire session by string/hash prefix. | Candidate matching requires exact full string equality, same-branch confinement, and same-compaction-segment confinement. | Eliminates prefix guessing; ambiguous or unconfined missing-parent cases remain `manual` without auto-repair. |
| **CLI Command Surface** | `check` accepted meaningless `--policy` flag; `repair` accepted `--salvage-unsupported`; `cmd_check` had duplicated orchestration. | `check` unified onto `api.check_file` / `api.check_dir`; `--policy` on `check` raises exit code 2; `--salvage-unsupported` deprecated in favor of `--policy salvage`. | Clean CLI contract with zero behavioral drift between CLI and Python API. |

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

### Requesting Adapter Support

Encountering an unsupported format or newer schema version? Use `sesslint bundle` to emit an evidence artifact and submit an adapter request:

1. **Generate the bundle**:
   ```bash
   sesslint bundle session.jsonl --out bundle.json
   ```
2. **Review privacy guarantees**: The bundle is strictly content-free (paths are basename-only, discriminators bounded, long IDs hashed via SHA-256, prompt texts excluded).
3. **Open an issue**: Use the [Adapter Request Template](.github/ISSUE_TEMPLATE/adapter_request.md).
4. **Attach bundle output**: Paste the `bundle.json` contents and optionally fill in synthetic records using the provided fixture skeleton.

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
