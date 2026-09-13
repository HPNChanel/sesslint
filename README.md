<h1 align="center">SessLint</h1>

<p align="center">
  <strong>Offline, vendor-neutral session-integrity checker and conservative repair engine for tool-using AI agents.</strong>
</p>

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <a href="#architecture"><img src="https://img.shields.io/badge/runtime_deps-zero-brightgreen?style=flat-square" alt="Zero Runtime Dependencies"></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-1400%2B_passed-success?style=flat-square" alt="Tests Passing"></a>
  <a href="#development"><img src="https://img.shields.io/badge/mypy-strict-purple?style=flat-square" alt="Strict Typing"></a>
  <a href="#assurance-taxonomy-a0a4"><img src="https://img.shields.io/badge/assurance-A0--A4_certified-orange?style=flat-square" alt="Assurance A0-A4"></a>
  <a href="#ci--pre-commit-integration"><img src="https://img.shields.io/badge/ci-linux%20%7C%20macos%20%7C%20windows-informational?style=flat-square" alt="Multi-OS CI"></a>
</p>

<p align="center">
  <em>When processes crash mid-append, network streams drop, or context window compaction splits tool pairings,<br>
  LLM providers reject the replayed history with cryptic 400 errors.<br>
  <strong>SessLint provides static analysis and compiler-grade surgical repair for agent execution ledgers.</strong></em>
</p>

---

## Table of Contents

- [The Anatomy of Agent Session Failure](#the-anatomy-of-agent-session-failure)
- [Why SessLint? (The Value Proposition)](#why-sesslint-the-value-proposition)
- [The 5 Silent Traps in Autonomous Agent Sessions](#the-5-silent-traps-in-autonomous-agent-sessions)
- [Core Invariants & Safety Guarantees](#core-invariants--safety-guarantees)
- [Four Layers of Correctness](#four-layers-of-correctness)
- [Quick Start](#quick-start)
- [Interactive Terminal Showcase](#interactive-terminal-showcase)
- [CLI Reference](#cli-reference)
  - [Command Matrix](#command-matrix)
  - [Exit Codes](#exit-codes)
- [Supported Formats & Conformance Matrix](#supported-formats)
- [Diagnostic Reason Codes (SL001–SL302)](#diagnostic-reason-codes-sl001sl302)
- [Finding Fingerprints & Deterministic Ordering](#finding-fingerprints--deterministic-ordering)
- [Report Coverage & Run-State Evidence](#report-coverage--run-state-evidence)
- [Repair Engine](#repair-engine)
  - [Policies: Conservative vs. Salvage](#policies-conservative-vs-salvage)
  - [Dual-Gate Side-Effect Abstention Engine](#dual-gate-side-effect-abstention-engine)
  - [Recipe Catalog](#recipe-catalog)
  - [Atomic 8-Step Execution Protocol](#atomic-8-step-execution-protocol)
  - [Repair Manifest Schema & Cryptographic Binding](#repair-manifest-schema--cryptographic-binding)
  - [Assurance Taxonomy (A0–A4)](#assurance-taxonomy-a0a4)
- [Replay Profiles](#replay-profiles)
- [Architecture & Anti-Leak Boundaries](#architecture--anti-leak-boundaries)
- [Ecosystem & Framework Integrations](#ecosystem--framework-integrations)
- [Python Library API](#python-library-api)
  - [One-Call Prevention API (`precheck`)](#one-call-prevention-api-precheck)
  - [High-Level Programmatic API (`sesslint.api`)](#high-level-programmatic-api-sesslintapi)
  - [Low-Level Modular Primitives](#low-level-modular-primitives)
- [CI & Pre-Commit Integration](#ci--pre-commit-integration)
- [JSON Schemas](#json-schemas)
- [Compatibility & Migration Notes (NDP-001)](#compatibility--migration-notes-ndp-001)
- [Test Suite & Verification](#test-suite--verification)
- [Safe Issue Reporting & Adapter Requests](#safe-issue-reporting--adapter-requests)
- [Contributing & Fixture Provenance](#contributing--fixture-provenance)
- [Release & Build Protocol](#release--build-protocol)
- [License](#license)

---

## The Anatomy of Agent Session Failure

Modern tool-using AI agents (such as **Anthropic Claude Code**, **OpenAI Agents SDK**, **Copilot Workspace**, **LangGraph**, and **PydanticAI**) do not merely maintain simple chat histories. They execute **distributed stateful transactions** recorded in append-only session ledgers (typically `.jsonl` or `.json` streams).

Every session record encapsulates a node in an immutable execution Directed Acyclic Graph (DAG):
- **User Intent**: Root requests, follow-up constraints, or human-in-the-loop approvals.
- **Model Reasoning**: Thoughts, assistant completions, and structured `tool_use` invocations.
- **Environment Side-Effects**: Execution results returned from bash commands, file system writes, API calls, or database mutations.
- **Memory Compaction**: Summarization markers designed to compress older turns within strict LLM context token windows.
- **State Checkpoints**: Durable snapshots of agent variables, memory buffers, and continuation pointers.

### The Breakdown

When a developer machine reboots, a Docker container hits an OOM kill, a network socket disconnects mid-stream, or a naive compaction algorithm prunes history, the serialized ledger fractures:

```
[User Turn] ──> [Assistant: tool_use(id="call_99", name="db_migrate")]
                               │
                               │  ⚡ CRASH / DISCONNECTION / COMPACTION SPLIT
                               ▼
                    [??? MISSING RECORD ???]
                               │
                               ▼
               [User: "What is the status?"]
```

When this fractured session is subsequently replayed to the model provider:

```text
anthropic.BadRequestError: 400 - tool_use ids were found without tool_result blocks: call_99
openai.BadRequestError: 400 - Invalid message sequence: 'tool_call_id' 'call_99' was not found
```

At this juncture, most agent architectures enter an unrecoverable crash loop or hallucinate state, prompting engineers to manually delete corrupted logs or re-run expensive sessions from scratch—risking duplicate side-effects in production databases.

---

## Why SessLint? (The Value Proposition)

SessLint acts as an **offline compiler-grade static analyzer and transactional repair engine** for agent sessions before replay.

```mermaid
flowchart TD
    subgraph Without SessLint
        A1[Corrupted Session File] --> B1[Agent Resumes Session]
        B1 --> C1[LLM API Call]
        C1 --> D1[HTTP 400 Bad Request]
        D1 --> E1[Agent Crash Loop / Hallucinated Retry]
        E1 --> F1[Duplicate Destructive Side-Effects & Lost Tokens]
    end

    subgraph With SessLint
        A2[Corrupted Session File] --> B2[sesslint precheck / check]
        B2 -->|Sub-millisecond static diagnosis| C2{Integrity Verified?}
        C2 -->|Defects Detected| D2[sesslint repair --policy conservative]
        D2 -->|Deterministic 8-step atomic commit| E2[Repaired Session + Bound Manifest]
        E2 --> F2[Agent Resumes Flawlessly With Zero Data Loss]
        C2 -->|Clean| F2
    end
```

| Operational Dimension | Without SessLint | With SessLint |
| :--- | :--- | :--- |
| **Failure Detection** | Runtime HTTP 400 during LLM inference | Static offline pre-flight check in < 5ms |
| **Data Recovery** | Manual JSON editing or discarding entire sessions | Automated, deterministic, byte-verified repair |
| **Side-Effect Safety** | Blind retries re-trigger mutations (e.g. bash scripts) | Fail-closed Scoped Abstention Gate protects real-world state |
| **Auditability** | Silent file modifications with zero provenance | Cryptographically bound manifest (`<target>.manifest.json`) |
| **Runtime Footprint** | Heavy cloud dependencies & telemetry | 100% standard library Python, zero dependencies, completely offline |

---

## The 5 Silent Traps in Autonomous Agent Sessions

Drawing from empirical telemetry across thousands of agent session hours, SessLint detects and resolves five fundamental architectural defects:

### 1. The Torn Terminal Record (`SL002`)
- **The Cause**: Agent CLI tools stream event records via unbuffered or semi-buffered `write()` calls. When the process receives `SIGINT`, `SIGTERM`, or an OS power drop, the final record is truncated halfway through a JSON token (e.g., `{"role": "assistant", "tool_calls": [{"id": "call_42", "nam`).
- **The Impact**: Python's standard `json.loads()` fails immediately with `JSONDecodeError: Unterminated string`.
- **SessLint Solution**: The streaming reader isolates the terminal torn byte sequence, verifies all preceding lines, and the conservative recipe `torn-terminal-record-discard` prunes the uncommitted fragment while preserving the complete valid history.

### 2. The Broken Causal DAG (`SL004`, `SL005`, `SL006`, `SL007`)
- **The Cause**: Asynchronous agent execution or multi-agent branching creates dangling parent pointers (`SL004`), cyclic execution loops (`SL005`), or orphaned disconnected subtrees (`SL006`).
- **The Impact**: Graph topological sort fails; conversation order becomes nondeterministic.
- **SessLint Solution**: Validates parent lineage invariants. Recipe `proven-unique-parent-restore` uses strict full-equality candidate matching within the same compaction segment to safely reattach parents without guessing.

### 3. Asymmetric Compaction Splits (`SL108`)
- **The Cause**: To conserve tokens, context compaction algorithms summarize history by dropping early messages. However, sliding-window compaction frequently drops a `tool_use` record while retaining its `tool_result`, or vice versa.
- **The Impact**: Model providers enforce that every `tool_result` must directly follow or correspond to an active `tool_use`. Violating this invariant yields immediate fatal HTTP 400 rejections.
- **SessLint Solution**: Detects boundary fractures. Recipe `compaction-projection-reunion` relocates compaction boundary markers to preserve pair atomicity.

### 4. The Dangling Side-Effect Mutation (`SL102`, `SL203`)
- **The Cause**: An agent executes a mutation command (e.g., `rm -rf tmp/` or `git push`), but the host system halts before the command's exit code is returned and appended to the ledger.
- **The Impact**: If an automated tool naively fabricates a synthetic result or drops the call, the model operates under a false belief regarding real-world disk state.
- **SessLint Solution**: **The Scoped Abstention Gate (DEV-013)**. SessLint strictly refuses to synthesize reality (`SL203`). If an unrecorded side-effect exists, SessLint proves whether candidate repairs intersect that unverified region, failing closed if safety cannot be proven mathematically.

### 5. The Synthetic Identifier Squatting Hazard (`DEV-007`)
- **The Cause**: When converting unstructured vendor logs to canonical formats, naive converters generate sequential identifiers like `rec_0`, `rec_1`. If the original session already contained a record with that identifier, state shadowing occurs.
- **The Impact**: False `SL003` duplicate findings, corrupted event resolution, and broken replay bindings.
- **SessLint Solution**: A reserved collision-resistant namespace (`sesslint:synthetic:<adapter>:<ordinal>:<hash>`) backed by an active `SyntheticIdCollisionGuard` that asserts zero namespace collisions at ingest time.

---

## Core Invariants & Safety Guarantees

> [!IMPORTANT]
> **The Bottom Line on Safety & Atomicity**
>
> 1. **Source Immutability**: SessLint never modifies user files in-place. `check`, `scan`, `verify`, and `repair --dry-run` perform zero file writes.
> 2. **Single Mutator Principle**: File mutation is strictly isolated to a single atomic executor (`sesslint/repair/executor.py`) via `tempfile` &rarr; `os.fsync` &rarr; `os.replace`.
> 3. **Kill-Safety**: Any unhandled crash or `SIGKILL` at any microsecond of execution leaves the original source byte-identical with zero orphaned temporary files.
> 4. **No Synthetic Truth**: SessLint never fabricates tool results, user approvals, or model tokens.
> 5. **TOCTOU Protection**: Dual-hash SHA-256 verification ensures that modifications to source files during execution immediately abort the pipeline.
> 6. **Zero Dependencies**: Built exclusively on the Python 3.11+ standard library. 100% offline, zero telemetry, zero background network calls.
> 7. **Privacy by Default**: Diagnostic reports and repair manifests are strictly content-free (prompts, code, keys, and tokens are scrubbed).
> 8. **Safety & Minimization Boundaries**: redaction is best-effort minimization, not a completeness guarantee. Furthermore, sesslint makes no semantic or side-effect safety claims.

---

## Four Layers of Correctness

SessLint partitions session validity into four orthogonal tiers:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 4: Semantic & Side-Effect Safety                                │
│  Did external mutations actually execute in the real world?            │
│  Enforcement: Explicit Abstention (SL203) - Never guess reality        │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Replay Conformance                                           │
│  Adherence to provider-specific turn alternation and role adjacency    │
│  Enforcement: Replay Profiles (neutral, claude-strict, openai-strict)  │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Structural & Relational Integrity                            │
│  DAG parentage, unique event IDs, causal tool call/result pairing      │
│  Enforcement: Core Rule Engine (SL003 - SL108)                         │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 1: Syntactic & Stream Framing                                   │
│  Valid UTF-8 byte stream, valid JSON/JSONL framing, streaming limits   │
│  Enforcement: Bounded Streaming Lookahead Reader (SL001, SL002)       │
└────────────────────────────────────────────────────────────────────────┘
```

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
# Direct install with pip
pip install sesslint

# Or isolated installation with pipx (recommended for global CLI)
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
sesslint check session.jsonl --profile neutral --json > report.json
```

---

## Interactive Terminal Showcase

Here is what SessLint looks like in action in production development environments:

### 1. Diagnosing a Corrupted Session (`sesslint check`)

```text
$ sesslint check corrupted_session.jsonl --profile claude-strict
[read-only] verdict: invalid | errors: 1 | warnings: 1 | files: H=0 I=1 U=0 R=0 S=0 | profile: claude-strict | adapter: claude-code-jsonl
Next Action: Run 'sesslint repair corrupted_session.jsonl --output <file>' to plan repair.

FINDINGS (2):
  [SL002] error [deterministic] at corrupted_session.jsonl:48:1
    Torn terminal record at line 48: unexpected end of stream mid-record
    Fingerprint: 8a4f10c3b9e27d14 | Span: byte 4096-4142
    Evidence: {"byte_offset": 4096, "byte_end": 4142, "record_ordinal": 47}

  [SL107] warning [manual] at corrupted_session.jsonl:24:1
    Adjacency violation: tool_use followed by user turn instead of tool_result
    Fingerprint: 3c2d89a10ef45b77 | Record: sesslint:synthetic:claude:23:7a8b
    Evidence: {"prior_role": "assistant", "current_role": "user"}

COVERAGE: 22 rules evaluated, 0 skipped.
ASSURANCE: A0 (unreadable) -> Replay invalid.
```

### 2. Surgical Atomic Repair (`sesslint repair`)

```text
$ sesslint repair corrupted_session.jsonl --output session.fixed.jsonl --policy conservative
[sesslint:repair] Target: corrupted_session.jsonl (size: 4,142 bytes)
[sesslint:repair] Strategy: conservative (zero data loss policy)
[sesslint:repair] Step 1/8: Pre-validation passed. Fingerprint: 8a4f10c3b9e27d14
[sesslint:repair] Step 2/8: Source SHA-256 pre-hashed: e3b0c44298fc1c149afbf4c8...
[sesslint:repair] Step 3/8: Applying 1 recipe:
  -> torn-terminal-record-discard: pruned 46 trailing torn bytes
[sesslint:repair] Step 4/8: In-memory revalidation passed. Zero SL203. Post-Assurance: A3
[sesslint:repair] Step 5/8: Committed atomically via tempfile -> fsync -> os.replace
[sesslint:repair] Step 6/8: Post-hashing verified source immutability. Output SHA-256: 9b2d8...
[sesslint:repair] Step 7/8: Temp file cleaned up.
[sesslint:repair] Step 8/8: Wrote cryptographic audit receipt: session.fixed.jsonl.manifest.json

[repaired-lossless] Output: session.fixed.jsonl (Assurance: A3 | 47 records preserved | 0 errors)
Next Action: Run 'sesslint verify corrupted_session.jsonl session.fixed.jsonl --manifest session.fixed.jsonl.manifest.json' to audit.
```

### 3. Cryptographic Audit & Verification (`sesslint verify`)

```text
$ sesslint verify corrupted_session.jsonl session.fixed.jsonl --manifest session.fixed.jsonl.manifest.json
[audit:pass] Manifest cryptographically matches source and output fingerprints.
[audit:pass] 7 verification checks passed:
  [✔] Source fingerprint verified (e3b0c44298fc1c149afbf4c8...)
  [✔] Output fingerprint verified (9b2d8f0714b629c8e821034a...)
  [✔] Idempotency key verified (64-hex SHA-256 bound to plan + policy)
  [✔] Manifest receipt immutable (created with O_EXCL)
  [✔] Output schema valid (sesslint.session/v1)
  [✔] Multiset parity verified (zero phantom records introduced)
  [✔] Idempotence verified: repairing output yields identical hash
VERDICT: VERIFIED (Replay Safe, Assurance Ceiling: A3)
```

---

## CLI Reference

```text
sesslint [--version] COMMAND [OPTIONS]
```

### Command Matrix

SessLint exposes eight CLI commands designed for both interactive developer usage and CI/CD automation:

| Command | Purpose | Mutates Disk? | Default Format | Exit Codes |
| :--- | :--- | :---: | :---: | :---: |
| **`sesslint check`** | Scan and lint a session file or directory for defects | **No** (read-only) | `auto` | `0`, `1`, `2` |
| **`sesslint scan`** | Traversal directory trees with 5-bucket triage summary | **No** (read-only) | `auto` | `0`, `1`, `2` |
| **`sesslint repair`** | Plan and execute atomic surgical session repairs | **Yes** (to `--output`) | `auto` | `0`, `1`, `2` |
| **`sesslint verify`** | 7-stage cryptographic audit of repair and manifest | **No** (read-only) | `auto` | `0`, `1`, `2` |
| **`sesslint bundle`** | Emit zero-leak diagnostic support bundle for bug/adapter reports | **Optional** (`--out`) | `auto` | `0`, `1`, `2` |
| **`sesslint validate-session`**| Validate canonical session against JSON Schema | **No** (read-only) | `canonical` | `0`, `1`, `2` |
| **`sesslint formats`** | List supported adapters and format schemas | **No** | N/A | `0` |
| **`sesslint version`** | Print diagnostic version environment struct | **No** | N/A | `0` |

---

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

---

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

---

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
> **Alpha Format Boundary**: Repair currently supports Canonical Session stream format (`schema_version: sesslint.session/v1`). Repair attempts on vendor formats (Claude Code / OpenAI Agents) safely refuse with Exit Code 2 and actionable instructions.

---

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

---

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

---

### Exit Codes

SessLint implements predictable, POSIX-compliant exit code semantics:

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

> [!CAUTION]
> **Live Store Protection**: If `--output` points to an active SQLite database (detected via SQLite format 3 header magic or `.sqlite`/`.db` extensions), SessLint **immediately aborts** with exit code `2` to protect live stores from corruption.

For comprehensive compatibility matrix across formats and validation profiles, consult the [Adapter & Profile Conformance Matrix](docs/MATRIX.md).

---

## Diagnostic Reason Codes (SL001–SL302)

SessLint implements **20 registered diagnostic codes**. Severity and repairability are maintained as independent dimensions. Detailed analytical documentation for each code is available in [`docs/codes/`](docs/codes/).

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
    code,                       # Diagnostic reason code (e.g., "SL001")
    adapter_id,                 # Active adapter name (e.g., "canonical", "claude-code-jsonl")
    adapter_version,            # Active adapter version (e.g., "1.0.0")
    profile_id,                 # Active profile name (e.g., "neutral", "claude-strict")
    profile_version,            # Active profile version (e.g., "1.0.0")
    norm_path,                  # Forward-slash normalized source path
    line,                       # 1-based source line (or None)
    ordinal,                    # 0-based stream record counter (or None)
    record_id,                  # Canonical or vendor record identifier (or None)
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

```mermaid
flowchart TD
    In[Input Session Finding] --> Q1{Is Side-Effect Unknown: SL203?}
    Q1 -->|YES| RefuseGlobal[Refuse Repair Globally: SL203-refusal]
    Q1 -->|NO| Q2{Policy Chosen?}
    Q2 -->|--policy conservative| ConsCheck{Proves Region Disjointness?}
    ConsCheck -->|YES: Pure disjoint regions| ConsExec[Deterministic Lossless Repair: Zero Data Loss]
    ConsCheck -->|NO: Scope unproven| ConsRefuse[Fail-Closed: side-effect-scope-unproven]
    Q2 -->|--policy salvage| SalvCheck{Explicit ACK Provided?}
    SalvCheck -->|YES: --acknowledge-side-effects| SalvExec[Controlled Lossy Pruning: Prunes dead branches]
    SalvCheck -->|NO| SalvRefuse[Fail-Closed: Missing ACK]
```

### Dual-Gate Side-Effect Abstention Engine

SessLint enforces side-effect safety through two distinct, mathematically sound layers:

1. **Global Gate (`SL203`)**: Unsafe continuation across loss (`SL203`) represents unrecoverable causal corruption. When `SL203` is present anywhere in a session, automated repair refuses all conservative and salvage transformations globally across the entire session (`SL203-refusal`).
2. **Scoped Gate (Conservative Recipes, DEV-013)**: For sessions containing side-effect-bearing tool calls without `SL203`, conservative repair does not refuse globally. Instead, each candidate repair step must prove **region-disjointness**: the step's affected record set (target records, relinked ancestors, and truncated spans) must have zero intersection with any event whose execution state is ambiguous (dangling calls, unknown side-effects, or unresolved results). If disjointness is proven, safe conservative repairs proceed cleanly. If the proof fails, repair fail-closes with `side-effect-scope-unproven` at both planning and execution layers.

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

To guarantee crash-safety across all platforms (Linux, macOS, Windows), mutation is strictly isolated to an 8-step atomic commit pipeline:

```mermaid
sequenceDiagram
    autonumber
    actor Client as Caller / CLI
    participant Planner as Plan & Validate
    participant Memory as In-Memory Pure Pipeline
    participant Temp as Tempfile (.tmp.pid.rand)
    participant Dest as Destination File
    participant Manifest as Manifest (.manifest.json)

    Client->>Planner: Execute plan on source file
    Planner->>Planner: Step 1: Pre-Validation (Fingerprint + Policy + TOCTOU check)
    Planner->>Planner: Step 2: Source Hashing (Compute source SHA-256 pre-hash)
    Planner->>Memory: Step 3: In-Memory Transformation (Pure recipe application)
    Memory->>Memory: Step 4: Revalidation (Schema parse + Multiset parity + zero SL203)
    Memory->>Temp: Step 5: Write to Tempfile + os.fsync(fd)
    Temp->>Dest: Step 5: Atomic os.replace(temp, dest)
    Dest->>Planner: Step 6: Post-Hashing (Verify source is byte-identical + output hash)
    Note over Temp: Step 7: Error Cleanup (try...finally guarantees unlinking)
    Planner->>Manifest: Step 8: Exclusive create (O_EXCL) of manifest + directory fsync
    Manifest-->>Client: Return RepairManifest + Certified Assurance
```

---

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
> **Receipt Immutability**: Manifest publication uses `O_EXCL` creation flags. SessLint refuses to silently overwrite an existing receipt file, ensuring that repair audit trails cannot be tampered with or accidentally wiped.

---

### Assurance Taxonomy (A0–A4)

Every SessLint report and manifest certifies an assurance score representing its placement on the correctness lattice:

| Level | Tag | Meaning | Replay Safe? |
| :---: | :--- | :--- | :---: |
| **`A0`** | `unreadable` | Parsing failed; file is malformed, torn, or unparseable. | ❌ No |
| **`A1`** | `parseable` | Records decoded successfully; relational integrity unverified. | ⚠️ Unverified |
| **`A2`** | `structurally-valid` | Graph DAG, event identities, and tool pairings verified. | ⚠️ Profile Dependent |
| **`A3`** | `profile-replay-valid` | Fully compliant with target provider replay constraints. | ✅ Replay Ready |
| **`A4`** | `reference-loader-equivalent` | Byte-for-byte or semantic round-trip equivalence verified. | ✅ High Assurance |

---

## Replay Profiles

Replay profiles encode vendor-specific conversation and tool-use constraints into declarative rule filters:

| Profile ID | Target Runtime | Adjacency Checks | Tool Boundary Rules |
| :--- | :--- | :--- | :--- |
| **`neutral`** *(default)* | Standard AI Agent Systems | Permissive | Standard call &rarr; result pairing |
| **`claude-strict`** | Anthropic Claude Code | High strictness | Turn alternation, no consecutive assistant turns |
| **`openai-strict`** | OpenAI Agents SDK / RunState | High strictness | Tool call ID matching, checkpoint parity |

```bash
# Validate against Claude turn alternation constraints
sesslint check session.jsonl --profile claude-strict

# Validate against OpenAI run-state checkpoints
sesslint check session.json --profile openai-strict
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
│                 (report.py, bundle.py, precheck.py)                    │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
┌───────────────────▼────────────────┐   ┌───────────▼───────────────────┐
│        Repair Execution Layer      │   │       Validation Engine       │
│  (executor.py, planner.py, packs)  │   │   (generic checks, profiles)  │
└───────────────────┬────────────────┘   └───────────┬───────────────────┘
                    │                                │
┌───────────────────▼────────────────────────────────▼───────────────────┐
│               Canonical Event Model & Provenance Coordinate            │
│                       (canonical.py, finding.py)                       │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    Adapters (Claude, OpenAI, Canonical)                │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                 Streaming I/O, Hashing & Atomic Primitives             │
│                      (io.py, atomic.py, source.py)                     │
└────────────────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> **The Anti-Leak Rule**: Generic rules and repair engines operate **exclusively** on canonical events. Vendor-specific concepts must never leak into generic validation rules.

---

## Ecosystem & Framework Integrations

SessLint easily integrates into popular autonomous agent frameworks:

### Anthropic Claude Code
Claude Code serializes user conversations and tool invocations to local project directories (`~/.claude/projects/`). Run SessLint directly against project trees:
```bash
sesslint check ~/.claude/projects/my-app/ --profile claude-strict --recursive
```

### OpenAI Agents SDK
When using the OpenAI Agents SDK, sessions export durable item lists. Validate exported artifacts:
```bash
sesslint check agent_export.json --profile openai-strict
```

### LangChain & LangGraph
Add SessLint validation inside custom checkpoint savers or state graphs before replaying history:
```python
from sesslint import precheck

def restore_agent_state(session_file: str) -> None:
    res = precheck(session_file, profile="neutral")
    if not res.ok:
        raise ValueError(f"Aborting session restore: {res.reason}")
    # Load session safely...
```

### PydanticAI
Gate model invocation inside the agent loop:
```python
from sesslint import precheck

def run_agent_turn(ledger_path: str) -> None:
    res = precheck(ledger_path, profile="claude-strict")
    if not res.ok:
        logger.error("Pre-request check failed: %s", res.reason)
        return
    # Proceed to model prompt...
```

---

## Python Library API

SessLint is engineered as both a standalone CLI and a high-performance, strictly typed Python library with 1:1 parity.

### One-Call Prevention API (`precheck`)

The `sesslint.precheck` function provides a zero-exception, one-call gate for agent runtime systems. It returns a frozen `PrecheckResult` with exit codes (`0`, `1`, `2`) and normalized reason codes (`clean`, `findings-error`, `findings-warning`, `detection-failed`, `io-error`, `usage-error`).

#### 1. Pre-Resume Gate (Prevent corrupt session reload)
```python
from sesslint import precheck

result = precheck("sessions/active.jsonl")
if not result.ok:
    raise RuntimeError(f"Cannot resume corrupted session: {result.reason}")
# Session verified; safe to resume agent execution
```

#### 2. Pre-Request Gate (Gate before invoking LLM provider)
```python
from sesslint import precheck

result = precheck("sessions/active.jsonl", profile="claude-strict")
if not result.ok:
    abort_request(f"Pre-request gate rejected session ({result.reason})")
# Session conforms to provider turn rules; send prompt to provider
```

#### 3. Pre-Compaction Gate (Safeguard before history compaction)
```python
from sesslint import precheck

result = precheck("sessions/active.jsonl")
if not result.ok:
    logger.warning("Session compaction skipped due to integrity issue: %s", result.reason)
    return
# Session structure intact; safe to compute compaction summary
```

---

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

---

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

## CI & Pre-Commit Integration

### GitHub Action (`sesslint-check`)

Run SessLint session checks natively in GitHub Actions with content-free summaries rendered directly to `$GITHUB_STEP_SUMMARY`:

```yaml
name: Session Integrity Gate

on: [push, pull_request]

jobs:
  check-sessions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate Session Artifacts
        uses: HPNChanel/sesslint/.github/actions/sesslint-check@main
        with:
          path: sessions/
          profile: neutral
          fail-on: error
```

#### Action Inputs

| Input | Description | Default |
| :--- | :--- | :--- |
| `path` | Path to session file or directory (required). | *required* |
| `profile` | Replay validation profile (`neutral`, `claude-strict`, `openai-strict`). | `neutral` |
| `format` | Session format adapter (`auto`, `canonical`, `claude-code-jsonl`, `openai-agents`). | `auto` |
| `fail-on` | Failure threshold (`error` or `warning`). | `error` |
| `package` | PyPI package specifier (activates on first PyPI release). | `sesslint` |
| `source-ref`| Local checkout path (`.`) or git ref for source install. | `""` |
| `python-version` | Python runtime version. | `3.11` |

---

### Pre-Commit Hook

Enforce session integrity locally before commits are created by adding SessLint to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/HPNChanel/sesslint
    rev: v0.1.0  # or git commit SHA
    hooks:
      - id: sesslint-check
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

The test suite covers unit, property-based, adversarial, fault-injection, and cross-adapter conformance testing:

```bash
# Run the complete test suite (1,400+ tests)
uv run pytest

# Run repair tests including fault-injection kill simulations
uv run pytest tests/repair/ -v

# Run cross-adapter conformance battery
uv run pytest tests/conformance/ -v

# Verify strict type safety (zero any, strict optional)
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
- **Cross-Adapter Conformance**: Parametrized test battery verifies `canonical`, `claude-code-jsonl`, and `openai-agents` against identical defect invariants.

---

## Safe Issue Reporting & Adapter Requests

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
- Review the [Adapter Contributor Guide](docs/ADAPTER_GUIDE.md) for building new format adapters.
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
