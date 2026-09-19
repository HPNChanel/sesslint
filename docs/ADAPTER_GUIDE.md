# Adapter Authoring & Conformance Guide

This document is the authoritative specification and implementation guide for contributing format adapters to **SessLint**. It establishes the technical contracts, privacy invariants, synthetic namespacing rules, and verification requirements for transforming vendor-specific session streams into normalized, audit-ready canonical sessions.

External contributors should start with the normative contract in
[ADAPTER_SDK.md](ADAPTER_SDK.md) (Adapter SDK v1); this guide is the deeper
internal reference.

---

## 1. Architectural Role of Adapters

In SessLint's architecture, an **Adapter** is a pure, side-effect-free translation layer. Its sole responsibility is parsing external agent session artifacts (e.g. Claude Code JSONL, OpenAI Agents SDK JSON, or custom orchestrator traces) into a normalized sequence of [`CanonicalEvent`](../src/sesslint/canonical.py) objects.

```mermaid
flowchart LR
    A["Vendor Session File (.json / .jsonl)"] --> B["Adapter: detect_*()"]
    B -->|Score >= CONFIDENCE_MIN| C["Adapter: load_*()"]
    C --> D["Sequence[CanonicalEvent]"]
    C --> E["list[Finding] (SL301 / SL302)"]
    D --> F["Core Checks (SL001 - SL203)"]
    E --> G["Report Generator"]
```

### Core Invariants

1. **Zero External Dependencies**: Adapters must execute exclusively using the Python 3.11+ standard library (`json`, `re`, `pathlib`, `hashlib`).
2. **Zero In-Place Mutation (Immutability)**: Adapters are read-only. Reading a session must never modify the file on disk or touch access times. Persisting adapter output is the job of `sesslint export` (repair-enablement, atomic write to a new file), never of the adapter itself.
3. **Zero Dynamic Evaluation**: No use of `eval()`, `pickle`, `ctypes`, or dynamic code execution.
4. **Zero Content Leaks in Diagnostics**: Discriminator failures and version errors must never leak user prompt content or session data into finding evidence.
5. **Deterministic Event Generation**: Calling the adapter twice on identical source bytes must produce bit-for-bit identical event IDs, content hashes, and finding fingerprints.

---

## 2. Adapter Interface Contract

Every adapter lives in `src/sesslint/adapters/<adapter_name>.py` and must export the following standard interface.

### A. Detection Function: `detect_<adapter>`

```python
def detect_<adapter>(first_bytes: bytes, filename: str) -> float:
    """Evaluate format confidence score for a candidate session artifact.

    Args:
        first_bytes: The initial byte prefix of the file (up to SNIFF_BYTES = 65536).
        filename: Base filename of the target artifact.

    Returns:
        Confidence float score strictly bounded to [0.0, 1.0].
    """
```

- **Threshold Rules**:
  - A matching session must score $\ge \text{CONFIDENCE\_MIN}$ (`0.55`).
  - Competing adapters must score lower by at least $\text{MARGIN\_MIN}$ (`0.15`) to achieve a `clear-winner` verdict in `detect_format`.
- **Heuristics**:
  - Prefer inspecting structural signatures in `first_bytes` (e.g. characteristic JSON keys, schema declarations, or JSONL record tags).
  - Use filename extensions only as weak tie-breakers; never rely on file extension alone.

### B. Ingestion Loader Function: `load_<adapter>`

```python
def load_<adapter>(
    path: Path | str,
    *,
    limits: ReaderLimits | None = None,
) -> tuple[Sequence[CanonicalEvent], list[Finding]]:
    """Parse session artifact into canonical events and adapter-level findings.

    Args:
        path: Path to session file.
        limits: Hostile-input reader limits (defaults to ReaderLimits()).

    Returns:
        Tuple of (events, findings). Findings contain format-level issues
        such as SL301 (unsupported version) or SL302 (unknown discriminator).
    """
```

- **Limits Enforcement**:
  - Wrap stream iteration with [`ReaderLimits`](../src/sesslint/io.py) to prevent line-length or record-count resource exhaustion.
- **Fail-Closed on Unknown Version (`SL301`)**:
  - Define an immutable version allowlist:
    ```python
    SUPPORTED_<ADAPTER>_VERSIONS: Final[frozenset[str]] = frozenset({"1.0", "1.1"})
    ```
  - When encountering an unlisted version, append an `SL301` error finding with structured evidence:
    ```python
    findings.append(
        make_finding(
            code=SL301,
            severity=Severity.ERROR,
            repairability=Repairability.MANUAL,
            message_template="Unsupported format version: {version_raw}",
            source=SourceRef(path=str(path), line=line_num),
            evidence={
                "version_raw": raw_version,
                "supported_set": sorted(SUPPORTED_ < ADAPTER > _VERSIONS),
            },
        )
    )
    ```

### C. Unknown Discriminators & Safe Bounding (`SL302`)

When an unknown record type or turn kind is encountered:
1. Do not crash or discard the record silently.
2. Filter the discriminator through [`safe_discriminator`](../src/sesslint/adapters/detect.py) before embedding in evidence:
   - Allowlisted safe alphanumeric identifiers ($\le 32$ chars, matching `^[a-zA-Z0-9_.-]+$`) are echoed verbatim.
   - Overlong or hostile strings containing punctuation, control characters, or secrets are bounded to `<type:len=N>` with `type_truncated=True`.

### D. Synthetic ID Namespacing (DEV-007)

If external session records do not provide persistent, globally-unique IDs:
1. **Reserved Namespace**: Synthetic IDs must strictly follow the prefix:
   ```text
   sesslint:synthetic:<adapter_id>:<seq>:<hash8>
   ```
2. **Helper API**:
   Use [`synthetic_event_id`](../src/sesslint/adapters/synthetic.py):
   ```python
   from sesslint.adapters.synthetic import synthetic_event_id

   event_id = synthetic_event_id(
       adapter="<adapter_id>",
       seq=record_index,
       source_hint=str(path),
       payload_len=len(raw_record_bytes),
   )
   ```
3. **Collision Guard**:
   Maintain a [`SyntheticIdCollisionGuard`](../src/sesslint/adapters/synthetic.py) instance during ingest to prevent duplicate IDs or collisions with native IDs.
4. **Never Leak Legacy Prefixes**:
   Do **not** use prefixes like `rec_` or `evt_` for synthetic IDs. Native IDs must set `original_id=event_id`, while synthetic IDs must set `original_id=None`.

### E. Run-State & Checkpoint Projections (DEV-011)

When importing orchestrator checkpoints, execution states, or runtime memory:
- **Redact Raw Values**: Never embed raw prompts, environment variables, or tool outputs into checkpoint finding evidence.
- **Structural Projections**: Transform runtime states into key name lists, value shapes, and lengths:
  ```json
  {
    "state_shape": {
      "variables": ["user_intent", "step_count"],
      "types": {"user_intent": "str:len=42", "step_count": "int"}
    }
  }
  ```

---

## 2. Fixture Authoring & Provenance Recipe

Every adapter must be accompanied by comprehensive test fixtures under `fixtures/<adapter>/` and `fixtures/conformance/<adapter>/`.

### Directory Layout

```text
fixtures/
├── <adapter>/
│   ├── PROVENANCE.json
│   ├── basic.jsonl
│   ├── version_unsupported.jsonl
│   └── ...
└── conformance/
    └── <adapter>/
        ├── PROVENANCE.json
        ├── healthy.<ext>
        ├── version_unsupported.<ext>
        ├── parallel_tool.<ext>
        ├── synthetic_ids.<ext>
        ├── discriminator_safe.<ext>
        └── discriminator_hostile.<ext>
```

### Mandatory `PROVENANCE.json`

Every directory containing fixtures must have a `PROVENANCE.json` defining license and origin:

```json
{
  "fixtures": {
    "healthy.jsonl": {
      "origin": "synthetic",
      "license": "Apache-2.0",
      "sanitized": true,
      "contains_pii": false,
      "description": "Minimal healthy session conforming to format specification."
    }
  }
}
```

### Privacy & Sanitization Hygiene

- **Zero Real Transcripts**: Real session logs from production environments or private LLM conversations are strictly prohibited.
- **Canary Tokens in Secret Tests**: For privacy regression tests, use designated dummy tokens matching known secret prefixes (`sk-ant-api03-...`, `sk-live-...`, `AKIA...`) with synthetic payloads only.

---

## 3. Running the Conformance Suite

SessLint provides a unified, data-driven cross-adapter conformance test suite in [`tests/conformance/test_adapter_suite.py`](../tests/conformance/test_adapter_suite.py).

To execute the suite locally:

```bash
# 1. Run the unified cross-adapter suite
uv run pytest tests/conformance/test_adapter_suite.py -v

# 2. Run all conformance matrix gates
uv run pytest tests/conformance/ -q

# 3. Run adapter-specific unit test suites
uv run pytest tests/adapters/ -q

# 4. Verify privacy invariants and secret shielding
uv run pytest tests/privacy/ -q
```

All tests must pass 100% green before submitting an adapter PR.

---

## 4. Version-Bump Checklist

When an upstream vendor publishes a new schema or format revision (e.g. Claude Code v2.0 or OpenAI Agents SDK v1.5):

- [ ] **1. Create Reproduction Fixtures**:
  - Add an unedited sample of the new format to `fixtures/<adapter>/`.
  - Document origin and license in `fixtures/<adapter>/PROVENANCE.json`.
- [ ] **2. Verify Detection Independence**:
  - Confirm `detect_<adapter>` recognizes the new revision without false-triggering other adapters.
- [ ] **3. Update Version Set**:
  - Add the new version string to `SUPPORTED_<ADAPTER>_VERSIONS` in `src/sesslint/adapters/<adapter>.py`.
- [ ] **4. Update Schema Mapping**:
  - Map any newly introduced turn kinds or message fields to `CanonicalEvent`.
  - Ensure any unknown tags map gracefully to `SL302` with bounded discriminators.
- [ ] **5. Run Conformance Suite**:
  - Run `uv run pytest tests/conformance/test_adapter_suite.py -v`.
- [ ] **6. Update Documentation**:
  - Update supported version tables in `docs/codes/` and `src/sesslint/cli.py` (`formats` command).

---

## 5. Adapter Fidelity Backlog

The table below tracks known open questions regarding upstream vendor formats. These items are classified as `SECONDARY_UNVERIFIED` until primary upstream documentation or consented real-world session captures confirm their semantics.

| Format / Adapter | Mechanism / Field | Current Classification | Status | Evidence Needed |
| :--- | :--- | :--- | :--- | :--- |
| `claude-code-jsonl` | `sourceToolAssistantUUID` | `SECONDARY_UNVERIFIED` | Pending Research | Upstream trace proving multi-agent subagent linkage semantics. |
| `claude-code-jsonl` | Record-type vocabulary expansion | `SECONDARY_UNVERIFIED` | Monitored | Verification whether new Claude Code CLI versions introduce types beyond `user`, `assistant`, `tool`. |
| `claude-code-jsonl` | Summary / Compaction records | `SECONDARY_UNVERIFIED` | Monitored | Confirming whether Claude Code emits explicit checkpoint markers or relies on implicit turn drops. |
| `openai-agents` | Compaction items in run items | `SECONDARY_UNVERIFIED` | Monitored | Schema verification for OpenAI Agents SDK memory condensation records. |
| `openai-agents` | Multi-agent handoff delegation | `SECONDARY_UNVERIFIED` | Monitored | Conformance traces for `agent_handoff` items between distinct agent definitions. |
| `codex-rollout` | Envelope `type` vocabulary expansion | `SECONDARY_UNVERIFIED` | Monitored | New envelope types beyond `session_meta`, `response_item`, `event_msg`, `turn_context`, `world_state`, `inter_agent_communication_metadata`, `compacted` route to SL302 by design. |
| `codex-rollout` | `response_item` payload-type expansion | `SECONDARY_UNVERIFIED` | Monitored | New payload types beyond the observed set route to SL302 by design. |
| `codex-rollout` | Explicit format-version marker | `SECONDARY_UNVERIFIED` | Monitored | Wild rollouts carry no `rollout_version`/`format_version`; if upstream adds one, the SL301 supported-set must be revisited. `cli_version` is never version-gated. |
| `codex-rollout` | Subagent history interleave (`subagent_history_start_ordinal`) | `SECONDARY_UNVERIFIED` | Pending Research | Evidence whether forked-agent records interleave in one stream or arrive as separate rollouts; linear-by-ordinal parentage is the current honest model. |

---

## 6. Codex Rollout Adapter Notes (DW-T-12)

`codex-rollout` ingests Codex CLI/Desktop `rollout-*.jsonl` session files.

- **Envelope**: every record is `{type, timestamp, ordinal, payload}`.
  `response_item` payloads carry their own `type`.
- **Kind mapping**: `function_call`/`custom_tool_call` → `tool_call`
  (actor `assistant`); `function_call_output`/`custom_tool_call_output` →
  `tool_result` (actor `tool`, `correlation_id` = `call_id`); `message` →
  `message` with role disambiguation (`developer` → `system`);
  `agent_message` → `assistant` `message`; `reasoning` → `assistant` `opaque`
  (encrypted content never projected); `compacted` → `compaction_boundary`;
  `session_meta`/`event_msg`/`turn_context`/`world_state`/
  `inter_agent_communication_metadata` → `system` `opaque` with identifier
  fields only.
- **Parentage**: rollout records have no explicit parent linkage. The adapter
  maps `parent_id` linearly — an event's parent is the previous emitted event
  when continuity is provable (no dropped line between them, and envelope
  `ordinal` values consecutive when present). Torn/lost records surface as
  honest new roots (`SL006`/`SL007`) rather than fabricated links.
- **Version negotiation**: the wild format is versionless. Explicit markers
  (`rollout_version`, `format_version`, `schema_version`, `export_version`)
  are honored when present against `SUPPORTED_CODEX_ROLLOUT_VERSIONS`;
  `cli_version` in `session_meta` is evidence-only and never gated.
- **Async pairing**: Codex interleaves asynchronous tool activity by design;
  `SL107` adjacency findings are expected on real sessions (see
  `docs/MATRIX.md` — Codex Rollout Notes).
- **Detection**: `detect_codex_rollout` scores the rollout envelope
  signature; `detect_openai_agents` contains a matching disambiguation guard
  so rollouts never tie with the Agents SDK export format.

---

## Shape Inventory (dev tool) *(next release)*

`scripts/shape_inventory.py` walks a local session directory and reports
which record `type` values, payload types, and key names exist — the
early-warning system for vendor format drift, run against real data
without committing any of it:

```bash
python scripts/shape_inventory.py ~/.codex/sessions --json
python scripts/shape_inventory.py DIR --unknown-only   # just the drift diff
python scripts/shape_inventory.py DIR --known-only     # histograms, no diff
```

- **Content-free by construction**: emits type names, key names, and
  counts only — never string values, payloads, or file paths beyond the
  root argument. Output is safe to paste into issues.
- **Live known-sets**: the diff imports the adapter tables directly
  (`TYPE_MAP`, `KNOWN_RECORD_KEYS`, `ENVELOPE_OPAQUE_TYPES`,
  `RESPONSE_ITEM_TYPE_MAP`, `KNOWN_ENVELOPE_KEYS`, `KNOWN_PAYLOAD_KEYS`,
  canonical `VALID_KINDS`/`KNOWN_EVENT_FIELDS`), so "unknown" always means
  "absent from the adapter the repo actually ships".
- **Bounded**: caps distinct types at 512 per set and keys at 4096,
  honoring the same file-size limits as `io.py`; marks `truncated` when
  caps are hit. Read-only, stdlib-only, no network — a maintainer-side
  script, not part of the wheel.

Workflow: run it over a real local tree after an adapter update — every
name in the `unknown` diff is either a format change to map, an
`SL302`-class unknown the adapter already flags honestly, or a new
opaque envelope to classify.

---

*For questions or guidance on contributing adapters, open an issue using the [Adapter Request Template](../.github/ISSUE_TEMPLATE/adapter_request.md) or join repository discussions.*
