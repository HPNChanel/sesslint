# Threat Model — SessLint *(next release)*

Structured threat model for an offline session-integrity checker and
conservative repair engine. Scope: the CLI/library as shipped — reading
hostile files, producing findings, planning and applying repairs, emitting
shareable reports. This document records what hostile input can attempt,
which bounds stop it, and which threats are declared out — so hardening
decisions are auditable and "it's offline" is not the whole security
story.

Method: assets → adversaries → trust boundaries → threats per boundary →
mitigations with `file:symbol` enforcement citations → out-of-scope →
residual-risk register. Every mitigation cites enforcing code and/or a
test; a mitigation without an enforcer is a bug report, not a doc line.

## 1. Assets

| Asset | What compromise means |
| ----- | --------------------- |
| Source file integrity | A repair writes bytes the user did not intend — fabricated or destroyed session history |
| Output correctness | Findings/reports misrepresent the ledger — corruption hidden or invented downstream |
| Host resources | CPU/memory/disk exhaustion from pathological input |
| Transcript privacy | Session payload content leaks into findings, reports, bundles, logs, or artifacts |
| Plan integrity | A stale or tampered repair plan is replayed against a changed or wrong file |

## 2. Adversaries

- **Hostile or corrupted input files** — the primary adversary; the tool's
  entire purpose is ingesting untrusted bytes.
- **Tampered manifests and repair plans** — a plan file edited after
  generation, or replayed against a different source.
- **Pathological-but-legal input** — files inside format rules that are
  crafted to exhaust resources (deep nesting, huge lines, record floods).

Explicitly *not* adversaries: remote attackers (no network surface),
hostile code inside the tool's own process (pickle/eval banned by
invariant — see §6).

## 3. Trust boundaries

```text
file ──B1──> reader ──B2──> parser ──B3──> canonical ──B4──> checks
                                                    │
plan ──B5──> executor ──B6──> write        report ◄──┘
```

- **B1 file→reader**: untrusted bytes enter; size/encoding bounds apply.
- **B2 reader→parser**: line structure and JSON decode; torn/malformed
  records isolated.
- **B3 parser→canonical**: adapter interpretation; unknown/drifted shapes
  fail closed into `opaque`/`unknown`, never guessed.
- **B4 canonical→checks**: rules judge structure; findings carry
  content-free evidence only.
- **B5 plan→executor**: a plan is re-validated before it may act.
- **B6 executor→write**: the only mutation boundary; atomicity and
  drift re-checks live here.

## 4. Threat catalog

### T-01 Oversized file — memory/CPU exhaustion

- **Boundary**: B1.
- **Attack**: multi-GB file; memory blowup before any parse.
- **Mitigation**: `DEFAULT_MAX_FILE_BYTES` = 100 MB refuses up front;
  `ReaderLimits.max_file_bytes` enforced by the reader
  (`io.py:ReaderLimits`). Streaming line iteration (`io.py`) avoids
  whole-file buffering on the check path.
- **Evidence**: `tests/io/test_limits.py`, `tests/io/test_hostile.py`;
  field test exercised 104 MB input — refused, not parsed.

### T-02 Oversized line — parser/memory exhaustion

- **Boundary**: B2.
- **Attack**: a single record line of hundreds of MB; per-line work
  explodes.
- **Mitigation**: `DEFAULT_MAX_LINE_BYTES` = 8 MB; oversized lines produce
  a bounded `LIMIT` finding, never a load
  (`io.py` line-limit path emitting `[detail: LIMIT]`).
- **Evidence**: `tests/io/test_limits.py`;
  `fixtures/hostile/huge_line.jsonl` (≈1.5 MiB variant in
  `fixtures/corpus/big-lines/` parses clean — the bound is a wall, not a
  heuristic).

### T-03 Deep nesting — recursion/stack exhaustion

- **Boundary**: B2→B3.
- **Attack**: JSON nested thousands of levels; recursive decode crashes
  the process.
- **Mitigation**: `DEFAULT_MAX_DEPTH` = 100 enforced during decode;
  violation yields a `LIMIT` finding (`io.py` depth check).
- **Evidence**: `tests/io/test_limits.py`;
  `fixtures/hostile/deep_nesting.json`; field test exercised 3000-deep
  nesting — bounded finding, no crash.

### T-04 Record flood — unbounded work per file

- **Boundary**: B2→B4.
- **Attack**: millions of tiny records; check and memory cost grow
  without limit.
- **Mitigation**: `ReaderLimits.max_records` optional cap (validated
  positive-int, `io.py`); the perf contract (`bench/perf_250k.py` —
  250 k events / 100 MB) bounds expected cost per unit input.
- **Residual note**: `max_records` defaults to `None` — see R-02.

### T-05 Decode attacks — NUL bytes, invalid UTF-8, BOM tricks

- **Boundary**: B1.
- **Attack**: NUL-injected or mis-encoded bytes crash decoders or smuggle
  content past encoding assumptions.
- **Mitigation**: `io.py:probe_stream_encoding` / `probe_text_encoding`
  pre-scan — incremental UTF-8 decode; `None` = clean, `"nul"` /
  `"utf8"` = refused class. Malformed records become bounded findings
  (SL001), never process-fatal.
- **Evidence**: `tests/io/test_encoding.py`, `tests/io/test_hostile.py`;
  `fixtures/hostile/null_bytes.jsonl`, `truncated_utf8.bin`,
  `bom_mismatch.jsonl`, `crlf_mixed.jsonl`; stateful fuzz rules
  `inject_bytes`/`truncate_bytes` (`tests/fuzz/test_stateful_sessions.py`).

### T-06 Malformed/torn records — parser escape

- **Boundary**: B2.
- **Attack**: truncated tails, mid-stream garbage, duplicate JSON keys —
  parser misreads or silently drops data.
- **Mitigation**: per-record isolation — one bad record cannot abort the
  file; torn terminals → SL002, malformed → SL001, duplicate keys →
  SL303 (bounded at `_MAX_DUP_KEYS_PER_RECORD` = 16 reports per record).
- **Evidence**: `tests/io/test_dup_keys.py`, `tests/io/test_hostile.py`;
  `fixtures/hostile/{torn_final,malformed_nonterminal}.jsonl`.

### T-07 Vendor-shape injection — format confusion

- **Boundary**: B3.
- **Attack**: records exploiting adapter assumptions — unknown critical
  fields, mid-file schema drift, unsupported versions.
- **Mitigation**: fail-closed mapping — unknown critical record → SL302,
  unsupported version → SL301, mid-file drift → SL304; unmapped content
  lands in `opaque`/`unknown` kinds, never reinterpreted
  (`adapters/*` type tables; ADR-0005 vendor-neutral core).
- **Evidence**: `tests/conformance/test_adapter_suite.py`;
  `fixtures/corpus/claude-2x/queue_operation.jsonl`,
  `codex-telemetry/unknown_type.jsonl`.

### T-08 Content exfiltration via findings — privacy breach

- **Boundary**: B4 and all reporting surfaces.
- **Attack**: craft a file whose payload strings would be echoed into
  findings/reports/bundles that get pasted into CI logs and tickets.
- **Mitigation**: content-free evidence is enforced at construction —
  `finding.py:_enforce_content_free_evidence_recursive` (P0-04) rejects
  payloads in evidence and detects cyclic structures; fingerprints hash
  an allowlisted evidence subset only
  (`finding.py:compute_finding_fingerprint`); unknown types are
  described by `safe_discriminator` shape descriptors, never verbatim.
  Paths are privacy-minimized (`report.py:minimize_path`,
  `minimize_id`).
- **Evidence**: `tests/privacy/` (safe discriminator, bundle privacy,
  run-state evidence); ADR-0006.

### T-09 Path tricks — disclosure via absolute paths

- **Boundary**: reporting surfaces.
- **Attack**: filenames or directory layouts leak user identity, project
  names, or secrets embedded in paths.
- **Mitigation**: all emitted paths go through
  `report.py:minimize_path` — home-relative/hashed minimization;
  `.._<hash>` form is deliberately irreversible.
- **Evidence**: `tests/privacy/`, `tests/test_determinism.py`;
  problem-matcher docs record the irreversibility as designed
  (`contrib/editors/README.md`).

### T-10 TOCTOU — source mutated between check and write

- **Boundary**: B6.
- **Attack**: the source file changes after the plan was computed;
  repair lands on bytes it was not proven safe for.
- **Mitigation**: executor re-validates before mutating — plan
  fingerprint recomputation, cap bounds, policy match, and TOCTOU
  abstention check (`repair/executor.py` step 1); writeback re-reads the
  source line and recomputes its record hash — drift aborts (`R4`,
  `repair/writeback.py`).
- **Evidence**: `repair/executor.py` TOCTOU re-check hook + tests;
  `tests/repair/test_executor.py`.

### T-11 Stale/tampered plan replay — wrong-file repair

- **Boundary**: B5.
- **Attack**: a plan file is edited after generation, or replayed against
  a different/newer source — repair steps land where they don't belong.
- **Mitigation**: `repair/fingerprint.py:compute_plan_fingerprint` —
  deterministic SHA-256 over the plan excluding the fingerprint field,
  binding the `policy` field into the domain (P0-03); the executor
  recomputes and refuses on mismatch (`PlanTampered`).
- **Evidence**: `tests/repair/test_executor.py`, plan apply/batch tests.

### T-12 Repair overreach — fail-open writes

- **Boundary**: B5→B6.
- **Attack**: a recipe applies where preconditions no longer hold, or a
  "repair" fabricates state (e.g. guessing unknown side-effect state).
- **Mitigation**: fail-closed policy is a pinned invariant —
  `repair/refusals.py` named "MUST refuse" rules for conservative and
  salvage profiles; SL203 is a permanent refusal (ADR-0002);
  preconditions re-verified at apply time; post-hashing reads back the
  target.
- **Evidence**: `tests/repair/` refusal matrices;
  `docs/codes/SL203.md`.

### T-13 Unsafe dynamic execution — code injection via input

- **Boundary**: entire pipeline.
- **Attack**: input crafted to trigger `eval`/`exec`/`pickle`/
  `subprocess` paths — arbitrary code execution from data.
- **Mitigation**: banned outright — zero occurrences permitted in
  `src/sesslint`; CI gate is static, not runtime-dependent.
- **Evidence**: `tests/io/test_no_eval.py` (forbidden-API audit +
  zero-dev-deps check).

### T-14 Nondeterminism injection — verification bypass

- **Boundary**: B4 and reporting.
- **Attack**: input or environment variance changes output bytes —
  fingerprints, signatures, and provenance become unverifiable.
- **Mitigation**: deterministic serialization via
  `_canonical_codec`/`determinism.py` primitives; double-run byte
  identity tested; parallel and incremental scan modes must emit
  identical bytes to sequential.
- **Evidence**: `tests/test_determinism.py`,
  `tests/fuzz/test_stateful_sessions.py` determinism invariants;
  ADR-0008.

## 5. Hostile-fixture ↔ threat map

| Fixture family | Threat entries |
| -------------- | -------------- |
| `huge_line.jsonl`, corpus `big-lines/` | T-02 |
| `deep_nesting.json` | T-03 |
| `null_bytes.jsonl`, `truncated_utf8.bin`, `bom_mismatch.jsonl`, `crlf_mixed.jsonl` | T-05 |
| `torn_final.jsonl`, `malformed_nonterminal.jsonl`, `empty.jsonl`, `whitespace_only.jsonl` | T-06 |
| `cycle_3.jsonl`, `self_parent.jsonl`, `interleaved_branches.jsonl`, `duplicate_ids/` | T-07 boundary (structural legality) |
| corpus `claude-2x`, `codex-telemetry`, `mixed-integrity`, `compaction-chains` | T-07 |
| stateful fuzz mutations (`inject_bytes`, `splice_blob`, `truncate_*`) | T-05, T-06, T-14 |

## 6. Declared out-of-scope

- **Malicious code execution via deserialization** — `eval`, `exec`,
  `pickle`, `subprocess` are banned by hard invariant and CI-gated
  (`tests/io/test_no_eval.py`); the threat exists only if the invariant
  is broken, which is a repository-integrity issue, not a runtime one.
- **Network attacks** — no network code exists in `src/sesslint`
  (`tests/test_no_egress.py`, `tests/test_no_telemetry.py`); there is no
  remote surface to model.
- **Supply-chain of the tool itself** — release signing, provenance, and
  distribution integrity are the release-dist domain: `RELEASING.md`,
  `.github/workflows/release.yml` (Sigstore + SLSA), `SECURITY.md`
  "Reproducible, hash-bound artifacts".
- **Compromised Python runtime/stdlib** — assumed trustworthy; a hostile
  interpreter voids any userspace mitigation.
- **OS-level adversaries** — filesystem permissions, hostile binaries on
  PATH, and kernel compromise are outside a userspace linter's reach.

## 7. Residual-risk register

| ID | Accepted risk | Rationale |
| -- | ------------- | --------- |
| R-01 | Regex/pathology CPU cost inside per-record bounds | Pathological-but-legal records can be slow per record without crossing byte/depth caps; bounded by T-04 record accounting and the perf contract; a hard per-record time budget would add nondeterminism |
| R-02 | `max_records` is opt-in (`None` default) | The common path is memory-bounded already (streaming + per-record isolation); the cap exists for hostile-scale inputs — callers guarding against floods should set it |
| R-03 | Path minimization is one-way | `.._<hash>` minimized paths cannot be reversed to the original — designed so reports are shareable; debugging against a local copy uses real paths from the user's own invocation |
| R-04 | Refusal outcomes can hide real damage | Fail-closed means some genuinely damaged sessions are refused rather than repaired; the alternative (guessed repair) destroys evidential value silently — see ADR-0002 |
| R-05 | Baseline/suppression files are user-managed | A stale baseline can suppress fresh findings; baselines are explicit opt-in user artifacts (`sesslint baseline`), not auto-maintained state |
| R-06 | Denial-of-service via many files in one scan | Per-file bounds apply but aggregate cost scales with corpus size; mitigated by parallel-scan determinism and `--max-*` flags; unbounded corpus size is a caller responsibility |

## 8. Cross-references

- `SECURITY.md` — reporting policy and release-artifact guarantees.
- `docs/adr/` — ADR-0002 (fail-closed), ADR-0005 (vendor-neutral core),
  ADR-0006 (content-free findings), ADR-0008 (determinism).
- `docs/SPEC.md` — normative canonical model (B3 boundary contract).
- `FIXTURES.md` — synthetic-fixture policy (fixture provenance is itself
  a privacy control).
