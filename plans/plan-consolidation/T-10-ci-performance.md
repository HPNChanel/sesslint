# T-10 — Performance and Windows gates

- Status: implemented; performance acceptance PASS on this host (2026-09-28); cross-platform CI runs remain the external gate
- Depends on: T-01
- Authority: approved completion plan, 2026-09-27

## Requirements and implementation

Reuse strict decoders within each load; reduce common-path validation, identity/ordering/graph allocations and unnecessary compaction indexes. Preserve duplicate keys, unsafe IDs, depth/encoding/number limits, findings, fingerprints, coverage and loss accounting. Missing/non-finite measurements fail; 512 MiB fails. No global session-data cache was introduced.

2026-09-28 follow-up: the canonical JSONL path now decodes the single-document probe from the first physical line only, skips slice copies for blank-line detection, feeds the SL009 tracker through zero-copy memoryview spans, and decodes each record without its line terminator so the whitespace trim is a no-op for clean lines. Identity, graph, ordering, tool-pairing and checkpoint loops read exact `SessionEvent` fields directly instead of repeated generic attribute/mapping probing; the SL203 trigger scan collects checkpoint and compaction indexes in one pass. Profiled call count dropped from ~29.8M to ~22.5M; all changes keep duplicate-key detection, unsafe-ID handling, depth/encoding/number limits, finding semantics, fingerprints, coverage and loss accounting byte-identical (semantic comparison hash unchanged across 320 fixtures: `d440766775261226c3ffa9137ac3ebf54bc391493e27fc60f82e360f8ec04e67`).

## Local acceptance evidence

OBSERVED: Windows Python 3.11.9–3.14.3 each passes 3,318 tests with one FIFO skip; each separate CI fuzz suite passes 21 tests. Coverage on 3.11 is 87.74%. Ruff whole repo, format, strict mypy and actionlint pass. The unchanged 10k report timing gate passes in fresh processes. Semantic comparison: 960 rows, no differences, with the exception-only limitation documented.

OBSERVED 2026-09-28 (same host, Python 3.11.9, unchanged 250k / 104,277,879-byte input, sha256 `38406debf39ce2f161a2ad7af382593519e179e71fe580ff7b96871aef3eebeb`): source fresh-process runs 7.562, 9.411, 8.793 s PASS; one run measured 35.199 s FAIL while a fuzz suite was deliberately running concurrently — retained as host-load evidence, not a code regression. Installed-wheel artifact `sesslint-0.4.1-py3-none-any.whl` (sha256 `2f8567935f6c7e716efe63988ee8ed797ddf2ebd5f5f7f4f0042954b3e99236f`, source digest `206d16946d35be4849c32020bacde613522b8afa518b64a9b6e0a8b5cc29c940`): sequence A measured 22.116 FAIL / 14.730 / 12.936 s; sequence B 14.661 / 13.333 / 15.221 FAIL; sequence C 14.614 / 12.510 / 13.861 s — **full three-run sequence PASS**, peak RSS 388–391 MiB in all runs. Receipts under `scratch/installed-bench/`.

## Remaining conditions

The three-run installed sequence now passes on this host, but wall-time on this machine remains load-sensitive (observed spread 7.5–35.2 s on identical bytes). Prior failures are retained above and in `scratch/installed-bench/`/`scratch/bench_input_250k.jsonl`; none are selected as acceptance. Linux/macOS CI runs remain the external gate for the platform matrix. No LOCAL_READY claim until the full prescribed acceptance sequence (tests, fuzz, coverage, determinism, reproducible build, installed acceptance) is re-executed end-to-end on the current tree.

## Evidence locations

[Current results and exact hashes](../../docs/COMPLETION_0.4.1.md) are authoritative.
The current handoff is `dist/sesslint-0.4.1-completion/`; raw evidence is retained
in `../sesslint-sandbox/run-20260927-completion/`. Original task bytes and the
pre-edit dirty source remain in that sandbox. Prior September 26 results are
history, not acceptance of changed source/artifact bytes.
