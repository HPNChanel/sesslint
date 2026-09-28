# T-13 — Current evidence and handoff

- Status: local reviewable handoff complete; overall readiness BLOCKED by T-10
- Depends on: T-10, T-11, T-12, T-14
- Authority: approved completion plan, 2026-09-27

## Requirements and implementation

Keep one current evidence entrypoint and new immutable candidate directory. Bind artifact hashes, source snapshot, toolchain, epoch and receipts. Replace fabricated console/absolute replay claims with exercised synthetic commands and explicit assurance limits. Preserve historical documents and artifacts.

## Local acceptance evidence

OBSERVED: wheel and sdist double-build hashes match at SOURCE_DATE_EPOCH 1790254221. README format and 106 affected documentation tests pass. MkDocs builds; 31 link warnings are confined to historical pages, zero current-page warnings. The handoff includes artifacts, starter/transfer kits, checksums, source binding, reproducibility, full/fuzz/coverage logs, installed/API receipts and all performance measurements.

## Remaining conditions

NOT_RELEASE_READY because normative latency and the three-run installed gate fail. LOCAL_READY requires every approved local gate. CANDIDATE_VERIFIED additionally requires the exact release commit, required platforms/clean Windows, signatures and provenance. PUBLISHED_VERIFIED requires both public download/hash/install checks. No commit/push/tag/publish occurred.

## Evidence locations

[Current results and exact hashes](../../docs/COMPLETION_0.4.1.md) are authoritative.
The current handoff is `dist/sesslint-0.4.1-completion/`; raw evidence is retained
in `../sesslint-sandbox/run-20260927-completion/`. Original task bytes and the
pre-edit dirty source remain in that sandbox. Prior September 26 results are
history, not acceptance of changed source/artifact bytes.
