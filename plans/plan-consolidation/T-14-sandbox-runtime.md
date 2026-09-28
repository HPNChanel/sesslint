# T-14 — Revision-bound sandbox acceptance

- Status: functional acceptance PASS; performance acceptance PASS on this host (2026-09-28, T-10 sequence C); cross-platform gate remains external
- Depends on: T-10, T-12
- Authority: approved completion plan, 2026-09-27

## Requirements and implementation

Use ../sesslint-sandbox/run-20260927-completion with protected baseline.json, baseline-source and baseline.diff. Each measurement/revision gets new paths; failures are never replaced. Bind broad CLI/API, PowerShell and benchmark receipts to the final wheel/EXE/source hashes.

## Local acceptance evidence

OBSERVED: 370 original fixture hashes, 47 historical artifact hashes and the frozen runtime snapshot remain unchanged. Windows 3.11–3.14, conformance, installed 19-command CLI / 21-function API / 13 schemas, Unicode, multiprocessing, privacy, determinism, cancellation and source immutability pass. Python/PowerShell share identical 32-case results.

## Remaining conditions

The normative source gate and one consecutive three-run installed sequence now pass on this host (2026-09-28; see T-10 and COMPLETION_0.4.1 §Performance — failures from earlier sequences and the load-contaminated run are retained). One interrupted run had an unexplained stateful-test failure without a final traceback, and is retained as incomplete historical evidence; a covered reproduction and final full/fuzz suites pass. Do not invent a root cause. Clean Windows, external CI/signing/publication and deferred platforms remain separate UNVERIFIED conditions; retain NOT_RELEASE_READY until they are exercised.

## Evidence locations

[Current results and exact hashes](../../docs/COMPLETION_0.4.1.md) are authoritative.
The current handoff is `dist/sesslint-0.4.1-completion/`; raw evidence is retained
in `../sesslint-sandbox/run-20260927-completion/`. Original task bytes and the
pre-edit dirty source remain in that sandbox. Prior September 26 results are
history, not acceptance of changed source/artifact bytes.
