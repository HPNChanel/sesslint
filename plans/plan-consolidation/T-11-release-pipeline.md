# T-11 — Immutable release and retry

- Status: local implementation and regressions PASS; external proof UNVERIFIED
- Depends on: T-10 for release acceptance
- Authority: approved completion plan, 2026-09-27

## Requirements and implementation

Use prior-attempt Jobs API history to prove a creation step never ran before allowing an initial build. Restore by immutable ID with commit/version/archive and asset digests; refuse missing, expired, ambiguous, altered or unqueryable evidence. Preserve exact-commit CI → build/smoke → complete signed draft → provenance → PyPI → public PyPI install/hash verification → GitHub promotion → public verification. Retain failed restore/benchmark diagnostics.

## Local acceptance evidence

OBSERVED: full suites include retry-after-build/assemble, partial draft/PyPI, promotion prerequisites, metadata whitelist and wrong-hash receipt regressions. Actual candidate staging selected only wheel and sdist despite man-page, starter-kit and Windows acceptance archives. Workflow validation passes.

## Remaining conditions

Remote environment/Trusted Publisher configuration, real OIDC signatures/provenance and public channel checks are UNVERIFIED. Confirm the pypi environment reviewer gate before triggering tags; review clean-Windows provisioning and receipt against the exact signed CI EXE hash before publication. Unit signatures are fixtures, never signing evidence.

## Evidence locations

[Current results and exact hashes](../../docs/COMPLETION_0.4.1.md) are authoritative.
The current handoff is `dist/sesslint-0.4.1-completion/`; raw evidence is retained
in `../sesslint-sandbox/run-20260927-completion/`. Original task bytes and the
pre-edit dirty source remain in that sandbox. Prior September 26 results are
history, not acceptance of changed source/artifact bytes.

SOURCE_VERIFIED API contracts (2026-09-27): [attempt jobs/steps](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt) and [artifact identity/digest/expiry/download](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact). These verify API shape, not execution of a release.
