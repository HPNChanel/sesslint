# T-12 — Installed artifacts and portable Windows acceptance

- Status: local installed acceptance PASS; clean Windows UNVERIFIED
- Depends on: T-10, T-11 for overall release readiness
- Authority: approved completion plan, 2026-09-27

## Requirements and implementation

Build the PowerShell 5.1+ transfer ZIP with EXE, starter kit, schema, license/notice, checksums and guidance. Both runners use the common 32-case catalog. Check hashes/version before execution, isolate HOME/TEMP/agent roots, use Unicode/spaced paths, preserve sources and refuse output for SL203. No Python/admin/system configuration changes are required by the runner.

## Local acceptance evidence

OBSERVED: final wheel, sdist and EXE each pass 32 shared CLI cases. PowerShell 5.1.26100.9549 matches Python case IDs, commands, exits and EXE/kit hashes. Wheel and EXE each additionally pass 116 cases / 147 invocations / 19 CLI commands / all 34 detector codes. Installed API passes 21 functions and 13 schemas with cancellation and a socket-denial audit.

## Remaining conditions

Run this exact transfer ZIP on known clean Windows without Python. Retain provisioning evidence, receipt and logs. Development-host PASS or removing Python from PATH does not qualify. Any changed EXE hash invalidates the prior clean-host qualification. Required other OS receipts remain deferred, with CI gates intact.

## Evidence locations

[Current results and exact hashes](../../docs/COMPLETION_0.4.1.md) are authoritative.
The current handoff is `dist/sesslint-0.4.1-completion/`; raw evidence is retained
in `../sesslint-sandbox/run-20260927-completion/`. Original task bytes and the
pre-edit dirty source remain in that sandbox. Prior September 26 results are
history, not acceptance of changed source/artifact bytes.
