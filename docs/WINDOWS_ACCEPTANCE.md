# Portable Windows acceptance

The `sesslint-0.4.1-acceptance-windows.zip` candidate contains the Windows EXE,
starter kit, schemas, license/notice, checksums and a PowerShell 5.1+ runner.
It does not need Python, network access or administrator rights. The runner
does not change execution policy or other system settings.

Verify the ZIP hash against the delivery manifest before extraction. Published
assets additionally require the [signature and provenance checks](VERIFYING.md).
An unsigned local candidate has no publisher-signature claim.

Extract into a new directory, open PowerShell there and run:

```powershell
.\Test-SessLint.ps1 -PackageRoot . -ReceiptPath "$PWD\acceptance.json"
```

The runner verifies package members before executing the EXE. It copies verified
synthetic inputs into a new temporary directory with spaces and Unicode, relocates
the EXE, removes Python from the child's PATH and isolates HOME, agent roots,
application data and temporary paths. It never discovers your actual sessions.
Machine execution policies still apply; use your organization's approved process
for trusted scripts if execution is restricted.

The same `smoke-contract.json` drives the Python and PowerShell runners. All 32
cases must pass: identity, healthy/repairable/refused examples, four report formats,
Unicode filenames, serial/parallel scan parity, dry-run, plan/apply, one-shot repair,
verification, idempotence, adapters/profiles, missing input, hook and MCP.
Source hashes must remain unchanged; refusal must create neither output nor manifest.

`acceptance.json` binds the tested EXE, kit and contract hashes to the OS/build and
per-case results. `acceptance.json.logs/` retains stdout/stderr for each command,
including failures. Work files are retained at the path in the receipt. A retry
uses a new receipt filename; old evidence is never overwritten.

## Functional acceptance versus a clean machine

A PASS on a development machine proves the tested functionality only. Removing
Python from PATH does not prove that Python is absent from the machine. The runner
records discoverable Python commands/registry state and leaves `clean_windows`
as `UNVERIFIED`; it cannot establish how an operating system was provisioned.

For clean-machine evidence, run the exact package on a known clean Windows machine
or VM without Python installed. Retain its image/provisioning record with the
receipt and logs, then review the evidence together. An EXE with a different hash
must be tested again, including an EXE subsequently rebuilt by release CI.

The [starter kit](STARTER_KIT.md) explains ordinary usage and refusal handling.
The [current completion report](COMPLETION_0.4.1.md) separates local evidence from
cross-platform, signing and publication evidence still required for release.
