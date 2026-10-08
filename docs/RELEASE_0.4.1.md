# SessLint 0.4.1

This patch improves CLI/API release delivery while preserving schema/API v1,
exit codes, four existing adapters, three profiles and zero runtime dependencies.

Malformed plan containers and unsupported profiles now return domain refusals
instead of unhandled exceptions. Canonical parsing, graph/checkpoint traversal
and secret scanning reduce processing cost without changing detector results.
Frozen binaries and installed preview/batch APIs can resolve their schemas.
Directory HTML reports now include remediation, and secret warnings direct
users to review and rotate credentials.

Windows reports accept Unicode filenames in redirected output. Frozen binaries
also support parallel directory scans; worker startup and Unicode filenames are
now exercised by the shared installed-artifact smoke test.

The test corpus adds actual public detection goldens for 34 codes, 70 labeled
synthetic secret cases across 14 families, adapter/plan fuzzing and 84 public
repair integration combinations. These labels establish synthetic correctness;
they are not measurements of detection accuracy on real transcripts.

The planned public delivery set includes wheel, sdist and native executables for Windows/macOS/Linux,
man pages and a starter kit with synthetic healthy/repairable/refused examples,
PowerShell/POSIX commands, schemas and license/notice. Follow the
[starter-kit guide](STARTER_KIT.md) for `check → plan → apply → verify`.
Use the [release procedure](https://github.com/HPNChanel/sesslint/blob/main/RELEASING.md) to verify downloaded hashes,
Sigstore signatures and SLSA provenance.

Repair modifies an explicit output copy. SL203 remains refused. A successful
structural verification does not prove application replay, semantic correctness,
side-effect safety, complete secret detection or recovery of absent bytes.
Review assurance/coverage and validate resume in the originating application.

Publication status is determined by the public release and downloaded receipts,
not this notes file or a local Git tag. During preparation, see
[current completion evidence](COMPLETION_0.4.1.md) and the historical
[initial delivery evidence](DELIVERY_0.4.1.md). Only Windows artifacts have been
tested locally. New adapters, desktop, native S2/S3,
GHCR and package-manager activation remain outside this patch's release scope.

The Windows delivery also includes a [portable acceptance kit](WINDOWS_ACCEPTANCE.md)
whose PowerShell runner needs no Python. It preserves failure logs and separates
functional PASS from clean-machine qualification. The release pipeline verifies
that its package and receipt match the exact EXE and starter-kit hashes.
