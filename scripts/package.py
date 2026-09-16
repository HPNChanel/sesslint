#!/usr/bin/env python3
"""Build orchestrator for SessLint native binaries (PyInstaller + signing hooks).

Prerequisite — PyInstaller is a BUILD-TIME-only dependency (never shipped in the
wheel, never a runtime dependency). Install the dedicated extra first:

    pip install -e ".[packaging]"       # or: uv pip install "pyinstaller>=6"

Usage (from the repository root):

    python scripts/package.py [--platforms auto|windows|macos|linux] \
        [--outdir dist/bin]

Pipeline:
  1. Runs ``python -m PyInstaller packaging/sesslint.spec`` into a staging dir.
  2. Renames the artifact deterministically:
     ``sesslint-<version>-<os>-<arch>[.exe]`` (version read from
     ``src/sesslint/_version.py`` — the single source of truth).
  3. Writes ``SHA256SUMS`` next to the binaries, one ``"<sha256>  <name>"``
     line per artifact (mirroring ``sha256sum`` output format).
  4. Runs OPT-IN signing hooks. Every hook is skipped cleanly (warning printed,
     exit code still 0) when its credentials are absent or its tool is missing:

       * Windows Authenticode — env ``CODESIGN_PFX`` (PKCS#12 path; optional
         ``CODESIGN_PFX_PASSWORD``) or ``CERT_THUMBPRINT`` (cert already in the
         machine/user store) -> ``signtool sign /fd sha256 /tr <ts> /td sha256``.
       * macOS — env ``APPLE_SIGNING_IDENTITY`` -> ``codesign --sign`` with
         hardened runtime; env ``APPLE_NOTARY_PROFILE`` -> zip +
         ``xcrun notarytool submit --keychain-profile <profile> --wait``.
       * Any OS — env ``GPG_KEY_ID`` -> ``gpg --detach-sign --armor`` producing
         ``<binary>.asc``.

Offline-by-default: this script performs no network access itself. The only
potentially networked operations are the signing tools you explicitly opted
into (timestamps/notarization are inherently networked). No telemetry, no
analytics.

Note: PyInstaller does not cross-compile — ``--platforms`` must resolve to the
host OS (``auto`` picks the host). Multi-OS release binaries are produced by
the ``binaries`` matrix job in ``.github/workflows/release.yml``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "packaging" / "sesslint.spec"
VERSION_PY = REPO_ROOT / "src" / "sesslint" / "_version.py"

SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "arm64": "arm64",
}

# RFC 3161 timestamp authority for Authenticode signing (used only when the
# CODESIGN_PFX/CERT_THUMBPRINT hook is explicitly enabled).
TIMESTAMP_URL = "http://timestamp.digicert.com"


def _info(message: str) -> None:
    print(f"[package] {message}")


def _warn(message: str) -> None:
    print(f"[package] WARNING: {message}", file=sys.stderr)


def _err(message: str) -> None:
    print(f"[package] ERROR: {message}", file=sys.stderr)


def host_platform() -> str:
    """Map sys.platform to one of SUPPORTED_PLATFORMS."""
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise SystemExit(f"Unsupported host platform for packaging: {sys.platform!r}")


def host_arch() -> str:
    """Return a normalized architecture token (x86_64, arm64, ...)."""
    machine = platform.machine().lower()
    return ARCH_ALIASES.get(machine, machine or "unknown")


def package_version() -> str:
    """Read __version__ from src/sesslint/_version.py without importing it."""
    match = re.search(r'__version__\s*=\s*"([^"]+)"', VERSION_PY.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"Could not parse __version__ from {VERSION_PY}")
    return match.group(1)


def artifact_name(version: str, os_name: str, arch: str) -> str:
    """Deterministic artifact name: sesslint-<version>-<os>-<arch>[.exe]."""
    suffix = ".exe" if os_name == "windows" else ""
    return f"sesslint-{version}-{os_name}-{arch}{suffix}"


def _run(cmd: list[str], description: str) -> bool:
    """Run a command; return True on success, warn + False on any failure."""
    _info(f"{description}: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        _warn(f"tool not found on PATH: {cmd[0]} — skipping {description}")
        return False
    except (OSError, subprocess.CalledProcessError) as exc:
        _warn(f"{description} failed: {exc}")
        return False
    return True


def run_pyinstaller(staging: Path, workpath: Path) -> Path:
    """Invoke PyInstaller with the repo spec; return the produced binary path."""
    probe = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], capture_output=True)
    if probe.returncode != 0:
        raise SystemExit(
            "PyInstaller is not installed for this interpreter. Install the "
            'build-time extra first: pip install -e ".[packaging]"'
        )
    _info(f"PyInstaller {probe.stdout.decode(errors='replace').strip()}")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(staging),
        "--workpath",
        str(workpath),
        str(SPEC_PATH),
    ]
    _info("building with PyInstaller: " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"PyInstaller build failed: {exc}") from exc

    produced = staging / ("sesslint.exe" if host_platform() == "windows" else "sesslint")
    if not produced.is_file():
        raise SystemExit(f"PyInstaller did not produce expected binary: {produced}")
    return produced


# ---------------------------------------------------------------------------
# Signing hooks — all OPT-IN. Absent credentials or missing tools warn and
# continue (exit 0); nothing here runs unless explicitly enabled via env.
# ---------------------------------------------------------------------------


def sign_windows(binary: Path) -> bool:
    """Authenticode-sign via signtool when CODESIGN_PFX or CERT_THUMBPRINT is set."""
    pfx = os.environ.get("CODESIGN_PFX")
    thumbprint = os.environ.get("CERT_THUMBPRINT")
    if not pfx and not thumbprint:
        _info("windows signing skipped (set CODESIGN_PFX or CERT_THUMBPRINT to enable)")
        return False
    if shutil.which("signtool") is None:
        _warn("signing credentials present but 'signtool' not on PATH — skipping")
        return False
    cmd = ["signtool", "sign", "/fd", "sha256", "/tr", TIMESTAMP_URL, "/td", "sha256"]
    if pfx:
        cmd += ["/f", pfx]
        password = os.environ.get("CODESIGN_PFX_PASSWORD")
        if password:
            cmd += ["/p", password]
    else:
        cmd += ["/sha1", thumbprint or ""]
    cmd.append(str(binary))
    return _run(cmd, "windows Authenticode signing")


def sign_macos(binary: Path) -> bool:
    """codesign + optional notarization when APPLE_* env vars are set."""
    signed = False
    identity = os.environ.get("APPLE_SIGNING_IDENTITY")
    if not identity:
        _info("macOS signing skipped (set APPLE_SIGNING_IDENTITY to enable)")
    elif shutil.which("codesign") is None:
        _warn("APPLE_SIGNING_IDENTITY set but 'codesign' not on PATH — skipping")
    else:
        signed = _run(
            [
                "codesign",
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                identity,
                str(binary),
            ],
            "macOS codesign",
        )

    profile = os.environ.get("APPLE_NOTARY_PROFILE")
    if not profile:
        _info("macOS notarization skipped (set APPLE_NOTARY_PROFILE to enable)")
    elif shutil.which("xcrun") is None:
        _warn("APPLE_NOTARY_PROFILE set but 'xcrun' not on PATH — skipping")
    else:
        # notarytool accepts archives, not bare Mach-O binaries.
        bundle = binary.with_suffix(binary.suffix + ".zip")
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(binary, binary.name)
        if _run(
            [
                "xcrun",
                "notarytool",
                "submit",
                str(bundle),
                "--keychain-profile",
                profile,
                "--wait",
            ],
            "macOS notarization (notarytool)",
        ):
            _run(
                ["xcrun", "stapler", "staple", str(binary)],
                "macOS staple (best-effort; bare binaries may not accept tickets)",
            )
        bundle.unlink(missing_ok=True)
    return signed


def sign_gpg(binary: Path) -> bool:
    """Emit <binary>.asc via gpg --detach-sign --armor when GPG_KEY_ID is set."""
    key_id = os.environ.get("GPG_KEY_ID")
    if not key_id:
        _info("GPG signing skipped (set GPG_KEY_ID to enable)")
        return False
    if shutil.which("gpg") is None:
        _warn("GPG_KEY_ID set but 'gpg' not on PATH — skipping")
        return False
    signature = binary.with_name(binary.name + ".asc")
    return _run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--local-user",
            key_id,
            "--armor",
            "--detach-sign",
            "--output",
            str(signature),
            str(binary),
        ],
        "GPG detached signature",
    )


def apply_signing_hooks(binary: Path, os_name: str) -> None:
    """Run every opt-in signing hook applicable to the target OS."""
    if os_name == "windows":
        sign_windows(binary)
    elif os_name == "macos":
        sign_macos(binary)
    sign_gpg(binary)


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256sums(outdir: Path, artifacts: list[Path]) -> Path:
    """Write SHA256SUMS ("<hash>  <name>" per line) covering the binaries."""
    sums_path = outdir / "SHA256SUMS"
    lines = [f"{sha256_file(p)}  {p.name}" for p in sorted(artifacts)]
    # Write raw bytes so SHA256SUMS always uses LF endings — keeps
    # `sha256sum -c` verification working identically on every OS.
    sums_path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    _info(f"wrote {sums_path}:\n" + "\n".join(lines))
    return sums_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build SessLint native binaries via PyInstaller with "
        "opt-in signing hooks. See module docstring for the full contract.",
    )
    parser.add_argument(
        "--platforms",
        choices=["auto", *SUPPORTED_PLATFORMS],
        default="auto",
        help="Target platform (default: auto = host OS). PyInstaller cannot "
        "cross-compile, so an explicit value must match the host OS.",
    )
    parser.add_argument(
        "--outdir",
        default="dist/bin",
        help="Output directory for the renamed binary + SHA256SUMS "
        "(default: dist/bin; relative paths resolve against the repo root).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    target = host_platform() if args.platforms == "auto" else args.platforms
    host = host_platform()
    if target != host:
        _err(
            f"cannot build for '{target}' on a '{host}' host — PyInstaller does "
            "not cross-compile. Use the per-OS matrix job in "
            ".github/workflows/release.yml for multi-OS binaries."
        )
        return 2

    version = package_version()
    arch = host_arch()
    final_name = artifact_name(version, target, arch)
    outdir = Path(args.outdir)
    if not outdir.is_absolute():
        outdir = REPO_ROOT / outdir
    staging = outdir / ".staging"
    workpath = REPO_ROOT / "build" / f"pyinstaller-{target}-{arch}"
    outdir.mkdir(parents=True, exist_ok=True)
    staging.mkdir(parents=True, exist_ok=True)

    _info(f"target={target} arch={arch} version={version} -> {outdir / final_name}")
    produced = run_pyinstaller(staging, workpath)

    binary = outdir / final_name
    binary.unlink(missing_ok=True)
    shutil.move(str(produced), binary)
    if target != "windows":
        binary.chmod(0o755)
    shutil.rmtree(staging, ignore_errors=True)
    _info(f"built {binary}")

    apply_signing_hooks(binary, target)
    write_sha256sums(outdir, [binary])
    _info("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
