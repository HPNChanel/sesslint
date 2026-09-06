"""Smoke tests for SessLint package, CLI entry points, and licensing."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import sesslint
from sesslint.cli import main


def verify_license_content(content: str) -> None:
    """Validate Apache-2.0 license markers in text."""
    if "Apache License" not in content or "Version 2.0" not in content:
        raise ValueError("Missing Apache-2.0 license markers")


def test_import_version() -> None:
    """Verify package importability and semver-shaped __version__."""
    assert hasattr(sesslint, "__version__")
    assert isinstance(sesslint.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", sesslint.__version__), (
        f"Version {sesslint.__version__!r} is not semver-shaped"
    )


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI --help exits 0, mentions sesslint, and contains no vendor terms."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    stdout_lower = captured.out.lower()
    assert "sesslint" in stdout_lower
    assert "claude" not in stdout_lower, "Vendor term 'claude' leaked into generic CLI help"
    assert "openai" not in stdout_lower, "Vendor term 'openai' leaked into generic CLI help"


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI --version exits 0 and prints the package version."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    # On some Python/argparse versions --version outputs to stdout or stderr
    output = captured.out or captured.err
    assert f"sesslint {sesslint.__version__}" in output


def test_cli_bare_invocation() -> None:
    """Verify CLI with empty argv exits 0."""
    exit_code = main([])
    assert exit_code == 0


def test_cli_unknown_flag() -> None:
    """Verify CLI with unknown flag exits with non-zero code."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--nonexistent-flag-test"])
    assert exc_info.value.code != 0


def test_subprocess_entrypoint_help() -> None:
    """Verify python -m sesslint --help executes __main__.py and exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "sesslint", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "sesslint" in result.stdout.lower()
    assert "claude" not in result.stdout.lower()
    assert "openai" not in result.stdout.lower()


def test_subprocess_entrypoint_version() -> None:
    """Verify python -m sesslint --version executes __main__.py and prints version."""
    result = subprocess.run(
        [sys.executable, "-m", "sesslint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    output = result.stdout or result.stderr
    assert f"sesslint {sesslint.__version__}" in output


def test_subprocess_entrypoint_unknown_flag() -> None:
    """Verify python -m sesslint with unknown flag exits non-zero."""
    result = subprocess.run(
        [sys.executable, "-m", "sesslint", "--bogus-flag-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_license_present() -> None:
    """Verify LICENSE file exists in repository root and contains Apache-2.0 markers."""
    repo_root = Path(__file__).resolve().parent.parent
    license_path = repo_root / "LICENSE"

    assert license_path.is_file(), f"LICENSE file not found at {license_path}"

    content = license_path.read_text(encoding="utf-8")
    verify_license_content(content)


def test_license_adversarial_validation() -> None:
    """Verify license validator fails loudly on missing or corrupted markers."""
    with pytest.raises(ValueError, match="Missing Apache-2.0 license markers"):
        verify_license_content("MIT License Copyright 2026")

    with pytest.raises(ValueError, match="Missing Apache-2.0 license markers"):
        verify_license_content("Apache License without version specification")


def test_no_network_imports() -> None:
    """Verify importing sesslint / cli / __main__ does not import network modules."""
    script = (
        "import sys\n"
        "import sesslint\n"
        "import sesslint.cli\n"
        "import sesslint.__main__\n"
        "network_modules = [\n"
        "    'socket', 'urllib.request', 'http.client',\n"
        "    'ftplib', 'poplib', 'imaplib', 'smtplib', 'ssl', 'asyncio',\n"
        "]\n"
        "imported = [mod for mod in network_modules if mod in sys.modules]\n"
        "if imported:\n"
        "    print(f'Network modules imported: {imported}', file=sys.stderr)\n"
        "    sys.exit(1)\n"
        "sys.exit(0)\n"
    )
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = str(repo_root / "src")
    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{existing_pp}" if existing_pp else src_dir

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, f"Importing sesslint loaded network modules:\n{result.stderr}"
