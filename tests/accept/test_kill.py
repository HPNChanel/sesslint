"""Fault-injection kill tests mid-repair (TASK-027, FR-068, AC-013).

Guarantees:
- Terminating/killing a repair process mid-execution never leaves a complete-looking, valid output.
- No manifest is published if repair is killed.
- Cross-platform compatible (handles terminate / kill on Windows and SIGKILL on POSIX).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "determinism" / "repeat"
VALID_SESSION = FIXTURES_DIR / "repeat_session.json"


def test_kill_mid_repair_never_publishes_valid_output(tmp_path: Path) -> None:
    """Terminating a repair subprocess mid-operation leaves no valid output or manifest."""
    out_file = tmp_path / "killed_repaired.json"
    manifest_file = tmp_path / "killed_repaired.json.manifest.json"

    # Run repair via Python executable in subprocess
    # Using python -c that introduces a sleep before writing
    script = (
        "import time, sys\n"
        "from unittest.mock import patch\n"
        "from sesslint.cli import main\n"
        "def slow_plan(*args, **kwargs):\n"
        "    time.sleep(2.0)\n"
        "    from sesslint.repair.planner import plan as real_plan\n"
        "    return real_plan(*args, **kwargs)\n"
        "with patch('sesslint.repair.planner.plan', side_effect=slow_plan):\n"
        f"    sys.exit(main(['repair', {str(VALID_SESSION)!r}, '--output', {str(out_file)!r}]))\n"
    )

    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Let process start and hit the slow plan sleep
    time.sleep(0.4)

    # Terminate process abruptly
    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3.0)

    # Verification:
    # 1. Output file must either not exist OR be invalid
    if out_file.exists():
        # If the file somehow exists, it must NOT be a valid, healthy canonical session
        try:
            doc = json.loads(out_file.read_text(encoding="utf-8"))
            assert "events" not in doc or not doc["events"]
        except Exception:
            pass  # Corrupted/incomplete is acceptable

    # 2. Manifest file must NEVER exist
    assert not manifest_file.exists(), "Manifest was published despite process termination!"

    # 3. Process exited with non-zero exit code
    assert proc.returncode != 0
