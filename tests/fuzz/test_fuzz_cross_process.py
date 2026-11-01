"""CL-16: cross-process determinism (DEV determinism invariant).

The same hostile input run through every report surface in separate
interpreters with different ``PYTHONHASHSEED``, ``TZ`` and locale settings
must produce byte-identical output and exit codes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fuzz.test_fuzz_hostile_inputs import MARKER, OPS, SEEDS, _mutated

_DRIVER = r"""
import contextlib, io, json, sys
from sesslint.cli import main
out = []
for argv in json.load(sys.stdin):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code
    out.append([argv[0], code, buf.getvalue(), err.getvalue()])
sys.stdout.buffer.write(json.dumps(out, ensure_ascii=True).encode())
"""

_ENVS = (
    {"PYTHONHASHSEED": "0", "TZ": "UTC", "LC_ALL": "C.utf8", "LANG": "C.utf8"},
    {"PYTHONHASHSEED": "4242", "TZ": "Pacific/Kiritimati", "LC_ALL": "POSIX", "LANG": "C"},
    {"PYTHONHASHSEED": "1", "TZ": "America/St_Johns", "LC_ALL": "", "LANG": "tr_TR.UTF-8"},
)


def _run(argvs: list[list[str]], env_over: dict[str, str], cwd: Path) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LC_", "SESSLINT_"))}
    env.update(env_over)
    env.pop("PYTHONUTF8", None)
    proc = subprocess.run(
        [sys.executable, "-c", _DRIVER],
        input=json.dumps(argvs).encode(),
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")[-2000:]
    return proc.stdout


@given(adapter=st.sampled_from(sorted(SEEDS)), ops=OPS, other=OPS)
# Three interpreters per example: capped for the dev budget (campaign: 150).
@settings(deadline=None, max_examples=5, suppress_health_check=[HealthCheck.too_slow])
def test_reports_are_byte_identical_across_processes(
    adapter: str, ops: list[tuple[str, int]], other: list[tuple[str, int]]
) -> None:
    ext = ".json" if adapter == "openai-agents" else ".jsonl"
    work = Path(tempfile.mkdtemp(prefix="sl-cl16-xp-"))
    try:
        (work / f"a{ext}").write_bytes(_mutated(adapter, ops))
        (work / f"b{ext}").write_bytes(_mutated(adapter, other))
        a, b = f"a{ext}", f"b{ext}"
        argvs = [
            ["check", a, "-f", "json"],
            ["check", a, "-f", "sarif"],
            ["check", a, "-f", "html"],
            ["check", a],
            ["check", ".", "-f", "json"],
            ["triage", a, "-f", "json"],
            ["triage", a],
            ["bundle", a, "--json"],
            ["stats", ".", "--json"],
            ["stats", "."],
            ["diff", a, b, "--json"],
            ["diff", a, b],
            ["repair", a, "--dry-run", "--json"],
        ]
        outputs = [_run(argvs, env, work) for env in _ENVS]
        assert outputs[0] == outputs[1] == outputs[2]
        assert MARKER.encode() not in outputs[0]
        for name, code, _out, _err in json.loads(outputs[0]):
            assert code in (0, 1, 2), name
    finally:
        shutil.rmtree(work, ignore_errors=True)
