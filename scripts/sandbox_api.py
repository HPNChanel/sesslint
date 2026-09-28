"""Exercise every exported API function against an installed wheel, offline.

Execute with the sandbox interpreter (-I) and a fresh --work directory. Only
synthetic inputs are copied. An audit hook rejects socket creation throughout.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any


def run(args: argparse.Namespace) -> None:
    args.fixtures = args.fixtures.resolve()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    home = work / "home"
    home.mkdir()
    os.environ.update(
        HOME=str(home),
        USERPROFILE=str(home),
        CODEX_HOME=str(home / ".codex"),
        CLAUDE_CONFIG_DIR=str(home / ".claude"),
    )
    os.chdir(work)

    def offline(event: str, _args: tuple[object, ...]) -> None:
        if event == "socket.__new__":
            raise AssertionError("Network attempted in offline API acceptance")

    sys.addaudithook(offline)
    import sesslint
    from sesslint import api

    assert Path(sesslint.__file__).is_relative_to(Path(sys.prefix))
    assert not [r for r in importlib.metadata.requires("sesslint") or [] if "extra ==" not in r]
    source = work / "source.jsonl"
    healthy = work / "healthy.jsonl"
    shutil.copyfile(args.fixtures / "repair_cli/basic/source.jsonl", source)
    shutil.copyfile(args.fixtures / "canonical/minimal.json", healthy)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (source, healthy)}
    called = []

    def call(name: str, *pos: Any, **kw: Any) -> Any:
        result = getattr(api, name)(*pos, **kw)
        called.append(name)
        return result

    assert not call("check_file", healthy).findings
    assert not call("check_bytes", healthy.read_bytes(), format="canonical").findings
    assert not call("check", healthy).findings
    assert call("check", work).files
    assert call("check_dir", work).files
    assert call("scan_bytes", healthy.read_bytes(), format="canonical").files
    assert call("precheck", healthy).ok
    assert call("validate_session", healthy)
    assert call("build_bundle", source).report
    assert (
        call("build_internal_error_envelope", ValueError("synthetic"), error_id="ERR-synthetic")[
            "code"
        ]
        == "INTERNAL_ERROR"
    )
    assert call("plan", source).steps
    plan = call("plan_repair", source)
    assert plan.steps
    assert call("repair_preview", source).steps
    _, manifest = call("apply_plan", source, plan.to_dict(), output_path=work / "applied.jsonl")
    assert manifest
    assert call("verify", source, work / "applied.jsonl", work / "applied.jsonl.manifest.json").ok
    assert call("repair", source, output_path=work / "direct.jsonl")[1]
    assert (work / "applied.jsonl").read_bytes() == (work / "direct.jsonl").read_bytes()
    assert call("repair_many", [source], output_dir=work / "batch")
    assert call("diff_sessions", healthy, healthy)
    assert call("stats_paths", [healthy])
    assert call("export_file", healthy, work / "export.jsonl")
    assert call("doctor_report", quick_checks=True)
    assert all(p.path.is_relative_to(home) for p in call("discover_session_roots"))
    token = api.CancellationToken()
    token.cancel()
    try:
        api.check_file(healthy, cancel_token=token)
    except api.OperationCancelled:
        pass
    else:
        raise AssertionError("Cancellation ignored")
    events = []
    api.check_file(source, progress_cb=events.append)
    assert events and all(isinstance(e, api.ProgressEvent) for e in events)
    functions = {n for n in api.__all__ if inspect.isfunction(getattr(api, n))}
    assert set(called) == functions, functions - set(called)
    loaded = []
    for module, names in {
        "canonical": ["session"],
        "finding": ["finding"],
        "report": ["report", "manifest"],
        "scan": ["scan"],
        "repair.planner": ["plan"],
        "bundle": ["bundle"],
        "diff": ["diff"],
        "doctor": ["doctor"],
        "stats": ["stats"],
        "seal": ["seal"],
        "preview": ["preview"],
        "batch": ["batch"],
    }.items():
        m = importlib.import_module("sesslint." + module)
        for name in names:
            assert getattr(m, "load_" + name + "_schema")()["$schema"]
            loaded.append(name)
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (source, healthy)}
    receipt = {
        "status": "PASS",
        "module": sesslint.__file__,
        "version": importlib.metadata.version("sesslint"),
        "public_functions": sorted(functions),
        "schemas": loaded,
        "network": "socket creation denied by audit hook",
        "source_immutable": True,
        "progress": len(events),
        "cancellation": "PASS",
    }
    (work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, ensure_ascii=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    run(parser.parse_args())
