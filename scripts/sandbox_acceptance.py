"""Persistent, synthetic installed CLI acceptance; never reads real agent roots.

Run with an unused --work directory, a copied fixture tree, starter kit and either
an installed Python or executable. This is process/directory isolation, not a VM.
Every invocation and output is retained, including failures. No publishing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import locale
import os
import shutil
import subprocess
import time
import zipfile
from collections.abc import Callable
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: argparse.Namespace) -> bool:
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    logs = work / "logs"
    logs.mkdir()
    with zipfile.ZipFile(args.kit) as archive:
        for member in archive.namelist():
            if not (work / member).resolve().is_relative_to(work):
                raise ValueError("Unsafe kit member")
        archive.extractall(work)
    shutil.copytree(args.fixtures, work / "fixtures")
    home = work / "home"
    for name in (".claude/projects", ".codex/sessions", "temp", "appdata", "localappdata"):
        (home / name).mkdir(parents=True)
    # Only the child receives these values; host configuration stays untouched.
    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "COVERAGE", "SESSLINT"))
    }
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(home / "appdata"),
            "LOCALAPPDATA": str(home / "localappdata"),
            "TMP": str(home / "temp"),
            "TEMP": str(home / "temp"),
            "CODEX_HOME": str(home / ".codex"),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "PYTHONUTF8": "1",
            "NO_COLOR": "1",
        }
    )
    if args.python:
        command = [str(args.python.resolve()), "-I", "-X", "utf8", "-m", "sesslint"]
    else:
        exe = work / args.binary.name
        shutil.copyfile(args.binary, exe)
        command = [str(exe)]
        env["PATH"] = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32")
    for source, dest in (
        ("claude.jsonl", ".claude/projects/test.jsonl"),
        ("codex.jsonl", ".codex/sessions/test.jsonl"),
    ):
        shutil.copyfile(work / "examples" / source, home / dest)
    before = {
        str(p.relative_to(work)): sha(p)
        for folder in ("examples", "fixtures")
        for p in (work / folder).rglob("*")
        if p.is_file()
    }
    receipt = {
        "schema_version": 1,
        "entrypoint_sha256": sha(args.binary or args.python),
        "kind": "binary" if args.binary else "installed-wheel",
        "isolation": "directory and child environment, not VM",
        "cases": [],
        "invocations": [],
    }

    def invoke(argv: list[str], exits: tuple[int, ...] = (0,), stdin: str = "") -> str:
        start = time.perf_counter()
        p = subprocess.run(
            command + argv,
            cwd=work,
            env=env,
            input=stdin.encode("utf-8"),
            capture_output=True,
            timeout=90,
        )

        def decode(raw: bytes) -> str:
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode(locale.getencoding())

        stdout, stderr = decode(p.stdout), decode(p.stderr)
        index = len(receipt["invocations"])
        stem = f"{index:03d}-{argv[0].lstrip('-')}"
        (logs / f"{stem}.stdout").write_text(stdout, encoding="utf-8")
        (logs / f"{stem}.stderr").write_text(stderr, encoding="utf-8")
        receipt["invocations"].append(
            {
                "argv": argv,
                "exit": p.returncode,
                "seconds": round(time.perf_counter() - start, 3),
                "log": stem,
            }
        )
        assert "Traceback (most recent call last)" not in stderr, stderr
        assert p.returncode in exits, f"{argv}: exit {p.returncode}: {stderr[:500]}"
        return stdout

    def check(name: str, fn: Callable[[], object]) -> None:
        if args.only and not any(name.startswith(prefix) for prefix in args.only.split(",")):
            return
        try:
            fn()
            row = {"name": name, "status": "PASS"}
        except Exception as exc:
            row = {"name": name, "status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}
        receipt["cases"].append(row)
        (work / "receipt.json").write_text(
            json.dumps(receipt, indent=2, ensure_ascii=True), encoding="utf-8"
        )
        print(f"{row['status']}: {name}", flush=True)

    def require(value: object) -> None:
        assert value

    healthy, broken, refused = (
        "examples/healthy.jsonl",
        "examples/repairable.jsonl",
        "examples/refused.json",
    )
    commands = (
        "baseline bundle check completion diff doctor export formats hook init-hooks "
        "mcp repair scan seal stats validate-session verify version watch"
    ).split()

    def root_help() -> None:
        rendered = invoke(["--help"])
        assert all(c in rendered for c in commands)

    check("root-help", root_help)
    for c in commands:
        check(f"help/{c}", lambda c=c: require("usage:" in invoke([c, "--help"])))
    check("version", lambda: require(json.loads(invoke(["version", "--json"]))["cli"] == "0.4.1"))
    check("formats", lambda: require("canonical" in invoke(["formats", "--json"])))
    check(
        "healthy", lambda: require(not json.loads(invoke(["check", healthy, "--json"]))["findings"])
    )
    check(
        "validate-session", lambda: invoke(["validate-session", "fixtures/canonical/minimal.json"])
    )
    for fmt in ("human", "json", "sarif", "html"):
        check(
            f"report/{fmt}",
            lambda fmt=fmt: require(
                "SL003" in invoke(["check", broken, "--output-format", fmt], (0, 1))
            ),
        )
    check(
        "determinism/check",
        lambda: require(
            invoke(["check", broken, "--json"], (0, 1))
            == invoke(["check", broken, "--json"], (0, 1))
        ),
    )
    for file, adapter in (
        ("../fixtures/canonical/minimal.json", "canonical"),
        ("claude.jsonl", "claude-code-jsonl"),
        ("codex.jsonl", "codex-rollout"),
        ("openai.json", "openai-agents"),
    ):
        for profile in ("neutral", "claude-strict", "openai-strict"):
            incompatible = (
                profile == "claude-strict" and adapter not in ("canonical", "claude-code-jsonl")
            ) or (profile == "openai-strict" and adapter == "claude-code-jsonl")
            check(
                f"adapter/{adapter}/{profile}",
                lambda file=file, adapter=adapter, profile=profile, incompatible=incompatible: (
                    invoke(
                        [
                            "check",
                            f"examples/{file}",
                            "--format",
                            adapter,
                            "--profile",
                            profile,
                            "--json",
                        ],
                        (2,) if incompatible else (0, 1),
                    )
                ),
            )

    def repair() -> None:
        invoke(["repair", broken, "--dry-run", "--json"])
        invoke(["repair", broken, "--preview", "--json"])
        assert not (work / "repaired.jsonl").exists()
        invoke(["repair", broken, "--plan-out", "plan.json"])
        invoke(
            ["repair", broken, "--apply-plan", "plan.json", "--output", "repaired.jsonl", "--json"]
        )
        invoke(
            [
                "verify",
                broken,
                "repaired.jsonl",
                "--manifest",
                "repaired.jsonl.manifest.json",
                "--json",
            ]
        )
        invoke(["repair", broken, "--output", "direct.jsonl", "--json"])
        assert sha(work / "direct.jsonl") == sha(work / "repaired.jsonl")
        assert not json.loads(invoke(["repair", "repaired.jsonl", "--dry-run", "--json"]))["steps"]

    check("repair/plan-apply-verify-idempotence", repair)

    def refusal() -> None:
        assert "SL203" in invoke(["check", refused, "--json"], (1,))
        invoke(["repair", refused, "--output", "refused-output.jsonl", "--json"], (1, 2))
        assert not list(work.glob("refused-output*"))
        plan = json.loads((work / "plan.json").read_text(encoding="utf-8"))
        plan["fingerprint"] = "0" * 64
        (work / "bad-plan.json").write_text(json.dumps(plan), encoding="utf-8")
        invoke(
            [
                "repair",
                broken,
                "--apply-plan",
                "bad-plan.json",
                "--output",
                "tampered-output.jsonl",
                "--json",
            ],
            (1, 2),
        )
        assert not list(work.glob("tampered-output*"))

    check("refusal/sl203-and-plan-tampering", refusal)

    def batch() -> None:
        (work / "batch-input").mkdir()
        for name in ("healthy.jsonl", "repairable.jsonl", "refused.json"):
            shutil.copyfile(work / "examples" / name, work / "batch-input" / name)
        invoke(["repair", "--batch", "batch-input", "--output-dir", "batch-output", "--json"], (1,))
        outputs = list((work / "batch-output").glob("*.jsonl"))
        assert len(outputs) == 1 and "repairable" in outputs[0].name
        invoke(
            [
                "verify",
                broken,
                str(outputs[0]),
                "--manifest",
                str(outputs[0]) + ".manifest.json",
                "--json",
            ]
        )
        invoke(["repair", "--files", broken, "--output-dir", "files-output", "--json"])

    check("repair/batch-and-files", batch)
    for fmt in ("human", "json", "sarif", "html"):
        check(
            f"scan/{fmt}",
            lambda fmt=fmt: require(
                "SL003" in invoke(["scan", "batch-input", "--output-format", fmt], (1,))
            ),
        )

    def scan() -> None:
        a = invoke(["scan", "batch-input", "--json"], (1,))
        b = invoke(["scan", "batch-input", "--json", "--jobs", "2"], (1,))
        assert a == b
        for _ in range(2):
            invoke(["scan", "batch-input", "--json", "--incremental", "--cache-dir", "cache"], (1,))
        invoke(["scan", "--agent", "all", "--json"], (0, 1))
        invoke(["scan", "--show-limits"])
        invoke(["scan", "-", "--json"], stdin=(work / healthy).read_text(encoding="utf-8"))

    check("scan/parallel-cache-discovery-stdin", scan)

    def baseline() -> None:
        invoke(["check", broken, "--write-baseline", "baseline.json", "--json"], (0, 1))
        assert not json.loads(invoke(["check", broken, "--baseline", "baseline.json", "--json"]))[
            "findings"
        ]
        (work / "legacy-baseline.json").write_text(
            '{"schema_version":"sesslint.baseline/v1","fingerprints":[]}', encoding="utf-8"
        )
        assert "sesslint.baseline/v2" in invoke(["baseline", "--upgrade", "legacy-baseline.json"])
        assert not json.loads(invoke(["check", broken, "--ignore", "SL003", "--json"]))["findings"]

    check("baseline-and-rule-filter", baseline)
    check(
        "diff", lambda: require('"schema_version"' in invoke(["diff", healthy, healthy, "--json"]))
    )
    check(
        "stats",
        lambda: require('"schema_version"' in invoke(["stats", "batch-input", "-r", "--json"])),
    )
    check("doctor", lambda: require('"schema_version"' in invoke(["doctor", "--json"])))
    check(
        "bundle/determinism",
        lambda: require(
            invoke(["bundle", broken, "--json"]) == invoke(["bundle", broken, "--json"])
        ),
    )

    def secret_privacy() -> None:
        corpus = json.loads(
            (work / "fixtures/conformance/secret_seed/consolidation/corpus.json").read_text(
                encoding="utf-8"
            )
        )
        positives = [row for row in corpus if row["category"] == "positive"]
        data = json.loads((work / "fixtures/canonical/minimal.json").read_text(encoding="utf-8"))
        data["events"][0]["payload"]["text"] = "\n".join(row["text"] for row in positives)
        (work / "synthetic-secrets.json").write_text(json.dumps(data), encoding="utf-8")
        for fmt in ("human", "json", "sarif", "html"):
            output = invoke(["check", "synthetic-secrets.json", "--output-format", fmt], (0, 1))
            assert "SL009" in output
            assert all(canary not in output for row in positives for canary in row["canaries"])
        invoke(
            [
                "bundle",
                "synthetic-secrets.json",
                "--strict-share",
                "--output",
                "unsafe-bundle.json",
            ],
            (1,),
        )
        assert not (work / "unsafe-bundle.json").exists()

    check("privacy/secret-output-and-strict-share", secret_privacy)

    def unicode_filename() -> None:
        name = "phiên kiểm thử.jsonl"
        shutil.copyfile(work / broken, work / name)
        for fmt in ("human", "json", "sarif", "html"):
            assert "SL003" in invoke(["check", name, "--output-format", fmt], (0, 1))
        invoke(["bundle", name, "--json"])

    check("paths/unicode-filename", unicode_filename)
    for name in ("claude.jsonl", "codex.jsonl", "openai.json"):

        def export(name: str = name) -> None:
            out = "export-" + name
            invoke(["export", "examples/" + name, "--output", out, "--json"])
            invoke(["check", out, "--format", "canonical", "--json"], (0, 1))

        check("export/" + name, export)

    def seal() -> None:
        invoke(["check", healthy, "--seal", "ledger.jsonl", "--json"])
        invoke(["seal", "--verify", "ledger.jsonl", "--json"])
        ledger = work / "ledger.jsonl"
        row = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
        row["schema_version"] = "tampered"
        (work / "tampered-ledger.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        invoke(["seal", "--verify", "tampered-ledger.jsonl", "--json"], (1, 2))

    check("seal/tamper-detection", seal)
    for shell in ("bash", "zsh", "fish", "powershell"):
        check(
            "completion/" + shell,
            lambda shell=shell: require("sesslint" in invoke(["completion", shell])),
        )
    for agent in ("claude", "codex", "all"):
        check(
            "init-hooks/" + agent,
            lambda agent=agent: require(
                "sesslint" in invoke(["init-hooks", "--agent", agent, "--json"])
            ),
        )
    for event in ("SessionStart", "PreCompact", "PostCompact", "SessionEnd", "Unknown"):
        check(
            "hook/" + event,
            lambda event=event: require(
                "sesslint.hook-result/v1"
                in invoke(
                    ["hook", "--event", event, "--json"],
                    stdin=json.dumps({"transcript_path": str(work / "examples/claude.jsonl")}),
                )
            ),
        )
    check(
        "hook/malformed",
        lambda: invoke(["hook", "--event", "SessionEnd", "--json"], stdin="{invalid"),
    )

    def mcp() -> None:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        for i, tool in enumerate(("sesslint_check", "sesslint_precheck", "sesslint_scan"), 3):
            requests.append(
                {
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {
                            "path": str(
                                work / ("batch-input" if tool.endswith("scan") else healthy)
                            )
                        },
                    },
                }
            )
        requests.append({"jsonrpc": "2.0", "id": 6, "method": "unknown"})
        results = [
            json.loads(x)
            for x in invoke(
                ["mcp"], stdin="".join(json.dumps(r) + "\n" for r in requests) + "{invalid\n"
            ).splitlines()
        ]
        assert len(results) == 7
        assert all("result" in r for r in results[:5])
        assert all(not r["result"]["isError"] for r in results[2:5])
        assert all("error" in r for r in results[5:])

    check("mcp/all-tools-and-protocol-errors", mcp)

    def watch() -> None:
        target = work / "watched.jsonl"
        shutil.copyfile(work / healthy, target)
        output = logs / "watch-transitions.ndjson"
        with output.open("wb") as stdout, (logs / "watch.stderr").open("wb") as stderr:
            proc = subprocess.Popen(
                command + ["watch", str(target), "--interval", "0.1", "--json"],
                cwd=work,
                env=env,
                stdout=stdout,
                stderr=stderr,
            )
            try:
                time.sleep(3)
                assert proc.poll() is None
                shutil.copyfile(work / broken, target)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not output.read_bytes():
                    time.sleep(0.1)
                assert output.read_bytes(), "No unhealthy transition"
                shutil.copyfile(work / healthy, target)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and len(output.read_bytes().splitlines()) < 2:
                    time.sleep(0.1)
                rows = [json.loads(x) for x in output.read_text(encoding="utf-8").splitlines()]
                assert len(rows) == 2 and rows[-1]["to"] == "healthy", rows
            finally:
                if proc.poll() is not None:
                    pass
                elif os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )
                else:
                    proc.terminate()
                proc.wait(timeout=15)

    check("watch/live-healthy-warning-healthy", watch)
    for argv in (
        ["check", "missing.jsonl", "--json"],
        ["check", healthy, "--profile", "nonexistent", "--json"],
        ["repair", broken, "--preview", "--output", "illegal.jsonl"],
        ["watch", "--interval", "0"],
        ["export", healthy],
    ):
        check("error/" + " ".join(argv), lambda argv=argv: invoke(argv, (2,)))

    # Execute every actual detector golden through the installed CLI, including
    # directory-only SL401/402. The old reader-only golden mode is tested by pytest.
    observed = set()
    for path in sorted((work / "fixtures/conformance/detectors").glob("*.expected.json")):

        def golden(path: Path = path) -> None:
            expected = json.loads(path.read_text(encoding="utf-8"))
            source = str(work / "fixtures" / expected["input"])
            argv = ["scan" if expected["mode"] == "scan" else "check", source, "--json"]
            if expected.get("format") and expected["mode"] != "scan":
                argv += ["--format", expected["format"]]
            doc = json.loads(invoke(argv, (0, 1)))
            findings = (
                [f for item in doc["files"] for f in item.get("findings", [])]
                if expected["mode"] == "scan"
                else doc["findings"]
            )
            actual = sorted(f["code"] for f in findings)
            assert actual == sorted(f["code"] for f in expected["findings"]), actual
            observed.update(actual)

        check("golden/" + path.stem, golden)
    check("detectors/34-codes", lambda: require(len(observed) == 34))
    after = {
        str(p.relative_to(work)): sha(p)
        for folder in ("examples", "fixtures")
        for p in (work / folder).rglob("*")
        if p.is_file()
    }
    check("all-original-inputs-immutable", lambda: require(before == after))
    receipt.update(
        status="PASS" if all(c["status"] == "PASS" for c in receipt["cases"]) else "FAIL",
        selected_prefixes=args.only,
        detector_codes=sorted(observed),
        input_hashes=before,
        environment={k: env[k] for k in ("HOME", "USERPROFILE", "CODEX_HOME", "CLAUDE_CONFIG_DIR")},
    )
    (work / "receipt.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return receipt["status"] == "PASS"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--only", help="Comma-separated case prefixes for a focused rerun")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--python", type=Path)
    group.add_argument("--binary", type=Path)
    raise SystemExit(0 if run(parser.parse_args()) else 1)
