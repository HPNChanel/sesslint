"""T-10/T-11: budget boundaries and partial-release safety, without remote writes."""

import io
import json
import subprocess
from pathlib import Path

import pytest
import yaml
from bench import measure_installed, perf_250k
from bench.measure_installed import within_budget
from scripts import github_stage, published_verify


@pytest.mark.parametrize(
    "seconds,peak,expected",
    [
        (15, 511.999, True),
        (15.001, 500, False),
        (1, 512, False),
        (1, None, False),
        (float("nan"), 1, False),
        (1, float("inf"), False),
        (-1, 1, False),
        (True, 1, False),
    ],
)
def test_installed_budget_is_closed(seconds, peak, expected):
    assert within_budget(seconds, peak) is expected


@pytest.mark.parametrize("peak", [512, None, float("nan")])
def test_normative_memory_boundary_and_unavailable_metrics(peak, monkeypatch, tmp_path):
    def measure(path):
        return {
            "exit_code": 0,
            "stdout": json.dumps({"counts": {"total": 0, "by_code": {}}}),
            "stats": {
                "check_s": 0.01,
                "peak_rss_mb": peak,
                "cpu_s": 0.01,
                "trace": False,
                "profile": False,
            },
            "stderr": "",
        }

    monkeypatch.setattr(perf_250k, "run_fresh_process_check", measure)
    receipt = tmp_path / "receipt.json"
    assert perf_250k.run_benchmark(100, 15, 512, receipt=receipt) == 1
    assert json.loads(receipt.read_text(encoding="utf-8"))["status"] == "FAIL"


@pytest.mark.parametrize(
    "failure", ["time-missing", "cpu-missing", "invalid-stats", "dense-spawn", "dense-stats"]
)
def test_missing_benchmark_results_still_save_failure(failure, monkeypatch, tmp_path):
    def measure(path):
        dense = path.name == "dense_lines.jsonl"
        if dense and failure == "dense-spawn":
            return None
        stats = dict(check_s=0.01, peak_rss_mb=20, cpu_s=0.01, trace=False, profile=False)
        if not dense and failure in {"time-missing", "cpu-missing"}:
            stats.pop("check_s" if failure == "time-missing" else "cpu_s")
        if dense and failure == "dense-stats":
            stats = {}
        if not dense and failure == "invalid-stats":
            stats = ["invalid"]
        return {
            "exit_code": 0,
            "stats": stats,
            "stdout": json.dumps({"counts": {"total": 0, "by_code": {}}}),
        }

    monkeypatch.setattr(perf_250k, "run_fresh_process_check", measure)
    receipt = tmp_path / "receipt.json"
    assert perf_250k.run_benchmark(100, 15, 512, receipt=receipt) == 1
    assert json.loads(receipt.read_text(encoding="utf-8"))["status"] == "FAIL"


def test_installed_timeout_retains_all_attempts(monkeypatch, tmp_path):
    import sys

    artifact, source = tmp_path / "wheel.whl", tmp_path / "input.jsonl"
    artifact.write_bytes(b"synthetic")
    source.write_bytes(b"synthetic")
    receipt = tmp_path / "measurement.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure",
            "--python",
            sys.executable,
            "--artifact",
            str(artifact),
            "--input",
            str(source),
            "--receipt",
            str(receipt),
        ],
    )

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 600)

    monkeypatch.setattr(measure_installed.subprocess, "run", timeout)
    assert measure_installed.main() == 1
    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["status"] == "FAIL" and len(data["runs"]) == 3
    assert all(row["status"] == "FAIL" for row in data["runs"])
    assert len(list(tmp_path.glob("measurement-*.json"))) == 3


@pytest.mark.parametrize("state", ["same", "different", "public-missing", "transport"])
def test_partial_draft_preserves_existing_assets(state, monkeypatch, tmp_path):
    (tmp_path / "asset.bin").write_bytes(b"verified")
    (tmp_path / "extra.bin").write_bytes(b"new")
    monkeypatch.setattr(
        github_stage, "verify", lambda *a, **k: {"commit": "commit", "version": "0.4.1"}
    )
    calls = []

    def gh(*args):
        calls.append(args)
        if args[0] == "api":
            if state == "transport":
                raise subprocess.CalledProcessError(1, args, stderr="HTTP 503")
            return json.dumps(
                {
                    "target_commitish": "commit",
                    "draft": state != "public-missing",
                    "assets": [{"name": "asset.bin"}],
                }
            )
        if args[1] == "download":
            (Path(args[-1]) / "asset.bin").write_bytes(
                b"wrong" if state == "different" else b"verified"
            )
        return ""

    monkeypatch.setattr(github_stage, "gh", gh)
    if state == "same":
        github_stage.stage(tmp_path, "synthetic/repo", "v0.4.1", "commit")
        assert sum(command[:2] == ("release", "upload") for command in calls) == 1
    else:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            github_stage.stage(tmp_path, "synthetic/repo", "v0.4.1", "commit")
        assert not any(command[:2] == ("release", "upload") for command in calls)
    assert not any("--clobber" in command for command in calls)


@pytest.mark.parametrize("wrong", [False, True])
def test_partial_pypi_only_stages_missing_verified_bytes(wrong, monkeypatch, tmp_path):
    import hashlib

    wheel, sdist = tmp_path / "wheel", tmp_path / "sdist"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    monkeypatch.setattr(published_verify, "distributions", lambda *a: (wheel, sdist))
    raw = b"wrong" if wrong else b"wheel"
    monkeypatch.setattr(
        published_verify,
        "pypi_files",
        lambda _: {
            "wheel": {
                "url": "https://files.pythonhosted.org/synthetic",
                "digests": {"sha256": hashlib.sha256(raw).hexdigest()},
            }
        },
    )
    monkeypatch.setattr(published_verify.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(raw))
    if wrong:
        with pytest.raises(ValueError):
            published_verify.verify_pypi(tmp_path, "0.4.1", tmp_path / "stage", allow_missing=True)
        assert not (tmp_path / "stage").exists()
    else:
        assert (
            published_verify.verify_pypi(tmp_path, "0.4.1", tmp_path / "stage", allow_missing=True)
            == 1
        )
        assert [p.name for p in (tmp_path / "stage").iterdir()] == ["sdist"]


def test_release_promotion_requires_verified_pypi_and_provenance():
    jobs = yaml.safe_load(
        (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text(encoding="utf-8")
    )["jobs"]
    assert set(jobs["pypi-publish"]["needs"]) == {"github-draft", "provenance-verify"}
    assert set(jobs["github-promote"]["needs"]) == {"pypi-verify", "provenance-verify"}
    assert "if" not in jobs["github-promote"]  # GitHub's default success gate stays active.
