"""T-11: absence, history and archive integrity determine retry safety."""

import hashlib
import io
import json
import subprocess
import sys
import zipfile

import pytest
from scripts import restore_release_artifact as helper

KW = dict(
    attempt=2, job="Build binary (windows)", step="Create binary", commit="a" * 40, version="0.4.1"
)


def history(conclusion="skipped", *, job_conclusion="failure"):
    return [
        {
            "jobs": [
                {
                    "name": KW["job"],
                    "head_sha": KW["commit"],
                    "status": "completed",
                    "conclusion": job_conclusion,
                    "steps": [
                        {"name": KW["step"], "status": "completed", "conclusion": conclusion}
                    ],
                }
            ]
        }
    ]


@pytest.mark.parametrize("conclusion", ["success", "failure", "cancelled", "unknown", None])
def test_missing_created_artifact_never_rebuilds(conclusion, monkeypatch, tmp_path):
    monkeypatch.setattr(
        helper,
        "pages",
        lambda endpoint: (
            [{"artifacts": []}] if endpoint.endswith("/artifacts") else history(conclusion)
        ),
    )
    with pytest.raises(ValueError, match="lost"):
        helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("unknown", [[], [{"jobs": []}], history()])
def test_unknown_or_changed_commit_history_refuses(unknown, monkeypatch, tmp_path):
    if unknown == history():
        unknown[0]["jobs"][0]["head_sha"] = "other"
    monkeypatch.setattr(
        helper,
        "pages",
        lambda endpoint: [{"artifacts": []}] if endpoint.endswith("/artifacts") else unknown,
    )
    with pytest.raises(ValueError):
        helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW)


@pytest.mark.parametrize("job_conclusion", ["failure", "skipped"])
def test_positive_skipped_history_allows_only_first_build(job_conclusion, monkeypatch, tmp_path):
    monkeypatch.setattr(
        helper,
        "pages",
        lambda endpoint: (
            [{"artifacts": []}]
            if endpoint.endswith("/artifacts")
            else history(job_conclusion=job_conclusion)
        ),
    )
    assert helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW) is False


def archive_bytes(member=None):
    binary = "sesslint-0.4.1-windows-x86_64.exe"
    raw = b"synthetic exe"
    receipt = {
        "status": "PASS",
        "version": "0.4.1",
        "platform": "Windows",
        "artifact": binary,
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "source_immutable": True,
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(binary, raw)
        archive.writestr("smoke-windows.json", json.dumps(receipt))
        archive.writestr("SHA256SUMS-windows", f"{hashlib.sha256(raw).hexdigest()}  {binary}\n")
        if member:
            archive.writestr(member, b"synthetic")
    return stream.getvalue()


@pytest.mark.parametrize(
    "mutation",
    [None, "expired", "duplicate", "commit", "digest", "corrupt", "transport", "traversal"],
)
def test_restores_by_verified_id_without_overwrite(mutation, monkeypatch, tmp_path):
    raw = archive_bytes("../escaped" if mutation == "traversal" else None)
    item = {
        "name": "binary-windows",
        "id": 7,
        "expired": False,
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "workflow_run": {"head_sha": KW["commit"]},
    }
    if mutation == "expired":
        item["expired"] = True
    if mutation == "commit":
        item["workflow_run"]["head_sha"] = "other"
    if mutation == "digest":
        item.pop("digest")
    monkeypatch.setattr(
        helper,
        "pages",
        lambda _: [{"artifacts": [item, item] if mutation == "duplicate" else [item]}],
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if mutation == "transport":
            raise subprocess.CalledProcessError(1, command)
        kwargs["stdout"].write(b"corrupt" if mutation == "corrupt" else raw)

    monkeypatch.setattr(helper.subprocess, "run", run)
    if mutation:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW)
        assert not list(tmp_path.iterdir())
    else:
        assert helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW)
        assert calls[0][-1].endswith("/artifacts/7/zip")
        (tmp_path / "sesslint-0.4.1-windows-x86_64.exe").write_bytes(b"protected")
        with pytest.raises(ValueError, match="replace"):
            helper.restore("owner/repo", "1", "binary-windows", tmp_path, **KW)
        assert (tmp_path / "sesslint-0.4.1-windows-x86_64.exe").read_bytes() == b"protected"


def test_all_prior_attempts_must_be_unstarted(monkeypatch, tmp_path):
    monkeypatch.setattr(
        helper,
        "pages",
        lambda endpoint: (
            [{"artifacts": []}]
            if endpoint.endswith("/artifacts")
            else history("success" if "/1/jobs" in endpoint else "skipped")
        ),
    )
    with pytest.raises(ValueError, match="lost"):
        helper.restore("owner/repo", "1", "binary-windows", tmp_path, **(KW | {"attempt": 3}))


def test_failed_cli_retains_diagnostic(monkeypatch, tmp_path):
    receipt = tmp_path / "failure.json"
    args = [
        "restore",
        "--repo",
        "owner/repo",
        "--run-id",
        "1",
        "--name",
        "release-dist",
        "--target",
        str(tmp_path / "out"),
        "--receipt",
        str(receipt),
    ]
    for key, value in KW.items():
        args += ["--" + key, str(value)]
    monkeypatch.setattr(sys, "argv", args)

    def fail(*args, **kwargs):
        raise ValueError("synthetic failure")

    monkeypatch.setattr(helper, "restore", fail)
    with pytest.raises(ValueError):
        helper.main()
    assert json.loads(receipt.read_text())["status"] == "FAIL"
