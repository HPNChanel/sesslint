"""Tests for the fail-closed GitHub draft staging helper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from scripts import github_stage


def _release() -> str:
    return json.dumps({"target_commitish": "commit", "draft": True, "assets": []})


def test_changelog_notes_extracts_only_requested_version(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n## [Unreleased]\n\n- Pending\n\n"
        "## [0.4.1] - 2026-10-08\n\n### Fixed\n\n- Bound release notes.\n\n"
        "## [0.4.0] - 2026-09-23\n\n- Older.\n",
        encoding="utf-8",
    )

    assert github_stage.changelog_notes(changelog, "0.4.1") == (
        "## [0.4.1] - 2026-10-08\n\n### Fixed\n\n- Bound release notes.\n"
    )


def test_changelog_notes_refuses_missing_version_section(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n- Pending\n", encoding="utf-8")

    with pytest.raises(ValueError, match="No versioned changelog section"):
        github_stage.changelog_notes(changelog, "0.4.1")


def test_stage_uses_extracted_tracked_changelog_notes(monkeypatch, tmp_path: Path) -> None:
    artifact = tmp_path / "sesslint.whl"
    artifact.write_bytes(b"artifact")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [0.4.1] - 2026-10-08\n\n- Release note.\n", encoding="utf-8")
    monkeypatch.setattr(
        github_stage, "verify", lambda *args, **kwargs: {"commit": "commit", "version": "0.4.1"}
    )
    calls: list[tuple[str, ...]] = []

    def gh(*args: str) -> str:
        calls.append(args)
        if args[0] == "api" and len([call for call in calls if call[0] == "api"]) == 1:
            raise subprocess.CalledProcessError(1, args, stderr="HTTP 404")
        if args[:2] == ("release", "create"):
            notes_path = Path(args[args.index("--notes-file") + 1])
            assert notes_path.read_text(encoding="utf-8") == (
                "## [0.4.1] - 2026-10-08\n\n- Release note.\n"
            )
        if args[0] == "api":
            return _release()
        return ""

    monkeypatch.setattr(github_stage, "gh", gh)
    github_stage.stage(tmp_path, "synthetic/repo", "v0.4.1", "commit", changelog=changelog)

    create = next(call for call in calls if call[:2] == ("release", "create"))
    assert "--notes-file" in create
    assert "--generate-notes" not in create


def test_stage_can_explicitly_generate_notes_when_no_version_section_exists(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "sesslint.whl").write_bytes(b"artifact")
    monkeypatch.setattr(
        github_stage, "verify", lambda *args, **kwargs: {"commit": "commit", "version": "0.4.1"}
    )
    calls: list[tuple[str, ...]] = []

    def gh(*args: str) -> str:
        calls.append(args)
        if args[0] == "api" and len([call for call in calls if call[0] == "api"]) == 1:
            raise subprocess.CalledProcessError(1, args, stderr="HTTP 404")
        if args[0] == "api":
            return _release()
        return ""

    monkeypatch.setattr(github_stage, "gh", gh)
    github_stage.stage(
        tmp_path,
        "synthetic/repo",
        "v0.4.1",
        "commit",
        changelog=tmp_path / "missing.md",
        generate_notes=True,
    )

    create = next(call for call in calls if call[:2] == ("release", "create"))
    assert "--generate-notes" in create
    assert "--notes-file" not in create


def test_stage_refuses_to_create_draft_without_versioned_notes(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        github_stage, "verify", lambda *args, **kwargs: {"commit": "commit", "version": "0.4.1"}
    )
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [Unreleased]\n\n- Pending\n", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    def gh(*args: str) -> str:
        calls.append(args)
        if args[0] == "api":
            raise subprocess.CalledProcessError(1, args, stderr="HTTP 404")
        return ""

    monkeypatch.setattr(github_stage, "gh", gh)

    with pytest.raises(ValueError, match="No versioned changelog section"):
        github_stage.stage(
            tmp_path,
            "synthetic/repo",
            "v0.4.1",
            "commit",
            changelog=changelog,
        )
    assert not any(call[:2] == ("release", "create") for call in calls)
