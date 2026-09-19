"""Tests for scripts/check_release_refs.py (field-test debt F5)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_release_refs.py"

spec = importlib.util.spec_from_file_location("check_release_refs", SCRIPT)
assert spec is not None and spec.loader is not None
crr = importlib.util.module_from_spec(spec)
sys.modules.setdefault("check_release_refs", crr)
spec.loader.exec_module(crr)


# ---------------------------------------------------------------------------
# parse_semver / classify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v0.2.0", (0, 2, 0)),
        ("0.2.0", (0, 2, 0)),
        ("v1.2.3", (1, 2, 3)),
        ("1.0.0-rc.1", (1, 0, 0)),
        ("main", None),
        ("deadbeef" * 5, None),
        ("v0.2", None),
        ("", None),
    ],
)
def test_parse_semver(text: str, expected: tuple[int, int, int] | None) -> None:
    assert crr.parse_semver(text) == expected


def _classify(value: str, latest=(0, 2, 0), dev=(0, 3, 0), tags=None) -> str:
    return crr.classify(value, latest, dev, tags or {(0, 1, 0), (0, 2, 0)})


def test_classify_match_latest_tag() -> None:
    assert _classify("v0.2.0") == "match"


def test_classify_dev_version_needs_marker() -> None:
    assert _classify("0.3.0") == "dev"
    assert _classify("v0.3.0") == "dev"


def test_classify_stale_older_tag() -> None:
    assert _classify("v0.1.0") == "stale"


def test_classify_unknown_version() -> None:
    assert _classify("v9.9.9") == "unknown"


def test_classify_nonsemver_ref() -> None:
    assert _classify("main") == "nonsemver"
    assert _classify("abc1234") == "nonsemver"


def test_classify_no_tags_dev_is_ok() -> None:
    # pre-first-release tree: docs describing the dev version are legitimate
    assert crr.classify("v0.3.0", None, (0, 3, 0), set()) == "match-dev"
    assert crr.classify("v0.2.0", None, (0, 3, 0), set()) == "unknown"


# ---------------------------------------------------------------------------
# scan_lines — pin extraction and marker coverage
# ---------------------------------------------------------------------------


def _scan(text: str, post_tag: frozenset[str] | set[str] = frozenset()) -> tuple[list, list]:
    return crr.scan_lines(text.splitlines(), "doc.md", post_tag)


def test_rev_pin_binds_to_sesslint_repo_only() -> None:
    text = (
        "```yaml\n"
        "repos:\n"
        "  - repo: https://github.com/HPNChanel/sesslint\n"
        "    rev: v0.2.0\n"
        "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
        "    rev: v6.0.0\n"
        "```\n"
    )
    pins, _ = _scan(text)
    assert len(pins) == 1
    assert pins[0].kind == "rev"
    assert pins[0].value == "v0.2.0"
    assert pins[0].line == 4


def test_pip_and_uses_pins() -> None:
    text = (
        "pipx install sesslint==0.2.0\n"
        "      - uses: HPNChanel/sesslint/.github/actions/sesslint-check@main\n"
        "      - uses: actions/checkout@v4\n"
    )
    pins, _ = _scan(text)
    kinds = {(p.kind, p.value) for p in pins}
    assert ("pip-pin", "0.2.0") in kinds
    assert ("uses-pin", "main") in kinds
    assert not any(p.value == "v4" for p in pins)  # third-party action ignored


def test_marker_same_line_covers() -> None:
    text = "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v0.3.0  # next-release\n"
    pins, _ = _scan(text)
    assert pins[0].covered is True


def test_section_marker_covers_until_next_heading() -> None:
    text = (
        "## Section\n"
        "<!-- next-release -->\n"
        "  - repo: https://github.com/HPNChanel/sesslint\n"
        "    rev: v0.3.0\n"
        "## Next section\n"
        "  - repo: https://github.com/HPNChanel/sesslint\n"
        "    rev: v0.3.0\n"
    )
    pins, _ = _scan(text)
    assert [p.covered for p in pins] == [True, False]


def test_heading_inside_fence_does_not_reset_marker() -> None:
    text = (
        "<!-- next-release -->\n"
        "```toml\n"
        "# sesslint.toml\n"
        "x = 1\n"
        "```\n"
        "  - repo: https://github.com/HPNChanel/sesslint\n"
        "    rev: v0.3.0\n"
    )
    pins, _ = _scan(text)
    assert pins[0].covered is True


def test_post_tag_flags_require_coverage() -> None:
    post = {"--select", "--agent"}
    text = (
        "| `--select` | flag | desc. *(next release)* |\n"
        "run `sesslint scan --agent codex` here\n"
        "unrelated --verbose mention\n"
    )
    _, flags = _scan(text, post)
    by_line = {f.line: f.covered for f in flags}
    assert by_line == {1: True, 2: False}


# ---------------------------------------------------------------------------
# main() end-to-end
# ---------------------------------------------------------------------------


def test_main_real_repo_is_consistent() -> None:
    # Passes both with tags (deep checkout) and without (shallow CI):
    # refs equal to dev version classify as match-dev when no tag exists.
    assert crr.main(["--root", str(REPO_ROOT)]) == 0


def test_seeded_bad_rev_fails(tmp_path: Path) -> None:
    (tmp_path / "src" / "sesslint").mkdir(parents=True)
    (tmp_path / "src" / "sesslint" / "cli.py").write_text('"--json"\n', encoding="utf-8")
    bad = tmp_path / "bad.md"
    bad.write_text(
        "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v9.9.9\n",
        encoding="utf-8",
    )
    rc = crr.main(
        [
            "--root",
            str(tmp_path),
            "--latest-tag",
            "v0.2.0",
            "--dev-version",
            "0.2.0",
            "--files",
            "bad.md",
        ]
    )
    assert rc == 1


def test_unmarked_dev_rev_fails(tmp_path: Path) -> None:
    (tmp_path / "src" / "sesslint").mkdir(parents=True)
    (tmp_path / "src" / "sesslint" / "cli.py").write_text('"--json"\n', encoding="utf-8")
    bad = tmp_path / "bad.md"
    bad.write_text(
        "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v0.3.0\n",
        encoding="utf-8",
    )
    rc = crr.main(
        [
            "--root",
            str(tmp_path),
            "--latest-tag",
            "v0.2.0",
            "--dev-version",
            "0.3.0",
            "--files",
            "bad.md",
        ]
    )
    assert rc == 1


def test_marked_dev_rev_passes(tmp_path: Path) -> None:
    (tmp_path / "src" / "sesslint").mkdir(parents=True)
    (tmp_path / "src" / "sesslint" / "cli.py").write_text('"--json"\n', encoding="utf-8")
    good = tmp_path / "good.md"
    good.write_text(
        "<!-- next-release -->\n  - repo: https://github.com/HPNChanel/sesslint\n    rev: v0.3.0\n",
        encoding="utf-8",
    )
    rc = crr.main(
        [
            "--root",
            str(tmp_path),
            "--latest-tag",
            "v0.2.0",
            "--dev-version",
            "0.3.0",
            "--files",
            "good.md",
        ]
    )
    assert rc == 0
