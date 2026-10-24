"""Tests for scripts/check_release_refs.py (field-test debt F5)."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
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


@pytest.mark.parametrize("pin", ["0.5.0rc1", "v0.5.0-rc.1", "0.5.0.dev0", "0.5.0a1", "0.5.0-rc.1"])
def test_classify_prerelease_pin_is_never_the_final_tag(pin: str) -> None:
    final = (0, 5, 0)
    assert crr.classify(pin, final, (0, 6, 0), {final}, "0.6.0") == "stale"
    assert crr.classify(pin, final, (0, 6, 0), {final}) == "stale"


def test_classify_exact_dev_version_pin_is_dev() -> None:
    tags = {(0, 5, 0)}
    assert crr.classify("0.6.0rc1", (0, 5, 0), (0, 6, 0), tags, "0.6.0rc1") == "dev"
    assert crr.classify("v0.6.0rc1", (0, 5, 0), (0, 6, 0), tags, "0.6.0rc1") == "dev"
    # a different spelling or another pre-release of the same X.Y.Z is not the dev version
    assert crr.classify("0.6.0-rc.1", (0, 5, 0), (0, 6, 0), tags, "0.6.0rc1") == "stale"
    assert crr.classify("0.6.0rc2", (0, 5, 0), (0, 6, 0), tags, "0.6.0rc1") == "stale"


def test_classify_final_pin_and_local_or_post_suffix_stay_a_match() -> None:
    tags = {(0, 5, 0)}
    for pin in ("v0.5.0", "0.5.0", "0.5.0.post1", "0.5.0+local.1", "0.5.0+a1"):
        assert crr.classify(pin, (0, 5, 0), (0, 6, 0), tags, "0.6.0") == "match", pin


def test_stale_prerelease_pin_fails_through_main(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG}, worktree_cli=JSON_FLAG)
    _doc(root, "pip install sesslint==0.4.0rc1")
    assert _run(root) == 1


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


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            *("-c", "user.name=t", "-c", "user.email=t@example.invalid"),
            *("-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"),
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


JSON_FLAG = '"--json"\n'
AS_OF_FLAG = '"--as-of"\n'
TARGET_FLAG = '"--target"\n'


def _repo(tmp_path: Path, *, tags: dict[str, str], worktree_cli: str = JSON_FLAG) -> Path:
    """Synthetic git repo: ``tags`` maps tag name -> CLI source committed at that tag."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    cli = tmp_path / "src" / "sesslint" / "cli.py"
    cli.parent.mkdir(parents=True)
    _git(tmp_path, "init", "-q")
    for tag, source in tags.items():
        cli.write_text(source, encoding="utf-8", newline="\n")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "--allow-empty", "-m", f"release {tag}")
        _git(tmp_path, "tag", tag)
    cli.write_text(worktree_cli, encoding="utf-8", newline="\n")
    return tmp_path


def _doc(root: Path, text: str) -> None:
    (root / "doc.md").write_text(text + "\n", encoding="utf-8", newline="\n")


def _run(root: Path, *extra: str, dev: str = "0.5.0") -> int:
    return crr.main(["--root", str(root), "--dev-version", dev, "--files", "doc.md", *extra])


def test_main_real_repo_with_explicit_opt_out_never_errors() -> None:
    # Whatever the checkout looks like (tags or none), the explicit opt-out is not an
    # operational error; the strict default is covered by the synthetic repos below.
    assert crr.main(["--root", str(REPO_ROOT), "--allow-no-baseline"]) in (0, 1)


def test_baseline_resolution_ignores_prerelease_and_future_tags() -> None:
    tags = ["v0.3.0", "v0.4.0", "v0.5.0-rc.1", "v0.6.0", "v0.4.1-rc.2", "nonsense"]
    assert crr.resolve_baseline(tags, (0, 5, 0)) == (0, 4, 0)
    assert crr.resolve_baseline(["v0.5.0-rc.1"], (0, 5, 0)) is None
    assert crr.resolve_baseline([], (0, 5, 0)) is None
    # A released tag equal to the dev version is a valid baseline (post-release state).
    assert crr.resolve_baseline(["v0.4.0", "v0.5.0"], (0, 5, 0)) == (0, 5, 0)


def test_new_unmarked_flag_is_checked_against_final_tag_not_rc(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        tags={"v0.4.0": JSON_FLAG, "v0.5.0-rc.1": JSON_FLAG + AS_OF_FLAG},
        worktree_cli=JSON_FLAG + AS_OF_FLAG,
    )
    _doc(root, "Pass `--as-of` to pin the evaluation instant.")
    # Baseline is v0.4.0 (the rc is ignored), so --as-of is post-tag and needs a marker.
    assert _run(root) == 1
    _doc(root, "Pass `--as-of` to pin the evaluation instant. *(next release)*")
    assert _run(root) == 0


def test_file_marker_covers_whole_document(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG}, worktree_cli=JSON_FLAG + AS_OF_FLAG)
    _doc(root, "# A\n`--as-of`\n## B\n`--as-of`")
    assert _run(root) == 1
    _doc(root, "<!-- next-release: file -->\n# A\n`--as-of`\n## B\n`--as-of`")
    assert _run(root) == 0


def test_repo_build_tooling_flags_are_not_cli_flags(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG}, worktree_cli=JSON_FLAG + TARGET_FLAG)
    _doc(root, "python scripts/release_artifacts.py compare --target dist/x")
    assert _run(root) == 0
    _doc(root, "sesslint outcome --target x")
    assert _run(root) == 1


def test_no_tags_fails_closed_unless_opted_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, tags={})
    _doc(root, "nothing to see")
    assert _run(root) == 2
    err = capsys.readouterr().err
    assert "no final release tag" in err and "git fetch --tags" in err
    assert "--allow-no-baseline" in err
    assert _run(root, "--allow-no-baseline") == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_only_prerelease_tag_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.5.0-rc.1": JSON_FLAG})
    _doc(root, "nothing to see")
    assert _run(root) == 2
    assert _run(root, "--allow-no-baseline") == 0


def test_opt_out_still_enforces_pins(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={})
    _doc(root, "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v9.9.9")
    assert _run(root, "--allow-no-baseline") == 1


def test_unreadable_cli_source_at_baseline_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG})
    _doc(root, "nothing")
    # Override to a baseline that has no tag: git cannot supply its CLI source.
    assert _run(root, "--latest-tag", "v0.3.0") == 2
    assert _run(root, "--latest-tag", "v0.3.0", "--allow-no-baseline") == 0


def test_not_a_git_repo_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Stop git discovery at tmp_path so an enclosing checkout is never picked up.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    cli = tmp_path / "src" / "sesslint" / "cli.py"
    cli.parent.mkdir(parents=True)
    cli.write_text(JSON_FLAG, encoding="utf-8", newline="\n")
    _doc(tmp_path, "nothing")
    assert _run(tmp_path) == 2


def test_json_report_records_skipped_flag_skew(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    root = _repo(tmp_path, tags={})
    _doc(root, "nothing")
    assert _run(root, "--allow-no-baseline", "--json") == 0
    assert '"flag_skew_checked": false' in capsys.readouterr().out


def test_seeded_bad_rev_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.2.0": JSON_FLAG})
    _doc(root, "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v9.9.9")
    assert _run(root, dev="0.2.0") == 1


def test_unmarked_dev_rev_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.2.0": JSON_FLAG})
    _doc(root, "  - repo: https://github.com/HPNChanel/sesslint\n    rev: v0.3.0")
    assert _run(root, dev="0.3.0") == 1


def test_marked_dev_rev_passes(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.2.0": JSON_FLAG})
    _doc(
        root,
        "<!-- next-release -->\n  - repo: https://github.com/HPNChanel/sesslint\n    rev: v0.3.0",
    )
    assert _run(root, dev="0.3.0") == 0


# ---------------------------------------------------------------------------
# Marker anchoring: only a marker alone on its own line, outside fences, counts
# ---------------------------------------------------------------------------

NEW_FLAG = {"--as-of"}


def _covered(text: str, post_tag: set[str] = NEW_FLAG) -> list[bool]:
    _, flags = _scan(text, post_tag)
    return [f.covered for f in flags]


def test_file_marker_inside_inline_code_has_no_effect() -> None:
    text = "Use `<!-- next-release: file -->` to mark a doc.\nPass `--as-of` here.\n"
    assert _covered(text) == [False]


def test_file_marker_inside_fenced_block_has_no_effect() -> None:
    text = "```md\n<!-- next-release: file -->\n```\nPass `--as-of` here.\n"
    assert _covered(text) == [False]


def test_section_marker_in_inline_code_or_fence_has_no_effect() -> None:
    inline = "## A\nWrite `<!-- next-release -->` alone on a line.\nPass `--as-of` here.\n"
    assert _covered(inline) == [False]
    fenced = "## A\n```md\n<!-- next-release -->\n```\nPass `--as-of` here.\n"
    assert _covered(fenced) == [False]


def test_trailing_markers_on_a_table_row_do_not_leak() -> None:
    table = (
        "| Name | Flag |\n"
        "| --- | --- |\n"
        "| One | `--as-of` <!-- next-release --> |\n"
        "| Two | `--as-of` |\n"
    )
    # The same-line token still covers its own row, but nothing after it.
    assert _covered(table) == [True, False]
    file_marker_row = "| One | x <!-- next-release: file --> |\n| Two | `--as-of` |\n"
    assert _covered(file_marker_row) == [False]


def test_marker_after_text_on_a_line_does_not_open_a_section() -> None:
    text = "## A\nSome prose <!-- next-release -->\nPass `--as-of` here.\n"
    assert _covered(text) == [False]


def test_own_line_markers_still_cover() -> None:
    section = "## A\n<!-- next-release -->\nPass `--as-of` here.\n## B\nPass `--as-of` here.\n"
    assert _covered(section) == [True, False]
    whole_file = (
        "# Title\n\n<!-- next-release: file -->\n\n## A\nPass `--as-of` here.\n## B\n`--as-of`\n"
    )
    assert _covered(whole_file) == [True, True]
    indented = "## A\n   <!-- next-release -->\nPass `--as-of` here.\n"
    assert _covered(indented) == [True]
    spaced = "<!--   next-release : file   -->  \nPass `--as-of` here.\n"
    assert _covered(spaced) == [True]


def test_file_marker_does_not_leak_through_main(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG}, worktree_cli=JSON_FLAG + AS_OF_FLAG)
    _doc(root, "Use `<!-- next-release: file -->` to mark a doc.\n`--as-of`")
    assert _run(root) == 1
    _doc(root, "```\n<!-- next-release: file -->\n```\n`--as-of`")
    assert _run(root) == 1
    _doc(root, "`--as-of` <!-- next-release: file -->\n`--as-of`")
    assert _run(root) == 1
    _doc(root, "<!-- next-release: file -->\n`--as-of`")
    assert _run(root) == 0


# ---------------------------------------------------------------------------
# Tooling-command exemption covers the command span only
# ---------------------------------------------------------------------------


def test_tooling_exemption_is_limited_to_the_command_span() -> None:
    post = {"--as-of", "--target"}
    chained = "python scripts/build.py --target o.zip && sesslint outcome c.json --as-of T"
    _, flags = _scan(chained, post)
    assert [f.flag for f in flags] == ["--as-of"]
    quoted = "Run `uv run python scripts/x.py --target a` before `sesslint outcome --as-of T`."
    _, flags = _scan(quoted, post)
    assert [f.flag for f in flags] == ["--as-of"]
    piped = (
        "python -m build --target x | sesslint outcome --as-of T; python3 scripts/y.py --target z"
    )
    _, flags = _scan(piped, post)
    assert [f.flag for f in flags] == ["--as-of"]


def test_tooling_flags_alone_on_a_line_are_still_ignored() -> None:
    post = {"--target"}
    for line in (
        "python scripts/release_artifacts.py compare --target dist/x",
        "`python -m build --target x`",
        "$ python3 scripts/y.py --target z",
    ):
        _, flags = _scan(line, post)
        assert flags == [], line


def test_tooling_span_ends_before_sesslint_in_unquoted_prose() -> None:
    post = {"--as-of", "--target"}
    prose = "Run python scripts/x.py --target a, then sesslint outcome --as-of T."
    _, flags = _scan(prose, post)
    assert [f.flag for f in flags] == ["--as-of"]
    _, flags = _scan("python scripts/x.py --target a", post)
    assert flags == []


def test_mixed_tooling_line_fails_through_main(tmp_path: Path) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG}, worktree_cli=JSON_FLAG + AS_OF_FLAG)
    _doc(root, "python scripts/build_starter_kit.py out.zip && sesslint outcome c.json --as-of T")
    assert _run(root) == 1


# ---------------------------------------------------------------------------
# Operational errors exit 2, one line, no traceback
# ---------------------------------------------------------------------------


def _one_line_error(capsys: pytest.CaptureFixture[str]) -> str:
    err = capsys.readouterr().err.strip()
    assert err.startswith("error: ") and "\n" not in err and "Traceback" not in err, err
    return err


def test_missing_input_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG})
    assert crr.main(["--root", str(root), "--dev-version", "0.5.0", "--files", "gone.md"]) == 2
    err = _one_line_error(capsys)
    assert "gone.md" in err and "not found" in err


def test_non_utf8_input_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG})
    (root / "doc.md").write_bytes(b"ok \xff\xfe\xfa not utf-8\n")
    assert _run(root) == 2
    err = _one_line_error(capsys)
    assert "doc.md" in err and "UTF-8" in err


def test_unreadable_and_foreign_inputs_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path / "repo", tags={"v0.4.0": JSON_FLAG})
    (root / "adir").mkdir()
    argv = ["--root", str(root), "--dev-version", "0.5.0", "--files"]
    assert crr.main([*argv, "adir"]) == 2
    assert "adir" in _one_line_error(capsys)
    outside = tmp_path / "outside-root.md"
    outside.write_text("x\n", encoding="utf-8")
    assert crr.main([*argv, str(outside)]) == 2
    assert "outside" in _one_line_error(capsys)


def test_non_utf8_worktree_cli_source_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG})
    (root / "src" / "sesslint" / "cli.py").write_bytes(b'"--json"\n\xff\xfe\n')
    _doc(root, "nothing")
    assert _run(root) == 2
    assert "cli.py" in _one_line_error(capsys)


# ---------------------------------------------------------------------------
# Baseline selection: PEP 440 pre-release development versions, --latest-tag names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["1.0.0rc1", "1.0.0a1", "1.0.0b2", "1.0.0.dev0", "1.0.0.post1", "1.0.0-rc.1", "v1.0.0rc1"],
)
def test_parse_semver_accepts_pep440_suffixes(text: str) -> None:
    assert crr.parse_semver(text) == (1, 0, 0)


@pytest.mark.parametrize("text", ["1.0.0rcx", "1.0.0foo", "1.0rc1", "rc1"])
def test_parse_semver_still_rejects_garbage(text: str) -> None:
    assert crr.parse_semver(text) is None


def test_is_prerelease() -> None:
    for text in ("1.0.0rc1", "1.0.0a1", "1.0.0b2", "1.0.0.dev0", "1.0.0-rc.1", "0.5.1.dev3"):
        assert crr.is_prerelease(text), text
    for text in ("1.0.0", "v0.5.0", "1.0.0.post1"):
        assert not crr.is_prerelease(text), text


def test_prerelease_dev_version_baselines_strictly_below() -> None:
    tags = ["v0.9.0", "v1.0.0"]
    assert crr.resolve_baseline(tags, (1, 0, 0)) == (1, 0, 0)
    assert crr.resolve_baseline(tags, (1, 0, 0), dev_is_prerelease=True) == (0, 9, 0)
    assert crr.resolve_baseline(["v1.0.0"], (1, 0, 0), dev_is_prerelease=True) is None


def test_pep440_rc_dev_version_uses_the_previous_release_as_baseline(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        tags={"v0.9.0": JSON_FLAG, "v1.0.0": JSON_FLAG + AS_OF_FLAG},
        worktree_cli=JSON_FLAG + AS_OF_FLAG,
    )
    _doc(root, "Pass `--as-of` to pin the evaluation instant.")
    # 1.0.0rc1 sorts below v1.0.0, so --as-of (added in v1.0.0) is still a post-baseline flag.
    assert _run(root, dev="1.0.0rc1") == 1
    assert _run(root, dev="1.0.0.dev0") == 1
    # The final 1.0.0 may use v1.0.0 as its baseline.
    assert _run(root, dev="1.0.0") == 0


def test_non_final_latest_tag_is_refused_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, tags={"v0.4.0": JSON_FLAG, "v0.5.0-rc.1": JSON_FLAG})
    _doc(root, "nothing")
    assert _run(root, "--latest-tag", "v0.5.0-rc.1") == 2
    err = _one_line_error(capsys)
    assert "v0.5.0-rc.1" in err and "final release tag" in err
    assert _run(root, "--latest-tag", "v0.4.0") == 0
