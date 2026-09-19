"""Tests for scripts/render_manifests.py + packaging/ templates (release T-04).

Validates the sha256sum parser, artifact-key derivation, the {if:key}
conditional renderer, fail-closed placeholder handling, and end-to-end
rendering of every channel template into schema-plausible manifests.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess  # noqa: S404 - test-only, host validation tool
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "render_manifests.py"
TEMPLATES = REPO_ROOT / "packaging"

spec = importlib.util.spec_from_file_location("render_manifests", SCRIPT)
assert spec is not None and spec.loader is not None
rm = importlib.util.module_from_spec(spec)
sys.modules.setdefault("render_manifests", rm)
spec.loader.exec_module(rm)

_SHA = {
    "macos_arm64": "a" * 64,
    "linux_x86_64": "b" * 64,
    "windows_x86_64": "c" * 64,
}


def _sums_file(tmp_path: Path, entries: dict[str, str]) -> Path:
    path = tmp_path / "sha256sums.txt"
    path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in entries.items()),
        encoding="utf-8",
    )
    return path


def _release_sums(tmp_path: Path) -> Path:
    return _sums_file(
        tmp_path,
        {
            f"sesslint-0.2.0-{k.replace('_', '-', 1)}{'.exe' if 'windows' in k else ''}": v
            for k, v in _SHA.items()
        },
    )


# ---------------------------------------------------------------------------
# parse_sums / artifact_key
# ---------------------------------------------------------------------------


def test_parse_sums_text_and_binary_markers(tmp_path: Path) -> None:
    path = tmp_path / "SHA256SUMS"
    path.write_text(
        "a" * 64
        + "  sesslint-0.2.0-linux-x86_64\n"
        + "b" * 64
        + " *sesslint-0.2.0-windows-x86_64.exe\n",
        encoding="utf-8",
    )
    entries = rm.parse_sums(path)
    assert entries["sesslint-0.2.0-linux-x86_64"] == "a" * 64
    assert entries["sesslint-0.2.0-windows-x86_64.exe"] == "b" * 64


def test_parse_sums_malformed_and_empty(tmp_path: Path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("not-a-checksum  file\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="not a sha256sum line"):
        rm.parse_sums(bad)
    empty = tmp_path / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="no checksum entries"):
        rm.parse_sums(empty)


def test_artifact_key_derivation() -> None:
    assert rm.artifact_key("sesslint-0.2.0-macos-arm64", "0.2.0") == "macos_arm64"
    assert rm.artifact_key("sesslint-0.2.0-windows-x86_64.exe", "0.2.0") == "windows_x86_64"
    assert rm.artifact_key("sesslint-0.2.0-py3-none-any.whl", "0.2.0") is None
    assert rm.artifact_key("SHA256SUMS-windows-latest", "0.2.0") is None
    assert rm.artifact_key("sesslint-0.1.0-linux-x86_64", "0.2.0") is None
    assert rm.artifact_key("sesslint-0.2.0-man.tar.gz", "0.2.0") == "man"


# ---------------------------------------------------------------------------
# conditional rendering
# ---------------------------------------------------------------------------


def _render(text: str, keys: frozenset[str]) -> str:
    return rm.render_template(
        text,
        values={"version": "0.2.0", "tag": "v0.2.0", "repo": "o/r"},
        keys=keys,
        source=Path("t"),
    )


def test_conditional_kept_and_dropped() -> None:
    text = "a\n{if:windows_x86_64}\nwin:{version}\n{/if:windows_x86_64}\nb\n"
    assert _render(text, frozenset({"windows_x86_64"})) == "a\nwin:0.2.0\nb\n"
    assert _render(text, frozenset()) == "a\nb\n"


def test_conditional_nested() -> None:
    text = "{if:a}\nA\n{if:b}\nAB\n{/if:b}\n{/if:a}\nz\n"
    both = frozenset({"a", "b"})
    only_a = frozenset({"a"})
    assert _render(text, both) == "A\nAB\nz\n"
    assert _render(text, only_a) == "A\nz\n"
    assert _render(text, frozenset()) == "z\n"


def test_conditional_unmatched_and_unclosed() -> None:
    with pytest.raises(SystemExit, match="unmatched"):
        _render("x\n{/if:a}\n", frozenset())
    with pytest.raises(SystemExit, match="unclosed"):
        _render("{if:a}\nx\n", frozenset({"a"}))


def test_unresolved_placeholder_fails() -> None:
    with pytest.raises(SystemExit, match="unresolved placeholder"):
        _render("v={version} k={sha256_nope}\n", frozenset())


def test_shell_and_ruby_interpolation_not_placeholders() -> None:
    text = 'v="{version}" shell=${pkgver} ruby=#{bin}\n'
    assert _render(text, frozenset()) == 'v="0.2.0" shell=${pkgver} ruby=#{bin}\n'


# ---------------------------------------------------------------------------
# end-to-end render
# ---------------------------------------------------------------------------


def test_render_all_channels(tmp_path: Path) -> None:
    sums = _release_sums(tmp_path)
    out = tmp_path / "out"
    written = rm.render_all(
        version="0.2.0",
        repo="HPNChanel/sesslint",
        sums_paths=[sums],
        templates_root=TEMPLATES,
        out_dir=out,
    )
    channels = {p.parent.name for p in written}
    assert channels == {"aur", "homebrew", "scoop", "winget"}
    for path in written:
        text = path.read_text(encoding="utf-8")
        assert "0.2.0" in text
        assert not rm._PLACEHOLDER.search(text), f"{path}: leftover placeholder"


def test_rendered_scoop_manifest_schema(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rm.render_all(
        version="0.2.0",
        repo="HPNChanel/sesslint",
        sums_paths=[_release_sums(tmp_path)],
        templates_root=TEMPLATES,
        out_dir=out,
    )
    manifest = json.loads((out / "scoop" / "sesslint.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "0.2.0"
    assert manifest["bin"] == "sesslint.exe"
    assert manifest["architecture"]["64bit"]["hash"] == "c" * 64
    assert manifest["architecture"]["64bit"]["url"].endswith(
        "sesslint-0.2.0-windows-x86_64.exe#/sesslint.exe"
    )
    assert manifest["checkver"]["github"] == "https://github.com/HPNChanel/sesslint"


def test_rendered_pkgbuild_bash_syntax(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rm.render_all(
        version="0.2.0",
        repo="HPNChanel/sesslint",
        sums_paths=[_release_sums(tmp_path)],
        templates_root=TEMPLATES,
        out_dir=out,
    )
    pkgbuild = out / "aur" / "PKGBUILD"
    text = pkgbuild.read_text(encoding="utf-8")
    assert "pkgver=0.2.0" in text
    assert f"'{_SHA['linux_x86_64']}'" in text
    bash = shutil.which("bash")
    if bash is not None:
        proc = subprocess.run(
            [bash, "-n", str(pkgbuild)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stderr


def test_rendered_formula_structure(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rm.render_all(
        version="0.2.0",
        repo="HPNChanel/sesslint",
        sums_paths=[_release_sums(tmp_path)],
        templates_root=TEMPLATES,
        out_dir=out,
    )
    text = (out / "homebrew" / "sesslint.rb").read_text(encoding="utf-8")
    assert "class Sesslint < Formula" in text
    assert "def install" in text and "test do" in text
    # absent artifacts drop their conditional stanzas
    assert "macos_x86_64" not in text and "linux_arm64" not in text
    assert _SHA["macos_arm64"] in text and _SHA["linux_x86_64"] in text
    assert text.count(" end") + text.count("\nend") >= 6  # class/2 on_*/def/test blocks


def test_rendered_winget_manifests(tmp_path: Path) -> None:
    out = tmp_path / "out"
    rm.render_all(
        version="0.2.0",
        repo="HPNChanel/sesslint",
        sums_paths=[_release_sums(tmp_path)],
        templates_root=TEMPLATES,
        out_dir=out,
    )
    winget = out / "winget"
    names = {p.name for p in winget.iterdir()}
    assert names == {
        "HPNChanel.Sesslint.yaml",
        "HPNChanel.Sesslint.installer.yaml",
        "HPNChanel.Sesslint.locale.en-US.yaml",
    }
    installer = (winget / "HPNChanel.Sesslint.installer.yaml").read_text(encoding="utf-8")
    assert "PackageVersion: 0.2.0" in installer
    assert f"InstallerSha256: {_SHA['windows_x86_64']}" in installer


def test_conflicting_digests_fail(tmp_path: Path) -> None:
    sums_a = _sums_file(tmp_path, {"sesslint-0.2.0-linux-x86_64": "a" * 64})
    sums_b = tmp_path / "other.txt"
    sums_b.write_text("b" * 64 + "  sesslint-0.2.0-linux-x86_64\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="conflicting digests"):
        rm.render_all(
            version="0.2.0",
            repo="o/r",
            sums_paths=[sums_a, sums_b],
            templates_root=TEMPLATES,
            out_dir=tmp_path / "o",
        )


def test_no_release_artifacts_fail(tmp_path: Path) -> None:
    sums = _sums_file(tmp_path, {"unrelated.tar.gz": "a" * 64})
    with pytest.raises(SystemExit, match="no release artifacts"):
        rm.render_all(
            version="0.2.0",
            repo="o/r",
            sums_paths=[sums],
            templates_root=TEMPLATES,
            out_dir=tmp_path / "o",
        )


def test_templates_exist_for_all_channels() -> None:
    for channel in ("homebrew", "scoop", "winget", "aur"):
        channel_dir = TEMPLATES / channel
        assert channel_dir.is_dir(), f"missing template dir {channel}"
        assert any(channel_dir.iterdir()), f"{channel} has no templates"
