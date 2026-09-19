#!/usr/bin/env python3
"""Release-reference consistency checker (field-test debt F5).

Scans user-facing docs for version pins and CLI flag mentions, and verifies
they resolve against released git tags:

- Version pins (``rev: vX.Y.Z``, ``sesslint==X.Y.Z``, ``sesslint@vX.Y.Z``,
  ``uses: ...sesslint...@vX.Y.Z``) must equal the latest published tag, or --
  when they reference the in-development ``_version.py`` version -- carry an
  explicit ``next-release`` marker.
- Documented ``--flags`` that do not exist in ``src/sesslint/cli.py`` at the
  latest tag describe working-tree features and must carry the marker.

Marker convention
-----------------
- ``next-release`` / ``next release`` token on the same line covers that line
  (e.g. a trailing ``*(next release)*`` in a table row).
- ``<!-- next-release -->`` on its own line covers everything until the next
  markdown heading (fenced code blocks are not treated as headings).

Exit codes: 0 = clean, 1 = violations found, 2 = operational error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_HINT = "sesslint"
VERSION_FILE = "src/sesslint/_version.py"
CLI_FILE = "src/sesslint/cli.py"
HOOK_MANIFEST = ".pre-commit-hooks.yaml"

SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[.\-+][0-9A-Za-z.\-]+)?$")
PIP_PIN_RE = re.compile(r"sesslint==([0-9]+\.[0-9]+\.[0-9]+[^\s'\"`,)]*)")
AT_PIN_RE = re.compile(r"(?<![\w.\-])sesslint@([^\s'\"`,)]+)")
USES_PIN_RE = re.compile(r"uses:\s*[^\s|]*sesslint[^\s|]*@([^\s'\"`,)]+)")
REPO_LINE_RE = re.compile(r"\s*-?\s*repo:\s*['\"]?([^\s'\"]+)")
REV_LINE_RE = re.compile(r"^\s*rev:\s*['\"]?([^\s'\"#]+)")
FLAG_RE = re.compile(r"--[a-z0-9][a-z0-9-]*")
MARKER_RE = re.compile(r"next[ -]release", re.IGNORECASE)
SECTION_MARKER_RE = re.compile(r"<!--\s*next[ -]release\s*-->", re.IGNORECASE)
HEADING_RE = re.compile(r"^#{1,6}\s")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
VERSION_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')
CLI_FLAG_RE = re.compile(r'"(--[a-z0-9-]+)"')

EXCLUDED_DIRS = (".git", "plans", "node_modules", "dist", ".venv", "venv", "__pycache__")
EXCLUDED_GLOBS = ("docs/implementation/", "tests/", "fixtures/", "bench/")
EXCLUDED_SUFFIX_PLAN = "-plan"  # root-level local planning packs (*-plan/)


@dataclass
class Ref:
    file: str
    line: int
    kind: str
    value: str
    covered: bool
    verdict: str = ""


@dataclass
class FlagHit:
    file: str
    line: int
    flag: str
    covered: bool


@dataclass
class Report:
    latest_tag: str | None
    dev_version: str
    pins: list[Ref] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    files_scanned: int = 0


def parse_semver(text: str) -> tuple[int, int, int] | None:
    m = SEMVER_RE.match(text.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout


def git_tags(root: Path) -> list[str]:
    try:
        out = _git(root, "tag", "--list", "v*")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [t.strip() for t in out.splitlines() if t.strip()]


def git_show(root: Path, ref: str, path: str) -> str | None:
    try:
        return _git(root, "show", f"{ref}:{path}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def dev_version(root: Path) -> str:
    text = (root / VERSION_FILE).read_text(encoding="utf-8")
    m = VERSION_RE.search(text)
    if not m:
        raise RuntimeError(f"cannot parse __version__ from {VERSION_FILE}")
    return m.group(1)


def cli_flags(source: str) -> set[str]:
    return set(CLI_FLAG_RE.findall(source))


def iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in ("README.md", "RELEASING.md", "CONTRIBUTING.md", ".pre-commit-config.yaml"):
        p = root / name
        if p.is_file():
            files.append(p)
    for base in ("docs", ".github"):
        d = root / base
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.suffix.lower() not in (".md", ".yml", ".yaml") or not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            # .github/actions/** are product manifests (like .pre-commit-hooks.yaml),
            # not consumer-facing docs — their inputs ship with the artifact itself.
            if rel.startswith(".github/actions/"):
                continue
            if any(rel.startswith(g) for g in EXCLUDED_GLOBS):
                continue
            if any(
                part.endswith(EXCLUDED_SUFFIX_PLAN) or part in EXCLUDED_DIRS for part in p.parts
            ):
                continue
            files.append(p)
    return files


def scan_lines(
    lines: list[str], rel: str, post_tag_flags: set[str]
) -> tuple[list[Ref], list[FlagHit]]:
    pins: list[Ref] = []
    flags: list[FlagHit] = []
    in_fence = False
    marked = False
    repo_ctx: str | None = None
    for lineno, line in enumerate(lines, 1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
        if not in_fence and HEADING_RE.match(line):
            marked = False
        if SECTION_MARKER_RE.search(line):
            marked = True
        covered = marked or bool(MARKER_RE.search(line))

        m = REPO_LINE_RE.match(line)
        if m:
            repo_ctx = m.group(1) if REPO_HINT in m.group(1).lower() else None
        m = REV_LINE_RE.match(line)
        if m:
            if repo_ctx:
                pins.append(Ref(rel, lineno, "rev", m.group(1), covered))
            repo_ctx = None

        claimed_spans: list[tuple[int, int]] = []
        for kind, rx in (("uses-pin", USES_PIN_RE), ("pip-pin", PIP_PIN_RE), ("at-pin", AT_PIN_RE)):
            for mm in rx.finditer(line):
                if any(s <= mm.start() < e for s, e in claimed_spans):
                    continue
                claimed_spans.append(mm.span())
                pins.append(Ref(rel, lineno, kind, mm.group(1), covered))

        for mm in FLAG_RE.finditer(line):
            # Flag coverage is a *documentation* contract: only markdown is
            # consumer-facing prose. YAML/CI files legitimately invoke other
            # tools whose flags (e.g. pip's --upgrade) collide with ours.
            if rel.endswith(".md") and mm.group(0) in post_tag_flags:
                flags.append(FlagHit(rel, lineno, mm.group(0), covered))
    return pins, flags


def classify(
    value: str,
    latest: tuple[int, int, int] | None,
    dev: tuple[int, int, int],
    tags: set[tuple[int, int, int]],
) -> str:
    v = parse_semver(value)
    if v is None:
        return "nonsemver"
    if latest and v == latest:
        return "match"
    if latest is None and v == dev:
        return "match-dev"  # no releases exist; docs describing dev version
    if v == dev:
        return "dev"  # ahead of latest tag -> needs marker
    if v in tags:
        return "stale"
    return "unknown"


def evaluate(
    root: Path,
    latest: tuple[int, int, int] | None,
    dev: tuple[int, int, int],
    tags: set[tuple[int, int, int]],
    files: list[Path],
) -> Report:
    rep = Report(
        latest_tag=f"v{'.'.join(map(str, latest))}" if latest else None,
        dev_version=".".join(map(str, dev)),
    )
    tag_flags: set[str] | None = None
    if latest:
        src = git_show(root, f"v{'.'.join(map(str, latest))}", CLI_FILE)
        if src is None:
            rep.advisories.append(f"cannot read {CLI_FILE} at latest tag; flag skew check skipped")
        else:
            tag_flags = cli_flags(src)
    wt_flags = cli_flags((root / CLI_FILE).read_text(encoding="utf-8"))
    post_tag = wt_flags - tag_flags if tag_flags is not None else set()
    if latest is None:
        rep.advisories.append("no git tags found; treating refs equal to dev version as valid")

    for p in files:
        rel = p.relative_to(root).as_posix()
        pins, hits = scan_lines(p.read_text(encoding="utf-8").splitlines(), rel, post_tag)
        rep.files_scanned += 1
        for ref in pins:
            ref.verdict = classify(ref.value, latest, dev, tags)
            rep.pins.append(ref)
        rep.flags.extend(hits)

    for ref in rep.pins:
        loc = f"{ref.file}:{ref.line}"
        if ref.verdict in ("stale", "unknown"):
            rep.violations.append(
                f"{loc}: {ref.kind} '{ref.value}' is {ref.verdict} "
                f"(latest tag: {rep.latest_tag or 'none'}, dev: {rep.dev_version})"
            )
        elif ref.verdict == "dev" and not ref.covered:
            rep.violations.append(
                f"{loc}: {ref.kind} '{ref.value}' matches in-development version "
                f"without a next-release marker"
            )

    for hit in rep.flags:
        if not hit.covered:
            rep.violations.append(
                f"{hit.file}:{hit.line}: documented flag '{hit.flag}' does not exist "
                f"at {rep.latest_tag} and lacks a next-release marker"
            )

    if latest:
        tag_manifest = git_show(root, f"v{'.'.join(map(str, latest))}", HOOK_MANIFEST)
        wt_manifest_path = root / HOOK_MANIFEST
        if tag_manifest is not None and wt_manifest_path.is_file():
            if wt_manifest_path.read_text(encoding="utf-8") != tag_manifest:
                rep.advisories.append(
                    f"{HOOK_MANIFEST} differs from {rep.latest_tag}: consumers pinning "
                    f"the tag get the tagged manifest; post-tag hook behavior must be "
                    f"marked next-release in docs"
                )
    return rep


def render_text(rep: Report) -> str:
    out = [
        f"release-refs: {rep.files_scanned} files scanned",
        f"latest tag: {rep.latest_tag or '(none)'} | dev version: {rep.dev_version}",
    ]
    for ref in rep.pins:
        mark = "" if ref.covered else " [unmarked]"
        out.append(f"  pin  {ref.file}:{ref.line}  {ref.kind} {ref.value}  -> {ref.verdict}{mark}")
    uncovered = [h for h in rep.flags if not h.covered]
    for h in rep.flags:
        if h in uncovered:
            out.append(f"  flag {h.file}:{h.line}  {h.flag}  -> UNCOVERED post-tag feature")
    for a in rep.advisories:
        out.append(f"  note: {a}")
    if rep.violations:
        out.append(f"FAIL: {len(rep.violations)} violation(s)")
        out.extend(f"  - {v}" for v in rep.violations)
    else:
        out.append("OK: all release references resolve")
    return "\n".join(out)


def render_json(rep: Report) -> str:
    return json.dumps(
        {
            "latest_tag": rep.latest_tag,
            "dev_version": rep.dev_version,
            "files_scanned": rep.files_scanned,
            "pins": [
                {
                    "file": r.file,
                    "line": r.line,
                    "kind": r.kind,
                    "value": r.value,
                    "covered": r.covered,
                    "verdict": r.verdict,
                }
                for r in rep.pins
            ],
            "uncovered_flags": [
                {"file": h.file, "line": h.line, "flag": h.flag} for h in rep.flags if not h.covered
            ],
            "advisories": rep.advisories,
            "violations": rep.violations,
            "ok": not rep.violations,
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--root", default=".", help="repository root (default: cwd)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable report")
    ap.add_argument(
        "--latest-tag", help="override latest tag (e.g. v0.2.0) when git is unavailable"
    )
    ap.add_argument("--dev-version", help="override _version.py version")
    ap.add_argument("--files", nargs="*", help="explicit files to scan instead of defaults")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        dev = (
            parse_semver(args.dev_version) if args.dev_version else parse_semver(dev_version(root))
        )
    except (RuntimeError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if dev is None:
        print("error: dev version is not semver", file=sys.stderr)
        return 2

    tags = set(v for t in git_tags(root) if (v := parse_semver(t)))
    if args.latest_tag:
        lt = parse_semver(args.latest_tag)
        if lt is None:
            print(f"error: --latest-tag '{args.latest_tag}' is not semver", file=sys.stderr)
            return 2
        latest: tuple[int, int, int] | None = lt
        tags.add(lt)
    else:
        latest = max(tags) if tags else None

    files = [root / f for f in args.files] if args.files else iter_scan_files(root)
    rep = evaluate(root, latest, dev, tags, files)
    print(render_json(rep) if args.json else render_text(rep))
    return 1 if rep.violations else 0


if __name__ == "__main__":
    sys.exit(main())
