#!/usr/bin/env python3
"""Release-reference consistency checker (field-test debt F5).

Scans user-facing docs for version pins and CLI flag mentions, and verifies
they resolve against locally available git tags (not public availability):

- Version pins (``rev: vX.Y.Z``, ``sesslint==X.Y.Z``, ``sesslint@vX.Y.Z``,
  ``uses: ...sesslint...@vX.Y.Z``) must equal the latest local tag, or --
  when they reference the in-development ``_version.py`` version -- carry an
  explicit ``next-release`` marker.
- Documented ``--flags`` that do not exist in the CLI source at the latest tag
  describe working-tree features and must carry the marker.

Baseline tag
------------
The "latest tag" is the highest **final** release tag (``vX.Y.Z``, no
pre-release suffix) that is not above the in-development version; pre-release
tags such as ``v0.5.0-rc.1`` are ignored (they are not a released CLI surface).
The check fails closed: if no baseline can be resolved, or the CLI source cannot
be read at the baseline tag (no tags, shallow clone, git unavailable), it exits
2 instead of silently skipping the flag-skew check. Fetch the tags
(``git fetch --tags``; CI uses ``fetch-depth: 0``) or, only where tags truly
cannot exist (a source archive, a no-history export), pass
``--allow-no-baseline`` to accept that the flag-skew check is skipped.

Marker convention
-----------------
- ``next-release`` / ``next release`` token on the same line covers that line
  (e.g. a trailing ``*(next release)*`` in a table row).
- ``<!-- next-release -->`` alone on its own line covers everything until the
  next markdown heading (fenced code blocks are not treated as headings).
- ``<!-- next-release: file -->`` alone on its own line, outside a fenced code
  block, covers the whole file (for a document that describes only an unreleased
  feature). Either marker anywhere else on a line -- inside inline code, at the
  end of a table row, inside a fence -- covers nothing beyond what the same-line
  ``next-release`` token already covers.
- Flags inside a command span that runs this repository's own build tooling
  (``python scripts/...``, ``python -m build``) are not SessLint CLI flags and are
  ignored; the span ends at the closing backtick, ``&``, ``|`` or ``;``, so a
  SessLint flag later on the same line is still checked.

Exit codes: 0 = clean, 1 = violations found, 2 = operational error (including
an unresolvable baseline tag without ``--allow-no-baseline``, an unreadable or
non-UTF-8 input file, or a non-final ``--latest-tag``).
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
CLI_PKG_DIR = "src/sesslint/cli"
HOOK_MANIFEST = ".pre-commit-hooks.yaml"

# Semver (``1.0.0-rc.1``) and PEP 440 (``1.0.0rc1``, ``1.0.0.dev0``, ``1.0.0.post1``) suffixes.
SEMVER_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)"
    r"(?:[.\-+][0-9A-Za-z.\-]+|(?:a|b|c|rc|alpha|beta|pre|preview)\d*(?:[.\-+][0-9A-Za-z.\-]+)?)?$"
)
# A development version below its own X.Y.Z: pre-release (``rc``, ``-rc.1``) or ``dev`` suffix.
PRERELEASE_RE = re.compile(
    r"^v?\d+\.\d+\.\d+[.\-_+]?(?:a|b|c|rc|alpha|beta|pre|preview|dev)(?![a-z])", re.IGNORECASE
)
PIP_PIN_RE = re.compile(r"sesslint==([0-9]+\.[0-9]+\.[0-9]+[^\s'\"`,)]*)")
AT_PIN_RE = re.compile(r"(?<![\w.\-])sesslint@([^\s'\"`,)]+)")
USES_PIN_RE = re.compile(r"uses:\s*[^\s|]*sesslint[^\s|]*@([^\s'\"`,)]+)")
REPO_LINE_RE = re.compile(r"\s*-?\s*repo:\s*['\"]?([^\s'\"]+)")
REV_LINE_RE = re.compile(r"^\s*rev:\s*['\"]?([^\s'\"#]+)")
FLAG_RE = re.compile(r"--[a-z0-9][a-z0-9-]*")
MARKER_RE = re.compile(r"next[ -]release", re.IGNORECASE)
# Section and file markers count only when alone on their line (at most three leading spaces).
SECTION_MARKER_RE = re.compile(r"^ {0,3}<!--\s*next[ -]release\s*-->\s*$", re.IGNORECASE)
FILE_MARKER_RE = re.compile(r"^ {0,3}<!--\s*next[ -]release\s*:\s*file\s*-->\s*$", re.IGNORECASE)
# Repository build tooling has its own flags (e.g. ``--target``); they are not CLI flags.
# Only the command span is ignored: it ends at a closing backtick, ``&``, ``|`` or ``;``.
TOOLING_SPAN_RE = re.compile(r"\bpython3?\s+(?:-m\s+build\b|scripts/)[^`&|;]*")
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
    flag_skew_checked: bool = True


FINAL_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
FINAL_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+$")


class BaselineError(RuntimeError):
    """The release baseline needed for the flag-skew check cannot be resolved."""


class ScanError(RuntimeError):
    """An input file cannot be read as UTF-8 text (operational error, exit 2)."""


def read_text(path: Path, label: str) -> str:
    """Read ``path`` as UTF-8; failures name the file, never its content."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ScanError(f"{label}: file not found") from None
    except UnicodeDecodeError:
        raise ScanError(f"{label}: not valid UTF-8") from None
    except OSError as e:
        raise ScanError(f"{label}: cannot read ({e.strerror or type(e).__name__})") from None


def final_tag_versions(tags: list[str]) -> dict[tuple[int, int, int], str]:
    """Map version triples to tag names for final releases only (``vX.Y.Z``)."""
    out: dict[tuple[int, int, int], str] = {}
    for tag in tags:
        m = FINAL_TAG_RE.match(tag.strip())
        if m:
            out[(int(m.group(1)), int(m.group(2)), int(m.group(3)))] = tag.strip()
    return out


def resolve_baseline(
    tags: list[str], dev: tuple[int, int, int], *, dev_is_prerelease: bool = False
) -> tuple[int, int, int] | None:
    """Highest final release tag that is not above the development version.

    A pre-release or ``dev`` build of ``X.Y.Z`` sorts below ``vX.Y.Z``, so for it the
    baseline must be strictly below ``X.Y.Z``.
    """
    candidates = [
        v for v in final_tag_versions(tags) if (v < dev if dev_is_prerelease else v <= dev)
    ]
    return max(candidates) if candidates else None


def parse_semver(text: str) -> tuple[int, int, int] | None:
    m = SEMVER_RE.match(text.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def is_prerelease(text: str) -> bool:
    """True for a version that sorts below its own ``X.Y.Z`` (pre-release or ``dev``)."""
    return PRERELEASE_RE.match(text.strip()) is not None


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout


def git_tags(root: Path) -> list[str]:
    try:
        out = _git(root, "tag", "--list", "v*")
    except (subprocess.CalledProcessError, OSError):
        return []
    return [t.strip() for t in out.splitlines() if t.strip()]


def git_show(root: Path, ref: str, path: str) -> str | None:
    try:
        return _git(root, "show", f"{ref}:{path}")
    except (subprocess.CalledProcessError, OSError):
        return None


def cli_source_at_ref(root: Path, ref: str) -> str | None:
    """Return the CLI source at ``ref`` — single-file ``cli.py`` or the
    ``cli/`` package (concatenated ``*.py``, sorted for determinism)."""
    src = git_show(root, ref, CLI_FILE)
    if src is not None:
        return src
    try:
        names = _git(root, "ls-tree", "-r", "--name-only", ref, "--", CLI_PKG_DIR)
    except (subprocess.CalledProcessError, OSError):
        return None
    parts = [
        git_show(root, ref, name) for name in sorted(names.splitlines()) if name.endswith(".py")
    ]
    text = "\n".join(p for p in parts if p is not None)
    return text or None


def cli_source_worktree(root: Path) -> str:
    """Return the worktree CLI source — ``cli/`` package when present, else
    the legacy single-file ``cli.py``."""
    pkg = root / CLI_PKG_DIR
    if pkg.is_dir():
        return "\n".join(
            read_text(p, p.relative_to(root).as_posix()) for p in sorted(pkg.glob("*.py"))
        )
    return read_text(root / CLI_FILE, CLI_FILE)


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
    file_marked = False
    fenced = False
    for text in lines:  # a file marker counts only alone on a line and outside a fenced block
        if FENCE_RE.match(text):
            fenced = not fenced
        elif not fenced and FILE_MARKER_RE.match(text):
            file_marked = True
    repo_ctx: str | None = None
    for lineno, line in enumerate(lines, 1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
        if not in_fence and HEADING_RE.match(line):
            marked = False
        if not in_fence and SECTION_MARKER_RE.match(line):
            marked = True
        covered = marked or file_marked or bool(MARKER_RE.search(line))

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

        tooling_spans = [m.span() for m in TOOLING_SPAN_RE.finditer(line)]
        for mm in FLAG_RE.finditer(line):
            if any(a <= mm.start() < b for a, b in tooling_spans):
                continue
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
    *,
    allow_no_baseline: bool = False,
) -> Report:
    """Evaluate pins and flags.

    Fails closed (:class:`BaselineError`) when the baseline tag or its CLI source
    is unavailable, unless ``allow_no_baseline`` explicitly accepts skipping the
    flag-skew check.
    """
    rep = Report(
        latest_tag=f"v{'.'.join(map(str, latest))}" if latest else None,
        dev_version=".".join(map(str, dev)),
    )
    tag_flags: set[str] | None = None
    problem: str | None = None
    if latest is None:
        problem = "no final release tag (vX.Y.Z) at or below the development version was found"
    else:
        src = cli_source_at_ref(root, f"v{'.'.join(map(str, latest))}")
        if src is None:
            problem = f"cannot read {CLI_FILE} or {CLI_PKG_DIR}/ at baseline tag {rep.latest_tag}"
        else:
            tag_flags = cli_flags(src)
    if problem is not None:
        if not allow_no_baseline:
            raise BaselineError(
                f"{problem}; the flag-skew check cannot run. Fetch release tags "
                f"(`git fetch --tags`; CI needs `fetch-depth: 0`), or pass "
                f"--allow-no-baseline only where tags cannot exist"
            )
        rep.flag_skew_checked = False
        rep.advisories.append(f"{problem}; flag skew check SKIPPED (--allow-no-baseline)")
    wt_flags = cli_flags(cli_source_worktree(root))
    post_tag = wt_flags - tag_flags if tag_flags is not None else set()

    for p in files:
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            raise ScanError(f"{p.as_posix()}: outside --root {root.as_posix()}") from None
        pins, hits = scan_lines(read_text(p, rel).splitlines(), rel, post_tag)
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
            if read_text(wt_manifest_path, HOOK_MANIFEST) != tag_manifest:
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
        skipped = "" if rep.flag_skew_checked else " (flag-skew check SKIPPED)"
        out.append(
            "OK: local tag references are consistent; public publication is not verified" + skipped
        )
    return "\n".join(out)


def render_json(rep: Report) -> str:
    return json.dumps(
        {
            "latest_tag": rep.latest_tag,
            "dev_version": rep.dev_version,
            "files_scanned": rep.files_scanned,
            "flag_skew_checked": rep.flag_skew_checked,
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
        "--latest-tag",
        help="override the baseline tag (e.g. v0.2.0); its CLI source must still be readable",
    )
    ap.add_argument(
        "--allow-no-baseline",
        action="store_true",
        help="do not fail when no baseline release tag can be resolved; the flag-skew check "
        "is then skipped (source archives / no-history exports only)",
    )
    ap.add_argument("--dev-version", help="override _version.py version")
    ap.add_argument("--files", nargs="*", help="explicit files to scan instead of defaults")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        dev_text = args.dev_version if args.dev_version else dev_version(root)
    except (RuntimeError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    dev = parse_semver(dev_text)
    if dev is None:
        print(f"error: dev version '{dev_text}' is not semver or PEP 440", file=sys.stderr)
        return 2

    tag_names = git_tags(root)
    tags = set(final_tag_versions(tag_names))
    if args.latest_tag:
        lt = parse_semver(args.latest_tag)
        if lt is None:
            print(f"error: --latest-tag '{args.latest_tag}' is not semver", file=sys.stderr)
            return 2
        if not FINAL_VERSION_RE.match(args.latest_tag.strip()):
            print(
                f"error: --latest-tag '{args.latest_tag}' is not a final release tag (vX.Y.Z); "
                "pre-release tags are not a released CLI surface",
                file=sys.stderr,
            )
            return 2
        latest: tuple[int, int, int] | None = lt
        tags.add(lt)
    else:
        latest = resolve_baseline(tag_names, dev, dev_is_prerelease=is_prerelease(dev_text))

    try:
        files = [root / f for f in args.files] if args.files else iter_scan_files(root)
        rep = evaluate(root, latest, dev, tags, files, allow_no_baseline=args.allow_no_baseline)
    except (BaselineError, ScanError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, subprocess.SubprocessError) as e:
        print(f"error: {type(e).__name__} while scanning the inputs", file=sys.stderr)
        return 2
    print(render_json(rep) if args.json else render_text(rep))
    return 1 if rep.violations else 0


if __name__ == "__main__":
    sys.exit(main())
