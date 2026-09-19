"""Render package-manager manifest templates for a release (release-dist T-04).

Reads ``sha256sum``-format checksum files (``sha256sums.txt`` plus the
per-OS ``SHA256SUMS-<os>`` assets produced by ``scripts/package.py``),
derives the release artifact set, and renders every template under
``packaging/<channel>/`` into ``<out>/<channel>/``.

Template syntax
---------------
``{version}``        bare version (``0.2.0``)
``{tag}``            release tag (``v0.2.0``)
``{repo}``           ``owner/name`` (default ``HPNChanel/sesslint``)
``{url_<key>}``      download URL for artifact ``sesslint-<version>-<key>``
                     (key uses ``-`` → ``_``: ``macos-arm64`` → ``macos_arm64``)
``{sha256_<key>}``   hex digest for the same artifact
``{if:<key>}`` ... ``{/if:<key>}``   block kept only when the artifact exists;
                     markers must occupy their own lines (never emitted).
                     Blocks may nest; unmatched markers fail closed.

Any ``{...}`` left over after rendering fails the render — a manifest that
silently shipped a placeholder is worse than no manifest.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_ROOT = REPO_ROOT / "packaging"
DEFAULT_REPO = "HPNChanel/sesslint"

_SUM_LINE = re.compile(r"^([0-9a-fA-F]{64})[ \t][ *](?P<name>.+?)[ \t]*$")
_IF_OPEN = re.compile(r"^\{if:([a-z0-9_]+)\}$")
_IF_CLOSE = re.compile(r"^\{/if:([a-z0-9_]+)\}$")
_PLACEHOLDER = re.compile(r"(?<![$#])\{([a-z0-9_]+)\}")
_ARTIFACT_PREFIX = "sesslint-"


def _die(message: str) -> SystemExit:
    return SystemExit(f"render_manifests: {message}")


def parse_sums(path: Path) -> dict[str, str]:
    """Parse a ``sha256sum``-format file into ``{filename: hexdigest}``."""
    entries: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        raise _die(f"cannot read sums file {path}: {err}") from err
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _SUM_LINE.match(line)
        if not match:
            raise _die(f"{path}:{lineno}: not a sha256sum line: {line!r}")
        name = match.group("name")
        if name in entries:
            raise _die(f"{path}:{lineno}: duplicate artifact {name!r}")
        entries[name] = match.group(1).lower()
    if not entries:
        raise _die(f"{path}: no checksum entries found")
    return entries


_BINARY_OSES = frozenset({"linux", "macos", "windows"})


def artifact_key(name: str, version: str) -> str | None:
    """``sesslint-0.2.0-macos-arm64`` -> ``macos_arm64``; non-matching -> None.

    Only OS-binary artifact names derive keys (``<os>-<arch>[.exe]`` with
    ``os`` in linux/macos/windows, matching ``package.py``'s naming) — the
    wheel and sdist are PyPI artifacts, not manifest placeholders.
    """
    prefix = f"{_ARTIFACT_PREFIX}{version}-"
    if not name.startswith(prefix):
        return None
    stem = name[len(prefix) :]
    if stem == "man.tar.gz":
        # Generated man-page bundle (docs-spec T-05): ``sesslint-<ver>-man.tar.gz``
        # yields the ``man`` key -> ``{url_man}`` / ``{sha256_man}`` placeholders.
        return "man"
    if stem.endswith(".exe"):
        stem = stem[: -len(".exe")]
    os_name, sep, arch = stem.partition("-")
    if not sep or os_name not in _BINARY_OSES or not arch:
        return None
    return f"{os_name}_{arch.replace('-', '_')}"


def _render_conditionals(lines: list[str], keys: frozenset[str], source: Path) -> list[str]:
    """Apply {if:key}...{/if:key} blocks; validate marker pairing."""
    out: list[str] = []
    stack: list[tuple[str, int]] = []  # (key, lineno)
    emit = True
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        open_m = _IF_OPEN.match(stripped)
        close_m = _IF_CLOSE.match(stripped)
        if open_m:
            key = open_m.group(1)
            stack.append((key, lineno))
            emit = emit and key in keys
            continue
        if close_m:
            key = close_m.group(1)
            if not stack or stack[-1][0] != key:
                raise _die(f"{source}:{lineno}: unmatched {{/if:{key}}}")
            stack.pop()
            emit = all(k in keys for k, _ in stack)
            continue
        if emit:
            out.append(line)
    if stack:
        key, lineno = stack[-1]
        raise _die(f"{source}:{lineno}: unclosed {{if:{key}}}")
    return out


def render_template(
    text: str,
    *,
    values: dict[str, str],
    keys: frozenset[str],
    source: Path,
) -> str:
    """Render one template: conditionals first, then scalar placeholders."""
    kept = _render_conditionals(text.splitlines(keepends=True), keys, source)

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in values:
            return values[name]
        raise _die(f"{source}: unresolved placeholder {{{name}}}")

    rendered = _PLACEHOLDER.sub(_sub, "".join(kept))
    if _PLACEHOLDER.search(rendered):
        raise _die(f"{source}: unresolved placeholder remains after render")
    return rendered


def build_values(
    *,
    version: str,
    repo: str,
    sums: dict[str, str],
) -> tuple[dict[str, str], frozenset[str]]:
    """Build the placeholder map + artifact key set from the sums entries."""
    keys: set[str] = set()
    values: dict[str, str] = {"version": version, "tag": f"v{version}", "repo": repo}
    for name, digest in sorted(sums.items()):
        key = artifact_key(name, version)
        if key is None:
            continue
        keys.add(key)
        values[f"sha256_{key}"] = digest
        values[f"url_{key}"] = f"https://github.com/{repo}/releases/download/v{version}/{name}"
    return values, frozenset(keys)


def render_all(
    *,
    version: str,
    repo: str,
    sums_paths: list[Path],
    templates_root: Path,
    out_dir: Path,
) -> list[Path]:
    sums: dict[str, str] = {}
    for path in sums_paths:
        for name, digest in parse_sums(path).items():
            prior = sums.get(name)
            if prior is not None and prior != digest:
                raise _die(f"conflicting digests for {name!r} across sums files")
            sums[name] = digest
    values, keys = build_values(version=version, repo=repo, sums=sums)
    if not keys:
        raise _die("no release artifacts found in the provided sums files")

    written: list[Path] = []
    for channel_dir in sorted(p for p in templates_root.iterdir() if p.is_dir()):
        for template in sorted(channel_dir.iterdir()):
            if not template.is_file():
                continue
            rendered = render_template(
                template.read_text(encoding="utf-8"),
                values=values,
                keys=keys,
                source=template,
            )
            dest = out_dir / channel_dir.name / template.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(rendered, encoding="utf-8", newline="\n")
            written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, e.g. 0.2.0")
    parser.add_argument(
        "--sums",
        required=True,
        action="append",
        type=Path,
        help="sha256sum-format file; repeatable (sha256sums.txt, SHA256SUMS-<os>)",
    )
    parser.add_argument("--repo", default=DEFAULT_REPO, help="owner/name for URLs")
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    parser.add_argument(
        "--templates",
        default=TEMPLATES_ROOT,
        type=Path,
        help="templates root (default: packaging/)",
    )
    args = parser.parse_args(argv)

    try:
        written = render_all(
            version=args.version,
            repo=args.repo,
            sums_paths=args.sums,
            templates_root=args.templates,
            out_dir=args.out,
        )
    except SystemExit as err:
        print(err, file=sys.stderr)
        return 2
    for path in written:
        print(f"rendered {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
