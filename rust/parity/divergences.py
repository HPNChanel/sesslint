"""Content-free, exact-capture divergence registry for RX-P1.3f.

Approval classifies a mismatch; it never changes strict parity acceptance.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

START = "<!-- sesslint-divergences-v1 -->\n```json\n"
END = "\n```\n<!-- /sesslint-divergences-v1 -->"
MAX_BYTES = 1_000_000
HASH_KEYS = (
    "fixture_sha256",
    "command_sha256",
    "python_stdout_sha256",
    "python_stderr_sha256",
    "rust_stdout_sha256",
    "rust_stderr_sha256",
)
IDENTITY_KEYS = ("pin", "fixture", *HASH_KEYS, "python_exit", "rust_exit")
ENTRY_KEYS = {*IDENTITY_KEYS, "id", "description", "suspected_python_bug", "reviewer", "date"}


class RegistryError(ValueError):
    """Only static, content-free reason codes escape parsing."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("divergences_duplicate_key")
        result[key] = value
    return result


def _hex(value: object, size: int) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{size}}}", value) is not None


def load_registry(path: Path) -> list[dict[str, Any]]:
    """Refuse missing/malformed/ambiguous registries and every pending entry."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise RegistryError("divergences_too_large")
        text = raw.decode("utf-8")
        if text.count(START) != 1 or text.count(END) != 1:
            raise RegistryError("divergences_markers")
        begin = text.index(START) + len(START)
        end = text.index(END)
        document = json.loads(text[begin:end], object_pairs_hook=_object)
    except RegistryError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise RegistryError("divergences_unreadable") from None
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "entries"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["entries"], list)
        or len(document["entries"]) > 1000
    ):
        raise RegistryError("divergences_schema")
    entries = document["entries"]
    seen_ids: set[str] = set()
    seen_identities: set[tuple[object, ...]] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise RegistryError("divergences_entry_schema")
        if (
            not isinstance(entry["id"], str)
            or re.fullmatch(r"DIV-[A-Za-z0-9][A-Za-z0-9_-]{0,63}", entry["id"]) is None
        ):
            raise RegistryError("divergences_id")
        fixture = entry["fixture"]
        if (
            not isinstance(fixture, str)
            or not fixture.startswith("fixtures/")
            or "\\" in fixture
            or any(part in ("", ".", "..") for part in fixture.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in fixture)
        ):
            raise RegistryError("divergences_fixture")
        if not _hex(entry["pin"], 40) or any(not _hex(entry[k], 64) for k in HASH_KEYS):
            raise RegistryError("divergences_hash")
        if any(type(entry[k]) is not int for k in ("python_exit", "rust_exit")):
            raise RegistryError("divergences_exit")
        if (
            not isinstance(entry["description"], str)
            or not entry["description"].strip()
            or type(entry["suspected_python_bug"]) is not bool
        ):
            raise RegistryError("divergences_description")
        reviewer, reviewed_on = entry["reviewer"], entry["date"]
        if (
            not isinstance(reviewer, str)
            or not reviewer.strip()
            or not isinstance(reviewed_on, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_on) is None
        ):
            raise RegistryError("divergences_unapproved")
        try:
            date.fromisoformat(reviewed_on)
        except ValueError:
            raise RegistryError("divergences_date") from None
        identity = tuple(entry[k] for k in IDENTITY_KEYS)
        if entry["id"] in seen_ids or identity in seen_identities:
            raise RegistryError("divergences_duplicate_entry")
        seen_ids.add(entry["id"])
        seen_identities.add(identity)
    return entries


def fingerprint(
    pin: str,
    fixture: str,
    fixture_sha256: str,
    command: list[str],
    python_capture: tuple[int, bytes, bytes],
    rust_capture: tuple[int, bytes, bytes],
) -> dict[str, object]:
    """Bind classification to invocation, source bytes and both full captures."""

    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    result: dict[str, object] = {
        "pin": pin,
        "fixture": fixture,
        "fixture_sha256": fixture_sha256,
        "command_sha256": digest(
            json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        ),
    }
    for name, (code, out, err) in (("python", python_capture), ("rust", rust_capture)):
        result[name + "_exit"] = code
        result[name + "_stdout_sha256"] = digest(out)
        result[name + "_stderr_sha256"] = digest(err)
    return result


def hash_fixture(path: Path) -> str:
    """Hash synthetic fixtures without retaining potentially large inputs."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def classify(entries: list[dict[str, Any]], observed: dict[str, object]) -> str | None:
    """Return an approved ID only when every identity field matches exactly."""
    for entry in entries:
        if all(entry[key] == observed.get(key) for key in IDENTITY_KEYS):
            return str(entry["id"])
    return None
