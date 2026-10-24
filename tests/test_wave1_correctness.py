"""Wave 1 correctness regressions for hostile but synthetic local inputs."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint._canonical_codec import PurePythonCanonicalCodec, canonical_json_bytes
from sesslint.adapters.safe_value import safe_discriminator
from sesslint.bundle import _count_records_bounded
from sesslint.cache import ScanCache
from sesslint.canonical import dump_session_file, load_session_file, parse_session
from sesslint.checks.hygiene import SecretScanTracker, _short_prefix_present
from sesslint.codes import SL001, Repairability, Severity
from sesslint.finding import SourceRef, make_finding
from sesslint.indexes import read_index
from sesslint.mcp_server import MAX_MCP_LINE_BYTES, handle_line, serve
from sesslint.sarif import render_sarif
from sesslint.verify import _parse_session_events


def _secret_families(raw: bytes) -> set[str]:
    tracker = SecretScanTracker()
    tracker.feed(
        raw,
        line_number=1,
        byte_offset=0,
        byte_end=len(raw),
        record_ordinal=0,
    )
    return {
        str(finding.evidence["secret_family"]) for finding in tracker.into_findings(path_str="x")
    }


@pytest.mark.parametrize("escape", [b"\\n", b"\\r", b"\\t", b"\\b", b"\\f"])
def test_secret_shapes_after_real_json_escapes_are_detected(escape: bytes) -> None:
    """Escaped JSON whitespace is a token boundary for raw-record scanning."""
    api_key = b'{"text":"' + escape + b"sk-" + b"A" * 24 + b'"}'
    private_key = b'{"text":"' + escape + b"-----BEGIN PRIVATE KEY-----" + b'"}'
    generic = b'{"api_key":"' + escape + b"abcdefghijklmnoq" + b'"}'

    assert "openai-api-key" in _secret_families(api_key)
    assert "private-key-block" in _secret_families(private_key)
    assert "generic-credential-assignment" in _secret_families(generic)
    for prefix, family in (
        (b"npm_", "npm-token"),
        (b"hf_", "huggingface-token"),
        (b"xoxz-", "slack-token"),
    ):
        assert family in _secret_families(b'{"text":"' + escape + prefix + b"A" * 24 + b'"}')


def test_escaped_backslash_text_does_not_create_a_secret_boundary() -> None:
    """A literal backslash plus ``n`` is not an escaped newline boundary."""
    ordinary_backslash_text = b'{"text":"\\\\nsk-' + b"A" * 24 + b'"}'
    assert "openai-api-key" not in _secret_families(ordinary_backslash_text)


@given(st.integers(min_value=1, max_value=256), st.sampled_from([b"n", b"r", b"t", b"b", b"f"]))
def test_escape_run_parity_preserves_secret_boundaries(run_length: int, suffix: bytes) -> None:
    raw = b'{"text":"' + b"\\" * run_length + suffix + b"sk-" + b"A" * 24 + b'"}'
    assert ("openai-api-key" in _secret_families(raw)) == bool(run_length % 2)


def test_private_key_digest_uses_original_bytes_after_escape_shadow() -> None:
    secret = b"-----BEGIN PRIVATE KEY-----\\n" + b"AbCdEfGh" * 2
    raw = b'{"text":"\\n' + secret + b'"}'
    tracker = SecretScanTracker()
    tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
    finding = next(
        f
        for f in tracker.into_findings(path_str="synthetic.jsonl")
        if f.evidence["secret_family"] == "private-key-block"
    )
    assert finding.evidence["match_sha256"] == [hashlib.sha256(secret).hexdigest()]


def test_secret_window_keeps_stripped_record_boundaries() -> None:
    tracker = SecretScanTracker()
    rows = [b"syntheticword", b"npm_" + b"A" * 24]
    for index, raw in enumerate(rows):
        tracker.feed(
            raw, line_number=index + 1, byte_offset=None, byte_end=None, record_ordinal=index
        )
    findings = tracker.into_findings(path_str="synthetic.jsonl")
    assert [finding.evidence["secret_family"] for finding in findings] == ["npm-token"]


@given(
    st.binary(max_size=128),
    st.sampled_from([b"npm_", b"hf_", b"xoxb-", b"xoxz-", b"xoxA-", b"xox!"]),
    st.binary(max_size=128),
)
@settings(max_examples=300)
def test_short_prefix_gate_preserves_reference_boundaries(
    before: bytes, prefix: bytes, after: bytes
) -> None:
    """The fast gate must agree with the prior regex on arbitrary byte context."""
    reference = re.compile(rb"(?:(?<![A-Za-z0-9_-])|(?<=\\[nrtbf]))(?:npm_|hf_|xox[a-z]-)")
    for separator in (b"", b"\\n", b"\\\\t", b" ", b"_"):
        raw = before + separator + prefix + after
        assert _short_prefix_present(raw) == (reference.search(raw) is not None)


@pytest.mark.parametrize(
    ("raw", "family", "discriminator"),
    [
        (b"AIza" + b"A" * 24, "google-api-key", "AIza" + "A" * 24),
        (b"xoxz-" + b"A" * 20, "slack-token", "xoxz-" + "A" * 20),
        (b"glpat-" + b"A" * 20, "gitlab-pat", "glpat-" + "A" * 20),
        (b"BEARER " + b"A" * 20, "bearer-token", "bearer-" + "A" * 20),
        (b"npm_" + b"A" * 20, "npm-token", "npm_" + "A" * 20),
        (b"hf_" + b"A" * 20, "huggingface-token", "hf_" + "A" * 20),
    ],
)
def test_shared_secret_families_are_detected_and_never_echoed(
    raw: bytes, family: str, discriminator: str
) -> None:
    """Hygiene and adapter evidence use the same conservative token families."""
    shown, truncated = safe_discriminator(discriminator)
    assert family in _secret_families(raw)
    assert truncated
    assert shown == f"<str:len={len(discriminator)}>"


def test_azure_and_gcp_service_account_secret_shapes_are_detected() -> None:
    """Azure account keys and GCP private-key blocks follow existing secret paths."""
    azure = b"AccountKey=" + b"Ab3d" * 10
    gcp = b'{"private_key":"-----BEGIN PRIVATE KEY-----\\n' + b"A" * 12 + b'"}'

    assert "generic-credential-assignment" in _secret_families(azure)
    assert "private-key-block" in _secret_families(gcp)
    assert safe_discriminator("azure-client-secret-" + "a" * 16)[1]
    assert safe_discriminator("gcp-service-account-" + "a" * 16)[1]
    assert safe_discriminator("npm_package_metadata") == ("npm_package_metadata", False)


def _header() -> dict[str, object]:
    return {
        "created_at": "2026-10-08T00:00:00Z",
        "schema_version": "sesslint.session/v1",
        "session_id": "wave1-correctness",
    }


def _event(text: str) -> dict[str, object]:
    return {
        "actor": "user",
        "id": "event-0",
        "kind": "message",
        "parent_id": None,
        "payload": {"text": text},
        "seq": 0,
        "ts": "2026-10-08T00:00:01Z",
    }


def test_dump_session_file_uses_atomic_writer_and_lf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Canonical persistence delegates publication to atomic_write_text with LF bytes."""
    session = parse_session({"header": _header(), "events": [_event("synthetic")]})
    target = tmp_path / "nested" / "session.jsonl"
    captured: dict[str, object] = {}

    def _atomic_writer(dest: Path, text: str, *, encoding: str) -> str:
        captured.update(dest=dest, text=text, encoding=encoding)
        return hashlib.sha256(text.encode(encoding)).hexdigest()

    monkeypatch.setattr("sesslint.canonical.atomic_write_text", _atomic_writer)
    dump_session_file(session, target)

    assert captured["dest"] == target
    assert captured["encoding"] == "utf-8"
    assert isinstance(captured["text"], str)
    assert captured["text"].endswith("\n")
    assert "\r\n" not in captured["text"]


def test_jsonl_readers_treat_unicode_separators_as_json_string_content(tmp_path: Path) -> None:
    """Only physical LF may delimit JSONL records across canonical, verify, and index readers."""
    text = "left\u2028middle\u2029right\u0085end"
    canonical_bytes = (
        json.dumps(_header(), ensure_ascii=False).encode("utf-8")
        + b"\n"
        + json.dumps(_event(text), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    session_path = tmp_path / "session.jsonl"
    session_path.write_bytes(canonical_bytes)

    session = load_session_file(session_path)
    header, events = _parse_session_events(canonical_bytes)
    assert session.events[0].payload["text"] == text
    assert header is not None
    assert events[0].payload["text"] == text

    index_path = tmp_path / "session_index.jsonl"
    index_path.write_text(
        json.dumps({"id": "thread-1", "thread_name": text}, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="",
    )
    index = read_index(index_path)
    assert index.membership_complete
    assert index.entry_ids == frozenset({"thread-1"})


class _BoundedReadStream(io.BytesIO):
    """BytesIO that proves MCP never requests an unbounded input line."""

    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.requested_sizes: list[int] = []

    def readline(self, size: int = -1) -> bytes:
        self.requested_sizes.append(size)
        assert 0 <= size <= MAX_MCP_LINE_BYTES + 1
        return super().readline(size)


def test_mcp_bounds_oversized_jsonl_and_recursion_failures() -> None:
    """MCP rejects oversized/deep input without echoing or consuming unbounded lines."""
    oversized = b"{" + b"x" * (MAX_MCP_LINE_BYTES + 32) + b"\n"
    valid = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
    stdin = _BoundedReadStream(oversized + valid)
    stdout = io.BytesIO()

    assert serve(stdin, stdout) == 0
    replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32700
    assert replies[1] == {"id": 7, "jsonrpc": "2.0", "result": {}}
    assert stdin.requested_sizes
    assert handle_line(b"[" * 2_000) is not None


def test_index_and_cache_recursion_fail_closed(tmp_path: Path) -> None:
    """Deep hostile JSON is classified as unusable cache/index data, never propagated."""
    index_path = tmp_path / "session_index.jsonl"
    index_path.write_text("[" * 2_000, encoding="utf-8")
    snapshot = read_index(index_path)
    assert not snapshot.parse_ok

    cache = ScanCache(tmp_path / "cache.sqlite")
    assert cache.healthy
    assert cache._db is not None
    cache._db.execute(
        "INSERT INTO cache_v1 (path, analysis_fp, file_sha256, result) VALUES (?,?,?,?)",
        ("synthetic", "analysis", "digest", "[" * 2_000),
    )
    cache._db.commit()
    assert cache.get("synthetic", "analysis", "digest") is None
    cache.close()


@given(data=st.binary(max_size=80_000))
@settings(
    max_examples=20,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_bundle_chunk_count_matches_physical_lf_reference(tmp_path: Path, data: bytes) -> None:
    """Chunked counting is exactly equivalent to the original physical-byte rule."""
    with tempfile.TemporaryDirectory(dir=tmp_path) as directory:
        path = Path(directory) / "records.bin"
        path.write_bytes(data)
        expected = sum(bool(line.strip(b" \t\r")) for line in data.split(b"\n"))
        assert _count_records_bounded(path) == expected


def test_sarif_artifact_uri_percent_encodes_path_bytes() -> None:
    """SARIF artifact locations are URI paths, never raw filesystem strings."""
    finding = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Synthetic malformed record",
        source=SourceRef(path="folder name/#?-%-ä.jsonl", line=1, record_id=None),
        evidence={},
    )
    document = json.loads(render_sarif([finding], tool_version="test"))
    uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "folder%20name/%23%3F-%25-%C3%A4.jsonl"


def test_deterministic_python_codec_wording_and_bytes_are_stable() -> None:
    """B33 changes wording only; established codec output stays byte-identical."""
    value = {"a": "x", "n": 0.0, "z": [True, None]}
    assert canonical_json_bytes(value, newline=False) == b'{"a":"x","n":0.0,"z":[true,null]}'
    assert "RFC 8785" not in (PurePythonCanonicalCodec.canonical_json_bytes.__doc__ or "")
