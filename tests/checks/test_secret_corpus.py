"""T-03: exact synthetic labels for all 14 families; no real-data accuracy claim."""

import json
import re
from pathlib import Path

import pytest

from sesslint import api
from sesslint.checks import hygiene

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "fixtures/conformance/secret_seed/consolidation/corpus.json"
)
ROWS = json.loads(CORPUS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row["id"])
def test_secret_corpus_exact_labels_and_privacy(row: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = row["text"].encode()

    def scan() -> list:
        tracker = hygiene.SecretScanTracker()
        tracker.feed(raw, line_number=1, byte_offset=0, byte_end=len(raw), record_ordinal=0)
        return tracker.into_findings(path_str="synthetic.jsonl")

    actual = scan()
    assert sorted(f.evidence["secret_family"] for f in actual) == row["expected"]
    # Differential guard: literal prefilters may never suppress an exact match.
    monkeypatch.setattr(hygiene, "_FAMILY_LITERALS", {})
    monkeypatch.setattr(hygiene, "_GATE_TOKEN_TAIL", re.compile(b""))
    assert actual == scan()
    report = api.check_bytes(raw, format="canonical")  # malformed raw records still scanned
    output = json.dumps([f.to_dict() for f in report.findings])
    for canary in row["canaries"]:
        assert canary not in output
        assert canary not in repr(actual)


def test_corpus_covers_every_family_and_label_class() -> None:
    assert {r["family"] for r in ROWS} == set(hygiene.SECRET_FAMILY_IDS)
    for family in hygiene.SECRET_FAMILY_IDS:
        rows = [r for r in ROWS if r["family"] == family]
        assert {r["category"] for r in rows} == {
            "positive",
            "near-miss",
            "placeholder",
            "truncated",
            "malformed",
        }
        assert all(
            r["expected"] == [family] for r in rows if r["category"] in {"positive", "malformed"}
        )


def test_secret_at_window_boundary_and_output_caps() -> None:
    token = "ghp_" + "SYNTHETIC0123456789" * 2
    raw = b"x" * (256 * 1024 - 1) + b" " + token.encode()
    tracker = hygiene.SecretScanTracker()
    for index in range(hygiene.MAX_SECRET_FINDINGS_PER_FILE + 2):
        tracker.feed(
            raw,
            line_number=index + 1,
            byte_offset=index * len(raw),
            byte_end=(index + 1) * len(raw),
            record_ordinal=index,
        )
    findings = tracker.into_findings(path_str="synthetic.jsonl")
    assert len(findings) <= hygiene.MAX_SECRET_FINDINGS_PER_FILE
    assert any(f.evidence.get("overflow") for f in findings)
    assert token not in repr(findings)
