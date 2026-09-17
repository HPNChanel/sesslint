"""Tests guarding docs against numeric drift from code constants (DW-T-03).

Invariants verified:
1. docs/ADAPTER_GUIDE.md states the same detection constants as
   src/sesslint/adapters/detect.py (CONFIDENCE_MIN, MARGIN_MIN, SNIFF_BYTES).
2. No stale threshold values (e.g. the historical 0.60 drift) reappear in the
   adapter authoring guide.
"""

from __future__ import annotations

from pathlib import Path

from sesslint.adapters.detect import CONFIDENCE_MIN, MARGIN_MIN, SNIFF_BYTES

REPO_ROOT = Path(__file__).resolve().parent.parent
GUIDE = REPO_ROOT / "docs" / "ADAPTER_GUIDE.md"


def _guide_text() -> str:
    assert GUIDE.is_file(), f"Adapter guide missing: {GUIDE}"
    return GUIDE.read_text(encoding="utf-8")


def test_adapter_guide_confidence_min_matches_code() -> None:
    """The guide must cite the same CONFIDENCE_MIN value as detect.py."""
    text = _guide_text()
    assert f"`{CONFIDENCE_MIN}`" in text, (
        f"ADAPTER_GUIDE.md must state CONFIDENCE_MIN as `{CONFIDENCE_MIN}` "
        f"(see src/sesslint/adapters/detect.py)"
    )


def test_adapter_guide_margin_min_matches_code() -> None:
    """The guide must cite the same MARGIN_MIN value as detect.py."""
    text = _guide_text()
    assert f"`{MARGIN_MIN}`" in text, (
        f"ADAPTER_GUIDE.md must state MARGIN_MIN as `{MARGIN_MIN}` "
        f"(see src/sesslint/adapters/detect.py)"
    )


def test_adapter_guide_sniff_bytes_matches_code() -> None:
    """The guide must cite the same SNIFF_BYTES value as detect.py."""
    text = _guide_text()
    assert f"SNIFF_BYTES = {SNIFF_BYTES}" in text, (
        f"ADAPTER_GUIDE.md must state SNIFF_BYTES = {SNIFF_BYTES} "
        f"(see src/sesslint/adapters/detect.py)"
    )


def test_adapter_guide_no_stale_threshold_values() -> None:
    """Known-stale detection values must not reappear as stated constants."""
    text = _guide_text()
    assert "`0.60`" not in text, (
        "ADAPTER_GUIDE.md reintroduced the stale CONFIDENCE_MIN=0.60 value; "
        f"the code constant is {CONFIDENCE_MIN}"
    )
    assert "SNIFF_BYTES = 4096" not in text, (
        f"ADAPTER_GUIDE.md reintroduced the stale SNIFF_BYTES=4096 value; "
        f"the code constant is {SNIFF_BYTES}"
    )
