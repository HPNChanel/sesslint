"""Catalog-lock tests for documented repair refusals (Phase 2).

Invariant: every detector code in codes.py resolves to exactly one of:
  (a) at least one registered repair recipe, or
  (b) a documented entry in the refusal registry with a non-empty,
      content-free rationale and a valid DEMAND citation.

This prevents future codes from becoming silent gaps where repair refuses
without explanation.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from pathlib import Path

import pytest

from sesslint.codes import ALL_CODES, SL001, SL101, SL203, SL301, SL302
from sesslint.finding import enforce_content_free_text
from sesslint.repair.planner import Blocked
from sesslint.repair.recipes_conservative import (
    register_all as register_conservative,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_salvage,
)
from sesslint.repair.recipes_sl002 import (
    register_all as register_sl002,
)
from sesslint.repair.refusals import (
    REFUSAL_CODES,
    REFUSAL_REGISTRY,
    RefusalRationale,
    refusal_rationale_for,
)
from sesslint.repair.registry import clear_registry, recipes_for

REPAIR_SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "sesslint" / "repair"

# Codes documented in the refusal registry that additionally gained a salvage
# recipe. The rationale stays registered because the refusal remains normative
# under the default conservative policy.
DOCUMENTED_BUT_COVERED: frozenset[str] = frozenset({SL101})

_CITATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(?:AC|FR|NFR|DEV|RVW)-\d{3}$"),
    re.compile(r"^Non-goal #\d+$"),
    re.compile(r"^(?:Conservative|Salvage) policy MUST refuse$"),
)


@pytest.fixture(autouse=True)
def _full_recipe_registry() -> Generator[None, None, None]:
    """Ensure the complete production recipe catalog is registered."""
    clear_registry()
    register_conservative()
    register_salvage()
    register_sl002()
    yield
    clear_registry()
    register_conservative()
    register_salvage()
    register_sl002()


def test_every_code_has_recipe_or_documented_refusal() -> None:
    """No code may be both recipe-less and rationale-less."""
    for code in sorted(ALL_CODES):
        recipes = recipes_for(code)
        entry = refusal_rationale_for(code)
        assert recipes or entry is not None, (
            f"{code} has neither a registered recipe nor a documented refusal rationale"
        )


def test_uncovered_codes_match_registry_exactly() -> None:
    """The refusal registry covers exactly the uncovered codes plus SL101."""
    uncovered = {c for c in ALL_CODES if not recipes_for(c)}
    assert uncovered == REFUSAL_CODES - DOCUMENTED_BUT_COVERED
    assert REFUSAL_CODES - uncovered == DOCUMENTED_BUT_COVERED


def test_registry_keys_are_known_codes() -> None:
    """Refusal entries may not reference unknown detector codes."""
    assert REFUSAL_CODES <= ALL_CODES
    for code in REFUSAL_CODES:
        assert code in ALL_CODES


def test_refusal_entries_are_well_formed() -> None:
    """Every entry has non-empty rationale, valid citation, and sane salvage path."""
    assert REFUSAL_REGISTRY, "refusal registry must not be empty"
    for code, entry in sorted(REFUSAL_REGISTRY.items()):
        assert isinstance(entry, RefusalRationale)
        assert entry.code == code
        assert entry.rationale.strip(), f"{code} rationale must be non-empty"
        assert entry.demand_citation.strip(), f"{code} citation must be non-empty"
        assert any(p.match(entry.demand_citation) for p in _CITATION_PATTERNS), (
            f"{code} citation {entry.demand_citation!r} is not a recognized DEMAND anchor"
        )
        if entry.salvage_path is not None:
            assert entry.salvage_path.strip(), f"{code} salvage path must be non-empty"


def test_refusal_entries_are_content_free() -> None:
    """Rationales and salvage paths must satisfy the content-free text contract."""
    for code, entry in REFUSAL_REGISTRY.items():
        enforce_content_free_text(entry.rationale, context=f"rationale {code}")
        enforce_content_free_text(entry.demand_citation, context=f"citation {code}")
        if entry.salvage_path is not None:
            enforce_content_free_text(entry.salvage_path, context=f"salvage path {code}")


def test_pinned_citations_for_key_codes() -> None:
    """Lock the normative anchors for the most sensitive refusals."""
    assert REFUSAL_REGISTRY[SL001].demand_citation == "AC-004"
    assert REFUSAL_REGISTRY[SL203].demand_citation == "FR-060"
    assert REFUSAL_REGISTRY[SL101].demand_citation == "Conservative policy MUST refuse"
    assert REFUSAL_REGISTRY[SL301].demand_citation == "FR-023"
    assert REFUSAL_REGISTRY[SL302].demand_citation == "FR-021"


def test_sl101_salvage_path_is_explicit_opt_in() -> None:
    """The SL101 entry documents the salvage-only lossy path explicitly."""
    entry = REFUSAL_REGISTRY[SL101]
    assert entry.salvage_path is not None
    assert "--policy salvage" in entry.salvage_path
    assert "--acknowledge-side-effects" in entry.salvage_path
    assert "orphan-result-drop" in entry.salvage_path


def test_blocked_describe_surfaces_rationale() -> None:
    """Blocked.describe() combines the stable reason with documented rationale."""
    b = Blocked(finding_fp="f" * 16, code=SL001, reason="no-recipe")
    detail = b.describe()
    assert detail.startswith("no-recipe: ")
    assert "malformed nonterminal data" in detail
    assert "(DEMAND: AC-004)" in detail

    b203 = Blocked(finding_fp="e" * 16, code=SL203, reason="SL203-refusal")
    detail203 = b203.describe()
    assert detail203.startswith("SL203-refusal: ")
    assert "DEMAND: FR-060" in detail203


def test_blocked_describe_falls_back_without_entry() -> None:
    """Codes with recipes but no refusal entry keep the bare machine reason."""
    b = Blocked(finding_fp="d" * 16, code="SL003", reason="precondition-failed:x")
    assert b.describe() == "precondition-failed:x"


def test_blocked_describe_includes_salvage_path() -> None:
    """SL101 blocked entries surface the explicit salvage opt-in path."""
    b = Blocked(finding_fp="c" * 16, code=SL101, reason="needs-salvage-policy")
    detail = b.describe()
    assert "needs-salvage-policy" in detail
    assert "salvage path:" in detail
    assert "orphan-result-drop" in detail
    assert "<file>" in detail  # placeholder remains when no path context exists


def test_render_substitutes_path_placeholder() -> None:
    """RefusalRationale.render() substitutes {path} in salvage path hints."""
    entry = REFUSAL_REGISTRY[SL101]
    rendered = entry.render(path="session.jsonl")
    assert "sesslint repair session.jsonl --policy salvage" in rendered
    assert "{path}" not in rendered


def test_registry_validation_rejects_bad_entries() -> None:
    """Fail-fast validation: unknown codes, empty rationale, bad citations."""
    with pytest.raises(ValueError, match="unknown code"):
        RefusalRationale(code="SL999", rationale="x", demand_citation="AC-001")
    with pytest.raises(ValueError, match="non-empty"):
        RefusalRationale(code=SL001, rationale="  ", demand_citation="AC-001")
    with pytest.raises(ValueError, match="DEMAND anchor"):
        RefusalRationale(code=SL001, rationale="x", demand_citation="some docs")
    with pytest.raises(ValueError, match="non-empty or None"):
        RefusalRationale(code=SL001, rationale="x", demand_citation="AC-001", salvage_path=" ")


def test_refusals_module_is_vendor_free() -> None:
    """refusals.py must contain no vendor-specific terminology."""
    path = REPAIR_SRC_DIR / "refusals.py"
    content = path.read_text(encoding="utf-8")
    for pattern in (
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\btoolUse\b"),
        re.compile(r"\bcall_id\b"),
    ):
        match = pattern.search(content)
        assert match is None, f"Forbidden vendor keyword '{match.group(0)}' in {path}"
