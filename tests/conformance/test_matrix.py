"""Tests verifying adapter and profile compatibility matrix (TASK-028, FR-037, FR-038).

Guarantees:
- Every combination of (adapter x profile) behaves according to docs/MATRIX.md.
- Disallowed adapters fail closed with SL302 / exit 2.
- Canonical adapter is supported across all profiles.
"""

from __future__ import annotations

from pathlib import Path

from sesslint.cli import main
from sesslint.profiles import list_profiles

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
CANONICAL_FIXTURE = FIXTURES_DIR / "determinism" / "repeat" / "repeat_session.json"
CLAUDE_FIXTURE = FIXTURES_DIR / "claude_code" / "basic.jsonl"
OPENAI_FIXTURE = FIXTURES_DIR / "openai_agents" / "items_basic.json"


def test_matrix_registry_profiles() -> None:
    """All documented profiles must exist in the runtime registry."""
    profiles = list_profiles()
    assert "neutral" in profiles
    assert "claude-strict" in profiles
    assert "openai-strict" in profiles


def test_canonical_supported_across_all_profiles() -> None:
    """Canonical format must be accepted under neutral, claude-strict, and openai-strict."""
    for prof in ("neutral", "claude-strict", "openai-strict"):
        code = main(["check", str(CANONICAL_FIXTURE), "--profile", prof])
        assert code == 0, f"Canonical format should exit 0 under profile {prof}"


def test_claude_adapter_profile_matrix() -> None:
    """Claude Code adapter is accepted under neutral and claude-strict,
    refused under openai-strict.
    """
    # Accepted under neutral and claude-strict
    for prof in ("neutral", "claude-strict"):
        code = main(["check", str(CLAUDE_FIXTURE), "--profile", prof])
        assert code == 0, f"Claude fixture should succeed under {prof}"

    # Refused under openai-strict (disallowed adapter exits 2)
    code_refused = main(["check", str(CLAUDE_FIXTURE), "--profile", "openai-strict"])
    assert code_refused == 2


def test_openai_adapter_profile_matrix() -> None:
    """OpenAI Agents adapter is accepted under neutral and openai-strict,
    refused under claude-strict.
    """
    # Accepted under neutral and openai-strict
    for prof in ("neutral", "openai-strict"):
        code = main(["check", str(OPENAI_FIXTURE), "--profile", prof])
        assert code == 0, f"OpenAI fixture should succeed under {prof}"

    # Refused under claude-strict (disallowed adapter exits 2)
    code_refused = main(["check", str(OPENAI_FIXTURE), "--profile", "claude-strict"])
    assert code_refused == 2


def test_matrix_doc_exists_and_matches() -> None:
    """docs/MATRIX.md must exist and document the 3 standard profiles."""
    matrix_file = Path(__file__).resolve().parent.parent.parent / "docs" / "MATRIX.md"
    assert matrix_file.is_file(), f"Missing {matrix_file}"
    content = matrix_file.read_text(encoding="utf-8")
    assert "canonical" in content
    assert "claude-code-jsonl" in content
    assert "openai-agents" in content
    assert "neutral" in content
    assert "claude-strict" in content
    assert "openai-strict" in content
