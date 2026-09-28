"""T-07: fixture navigation must describe the current synthetic inventory."""

from scripts.fixture_index import ROOT, render


def test_fixture_index_is_current() -> None:
    assert (ROOT / "fixtures/INDEX.md").read_text(encoding="utf-8") == render()
