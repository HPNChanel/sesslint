"""T-08: actionable SL009/SL402 guidance survives every output surface."""

from pathlib import Path

import pytest

from sesslint.cli import main


@pytest.mark.parametrize("fmt", ["human", "json", "sarif", "html"])
@pytest.mark.parametrize("code", ["SL009", "SL402"])
def test_guidance_on_actual_findings(code: str, fmt: str, capsys) -> None:
    import json

    golden = json.loads(
        Path(f"fixtures/conformance/detectors/{code.lower()}.expected.json").read_text(
            encoding="utf-8"
        )
    )
    command = "scan" if code == "SL402" else "check"
    main([command, str(Path("fixtures") / golden["input"]), "--output-format", fmt])
    output = capsys.readouterr().out
    assert code in output
    if fmt == "sarif":
        assert f"docs/codes/{code}.md" in output
    elif code == "SL009":
        assert "rotat" in output.lower()
    else:
        assert "explicit" in output.lower() or "manual" in output.lower()
