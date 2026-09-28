"""T-09: authoritative JSON Schema validation, development dependency only."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"


def assert_schema(document: object, filename: str) -> None:
    schema = json.loads((SCHEMAS / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(document))
    assert not errors, "Schema violation at " + ", ".join(
        "/".join(str(part) for part in error.absolute_path) or "<root>" for error in errors
    )
