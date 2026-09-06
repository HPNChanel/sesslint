"""Tests for RepairManifest envelope, idempotency key binding, and
never-synthetic-success (TASK-004).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sesslint.errors import (
    ContentLeakError,
    SchemaError,
    UnknownFieldError,
    VersionError,
)
from sesslint.report import (
    KNOWN_MANIFEST_FIELDS,
    REQUIRED_MANIFEST_FIELDS,
    VALID_POLICIES,
    RepairAction,
    RepairManifest,
    build_manifest,
    compute_manifest_idempotency_key,
    dump_manifest,
    enforce_content_free,
    get_manifest_schema_path,
    load_manifest_schema,
    parse_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_FIXTURE_PATH = REPO_ROOT / "fixtures" / "manifests" / "conservative-empty.json"


def test_conservative_empty_fixture_roundtrip() -> None:
    """Verify fixtures/manifests/conservative-empty.json parses and round-trips byte-stably."""
    assert MANIFEST_FIXTURE_PATH.is_file(), f"Fixture missing at {MANIFEST_FIXTURE_PATH}"
    fixture_text = MANIFEST_FIXTURE_PATH.read_text(encoding="utf-8")
    manifest = parse_manifest(fixture_text)

    assert manifest.schema_version == "sesslint.repair-manifest/v1"
    assert manifest.input_fingerprint == "input-hash-abc123"
    assert manifest.output_fingerprint == "output-hash-def456"
    assert manifest.policy == "conservative"
    assert manifest.actions == ()
    assert manifest.declared_loss == ()
    assert manifest.revalidate_report is None
    assert len(manifest.idempotency_key) == 64
    assert manifest.idempotency_key == compute_manifest_idempotency_key(
        input_fingerprint=manifest.input_fingerprint,
        policy=manifest.policy,
        actions=manifest.actions,
    )

    # Byte stability across dump -> parse -> dump
    dumped = dump_manifest(manifest)
    reparsed = parse_manifest(dumped)
    redumped = dump_manifest(reparsed)
    assert dumped == redumped


def test_manifest_idempotency_key_stability() -> None:
    """Verify idempotency key is 64-char hex, deterministic, and sensitive to inputs."""
    act1 = RepairAction(kind="reorder", record_id="evt-1", detail="reorder call before result")
    act2 = RepairAction(kind="neutralize", record_id="evt-2", detail="convert to inert note")

    m1 = build_manifest(
        input_fingerprint="in-fp-1",
        output_fingerprint="out-fp-1",
        policy="conservative",
        actions=[act1, act2],
    )
    m2 = build_manifest(
        input_fingerprint="in-fp-1",
        output_fingerprint="out-fp-1",
        policy="conservative",
        actions=[act1, act2],
    )

    assert len(m1.idempotency_key) == 64
    assert m1.idempotency_key == m2.idempotency_key

    # Different policy yields different key
    m_salvage = build_manifest(
        input_fingerprint="in-fp-1",
        output_fingerprint="out-fp-1",
        policy="salvage",
        actions=[act1, act2],
    )
    assert m_salvage.idempotency_key != m1.idempotency_key

    # Different input fingerprint yields different key
    m_diff_in = build_manifest(
        input_fingerprint="in-fp-DIFFERENT",
        output_fingerprint="out-fp-1",
        policy="conservative",
        actions=[act1, act2],
    )
    assert m_diff_in.idempotency_key != m1.idempotency_key

    # Different actions yield different key
    m_diff_act = build_manifest(
        input_fingerprint="in-fp-1",
        output_fingerprint="out-fp-1",
        policy="conservative",
        actions=[act1],
    )
    assert m_diff_act.idempotency_key != m1.idempotency_key


def test_action_order_insensitivity_idempotency_key() -> None:
    """Two manifests differing only in action order produce identical key and sorted actions."""
    act_a = RepairAction(kind="delete", record_id="evt-a", detail="delete orphan")
    act_b = RepairAction(kind="reparent", record_id="evt-b", detail="reparent orphan to root")
    act_c = RepairAction(kind="rewrite", record_id="evt-c", detail="rewrite payload coordinate")

    m_order1 = build_manifest(
        input_fingerprint="in-123",
        output_fingerprint="out-123",
        policy="conservative",
        actions=[act_c, act_a, act_b],
    )
    m_order2 = build_manifest(
        input_fingerprint="in-123",
        output_fingerprint="out-123",
        policy="conservative",
        actions=[act_a, act_b, act_c],
    )

    assert m_order1.idempotency_key == m_order2.idempotency_key
    assert m_order1.actions == m_order2.actions
    assert dump_manifest(m_order1) == dump_manifest(m_order2)


def test_never_synthetic_success_contract() -> None:
    """Verify manifest schema and type have no 'success' or 'passed' boolean fields."""
    # 1. Type level assertion
    assert not hasattr(RepairManifest, "success"), "RepairManifest must not have 'success' field"
    assert not hasattr(RepairManifest, "passed"), "RepairManifest must not have 'passed' field"
    assert not hasattr(RepairManifest, "ok"), "RepairManifest must not have 'ok' field"

    # 2. Schema level assertion
    schema = load_manifest_schema()
    props = schema["properties"]
    assert "success" not in props, "Schema must not define 'success' property"
    assert "passed" not in props, "Schema must not define 'passed' property"
    assert "ok" not in props, "Schema must not define 'ok' property"
    assert schema["additionalProperties"] is False

    # 3. Parser level assertion: explicitly rejects synthetic success
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
    )
    for forbidden_field in ("success", "passed", "ok", "healthy"):
        d = m.to_dict()
        d[forbidden_field] = True
        with pytest.raises(SchemaError, match="never-synthetic-success invariant"):
            parse_manifest(d)


def test_manifest_schema_anti_drift() -> None:
    """Verify committed JSON Schema matches RepairManifest model properties and enums."""
    assert get_manifest_schema_path().is_file()
    schema = load_manifest_schema()
    assert schema["$id"] == "https://sesslint.dev/schemas/sesslint.repair-manifest/v1"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False

    assert set(schema["required"]) == REQUIRED_MANIFEST_FIELDS
    assert set(schema["properties"].keys()) == KNOWN_MANIFEST_FIELDS

    policy_enum = set(schema["properties"]["policy"]["enum"])
    assert policy_enum == VALID_POLICIES

    assert schema["properties"]["idempotency_key"]["pattern"] == "^[0-9a-f]{64}$"


def test_parse_manifest_unknown_field_raises_sl302() -> None:
    """Verify unknown top-level field in manifest raises UnknownFieldError (SL302)."""
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
    )
    d = m.to_dict()
    d["unrecognized_field"] = "payload"

    with pytest.raises(UnknownFieldError) as exc:
        parse_manifest(d)
    assert exc.value.reason_code == "SL302"
    assert "unrecognized_field" in str(exc.value)


def test_parse_manifest_unsupported_version_raises_sl301() -> None:
    """Verify unsupported manifest schema version raises VersionError (SL301)."""
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
    )
    d = m.to_dict()
    d["schema_version"] = "sesslint.repair-manifest/v99"

    with pytest.raises(VersionError) as exc:
        parse_manifest(d)
    assert exc.value.reason_code == "SL301"


def test_declared_loss_accounting() -> None:
    """Verify declared loss items are stored, validated, and normalized."""
    losses = ["dropped_orphan:evt-10", "neutralized_call:call-20"]
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="salvage",
        declared_loss=losses,
    )
    assert m.declared_loss == tuple(losses)

    # Empty loss item raises SchemaError
    with pytest.raises(SchemaError, match="declared_loss\\[0\\] must be a non-empty string"):
        build_manifest(
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="salvage",
            declared_loss=[""],
        )


def test_revalidate_report_path_handling() -> None:
    """Verify revalidate_report accepts normalized file path string and rejects invalid types."""
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
        revalidate_report="reports\\post_repair.json",
    )
    assert m.revalidate_report == "reports/post_repair.json"

    # Empty string raises
    with pytest.raises(SchemaError, match="revalidate_report must be a non-empty string path"):
        build_manifest(
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            revalidate_report="",
        )


def test_enforce_content_free_manifest_catches_smuggled_payload() -> None:
    """Verify action detail smuggling forbidden payload text raises ContentLeakError."""
    act_leaky = RepairAction(
        kind="rewrite",
        record_id="evt-1",
        detail="Updated payment for Filament invoice 1234",
    )
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
        actions=[act_leaky],
    )

    with pytest.raises(ContentLeakError, match="Forbidden payload text 'Filament invoice 1234'"):
        enforce_content_free(m, forbidden_substrings=["Filament invoice 1234"])


def test_repair_action_total_order() -> None:
    """Verify RepairAction implements deterministic total ordering."""
    a1 = RepairAction(kind="delete", record_id="evt-1", detail="detail a")
    a2 = RepairAction(kind="delete", record_id="evt-2", detail="detail b")
    a3 = RepairAction(kind="insert", record_id="evt-1", detail="detail c")
    a_none = RepairAction(kind="delete", record_id=None, detail="detail 0")

    assert a_none < a1
    assert a1 < a2
    assert a2 < a3
    assert a3 > a2
    assert a1 <= a1
    assert a1 >= a1


def test_invalid_policy_raises() -> None:
    """Verify policy outside conservative or salvage raises SchemaError."""
    for bad_pol in ("aggressive", "automatic", "force", ""):
        with pytest.raises(SchemaError, match="policy must be one of"):
            build_manifest(
                input_fingerprint="in-1",
                output_fingerprint="out-1",
                policy=bad_pol,  # type: ignore[arg-type]
            )


def test_manifest_schema_loader_file_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify load_manifest_schema raises FileNotFoundError when schema file is missing."""
    monkeypatch.setattr(
        "sesslint.report.get_manifest_schema_path",
        lambda: Path("/nonexistent/sesslint.repair-manifest.v1.json"),
    )
    with pytest.raises(FileNotFoundError):
        load_manifest_schema()


def test_repair_action_validation_errors() -> None:
    """Verify RepairAction constructor validates fields strictly."""
    with pytest.raises(SchemaError, match="RepairAction.kind must be a non-empty string"):
        RepairAction(kind="")

    with pytest.raises(
        SchemaError, match="RepairAction.record_id must be non-empty string or None"
    ):
        RepairAction(kind="delete", record_id="")

    with pytest.raises(SchemaError, match="RepairAction.detail must be a string"):
        RepairAction(kind="delete", detail=123)  # type: ignore[arg-type]


def test_repair_action_comparison_edge_cases() -> None:
    """Verify RepairAction comparisons with non-RepairAction return NotImplemented."""
    a = RepairAction(kind="delete", record_id="evt-1", detail="d1")
    assert a.__lt__("other") is NotImplemented
    assert a.__le__("other") is NotImplemented
    assert a.__gt__("other") is NotImplemented
    assert a.__ge__("other") is NotImplemented
    with pytest.raises(TypeError):
        _ = a < "other"


def test_repair_manifest_model_validation_errors() -> None:
    """Verify RepairManifest constructor rejects invalid inputs and bad types."""
    valid_key = "0" * 64

    with pytest.raises(VersionError, match="RepairManifest.schema_version must be"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v2",  # type: ignore[arg-type]
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(
        SchemaError, match="RepairManifest.input_fingerprint must be a non-empty string"
    ):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(
        SchemaError, match="RepairManifest.output_fingerprint must be a non-empty string"
    ):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="",
            policy="conservative",
            actions=(),
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(SchemaError, match="RepairManifest.policy must be one of"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="INVALID",  # type: ignore[arg-type]
            actions=(),
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(SchemaError, match="RepairManifest.actions must be a tuple"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=[],  # type: ignore[arg-type]
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(SchemaError, match="RepairManifest.actions\\[0\\] must be a RepairAction"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=("not-action",),  # type: ignore[arg-type]
            declared_loss=(),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(SchemaError, match="RepairManifest.declared_loss must be a tuple"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=[],  # type: ignore[arg-type]
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(
        SchemaError, match="RepairManifest.declared_loss\\[0\\] must be a non-empty string"
    ):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=("",),
            revalidate_report=None,
            idempotency_key=valid_key,
        )

    with pytest.raises(
        SchemaError, match="RepairManifest.revalidate_report must be a non-empty string path"
    ):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=(),
            revalidate_report="",
            idempotency_key=valid_key,
        )

    with pytest.raises(SchemaError, match="RepairManifest.idempotency_key must be a 64-character"):
        RepairManifest(
            schema_version="sesslint.repair-manifest/v1",
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            actions=(),
            declared_loss=(),
            revalidate_report=None,
            idempotency_key="too-short",
        )


def test_build_manifest_argument_validation() -> None:
    """Verify build_manifest rejects invalid fingerprints."""
    with pytest.raises(SchemaError, match="input_fingerprint must be a non-empty string"):
        build_manifest(input_fingerprint="", output_fingerprint="out-1", policy="conservative")

    with pytest.raises(SchemaError, match="output_fingerprint must be a non-empty string"):
        build_manifest(input_fingerprint="in-1", output_fingerprint="", policy="conservative")


def test_dump_manifest_type_error() -> None:
    """Verify dump_manifest raises TypeError when passed a non-RepairManifest object."""
    with pytest.raises(TypeError, match="Expected RepairManifest instance"):
        dump_manifest({"not": "a manifest"})  # type: ignore[arg-type]


def test_parse_manifest_error_cases() -> None:
    """Verify parse_manifest error paths for malformed inputs."""
    with pytest.raises(SchemaError, match="Malformed JSON in manifest"):
        parse_manifest("not valid json {")

    with pytest.raises(SchemaError, match="Manifest must be a Mapping or JSON string"):
        parse_manifest(456)  # type: ignore[arg-type]

    with pytest.raises(SchemaError, match="Manifest root must be a mapping"):
        parse_manifest("[]")

    m = build_manifest(input_fingerprint="in-1", output_fingerprint="out-1", policy="conservative")

    # Missing required field
    d = m.to_dict()
    del d["input_fingerprint"]
    with pytest.raises(
        SchemaError, match="Missing required field in manifest: 'input_fingerprint'"
    ):
        parse_manifest(d)

    # Invalid policy in mapping
    d2 = m.to_dict()
    d2["policy"] = "unsupported-policy"
    with pytest.raises(SchemaError, match="Invalid manifest policy"):
        parse_manifest(d2)

    # Actions not list
    d3 = m.to_dict()
    d3["actions"] = "not-a-list"
    with pytest.raises(SchemaError, match="actions must be a list or tuple"):
        parse_manifest(d3)

    # Action item not mapping
    d4 = m.to_dict()
    d4["actions"] = ["not-a-dict"]
    with pytest.raises(SchemaError, match="actions\\[0\\] must be a mapping"):
        parse_manifest(d4)

    # Action item missing 'kind'
    d5 = m.to_dict()
    d5["actions"] = [{"record_id": "evt-1"}]
    with pytest.raises(SchemaError, match="actions\\[0\\] missing required field 'kind'"):
        parse_manifest(d5)

    # Action item unknown field
    d6 = m.to_dict()
    d6["actions"] = [{"kind": "delete", "rogue_action_key": True}]
    with pytest.raises(
        UnknownFieldError, match="Unknown field in action\\[0\\]: 'rogue_action_key'"
    ):
        parse_manifest(d6)

    # Declared loss not list
    d7 = m.to_dict()
    d7["declared_loss"] = "not-a-list"
    with pytest.raises(SchemaError, match="declared_loss must be a list or tuple"):
        parse_manifest(d7)


def test_enforce_content_free_manifest_all_locations() -> None:
    """Verify enforce_content_free checks revalidate_report, declared_loss, kind, and record_id."""
    act = RepairAction(kind="neutralize_secret_token", record_id="user_payroll_id", detail="clean")
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
        actions=[act],
        declared_loss=["dropped_ssn_record"],
        revalidate_report="reports/confidential_audit.json",
    )

    # Leak in kind
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'neutralize_secret_token'"):
        enforce_content_free(m, forbidden_substrings=["neutralize_secret_token"])

    # Leak in record_id
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'user_payroll_id'"):
        enforce_content_free(m, forbidden_substrings=["user_payroll_id"])

    # Leak in declared_loss
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'dropped_ssn_record'"):
        enforce_content_free(m, forbidden_substrings=["dropped_ssn_record"])

    # Leak in revalidate_report
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'confidential_audit'"):
        enforce_content_free(m, forbidden_substrings=["confidential_audit"])


def test_get_manifest_schema_path_prefix_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify get_manifest_schema_path resolves via sys.prefix when dev_path does not exist."""
    fake_share = tmp_path / "share" / "sesslint" / "schemas"
    fake_share.mkdir(parents=True, exist_ok=True)
    fake_schema = fake_share / "sesslint.repair-manifest.v1.json"
    fake_schema.write_text("{}", encoding="utf-8")

    monkeypatch.setattr("sys.prefix", str(tmp_path))
    monkeypatch.setattr(
        "sesslint.report.Path.is_file",
        lambda self: str(self) == str(fake_schema),
    )

    resolved = get_manifest_schema_path()
    assert resolved == fake_schema


def test_repair_action_whitespace_normalization() -> None:
    """Verify RepairAction strips leading and trailing whitespace from strings."""
    act = RepairAction(
        kind="  reorder  ", record_id="  evt-whitespace  ", detail="  cleaned detail  "
    )
    assert act.kind == "reorder"
    assert act.record_id == "evt-whitespace"
    assert act.detail == "cleaned detail"


def test_parse_manifest_with_actions_roundtrip() -> None:
    """Verify parse_manifest parses list of actions with and without record_id."""
    act1 = RepairAction(kind="delete", record_id="evt-1", detail="delete orphan")
    act2 = RepairAction(kind="neutralize", record_id=None, detail="neutralize session state")
    m = build_manifest(
        input_fingerprint="in-actions",
        output_fingerprint="out-actions",
        policy="conservative",
        actions=[act1, act2],
    )
    d = m.to_dict()
    reparsed = parse_manifest(d)
    assert reparsed == m


def test_enforce_content_free_manifest_fingerprints_leaks() -> None:
    """Verify enforce_content_free catches payload leaks in input/output fingerprints."""
    m_in_leak = build_manifest(
        input_fingerprint="leak_invoice_999",
        output_fingerprint="out-hash",
        policy="conservative",
    )
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'leak_invoice_999'"):
        enforce_content_free(m_in_leak, forbidden_substrings=["leak_invoice_999"])

    m_out_leak = build_manifest(
        input_fingerprint="in-hash",
        output_fingerprint="out-secret_token",
        policy="conservative",
    )
    with pytest.raises(ContentLeakError, match="Forbidden payload text 'secret_token'"):
        enforce_content_free(m_out_leak, forbidden_substrings=["secret_token"])


def test_parse_manifest_strict_field_type_validation() -> None:
    """Verify parse_manifest rejects non-string types for all string fields."""
    m = build_manifest(
        input_fingerprint="in-1",
        output_fingerprint="out-1",
        policy="conservative",
    )

    d_bad_in = m.to_dict()
    d_bad_in["input_fingerprint"] = 12345
    with pytest.raises(
        SchemaError, match="RepairManifest.input_fingerprint must be a non-empty string"
    ):
        parse_manifest(d_bad_in)

    d_bad_out = m.to_dict()
    d_bad_out["output_fingerprint"] = True
    with pytest.raises(
        SchemaError, match="RepairManifest.output_fingerprint must be a non-empty string"
    ):
        parse_manifest(d_bad_out)

    d_bad_key = m.to_dict()
    d_bad_key["idempotency_key"] = 12345
    with pytest.raises(SchemaError, match="RepairManifest.idempotency_key must be a 64-character"):
        parse_manifest(d_bad_key)

    d_bad_reval = m.to_dict()
    d_bad_reval["revalidate_report"] = 12345
    with pytest.raises(
        SchemaError, match="RepairManifest.revalidate_report must be a non-empty string path"
    ):
        parse_manifest(d_bad_reval)

    d_bad_loss = m.to_dict()
    d_bad_loss["declared_loss"] = [123]
    with pytest.raises(SchemaError, match="declared_loss\\[0\\] must be a non-empty string"):
        parse_manifest(d_bad_loss)

    d_bad_act_kind = m.to_dict()
    d_bad_act_kind["actions"] = [{"kind": 123}]
    with pytest.raises(SchemaError, match="actions\\[0\\].kind must be a non-empty string"):
        parse_manifest(d_bad_act_kind)

    d_bad_act_rec = m.to_dict()
    d_bad_act_rec["actions"] = [{"kind": "delete", "record_id": 123}]
    with pytest.raises(
        SchemaError, match="actions\\[0\\].record_id must be non-empty string or None"
    ):
        parse_manifest(d_bad_act_rec)

    d_bad_act_det = m.to_dict()
    d_bad_act_det["actions"] = [{"kind": "delete", "detail": 123}]
    with pytest.raises(SchemaError, match="actions\\[0\\].detail must be a string"):
        parse_manifest(d_bad_act_det)


def test_parse_manifest_sorts_actions_into_canonical_order() -> None:
    """Verify parse_manifest sorts actions canonically if input was unsorted."""
    m_dict = {
        "schema_version": "sesslint.repair-manifest/v1",
        "input_fingerprint": "in-1",
        "output_fingerprint": "out-1",
        "policy": "conservative",
        "actions": [
            {"kind": "rewrite", "record_id": "evt-2", "detail": "second"},
            {"kind": "delete", "record_id": "evt-1", "detail": "first"},
        ],
        "declared_loss": [],
        "revalidate_report": None,
        "idempotency_key": "0" * 64,
    }
    m = parse_manifest(m_dict)
    assert [a.kind for a in m.actions] == ["delete", "rewrite"]


def test_compute_manifest_idempotency_key_validations() -> None:
    """Verify compute_manifest_idempotency_key validates input_fingerprint and policy."""
    with pytest.raises(SchemaError, match="input_fingerprint must be a non-empty string"):
        compute_manifest_idempotency_key(input_fingerprint="", policy="conservative", actions=[])

    with pytest.raises(SchemaError, match="policy must be one of"):
        compute_manifest_idempotency_key(input_fingerprint="fp-1", policy="INVALID", actions=[])


def test_repair_action_content_leak_raises_content_leak_error() -> None:
    """Verify RepairAction raises ContentLeakError when sensitive credentials or newlines leak."""
    with pytest.raises(ContentLeakError, match="Intrinsic content leak in RepairAction.kind"):
        RepairAction(kind="action\nwith_newline")

    with pytest.raises(ContentLeakError, match="Intrinsic content leak in RepairAction.record_id"):
        RepairAction(kind="delete", record_id="user@company.com")

    with pytest.raises(ContentLeakError, match="Intrinsic content leak in RepairAction.detail"):
        RepairAction(kind="delete", detail="Bearer 12345678901234567890")


def test_build_manifest_content_leaks_in_declared_loss_and_revalidate_report() -> None:
    """Verify build_manifest rejects credential or control char leaks in loss and revalidate."""
    with pytest.raises(ContentLeakError, match="Content leak in declared_loss"):
        build_manifest(
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="salvage",
            declared_loss=["dropped: user@company.com"],
        )

    with pytest.raises(ContentLeakError, match="Content leak in revalidate_report"):
        build_manifest(
            input_fingerprint="in-1",
            output_fingerprint="out-1",
            policy="conservative",
            revalidate_report="reports/user@company.com/report.json",
        )


def test_parse_manifest_normalizes_paths_and_loss() -> None:
    """Verify parse_manifest normalizes Windows backslashes in revalidate_report and stores loss."""
    m_dict = {
        "schema_version": "sesslint.repair-manifest/v1",
        "input_fingerprint": "in-1",
        "output_fingerprint": "out-1",
        "policy": "salvage",
        "actions": [{"kind": "neutralize", "record_id": "rec-1", "detail": "clean"}],
        "declared_loss": ["omitted_orphan:rec-1"],
        "revalidate_report": "reports\\validation_v1.json",
        "idempotency_key": "0" * 64,
    }
    m = parse_manifest(m_dict)
    assert m.revalidate_report == "reports/validation_v1.json"
    assert m.declared_loss == ("omitted_orphan:rec-1",)
