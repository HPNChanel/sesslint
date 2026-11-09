//! Dispositions for the 10 `def test_` functions in pinned
//! `tests/outcome/test_outcome_contract.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (194 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `outcome/vectors.json` whose call is the same
//! function and the same success or failure mode as that entire pinned test.
//! A `verify_outcome` cartesian cell is not the whole test. Expected needles
//! come from the pin. JSON is scanned with substring finds; this file does not
//! call `serde_json::from_str`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 10;
const OUTCOME_VECTOR_COUNT: usize = 4818;
const CONTRACT_ERROR_COUNT: usize = 3;
const VECTORS_REL: &str = "parity/vectors/outcome/vectors.json";
const MANIFEST_REL: &str = "parity/vectors/outcome/manifest.json";
const COVERAGE_REL: &str = "parity/vectors/outcome/coverage.json";
const PROVENANCE_REL: &str = "parity/vectors/outcome/PROVENANCE.json";
const FIXTURE_PROVENANCE_REL: &str = "parity/vectors/outcome/fixtures/PROVENANCE.json";

/// Pinned `contract_from_dict` / `load_contract` / `explain_contract` needles.
/// They are absent from the verify sweep, so no cell is that whole test.
const PIN_NEEDLES_ABSENT_FROM_VECTORS: &[&str] = &[
    "shipment-exists",
    "order_id",
    "non-empty list",
    "unknown key 'surprise'",
    "unknown key 'fieldd'",
    "'type' must be one of",
    "'op' must be one of",
    "observation basis takes no 'field'",
    "never be violated",
    "cannot prove",
    "must not exceed",
    "needs 'min', 'max'",
    "unsupported normalize",
    "no decisive condition",
    "every condition is disabled",
    "same number of fields",
    "cannot nest",
    "advisory or disabled",
    "no active exists/count",
    "1 MiB",
    "[advisory",
    "sesslint.outcome-contract.v1.json",
    "NaN",
    "within_seconds",
    "key.source",
];

/// `covered` names a vector id in `outcome/vectors.json`.
/// `not_applicable` records a contract, schema, or explain assertion no single
/// verify vector reproduces in full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
    Covered {
        vector_id: &'static str,
        needles: &'static [&'static str],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    Row {
        name: "test_fixture_contract_loads_and_matches_schema",
        disposition: Disposition::NotApplicable(
            "load_contract of ORDERS/contract.json succeeds with source_key (\"order_id\",), condition id shipment-exists, warnings (), and assert_schema sesslint.outcome-contract.v1.json; a cartesian verify_outcome cell on fixtures/contract.json is not that load plus schema check",
        ),
    },
    Row {
        name: "test_empty_contract_is_an_error_not_a_pass",
        disposition: Disposition::NotApplicable(
            "contract_from_dict of conditions=[] raises ContractError containing \"non-empty list\" (AT-40); the ContractError rows are cartesian verify_outcome cells on invalid.json, not that empty-conditions failure",
        ),
    },
    Row {
        name: "test_invalid_contracts_are_rejected",
        disposition: Disposition::NotApplicable(
            "nineteen contract_from_dict failures: unknown key surprise, schema_version v0, type magic, fieldd, eligibility op like, on_time without due, observation field, count min 0, count max 0, min above max, range without min/max, empty one_of values, normalize stem, route without when, duplicate id, advisory-only, disabled later, unequal key arity, empty key.source, negative within_seconds; one cartesian verify_outcome cell is not that whole parametrization",
        ),
    },
    Row {
        name: "test_any_of_cannot_nest_or_hide_flags",
        disposition: Disposition::NotApplicable(
            "two contract_from_dict failures contain \"cannot nest\" and \"advisory or disabled\"; a cartesian verify_outcome cell does not build a nested any_of and is not both failures",
        ),
    },
    Row {
        name: "test_every_problem_is_reported_at_once",
        disposition: Disposition::NotApplicable(
            "contract_from_dict of name null, empty version, extra true, and a condition missing id reports at least three problems; a cartesian invalid.json ContractError is a different failure mode",
        ),
    },
    Row {
        name: "test_load_rejects_non_strict_json",
        disposition: Disposition::NotApplicable(
            "load_contract raises ContractError for a duplicate schema_version key, NaN, a bare array, and a double-BOM object; the invalid.json cartesian cells are the single character {, not those four texts",
        ),
    },
    Row {
        name: "test_load_rejects_oversized_and_non_utf8",
        disposition: Disposition::NotApplicable(
            "load_contract of 1024*1024+1 spaces matches \"1 MiB\" and latin-1 {\"name\": \"\\xe9\"} matches \"UTF-8\"; the invalid.json message is a truncated-object JSONDecodeError, a different failure mode, and one cartesian slice rather than both assertions",
        ),
    },
    Row {
        name: "test_fingerprint_ignores_key_order_but_not_values",
        disposition: Disposition::NotApplicable(
            "three contract_from_dict successes: the default dict and its key-reversed form share sha256, and version \"2\" does not; no cartesian verify cell compares those three fingerprints",
        ),
    },
    Row {
        name: "test_warnings_flag_gaps_without_failing",
        disposition: Disposition::NotApplicable(
            "contract_from_dict of a required status field succeeds with both \"no active exists/count\" and \"no due window\"; fixture verify warnings are \"no due window declared: absence is judged at the evaluation instant\" on an exists condition, a different contract inside a cartesian cell",
        ),
    },
    Row {
        name: "test_explain_is_deterministic_and_lists_every_condition",
        disposition: Disposition::NotApplicable(
            "explain_contract of ORDERS/contract.json is byte-identical across two loads, lists every \"- {id}:\", and contains \"[advisory\" and \"INCONCLUSIVE\"; render_human on one cartesian verify cell is not explain_contract of that orders contract",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fixture_contract_loads_and_matches_schema",
    "test_empty_contract_is_an_error_not_a_pass",
    "test_invalid_contracts_are_rejected",
    "test_any_of_cannot_nest_or_hide_flags",
    "test_every_problem_is_reported_at_once",
    "test_load_rejects_non_strict_json",
    "test_load_rejects_oversized_and_non_utf8",
    "test_fingerprint_ignores_key_order_but_not_values",
    "test_warnings_flag_gaps_without_failing",
    "test_explain_is_deterministic_and_lists_every_condition",
];

struct VerifyCase<'a> {
    id: u32,
    family: &'a str,
    contract: &'a str,
    error_kind: Option<&'a str>,
    error_message: Option<&'a str>,
}

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_text(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn json_string_field<'a>(line: &'a str, key: &str) -> &'a str {
    let marker = format!("\"{key}\":\"");
    let pos = line
        .find(&marker)
        .unwrap_or_else(|| panic!("case is missing {key}"));
    let tail = &line[pos + marker.len()..];
    let end = tail
        .find('"')
        .unwrap_or_else(|| panic!("{key} value is not a JSON string"));
    assert!(
        !tail[end + 1..].contains(&marker),
        "case line repeats {key}"
    );
    &tail[..end]
}

fn case_id(line: &str) -> u32 {
    const MARKER: &str = "\"id\":";
    let pos = line.find(MARKER).expect("case id");
    let tail = &line[pos + MARKER.len()..];
    let end = tail
        .find(|ch: char| !ch.is_ascii_digit())
        .expect("id terminator");
    assert!(end > 0, "empty id");
    assert!(!tail[end..].contains(MARKER), "case line has a second id");
    tail[..end].parse().expect("id integer")
}

fn expected_error(line: &str) -> Option<(&str, &str)> {
    const PREFIX: &str = "{\"expected_json\":\"{\\\"error\\\":\\\"";
    if !line.starts_with(PREFIX) {
        assert!(
            line.starts_with("{\"expected_json\":\"{\\\"ok\\\":"),
            "case is neither an error nor an ok result"
        );
        return None;
    }
    let rest = &line[PREFIX.len()..];
    let kind_end = rest.find("\\\"").expect("error kind");
    let kind = &rest[..kind_end];
    const MSG_MARK: &str = "\\\",\\\"message\\\":\\\"";
    let after = &rest[kind_end..];
    assert!(
        after.starts_with(MSG_MARK),
        "error object is missing message"
    );
    let message = &after[MSG_MARK.len()..];
    let message_end = message.find("\\\"").expect("message end");
    Some((kind, &message[..message_end]))
}

fn verify_case(line: &str) -> VerifyCase<'_> {
    let (error_kind, error_message) = match expected_error(line) {
        Some((kind, message)) => (Some(kind), Some(message)),
        None => (None, None),
    };
    VerifyCase {
        id: case_id(line),
        family: json_string_field(line, "family"),
        contract: json_string_field(line, "contract"),
        error_kind,
        error_message,
    }
}

fn case_lines(json: &str) -> Vec<&str> {
    assert!(!json.contains('\r'), "outcome vectors.json contains CR");
    let mut lines = json.split('\n').filter(|line| !line.is_empty());
    let header = lines.next().expect("vectors header");
    assert!(
        header.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "outcome vectors are pinned to {PIN}"
    );
    assert!(header.contains("\"module\":\"sesslint.outcome\""));
    assert!(header.contains("\"schema\":\"sesslint.parity-module-vectors/v1\""));
    assert!(header.ends_with("\"cases\":["));
    let mut body: Vec<&str> = lines.collect();
    let closer = body.pop().expect("vectors closer");
    assert_eq!(closer, "]}");
    body
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\":{id}");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("outcome vectors.json is missing id {id}"));
    let after_id = start + marker.len();
    let next = json.as_bytes().get(after_id).copied();
    assert!(
        next.is_some_and(|byte| !byte.is_ascii_digit()),
        "id {id} is a prefix of another id"
    );
    let rest = &json[after_id..];
    let end = rest
        .find("\"id\":")
        .map(|offset| after_id + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn coverage_row<'a>(json: &'a str, name: &str) -> &'a str {
    let marker = format!("\"test_name\": \"{name}\"");
    assert_eq!(json.matches(&marker).count(), 1, "{name}");
    let pos = json
        .find(&marker)
        .unwrap_or_else(|| panic!("coverage.json is missing {name}"));
    let start = json[..pos]
        .rfind('{')
        .unwrap_or_else(|| panic!("coverage row start for {name}"));
    let end_rel = json[pos..]
        .find('}')
        .unwrap_or_else(|| panic!("coverage row end for {name}"));
    &json[start..pos + end_rel + 1]
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_outcome_contract_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    let mut covered_ids = BTreeSet::new();
    for row in ROWS {
        assert!(
            names.insert(row.name),
            "duplicate pinned test name {}",
            row.name
        );
        match row.disposition {
            Disposition::Covered { vector_id, needles } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(!reason.is_empty(), "{}", row.name);
                assert!(
                    reason.contains("cartesian"),
                    "{} not_applicable reason must say why a cartesian slice is not the whole test",
                    row.name
                );
                assert!(reasons.insert(reason), "duplicate reason for {}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_outcome_vectors() {
    let json = read_text(VECTORS_REL);
    let lines = case_lines(&json);
    assert_eq!(lines.len(), OUTCOME_VECTOR_COUNT);
    assert_eq!(json.matches("\"id\":").count(), OUTCOME_VECTOR_COUNT);
    assert_eq!(
        json.matches("\"family\":\"verify\"").count(),
        OUTCOME_VECTOR_COUNT
    );
    assert_eq!(
        json.matches("\"contract\":\"").count(),
        OUTCOME_VECTOR_COUNT
    );

    let mut ids = BTreeSet::new();
    let mut contract_errors = 0usize;
    for line in &lines {
        let case = verify_case(line);
        assert_eq!(case.family, "verify", "id {}", case.id);
        assert!(
            matches!(
                case.contract,
                "contract.json" | "invalid.json" | "missing.json"
            ),
            "id {} contract {}",
            case.id,
            case.contract
        );
        assert!(ids.insert(case.id), "duplicate id {}", case.id);
        if case.error_kind == Some("ContractError") {
            assert_eq!(case.contract, "invalid.json");
            assert_eq!(
                case.error_message,
                Some("contract: not valid strict UTF-8 JSON (JSONDecodeError)")
            );
            contract_errors += 1;
        }
    }
    assert_eq!(ids.len(), OUTCOME_VECTOR_COUNT);
    assert_eq!(ids.iter().next().copied(), Some(0));
    assert_eq!(ids.iter().next_back().copied(), Some(4817));
    assert_eq!(contract_errors, CONTRACT_ERROR_COUNT);

    for needle in PIN_NEEDLES_ABSENT_FROM_VECTORS {
        assert!(
            !json.contains(needle),
            "pin needle {needle} is present, so a covered claim would be a slice"
        );
    }
    assert!(json.contains("no due window declared: absence is judged at the evaluation instant"));
    assert!(json.contains("INCONCLUSIVE"));

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            ids.contains(&vector_id.parse::<u32>().expect("covered id")),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing pinned needle {needle}",
                row.name
            );
        }
    }

    let manifest = read_text(MANIFEST_REL);
    assert!(manifest.contains(&format!("\"python_commit\": \"{PIN}\"")));
    assert!(manifest.contains("\"module\": \"sesslint.outcome\""));
    assert!(manifest.contains("\"vector_count\": 4818"));
    assert!(manifest.contains("tests/outcome/test_outcome_contract.py"));

    let coverage = read_text(COVERAGE_REL);
    assert!(coverage.contains("\"covered_count\": 0"));
    for name in PINNED_NAMES {
        let row = coverage_row(&coverage, name);
        assert!(row.contains("\"status\": \"not_applicable\""), "{name}");
        assert!(row.contains("\"vector_ids\": []"), "{name}");
        assert!(
            row.contains("\"test_file\": \"tests/outcome/test_outcome_contract.py\""),
            "{name}"
        );
    }

    for rel in [PROVENANCE_REL, FIXTURE_PROVENANCE_REL] {
        let provenance = read_text(rel);
        assert!(
            provenance.contains("\"contains_real_data\": false"),
            "{rel}"
        );
        assert!(provenance.contains("\"origin\": \"synthetic\""), "{rel}");
        assert!(
            provenance.contains(&format!("\"python_commit\": \"{PIN}\"")),
            "{rel}"
        );
    }
}
