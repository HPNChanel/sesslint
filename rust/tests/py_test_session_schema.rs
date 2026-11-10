//! Dispositions for the thirteen `def test_` functions in pinned
//! `tests/test_session_schema.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (318 splitlines). Exactly
//! thirteen test functions, in module order. None is parametrized. Each row is
//! the whole function. An API error is not a CLI exit. An in-process main is
//! not a subprocess. A JSONL line walk is not a flat document. One set is not
//! the parser match. Fixture lines, the nested event object, and a session
//! payload are not copied here. `REPO_ROOT`, `SCHEMA_PATH`, and `FIXTURES_DIR`
//! are not tests.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-command hints, removed-flag hints, verbose
//! provenance, and removed-subcommand exits. None of those vectors is one of
//! these thirteen functions. `check_exit_constants` records help text that an
//! internal tool error exits 2. That help text is not
//! `test_cli_check_canonical_missing_file` and not
//! `test_cli_check_canonical_unexpected_error`.
//! `parity/vectors/canonical/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its twelve ids are
//! `header_minimal_parsed_fields`, `header_bad_schema_version_sl301_suffix`,
//! `event_minimal`, `event_duplicate_id`, `event_self_parent`,
//! `event_bad_actor_sorted_expected_actors`,
//! `session_framed_experimental_fields`, `session_flat_experimental_fields`,
//! `parse_session_lines_blank_line_one_event`, `load_session_file_small_jsonl`,
//! `validate_rfc3339_utc_ok_leap_day`, and
//! `validate_rfc3339_utc_calendar_fail_original_ts_in_message`. They are not
//! among the 33 cli vectors and are not used to mark a row covered.
//! `header_bad_schema_version_sl301_suffix` is one header parse error at that
//! other pin, so it does not cover `test_wrong_version_fixture`.
//! `load_session_file_small_jsonl` does not cover `test_minimal_valid_fixture`.
//! `event_minimal` does not cover `test_unknown_nested_payload_keys_permitted`.
//! `session_flat_experimental_fields` does not cover
//! `test_minimal_canonical_fixture_satisfies_flat_schema`.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call canonical or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 318;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. An API error is not a CLI exit.
/// An in-process main is not a subprocess. A JSONL line walk is not a flat
/// document. `not_applicable` names the missing stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Present so a later whole-pytest vector can be claimed. None qualifies.
    #[expect(dead_code)]
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
        name: "test_schema_file_exists_and_parses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_schema_file_exists_and_parses: schemas/sesslint.session.v1.json exists, its $id is the session v1 URL https://sesslint.dev/schemas/sesslint.session/v1, and its $schema is draft 2020-12 https://json-schema.org/draft/2020-12/schema; missing stop: all three together; all three are one row; the file check is not the $id and the $id is not the $schema; test_schema_and_parser_required_keys_match compares header and event required and known sets, actor and kind enums, the execution_state enum without null, and the flat and framed oneOf sets and is not this file, $id, and $schema",
        ),
    },
    Row {
        name: "test_schema_and_parser_required_keys_match",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_schema_and_parser_required_keys_match: header and event required sets match the parser, known property sets match, actor and kind enums match, the execution_state enum without null matches, the flat oneOf required set is the header required set plus events and its known set is the header known set plus events, and the framed oneOf required and property sets are header and events; missing stop: all of those together; all of those are one row; one set is not this pytest; test_schema_file_exists_and_parses checks that the schema file exists and that $id and $schema match and is not these sets",
        ),
    },
    Row {
        name: "test_vendor_neutrality_in_canonical_and_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_neutrality_in_canonical_and_schema: canonical.py and the session schema contain none of anthropic, openai, claude, gpt, tool_use, or function_call, case insensitive; missing stop: both files and every word together; both files are one row; one file is not this pytest; one word is not this pytest; test_schema_and_parser_required_keys_match compares parser sets and enums and is not these absent words",
        ),
    },
    Row {
        name: "test_minimal_valid_fixture",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_minimal_valid_fixture: minimal-valid.jsonl loads, the session id is sess_min_001, the schema is sesslint.session/v1, there are three events, the parent chain is none then the first id then the second id, and the dump equals the stripped original plus a trailing newline; missing stop: all of those together; all of those are one row; the session id is not the parent chain and the parent chain is not the dump; fixture lines are not copied here; test_jsonl_header_and_event_lines_satisfy_schema walks the same file for header and event key sets and is not this load, parent chain, and dump",
        ),
    },
    Row {
        name: "test_wrong_version_fixture",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_wrong_version_fixture: load raises VersionError, the code is VERSION, the reason is SL301, and both strings are in the message; missing stop: all of those together; all of those are one row; the exception type is not the code, the code is not the reason, and the reason is not the message; an API error is not a CLI exit; the CLI SL001 is not this API; test_cli_check_canonical_subcommand on the wrong-version fixture exits 1 and stdout contains SL001 and is not this VersionError",
        ),
    },
    Row {
        name: "test_unknown_top_level_field_fixture",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_top_level_field_fixture: load raises UnknownFieldError, the code is UNKNOWN_FIELD, the reason is SL302, and both strings are in the message; missing stop: all of those together; all of those are one row; the exception type is not the code, the code is not the reason, and the reason is not the message; an API error is not a CLI exit; the CLI that tolerates the field is not this API; test_cli_check_canonical_subcommand on the unknown-field fixture exits 0 and stdout contains healthy and is not this UnknownFieldError",
        ),
    },
    Row {
        name: "test_unknown_nested_payload_keys_permitted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_nested_payload_keys_permitted: parse_session_event accepts a nested unknown payload, arbitrary_user_key is 42, and the nested foo is bar; missing stop: both assertions together; both assertions are one row; arbitrary_user_key is not the nested foo; the event object is not copied here; the top-level unknown-field error is not this pytest; test_unknown_top_level_field_fixture raises UnknownFieldError with code UNKNOWN_FIELD and reason SL302 and is not this accepted nested payload",
        ),
    },
    Row {
        name: "test_cli_check_canonical_subcommand",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_canonical_subcommand: three in-process checks; the healthy fixture exits 0 and stdout contains Valid canonical session; the wrong-version fixture exits 1 and stdout contains SL001; the unknown-field fixture exits 0 and stdout contains healthy; missing stop: all three phases together; all three phases are one row; the healthy exit is not the wrong-version exit and the wrong-version exit is not the unknown-field exit; an API error is not a CLI exit; the API errors are not this CLI; test_wrong_version_fixture raises VersionError with SL301 and test_unknown_top_level_field_fixture raises UnknownFieldError with SL302 and neither is this in-process main; an in-process main is not a subprocess; the subprocess test is not this in-process main; test_cli_subprocess_check_canonical runs python -m sesslint and does not assert the wrong-version code equals 1",
        ),
    },
    Row {
        name: "test_cli_subprocess_check_canonical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_subprocess_check_canonical: two subprocess python -m sesslint runs; the healthy fixture returns 0 and stdout contains Valid canonical session; the wrong-version fixture returns a code that is not 0, and that code is not asserted equal to 1, and stdout contains SL001; missing stop: both runs together; both runs are one row; the healthy return is not the wrong-version return; a code that is not 0 is not an assertion that the code equals 1; an in-process main is not a subprocess; the in-process main is not this subprocess; test_cli_check_canonical_subcommand calls main in process, asserts the wrong-version exit equals 1, and also checks the unknown-field fixture and is not these two subprocess runs",
        ),
    },
    Row {
        name: "test_cli_check_canonical_missing_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_canonical_missing_file: a missing path exits 2 and stderr contains Error:; missing stop: both together; both are one row; the exit is not the stderr phrase; the unexpected RuntimeError is not this missing path; test_cli_check_canonical_unexpected_error monkeypatches check_file to raise RuntimeError Unexpected boom, exits 2, and stderr contains that phrase and is not this missing path",
        ),
    },
    Row {
        name: "test_cli_check_canonical_unexpected_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_canonical_unexpected_error: a monkeypatched check_file raises RuntimeError Unexpected boom, the exit is 2, and stderr contains that phrase; missing stop: all three together; all three are one row; the monkeypatch is not the exit and the exit is not the stderr phrase; the missing-file exit is not this pytest; test_cli_check_canonical_missing_file exits 2 because the path is missing and stderr contains Error: and is not this RuntimeError",
        ),
    },
    Row {
        name: "test_jsonl_header_and_event_lines_satisfy_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_jsonl_header_and_event_lines_satisfy_schema: the schema oneOf refs include header and event, minimal-valid.jsonl has at least two lines, the header keys satisfy required and known, and every later line satisfies event required and known; missing stop: all of those together; all of those are one row; the refs are not the line count and the header line is not every later event line; lines are not copied here; a JSONL line walk is not a flat document; the flat JSON document is not this JSONL; test_minimal_canonical_fixture_satisfies_flat_schema checks fixtures/canonical/minimal.json against the flat oneOf sets and parse_session and is not this JSONL line walk",
        ),
    },
    Row {
        name: "test_minimal_canonical_fixture_satisfies_flat_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_minimal_canonical_fixture_satisfies_flat_schema: fixtures/canonical/minimal.json satisfies the flat oneOf required and known sets, parse_session reports session id canonical-session, and there are two events; missing stop: all of those together; all of those are one row; the required set is not the known set, the key sets are not the session id, and the session id is not the event count; the document is not copied here; a JSONL line walk is not a flat document; the JSONL line walk is not this flat document; test_jsonl_header_and_event_lines_satisfy_schema walks minimal-valid.jsonl header and event lines and is not this flat document",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_schema_file_exists_and_parses",
    "test_schema_and_parser_required_keys_match",
    "test_vendor_neutrality_in_canonical_and_schema",
    "test_minimal_valid_fixture",
    "test_wrong_version_fixture",
    "test_unknown_top_level_field_fixture",
    "test_unknown_nested_payload_keys_permitted",
    "test_cli_check_canonical_subcommand",
    "test_cli_subprocess_check_canonical",
    "test_cli_check_canonical_missing_file",
    "test_cli_check_canonical_unexpected_error",
    "test_jsonl_header_and_event_lines_satisfy_schema",
    "test_minimal_canonical_fixture_satisfies_flat_schema",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_session_schema_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 318);
}

#[test]
fn pinned_test_session_schema_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
}

#[test]
fn every_pinned_test_session_schema_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
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
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        if !id_set.contains(vector_id) {
            continue;
        }
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
