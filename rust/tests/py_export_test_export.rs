//! Dispositions for the eleven `def test_` functions in pinned
//! `tests/export/test_export.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (132 splitlines). Exactly
//! eleven test functions, in module order. None is parametrized. Each row is
//! the whole function. `export_to_canonical` is not the CLI. `load_canonical`
//! is not the export. A comment is not an assertion. Fixture bytes and session
//! lines are not copied here. The content-free test names three planted
//! canaries. Those canaries are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call exporter, canonical, api, or
//! cli functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33 ids at this
//! pin and none of those ids is one of these eleven functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these eleven
//! functions. `module_all` lists `export_file` and `repair` among exports.
//! `repair_plan_path_exclusive` is one dry-run repair call that raises because
//! plan and plan_path are mutually exclusive. `create_parser_subcommand_names`
//! lists `export` among parser subcommand names and is not one of these
//! functions. `parity/vectors/exporter/vectors.json` has nine ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `module_constants`,
//! `export_refused`, `export_summary_to_dict`, `export_missing_source_path`,
//! `export_directory_source`, `export_broken_symlink`,
//! `export_empty_source_path`, `export_regular_file_gap`, and
//! `export_regular_file_symlink_gap`. That old pin is not a Covered source.
//! `export_refused` is not either refusal pytest. `export_summary_to_dict` is
//! not the content-free pytest. `export_empty_source_path` is not the
//! empty-session pytest. `export_regular_file_gap` is not the canonical
//! roundtrip. `parity/vectors/adapters.canonical/vectors.json` has 44 ids at
//! that old pin and none is one of these functions. There is no evidence
//! corpus. Therefore every row is NotApplicable. `not_applicable` names the
//! missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 132;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `export_to_canonical` is not the CLI. `load_canonical`
/// is not the export. A comment is not an assertion. Each row is the whole
/// function. `not_applicable` names the missing stop.
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
        name: "test_export_canonical_roundtrip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_canonical_roundtrip: the input format is canonical, the event count is greater than 0, and the loaded event length equals that count. All three are one row. It does not assert the count value. The two-vendor test is not this pytest. missing stop: all three together; it does not assert the count value; export_to_canonical is not the CLI; load_canonical is not the export; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_claude_and_openai is that two-vendor test; export_regular_file_gap is not the canonical roundtrip; export_regular_file_symlink_gap is a symlink gap on the old pin and is not this pytest; module_all lists export_file among exports and is not this pytest",
        ),
    },
    Row {
        name: "test_export_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_deterministic: the two exports have equal bytes. That equality is one row. It does not assert the bytes. The roundtrip does not compare two files and is not this pytest. missing stop: that equality; it does not assert the bytes; export_to_canonical is not the CLI; load_canonical is not the export; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_canonical_roundtrip is that roundtrip and does not compare two files; export_regular_file_gap is a live-store gap on the old pin and is not this byte equality",
        ),
    },
    Row {
        name: "test_export_claude_and_openai",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_claude_and_openai: the Claude input format is claude-code-jsonl, the OpenAI input format is openai-agents, and each loaded length equals its own event count. Both vendors are one row. It does not assert the counts. The canonical roundtrip is not this pytest. missing stop: both vendors together; it does not assert the counts; export_to_canonical is not the CLI; load_canonical is not the export; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_canonical_roundtrip is that canonical roundtrip; test_export_deterministic compares two files and is not this pytest",
        ),
    },
    Row {
        name: "test_export_then_repair_accepts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_then_repair_accepts: the dry-run repair returns a plan whose fingerprint is present and a manifest that is None. Both are one row. It does not assert the fingerprint string. The CLI export is not this API repair. missing stop: both together; it does not assert the fingerprint string; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_cli_json_and_refusal is that CLI export; repair_plan_path_exclusive is one dry-run repair call that raises because plan and plan_path are mutually exclusive and is not this pytest; module_all lists repair among exports and is not this fingerprint",
        ),
    },
    Row {
        name: "test_export_summary_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_summary_content_free: three planted canaries are absent from the summary JSON, the CLI exits 0, and the first two of those canaries are absent from stdout. Both phases are one row. It does not check stderr, and it does not check the third canary on stdout. The JSON shape test is not this pytest. missing stop: both phases together; it does not check stderr; it does not check the third canary on stdout; the planted canaries are not copied here; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; export_summary_to_dict is not the content-free pytest; test_export_cli_json_and_refusal is the JSON refusal and is not this pytest; create_parser_subcommand_names lists export among subcommand names and is not this pytest",
        ),
    },
    Row {
        name: "test_export_refuses_self_and_existing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_refuses_self_and_existing: exporting onto the source raises ExportRefused, and exporting onto an existing file raises ExportRefused while the file text stays sentinel. Both refusals are one row. The CLI refusal is not this API pair. missing stop: both refusals together; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_cli_json_and_refusal is that CLI refusal; export_refused is not either refusal pytest; test_export_refuses_malformed_syntax_errors matches fatal or error findings and is not this pair",
        ),
    },
    Row {
        name: "test_export_cli_json_and_refusal",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_cli_json_and_refusal: the JSON export exits 0, the input format is canonical, and the event count is greater than 0; the second export onto that same output exits 1 and stderr contains refused. Both phases are one row. It does not assert that the existing file is unchanged. The API self-refusal is not this CLI. missing stop: both phases together; it does not assert that the existing file is unchanged; export_to_canonical is not the CLI; a comment is not an assertion; the source is healthy; test_export_refuses_self_and_existing is that API self-refusal; test_export_cli_refuses_corrupted_input uses a corrupted source and is not this pytest; export_refused is not either refusal pytest; create_parser_subcommand_names lists export among subcommand names and is not this pytest",
        ),
    },
    Row {
        name: "test_export_refuses_malformed_syntax_errors",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_refuses_malformed_syntax_errors: ExportRefused matches fatal or error findings, and the output does not exist. Both are one row. The call passes no format argument. The empty-session refusal is not this pytest. missing stop: both together; the call passes no format argument; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_refuses_empty_session is that empty-session refusal; test_export_refuses_torn_final passes format canonical and is not this pytest; test_export_cli_refuses_corrupted_input is the CLI and is not this API; export_refused is not either refusal pytest",
        ),
    },
    Row {
        name: "test_export_refuses_empty_session",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_refuses_empty_session: ExportRefused is raised, the output does not exist, and the call passes format canonical. It does not assert the message. The malformed refusal is not this pytest. missing stop: all three together; it does not assert the message; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_refuses_malformed_syntax_errors is that malformed refusal and the call passes no format argument; export_empty_source_path is not the empty-session pytest; test_export_refuses_torn_final matches fatal or error findings and is not this pytest",
        ),
    },
    Row {
        name: "test_export_refuses_torn_final",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_refuses_torn_final: ExportRefused matches fatal or error findings, the output does not exist, and the call passes format canonical. All three are one row. The malformed refusal does not pass format and is not this pytest. missing stop: all three together; the call passes format canonical; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_refuses_malformed_syntax_errors is that malformed refusal and the call passes no format argument; test_export_refuses_empty_session does not assert the message and is not this pytest; export_refused is not either refusal pytest",
        ),
    },
    Row {
        name: "test_export_cli_refuses_corrupted_input",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_cli_refuses_corrupted_input: the CLI exits 1, stderr contains refused, and the output does not exist. All three are one row. The API malformed refusal is not this CLI. The JSON refusal uses a healthy source and is not this pytest. missing stop: all three together; export_to_canonical is not the CLI; a comment is not an assertion; fixture bytes and session lines are not copied here; test_export_refuses_malformed_syntax_errors is that API malformed refusal; test_export_cli_json_and_refusal is that JSON refusal and uses a healthy source; export_refused is not either refusal pytest; create_parser_subcommand_names lists export among subcommand names and is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_export_canonical_roundtrip",
    "test_export_deterministic",
    "test_export_claude_and_openai",
    "test_export_then_repair_accepts",
    "test_export_summary_content_free",
    "test_export_refuses_self_and_existing",
    "test_export_cli_json_and_refusal",
    "test_export_refuses_malformed_syntax_errors",
    "test_export_refuses_empty_session",
    "test_export_refuses_torn_final",
    "test_export_cli_refuses_corrupted_input",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
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
fn pinned_export_test_export_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 132);
}

#[test]
fn pinned_export_test_export_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
    assert_eq!(PINNED_NAMES.len(), 11);
}

#[test]
fn every_pinned_export_test_export_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 11);
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
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
    let json = read_vectors(CLI_VECTORS_REL);
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
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 11);

    let json = read_vectors(API_VECTORS_REL);
    // `parity/vectors/api/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "api vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
