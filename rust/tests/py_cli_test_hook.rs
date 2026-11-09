//! Dispositions for the 28 `def test_` functions in pinned `tests/cli/test_hook.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (256 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 28;
const HOOK_VECTOR_COUNT: usize = 22;
const VECTORS_REL: &str = "parity/vectors/hook_event/vectors.json";

/// `covered` names a vector id in `hook_event/vectors.json`.
/// `not_applicable` records a `run_hook` or CLI call this package cannot reach
/// without a `Cargo.toml` change outside the owned path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
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
        name: "test_claude_json_cli_envelope",
        disposition: Disposition::NotApplicable("CLI hook process with a claude-json envelope"),
    },
    Row {
        name: "test_malformed_json_skips",
        disposition: Disposition::Covered {
            vector_id: "run_malformed_json",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"malformed-payload\"",
                "\"exit_code\": 0",
            ],
        },
    },
    Row {
        name: "test_non_object_payload_skips",
        disposition: Disposition::Covered {
            vector_id: "run_non_object_payload",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"malformed-payload\"",
            ],
        },
    },
    Row {
        name: "test_missing_transcript_path_skips",
        disposition: Disposition::Covered {
            vector_id: "run_missing_transcript_path",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"no-transcript-path\"",
            ],
        },
    },
    Row {
        name: "test_wrong_typed_transcript_path_skips",
        disposition: Disposition::NotApplicable(
            "integer transcript_path skip has no hook_event vector",
        ),
    },
    Row {
        name: "test_nonexistent_transcript_skips",
        disposition: Disposition::Covered {
            vector_id: "run_transcript_not_found",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"transcript-not-found\"",
            ],
        },
    },
    Row {
        name: "test_directory_transcript_skips",
        disposition: Disposition::Covered {
            vector_id: "run_directory_transcript",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"transcript-not-found\"",
            ],
        },
    },
    Row {
        name: "test_oversized_payload_skips",
        disposition: Disposition::Covered {
            vector_id: "run_oversized_payload",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"reason\": \"payload-too-large\"",
            ],
        },
    },
    Row {
        name: "test_empty_stdin_skips",
        disposition: Disposition::Covered {
            vector_id: "run_empty_stdin",
            needles: &["\"verdict\": \"skipped\"", "\"exit_code\": 0"],
        },
    },
    Row {
        name: "test_sessionstart_clean_ok",
        disposition: Disposition::Covered {
            vector_id: "classify_clean",
            needles: &[
                "\"verdict\": \"ok\"",
                "\"reason\": \"clean\"",
                "\"exit_code\": 0",
                "\"line\": \"sesslint hook[SessionStart]: ok\"",
            ],
        },
    },
    Row {
        name: "test_sessionstart_over_budget_skips_without_reading_transcript",
        disposition: Disposition::Covered {
            vector_id: "run_fast_budget_exceeded",
            needles: &[
                "\"event\": \"SessionStart\"",
                "\"verdict\": \"skipped\"",
                "\"reason\": \"budget-exceeded\"",
                "\"exit_code\": 0",
            ],
        },
    },
    // Pinned assertions name SL009.
    Row {
        name: "test_sessionend_runs_sl009_only",
        disposition: Disposition::NotApplicable(
            "SessionEnd findings call run_hook on a transcript",
        ),
    },
    Row {
        name: "test_sessionend_clean_transcript_ok",
        disposition: Disposition::NotApplicable("SessionEnd clean transcript calls run_hook"),
    },
    Row {
        name: "test_unknown_event_runs_generic_check",
        disposition: Disposition::NotApplicable(
            "generic event findings call run_hook on a transcript",
        ),
    },
    Row {
        name: "test_fail_on_warning_exits_1_on_findings",
        disposition: Disposition::Covered {
            vector_id: "classify_fail_on_warning",
            needles: &[
                "\"fail_on\": \"warning\"",
                "\"verdict\": \"findings\"",
                "\"exit_code\": 1",
            ],
        },
    },
    // Pinned assertions name SL009 and SL303.
    Row {
        name: "test_fail_on_error_ignores_warnings",
        disposition: Disposition::NotApplicable(
            "warning-versus-error gate calls run_hook on transcripts",
        ),
    },
    Row {
        name: "test_fail_on_never_is_default",
        disposition: Disposition::NotApplicable("explicit fail_on never has no hook_event vector"),
    },
    Row {
        name: "test_fail_on_skipped_still_0",
        disposition: Disposition::Covered {
            vector_id: "classify_limitation_skipped",
            needles: &[
                "\"fail_on\": \"warning\"",
                "\"verdict\": \"skipped\"",
                "\"exit_code\": 0",
            ],
        },
    },
    // Pinned assertions name SL009.
    Row {
        name: "test_json_shape_and_schema",
        disposition: Disposition::NotApplicable(
            "findings JSON from run_hook includes a hashed session id",
        ),
    },
    Row {
        name: "test_skipped_json_shape",
        disposition: Disposition::Covered {
            vector_id: "run_blank_transcript_path",
            needles: &[
                "\"verdict\": \"skipped\"",
                "\"top_code\": null",
                "\\\"findings_by_code\\\": {}",
                "\\\"reason\\\": \\\"no-transcript-path\\\"",
            ],
        },
    },
    Row {
        name: "test_no_secret_values_in_output",
        disposition: Disposition::NotApplicable(
            "seeded run_hook output scan stays outside this package",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "paired run_hook JSON comparison stays outside this package",
        ),
    },
    // Pinned stdout assertion names SL009.
    Row {
        name: "test_cli_sessionend_findings_line",
        disposition: Disposition::NotApplicable("CLI SessionEnd findings line"),
    },
    Row {
        name: "test_cli_fail_on_warning_exits_1",
        disposition: Disposition::NotApplicable("CLI fail-on warning exit status"),
    },
    Row {
        name: "test_cli_json_output",
        disposition: Disposition::NotApplicable("CLI JSON stdout from hook"),
    },
    Row {
        name: "test_cli_garbage_stdin_skips_exit_0",
        disposition: Disposition::NotApplicable("CLI garbage stdin skip"),
    },
    Row {
        name: "test_cli_never_exits_2",
        disposition: Disposition::NotApplicable("CLI hook exit stays in the advisory range"),
    },
    Row {
        name: "test_result_validates_against_schema",
        disposition: Disposition::NotApplicable(
            "schema-file check validates live run_hook results",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_claude_json_cli_envelope",
    "test_malformed_json_skips",
    "test_non_object_payload_skips",
    "test_missing_transcript_path_skips",
    "test_wrong_typed_transcript_path_skips",
    "test_nonexistent_transcript_skips",
    "test_directory_transcript_skips",
    "test_oversized_payload_skips",
    "test_empty_stdin_skips",
    "test_sessionstart_clean_ok",
    "test_sessionstart_over_budget_skips_without_reading_transcript",
    "test_sessionend_runs_sl009_only",
    "test_sessionend_clean_transcript_ok",
    "test_unknown_event_runs_generic_check",
    "test_fail_on_warning_exits_1_on_findings",
    "test_fail_on_error_ignores_warnings",
    "test_fail_on_never_is_default",
    "test_fail_on_skipped_still_0",
    "test_json_shape_and_schema",
    "test_skipped_json_shape",
    "test_no_secret_values_in_output",
    "test_determinism",
    "test_cli_sessionend_findings_line",
    "test_cli_fail_on_warning_exits_1",
    "test_cli_json_output",
    "test_cli_garbage_stdin_skips_exit_0",
    "test_cli_never_exits_2",
    "test_result_validates_against_schema",
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
        .unwrap_or_else(|| panic!("hook_event vectors.json is missing id {id}"));
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
fn every_pinned_hook_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
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
    assert!(not_applicable > 0);
    assert!(covered > 0);
}

#[test]
fn covered_vector_ids_are_present_in_hook_event_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "hook_event vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.hook_event\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), HOOK_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
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
