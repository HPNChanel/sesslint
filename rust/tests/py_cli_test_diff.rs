//! Dispositions for the 17 `def test_` functions in pinned `tests/cli/test_diff.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (248 splitlines). Exactly seventeen
//! test functions, in module order. None is parametrized. Helpers `_claude_records`
//! and `_write_jsonl` are not tests. Each row is the whole function. A main exit
//! code is not a structural delta. One category is not the JSON schema sweep. The
//! self-diff is not the identical-pair run. One field is not the whole pytest. One
//! key is not the whole pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` or
//! `sesslint.diff` without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. The diff parity corpus at `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`
//! is a different pin. A main exit code is not a structural delta. One category
//! is not the JSON schema sweep. The self-diff is not the identical-pair run.
//! One field is not the whole pytest. One key is not the whole pytest.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 17;
const PINNED_SPLITLINES: usize = 248;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A main exit code is not a structural delta. One category is not the
/// JSON schema sweep. The self-diff is not the identical-pair run. One field
/// is not the whole pytest. One key is not the whole pytest. `not_applicable`
/// names the missing stop.
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
        name: "test_diff_identical_exit_0",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_identical_exit_0 calling sesslint.cli.main on diff of two identical four-record sessions with --adapter claude-code-jsonl and requiring exit 0; missing stop: that identical-pair main diff exit 0; the self-diff of fixtures/cli/check_basic/healthy.jsonl is not this pytest; a main exit code is not a structural delta; check_exit_constants only stores the phrase a clean session exits 0 and is not this run; create_parser_subcommand_names lists diff among subcommand names and does not run main diff; removed_flag_hint_format_membership is a removed --format hint and is not this --adapter diff; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this exit 0; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_self_exit_0",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_self_exit_0 calling sesslint.cli.main on diff of fixtures/cli/check_basic/healthy.jsonl against itself with no adapter flag and requiring exit 0; missing stop: that self-diff exit 0; the identical-pair run is not this pytest; a main exit code is not a structural delta; check_exit_constants only stores the phrase a clean session exits 0 and is not this run; create_parser_subcommand_names lists diff among subcommand names and does not run main diff; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_removed_event",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_removed_event calling sesslint.diff.diff_sessions on five records versus four with format_a claude-code-jsonl and format_b claude-code-jsonl, requiring identical false, category removed present, and the first removed delta to have event id m5 and a_index 4; missing stop: that removed delta on m5 at a_index 4; a main exit code is not a structural delta; one category is not the JSON schema sweep; the added-event pytest is not this pytest; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_added_event",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_added_event calling sesslint.diff.diff_sessions on three records versus four with format_a claude-code-jsonl and format_b claude-code-jsonl, requiring exactly one added delta whose event id is m4 and whose b_index is 3; missing stop: that added delta on m4 at b_index 3; a main exit code is not a structural delta; one category is not the JSON schema sweep; counts.added on the main --json pytest is not this delta; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_kind_changed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_kind_changed calling sesslint.diff.diff_events on two in-memory events with no files, the second kind changing from message to checkpoint, requiring exactly one kind-changed delta on event id e2 with kind_a message and kind_b checkpoint; missing stop: that kind-changed delta on e2; a main exit code is not a structural delta; one category is not the JSON schema sweep; the file-backed diff_sessions pytests are not this in-memory run; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_events and sesslint.canonical.SessionEvent are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_parent_relinked",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_parent_relinked calling sesslint.diff.diff_sessions on four records with format_a claude-code-jsonl and format_b claude-code-jsonl, the fourth record parent changing from m3 to m1, requiring exactly one parent-relinked delta on event id m4 with parent_a m3 and parent_b m1; missing stop: that parent-relinked delta on m4; a main exit code is not a structural delta; one category is not the JSON schema sweep; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_seq_reordered",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_seq_reordered calling sesslint.diff.diff_sessions on four records with format_a claude-code-jsonl and format_b claude-code-jsonl, the second and third records swapping, requiring exactly one seq-reordered delta on event id m3 at b_index 1; missing stop: that seq-reordered delta on m3 at b_index 1; a main exit code is not a structural delta; one category is not the JSON schema sweep; the in-memory swapped pair in test_diff_events_pure is not this pytest; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_content_changed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_content_changed calling sesslint.diff.diff_sessions on three records with format_a claude-code-jsonl and format_b claude-code-jsonl, the first record message text changing, requiring exactly one content-changed delta on event id m1 and the replacement text absent from the serialized diff (JSON serialization of to_dict); missing stop: that content-changed delta on m1 and the absence of the replacement text; a main exit code is not a structural delta; one category is not the JSON schema sweep; the human-stdout absences in test_diff_no_payload_in_output are not this pytest; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_json_output_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_json_output_schema calling sesslint.cli.main on diff of three records versus four with --adapter claude-code-jsonl and --json, requiring exit 1, captured stdout to parse as JSON, schema_version equal to DIFF_SCHEMA_VERSION, identical false, counts.added 1, side event counts 3 and 4, deltas a list, and every category one of added, removed, kind-changed, parent-relinked, seq-reordered, or content-changed; missing stop: that whole JSON diff object; one field is not the whole pytest; one category is not the JSON schema sweep; a main exit code is not a structural delta; the added-event delta on m4 is not this pytest; the load_diff_schema validation is not this pytest; check_exit_constants only stores the phrase a session with findings exits 1 and is not this run; create_parser_subcommand_names lists diff among subcommand names and does not run main diff --json; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main and sesslint.diff.DIFF_SCHEMA_VERSION are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_json_validates_against_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_json_validates_against_schema calling sesslint.diff.diff_sessions on an identical three-record pair with format_a claude-code-jsonl and format_b claude-code-jsonl, then load_diff_schema on to_dict, requiring schema_version equal to the schema const, every required key present, every side required key present on sides a and b, and every delta category in the schema enum; missing stop: that whole schema validation; one key is not the whole pytest; one category is not the JSON schema sweep; the main --json field sweep is not this pytest; the identical-pair main exit 0 is not this pytest; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions and sesslint.diff.load_diff_schema are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_deterministic calling sesslint.diff.diff_sessions twice on the same five-versus-three selection (five records versus the first, third, and fifth of those records, ids m1, m3, and m5) with format_a claude-code-jsonl and format_b claude-code-jsonl and requiring the two to_json values to be equal; missing stop: those two equal to_json results; a main exit code is not a structural delta; one category is not this equality; removed_flag_hint_format_a and removed_flag_hint_format_b are removed --format-a and --format-b hints on check and are not these format_a and format_b keywords; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_missing_path_exit_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_missing_path_exit_2 calling sesslint.cli.main on diff of a two-record session against a missing path with no adapter flag and requiring exit 2; missing stop: that missing-path exit 2; a main exit code is not a structural delta; the unrecognized-object exit 2 and the directory exit 2 are not this pytest; the DiffInputError pytest is not this pytest; check_exit_constants only stores an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this missing path; create_parser_subcommand_names lists diff among subcommand names and does not run main diff; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_undetectable_exit_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_undetectable_exit_2 calling sesslint.cli.main on diff of a two-record session against one unrecognized JSON object with no adapter flag and requiring exit 2; missing stop: that unrecognized-object exit 2; a main exit code is not a structural delta; the missing-path exit 2, the directory exit 2, and the DiffInputError pytest are not this pytest; check_exit_constants only stores an internal tool error exits 2 and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this unrecognized object; create_parser_subcommand_names lists diff among subcommand names and does not run main diff; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_directory_input_exit_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_directory_input_exit_2 calling sesslint.cli.main on diff of a two-record session against a directory with no adapter flag and requiring exit 2; missing stop: that directory exit 2; a main exit code is not a structural delta; the missing-path exit 2 and the unrecognized-object exit 2 are not this pytest; check_exit_constants only stores an internal tool error exits 2 and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this directory; create_parser_subcommand_names lists diff among subcommand names and does not run main diff; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_no_payload_in_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_no_payload_in_output calling sesslint.cli.main on diff of three records versus those records with each message replaced, --adapter claude-code-jsonl and no --json, requiring human stdout to contain neither the synthetic payload token nor the original message text; missing stop: both absences in that human stdout; both absences are one row; this pytest does not assert an exit code; the content-changed absence from the serialized to_dict is not this pytest; a main exit code is not a structural delta; create_parser_subcommand_names lists diff among subcommand names and does not run this human diff; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_events_pure",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_events_pure calling sesslint.diff.diff_events with no files, where both halves are one row: equal in-memory sequences of event ids e1 then e2 yield no deltas, and a swapped pair yields only seq-reordered; missing stop: both halves; one half is not the whole pytest; the file-backed seq-reordered delta on m3 at b_index 1 is not this pytest; the kind-changed in-memory pytest is not this pytest; a main exit code is not a structural delta; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_events and sesslint.canonical.SessionEvent are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_diff_load_side_undetectable_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_diff_load_side_undetectable_raises calling sesslint.diff.diff_sessions with no format arguments on a readable two-record side plus an unrecognized side and requiring DiffInputError; missing stop: that DiffInputError; the main exit-2 run is not this pytest; its unrecognized side is a different object from the main exit-2 pytest; a main exit code is not a structural delta; check_exit_constants exit 2 is not this exception; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.diff.diff_sessions and sesslint.diff.DiffInputError are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_diff_identical_exit_0",
    "test_diff_self_exit_0",
    "test_diff_removed_event",
    "test_diff_added_event",
    "test_diff_kind_changed",
    "test_diff_parent_relinked",
    "test_diff_seq_reordered",
    "test_diff_content_changed",
    "test_diff_json_output_schema",
    "test_diff_json_validates_against_schema",
    "test_diff_deterministic",
    "test_diff_missing_path_exit_2",
    "test_diff_undetectable_exit_2",
    "test_diff_directory_input_exit_2",
    "test_diff_no_payload_in_output",
    "test_diff_events_pure",
    "test_diff_load_side_undetectable_raises",
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
fn pinned_cli_test_diff_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 248);
}

#[test]
fn pinned_cli_test_diff_row_count_equals_seventeen() {
    assert_eq!(ROWS.len(), 17);
    assert_eq!(PINNED_TEST_COUNT, 17);
}

#[test]
fn every_pinned_cli_test_diff_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 17);
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
