//! Dispositions for the 7 `def test_` functions in pinned `tests/cli/test_removed_surface.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (118 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. The helper `_run` is not a test.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 7;
const CLI_VECTOR_COUNT: usize = 33;
const MAIN_VECTOR_COUNT: usize = 7;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const MAIN_VECTORS_REL: &str = "parity/vectors/__main__/vectors.json";

/// `covered` names one vector id whose construct is the same function and the
/// same success or failure mode as that entire pinned test, including every
/// parameter case. `not_applicable` is a pytest no single committed vector records.
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
    // `main_removed_*` and `__main__` `non_frozen_removed_*` each record one command.
    Row {
        name: "test_removed_command_exits_2_with_replacement",
        disposition: Disposition::NotApplicable(
            "four removed-command cases; no single vector is that entire pytest",
        ),
    },
    // `removed_flag_hint_*` each record one flag. `check` stops before argparse.
    Row {
        name: "test_removed_flag_exits_2_with_hint",
        disposition: Disposition::NotApplicable(
            "check stops before argparse; no single vector records every removed flag",
        ),
    },
    // `removed_flag_hint_format_membership` is a hint probe, not this `main` exit.
    Row {
        name: "test_adapter_misuse_via_format_flag_hints_adapter",
        disposition: Disposition::NotApplicable(
            "check stops before argparse; no vector records this --format adapter exit",
        ),
    },
    // `create_parser_subcommand_names` lists check and scan and does not record stdout.
    Row {
        name: "test_scan_alias_stdout_byte_identical_to_check",
        disposition: Disposition::NotApplicable(
            "check and scan stop before argparse; no vector records identical JSON stdout",
        ),
    },
    Row {
        name: "test_check_directory_recursive_without_flag",
        disposition: Disposition::NotApplicable(
            "check stops before argparse; no vector records a recursive directory scan",
        ),
    },
    Row {
        name: "test_check_agent_all_latest_rejected",
        disposition: Disposition::NotApplicable(
            "check stops before argparse; no vector records --agent all --latest",
        ),
    },
    Row {
        name: "test_repair_multi_path_requires_output_dir",
        disposition: Disposition::NotApplicable(
            "repair stops before argparse; no vector records two paths without --output-dir",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_removed_command_exits_2_with_replacement",
    "test_removed_flag_exits_2_with_hint",
    "test_adapter_misuse_via_format_flag_hints_adapter",
    "test_scan_alias_stdout_byte_identical_to_check",
    "test_check_directory_recursive_without_flag",
    "test_check_agent_all_latest_rejected",
    "test_repair_multi_path_requires_output_dir",
];

fn load_vectors(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
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
fn every_pinned_removed_surface_test_has_one_disposition() {
    assert_eq!(ROWS.len(), 7);
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
    assert_eq!(not_applicable, 7);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let cli = load_vectors(CLI_VECTORS_REL);
    assert!(
        cli.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(cli.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&cli);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    let main_vectors = load_vectors(MAIN_VECTORS_REL);
    assert!(
        main_vectors.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "__main__ vectors are pinned to {PIN}"
    );
    assert!(main_vectors.contains("\"module\": \"sesslint.__main__\""));
    let main_ids = vector_ids(&main_vectors);
    assert_eq!(main_ids.len(), MAIN_VECTOR_COUNT);
    let main_set: BTreeSet<&str> = main_ids.iter().copied().collect();
    assert_eq!(main_set.len(), main_ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&cli, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
