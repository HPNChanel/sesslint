//! Dispositions for the twenty-two test functions in pinned
//! `tests/test_baseline.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (317 splitlines). Exactly
//! twenty-two test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_v1_file` and `_findings` are not tests.
//! `FIXTURES` and `CORRUPT` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these twenty-two names. `removed_command_hint_baseline` and
//! `main_removed_baseline` are removed-command results. They are not these
//! pytests.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these twenty-two names. `check_file_missing_default`
//! is a missing-file guard. It is not a baseline load and it is not a
//! baseline check.
//! `parity/vectors/baseline/vectors.json` has 36 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `load_v1_ok` loads one v1 document. `load_v2_ok` loads one v2 document.
//! A baseline vector that only loads one schema version is not the whole
//! pytest. `file_role_windows` is one spelling. It is not the five-result
//! spelling test. `filter_ambiguous_shared_v2` is not the keep-both filter.
//! That old pin is not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `load_baseline`,
//! `write_baseline`, `upgrade_baseline`, `file_role`, `compute_v2_key`,
//! `filter_findings`, `check_file`, or `main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 22;
const PINNED_SPLITLINES: usize = 317;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these twenty-two functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A baseline vector that only loads one schema version is not the whole
/// pytest. `load_v1_ok` is a v1 load. It is not the v2 round trip.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_baseline_v2_round_trip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_baseline_v2_round_trip: write_baseline returns the number of distinct v2 keys, load_baseline equals that set of v2 keys, the file text equals dump_baseline for the same created_by argument, schema_version equals the v2 constant, and every entry has exactly the keys code, created_by, file_role, and key; load_v2_ok only loads one schema version and is not the whole pytest; missing stop: that count, that key set, that equal text, that v2 schema, and those entry keys together; The v1 load is not this; test_load_v1_still_supported is that v1 load",
        ),
    },
    Row {
        name: "test_load_v1_still_supported",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_v1_still_supported: load_baseline equals the frozenset of the two fingerprints written into the v1 file; load_v1_ok only loads one schema version and is not the whole pytest; missing stop: that equal frozenset together; The v2 round trip is not this; test_baseline_v2_round_trip is that v2 round trip",
        ),
    },
    Row {
        name: "test_load_missing_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_missing_fails: load_baseline of a missing path raises BaselineError matching not found; missing stop: that not found error together; The malformed v1 load is not this; test_load_malformed_v1_fails is that malformed v1 load",
        ),
    },
    Row {
        name: "test_load_malformed_v1_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_malformed_v1_fails: load_baseline of a v1 document raises BaselineError matching 16-hex; missing stop: that 16-hex error together; The malformed v2 load is not this; test_load_malformed_v2_fails is that malformed v2 load",
        ),
    },
    Row {
        name: "test_load_malformed_v2_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_malformed_v2_fails: load_baseline of a v2 document raises BaselineError matching 16-hex; missing stop: that 16-hex error together; The malformed v1 load is not this; test_load_malformed_v1_fails is that malformed v1 load",
        ),
    },
    Row {
        name: "test_load_wrong_schema_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_wrong_schema_fails: load_baseline raises BaselineError matching schema_version; missing stop: that schema_version error together; The malformed v2 load is not this; test_load_malformed_v2_fails is that malformed v2 load",
        ),
    },
    Row {
        name: "test_file_role_normalizes_spelling",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_file_role_normalizes_spelling: a windows absolute spelling, a relative spelling, a dot-relative spelling, and a posix absolute spelling each equal one file role, and a sentinel spelling equals that sentinel; file_role_windows is one spelling on the old pin and is not this pytest; missing stop: those five equal results together; The bare-name file role is not this; test_file_role_bare_name_uses_cwd is that bare-name file role",
        ),
    },
    Row {
        name: "test_file_role_bare_name_uses_cwd",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_file_role_bare_name_uses_cwd: after changing directory, file_role of a bare name equals one file role and file_role of a dotdot spelling equals that same role; the docstring is not an assertion; the lexical-collapse comment is not an assertion; missing stop: those two equal roles together; The spelling normalization is not this; test_file_role_normalizes_spelling is that spelling normalization",
        ),
    },
    Row {
        name: "test_v2_key_path_spelling_independent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_v2_key_path_spelling_independent: the two findings have unequal fingerprints and equal v2 keys; the docstring is not an assertion; the path-binding comment is not an assertion; missing stop: that fingerprint inequality and that key equality together; The immediate-parent rename is not this; test_v2_key_immediate_parent_rename_differs is that immediate-parent rename",
        ),
    },
    Row {
        name: "test_v2_key_immediate_parent_rename_differs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_v2_key_immediate_parent_rename_differs: the two findings have unequal v2 keys; the docstring is not an assertion; missing stop: that key inequality together; The path-spelling key test is not this; test_v2_key_path_spelling_independent is that path-spelling key test",
        ),
    },
    Row {
        name: "test_check_write_v2_then_baseline",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_write_v2_then_baseline: check with write-baseline exits 1, the written schema_version equals the v2 constant, the entry list length is 1, and check with that baseline and json has an SL101 count of 0 and exits 0; the comments are not assertions; missing stop: that exit 1, that v2 schema, that entry length, that zero SL101 count, and that exit 0 together; The relative check is not this; test_check_v2_baseline_survives_relative_invoke is that relative check",
        ),
    },
    Row {
        name: "test_check_v2_baseline_survives_relative_invoke",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_v2_baseline_survives_relative_invoke: check with write-baseline exits 1, then check of the relative name after changing to the parent directory, with that baseline and json, has an SL101 count of 0 and exits 0; the docstring is not an assertion; missing stop: that exit 1, that relative check, that zero SL101 count, and that exit 0 together; The absolute check is not this; test_check_write_v2_then_baseline is that absolute check",
        ),
    },
    Row {
        name: "test_v1_baseline_still_suppresses_via_v1_leg",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_v1_baseline_still_suppresses_via_v1_leg: check with a v1 baseline of the finding fingerprints and json has an SL101 count of 0 and exits 0; the docstring is not an assertion; missing stop: that zero SL101 count and that exit 0 together; The relative v2 check is not this; test_check_v2_baseline_survives_relative_invoke is that relative v2 check",
        ),
    },
    Row {
        name: "test_ambiguous_v2_key_suppresses_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ambiguous_v2_key_suppresses_nothing: the two findings have unequal fingerprints and equal v2 keys, filtering both by the shared key keeps both in order, and filtering the first alone by that key returns an empty list; the docstring is not an assertion; the adapter comments are not assertions; filter_ambiguous_shared_v2 is on the old pin and is not this pytest; missing stop: that fingerprint inequality, that key equality, that kept pair, and that empty list together; The v1 suppression check is not this; test_v1_baseline_still_suppresses_via_v1_leg is that v1 suppression check",
        ),
    },
    Row {
        name: "test_upgrade_unverified_without_source",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_upgrade_unverified_without_source: upgrade with no findings returns verified 0 and unverified 2, schema_version equals the v2 constant, every entry migrated equals unverified, and the entry keys equal the two written fingerprints; the suppression comment is not an assertion; missing stop: those two counts, that v2 schema, that unverified migration, and those keys together; The verified upgrade is not this; test_upgrade_verified_with_source is that verified upgrade",
        ),
    },
    Row {
        name: "test_upgrade_verified_with_source",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_upgrade_verified_with_source: upgrade with findings returns verified 1 and unverified 1, the verified entry key equals the v2 key of the finding, the verified file_role equals the file role of that finding source, and the unverified entry key equals the extra fingerprint; missing stop: those two counts, that verified key, that file role, and that extra key together; The unverified upgrade is not this; test_upgrade_unverified_without_source is that unverified upgrade",
        ),
    },
    Row {
        name: "test_upgrade_rejects_non_v1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_upgrade_rejects_non_v1: upgrade of a v2 baseline raises BaselineError matching requires; missing stop: that requires error together; The deterministic upgrade is not this; test_upgrade_deterministic is that deterministic upgrade",
        ),
    },
    Row {
        name: "test_upgrade_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_upgrade_deterministic: two upgrades of the same v1 baseline with no findings return equal document text; missing stop: that equal text together; The non-v1 rejection is not this; test_upgrade_rejects_non_v1 is that non-v1 rejection",
        ),
    },
    Row {
        name: "test_check_missing_baseline_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_missing_baseline_fails: check with a missing baseline exits 2 and the lowercased stderr contains not found; missing stop: that exit 2 and that not found stderr together; A scan invocation is not this; test_scan_baseline_suppresses is that scan invocation",
        ),
    },
    Row {
        name: "test_scan_baseline_suppresses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_baseline_suppresses: scan with json, using a baseline written by an earlier scan, reports invalid 0 and healthy 1 and exits 0; missing stop: that invalid count, that healthy count, and that exit 0 together; A check invocation is not this; test_check_missing_baseline_fails is that check invocation",
        ),
    },
    Row {
        name: "test_scan_v2_baseline_survives_tree_rename",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_v2_baseline_survives_tree_rename: scan with json of the relocated tree, using a baseline written from the original tree, reports invalid 0 and healthy 1 and exits 0; the docstring is not an assertion; the relocation comment is not an assertion; missing stop: that invalid count, that healthy count, and that exit 0 together; The unmoved scan is not this; test_scan_baseline_suppresses is that unmoved scan",
        ),
    },
    Row {
        name: "test_baseline_flags_mutually_exclusive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_baseline_flags_mutually_exclusive: check with both baseline and write-baseline raises SystemExit with code 2; missing stop: that exit code together; A scan invocation is not this; test_scan_v2_baseline_survives_tree_rename is that scan invocation",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_baseline_v2_round_trip",
    "test_load_v1_still_supported",
    "test_load_missing_fails",
    "test_load_malformed_v1_fails",
    "test_load_malformed_v2_fails",
    "test_load_wrong_schema_fails",
    "test_file_role_normalizes_spelling",
    "test_file_role_bare_name_uses_cwd",
    "test_v2_key_path_spelling_independent",
    "test_v2_key_immediate_parent_rename_differs",
    "test_check_write_v2_then_baseline",
    "test_check_v2_baseline_survives_relative_invoke",
    "test_v1_baseline_still_suppresses_via_v1_leg",
    "test_ambiguous_v2_key_suppresses_nothing",
    "test_upgrade_unverified_without_source",
    "test_upgrade_verified_with_source",
    "test_upgrade_rejects_non_v1",
    "test_upgrade_deterministic",
    "test_check_missing_baseline_fails",
    "test_scan_baseline_suppresses",
    "test_scan_v2_baseline_survives_tree_rename",
    "test_baseline_flags_mutually_exclusive",
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

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_baseline_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 317);
}

#[test]
fn pinned_test_baseline_row_count_equals_twenty_two() {
    assert_eq!(ROWS.len(), 22);
    assert_eq!(PINNED_TEST_COUNT, 22);
    assert_eq!(PINNED_NAMES.len(), 22);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_baseline_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 22);
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
    assert_python_commit_one_space(&json, "cli");
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
    assert_eq!(not_applicable, 22);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
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
