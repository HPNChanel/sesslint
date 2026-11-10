//! Dispositions for the eight `def test_` functions in pinned
//! `tests/test_scan_filters.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (93 splitlines). Exactly
//! eight test functions, in module order. None is parametrized. Each row is
//! the whole function. A library total is not a CLI exit. A dotted extension
//! is not a bare name. A directory exclude is not one relative path. The
//! helper `_tree` and the constant `CORRUPT` are not tests. `_tree` builds
//! four files and is not a row. Those file bytes are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-command hints, removed-flag hints, verbose
//! provenance, and removed-subcommand exits. None of those vectors is one of
//! these eight functions. `create_parser_subcommand_names` lists the name
//! `scan` and stops at `GAP-cli-init-create-parser`. `check_exit_constants`
//! records the help line that a session with findings exits 1. That help line
//! is not `test_cli_exclude_and_ext`.
//! `parity/vectors/scan/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its vectors are module
//! constants, aggregate scans, `session_link_wire_round_trip`,
//! `rollout_uuid_00` through `rollout_uuid_03`, and `looks_pathy_00` through
//! `looks_pathy_04`. None of those is `scan_path` with an extension allowlist
//! or an exclude, and none is `scan --ext` or `scan --exclude`. They are not
//! among the 33 cli vectors and are not used to mark a row covered.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call scan or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 8;
const PINNED_SPLITLINES: usize = 93;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. A library total is not a CLI exit.
/// A dotted extension is not a bare name. A directory exclude is not one
/// relative path. `not_applicable` names the missing stop.
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
        name: "test_no_filter_scans_everything",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_filter_scans_everything: scan_path of the four-file tree with recursive true has totals.total 4; missing stop: that one total; that one total is the whole function; a library total is not a CLI exit; the extension allowlist is not this pytest; test_ext_allowlist is the dotted .jsonl allowlist with totals.total 2 and totals.invalid 2 and is not this unfiltered total",
        ),
    },
    Row {
        name: "test_ext_allowlist",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ext_allowlist: the same tree with ext containing .jsonl has totals.total 2 and totals.invalid 2; missing stop: both totals; both are one row; a dotted extension is not a bare name; the bare-name test does not assert invalid; test_ext_accepts_bare_names asserts totals.total 2 for ext jsonl with no leading dot and does not assert invalid",
        ),
    },
    Row {
        name: "test_ext_accepts_bare_names",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ext_accepts_bare_names: the same tree with ext containing jsonl and no leading dot has totals.total 2; missing stop: that one total; it does not assert invalid; a dotted extension is not a bare name; the dotted allowlist is not this pytest; test_ext_allowlist asserts totals.total 2 and totals.invalid 2 for ext .jsonl and is not this bare name",
        ),
    },
    Row {
        name: "test_exclude_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_exclude_dir: exclude containing nested has totals.total 3, and no file path contains nested; missing stop: both assertions; both are one row; a directory exclude is not one relative path; the relative-path exclude is not this pytest; test_exclude_relative_path excludes nested/deep.jsonl, asserts totals.total 3, and asserts no path ends with deep.jsonl",
        ),
    },
    Row {
        name: "test_exclude_glob",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_exclude_glob: exclude containing *.jsonl has totals.total 2, and no path ends with .jsonl; missing stop: both assertions; both are one row; the directory exclude is not this pytest; test_exclude_dir excludes the directory name nested, asserts totals.total 3, and asserts no path contains nested",
        ),
    },
    Row {
        name: "test_exclude_relative_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_exclude_relative_path: exclude containing nested/deep.jsonl has totals.total 3, and no path ends with deep.jsonl; missing stop: both assertions; both are one row; a directory exclude is not one relative path; the directory-name exclude is not this one file; test_exclude_dir excludes nested and asserts no path contains nested",
        ),
    },
    Row {
        name: "test_cli_exclude_and_ext",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_exclude_and_ext: scan with --ext .jsonl, --exclude nested, and --json; totals total is 1, totals invalid is 1, and the exit is 1; missing stop: all three; all three are one row; a library total is not a CLI exit; the config-file test does not assert invalid; test_config_exclude_and_ext reads sesslint.toml and scan --json with neither flag, asserts totals total 1 and exit 1, and does not assert invalid",
        ),
    },
    Row {
        name: "test_config_exclude_and_ext",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_exclude_and_ext: sesslint.toml sets ext to .jsonl and exclude to nested, then scan --json passes neither flag; totals total is 1 and the exit is 1; missing stop: both; both are one row; it does not assert invalid; a library total is not a CLI exit; the CLI flag test is not this config; test_cli_exclude_and_ext passes --ext .jsonl and --exclude nested and also asserts totals invalid 1",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_no_filter_scans_everything",
    "test_ext_allowlist",
    "test_ext_accepts_bare_names",
    "test_exclude_dir",
    "test_exclude_glob",
    "test_exclude_relative_path",
    "test_cli_exclude_and_ext",
    "test_config_exclude_and_ext",
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
fn pinned_test_scan_filters_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 93);
}

#[test]
fn pinned_test_scan_filters_row_count_equals_eight() {
    assert_eq!(ROWS.len(), 8);
    assert_eq!(PINNED_TEST_COUNT, 8);
}

#[test]
fn every_pinned_test_scan_filters_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 8);
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
