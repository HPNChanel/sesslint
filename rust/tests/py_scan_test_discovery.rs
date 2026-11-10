//! Dispositions for the eleven `def test_` functions in pinned
//! `tests/scan/test_discovery.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (164 splitlines). Exactly
//! eleven test functions. None is parametrized. `SESSION_LINE` is not a test.
//! A skip and the assertion that follows it are one row. A comment is not an
//! assertion. A docstring is not an assertion. Record ids, message texts, and
//! session documents are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `discover_session_roots` or
//! `main` without a `Cargo.toml` change. This test does not call product
//! functions.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `Disposition::Covered` exists only so a later
//! whole-pytest vector can be claimed. `parity/vectors/cli/vectors.json` has
//! 33 ids at this pin and none of those ids is one of these eleven
//! functions. The five CLI scan tests have no CLI vector.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for module
//! `sesslint.api`. None of those 77 is one of these eleven functions.
//! `discover_agents_empty` returns an empty root list.
//! `discover_agents_reordered` asks for codex then claude and returns that
//! order with paths and sources. It is not the no-argument order pytest.
//! `discover_defaults` asserts both sources are default. The default-home
//! pytest does not assert the codex source. `discover_env_both_agents` passes
//! an explicit agents list. The env-override pytest does not.
//! `discover_env_override_mixed` uses a lowercase key and padded values.
//! `discover_classify_nondir_codex_sessions` asserts source default as well
//! as exists false. The missing-and-nondir pytest asserts exists false only.
//! `discover_claude_symlink` expects exists false and source default and has
//! no host skip. `discover_unknown_cursor` raises ValueError and asserts the
//! message. The unknown-agent pytest does not assert the message. None of
//! those is the whole pytest.
//!
//! `parity/vectors/discovery/vectors.json` has 12 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `claude_two_part_jsonl_accepted`, `claude_two_part_non_jsonl_rejected`,
//! `claude_subagent_accepted_when_enabled`,
//! `claude_subagent_rejected_when_disabled`,
//! `claude_four_part_requires_subagents_dir`,
//! `claude_four_part_requires_agent_prefix`,
//! `codex_rollout_shallow_accepted`, `codex_rollout_nested_accepted`,
//! `codex_non_rollout_name_rejected`, `codex_rollout_non_jsonl_rejected`,
//! `unknown_agent_value_error`, and `not_under_root_before_agent_check`.
//! `unknown_agent_value_error` is not this pytest. That old pin is not a
//! Covered source.
//!
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to that old pin:
//! `module_constants`, `aggregate_by_code_exact`,
//! `aggregate_by_code_sort_order`, `aggregate_worst_files_exact`,
//! `aggregate_worst_files_excludes_healthy`, `aggregate_top_one`,
//! `aggregate_top_zero`, `aggregate_top_negative`, `aggregate_group_by_none`,
//! `aggregate_group_by_invalid`, `aggregate_deterministic`,
//! `session_link_wire_round_trip`, `rollout_uuid_00`, `rollout_uuid_01`,
//! `rollout_uuid_02`, `rollout_uuid_03`, `looks_pathy_00`, `looks_pathy_01`,
//! `looks_pathy_02`, `looks_pathy_03`, and `looks_pathy_04`.
//! `parity/vectors/cli._scan_args/vectors.json` has 9 ids on that old pin:
//! `omitted_fields_pin_defaults`, `recursive_always_true`,
//! `jobs_positive_integer`, `jobs_non_integer_token`, `jobs_below_one`,
//! `explicit_fields_and_rule_codes`, `gap_jobs_auto_cpu_count`,
//! `gap_jobs_zero_cpu_count`, and `gap_jobs_positive_i64_overflow`. Do not
//! use those corpora as Covered. An `e91d50b2` corpus is not a Covered
//! source.
//!
//! Therefore every row is NotApplicable. `not_applicable` names the missing
//! stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 164;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A docstring is not an assertion. A comment is not an
/// assertion. None is parametrized. A skip and the assertion that follows it
/// are one row. `not_applicable` names the missing stop.
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
        name: "test_discovery_order_is_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_order_is_deterministic: discover_session_roots with no arguments returns agents claude then codex. It does not assert paths or sources. missing stop: that two-agent order together. discover_agents_reordered asks for the opposite order and is not this",
        ),
    },
    Row {
        name: "test_discovery_env_overrides",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_env_overrides: both env roots exist, both sources are env, the claude path is the projects directory, and the codex path is the sessions directory. It does not pass an agents list. missing stop: those two paths, those two sources, and those two exists flags together. discover_env_both_agents passes an explicit agents list and is not this",
        ),
    },
    Row {
        name: "test_discovery_default_home",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_default_home: the claude path is the projects directory, its source is default, and it exists. The codex path is the sessions directory and it exists. It does not assert the codex source. missing stop: that claude path, that default source, that claude exists flag, that codex path, and that codex exists flag together. discover_defaults asserts the codex source and is not this",
        ),
    },
    Row {
        name: "test_discovery_missing_and_nondir_roots",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_missing_and_nondir_roots: both exists flags are false. It does not assert the sources. One root is missing and the other is a file. The comment is not an assertion. missing stop: those two false exists flags together. discover_classify_nondir_codex_sessions asserts the sources and is not this",
        ),
    },
    Row {
        name: "test_discovery_unknown_agent_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_unknown_agent_rejected: discover_session_roots of the unknown agent raises ValueError. It does not assert the message. missing stop: that ValueError together. discover_unknown_cursor asserts the message and is not this. unknown_agent_value_error is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_discovery_symlinked_root_not_followed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_symlinked_root_not_followed: the host skip and the false exists flag are one row. The call asks for claude only. It does not assert the source. missing stop: that skip and that false exists flag together. discover_claude_symlink has no skip and is not this",
        ),
    },
    Row {
        name: "test_cli_scan_agent_discovers_env_root",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_agent_discovers_env_root: scan --agent claude --json exits 0 or 1, the schema is sesslint.scan-report/v1, and totals.total is at least 1. It does not assert a single exit code. missing stop: that exit pair, that schema, and that total together. The API env-override test is not this CLI. test_discovery_env_overrides is the API env-override test and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_scan_agent_missing_root_is_skipped",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_agent_missing_root_is_skipped: scan --agent codex --json exits 0, skipped is 1, and skipped_reason is agent-root-missing. missing stop: that exit, that skipped count, and that reason together. The nondirectory skip is not this. test_cli_scan_agent_nondir_root_is_skipped is the nondirectory skip and is not this",
        ),
    },
    Row {
        name: "test_cli_scan_agent_nondir_root_is_skipped",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_agent_nondir_root_is_skipped: scan --agent codex --json exits 0 and skipped_reason is agent-root-not-directory. It does not assert the skipped count. missing stop: that exit and that reason together. The missing-root skip is not this. test_cli_scan_agent_missing_root_is_skipped is the missing-root skip and is not this",
        ),
    },
    Row {
        name: "test_cli_scan_explicit_path_overrides_agent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_explicit_path_overrides_agent: scan of the explicit directory with --agent codex --json exits 0, stderr contains overrides --agent, and skipped is 0. The comment is not an assertion. missing stop: that exit, that stderr fragment, and that zero skipped together. The merged-roots scan is not this. test_cli_scan_agent_all_merges_roots is the merged-roots scan and is not this",
        ),
    },
    Row {
        name: "test_cli_scan_agent_all_merges_roots",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_agent_all_merges_roots: scan --agent all --json has totals.total 2 and exits 0 or 1. missing stop: that total and that exit pair together. The explicit-path scan is not this. test_cli_scan_explicit_path_overrides_agent is the explicit-path scan and is not this",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_discovery_order_is_deterministic",
    "test_discovery_env_overrides",
    "test_discovery_default_home",
    "test_discovery_missing_and_nondir_roots",
    "test_discovery_unknown_agent_rejected",
    "test_discovery_symlinked_root_not_followed",
    "test_cli_scan_agent_discovers_env_root",
    "test_cli_scan_agent_missing_root_is_skipped",
    "test_cli_scan_agent_nondir_root_is_skipped",
    "test_cli_scan_explicit_path_overrides_agent",
    "test_cli_scan_agent_all_merges_roots",
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
fn pinned_scan_test_discovery_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 164);
}

#[test]
fn pinned_scan_test_discovery_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
    assert_eq!(PINNED_NAMES.len(), 11);
}

#[test]
fn every_pinned_scan_test_discovery_test_has_one_disposition() {
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
    // `parity/vectors/cli/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "cli vectors python_commit spacing does not match {needle}"
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
