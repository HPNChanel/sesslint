//! Dispositions for the twenty-five test functions in pinned
//! `tests/scan/test_index_divergence.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (310 splitlines). Exactly
//! twenty-five test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_sl402`, `_write_session`, `_write_index`, and
//! `_human_output` are not tests. `FIXTURES_DIR`, `DIVERGENCE`, `CODEX_UA`,
//! and `CODEX_UB` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these twenty-five names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids and module
//! `sesslint.api`. None of those 77 is one of these twenty-five names.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `parity/vectors/indexes/vectors.json` has 7 ids on that old pin.
//! `codex_jsonl_malformed_mid_line` reads one index. It is not
//! `test_codex_malformed_mid_line`, and that old pin is not a Covered source.
//! `parity/vectors/cli._render/vectors.json` is on that old pin. A header
//! fragment is not a whole pytest. Those corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `scan_path`, `check_file`,
//! or `format_scan_report_human` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 25;
const PINNED_SPLITLINES: usize = 310;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these twenty-five functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A header fragment is not a whole pytest.
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
        name: "test_missing_member_flags_unindexed_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_member_flags_unindexed_file: a recursive scan has one SL402 whose path ends with sess-c.jsonl, severity WARNING, divergence file-not-in-index, resolution missing, index_entry_count 2, and session_id_hash8 length 8, and the whole report has SL402 count 1; missing stop: that one hit, that WARNING severity, that missing resolution, that entry count, that hash length, and that whole-report count together; The dangling index hit is not this; test_dangling_entry_flags_index is that dangling index hit",
        ),
    },
    Row {
        name: "test_dangling_entry_flags_index",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_dangling_entry_flags_index: a recursive scan has one SL402 whose path ends with sessions-index.json, divergence index-entry-no-file, resolution dangling, and entry_id_hash8 length 8; it does not assert severity; missing stop: that one hit, that dangling resolution, and that hash length together; The malformed-index hit is not this; test_malformed_index_emits_only_malformed is that malformed-index hit",
        ),
    },
    Row {
        name: "test_malformed_index_emits_only_malformed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_index_emits_only_malformed: a recursive scan has one SL402 whose path ends with sessions-index.json, divergence index-malformed, resolution unparseable, and error_kind malformed; it does not assert severity; missing stop: that one hit, that unparseable resolution, and that malformed error kind together; The dangling index hit is not this; test_dangling_entry_flags_index is that dangling index hit",
        ),
    },
    Row {
        name: "test_truncated_index_emits_only_truncated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_truncated_index_emits_only_truncated: a recursive scan has one SL402 whose path ends with sessions-index.json, divergence index-truncated, resolution truncated, and parsed_entry_count 1; it does not assert severity; missing stop: that one hit, that truncated resolution, and that parsed count together; The silent absent index is not this; test_absent_index_is_silent is that silent absent index",
        ),
    },
    Row {
        name: "test_absent_index_is_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_absent_index_is_silent: a recursive scan has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that empty list together; The single-file check is not this; test_single_file_check_never_emits_sl402 is that single-file check",
        ),
    },
    Row {
        name: "test_single_file_check_never_emits_sl402",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_file_check_never_emits_sl402: check_file has no finding whose code is SL402, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that absent code together; The silent absent index is not this; test_absent_index_is_silent is that silent absent index",
        ),
    },
    Row {
        name: "test_select_and_ignore_gate_sl402",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_and_ignore_gate_sl402: a recursive scan ignoring SL402 has SL402 count 0, and a recursive scan selecting SL402 has SL402 count 1 whose divergence is index-entry-no-file; it does not assert severity or resolution; missing stop: that ignore, that empty list, that select, that one hit, and that divergence together; The single-file check is not this; test_single_file_check_never_emits_sl402 is that single-file check",
        ),
    },
    Row {
        name: "test_deterministic_across_jobs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_deterministic_across_jobs: a recursive scan with jobs 1 and a recursive scan with jobs 4 have equal lists of code and evidence pairs; it does not assert one code, one severity, one count, or one resolution; missing stop: that jobs pair and that equal evidence together; The sidecar silence is not this; test_non_session_sidecars_not_members is that sidecar silence",
        ),
    },
    Row {
        name: "test_non_session_sidecars_not_members",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_session_sidecars_not_members: a recursive scan of a temporary directory has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that empty list together; The jobs equality is not this; test_deterministic_across_jobs is that jobs equality",
        ),
    },
    Row {
        name: "test_filtered_file_satisfies_index_entry",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_filtered_file_satisfies_index_entry: a recursive scan that excludes sess-b.jsonl has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that exclude and that empty list together; The renamed-member silence is not this; test_renamed_file_member_via_session_id is that renamed-member silence",
        ),
    },
    Row {
        name: "test_renamed_file_member_via_session_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_renamed_file_member_via_session_id: a recursive scan of a temporary directory has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; the comment is not an assertion; missing stop: that empty list together; The idless kind list is not this; test_idless_entries_block_absence_allow_dangling is that idless kind list",
        ),
    },
    Row {
        name: "test_idless_entries_block_absence_allow_dangling",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_idless_entries_block_absence_allow_dangling: the SL402 divergence kinds equal one index-entry-no-file, so the SL402 count is 1; it does not assert severity or resolution; the comment is not an assertion; missing stop: that one-element kinds list together; The renamed-member silence is not this; test_renamed_file_member_via_session_id is that renamed-member silence",
        ),
    },
    Row {
        name: "test_baseline_suppresses_new_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_baseline_suppresses_new_findings: a second recursive scan whose baseline is the fingerprint set of the first scan's SL402 findings has an empty SL402 list, so that second SL402 count is 0; it does not assert severity or resolution; missing stop: that baseline and that empty list together; The nested one-hit scan is not this; test_nested_dirs_reconcile_per_index is that nested one-hit scan",
        ),
    },
    Row {
        name: "test_nested_dirs_reconcile_per_index",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nested_dirs_reconcile_per_index: a recursive scan has one SL402 whose path ends with sess-b.jsonl and whose divergence is file-not-in-index, so the SL402 count is 1; it does not assert severity or resolution; the comment is not an assertion; missing stop: that one hit and that divergence together; The baseline silence is not this; test_baseline_suppresses_new_findings is that baseline silence",
        ),
    },
    Row {
        name: "test_evidence_is_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_evidence_is_content_free: every SL402 evidence json lacks sess-ghost and lacks synthetic; it does not assert a count, a severity, or a resolution; missing stop: those two absent tokens together; The file-not-in-index summary is not this; test_scan_summary_line_file_not_in_index is that file-not-in-index summary",
        ),
    },
    Row {
        name: "test_scan_summary_line_file_not_in_index",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_summary_line_file_not_in_index: the human summary contains the index-divergence wording for count 1 unlisted session file, the resumable-by-explicit-id wording, and docs/codes/SL402.md; it does not assert a severity or a resolution; missing stop: that count of 1, that resumable wording, and that SL402 doc path together; The index-side summary line is not this; test_scan_summary_line_index_side_kinds is that index-side summary line",
        ),
    },
    Row {
        name: "test_scan_summary_line_index_side_kinds",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_summary_line_index_side_kinds: the dangling-fixture human summary contains the index-divergence wording for count 1 dangling entry, the malformed-fixture summary contains the malformed-index wording, and the truncated-fixture summary contains the truncated-index wording; it does not assert a code, a severity, or a resolution; missing stop: that count of 1 and those three wordings together; The file-not-in-index summary is not this; test_scan_summary_line_file_not_in_index is that file-not-in-index summary",
        ),
    },
    Row {
        name: "test_scan_summary_line_absent_when_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_summary_line_absent_when_clean: the human summary does not contain the index-divergence wording; it does not assert a code, a severity, a count, or a resolution; missing stop: that absent wording together; The clean codex scan is not this; test_codex_consistent_clean is that clean codex scan",
        ),
    },
    Row {
        name: "test_codex_consistent_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_consistent_clean: a recursive scan has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that empty list together; The silent unindexed codex member is not this; test_codex_unindexed_member_silent is that silent unindexed codex member",
        ),
    },
    Row {
        name: "test_codex_unindexed_member_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_unindexed_member_silent: a recursive scan has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; the docstring is not an assertion; missing stop: that empty list together; The clean codex scan is not this; test_codex_consistent_clean is that clean codex scan",
        ),
    },
    Row {
        name: "test_codex_dangling_entry_flags_index",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_dangling_entry_flags_index: a recursive scan has one SL402 whose path ends with session_index.jsonl, divergence index-entry-no-file, and resolution dangling; it does not assert severity; missing stop: that one hit and that dangling resolution together; The truncated codex index is not this; test_codex_truncated_tail_line is that truncated codex index",
        ),
    },
    Row {
        name: "test_codex_truncated_tail_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_truncated_tail_line: a recursive scan has one SL402 whose path ends with session_index.jsonl, divergence index-truncated, and parsed_entry_count 1; it does not assert severity or resolution; missing stop: that one hit and that parsed count together; The dangling codex index is not this; test_codex_dangling_entry_flags_index is that dangling codex index",
        ),
    },
    Row {
        name: "test_codex_malformed_mid_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_malformed_mid_line: a recursive scan has one SL402 whose path ends with session_index.jsonl and whose divergence is index-malformed, and the member path built from the first codex id has an empty SL402 list; it does not assert severity or resolution; the comment is not an assertion; missing stop: that one hit and that empty member list together; The truncated codex index is not this; test_codex_truncated_tail_line is that truncated codex index",
        ),
    },
    Row {
        name: "test_codex_index_without_sessions_subtree_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_index_without_sessions_subtree_silent: a recursive scan has an empty SL402 list, so the SL402 count is 0; it does not assert severity or resolution; missing stop: that empty list together; The content-free codex evidence is not this; test_codex_evidence_is_content_free is that content-free codex evidence",
        ),
    },
    Row {
        name: "test_codex_evidence_is_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_evidence_is_content_free: the SL402 list is non-empty, and every SL402 evidence json lacks synthetic, lacks thread_name, and lacks both codex id constants; it does not assert a numeric count, a severity, or a resolution; the comment is not an assertion; missing stop: that non-empty list and those absent tokens together; The silent codex index without a sessions subtree is not this; test_codex_index_without_sessions_subtree_silent is that silent codex index",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_missing_member_flags_unindexed_file",
    "test_dangling_entry_flags_index",
    "test_malformed_index_emits_only_malformed",
    "test_truncated_index_emits_only_truncated",
    "test_absent_index_is_silent",
    "test_single_file_check_never_emits_sl402",
    "test_select_and_ignore_gate_sl402",
    "test_deterministic_across_jobs",
    "test_non_session_sidecars_not_members",
    "test_filtered_file_satisfies_index_entry",
    "test_renamed_file_member_via_session_id",
    "test_idless_entries_block_absence_allow_dangling",
    "test_baseline_suppresses_new_findings",
    "test_nested_dirs_reconcile_per_index",
    "test_evidence_is_content_free",
    "test_scan_summary_line_file_not_in_index",
    "test_scan_summary_line_index_side_kinds",
    "test_scan_summary_line_absent_when_clean",
    "test_codex_consistent_clean",
    "test_codex_unindexed_member_silent",
    "test_codex_dangling_entry_flags_index",
    "test_codex_truncated_tail_line",
    "test_codex_malformed_mid_line",
    "test_codex_index_without_sessions_subtree_silent",
    "test_codex_evidence_is_content_free",
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
fn pinned_scan_test_index_divergence_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 310);
}

#[test]
fn pinned_scan_test_index_divergence_row_count_equals_twenty_five() {
    assert_eq!(ROWS.len(), 25);
    assert_eq!(PINNED_TEST_COUNT, 25);
    assert_eq!(PINNED_NAMES.len(), 25);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_index_divergence_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 25);
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
    assert_eq!(not_applicable, 25);

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
