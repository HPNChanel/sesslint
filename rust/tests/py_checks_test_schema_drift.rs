//! Dispositions for the thirteen `def test_` functions in pinned
//! `tests/checks/test_schema_drift.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (187 splitlines). Exactly
//! thirteen test functions, in module order. None is parametrized. The helpers
//! `_sl304` and `_load` are not tests. Each row is the whole function.
//! A DriftTracker call is not load_claude_code. A load is not check_file. A
//! comment is not an assertion. Session lines, timestamps, and message text
//! are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these thirteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these thirteen
//! functions.
//! `parity/vectors/adapters.drift/vectors.json` has sixteen ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `module_exports`,
//! `version_chain_first_difference`, `version_baseline_only_flush_empty`,
//! `version_unsupported_marker_sets_sl301`,
//! `unsupported_before_baseline_suppresses`, `note_unsupported_clears_flush`,
//! `unsupported_after_buffer_suppresses_flush`,
//! `signature_foreign_turn_context`, `signature_dedup_keeps_first_coordinates`,
//! `signature_dedup_and_cap`, `cap_full_advances_baseline_drops_version_row`,
//! `version_string_equality_not_numeric`, `version_and_signature_key_distinct`,
//! `native_signature_silent_for_own_format`,
//! `gap_flush_single_buffered_signature`, and
//! `fresh_tracker_flush_empty_without_steps`. That corpus is not a Covered
//! source. `version_chain_first_difference` is not the whole version-chain
//! pytest. `signature_foreign_turn_context` is not the five-observation pytest.
//! `signature_dedup_and_cap` is not the foreign-type loop. `profiles.profile`
//! is the same old pin and is not a Covered source. There is no
//! `checks.schema_drift` corpus. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or profile
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 187;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A DriftTracker call is not load_claude_code. A load is
/// not check_file. A comment is not an assertion. The repeated same marker is
/// one row. Both bounds of the cap test are one row. Both phases of the
/// gating test are one row. `not_applicable` names the missing stop and the
/// nearest different test.
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
        name: "test_tracker_version_chain",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_tracker_version_chain: one finding, drift_kind version, previous_marker 1, and observed_marker 0.1; missing stop: that one finding and those evidence fields together; the repeated same marker is part of that one row; it does not assert the field name; a comment is not an assertion; version_chain_first_difference is not the whole version-chain pytest; the version-drift fixture is a load and is not this tracker call; test_fixture_version_drift is that load",
        ),
    },
    Row {
        name: "test_tracker_unsupported_suppresses_all",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_tracker_unsupported_suppresses_all: a supported transition, a signature, and then an unsupported marker yield an empty finding list; missing stop: that empty finding list after those observations; all three observations are one row; it does not assert SL301; the unsupported fixture is not this tracker call; test_fixture_unsupported_precedence is that load",
        ),
    },
    Row {
        name: "test_tracker_signature_foreign_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_tracker_signature_foreign_only: five observations produce one finding whose drift_kind is signature, whose observed_marker is turn_context, and whose observed_format is codex-rollout; missing stop: that one finding and those evidence fields together; the own type, the shared type, the unknown string, and the non-string are part of that one row; signature_foreign_turn_context is not the five-observation pytest; the splice fixture does not assert the marker and is not this tracker call; test_fixture_foreign_splice is that load",
        ),
    },
    Row {
        name: "test_tracker_signature_dedupes_and_caps",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_tracker_signature_dedupes_and_caps: three identical signatures and then every foreign signature type produce a signature-finding count equal to the minimum of the foreign-type count and the transition cap, and the total finding count is at most the cap; missing stop: both bounds together; both bounds are one row; signature_dedup_and_cap is not the foreign-type loop; the multi-transition fixture is not this tracker call; test_fixture_multi_transition_cap is that load",
        ),
    },
    Row {
        name: "test_evidence_is_structural",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_evidence_is_structural: the evidence keys are a subset of the eight-key allowlist and the severity is WARNING; missing stop: that allowlist subset and that severity together; both are one row; it does not assert the record id; the splice fixture asserts severity and is not this tracker call; test_fixture_foreign_splice is that load",
        ),
    },
    Row {
        name: "test_fixture_foreign_splice",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_foreign_splice: the claude load has exactly one SL304, drift_kind signature, observed_format codex-rollout, and severity WARNING; missing stop: that one SL304, that drift_kind, that observed_format, and that severity together; it does not assert the observed marker; a comment is not an assertion; the tracker signature test is not this load; test_tracker_signature_foreign_only is that tracker call",
        ),
    },
    Row {
        name: "test_fixture_version_drift",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_version_drift: the claude load has exactly one SL304, drift_kind version, previous_marker 1, and observed_marker 0.1; missing stop: that one SL304 and those evidence fields together; it does not assert severity; the tracker version chain is not this load; test_tracker_version_chain is that tracker call",
        ),
    },
    Row {
        name: "test_fixture_compatible_bump_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_compatible_bump_clean: the compatible-bump load has an empty SL304 list; missing stop: that empty SL304 list; it does not assert that every other code is absent; a comment is not an assertion; the unsupported fixture is not this pytest; test_fixture_unsupported_precedence is that pytest",
        ),
    },
    Row {
        name: "test_fixture_unsupported_precedence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_unsupported_precedence: the unsupported-version load has an empty SL304 list and at least one SL301; missing stop: that empty SL304 list and that SL301 together; both are one row; the tracker suppression test does not assert SL301 and is not this load; test_tracker_unsupported_suppresses_all is that tracker call",
        ),
    },
    Row {
        name: "test_fixture_multi_transition_cap",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_multi_transition_cap: the multi-transition load has an SL304 count equal to the transition cap; missing stop: that SL304 count; it does not assert the foreign-type minimum; a comment is not an assertion; the tracker cap test is not this load; test_tracker_signature_dedupes_and_caps is that tracker call",
        ),
    },
    Row {
        name: "test_codex_version_drift",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_version_drift: the codex load has one SL304, drift_kind version, and field rollout_version; missing stop: that one SL304, that drift_kind, and that field together; it does not assert the marker strings; the claude version fixture is not this load; test_fixture_version_drift is that load",
        ),
    },
    Row {
        name: "test_gating_via_rule_selection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_gating_via_rule_selection: the unfiltered check_file has at least one SL304, and ignoring SL304 through the neutral profile leaves an empty SL304 list; missing stop: both phases together; both phases are one row; it does not assert the unfiltered evidence; the splice load is not this check_file pair; test_fixture_foreign_splice is that load",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism: two check_file calls have equal fingerprints for every finding, not only SL304; missing stop: that fingerprint equality for every finding; the cap fixture asserts a count and is not this pytest; test_fixture_multi_transition_cap is that pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_tracker_version_chain",
    "test_tracker_unsupported_suppresses_all",
    "test_tracker_signature_foreign_only",
    "test_tracker_signature_dedupes_and_caps",
    "test_evidence_is_structural",
    "test_fixture_foreign_splice",
    "test_fixture_version_drift",
    "test_fixture_compatible_bump_clean",
    "test_fixture_unsupported_precedence",
    "test_fixture_multi_transition_cap",
    "test_codex_version_drift",
    "test_gating_via_rule_selection",
    "test_determinism",
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
fn pinned_checks_test_schema_drift_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 187);
}

#[test]
fn pinned_checks_test_schema_drift_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
    assert_eq!(PINNED_NAMES.len(), 13);
}

#[test]
fn every_pinned_checks_test_schema_drift_test_has_one_disposition() {
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
    assert_eq!(not_applicable, 13);

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
