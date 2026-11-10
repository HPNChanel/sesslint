//! Dispositions for the twenty-one `def test_` functions in pinned
//! `tests/checks/test_durable_prefix.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (388 splitlines). Exactly
//! twenty-one test functions, in module order. One is parametrized,
//! `test_violation_fixtures_fire_via_api`, with two cells. That function is
//! one row covering both cells. The helpers `_ev`, `_ctx`, `_rollout`, and
//! `_msg` are not tests. Each row is the whole function. A `check_file` is
//! not `load_codex_rollout`. A load is not `check_durable_prefix`. An empty
//! SL206 list is not an empty findings list. A comment is not an assertion.
//! Rollout records are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or api
//! functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33
//! parser-metadata vectors at this pin and none is one of these twenty-one
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for envelopes, directory limits, discovery, module constants, plan and
//! repair rejection, thresholds, and validate_session. None of those 77 is
//! one of these twenty-one functions.
//! `parity/vectors/checks.durable_prefix/vectors.json` has six ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `module_all_exports_only_check_durable_prefix`,
//! `no_codex_marker_empty_findings`,
//! `non_durable_tail_no_claim_empty_findings`,
//! `durable_interleaved_non_durable_not_a_gap_empty_findings`,
//! `reasoning_all_missing_encrypted_content_empty_findings`, and
//! `bool_ordinal_ignored_empty_findings`. That corpus is not a Covered
//! source. Those similar names are not these twenty-one functions.
//! `bool_ordinal_ignored_empty_findings` is one of four malformed markers,
//! not the whole pytest. `checks.runner`, `adapters.codex_rollout`, and
//! `context` are the same old pin and are not Covered sources. Therefore
//! every row is NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 21;
const PINNED_SPLITLINES: usize = 388;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A `check_file` is not `load_codex_rollout`. A load is
/// not `check_durable_prefix`. An empty SL206 list is not an empty findings
/// list. A comment is not an assertion. `not_applicable` names the missing
/// stop.
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
        name: "test_conformance_healthy_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conformance_healthy_stays_clean: the conformance healthy file has no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; the healthy_min fixture is not this pytest; test_healthy_min_stays_clean is that fixture",
        ),
    },
    Row {
        name: "test_healthy_min_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_healthy_min_stays_clean: healthy_min has no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; the conformance file is not this pytest; test_conformance_healthy_stays_clean is that file",
        ),
    },
    Row {
        name: "test_nondurable_interleave_is_legitimate",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nondurable_interleave_is_legitimate: an event_msg and a turn_context inside the durable range produce no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; a comment is not an assertion; the records are not copied here; the durable-gap fixture is not this pytest; test_durable_gap_fires_once is that fixture",
        ),
    },
    Row {
        name: "test_trailing_nondurable_fires_once_with_ordinals",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_trailing_nondurable_fires_once_with_ordinals: one SL206 warning, source line 6, divergence trailing-non-durable, expected durable ordinal 5, last durable ordinal 4, tail ordinal 5, tail family event_msg, and inherited prefix ordinal 5; missing stop: all of those together; all of those are one row; the constructed claim test asserts only one SL206 plus inherited 4 and expected 4, and is not this pytest; test_trailing_requires_inherited_prefix_claim is that test",
        ),
    },
    Row {
        name: "test_trailing_requires_inherited_prefix_claim",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_trailing_requires_inherited_prefix_claim: one SL206, inherited prefix ordinal 4, and expected durable ordinal 4; it does not assert the line, the severity, or the tail family; missing stop: those three together; the records are not copied here; a comment is not an assertion; the fixture trailing test is not this pytest; test_trailing_nondurable_fires_once_with_ordinals is that test",
        ),
    },
    Row {
        name: "test_bare_telemetry_tail_without_claim_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bare_telemetry_tail_without_claim_silent: a telemetry tail with no inherited-prefix claim has no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; the records are not copied here; a comment is not an assertion; the claim test is not this pytest; test_trailing_requires_inherited_prefix_claim is that test",
        ),
    },
    Row {
        name: "test_claim_within_durable_coverage_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_claim_within_durable_coverage_silent: a claim of ordinal 2 that the durable prefix covers, with telemetry after it, has no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; the records are not copied here; a comment is not an assertion; the bare tail has no claim and is not this pytest; test_bare_telemetry_tail_without_claim_silent is that tail",
        ),
    },
    Row {
        name: "test_durable_gap_fires_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_durable_gap_fires_once: one SL206, source line 3, divergence durable-gap, missing ordinal 2, and last durable ordinal 4; it does not assert severity; missing stop: those fields together with the one finding; the parametrized fixture test only asserts that some SL206 exists and is not this pytest; test_violation_fixtures_fire_via_api is that test",
        ),
    },
    Row {
        name: "test_missing_required_field_mixed_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_required_field_mixed_fires: one SL206, divergence missing-required-field, field encrypted_content, item family reasoning, missing count 1, present count 1, and first missing ordinal 2; missing stop: all of those together; all of those are one row; the uniform-absence test is not this pytest; test_uniform_absence_of_field_silent is that test",
        ),
    },
    Row {
        name: "test_uniform_absence_of_field_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_uniform_absence_of_field_silent: two reasoning items without the field have no SL206; missing stop: that absence of SL206; an empty SL206 list is not an empty findings list; the records are not copied here; a comment is not an assertion; the mixed fixture is not this pytest; test_missing_required_field_mixed_fires is that fixture",
        ),
    },
    Row {
        name: "test_gap_beyond_durable_range_not_a_hole",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_gap_beyond_durable_range_not_a_hole: durable-gap is absent from the divergence set; it does not assert that the finding list is empty; missing stop: that absence from the divergence set; a load is not check_durable_prefix; a check_file is not load_codex_rollout; the records are not copied here; a comment is not an assertion; the durable-gap fixture asserts one durable-gap and is not this pytest; test_durable_gap_fires_once is that fixture",
        ),
    },
    Row {
        name: "test_no_ordinals_no_markers_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_ordinals_no_markers_silent: two events without markers produce an empty finding list; missing stop: that empty finding list; the zero-durable test has durable-false markers and is not this pytest; test_zero_durable_records_silent is that test",
        ),
    },
    Row {
        name: "test_zero_durable_records_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_zero_durable_records_silent: two durable-false markers produce an empty finding list; missing stop: that empty finding list; the no-marker test is not this pytest; test_no_ordinals_no_markers_silent is that test",
        ),
    },
    Row {
        name: "test_malformed_codex_markers_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_codex_markers_ignored: a non-mapping marker, a string ordinal, a bool ordinal, and one usable ordinal produce an empty finding list; missing stop: all four markers together; all four markers are one row; the comment about ordinal 2 is not an extra assertion; a comment is not an assertion; the zero-durable test is not this pytest; test_zero_durable_records_silent is that test",
        ),
    },
    Row {
        name: "test_non_codex_adapter_skips_rule",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_codex_adapter_skips_rule: a claude adapter yields no SL206, SL206 is not performed, and the skip pair is SL206 with adapter-not-applicable; missing stop: all three together; all three are one row; an empty SL206 list is not an empty findings list; the select test is not this pytest; test_select_sl206_runs is that test",
        ),
    },
    Row {
        name: "test_select_sl206_runs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_sl206_runs: select SL206 makes the finding codes exactly SL206; missing stop: that exact code list; the ignore test asserts an empty code list and is not this pytest; test_ignore_sl206_suppresses is that test; the trailing fixture test asserts evidence and is not this pytest; test_trailing_nondurable_fires_once_with_ordinals is that test",
        ),
    },
    Row {
        name: "test_ignore_sl206_suppresses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ignore_sl206_suppresses: ignore SL206 makes the finding codes exactly empty; missing stop: that empty code list; the select test is not this pytest; test_select_sl206_runs is that test",
        ),
    },
    Row {
        name: "test_determinism_replay_identical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism_replay_identical: two checks of the trailing fixture have equal SL206 findings and equal fingerprints; missing stop: both equalities together; both equalities are one row; the trailing evidence test is not this pytest; test_trailing_nondurable_fires_once_with_ordinals is that test",
        ),
    },
    Row {
        name: "test_content_free_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_content_free_evidence: every SL206 evidence value is an int, a string, or null; every string is in the allowlist of divergence names, the field name, the reasoning family, and the envelope family names; and token_count is absent from the dumped report or event_msg is present; missing stop: all of that together; all of that is one row; a payload is not copied here; the trailing evidence test asserts specific ordinals and is not this pytest; test_trailing_nondurable_fires_once_with_ordinals is that test",
        ),
    },
    Row {
        name: "test_adapter_populates_codex_extra",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_populates_codex_extra: the first event is durable with ordinal 0, envelope session_meta, and start ordinal 2; the second is durable reasoning without encrypted content; the third is not durable and is event_msg; missing stop: all three events together; all three events are one row; a check_file is not this load; the records are not copied here; the gap-beyond test loads and then calls check_durable_prefix and is not this pytest; test_gap_beyond_durable_range_not_a_hole is that test",
        ),
    },
    Row {
        name: "test_violation_fixtures_fire_via_api",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_violation_fixtures_fire_via_api: both cells, sl206_durable_gap and sl206_missing_field, each have at least one SL206; neither cell asserts the evidence fields; missing stop: both cells together; both cells are one row; the unit gap test is not this pytest; test_durable_gap_fires_once is that test; the unit field test is not this pytest; test_missing_required_field_mixed_fires is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conformance_healthy_stays_clean",
    "test_healthy_min_stays_clean",
    "test_nondurable_interleave_is_legitimate",
    "test_trailing_nondurable_fires_once_with_ordinals",
    "test_trailing_requires_inherited_prefix_claim",
    "test_bare_telemetry_tail_without_claim_silent",
    "test_claim_within_durable_coverage_silent",
    "test_durable_gap_fires_once",
    "test_missing_required_field_mixed_fires",
    "test_uniform_absence_of_field_silent",
    "test_gap_beyond_durable_range_not_a_hole",
    "test_no_ordinals_no_markers_silent",
    "test_zero_durable_records_silent",
    "test_malformed_codex_markers_ignored",
    "test_non_codex_adapter_skips_rule",
    "test_select_sl206_runs",
    "test_ignore_sl206_suppresses",
    "test_determinism_replay_identical",
    "test_content_free_evidence",
    "test_adapter_populates_codex_extra",
    "test_violation_fixtures_fire_via_api",
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
fn pinned_test_durable_prefix_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 388);
}

#[test]
fn pinned_test_durable_prefix_row_count_equals_twenty_one() {
    assert_eq!(ROWS.len(), 21);
    assert_eq!(PINNED_TEST_COUNT, 21);
    assert_eq!(PINNED_NAMES.len(), 21);
}

#[test]
fn every_pinned_test_durable_prefix_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 21);
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
        assert!(
            !names.contains(id),
            "cli id {id} is one of the twenty-one functions"
        );
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
    assert_eq!(not_applicable, 21);

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
        assert!(
            !names.contains(id),
            "api id {id} is one of the twenty-one functions"
        );
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
