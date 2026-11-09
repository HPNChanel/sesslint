//! Dispositions for the 38 `def test_` functions in pinned
//! `tests/outcome/test_outcome_engine.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (560 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` would name one id in `outcome/vectors.json` whose recorded call is
//! the same function and the same success or failure mode as that entire pinned
//! test. Those vectors are the `cases.py` cartesian sweep: 4800 `verify_outcome`
//! rows plus 18 invalid-path rows, 4818 in total. A fixture row is one slice.
//! `not_applicable` records that the slice is not the whole pytest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 38;
const OUTCOME_VECTOR_COUNT: usize = 4818;
const PINNED_SOURCE_SHA256: &str =
    "f890f8ba2b890812258b727ee9b422764b6b8afcae69b56b919b23c28464a1c3";
const VECTORS_REL: &str = "parity/vectors/outcome/vectors.json";
const MANIFEST_REL: &str = "parity/vectors/outcome/manifest.json";
const COVERAGE_REL: &str = "parity/vectors/outcome/coverage.json";
const PROVENANCE_REL: &str = "parity/vectors/outcome/PROVENANCE.json";

/// `covered` names a vector id in `outcome/vectors.json`.
/// `not_applicable` records a pinned pytest no single verify_outcome fixture row reproduces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
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
        name: "test_orders_fixture_end_to_end_against_golden",
        disposition: Disposition::NotApplicable(
            "verify_outcome on the orders fixtures compares a schema-checked report to expected_report.json, eight item statuses, and exit code 1. Outcome vectors are verify_outcome rows on contract.json and the snapshot fixtures. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at06_missing_and_duplicate_per_id_not_totals",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate with exists and count for ids a, b, and c and expects too_many, missing, VERIFIED for b, and outcome VIOLATED. Vectors record verify_outcome for an exists-only fixture contract. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at07_ineligible_items_are_not_applicable",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate with an eligibility inclusion list and expects NOT_APPLICABLE, not_eligible, and excluded_items 1. Vectors have no eligibility condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_eligibility_on_missing_field_is_undecidable",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate with eligibility gt on a missing amount and expects eligibility_undecidable. Vectors have no eligibility condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at08_before_deadline_is_pending",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate before the due window and expects PENDING awaiting_due. Vectors have no due window. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at09_missing_after_deadline_in_complete_target_is_violated",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate after the due window on an empty complete target and expects VIOLATED missing. Vectors have no due window. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at10_11_22_absence_needs_complete_current_target",
        disposition: Disposition::NotApplicable(
            "The parametrized helper run calls evaluate for five target metadata rows and expects five INCONCLUSIVE reasons. Fixture rows that mention target_incomplete or target_observed_at_unknown omit the due window and the other reasons. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_unkeyed_target_rows_block_absence",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate on unkeyed target rows and expects INCONCLUSIVE target_unkeyed_rows with unkeyed_target_rows 2. Vectors do not record that reason. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at12_late_arrival_exists_but_on_time_violated",
        disposition: Disposition::NotApplicable(
            "Two helper runs call evaluate: on_time late with late_by_seconds 1800, then the same arrival on a partial target with late_unconfirmed. Vectors have no on_time condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_on_time_uses_earliest_valid_completion",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects completed_on_time for the earliest offset completion and completion_time_unusable for a naive completion. Vectors have no on_time condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at46_47_observation_basis",
        disposition: Disposition::NotApplicable(
            "The parametrized helper run calls evaluate on an observation basis and expects observed_on_time and first_seen_after_deadline. Vectors have no on_time condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at13_17_keys_match_exactly",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects three exact-key misses and three unmatched target keys. Fixture rows compare the synthetic id field. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_integer_and_string_keys_compare_as_text",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate with source id 7 and target text 7 and expects VERIFIED. Fixture contracts compare id to id. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_invalid_keys_are_inconclusive_not_dropped",
        disposition: Disposition::NotApplicable(
            "The parametrized helper run calls evaluate on four invalid keys and expects a null key with key_missing or key_invalid. Vectors have no invalid keys. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at14_composite_namespaced_keys",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate on namespaced tenant and id keys and expects VERIFIED for t1/1 and VIOLATED missing for t2/1. Vectors use a single id field. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at15_identical_retries_merge_and_conflicts_do_not",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects a merged VERIFIED retry, source_conflict, and retried_items 2. Vectors have no equals condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at16_route_is_separate_from_existence",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects present, wrong_route, route_not_applicable, and route_undecidable together. Vectors have no route condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at18_19_session_integrity_is_a_separate_dimension",
        disposition: Disposition::NotApplicable(
            "OutcomeReport wraps evaluate with session_dimension on a fixture path, an absent path, and None. The pin expects session status no_findings or findings, link user_asserted, outcome VIOLATED, monitoring not_configured, incident not_tracked, unreadable, and not_linked. Vectors fold an injected check into verify_outcome. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at21_unproven_source_coverage_never_verifies",
        disposition: Disposition::NotApplicable(
            "Two helper runs call evaluate: a partial source stays INCONCLUSIVE with source_coverage_unproven while the item is VERIFIED, then a complete source is VERIFIED with exit code 0. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at23_mapping_problems_surface",
        disposition: Disposition::NotApplicable(
            "Two helper runs call evaluate and expect field_not_in_snapshot, then target_key_field_absent with an outcome other than VERIFIED. Vectors map id to id on exists. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_field_conditions_and_typing",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate for required, type, range, and one_of and expects the ok item VERIFIED plus type_mismatch, not_a_number, out_of_range, field_empty, and field_null. Vectors only record exists. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_csv_values_coerce_strictly",
        disposition: Disposition::NotApplicable(
            "evaluate on two CSV snapshots expects in_range and not_a_number. Vectors call verify_outcome on JSON fixtures. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_any_of_advisory_and_disabled",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects any_branch_verified, advisory field_null, disabled NOT_EVALUATED, and item VERIFIED together. Vectors have none of those conditions. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at41_violations_and_inconclusive_items_are_both_reported",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects coverage counts VIOLATED 1 and INCONCLUSIVE 1, outcome VIOLATED, and both words in the human render. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at42_naive_source_time_is_inconclusive",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate on a naive source timestamp and expects INCONCLUSIVE due_unknown. Vectors have no due window. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at45_run_status_is_not_the_outcome",
        disposition: Disposition::NotApplicable(
            "The helper calls evaluate, and the pinned success mode is the triple run_status completed, outcome VIOLATED, and exit code 1. Each vector is verify_outcome on a fixture triple. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_empty_or_unavailable_source",
        disposition: Disposition::NotApplicable(
            "Two helper runs call evaluate and expect NOT_EVALUATED with no_source_items, then INCONCLUSIVE with source_unavailable. Vectors keep a non-empty complete source. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_evaluation_instant_is_never_the_wall_clock",
        disposition: Disposition::NotApplicable(
            "verify_outcome raises EvaluationError matching instant is required, then evaluate raises EvaluationError matching precedes. A verify_outcome error row is one of those failures. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_at38_deterministic_regardless_of_record_order",
        disposition: Disposition::NotApplicable(
            "load_contract and load_snapshot read the orders fixtures, two evaluate results compare equal, and a shuffled JSONL target compares equal again. Vectors do not record that pair. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_hash_keys_hide_plain_keys",
        disposition: Disposition::NotApplicable(
            "The helper run is rewrapped with hash_keys true and expects the plain keys to be absent, a sha256 key display, key_display sha256, and a pseudonym limitation. A verify_outcome hash_keys flag on fixture id a is a different call. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_reports_are_content_free",
        disposition: Disposition::NotApplicable(
            "The helper run expects seeded field literals to stay out of the JSON and human render. Vectors do not record that scan. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_demo_snapshots_are_flagged",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate with target demo true and expects demo true and DEMO DATA in the human render. Fixture envelopes are demo false. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_every_emitted_reason_is_documented",
        disposition: Disposition::NotApplicable(
            "verify_outcome on the orders CSV and a partial JSONL target must emit only documented REASONS codes, and docs/OUTCOME.md must name every code. Vectors do not record that document scan. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_unevaluated_items_never_roll_up_to_verified",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate and expects one VERIFIED item, one NOT_EVALUATED item, outcome INCONCLUSIVE, some_items_not_evaluated, and exit code 1. Vectors have no required-field condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_extreme_numbers_and_times_do_not_crash",
        disposition: Disposition::NotApplicable(
            "The helper run calls evaluate on a huge integer, a far-future timestamp, and a year-0001 offset and expects out_of_range and two due_unknown results. Vectors have no range or due window. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_equals_compares_json_numbers_numerically",
        disposition: Disposition::NotApplicable(
            "evaluate on a CSV source and a JSON target expects values_match and two values_differ results. Vectors call verify_outcome on JSON envelopes with no equals condition. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_hashed_output_order_does_not_follow_plain_keys",
        disposition: Disposition::NotApplicable(
            "The helper run of 40 ids is rewrapped with hash_keys true and expects item keys and unmatched target keys sorted by the hash. That reorder is a different call from a hash_keys fixture row. One cartesian row is not the whole test.",
        ),
    },
    Row {
        name: "test_default_detail_lists_only_non_passing_conditions",
        disposition: Disposition::NotApplicable(
            "OutcomeReport on the helper run expects condition_detail non_passing, no conditions on the passing item, only the advisory condition on the other, summary counts, and the outcome-report schema. One cartesian row is not the whole test.",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_orders_fixture_end_to_end_against_golden",
    "test_at06_missing_and_duplicate_per_id_not_totals",
    "test_at07_ineligible_items_are_not_applicable",
    "test_eligibility_on_missing_field_is_undecidable",
    "test_at08_before_deadline_is_pending",
    "test_at09_missing_after_deadline_in_complete_target_is_violated",
    "test_at10_11_22_absence_needs_complete_current_target",
    "test_unkeyed_target_rows_block_absence",
    "test_at12_late_arrival_exists_but_on_time_violated",
    "test_on_time_uses_earliest_valid_completion",
    "test_at46_47_observation_basis",
    "test_at13_17_keys_match_exactly",
    "test_integer_and_string_keys_compare_as_text",
    "test_invalid_keys_are_inconclusive_not_dropped",
    "test_at14_composite_namespaced_keys",
    "test_at15_identical_retries_merge_and_conflicts_do_not",
    "test_at16_route_is_separate_from_existence",
    "test_at18_19_session_integrity_is_a_separate_dimension",
    "test_at21_unproven_source_coverage_never_verifies",
    "test_at23_mapping_problems_surface",
    "test_field_conditions_and_typing",
    "test_csv_values_coerce_strictly",
    "test_any_of_advisory_and_disabled",
    "test_at41_violations_and_inconclusive_items_are_both_reported",
    "test_at42_naive_source_time_is_inconclusive",
    "test_at45_run_status_is_not_the_outcome",
    "test_empty_or_unavailable_source",
    "test_evaluation_instant_is_never_the_wall_clock",
    "test_at38_deterministic_regardless_of_record_order",
    "test_hash_keys_hide_plain_keys",
    "test_reports_are_content_free",
    "test_demo_snapshots_are_flagged",
    "test_every_emitted_reason_is_documented",
    "test_unevaluated_items_never_roll_up_to_verified",
    "test_extreme_numbers_and_times_do_not_crash",
    "test_equals_compares_json_numbers_numerically",
    "test_hashed_output_order_does_not_follow_plain_keys",
    "test_default_detail_lists_only_non_passing_conditions",
];

const ABSENT_FROM_SWEEP: &[&str] = &[
    "expected_report.json",
    "target_complete.json",
    "target.jsonl",
    "source.csv",
    "fixtures/outcome/orders",
    "docs/OUTCOME.md",
    "minimal-valid.jsonl",
    "session_dimension",
    "def test_",
    "tests/outcome/test_outcome_engine.py",
    "too_many",
    "not_eligible",
    "eligibility_undecidable",
    "awaiting_due",
    "target_unkeyed_rows",
    "late_by_seconds",
    "wrong_route",
    "source_conflict",
    "source_coverage_unproven",
    "no_source_items",
    "source_unavailable",
    "some_items_not_evaluated",
    "DEMO DATA",
    "values_differ",
];

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_text(rel: &str) -> String {
    let path = repo_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn case_body(line: &str, last: bool) -> &str {
    if last {
        assert!(
            line.ends_with('}'),
            "last verify_outcome row has no trailing comma"
        );
        assert!(!line.ends_with(','), "last verify_outcome row");
        line
    } else {
        line.strip_suffix(',').expect("verify_outcome row comma")
    }
}

fn vector_line(json: &str, id: u32) -> &str {
    let marker = format!("\"id\":{id},\"input\":");
    assert_eq!(json.matches(&marker).count(), 1, "id {id}");
    let pos = json
        .find(&marker)
        .unwrap_or_else(|| panic!("outcome vectors are missing id {id}"));
    let start = json[..pos].rfind('\n').map(|index| index + 1).unwrap_or(0);
    let end = json[pos..]
        .find('\n')
        .map(|index| pos + index)
        .unwrap_or(json.len());
    let last = id + 1 == u32::try_from(OUTCOME_VECTOR_COUNT).expect("vector count");
    case_body(&json[start..end], last)
}

fn assert_once(haystack: &str, marker: &str) {
    assert_eq!(haystack.matches(marker).count(), 1, "{marker}");
}

fn quoted_field<'a>(haystack: &'a str, marker: &str) -> &'a str {
    assert_once(haystack, marker);
    let pos = haystack.find(marker).expect(marker);
    let tail = &haystack[pos + marker.len()..];
    let end = tail
        .find('"')
        .unwrap_or_else(|| panic!("unterminated {marker}"));
    assert!(end > 0, "{marker}");
    &tail[..end]
}

fn json_bool<'a>(haystack: &'a str, marker: &str) -> &'a str {
    assert_once(haystack, marker);
    let pos = haystack.find(marker).expect(marker);
    let tail = &haystack[pos + marker.len()..];
    if let Some(rest) = tail.strip_prefix("true") {
        assert!(rest.starts_with(',') || rest.starts_with('}'));
        &tail[..4]
    } else if let Some(rest) = tail.strip_prefix("false") {
        assert!(rest.starts_with(',') || rest.starts_with('}'));
        &tail[..5]
    } else {
        panic!("{marker} is not a JSON bool");
    }
}

fn input_suffix(line: &str) -> &str {
    const MARKER: &str = "\"input\":{";
    assert_once(line, MARKER);
    let pos = line.find(MARKER).expect(MARKER);
    let suffix = &line[pos..];
    assert!(
        suffix.starts_with("\"input\":{\"all_conditions\":true,")
            || suffix.starts_with("\"input\":{\"all_conditions\":false,"),
        "verify_outcome input object"
    );
    suffix
}

fn parse_id(line: &str) -> u32 {
    const MARKER: &str = "\"id\":";
    assert_once(line, MARKER);
    let pos = line.find(MARKER).expect(MARKER);
    let tail = &line[pos + MARKER.len()..];
    let end = tail
        .find(|ch: char| !ch.is_ascii_digit())
        .expect("vector id ends");
    assert!(end > 0, "vector id is an integer");
    assert!(
        tail[end..].starts_with(','),
        "vector id is followed by a comma"
    );
    tail[..end].parse().expect("vector id fits u32")
}

fn parse_as_of(input: &str) -> &str {
    const MARKER: &str = "\"as_of\":";
    assert_once(input, MARKER);
    let pos = input.find(MARKER).expect(MARKER);
    let tail = &input[pos + MARKER.len()..];
    if let Some(rest) = tail.strip_prefix("null") {
        assert!(rest.starts_with(','));
        "null"
    } else {
        assert!(tail.starts_with('"'), "as_of string");
        let end = tail[1..]
            .find('"')
            .unwrap_or_else(|| panic!("unterminated as_of"));
        &tail[1..1 + end]
    }
}

fn parse_loaded(input: &str) -> &str {
    const MARKER: &str = "\"loaded\":[";
    assert_once(input, MARKER);
    let pos = input.find(MARKER).expect(MARKER);
    let tail = &input[pos + MARKER.len()..];
    let end = tail.find(']').expect("loaded list");
    let body = &tail[..end];
    let mut count = 0usize;
    for part in body.split(',') {
        assert!(part == "true" || part == "false", "loaded bool {part}");
        count += 1;
    }
    assert_eq!(count, 3, "loaded triple");
    body
}

struct Tallies<'a> {
    contract: BTreeMap<&'a str, usize>,
    source: BTreeMap<&'a str, usize>,
    target: BTreeMap<&'a str, usize>,
    as_of: BTreeMap<&'a str, usize>,
    session: BTreeMap<&'a str, usize>,
    hash_keys: BTreeMap<&'a str, usize>,
    all_conditions: BTreeMap<&'a str, usize>,
    loaded: BTreeMap<&'a str, usize>,
}

impl<'a> Tallies<'a> {
    fn new() -> Self {
        Self {
            contract: BTreeMap::new(),
            source: BTreeMap::new(),
            target: BTreeMap::new(),
            as_of: BTreeMap::new(),
            session: BTreeMap::new(),
            hash_keys: BTreeMap::new(),
            all_conditions: BTreeMap::new(),
            loaded: BTreeMap::new(),
        }
    }

    fn bump(map: &mut BTreeMap<&'a str, usize>, key: &'a str) {
        *map.entry(key).or_default() += 1;
    }

    fn record(&mut self, line: &'a str, expected_id: u32) {
        let last = expected_id + 1 == u32::try_from(OUTCOME_VECTOR_COUNT).expect("vector count");
        let body = case_body(line, last);
        assert!(body.starts_with('{'), "case object");
        assert_eq!(body.matches("\"family\":\"verify\"").count(), 1);
        assert_eq!(parse_id(body), expected_id);
        let input = input_suffix(body);
        let contract_name = quoted_field(input, "\"contract\":\"");
        let source_name = quoted_field(input, "\"source\":\"");
        let target_name = quoted_field(input, "\"target\":\"");
        let as_of_name = parse_as_of(input);
        let session_name = quoted_field(input, "\"session\":\"");
        let hash_name = json_bool(input, "\"hash_keys\":");
        let all_name = json_bool(input, "\"all_conditions\":");
        let loaded_name = parse_loaded(input);
        assert!(matches!(
            contract_name,
            "contract.json" | "invalid.json" | "missing.json"
        ));
        assert!(matches!(
            source_name,
            "source.json" | "source-unicode.json" | "invalid.json" | "missing.json"
        ));
        assert!(matches!(
            target_name,
            "target.json"
                | "empty.json"
                | "unobserved.json"
                | "future.json"
                | "partial.json"
                | "invalid.json"
                | "missing.json"
        ));
        assert!(matches!(
            as_of_name,
            "null"
                | "naive"
                | "2026-11-08T00:00:00Z"
                | "2026-11-09T00:00:00Z"
                | "2026-11-11T00:00:00Z"
        ));
        assert!(matches!(session_name, "none" | "ok" | "os"));
        Self::bump(&mut self.contract, contract_name);
        Self::bump(&mut self.source, source_name);
        Self::bump(&mut self.target, target_name);
        Self::bump(&mut self.as_of, as_of_name);
        Self::bump(&mut self.session, session_name);
        Self::bump(&mut self.hash_keys, hash_name);
        Self::bump(&mut self.all_conditions, all_name);
        Self::bump(&mut self.loaded, loaded_name);
    }

    fn assert_totals(&self) {
        // 2 sources x 5 targets x 8 loaded triples x 5 as_of x 2 hash_keys
        // x 2 all_conditions x 3 sessions = 4800, plus 18 invalid-path rows.
        assert_tally(
            &self.contract,
            &[
                ("contract.json", 4812),
                ("invalid.json", 3),
                ("missing.json", 3),
            ],
            "contract",
        );
        assert_tally(
            &self.source,
            &[
                ("invalid.json", 6),
                ("missing.json", 6),
                ("source-unicode.json", 2400),
                ("source.json", 2406),
            ],
            "source",
        );
        assert_tally(
            &self.target,
            &[
                ("empty.json", 960),
                ("future.json", 960),
                ("invalid.json", 9),
                ("missing.json", 9),
                ("partial.json", 960),
                ("target.json", 960),
                ("unobserved.json", 960),
            ],
            "target",
        );
        assert_tally(
            &self.as_of,
            &[
                ("2026-11-08T00:00:00Z", 966),
                ("2026-11-09T00:00:00Z", 960),
                ("2026-11-11T00:00:00Z", 960),
                ("naive", 966),
                ("null", 966),
            ],
            "as_of",
        );
        assert_tally(
            &self.session,
            &[("none", 1600), ("ok", 1618), ("os", 1600)],
            "session",
        );
        assert_tally(
            &self.hash_keys,
            &[("false", 2418), ("true", 2400)],
            "hash_keys",
        );
        assert_tally(
            &self.all_conditions,
            &[("false", 2418), ("true", 2400)],
            "all_conditions",
        );
        assert_tally(
            &self.loaded,
            &[
                ("false,false,false", 618),
                ("false,false,true", 600),
                ("false,true,false", 600),
                ("false,true,true", 600),
                ("true,false,false", 600),
                ("true,false,true", 600),
                ("true,true,false", 600),
                ("true,true,true", 600),
            ],
            "loaded",
        );
    }
}

fn assert_tally(map: &BTreeMap<&str, usize>, expected: &[(&str, usize)], label: &str) {
    let actual: Vec<(&str, usize)> = map.iter().map(|(key, count)| (*key, *count)).collect();
    assert_eq!(actual, expected, "{label}");
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_outcome_engine_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut reasons = BTreeSet::new();
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
                    reason.contains("cartesian row is not the whole test"),
                    "{}",
                    row.name
                );
                assert!(reasons.insert(reason), "duplicate reason {}", row.name);
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
fn covered_vector_ids_are_present_in_outcome_vectors() {
    let json = read_text(VECTORS_REL);
    assert!(!json.contains('\r'), "outcome vectors are LF");
    assert!(json.contains(&format!("\"python_commit\":\"{PIN}\"")));
    assert!(json.contains("\"module\":\"sesslint.outcome\""));
    assert!(json.contains("\"schema\":\"sesslint.parity-module-vectors/v1\""));
    for anchor in ABSENT_FROM_SWEEP {
        assert!(!json.contains(anchor), "sweep contains {anchor}");
    }
    assert!(json.contains("an evaluation instant is required"));
    assert!(json.contains("the evaluation instant precedes the target observation time"));
    assert!(json.contains("target_incomplete"));
    assert!(json.contains("target_observed_at_unknown"));

    let lines: Vec<&str> = json.lines().collect();
    assert_eq!(lines.len(), OUTCOME_VECTOR_COUNT + 2);
    assert_eq!(
        lines[0],
        format!(
            "{{\"module\":\"sesslint.outcome\",\"python_commit\":\"{PIN}\",\"schema\":\"sesslint.parity-module-vectors/v1\",\"cases\":["
        )
    );
    assert_eq!(lines[OUTCOME_VECTOR_COUNT + 1], "]}");

    let mut tallies = Tallies::new();
    for (index, line) in lines[1..=OUTCOME_VECTOR_COUNT].iter().enumerate() {
        let id = u32::try_from(index).expect("case index");
        tallies.record(line, id);
    }
    tallies.assert_totals();
    assert_eq!(
        vector_line(&json, 0),
        case_body(lines[1], false),
        "id 0 line"
    );
    let last_id = u32::try_from(OUTCOME_VECTOR_COUNT - 1).expect("last id");
    assert_eq!(
        vector_line(&json, last_id),
        case_body(lines[OUTCOME_VECTOR_COUNT], true),
        "last id line"
    );

    let manifest = read_text(MANIFEST_REL);
    assert!(manifest.contains(&format!("\"python_commit\": \"{PIN}\"")));
    assert!(manifest.contains("\"module\": \"sesslint.outcome\""));
    assert!(manifest.contains("\"vector_count\": 4818"));
    assert!(manifest.contains(&format!(
        "\"tests/outcome/test_outcome_engine.py\": \"{PINNED_SOURCE_SHA256}\""
    )));

    let coverage = read_text(COVERAGE_REL);
    assert!(coverage.contains("\"covered_count\": 0"));
    assert!(coverage.contains("\"not_applicable_count\": 59"));
    assert_eq!(
        coverage.matches("\"status\": \"not_applicable\"").count(),
        59
    );
    assert_eq!(coverage.matches("\"vector_ids\": []").count(), 59);
    assert_eq!(coverage.matches("\"status\": \"covered\"").count(), 0);
    for name in PINNED_NAMES {
        let marker = format!("\"test_name\": \"{name}\"");
        assert_eq!(coverage.matches(&marker).count(), 1, "{name}");
    }

    let provenance = read_text(PROVENANCE_REL);
    assert!(provenance.contains("\"contains_real_data\": false"));
    assert!(provenance.contains("\"origin\": \"synthetic\""));
    assert!(provenance.contains(&format!("\"python_commit\": \"{PIN}\"")));

    let mut id_set = BTreeSet::new();
    for id in 0..OUTCOME_VECTOR_COUNT {
        assert!(id_set.insert(u32::try_from(id).expect("id")));
    }
    assert_eq!(id_set.len(), OUTCOME_VECTOR_COUNT);

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let id: u32 = vector_id.parse().unwrap_or_else(|_| {
            panic!(
                "{} covered id {vector_id} is not an outcome vector integer",
                row.name
            )
        });
        assert!(
            id_set.contains(&id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_line(&json, id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
