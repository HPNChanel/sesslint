//! Dispositions for the twenty-eight `def test_` functions in pinned
//! `tests/checks/test_hygiene.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (490 splitlines). Exactly
//! twenty-eight test functions, in module order. None is parametrized. The
//! helpers `_sl009` and `_serialized` are not tests. Each row is the whole
//! function. A load is not `check_file`. `check_file` is not `check_bytes`.
//! A tracker feed is not an adapter load. A docstring is not an assertion.
//! Canaries, tokens, assignment values, matched spans, and vendor-prefix
//! byte sequences are not copied here. This file does not generate a large
//! buffer and does not call a clock.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, cli, or
//! hygiene functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33
//! parser-metadata vectors at this pin and none is one of these twenty-eight
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for envelopes, directory limits, discovery, module constants, plan and
//! repair rejection, thresholds, and validate_session. None of those 77 is
//! one of these twenty-eight functions.
//! `parity/vectors/checks.hygiene/vectors.json` has 95 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, including short_prefix cells,
//! kw_assignment cells, gate cells, json_escape_shadow cells, placeholder
//! cells, and tracker cells such as `tracker_placeholder_assignments_silent`,
//! `tracker_json_escape_enables_match`, `tracker_aggregates_per_family`,
//! `tracker_sort_line_ordinal_family`, and `tracker_finding_cap_overflow`.
//! That corpus is not a Covered source. A single tracker cell is not one of
//! these twenty-eight functions. Therefore every row is NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 28;
const PINNED_SPLITLINES: usize = 490;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A load is not `check_file`. `check_file` is not
/// `check_bytes`. A tracker feed is not an adapter load. A docstring is not
/// an assertion. `not_applicable` names the missing stop.
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
        name: "test_seeded_fixture_fires_all_families",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_seeded_fixture_fires_all_families: the seeded canonical load has at least the fourteen families anthropic-api-key, openai-api-key, openrouter-api-key, github-pat-classic, github-pat-fine-grained, github-oauth-token, stripe-webhook-secret, stripe-key, aws-access-key, supabase-pat, telegram-bot-token, jwt, private-key-block, and generic-credential-assignment, and every SL009 hit is WARNING and MANUAL; missing stop: that subset of families together with WARNING and MANUAL; the subset assertion is not an exact-set assertion; all of that is one row; a load is not check_file; the aggregation test is not this pytest; test_aggregation_same_family_one_record is that test",
        ),
    },
    Row {
        name: "test_aggregation_same_family_one_record",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregation_same_family_one_record: the seeded load has one aws-access-key finding, occurrence_count 3, and three match_sha256 digests; missing stop: those three together; it does not assert the other families; those three are one row; a load is not check_file; the all-families test is not this pytest; test_seeded_fixture_fires_all_families is that test",
        ),
    },
    Row {
        name: "test_clean_and_near_miss_fixtures_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_clean_and_near_miss_fixtures_silent: both the clean file and the near-miss file have an empty SL009 list; missing stop: both empty SL009 lists together; both files are one row; an empty SL009 list is not an empty findings list; a docstring is not an assertion; the malformed file is not this pytest; test_malformed_line_still_scanned is that file",
        ),
    },
    Row {
        name: "test_malformed_line_still_scanned",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_line_still_scanned: the malformed file has SL001 and at least one SL009 whose source line is 2; missing stop: both of those together; both are one row; it does not assert an SL009 count; a docstring is not an assertion; the clean and near-miss test is not this pytest; test_clean_and_near_miss_fixtures_silent is that pair",
        ),
    },
    Row {
        name: "test_secret_bytes_never_in_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_secret_bytes_never_in_finding: each serialized SL009 finding lacks the three planted canaries in that function, and assert_no_pii is called on each finding dict; missing stop: those absences together with assert_no_pii; all of that is one row; the canaries are not copied here; the evidence-key test is not this pytest; test_evidence_keys_bounded_to_allowlist is that test",
        ),
    },
    Row {
        name: "test_digest_present_and_discriminates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_digest_present_and_discriminates: two findings, the first occurrence_count is 2 and its digest list is the digest of the repeated span, and the second digest list is the digest of the other span; missing stop: both findings together; both findings are one row; a tracker feed is not an adapter load; the spans are not copied here; the aggregation test is not this pytest; test_aggregation_same_family_one_record is that load",
        ),
    },
    Row {
        name: "test_escaped_quote_assignment_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_escaped_quote_assignment_fires: an escaped quoted assignment yields generic-credential-assignment among the families; missing stop: that family among the families; it does not assert that family is the only one; the raw line is not copied here; a tracker feed is not an adapter load; the escaped-key test is not this pytest; test_escaped_json_key_assignment_fires is that test",
        ),
    },
    Row {
        name: "test_escaped_json_key_assignment_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_escaped_json_key_assignment_fires: an escaped key assignment yields generic-credential-assignment; missing stop: that family; the raw line is not copied here; a tracker feed is not an adapter load; the escaped-quote test is not this pytest; test_escaped_quote_assignment_fires is that test",
        ),
    },
    Row {
        name: "test_placeholder_assignments_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_placeholder_assignments_silent: the placeholder feed yields an empty finding list; missing stop: that empty finding list; the placeholder bytes are not copied here; a tracker feed is not an adapter load; an empty SL009 list is not this empty finding list; the escaped-key test is not this pytest; test_escaped_json_key_assignment_fires is that test",
        ),
    },
    Row {
        name: "test_evidence_keys_bounded_to_allowlist",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_evidence_keys_bounded_to_allowlist: every SL009 evidence key is in the ten-key allowlist secret_family, secret_family_set, occurrence_count, match_sha256, match_len, record_ordinal, byte_offset, byte_end, truncated, and overflow, secret_family_set equals the module constant, occurrence_count is an int of at least 1, match_sha256 is a non-empty list, and byte_end is greater than byte_offset which is at least 0; missing stop: all of that together; all of that is one row; the module constant value is not invented here; a load is not check_file; the secret-bytes test is not this pytest; test_secret_bytes_never_in_finding is that test",
        ),
    },
    Row {
        name: "test_findings_deterministic_across_runs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_findings_deterministic_across_runs: two loads have equal finding dictionaries and equal fingerprints; missing stop: both equalities together; both equalities cover every finding, not only SL009, and are one row; a docstring is not an assertion; a load is not check_file; the all-families test is not this pytest; test_seeded_fixture_fires_all_families is that load",
        ),
    },
    Row {
        name: "test_digest_cap_marks_truncated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_digest_cap_marks_truncated: one finding, occurrence_count equals the digest cap plus 3, the digest list length equals the digest cap, and truncated is true; missing stop: all of that together; all of that is one row; the generated spans are not copied here; a tracker feed is not an adapter load; the finding-cap test is not this pytest; test_finding_cap_marks_overflow is that test",
        ),
    },
    Row {
        name: "test_finding_cap_marks_overflow",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_finding_cap_marks_overflow: the finding count equals the finding cap, the last overflow is 5, and the last truncated is true; missing stop: all of that together; all of that is one row; the generated spans are not copied here; a tracker feed is not an adapter load; the digest-cap test is not this pytest; test_digest_cap_marks_truncated is that test",
        ),
    },
    Row {
        name: "test_findings_ordered_by_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_findings_ordered_by_line: the source lines equal those lines sorted; missing stop: that sorted-line equality; it does not assert ordinal order or family order; the docstring is not that assertion; three feeds are one row; the spans are not copied here; a tracker feed is not an adapter load; the finding-cap test is not this pytest; test_finding_cap_marks_overflow is that test",
        ),
    },
    Row {
        name: "test_iter_events_emits_sl009",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_iter_events_emits_sl009: some yielded item is a Finding whose code is SL009; missing stop: that yielded Finding; it does not assert the events; a docstring is not an assertion; an adapter load is not this iterator; the vendor-adapter test is not this pytest; test_vendor_adapters_emit_sl009 is that test",
        ),
    },
    Row {
        name: "test_vendor_adapters_emit_sl009",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_adapters_emit_sl009: claude, codex rollout, and openai agents each produce at least one SL009; missing stop: all three loaders together; all three loaders are one row; the coordinate test is not this pytest; test_openai_single_doc_coordinates is that test",
        ),
    },
    Row {
        name: "test_openai_single_doc_coordinates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_openai_single_doc_coordinates: the hits are non-empty, every hit lacks record_ordinal, byte_end is greater than byte_offset which is at least 0, and the source line is present and at least 1; missing stop: all of that together; all of that is one row; the vendor-adapter test is not this pytest; test_vendor_adapters_emit_sl009 is that test",
        ),
    },
    Row {
        name: "test_check_file_report_is_secret_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_report_is_secret_free: the serialized canonical report lacks the two planted report canaries, assert_no_pii is called, and at least one finding is SL009; missing stop: all of that together; all of that is one row; the canaries are not copied here; a load is not this check_file; the coverage test is not this pytest; test_coverage_marks_sl009_performed is that test",
        ),
    },
    Row {
        name: "test_cli_default_exit_zero_and_select",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_default_exit_zero_and_select: default exit 0 with SL009 present, select exit 0 with the code set exactly SL009, and ignore exit 0 with SL009 absent; missing stop: all three phases together; three phases are one row; the first phase does not assert that SL009 is the only code; the secret-output test is not this pytest; test_cli_output_never_contains_secret is that test",
        ),
    },
    Row {
        name: "test_cli_output_never_contains_secret",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_output_never_contains_secret: both the human invocation and the JSON invocation keep both planted canaries out of stdout and out of stderr; missing stop: both invocations together; both invocations are one row; it does not assert the exit code; the canaries are not copied here; the exit-code test is not this pytest; test_cli_default_exit_zero_and_select is that test",
        ),
    },
    Row {
        name: "test_coverage_marks_sl009_performed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_coverage_marks_sl009_performed: SL009 is in performed; missing stop: that membership in performed; it does not assert the findings; a docstring is not an assertion; the secret-free report test is not this pytest; test_check_file_report_is_secret_free is that test",
        ),
    },
    Row {
        name: "test_bytes_stream_input",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bytes_stream_input: check_bytes of the seeded file bytes has at least one SL009; missing stop: that SL009 from check_bytes; check_file is not check_bytes; the canonical load of that file is not this pytest; test_seeded_fixture_fires_all_families is that load",
        ),
    },
    Row {
        name: "test_render_human_sl009_rollup_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_render_human_sl009_rollup_line: the human text contains SL009 warning, secret-shaped material, and families:, and it lacks the two planted report canaries; missing stop: all of that together; all of that is one row; the canaries are not copied here; the three-renderer test is not this pytest; test_renderers_never_leak_secret is that test",
        ),
    },
    Row {
        name: "test_renderers_never_leak_secret",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_renderers_never_leak_secret: JSON, SARIF, and HTML each lack both planted report canaries, at least one SARIF result has rule SL009, and each of those results is level warning and carries sesslint/secret-match-sha256; missing stop: all of that together; all of that is one row; the canaries are not copied here; a comment is not an assertion; the human rollup test is not this pytest; test_render_human_sl009_rollup_line is that test",
        ),
    },
    Row {
        name: "test_scan_human_summary_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_human_summary_line: the human scan text contains secret-shaped material: 1 file(s) and SL009, and it lacks the short vendor prefix forbidden by that assertion; missing stop: all of that together; all of that is one row; that prefix is not copied here; the JSON scan test is not this pytest; test_scan_json_by_code_lists_sl009 is that test",
        ),
    },
    Row {
        name: "test_scan_json_by_code_lists_sl009",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_json_by_code_lists_sl009: SL009 is in by_code, its severity is warning, and its file count is 1; missing stop: all three together; all three are one row; the human scan line is not this pytest; test_scan_human_summary_line is that line",
        ),
    },
    Row {
        name: "test_generic_assignment_no_catastrophic_backtracking",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_generic_assignment_no_catastrophic_backtracking: the noise is longer than 1000000 bytes, the finding list is empty, and the elapsed time is under 10 seconds; missing stop: all three together; all three are one row; an empty list alone is not this pytest; the placeholder feed is that empty list; test_placeholder_assignments_silent is that feed; the noise is not copied here; a clock is not called here",
        ),
    },
    Row {
        name: "test_vendor_prefix_families_require_token_boundary",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_prefix_families_require_token_boundary: a vendor-prefix shape at a quoted value, at an assignment, and at a line start each produces a finding, and the same shape after two letters, after an alphanumeric run, after a hyphen inside a token, and after an underscore inside a token each produces an empty list; missing stop: all seven scans together; all seven scans are one row; the shape bytes are not copied here; a docstring is not an assertion; a tracker feed is not an adapter load; the backtracking test is not this pytest; test_generic_assignment_no_catastrophic_backtracking is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_seeded_fixture_fires_all_families",
    "test_aggregation_same_family_one_record",
    "test_clean_and_near_miss_fixtures_silent",
    "test_malformed_line_still_scanned",
    "test_secret_bytes_never_in_finding",
    "test_digest_present_and_discriminates",
    "test_escaped_quote_assignment_fires",
    "test_escaped_json_key_assignment_fires",
    "test_placeholder_assignments_silent",
    "test_evidence_keys_bounded_to_allowlist",
    "test_findings_deterministic_across_runs",
    "test_digest_cap_marks_truncated",
    "test_finding_cap_marks_overflow",
    "test_findings_ordered_by_line",
    "test_iter_events_emits_sl009",
    "test_vendor_adapters_emit_sl009",
    "test_openai_single_doc_coordinates",
    "test_check_file_report_is_secret_free",
    "test_cli_default_exit_zero_and_select",
    "test_cli_output_never_contains_secret",
    "test_coverage_marks_sl009_performed",
    "test_bytes_stream_input",
    "test_render_human_sl009_rollup_line",
    "test_renderers_never_leak_secret",
    "test_scan_human_summary_line",
    "test_scan_json_by_code_lists_sl009",
    "test_generic_assignment_no_catastrophic_backtracking",
    "test_vendor_prefix_families_require_token_boundary",
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
fn pinned_test_hygiene_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 490);
}

#[test]
fn pinned_test_hygiene_row_count_equals_twenty_eight() {
    assert_eq!(ROWS.len(), 28);
    assert_eq!(PINNED_TEST_COUNT, 28);
    assert_eq!(PINNED_NAMES.len(), 28);
}

#[test]
fn every_pinned_test_hygiene_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 28);
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
            "cli id {id} is one of the twenty-eight functions"
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
    assert_eq!(not_applicable, 28);

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
            "api id {id} is one of the twenty-eight functions"
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
