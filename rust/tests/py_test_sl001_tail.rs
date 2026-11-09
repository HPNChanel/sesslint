//! Dispositions for the 16 indented `def test_` functions in pinned
//! `tests/test_sl001_tail.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (236 lines). A column-0
//! scan finds 0 `def test_` functions. All 16 names are indented methods.
//! This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call adapters, scan,
//! report, or io.
//!
//! `covered` names every id in a published `vectors.json` whose constructs
//! together are the same function and the same success or failure as that
//! entire pinned test. One example inside a sweep, a different input, or a
//! shared field is not coverage. A loader seam does not return the pin
//! events or findings. `not_applicable` records a call this package cannot
//! reach without a `Cargo.toml` change, or a mode no published vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 16;

/// `covered` names vector ids that together match one entire pinned test.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from the
/// published vector files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
    Covered {
        vector_ids: &'static [&'static str],
        needles: &'static [&'static [&'static str]],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

struct PublishedFile {
    rel: &'static str,
    module: &'static str,
    id_count: usize,
    unique_count: usize,
}

struct CitedVector {
    rel: &'static str,
    id: &'static str,
    construct: &'static str,
    extra: &'static [&'static str],
}

const NO_EXTRA: &[&str] = &[];

const PUBLISHED: &[PublishedFile] = &[
    PublishedFile {
        rel: "parity/vectors/io/vectors.json",
        module: "sesslint.io",
        id_count: 35,
        unique_count: 34,
    },
    PublishedFile {
        rel: "parity/vectors/adapters.claude_code/vectors.json",
        module: "sesslint.adapters.claude_code",
        id_count: 27,
        unique_count: 27,
    },
    PublishedFile {
        rel: "parity/vectors/adapters.codex_rollout/vectors.json",
        module: "sesslint.adapters.codex_rollout",
        id_count: 30,
        unique_count: 30,
    },
    PublishedFile {
        rel: "parity/vectors/adapters.openai_agents/vectors.json",
        module: "sesslint.adapters.openai_agents",
        id_count: 42,
        unique_count: 42,
    },
    PublishedFile {
        rel: "parity/vectors/report/vectors.json",
        module: "sesslint.report",
        id_count: 17,
        unique_count: 17,
    },
    PublishedFile {
        rel: "parity/vectors/seal/vectors.json",
        module: "sesslint.seal",
        id_count: 21,
        unique_count: 21,
    },
];

const CITED: &[CitedVector] = &[
    CitedVector {
        rel: "parity/vectors/io/vectors.json",
        id: "iter_events_two_events",
        construct: "io_iter_events_stream",
        extra: &["\"event_count\": 2", "\"id\": \"evt-one\"", "\"id\": \"evt-two\""],
    },
    CitedVector {
        rel: "parity/vectors/io/vectors.json",
        id: "iter_events_no_records",
        construct: "io_iter_events_stream",
        extra: &["\"Session file contains no records: <stream>\""],
    },
    CitedVector {
        rel: "parity/vectors/io/vectors.json",
        id: "torn_7b226964223a_False",
        construct: "io_is_torn_append",
        extra: NO_EXTRA,
    },
    CitedVector {
        rel: "parity/vectors/adapters.claude_code/vectors.json",
        id: "gap_load_bytes",
        construct: "load_claude_code",
        extra: &["\"event_count\": 1", "\"finding_count\": 0"],
    },
    CitedVector {
        rel: "parity/vectors/adapters.claude_code/vectors.json",
        id: "gap_load_readable_path",
        construct: "load_claude_code",
        extra: &[
            "fixtures/syn-readable.jsonl",
            "\"event_count\": 1",
            "\"finding_count\": 0",
        ],
    },
    CitedVector {
        rel: "parity/vectors/adapters.claude_code/vectors.json",
        id: "gap_process_nul_fingerprint",
        construct: "process_claude_line",
        extra: &["\"SL001\""],
    },
    CitedVector {
        rel: "parity/vectors/adapters.codex_rollout/vectors.json",
        id: "gap_load_torn_line",
        construct: "load_codex_rollout",
        extra: &["\"SL001\""],
    },
    CitedVector {
        rel: "parity/vectors/adapters.codex_rollout/vectors.json",
        id: "gap_load_envelope_line",
        construct: "load_codex_rollout",
        extra: &["\"event_count\": 1", "\"finding_count\": 0"],
    },
    CitedVector {
        rel: "parity/vectors/adapters.openai_agents/vectors.json",
        id: "gap_jsonl_tail",
        construct: "load_openai_agents_jsonl",
        extra: &["\"pin_mode\": \"error\""],
    },
    CitedVector {
        rel: "parity/vectors/adapters.openai_agents/vectors.json",
        id: "gap_jsonl_object",
        construct: "load_openai_agents_jsonl",
        extra: &["\"pin_mode\": \"error\""],
    },
    CitedVector {
        rel: "parity/vectors/adapters.openai_agents/vectors.json",
        id: "load_empty_bytes",
        construct: "load_openai_agents",
        extra: &["\"event_count\": 0", "\"finding_count\": 0"],
    },
    CitedVector {
        rel: "parity/vectors/report/vectors.json",
        id: "render_human_healthy_header",
        construct: "render_human",
        extra: &["\"report_kind\": \"empty_clean\""],
    },
    CitedVector {
        rel: "parity/vectors/report/vectors.json",
        id: "render_human_with_finding_gap",
        construct: "render_human",
        extra: &["\"report_kind\": \"one_error\""],
    },
    CitedVector {
        rel: "parity/vectors/seal/vectors.json",
        id: "constants_closed_vocabulary",
        construct: "module_constants",
        extra: &["\"malformed-line\""],
    },
    CitedVector {
        rel: "parity/vectors/seal/vectors.json",
        id: "verify_lines_malformed_json_truncated_object",
        construct: "verify_lines",
        extra: &["\"kind\": \"malformed-line\""],
    },
];

/// Substrings that would be required for a published vector to be one of
/// these pin results. Their absence is why none of the 16 tests is covered.
const ABSENT_PIN_RESULTS: &[&str] = &[
    "following_complete_records",
    "following_bytes",
    "following_records",
    "_human_bytes",
    "may be invisible to vendor loaders",
    "3 further record(s)",
    "\"410 B\"",
    "\"2.0 KiB\"",
    "\"11.0 MiB\"",
    "malformed-mid",
    "minimal-valid",
    "items_basic",
    "\"type\": \"MalformedTailTracker\"",
    "\"type\": \"_human_bytes\"",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_mid_file_malformed_counts_tail",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/malformed-line.jsonl returns the first SL001 with following_complete_records 3 and following_bytes equal to the file size minus byte_end; iter_events_two_events is a clean evt-one and evt-two stream, constants_closed_vocabulary only lists the divergence kind malformed-line, and verify_lines_malformed_json_truncated_object is verify_lines on a truncated brace",
        ),
    },
    Row {
        name: "test_stream_order_unchanged",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/malformed-line.jsonl yields a SessionEvent, an SL001 Finding, then a SessionEvent; iter_events_two_events yields two events, and the io finding-stream gap omits that order",
        ),
    },
    Row {
        name: "test_clean_file_no_keys",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/minimal-valid.jsonl yields no Finding values; iter_events_two_events is a different two-event stream, and iter_events_no_records is an empty stream that errors",
        ),
    },
    Row {
        name: "test_malformed_then_only_torn_tail_omits_keys",
        disposition: Disposition::NotApplicable(
            "iter_events on one complete event, the text BROKEN LINE, and a torn object yields one SL001 whose evidence omits the tail keys, plus one SL002; torn_7b226964223a_False is io_is_torn_append on a different line",
        ),
    },
    Row {
        name: "test_multiple_malformed_only_first_enriched",
        disposition: Disposition::NotApplicable(
            "iter_events on FIRST BROKEN, SECOND BROKEN, and one complete event yields two SL001 findings, and only the first has following_complete_records 1 and following_bytes; no io_iter_events_stream vector records that pair",
        ),
    },
    Row {
        name: "test_torn_terminal_excluded_from_tail_bytes",
        disposition: Disposition::NotApplicable(
            "iter_events on a complete line, BROKEN, the same complete line, and a torn object yields a first SL001 whose following_complete_records is 1 and whose following_bytes equals that complete line; no published vector records that length",
        ),
    },
    Row {
        name: "test_multibyte_and_crlf_byte_exactness",
        disposition: Disposition::NotApplicable(
            "iter_events on an LF copy and a CRLF copy of one complete multibyte record, a broken line, and the same record yields following_bytes of the record length plus 1 and plus 2; no published vector records those two files",
        ),
    },
    Row {
        name: "test_golden_fixture_pinned_counts",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/claude_code/malformed-mid.jsonl returns 4 events and one SL001 with following_complete_records 3 and following_bytes equal to the file size minus byte_end; gap_load_readable_path is fixtures/syn-readable.jsonl and stops at the open-byte-source seam with a pin of one event and zero findings, gap_load_bytes is a different line with zero findings, and gap_process_nul_fingerprint is process_claude_line on a different line",
        ),
    },
    Row {
        name: "test_synthetic_mid_malformed",
        disposition: Disposition::NotApplicable(
            "load_claude_code of two user_message lines separated by BROKEN returns 2 events and one SL001 with following_complete_records 1; gap_load_bytes is a different single line whose pin has zero findings",
        ),
    },
    Row {
        name: "test_codex_rollout_enriched",
        disposition: Disposition::NotApplicable(
            "load_codex_rollout of a session_meta line, BROKEN LINE, and two response_item lines returns one SL001 with following_complete_records 2 and a positive following_bytes; gap_load_torn_line is an open brace and a newline, and gap_load_envelope_line is one event_msg line with zero findings",
        ),
    },
    Row {
        name: "test_openai_agents_enriched",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of one compact items_basic item, BROKEN LINE, and that item twice more returns one SL001 with following_complete_records 2 and following_bytes equal to twice the line length plus one; gap_jsonl_tail and gap_jsonl_object are load_openai_agents_jsonl failures on empty bytes and an empty object, and load_empty_bytes is an empty load_openai_agents success",
        ),
    },
    Row {
        name: "test_no_enrichment_without_sl001",
        disposition: Disposition::NotApplicable(
            "MalformedTailTracker.finalize with total_bytes 100 leaves following_records at 0; no published construct type is MalformedTailTracker, and the openai gap text only names that tracker as a loader stop",
        ),
    },
    Row {
        name: "test_finding_without_dict_evidence_ignored",
        disposition: Disposition::NotApplicable(
            "MalformedTailTracker.finalize with total_bytes 50 and torn_tail_offset 10 leaves following_records at 0; the body passes no finding, and no published vector calls finalize or records following_records",
        ),
    },
    Row {
        name: "test_human_render_suffix",
        disposition: Disposition::NotApplicable(
            "_human_bytes(410) is 410 B, _human_bytes(2048) is 2.0 KiB, and _human_bytes(11 * 1024 * 1024) is 11.0 MiB; report vectors have no _human_bytes construct, and render_human_healthy_header is render_human of an empty clean report",
        ),
    },
    Row {
        name: "test_check_report_contains_suffix",
        disposition: Disposition::NotApplicable(
            "check_file of fixtures/claude_code/malformed-mid.jsonl with format claude-code-jsonl, then render_human, contains \"may be invisible to vendor loaders\" and \"3 further record(s)\"; no sesslint.api vectors.json is published, and render_human_with_finding_gap is render_human of a synthetic one-error report",
        ),
    },
    Row {
        name: "test_determinism_replay",
        disposition: Disposition::NotApplicable(
            "two load_claude_code calls on fixtures/claude_code/malformed-mid.jsonl return equal evidence lists; each adapters.claude_code load vector is a single call, and gap_load_readable_path is a different path that stops before findings",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_mid_file_malformed_counts_tail",
    "test_stream_order_unchanged",
    "test_clean_file_no_keys",
    "test_malformed_then_only_torn_tail_omits_keys",
    "test_multiple_malformed_only_first_enriched",
    "test_torn_terminal_excluded_from_tail_bytes",
    "test_multibyte_and_crlf_byte_exactness",
    "test_golden_fixture_pinned_counts",
    "test_synthetic_mid_malformed",
    "test_codex_rollout_enriched",
    "test_openai_agents_enriched",
    "test_no_enrichment_without_sl001",
    "test_finding_without_dict_evidence_ignored",
    "test_human_render_suffix",
    "test_check_report_contains_suffix",
    "test_determinism_replay",
];

fn expected_covered_ids(_name: &str) -> Option<&'static [&'static str]> {
    None
}

fn read_rel(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_pin_results_absent(dir: &Path, rel: &str) {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {rel}: {err}")) {
        let entry = entry.unwrap_or_else(|err| panic!("dir entry under {rel}: {err}"));
        names.push(entry.file_name());
    }
    names.sort();
    for name in names {
        let name_str = name
            .to_str()
            .unwrap_or_else(|| panic!("non-utf8 path under {rel}"));
        let child = if rel.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel}/{name_str}")
        };
        let path = dir.join(&name);
        if path.is_dir() {
            assert_pin_results_absent(&path, &child);
        } else if name_str == "vectors.json" {
            let json = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {child}: {err}"));
            for needle in ABSENT_PIN_RESULTS {
                assert!(
                    !json.contains(needle),
                    "{child} contains pin result {needle}"
                );
            }
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_sl001_tail_test_has_one_disposition() {
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
            Disposition::Covered {
                vector_ids,
                needles,
            } => {
                let expected = expected_covered_ids(row.name)
                    .unwrap_or_else(|| panic!("{} is not a fully covered pin test", row.name));
                assert_eq!(vector_ids, expected, "{}", row.name);
                assert!(!vector_ids.is_empty(), "{}", row.name);
                assert_eq!(vector_ids.len(), needles.len(), "{}", row.name);
                for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
                    assert!(!vector_id.is_empty(), "{}", row.name);
                    assert!(!needles.is_empty(), "{}", row.name);
                    assert!(
                        needles
                            .iter()
                            .any(|needle| needle.starts_with("\"type\": \"")),
                        "{} covered row is missing a construct type needle",
                        row.name
                    );
                    assert!(
                        covered_ids.insert(*vector_id),
                        "duplicate covered vector {vector_id}"
                    );
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(
                    expected_covered_ids(row.name).is_none(),
                    "{} is not_applicable but lists covered ids",
                    row.name
                );
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_published_vectors() {
    let api = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/api/vectors.json");
    assert!(
        !api.exists(),
        "sesslint.api has no published vectors.json"
    );

    let mut loaded = BTreeSet::new();
    for published in PUBLISHED {
        let json = read_rel(published.rel);
        assert!(
            json.contains(&format!("\"python_commit\": \"{PIN}\"")),
            "{} is pinned to {PIN}",
            published.rel
        );
        assert!(
            json.contains(&format!("\"module\": \"{}\"", published.module)),
            "{} module drifted",
            published.rel
        );
        let ids = vector_ids(&json);
        assert_eq!(ids.len(), published.id_count, "{}", published.rel);
        assert_eq!(
            ids.iter().collect::<BTreeSet<_>>().len(),
            published.unique_count,
            "{}",
            published.rel
        );
        if published.module == "sesslint.io" {
            assert!(
                json.contains("SL001, SL002, SL303, and SL009 findings"),
                "io vectors record the finding-stream gap"
            );
        }
        if published.module == "sesslint.adapters.openai_agents" {
            assert!(
                json.contains("MalformedTailTracker"),
                "openai vectors name the tail tracker only as a loader stop"
            );
        }
        assert!(loaded.insert(published.rel));
    }

    for cited in CITED {
        assert!(loaded.contains(cited.rel), "cited file {} is not published", cited.rel);
        let json = read_rel(cited.rel);
        let slice = vector_slice(&json, cited.id);
        let type_needle = format!("\"type\": \"{}\"", cited.construct);
        assert!(
            slice.contains(&type_needle),
            "{} is missing construct {}",
            cited.id,
            cited.construct
        );
        for needle in cited.extra {
            assert!(
                slice.contains(needle),
                "{} is missing {needle}",
                cited.id
            );
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/vectors");
    assert_pin_results_absent(&root, "parity/vectors");

    for row in ROWS {
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
            let mut found = false;
            for cited in CITED {
                if cited.id == *vector_id {
                    found = true;
                    let json = read_rel(cited.rel);
                    let slice = vector_slice(&json, vector_id);
                    for needle in *needles {
                        assert!(
                            slice.contains(needle),
                            "{} vector {vector_id} is missing {needle}",
                            row.name
                        );
                    }
                }
            }
            assert!(found, "{} names missing vector {vector_id}", row.name);
        }
    }
}
