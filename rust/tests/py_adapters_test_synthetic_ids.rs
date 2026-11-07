//! Dispositions for the 18 column-0 `def test_` functions in pinned
//! `tests/adapters/test_synthetic_ids.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (494 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.adapters`.
//!
//! `covered` names every id in `adapters.synthetic/vectors.json` whose
//! constructs together are the same function and the same success or failure
//! mode as that entire pinned test. One example inside a sweep, a different
//! input, or a shared field such as an event id is not coverage.
//! `not_applicable` records a `sesslint.adapters.synthetic` call this package
//! cannot reach without a `Cargo.toml` change, or a mode no vector records.
//! `load_claude_code` and `load_openai_agents` do not return events in this
//! tree, so those tests stay `not_applicable`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 18;
const ADAPTER_VECTOR_COUNT: usize = 22;
const VECTORS_REL: &str = "parity/vectors/adapters.synthetic/vectors.json";

/// `covered` names every vector id in `adapters.synthetic/vectors.json` that
/// together match one entire pinned test. `not_applicable` records behavior
/// this package cannot reach without a `Cargo.toml` change outside the owned
/// path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
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

/// Vector id, construct type, and whether the expected result is an error.
/// A thrown `AdapterError` is the key `"raises"`. Returned ids, bools, and a
/// null guard result are not that key.
const ADAPTER_VECTORS: &[(&str, &str, bool)] = &[
    ("synthetic_event_id_ascii_hint", "synthetic_event_id", false),
    (
        "synthetic_event_id_negative_ordinal",
        "synthetic_event_id",
        false,
    ),
    (
        "synthetic_event_id_non_ascii_letter_hint",
        "synthetic_event_id",
        false,
    ),
    (
        "synthetic_event_id_defaults_empty",
        "synthetic_event_id",
        false,
    ),
    ("is_synthetic_id_prefix_with_tail", "is_synthetic_id", false),
    ("is_synthetic_id_prefix_only", "is_synthetic_id", false),
    (
        "is_synthetic_id_sesslint_synthetic_without_colon",
        "is_synthetic_id",
        false,
    ),
    (
        "is_synthetic_id_sesslint_synthetic_x",
        "is_synthetic_id",
        false,
    ),
    ("is_synthetic_id_empty", "is_synthetic_id", false),
    (
        "advance_reserved_ascii_ordinal_increments_keeps_digest",
        "advance_synthetic_id",
        false,
    ),
    (
        "advance_reserved_leading_zero_ordinal",
        "advance_synthetic_id",
        false,
    ),
    (
        "advance_negative_reserved_ordinal_appends_suffix",
        "advance_synthetic_id",
        false,
    ),
    ("advance_bare_appends_one", "advance_synthetic_id", false),
    ("advance_ascii_digit_suffix", "advance_synthetic_id", false),
    ("advance_leading_zero_suffix", "advance_synthetic_id", false),
    (
        "advance_single_digit_rollover",
        "advance_synthetic_id",
        false,
    ),
    (
        "advance_vulgar_fraction_not_digit",
        "advance_synthetic_id",
        false,
    ),
    ("guard_clean_then_assert_no_collision", "guard_run", false),
    (
        "guard_register_synthetic_collides_prior_real",
        "guard_run",
        true,
    ),
    (
        "guard_register_real_collides_prior_synthetic",
        "guard_run",
        true,
    ),
    (
        "guard_register_dispatches_is_synthetic_flag",
        "guard_run",
        true,
    ),
    (
        "guard_assert_no_collision_lexicographic_first",
        "guard_preloaded_assert_no_collision",
        true,
    ),
];

/// `register_real` then `register_synthetic` on one claude_code id.
const GUARD_SYNTHETIC_COLLIDES_REAL_IDS: &[&str] =
    &["guard_register_synthetic_collides_prior_real"];

/// `register_synthetic` then `register_real` on one openai_agents id.
const GUARD_REAL_COLLIDES_SYNTHETIC_IDS: &[&str] =
    &["guard_register_real_collides_prior_synthetic"];

/// Reserved ordinal, numbered suffix, then a bare id. Each id is one call.
const ADVANCE_HELPER_IDS: &[&str] = &[
    "advance_reserved_ascii_ordinal_increments_keeps_digest",
    "advance_ascii_digit_suffix",
    "advance_bare_appends_one",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_synthetic_event_id_format",
        disposition: Disposition::NotApplicable(
            "synthetic_event_id of claude_code ordinal 42 source_hint session.jsonl payload_len 128 matches sesslint:synthetic:claude_code:42 and eight hex digits, then is_synthetic_id of that id is true; synthetic_event_id_ascii_hint uses source_hint synthetic-hint",
        ),
    },
    Row {
        name: "test_synthetic_event_id_hash_exact",
        disposition: Disposition::NotApplicable(
            "synthetic_event_id of openai_agents ordinal 7 source_hint test_source.json payload_len 256 equals sesslint:synthetic:openai_agents:7 plus the eight-hex sha256 of those coordinates; no adapters.synthetic vector records that call",
        ),
    },
    Row {
        name: "test_synthetic_event_id_determinism_and_differentiation",
        disposition: Disposition::NotApplicable(
            "synthetic_event_id of adapter_a ordinal 0 source_hint file.jsonl payload_len 100 equals a repeat call and differs for adapter_b, ordinal 1, source_hint other.jsonl, and payload_len 101; no adapters.synthetic vector records those calls, and one call would not be the sweep",
        ),
    },
    Row {
        name: "test_synthetic_event_id_edge_cases",
        disposition: Disposition::NotApplicable(
            "synthetic_event_id of test ordinal 0 with an empty hint and payload_len 0, of source_hint /путь/к/файлу/日本語/session.jsonl ordinal 10 payload_len 1024, and of ordinal 10000000 source_hint stream payload_len 50000000 each keep an eight-hex suffix; synthetic_event_id_defaults_empty is only the empty call, and synthetic_event_id_non_ascii_letter_hint uses source_hint synthetic-hint-é, so one call is not the sweep",
        ),
    },
    Row {
        name: "test_is_synthetic_id",
        disposition: Disposition::NotApplicable(
            "is_synthetic_id is true for the prefix plus any:1:abc and false for rec_0, uuid-1234, and the empty string; is_synthetic_id_prefix_with_tail and is_synthetic_id_empty are two of those inputs, while is_synthetic_id_prefix_only, is_synthetic_id_sesslint_synthetic_without_colon, and is_synthetic_id_sesslint_synthetic_x are different strings, so none is the whole sweep",
        ),
    },
    Row {
        name: "test_collision_guard_clean_operation",
        disposition: Disposition::NotApplicable(
            "SyntheticIdCollisionGuard registers real_1 and real_2, registers sesslint:synthetic:adapter:0:12345678 and sesslint:synthetic:adapter:1:87654321, checks those frozensets, repeats the first of each, and assert_no_collision returns; guard_clean_then_assert_no_collision registers the adapter ids as real and different synthetic ids then returns null, and guard_assert_no_collision_lexicographic_first raises AdapterError",
        ),
    },
    // One guard_run. register_real then register_synthetic of the claude_code id.
    Row {
        name: "test_collision_guard_fires_on_synthetic_colliding_with_prior_real",
        disposition: Disposition::Covered {
            vector_ids: GUARD_SYNTHETIC_COLLIDES_REAL_IDS,
            needles: &[&[
                "\"type\": \"guard_run\"",
                "\"action\": \"register_real\"",
                "\"event_id\": \"sesslint:synthetic:claude_code:0:deadbeef\"",
                "\"action\": \"register_synthetic\"",
                "\"result\": \"error\"",
                "\"raises\": \"AdapterError\"",
                "\"display\": \"Synthetic ID collision: synthetic ID 'sesslint:synthetic:claude_code:0:deadbeef' collides with a previously seen real ID\"",
            ]],
        },
    },
    // One guard_run. register_synthetic then register_real of the openai_agents id.
    Row {
        name: "test_collision_guard_fires_on_real_colliding_with_prior_synthetic",
        disposition: Disposition::Covered {
            vector_ids: GUARD_REAL_COLLIDES_SYNTHETIC_IDS,
            needles: &[&[
                "\"type\": \"guard_run\"",
                "\"action\": \"register_synthetic\"",
                "\"event_id\": \"sesslint:synthetic:openai_agents:1:cafebabe\"",
                "\"action\": \"register_real\"",
                "\"result\": \"error\"",
                "\"raises\": \"AdapterError\"",
                "\"display\": \"Synthetic ID collision: real ID 'sesslint:synthetic:openai_agents:1:cafebabe' collides with a previously generated synthetic ID\"",
            ]],
        },
    },
    Row {
        name: "test_collision_guard_check_event",
        disposition: Disposition::NotApplicable(
            "check_event registers SessionEvent real_event_1 as real and sesslint:synthetic:claude_code:1:11223344 as synthetic, then raises AdapterError on a real event whose original_id is that synthetic id; guard_register_dispatches_is_synthetic_flag calls register on different ids and raises on a synthetic-after-real collision, and no adapters.synthetic vector records check_event",
        ),
    },
    Row {
        name: "test_namespace_squat_fixture_claude_code",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/adapters/namespace_squat.jsonl returns four events with ids rec_0, a claude_code synthetic at ordinal 1, rec_1, and a claude_code synthetic at ordinal 3, zero findings, and check_identities returns zero SL003 findings; load_claude_code does not return events in this tree, and no adapters.synthetic vector records that load",
        ),
    },
    Row {
        name: "test_namespace_squat_fixture_openai_agents",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of fixtures/adapters/namespace_squat.jsonl returns four events with ids rec_0, an openai_agents synthetic at ordinal 1, rec_1, and an openai_agents synthetic at ordinal 3, zero findings, and check_identities returns zero SL003 findings; load_openai_agents does not return events in this tree, and no adapters.synthetic vector records that load",
        ),
    },
    Row {
        name: "test_hostile_collision_claude_code_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a two-line JSONL file whose second id is synthetic_event_id for claude_code ordinal 0 of the first line raises AdapterError matching Synthetic ID collision; load_claude_code does not return events in this tree, and no adapters.synthetic vector records that load",
        ),
    },
    Row {
        name: "test_hostile_collision_openai_agents_jsonl_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a two-line JSONL file whose second id is synthetic_event_id for openai_agents ordinal 0 of the first line raises AdapterError matching Synthetic ID collision; load_openai_agents does not return events in this tree, and no adapters.synthetic vector records that load",
        ),
    },
    Row {
        name: "test_hostile_collision_openai_agents_json_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a JSON items document whose second id is synthetic_event_id for openai_agents ordinal 0 over canonical_bytes of the first item raises AdapterError matching Synthetic ID collision; load_openai_agents does not return events in this tree, and no adapters.synthetic vector records that load",
        ),
    },
    Row {
        name: "test_secondary_id_text_collision_claude_code_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_claude_code of rec_01 with text and tool_use content, then real id rec_01_text, raises AdapterError matching Synthetic ID collision; load_claude_code does not return events in this tree, and advance_bare_appends_one advances rec_item_text",
        ),
    },
    Row {
        name: "test_secondary_id_call_collision_claude_code_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_claude_code of rec_02 with two tool_use blocks, then real id rec_02_call_0, raises AdapterError matching Synthetic ID collision; load_claude_code does not return events in this tree, and advance_ascii_digit_suffix advances rec_item_call_2",
        ),
    },
    Row {
        name: "test_secondary_id_res_collision_claude_code_fails_closed",
        disposition: Disposition::NotApplicable(
            "load_claude_code of rec_03 with two tool_result blocks, then real id rec_03_res_0, raises AdapterError matching Synthetic ID collision; load_claude_code does not return events in this tree, and no adapters.synthetic vector records a _res_ suffix",
        ),
    },
    // Three _advance_synthetic_id calls. Each committed vector is one of those inputs.
    Row {
        name: "test_advance_synthetic_id_helper",
        disposition: Disposition::Covered {
            vector_ids: ADVANCE_HELPER_IDS,
            needles: &[
                &[
                    "\"type\": \"advance_synthetic_id\"",
                    "\"candidate_id\": \"sesslint:synthetic:adapter_test:3:12345678\"",
                    "\"result\": \"ok\"",
                    "\"value\": \"sesslint:synthetic:adapter_test:4:12345678\"",
                ],
                &[
                    "\"type\": \"advance_synthetic_id\"",
                    "\"candidate_id\": \"rec_item_call_2\"",
                    "\"result\": \"ok\"",
                    "\"value\": \"rec_item_call_3\"",
                ],
                &[
                    "\"type\": \"advance_synthetic_id\"",
                    "\"candidate_id\": \"rec_item_text\"",
                    "\"result\": \"ok\"",
                    "\"value\": \"rec_item_text_1\"",
                ],
            ],
        },
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_synthetic_event_id_format",
    "test_synthetic_event_id_hash_exact",
    "test_synthetic_event_id_determinism_and_differentiation",
    "test_synthetic_event_id_edge_cases",
    "test_is_synthetic_id",
    "test_collision_guard_clean_operation",
    "test_collision_guard_fires_on_synthetic_colliding_with_prior_real",
    "test_collision_guard_fires_on_real_colliding_with_prior_synthetic",
    "test_collision_guard_check_event",
    "test_namespace_squat_fixture_claude_code",
    "test_namespace_squat_fixture_openai_agents",
    "test_hostile_collision_claude_code_fails_closed",
    "test_hostile_collision_openai_agents_jsonl_fails_closed",
    "test_hostile_collision_openai_agents_json_fails_closed",
    "test_secondary_id_text_collision_claude_code_fails_closed",
    "test_secondary_id_call_collision_claude_code_fails_closed",
    "test_secondary_id_res_collision_claude_code_fails_closed",
    "test_advance_synthetic_id_helper",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_collision_guard_fires_on_synthetic_colliding_with_prior_real" => {
            Some(GUARD_SYNTHETIC_COLLIDES_REAL_IDS)
        }
        "test_collision_guard_fires_on_real_colliding_with_prior_synthetic" => {
            Some(GUARD_REAL_COLLIDES_SYNTHETIC_IDS)
        }
        "test_advance_synthetic_id_helper" => Some(ADVANCE_HELPER_IDS),
        _ => None,
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested step objects have no id key.
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
        .unwrap_or_else(|| panic!("adapters.synthetic vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
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
fn every_pinned_adapter_synthetic_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ADAPTER_VECTORS.len(), ADAPTER_VECTOR_COUNT);
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
                let expected = expected_covered_ids(row.name).unwrap_or_else(|| {
                    panic!(
                        "{} is not one of the three fully covered pin tests",
                        row.name
                    )
                });
                assert_eq!(vector_ids, expected, "{}", row.name);
                assert!(!vector_ids.is_empty(), "{}", row.name);
                assert_eq!(vector_ids.len(), needles.len(), "{}", row.name);
                for (vector_id, vector_needles) in vector_ids.iter().zip(needles.iter()) {
                    assert!(!vector_id.is_empty(), "{}", row.name);
                    assert!(!vector_needles.is_empty(), "{}", row.name);
                    assert!(
                        vector_needles
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
    assert_eq!(covered, 3);
    assert_eq!(not_applicable, 15);
}

#[test]
fn covered_vector_ids_are_present_in_adapter_synthetic_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapter synthetic vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.synthetic\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ADAPTER_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in ADAPTER_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"raises\":"),
            fails,
            "{id} error mode does not match the vector file"
        );
    }

    for row in ROWS {
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, vector_needles) in vector_ids.iter().zip(needles.iter()) {
            assert!(
                id_set.contains(vector_id),
                "{} names missing vector {vector_id}",
                row.name
            );
            let slice = vector_slice(&json, vector_id);
            for needle in *vector_needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
    }
}
