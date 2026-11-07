//! Dispositions for the 45 `def test_` functions in pinned
//! `tests/adapters/test_openai_agents.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (1029 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.adapters`.
//!
//! `covered` names every id in `adapters.openai_agents/vectors.json` whose
//! constructs together are the same function and the same success or failure
//! mode as that entire pinned test. One example inside a sweep, a different
//! input, or a shared field such as `supported_versions` is not coverage.
//! `not_applicable` records a `sesslint.adapters.openai_agents` call this
//! package cannot reach without a `Cargo.toml` change, or a mode no vector
//! records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 45;
const ADAPTER_VECTOR_COUNT: usize = 42;
const VECTORS_REL: &str = "parity/vectors/adapters.openai_agents/vectors.json";

/// `covered` names every vector id in `adapters.openai_agents/vectors.json`
/// that together match one entire pinned test. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change outside
/// the owned path, or a mode absent from that vector file.
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
/// A thrown loader failure is the key `"message"`. Scores, projections, pin
/// summaries, and gap assertions are not that key.
const ADAPTER_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("normalize_plain", "normalize_version", false),
    ("normalize_v_prefix", "normalize_version", false),
    ("normalize_whitespace_case", "normalize_version", false),
    ("normalize_openai_label", "normalize_version", false),
    ("detect_export_json", "detect_openai_agents", false),
    ("detect_run_state_wrapper", "detect_openai_agents", false),
    ("detect_sqlite_sqlite_name", "detect_openai_agents", false),
    ("detect_sqlite_json_name", "detect_openai_agents", false),
    ("detect_unrelated_txt", "detect_openai_agents", false),
    ("detect_empty_json", "detect_openai_agents", false),
    ("detect_function_call_tokens", "detect_openai_agents", false),
    ("detect_notes_txt", "detect_openai_agents", false),
    ("detect_call_id_only", "detect_openai_agents", false),
    ("detect_run_state_jsonl", "detect_openai_agents", false),
    ("detect_items_and_call", "detect_openai_agents", false),
    ("detect_tool_fields", "detect_openai_agents", false),
    ("detect_hello_session_json", "detect_openai_agents", false),
    ("detect_hello_session_db", "detect_openai_agents", false),
    ("run_state_none", "project_run_state", false),
    ("run_state_empty_dict", "project_run_state", false),
    ("run_state_irrelevant", "project_run_state", false),
    ("safe_type_str", "safe_type_value", false),
    ("safe_type_none", "safe_type_value", false),
    ("safe_type_list", "safe_type_value", false),
    ("safe_type_dict", "safe_type_value", false),
    ("load_empty_bytes", "load_openai_agents", false),
    ("load_whitespace_bytes", "load_openai_agents", false),
    ("load_bom_only", "load_openai_agents", false),
    ("gap_load_items_json", "load_openai_agents", false),
    ("gap_load_jsonl_line", "load_openai_agents", false),
    ("gap_load_bytes_input", "load_openai_agents", false),
    ("gap_sqlite_bytes", "load_openai_agents", false),
    ("gap_size_bytes", "load_openai_agents", false),
    ("gap_json_feed_blob", "load_openai_agents_json", false),
    ("gap_json_nul", "load_openai_agents_json", false),
    ("gap_jsonl_tail", "load_openai_agents_jsonl", false),
    ("gap_jsonl_object", "load_openai_agents_jsonl", false),
    ("gap_session_envelope", "load_openai_agents_session", false),
    ("load_bool_cap_true", "load_openai_agents", true),
    ("gap_process_message_item", "process_openai_item", false),
];

const DETECT_OPENAI_AGENTS_IDS: &[&str] = &[
    "detect_export_json",
    "detect_run_state_wrapper",
    "detect_sqlite_sqlite_name",
    "detect_sqlite_json_name",
    "detect_unrelated_txt",
    "detect_empty_json",
];

const NORMALIZE_VERSION_IDS: &[&str] = &[
    "normalize_plain",
    "normalize_v_prefix",
    "normalize_whitespace_case",
    "normalize_openai_label",
];

const DETECT_EXTENDED_IDS: &[&str] = &["detect_function_call_tokens"];

const RUN_STATE_EMPTY_IDS: &[&str] = &[
    "run_state_none",
    "run_state_empty_dict",
    "run_state_irrelevant",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_items_basic",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of fixtures/openai_agents/items_basic.json returns five events, zero findings, and to_canonical_json matches snapshots/openai_basic.canonical.json; gap_load_bytes_input is a different one-item document and a secret-scan gap",
        ),
    },
    Row {
        name: "test_run_state_checkpoints_preserved",
        disposition: Disposition::NotApplicable(
            "load_openai_agents and load_openai_agents_session of fixtures/openai_agents/run_state_checkpoint.json keep two checkpoints and thread_id thread_abc123; run_state_none is project_run_state of null, and gap_session_envelope loads a different document",
        ),
    },
    Row {
        name: "test_unknown_item_SL302",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of fixtures/openai_agents/unknown_item.json returns kind unknown and one SL302 for type futureTool; no adapters.openai_agents vector records SL302",
        ),
    },
    Row {
        name: "test_old_sdk_version_SL301",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of export_version 0.0.1 returns one SL301 whose version_raw is 0.0.1; module_constants lists supported versions and is not that load",
        ),
    },
    Row {
        name: "test_live_db_refused",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of fixtures/openai_agents/live_db_fake.sqlite returns one fatal SL001 refused_live_db and leaves the file digest and sqlite3 import unchanged; gap_sqlite_bytes is magic plus a marker under max_file_bytes 64 and stops at the fingerprint codec",
        ),
    },
    Row {
        name: "test_jsonl_stream",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of items_basic.json and of those items as JSONL returns equal canonical_bytes; gap_load_jsonl_line is one different JSONL line and a secret-scan gap",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "load_openai_agents twice on items_basic.json returns equal canonical JSON and equal finding dicts; no adapters.openai_agents vector calls the loader twice",
        ),
    },
    Row {
        name: "test_limit_gate",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a one-item JSON file with ReaderLimits max_file_bytes 10 returns SL001 size_limit_exceeded; gap_size_bytes is a different byte string under max_file_bytes 8",
        ),
    },
    // Six detect_openai_agents calls. Each committed vector is one of those inputs.
    Row {
        name: "test_detect_openai_agents",
        disposition: Disposition::Covered {
            vector_ids: DETECT_OPENAI_AGENTS_IDS,
            needles: &[
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"7b226974656d73223a205b7b226964223a202231222c202263616c6c5f6964223a20226331222c202274797065223a2022746f6f6c5f63616c6c227d5d7d\"",
                    "\"filename\": \"export.json\"",
                    "\"score\": 1.0",
                ],
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"7b2272756e5f7374617465223a207b7d2c2022636865636b706f696e7473223a205b5d7d\"",
                    "\"filename\": \"state.json\"",
                    "\"score\": 1.0",
                ],
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"53514c69746520666f726d6174203300\"",
                    "\"filename\": \"session.sqlite\"",
                    "\"score\": 1.0",
                ],
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"53514c69746520666f726d6174203300\"",
                    "\"filename\": \"session.json\"",
                    "\"score\": 0.5",
                ],
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"7b2272616e646f6d223a203132337d\"",
                    "\"filename\": \"other.txt\"",
                    "\"score\": 0.0",
                ],
                &[
                    "\"type\": \"detect_openai_agents\"",
                    "\"bytes_hex\": \"\"",
                    "\"filename\": \"empty.json\"",
                    "\"score\": 0.0",
                ],
            ],
        },
    },
    // Four normalize_version calls. Each committed vector is one of those inputs.
    Row {
        name: "test_normalize_version",
        disposition: Disposition::Covered {
            vector_ids: NORMALIZE_VERSION_IDS,
            needles: &[
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"1.0.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"v1.0.0\"",
                    "\"text\": \"1.0.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"  V0.2.0  \"",
                    "\"text\": \"0.2.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"openai-agents-v1\"",
                ],
            ],
        },
    },
    Row {
        name: "test_load_openai_agents_session",
        disposition: Disposition::NotApplicable(
            "load_openai_agents_session of fixtures/openai_agents/items_basic.json returns schema sesslint.session/v1, session_id openai-agents-session, and five events; gap_session_envelope loads an empty items document and stops before a Session envelope",
        ),
    },
    Row {
        name: "test_adversarial_sqlite_magic_renamed_to_json",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of SQLITE magic plus 32 zero bytes named sneaky.json returns fatal SL001 refused_live_db; detect_sqlite_json_name only scores session.json, and gap_sqlite_bytes appends a marker under max_file_bytes 64",
        ),
    },
    Row {
        name: "test_adversarial_items_as_dict",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of items as one object returns one event id single and zero findings; gap_load_items_json is an empty items array and a secret-scan gap",
        ),
    },
    Row {
        name: "test_adversarial_handoff_missing_target",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a handoff item without target returns kind handoff and target None; no adapters.openai_agents vector records that item",
        ),
    },
    Row {
        name: "test_adversarial_nul_byte",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a JSON document with a NUL between id and type returns one SL001; gap_json_nul is a lone NUL byte and stops at feed_blob",
        ),
    },
    Row {
        name: "test_adversarial_invalid_utf8",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a JSON document containing bytes ff fe returns one SL001 ENCODING finding; no adapters.openai_agents vector records those bytes",
        ),
    },
    Row {
        name: "test_adversarial_version_type_confusion",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of sdk_version as an object returns one SL301 whose version_raw is an invalid-type shape; normalize_version vectors take strings, and no vector records that document",
        ),
    },
    Row {
        name: "test_deep_nesting_limit",
        disposition: Disposition::NotApplicable(
            "load_openai_agents with ReaderLimits max_depth 5 on a 15-deep document returns one SL001 LIMIT finding; no adapters.openai_agents vector passes max_depth",
        ),
    },
    Row {
        name: "test_file_not_found",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a missing path raises FileNotFoundError; no adapters.openai_agents vector records that exception",
        ),
    },
    Row {
        name: "test_directory_path",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a directory raises IsADirectoryError; no adapters.openai_agents vector records that exception",
        ),
    },
    Row {
        name: "test_max_records_exceeded",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of three items with ReaderLimits max_records 2 raises MaxRecordsExceededError; no adapters.openai_agents vector records that exception",
        ),
    },
    Row {
        name: "test_jsonl_torn_tail_delegates_SL002",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of one complete JSONL line plus a torn second line returns one event and SL002 on line 2; gap_jsonl_tail is empty bytes and stops at MalformedTailTracker",
        ),
    },
    Row {
        name: "test_jsonl_malformed_midstream_delegates_SL001",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a corrupt middle JSONL line between two good lines returns two events and SL001 on line 2; gap_jsonl_object is an empty object and stops at MalformedTailTracker",
        ),
    },
    Row {
        name: "test_bytes_direct_input",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of bytes whose message content is from_bytes returns event id m1 and zero findings; gap_load_bytes_input uses content x and stops at SecretScanTracker",
        ),
    },
    Row {
        name: "test_source_metadata_attribute_error",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of an empty items document then a missing source attribute raises AttributeError; gap_load_items_json is that document as a secret-scan gap and does not read the attribute",
        ),
    },
    // One detect_openai_agents call. detect_function_call_tokens is that input.
    Row {
        name: "test_detect_openai_agents_extended_signals",
        disposition: Disposition::Covered {
            vector_ids: DETECT_EXTENDED_IDS,
            needles: &[&[
                "\"type\": \"detect_openai_agents\"",
                "\"bytes_hex\": \"7b2274797065223a202266756e6374696f6e5f63616c6c222c20226e616d65223a2022646f5f7461736b222c202268616e646f6666223a20747275657d\"",
                "\"filename\": \"session.json\"",
                "\"score\": 1.0",
            ]],
        },
    },
    Row {
        name: "test_tool_call_json_string_input",
        disposition: Disposition::NotApplicable(
            "load_openai_agents decodes a tool_call args JSON string into payload input; gap_process_message_item is a message item and stops at the content-hash seam",
        ),
    },
    Row {
        name: "test_checkpoint_and_compaction_items",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of one checkpoint item and one compaction_boundary item returns those kinds and payload fields; module_constants maps the type names and is not that load",
        ),
    },
    Row {
        name: "test_json_doc_top_level_list_and_non_dict_items",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a top-level list with one message and one string returns one event and SL001 item_not_dict; no adapters.openai_agents vector records that document",
        ),
    },
    Row {
        name: "test_role_dispatches_and_missing_type",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of seven role rows returns system, tool, user, assistant, and unknown kinds; module_constants item_type_map is not that load, and one row would not be the sweep",
        ),
    },
    Row {
        name: "test_critical_field_sl302",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of critical_flag returns one SL302 whose field_path is critical_flag; module_constants lists critical key names and does not record that finding",
        ),
    },
    Row {
        name: "test_tool_result_failure_state",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a tool_result with is_error true returns execution_state failure; no adapters.openai_agents vector records that item",
        ),
    },
    Row {
        name: "test_jsonl_hostile_limits_matrix",
        disposition: Disposition::NotApplicable(
            "load_openai_agents covers a NUL line, invalid UTF-8, max_line_bytes 50, and max_depth 5; gap_json_nul is one NUL byte at feed_blob, so none of the gap vectors is the whole sweep",
        ),
    },
    // Three project_run_state calls. Each committed vector is one of those inputs.
    Row {
        name: "test_project_run_state_empty_and_absent",
        disposition: Disposition::Covered {
            vector_ids: RUN_STATE_EMPTY_IDS,
            needles: &[
                &[
                    "\"type\": \"project_run_state\"",
                    "\"kind\": \"null\"",
                    "\"checkpoints\": []",
                    "\"keys\": []",
                    "\"shapes\": {}",
                    "\"truncated\": false",
                ],
                &[
                    "\"type\": \"project_run_state\"",
                    "\"kind\": \"map\"",
                    "\"entries\": []",
                    "\"checkpoints\": []",
                    "\"keys\": []",
                    "\"shapes\": {}",
                    "\"truncated\": false",
                ],
                &[
                    "\"type\": \"project_run_state\"",
                    "\"text\": \"irrelevant_field\"",
                    "\"kind\": \"int\"",
                    "\"value\": 123",
                    "\"checkpoints\": []",
                    "\"keys\": []",
                    "\"shapes\": {}",
                    "\"truncated\": false",
                ],
            ],
        },
    },
    Row {
        name: "test_project_run_state_bounding_and_truncation",
        disposition: Disposition::NotApplicable(
            "project_run_state of 40 keys and 12 checkpoints returns 32 keys, 8 checkpoints, and truncated true; run_state_irrelevant is one irrelevant key and truncated false",
        ),
    },
    Row {
        name: "test_project_run_state_content_redaction_and_shapes",
        disposition: Disposition::NotApplicable(
            "project_run_state shapes five run_state values and one checkpoint without echoing raw text; safe_type_str, safe_type_list, and safe_type_dict are one value each, so none is the whole projection",
        ),
    },
    Row {
        name: "test_project_run_state_object_attributes",
        disposition: Disposition::NotApplicable(
            "project_run_state of an object with run_state and one checkpoint object returns key state_var and checkpoint id chk_obj; no adapters.openai_agents vector records an object source",
        ),
    },
    Row {
        name: "test_project_run_state_non_string_keys_and_collisions",
        disposition: Disposition::NotApplicable(
            "project_run_state of integer keys, spaced keys, and a secret-shaped checkpoint id returns four keys and a redacted id; no adapters.openai_agents vector records those keys",
        ),
    },
    Row {
        name: "test_project_run_state_no_bypass_hostile_input",
        disposition: Disposition::NotApplicable(
            "project_run_state of 50 keys, 20 checkpoints, and planted projection fields, then two object forms, stays clamped and truncated; run_state_irrelevant is one key and truncated false, so it is not that sweep",
        ),
    },
    Row {
        name: "test_handoff_benign_reason_echoed",
        disposition: Disposition::NotApplicable(
            "load_openai_agents keeps handoff reason user_escalation and target support_agent; no adapters.openai_agents vector records that item",
        ),
    },
    Row {
        name: "test_handoff_secret_reason_bounded",
        disposition: Disposition::NotApplicable(
            "load_openai_agents bounds a secret-shaped handoff reason to a length shape and omits the raw reason; no adapters.openai_agents vector records that reason",
        ),
    },
    Row {
        name: "test_handoff_hostile_prose_reason_bounded",
        disposition: Disposition::NotApplicable(
            "load_openai_agents bounds a repeated prose handoff reason to a length shape; no adapters.openai_agents vector records that reason",
        ),
    },
    Row {
        name: "test_naive_timestamp_preserves_naive",
        disposition: Disposition::NotApplicable(
            "load_openai_agents keeps timestamp 2026-01-01T12:00:00 without a trailing Z; no adapters.openai_agents vector records that timestamp",
        ),
    },
    Row {
        name: "test_falsy_call_id_and_input_preserved",
        disposition: Disposition::NotApplicable(
            "load_openai_agents keeps call_id 0, empty call_id, input value 0, and empty output across three items; no adapters.openai_agents vector records those items",
        ),
    },
    Row {
        name: "test_stream_read_bounded_refuses_oversized",
        disposition: Disposition::NotApplicable(
            "load_openai_agents of a stream longer than max_file_bytes 100 returns one SL001 LIMIT finding; gap_size_bytes is a different byte string under max_file_bytes 8 and is not a stream",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_items_basic",
    "test_run_state_checkpoints_preserved",
    "test_unknown_item_SL302",
    "test_old_sdk_version_SL301",
    "test_live_db_refused",
    "test_jsonl_stream",
    "test_determinism",
    "test_limit_gate",
    "test_detect_openai_agents",
    "test_normalize_version",
    "test_load_openai_agents_session",
    "test_adversarial_sqlite_magic_renamed_to_json",
    "test_adversarial_items_as_dict",
    "test_adversarial_handoff_missing_target",
    "test_adversarial_nul_byte",
    "test_adversarial_invalid_utf8",
    "test_adversarial_version_type_confusion",
    "test_deep_nesting_limit",
    "test_file_not_found",
    "test_directory_path",
    "test_max_records_exceeded",
    "test_jsonl_torn_tail_delegates_SL002",
    "test_jsonl_malformed_midstream_delegates_SL001",
    "test_bytes_direct_input",
    "test_source_metadata_attribute_error",
    "test_detect_openai_agents_extended_signals",
    "test_tool_call_json_string_input",
    "test_checkpoint_and_compaction_items",
    "test_json_doc_top_level_list_and_non_dict_items",
    "test_role_dispatches_and_missing_type",
    "test_critical_field_sl302",
    "test_tool_result_failure_state",
    "test_jsonl_hostile_limits_matrix",
    "test_project_run_state_empty_and_absent",
    "test_project_run_state_bounding_and_truncation",
    "test_project_run_state_content_redaction_and_shapes",
    "test_project_run_state_object_attributes",
    "test_project_run_state_non_string_keys_and_collisions",
    "test_project_run_state_no_bypass_hostile_input",
    "test_handoff_benign_reason_echoed",
    "test_handoff_secret_reason_bounded",
    "test_handoff_hostile_prose_reason_bounded",
    "test_naive_timestamp_preserves_naive",
    "test_falsy_call_id_and_input_preserved",
    "test_stream_read_bounded_refuses_oversized",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_detect_openai_agents" => Some(DETECT_OPENAI_AGENTS_IDS),
        "test_normalize_version" => Some(NORMALIZE_VERSION_IDS),
        "test_detect_openai_agents_extended_signals" => Some(DETECT_EXTENDED_IDS),
        "test_project_run_state_empty_and_absent" => Some(RUN_STATE_EMPTY_IDS),
        _ => None,
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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
        .unwrap_or_else(|| panic!("adapters.openai_agents vectors.json is missing id {id}"));
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
fn every_pinned_adapter_openai_agents_test_has_one_disposition() {
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
                        "{} is not one of the four fully covered pin tests",
                        row.name
                    )
                });
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
    assert_eq!(covered, 4);
    assert_eq!(not_applicable, 41);
}

#[test]
fn covered_vector_ids_are_present_in_adapter_openai_agents_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapter openai_agents vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.openai_agents\""));

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
            slice.contains("\"message\":"),
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
        for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
            assert!(
                id_set.contains(vector_id),
                "{} names missing vector {vector_id}",
                row.name
            );
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
}
