//! Dispositions for the fifty-eight `def test_` functions in pinned
//! `tests/adapters/test_codex_rollout.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (686 splitlines). Exactly
//! fifty-eight test functions, in class order. None is parametrized. The
//! helpers `_env`, `_item`, and `_jsonl` are not tests. Each row is the whole
//! function. Two asserts in one function are one row. A load is not a
//! check_file. A check_file is not api.repair. A warning is not an error. One
//! fixture is not the next fixture. Record bodies, paths, secrets, and fixture
//! bytes are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call adapter, api, or repair
//! functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. `parity/vectors/cli/vectors.json` has 33 vectors at this pin and
//! they are parser metadata. None of those 33 is one of these fifty-eight
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids:
//! envelopes, directory limits, discovery, module constants, plan and repair
//! rejection, thresholds, and validate_session. None of those 77 is one of
//! these fifty-eight functions. `repair_emit_reject_*` is not a successful
//! vendor or canonical repair.
//! `parity/vectors/adapters.codex_rollout/vectors.json`, `adapters.synthetic`,
//! `adapters`, `adapters.detect`, `codes`, `canonical`, and `io` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and are not Covered sources.
//! Similar e91 ids such as `detect_rollout_filename`, `detect_session_txt`,
//! `detect_empty_rollout_jsonl`, and `is_synthetic_id_prefix_with_tail` are
//! not these pytest functions. Therefore every row is NotApplicable.
//! `not_applicable` names the missing stop and the nearest different test.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 58;
const PINNED_SPLITLINES: usize = 686;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A load is not a check_file. A check_file is not api.repair. A
/// warning is not an error. One fixture is not the next fixture.
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
        name: "test_detect_rollout_envelope",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_detect_rollout_envelope: detect of a rollout-named jsonl scores 1.0; missing stop: that rollout-named score of 1.0; test_detect_without_rollout_filename scores session.jsonl at 1.0 and is not this pytest",
        ),
    },
    Row {
        name: "test_detect_without_rollout_filename",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_detect_without_rollout_filename: detect of session.jsonl scores 1.0; missing stop: that session.jsonl score of 1.0; test_detect_rollout_envelope scores a rollout-named jsonl at 1.0 and is not this pytest",
        ),
    },
    Row {
        name: "test_detect_rejects_non_jsonl_extension",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_detect_rejects_non_jsonl_extension: session.txt and a sqlite-named path both score 0.0; missing stop: both extension scores; both scores are one row; test_detect_empty_and_sqlite scores empty bytes and a sqlite-magic prefix on a jsonl name and is not this pytest",
        ),
    },
    Row {
        name: "test_detect_empty_and_sqlite",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_detect_empty_and_sqlite: empty bytes and a sqlite-magic prefix both score 0.0 on a jsonl name; missing stop: both detect scores; both are one row; the load refusal is not this detect",
        ),
    },
    Row {
        name: "test_detect_weak_signal_partial",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_detect_weak_signal_partial: an ordinal-plus-payload line with no envelope type scores strictly between 0 and 1; missing stop: that partial score; a score of 1.0 is not this pytest",
        ),
    },
    Row {
        name: "test_healthy_min_events",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_healthy_min_events: healthy_min has zero findings and three events, opaque with system, message with user, and message with assistant; missing stop: that whole healthy_min load; all of those are one row; parentage is not this pytest",
        ),
    },
    Row {
        name: "test_linear_parentage",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_linear_parentage: the same fixture has a none parent, then each event parents the previous id; missing stop: that parent chain; all of those are one row; test_healthy_min_events asserts event kinds and is not this pytest",
        ),
    },
    Row {
        name: "test_source_coords_preserved",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_source_coords_preserved: every event has a source line at least 1, a sha256 source hash, and adapter codex-rollout; missing stop: those source coordinates on every event; all of those are one row; parentage is not this pytest",
        ),
    },
    Row {
        name: "test_message_roles",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_message_roles: user, assistant, developer mapped to system, and agent_message mapped to assistant message; missing stop: those four role mappings; all of those are one row; the healthy fixture is not this pytest",
        ),
    },
    Row {
        name: "test_reasoning_is_opaque",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_reasoning_is_opaque: reasoning is opaque, actor assistant, and encrypted_content is absent from the payload; missing stop: those three assertions; all three are one row; test_opaque_envelopes keeps a session id and a turn id and is not this pytest",
        ),
    },
    Row {
        name: "test_opaque_envelopes",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_opaque_envelopes: five envelopes are all opaque and system, and only the session id and turn id are kept; missing stop: those five envelopes; all of those are one row; test_compacted_maps_compaction_boundary is not this pytest",
        ),
    },
    Row {
        name: "test_compacted_maps_compaction_boundary",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_compacted_maps_compaction_boundary: the compacted envelope is kind compaction_boundary and actor system; missing stop: that compacted mapping; both are one row; the five opaque envelopes test is not this pytest",
        ),
    },
    Row {
        name: "test_session_meta_source_metadata",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_session_meta_source_metadata: session metadata keeps cli_version and session_id, and cwd is absent; missing stop: those metadata assertions; all of those are one row; test_cli_version_not_version_gated is not this pytest",
        ),
    },
    Row {
        name: "test_token_usage_record_uses_usage_as_contribution",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_token_usage_record_uses_usage_as_contribution: usage is the contribution slot and thread usage is the cumulative slot, for two records; missing stop: both records' contribution and cumulative slots; both records are one row; the no-slot test is not this pytest",
        ),
    },
    Row {
        name: "test_token_usage_record_without_usage_emits_no_slot",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_token_usage_record_without_usage_emits_no_slot: a record without usage has no usage extra field; missing stop: that absent usage field; the contribution mapping is not this pytest",
        ),
    },
    Row {
        name: "test_turn_cumulative_growth_does_not_fire_sl204",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_turn_cumulative_growth_does_not_fire_sl204: check_file of growing turn cumulatives has no SL204; missing stop: that silent check_file; the divergence test is not this pytest",
        ),
    },
    Row {
        name: "test_usage_thread_divergence_still_fires_sl204",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_usage_thread_divergence_still_fires_sl204: check_file finds exactly one SL204; missing stop: that single SL204; the silent growth test is not this pytest",
        ),
    },
    Row {
        name: "test_timestamp_normalization",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_timestamp_normalization: a supplied timestamp is kept, and a missing timestamp becomes the epoch; missing stop: both timestamp loads; both loads are one row; test_session_meta_source_metadata keeps metadata and is not this pytest",
        ),
    },
    Row {
        name: "test_function_call_pairs_via_call_id",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_function_call_pairs_via_call_id: parallel_tool call ids equal result ids, calls are assistant, and results are tool with success and side effect none; missing stop: that whole pairing; all of those are one row; the custom-tool fixture is not this pytest",
        ),
    },
    Row {
        name: "test_custom_tool_call_pairs",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_custom_tool_call_pairs: the custom-tool call is a tool call, the custom-tool result is a tool result, and the two events share one correlation id; missing stop: that shared correlation id; all of those are one row; the parallel fixture is not this pytest",
        ),
    },
    Row {
        name: "test_tool_call_arguments_parsed",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tool_call_arguments_parsed: the function-call payload has a parsed input, a tool name, and a tool id; missing stop: those three payload fields; all three are one row; the pairing test is not this pytest",
        ),
    },
    Row {
        name: "test_orphan_output_detected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_orphan_output_detected: check_file of orphan_output finds SL101; missing stop: that SL101; the dangling fixture is not this pytest",
        ),
    },
    Row {
        name: "test_dangling_call_detected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_dangling_call_detected: check_file of dangling_call finds SL102; missing stop: that SL102; the tail-loss fixture is not this pytest",
        ),
    },
    Row {
        name: "test_tail_loss_dangling_detected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tail_loss_dangling_detected: check_file of tail_loss finds SL102; missing stop: that SL102; the dangling fixture is not this pytest",
        ),
    },
    Row {
        name: "test_duplicate_ordinal_breaks_chain",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_duplicate_ordinal_breaks_chain: findings include SL006 or SL007; missing stop: that either-code finding; a single required code is not this pytest",
        ),
    },
    Row {
        name: "test_async_pairing_profile_interplay",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_async_pairing_profile_interplay: neutral SL107 is warning and openai-strict SL107 is error; missing stop: both profiles; both profiles are one row; a warning is not an error; test_orphan_output_detected is one check_file and is not this pytest",
        ),
    },
    Row {
        name: "test_unknown_version_sl301",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unknown_version_sl301: SL301 evidence has the raw version and the supported set; missing stop: that evidence pair; both evidence fields are one row; the type-error test is not this pytest",
        ),
    },
    Row {
        name: "test_supported_version_marker_no_finding",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_supported_version_marker_no_finding: rollout_version 1.0.0 produces no SL301; missing stop: that absent SL301; it does not assert event count; test_unknown_version_sl301 asserts the raw version and is not this pytest",
        ),
    },
    Row {
        name: "test_invalid_version_type_sl301",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_invalid_version_type_sl301: a non-string rollout_version produces SL301; missing stop: that type-error SL301; the raw-version evidence test is not this pytest",
        ),
    },
    Row {
        name: "test_unknown_non_linking_envelope_type_is_advisory",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unknown_non_linking_envelope_type_is_advisory: one SL306 at info, the type value is the mystery envelope, and SL302 is absent; missing stop: that advisory triple; all of those are one row; the payload-type test is not this pytest",
        ),
    },
    Row {
        name: "test_unknown_payload_type_sl302",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unknown_payload_type_sl302: SL302 evidence carries the payload type value; missing stop: that payload type evidence; the advisory test is not this pytest",
        ),
    },
    Row {
        name: "test_non_mapping_payload_sl302",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_non_mapping_payload_sl302: a non-mapping payload produces SL302; missing stop: that non-mapping SL302; the field-path test is not this pytest",
        ),
    },
    Row {
        name: "test_unknown_critical_field_sl302",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unknown_critical_field_sl302: SL302 evidence field_path is the unknown critical field; missing stop: that field_path; the non-mapping test is not this pytest",
        ),
    },
    Row {
        name: "test_cli_version_not_version_gated",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_cli_version_not_version_gated: a cli_version does not produce SL301; missing stop: that absent SL301; the rollout_version test is not this pytest",
        ),
    },
    Row {
        name: "test_torn_tail_sl002",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_torn_tail_sl002: torn_tail has SL002 and not SL001; missing stop: that SL002-without-SL001 load; both are one row; the mid-line test is not this pytest",
        ),
    },
    Row {
        name: "test_malformed_escaped_mid_line_sl001",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_malformed_escaped_mid_line_sl001: SL001 source line is 2 and the last event parent is none; missing stop: that line and that parent; both are one row; the torn-tail test is not this pytest",
        ),
    },
    Row {
        name: "test_nul_byte_rejected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_nul_byte_rejected: a newline-terminated NUL is SL001 with NUL in the message and not SL002; missing stop: that NUL finding; all of those are one row; the padded torn tail is not this pytest",
        ),
    },
    Row {
        name: "test_nul_padded_torn_tail_is_sl002",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_nul_padded_torn_tail_is_sl002: one SL002 whose evidence unterminated is true; missing stop: that unterminated SL002; both are one row; the newline NUL test is not this pytest",
        ),
    },
    Row {
        name: "test_invalid_utf8",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_invalid_utf8: a message contains UTF-8; missing stop: that UTF-8 message; it does not assert a code; test_nul_byte_rejected asserts SL001 and is not this pytest",
        ),
    },
    Row {
        name: "test_oversize_line",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_oversize_line: max_line_bytes 256 yields a line byte limit message; missing stop: that line byte limit; the file-size test is not this pytest",
        ),
    },
    Row {
        name: "test_oversize_file",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_oversize_file: max_file_bytes 64 yields a file size message; missing stop: that file size message; the line-limit test is not this pytest",
        ),
    },
    Row {
        name: "test_max_records",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_max_records: max_records 1 raises MaxRecordsExceededError; missing stop: that raise; a finding is not this raise",
        ),
    },
    Row {
        name: "test_deep_nesting",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_deep_nesting: max_depth 3 yields a depth message; missing stop: that depth message; the NaN test is not this pytest",
        ),
    },
    Row {
        name: "test_strict_json_constants_rejected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_strict_json_constants_rejected: NaN yields at least one finding; missing stop: that finding; a depth message is not this pytest",
        ),
    },
    Row {
        name: "test_non_dict_record_malformed",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_non_dict_record_malformed: a non-dict record yields SL001 or SL002; missing stop: that either-code finding; the sqlite refusal is not this pytest",
        ),
    },
    Row {
        name: "test_sqlite_refusal",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_sqlite_refusal: the first finding is SL001, fatal, and reason refused_live_db; missing stop: that refused load; all three are one row; the detect sqlite score is not this load",
        ),
    },
    Row {
        name: "test_empty_stream",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_empty_stream: empty bytes yield zero events and zero findings; missing stop: that empty load; both are one row; the detect empty score is not this load",
        ),
    },
    Row {
        name: "test_synthetic_ids_for_missing_payload_id",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_synthetic_ids_for_missing_payload_id: three events, each id is synthetic with the codex_rollout prefix, and original_id is none; missing stop: those three synthetic ids; all of those are one row; the native-id test is not this pytest",
        ),
    },
    Row {
        name: "test_native_ids_preserved",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_native_ids_preserved: one event id equals its original id; missing stop: that preserved id; the synthetic test is not this pytest",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_determinism: two loads match ids, content hashes, and finding code plus message; missing stop: that three-way match; all three matches are one row; the stream-length test is not this pytest",
        ),
    },
    Row {
        name: "test_session_wrap",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_session_wrap: the result is a Session, schema sesslint.session/v1, a session id, eleven events, and zero findings; missing stop: that whole session wrap; all of those are one row; the stream load is not this wrap",
        ),
    },
    Row {
        name: "test_source_immutability",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_source_immutability: load and check_file leave the file bytes unchanged; missing stop: both calls and the unchanged bytes; both calls are one row; test_stream_input is a load only and is not this pytest",
        ),
    },
    Row {
        name: "test_stream_input",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_stream_input: a BytesIO load has eleven events and zero findings; missing stop: that stream load; both are one row; the session wrap is not this pytest",
        ),
    },
    Row {
        name: "test_no_content_in_findings",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_no_content_in_findings: the type discriminator is present in evidence, and content and arguments keys are absent; missing stop: that evidence shape; all of those are one row; test_unknown_payload_type_sl302 asserts the payload type value and is not this pytest",
        ),
    },
    Row {
        name: "test_repair_auto_emits_vendor_writeback",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_repair_auto_emits_vendor_writeback: api.repair returns a manifest with adapter codex-rollout, the first output record type is session_meta, and the only recipe is torn-terminal-record-discard; missing stop: that vendor writeback; all of those are one row; the explicit vendor emit is not this pytest",
        ),
    },
    Row {
        name: "test_repair_vendor_emit_accepted",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_repair_vendor_emit_accepted: api.repair emit vendor returns adapter codex-rollout and the output file exists; missing stop: that vendor emit; both are one row; it does not assert the recipe; test_repair_auto_emits_vendor_writeback asserts the recipe and is not this pytest",
        ),
    },
    Row {
        name: "test_repair_canonical_emit",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_repair_canonical_emit: api.repair emit canonical returns adapter canonical and the first record schema is sesslint.session/v1; missing stop: that canonical emit; both are one row; the vendor emit is not this pytest",
        ),
    },
    Row {
        name: "test_repair_dry_run_no_writes",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_repair_dry_run_no_writes: api.repair dry_run returns no manifest, one plan step, and an empty directory; missing stop: that dry run; all three are one row; a written file is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_detect_rollout_envelope",
    "test_detect_without_rollout_filename",
    "test_detect_rejects_non_jsonl_extension",
    "test_detect_empty_and_sqlite",
    "test_detect_weak_signal_partial",
    "test_healthy_min_events",
    "test_linear_parentage",
    "test_source_coords_preserved",
    "test_message_roles",
    "test_reasoning_is_opaque",
    "test_opaque_envelopes",
    "test_compacted_maps_compaction_boundary",
    "test_session_meta_source_metadata",
    "test_token_usage_record_uses_usage_as_contribution",
    "test_token_usage_record_without_usage_emits_no_slot",
    "test_turn_cumulative_growth_does_not_fire_sl204",
    "test_usage_thread_divergence_still_fires_sl204",
    "test_timestamp_normalization",
    "test_function_call_pairs_via_call_id",
    "test_custom_tool_call_pairs",
    "test_tool_call_arguments_parsed",
    "test_orphan_output_detected",
    "test_dangling_call_detected",
    "test_tail_loss_dangling_detected",
    "test_duplicate_ordinal_breaks_chain",
    "test_async_pairing_profile_interplay",
    "test_unknown_version_sl301",
    "test_supported_version_marker_no_finding",
    "test_invalid_version_type_sl301",
    "test_unknown_non_linking_envelope_type_is_advisory",
    "test_unknown_payload_type_sl302",
    "test_non_mapping_payload_sl302",
    "test_unknown_critical_field_sl302",
    "test_cli_version_not_version_gated",
    "test_torn_tail_sl002",
    "test_malformed_escaped_mid_line_sl001",
    "test_nul_byte_rejected",
    "test_nul_padded_torn_tail_is_sl002",
    "test_invalid_utf8",
    "test_oversize_line",
    "test_oversize_file",
    "test_max_records",
    "test_deep_nesting",
    "test_strict_json_constants_rejected",
    "test_non_dict_record_malformed",
    "test_sqlite_refusal",
    "test_empty_stream",
    "test_synthetic_ids_for_missing_payload_id",
    "test_native_ids_preserved",
    "test_determinism",
    "test_session_wrap",
    "test_source_immutability",
    "test_stream_input",
    "test_no_content_in_findings",
    "test_repair_auto_emits_vendor_writeback",
    "test_repair_vendor_emit_accepted",
    "test_repair_canonical_emit",
    "test_repair_dry_run_no_writes",
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

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
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
fn pinned_test_codex_rollout_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 686);
}

#[test]
fn pinned_test_codex_rollout_row_count_equals_fifty_eight() {
    assert_eq!(ROWS.len(), 58);
    assert_eq!(PINNED_TEST_COUNT, 58);
}

#[test]
fn every_pinned_test_codex_rollout_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 58);
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
    let path = vectors_path(CLI_VECTORS_REL);
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

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 58);

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
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
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
