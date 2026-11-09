//! Dispositions for the 15 `def test_` functions in pinned
//! `tests/test_wave1_correctness.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (302 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` would name one vector whose construct is the same function and
//! the same success or failure mode as that entire pinned test. No pinned
//! test has such a vector. `not_applicable` is the disposition for all 15.
//! A partial vector, a different input, or a seam that returns unavailable
//! is not coverage. This file does not invent a passing `verify()`, canonical
//! dump, or scan result.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const ANCESTOR_PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 15;
const ID_MARKER: &str = "\n      \"id\": \"";

const HYGIENE_REL: &str = "parity/vectors/checks.hygiene/vectors.json";
const CANONICAL_REL: &str = "parity/vectors/canonical/vectors.json";
const VERIFY_REL: &str = "parity/vectors/verify/vectors.json";
const INDEXES_REL: &str = "parity/vectors/indexes/vectors.json";
const MCP_REL: &str = "parity/vectors/mcp_server/vectors.json";
const CACHE_REL: &str = "parity/vectors/cache/vectors.json";
const BUNDLE_REL: &str = "parity/vectors/bundle/vectors.json";
const SARIF_REL: &str = "parity/vectors/sarif/vectors.json";
const CODEC_REL: &str = "parity/vectors/_canonical_codec/vectors.json";
const SAFE_VALUE_REL: &str = "parity/vectors/adapters.safe_value/vectors.json";
const ATOMIC_REL: &str = "parity/vectors/atomic/vectors.json";

/// `covered` names one vector id. `not_applicable` records a mode this package
/// cannot reach without a `Cargo.toml` change, or a mode no one vector records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
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
        name: "test_secret_shapes_after_real_json_escapes_are_detected",
        disposition: Disposition::NotApplicable(
            "parametrized SecretScanTracker.into_findings for five JSON escapes and six families; tracker_json_escape_enables_match is one hex 785c6e sk- feed, and a hit makes into_findings return sesslint.determinism.canonical_json_bytes is not available",
        ),
    },
    Row {
        name: "test_escaped_backslash_text_does_not_create_a_secret_boundary",
        disposition: Disposition::NotApplicable(
            "a literal backslash before n must not yield openai-api-key; no hygiene vector feeds that record, and a hit returns the fingerprint codec unavailable instead of a finding list",
        ),
    },
    Row {
        name: "test_escape_run_parity_preserves_secret_boundaries",
        disposition: Disposition::NotApplicable(
            "Hypothesis over backslash runs 1 through 256; this package has no proptest, and no one hygiene vector is that parity",
        ),
    },
    Row {
        name: "test_private_key_digest_uses_original_bytes_after_escape_shadow",
        disposition: Disposition::NotApplicable(
            "into_findings match_sha256 must be the unshadowed private-key bytes; Rust into_findings returns the fingerprint codec unavailable on a hit, and tracker_sort_line_ordinal_family hashes a different feed",
        ),
    },
    Row {
        name: "test_secret_window_keeps_stripped_record_boundaries",
        disposition: Disposition::NotApplicable(
            "two offset-free feeds must yield findings [npm-token]; into_findings errors when a hit exists, and tracker_line_gate_skips_clean_record is an openai key with offsets",
        ),
    },
    Row {
        name: "test_short_prefix_gate_preserves_reference_boundaries",
        disposition: Disposition::NotApplicable(
            "Hypothesis that short_prefix_present matches a reference regex; short_prefix_escape_n is only hex 5c6e68665f, and this package has no proptest",
        ),
    },
    Row {
        name: "test_shared_secret_families_are_detected_and_never_echoed",
        disposition: Disposition::NotApplicable(
            "six rows need a hygiene finding and a truncated safe_discriminator; into_findings errors on a hit, and no one safe_value vector is that pair",
        ),
    },
    Row {
        name: "test_azure_and_gcp_service_account_secret_shapes_are_detected",
        disposition: Disposition::NotApplicable(
            "AccountKey and GCP private-key findings plus three safe_discriminator calls; cloud_azure_client_secret_16 and allowlist_echo_npm_package_metadata are single discriminator calls, and into_findings does not return those findings",
        ),
    },
    Row {
        name: "test_dump_session_file_uses_atomic_writer_and_lf",
        disposition: Disposition::NotApplicable(
            "dump_session_file must call atomic_write_text with utf-8 LF text; Rust returns sesslint._canonical_codec.canonical_json_bytes is not available and writes nothing; text_utf8_default_digest is a different write",
        ),
    },
    Row {
        name: "test_jsonl_readers_treat_unicode_separators_as_json_string_content",
        disposition: Disposition::NotApplicable(
            "load_session_file, _parse_session_events, and read_index on one U+2028/U+2029/U+0085 payload with index id thread-1; load_session_file_small_jsonl and parse_accepts_valid_jsonl are other ledgers; verify() returns sesslint.report.parse_manifest is not available and is not this success",
        ),
    },
    Row {
        name: "test_mcp_bounds_oversized_jsonl_and_recursion_failures",
        disposition: Disposition::NotApplicable(
            "serve of an oversized line then ping, bounded readline sizes, and handle_line of 2000 brackets; serve_oversized_then_ping omits readline sizes and deep_brackets_parse_error is a separate call",
        ),
    },
    Row {
        name: "test_index_and_cache_recursion_fail_closed",
        disposition: Disposition::NotApplicable(
            "read_index of 2000 brackets is not parse_ok and ScanCache.get of that text is None; no index vector is that file, and row-json-0 injects '{' then returns a healthy payload",
        ),
    },
    Row {
        name: "test_bundle_chunk_count_matches_physical_lf_reference",
        disposition: Disposition::NotApplicable(
            "Hypothesis that _count_records_bounded matches a physical LF count up to 80000 bytes; count_split_chunk counts fixtures/split.jsonl as 1, and this package has no proptest",
        ),
    },
    Row {
        name: "test_sarif_artifact_uri_percent_encodes_path_bytes",
        disposition: Disposition::NotApplicable(
            "make_finding with message Synthetic malformed record then render_sarif; make_finding without a fingerprint returns sesslint.determinism.canonical_json_bytes is not available; render_sarif_relative_percent_encode uses message synthetic path marker and a fixed fingerprint",
        ),
    },
    Row {
        name: "test_deterministic_python_codec_wording_and_bytes_are_stable",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes of a, x, n 0.0, and z true/null with newline false, plus a docstring without RFC 8785; canonical_flat_object is a different object, and content_identity_bytes_unsupported returns Unsupported",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_secret_shapes_after_real_json_escapes_are_detected",
    "test_escaped_backslash_text_does_not_create_a_secret_boundary",
    "test_escape_run_parity_preserves_secret_boundaries",
    "test_private_key_digest_uses_original_bytes_after_escape_shadow",
    "test_secret_window_keeps_stripped_record_boundaries",
    "test_short_prefix_gate_preserves_reference_boundaries",
    "test_shared_secret_families_are_detected_and_never_echoed",
    "test_azure_and_gcp_service_account_secret_shapes_are_detected",
    "test_dump_session_file_uses_atomic_writer_and_lf",
    "test_jsonl_readers_treat_unicode_separators_as_json_string_content",
    "test_mcp_bounds_oversized_jsonl_and_recursion_failures",
    "test_index_and_cache_recursion_fail_closed",
    "test_bundle_chunk_count_matches_physical_lf_reference",
    "test_sarif_artifact_uri_percent_encodes_path_bytes",
    "test_deterministic_python_codec_wording_and_bytes_are_stable",
];

fn read_rel(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    while let Some(pos) = rest.find(ID_MARKER) {
        let tail = &rest[pos + ID_MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("{ID_MARKER}{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors are missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find(ID_MARKER)
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_needles(slice: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(slice.contains(needle), "{label} is missing {needle}");
    }
}

fn assert_absent(haystack: &str, label: &str, needle: &str) {
    assert!(
        !haystack.contains(needle),
        "{label} unexpectedly contains {needle}"
    );
}

fn assert_module(json: &str, module: &str, python_commit: &str) {
    assert!(json.contains(&format!("\"module\": \"{module}\"")));
    assert!(json.contains(&format!("\"python_commit\": \"{python_commit}\"")));
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_wave1_correctness_test_has_one_disposition() {
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
            Disposition::Covered { vector_id, needles } => {
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
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
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
fn hygiene_vectors_are_not_the_secret_tests() {
    let json = read_rel(HYGIENE_REL);
    assert_module(&json, "sesslint.checks.hygiene", ANCESTOR_PIN);
    assert!(json.contains(
        "When SecretScanTracker has hits, into_findings calls make_finding with the fingerprint omitted. Rust returns FINGERPRINT_CODEC_UNAVAILABLE."
    ));
    let ids = vector_ids(&json);
    for id in [
        "tracker_json_escape_enables_match",
        "tracker_line_gate_skips_clean_record",
        "tracker_sort_line_ordinal_family",
        "short_prefix_escape_n",
    ] {
        assert!(ids.contains(&id), "hygiene vectors are missing {id}");
    }

    let escape = vector_slice(&json, "tracker_json_escape_enables_match");
    assert_needles(
        escape,
        "tracker_json_escape_enables_match",
        &[
            "\"type\": \"hygiene_tracker\"",
            "\"hex\": \"785c6e\"",
            "\"family\": \"openai-api-key\"",
        ],
    );
    assert_absent(escape, "tracker_json_escape_enables_match", "{\"text\":\"");

    let gate = vector_slice(&json, "short_prefix_escape_n");
    assert_needles(
        gate,
        "short_prefix_escape_n",
        &[
            "\"type\": \"hygiene_bool_fn\"",
            "\"fn\": \"short_prefix_present\"",
            "\"hex\": \"5c6e68665f\"",
            "\"value\": true",
        ],
    );

    let line_gate = vector_slice(&json, "tracker_line_gate_skips_clean_record");
    assert_needles(
        line_gate,
        "tracker_line_gate_skips_clean_record",
        &["\"family\": \"openai-api-key\"", "\"byte_offset\": 11"],
    );
    assert_absent(&json, "hygiene vectors", "AbCdEfGh");
}

#[test]
fn canonical_dump_and_reader_vectors_are_not_the_pinned_calls() {
    let canonical = read_rel(CANONICAL_REL);
    assert_module(&canonical, "sesslint.canonical", ANCESTOR_PIN);
    assert!(canonical.contains(
        "dump_session, dump_session_file, to_canonical_json, canonical_bytes, to_canonical_dict, normalize, content identity, compute_content_hash, and reparse_identity_hashes: Rust returns a typed unavailable error"
    ));
    assert_absent(
        &canonical,
        "canonical vectors",
        "\"type\": \"dump_session_file\"",
    );
    assert_absent(&canonical, "canonical vectors", "wave1-correctness");

    let loaded = vector_slice(&canonical, "load_session_file_small_jsonl");
    assert_needles(
        loaded,
        "load_session_file_small_jsonl",
        &[
            "\"type\": \"load_session_file_bytes\"",
            "\"session_id\": \"sess-parity-synthetic\"",
            "\"id\": \"evt-1\"",
        ],
    );

    let verify = read_rel(VERIFY_REL);
    assert_module(&verify, "sesslint.verify", PIN);
    assert!(verify.contains(
        "GAP-verify-end-to-end: verify() on committed fixture bundles calls sesslint.report.parse_manifest in Python; Rust returns sesslint.report.parse_manifest is not available"
    ));
    assert!(verify.contains(
        "GAP-verify-wave1: tests/test_wave1_correctness.py does not exercise sesslint.verify."
    ));
    let parsed = vector_slice(&verify, "parse_accepts_valid_jsonl");
    assert_needles(
        parsed,
        "parse_accepts_valid_jsonl",
        &[
            "\"type\": \"parse_session_events\"",
            "\"kind\": \"ok\"",
            "\"header_session_id\": \"parity-sess\"",
            "\"first_event_id\": \"msg-0\"",
        ],
    );
    assert_absent(&verify, "verify vectors", "wave1-correctness");
    assert_absent(&verify, "verify vectors", "thread-1");

    let indexes = read_rel(INDEXES_REL);
    assert_module(&indexes, "sesslint.indexes", ANCESTOR_PIN);
    let oversized = vector_slice(&indexes, "read_index_oversized_refused");
    assert_needles(
        oversized,
        "read_index_oversized_refused",
        &[
            "\"type\": \"read_index\"",
            "\"setup\": \"oversized_claude\"",
            "\"schema_note\": \"oversized\"",
            "\"parse_ok\": false",
        ],
    );
    assert_absent(&indexes, "index vectors", "thread-1");
    assert_absent(&indexes, "index vectors", &"[".repeat(2000));

    let atomic = read_rel(ATOMIC_REL);
    assert_module(&atomic, "sesslint.atomic", ANCESTOR_PIN);
    let utf8 = vector_slice(&atomic, "text_utf8_default_digest");
    assert_needles(
        utf8,
        "text_utf8_default_digest",
        &[
            "\"type\": \"atomic_write_text\"",
            "\"dest\": \"utf8.bin\"",
            "\"result\": \"ok\"",
        ],
    );
    assert_absent(utf8, "text_utf8_default_digest", "dump_session_file");
}

#[test]
fn mcp_cache_and_bundle_vectors_are_narrower_than_the_pinned_tests() {
    let mcp = read_rel(MCP_REL);
    assert_module(&mcp, "sesslint.mcp_server", PIN);
    assert!(mcp.contains(
        "GAP-mcp-server-serve-readline: test_wave1_correctness MCP bounds case also asserts bounded readline(size) on stdin; vectors assert serve output only."
    ));
    assert_absent(&mcp, "mcp vectors", "requested_sizes");
    let ids = vector_ids(&mcp);
    assert!(ids.contains(&"serve_oversized_then_ping"));
    assert!(ids.contains(&"deep_brackets_parse_error"));
    assert_ne!(
        ids.iter().position(|id| *id == "serve_oversized_then_ping"),
        ids.iter().position(|id| *id == "deep_brackets_parse_error")
    );

    let served = vector_slice(&mcp, "serve_oversized_then_ping");
    assert_needles(
        served,
        "serve_oversized_then_ping",
        &[
            "\"type\": \"serve\"",
            "\"exit_code\": 0",
            "\"first_error_code\": -32700",
            "\"second_id\": 7",
            "\"second_has_empty_result\": true",
        ],
    );
    assert_absent(
        served,
        "serve_oversized_then_ping",
        "\"type\": \"handle_line\"",
    );

    let deep = vector_slice(&mcp, "deep_brackets_parse_error");
    assert_needles(
        deep,
        "deep_brackets_parse_error",
        &["\"type\": \"handle_line\"", "\"kind\": \"bytes\""],
    );
    assert_absent(deep, "deep_brackets_parse_error", "\"exit_code\": 0");

    let cache = read_rel(CACHE_REL);
    assert_module(&cache, "sesslint.cache", PIN);
    let row = vector_slice(&cache, "row-json-0");
    assert_needles(
        row,
        "row-json-0",
        &[
            "\"op\": \"inject\"",
            "\"text\": \"{\"",
            "\"verdict\": \"healthy\"",
        ],
    );

    let bundle = read_rel(BUNDLE_REL);
    assert_module(&bundle, "sesslint.bundle", ANCESTOR_PIN);
    let count = vector_slice(&bundle, "count_split_chunk");
    assert_needles(
        count,
        "count_split_chunk",
        &[
            "\"type\": \"count_records_bounded\"",
            "\"path\": \"fixtures/split.jsonl\"",
            "\"count\": 1",
        ],
    );
    assert_absent(&bundle, "bundle vectors", "max_examples");
}

#[test]
fn sarif_codec_and_discriminator_vectors_are_not_the_pinned_calls() {
    let sarif = read_rel(SARIF_REL);
    assert_module(&sarif, "sesslint.sarif", ANCESTOR_PIN);
    let rendered = vector_slice(&sarif, "render_sarif_relative_percent_encode");
    assert_needles(
        rendered,
        "render_sarif_relative_percent_encode",
        &[
            "\"type\": \"render_sarif\"",
            "\"path\": \"folder name/#?-%-ä.jsonl\"",
            "\"message\": \"synthetic path marker\"",
            "\"fingerprint\": \"1d2f345a7c41b867\"",
            "\"tool_version\": \"test\"",
            "\"artifact_uri\": \"folder%20name/%23%3F-%25-%C3%A4.jsonl\"",
        ],
    );
    assert_absent(&sarif, "sarif vectors", "Synthetic malformed record");
    let gap = vector_slice(&sarif, "scan_report_sarif_gap");
    assert_needles(
        gap,
        "scan_report_sarif_gap",
        &[
            "\"type\": \"scan_report_sarif\"",
            "\"mode\": \"gap_scan_report\"",
        ],
    );
    assert_absent(gap, "scan_report_sarif_gap", "\"artifact_uri\"");

    let codec = read_rel(CODEC_REL);
    assert_module(&codec, "sesslint._canonical_codec", ANCESTOR_PIN);
    let flat = vector_slice(&codec, "canonical_flat_object");
    assert_needles(
        flat,
        "canonical_flat_object",
        &[
            "\"type\": \"canonical_json_bytes\"",
            "\"newline\": false",
            "\"b\": 2",
            "\"a\": 1",
            "\"result\": \"ok\"",
        ],
    );
    let identity = vector_slice(&codec, "content_identity_bytes_unsupported");
    assert_needles(
        identity,
        "content_identity_bytes_unsupported",
        &[
            "\"type\": \"content_identity_bytes\"",
            "\"result\": \"error\"",
            "\"raises\": \"Unsupported\"",
        ],
    );
    assert_absent(&codec, "codec vectors", "RFC 8785");
    assert_absent(&codec, "codec vectors", "\"n\": 0.0");

    let safe_value = read_rel(SAFE_VALUE_REL);
    assert_module(&safe_value, "sesslint.adapters.safe_value", ANCESTOR_PIN);
    let azure = vector_slice(&safe_value, "cloud_azure_client_secret_16");
    assert_needles(
        azure,
        "cloud_azure_client_secret_16",
        &[
            "\"type\": \"safe_discriminator\"",
            "\"text\": \"azure-client-secret-aaaaaaaaaaaaaaaa\"",
            "\"is_truncated\": true",
        ],
    );
    let npm = vector_slice(&safe_value, "allowlist_echo_npm_package_metadata");
    assert_needles(
        npm,
        "allowlist_echo_npm_package_metadata",
        &[
            "\"type\": \"safe_discriminator\"",
            "\"text\": \"npm_package_metadata\"",
            "\"is_truncated\": false",
        ],
    );
    assert_absent(&safe_value, "safe_value vectors", "AccountKey=");
}
