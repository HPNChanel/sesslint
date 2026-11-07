//! Dispositions for the 16 `def test_` functions in pinned `tests/test_source.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (187 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! A column-0 scan finds all 16 tests. Each of those names has one disposition.
//!
//! `covered` names one id in `source/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! Sharing temp_count, dest_exists, exit_code, schema_version, or one example
//! inside a sweep is not coverage. A different input string is not coverage.
//! If the construct or the error kind differs, the row is `not_applicable`.
//! `not_applicable` records a `fingerprint_file`, `guard`, `verify`, `guarded`,
//! or `guarded_iter_events` mode this package cannot reach without a
//! `Cargo.toml` change, or a mode absent from that vector file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 16;
const SOURCE_VECTOR_COUNT: usize = 13;
const VECTORS_REL: &str = "parity/vectors/source/vectors.json";

/// `covered` names a vector id in `source/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Vector id, construct type, and whether the expected outcome is an error.
/// Source vectors record `"sha256"` on success and `"raises": "ValueError"`
/// on chunk-size failure. They have no `"outcome"` field.
const SOURCE_VECTORS: &[(&str, &str, bool)] = &[
    ("fingerprint_bytes_empty", "fingerprint_bytes", false),
    ("fingerprint_bytes_abc", "fingerprint_bytes", false),
    (
        "fingerprint_bytes_synthetic_line",
        "fingerprint_bytes",
        false,
    ),
    ("fingerprint_bytes_nul_and_crlf", "fingerprint_bytes", false),
    (
        "fingerprint_file_chunk_size_zero",
        "fingerprint_file_chunk",
        true,
    ),
    (
        "fingerprint_file_chunk_size_negative_one",
        "fingerprint_file_chunk",
        true,
    ),
    (
        "fingerprint_file_chunk_size_negative_hundred",
        "fingerprint_file_chunk",
        true,
    ),
    (
        "fingerprint_file_empty_default_chunk",
        "fingerprint_file_bytes",
        false,
    ),
    (
        "fingerprint_file_synthetic_default_chunk",
        "fingerprint_file_bytes",
        false,
    ),
    (
        "fingerprint_file_synthetic_chunk_4096",
        "fingerprint_file_bytes",
        false,
    ),
    (
        "fingerprint_file_synthetic_chunk_one",
        "fingerprint_file_bytes",
        false,
    ),
    (
        "fingerprint_file_large_payload_across_chunks",
        "fingerprint_file_bytes",
        false,
    ),
    (
        "fingerprint_file_large_payload_chunk_default",
        "fingerprint_file_bytes",
        false,
    ),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_fingerprint_file_stability",
        disposition: Disposition::NotApplicable(
            "fingerprint_file twice on fixtures/sessions/stable-small.jsonl returns equal 64-character lowercase hex digests; fingerprint_file_synthetic_default_chunk hashes a different byte string and records one call",
        ),
    },
    Row {
        name: "test_fingerprint_file_matches_sidecar",
        disposition: Disposition::NotApplicable(
            "fingerprint_file on fixtures/sessions/stable-small.jsonl equals the text of its .sha256 sidecar; no source vector reads a sidecar digest",
        ),
    },
    // Zero-byte file at the default chunk. fingerprint_bytes_empty shares the
    // empty digest and calls fingerprint_bytes.
    Row {
        name: "test_fingerprint_file_empty_file",
        disposition: Disposition::Covered {
            vector_id: "fingerprint_file_empty_default_chunk",
            needles: &[
                "\"type\": \"fingerprint_file_bytes\"",
                "\"data_hex\": \"\"",
                "\"chunk_size\": 65536",
                "\"sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
            ],
        },
    },
    // chunk_size 0 and chunk_size -100. Each ValueError vector is one example.
    Row {
        name: "test_fingerprint_file_invalid_chunk_size",
        disposition: Disposition::NotApplicable(
            "fingerprint_file raises ValueError for chunk_size 0 and for chunk_size -100; fingerprint_file_chunk_size_zero and fingerprint_file_chunk_size_negative_hundred are one ValueError each, so neither is the whole sweep",
        ),
    },
    Row {
        name: "test_fingerprint_file_directory_raises",
        disposition: Disposition::NotApplicable(
            "fingerprint_file on a directory raises IsADirectoryError matching Expected file, got directory; no source vector records IsADirectoryError",
        ),
    },
    Row {
        name: "test_fingerprint_file_missing_file_raises",
        disposition: Disposition::NotApplicable(
            "fingerprint_file on a missing path raises FileNotFoundError; chunk-size vectors raise ValueError before the path is opened, a different error kind",
        ),
    },
    // Pin payload is b"A" * 150_000 + b"B" * 50_000 at chunk_size 4096.
    // fingerprint_file_large_payload_chunk_default uses chunk_size 65536.
    Row {
        name: "test_fingerprint_file_chunked_streaming",
        disposition: Disposition::Covered {
            vector_id: "fingerprint_file_large_payload_across_chunks",
            needles: &[
                "\"type\": \"fingerprint_file_bytes\"",
                "\"chunk_size\": 4096",
                "\"sha256\": \"c733df9c7a7312f300d08bedf39657f94f915eb2f10adea7bfc3569c206c7b5c\"",
            ],
        },
    },
    Row {
        name: "test_guard_and_verify_clean",
        disposition: Disposition::NotApplicable(
            "guard returns a SourceGuard and verify accepts the unmodified file; GAP-source-filesystem-snapshot leaves guard and verify unpinned",
        ),
    },
    Row {
        name: "test_guard_directory_raises",
        disposition: Disposition::NotApplicable(
            "guard on a directory raises IsADirectoryError; GAP-source-filesystem-snapshot leaves guard unpinned",
        ),
    },
    Row {
        name: "test_verify_raises_on_content_append",
        disposition: Disposition::NotApplicable(
            "verify after an append raises SourceChangedError matching Source file metadata changed concurrently; GAP-source-filesystem-snapshot leaves verify unpinned",
        ),
    },
    Row {
        name: "test_verify_raises_on_same_size_content_change",
        disposition: Disposition::NotApplicable(
            "verify after a same-length rewrite raises SourceChangedError; GAP-source-filesystem-snapshot leaves verify unpinned",
        ),
    },
    Row {
        name: "test_verify_raises_on_file_deletion",
        disposition: Disposition::NotApplicable(
            "verify after removal raises SourceChangedError matching Source file inaccessible or removed; GAP-source-filesystem-snapshot leaves verify unpinned",
        ),
    },
    Row {
        name: "test_guarded_contextmanager_success",
        disposition: Disposition::NotApplicable(
            "guarded yields a SourceGuard whose size equals the file; GAP-source-filesystem-snapshot leaves guarded unpinned",
        ),
    },
    Row {
        name: "test_guarded_contextmanager_mutation_raises",
        disposition: Disposition::NotApplicable(
            "guarded raises SourceChangedError when the file changes before exit; GAP-source-filesystem-snapshot leaves guarded unpinned",
        ),
    },
    Row {
        name: "test_guarded_iter_events_success",
        disposition: Disposition::NotApplicable(
            "guarded_iter_events on fixtures/sessions/stable-small.jsonl yields four SessionEvent values; GAP-source-guarded-iter-events leaves that integration unpinned",
        ),
    },
    Row {
        name: "test_guarded_iter_events_mutation_aborts",
        disposition: Disposition::NotApplicable(
            "guarded_iter_events raises SourceChangedError when the file grows after the first event; GAP-source-guarded-iter-events leaves that integration unpinned",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fingerprint_file_stability",
    "test_fingerprint_file_matches_sidecar",
    "test_fingerprint_file_empty_file",
    "test_fingerprint_file_invalid_chunk_size",
    "test_fingerprint_file_directory_raises",
    "test_fingerprint_file_missing_file_raises",
    "test_fingerprint_file_chunked_streaming",
    "test_guard_and_verify_clean",
    "test_guard_directory_raises",
    "test_verify_raises_on_content_append",
    "test_verify_raises_on_same_size_content_change",
    "test_verify_raises_on_file_deletion",
    "test_guarded_contextmanager_success",
    "test_guarded_contextmanager_mutation_raises",
    "test_guarded_iter_events_success",
    "test_guarded_iter_events_mutation_aborts",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
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
        .unwrap_or_else(|| panic!("source vectors.json is missing id {id}"));
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
fn every_pinned_source_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(SOURCE_VECTORS.len(), SOURCE_VECTOR_COUNT);
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
                for needle in needles {
                    assert!(
                        !needle.contains("temp_count")
                            && !needle.contains("dest_exists")
                            && !needle.contains("exit_code")
                            && !needle.contains("schema_version"),
                        "{} needle {needle} is a shared field",
                        row.name
                    );
                }
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
    assert_eq!(covered, 2);
    assert_eq!(not_applicable, 14);
}

#[test]
fn covered_vector_ids_are_present_in_source_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "source vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.source\""));
    assert!(
        json.contains("GAP-source-filesystem-snapshot"),
        "source vectors record the filesystem snapshot gap"
    );
    assert!(
        json.contains("GAP-source-guarded-iter-events"),
        "source vectors record the guarded_iter_events gap"
    );

    let ids = vector_ids(&json);
    let expected: Vec<&str> = SOURCE_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), SOURCE_VECTOR_COUNT);

    for &(id, construct, fails) in SOURCE_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"raises\": \"ValueError\""),
            fails,
            "{id} error mode does not match the vector file"
        );
        assert_eq!(
            slice.contains("\"sha256\": \""),
            !fails,
            "{id} success mode does not match the vector file"
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
