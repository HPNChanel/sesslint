//! Dispositions for the 12 `def test_` functions in pinned `tests/test_atomic.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (201 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names a vector id in `atomic/vectors.json` with the same function
//! and the same success or failure mode. `not_applicable` records a
//! `sesslint.atomic` call this package cannot reach without a `Cargo.toml`
//! change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 12;
const ATOMIC_VECTOR_COUNT: usize = 15;
const VECTORS_REL: &str = "parity/vectors/atomic/vectors.json";

/// `covered` names a vector id in `atomic/vectors.json`. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change outside the
/// owned path, or a mode absent from that vector file.
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

const ROWS: &[Row] = &[
    Row {
        name: "test_atomic_write_bytes_basic",
        disposition: Disposition::Covered {
            vector_id: "happy_write_synthetic_digest",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"setup\": \"empty\"",
                "\"result\": \"ok\"",
                "\"sha256\": \"6d2be2f98608ff3a889e146ea56ea3a3087fcaa42ca1a35e3c30c519e654868d\"",
                "\"dest_b64\": \"c3ludGhldGljLWJ5dGVzCg==\"",
            ],
        },
    },
    Row {
        name: "test_atomic_write_text_basic",
        disposition: Disposition::Covered {
            vector_id: "text_utf8_default_digest",
            needles: &[
                "\"type\": \"atomic_write_text\"",
                "\"dest\": \"utf8.bin\"",
                "\"text\": \"synthetic-é\\n\"",
                "\"result\": \"ok\"",
                "\"sha256\": \"9eb40278b60348b930cd6120ab0f409b5d587e106312d42cc33f3d0977077e4a\"",
            ],
        },
    },
    // Identical path. Hardlink, case alias, and dotdot are other identity modes.
    Row {
        name: "test_atomic_write_refuses_protected_source_path",
        disposition: Disposition::NotApplicable(
            "identical dest and refuse path; no atomic vector refuses that same path",
        ),
    },
    Row {
        name: "test_atomic_write_refuses_equivalent_resolved_path",
        disposition: Disposition::Covered {
            vector_id: "refuse_dotdot_before_parent_error",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"dest\": \"missing/../out.bin\"",
                "\"error_kind\": \"refuse_protected\"",
                "\"dest_rel\": \"missing/../out.bin\"",
                "\"prohibited_rel\": \"out.bin\"",
            ],
        },
    },
    Row {
        name: "test_atomic_write_nonexistent_parent_raises",
        disposition: Disposition::Covered {
            vector_id: "missing_parent_no_temp",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"dest\": \"missing_dir/out.bin\"",
                "\"raises\": \"AtomicWriteError\"",
                "\"error_kind\": \"missing_parent\"",
            ],
        },
    },
    Row {
        name: "test_atomic_write_parent_is_not_dir_raises",
        disposition: Disposition::Covered {
            vector_id: "parent_path_is_file_refused",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"setup\": \"parent_is_file\"",
                "\"dest\": \"file.txt/out.bin\"",
                "\"error_kind\": \"parent_not_dir\"",
                "\"parent_rel\": \"file.txt\"",
            ],
        },
    },
    // os.replace OSError. hook_pre_rename_fail_cleans_temp is a RuntimeError hook.
    Row {
        name: "test_atomic_write_failure_cleans_temp_file",
        disposition: Disposition::NotApplicable(
            "OSError injected into os.replace; no atomic vector models that injection",
        ),
    },
    Row {
        name: "test_atomic_write_overwrites_existing_unprotected_dest",
        disposition: Disposition::Covered {
            vector_id: "overwrite_true_replaces_bytes",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"setup\": \"seed_overwrite\"",
                "\"result\": \"ok\"",
                "\"dest_b64\": \"c3ludGhldGljLWJ5dGVzCg==\"",
            ],
        },
    },
    Row {
        name: "test_atomic_write_mode_applied",
        disposition: Disposition::NotApplicable(
            "permission mode 0o600; no atomic vector records a mode",
        ),
    },
    Row {
        name: "test_atomic_write_custom_prefix",
        disposition: Disposition::NotApplicable(
            "custom temporary prefix; no atomic vector records a prefix",
        ),
    },
    // Success order only. The seeded hook-fail vector is a different setup.
    Row {
        name: "test_atomic_write_hooks_lifecycle",
        disposition: Disposition::Covered {
            vector_id: "hooks_pre_write_then_pre_rename",
            needles: &[
                "\"type\": \"atomic_write_bytes\"",
                "\"hook\": \"lifecycle\"",
                "\"sync_dir\": true",
                "\"result\": \"ok\"",
                "\"pre_write\"",
                "\"pre_rename\"",
                "\"dest_b64\": \"cGF5bG9hZA==\"",
            ],
        },
    },
    Row {
        name: "test_atomic_write_text_passthrough_options",
        disposition: Disposition::NotApplicable(
            "atomic_write_text prefix, pre_rename hook, and sync_dir; no text vector carries those options",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_atomic_write_bytes_basic",
    "test_atomic_write_text_basic",
    "test_atomic_write_refuses_protected_source_path",
    "test_atomic_write_refuses_equivalent_resolved_path",
    "test_atomic_write_nonexistent_parent_raises",
    "test_atomic_write_parent_is_not_dir_raises",
    "test_atomic_write_failure_cleans_temp_file",
    "test_atomic_write_overwrites_existing_unprotected_dest",
    "test_atomic_write_mode_applied",
    "test_atomic_write_custom_prefix",
    "test_atomic_write_hooks_lifecycle",
    "test_atomic_write_text_passthrough_options",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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
        .unwrap_or_else(|| panic!("atomic vectors.json is missing id {id}"));
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
fn every_pinned_atomic_test_has_one_disposition() {
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
                for needle in needles {
                    assert!(
                        !needle.contains("temp_count") && !needle.contains("dest_exists"),
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
    assert_eq!(covered, 7);
    assert_eq!(not_applicable, 5);
}

#[test]
fn covered_vector_ids_are_present_in_atomic_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "atomic vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.atomic\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), ATOMIC_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

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
