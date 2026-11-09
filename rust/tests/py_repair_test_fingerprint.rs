//! Dispositions for the 5 `def test_` functions in pinned
//! `tests/repair/test_fingerprint.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. This integration test crate
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only.
//!
//! `covered` names one id in `repair.fingerprint/vectors.json` or
//! `repair.executor/vectors.json` whose construct is the same function and the
//! same success or failure mode as that entire pinned test. One digest pair or
//! seam assertion inside a sweep is not coverage. `not_applicable` records a
//! `compute_plan_fingerprint`, `load_plan`, or `execute` check this package
//! cannot reach without a `Cargo.toml` change, or a mode no vector records as
//! the full pin outcome. Rust `execute` stops at
//! `sesslint.repair.fingerprint.compute_plan_fingerprint is not available`
//! after the 256-step cap; that seam is not a conservative-policy refusal.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 5;
const PLAN_FINGERPRINT_VECTORS_REL: &str = "parity/vectors/repair.fingerprint/vectors.json";
const EXECUTOR_VECTORS_REL: &str = "parity/vectors/repair.executor/vectors.json";

/// `covered` names a vector id. `not_applicable` records behavior this package
/// cannot reach without a `Cargo.toml` change, or a mode absent from the
/// vector files named above.
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

/// Top-level plan-fingerprint ids. Nested `"id": "s1"` is a plan field.
const PLAN_FINGERPRINT_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("plan_fp_small_policy_omitted", "compute_plan_fingerprint"),
    (
        "plan_fp_small_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_omitted",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "canonical_json_non_ascii_newline_true",
        "canonical_json_bytes",
    ),
    (
        "canonical_json_non_ascii_newline_false",
        "canonical_json_bytes",
    ),
];

const EXECUTOR_VECTORS: &[(&str, &str)] = &[
    ("load_plan_salvage_under_conservative", "load_plan_salvage_policy_mismatch"),
    ("execute_fingerprint_import_seam", "execute_fingerprint_gap"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_plan_fingerprint_determinism",
        disposition: Disposition::NotApplicable(
            "compute_plan_fingerprint on two full sesslint.plan/v1 mappings with permuted key order and equal 64-hex digests; this package does not call compute_plan_fingerprint, and repair.fingerprint vectors hash minimal id s1 plans, not that reordering pair",
        ),
    },
    Row {
        name: "test_plan_fingerprint_policy_binding",
        disposition: Disposition::NotApplicable(
            "compute_plan_fingerprint must yield distinct digests for conservative versus salvage policy and match a keyword policy override on the same base plan; plan_fp_small_policy_omitted and plan_fp_small_policy_conservative are two digests on id s1 only, without keyword binding or full plan preimages",
        ),
    },
    Row {
        name: "test_plan_fingerprint_excludes_fingerprint_key",
        disposition: Disposition::NotApplicable(
            "compute_plan_fingerprint on a full plan, then again after embedding the first digest under fingerprint, must return the same digest; plan_fp_extra_fingerprint_policy_omitted omits self-hash on a minimal plan with a static marker, not that full-plan cycle",
        ),
    },
    Row {
        name: "test_load_plan_refuses_salvage_under_conservative_policy",
        disposition: Disposition::NotApplicable(
            "load_plan must raise PolicyMismatch for salvage-class steps under conservative policy and succeed under salvage; load_plan is not callable from this package without a Cargo.toml change, and load_plan_salvage_under_conservative is only a published message fixture",
        ),
    },
    Row {
        name: "test_execute_refuses_salvage_plan_under_conservative_policy",
        disposition: Disposition::NotApplicable(
            "execute with a loaded salvage plan must raise PolicyMismatch under conservative policy after fingerprinting a session-derived source hash; execute is not callable here, Rust stops at compute_plan_fingerprint is not available after the step cap, and execute_fingerprint_import_seam records fingerprint_unavailable, not that PolicyMismatch refusal",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_plan_fingerprint_determinism",
    "test_plan_fingerprint_policy_binding",
    "test_plan_fingerprint_excludes_fingerprint_key",
    "test_load_plan_refuses_salvage_under_conservative_policy",
    "test_execute_refuses_salvage_plan_under_conservative_policy",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
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

const TOP_LEVEL_ID_PREFIX: &str = "\n      \"id\": \"";

fn assert_top_level_catalog(json: &str, label: &str, rows: &[(&str, &str)]) {
    let mut cursor = 0usize;
    for &(id, construct) in rows {
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{id}\"");
        let rel = json[cursor..]
            .find(&marker)
            .unwrap_or_else(|| panic!("{label} is missing top-level id {id}"));
        let start = cursor + rel;
        let after = start + marker.len();
        let next = json[after..]
            .find(TOP_LEVEL_ID_PREFIX)
            .map(|offset| after + offset)
            .unwrap_or(json.len());
        let slice = &json[start..next];
        let type_key = "\"type\": \"";
        let type_at = slice
            .find(type_key)
            .unwrap_or_else(|| panic!("{label} {id} is missing a construct type"));
        let tail = &slice[type_at + type_key.len()..];
        let end = tail.find('"').expect("construct type is a JSON string");
        assert_eq!(&tail[..end], construct, "{label} {id}");
        cursor = after;
    }
    assert_eq!(
        json.matches(TOP_LEVEL_ID_PREFIX).count(),
        rows.len(),
        "{label} top-level id count"
    );
}

fn read_vectors(rel: &str, module: &str) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")));
    json
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("{TOP_LEVEL_ID_PREFIX}{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing top-level id {id}"));
    let after = start + marker.len();
    let end = json[after..]
        .find(TOP_LEVEL_ID_PREFIX)
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
fn every_pinned_repair_fingerprint_test_has_one_disposition() {
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
fn cited_repair_fingerprint_and_executor_vectors_are_present() {
    let plan = read_vectors(PLAN_FINGERPRINT_VECTORS_REL, "sesslint.repair.fingerprint");
    assert_top_level_catalog(&plan, "repair.fingerprint", PLAN_FINGERPRINT_VECTORS);

    let executor = read_vectors(EXECUTOR_VECTORS_REL, "sesslint.repair.executor");

    let executor_ids: BTreeSet<&str> = vector_ids(&executor).into_iter().collect();

    assert!(
        vector_slice(&plan, "module_all_export_order").contains("compute_plan_fingerprint"),
        "repair.fingerprint export list no longer names compute_plan_fingerprint"
    );
    for &(id, construct) in EXECUTOR_VECTORS {
        assert!(
            executor_ids.contains(id),
            "repair.executor is missing id {id}"
        );
        let slice = vector_slice(&executor, id);
        assert!(
            slice.contains(&format!("\"type\": \"{construct}\"")),
            "repair.executor {id} construct type"
        );
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let plan_marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let slice = if plan.contains(&plan_marker) {
            vector_slice(&plan, vector_id)
        } else {
            vector_slice(&executor, vector_id)
        };
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
