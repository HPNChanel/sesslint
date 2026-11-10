//! Dispositions for the seven `def test_` functions in pinned
//! `tests/repair/test_exclusive_publish.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (125 splitlines). Exactly
//! seven test functions. One is parametrized. The helper `_stage` is not a
//! test. `SOURCE` is not a test. A parametrized function is one row covering
//! every cell, not one row per cell. A skip and the assertion that follows it
//! are one row. The timestamp value, the vendor record, and competing byte
//! literals are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call repair, atomic, batch, api,
//! or cli functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `Disposition::Covered` exists only so a later
//! whole-pytest vector can be claimed. A header fragment is not a whole
//! pytest. `parity/vectors/cli/vectors.json` has 33 ids at this pin and none
//! of those ids is one of these seven functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these seven
//! functions. `repair_plan_path_exclusive` is a repair call with `plan_path`
//! and `with_plan`. It is not the atomic race.
//! `repair_emit_reject_vendor_space` is a dry-run repair whose emit is a
//! vendor token with a leading space. It is not the canonical header
//! timestamp test. `repair_emit_reject_canonical_space` is a dry-run repair
//! that raises on a canonical emit token with a trailing space. It is not
//! that header. `discover_claude_symlink` is discovery, not a repair
//! destination.
//!
//! `parity/vectors/atomic/vectors.json` has 15 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `overwrite_false_keeps_existing_bytes` seeds a destination and leaves those
//! bytes unchanged. It is not the hook that writes the competing bytes during
//! `pre_rename`. `overwrite_true_replaces_bytes` replaces a seeded file.
//! `refuse_hardlink_same_file` refuses a hardlink alias.
//! `hooks_pre_write_then_pre_rename` is a lifecycle hook.
//! `hook_pre_rename_fail_cleans_temp` cleans a temp after a failing hook.
//! None of those is one of these pytests, and that old pin is not a Covered
//! source.
//!
//! `parity/vectors/errors/vectors.json` is on that old pin.
//! `atomic_write_default` and `atomic_write_with_code` construct errors. They
//! are not the exclusive race. `parity/vectors/repair.errors/vectors.json` is
//! on that old pin. `manifest_collision_default` and
//! `manifest_collision_custom_code` construct `ManifestCollision`. They do
//! not call `api.repair` on a dangling symlink. Vendor refusal ids are not
//! the header timestamp test. `parity/vectors/repair.executor/vectors.json`
//! is on that old pin. `relocate_step_removed_target` is a removed-event
//! message. `load_session_broken_symlink` and `load_session_symlink_file_seam`
//! load a session. They are not `api.repair` of a dangling destination and
//! not the batch receipt.
//!
//! `parity/vectors/repair/vectors.json` has 1 id on the old pin.
//! `parity/vectors/batch/vectors.json` has 16 ids on the old pin.
//! `parity/vectors/cli.repair/vectors.json` has 1 id on the old pin. Exporter
//! and `cli.export` symlink ids are export, not this module. `cli._render`
//! `scan_dangling_plural_index_line` is render text. `policy.abstention`
//! `ambiguous_dangling_call` is not this symlink pytest. None of those old-pin
//! corpora is a Covered source.
//!
//! Therefore every row is NotApplicable. `not_applicable` names the missing
//! stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 7;
const PINNED_SPLITLINES: usize = 125;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A header fragment is not a whole pytest. A parametrized
/// function is one row covering every cell. A skip and the assertion that
/// follows it are one row. `not_applicable` names the missing stop.
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
        name: "test_exclusive_atomic_write_preserves_racing_destination",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_exclusive_atomic_write_preserves_racing_destination: atomic_write_bytes raises AtomicWriteError, overwrite is false, the pre_rename hook writes the competing bytes, the destination equals that write, and no .sesslint temp remains. It does not call repair or execute. The seeded overwrite_false vector is not this hook. missing stop: that raise, that preserved destination, and the absent temp together; it does not call repair or execute; overwrite_false_keeps_existing_bytes seeds a destination and leaves those bytes unchanged and is not this hook; overwrite_true_replaces_bytes replaces a seeded file and is not this hook; hooks_pre_write_then_pre_rename is a lifecycle hook on the old pin and is not this hook; hook_pre_rename_fail_cleans_temp cleans a temp after a failing hook and is not this hook; atomic_write_default constructs an error and is not this race; atomic_write_with_code constructs an error and is not this race",
        ),
    },
    Row {
        name: "test_repair_preserves_racing_output_and_removes_own_receipt",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_preserves_racing_output_and_removes_own_receipt: execute raises OutputInvalid, the plan comes from api.plan_repair, the hook writes the competing bytes, the destination equals that write, the source bytes stay unchanged, the manifest path is absent, and no .sesslint temp remains. It does not assert AtomicWriteError. The atomic-only test is not this execute call. missing stop: that raise, that preserved destination, those unchanged source bytes, that absent manifest path, and the absent temp together; it does not assert AtomicWriteError; test_exclusive_atomic_write_preserves_racing_destination is the atomic-only test and is not this execute call; output_invalid_default constructs OutputInvalid and is not this execute call; repair_plan_path_exclusive is a repair call with plan_path and with_plan and is not this race",
        ),
    },
    Row {
        name: "test_dangling_symlink_is_an_existing_destination",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_dangling_symlink_is_an_existing_destination: one row covers both cells, output and manifest. The host skip and the raise are one row. The output cell raises RepairRefused. The manifest cell raises ManifestCollision. The target stays a symlink and the missing path does not exist. It does not assert competing bytes. A constructed ManifestCollision is not this api.repair call. A load-session symlink vector is not this. missing stop: that host skip and that raise together for the output cell and the manifest cell; it does not assert competing bytes; manifest_collision_default constructs ManifestCollision and is not this api.repair call; manifest_collision_custom_code constructs ManifestCollision and is not this api.repair call; repair_refused_default constructs RepairRefused and is not this api.repair call; load_session_broken_symlink loads a session and is not this; load_session_symlink_file_seam loads a session and is not this; discover_claude_symlink is discovery and is not this repair destination; export_broken_symlink is export and is not this; run_broken_symlink is export and is not this; scan_dangling_plural_index_line is render text and is not this; ambiguous_dangling_call is not this symlink pytest",
        ),
    },
    Row {
        name: "test_windows_repair_works_without_hardlinks",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_windows_repair_works_without_hardlinks: skipped unless the OS is Windows. os.link is patched to raise ENOTSUP. api.repair returns a manifest, the output is a file, and the adjacent manifest file exists. It does not assert a POSIX mode. The hardlink-alias refusal is not this patch. The POSIX permission test is not this Windows test. missing stop: that Windows skip, that ENOTSUP patch, that returned manifest, that output file, and that adjacent manifest file together; it does not assert a POSIX mode; refuse_hardlink_same_file refuses a hardlink alias and is not this patch; test_repair_preserves_source_permissions is the POSIX permission test and is not this Windows test",
        ),
    },
    Row {
        name: "test_repair_preserves_source_permissions",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_preserves_source_permissions: skipped on Windows. The source mode is set to 0o640 and the output mode equals 0o640. It does not assert a manifest. The Windows hardlink test is not this. missing stop: that Windows skip and that equal 0o640 mode together; it does not assert a manifest; test_windows_repair_works_without_hardlinks patches os.link and is not this; refuse_hardlink_same_file refuses a hardlink alias and is not this",
        ),
    },
    Row {
        name: "test_batch_existing_relocated_receipt_is_preserved",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_existing_relocated_receipt_is_preserved: repair_many reports repaired 1, the row reason is manifest-relocation-refused, the existing receipt bytes stay unchanged, and the repaired sidecar manifest is a file. The digest value is not asserted. relocate_step_removed_target is not this batch call. missing stop: that repaired 1, that manifest-relocation-refused reason, those unchanged receipt bytes, and that sidecar file together; the digest value is not asserted; relocate_step_removed_target is a removed-event message and is not this batch call; repair_many_gap is a batch gap on the old pin and is not this batch call",
        ),
    },
    Row {
        name: "test_vendor_canonical_header_uses_source_event_timestamp",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_canonical_header_uses_source_event_timestamp: api.repair uses format claude-code-jsonl and emit canonical. The header created_at equals the source event timestamp, and metadata created_at_source is first_event. A header fragment is not a whole pytest. repair_emit_reject_vendor_space is not this header. missing stop: that claude-code-jsonl format, that canonical emit, that equal created_at timestamp, and that first_event source together; repair_emit_reject_vendor_space is a dry-run repair whose emit is a vendor token with a leading space and is not this header; repair_emit_reject_canonical_space is a dry-run repair that raises on a canonical emit token with a trailing space and is not this header; vendor_repair_refused_default constructs an error and is not this header; vendor_projection_refused_default constructs an error and is not this header",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_exclusive_atomic_write_preserves_racing_destination",
    "test_repair_preserves_racing_output_and_removes_own_receipt",
    "test_dangling_symlink_is_an_existing_destination",
    "test_windows_repair_works_without_hardlinks",
    "test_repair_preserves_source_permissions",
    "test_batch_existing_relocated_receipt_is_preserved",
    "test_vendor_canonical_header_uses_source_event_timestamp",
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
fn pinned_repair_test_exclusive_publish_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 125);
}

#[test]
fn pinned_repair_test_exclusive_publish_row_count_equals_seven() {
    assert_eq!(ROWS.len(), 7);
    assert_eq!(PINNED_TEST_COUNT, 7);
    assert_eq!(PINNED_NAMES.len(), 7);
}

#[test]
fn every_pinned_repair_test_exclusive_publish_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 7);
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
    // `parity/vectors/cli/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "cli vectors python_commit spacing does not match {needle}"
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
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
    assert_eq!(not_applicable, 7);

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
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
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
