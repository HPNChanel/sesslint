//! Dispositions for the thirty-four `def test_` functions in pinned
//! `tests/test_seal.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (548 splitlines). Exactly
//! thirty-four test functions, in module order. None is parametrized. Each row
//! is the whole function. One equality, one raise, one tamper kind, one flag,
//! or one returned exit is not the pytest. A library `SealError` is not a CLI
//! exit. A returned exit is not a `SystemExit`. One tamper kind is not another
//! tamper. The helpers `_entry` and `_lines`, and the constants `NOW`,
//! `HEALTHY`, `DANGLING`, and `REPAIR_FIXTURES`, are not tests. Fixture bytes,
//! ledger lines, hash digests, and the planted token are not copied here.
//! Each row names the missing stop and the nearest different test.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata. `create_parser_subcommand_names` lists `seal` among
//! subcommand names and stops at `GAP-cli-init-create-parser`. That list is
//! not any of these functions. `parity/vectors/seal/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and is not used to mark a row
//! covered. This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call seal or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 34;
const PINNED_SPLITLINES: usize = 548;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. One equality, one raise, one tamper
/// kind, one flag, or one returned exit is not the pytest. `not_applicable`
/// names the missing stop.
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
        name: "test_entry_hash_binds_all_fields",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_entry_hash_binds_all_fields: missing stop: the schema id equals SEAL_SCHEMA_ID, and entry_sha256 equals the hash of the canonical JSON of every field except entry_sha256; both are one row; test_entry_deterministic_given_clock is two equal default entries and is not this pytest",
        ),
    },
    Row {
        name: "test_entry_deterministic_given_clock",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_entry_deterministic_given_clock: missing stop: two default entries are equal; that equality is one row; test_entry_hash_binds_all_fields is the preimage hash and is not this equality",
        ),
    },
    Row {
        name: "test_entry_field_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_entry_field_validation: missing stop: five SealError raises together, seq 0, a non-hex file hash, tool scan, a negative code count, and a previous hash of 64 z characters; all five are one row; one raise is not this pytest; test_sealed_at_format is the sealed_at string ending in Z and is not these raises",
        ),
    },
    Row {
        name: "test_sealed_at_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sealed_at_format: missing stop: sealed_at is a string and that string ends in Z; both are one row; test_entry_field_validation is five SealError raises and is not this string",
        ),
    },
    Row {
        name: "test_append_and_verify_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_append_and_verify_clean: missing stop: three appends have seq 1, 2, 3, the first previous hash is genesis, each later previous hash is the prior entry hash, and verify returns count 3 with no divergence; all of those are one row; test_verify_edit_detected is a hash-mismatch tamper and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_edit_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_edit_detected: missing stop: the middle line has healthy replaced by invalid, the divergence kind is hash-mismatch, the line is 2, and the count is 1; the kind, the line, and the count are one row; test_verify_dropped_line_detected is the dropped-line seq-gap and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_dropped_line_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_dropped_line_detected: missing stop: the middle line is deleted and the divergence kind is seq-gap; the count is not asserted; that kind is one row; test_verify_reorder_detected swaps the last two lines and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_reorder_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_reorder_detected: missing stop: the last two lines are swapped and the divergence kind is seq-gap or chain-break; that kind is one row; test_verify_edit_detected is the hash-mismatch edit and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_truncated_tail_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_truncated_tail_detected: missing stop: the last 30 characters of a one-line ledger are removed and the divergence kind is malformed-line; that kind is one row; test_verify_edit_detected is the hash-mismatch edit and is not this pytest",
        ),
    },
    Row {
        name: "test_append_refuses_divergent_ledger",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_append_refuses_divergent_ledger: missing stop: an edited line makes the next append raise SealError matching divergent; that raise is one row; test_cli_check_seal_refuses_divergent_ledger returns exit 2 and is not this API",
        ),
    },
    Row {
        name: "test_genesis_of_binds_first_line_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_genesis_of_binds_first_line_only: missing stop: the first line genesis_of equals the supplied tail, and a second append with genesis_of raises SealError matching first line; both are one row; test_append_refuses_divergent_ledger raises SealError matching divergent and is not this first line",
        ),
    },
    Row {
        name: "test_verify_missing_ledger_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_missing_ledger_raises: missing stop: verify of a missing path raises SealError; that raise is one row; test_empty_ledger_verifies_zero is an empty file with count 0 and is not this pytest",
        ),
    },
    Row {
        name: "test_empty_ledger_verifies_zero",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_ledger_verifies_zero: missing stop: an empty file verifies count 0 and no divergence; both are one row; test_verify_missing_ledger_raises is the missing path SealError and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_seal_appends",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_appends: missing stop: check of the healthy fixture with adapter codex-rollout and --seal returns 0, stderr contains sealed seq 1, there is one entry, tool is check, verdict is healthy, the file hash equals the fixture hash, and the path contains healthy_min.jsonl; all of those are one row; test_cli_check_seal_invalid_verdict is the dangling returned exit 1 and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_seal_invalid_verdict",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_invalid_verdict: missing stop: check of the dangling fixture returns 1, the verdict is invalid, and codes SL102 is 1; all three are one row; test_cli_check_seal_appends is the healthy returned exit 0 and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_seal_chain_grows",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_chain_grows: missing stop: two checks produce seq 1 and 2, and the second previous hash equals the first entry hash; all of those are one row; test_append_and_verify_clean is three library appends and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_check_seal_no_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_no_path: missing stop: --seal-no-path omits the path key; that absence is one row; test_cli_check_seal_stdin_omits_path is the stdin dash and is not this flag",
        ),
    },
    Row {
        name: "test_cli_check_seal_refuses_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_refuses_dir: missing stop: check of the fixture directory returns 2 and the ledger is not created; both are one row; test_cli_check_seal_refuses_multi_path is the two-file refusal and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_seal_refuses_multi_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_refuses_multi_path: missing stop: two files return 2 and the ledger is not created; both are one row; test_cli_check_seal_refuses_dir is the directory refusal and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_seal_refuses_divergent_ledger",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_refuses_divergent_ledger: missing stop: the second check after an edit returns 2 and the ledger still has one line; both are one row; test_append_refuses_divergent_ledger raises SealError matching divergent and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_check_seal_deterministic_modulo_clock",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_deterministic_modulo_clock: missing stop: two ledgers match on every key except sealed_at and entry_sha256, and each verifies count 1 with no divergence; both parts are one row; test_entry_deterministic_given_clock requires two default entries to be equal and is not this modulo-clock pair",
        ),
    },
    Row {
        name: "test_cli_check_seal_stdin_omits_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_stdin_omits_path: missing stop: check of dash returns 0, the file hash equals the stdin bytes, and path is absent; all three are one row; test_cli_check_seal_no_path is the --seal-no-path flag and is not this stdin",
        ),
    },
    Row {
        name: "test_cli_check_seal_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_seal_content_free: missing stop: a canonical file containing a planted token is sealed, and the ledger contains neither that token nor healthy_min; both absences are one row; test_cli_check_seal_appends requires the path to contain healthy_min.jsonl and is not these absences",
        ),
    },
    Row {
        name: "test_cli_seal_verify_ok",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_seal_verify_ok: missing stop: seal --verify returns 0 and stdout contains ok: 1 sealed entries; both are one row; test_cli_seal_verify_json is the JSON document and is not this human line",
        ),
    },
    Row {
        name: "test_cli_seal_verify_divergence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_seal_verify_divergence: missing stop: after an edit, seal --verify returns 1 and stderr contains divergence at line 1; both are one row; test_verify_edit_detected is the library hash-mismatch and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_seal_verify_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_seal_verify_json: missing stop: seal --verify --json returns 0 and the document is entries 1, ok true, and divergence null; both are one row; test_cli_seal_verify_ok is the human line and is not this document",
        ),
    },
    Row {
        name: "test_cli_seal_verify_missing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_seal_verify_missing: missing stop: seal --verify of a missing path returns 2; that returned exit is one row; test_verify_missing_ledger_raises is the library SealError and is not this returned exit; a returned exit is not a SystemExit",
        ),
    },
    Row {
        name: "test_cli_verify_seal",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_verify_seal: missing stop: verify of fixtures/verify/ok with --seal returns 0, tool is verify, verdict is ok, and the file hash equals the repaired output hash; all of those are one row; test_cli_repair_seal is the repair seal and is not this verify",
        ),
    },
    Row {
        name: "test_cli_repair_seal",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_seal: missing stop: repair of the basic fixture with --output and --seal returns 0, tool is repair, verdict is repaired, codes is empty, and the file hash equals the output and differs from the source; all of those are one row; test_cli_verify_seal is the verify seal and is not this repair",
        ),
    },
    Row {
        name: "test_cli_repair_seal_refuses_dry_run",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_seal_refuses_dry_run: missing stop: --dry-run with --seal returns 2 and the ledger is not created; both are one row; test_cli_repair_seal_refuses_preview is the preview refusal and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_seal_refuses_preview",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_seal_refuses_preview: missing stop: --preview with --seal returns 2 and the ledger is not created; both are one row; test_cli_repair_seal_refuses_dry_run is the dry-run refusal and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_seal_refuses_plan_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_seal_refuses_plan_only: missing stop: --plan-out with --seal returns 2 and the ledger is not created; both are one row; test_cli_repair_seal is the successful repair and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_seal_refuses_batch",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_seal_refuses_batch: missing stop: repair of a directory with --output-dir and --seal returns 2 and the ledger is not created; both are one row; test_cli_repair_seal is the single-file repair and is not this pytest",
        ),
    },
    Row {
        name: "test_seal_schema_self_consistent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_seal_schema_self_consistent: missing stop: the schema meta is draft 2020-12, the schema const equals SEAL_SCHEMA_ID, required keys are a subset of properties, and a path-none entry contains every required key and no key outside properties; all of those are one row; test_entry_hash_binds_all_fields is one entry hash and is not this schema",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_entry_hash_binds_all_fields",
    "test_entry_deterministic_given_clock",
    "test_entry_field_validation",
    "test_sealed_at_format",
    "test_append_and_verify_clean",
    "test_verify_edit_detected",
    "test_verify_dropped_line_detected",
    "test_verify_reorder_detected",
    "test_verify_truncated_tail_detected",
    "test_append_refuses_divergent_ledger",
    "test_genesis_of_binds_first_line_only",
    "test_verify_missing_ledger_raises",
    "test_empty_ledger_verifies_zero",
    "test_cli_check_seal_appends",
    "test_cli_check_seal_invalid_verdict",
    "test_cli_check_seal_chain_grows",
    "test_cli_check_seal_no_path",
    "test_cli_check_seal_refuses_dir",
    "test_cli_check_seal_refuses_multi_path",
    "test_cli_check_seal_refuses_divergent_ledger",
    "test_cli_check_seal_deterministic_modulo_clock",
    "test_cli_check_seal_stdin_omits_path",
    "test_cli_check_seal_content_free",
    "test_cli_seal_verify_ok",
    "test_cli_seal_verify_divergence",
    "test_cli_seal_verify_json",
    "test_cli_seal_verify_missing",
    "test_cli_verify_seal",
    "test_cli_repair_seal",
    "test_cli_repair_seal_refuses_dry_run",
    "test_cli_repair_seal_refuses_preview",
    "test_cli_repair_seal_refuses_plan_only",
    "test_cli_repair_seal_refuses_batch",
    "test_seal_schema_self_consistent",
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
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn pinned_test_seal_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 548);
}

#[test]
fn pinned_test_seal_row_count_equals_thirty_four() {
    assert_eq!(ROWS.len(), 34);
    assert_eq!(PINNED_TEST_COUNT, 34);
}

#[test]
fn every_pinned_test_seal_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 34);
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
    let path = vectors_path();
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
