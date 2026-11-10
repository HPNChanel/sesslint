//! Dispositions for the twenty `def test_` functions in pinned
//! `tests/cli/test_plan_apply.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (347 splitlines). Exactly
//! twenty test functions, in module order. One is parametrized:
//! `test_apply_plan_refuses_overrides` has three flag cells. That function is
//! one row covering every cell. The helpers `_stage`, `_sha`, and `_one_shot`
//! are not tests. Each row is the whole function. A CLI command is not
//! `api.plan_repair`. `api.apply_plan` is not the CLI. A comment is not an
//! assertion. Source bytes and session lines are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call cli, repair, or api functions
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33 ids at this
//! pin and none of those ids is one of these twenty functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these twenty
//! functions. `parity/vectors/repair/vectors.json` has one id,
//! `python_dunder_all`, pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source, and that one id is not one of these twenty functions. There is no
//! `repair.plan` corpus. `removed_flag_hint_salvage` is a removed check-flag
//! hint. `module_all` lists export names. `repair_plan_path_exclusive` is one
//! dry-run repair call. `plan_source_mismatch_default` and
//! `plan_tampered_default` are constructor cells on the old pin. None of those
//! is an entire pinned test. Therefore every row is NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 20;
const PINNED_SPLITLINES: usize = 347;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A CLI command is not `api.plan_repair`. `api.apply_plan`
/// is not the CLI. A comment is not an assertion. Each row is the whole
/// function. `not_applicable` names the missing stop.
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
        name: "test_plan_out_export_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_export_only: the CLI exits 0, the plan file exists, the seven keys are present, the version is sesslint.plan/v1, no manifest exists, and stdout contains Plan written to and Plan fingerprint:. All of that is one row. It does not assert the hash values. missing stop: all of that together; those keys are version, source_hash, profile, fingerprint, steps, blocked, and loss_accounting; a comment is not an assertion that no output file exists; a CLI command is not api.plan_repair; the deterministic-bytes test is not this pytest; test_plan_out_deterministic_bytes is those two exports",
        ),
    },
    Row {
        name: "test_plan_out_deterministic_bytes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_deterministic_bytes: both dry-run exports exit 0 and the plan bytes are equal. Both exports are one row. The single export test is not this pytest. missing stop: both exports together; it does not assert the seven keys, the version, or stdout; test_plan_out_export_only is that single export; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_byte_identical_to_one_shot",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_byte_identical_to_one_shot: the export exits 0, the apply exits 0, the one-shot exits 0, the output hashes are equal, and the manifest hashes are equal. All of that is one row. It does not assert the hash strings. The same-run command is not this sequence. missing stop: all of that together; a CLI command is not api.plan_repair; test_plan_out_then_apply_same_run is that same-run command; the helper _one_shot is not this sequence",
        ),
    },
    Row {
        name: "test_plan_out_then_apply_same_run",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_then_apply_same_run: one command exits 0, the plan file exists, the one-shot exits 0, and both the output hashes and the manifest hashes are equal. All of that is one row. The two-command apply is not this pytest. missing stop: all of that together; it does not assert the hash strings; test_apply_plan_byte_identical_to_one_shot is that separate export and apply; a CLI command is not api.plan_repair; the helper _one_shot is not this pytest",
        ),
    },
    Row {
        name: "test_legacy_plan_flag_still_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_legacy_plan_flag_still_applies: the export exits 0, the --plan apply exits 0, and the output file exists. It does not assert byte identity. The --apply-plan identity test is not this pytest. missing stop: all of that together; it does not assert a manifest; test_apply_plan_byte_identical_to_one_shot is that --apply-plan identity test; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_stale_source_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_stale_source_refused: the export exits 0, the drifted apply exits 1, and stderr contains PLAN_SOURCE_MISMATCH. All of that is one row. The API exception test is not this CLI. missing stop: all of that together; it does not assert an exception type; api.apply_plan is not the CLI; test_api_apply_plan_stale_raises is that API exception; plan_source_mismatch_default is a constructor cell and is not this CLI",
        ),
    },
    Row {
        name: "test_apply_plan_tampered_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_tampered_refused: the export exits 0, the emptied-steps apply exits 1, and stderr contains PLAN_TAMPERED. All of that is one row. The API exception tuple is not this CLI. missing stop: all of that together; api.apply_plan is not the CLI; test_api_apply_plan_tampered_raises is that tuple; plan_tampered_default is a constructor cell and is not this CLI",
        ),
    },
    Row {
        name: "test_apply_plan_salvage_policy_derived",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_salvage_policy_derived: the salvage export exits 0 and the document policy is salvage; the apply without a policy flag exits 0 and the manifest is present. Both commands are one row. It does not assert an output hash. missing stop: both commands together; removed_flag_hint_salvage is a removed check-flag hint and is not this pytest; the three-cell override refusal is not this pytest; test_apply_plan_refuses_overrides is those three cells; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_dry_run_validates_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_dry_run_validates_only: the export exits 0, the dry-run apply exits 0, stdout contains Plan fingerprint:, and no manifest exists. All of that is one row. The export-only test also writes a plan without dry-run and is not this pytest. missing stop: all of that together; it does not assert Plan written to; test_plan_out_export_only is that export-only test; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_refuses_overrides",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_refuses_overrides: all three cells, policy, profile, and adapter, exit 2 and stderr contains authoritative. All three cells are one row. The salvage apply is not this pytest. missing stop: all three cells together; the values are salvage, strict, and canonical; each cell exports with exit 0 before the refusal; test_apply_plan_salvage_policy_derived is that salvage apply; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_plan_out_conflict",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_plan_out_conflict: the export exits 0, the combined apply and plan-out exits 2, and stderr contains --plan-out. It does not assert that the second plan file is absent. The required-output test is not this pytest. missing stop: all of that together; test_apply_plan_requires_output_unless_dry is that required-output test; the API mutex is not this CLI; test_api_repair_plan_mutex is that ValueError; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_plan_out_refuses_source_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_refuses_source_path: the CLI exits 2, the source bytes are unchanged, and stderr contains Error writing plan. The hard-link test is not this pytest. missing stop: all of that together; all of that is one row; test_plan_out_refuses_hard_link_to_source is that hard-link test; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_plan_out_refuses_hard_link_to_source",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_refuses_hard_link_to_source: when the filesystem cannot make a hard link the test skips; otherwise the alias exits 2, the source bytes are unchanged, and stderr contains Error writing plan. The skip and the refusal are one row. The same-path test is not this pytest. missing stop: the skip and the refusal together; test_plan_out_refuses_source_path is that same-path test; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_plan_out_refuses_output_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_out_refuses_output_path: the CLI exits 2, the output does not exist, the source bytes are unchanged, and stderr contains Error writing plan. All of that is one row. The same-path test is not this pytest. missing stop: all of that together; test_plan_out_refuses_source_path is that same-path test; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_apply_plan_requires_output_unless_dry",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_plan_requires_output_unless_dry: the export exits 0, the apply without output exits 2, and stderr contains --output is required. All of that is one row. The dry-run apply is not this pytest. missing stop: all of that together; test_apply_plan_dry_run_validates_only is that dry-run apply; a CLI command is not api.plan_repair",
        ),
    },
    Row {
        name: "test_api_plan_repair_and_apply_plan",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_plan_repair_and_apply_plan: the plan is a RepairPlan with at least one step; applying the object yields a manifest and a file; applying the path yields a manifest and the same output hash; applying the mapping yields a manifest and the same output hash. All three forms are one row. A CLI command is not this API sequence. missing stop: all three forms together; it does not assert the hash strings; it does not assert that the manifest hashes are equal; module_all lists plan_repair and apply_plan among exports and is not this API sequence; a CLI command is not api.plan_repair; api.apply_plan is not the CLI",
        ),
    },
    Row {
        name: "test_api_apply_plan_stale_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_apply_plan_stale_raises: the drifted apply raises PlanSourceMismatch. It does not assert a CLI code. The CLI stale test is not this pytest. missing stop: that PlanSourceMismatch; it does not assert a message; plan_repair returns before the drift; api.apply_plan is not the CLI; test_apply_plan_stale_source_refused is that CLI stale test; plan_source_mismatch_default is a constructor cell and is not this pytest",
        ),
    },
    Row {
        name: "test_api_apply_plan_tampered_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_apply_plan_tampered_raises: the emptied-steps mapping raises PlanTampered, PlanSourceMismatch, or ValueError. That tuple is one row. The CLI test asserts PLAN_TAMPERED and is not this pytest. missing stop: that tuple; a comment is not an assertion that only PlanTampered is raised; api.apply_plan is not the CLI; test_apply_plan_tampered_refused is that CLI test; plan_tampered_default is a constructor cell and is not this pytest",
        ),
    },
    Row {
        name: "test_api_repair_plan_mutex",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_repair_plan_mutex: passing both a plan object and a plan path raises ValueError whose message contains mutually exclusive. The conflict CLI is not this pytest. missing stop: that ValueError; it does not assert the words plan and plan_path; repair_plan_path_exclusive is one dry-run repair call with with_plan and is not this pytest; test_apply_plan_plan_out_conflict is that conflict CLI; a CLI command is not api.plan_repair; api.repair is not the CLI",
        ),
    },
    Row {
        name: "test_load_plan_strict_round_trip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_plan_strict_round_trip: the loaded fingerprint equals the exported fingerprint and the loaded source hash equals the exported source hash. Both equalities are one row. It does not assert the policy. The salvage document test is not this pytest. missing stop: both equalities together; load_plan is not the CLI; a CLI command is not api.plan_repair; test_apply_plan_salvage_policy_derived is that salvage document test; python_dunder_all is not this pytest; there is no repair.plan corpus",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_plan_out_export_only",
    "test_plan_out_deterministic_bytes",
    "test_apply_plan_byte_identical_to_one_shot",
    "test_plan_out_then_apply_same_run",
    "test_legacy_plan_flag_still_applies",
    "test_apply_plan_stale_source_refused",
    "test_apply_plan_tampered_refused",
    "test_apply_plan_salvage_policy_derived",
    "test_apply_plan_dry_run_validates_only",
    "test_apply_plan_refuses_overrides",
    "test_apply_plan_plan_out_conflict",
    "test_plan_out_refuses_source_path",
    "test_plan_out_refuses_hard_link_to_source",
    "test_plan_out_refuses_output_path",
    "test_apply_plan_requires_output_unless_dry",
    "test_api_plan_repair_and_apply_plan",
    "test_api_apply_plan_stale_raises",
    "test_api_apply_plan_tampered_raises",
    "test_api_repair_plan_mutex",
    "test_load_plan_strict_round_trip",
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
fn pinned_cli_test_plan_apply_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 347);
}

#[test]
fn pinned_cli_test_plan_apply_row_count_equals_twenty() {
    assert_eq!(ROWS.len(), 20);
    assert_eq!(PINNED_TEST_COUNT, 20);
    assert_eq!(PINNED_NAMES.len(), 20);
}

#[test]
fn every_pinned_cli_test_plan_apply_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 20);
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
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(
            !names.contains(id),
            "cli id {id} equals a pinned test name"
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
    assert_eq!(not_applicable, 20);

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
        assert!(
            !names.contains(id),
            "api id {id} equals a pinned test name"
        );
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
