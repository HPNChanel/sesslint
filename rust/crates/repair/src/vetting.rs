//! Validate an untrusted repair plan against the current source (B20).
//!
//! Port of `src/sesslint/repair/vetting.py` lines 1–67
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`_plan_step_identity`] drops `seq` from [`PlanStep::to_dict`] and stops.
//! The next Python call is `json.dumps`. This crate does not have
//! `json.dumps`. [`Display`](fmt::Display) is [`JSON_DUMPS_UNAVAILABLE`].
//! No JSON text is built.
//!
//! [`vet_plan`] calls [`compute_events_source_hash`] before the membership
//! test. A hash error is [`VetPlanError::SourceHash`] and is not replaced
//! with a digest. When the plan `source_hash` equals neither the caller
//! hash nor that events hash, the result is [`PlanSourceMismatch`].
//! [`Display`](fmt::Display) is the pin sentence. [`plan`] is not called
//! on that arm.
//!
//! Otherwise [`plan`] is called with the supplied profile, policy, and
//! `source_hash`. That function stops at
//! `sesslint.repair.recipes_conservative.register_all`. [`VetPlanError::Plan`]
//! carries that [`PlanError`]. Steps are not compared. Success is
//! [`Infallible`]. The error is not turned into
//! [`RepairRefused`](crate::errors::RepairRefused).

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use model::finding::Finding;

use crate::errors::PlanSourceMismatch;
use crate::planner::{
    compute_events_source_hash, plan, PlanError, PlanPolicy, PlanProfile, PlanStep, PlanValue,
    RepairPlan, SourceHashError, SourceHashEvent,
};

/// `json.dumps` is not available in this crate.
pub const JSON_DUMPS_UNAVAILABLE: &str = "json.dumps is not available";

/// `json.dumps` is not available in this crate.
///
/// [`Display`](fmt::Display) is exactly [`JSON_DUMPS_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonDumpsUnavailable;

impl fmt::Display for JsonDumpsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(JSON_DUMPS_UNAVAILABLE)
    }
}

impl Error for JsonDumpsUnavailable {}

/// Failure from [`vet_plan`].
///
/// [`Display`](fmt::Display) is the inner message only.
/// [`Self::SourceHash`] displays the [`SourceHashError`].
/// [`Self::PlanSourceMismatch`] displays the pin sentence.
/// [`Self::Plan`] displays the [`PlanError`] and is not
/// [`RepairRefused`](crate::errors::RepairRefused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetPlanError {
    /// [`compute_events_source_hash`] failed. The error is unchanged.
    SourceHash(SourceHashError),
    /// The plan `source_hash` matched neither compared hash.
    PlanSourceMismatch(PlanSourceMismatch),
    /// [`plan`] failed. The error is unchanged.
    Plan(PlanError),
}

impl fmt::Display for VetPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceHash(error) => error.fmt(formatter),
            Self::PlanSourceMismatch(error) => error.fmt(formatter),
            Self::Plan(error) => error.fmt(formatter),
        }
    }
}

impl Error for VetPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SourceHash(error) => Some(error),
            Self::PlanSourceMismatch(error) => Some(error),
            Self::Plan(error) => Some(error),
        }
    }
}

fn step_body_without_seq(step: &PlanStep) -> Vec<(String, PlanValue)> {
    step.to_dict()
        .into_iter()
        .filter(|(key, _value)| key != "seq")
        .collect()
}

/// `body` is the `json.dumps` argument. It is not serialized.
fn json_dumps_unavailable(body: &[(String, PlanValue)]) -> JsonDumpsUnavailable {
    debug_assert!(body.iter().all(|(key, _value)| key != "seq"));
    JsonDumpsUnavailable
}

/// Python: `_plan_step_identity`.
///
/// Builds the [`PlanStep::to_dict`] entries except `seq`. Python then calls
/// `json.dumps(body, sort_keys=True, separators=(",", ":"))`. This crate
/// returns [`JsonDumpsUnavailable`] and does not build that text.
///
/// # Errors
///
/// Always returns [`JsonDumpsUnavailable`]. Display is
/// [`JSON_DUMPS_UNAVAILABLE`]. This function does not panic.
pub fn _plan_step_identity(step: &PlanStep) -> Result<Infallible, JsonDumpsUnavailable> {
    let body = step_body_without_seq(step);
    Err(json_dumps_unavailable(&body))
}

/// Python: `vet_plan`.
///
/// [`compute_events_source_hash`] runs first, including when `source_hash`
/// already equals the plan hash. Its error is returned unchanged.
/// Membership then accepts the caller hash or the events hash. Any other
/// plan hash returns [`PlanSourceMismatch`] with the pin sentence and does
/// not call [`plan`].
///
/// A matching hash calls [`plan`] with the supplied profile, policy, and
/// `source_hash`. `acknowledge_side_effects` and `input_format` are passed
/// through. [`plan`] stops at
/// `sesslint.repair.recipes_conservative.register_all`. That [`PlanError`]
/// is returned unchanged. Steps are not compared.
///
/// # Errors
///
/// Returns [`VetPlanError`]. Success is [`Infallible`], so a vetted plan is
/// not returned. This function does not panic.
pub fn vet_plan(
    supplied: &RepairPlan,
    findings: &[Finding],
    events: &[SourceHashEvent],
    source_hash: &str,
    acknowledge_side_effects: bool,
    input_format: &str,
) -> Result<Infallible, VetPlanError> {
    let events_hash = match compute_events_source_hash(events) {
        Ok(hash) => hash,
        Err(error) => return Err(VetPlanError::SourceHash(error)),
    };
    let plan_hash = supplied.source_hash();
    if plan_hash != source_hash && plan_hash != events_hash.as_str() {
        return Err(VetPlanError::PlanSourceMismatch(PlanSourceMismatch::new(
            format!(
                "Plan source_hash mismatch: plan '{plan_hash}' matches neither source file SHA-256 ('{source_hash}') nor the source events hash"
            ),
        )));
    }
    let profile = PlanProfile::str_value(supplied.profile());
    let policy = PlanPolicy::str_value(supplied.policy());
    match plan(
        findings,
        events,
        &profile,
        Some(plan_hash),
        &policy,
        acknowledge_side_effects,
        Some(input_format),
    ) {
        Ok(never) => match never {},
        Err(error) => Err(VetPlanError::Plan(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use model::canonical::SessionEvent;
    use model::codes::{Repairability, Severity};
    use model::events::{EventField, EventMapping, PYTHON_STR_UNREPRESENTABLE};
    use model::finding::{Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};

    use crate::errors::{PlanSourceMismatch, RepairRefused};
    use crate::planner::{
        compute_events_source_hash, plan, Blocked, Loss, PlanError, PlanPolicy, PlanProfile,
        PlanStep, PlanStepFields, PlanValue, RepairPlan, RepairPlanFields, SourceHashError,
        SourceHashEvent, EMPTY_EVENTS_HASH, HASHLIB_SHA256_UNAVAILABLE, PLAN_VERSION,
        RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
    };

    use super::{
        step_body_without_seq, vet_plan, JsonDumpsUnavailable, VetPlanError, _plan_step_identity,
        JSON_DUMPS_UNAVAILABLE,
    };

    fn is_digest(text: &str) -> bool {
        text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn assert_no_payload(text: &str) {
        assert!(!is_digest(text), "{text}");
        assert!(!text.contains(EMPTY_EVENTS_HASH), "{text}");
        assert!(!text.contains("synthetic-recipe"), "{text}");
        assert!(!text.contains("synthetic-blocked"), "{text}");
        assert!(!text.contains("synthetic target marker"), "{text}");
        assert!(!text.contains("synthetic-fingerprint"), "{text}");
        assert!(!text.contains("0123456789abcdef"), "{text}");
        assert!(!text.contains("SL203"), "{text}");
        assert!(!text.contains("SL108"), "{text}");
        assert!(!text.contains("rec-synthetic"), "{text}");
        assert!(!text.contains("echo-me"), "{text}");
        assert!(!text.contains("evt-synthetic"), "{text}");
        assert!(!text.contains("evt-a"), "{text}");
        assert!(!text.contains("derives for this source now"), "{text}");
        assert!(!text.contains("same name and bytes"), "{text}");
        assert!(!text.contains("PLAN_SOURCE_MISMATCH"), "{text}");
        assert!(!text.contains("REPAIR_REFUSED"), "{text}");
        assert!(!text.contains('{'), "{text}");
        assert!(!text.contains("discarded-suffix"), "{text}");
    }

    fn assert_not_repair_refused(err: &VetPlanError) {
        assert_no_payload(&err.to_string());
        if let Some(source) = err.source() {
            assert!(source.downcast_ref::<RepairRefused>().is_none());
        }
    }

    fn step_at(seq: i128, lossy: bool) -> PlanStep {
        let mut fields = PlanStepFields::new(seq, "synthetic-recipe", "0123456789abcdef", Some(0));
        if lossy {
            fields.lossy = true;
            fields.loss = vec![("discarded-suffix".to_owned(), 2)];
        }
        PlanStep::try_new(fields).expect("step")
    }

    fn marker_finding() -> Finding {
        let source =
            SourceRef::try_new("<canonical>", None, Some("rec-synthetic")).expect("source");
        Finding::try_new(FindingInput {
            code: PyValue::string("SL203"),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic target marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        })
        .expect("finding")
    }

    fn supplied_plan(source_hash: &str, profile: &str, policy: &str) -> RepairPlan {
        RepairPlan::new(RepairPlanFields {
            source_hash: source_hash.to_owned(),
            profile: profile.to_owned(),
            steps: vec![step_at(41, true)],
            blocked: vec![Blocked::new(
                "0123456789abcdef",
                "SL108",
                "synthetic-blocked",
            )],
            loss_accounting: Loss::default(),
            fingerprint: "synthetic-fingerprint".to_owned(),
            version: PLAN_VERSION.to_owned(),
            policy: policy.to_owned(),
        })
    }

    fn planner_error(
        supplied: &RepairPlan,
        findings: &[Finding],
        events: &[SourceHashEvent],
        acknowledge_side_effects: bool,
        input_format: &str,
    ) -> PlanError {
        plan(
            findings,
            events,
            &PlanProfile::str_value(supplied.profile()),
            Some(supplied.source_hash()),
            &PlanPolicy::str_value(supplied.policy()),
            acknowledge_side_effects,
            Some(input_format),
        )
        .expect_err("planner seam")
    }

    fn vet(
        supplied: &RepairPlan,
        findings: &[Finding],
        events: &[SourceHashEvent],
        source_hash: &str,
        acknowledge_side_effects: bool,
        input_format: &str,
    ) -> VetPlanError {
        let err = vet_plan(
            supplied,
            findings,
            events,
            source_hash,
            acknowledge_side_effects,
            input_format,
        )
        .expect_err("vet_plan stops");
        assert_not_repair_refused(&err);
        err
    }

    #[test]
    fn plan_step_identity_stops_at_json_dumps_without_json_text() {
        assert_eq!(JSON_DUMPS_UNAVAILABLE, "json.dumps is not available");
        let seq_one = step_at(1, false);
        let seq_other = step_at(99, false);
        let lossy = step_at(41, true);
        assert_ne!(seq_one.to_dict(), seq_other.to_dict());
        assert_eq!(
            step_body_without_seq(&seq_one),
            step_body_without_seq(&seq_other)
        );
        assert!(step_body_without_seq(&seq_one)
            .iter()
            .all(|(key, _value)| key != "seq"));
        assert!(step_body_without_seq(&seq_one).iter().any(|(key, value)| {
            key == "recipe" && value == &PlanValue::str_value("synthetic-recipe")
        }));
        assert_eq!(
            step_body_without_seq(&seq_one).len() + 1,
            seq_one.to_dict().len()
        );
        assert!(step_body_without_seq(&lossy)
            .iter()
            .any(|(key, _value)| key == "loss"));
        assert_ne!(
            step_body_without_seq(&seq_one).len(),
            step_body_without_seq(&lossy).len()
        );

        let plain_err = _plan_step_identity(&seq_one).expect_err("plain");
        let other_err = _plan_step_identity(&seq_other).expect_err("other seq");
        let lossy_err = _plan_step_identity(&lossy).expect_err("lossy");
        assert_eq!(plain_err, JsonDumpsUnavailable);
        assert_eq!(plain_err, other_err);
        assert_eq!(plain_err, lossy_err);
        assert_eq!(plain_err.to_string(), "json.dumps is not available");
        assert!(plain_err
            .to_string()
            .bytes()
            .all(|byte| !byte.is_ascii_digit()));
        assert!(!plain_err.to_string().contains("synthetic-recipe"));
        assert!(!plain_err.to_string().contains('{'));
        assert!(!plain_err.to_string().contains("seq"));
        assert!(plain_err.source().is_none());
    }

    #[test]
    fn events_hash_failure_is_propagated_before_membership() {
        let rendered = vec![
            SourceHashEvent::Rendered("echo-me".to_owned()),
            SourceHashEvent::Rendered("later-synthetic".to_owned()),
        ];
        let unrendered = vec![SourceHashEvent::Unrenderable];
        let mapping = vec![SourceHashEvent::Mapping(EventMapping::new(vec![(
            "id".to_owned(),
            EventField::Str("evt-a".to_owned()),
        )]))];
        let session = vec![SourceHashEvent::Session(Box::new(SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        )))];
        let findings = [marker_finding()];
        let pairs = [
            ("same-synthetic-hash", "same-synthetic-hash"),
            ("plan-synthetic-hash", "caller-synthetic-hash"),
        ];
        for events in [&rendered, &unrendered, &mapping, &session] {
            let direct = compute_events_source_hash(events).expect_err("events hash");
            assert!(!is_digest(&direct.to_string()));
            for (plan_hash, caller) in pairs {
                let supplied = supplied_plan(plan_hash, "strict", "conservative");
                let err = vet(&supplied, &findings, events, caller, true, "canonical");
                assert_eq!(err, VetPlanError::SourceHash(direct));
                assert_eq!(err.to_string(), direct.to_string());
                assert_ne!(
                    err.to_string(),
                    RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
                );
                assert!(!err.to_string().starts_with("Plan source_hash mismatch:"));
                match &direct {
                    SourceHashError::Hashlib => {
                        assert_eq!(err.to_string(), HASHLIB_SHA256_UNAVAILABLE);
                    }
                    SourceHashError::Unrenderable => {
                        assert_eq!(err.to_string(), PYTHON_STR_UNREPRESENTABLE);
                        assert_ne!(err.to_string(), HASHLIB_SHA256_UNAVAILABLE);
                    }
                    SourceHashError::Canonical(_) => {
                        assert_ne!(err.to_string(), HASHLIB_SHA256_UNAVAILABLE);
                        assert_ne!(err.to_string(), PYTHON_STR_UNREPRESENTABLE);
                    }
                }
                let source = err.source().expect("source");
                assert_eq!(source.downcast_ref::<SourceHashError>(), Some(&direct));
                assert!(source.downcast_ref::<PlanError>().is_none());
                assert!(source.downcast_ref::<PlanSourceMismatch>().is_none());
            }
        }
    }

    #[test]
    fn mismatch_display_is_the_pin_sentence_and_plan_is_not_called() {
        let findings = [marker_finding()];
        for (plan_hash, caller) in [
            ("plan-synthetic-hash", "caller-synthetic-hash"),
            ("abc", "ab"),
            ("abc", "zzabczz"),
            ("", "caller-synthetic-hash"),
        ] {
            let supplied = supplied_plan(plan_hash, "neutral", "Aggressive");
            let err = vet(&supplied, &findings, &[], caller, true, "not-a-format");
            let expected = format!(
                "Plan source_hash mismatch: plan '{plan_hash}' matches neither source file SHA-256 ('{caller}') nor the source events hash"
            );
            assert_eq!(err.to_string(), expected);
            let VetPlanError::PlanSourceMismatch(inner) = &err else {
                panic!("expected PlanSourceMismatch, got {err:?}");
            };
            assert_eq!(inner.to_string(), expected);
            assert_eq!(inner.code(), PlanSourceMismatch::DEFAULT_CODE);
            assert_eq!(inner.code(), "PLAN_SOURCE_MISMATCH");
            assert!(!err.to_string().contains("Invalid repair policy"));
            assert!(!err.to_string().contains("events hash ('"));
            assert_ne!(
                err.to_string(),
                RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
            );
            let planned = planner_error(&supplied, &findings, &[], true, "not-a-format");
            assert!(matches!(planned, PlanError::Policy(_)));
            assert_eq!(
                planned.to_string(),
                "Invalid repair policy: 'Aggressive'. Must be 'conservative' or 'salvage'"
            );
            assert_ne!(err.to_string(), planned.to_string());
            let source = err.source().expect("source");
            assert_eq!(source.downcast_ref::<PlanSourceMismatch>(), Some(inner));
            assert!(source.downcast_ref::<PlanError>().is_none());
        }
    }

    #[test]
    fn matching_caller_hash_propagates_the_planner_error() {
        let findings = [marker_finding()];
        let supplied = supplied_plan("caller-synthetic-hash", "strict", "conservative");
        let err = vet(
            &supplied,
            &findings,
            &[],
            "caller-synthetic-hash",
            true,
            "canonical",
        );
        let planned = planner_error(&supplied, &findings, &[], true, "canonical");
        assert_eq!(planned, PlanError::RegisterAll);
        assert_eq!(err, VetPlanError::Plan(planned));
        assert_eq!(
            err.to_string(),
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
        );
        assert_eq!(
            err.to_string(),
            "sesslint.repair.recipes_conservative.register_all is not available"
        );
        assert_eq!(
            err.source().expect("source").downcast_ref::<PlanError>(),
            Some(&PlanError::RegisterAll)
        );

        let empty = supplied_plan("", "neutral", "conservative");
        let empty_err = vet(&empty, &findings, &[], "", false, "canonical");
        assert_eq!(empty_err, VetPlanError::Plan(PlanError::RegisterAll));
        assert!(!empty_err
            .to_string()
            .starts_with("Plan source_hash mismatch:"));
    }

    #[test]
    fn matching_events_hash_propagates_the_planner_error() {
        let findings = [marker_finding()];
        let events_hash = compute_events_source_hash(&[]).expect("empty events");
        assert_eq!(events_hash, EMPTY_EVENTS_HASH);
        let supplied = supplied_plan(&events_hash, "neutral", "salvage");
        let err = vet(
            &supplied,
            &findings,
            &[],
            "caller-synthetic-hash",
            false,
            "not-a-format",
        );
        let planned = planner_error(&supplied, &findings, &[], false, "not-a-format");
        assert_eq!(planned, PlanError::RegisterAll);
        assert_eq!(err, VetPlanError::Plan(planned));
        assert_ne!(
            supplied.source_hash(),
            "caller-synthetic-hash",
            "events hash is the only match"
        );

        let both = supplied_plan(EMPTY_EVENTS_HASH, "neutral", "conservative");
        let both_err = vet(&both, &findings, &[], EMPTY_EVENTS_HASH, true, "canonical");
        assert_eq!(both_err, VetPlanError::Plan(PlanError::RegisterAll));
    }

    #[test]
    fn matching_invalid_policy_is_propagated_and_not_repair_refused() {
        let findings = [marker_finding()];
        let supplied = supplied_plan("caller-synthetic-hash", "neutral", "nope");
        let err = vet(
            &supplied,
            &findings,
            &[],
            "caller-synthetic-hash",
            false,
            "canonical",
        );
        let planned = planner_error(&supplied, &findings, &[], false, "canonical");
        assert_eq!(err, VetPlanError::Plan(planned.clone()));
        assert!(matches!(planned, PlanError::Policy(_)));
        assert_eq!(
            err.to_string(),
            "Invalid repair policy: 'nope'. Must be 'conservative' or 'salvage'"
        );
        assert_ne!(
            err.to_string(),
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
        );
        assert!(err
            .source()
            .expect("source")
            .downcast_ref::<RepairRefused>()
            .is_none());
        assert_eq!(
            err.source().expect("source").downcast_ref::<PlanError>(),
            Some(&planned)
        );
    }
}
