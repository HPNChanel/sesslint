//! Offline outcome-contract verification over observed snapshots (ITF-02, EXE-04).
//! Session integrity and outcome verification remain independent dimensions.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::OutcomeError;

pub mod contract;
pub mod engine;
pub mod report;
pub mod snapshot;

#[path = "schema/sesslint.snapshot.v1.rs"]
pub mod snapshot_schema;

#[path = "schema/sesslint.outcome-report.v1.rs"]
pub mod report_schema;

pub use contract::{
    contract_from_dict, load_contract, Contract, ContractError, CONTRACT_SCHEMA_VERSION,
};
pub use engine::{evaluate, EvaluationError, REASONS, STATUSES};
pub use report::{
    explain_contract, session_dimension, OutcomeReport, OUTCOME_REPORT_SCHEMA_VERSION,
};
pub use snapshot::{
    load_snapshot, parse_instant, Snapshot, SnapshotError, SNAPSHOT_SCHEMA_VERSION,
};

use std::borrow::Cow;
use std::fmt;
use std::path::Path;

/// A preloaded value retains its identity; a path is read by the existing loader.
#[derive(Debug, Clone, Copy)]
pub enum Input<'a, T> {
    Value(&'a T),
    Path(&'a Path),
}

/// Explicit naive datetimes retain Python's error behavior without a local clock.
#[derive(Debug, Clone, Copy)]
pub enum AsOf {
    Aware(snapshot::Instant),
    Naive,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOptions<'a> {
    pub as_of: Option<AsOf>,
    pub session: Option<&'a Path>,
    pub hash_keys: bool,
    pub all_conditions: bool,
}

#[derive(Debug)]
pub enum VerifyError {
    Contract(contract::LoadError),
    Source(snapshot::LoadError),
    Target(snapshot::LoadError),
    Evaluation(EvaluationError),
    Session(report::ReportError),
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(e) => e.fmt(f),
            Self::Source(e) | Self::Target(e) => e.fmt(f),
            Self::Evaluation(e) => e.fmt(f),
            Self::Session(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for VerifyError {}

/// Load, reconcile, then inspect the optional session, preserving first errors.
/// Missing as_of uses only the target observation time, never the wall clock.
pub fn verify_outcome<'a>(
    contract: Input<'a, Contract>,
    source: Input<'a, Snapshot>,
    target: Input<'a, Snapshot>,
    options: VerifyOptions<'_>,
) -> Result<OutcomeReport<'a>, VerifyError> {
    verify_with(contract, source, target, options, |path| {
        session_dimension(path, None)
    })
}

/// Adapter seam for the separately implemented session-check API. Default linked
/// sessions still return Unsupported until that backend is available.
pub fn verify_outcome_with<'a>(
    contract: Input<'a, Contract>,
    source: Input<'a, Snapshot>,
    target: Input<'a, Snapshot>,
    options: VerifyOptions<'_>,
    backend: &impl report::SessionBackend,
) -> Result<OutcomeReport<'a>, VerifyError> {
    verify_with(contract, source, target, options, |path| {
        report::session_dimension_with(path, None, backend)
    })
}

fn verify_with<'a>(
    contract: Input<'a, Contract>,
    source: Input<'a, Snapshot>,
    target: Input<'a, Snapshot>,
    options: VerifyOptions<'_>,
    session: impl FnOnce(Option<&Path>) -> Result<contract::Mapping, report::ReportError>,
) -> Result<OutcomeReport<'a>, VerifyError> {
    let resolved = match contract {
        Input::Value(value) => Cow::Borrowed(value),
        Input::Path(path) => Cow::Owned(load_contract(path).map_err(VerifyError::Contract)?),
    };
    let src = match source {
        Input::Value(value) => Cow::Borrowed(value),
        Input::Path(path) => Cow::Owned(
            load_snapshot(path, &snapshot::LoadOptions::new("source"))
                .map_err(VerifyError::Source)?,
        ),
    };
    let tgt = match target {
        Input::Value(value) => Cow::Borrowed(value),
        Input::Path(path) => Cow::Owned(
            load_snapshot(path, &snapshot::LoadOptions::new("target"))
                .map_err(VerifyError::Target)?,
        ),
    };
    let instant = options
        .as_of
        .or(tgt.observed_at.map(AsOf::Aware))
        .ok_or_else(|| {
            VerifyError::Evaluation(EvaluationError(
                "an evaluation instant is required: pass as_of or a target observed_at".into(),
            ))
        })?;
    let instant = match instant {
        AsOf::Aware(time) => Some(time),
        AsOf::Naive => None,
    };
    let engine::Evaluation {
        as_of,
        outcome,
        outcome_reasons,
        items,
        coverage,
        unmatched_target_keys,
        ..
    } = evaluate(&resolved, &src, &tgt, instant).map_err(VerifyError::Evaluation)?;
    let dimension = session(options.session).map_err(VerifyError::Session)?;
    Ok(OutcomeReport {
        evaluation: engine::Evaluation {
            contract: resolved,
            source: src,
            target: tgt,
            as_of,
            outcome,
            outcome_reasons,
            items,
            coverage,
            unmatched_target_keys,
        },
        session: dimension,
        hash_keys: options.hash_keys,
        all_conditions: options.all_conditions,
    })
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use contract::parse_strict_json;
    use std::cell::Cell;

    const SPEC: &str = r#"{"schema_version":"sesslint.outcome-contract/v1","name":"synthetic","version":"1","key":{"source":"id","target":"id"},"conditions":[{"id":"present","type":"exists"}]}"#;
    const ENVELOPE: &str = r#"{"schema_version":"sesslint.snapshot/v1","observed_at":"2026-11-09T00:00:00Z","completeness":"complete","records":[{"id":"a"}]}"#;
    fn spec() -> Contract {
        contract_from_dict(&parse_strict_json(SPEC).unwrap()).unwrap()
    }
    fn snapshot(role: &str) -> Snapshot {
        let contract::Json::Object(row) = parse_strict_json(r#"{"id":"a"}"#).unwrap() else {
            panic!()
        };
        Snapshot {
            role: role.into(),
            name: "synthetic.json".into(),
            sha256: "0".repeat(64),
            input_format: "json".into(),
            records: vec![snapshot::scalarize(&row)],
            fields: ["id".into()].into_iter().collect(),
            observed_at: snapshot::parse_instant_str("2026-11-09T00:00:00Z"),
            completeness: "complete".into(),
            origin: "user_file".into(),
            demo: false,
        }
    }
    struct Files(std::path::PathBuf);
    impl Files {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static SERIAL: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "sesslint-outcome-api-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, text: &str) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, text).unwrap();
            path
        }
    }
    impl Drop for Files {
        fn drop(&mut self) {
            // Only the test's exclusively created directory is removed.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn borrowed_values_and_flags_match_direct_report() {
        let (contract, source, target) = (spec(), snapshot("source"), snapshot("target"));
        for hash_keys in [false, true] {
            for all_conditions in [false, true] {
                let got = verify_outcome(
                    Input::Value(&contract),
                    Input::Value(&source),
                    Input::Value(&target),
                    VerifyOptions {
                        hash_keys,
                        all_conditions,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert!(
                    matches!(got.evaluation.contract, Cow::Borrowed(c) if std::ptr::eq(c, &contract))
                );
                assert!(
                    matches!(got.evaluation.source, Cow::Borrowed(s) if std::ptr::eq(s, &source))
                );
                assert!(
                    matches!(got.evaluation.target, Cow::Borrowed(t) if std::ptr::eq(t, &target))
                );
                let mut expected = OutcomeReport::new(
                    evaluate(&contract, &source, &target, target.observed_at).unwrap(),
                );
                expected.hash_keys = hash_keys;
                expected.all_conditions = all_conditions;
                assert_eq!(got.to_json().unwrap(), expected.to_json().unwrap());
                assert_eq!(
                    got.render_human().unwrap(),
                    expected.render_human().unwrap()
                );
                assert_eq!(got.outcome(), "VERIFIED");
            }
        }
    }
    #[test]
    fn path_inputs_are_owned_and_mixed_inputs_keep_roles() {
        let files = Files::new();
        let c = files.write("contract.json", SPEC);
        let s = files.write("source.json", ENVELOPE);
        let t = files.write("target.json", ENVELOPE);
        let source = load_snapshot(&s, &snapshot::LoadOptions::new("source")).unwrap();
        let got = verify_outcome(
            Input::Path(&c),
            Input::Value(&source),
            Input::Path(&t),
            VerifyOptions::default(),
        )
        .unwrap();
        assert!(matches!(got.evaluation.contract, Cow::Owned(_)));
        assert!(matches!(got.evaluation.source, Cow::Borrowed(_)));
        assert!(matches!(got.evaluation.target, Cow::Owned(_)));
        assert_eq!(got.outcome(), "VERIFIED");
        let paths = verify_outcome(
            Input::Path(&c),
            Input::Path(&s),
            Input::Path(&t),
            VerifyOptions::default(),
        )
        .unwrap();
        assert_eq!(got.to_json().unwrap(), paths.to_json().unwrap());
        assert_eq!(paths.evaluation.source.role, "source");
        assert_eq!(paths.evaluation.target.role, "target");
        // Loaded observations are retained without reopening the files.
        std::fs::write(&t, "invalid").unwrap();
        assert_eq!(paths.outcome(), "VERIFIED");
        assert_eq!(got.to_json().unwrap(), paths.to_json().unwrap());
    }
    #[test]
    fn loader_errors_precede_time_and_session_errors() {
        let files = Files::new();
        let bad = files.write("invalid.json", "{");
        let missing = files.0.join("absent.json");
        let (contract, source, mut target) = (spec(), snapshot("source"), snapshot("target"));
        target.observed_at = None;
        let options = VerifyOptions {
            session: Some(&missing),
            ..Default::default()
        };
        for path in [&bad, &missing] {
            assert!(matches!(
                verify_outcome(
                    Input::Path(path),
                    Input::Path(path),
                    Input::Path(path),
                    options
                ),
                Err(VerifyError::Contract(_))
            ));
            assert!(matches!(
                verify_outcome(
                    Input::Value(&contract),
                    Input::Path(path),
                    Input::Path(path),
                    options
                ),
                Err(VerifyError::Source(_))
            ));
            assert!(matches!(
                verify_outcome(
                    Input::Value(&contract),
                    Input::Value(&source),
                    Input::Path(path),
                    options
                ),
                Err(VerifyError::Target(_))
            ));
        }
        let err = verify_outcome(
            Input::Value(&contract),
            Input::Value(&source),
            Input::Value(&target),
            options,
        )
        .err()
        .expect("expected verification error");
        assert_eq!(
            err.to_string(),
            "an evaluation instant is required: pass as_of or a target observed_at"
        );
    }
    #[test]
    fn explicit_time_overrides_target_and_naive_is_not_defaulted() {
        let (contract, source, target) = (spec(), snapshot("source"), snapshot("target"));
        for (as_of, message) in [
            (AsOf::Naive, "the evaluation instant needs a UTC offset"),
            (
                AsOf::Aware(snapshot::parse_instant_str("2026-11-08T00:00:00Z").unwrap()),
                "the evaluation instant precedes the source observation time",
            ),
        ] {
            let err = verify_outcome(
                Input::Value(&contract),
                Input::Value(&source),
                Input::Value(&target),
                VerifyOptions {
                    as_of: Some(as_of),
                    ..Default::default()
                },
            )
            .err()
            .expect("expected verification error");
            assert_eq!(err.to_string(), message);
        }
        let mut later = target.clone();
        later.observed_at = snapshot::parse_instant_str("2026-11-10T00:00:00Z");
        let options = VerifyOptions {
            as_of: source.observed_at.map(AsOf::Aware),
            ..Default::default()
        };
        let err = verify_outcome(
            Input::Value(&contract),
            Input::Value(&source),
            Input::Value(&later),
            options,
        )
        .err()
        .expect("expected verification error");
        assert_eq!(
            err.to_string(),
            "the evaluation instant precedes the target observation time"
        );
        later.observed_at = None;
        assert_eq!(
            verify_outcome(
                Input::Value(&contract),
                Input::Value(&source),
                Input::Value(&later),
                options
            )
            .unwrap()
            .outcome(),
            "VERIFIED"
        );
    }
    struct Backend {
        calls: Cell<usize>,
    }
    impl report::SessionBackend for Backend {
        fn check_file(
            &self,
            _: &Path,
            limit: i64,
        ) -> Result<report::SessionCheck, report::SessionCheckError> {
            assert_eq!(limit, report::DEFAULT_MAX_FILE_BYTES);
            self.calls.set(self.calls.get() + 1);
            Err(report::SessionCheckError::Os)
        }
    }
    #[test]
    fn session_runs_only_after_evaluation_and_does_not_change_outcome() {
        let (contract, source, target) = (spec(), snapshot("source"), snapshot("target"));
        let backend = Backend {
            calls: Cell::new(0),
        };
        let options = VerifyOptions {
            session: Some(Path::new("synthetic-session.jsonl")),
            ..Default::default()
        };
        let got = verify_outcome_with(
            Input::Value(&contract),
            Input::Value(&source),
            Input::Value(&target),
            options,
            &backend,
        )
        .unwrap();
        assert_eq!(got.outcome(), "VERIFIED");
        assert_eq!(got.session["status"].as_str(), Some("unreadable"));
        assert_eq!(backend.calls.get(), 1);
        let bad = VerifyOptions {
            as_of: Some(AsOf::Naive),
            ..options
        };
        assert!(matches!(
            verify_outcome_with(
                Input::Value(&contract),
                Input::Value(&source),
                Input::Value(&target),
                bad,
                &backend
            ),
            Err(VerifyError::Evaluation(_))
        ));
        assert_eq!(backend.calls.get(), 1);
        assert!(matches!(
            verify_outcome(
                Input::Value(&contract),
                Input::Value(&source),
                Input::Value(&target),
                options
            ),
            Err(VerifyError::Session(report::ReportError::Unsupported(_)))
        ));
    }
}
