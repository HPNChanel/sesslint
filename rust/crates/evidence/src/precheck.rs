//! One-call precheck gate (DEV-015 / US-014 / UC-05).
//!
//! Port of `src/sesslint/precheck.py` lines 1–167
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `750cad1008deb5314a318792a38a19da3703053d`.
//!
//! `fs::metadata` follows symlinks, like `stat`. `io-error` is returned only
//! when that metadata succeeds and `is_dir()` is true. A missing path, a
//! metadata error, or a regular file is not reported as `io-error`.
//! `sesslint.api.check_file` is not ported in this crate, so those paths
//! return [`CheckFileUnavailable`]. [`decide_precheck`] classifies the fields
//! read after a report exists. It does not call `check_file`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

/// Text of the typed error returned when `check_file` cannot be called.
pub const CHECK_FILE_UNAVAILABLE: &str = "sesslint.api.check_file is not available";

/// `sesslint.api.check_file` is not available in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckFileUnavailable;

impl fmt::Display for CheckFileUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(CHECK_FILE_UNAVAILABLE)
    }
}

impl Error for CheckFileUnavailable {}

/// Closed reason vocabulary from `PrecheckReason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckReason {
    Clean,
    FindingsError,
    FindingsWarning,
    DetectionFailed,
    IoError,
    /// Present in the Python vocabulary. Not produced until `check_file` exists.
    UsageError,
}

impl PrecheckReason {
    /// Python reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::FindingsError => "findings-error",
            Self::FindingsWarning => "findings-warning",
            Self::DetectionFailed => "detection-failed",
            Self::IoError => "io-error",
            Self::UsageError => "usage-error",
        }
    }
}

/// Uninhabited report slot.
///
/// `sesslint.report.Report` is not defined in this crate, so a completed
/// report cannot be embedded. The directory `io-error` result uses `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbsentReport {}

/// Outcome of one precheck call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecheckResult {
    pub ok: bool,
    pub reason: PrecheckReason,
    /// `None` on `io-error`. This crate has no report value to store.
    pub report: Option<AbsentReport>,
    pub exit_code: i64,
}

/// Fields Python reads after `check_file` returns.
///
/// `by_severity` is consulted only for the keys `error`, `fatal`, and
/// `warning`. A missing key is 0. Other keys are ignored.
#[derive(Clone, Copy, Debug)]
pub struct ReportFields<'a> {
    pub limitation: &'a str,
    pub finding_codes: &'a [&'a str],
    pub by_severity: &'a BTreeMap<String, i64>,
}

/// Decision from [`decide_precheck`]. No report is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecheckDecision {
    pub ok: bool,
    pub reason: PrecheckReason,
    pub exit_code: i64,
}

/// Gate one path.
///
/// A directory becomes `io-error` (`ok` false, report `None`, exit 2).
/// Every other path returns [`CheckFileUnavailable`]. `profile` and `format`
/// are accepted and are not interpreted.
pub fn precheck(
    path: impl AsRef<Path>,
    _profile: Option<&str>,
    _format: Option<&str>,
) -> Result<PrecheckResult, CheckFileUnavailable> {
    match fs::metadata(path.as_ref()) {
        Ok(metadata) if metadata.is_dir() => Ok(PrecheckResult {
            ok: false,
            reason: PrecheckReason::IoError,
            report: None,
            exit_code: 2,
        }),
        Ok(_) | Err(_) => Err(CheckFileUnavailable),
    }
}

/// Classify report fields. Detection wins over error. Error wins over warning.
///
/// Finding codes match `SL301` and `SL302` by equality. `limitation` is
/// `detection-failed` when it starts with `Unsupported:` or `Skipped:`.
pub fn decide_precheck(fields: &ReportFields<'_>) -> PrecheckDecision {
    if limitation_failed(fields.limitation) || finding_failed(fields.finding_codes) {
        return decision(false, PrecheckReason::DetectionFailed, 1);
    }
    let error = severity_count(fields.by_severity, "error");
    let fatal = severity_count(fields.by_severity, "fatal");
    if error > 0 || fatal > 0 {
        return decision(false, PrecheckReason::FindingsError, 1);
    }
    if severity_count(fields.by_severity, "warning") > 0 {
        return decision(true, PrecheckReason::FindingsWarning, 0);
    }
    decision(true, PrecheckReason::Clean, 0)
}

fn decision(ok: bool, reason: PrecheckReason, exit_code: i64) -> PrecheckDecision {
    PrecheckDecision {
        ok,
        reason,
        exit_code,
    }
}

fn limitation_failed(limitation: &str) -> bool {
    limitation.starts_with("Unsupported:") || limitation.starts_with("Skipped:")
}

fn finding_failed(codes: &[&str]) -> bool {
    codes.iter().any(|&code| code == "SL301" || code == "SL302")
}

fn severity_count(counts: &BTreeMap<String, i64>, key: &str) -> i64 {
    match counts.get(key) {
        Some(value) => *value,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use super::{
        decide_precheck, precheck, CheckFileUnavailable, PrecheckDecision, PrecheckReason,
        ReportFields, CHECK_FILE_UNAVAILABLE,
    };

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesslint-rx-precheck-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn counts(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), *value))
            .collect()
    }

    fn decide(limitation: &str, codes: &[&str], pairs: &[(&str, i64)]) -> PrecheckDecision {
        let by_severity = counts(pairs);
        decide_precheck(&ReportFields {
            limitation,
            finding_codes: codes,
            by_severity: &by_severity,
        })
    }

    fn assert_decision(got: PrecheckDecision, ok: bool, reason: PrecheckReason, exit_code: i64) {
        assert_eq!(got.ok, ok);
        assert_eq!(got.reason, reason);
        assert_eq!(got.reason.as_str(), reason.as_str());
        assert_eq!(got.exit_code, exit_code);
    }

    fn assert_unavailable(path: &std::path::Path) {
        match precheck(path, Some("neutral"), Some("override")) {
            Err(CheckFileUnavailable) => {
                assert_eq!(
                    CheckFileUnavailable.to_string(),
                    "sesslint.api.check_file is not available"
                );
                assert_eq!(
                    CHECK_FILE_UNAVAILABLE,
                    "sesslint.api.check_file is not available"
                );
            }
            Ok(result) => panic!(
                "path must not become {}: {}",
                result.reason.as_str(),
                path.display()
            ),
        }
    }

    #[test]
    fn directory_is_io_error() {
        let dir = TempDir::new("directory");
        let nested = dir.child("nested");
        fs::create_dir(&nested).unwrap();
        for path in [&dir.path, &nested] {
            let result = precheck(path, Some("neutral"), None).unwrap();
            assert!(!result.ok);
            assert_eq!(result.reason, PrecheckReason::IoError);
            assert_eq!(result.reason.as_str(), "io-error");
            assert!(result.report.is_none());
            assert_eq!(result.exit_code, 2);
        }
    }

    #[test]
    fn missing_path_is_not_io_error() {
        let dir = TempDir::new("missing");
        let missing = dir.child("absent");
        assert!(!missing.exists());
        assert_unavailable(&missing);
    }

    #[test]
    fn regular_file_is_check_file_unavailable() {
        let dir = TempDir::new("file");
        let file = dir.child("plain");
        fs::write(&file, b"synthetic").unwrap();
        assert!(file.is_file());
        assert_unavailable(&file);
    }

    #[test]
    fn metadata_error_is_not_io_error() {
        let dir = TempDir::new("metadata");
        let file = dir.child("plain");
        fs::write(&file, b"synthetic").unwrap();
        let nested = file.join("child");
        assert_unavailable(&nested);
    }

    #[test]
    fn unsupported_and_skipped_are_detection_failed_with_clean_counts() {
        for limitation in [
            "Unsupported:",
            "Unsupported: synthetic",
            "Skipped:",
            "Skipped: synthetic",
        ] {
            assert_decision(
                decide(limitation, &[], &[]),
                false,
                PrecheckReason::DetectionFailed,
                1,
            );
        }
    }

    #[test]
    fn sl301_and_sl302_are_detection_failed() {
        assert_decision(
            decide("", &["SL301"], &[]),
            false,
            PrecheckReason::DetectionFailed,
            1,
        );
        assert_decision(
            decide(
                "",
                &["SL302"],
                &[("error", 0), ("fatal", 0), ("warning", 0)],
            ),
            false,
            PrecheckReason::DetectionFailed,
            1,
        );
        assert_decision(
            decide("", &["other", "SL302"], &[]),
            false,
            PrecheckReason::DetectionFailed,
            1,
        );
    }

    #[test]
    fn sl3010_is_not_a_finding_match() {
        assert_decision(decide("", &["SL3010"], &[]), true, PrecheckReason::Clean, 0);
        assert_decision(
            decide("", &["XSL301", "SL3020"], &[("warning", 2)]),
            true,
            PrecheckReason::FindingsWarning,
            0,
        );
    }

    #[test]
    fn error_or_fatal_beats_warning() {
        assert_decision(
            decide("", &[], &[("error", 1), ("warning", 4)]),
            false,
            PrecheckReason::FindingsError,
            1,
        );
        assert_decision(
            decide("", &[], &[("fatal", 1), ("warning", 9)]),
            false,
            PrecheckReason::FindingsError,
            1,
        );
        assert_decision(
            decide("", &[], &[("error", 2)]),
            false,
            PrecheckReason::FindingsError,
            1,
        );
        assert_decision(
            decide("", &[], &[("fatal", 3)]),
            false,
            PrecheckReason::FindingsError,
            1,
        );
    }

    #[test]
    fn warning_only_is_ok() {
        assert_decision(
            decide("", &[], &[("warning", 1)]),
            true,
            PrecheckReason::FindingsWarning,
            0,
        );
        assert_decision(
            decide(
                "ok",
                &["note"],
                &[("error", 0), ("fatal", 0), ("warning", 2)],
            ),
            true,
            PrecheckReason::FindingsWarning,
            0,
        );
    }

    #[test]
    fn no_detection_and_zero_counts_is_clean() {
        assert_decision(decide("", &[], &[]), true, PrecheckReason::Clean, 0);
        assert_decision(
            decide("", &[], &[("error", 0), ("fatal", 0), ("warning", 0)]),
            true,
            PrecheckReason::Clean,
            0,
        );
        for limitation in [
            "Unsupported",
            "Skipped",
            "unsupported:",
            " skipped:",
            "xUnsupported:",
        ] {
            assert_decision(decide(limitation, &[], &[]), true, PrecheckReason::Clean, 0);
        }
    }

    #[test]
    fn detection_beats_error() {
        assert_decision(
            decide(
                "Unsupported: synthetic",
                &[],
                &[("error", 9), ("fatal", 9), ("warning", 9)],
            ),
            false,
            PrecheckReason::DetectionFailed,
            1,
        );
        assert_decision(
            decide(
                "Skipped: synthetic",
                &["SL301"],
                &[("error", 4), ("warning", 1)],
            ),
            false,
            PrecheckReason::DetectionFailed,
            1,
        );
        assert_eq!(PrecheckReason::UsageError.as_str(), "usage-error");
    }
}
