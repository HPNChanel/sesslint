//! SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).
//!
//! Port of `src/sesslint/api.py` lines 1–516
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! This module exposes pure library functions. It performs no terminal
//! printing, no process exit, and no color formatting.
//!
//! [`check_file`] (lines 83–134) and [`check_bytes`] (lines 137–181) keep the
//! pin's argument order. [`check_bytes`] applies `min` when `max_input_bytes`
//! is set (lines 164–165). Both then call [`_check_impl`] (lines 184–516)
//! with `_capture_events = None` and `_oversized_snapshot = False`.
//!
//! [`_check_impl`] screens thresholds (line 208), then `Path.exists` when
//! `data is None` (line 216). The next call is
//! `sesslint.profiles.apply_rule_selection` (line 219). That function is not
//! the same function: `get_profile` does not load a profile. This crate does
//! not link `sesslint.profiles`. The call returns [`ApiError::Unsupported`]
//! with [`APPLY_RULE_SELECTION_UNAVAILABLE`]. The file is not opened. No
//! report, finding, or assurance value is built.
//!
//! Later pin steps are not evaluated. That includes the byte cap, timestamp
//! skew, `resolve_effective_config`, the oversized read, and these late
//! imports: `sesslint.io` (`probe_bytes_encoding`, `probe_text_encoding`),
//! `sesslint.baseline.filter_findings`, `sesslint.adapters.detect.resolve_format_bytes`,
//! `sesslint.adapters.load`, and `sesslint.reference.reference_equivalent_if_clean`.
//! `sesslint.repair.errors` and `sesslint.repair.writeback` are not imported
//! in lines 184–516.
//!
//! # Recorded gaps
//!
//! * Python `bool` is not an `int` and not a `float`. Thresholds are
//!   `Option<f64>`. `True` and `False` cannot be passed. An `int` cannot be
//!   passed, so `got 1` is not produced; `1.0` is the float.
//! * Python `int` is unbounded. Caps and `timestamp_skew_ms` are `i64`.
//!   Those checks sit after `apply_rule_selection` and are not reached.
//! * Python `str` can hold a lone surrogate. Paths are `Path`.
//! * Threshold text uses the adapters rendering for `0.0`, `-0.0`, `nan`,
//!   `inf`, `-inf`, and debug text that already has a decimal or an exponent.
//!   Other magnitudes can differ from Python `str(float)`.
//! * `Path.exists` errors that are not absence keep Rust's [`std::io::Error`]
//!   text. Python would raise that `OSError`.
//! * Line 80 is `VerifyVerdict = Verdict`. `sesslint.verify.Verdict` is not a
//!   dependency of this crate. This module does not alias another verdict type.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use model::canonical::SessionEvent;
use report::progress::{CancellationToken, ProgressEvent};

/// Python `sesslint.io.DEFAULT_MAX_FILE_BYTES` (`100 * 1024 * 1024`).
///
/// The pin imports the name and uses it as the default cap. This crate does
/// not link `sesslint.io`. The integer is that default, not a read.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// Python `profile: str = "neutral"`.
pub const DEFAULT_PROFILE: &str = "neutral";

/// Python `virtual_path: str = "<stdin>"`.
///
/// Reported verbatim. It is not resolved against the current directory.
pub const DEFAULT_VIRTUAL_PATH: &str = "<stdin>";

/// Next call after the exists check. Not the same function in this crate.
pub const APPLY_RULE_SELECTION_UNAVAILABLE: &str =
    "sesslint.profiles.apply_rule_selection is not available";

/// Python `_capture_events`. Not invoked by this slice.
type CaptureEvents<'a> = &'a dyn Fn(&str, &[SessionEvent]);

/// Failure from [`check_file`], [`check_bytes`], and [`_check_impl`].
///
/// [`Self::Value`] is a threshold `ValueError`. [`Self::NotFound`] is
/// `FileNotFoundError`. [`Self::Io`] is an `OSError` from `Path.exists`.
/// [`Self::Unsupported`] is the static seam. Its text does not include a
/// path or payload bytes.
#[derive(Debug)]
pub enum ApiError {
    /// The next call is not the same function as the pin.
    Unsupported(&'static str),
    /// Python `ValueError` from `validate_detection_thresholds`.
    Value(String),
    /// Python `FileNotFoundError`: `Path not found: {path}`.
    NotFound(String),
    /// `Path.exists` failed with an error other than absence.
    Io(io::Error),
}

impl ApiError {
    /// Static seam text, when this is [`Self::Unsupported`].
    #[must_use]
    pub const fn unsupported_message(&self) -> Option<&'static str> {
        match self {
            Self::Unsupported(message) => Some(*message),
            Self::Value(_) | Self::NotFound(_) | Self::Io(_) => None,
        }
    }
}

impl PartialEq for ApiError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsupported(left), Self::Unsupported(right)) => left == right,
            (Self::Value(left), Self::Value(right))
            | (Self::NotFound(left), Self::NotFound(right)) => left == right,
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            _ => false,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => formatter.write_str(message),
            Self::Value(message) | Self::NotFound(message) => formatter.write_str(message),
            Self::Io(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Unsupported(_) | Self::Value(_) | Self::NotFound(_) => None,
        }
    }
}

impl From<io::Error> for ApiError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Python lines 164–165. `None` leaves `max_file_bytes` unchanged.
fn bound_max_file_bytes(max_file_bytes: i64, max_input_bytes: Option<i64>) -> i64 {
    match max_input_bytes {
        Some(bound) => max_file_bytes.min(bound),
        None => max_file_bytes,
    }
}

/// Python `Path(virtual_path)` without resolving against the current directory.
fn display_path(virtual_path: &str) -> &Path {
    Path::new(virtual_path)
}

/// Pin line 208, for `None` and `f64` only.
///
/// `sesslint.adapters.detect.validate_detection_thresholds` is not linked.
/// `bool`, `int`, and `str` cannot be passed through [`Option<f64>`].
/// `None` is skipped. A non-finite float, or a float outside `(0.0, 1.0)`,
/// fails before the other name is screened. `margin_min > confidence_min`
/// is checked only after both values pass.
fn screen_thresholds(confidence_min: Option<f64>, margin_min: Option<f64>) -> Result<(), ApiError> {
    let confidence_min = screen_one("confidence_min", confidence_min)?;
    let margin_min = screen_one("margin_min", margin_min)?;
    if let (Some(confidence_min), Some(margin_min)) = (confidence_min, margin_min) {
        if margin_min > confidence_min {
            return Err(ApiError::Value(format!(
                "margin_min ({}) cannot exceed confidence_min ({})",
                python_float_text(margin_min),
                python_float_text(confidence_min)
            )));
        }
    }
    Ok(())
}

fn screen_one(name: &str, value: Option<f64>) -> Result<Option<f64>, ApiError> {
    let Some(number) = value else {
        return Ok(None);
    };
    if number.is_nan() || number.is_infinite() || !(0.0 < number && number < 1.0) {
        return Err(ApiError::Value(format!(
            "{name} must be strictly between 0.0 and 1.0 exclusive, got {}",
            python_float_text(number)
        )));
    }
    Ok(Some(number))
}

/// Rendering used by the adapters port of `validate_detection_thresholds`.
fn python_float_text(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        if value.is_sign_negative() {
            return "-inf".to_owned();
        }
        return "inf".to_owned();
    }
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_owned();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_owned();
    }
    let text = format!("{value:?}");
    if text.contains(['.', 'e', 'E']) {
        text
    } else {
        format!("{text}.0")
    }
}

/// `Path.exists` when `data is None`.
///
/// An empty path is `.`, matching `Path("")`. Absence is `Ok(false)`.
/// Any other metadata error is returned and not turned into `FileNotFoundError`.
fn path_exists(path: &Path) -> io::Result<bool> {
    let probed = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::metadata(probed) {
        Ok(_) => Ok(true),
        Err(error) if is_missing(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_missing(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Python `FileNotFoundError(f"Path not found: {target_path}")`.
fn path_not_found(path: &Path) -> ApiError {
    let shown = crate::bundle::path_text(path);
    ApiError::NotFound(format!("Path not found: {shown}"))
}

/// Evaluate a single session file artifact.
///
/// Python `check_file` lines 83–134. Calls [`_check_impl`] with `data=None`,
/// `virtual_path=None`, `_capture_events=None`, and `_oversized_snapshot=False`.
///
/// Rust has no keyword defaults. Pass `None`, [`DEFAULT_PROFILE`], and
/// [`DEFAULT_MAX_FILE_BYTES`] for the Python defaults. `select` and `ignore`
/// are not checked for mutual exclusion here.
///
/// # Errors
///
/// [`ApiError::Value`] when a threshold is rejected.
/// [`ApiError::NotFound`] when the path is absent.
/// [`ApiError::Io`] when `exists` fails for another reason.
/// [`ApiError::Unsupported`] ([`APPLY_RULE_SELECTION_UNAVAILABLE`]) when the
/// path exists and the thresholds pass. This function does not return a report.
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn check_file(
    path: impl AsRef<Path>,
    format: Option<&str>,
    profile: &str,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
    baseline: Option<&[&str]>,
    max_file_bytes: i64,
    timestamp_skew_ms: Option<i64>,
) -> Result<Infallible, ApiError> {
    let path = path.as_ref();
    _check_impl(
        path,
        None,
        None,
        format,
        profile,
        confidence_min,
        margin_min,
        progress_cb,
        cancel_token,
        select,
        ignore,
        baseline,
        max_file_bytes,
        timestamp_skew_ms,
        None,
        false,
    )
}

/// Evaluate a session artifact held in memory.
///
/// Python `check_bytes` lines 137–181. When `max_input_bytes` is `Some`, the
/// cap passed onward is `min(max_file_bytes, max_input_bytes)` (lines
/// 164–165). `virtual_path` becomes a [`Path`] and is not resolved against
/// the current directory. The body then calls [`_check_impl`] with that path,
/// `data`, `virtual_path`, `_capture_events=None`, and
/// `_oversized_snapshot=False`.
///
/// `data` is `Some`, so the exists check is skipped. The cap is not applied:
/// that comparison is after `apply_rule_selection`. An oversized buffer does
/// not become an SL001 finding.
///
/// # Errors
///
/// [`ApiError::Value`] when a threshold is rejected.
/// [`ApiError::Unsupported`] ([`APPLY_RULE_SELECTION_UNAVAILABLE`]) when the
/// thresholds pass. [`ApiError::NotFound`] is not returned from this wrapper.
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn check_bytes(
    data: &[u8],
    virtual_path: &str,
    format: Option<&str>,
    profile: &str,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
    baseline: Option<&[&str]>,
    max_input_bytes: Option<i64>,
    max_file_bytes: i64,
    timestamp_skew_ms: Option<i64>,
) -> Result<Infallible, ApiError> {
    let max_file_bytes = bound_max_file_bytes(max_file_bytes, max_input_bytes);
    let path = display_path(virtual_path);
    _check_impl(
        path,
        Some(data),
        Some(virtual_path),
        format,
        profile,
        confidence_min,
        margin_min,
        progress_cb,
        cancel_token,
        select,
        ignore,
        baseline,
        max_file_bytes,
        timestamp_skew_ms,
        None,
        false,
    )
}

/// Shared check pipeline for file and in-memory byte sources (ux T-06).
///
/// `data.is_some()` selects byte mode. Thresholds are screened first. When
/// `data` is `None` and the path does not exist, the result is
/// [`ApiError::NotFound`]. Otherwise the result is
/// [`ApiError::Unsupported`] ([`APPLY_RULE_SELECTION_UNAVAILABLE`]).
///
/// # Errors
///
/// [`ApiError::Value`], [`ApiError::NotFound`], [`ApiError::Io`], or
/// [`ApiError::Unsupported`]. Success is [`Infallible`]. This function does
/// not build a report.
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
fn _check_impl(
    target_path: &Path,
    data: Option<&[u8]>,
    virtual_path: Option<&str>,
    format: Option<&str>,
    profile: &str,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
    baseline: Option<&[&str]>,
    max_file_bytes: i64,
    timestamp_skew_ms: Option<i64>,
    capture_events: Option<CaptureEvents<'_>>,
    oversized_snapshot: bool,
) -> Result<Infallible, ApiError> {
    screen_thresholds(confidence_min, margin_min)?;
    if data.is_none() && !path_exists(target_path)? {
        return Err(path_not_found(target_path));
    }
    // Pin line 219. The values above are the ones later steps would read.
    // They are not applied. `capture_events` is not called.
    let _pending = (
        data,
        virtual_path,
        format,
        profile,
        progress_cb,
        cancel_token,
        select,
        ignore,
        baseline,
        max_file_bytes,
        timestamp_skew_ms,
        capture_events,
        oversized_snapshot,
    );
    Err(ApiError::Unsupported(APPLY_RULE_SELECTION_UNAVAILABLE))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use model::canonical::SessionEvent;
    use report::progress::{CancellationToken, OperationCancelled, ProgressEvent};

    use super::{
        _check_impl, bound_max_file_bytes, check_bytes, check_file, display_path, is_missing,
        path_exists, python_float_text, ApiError, APPLY_RULE_SELECTION_UNAVAILABLE,
        DEFAULT_MAX_FILE_BYTES, DEFAULT_PROFILE, DEFAULT_VIRTUAL_PATH,
    };
    use crate::bundle::path_text;

    fn missing_path() -> &'static Path {
        Path::new("synthetic/sesslint-rx-cli-api-02-missing.json")
    }

    fn existing_file() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
    }

    fn require_stop(error: &ApiError) {
        assert_eq!(
            error,
            &ApiError::Unsupported(APPLY_RULE_SELECTION_UNAVAILABLE)
        );
        assert_eq!(
            error.unsupported_message(),
            Some(APPLY_RULE_SELECTION_UNAVAILABLE)
        );
        assert_eq!(
            error.to_string(),
            "sesslint.profiles.apply_rule_selection is not available"
        );
        assert!(Error::source(error).is_none());
        let text = error.to_string();
        for absent in [
            "Path not found",
            "max_file_bytes must be a positive integer",
            "timestamp_skew_ms must be a nonnegative integer",
            "select and ignore are mutually exclusive",
            "Unknown profile",
            "Unknown rule",
            "SL001",
            "SL301",
            "SL302",
            "file-too-large",
            "assurance",
            "A0",
            "finding",
            "ok:true",
            "sesslint.api._check_impl is not available",
            "sesslint.api.check_file is not available",
            "sesslint.api.check_bytes is not available",
            "sesslint.adapters.load",
            "sesslint.baseline",
            "sesslint.reference",
            "sesslint.repair.errors",
            "sesslint.repair.writeback",
            "sesslint.io.probe_bytes_encoding",
            "\n",
            "\r",
            "/",
            "\\",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
    }

    fn require_value(error: &ApiError, expected: &str) {
        assert_eq!(error.to_string(), expected);
        assert_eq!(error, &ApiError::Value(expected.to_owned()));
        assert!(error.unsupported_message().is_none());
        assert!(Error::source(error).is_none());
        assert!(!error.to_string().contains("Path not found"));
        assert!(!error.to_string().contains("apply_rule_selection"));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\n'));
    }

    fn require_missing(error: &ApiError, path: &Path) {
        let expected = format!("Path not found: {}", path_text(path));
        assert_eq!(error.to_string(), expected);
        assert_eq!(error, &ApiError::NotFound(expected));
        assert!(error.unsupported_message().is_none());
        assert!(Error::source(error).is_none());
        assert!(!error.to_string().contains("apply_rule_selection"));
        assert!(!error.to_string().contains("positive integer"));
        assert!(!error.to_string().contains("SL001"));
        assert!(!error.to_string().contains('\r'));
    }

    fn file_at(
        path: &Path,
        confidence_min: Option<f64>,
        margin_min: Option<f64>,
        max_file_bytes: i64,
        timestamp_skew_ms: Option<i64>,
    ) -> ApiError {
        match check_file(
            path,
            None,
            DEFAULT_PROFILE,
            confidence_min,
            margin_min,
            None,
            None,
            None,
            None,
            None,
            max_file_bytes,
            timestamp_skew_ms,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn bytes_at(
        data: &[u8],
        virtual_path: &str,
        confidence_min: Option<f64>,
        margin_min: Option<f64>,
        max_input_bytes: Option<i64>,
        max_file_bytes: i64,
        timestamp_skew_ms: Option<i64>,
    ) -> ApiError {
        match check_bytes(
            data,
            virtual_path,
            None,
            DEFAULT_PROFILE,
            confidence_min,
            margin_min,
            None,
            None,
            None,
            None,
            None,
            max_input_bytes,
            max_file_bytes,
            timestamp_skew_ms,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    #[test]
    fn default_max_file_bytes_matches_the_pin() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 104_857_600);
        assert_eq!(DEFAULT_PROFILE, "neutral");
        assert_eq!(DEFAULT_VIRTUAL_PATH, "<stdin>");
        assert_eq!(
            APPLY_RULE_SELECTION_UNAVAILABLE,
            "sesslint.profiles.apply_rule_selection is not available"
        );
    }

    #[test]
    fn omitted_input_bound_keeps_max_file_bytes() {
        assert_eq!(
            bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, None),
            DEFAULT_MAX_FILE_BYTES
        );
        assert_eq!(bound_max_file_bytes(0, None), 0);
        assert_eq!(bound_max_file_bytes(-5, None), -5);
        assert_eq!(bound_max_file_bytes(i64::MIN, None), i64::MIN);
        assert_eq!(bound_max_file_bytes(i64::MAX, None), i64::MAX);
    }

    #[test]
    fn input_bound_takes_the_minimum() {
        assert_eq!(bound_max_file_bytes(10, Some(3)), 3);
        assert_eq!(bound_max_file_bytes(3, Some(10)), 3);
        assert_eq!(bound_max_file_bytes(10, Some(10)), 10);
        assert_eq!(bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, Some(1)), 1);
        assert_eq!(
            bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, Some(DEFAULT_MAX_FILE_BYTES + 1)),
            DEFAULT_MAX_FILE_BYTES
        );
        assert_eq!(bound_max_file_bytes(i64::MAX, Some(i64::MIN)), i64::MIN);
        assert_eq!(bound_max_file_bytes(i64::MIN, Some(i64::MAX)), i64::MIN);
    }

    #[test]
    fn zero_and_negative_bounds_are_not_rewritten() {
        assert_eq!(bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, Some(0)), 0);
        assert_eq!(bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, Some(-1)), -1);
        assert_eq!(bound_max_file_bytes(-8, Some(-3)), -8);
        assert_eq!(bound_max_file_bytes(-3, Some(-8)), -8);
    }

    #[test]
    fn float_text_matches_the_screened_cases() {
        assert_eq!((-0.0_f64).to_bits(), 1_u64 << 63);
        assert_eq!(python_float_text(-0.0), "-0.0");
        assert_eq!(python_float_text(0.0), "0.0");
        assert_eq!(python_float_text(1.0), "1.0");
        assert_eq!(python_float_text(0.2), "0.2");
        assert_eq!(python_float_text(0.3), "0.3");
        assert_eq!(python_float_text(f64::NAN), "nan");
        assert_eq!(python_float_text(f64::INFINITY), "inf");
        assert_eq!(python_float_text(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn threshold_errors_keep_pin_order_and_do_not_touch_the_path() {
        let cases = [
            (
                Some(f64::NAN),
                Some(f64::NAN),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got nan",
            ),
            (
                Some(f64::INFINITY),
                None,
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got inf",
            ),
            (
                Some(f64::NEG_INFINITY),
                None,
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got -inf",
            ),
            (
                Some(0.0),
                None,
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 0.0",
            ),
            (
                Some(-0.0),
                None,
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got -0.0",
            ),
            (
                Some(1.0),
                None,
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1.0",
            ),
            (
                Some(-1.0),
                Some(0.2),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got -1.0",
            ),
            (
                Some(1.5),
                Some(0.2),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1.5",
            ),
            (
                Some(0.5),
                Some(f64::NAN),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got nan",
            ),
            (
                Some(0.5),
                Some(f64::INFINITY),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got inf",
            ),
            (
                Some(0.5),
                Some(f64::NEG_INFINITY),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got -inf",
            ),
            (
                Some(0.5),
                Some(0.0),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got 0.0",
            ),
            (
                Some(0.5),
                Some(-0.0),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got -0.0",
            ),
            (
                Some(0.5),
                Some(1.0),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got 1.0",
            ),
            (
                Some(0.2),
                Some(0.3),
                "margin_min (0.3) cannot exceed confidence_min (0.2)",
            ),
        ];
        let missing = missing_path();
        assert!(!missing.exists());
        for (confidence, margin, expected) in cases {
            let from_bytes = bytes_at(
                b"UNIQUE_PAYLOAD_MARKER",
                "synthetic/sesslint-rx-cli-api-02-missing.json",
                confidence,
                margin,
                Some(1),
                0,
                Some(-1),
            );
            require_value(&from_bytes, expected);
            assert!(!from_bytes.to_string().contains("UNIQUE_PAYLOAD_MARKER"));
            assert!(!from_bytes.to_string().contains("synthetic"));
            let from_file = file_at(missing, confidence, margin, 0, Some(-1));
            require_value(&from_file, expected);
            assert!(!from_file.to_string().contains("synthetic"));
        }
    }

    #[test]
    fn equal_thresholds_and_omitted_thresholds_are_accepted() {
        let missing = missing_path();
        require_missing(
            &file_at(missing, Some(0.5), Some(0.5), 0, Some(-1)),
            missing,
        );
        require_missing(
            &file_at(missing, Some(0.2), Some(0.2), i64::MIN, None),
            missing,
        );
        require_missing(
            &file_at(missing, None, Some(0.9), -1, Some(i64::MIN)),
            missing,
        );
        require_missing(
            &file_at(missing, Some(0.2), None, i64::MAX, Some(0)),
            missing,
        );
        require_missing(
            &file_at(missing, None, None, DEFAULT_MAX_FILE_BYTES, None),
            missing,
        );
        require_stop(&bytes_at(
            b"",
            DEFAULT_VIRTUAL_PATH,
            Some(0.5),
            Some(0.5),
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        ));
        require_stop(&bytes_at(
            b"synthetic",
            DEFAULT_VIRTUAL_PATH,
            None,
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        ));
        require_stop(&bytes_at(
            b"synthetic",
            DEFAULT_VIRTUAL_PATH,
            Some(1e-10),
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        ));
    }

    #[test]
    fn missing_path_is_not_found_before_the_cap_or_rule_selection() {
        let missing = missing_path();
        assert!(!missing.exists());
        for cap in [0_i64, -1, i64::MIN, i64::MAX, DEFAULT_MAX_FILE_BYTES] {
            require_missing(&file_at(missing, None, None, cap, Some(-1)), missing);
        }
        let dotted = Path::new("synthetic/./sesslint-rx-cli-api-02-missing.json");
        assert!(!dotted.exists());
        require_missing(&file_at(dotted, None, None, 0, None), dotted);
        assert!(!file_at(dotted, None, None, 0, None)
            .to_string()
            .contains("/./"));
        assert!(!file_at(dotted, None, None, 0, None)
            .to_string()
            .contains("\\./"));
        let parent =
            Path::new("sesslint-rx-cli-api-02-missing/../sesslint-rx-cli-api-02-also-missing.json");
        assert!(!parent.exists());
        require_missing(&file_at(parent, None, None, 1, None), parent);
        assert!(file_at(parent, None, None, 1, None)
            .to_string()
            .contains(".."));
    }

    #[test]
    fn existing_paths_and_bytes_stop_at_apply_rule_selection() {
        let manifest = existing_file();
        assert!(manifest.is_file());
        assert!(Path::new(".").is_dir());
        require_stop(&file_at(
            Path::new("."),
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        ));
        require_stop(&file_at(Path::new(""), None, None, 0, Some(-1)));
        for cap in [0_i64, -1, i64::MIN, i64::MAX] {
            let error = file_at(manifest, Some(0.4), Some(0.4), cap, Some(-5));
            require_stop(&error);
            assert!(!error.to_string().contains("Cargo"));
            assert!(!error.to_string().contains("package"));
        }
        let payloads: [&[u8]; 5] = [
            b"",
            b"{\"kind\":\"synthetic-session\"}\n",
            b"\xff\xfe",
            b"not-json",
            b"\0synthetic",
        ];
        for data in payloads {
            let error = bytes_at(data, DEFAULT_VIRTUAL_PATH, None, None, Some(1), 8, Some(5));
            require_stop(&error);
            assert!(!error.to_string().contains("kind"));
            assert!(!error.to_string().contains("not-json"));
            assert!(!error.to_string().contains(DEFAULT_VIRTUAL_PATH));
            assert_eq!(bound_max_file_bytes(8, Some(1)), 1);
        }
    }

    #[test]
    fn byte_mode_does_not_treat_a_missing_virtual_path_as_absent() {
        let missing = missing_path();
        assert!(!missing.exists());
        let shown = path_text(missing);
        let virtual_path = shown.as_str();
        let error = bytes_at(
            b"UNIQUE_PAYLOAD_MARKER",
            virtual_path,
            None,
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        );
        require_stop(&error);
        assert!(!error.to_string().contains("UNIQUE_PAYLOAD_MARKER"));
        assert!(!error.to_string().contains("synthetic"));
        assert!(!error.to_string().contains(".."));
    }

    #[test]
    fn non_default_arguments_do_not_leak_into_the_stop() {
        let select = ["SL001", "SL101"];
        let ignore = ["SL101", "SL001"];
        let baseline = ["fp-b", "fp-a", "fp-b"];
        let manifest = existing_file();
        let error = match check_file(
            manifest,
            Some("not-a-format"),
            "not-a-profile",
            Some(0.4),
            Some(0.2),
            None,
            None,
            Some(&select),
            Some(&ignore),
            Some(&baseline),
            1,
            Some(-1),
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_stop(&error);
        let text = error.to_string();
        assert!(!text.contains("not-a-format"));
        assert!(!text.contains("not-a-profile"));
        assert!(!text.contains("SL101"));
        assert!(!text.contains("fp-"));
        let empty: [&str; 0] = [];
        require_stop(&match check_file(
            Path::new("."),
            Some("auto"),
            DEFAULT_PROFILE,
            Some(0.25),
            Some(0.25),
            None,
            None,
            Some(&empty),
            Some(&empty),
            Some(&empty),
            DEFAULT_MAX_FILE_BYTES,
            Some(0),
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        });
    }

    #[test]
    fn wrappers_pass_pin_defaults_into_check_impl() {
        let missing = missing_path();
        let from_file = file_at(missing, None, None, DEFAULT_MAX_FILE_BYTES, None);
        let from_impl = match _check_impl(
            missing,
            None,
            None,
            None,
            DEFAULT_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
            None,
            false,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(from_file, from_impl);
        require_missing(&from_file, missing);

        let data = b"synthetic-bytes";
        let from_bytes = bytes_at(data, DEFAULT_VIRTUAL_PATH, None, None, Some(3), 9, None);
        let from_impl = match _check_impl(
            display_path(DEFAULT_VIRTUAL_PATH),
            Some(data),
            Some(DEFAULT_VIRTUAL_PATH),
            None,
            DEFAULT_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            bound_max_file_bytes(9, Some(3)),
            None,
            None,
            false,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(from_bytes, from_impl);
        require_stop(&from_bytes);
        assert_eq!(bound_max_file_bytes(9, Some(3)), 3);
    }

    #[test]
    fn oversized_flag_and_capture_are_not_consulted() {
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let capture = |_resolved: &str, _events: &[SessionEvent]| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let missing = missing_path();
        let missing_error = match _check_impl(
            missing,
            None,
            None,
            Some("canonical"),
            "not-a-profile",
            None,
            None,
            Some(&progress),
            Some(&token),
            None,
            None,
            None,
            0,
            Some(-1),
            Some(&capture),
            true,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_missing(&missing_error, missing);
        assert!(!called.load(Ordering::Relaxed));
        assert_ne!(missing_error.to_string(), OperationCancelled::MESSAGE);

        let byte_error = match _check_impl(
            Path::new("."),
            Some(b"\xffUNIQUE_PAYLOAD_MARKER"),
            Some("../synthetic/session.json"),
            Some("not-a-format"),
            "not-a-profile",
            Some(0.5),
            Some(0.1),
            Some(&progress),
            Some(&token),
            None,
            None,
            None,
            1,
            Some(-8),
            Some(&capture),
            true,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_stop(&byte_error);
        assert!(!byte_error.to_string().contains("UNIQUE_PAYLOAD_MARKER"));
        assert!(!byte_error.to_string().contains("synthetic"));
        assert!(!byte_error.to_string().contains(".."));
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert_ne!(byte_error.to_string(), OperationCancelled::MESSAGE);
    }

    #[test]
    fn virtual_path_is_not_resolved_against_cwd() {
        let stdin = display_path(DEFAULT_VIRTUAL_PATH);
        assert_eq!(stdin.as_os_str(), DEFAULT_VIRTUAL_PATH);
        assert!(stdin.is_relative());

        let relative = display_path("../synthetic/session.json");
        assert_eq!(relative.as_os_str(), "../synthetic/session.json");
        assert!(relative.is_relative());
        assert_eq!(relative.components().count(), 3);

        let absolute_text = if cfg!(windows) {
            "C:/synthetic/session.json"
        } else {
            "/synthetic/session.json"
        };
        let absolute = display_path(absolute_text);
        assert!(absolute.is_absolute());
        assert_eq!(absolute.as_os_str(), absolute_text);

        let error = bytes_at(
            b"synthetic",
            "../synthetic/session.json",
            None,
            None,
            Some(4),
            9,
            None,
        );
        require_stop(&error);
        assert!(!error.to_string().contains("synthetic"));
        assert!(!error.to_string().contains(".."));
        assert_eq!(bound_max_file_bytes(9, Some(4)), 4);
    }

    #[test]
    fn existence_distinguishes_absence_from_other_io_errors() {
        assert_eq!(path_exists(Path::new(".")).ok(), Some(true));
        assert_eq!(path_exists(Path::new("")).ok(), Some(true));
        assert_eq!(path_exists(missing_path()).ok(), Some(false));
        assert!(is_missing(&io::Error::new(
            io::ErrorKind::NotFound,
            "synthetic-absent"
        )));
        assert!(is_missing(&io::Error::new(
            io::ErrorKind::NotADirectory,
            "synthetic-not-a-directory"
        )));
        assert!(!is_missing(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic-denied"
        )));
        let wrapped = ApiError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic-denied",
        ));
        assert_eq!(wrapped.to_string(), "synthetic-denied");
        assert!(Error::source(&wrapped).is_some());
        assert!(wrapped.unsupported_message().is_none());
    }

    #[test]
    fn nul_in_a_file_path_does_not_panic() {
        let path = Path::new("synthetic/\0sesslint-rx-cli-api-02-missing");
        let error = file_at(path, None, None, DEFAULT_MAX_FILE_BYTES, None);
        assert!(
            matches!(error, ApiError::Io(_) | ApiError::NotFound(_)),
            "nul path must stop as io or not-found"
        );
        assert!(error.unsupported_message().is_none());
        assert!(!error.to_string().contains("apply_rule_selection"));
        assert!(!error.to_string().contains("SL001"));
    }
}
