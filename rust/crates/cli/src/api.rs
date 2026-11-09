//! SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).
//!
//! Port of `src/sesslint/api.py` lines 1–181
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! This module exposes pure, side-effect-free library functions. It performs
//! no terminal printing, no process exit, and no color formatting.
//!
//! [`check_file`] (lines 83–134) and [`check_bytes`] (lines 137–181) keep the
//! pin's argument order. [`check_bytes`] applies `min` when `max_input_bytes`
//! is set (lines 164–165). Both then call `_check_impl`. That function starts
//! at line 184 and is not this slice, so the call returns
//! [`ApiError::Unsupported`] with [`CHECK_IMPL_UNAVAILABLE`]. Neither function
//! detects a format, loads a session, scans bytes, or builds a report.
//!
//! Static imports on lines 9–78 are not calls. The card's late imports
//! (`sesslint.adapters.load`, `sesslint.baseline`, `sesslint.reference`,
//! `sesslint.repair.errors`, `sesslint.repair.writeback`) sit outside lines
//! 1–181 and are not reached.
//!
//! # Recorded gaps
//!
//! * Python `bool` is an `int` subclass. Caps and `timestamp_skew_ms` are
//!   `i64`. `True` is not `1` and `False` is not `0`.
//! * Python `int` is unbounded. [`DEFAULT_MAX_FILE_BYTES`] fits in `i64`.
//!   A larger integer is not representable here.
//! * Python `str` can hold a lone surrogate. Paths and rule codes are `&str`.
//!   This slice does not invent a surrogate path.
//! * Line 80 is `VerifyVerdict = Verdict`. `sesslint.verify.Verdict` is not a
//!   dependency of this crate. This module does not alias another verdict type.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::path::Path;

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

/// `sesslint.api._check_impl` is not in lines 1–181.
pub const CHECK_IMPL_UNAVAILABLE: &str = "sesslint.api._check_impl is not available";

/// Failure from [`check_file`] and [`check_bytes`].
///
/// [`Display`](fmt::Display) is the static seam text. Caller paths and
/// payloads are not copied into the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The next call is not the same function as the pin.
    Unsupported(&'static str),
}

impl ApiError {
    /// Static seam text.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unsupported(message) => message,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ApiError {}

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

/// Evaluate a single session file artifact.
///
/// Python `check_file` lines 83–134. `Path(path)` is not resolved and the
/// path is not opened. The body returns `_check_impl` at line 119. That
/// function is not this slice.
///
/// Rust has no keyword defaults. Pass `None`, [`DEFAULT_PROFILE`], and
/// [`DEFAULT_MAX_FILE_BYTES`] for the Python defaults. `select` and `ignore`
/// are not checked for mutual exclusion here.
///
/// # Errors
///
/// Always [`ApiError::Unsupported`] ([`CHECK_IMPL_UNAVAILABLE`]). The Python
/// return is a report built by `_check_impl`, which this function does not call.
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
    // Arguments of `_check_impl`, in pin order (lines 120–133). Not called.
    let _for_check_impl = (
        path,
        Option::<&[u8]>::None,
        Option::<&str>::None,
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
    );
    Err(ApiError::Unsupported(CHECK_IMPL_UNAVAILABLE))
}

/// Evaluate a session artifact held in memory.
///
/// Python `check_bytes` lines 137–181. When `max_input_bytes` is `Some`, the
/// cap passed onward is `min(max_file_bytes, max_input_bytes)` (lines
/// 164–165). `virtual_path` becomes a [`Path`] and is not resolved against
/// the current directory. The body then returns `_check_impl` at line 166.
///
/// The pin docstring says an oversized buffer becomes an SL001 finding. That
/// finding is built inside `_check_impl`, which is not this slice. This
/// function does not invent the finding.
///
/// # Errors
///
/// Always [`ApiError::Unsupported`] ([`CHECK_IMPL_UNAVAILABLE`]).
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
    // Arguments of `_check_impl`, in pin order (lines 167–180). Not called.
    let _for_check_impl = (
        path,
        data,
        virtual_path,
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
    );
    Err(ApiError::Unsupported(CHECK_IMPL_UNAVAILABLE))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use report::progress::{CancellationToken, OperationCancelled, ProgressEvent};

    use super::{
        bound_max_file_bytes, check_bytes, check_file, display_path, ApiError,
        CHECK_IMPL_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES, DEFAULT_PROFILE, DEFAULT_VIRTUAL_PATH,
    };

    fn require_unsupported(error: ApiError) {
        assert_eq!(error, ApiError::Unsupported(CHECK_IMPL_UNAVAILABLE));
        assert_eq!(error.message(), CHECK_IMPL_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.api._check_impl is not available"
        );
        assert!(Error::source(&error).is_none());
    }

    fn check_file_default(path: impl AsRef<Path>) -> ApiError {
        match check_file(
            path,
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
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn check_bytes_at(data: &[u8], virtual_path: &str, max_input_bytes: Option<i64>) -> ApiError {
        match check_bytes(
            data,
            virtual_path,
            None,
            DEFAULT_PROFILE,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            max_input_bytes,
            DEFAULT_MAX_FILE_BYTES,
            None,
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
    fn check_file_on_a_missing_path_stops_before_any_read() {
        let missing = Path::new("synthetic/missing-session.json");
        require_unsupported(check_file_default(missing));
        require_unsupported(check_file_default("synthetic/missing-session.json"));
        let error = check_file_default(missing);
        let text = error.to_string();
        assert!(!text.contains("synthetic"));
        assert!(!text.contains("NotFound"));
        assert_ne!(text, "Triage requires a regular file");
        assert_ne!(text, "max_file_bytes must be a positive integer");
    }

    #[test]
    fn check_file_does_not_reject_a_non_positive_cap() {
        let path = Path::new("synthetic/missing-session.json");
        for cap in [0_i64, -1, i64::MIN, i64::MAX] {
            let error = match check_file(
                path,
                None,
                DEFAULT_PROFILE,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                cap,
                None,
            ) {
                Ok(never) => match never {},
                Err(error) => error,
            };
            require_unsupported(error);
            assert_ne!(
                error.to_string(),
                "max_file_bytes must be a positive integer"
            );
        }
    }

    #[test]
    fn non_default_arguments_still_stop() {
        let select = ["SL001", "SL101"];
        let ignore = ["SL101", "SL001"];
        let baseline = ["fp-b", "fp-a", "fp-b"];
        let empty: [&str; 0] = [];
        let error = match check_file(
            "synthetic/missing-session.json",
            Some("not-a-format"),
            "not-a-profile",
            Some(f64::NAN),
            Some(f64::INFINITY),
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
        require_unsupported(error);
        let text = error.to_string();
        assert!(!text.contains("not-a-format"));
        assert!(!text.contains("not-a-profile"));
        assert!(!text.contains("SL101"));
        assert!(!text.contains("fp-"));
        require_unsupported(
            match check_file(
                "synthetic/missing-session.json",
                Some("auto"),
                DEFAULT_PROFILE,
                Some(0.0),
                Some(0.0),
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
            },
        );
    }

    #[test]
    fn check_file_does_not_invoke_progress_or_cancellation() {
        let called = AtomicBool::new(false);
        let callback = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
        let error = match check_file(
            "synthetic/missing-session.json",
            None,
            DEFAULT_PROFILE,
            None,
            None,
            Some(&callback),
            Some(&token),
            None,
            None,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_unsupported(error);
        assert!(!called.load(Ordering::Relaxed));
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        assert!(token.is_cancelled());
    }

    #[test]
    fn synthetic_bytes_do_not_produce_a_report() {
        let cases: [&[u8]; 4] = [
            b"",
            b"{\"kind\":\"synthetic-session\"}\n",
            b"\xff\xfe",
            b"not-json",
        ];
        for data in cases {
            let error = check_bytes_at(data, DEFAULT_VIRTUAL_PATH, None);
            require_unsupported(error);
            let text = error.to_string();
            assert!(!text.contains("assurance"));
            assert!(!text.contains("finding"));
            assert!(!text.contains("SL001"));
            assert!(!text.contains("report"));
        }
    }

    #[test]
    fn oversized_synthetic_bytes_are_not_an_sl001_finding() {
        let data = b"synthetic-bytes-past-the-cap";
        assert!(data.len() > 1);
        assert_eq!(bound_max_file_bytes(DEFAULT_MAX_FILE_BYTES, Some(1)), 1);
        let error = check_bytes_at(data, DEFAULT_VIRTUAL_PATH, Some(1));
        require_unsupported(error);
        assert!(!error.to_string().contains("SL001"));
        assert!(!error.to_string().contains(DEFAULT_VIRTUAL_PATH));
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

        let error = check_bytes_at(b"synthetic", "../synthetic/session.json", Some(4));
        require_unsupported(error);
        assert!(!error.to_string().contains("synthetic"));
        assert!(!error.to_string().contains(".."));
    }

    #[test]
    fn both_entry_points_share_one_unsupported_seam() {
        let from_file = check_file_default("synthetic/missing-session.json");
        let from_bytes = check_bytes_at(b"synthetic", DEFAULT_VIRTUAL_PATH, None);
        assert_eq!(from_file, from_bytes);
        require_unsupported(from_file);
        require_unsupported(from_bytes);
        assert_ne!(
            from_file.to_string(),
            "sesslint.api.check_file is not available"
        );
        assert_ne!(
            from_bytes.to_string(),
            "sesslint.api.check_bytes is not available"
        );
        assert_ne!(
            from_file.to_string(),
            "sesslint.verify.Verdict is not available"
        );
    }

    #[test]
    fn cancelled_bytes_still_stop_at_check_impl() {
        let called = AtomicBool::new(false);
        let callback = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let error = match check_bytes(
            b"\xff",
            DEFAULT_VIRTUAL_PATH,
            Some("canonical"),
            "neutral",
            Some(-1.0),
            Some(2.0),
            Some(&callback),
            Some(&token),
            None,
            None,
            None,
            Some(0),
            8,
            Some(5),
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_unsupported(error);
        assert!(!called.load(Ordering::Relaxed));
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        assert_eq!(bound_max_file_bytes(8, Some(0)), 0);
    }
}
