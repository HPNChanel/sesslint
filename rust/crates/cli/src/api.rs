//! SessLint public programmatic API providing 1:1 library-CLI parity (TASK-024).
//!
//! Port of `src/sesslint/api.py` lines 1–516, [`check_dir`] lines 519–612,
//! [`repair`] lines 615–865, [`verify`] lines 868–899, and [`plan`] through
//! [`validate_session`] lines 902–1202
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
//! [`check_dir`] (lines 519–612) rejects a non-positive `max_files`, then a
//! non-positive `max_bytes`, then screens thresholds with
//! [`screen_thresholds`]. The next call is `sesslint.scan.scan_path` (line
//! 585). That function is not linked. The call returns
//! [`ApiError::Unsupported`] with [`SCAN_PATH_UNAVAILABLE`]. The directory
//! is not walked. No file is read. `progress_cb` is not called. `baseline`
//! is not copied into a set. No report or finding is built. Lines 586–612
//! are not evaluated.
//!
//! [`repair`] (lines 615–865) treats `source_path` as `Path(...).is_file()`.
//! A missing path or a directory, including the empty path (`.` is a
//! directory), is `FileNotFoundError`: `Source file not found: {shown}`.
//! `shown` is [`crate::bundle::path_text`]. Any other metadata error is
//! [`ApiError::Io`]. The file is not opened. `emit` must then be `auto`,
//! `canonical`, or `vendor`. Supplying both an in-memory plan and `plan_path`
//! is `ValueError`: `plan and plan_path are mutually exclusive`. The plan is
//! an [`InMemoryPlan`] marker. `plan_path` is not parsed. Policy is not
//! validated. The next statement is
//! `from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format`.
//! That function is not linked. The call returns [`ApiError::Unsupported`]
//! with [`DETECT_FORMAT_UNAVAILABLE`]. No format is detected.
//! `sesslint.repair.writeback` is not imported. `VendorRepairRefused` is not
//! raised. No output file is written. `progress_cb` is not called. No
//! `RepairPlan` or `RepairManifest` is built. Lines after that import are
//! not evaluated.
//!
//! [`verify`] (lines 868–899) has no local check. The pin resolves
//! `sesslint.verify.verify` through `sys.modules` and calls it. That function
//! is not linked. The call returns [`ApiError::Unsupported`] with
//! [`VERIFY_UNAVAILABLE`] before any of the three paths is read. No
//! `VerifyVerdict` is built. No verify helper in another crate is called.
//!
//! [`plan`] (lines 902–931) calls [`repair`] with `output_path=None`, the
//! supplied policy, format, profile, and `acknowledge_side_effects`, and
//! `dry_run=True`. `plan_path`, `plan`, `emit`, `progress_cb`, and
//! `cancel_token` stay at the pin defaults (`None`, `None`, `"auto"`, `None`,
//! `None`). No `RepairPlan` is built. A missing source stays
//! `Source file not found`. A file source stops at [`DETECT_FORMAT_UNAVAILABLE`].
//!
//! [`plan_repair`] (lines 948–954) calls [`plan`] with those same arguments.
//! It does not add a stop in front of that call.
//!
//! [`apply_plan`] (lines 998–1025) has no `RepairPlan`. [`InMemoryPlan`] is not
//! one, so there is no `isinstance` arm. Every `plan_doc` takes the other
//! branch, `sesslint.repair.load_plan`. That function is not linked. The call
//! returns [`ApiError::Unsupported`] with [`LOAD_PLAN_UNAVAILABLE`] before
//! `resolve_effective_config`, `RepairRefused`, or [`repair`]. `plan_doc` is
//! not read. `output_path` is not written.
//!
//! [`repair_preview`] (lines 1043–1051) starts at
//! `from sesslint.preview import repair_preview`. That function is not linked.
//! The call returns [`ApiError::Unsupported`] with
//! [`REPAIR_PREVIEW_UNAVAILABLE`] immediately. No preview document is built.
//!
//! [`repair_many`] (lines 1077–1092) starts at
//! `from sesslint.batch import repair_many`. That function is not linked. The
//! call returns [`ApiError::Unsupported`] with [`REPAIR_MANY_UNAVAILABLE`]
//! immediately. Files are not sorted. `output_dir` is not created. No batch
//! report is built.
//!
//! [`check`] (lines 1145–1183) states the path with [`path_exists`]. Absence is
//! `FileNotFoundError`: `Path not found: {shown}`, and `shown` is
//! [`crate::bundle::path_text`]. The empty path is `.` and exists, so it is
//! not that error. Any other metadata error is [`ApiError::Io`]. A directory
//! calls [`check_dir`] with the pin arguments. A file calls [`check_file`].
//! No `Report` or `ScanReport` is built. Those callees stop at
//! [`SCAN_PATH_UNAVAILABLE`] or [`APPLY_RULE_SELECTION_UNAVAILABLE`].
//!
//! [`validate_session`] (lines 1199–1202) uses the same existence check.
//! Absence is `FileNotFoundError`: `Session file not found: {shown}` with
//! [`crate::bundle::path_text`]. The loader does not replace that message.
//! An existing path calls [`load_session_file`]. Its [`SchemaError`] is
//! returned unchanged. This module does not parse JSON.
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
//! * `check_dir` rejects a Python `bool` before the `int` test. `max_files`
//!   and `max_bytes` are `i64`. `True` renders as `True` and `False` as
//!   `False`. Those sentences cannot be produced. Decimal `str(int)` is used
//!   for `0` and for negative values.
//! * Line 80 is `VerifyVerdict = Verdict`. `sesslint.verify.Verdict` is not a
//!   dependency of this crate. This module does not alias another verdict type.
//!   [`verify`] stops before a verdict would be built.
//! * [`repair`] `emit` is `&str`. A non-`str` Python `repr` cannot be passed.
//!   The error uses single quotes around the supplied text (`got 'bad'`).
//!   Python may switch to double quotes when the text contains `'` and no `"`.
//! * `plan` is [`Option<InMemoryPlan>`]. The pin's `RepairPlan` is not built.
//! * `Path.is_file` errors that are not absence keep Rust's [`std::io::Error`]
//!   text. Python would raise that `OSError`.
//! * [`plan`] and [`plan_repair`] do not return a `RepairPlan`. Both end where
//!   [`repair`] ends.
//! * [`apply_plan`] cannot match `isinstance(plan_doc, RepairPlan)`.
//!   [`InMemoryPlan`] is only a marker for [`repair`]'s `plan` argument.
//! * [`validate_session`] returns [`ValidateSessionError`]. Absence keeps
//!   [`crate::bundle::path_text`]. [`load_session_file`] spells its own missing
//!   file with `path.display()`, and that text is used only when the loader runs.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use model::canonical::{load_session_file, Session, SessionEvent};
use model::errors::SchemaError;
use report::progress::{CancellationToken, ProgressEvent};

/// Python `sesslint.io.DEFAULT_MAX_FILE_BYTES` (`100 * 1024 * 1024`).
///
/// The pin imports the name and uses it as the default cap. This crate does
/// not link `sesslint.io`. The integer is that default, not a read.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// Python `sesslint.scan.DEFAULT_MAX_FILES` (`10000`).
///
/// The pin imports the name and uses it as the `check_dir` default. This
/// crate does not link `sesslint.scan`. The integer is that default, not a walk.
pub const DEFAULT_MAX_FILES: i64 = 10000;

/// Python `sesslint.scan.DEFAULT_MAX_BYTES` (`1024 * 1024 * 1024`).
///
/// The pin imports the name and uses it as the `check_dir` default. This
/// crate does not link `sesslint.scan`. The integer is that default, not a walk.
pub const DEFAULT_MAX_BYTES: i64 = 1024 * 1024 * 1024;

/// Python `profile: str = "neutral"`.
pub const DEFAULT_PROFILE: &str = "neutral";

/// Python `virtual_path: str = "<stdin>"`.
///
/// Reported verbatim. It is not resolved against the current directory.
pub const DEFAULT_VIRTUAL_PATH: &str = "<stdin>";

/// Next call after the exists check. Not the same function in this crate.
pub const APPLY_RULE_SELECTION_UNAVAILABLE: &str =
    "sesslint.profiles.apply_rule_selection is not available";

/// Next call after the `check_dir` threshold screen. `sesslint.scan` is not linked.
pub const SCAN_PATH_UNAVAILABLE: &str = "sesslint.scan.scan_path is not available";

/// Next import inside [`repair`], after the source, emit, and plan checks.
///
/// `sesslint.adapters.detect.detect_format` is not linked. `FORMAT_CANONICAL`
/// is the other name in that import and is not used.
pub const DETECT_FORMAT_UNAVAILABLE: &str =
    "sesslint.adapters.detect.detect_format is not available";

/// `sesslint.verify.verify` is not linked. [`verify`] returns this immediately.
pub const VERIFY_UNAVAILABLE: &str = "sesslint.verify.verify is not available";

/// `sesslint.repair.load_plan` is not linked. [`apply_plan`] returns this
/// before `resolve_effective_config`, `RepairRefused`, or [`repair`].
pub const LOAD_PLAN_UNAVAILABLE: &str = "sesslint.repair.load_plan is not available";

/// `sesslint.preview.repair_preview` is not linked. [`repair_preview`] returns
/// this immediately.
pub const REPAIR_PREVIEW_UNAVAILABLE: &str = "sesslint.preview.repair_preview is not available";

/// `sesslint.batch.repair_many` is not linked. [`repair_many`] returns this
/// immediately.
pub const REPAIR_MANY_UNAVAILABLE: &str = "sesslint.batch.repair_many is not available";

/// Marker that the pin's in-memory `plan` argument is not `None`.
///
/// This is not a `RepairPlan`. [`repair`] only tests whether the [`Option`] is
/// `Some`. The marker is not read, and `plan_path` is not parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InMemoryPlan;

/// Python `_capture_events`. Not invoked by this slice.
type CaptureEvents<'a> = &'a dyn Fn(&str, &[SessionEvent]);

/// Failure from [`check_file`], [`check_bytes`], [`check_dir`], [`_check_impl`],
/// [`repair`], [`verify`], [`plan`], [`plan_repair`], [`apply_plan`],
/// [`repair_preview`], [`repair_many`], and [`check`].
///
/// [`validate_session`] returns [`ValidateSessionError`] instead.
///
/// [`Self::Value`] is a `ValueError` from `max_files`, `max_bytes`, a
/// threshold, `emit`, or plan mutual exclusion. [`Self::NotFound`] is
/// `FileNotFoundError`. [`Self::Io`] is an `OSError` from `Path.exists` or
/// `Path.is_file`. [`Self::Unsupported`] is the static seam. Its text does
/// not include a path or payload bytes.
#[derive(Debug)]
pub enum ApiError {
    /// The next call is not the same function as the pin.
    Unsupported(&'static str),
    /// Python `ValueError` from `max_files`, `max_bytes`,
    /// `validate_detection_thresholds`, `emit`, or plan mutual exclusion.
    Value(String),
    /// Python `FileNotFoundError`.
    ///
    /// [`check_file`] and [`check`] use `Path not found: {path}`. [`repair`] uses
    /// `Source file not found: {path}`.
    NotFound(String),
    /// `Path.exists` or `Path.is_file` failed with an error other than absence.
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

/// Failure from [`validate_session`].
///
/// [`Self::NotFound`] is `FileNotFoundError` (`Session file not found: {path}`).
/// [`Self::Io`] is an `OSError` from `Path.exists` other than absence.
/// [`Self::Schema`] is the [`SchemaError`] from [`load_session_file`], unchanged.
#[derive(Debug)]
pub enum ValidateSessionError {
    /// Python `FileNotFoundError` for a path [`path_exists`] reports as absent.
    NotFound(String),
    /// `Path.exists` failed with an error other than absence.
    Io(io::Error),
    /// [`load_session_file`] failed. The value is that error.
    Schema(SchemaError),
}

impl ValidateSessionError {
    /// The loader error, when this is [`Self::Schema`].
    #[must_use]
    pub const fn schema(&self) -> Option<&SchemaError> {
        match self {
            Self::Schema(error) => Some(error),
            Self::NotFound(_) | Self::Io(_) => None,
        }
    }
}

impl PartialEq for ValidateSessionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NotFound(left), Self::NotFound(right)) => left == right,
            (Self::Schema(left), Self::Schema(right)) => left == right,
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            _ => false,
        }
    }
}

impl fmt::Display for ValidateSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message) => formatter.write_str(message),
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Schema(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for ValidateSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::NotFound(_) | Self::Schema(_) => None,
        }
    }
}

impl From<io::Error> for ValidateSessionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<SchemaError> for ValidateSessionError {
    fn from(error: SchemaError) -> Self {
        Self::Schema(error)
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

/// `Path.is_file` after `Path(source_path)`.
///
/// An empty path is `.`, matching `Path("")`. A missing path is `Ok(false)`.
/// A directory is `Ok(false)`. `fs::metadata` follows symlinks, as `stat`
/// does. Any other metadata error is returned and is not turned into
/// `FileNotFoundError`. The file is not opened.
fn path_is_file(path: &Path) -> io::Result<bool> {
    let probed = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::metadata(probed) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if is_missing(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// `Path.is_dir` after `Path(path)`.
///
/// An empty path is `.`, matching `Path("")`. A missing path is `Ok(false)`,
/// matching `pathlib.Path.is_dir`. `fs::metadata` follows symlinks, as `stat`
/// does. Any other metadata error is returned. The path is not opened.
fn path_is_dir(path: &Path) -> io::Result<bool> {
    let probed = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::metadata(probed) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if is_missing(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Python `FileNotFoundError(f"Source file not found: {src}")`.
fn source_file_not_found(path: &Path) -> ApiError {
    let shown = crate::bundle::path_text(path);
    ApiError::NotFound(format!("Source file not found: {shown}"))
}

/// Pin `emit not in ("auto", "canonical", "vendor")`.
fn emit_is_allowed(emit: &str) -> bool {
    matches!(emit, "auto" | "canonical" | "vendor")
}

/// Python `repr` of the supplied emit text, with single quotes.
///
/// `bad` is `'bad'`. Backslash, apostrophe, and the line breaks Python spells
/// as `\\`, `\'`, `\n`, `\r`, and `\t` are escaped. Python may switch to
/// double quotes when the text contains `'` and no `"`; this slice keeps
/// single quotes.
fn python_str_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('\'');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

fn emit_value_error(emit: &str) -> ApiError {
    ApiError::Value(format!(
        "emit must be 'auto', 'canonical', or 'vendor', got {}",
        python_str_repr(emit)
    ))
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

/// `max_files` and `max_bytes` must be a positive `int` (pin lines 580–583).
///
/// Python rejects `bool` before `int` because `bool` is a subclass of `int`.
/// `True` renders as `True` and `False` as `False`, not as `1` or `0`. An
/// `i64` cannot receive a `bool`, so those sentences are not produced. `0`
/// and every negative value render with decimal `str(int)`. `1` is the
/// smallest positive value and is accepted.
fn screen_positive_count(name: &str, value: i64) -> Result<(), ApiError> {
    if value <= 0 {
        return Err(ApiError::Value(format!(
            "{name} must be a positive integer (> 0), got {value}"
        )));
    }
    Ok(())
}

/// Scan a directory tree and stop before `scan_path`.
///
/// Python `check_dir` lines 519–612. Argument order matches the pin. Rust
/// has no keyword defaults. Pass `true`, `false`, [`DEFAULT_MAX_FILES`],
/// [`DEFAULT_MAX_BYTES`], `None`, [`DEFAULT_PROFILE`], `None`, `None`,
/// `None`, `None`, `false`, `None`, `None`, `None`, `None`, `None`, `1`,
/// `false`, `None`, [`DEFAULT_MAX_FILE_BYTES`], `None`, `None`, `None`,
/// `None`, and `20` for those Python defaults.
///
/// `max_files` is screened, then `max_bytes`, then [`screen_thresholds`].
/// The next call is `scan_path`, which this crate does not link. The result
/// is [`ApiError::Unsupported`] ([`SCAN_PATH_UNAVAILABLE`]).
///
/// The other arguments are bound and are not applied. This function does not
/// stat `path`, walk a directory, read a file, call `progress_cb`, check
/// `cancel_token`, copy `baseline`, or build a report.
///
/// # Errors
///
/// [`ApiError::Value`] when `max_files`, `max_bytes`, or a threshold is
/// rejected. [`ApiError::Unsupported`] when those checks pass. Success is
/// [`Infallible`].
#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "pinned keyword list, in that order"
)]
pub fn check_dir(
    path: impl AsRef<Path>,
    recursive: bool,
    follow_symlinks: bool,
    max_files: i64,
    max_bytes: i64,
    format: Option<&str>,
    profile: &str,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
    skip_undetected: bool,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
    baseline: Option<&[&str]>,
    exclude: Option<&[&str]>,
    ext: Option<&[&str]>,
    jobs: i64,
    incremental: bool,
    cache_dir: Option<&Path>,
    max_file_bytes: i64,
    timestamp_skew_ms: Option<i64>,
    vendor_layout: Option<&str>,
    newest: Option<i64>,
    since: Option<&str>,
    max_findings_per_code: i64,
) -> Result<Infallible, ApiError> {
    screen_positive_count("max_files", max_files)?;
    screen_positive_count("max_bytes", max_bytes)?;
    screen_thresholds(confidence_min, margin_min)?;
    // Pin line 585. These are the values `scan_path` would read. They are
    // not applied. `progress_cb` is not called.
    let path = path.as_ref();
    let _pending = (
        path,
        recursive,
        follow_symlinks,
        max_files,
        max_bytes,
        format,
        profile,
        progress_cb,
        cancel_token,
        skip_undetected,
        select,
        ignore,
        baseline,
        exclude,
        ext,
        jobs,
        incremental,
        cache_dir,
        max_file_bytes,
        timestamp_skew_ms,
        vendor_layout,
        newest,
        since,
        max_findings_per_code,
    );
    Err(ApiError::Unsupported(SCAN_PATH_UNAVAILABLE))
}

/// Plan and execute a repair, then stop before `detect_format`.
///
/// Python `repair` lines 615–865. Argument order matches the pin. Rust has no
/// keyword defaults. Pass `None`, `"conservative"`, `None`, [`DEFAULT_PROFILE`],
/// `None`, `None`, `false`, `false`, `"auto"`, `None`, and `None` for those
/// Python defaults.
///
/// `source_path` is checked with [`path_is_file`] first. A missing path or a
/// directory is [`ApiError::NotFound`] (`Source file not found: {shown}`).
/// The empty path is `.`. Another metadata error is [`ApiError::Io`]. The
/// file is not opened. `emit` is then one of `auto`, `canonical`, or `vendor`.
/// An in-memory [`InMemoryPlan`] together with `plan_path` is
/// [`ApiError::Value`] (`plan and plan_path are mutually exclusive`). The
/// marker is not a `RepairPlan` and `plan_path` is not parsed. Policy is not
/// validated.
///
/// The next pin statement imports `detect_format`. This crate does not link
/// it. The result is [`ApiError::Unsupported`]
/// ([`DETECT_FORMAT_UNAVAILABLE`]). The other arguments are bound and are not
/// applied. This function does not detect a format, import write-back, raise
/// `VendorRepairRefused`, write `output_path`, call `progress_cb`, or build a
/// plan or a manifest.
///
/// # Errors
///
/// [`ApiError::NotFound`] when the source is missing or a directory.
/// [`ApiError::Io`] when stating the source fails for another reason.
/// [`ApiError::Value`] when `emit` is rejected or both plan inputs are set.
/// [`ApiError::Unsupported`] when those checks pass. Success is [`Infallible`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn repair(
    source_path: impl AsRef<Path>,
    output_path: Option<&Path>,
    policy: &str,
    format: Option<&str>,
    profile: &str,
    plan_path: Option<&Path>,
    plan: Option<InMemoryPlan>,
    dry_run: bool,
    acknowledge_side_effects: bool,
    emit: &str,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
) -> Result<Infallible, ApiError> {
    let source_path = source_path.as_ref();
    if !path_is_file(source_path)? {
        return Err(source_file_not_found(source_path));
    }
    if !emit_is_allowed(emit) {
        return Err(emit_value_error(emit));
    }
    if plan.is_some() && plan_path.is_some() {
        return Err(ApiError::Value(
            "plan and plan_path are mutually exclusive".to_owned(),
        ));
    }
    // Pin: `from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format`.
    // These are the values later steps would read. They are not applied.
    // `progress_cb` is not called. `output_path` is not created.
    let _pending = (
        source_path,
        output_path,
        policy,
        format,
        profile,
        plan_path,
        plan,
        dry_run,
        acknowledge_side_effects,
        emit,
        progress_cb,
        cancel_token,
    );
    Err(ApiError::Unsupported(DETECT_FORMAT_UNAVAILABLE))
}

/// Verify a repaired session, then stop before `sesslint.verify.verify`.
///
/// Python `verify` lines 868–899. Argument order matches the pin. Rust has no
/// keyword defaults. Pass `None` and `false` for `plan_path` and
/// `acknowledge_side_effects`.
///
/// The pin has no local check. It resolves `sesslint.verify.verify` through
/// `sys.modules` and calls it. This crate does not link that function. The
/// result is [`ApiError::Unsupported`] ([`VERIFY_UNAVAILABLE`]). The arguments
/// are bound and are not applied. This function does not stat or read
/// `source_path`, `output_path`, or `manifest_path`, and it does not build a
/// `VerifyVerdict`.
///
/// # Errors
///
/// [`ApiError::Unsupported`]. Success is [`Infallible`].
pub fn verify(
    source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    plan_path: Option<&Path>,
    acknowledge_side_effects: bool,
) -> Result<Infallible, ApiError> {
    let source_path = source_path.as_ref();
    let output_path = output_path.as_ref();
    let manifest_path = manifest_path.as_ref();
    // The pin calls `verify_fn(...)` with these arguments. They are not applied.
    let _pending = (
        source_path,
        output_path,
        manifest_path,
        plan_path,
        acknowledge_side_effects,
    );
    Err(ApiError::Unsupported(VERIFY_UNAVAILABLE))
}

/// Compute a dry-run repair plan, then stop where [`repair`] stops.
///
/// Python `plan` lines 902–931. Argument order matches the pin. Rust has no
/// keyword defaults. Pass `"conservative"`, `None`, [`DEFAULT_PROFILE`], and
/// `false` for those Python defaults.
///
/// The body calls [`repair`] with `output_path=None`, the supplied policy,
/// format, profile, and `acknowledge_side_effects`, and `dry_run=True`.
/// `plan_path` and `plan` are `None`. `emit` is `"auto"`. No progress callback
/// or cancel token is forwarded. No `RepairPlan` is built.
///
/// # Errors
///
/// The [`repair`] error. A missing source or a directory is
/// [`ApiError::NotFound`] (`Source file not found`). A file source is
/// [`ApiError::Unsupported`] ([`DETECT_FORMAT_UNAVAILABLE`]). Success is
/// [`Infallible`].
pub fn plan(
    source_path: impl AsRef<Path>,
    policy: &str,
    format: Option<&str>,
    profile: &str,
    acknowledge_side_effects: bool,
) -> Result<Infallible, ApiError> {
    repair(
        source_path,
        None,
        policy,
        format,
        profile,
        None,
        None,
        true,
        acknowledge_side_effects,
        "auto",
        None,
        None,
    )
}

/// Compute a repair plan without writing files, by calling [`plan`].
///
/// Python `plan_repair` lines 948–954. Argument order matches the pin. The
/// body is that call. It does not add a stop in front of it, and it does not
/// build a `RepairPlan`.
///
/// # Errors
///
/// The [`plan`] error. Success is [`Infallible`].
pub fn plan_repair(
    source_path: impl AsRef<Path>,
    policy: &str,
    format: Option<&str>,
    profile: &str,
    acknowledge_side_effects: bool,
) -> Result<Infallible, ApiError> {
    plan(
        source_path,
        policy,
        format,
        profile,
        acknowledge_side_effects,
    )
}

/// Execute a previously exported repair plan, then stop before `load_plan`.
///
/// Python `apply_plan` lines 998–1025. Argument order matches the pin. Rust
/// has no keyword defaults. Pass `None`, `None`, `false`, `"auto"`, `false`,
/// `None`, and `None` for those Python defaults.
///
/// This crate has no `RepairPlan`. `plan_doc` is not inspected, and
/// [`InMemoryPlan`] is not treated as one. The other branch is
/// `sesslint.repair.load_plan`, which is not linked. The result is
/// [`ApiError::Unsupported`] ([`LOAD_PLAN_UNAVAILABLE`]) before
/// `resolve_effective_config`, `RepairRefused`, or [`repair`].
///
/// The arguments are bound and are not applied. This function does not stat
/// or read `source_path`, `plan_doc`, or `output_path`, and it does not create
/// `output_path`.
///
/// # Errors
///
/// [`ApiError::Unsupported`]. Success is [`Infallible`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn apply_plan<T: ?Sized>(
    source_path: impl AsRef<Path>,
    plan_doc: &T,
    output_path: Option<&Path>,
    format: Option<&str>,
    acknowledge_side_effects: bool,
    emit: &str,
    dry_run: bool,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
) -> Result<Infallible, ApiError> {
    let source_path = source_path.as_ref();
    // Pin lines 998–1001. There is no RepairPlan arm. Lines 1004–1025, including
    // `resolve_effective_config` and `repair`, are not evaluated.
    let _pending = (
        source_path,
        plan_doc,
        output_path,
        format,
        acknowledge_side_effects,
        emit,
        dry_run,
        progress_cb,
        cancel_token,
    );
    Err(ApiError::Unsupported(LOAD_PLAN_UNAVAILABLE))
}

/// Structural repair preview, then stop at the preview import.
///
/// Python `repair_preview` lines 1043–1051. Argument order matches the pin.
/// Rust has no keyword defaults. Pass `None`, `"conservative"`,
/// [`DEFAULT_PROFILE`], and `false` for those Python defaults.
///
/// The pin starts with `from sesslint.preview import repair_preview`. That
/// function is not linked. The result is [`ApiError::Unsupported`]
/// ([`REPAIR_PREVIEW_UNAVAILABLE`]). The arguments are bound and are not
/// applied. This function does not stat `source_path` and does not build a
/// preview document.
///
/// # Errors
///
/// [`ApiError::Unsupported`]. Success is [`Infallible`].
pub fn repair_preview(
    source_path: impl AsRef<Path>,
    format: Option<&str>,
    policy: &str,
    profile: &str,
    acknowledge_side_effects: bool,
) -> Result<Infallible, ApiError> {
    let source_path = source_path.as_ref();
    let _pending = (
        source_path,
        format,
        policy,
        profile,
        acknowledge_side_effects,
    );
    Err(ApiError::Unsupported(REPAIR_PREVIEW_UNAVAILABLE))
}

/// Repair every eligible file, then stop at the batch import.
///
/// Python `repair_many` lines 1077–1092. Argument order matches the pin. Rust
/// has no keyword defaults. Pass `None`, `None`, `"conservative"`, `None`,
/// [`DEFAULT_PROFILE`], `false`, `"auto"`, `false`, `None`, and `None` for
/// those Python defaults.
///
/// The pin starts with `from sesslint.batch import repair_many`. That function
/// is not linked. The result is [`ApiError::Unsupported`]
/// ([`REPAIR_MANY_UNAVAILABLE`]). The arguments are bound and are not applied.
/// This function does not sort `files`, stat a path, create `output_dir`, or
/// build a batch report.
///
/// # Errors
///
/// [`ApiError::Unsupported`]. Success is [`Infallible`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn repair_many(
    files: &[&Path],
    output_dir: impl AsRef<Path>,
    manifest_dir: Option<&Path>,
    common_root: Option<&Path>,
    policy: &str,
    format: Option<&str>,
    profile: &str,
    acknowledge_side_effects: bool,
    emit: &str,
    dry_run: bool,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
) -> Result<Infallible, ApiError> {
    let output_dir = output_dir.as_ref();
    let _pending = (
        files,
        output_dir,
        manifest_dir,
        common_root,
        policy,
        format,
        profile,
        acknowledge_side_effects,
        emit,
        dry_run,
        progress_cb,
        cancel_token,
    );
    Err(ApiError::Unsupported(REPAIR_MANY_UNAVAILABLE))
}

/// Unified check dispatcher, then stop where [`check_dir`] or [`check_file`] stops.
///
/// Python `check` lines 1145–1183. Argument order matches the pin. Rust has no
/// keyword defaults. Pass `None`, [`DEFAULT_PROFILE`], `true`, `false`,
/// [`DEFAULT_MAX_FILES`], [`DEFAULT_MAX_BYTES`], [`DEFAULT_MAX_FILE_BYTES`],
/// and `None` for the remaining options.
///
/// The path is stated with [`path_exists`]. Absence is [`ApiError::NotFound`]
/// (`Path not found: {shown}`), using [`crate::bundle::path_text`]. The empty
/// path is `.` and exists. Any other metadata error is [`ApiError::Io`]. A
/// directory calls [`check_dir`] with these arguments and the pin defaults
/// `check` does not override: `skip_undetected=False`, `jobs=1`,
/// `incremental=False`, `cache_dir=None`, `vendor_layout=None`, `newest=None`,
/// `since=None`, and `max_findings_per_code=20`. A file calls [`check_file`].
/// No `Report` or `ScanReport` is built.
///
/// # Errors
///
/// [`ApiError::NotFound`] when the path is absent. [`ApiError::Io`] when
/// stating it fails for another reason. [`ApiError::Value`] when the callee
/// rejects a limit or a threshold. [`ApiError::Unsupported`] when a directory
/// reaches [`SCAN_PATH_UNAVAILABLE`] or a file reaches
/// [`APPLY_RULE_SELECTION_UNAVAILABLE`]. Success is [`Infallible`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn check(
    path: impl AsRef<Path>,
    format: Option<&str>,
    profile: &str,
    recursive: bool,
    follow_symlinks: bool,
    max_files: i64,
    max_bytes: i64,
    max_file_bytes: i64,
    timestamp_skew_ms: Option<i64>,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
    progress_cb: Option<&dyn Fn(&ProgressEvent)>,
    cancel_token: Option<&CancellationToken>,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
    baseline: Option<&[&str]>,
    exclude: Option<&[&str]>,
    ext: Option<&[&str]>,
) -> Result<Infallible, ApiError> {
    let target_path = path.as_ref();
    if !path_exists(target_path)? {
        return Err(path_not_found(target_path));
    }
    if path_is_dir(target_path)? {
        return check_dir(
            target_path,
            recursive,
            follow_symlinks,
            max_files,
            max_bytes,
            format,
            profile,
            confidence_min,
            margin_min,
            progress_cb,
            cancel_token,
            false,
            select,
            ignore,
            baseline,
            exclude,
            ext,
            1,
            false,
            None,
            max_file_bytes,
            timestamp_skew_ms,
            None,
            None,
            None,
            20,
        );
    }
    check_file(
        target_path,
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
    )
}

/// Python `FileNotFoundError(f"Session file not found: {target}")`.
fn session_file_not_found(path: &Path) -> ValidateSessionError {
    let shown = crate::bundle::path_text(path);
    ValidateSessionError::NotFound(format!("Session file not found: {shown}"))
}

/// Validate a canonical session file.
///
/// Python `validate_session` lines 1199–1202. Absence is
/// [`ValidateSessionError::NotFound`] (`Session file not found: {shown}`),
/// using [`crate::bundle::path_text`]. The empty path is `.` and exists, so
/// it is not that error. Any other metadata error is
/// [`ValidateSessionError::Io`]. The loader is not called for absence, so its
/// `path.display()` text does not replace this message.
///
/// An existing path calls [`load_session_file`]. A [`SchemaError`] from that
/// call is returned unchanged. This function does not parse JSON.
///
/// # Errors
///
/// [`ValidateSessionError::NotFound`] when the path is absent.
/// [`ValidateSessionError::Io`] when `exists` fails for another reason.
/// [`ValidateSessionError::Schema`] when the loader rejects the path.
pub fn validate_session(path: impl AsRef<Path>) -> Result<Session, ValidateSessionError> {
    let target = path.as_ref();
    if !path_exists(target)? {
        return Err(session_file_not_found(target));
    }
    load_session_file(target).map_err(ValidateSessionError::Schema)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use model::canonical::SessionEvent;
    use report::progress::{CancellationToken, OperationCancelled, ProgressEvent};

    use super::{
        _check_impl, apply_plan, bound_max_file_bytes, check, check_bytes, check_dir, check_file,
        display_path, is_missing, load_session_file, path_exists, plan, plan_repair,
        python_float_text, python_str_repr, repair, repair_many, repair_preview, validate_session,
        verify, ApiError, InMemoryPlan, ValidateSessionError, APPLY_RULE_SELECTION_UNAVAILABLE,
        DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES, DEFAULT_PROFILE,
        DEFAULT_VIRTUAL_PATH, DETECT_FORMAT_UNAVAILABLE, LOAD_PLAN_UNAVAILABLE,
        REPAIR_MANY_UNAVAILABLE, REPAIR_PREVIEW_UNAVAILABLE, SCAN_PATH_UNAVAILABLE,
        VERIFY_UNAVAILABLE,
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

    fn missing_dir() -> &'static Path {
        Path::new("synthetic/sesslint-rx-cli-api-03-missing")
    }

    fn require_scan_stop(error: &ApiError) {
        assert_eq!(error, &ApiError::Unsupported(SCAN_PATH_UNAVAILABLE));
        assert_eq!(error.unsupported_message(), Some(SCAN_PATH_UNAVAILABLE));
        assert_eq!(
            error.to_string(),
            "sesslint.scan.scan_path is not available"
        );
        assert!(Error::source(error).is_none());
        let text = error.to_string();
        for absent in [
            "Path not found",
            "max_files must be a positive integer",
            "max_bytes must be a positive integer",
            "apply_rule_selection",
            "confidence_min",
            "margin_min",
            "SL001",
            "finding",
            "synthetic",
            "Cargo",
            "not-a-format",
            "not-a-profile",
            "not-a-layout",
            "not-a-date",
            "fp-",
            ".secret",
            ".jsonl",
            "\n",
            "\r",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
    }

    fn dir_limits(
        max_files: i64,
        max_bytes: i64,
        confidence_min: Option<f64>,
        margin_min: Option<f64>,
    ) -> ApiError {
        match check_dir(
            missing_dir(),
            true,
            false,
            max_files,
            max_bytes,
            None,
            DEFAULT_PROFILE,
            confidence_min,
            margin_min,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            1,
            false,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
            None,
            None,
            None,
            20,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    #[test]
    fn directory_limit_defaults_match_the_pin() {
        assert_eq!(DEFAULT_MAX_FILES, 10000);
        assert_eq!(DEFAULT_MAX_BYTES, 1024 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_BYTES, 1_073_741_824);
        assert_eq!(
            SCAN_PATH_UNAVAILABLE,
            "sesslint.scan.scan_path is not available"
        );
    }

    #[test]
    fn max_files_rejects_zero_and_negative_with_pin_rendering() {
        // A bool cannot be passed. `got True` and `got False` are not expressible.
        let cases = [
            (0, "max_files must be a positive integer (> 0), got 0"),
            (-1, "max_files must be a positive integer (> 0), got -1"),
            (-500, "max_files must be a positive integer (> 0), got -500"),
            (
                i64::MIN,
                "max_files must be a positive integer (> 0), got -9223372036854775808",
            ),
        ];
        for (value, expected) in cases {
            let error = dir_limits(value, 0, Some(f64::NAN), Some(1.0));
            require_value(&error, expected);
            assert!(!error.to_string().contains("max_bytes"));
            assert!(!error.to_string().contains("confidence_min"));
            assert!(!error.to_string().contains("scan_path"));
            assert!(!error.to_string().contains("synthetic"));
            assert!(!error.to_string().contains("True"));
            assert!(!error.to_string().contains("False"));
        }
    }

    #[test]
    fn max_bytes_is_screened_after_the_positive_boundary() {
        // `1` is the smallest positive `i64` and passes the `max_files` check.
        let cases = [
            (0, "max_bytes must be a positive integer (> 0), got 0"),
            (-1, "max_bytes must be a positive integer (> 0), got -1"),
            (-500, "max_bytes must be a positive integer (> 0), got -500"),
            (
                i64::MIN,
                "max_bytes must be a positive integer (> 0), got -9223372036854775808",
            ),
        ];
        for (value, expected) in cases {
            let error = dir_limits(1, value, Some(0.0), None);
            require_value(&error, expected);
            assert!(!error.to_string().contains("max_files"));
            assert!(!error.to_string().contains("confidence_min"));
            assert!(!error.to_string().contains("scan_path"));
            assert!(!error.to_string().contains("True"));
            assert!(!error.to_string().contains("False"));
        }
        require_value(
            &dir_limits(i64::MAX, -4, None, None),
            "max_bytes must be a positive integer (> 0), got -4",
        );
    }

    #[test]
    fn omitted_thresholds_stop_at_scan_path() {
        let missing = missing_dir();
        assert!(!missing.exists());
        require_scan_stop(&dir_limits(1, 1, None, None));
        require_scan_stop(&dir_limits(
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_BYTES,
            None,
            None,
        ));
        require_scan_stop(&dir_limits(i64::MAX, i64::MAX, None, None));
    }

    #[test]
    fn invalid_threshold_fails_before_the_scan_stop() {
        let error = dir_limits(1, DEFAULT_MAX_BYTES, Some(0.0), None);
        require_value(
            &error,
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 0.0",
        );
        assert_ne!(error.to_string(), SCAN_PATH_UNAVAILABLE);
        let margin = dir_limits(DEFAULT_MAX_FILES, 1, Some(0.2), Some(0.3));
        require_value(
            &margin,
            "margin_min (0.3) cannot exceed confidence_min (0.2)",
        );
        assert!(!margin.to_string().contains("scan_path"));
        assert!(!margin.to_string().contains("synthetic"));
    }

    #[test]
    fn valid_directory_call_stops_at_scan_path() {
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let select = ["SL001"];
        let ignore = ["SL101"];
        let baseline = ["fp-a"];
        let exclude = ["*.secret"];
        let ext = [".jsonl"];
        let cache = Path::new("synthetic/sesslint-rx-cli-api-03-cache");
        let missing = missing_dir();
        assert!(!missing.exists());
        let error = match check_dir(
            missing,
            false,
            true,
            1,
            1,
            Some("not-a-format"),
            "not-a-profile",
            Some(0.5),
            Some(0.4),
            Some(&progress),
            Some(&token),
            true,
            Some(&select),
            Some(&ignore),
            Some(&baseline),
            Some(&exclude),
            Some(&ext),
            0,
            true,
            Some(cache),
            0,
            Some(-1),
            Some("not-a-layout"),
            Some(0),
            Some("not-a-date"),
            0,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_scan_stop(&error);
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        let from_defaults = dir_limits(DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES, Some(0.5), Some(0.5));
        assert_eq!(error, from_defaults);
        let from_dot = match check_dir(
            Path::new("."),
            true,
            false,
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_BYTES,
            None,
            DEFAULT_PROFILE,
            None,
            None,
            Some(&progress),
            Some(&token),
            false,
            None,
            None,
            None,
            None,
            None,
            1,
            false,
            None,
            DEFAULT_MAX_FILE_BYTES,
            None,
            None,
            None,
            None,
            20,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(from_dot, from_defaults);
        require_scan_stop(&from_dot);
        assert!(!called.load(Ordering::Relaxed));
        assert!(Path::new(".").is_dir());
    }

    fn source_file() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
    }

    fn source_dir() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    fn absent_output() -> &'static Path {
        Path::new("synthetic/sesslint-rx-cli-api-04-output.json")
    }

    fn absent_plan() -> &'static Path {
        Path::new("synthetic/sesslint-rx-cli-api-04-plan.json")
    }

    fn repair_err(
        source: &Path,
        emit: &str,
        plan_path: Option<&Path>,
        plan: Option<InMemoryPlan>,
        progress: Option<&dyn Fn(&ProgressEvent)>,
        token: Option<&CancellationToken>,
    ) -> ApiError {
        match repair(
            source,
            Some(absent_output()),
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            plan_path,
            plan,
            false,
            true,
            emit,
            progress,
            token,
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn require_source_missing(error: &ApiError, path: &Path) {
        let expected = format!("Source file not found: {}", path_text(path));
        assert_eq!(error.to_string(), expected);
        assert_eq!(error, &ApiError::NotFound(expected));
        assert!(error.unsupported_message().is_none());
        assert!(Error::source(error).is_none());
        let text = error.to_string();
        assert!(text.starts_with("Source file not found: "));
        assert!(!text.contains("emit must"));
        assert!(!text.contains("mutually exclusive"));
        assert!(!text.contains("detect_format"));
        assert!(!text.contains("not-a-policy"));
        assert!(!text.contains("not-a-format"));
        assert!(!text.contains("not-a-profile"));
        assert!(!text.contains("VendorRepairRefused"));
        assert!(!text.contains("writeback"));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\n'));
    }

    fn require_detect_stop(error: &ApiError) {
        assert_eq!(error, &ApiError::Unsupported(DETECT_FORMAT_UNAVAILABLE));
        assert_eq!(error.unsupported_message(), Some(DETECT_FORMAT_UNAVAILABLE));
        assert_eq!(
            error.to_string(),
            "sesslint.adapters.detect.detect_format is not available"
        );
        assert!(Error::source(error).is_none());
        let text = error.to_string();
        for absent in [
            "Source file not found",
            "emit must",
            "mutually exclusive",
            "not-a-policy",
            "not-a-format",
            "not-a-profile",
            "VendorRepairRefused",
            "writeback",
            "RepairPlan",
            "RepairManifest",
            "package",
            "Cargo",
            "synthetic",
            "\n",
            "\r",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
    }

    #[test]
    fn missing_source_is_rejected_before_emit_is_considered() {
        let missing = Path::new("synthetic/sesslint-rx-cli-api-04-missing.json");
        assert!(!missing.exists());
        assert!(!absent_output().exists());
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let error = repair_err(
            missing,
            "bad",
            Some(absent_plan()),
            Some(InMemoryPlan),
            Some(&progress),
            Some(&token),
        );
        require_source_missing(&error, missing);
        assert_ne!(
            error.to_string(),
            "emit must be 'auto', 'canonical', or 'vendor', got 'bad'"
        );
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        assert!(!absent_output().exists());
        assert!(!absent_plan().exists());
        assert!(!Path::new("synthetic").exists());
    }

    #[test]
    fn directory_source_is_source_file_not_found() {
        let dir = source_dir();
        assert!(dir.is_dir());
        assert!(!dir.is_file());
        let error = repair_err(dir, "bad", None, None, None, None);
        require_source_missing(&error, dir);
        assert!(error.to_string().contains(path_text(dir).as_str()));

        assert!(Path::new(".").is_dir());
        let dotted = repair_err(Path::new("."), "auto", None, None, None, None);
        require_source_missing(&dotted, Path::new("."));
        assert_eq!(dotted.to_string(), "Source file not found: .");

        let empty = repair_err(
            Path::new(""),
            "vendor",
            Some(absent_plan()),
            None,
            None,
            None,
        );
        require_source_missing(&empty, Path::new(""));
        assert_eq!(empty.to_string(), "Source file not found: .");
        assert!(!absent_output().exists());
    }

    #[test]
    fn emit_repr_uses_single_quotes() {
        assert_eq!(python_str_repr("bad"), "'bad'");
        let source = source_file();
        assert!(source.is_file());
        let error = repair_err(source, "bad", None, None, None, None);
        let expected = "emit must be 'auto', 'canonical', or 'vendor', got 'bad'";
        assert_eq!(error.to_string(), expected);
        assert_eq!(error, ApiError::Value(expected.to_owned()));
        assert!(error.unsupported_message().is_none());
        assert!(Error::source(&error).is_none());
        assert!(error.to_string().contains("'bad'"));
        assert!(!error.to_string().contains("\"bad\""));
        assert!(!error.to_string().contains("detect_format"));
        assert!(!error.to_string().contains("mutually exclusive"));
        assert!(!error.to_string().contains("Cargo"));
        assert!(!error.to_string().contains("package"));
        assert!(!error.to_string().contains('\r'));

        let both = repair_err(
            source,
            "bad",
            Some(absent_plan()),
            Some(InMemoryPlan),
            None,
            None,
        );
        assert_eq!(both.to_string(), expected);
        assert!(!both.to_string().contains("mutually exclusive"));

        for rejected in ["", "Auto", "AUTO", "canonical ", " vendor", "json"] {
            let rejected_error = repair_err(source, rejected, None, None, None, None);
            let rendered = format!(
                "emit must be 'auto', 'canonical', or 'vendor', got {}",
                python_str_repr(rejected)
            );
            assert_eq!(rejected_error.to_string(), rendered);
            assert!(rendered.contains('\''));
            assert!(!rendered.contains("detect_format"));
        }
        assert!(!absent_output().exists());
    }

    #[test]
    fn plan_and_plan_path_are_exclusive_before_detect_format() {
        let source = source_file();
        assert!(source.is_file());
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let error = repair_err(
            source,
            "auto",
            Some(absent_plan()),
            Some(InMemoryPlan),
            Some(&progress),
            Some(&token),
        );
        let expected = "plan and plan_path are mutually exclusive";
        assert_eq!(error.to_string(), expected);
        assert_eq!(error, ApiError::Value(expected.to_owned()));
        assert!(error.unsupported_message().is_none());
        assert!(Error::source(&error).is_none());
        assert_ne!(error.to_string(), DETECT_FORMAT_UNAVAILABLE);
        assert!(!error.to_string().contains("emit must"));
        assert!(!error.to_string().contains("Source file not found"));
        assert!(!error.to_string().contains("not-a-policy"));
        assert!(!error.to_string().contains("detect_format"));
        assert!(!called.load(Ordering::Relaxed));
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        assert!(!absent_output().exists());
        assert!(!absent_plan().exists());

        for emit in ["canonical", "vendor"] {
            let again = repair_err(
                source,
                emit,
                Some(absent_plan()),
                Some(InMemoryPlan),
                Some(&progress),
                Some(&token),
            );
            assert_eq!(again.to_string(), expected);
        }
        assert!(!called.load(Ordering::Relaxed));
    }

    #[test]
    fn other_metadata_errors_stay_io_before_emit() {
        let path = Path::new("synthetic/\0sesslint-rx-cli-api-04-missing");
        let error = repair_err(
            path,
            "bad",
            Some(absent_plan()),
            Some(InMemoryPlan),
            None,
            None,
        );
        match &error {
            ApiError::Io(io_error) => {
                assert!(!is_missing(io_error));
                assert!(Error::source(&error).is_some());
            }
            ApiError::NotFound(message) => {
                assert!(message.starts_with("Source file not found: "));
            }
            ApiError::Value(_) | ApiError::Unsupported(_) => {
                panic!("metadata failure must precede emit and detect_format");
            }
        }
        assert!(error.unsupported_message().is_none());
        assert!(!error.to_string().contains("emit must"));
        assert!(!error.to_string().contains("detect_format"));
        assert!(!error.to_string().contains("mutually exclusive"));
        assert!(!absent_output().exists());
    }

    #[test]
    fn valid_repair_stops_at_detect_format_without_creating_a_file() {
        let source = source_file();
        assert!(source.is_file());
        let before = fs::metadata(source).expect("source metadata").len();
        assert!(!absent_output().exists());
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let cases = [
            ("auto", None, None),
            ("canonical", Some(absent_plan()), None),
            ("vendor", None, Some(InMemoryPlan)),
        ];
        for (emit, plan_path, plan) in cases {
            let error = repair_err(source, emit, plan_path, plan, Some(&progress), Some(&token));
            require_detect_stop(&error);
            assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        }
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert!(!absent_output().exists());
        assert!(!absent_plan().exists());
        assert!(!Path::new("synthetic").exists());
        let after = fs::metadata(source).expect("source metadata").len();
        assert_eq!(before, after);

        let dry = match repair(
            source,
            None,
            "conservative",
            None,
            DEFAULT_PROFILE,
            None,
            None,
            true,
            false,
            "auto",
            Some(&progress),
            Some(&token),
        ) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        require_detect_stop(&dry);
        assert!(!called.load(Ordering::Relaxed));
        assert!(!absent_output().exists());
    }

    #[test]
    fn verify_stops_before_any_path_read() {
        let source = Path::new("synthetic/\0sesslint-rx-cli-api-04-source");
        let output = Path::new("synthetic/\0sesslint-rx-cli-api-04-output");
        let manifest = Path::new("synthetic/\0sesslint-rx-cli-api-04-manifest");
        let plan = Path::new("synthetic/\0sesslint-rx-cli-api-04-plan.json");
        let nul_error = match verify(source, output, manifest, Some(plan), true) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(nul_error, ApiError::Unsupported(VERIFY_UNAVAILABLE));
        assert_eq!(nul_error.unsupported_message(), Some(VERIFY_UNAVAILABLE));
        assert_eq!(
            nul_error.to_string(),
            "sesslint.verify.verify is not available"
        );
        assert!(Error::source(&nul_error).is_none());
        assert!(!matches!(nul_error, ApiError::Io(_)));
        assert!(!nul_error.to_string().contains("synthetic"));
        assert!(!nul_error.to_string().contains("Source file not found"));
        assert!(!nul_error.to_string().contains('\0'));
        assert!(!nul_error.to_string().contains('\r'));

        let existing = source_file();
        assert!(existing.is_file());
        let from_file = match verify(existing, existing, existing, Some(existing), false) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(from_file, nul_error);
        assert!(!from_file.to_string().contains("package"));
        assert!(!from_file.to_string().contains("Cargo"));

        let missing = Path::new("synthetic/sesslint-rx-cli-api-04-missing.json");
        assert!(!missing.exists());
        let from_missing = match verify(missing, absent_output(), absent_plan(), None, false) {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(from_missing, nul_error);
        assert!(!absent_output().exists());
        assert!(!Path::new("synthetic").exists());
    }

    fn must(result: Result<Infallible, ApiError>) -> ApiError {
        match result {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn repair_as_plan(
        source: &Path,
        policy: &str,
        format: Option<&str>,
        profile: &str,
        acknowledge_side_effects: bool,
    ) -> ApiError {
        must(repair(
            source,
            None,
            policy,
            format,
            profile,
            None,
            None,
            true,
            acknowledge_side_effects,
            "auto",
            None,
            None,
        ))
    }

    fn pinned_check(
        path: &Path,
        max_files: i64,
        max_bytes: i64,
        confidence_min: Option<f64>,
        margin_min: Option<f64>,
    ) -> ApiError {
        must(check(
            path,
            None,
            DEFAULT_PROFILE,
            true,
            false,
            max_files,
            max_bytes,
            DEFAULT_MAX_FILE_BYTES,
            None,
            confidence_min,
            margin_min,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ))
    }

    #[test]
    fn missing_paths_keep_the_pin_messages() {
        let missing = Path::new("synthetic/./sesslint-rx-cli-api-05-missing.json");
        assert!(!missing.exists());
        let planned = must(plan(
            missing,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        ));
        let planned_again = must(plan_repair(
            missing,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        ));
        let from_repair = repair_as_plan(
            missing,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        );
        assert_eq!(planned, from_repair);
        assert_eq!(planned_again, planned);
        require_source_missing(&planned, missing);
        assert!(!planned.to_string().contains("./"));
        assert!(!planned.to_string().contains(".\\"));

        let empty_plan = must(plan(
            Path::new(""),
            "conservative",
            None,
            DEFAULT_PROFILE,
            false,
        ));
        require_source_missing(&empty_plan, Path::new(""));
        assert_eq!(empty_plan.to_string(), "Source file not found: .");
        assert_eq!(
            must(plan_repair(
                Path::new("."),
                "conservative",
                None,
                DEFAULT_PROFILE,
                false,
            ))
            .to_string(),
            "Source file not found: ."
        );

        let checked = pinned_check(missing, 0, 0, Some(f64::NAN), Some(1.0));
        let expected = format!("Path not found: {}", path_text(missing));
        assert_eq!(checked.to_string(), expected);
        assert_eq!(checked, ApiError::NotFound(expected));
        assert!(!checked.to_string().contains("./"));
        assert!(!checked.to_string().contains(".\\"));
        assert!(!checked.to_string().contains("max_files"));
        assert!(!checked.to_string().contains("confidence_min"));
        assert!(!checked.to_string().contains("scan_path"));
        assert!(!checked.to_string().contains("apply_rule_selection"));
        assert!(checked.unsupported_message().is_none());

        let empty_check = pinned_check(
            Path::new(""),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_BYTES,
            None,
            None,
        );
        require_scan_stop(&empty_check);
        assert_ne!(empty_check.to_string(), "Path not found: .");

        let session = validate_session(missing).unwrap_err();
        let session_text = format!("Session file not found: {}", path_text(missing));
        assert_eq!(session.to_string(), session_text);
        assert_eq!(session, ValidateSessionError::NotFound(session_text));
        assert!(session.schema().is_none());
        assert!(Error::source(&session).is_none());
        let loader = load_session_file(missing).unwrap_err();
        assert_ne!(session.to_string(), loader.to_string());
        assert!(loader.to_string().contains("./") || loader.to_string().contains(".\\"));
        assert!(!session.to_string().contains("./"));
        assert!(!session.to_string().contains(".\\"));
        assert!(!session.to_string().contains('\r'));
        assert!(!Path::new("synthetic").exists());
    }

    #[test]
    fn plan_and_plan_repair_reach_the_repair_stop() {
        let source = existing_file();
        assert!(source.is_file());
        let before = fs::metadata(source).expect("source metadata").len();
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let from_plan = must(plan(
            source,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        ));
        let from_plan_repair = must(plan_repair(
            source,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        ));
        let from_repair = repair_as_plan(
            source,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            true,
        );
        assert_eq!(from_plan, from_repair);
        assert_eq!(from_plan_repair, from_plan);
        require_detect_stop(&from_plan);
        assert_ne!(from_plan.to_string(), LOAD_PLAN_UNAVAILABLE);
        let dry = must(repair(
            source,
            None,
            "not-a-policy",
            Some("not-a-format"),
            "not-a-profile",
            None,
            None,
            true,
            true,
            "auto",
            Some(&progress),
            None,
        ));
        assert_eq!(from_plan, dry);
        assert!(!called.load(Ordering::Relaxed));
        assert!(!absent_output().exists());
        assert!(!Path::new("synthetic").exists());
        let after = fs::metadata(source).expect("source metadata").len();
        assert_eq!(before, after);
    }

    #[test]
    fn apply_plan_stops_without_reading_inputs() {
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let marker = br#"{"UNIQUE_PLAN_MARKER":true}"#;
        let output = Path::new("synthetic/sesslint-rx-cli-api-05-output.json");
        let nul_source = Path::new("synthetic/\0sesslint-rx-cli-api-05-source");
        let nul_plan = Path::new("synthetic/\0sesslint-rx-cli-api-05-plan");
        assert!(!output.exists());
        let from_marker = must(apply_plan(
            nul_source,
            marker,
            Some(output),
            Some("not-a-format"),
            true,
            "bad",
            false,
            Some(&progress),
            Some(&token),
        ));
        let from_memory = must(apply_plan(
            existing_file(),
            &InMemoryPlan,
            Some(output),
            Some("not-a-format"),
            false,
            "auto",
            true,
            Some(&progress),
            Some(&token),
        ));
        let from_path = must(apply_plan(
            nul_plan, nul_plan, None, None, false, "vendor", true, None, None,
        ));
        assert_eq!(from_marker, ApiError::Unsupported(LOAD_PLAN_UNAVAILABLE));
        assert_eq!(
            from_marker.unsupported_message(),
            Some(LOAD_PLAN_UNAVAILABLE)
        );
        assert_eq!(
            from_marker.to_string(),
            "sesslint.repair.load_plan is not available"
        );
        assert_eq!(from_memory, from_marker);
        assert_eq!(from_path, from_marker);
        assert!(Error::source(&from_marker).is_none());
        assert!(!matches!(from_marker, ApiError::Io(_)));
        assert_ne!(from_marker.to_string(), DETECT_FORMAT_UNAVAILABLE);
        assert_ne!(from_marker.to_string(), OperationCancelled::MESSAGE);
        let text = from_marker.to_string();
        for absent in [
            "UNIQUE_PLAN_MARKER",
            "not-a-format",
            "emit must",
            "Source file not found",
            "RepairRefused",
            "resolve_effective_config",
            "synthetic",
            "Cargo",
            "package",
            "\0",
            "\n",
            "\r",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert!(!output.exists());
        assert!(!nul_plan.exists());
        assert!(!Path::new("synthetic").exists());
    }

    #[test]
    fn repair_preview_stops_at_the_import() {
        let source = Path::new("synthetic/\0sesslint-rx-cli-api-05-preview");
        let error = must(repair_preview(
            source,
            Some("not-a-format"),
            "UNIQUE_PREVIEW_POLICY",
            "not-a-profile",
            true,
        ));
        assert_eq!(error, ApiError::Unsupported(REPAIR_PREVIEW_UNAVAILABLE));
        assert_eq!(
            error.unsupported_message(),
            Some(REPAIR_PREVIEW_UNAVAILABLE)
        );
        assert_eq!(
            error.to_string(),
            "sesslint.preview.repair_preview is not available"
        );
        assert!(Error::source(&error).is_none());
        assert!(!matches!(error, ApiError::Io(_)));
        assert_ne!(error.to_string(), DETECT_FORMAT_UNAVAILABLE);
        assert_ne!(error.to_string(), "Source file not found: .");
        let text = error.to_string();
        for absent in [
            "UNIQUE_PREVIEW_POLICY",
            "not-a-format",
            "not-a-profile",
            "PreviewDoc",
            "synthetic",
            "\0",
            "\n",
            "\r",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
        let existing = must(repair_preview(
            existing_file(),
            None,
            "conservative",
            DEFAULT_PROFILE,
            false,
        ));
        assert_eq!(existing, error);
        assert!(!existing.to_string().contains("Cargo"));
        assert!(!existing.to_string().contains("package"));
        assert!(!Path::new("synthetic").exists());
    }

    #[test]
    fn repair_many_stops_at_the_import() {
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let later = Path::new("synthetic/\0sesslint-rx-cli-api-05-b.json");
        let earlier = Path::new("synthetic/\0sesslint-rx-cli-api-05-a.json");
        let files = [later, earlier];
        let output = Path::new("synthetic/sesslint-rx-cli-api-05-batch");
        let manifest = Path::new("synthetic/\0sesslint-rx-cli-api-05-manifests");
        let root = Path::new("synthetic/\0sesslint-rx-cli-api-05-root");
        assert!(!output.exists());
        let error = must(repair_many(
            &files,
            output,
            Some(manifest),
            Some(root),
            "UNIQUE_BATCH_POLICY",
            Some("not-a-format"),
            "not-a-profile",
            true,
            "bad",
            false,
            Some(&progress),
            Some(&token),
        ));
        assert_eq!(error, ApiError::Unsupported(REPAIR_MANY_UNAVAILABLE));
        assert_eq!(error.unsupported_message(), Some(REPAIR_MANY_UNAVAILABLE));
        assert_eq!(
            error.to_string(),
            "sesslint.batch.repair_many is not available"
        );
        assert!(Error::source(&error).is_none());
        assert!(!matches!(error, ApiError::Io(_)));
        assert_ne!(error.to_string(), DETECT_FORMAT_UNAVAILABLE);
        assert_ne!(error.to_string(), OperationCancelled::MESSAGE);
        let text = error.to_string();
        for absent in [
            "UNIQUE_BATCH_POLICY",
            "not-a-format",
            "not-a-profile",
            "emit must",
            "sesslint-rx-cli-api-05",
            "BatchRepairReport",
            "synthetic",
            "\0",
            "\n",
            "\r",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert!(!output.exists());
        assert!(!manifest.exists());
        assert!(!Path::new("synthetic").exists());
        let empty: [&Path; 0] = [];
        let from_empty = must(repair_many(
            &empty,
            output,
            None,
            None,
            "conservative",
            None,
            DEFAULT_PROFILE,
            false,
            "auto",
            true,
            None,
            None,
        ));
        assert_eq!(from_empty, error);
        assert!(!output.exists());
    }

    #[test]
    fn directory_check_reaches_scan_path() {
        assert!(Path::new(".").is_dir());
        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let from_defaults = pinned_check(
            Path::new("."),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_BYTES,
            None,
            None,
        );
        let from_dir = dir_limits(DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES, None, None);
        assert_eq!(from_defaults, from_dir);
        require_scan_stop(&from_defaults);
        assert_ne!(
            from_defaults,
            file_at(Path::new("."), None, None, DEFAULT_MAX_FILE_BYTES, None)
        );

        let limits = pinned_check(Path::new("."), 0, 0, Some(f64::NAN), None);
        require_value(&limits, "max_files must be a positive integer (> 0), got 0");
        assert!(!limits.to_string().contains("confidence_min"));
        assert!(!limits.to_string().contains("scan_path"));

        let select = ["SL001"];
        let ignore = ["SL101"];
        let with_markers = must(check(
            Path::new("."),
            Some("not-a-format"),
            "not-a-profile",
            true,
            false,
            1,
            1,
            DEFAULT_MAX_FILE_BYTES,
            Some(-1),
            Some(0.5),
            Some(0.4),
            Some(&progress),
            Some(&token),
            Some(&select),
            Some(&ignore),
            None,
            None,
            None,
        ));
        require_scan_stop(&with_markers);
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert_ne!(with_markers.to_string(), OperationCancelled::MESSAGE);
        assert_eq!(with_markers, from_defaults);
    }

    #[test]
    fn file_check_reaches_apply_rule_selection() {
        let manifest = existing_file();
        assert!(manifest.is_file());
        let from_check = pinned_check(manifest, DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES, None, None);
        let from_file = file_at(manifest, None, None, DEFAULT_MAX_FILE_BYTES, None);
        assert_eq!(from_check, from_file);
        require_stop(&from_check);
        assert_ne!(from_check.to_string(), SCAN_PATH_UNAVAILABLE);
        assert!(!from_check.to_string().contains("Cargo"));
        assert!(!from_check.to_string().contains("package"));

        let ignored_limits = pinned_check(manifest, 0, 0, None, None);
        require_stop(&ignored_limits);
        assert!(!ignored_limits.to_string().contains("max_files"));
        assert!(!ignored_limits.to_string().contains("max_bytes"));

        let screened = pinned_check(manifest, 0, 0, Some(f64::NAN), None);
        require_value(
            &screened,
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got nan",
        );
        assert!(!screened.to_string().contains("max_files"));
        assert!(!screened.to_string().contains("scan_path"));

        let called = AtomicBool::new(false);
        let progress = |_event: &ProgressEvent| {
            called.store(true, Ordering::Relaxed);
        };
        let token = CancellationToken::new();
        token.cancel();
        let select = ["SL001"];
        let ignore = ["SL101"];
        let with_markers = must(check(
            manifest,
            Some("not-a-format"),
            "not-a-profile",
            false,
            true,
            0,
            0,
            0,
            Some(-1),
            Some(0.4),
            Some(0.2),
            Some(&progress),
            Some(&token),
            Some(&select),
            Some(&ignore),
            None,
            None,
            None,
        ));
        require_stop(&with_markers);
        assert!(!with_markers.to_string().contains("not-a-format"));
        assert!(!with_markers.to_string().contains("not-a-profile"));
        assert!(!called.load(Ordering::Relaxed));
        assert!(token.is_cancelled());
        assert_ne!(with_markers.to_string(), OperationCancelled::MESSAGE);
        assert_ne!(with_markers.to_string(), SCAN_PATH_UNAVAILABLE);
    }

    #[test]
    fn existing_validate_session_reaches_the_canonical_loader() {
        let path = existing_file();
        assert!(path.is_file());
        let error = validate_session(path).unwrap_err();
        let loader = load_session_file(path).unwrap_err();
        assert_eq!(error.schema(), Some(&loader));
        assert_eq!(error.to_string(), loader.to_string());
        assert_eq!(loader.code(), "SCHEMA");
        assert!(error
            .to_string()
            .starts_with("Malformed JSON on header line (line 1): "));
        assert!(error.schema().is_some());
        assert!(!matches!(error, ValidateSessionError::NotFound(_)));
        assert!(!matches!(error, ValidateSessionError::Io(_)));
        assert!(!error.to_string().starts_with("Session file not found:"));
        assert!(Error::source(&error).is_none());

        let directory = validate_session(Path::new(".")).unwrap_err();
        let directory_loader = load_session_file(Path::new(".")).unwrap_err();
        assert_eq!(directory.schema(), Some(&directory_loader));
        assert_ne!(
            directory,
            ValidateSessionError::NotFound("Session file not found: .".to_owned())
        );

        let empty = validate_session(Path::new("")).unwrap_err();
        let empty_loader = load_session_file(Path::new("")).unwrap_err();
        assert_eq!(empty.schema(), Some(&empty_loader));
        assert_ne!(
            empty,
            ValidateSessionError::NotFound("Session file not found: .".to_owned())
        );
        assert_ne!(empty.to_string(), "Session file not found: .");

        let nul = validate_session(Path::new("synthetic/\0sesslint-rx-cli-api-05")).unwrap_err();
        assert!(
            nul.schema().is_none(),
            "a metadata failure must not be replaced by the loader"
        );
        match nul {
            ValidateSessionError::NotFound(message) => {
                assert!(message.starts_with("Session file not found: "));
            }
            ValidateSessionError::Io(_) => {
                assert!(Error::source(&nul).is_some());
            }
            ValidateSessionError::Schema(_) => panic!("loader ran before the exists check"),
        }
    }
}
