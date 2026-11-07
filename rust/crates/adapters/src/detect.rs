//! Format auto-detection through the clear-winner return.
//!
//! Port of `src/sesslint/adapters/detect.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–274.
//! Stops before `resolve_format`. [`resolve_format`], `resolve_format_bytes`,
//! and `_resolve_failure_finding` are not in this file.
//!
//! [`detect_format`] validates thresholds, refuses a missing path or a
//! directory, then reads at most [`SNIFF_BYTES`]. [`detect_format_bytes`]
//! uses the same head limit. [`_detect_from_head`] refuses a live SQLite
//! prefix and an empty or ASCII-whitespace head before it calls
//! [`detect_claude_code`], [`detect_openai_agents`], [`detect_codex_rollout`],
//! and [`detect_canonical`]. Those four scorers are the ones already exported
//! by this crate. This file does not score vendors itself.
//!
//! A bool threshold is [`ThresholdInput::Bool`], never [`ThresholdInput::Int`].
//! `True` stays `True` in the `ValueError`.
//!
//! Gaps vs Python (recorded, not papered over):
//! - [`ThresholdInput::Int`] is `i64`. Python `int` is unbounded.
//! - `str.lower` follows Rust Unicode lowercase. A few scalars such as
//!   U+0130 differ from CPython. ASCII matches.
//! - Finite float text in a `ValueError` is Rust debug, with `nan`, `inf`,
//!   `-inf`, `0.0`, and `-0.0` spelled as CPython does. A few shortest
//!   round-trips differ from CPython.
//! - [`python_round3`] is Rust `{:.3}` parsed back to `f64`. That matches
//!   CPython `round(value, 3)` for the halfway values this module locks,
//!   including `0.1235` → `0.123` and `0.0025` → `0.003`.
//! - A non-UTF-8 path component is lossy. Python `Path.name` can keep the
//!   original bytes.
//! - `open` and `read` failures display Rust's `io::Error`. The pin
//!   propagates the Python exception object.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PrefixComponent};

use crate::canonical::detect_canonical;
use crate::claude_code::detect_claude_code;
use crate::codex_rollout::detect_codex_rollout;
use crate::openai_agents::{detect_openai_agents, SQLITE_MAGIC};

/// Python: `CONFIDENCE_MIN`.
pub const CONFIDENCE_MIN: f64 = 0.55;

/// Python: `MARGIN_MIN`.
pub const MARGIN_MIN: f64 = 0.15;

/// Python: `SNIFF_BYTES`. Sixty-four kibibytes.
pub const SNIFF_BYTES: usize = 65_536;

/// Python: `EPSILON`.
pub const EPSILON: f64 = 1e-9;

/// Python: `FORMAT_CLAUDE_CODE`.
pub const FORMAT_CLAUDE_CODE: &str = "claude-code-jsonl";

/// Python: `FORMAT_OPENAI_AGENTS`.
pub const FORMAT_OPENAI_AGENTS: &str = "openai-agents";

/// Python: `FORMAT_CODEX_ROLLOUT`.
pub const FORMAT_CODEX_ROLLOUT: &str = "codex-rollout";

/// Python: `FORMAT_CANONICAL`.
pub const FORMAT_CANONICAL: &str = "canonical";

/// Python: `FORMAT_AUTO`.
pub const FORMAT_AUTO: &str = "auto";

/// Python: `SUPPORTED_FORMATS`, in the pin's literal order.
///
/// This is not a sorted set. Confidence maps use this order.
pub const SUPPORTED_FORMATS: [&str; 4] = [
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_CANONICAL,
];

/// Python: `VALID_FORMAT_OPTIONS`. [`FORMAT_AUTO`] is last, not sorted in.
pub const VALID_FORMAT_OPTIONS: [&str; 5] = [
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_CANONICAL,
    FORMAT_AUTO,
];

/// Python: `REASON_CLEAR_WINNER`.
pub const REASON_CLEAR_WINNER: &str = "clear-winner";

/// Python: `REASON_LOW_CONFIDENCE`.
pub const REASON_LOW_CONFIDENCE: &str = "low-confidence";

/// Python: `REASON_TIE`.
pub const REASON_TIE: &str = "tie";

/// Python: `REASON_EMPTY`.
pub const REASON_EMPTY: &str = "empty";

/// Python: `REASON_REFUSED_LIVE_DB`.
pub const REASON_REFUSED_LIVE_DB: &str = "refused-live-db";

/// Python: `REASON_EXPLICIT_OVERRIDE`.
///
/// Declared with the other reason constants. `resolve_format` is not ported
/// here, so this slice never returns it.
pub const REASON_EXPLICIT_OVERRIDE: &str = "explicit-override";

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const UNKNOWN_REASON: &str = "unknown";
const NONE_COMPARISON: &str = "'<' not supported between instances of 'float' and 'NoneType'";

/// One threshold argument as Python would classify it.
///
/// [`Self::Bool`] is not an integer. `True` is not `1` and `False` is not `0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThresholdInput<'a> {
    /// Python `None`. Skipped by [`validate_detection_thresholds`].
    ///
    /// This is not the default of [`detect_format`]. The Python defaults are
    /// [`CONFIDENCE_MIN`] and [`MARGIN_MIN`]. Explicit `None` reaches a
    /// comparison only after the SQLite and empty gates, and that comparison
    /// is a `TypeError`.
    None,
    /// Python `bool`.
    Bool(bool),
    /// Python `int` that fits in `i64`. Not a bool.
    Int(i64),
    /// Python `float`.
    Float(f64),
    /// Not an int or float. `text` is Python's `f"{value}"` for that object.
    Text(&'a str),
}

/// Failure from threshold checks, path checks, or a `None` comparison.
#[derive(Debug)]
pub enum DetectError {
    /// Python `ValueError` from [`validate_detection_thresholds`].
    Value(String),
    /// Python `FileNotFoundError`: `Session file not found: {path}`.
    NotFound(String),
    /// Python `IsADirectoryError`: `Expected session file, got directory: {path}`.
    IsADirectory(String),
    /// `open` or `read` failed. Display is Rust's `io::Error`.
    Io(io::Error),
    /// Python `TypeError` when a `None` threshold is compared.
    Type(String),
}

impl fmt::Display for DetectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(message)
            | Self::NotFound(message)
            | Self::IsADirectory(message)
            | Self::Type(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl Error for DetectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Value(_) | Self::NotFound(_) | Self::IsADirectory(_) | Self::Type(_) => None,
        }
    }
}

/// Outcome of format auto-detection.
///
/// Python: `DetectionResult`. `confidences` keeps insertion order.
/// This is not a `HashMap` and not a `BTreeMap`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionResult {
    /// Winning format, or `None` when detection abstains.
    pub format: Option<String>,
    /// Scores in insertion order.
    pub confidences: Vec<(String, f64)>,
    /// Decision reason. Empty when the value was constructed that way.
    pub reason: String,
}

impl DetectionResult {
    /// Python: `DetectionResult.to_source_block`.
    #[must_use]
    pub fn to_source_block(&self, requested: Option<&str>) -> SourceDetectionBlock {
        source_detection_block(Some(self), requested)
    }
}

/// `source.detection` audit block.
///
/// Field order is `requested`, `resolved`, `confidences`, `reason`.
/// Confidence pairs keep the result's insertion order. Each score is
/// `round(value, 3)`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceDetectionBlock {
    /// Stripped and lowercased request, or [`FORMAT_AUTO`] when omitted.
    pub requested: String,
    /// Resolved format, or `None`.
    pub resolved: Option<String>,
    /// Rounded scores in insertion order.
    pub confidences: Vec<(String, f64)>,
    /// Reason text. `unknown` when the result is `None`.
    pub reason: String,
}

/// Thresholds that survived [`validate_detection_thresholds`].
///
/// `None` means the caller passed Python `None`, not "use the default".
#[derive(Debug, Clone, Copy, PartialEq)]
struct ScreenedThresholds {
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
}

/// Validate detection thresholds.
///
/// Python: `validate_detection_thresholds`. `None` is skipped. A bool is
/// rejected before any integer check. A non-number is rejected before
/// `isnan`. `nan` and infinity are rejected before the open unit interval.
/// Only after both values pass may `margin_min` be compared with
/// `confidence_min`.
///
/// # Errors
///
/// A `ValueError` sentence from the pin.
#[must_use = "an invalid threshold is the result"]
pub fn validate_detection_thresholds(
    confidence_min: ThresholdInput<'_>,
    margin_min: ThresholdInput<'_>,
) -> Result<(), DetectError> {
    let _screened = screen_thresholds(confidence_min, margin_min)?;
    Ok(())
}

/// Emit the `source.detection` audit block.
///
/// Python: `to_source_block`. `requested` `None` becomes [`FORMAT_AUTO`].
/// A present string is stripped with Python whitespace rules, then lowercased.
#[must_use]
pub fn to_source_block(
    result: Option<&DetectionResult>,
    requested: Option<&str>,
) -> SourceDetectionBlock {
    source_detection_block(result, requested)
}

/// Sniff a session file header.
///
/// Python: `detect_format`. Thresholds are checked before `exists`,
/// `is_dir`, and `open`. An explicit `None` is not replaced with
/// [`CONFIDENCE_MIN`] or [`MARGIN_MIN`].
///
/// # Errors
///
/// Invalid thresholds, a missing path, a directory, or an `open` / `read`
/// failure. A `None` threshold that reaches a numeric comparison is a
/// `TypeError` after the SQLite and empty gates.
#[must_use = "detection abstains with a reason instead of guessing"]
pub fn detect_format(
    path: &Path,
    confidence_min: ThresholdInput<'_>,
    margin_min: ThresholdInput<'_>,
) -> Result<DetectionResult, DetectError> {
    let screened = screen_thresholds(confidence_min, margin_min)?;
    let displayed = displayed_path(path);
    let fs_path = session_fs_path(path);
    match fs_path.metadata() {
        Ok(meta) if meta.is_dir() => {
            return Err(DetectError::IsADirectory(format!(
                "Expected session file, got directory: {}",
                displayed.text
            )));
        }
        Ok(_) => {}
        Err(_) => {
            return Err(DetectError::NotFound(format!(
                "Session file not found: {}",
                displayed.text
            )));
        }
    }
    let mut file = File::open(fs_path).map_err(DetectError::Io)?;
    let head = read_prefix(&mut file, sniff_limit()).map_err(DetectError::Io)?;
    drop(file);
    _detect_from_head(&head, &displayed.name, screened)
}

/// Sniff a byte buffer.
///
/// Python: `detect_format_bytes`. Uses `data[:SNIFF_BYTES]` and the given
/// filename. The filename is not a path and is not stripped.
///
/// # Errors
///
/// Invalid thresholds, or a `None` threshold that reaches a comparison.
#[must_use = "detection abstains with a reason instead of guessing"]
pub fn detect_format_bytes(
    data: &[u8],
    filename: &str,
    confidence_min: ThresholdInput<'_>,
    margin_min: ThresholdInput<'_>,
) -> Result<DetectionResult, DetectError> {
    let screened = screen_thresholds(confidence_min, margin_min)?;
    let head = match data.get(..SNIFF_BYTES) {
        Some(prefix) => prefix,
        None => data,
    };
    _detect_from_head(head, filename, screened)
}

/// SQLite gate, empty gate, then score and arbitrate.
///
/// Python: `_detect_from_head`, through the `REASON_CLEAR_WINNER` return.
fn _detect_from_head(
    head_bytes: &[u8],
    filename: &str,
    thresholds: ScreenedThresholds,
) -> Result<DetectionResult, DetectError> {
    if head_bytes.starts_with(SQLITE_MAGIC) {
        return Ok(zeroed(REASON_REFUSED_LIVE_DB));
    }
    let clean = match head_bytes.strip_prefix(UTF8_BOM) {
        Some(rest) => rest,
        None => head_bytes,
    };
    if bytes_strip(clean).is_empty() {
        return Ok(zeroed(REASON_EMPTY));
    }
    let [claude, openai, codex, canonical] = SUPPORTED_FORMATS;
    let raw_scores = [
        (claude, detect_claude_code(head_bytes, filename)),
        (openai, detect_openai_agents(head_bytes, filename)),
        (codex, detect_codex_rollout(head_bytes, filename)),
        (canonical, detect_canonical(head_bytes, filename)),
    ];
    arbitrate_scores(raw_scores, thresholds)
}

fn screen_thresholds(
    confidence_min: ThresholdInput<'_>,
    margin_min: ThresholdInput<'_>,
) -> Result<ScreenedThresholds, DetectError> {
    let confidence_min = screen_one("confidence_min", confidence_min)?;
    let margin_min = screen_one("margin_min", margin_min)?;
    if let (Some(confidence_min), Some(margin_min)) = (confidence_min, margin_min) {
        if margin_min > confidence_min {
            return Err(DetectError::Value(format!(
                "margin_min ({}) cannot exceed confidence_min ({})",
                python_float_text(margin_min),
                python_float_text(confidence_min)
            )));
        }
    }
    Ok(ScreenedThresholds {
        confidence_min,
        margin_min,
    })
}

fn screen_one(name: &str, value: ThresholdInput<'_>) -> Result<Option<f64>, DetectError> {
    match value {
        ThresholdInput::None => Ok(None),
        ThresholdInput::Bool(flag) => Err(bounds_error(name, python_bool_text(flag))),
        ThresholdInput::Text(text) => Err(bounds_error(name, text)),
        ThresholdInput::Int(number) => {
            // `isnan` and `isinf` are false for an int. No integer is inside
            // `(0.0, 1.0)`. The rendered text is the decimal, not `1.0`.
            Err(bounds_error(name, &number.to_string()))
        }
        ThresholdInput::Float(number) => {
            if number.is_nan() || number.is_infinite() || !(0.0 < number && number < 1.0) {
                Err(bounds_error(name, &python_float_text(number)))
            } else {
                Ok(Some(number))
            }
        }
    }
}

fn bounds_error(name: &str, rendered: &str) -> DetectError {
    DetectError::Value(format!(
        "{name} must be strictly between 0.0 and 1.0 exclusive, got {rendered}"
    ))
}

fn python_bool_text(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

fn arbitrate_scores(
    raw_scores: [(&str, f64); 4],
    thresholds: ScreenedThresholds,
) -> Result<DetectionResult, DetectError> {
    let mut normalized = [0.0_f64; 4];
    let mut confidences = Vec::with_capacity(raw_scores.len());
    for (slot, (name, score)) in normalized.iter_mut().zip(raw_scores) {
        let value = normalize_score(score);
        *slot = value;
        confidences.push((name.to_owned(), value));
    }
    let mut order = [0_usize, 1, 2, 3];
    order.sort_by(|&left, &right| match score_at(&normalized, right) {
        Some(right_score) => match score_at(&normalized, left) {
            Some(left_score) => match right_score.partial_cmp(&left_score) {
                Some(ordering) => ordering,
                None => Ordering::Equal,
            },
            None => Ordering::Equal,
        },
        None => Ordering::Equal,
    });
    let [winner_index, second_index, _, _] = order;
    let (Some(winner_score), Some(second_score)) = (
        score_at(&normalized, winner_index),
        score_at(&normalized, second_index),
    ) else {
        return Ok(undecided(confidences, REASON_LOW_CONFIDENCE));
    };
    let Some(winner_fmt) = raw_scores.get(winner_index).map(|(name, _)| *name) else {
        return Ok(undecided(confidences, REASON_LOW_CONFIDENCE));
    };
    let Some(confidence_min) = thresholds.confidence_min else {
        return Err(none_comparison());
    };
    if winner_score < confidence_min {
        return Ok(undecided(confidences, REASON_LOW_CONFIDENCE));
    }
    let Some(margin_min) = thresholds.margin_min else {
        return Err(none_comparison());
    };
    let score_diff = winner_score - second_score;
    if (score_diff + EPSILON) < margin_min || score_diff.abs() <= EPSILON {
        return Ok(undecided(confidences, REASON_TIE));
    }
    Ok(DetectionResult {
        format: Some(winner_fmt.to_owned()),
        confidences,
        reason: REASON_CLEAR_WINNER.to_owned(),
    })
}

fn score_at(scores: &[f64; 4], index: usize) -> Option<f64> {
    scores.get(index).copied()
}

fn normalize_score(score: f64) -> f64 {
    if !score.is_finite() {
        return 0.0;
    }
    let upper = if score < 1.0 { score } else { 1.0 };
    let clamped = if upper > 0.0 { upper } else { 0.0 };
    python_round3(clamped)
}

/// CPython `round(value, 3)` for the values this module compares.
///
/// Non-finite values are unchanged. A finite value is formatted with three
/// digits after the decimal point and parsed back, which preserves a
/// negative zero.
fn python_round3(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let text = format!("{value:.3}");
    match text.parse::<f64>() {
        Ok(parsed) => parsed,
        Err(_) => value,
    }
}

fn python_float_text(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
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

fn none_comparison() -> DetectError {
    DetectError::Type(NONE_COMPARISON.to_owned())
}

fn zeroed(reason: &str) -> DetectionResult {
    undecided(zero_confidences(), reason)
}

fn undecided(confidences: Vec<(String, f64)>, reason: &str) -> DetectionResult {
    DetectionResult {
        format: None,
        confidences,
        reason: reason.to_owned(),
    }
}

fn zero_confidences() -> Vec<(String, f64)> {
    SUPPORTED_FORMATS
        .iter()
        .map(|name| ((*name).to_owned(), 0.0))
        .collect()
}

fn source_detection_block(
    result: Option<&DetectionResult>,
    requested: Option<&str>,
) -> SourceDetectionBlock {
    let requested = requested_label(requested);
    let Some(result) = result else {
        return SourceDetectionBlock {
            requested,
            resolved: None,
            confidences: Vec::new(),
            reason: UNKNOWN_REASON.to_owned(),
        };
    };
    SourceDetectionBlock {
        requested,
        resolved: result.format.clone(),
        confidences: round_confidences(&result.confidences),
        reason: result.reason.clone(),
    }
}

fn requested_label(requested: Option<&str>) -> String {
    match requested {
        None => FORMAT_AUTO.to_owned(),
        Some(text) => python_strip(text).to_lowercase(),
    }
}

fn round_confidences(confidences: &[(String, f64)]) -> Vec<(String, f64)> {
    confidences
        .iter()
        .map(|(name, score)| (name.clone(), python_round3(*score)))
        .collect()
}

fn sniff_limit() -> u64 {
    match u64::try_from(SNIFF_BYTES) {
        Ok(limit) => limit,
        Err(_) => u64::MAX,
    }
}

fn read_prefix(reader: &mut dyn Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    reader.take(limit).read_to_end(&mut head)?;
    Ok(head)
}

fn session_fs_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

struct DisplayedPath {
    text: String,
    name: String,
}

fn displayed_path(path: &Path) -> DisplayedPath {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = prefix_text(&prefix_component);
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
        }
    }
    let name = match parts.last() {
        Some(part) => part.clone(),
        None => String::new(),
    };
    DisplayedPath {
        text: join_python_path(&prefix, rooted, &parts),
        name,
    }
}

fn prefix_text(component: &PrefixComponent<'_>) -> String {
    component.as_os_str().to_string_lossy().into_owned()
}

fn join_python_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return ".".to_owned();
    }
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
    }
    if rooted && !out.ends_with(sep) {
        out.push(sep);
    }
    for (index, part) in parts.iter().enumerate() {
        let drive_relative = index == 0 && !rooted && prefix.ends_with(':');
        if !out.is_empty() && !out.ends_with(sep) && !drive_relative {
            out.push(sep);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        ".".to_owned()
    } else {
        out
    }
}

/// Python `str.strip` using the adapter whitespace set.
fn python_strip(text: &str) -> &str {
    let mut start = 0_usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start = match start.checked_add(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    let Some(tail) = text.get(start..) else {
        return "";
    };
    let mut end = tail.len();
    for ch in tail.chars().rev() {
        if !is_python_space(ch) {
            break;
        }
        end = match end.checked_sub(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    tail.get(..end).unwrap_or("")
}

fn is_python_space(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x0009
            | 0x000A
            | 0x000B
            | 0x000C
            | 0x000D
            | 0x001C
            | 0x001D
            | 0x001E
            | 0x001F
            | 0x0020
            | 0x0085
            | 0x00A0
            | 0x1680
            | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

/// Python `bytes.strip()` with no argument. ASCII whitespace only.
fn bytes_strip(data: &[u8]) -> &[u8] {
    let Some(start) = data.iter().position(|byte| !is_ascii_byte_space(*byte)) else {
        return &[];
    };
    let Some(last) = data.iter().rposition(|byte| !is_ascii_byte_space(*byte)) else {
        return &[];
    };
    let Some(end) = last.checked_add(1) else {
        return &[];
    };
    data.get(start..end).unwrap_or(&[])
}

fn is_ascii_byte_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        arbitrate_scores, detect_format, detect_format_bytes, displayed_path, python_round3,
        screen_thresholds, to_source_block, validate_detection_thresholds, DetectError,
        DetectionResult, ScreenedThresholds, ThresholdInput, CONFIDENCE_MIN, EPSILON, FORMAT_AUTO,
        FORMAT_CANONICAL, FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT, FORMAT_OPENAI_AGENTS,
        MARGIN_MIN, REASON_CLEAR_WINNER, REASON_EMPTY, REASON_EXPLICIT_OVERRIDE,
        REASON_LOW_CONFIDENCE, REASON_REFUSED_LIVE_DB, REASON_TIE, SNIFF_BYTES, SUPPORTED_FORMATS,
        VALID_FORMAT_OPTIONS,
    };
    use crate::openai_agents::{detect_openai_agents, SQLITE_MAGIC};

    fn defaults() -> (ThresholdInput<'static>, ThresholdInput<'static>) {
        (
            ThresholdInput::Float(CONFIDENCE_MIN),
            ThresholdInput::Float(MARGIN_MIN),
        )
    }

    fn detect_bytes(data: &[u8], filename: &str) -> Result<DetectionResult, DetectError> {
        let (confidence_min, margin_min) = defaults();
        detect_format_bytes(data, filename, confidence_min, margin_min)
    }

    fn screened(confidence_min: f64, margin_min: f64) -> ScreenedThresholds {
        ScreenedThresholds {
            confidence_min: Some(confidence_min),
            margin_min: Some(margin_min),
        }
    }

    fn scores(values: [f64; 4]) -> [(&'static str, f64); 4] {
        let [claude, openai, codex, canonical] = SUPPORTED_FORMATS;
        [
            (claude, values[0]),
            (openai, values[1]),
            (codex, values[2]),
            (canonical, values[3]),
        ]
    }

    struct TempPath {
        path: PathBuf,
        directory: bool,
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            if self.directory {
                let _ = fs::remove_dir_all(&self.path);
            } else {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    fn temp_path(label: &str, directory: bool) -> TempPath {
        static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        TempPath {
            path: std::env::temp_dir().join(format!("sesslint-detect-01-{label}-{n}")),
            directory,
        }
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(CONFIDENCE_MIN.to_bits(), 0.55_f64.to_bits());
        assert_eq!(MARGIN_MIN.to_bits(), 0.15_f64.to_bits());
        assert_eq!(SNIFF_BYTES, 65_536);
        assert_eq!(EPSILON.to_bits(), 0x3e11_2e0b_e826_d695);
        assert_eq!(FORMAT_CLAUDE_CODE, "claude-code-jsonl");
        assert_eq!(FORMAT_OPENAI_AGENTS, "openai-agents");
        assert_eq!(FORMAT_CODEX_ROLLOUT, "codex-rollout");
        assert_eq!(FORMAT_CANONICAL, "canonical");
        assert_eq!(FORMAT_AUTO, "auto");
        assert_eq!(
            SUPPORTED_FORMATS,
            [
                "claude-code-jsonl",
                "openai-agents",
                "codex-rollout",
                "canonical",
            ]
        );
        assert_eq!(
            VALID_FORMAT_OPTIONS,
            [
                "claude-code-jsonl",
                "openai-agents",
                "codex-rollout",
                "canonical",
                "auto",
            ]
        );
        assert_eq!(REASON_CLEAR_WINNER, "clear-winner");
        assert_eq!(REASON_LOW_CONFIDENCE, "low-confidence");
        assert_eq!(REASON_TIE, "tie");
        assert_eq!(REASON_EMPTY, "empty");
        assert_eq!(REASON_REFUSED_LIVE_DB, "refused-live-db");
        assert_eq!(REASON_EXPLICIT_OVERRIDE, "explicit-override");
    }

    #[test]
    fn round3_matches_cpython_bits() {
        assert_eq!(python_round3(0.123_456).to_bits(), 0x3fbf_7ced_9168_72b0);
        assert_eq!(python_round3(0.1235).to_bits(), 0x3fbf_7ced_9168_72b0);
        assert_eq!(python_round3(0.0025).to_bits(), 0x3f68_9374_bc6a_7efa);
        assert_eq!(python_round3(0.0005).to_bits(), 0x3f50_624d_d2f1_a9fc);
        assert_eq!(python_round3(0.0015).to_bits(), 0x3f60_624d_d2f1_a9fc);
        assert_eq!(python_round3(0.9995).to_bits(), 1.0_f64.to_bits());
        assert_eq!(python_round3(-0.0004).to_bits(), 0x8000_0000_0000_0000);
        assert_eq!(python_round3(-0.0005).to_bits(), 0xbf50_624d_d2f1_a9fc);
        assert!(python_round3(f64::NAN).is_nan());
        assert_eq!(
            python_round3(f64::INFINITY).to_bits(),
            f64::INFINITY.to_bits()
        );
    }

    #[test]
    fn bool_is_not_an_int_and_checks_keep_pin_order() {
        let missing = Path::new("missing-detect-threshold.json");
        let true_err = detect_format(
            missing,
            ThresholdInput::Bool(true),
            ThresholdInput::Float(0.2),
        )
        .expect_err("bool");
        assert_eq!(
            true_err.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got True"
        );
        assert!(!true_err.to_string().contains("Session file not found"));

        let false_err =
            validate_detection_thresholds(ThresholdInput::Float(0.5), ThresholdInput::Bool(false))
                .expect_err("false");
        assert_eq!(
            false_err.to_string(),
            "margin_min must be strictly between 0.0 and 1.0 exclusive, got False"
        );

        let int_err = detect_format(missing, ThresholdInput::Int(1), ThresholdInput::Float(0.2))
            .expect_err("int");
        assert_eq!(
            int_err.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1"
        );
        let float_one = detect_format(missing, ThresholdInput::Float(1.0), ThresholdInput::None)
            .expect_err("float one");
        assert_eq!(
            float_one.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1.0"
        );
        let zero_int = validate_detection_thresholds(ThresholdInput::Int(0), ThresholdInput::None)
            .expect_err("zero int");
        assert_eq!(
            zero_int.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 0"
        );
        let text = validate_detection_thresholds(ThresholdInput::Text("0.7"), ThresholdInput::None)
            .expect_err("text");
        assert_eq!(
            text.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 0.7"
        );
        assert!(!text.to_string().contains("'0.7'"));

        let confidence_first =
            validate_detection_thresholds(ThresholdInput::Bool(true), ThresholdInput::Float(0.0))
                .expect_err("confidence first");
        assert!(confidence_first.to_string().starts_with("confidence_min"));

        let range_before_pair =
            validate_detection_thresholds(ThresholdInput::Float(0.5), ThresholdInput::Float(0.0))
                .expect_err("range");
        assert_eq!(
            range_before_pair.to_string(),
            "margin_min must be strictly between 0.0 and 1.0 exclusive, got 0.0"
        );
        let pair =
            validate_detection_thresholds(ThresholdInput::Float(0.5), ThresholdInput::Float(0.9))
                .expect_err("pair");
        assert_eq!(
            pair.to_string(),
            "margin_min (0.9) cannot exceed confidence_min (0.5)"
        );
        let long = validate_detection_thresholds(
            ThresholdInput::Float(0.3),
            ThresholdInput::Float(0.300_000_000_000_000_04),
        )
        .expect_err("long");
        assert_eq!(
            long.to_string(),
            "margin_min (0.30000000000000004) cannot exceed confidence_min (0.3)"
        );
        let negative =
            validate_detection_thresholds(ThresholdInput::Float(-0.1), ThresholdInput::None)
                .expect_err("negative");
        assert_eq!(
            negative.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got -0.1"
        );
        let nan =
            validate_detection_thresholds(ThresholdInput::Float(f64::NAN), ThresholdInput::None)
                .expect_err("nan");
        assert_eq!(
            nan.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got nan"
        );
        let inf = validate_detection_thresholds(
            ThresholdInput::Float(f64::INFINITY),
            ThresholdInput::None,
        )
        .expect_err("inf");
        assert_eq!(
            inf.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got inf"
        );
        let neg_inf = validate_detection_thresholds(
            ThresholdInput::None,
            ThresholdInput::Float(f64::NEG_INFINITY),
        )
        .expect_err("neg inf");
        assert_eq!(
            neg_inf.to_string(),
            "margin_min must be strictly between 0.0 and 1.0 exclusive, got -inf"
        );
        let neg_zero =
            validate_detection_thresholds(ThresholdInput::Float(-0.0), ThresholdInput::None)
                .expect_err("neg zero");
        assert_eq!(
            neg_zero.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got -0.0"
        );
        let big_int_first =
            validate_detection_thresholds(ThresholdInput::Int(2), ThresholdInput::Float(0.9))
                .expect_err("int before margin");
        assert_eq!(
            big_int_first.to_string(),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 2"
        );
    }

    #[test]
    fn validate_accepts_none_and_equal_bounds() {
        validate_detection_thresholds(ThresholdInput::None, ThresholdInput::None)
            .expect("both none");
        validate_detection_thresholds(ThresholdInput::None, ThresholdInput::Float(0.2))
            .expect("margin only");
        validate_detection_thresholds(ThresholdInput::Float(0.5), ThresholdInput::None)
            .expect("confidence only");
        validate_detection_thresholds(ThresholdInput::Float(0.5), ThresholdInput::Float(0.5))
            .expect("equal");
        validate_detection_thresholds(ThresholdInput::Float(1.1), ThresholdInput::None)
            .expect_err("above one");
    }

    #[test]
    fn source_block_rounds_in_insertion_order() {
        let result = DetectionResult {
            format: Some(FORMAT_CANONICAL.to_owned()),
            confidences: vec![
                (FORMAT_CLAUDE_CODE.to_owned(), 0.123_456),
                (FORMAT_OPENAI_AGENTS.to_owned(), 0.0),
                (FORMAT_CANONICAL.to_owned(), 1.0),
            ],
            reason: REASON_CLEAR_WINNER.to_owned(),
        };
        let block = to_source_block(Some(&result), Some("auto"));
        assert_eq!(block.requested, "auto");
        assert_eq!(block.resolved.as_deref(), Some(FORMAT_CANONICAL));
        assert_eq!(block.reason, REASON_CLEAR_WINNER);
        assert_eq!(
            block.confidences,
            vec![
                (FORMAT_CLAUDE_CODE.to_owned(), python_round3(0.123_456)),
                (FORMAT_OPENAI_AGENTS.to_owned(), 0.0),
                (FORMAT_CANONICAL.to_owned(), 1.0),
            ]
        );
        assert_eq!(block.confidences[0].1.to_bits(), 0x3fbf_7ced_9168_72b0);
        assert_eq!(result.confidences[0].1.to_bits(), 0.123_456_f64.to_bits());
        assert_ne!(
            result.confidences[0].1.to_bits(),
            block.confidences[0].1.to_bits()
        );

        let via_method = result.to_source_block(Some("canonical"));
        assert_eq!(via_method.requested, "canonical");
        assert_eq!(via_method.resolved.as_deref(), Some(FORMAT_CANONICAL));

        let absent = to_source_block(None, Some("auto"));
        assert_eq!(absent.requested, "auto");
        assert!(absent.resolved.is_none());
        assert!(absent.confidences.is_empty());
        assert_eq!(absent.reason, "unknown");

        let stripped = to_source_block(None, Some("  AUTO\n"));
        assert_eq!(stripped.requested, "auto");
        let file_sep = to_source_block(None, Some("\u{1c}auto"));
        assert_eq!(file_sep.requested, "auto");
        let nbsp = to_source_block(None, Some("auto\u{00a0}"));
        assert_eq!(nbsp.requested, "auto");
        let omitted = to_source_block(None, None);
        assert_eq!(omitted.requested, FORMAT_AUTO);
        let default_result = DetectionResult::default();
        assert_eq!(default_result.to_source_block(None).reason, "");
    }

    #[test]
    fn sqlite_magic_is_refused_before_the_openai_scorer() {
        assert_eq!(detect_openai_agents(SQLITE_MAGIC, "session.sqlite"), 1.0);
        let refused = detect_bytes(SQLITE_MAGIC, "session.sqlite").expect("refused");
        assert!(refused.format.is_none());
        assert_eq!(refused.reason, REASON_REFUSED_LIVE_DB);
        assert_eq!(refused.confidences.len(), 4);
        assert!(refused.confidences.iter().all(|(_, score)| *score == 0.0));
        assert_eq!(refused.confidences[0].0, FORMAT_CLAUDE_CODE);
        assert_eq!(refused.confidences[3].0, FORMAT_CANONICAL);

        let mut bom_magic = UTF8_BOM_TEST.to_vec();
        bom_magic.extend_from_slice(SQLITE_MAGIC);
        let not_short = detect_bytes(&bom_magic, "session.sqlite").expect("bom magic");
        assert_ne!(not_short.reason, REASON_REFUSED_LIVE_DB);
        assert_ne!(not_short.reason, REASON_EMPTY);
    }

    const UTF8_BOM_TEST: &[u8] = &[0xEF, 0xBB, 0xBF];

    #[test]
    fn empty_heads_refuse_before_scoring() {
        for data in [
            &b""[..],
            b"   \n\t  \r\n   ",
            b" \t\n\r\x0b\x0c",
            UTF8_BOM_TEST,
            b"\xef\xbb\xbf   \r\n\t",
        ] {
            let result = detect_bytes(data, "whitespace.json").expect("empty");
            assert!(result.format.is_none());
            assert_eq!(result.reason, REASON_EMPTY);
            assert!(result.confidences.iter().all(|(_, score)| *score == 0.0));
        }
        let unit = detect_bytes(b"\x1c", "random.txt").expect("unit separator");
        assert_eq!(unit.reason, REASON_LOW_CONFIDENCE);
        assert!(unit.format.is_none());
    }

    #[test]
    fn sniff_window_drops_bytes_past_the_cap() {
        let mut data = vec![b' '; SNIFF_BYTES];
        data.extend_from_slice(br#"{"schema": "sesslint.session/v1"}"#);
        let sliced = detect_bytes(&data, "notes.txt").expect("sliced");
        assert_eq!(sliced.reason, REASON_EMPTY);

        let held = temp_path("sniff", false);
        fs::write(&held.path, &data).expect("write");
        let (confidence_min, margin_min) = defaults();
        let from_file = detect_format(&held.path, confidence_min, margin_min).expect("file sniff");
        assert_eq!(from_file.reason, REASON_EMPTY);
        assert_eq!(from_file, sliced);
    }

    #[test]
    fn missing_path_and_directory_use_path_text() {
        let missing = Path::new("nonexistent_session_file_12345.json");
        let (confidence_min, margin_min) = defaults();
        let err = detect_format(missing, confidence_min, margin_min).expect_err("missing");
        let shown = displayed_path(missing);
        assert_eq!(
            err.to_string(),
            format!("Session file not found: {}", shown.text)
        );
        assert!(matches!(err, DetectError::NotFound(_)));

        let slash = Path::new("foo/");
        let slash_err = detect_format(slash, confidence_min, margin_min).expect_err("slash");
        assert_eq!(slash_err.to_string(), "Session file not found: foo");

        let directory = temp_path("dir", true);
        fs::create_dir(&directory.path).expect("dir");
        let dir_err = detect_format(&directory.path, confidence_min, margin_min).expect_err("dir");
        let dir_shown = displayed_path(&directory.path);
        assert_eq!(
            dir_err.to_string(),
            format!("Expected session file, got directory: {}", dir_shown.text)
        );
        assert!(matches!(dir_err, DetectError::IsADirectory(_)));

        let empty =
            detect_format(Path::new(""), confidence_min, margin_min).expect_err("empty path");
        assert_eq!(empty.to_string(), "Expected session file, got directory: .");
    }

    #[test]
    fn canonical_and_claude_markers_win_on_synthetic_bytes() {
        let canonical =
            detect_bytes(br#"{"schema": "sesslint.session/v1"}"#, "notes.txt").expect("canonical");
        assert_eq!(canonical.format.as_deref(), Some(FORMAT_CANONICAL));
        assert_eq!(canonical.reason, REASON_CLEAR_WINNER);
        assert_eq!(canonical.confidences[3].1.to_bits(), 1.0_f64.to_bits());
        assert_eq!(canonical.confidences[0].1.to_bits(), 0.0_f64.to_bits());
        let again =
            detect_bytes(br#"{"schema": "sesslint.session/v1"}"#, "notes.txt").expect("again");
        assert_eq!(canonical, again);

        let claude =
            detect_bytes(b"{\"type\":\"user_message\"}\n", "Session.JSONL").expect("claude");
        assert_eq!(claude.format.as_deref(), Some(FORMAT_CLAUDE_CODE));
        assert_eq!(claude.reason, REASON_CLEAR_WINNER);

        let low = detect_bytes(b"random unstructured log", "random.txt").expect("low");
        assert!(low.format.is_none());
        assert_eq!(low.reason, REASON_LOW_CONFIDENCE);
        assert!(low
            .confidences
            .iter()
            .all(|(_, score)| *score < CONFIDENCE_MIN));
    }

    #[test]
    fn arbitration_follows_threshold_then_margin_then_epsilon() {
        let clear = arbitrate_scores(
            scores([0.0, 0.0, 0.0, 0.55]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("clear 0.55");
        assert_eq!(clear.format.as_deref(), Some(FORMAT_CANONICAL));
        assert_eq!(clear.reason, REASON_CLEAR_WINNER);
        assert_eq!(clear.confidences[3].1.to_bits(), 0.55_f64.to_bits());

        let low = arbitrate_scores(
            scores([0.0, 0.0, 0.0, 0.549]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("low 0.549");
        assert!(low.format.is_none());
        assert_eq!(low.reason, REASON_LOW_CONFIDENCE);

        let margin_ok = arbitrate_scores(
            scores([0.55, 0.0, 0.0, 0.70]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("margin");
        assert_eq!(margin_ok.format.as_deref(), Some(FORMAT_CANONICAL));
        assert_eq!(margin_ok.reason, REASON_CLEAR_WINNER);

        let margin_tie = arbitrate_scores(
            scores([0.551, 0.0, 0.0, 0.70]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("margin tie");
        assert!(margin_tie.format.is_none());
        assert_eq!(margin_tie.reason, REASON_TIE);

        let epsilon = arbitrate_scores(
            scores([0.80, 0.0, 0.0, 0.800_000_000_1]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("epsilon");
        assert!(epsilon.format.is_none());
        assert_eq!(epsilon.reason, REASON_TIE);
        assert_eq!(epsilon.confidences[0].1.to_bits(), 0.8_f64.to_bits());
        assert_eq!(epsilon.confidences[3].1.to_bits(), 0.8_f64.to_bits());

        let strict = arbitrate_scores(scores([0.60, 0.10, 0.0, 0.10]), screened(0.70, MARGIN_MIN))
            .expect("strict");
        assert!(strict.format.is_none());
        assert_eq!(strict.reason, REASON_LOW_CONFIDENCE);
        let loose = arbitrate_scores(
            scores([0.60, 0.10, 0.0, 0.10]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("loose");
        assert_eq!(loose.format.as_deref(), Some(FORMAT_CLAUDE_CODE));

        let tight_margin = arbitrate_scores(
            scores([0.60, 0.50, 0.0, 0.10]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("default margin");
        assert_eq!(tight_margin.reason, REASON_TIE);
        let wide_margin = arbitrate_scores(
            scores([0.60, 0.50, 0.0, 0.10]),
            screened(CONFIDENCE_MIN, 0.05),
        )
        .expect("wide margin");
        assert_eq!(wide_margin.format.as_deref(), Some(FORMAT_CLAUDE_CODE));
        assert_eq!(wide_margin.reason, REASON_CLEAR_WINNER);

        let both_low = arbitrate_scores(
            scores([0.50, 0.50, 0.0, 0.0]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("both low");
        assert_eq!(both_low.reason, REASON_LOW_CONFIDENCE);
        let both_tie = arbitrate_scores(scores([0.50, 0.50, 0.0, 0.0]), screened(0.40, MARGIN_MIN))
            .expect("both tie");
        assert_eq!(both_tie.reason, REASON_TIE);
        assert!(both_tie.format.is_none());

        let nan = arbitrate_scores(
            scores([0.0, 0.0, 0.0, f64::NAN]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("nan");
        assert_eq!(nan.confidences[3].1.to_bits(), 0.0_f64.to_bits());
        assert_eq!(nan.reason, REASON_LOW_CONFIDENCE);
        let negative = arbitrate_scores(
            scores([0.0, 0.0, 0.0, -0.5]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("negative");
        assert_eq!(negative.confidences[3].1.to_bits(), 0.0_f64.to_bits());
        let high = arbitrate_scores(
            scores([0.0, 0.0, 0.0, 1.4]),
            screened(CONFIDENCE_MIN, MARGIN_MIN),
        )
        .expect("clamp");
        assert_eq!(high.confidences[3].1.to_bits(), 1.0_f64.to_bits());
        assert_eq!(high.format.as_deref(), Some(FORMAT_CANONICAL));
    }

    #[test]
    fn none_threshold_is_not_a_default_and_not_a_winner() {
        let empty = detect_format_bytes(
            b" \t",
            "blank.txt",
            ThresholdInput::None,
            ThresholdInput::None,
        )
        .expect("empty before compare");
        assert_eq!(empty.reason, REASON_EMPTY);

        let compared = detect_format_bytes(
            b"x",
            "random.txt",
            ThresholdInput::None,
            ThresholdInput::Float(MARGIN_MIN),
        )
        .expect_err("none confidence");
        assert_eq!(
            compared.to_string(),
            "'<' not supported between instances of 'float' and 'NoneType'"
        );
        assert!(matches!(compared, DetectError::Type(_)));

        let low_skips_margin = arbitrate_scores(
            scores([0.0, 0.0, 0.0, 0.0]),
            ScreenedThresholds {
                confidence_min: Some(CONFIDENCE_MIN),
                margin_min: None,
            },
        )
        .expect("low before margin");
        assert_eq!(low_skips_margin.reason, REASON_LOW_CONFIDENCE);

        let margin_none = arbitrate_scores(
            scores([0.90, 0.10, 0.0, 0.0]),
            ScreenedThresholds {
                confidence_min: Some(CONFIDENCE_MIN),
                margin_min: None,
            },
        )
        .expect_err("none margin");
        assert_eq!(
            margin_none.to_string(),
            "'<' not supported between instances of 'float' and 'NoneType'"
        );
    }

    #[test]
    fn path_text_matches_pathlib_samples() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(displayed_path(Path::new("")).text, ".");
        assert_eq!(displayed_path(Path::new("")).name, "");
        assert_eq!(displayed_path(Path::new(".")).name, "");
        assert_eq!(displayed_path(Path::new("./dir")).text, "dir");
        assert_eq!(displayed_path(Path::new("foo/")).text, "foo");
        assert_eq!(displayed_path(Path::new("foo/")).name, "foo");
        assert_eq!(
            displayed_path(Path::new("foo/../bar")).text,
            format!("foo{sep}..{sep}bar")
        );
        assert_eq!(displayed_path(Path::new("foo/../bar")).name, "bar");
        assert_eq!(displayed_path(Path::new("a//b")).text, format!("a{sep}b"));
        assert_eq!(displayed_path(Path::new("a/./b")).text, format!("a{sep}b"));
        assert_eq!(
            displayed_path(Path::new("missing/file.json")).text,
            format!("missing{sep}file.json")
        );
        assert_eq!(
            displayed_path(Path::new("missing/file.json")).name,
            "file.json"
        );
    }

    #[cfg(windows)]
    #[test]
    fn path_text_matches_windows_pathlib() {
        assert_eq!(displayed_path(Path::new("C:/nope/x")).text, r"C:\nope\x");
        assert_eq!(displayed_path(Path::new("C:/nope/x")).name, "x");
        assert_eq!(displayed_path(Path::new(r"/abs/file")).text, r"\abs\file");
        assert_eq!(displayed_path(Path::new("C:foo")).text, "C:foo");
        assert_eq!(displayed_path(Path::new("C:foo")).name, "foo");
        assert_eq!(displayed_path(Path::new("C:/")).text, r"C:\");
        assert_eq!(displayed_path(Path::new("C:/")).name, "");
        assert_eq!(displayed_path(Path::new("/")).text, r"\");
        assert_eq!(
            displayed_path(Path::new(r"\\server\share\f")).text,
            r"\\server\share\f"
        );
        assert_eq!(displayed_path(Path::new(r"\\server\share\f")).name, "f");
    }

    #[test]
    fn screen_keeps_a_finite_float_inside_the_interval() {
        let ok = screen_thresholds(ThresholdInput::Float(0.4), ThresholdInput::Float(0.2))
            .expect("screen");
        assert_eq!(ok.confidence_min, Some(0.4));
        assert_eq!(ok.margin_min, Some(0.2));
    }
}

#[allow(
    clippy::items_after_test_module,
    reason = "resolve_format is appended after the detection tests"
)]
mod resolve_port {
    //! `resolve_format`, `resolve_format_bytes`, and `_resolve_failure_finding`.
    //!
    //! Port of `src/sesslint/adapters/detect.py`
    //! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 277–431.
    //! Stops at the fingerprint refusal inside `_resolve_failure_finding`.

    use std::convert::Infallible;
    use std::error::Error;
    use std::fmt;
    use std::path::Path;

    use model::codes::{Repairability, Severity, SL001, SL302};
    use model::errors::FindingError;
    use model::finding::{
        make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef,
        FINGERPRINT_CODEC_UNAVAILABLE,
    };

    use super::{
        detect_format, detect_format_bytes, displayed_path, python_strip, DetectError,
        DetectionResult, ThresholdInput, FORMAT_AUTO, REASON_EMPTY, REASON_EXPLICIT_OVERRIDE,
        REASON_REFUSED_LIVE_DB, SUPPORTED_FORMATS, VALID_FORMAT_OPTIONS,
    };

    const REFUSED_LIVE_DB_TEMPLATE: &str = concat!(
        "Refused live SQLite database; SessLint requires exported items or ",
        "checkpoints [detail: refused_live_db]"
    );
    const EMPTY_INPUT_TEMPLATE: &str = "Session input is empty [detail: EMPTY]";
    const AMBIGUOUS_FORMAT_TEMPLATE: &str = concat!(
        "Unable to determine session format with sufficient confidence ",
        "[detail: ambiguous_format]"
    );

    /// Successful resolution.
    ///
    /// Python's success tuple is `(format_name, result, [])`. `findings` is
    /// empty. An unresolved sniff is [`ResolveFormatError`], not a finding.
    #[derive(Debug, Clone, PartialEq)]
    pub struct FormatResolution {
        /// Normalized format name.
        pub format: String,
        /// Explicit override, or the sniff [`DetectionResult`].
        pub result: DetectionResult,
        /// Always empty. The failure finding is not returned.
        pub findings: Vec<Finding>,
    }

    /// Pin `ValueError`, filesystem and comparison errors, or the fingerprint refusal.
    #[derive(Debug)]
    pub enum ResolveFormatError {
        /// Threshold, path, I/O, or `None` comparison error.
        Detect(DetectError),
        /// Unknown explicit name. Display is the pin `ValueError`.
        UnknownFormat(String),
        /// [`make_finding`] or [`SourceRef`] refused. Display is that error.
        Finding(FindingError),
    }

    impl fmt::Display for ResolveFormatError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Detect(error) => error.fmt(formatter),
                Self::UnknownFormat(message) => formatter.write_str(message),
                Self::Finding(error) => error.fmt(formatter),
            }
        }
    }

    impl Error for ResolveFormatError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Detect(error) => Some(error),
                Self::Finding(error) => Some(error),
                Self::UnknownFormat(_) => None,
            }
        }
    }

    impl From<DetectError> for ResolveFormatError {
        fn from(error: DetectError) -> Self {
            Self::Detect(error)
        }
    }

    impl From<FindingError> for ResolveFormatError {
        fn from(error: FindingError) -> Self {
            Self::Finding(error)
        }
    }

    /// Resolve an explicit format or auto-detect, failing closed.
    ///
    /// Python: `resolve_format` lines 277–331. Thresholds are validated before
    /// the name is read and before `path` is opened. A bool is not an int:
    /// `True` stays `True` in the `ValueError`. A known non-auto name does
    /// not open `path`. It returns that normalized name,
    /// [`REASON_EXPLICIT_OVERRIDE`], and no findings. `auto` and `None` call
    /// [`detect_format`]. A resolved format returns empty findings. An
    /// unresolved result calls [`_resolve_failure_finding`] and propagates
    /// that error.
    ///
    /// Strip uses the Python whitespace set already in this file, then Rust
    /// Unicode lowercase. `path` text is `displayed_path` with `\` replaced
    /// by `/`, matching `str(Path).replace("\\", "/")`.
    ///
    /// # Errors
    ///
    /// Unknown names are the pin `ValueError` (`repr` of the original name,
    /// then `sorted(VALID_FORMAT_OPTIONS)`). Threshold, path, and comparison
    /// errors come from the existing validators and [`detect_format`]. An
    /// unresolved sniff propagates the fingerprint error.
    #[must_use = "an unresolved format propagates the fingerprint error"]
    pub fn resolve_format(
        explicit: Option<&str>,
        path: &Path,
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> Result<FormatResolution, ResolveFormatError> {
        validate_first(confidence_min, margin_min)?;
        let path_str = forward_slash_path(path);
        if let Some(resolved) = explicit_resolution(explicit)? {
            return Ok(resolved);
        }
        let result = detect_format(path, confidence_min, margin_min)?;
        resolved_or_failure(result, &path_str, confidence_min, margin_min)
    }

    /// Resolve an explicit format or sniff a buffer, failing closed.
    ///
    /// Python: `resolve_format_bytes` lines 334–379. `filename` is passed
    /// through to [`detect_format_bytes`] and is not stripped. `display_path`
    /// is the failure [`SourceRef`] path and is not rewritten here.
    /// Thresholds, the explicit arm, and the unresolved arm match
    /// [`resolve_format`].
    ///
    /// # Errors
    ///
    /// Same as [`resolve_format`], except path errors come from the byte
    /// sniff's threshold checks and from [`SourceRef`] on the failure arm.
    #[must_use = "an unresolved format propagates the fingerprint error"]
    pub fn resolve_format_bytes(
        explicit: Option<&str>,
        data: &[u8],
        filename: &str,
        display_path: &str,
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> Result<FormatResolution, ResolveFormatError> {
        validate_first(confidence_min, margin_min)?;
        if let Some(resolved) = explicit_resolution(explicit)? {
            return Ok(resolved);
        }
        let result = detect_format_bytes(data, filename, confidence_min, margin_min)?;
        resolved_or_failure(result, display_path, confidence_min, margin_min)
    }

    /// Build the failure inputs and stop at the fingerprint.
    ///
    /// Python: `_resolve_failure_finding` lines 382–431. [`SourceRef`] is
    /// built first (`line` 1, `record_id` `None`). `refused-live-db` is
    /// SL001 fatal unsupported. `empty` is SL001 error manual. Every other
    /// reason is SL302 error manual. No other code is selected.
    ///
    /// [`make_finding`] is called with the fingerprint omitted. It validates,
    /// then its [`Display`](fmt::Display) is
    /// [`FINGERPRINT_CODEC_UNAVAILABLE`]. A [`Finding`] is not returned.
    /// Success is [`Infallible`].
    ///
    /// # Errors
    ///
    /// [`SourceRef`] rejection, or the omitted-fingerprint error.
    #[must_use = "the fingerprint error is the result"]
    pub fn _resolve_failure_finding(
        result: &DetectionResult,
        path_str: &str,
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> Result<Infallible, FindingError> {
        let source = SourceRef::try_new(path_str, Some(SourceLine::Int(1)), None)?;
        let kind = failure_kind(&result.reason);
        let labels = failure_labels(kind);
        let evidence = failure_evidence(result, kind, confidence_min, margin_min);
        match make_finding(&MakeFindingInput {
            code: PyValue::string(labels.code),
            severity: PyValue::severity(labels.severity),
            repairability: PyValue::repairability(labels.repairability),
            message_template: PyValue::string(labels.template),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            evidence,
            fingerprint: PyValue::None,
            adapter_id: None,
            adapter_version: None,
            profile_id: None,
            profile_version: None,
            ordinal: None,
            context: None,
        }) {
            Err(error) => Err(error),
            Ok(_finding) => Err(FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE)),
        }
    }

    fn validate_first(
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> Result<(), ResolveFormatError> {
        super::validate_detection_thresholds(confidence_min, margin_min)?;
        Ok(())
    }

    fn explicit_resolution(
        explicit: Option<&str>,
    ) -> Result<Option<FormatResolution>, ResolveFormatError> {
        let Some(explicit) = explicit else {
            return Ok(None);
        };
        let normalized = python_strip(explicit).to_lowercase();
        if normalized == FORMAT_AUTO {
            return Ok(None);
        }
        if !SUPPORTED_FORMATS.iter().any(|name| *name == normalized) {
            return Err(ResolveFormatError::UnknownFormat(unknown_format_message(
                explicit,
            )));
        }
        Ok(Some(explicit_success(normalized)))
    }

    fn explicit_success(normalized: String) -> FormatResolution {
        FormatResolution {
            format: normalized.clone(),
            result: DetectionResult {
                format: Some(normalized),
                confidences: Vec::new(),
                reason: REASON_EXPLICIT_OVERRIDE.to_owned(),
            },
            findings: Vec::new(),
        }
    }

    fn resolved_or_failure(
        result: DetectionResult,
        path_str: &str,
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> Result<FormatResolution, ResolveFormatError> {
        match result.format.clone() {
            Some(format) => Ok(FormatResolution {
                format,
                result,
                findings: Vec::new(),
            }),
            None => {
                let never =
                    _resolve_failure_finding(&result, path_str, confidence_min, margin_min)?;
                match never {}
            }
        }
    }

    fn forward_slash_path(path: &Path) -> String {
        displayed_path(path).text.replace('\\', "/")
    }

    fn unknown_format_message(explicit: &str) -> String {
        format!(
            "Unknown format {}. Must be one of {}",
            python_str_repr(explicit),
            sorted_valid_formats_repr()
        )
    }

    fn sorted_valid_formats_repr() -> String {
        let mut names = VALID_FORMAT_OPTIONS;
        names.sort_unstable();
        let mut out = String::from("[");
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            out.push_str(&python_str_repr(name));
        }
        out.push(']');
        out
    }

    /// Python `repr` for `str`, preferring single quotes.
    fn python_str_repr(value: &str) -> String {
        let quote = if value.contains('\'') && !value.contains('"') {
            '"'
        } else {
            '\''
        };
        let mut out = String::with_capacity(value.len().saturating_add(2));
        out.push(quote);
        for ch in value.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                found if found == quote => {
                    out.push('\\');
                    out.push(quote);
                }
                found if python_repr_literal(found) => out.push(found),
                found if u32::from(found) < 0x100 => push_hex(&mut out, "\\x", u32::from(found), 2),
                found if u32::from(found) < 0x10000 => {
                    push_hex(&mut out, "\\u", u32::from(found), 4);
                }
                found => push_hex(&mut out, "\\U", u32::from(found), 8),
            }
        }
        out.push(quote);
        out
    }

    fn python_repr_literal(ch: char) -> bool {
        if ch.is_ascii() {
            return ch == ' ' || ch.is_ascii_graphic();
        }
        !ch.is_control() && !matches!(ch, '\u{2028}' | '\u{2029}')
    }

    fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
        const HEX: [char; 16] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        out.push_str(prefix);
        for shift in (0..width).rev() {
            let Ok(shift_bits) = u32::try_from(shift) else {
                return;
            };
            let nibble = (value >> shift_bits.saturating_mul(4)) & 0x0f;
            let Ok(index) = usize::try_from(nibble) else {
                return;
            };
            let Some(ch) = HEX.get(index).copied() else {
                return;
            };
            out.push(ch);
        }
    }

    #[derive(Clone, Copy)]
    enum FailureKind {
        Refused,
        Empty,
        Ambiguous,
    }

    struct FailureLabels {
        code: &'static str,
        severity: Severity,
        repairability: Repairability,
        template: &'static str,
    }

    fn failure_kind(reason: &str) -> FailureKind {
        if reason == REASON_REFUSED_LIVE_DB {
            FailureKind::Refused
        } else if reason == REASON_EMPTY {
            FailureKind::Empty
        } else {
            FailureKind::Ambiguous
        }
    }

    fn failure_labels(kind: FailureKind) -> FailureLabels {
        match kind {
            FailureKind::Refused => FailureLabels {
                code: SL001,
                severity: Severity::Fatal,
                repairability: Repairability::Unsupported,
                template: REFUSED_LIVE_DB_TEMPLATE,
            },
            FailureKind::Empty => FailureLabels {
                code: SL001,
                severity: Severity::Error,
                repairability: Repairability::Manual,
                template: EMPTY_INPUT_TEMPLATE,
            },
            FailureKind::Ambiguous => FailureLabels {
                code: SL302,
                severity: Severity::Error,
                repairability: Repairability::Manual,
                template: AMBIGUOUS_FORMAT_TEMPLATE,
            },
        }
    }

    fn failure_evidence(
        result: &DetectionResult,
        kind: FailureKind,
        confidence_min: ThresholdInput<'_>,
        margin_min: ThresholdInput<'_>,
    ) -> PyValue {
        match kind {
            FailureKind::Refused => reason_only("refused_live_db"),
            FailureKind::Empty => reason_only("empty_input"),
            FailureKind::Ambiguous => PyValue::map(vec![
                (PyValue::string("reason"), PyValue::string(&result.reason)),
                (
                    PyValue::string("confidences"),
                    confidences_evidence(&result.confidences),
                ),
                (
                    PyValue::string("confidence_min"),
                    threshold_evidence(confidence_min),
                ),
                (
                    PyValue::string("margin_min"),
                    threshold_evidence(margin_min),
                ),
            ]),
        }
    }

    fn reason_only(reason: &str) -> PyValue {
        PyValue::map(vec![(PyValue::string("reason"), PyValue::string(reason))])
    }

    fn confidences_evidence(pairs: &[(String, f64)]) -> PyValue {
        PyValue::map(
            pairs
                .iter()
                .map(|(name, _score)| (PyValue::string(name.clone()), unrepresentable_float()))
                .collect(),
        )
    }

    /// Python `float` has no [`PyValue`] variant.
    ///
    /// The leaf is not an int, not a bool, and not a decimal string. `True`
    /// is not `1`. [`ThresholdInput::None`] is a different match arm.
    /// [`PyValue`] cannot store the IEEE value, so the key's leaf is
    /// [`PyValue::None`], the same stand-in `checks::size` uses when a float
    /// cannot be passed to [`make_finding`].
    fn unrepresentable_float() -> PyValue {
        PyValue::None
    }

    fn threshold_evidence(value: ThresholdInput<'_>) -> PyValue {
        match value {
            ThresholdInput::None => PyValue::None,
            ThresholdInput::Bool(flag) => PyValue::bool_value(flag),
            ThresholdInput::Int(number) => PyValue::int(number),
            ThresholdInput::Text(text) => PyValue::string(text),
            ThresholdInput::Float(_number) => unrepresentable_float(),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

        use super::super::{
            DetectError, ThresholdInput, CONFIDENCE_MIN, FORMAT_AUTO, FORMAT_CANONICAL,
            FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT, FORMAT_OPENAI_AGENTS, MARGIN_MIN,
            REASON_CLEAR_WINNER, REASON_EMPTY, REASON_EXPLICIT_OVERRIDE, REASON_LOW_CONFIDENCE,
            REASON_REFUSED_LIVE_DB, REASON_TIE,
        };
        use super::{
            _resolve_failure_finding, failure_evidence, failure_kind, failure_labels,
            forward_slash_path, python_str_repr, resolve_format, resolve_format_bytes,
            threshold_evidence, DetectionResult, FailureKind, FormatResolution, PyValue,
            ResolveFormatError, AMBIGUOUS_FORMAT_TEMPLATE, EMPTY_INPUT_TEMPLATE,
            REFUSED_LIVE_DB_TEMPLATE,
        };
        use crate::openai_agents::SQLITE_MAGIC;

        const SORTED_OPTIONS: &str =
            "['auto', 'canonical', 'claude-code-jsonl', 'codex-rollout', 'openai-agents']";
        const FINGERPRINT_SENTENCE: &str =
            "sesslint.determinism.canonical_json_bytes is not available";

        fn defaults() -> (ThresholdInput<'static>, ThresholdInput<'static>) {
            (
                ThresholdInput::Float(CONFIDENCE_MIN),
                ThresholdInput::Float(MARGIN_MIN),
            )
        }

        fn unknown_message(explicit: &str) -> String {
            format!(
                "Unknown format {}. Must be one of {SORTED_OPTIONS}",
                python_str_repr(explicit)
            )
        }

        struct TempPath {
            path: PathBuf,
            directory: bool,
        }

        impl Drop for TempPath {
            fn drop(&mut self) {
                if self.directory {
                    let _ = fs::remove_dir_all(&self.path);
                } else {
                    let _ = fs::remove_file(&self.path);
                }
            }
        }

        fn temp_path(label: &str, directory: bool) -> TempPath {
            static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            TempPath {
                path: std::env::temp_dir().join(format!("sesslint-detect-02-{label}-{n}")),
                directory,
            }
        }

        fn assert_fingerprint(err: &ResolveFormatError) {
            assert!(matches!(err, ResolveFormatError::Finding(_)));
            assert_eq!(err.to_string(), FINGERPRINT_SENTENCE);
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        }

        fn assert_explicit(resolved: &FormatResolution, format: &str) {
            assert_eq!(resolved.format, format);
            assert_eq!(resolved.result.format.as_deref(), Some(format));
            assert_eq!(resolved.result.reason, REASON_EXPLICIT_OVERRIDE);
            assert!(resolved.result.confidences.is_empty());
            assert!(resolved.findings.is_empty());
        }

        #[test]
        fn python_repr_matches_cpython_samples() {
            assert_eq!(python_str_repr("bogus"), "'bogus'");
            assert_eq!(python_str_repr("it's"), "\"it's\"");
            assert_eq!(python_str_repr("a\\b"), "'a\\\\b'");
            assert_eq!(python_str_repr("a\nb"), "'a\\nb'");
            assert_eq!(python_str_repr(""), "''");
            assert_eq!(python_str_repr("\u{001c}"), "'\\x1c'");
            assert_eq!(python_str_repr("  Bogus  "), "'  Bogus  '");
        }

        #[test]
        fn unknown_format_uses_repr_and_sorted_options() {
            let missing = Path::new("sesslint-detect-02-missing.json");
            let (confidence_min, margin_min) = defaults();
            for explicit in ["bogus", "yaml", "it's", "", "a\\b", "  Bogus  "] {
                let err = resolve_format(Some(explicit), missing, confidence_min, margin_min)
                    .expect_err("unknown");
                assert!(matches!(err, ResolveFormatError::UnknownFormat(_)));
                assert_eq!(err.to_string(), unknown_message(explicit));
            }
            let bytes_err = resolve_format_bytes(
                Some("bogus"),
                b"",
                "ignored.json",
                "",
                confidence_min,
                margin_min,
            )
            .expect_err("bytes unknown before empty");
            assert_eq!(
                bytes_err.to_string(),
                format!("Unknown format 'bogus'. Must be one of {SORTED_OPTIONS}")
            );
        }

        #[test]
        fn explicit_override_is_pure_and_returns_empty_findings() {
            let directory = temp_path("explicit-dir", true);
            fs::create_dir(&directory.path).expect("dir");
            let (confidence_min, margin_min) = defaults();
            let resolved = resolve_format(
                Some("Canonical"),
                &directory.path,
                confidence_min,
                margin_min,
            )
            .expect("explicit skips the directory");
            assert_explicit(&resolved, FORMAT_CANONICAL);

            let mixed = resolve_format_bytes(
                Some("  Claude-Code-JSONL \t"),
                b"",
                "ignored.json",
                "",
                ThresholdInput::Float(0.99),
                ThresholdInput::Float(0.99),
            )
            .expect("explicit skips bytes");
            assert_explicit(&mixed, FORMAT_CLAUDE_CODE);

            let spaced = resolve_format(
                Some("\u{001c}openai-agents"),
                Path::new("sesslint-detect-02-missing.json"),
                confidence_min,
                margin_min,
            )
            .expect("python strip");
            assert_explicit(&spaced, FORMAT_OPENAI_AGENTS);

            let codex = resolve_format_bytes(
                Some(FORMAT_CODEX_ROLLOUT),
                SQLITE_MAGIC,
                "session.sqlite",
                "virtual/session.sqlite",
                confidence_min,
                margin_min,
            )
            .expect("explicit skips sqlite");
            assert_explicit(&codex, FORMAT_CODEX_ROLLOUT);
        }

        #[test]
        fn thresholds_are_checked_before_the_name_and_the_file() {
            let missing = Path::new("sesslint-detect-02-missing.json");
            let high = resolve_format(
                Some(FORMAT_CANONICAL),
                missing,
                ThresholdInput::Float(2.0),
                ThresholdInput::Float(MARGIN_MIN),
            )
            .expect_err("high");
            assert_eq!(
                high.to_string(),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 2.0"
            );
            assert!(matches!(high, ResolveFormatError::Detect(DetectError::Value(_))));

            let margin = resolve_format(
                Some("bogus"),
                missing,
                ThresholdInput::Float(0.5),
                ThresholdInput::Float(0.9),
            )
            .expect_err("margin");
            assert_eq!(
                margin.to_string(),
                "margin_min (0.9) cannot exceed confidence_min (0.5)"
            );

            let bool_before_name = resolve_format_bytes(
                Some("bogus"),
                b"",
                "x.json",
                "stdin",
                ThresholdInput::Bool(true),
                ThresholdInput::Bool(false),
            )
            .expect_err("bool before name");
            assert_eq!(
                bool_before_name.to_string(),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got True"
            );
        }

        #[test]
        fn bool_is_not_an_int() {
            let missing = Path::new("sesslint-detect-02-missing.json");
            let truth = resolve_format(
                Some(FORMAT_CANONICAL),
                missing,
                ThresholdInput::Bool(true),
                ThresholdInput::Int(1),
            )
            .expect_err("true");
            assert_eq!(
                truth.to_string(),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got True"
            );
            let one = resolve_format(
                Some(FORMAT_CANONICAL),
                missing,
                ThresholdInput::Int(1),
                ThresholdInput::Float(MARGIN_MIN),
            )
            .expect_err("one");
            assert_eq!(
                one.to_string(),
                "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1"
            );
            let false_bit = resolve_format(
                Some(FORMAT_CANONICAL),
                missing,
                ThresholdInput::Float(CONFIDENCE_MIN),
                ThresholdInput::Bool(false),
            )
            .expect_err("false");
            assert_eq!(
                false_bit.to_string(),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got False"
            );
            let zero = resolve_format(
                Some(FORMAT_CANONICAL),
                missing,
                ThresholdInput::Float(CONFIDENCE_MIN),
                ThresholdInput::Int(0),
            )
            .expect_err("zero");
            assert_eq!(
                zero.to_string(),
                "margin_min must be strictly between 0.0 and 1.0 exclusive, got 0"
            );
            assert_ne!(truth.to_string(), one.to_string());
            assert_ne!(false_bit.to_string(), zero.to_string());
        }

        #[test]
        fn auto_and_none_return_a_clear_winner_with_empty_findings() {
            let file = temp_path("canonical", false);
            fs::write(&file.path, br#"{"schema": "sesslint.session/v1"}"#).expect("write");
            let (confidence_min, margin_min) = defaults();
            let from_none =
                resolve_format(None, &file.path, confidence_min, margin_min).expect("none");
            let from_auto = resolve_format(Some(FORMAT_AUTO), &file.path, confidence_min, margin_min)
                .expect("auto");
            assert_eq!(from_none, from_auto);
            assert_eq!(from_none.format, FORMAT_CANONICAL);
            assert_eq!(from_none.result.reason, REASON_CLEAR_WINNER);
            assert!(from_none.findings.is_empty());

            let spaced_auto = resolve_format(
                Some(" AUTO\t"),
                &file.path,
                confidence_min,
                margin_min,
            )
            .expect("spaced auto");
            assert_eq!(spaced_auto, from_none);

            let from_bytes = resolve_format_bytes(
                None,
                br#"{"schema": "sesslint.session/v1"}"#,
                "notes.txt",
                "virtual/session.json",
                confidence_min,
                margin_min,
            )
            .expect("bytes");
            assert_eq!(from_bytes.format, FORMAT_CANONICAL);
            assert_eq!(from_bytes.result.reason, REASON_CLEAR_WINNER);
            assert!(from_bytes.findings.is_empty());
        }

        #[test]
        fn unresolved_detection_propagates_the_fingerprint_error() {
            let (confidence_min, margin_min) = defaults();
            let empty = resolve_format_bytes(
                None,
                b"",
                "empty.jsonl",
                "virtual/empty.jsonl",
                confidence_min,
                margin_min,
            )
            .expect_err("empty");
            assert_fingerprint(&empty);

            let whitespace = resolve_format_bytes(
                Some("auto"),
                b"   \n\t  \r\n   ",
                "whitespace.json",
                "virtual/whitespace.json",
                confidence_min,
                margin_min,
            )
            .expect_err("whitespace");
            assert_fingerprint(&whitespace);

            let sqlite = resolve_format_bytes(
                None,
                SQLITE_MAGIC,
                "session.sqlite",
                "virtual/session.sqlite",
                confidence_min,
                margin_min,
            )
            .expect_err("sqlite");
            assert_fingerprint(&sqlite);

            let low = resolve_format_bytes(
                Some(FORMAT_AUTO),
                b"random unstructured log",
                "random.txt",
                "virtual/random.txt",
                confidence_min,
                margin_min,
            )
            .expect_err("low");
            assert_fingerprint(&low);

            let file = temp_path("empty-file", false);
            fs::write(&file.path, b"").expect("write");
            let from_file =
                resolve_format(None, &file.path, confidence_min, margin_min).expect_err("file");
            assert_fingerprint(&from_file);
        }

        #[test]
        fn none_threshold_reaches_comparison_only_after_the_early_gates() {
            let empty = resolve_format_bytes(
                None,
                b" \t",
                "blank.txt",
                "virtual/blank.txt",
                ThresholdInput::None,
                ThresholdInput::None,
            )
            .expect_err("empty before compare");
            assert_fingerprint(&empty);

            let compared = resolve_format_bytes(
                Some(FORMAT_AUTO),
                b"x",
                "random.txt",
                "virtual/random.txt",
                ThresholdInput::None,
                ThresholdInput::Float(MARGIN_MIN),
            )
            .expect_err("none confidence");
            assert_eq!(
                compared.to_string(),
                "'<' not supported between instances of 'float' and 'NoneType'"
            );
            assert!(matches!(
                compared,
                ResolveFormatError::Detect(DetectError::Type(_))
            ));

            let explicit = resolve_format(
                Some(FORMAT_CANONICAL),
                Path::new("sesslint-detect-02-missing.json"),
                ThresholdInput::None,
                ThresholdInput::None,
            )
            .expect("none is skipped before the explicit return");
            assert_explicit(&explicit, FORMAT_CANONICAL);
        }

        #[test]
        fn missing_path_and_directory_propagate_detect_errors() {
            let missing = Path::new("sesslint-detect-02-missing.json");
            let (confidence_min, margin_min) = defaults();
            let err = resolve_format(Some(" auto "), missing, confidence_min, margin_min)
                .expect_err("missing");
            assert_eq!(err.to_string(), "Session file not found: sesslint-detect-02-missing.json");
            assert!(matches!(err, ResolveFormatError::Detect(DetectError::NotFound(_))));

            let directory = temp_path("dir", true);
            fs::create_dir(&directory.path).expect("dir");
            let dir_err = resolve_format(None, &directory.path, confidence_min, margin_min)
                .expect_err("dir");
            assert!(dir_err
                .to_string()
                .starts_with("Expected session file, got directory: "));
            assert!(matches!(
                dir_err,
                ResolveFormatError::Detect(DetectError::IsADirectory(_))
            ));
        }

        #[test]
        fn failure_branches_select_only_sl001_and_sl302() {
            let refused = failure_labels(failure_kind(REASON_REFUSED_LIVE_DB));
            assert_eq!(refused.code, "SL001");
            assert_eq!(refused.severity, model::codes::Severity::Fatal);
            assert_eq!(
                refused.repairability,
                model::codes::Repairability::Unsupported
            );
            assert_eq!(
                refused.template,
                "Refused live SQLite database; SessLint requires exported items or checkpoints [detail: refused_live_db]"
            );
            assert_eq!(REFUSED_LIVE_DB_TEMPLATE, refused.template);

            let empty = failure_labels(failure_kind(REASON_EMPTY));
            assert_eq!(empty.code, "SL001");
            assert_eq!(empty.severity, model::codes::Severity::Error);
            assert_eq!(empty.repairability, model::codes::Repairability::Manual);
            assert_eq!(empty.template, "Session input is empty [detail: EMPTY]");
            assert_eq!(EMPTY_INPUT_TEMPLATE, empty.template);

            for reason in [REASON_TIE, REASON_LOW_CONFIDENCE, REASON_CLEAR_WINNER, "other"] {
                let ambiguous = failure_labels(failure_kind(reason));
                assert_eq!(ambiguous.code, "SL302");
                assert_eq!(ambiguous.severity, model::codes::Severity::Error);
                assert_eq!(
                    ambiguous.repairability,
                    model::codes::Repairability::Manual
                );
                assert_eq!(
                    ambiguous.template,
                    "Unable to determine session format with sufficient confidence [detail: ambiguous_format]"
                );
                assert_eq!(AMBIGUOUS_FORMAT_TEMPLATE, ambiguous.template);
            }

            let tie = DetectionResult {
                format: None,
                confidences: vec![
                    (FORMAT_CLAUDE_CODE.to_owned(), 0.70),
                    (FORMAT_OPENAI_AGENTS.to_owned(), 0.60),
                    (FORMAT_CODEX_ROLLOUT.to_owned(), 0.0),
                    (FORMAT_CANONICAL.to_owned(), 0.0),
                ],
                reason: REASON_TIE.to_owned(),
            };
            let err = _resolve_failure_finding(
                &tie,
                "session.jsonl",
                ThresholdInput::Float(CONFIDENCE_MIN),
                ThresholdInput::None,
            )
            .expect_err("tie");
            assert_eq!(err.to_string(), FINGERPRINT_SENTENCE);

            let blank = _resolve_failure_finding(
                &tie,
                "  ",
                ThresholdInput::Float(CONFIDENCE_MIN),
                ThresholdInput::Float(MARGIN_MIN),
            )
            .expect_err("blank path");
            assert_eq!(
                blank.to_string(),
                "SourceRef.path must be a non-empty string, got '  '"
            );
            assert_ne!(blank.to_string(), FINGERPRINT_SENTENCE);
        }

        #[test]
        fn evidence_keeps_bool_distinct_and_does_not_store_a_float_as_an_int() {
            assert_eq!(
                threshold_evidence(ThresholdInput::Bool(true)),
                PyValue::bool_value(true)
            );
            assert_ne!(
                threshold_evidence(ThresholdInput::Bool(true)),
                PyValue::int(1)
            );
            assert_eq!(threshold_evidence(ThresholdInput::Int(1)), PyValue::int(1));
            assert_ne!(
                threshold_evidence(ThresholdInput::Int(1)),
                PyValue::bool_value(true)
            );
            assert_eq!(
                threshold_evidence(ThresholdInput::Bool(false)),
                PyValue::bool_value(false)
            );
            assert_ne!(
                threshold_evidence(ThresholdInput::Bool(false)),
                PyValue::int(0)
            );
            assert_eq!(threshold_evidence(ThresholdInput::Int(0)), PyValue::int(0));
            assert_eq!(threshold_evidence(ThresholdInput::None), PyValue::None);
            assert_eq!(
                threshold_evidence(ThresholdInput::Text("True")),
                PyValue::string("True")
            );
            let float_leaf = threshold_evidence(ThresholdInput::Float(CONFIDENCE_MIN));
            assert!(!matches!(
                float_leaf,
                PyValue::Int(_) | PyValue::Bool(_) | PyValue::Str(_)
            ));

            let refused = DetectionResult {
                format: None,
                confidences: vec![(FORMAT_CANONICAL.to_owned(), 0.0)],
                reason: REASON_REFUSED_LIVE_DB.to_owned(),
            };
            assert_eq!(
                failure_evidence(
                    &refused,
                    FailureKind::Refused,
                    ThresholdInput::Bool(true),
                    ThresholdInput::Int(1),
                ),
                PyValue::map(vec![(
                    PyValue::string("reason"),
                    PyValue::string("refused_live_db")
                )])
            );

            let tie = DetectionResult {
                format: None,
                confidences: vec![
                    (FORMAT_CLAUDE_CODE.to_owned(), 0.70),
                    (FORMAT_CANONICAL.to_owned(), 0.60),
                ],
                reason: REASON_TIE.to_owned(),
            };
            let evidence = failure_evidence(
                &tie,
                failure_kind(REASON_TIE),
                ThresholdInput::Float(0.70),
                ThresholdInput::None,
            );
            let PyValue::Map(entries) = evidence else {
                panic!("evidence map");
            };
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[0].0, PyValue::string("reason"));
            assert_eq!(entries[0].1, PyValue::string(REASON_TIE));
            assert_eq!(entries[1].0, PyValue::string("confidences"));
            let PyValue::Map(scores) = &entries[1].1 else {
                panic!("confidences map");
            };
            assert_eq!(scores[0].0, PyValue::string(FORMAT_CLAUDE_CODE));
            assert_eq!(scores[1].0, PyValue::string(FORMAT_CANONICAL));
            assert!(scores.iter().all(|(_, score)| !matches!(
                score,
                PyValue::Int(_) | PyValue::Bool(_) | PyValue::Str(_)
            )));
            assert_eq!(entries[2].0, PyValue::string("confidence_min"));
            assert!(!matches!(
                entries[2].1,
                PyValue::Int(_) | PyValue::Bool(_) | PyValue::Str(_)
            ));
            assert_eq!(entries[3].0, PyValue::string("margin_min"));
            assert_eq!(entries[3].1, PyValue::None);
        }

        #[test]
        fn finding_path_uses_forward_slashes() {
            assert_eq!(forward_slash_path(Path::new("")), ".");
            assert_eq!(forward_slash_path(Path::new("foo/bar")), "foo/bar");
            assert_eq!(forward_slash_path(Path::new("foo\\bar")), "foo/bar");
            assert_eq!(forward_slash_path(Path::new("foo/../bar")), "foo/../bar");
        }
    }
}

pub use resolve_port::{
    _resolve_failure_finding, resolve_format, resolve_format_bytes, FormatResolution,
    ResolveFormatError,
};
