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
