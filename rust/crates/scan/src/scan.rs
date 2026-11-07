//! Scan summary types for one file and for aggregated rows (TASK-024, T-08).
//!
//! Port of `src/sesslint/scan.py` lines 1–280
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Stops before `ScanReport`. This module does not walk a directory, does not
//! open sqlite, and does not link the report crate. `aggregate_scan` is past
//! the pin slice and is not implemented here.
//!
//! # Recorded gaps
//!
//! * A bool is not an int. `SessionLink.line`, `error_count`, `warning_count`,
//!   and `max_findings_per_code` reject `True` and `False`. They are not `1`
//!   and `0`.
//! * `cache_hit` rejects an int. `1` is not `True`. `0` is not `False`.
//!   A missing value and `None` follow `bool(...)` and are false.
//! * [`FileResult::to_dict`] and [`WorstFileRow::to_dict`] call
//!   `sesslint.report.minimize_path` before any later report helper. Display
//!   is [`MINIMIZE_PATH_UNAVAILABLE`]. The path is not rewritten and findings
//!   are not formatted.
//! * Bucket counts are `i64`. [`ScanTotals::total`] uses the mathematical sum.
//!   A sum outside `i64` is [`TotalOverflow`] and is not wrapped.

use std::error::Error;
use std::fmt;

use model::errors::FindingError;
use model::finding::{DictValue, Finding};

/// Python: `DEFAULT_MAX_FILES = 10000`.
pub const DEFAULT_MAX_FILES: i64 = 10_000;

/// Python: `DEFAULT_MAX_BYTES = 1024 * 1024 * 1024`.
pub const DEFAULT_MAX_BYTES: i64 = 1024 * 1024 * 1024;

/// Dataclass default for `FileResult.max_findings_per_code`.
const DEFAULT_MAX_FINDINGS_PER_CODE: i64 = 20;

/// `sesslint.report.minimize_path` is not linked from this crate.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// Insertion-ordered dictionary. This is not `serde_json` and not a `BTreeMap`.
pub type ScanDict = Vec<(&'static str, DictValue)>;

/// Python: `Verdict = Literal["healthy", "invalid", "unsupported", "unreadable", "skipped"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    Healthy,
    Invalid,
    Unsupported,
    Unreadable,
    Skipped,
}

impl Verdict {
    /// Python literal value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
            Self::Unreadable => "unreadable",
            Self::Skipped => "skipped",
        }
    }

    /// Accept only the five pinned buckets.
    ///
    /// Any other string is [`UnknownVerdict`]. It is not stored as a sixth
    /// bucket and it is not rewritten to `skipped`.
    pub const fn parse(text: &str) -> Result<Self, UnknownVerdict> {
        match text.as_bytes() {
            b"healthy" => Ok(Self::Healthy),
            b"invalid" => Ok(Self::Invalid),
            b"unsupported" => Ok(Self::Unsupported),
            b"unreadable" => Ok(Self::Unreadable),
            b"skipped" => Ok(Self::Skipped),
            _ => Err(UnknownVerdict),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A verdict string outside the five pinned buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownVerdict;

impl fmt::Display for UnknownVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("verdict must be healthy, invalid, unsupported, unreadable, or skipped")
    }
}

impl Error for UnknownVerdict {}

/// `sesslint.report.minimize_path` is not available in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimizePathUnavailable;

impl fmt::Display for MinimizePathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MINIMIZE_PATH_UNAVAILABLE)
    }
}

impl Error for MinimizePathUnavailable {}

/// The five bucket counts sum to a value `i64` cannot store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotalOverflow;

impl fmt::Display for TotalOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scan total exceeds i64")
    }
}

impl Error for TotalOverflow {}

/// A dictionary passed to [`SessionLink::from_dict`] or [`FileResult::from_wire`]
/// does not match the pinned constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanDictError {
    /// Python `KeyError` for a required mapping key. Display is `'key'`.
    MissingKey(&'static str),
    /// A bool was supplied where an int is required.
    NotAnInt {
        /// Attribute name, such as `SessionLink.line`.
        field: &'static str,
    },
    /// An int was supplied where a bool is required.
    NotABool {
        /// Attribute name, such as `FileResult.cache_hit`.
        field: &'static str,
    },
    /// The value is present and has the wrong shape.
    Type {
        /// Attribute or key the constructor was reading.
        field: &'static str,
        /// Expected Python kinds, without a guessed coercion.
        expected: &'static str,
    },
    /// `verdict` is a string outside the five buckets.
    Verdict(UnknownVerdict),
    /// A link or finding item is not a mapping.
    NotAMapping {
        /// `FileResult.links` or `FileResult.findings`.
        field: &'static str,
    },
    /// `links` or `findings` is present and is not a list or tuple.
    NotAList {
        /// `FileResult.links` or `FileResult.findings`.
        field: &'static str,
    },
    /// [`Finding::from_dict`] rejected one findings item.
    Finding(FindingError),
}

impl fmt::Display for ScanDictError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(key) => write!(formatter, "'{key}'"),
            Self::NotAnInt { field } => write!(formatter, "{field} bool is not an int"),
            Self::NotABool { field } => write!(formatter, "{field} int is not a bool"),
            Self::Type { field, expected } => {
                write!(formatter, "{field} must be {expected}")
            }
            Self::Verdict(err) => write!(formatter, "{err}"),
            Self::NotAMapping { field } => write!(formatter, "{field} must be a mapping"),
            Self::NotAList { field } => write!(formatter, "{field} must be a list or tuple"),
            Self::Finding(err) => write!(formatter, "{err}"),
        }
    }
}

impl Error for ScanDictError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(err) => Some(err),
            Self::Verdict(err) => Some(err),
            Self::MissingKey(_)
            | Self::NotAnInt { .. }
            | Self::NotABool { .. }
            | Self::Type { .. }
            | Self::NotAMapping { .. }
            | Self::NotAList { .. } => None,
        }
    }
}

/// Bounded cross-file resume pointer (SL401).
///
/// `target` is a structural identifier. This type does not read a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLink {
    pub kind: String,
    pub target: String,
    pub record_id: Option<String>,
    pub line: Option<i64>,
}

impl SessionLink {
    /// `record_id` and `line` start as `None`, matching the dataclass defaults.
    #[must_use]
    pub fn new(kind: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            target: target.into(),
            record_id: None,
            line: None,
        }
    }

    /// Python: `SessionLink.to_dict`. Keys stay in the literal order.
    #[must_use]
    pub fn to_dict(&self) -> ScanDict {
        vec![
            ("kind", DictValue::Str(self.kind.clone())),
            ("line", optional_int(self.line)),
            ("record_id", optional_text(&self.record_id)),
            ("target", DictValue::Str(self.target.clone())),
        ]
    }

    /// Python: `SessionLink.from_dict`.
    ///
    /// `kind` and `target` use `str` on a string, an int, a bool, or `None`.
    /// `record_id` stays a string or `None`. `line` stays an int or `None`.
    /// A bool line is rejected. The last duplicate key wins.
    pub fn from_dict<K: AsRef<str>>(entries: &[(K, DictValue)]) -> Result<Self, ScanDictError> {
        let kind = required_python_str(entries, "kind")?;
        let target = required_python_str(entries, "target")?;
        let record_id = optional_record_id(entries)?;
        let line = optional_line(entries)?;
        Ok(Self {
            kind,
            target,
            record_id,
            line,
        })
    }
}

/// Outcome of scanning one file artifact.
///
/// Construction stores the fields the caller already has. It does not scan
/// the path and it does not open the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    pub path: String,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub skipped_reason: Option<String>,
    pub error_count: i64,
    pub warning_count: i64,
    pub cache_hit: bool,
    pub links: Vec<SessionLink>,
    pub session_id: Option<String>,
    pub tip_id: Option<String>,
    pub detected_format: Option<String>,
    pub max_findings_per_code: i64,
}

impl FileResult {
    /// Dataclass defaults: no findings, no links, counts at `0`, `cache_hit`
    /// false, and [`DEFAULT_MAX_FINDINGS_PER_CODE`].
    #[must_use]
    pub fn new(path: impl Into<String>, verdict: Verdict) -> Self {
        Self {
            path: path.into(),
            verdict,
            findings: Vec::new(),
            skipped_reason: None,
            error_count: 0,
            warning_count: 0,
            cache_hit: false,
            links: Vec::new(),
            session_id: None,
            tip_id: None,
            detected_format: None,
            max_findings_per_code: DEFAULT_MAX_FINDINGS_PER_CODE,
        }
    }

    /// Python: `FileResult.to_dict`.
    ///
    /// The body imports `minimize_path` and calls it while building `path`.
    /// That function is not available here, so this returns
    /// [`MINIMIZE_PATH_UNAVAILABLE`] before `finding_report_sort_key` or
    /// `format_finding_content_free`. No report dictionary is returned.
    pub fn to_dict(&self) -> Result<ScanDict, MinimizePathUnavailable> {
        let _bound = (
            self.path.as_str(),
            self.verdict,
            self.findings.len(),
            self.skipped_reason.as_deref(),
            self.error_count,
            self.warning_count,
            self.cache_hit,
            self.links.len(),
            self.session_id.as_deref(),
            self.tip_id.as_deref(),
            self.detected_format.as_deref(),
            self.max_findings_per_code,
        );
        Err(MinimizePathUnavailable)
    }

    /// Python: `FileResult.to_wire`.
    ///
    /// The path is copied verbatim. Findings use the ported
    /// [`Finding::to_dict`]. Links use [`SessionLink::to_dict`].
    #[must_use]
    pub fn to_wire(&self) -> ScanDict {
        vec![
            ("path", DictValue::Str(self.path.clone())),
            ("verdict", DictValue::Str(self.verdict.as_str().to_owned())),
            ("skipped_reason", optional_text(&self.skipped_reason)),
            ("error_count", DictValue::Int(self.error_count)),
            ("warning_count", DictValue::Int(self.warning_count)),
            ("cache_hit", DictValue::Bool(self.cache_hit)),
            (
                "links",
                DictValue::List(
                    self.links
                        .iter()
                        .map(|link| as_map(link.to_dict()))
                        .collect(),
                ),
            ),
            ("session_id", optional_text(&self.session_id)),
            ("tip_id", optional_text(&self.tip_id)),
            ("detected_format", optional_text(&self.detected_format)),
            (
                "max_findings_per_code",
                DictValue::Int(self.max_findings_per_code),
            ),
            (
                "findings",
                DictValue::List(
                    self.findings
                        .iter()
                        .map(|finding| as_map(finding.to_dict()))
                        .collect(),
                ),
            ),
        ]
    }

    /// Python: `FileResult.from_wire`.
    ///
    /// Required keys are `path` and `verdict`. Counts default to `0`.
    /// `max_findings_per_code` defaults to [`DEFAULT_MAX_FINDINGS_PER_CODE`].
    /// Missing `links` and `findings` are empty. An explicit `None` for those
    /// lists is not treated as empty. A bool is not used as an int. An int is
    /// not used as `cache_hit`. The last duplicate key wins.
    pub fn from_wire<K: AsRef<str>>(entries: &[(K, DictValue)]) -> Result<Self, ScanDictError> {
        let path = required_text(entries, "path")?;
        let verdict_text = required_text(entries, "verdict")?;
        let verdict = Verdict::parse(&verdict_text).map_err(ScanDictError::Verdict)?;
        let skipped_reason = optional_text_field(entries, "skipped_reason")?;
        let error_count = int_or(entries, "error_count", "FileResult.error_count", 0)?;
        let warning_count = int_or(entries, "warning_count", "FileResult.warning_count", 0)?;
        let cache_hit = cache_hit_field(entries)?;
        let links = links_field(entries)?;
        let session_id = optional_text_field(entries, "session_id")?;
        let tip_id = optional_text_field(entries, "tip_id")?;
        let detected_format = optional_text_field(entries, "detected_format")?;
        let max_findings_per_code = int_or(
            entries,
            "max_findings_per_code",
            "FileResult.max_findings_per_code",
            DEFAULT_MAX_FINDINGS_PER_CODE,
        )?;
        let findings = findings_field(entries)?;
        Ok(Self {
            path,
            verdict,
            findings,
            skipped_reason,
            error_count,
            warning_count,
            cache_hit,
            links,
            session_id,
            tip_id,
            detected_format,
            max_findings_per_code,
        })
    }
}

/// Five mutually exclusive scan buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanTotals {
    pub healthy: i64,
    pub invalid: i64,
    pub unsupported: i64,
    pub unreadable: i64,
    pub skipped: i64,
}

impl ScanTotals {
    /// Python: `ScanTotals.total`.
    ///
    /// The sum is `healthy + invalid + unsupported + unreadable + skipped`.
    /// Addition uses `i128`, so a pair that overflows `i64` on the way to a
    /// representable total still succeeds. A total outside `i64` is
    /// [`TotalOverflow`].
    pub fn total(self) -> Result<i64, TotalOverflow> {
        let sum = i128::from(self.healthy)
            + i128::from(self.invalid)
            + i128::from(self.unsupported)
            + i128::from(self.unreadable)
            + i128::from(self.skipped);
        i64::try_from(sum).map_err(|_| TotalOverflow)
    }

    /// Python: `ScanTotals.to_dict`. Keys stay in the literal order.
    pub fn to_dict(self) -> Result<ScanDict, TotalOverflow> {
        let total = self.total()?;
        Ok(vec![
            ("healthy", DictValue::Int(self.healthy)),
            ("invalid", DictValue::Int(self.invalid)),
            ("skipped", DictValue::Int(self.skipped)),
            ("total", DictValue::Int(total)),
            ("unreadable", DictValue::Int(self.unreadable)),
            ("unsupported", DictValue::Int(self.unsupported)),
        ])
    }
}

/// One aggregated rule-code row.
///
/// `code` and `severity` are stored as given. This type does not look the
/// code up and does not assign a severity rank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByCodeRow {
    pub code: String,
    pub severity: String,
    pub count: i64,
    pub files: i64,
}

impl ByCodeRow {
    /// Python: `ByCodeRow.to_dict`. Keys stay in the literal order.
    #[must_use]
    pub fn to_dict(&self) -> ScanDict {
        vec![
            ("code", DictValue::Str(self.code.clone())),
            ("count", DictValue::Int(self.count)),
            ("files", DictValue::Int(self.files)),
            ("severity", DictValue::Str(self.severity.clone())),
        ]
    }
}

/// One worst-file row ranked by the caller.
///
/// `path` is the stored path. Minimizing it is [`Self::to_dict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorstFileRow {
    pub path: String,
    pub error_count: i64,
    pub warning_count: i64,
}

impl WorstFileRow {
    /// Python: `WorstFileRow.to_dict`.
    ///
    /// The body calls `sesslint.report.minimize_path`. That function is not
    /// available here. The stored path is left unchanged and no row dictionary
    /// is returned.
    pub fn to_dict(&self) -> Result<ScanDict, MinimizePathUnavailable> {
        let _bound = (self.path.as_str(), self.error_count, self.warning_count);
        Err(MinimizePathUnavailable)
    }
}

/// Presentation-layer aggregation over file results.
///
/// Row order is the order the caller stored. This type does not sort and does
/// not count findings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanSummary {
    pub by_code: Vec<ByCodeRow>,
    pub worst_files: Vec<WorstFileRow>,
}

impl ScanSummary {
    /// Python: `ScanSummary.to_dict`.
    ///
    /// `by_code` rows only build dictionaries. Each worst-file row calls
    /// [`WorstFileRow::to_dict`]. An empty `worst_files` list does not call
    /// `minimize_path`. A non-empty list stops at
    /// [`MINIMIZE_PATH_UNAVAILABLE`] and does not return a partial dictionary.
    pub fn to_dict(&self) -> Result<ScanDict, MinimizePathUnavailable> {
        let by_code = DictValue::List(
            self.by_code
                .iter()
                .map(|row| as_map(row.to_dict()))
                .collect(),
        );
        let mut worst_files = Vec::with_capacity(self.worst_files.len());
        for row in &self.worst_files {
            worst_files.push(as_map(row.to_dict()?));
        }
        Ok(vec![
            ("by_code", by_code),
            ("worst_files", DictValue::List(worst_files)),
        ])
    }
}

fn as_map(entries: ScanDict) -> DictValue {
    DictValue::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn optional_int(value: Option<i64>) -> DictValue {
    match value {
        Some(number) => DictValue::Int(number),
        None => DictValue::None,
    }
}

fn optional_text(value: &Option<String>) -> DictValue {
    match value {
        Some(text) => DictValue::Str(text.clone()),
        None => DictValue::None,
    }
}

fn lookup<'a, K: AsRef<str>>(entries: &'a [(K, DictValue)], key: &str) -> Option<&'a DictValue> {
    entries
        .iter()
        .rev()
        .find(|(entry_key, _)| entry_key.as_ref() == key)
        .map(|(_, value)| value)
}

fn required_text<K: AsRef<str>>(
    entries: &[(K, DictValue)],
    key: &'static str,
) -> Result<String, ScanDictError> {
    match lookup(entries, key) {
        None => Err(ScanDictError::MissingKey(key)),
        Some(DictValue::Str(text)) => Ok(text.clone()),
        Some(_) => Err(ScanDictError::Type {
            field: key,
            expected: "a str",
        }),
    }
}

fn required_python_str<K: AsRef<str>>(
    entries: &[(K, DictValue)],
    key: &'static str,
) -> Result<String, ScanDictError> {
    match lookup(entries, key) {
        None => Err(ScanDictError::MissingKey(key)),
        Some(value) => python_str_scalar(value).ok_or(ScanDictError::Type {
            field: key,
            expected: "a str, int, bool, or None",
        }),
    }
}

fn python_str_scalar(value: &DictValue) -> Option<String> {
    match value {
        DictValue::Str(text) => Some(text.clone()),
        DictValue::Int(number) => Some(number.to_string()),
        DictValue::Bool(true) => Some("True".to_owned()),
        DictValue::Bool(false) => Some("False".to_owned()),
        DictValue::None => Some("None".to_owned()),
        DictValue::Bytes(_)
        | DictValue::List(_)
        | DictValue::Tuple(_)
        | DictValue::Set(_)
        | DictValue::FrozenSet(_)
        | DictValue::Map(_) => None,
    }
}

fn optional_record_id<K: AsRef<str>>(
    entries: &[(K, DictValue)],
) -> Result<Option<String>, ScanDictError> {
    match lookup(entries, "record_id") {
        None | Some(DictValue::None) => Ok(None),
        Some(DictValue::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ScanDictError::Type {
            field: "SessionLink.record_id",
            expected: "a str or None",
        }),
    }
}

fn optional_line<K: AsRef<str>>(entries: &[(K, DictValue)]) -> Result<Option<i64>, ScanDictError> {
    match lookup(entries, "line") {
        None | Some(DictValue::None) => Ok(None),
        Some(DictValue::Int(number)) => Ok(Some(*number)),
        Some(DictValue::Bool(_)) => Err(ScanDictError::NotAnInt {
            field: "SessionLink.line",
        }),
        Some(_) => Err(ScanDictError::Type {
            field: "SessionLink.line",
            expected: "an int or None",
        }),
    }
}

fn optional_text_field<K: AsRef<str>>(
    entries: &[(K, DictValue)],
    key: &'static str,
) -> Result<Option<String>, ScanDictError> {
    match lookup(entries, key) {
        None | Some(DictValue::None) => Ok(None),
        Some(DictValue::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ScanDictError::Type {
            field: key,
            expected: "a str or None",
        }),
    }
}

fn int_or<K: AsRef<str>>(
    entries: &[(K, DictValue)],
    key: &'static str,
    field: &'static str,
    default: i64,
) -> Result<i64, ScanDictError> {
    match lookup(entries, key) {
        None => Ok(default),
        Some(DictValue::Int(number)) => Ok(*number),
        Some(DictValue::Bool(_)) => Err(ScanDictError::NotAnInt { field }),
        Some(_) => Err(ScanDictError::Type {
            field,
            expected: "an int",
        }),
    }
}

fn cache_hit_field<K: AsRef<str>>(entries: &[(K, DictValue)]) -> Result<bool, ScanDictError> {
    match lookup(entries, "cache_hit") {
        None | Some(DictValue::None) => Ok(false),
        Some(DictValue::Bool(value)) => Ok(*value),
        Some(DictValue::Int(_)) => Err(ScanDictError::NotABool {
            field: "FileResult.cache_hit",
        }),
        Some(_) => Err(ScanDictError::Type {
            field: "FileResult.cache_hit",
            expected: "a bool",
        }),
    }
}

fn links_field<K: AsRef<str>>(
    entries: &[(K, DictValue)],
) -> Result<Vec<SessionLink>, ScanDictError> {
    let Some(items) = sequence(entries, "links", "FileResult.links")? else {
        return Ok(Vec::new());
    };
    let mut links = Vec::with_capacity(items.len());
    for item in items {
        let map = expect_map(item, "FileResult.links")?;
        links.push(SessionLink::from_dict(map)?);
    }
    Ok(links)
}

fn findings_field<K: AsRef<str>>(
    entries: &[(K, DictValue)],
) -> Result<Vec<Finding>, ScanDictError> {
    let Some(items) = sequence(entries, "findings", "FileResult.findings")? else {
        return Ok(Vec::new());
    };
    let mut findings = Vec::with_capacity(items.len());
    for item in items {
        let map = expect_map(item, "FileResult.findings")?;
        let borrowed: Vec<(&str, DictValue)> = map
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        findings.push(Finding::from_dict(&borrowed).map_err(ScanDictError::Finding)?);
    }
    Ok(findings)
}

fn sequence<'a, K: AsRef<str>>(
    entries: &'a [(K, DictValue)],
    key: &str,
    field: &'static str,
) -> Result<Option<&'a [DictValue]>, ScanDictError> {
    match lookup(entries, key) {
        None => Ok(None),
        Some(DictValue::List(items) | DictValue::Tuple(items)) => Ok(Some(items.as_slice())),
        Some(_) => Err(ScanDictError::NotAList { field }),
    }
}

fn expect_map<'a>(
    value: &'a DictValue,
    field: &'static str,
) -> Result<&'a [(String, DictValue)], ScanDictError> {
    match value {
        DictValue::Map(entries) => Ok(entries.as_slice()),
        _ => Err(ScanDictError::NotAMapping { field }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ByCodeRow, FileResult, MinimizePathUnavailable, ScanDictError, ScanSummary, ScanTotals,
        SessionLink, TotalOverflow, UnknownVerdict, Verdict, WorstFileRow, DEFAULT_MAX_BYTES,
        DEFAULT_MAX_FILES, MINIMIZE_PATH_UNAVAILABLE,
    };
    use model::codes::{Repairability, Severity, SL001};
    use model::finding::{
        DictValue, Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION,
    };
    use std::error::Error;

    fn keys(dict: &super::ScanDict) -> Vec<&str> {
        dict.iter().map(|(key, _)| *key).collect()
    }

    fn entry<'a>(dict: &'a super::ScanDict, key: &str) -> &'a DictValue {
        dict.iter()
            .rev()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
            .expect("key present")
    }

    fn synthetic_finding() -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), None)
            .expect("synthetic source");
        Finding::try_new(FindingInput {
            code: PyValue::string(SL001),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        })
        .expect("synthetic finding")
    }

    #[test]
    fn constants_and_verdict_names_match_the_pin() {
        assert_eq!(DEFAULT_MAX_FILES, 10_000);
        assert_eq!(DEFAULT_MAX_BYTES, 1024 * 1024 * 1024);
        assert_eq!(
            MINIMIZE_PATH_UNAVAILABLE,
            "sesslint.report.minimize_path is not available"
        );
        assert_eq!(
            [
                Verdict::Healthy.as_str(),
                Verdict::Invalid.as_str(),
                Verdict::Unsupported.as_str(),
                Verdict::Unreadable.as_str(),
                Verdict::Skipped.as_str(),
            ],
            ["healthy", "invalid", "unsupported", "unreadable", "skipped"]
        );
        assert_eq!(Verdict::parse("healthy"), Ok(Verdict::Healthy));
        assert_eq!(Verdict::parse("nope"), Err(UnknownVerdict));
        assert_eq!(
            UnknownVerdict.to_string(),
            "verdict must be healthy, invalid, unsupported, unreadable, or skipped"
        );
    }

    #[test]
    fn session_link_to_dict_keeps_nulls_and_pin_order() {
        let link = SessionLink::new("session_ref", "sess-1");
        assert_eq!(
            keys(&link.to_dict()),
            ["kind", "line", "record_id", "target"]
        );
        assert_eq!(entry(&link.to_dict(), "line"), &DictValue::None);
        assert_eq!(entry(&link.to_dict(), "record_id"), &DictValue::None);
        assert_eq!(
            entry(&link.to_dict(), "kind"),
            &DictValue::Str("session_ref".to_owned())
        );
        let mut with_line = link;
        with_line.line = Some(4);
        with_line.record_id = Some("rec-1".to_owned());
        let dict = with_line.to_dict();
        assert_eq!(entry(&dict, "line"), &DictValue::Int(4));
        assert_eq!(
            entry(&dict, "record_id"),
            &DictValue::Str("rec-1".to_owned())
        );
    }

    #[test]
    fn session_link_from_dict_round_trips_and_coerces_scalars() {
        let dict = [
            ("kind", DictValue::Str("head_ref".to_owned())),
            ("target", DictValue::Str("tip-1".to_owned())),
            ("record_id", DictValue::Str("rec-9".to_owned())),
            ("line", DictValue::Int(3)),
        ];
        let link = SessionLink::from_dict(&dict).expect("link");
        assert_eq!(link.kind, "head_ref");
        assert_eq!(link.target, "tip-1");
        assert_eq!(link.record_id.as_deref(), Some("rec-9"));
        assert_eq!(link.line, Some(3));
        assert_eq!(
            SessionLink::from_dict(&link.to_dict()).expect("round"),
            link
        );

        let coerced = [
            ("target", DictValue::Int(7)),
            ("kind", DictValue::Bool(true)),
            ("kind", DictValue::Str("session_ref".to_owned())),
        ];
        let link = SessionLink::from_dict(&coerced).expect("last kind wins");
        assert_eq!(link.kind, "session_ref");
        assert_eq!(link.target, "7");
        assert_eq!(link.record_id, None);
        assert_eq!(link.line, None);

        let none_kind = [
            ("kind", DictValue::None),
            ("target", DictValue::Bool(false)),
        ];
        let link = SessionLink::from_dict(&none_kind).expect("scalar str");
        assert_eq!(link.kind, "None");
        assert_eq!(link.target, "False");
    }

    #[test]
    fn session_link_rejects_missing_keys_and_non_scalars() {
        let err = SessionLink::from_dict(&[("target", DictValue::Str("sess-1".to_owned()))])
            .expect_err("kind");
        assert_eq!(err.to_string(), "'kind'");
        assert!(err.source().is_none());

        let err = SessionLink::from_dict(&[
            ("kind", DictValue::List(Vec::new())),
            ("target", DictValue::Str("sess-1".to_owned())),
        ])
        .expect_err("list kind");
        assert_eq!(err.to_string(), "kind must be a str, int, bool, or None");
    }

    #[test]
    fn session_link_line_bool_is_not_an_int() {
        let err = SessionLink::from_dict(&[
            ("kind", DictValue::Str("session_ref".to_owned())),
            ("target", DictValue::Str("sess-1".to_owned())),
            ("line", DictValue::Bool(true)),
        ])
        .expect_err("bool line");
        assert_eq!(err.to_string(), "SessionLink.line bool is not an int");
        assert!(err.source().is_none());

        let err = SessionLink::from_dict(&[
            ("kind", DictValue::Str("session_ref".to_owned())),
            ("target", DictValue::Str("sess-1".to_owned())),
            ("line", DictValue::Str("4".to_owned())),
        ])
        .expect_err("string line");
        assert_eq!(err.to_string(), "SessionLink.line must be an int or None");

        let link = SessionLink::from_dict(&[
            ("kind", DictValue::Str("session_ref".to_owned())),
            ("target", DictValue::Str("sess-1".to_owned())),
            ("line", DictValue::None),
            ("record_id", DictValue::Bool(false)),
        ])
        .expect_err("bool record");
        assert_eq!(
            link.to_string(),
            "SessionLink.record_id must be a str or None"
        );
    }

    #[test]
    fn scan_totals_to_dict_uses_the_mathematical_sum() {
        let totals = ScanTotals {
            healthy: 1,
            invalid: 2,
            unsupported: 3,
            unreadable: 4,
            skipped: 5,
        };
        assert_eq!(totals.total().expect("sum"), 15);
        let dict = totals.to_dict().expect("dict");
        assert_eq!(
            keys(&dict),
            [
                "healthy",
                "invalid",
                "skipped",
                "total",
                "unreadable",
                "unsupported"
            ]
        );
        assert_eq!(entry(&dict, "total"), &DictValue::Int(15));
        assert_eq!(entry(&dict, "healthy"), &DictValue::Int(1));

        let around = ScanTotals {
            healthy: i64::MAX,
            invalid: 1,
            unsupported: -1,
            ..ScanTotals::default()
        };
        assert_eq!(around.total().expect("fits"), i64::MAX);

        let overflow = ScanTotals {
            healthy: i64::MAX,
            invalid: 1,
            ..ScanTotals::default()
        };
        let err = overflow.to_dict().expect_err("overflow");
        assert_eq!(err, TotalOverflow);
        assert_eq!(err.to_string(), "scan total exceeds i64");
        assert!(err.source().is_none());
        let zero = ScanTotals::default().to_dict().expect("zero");
        assert_eq!(entry(&zero, "total"), &DictValue::Int(0));
    }

    #[test]
    fn by_code_row_to_dict_keeps_the_given_code_and_order() {
        let row = ByCodeRow {
            code: SL001.to_owned(),
            severity: "error".to_owned(),
            count: 2,
            files: 1,
        };
        let dict = row.to_dict();
        assert_eq!(keys(&dict), ["code", "count", "files", "severity"]);
        assert_eq!(entry(&dict, "code"), &DictValue::Str(SL001.to_owned()));
        assert_eq!(entry(&dict, "count"), &DictValue::Int(2));
        assert_eq!(entry(&dict, "files"), &DictValue::Int(1));
        assert_eq!(
            entry(&dict, "severity"),
            &DictValue::Str("error".to_owned())
        );
    }

    #[test]
    fn worst_file_to_dict_stops_without_rewriting_the_path() {
        let row = WorstFileRow {
            path: "C:/synthetic/session.jsonl".to_owned(),
            error_count: 3,
            warning_count: 1,
        };
        let err = row.to_dict().expect_err("minimize");
        assert_eq!(err, MinimizePathUnavailable);
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic"));
        assert_eq!(row.path, "C:/synthetic/session.jsonl");
        assert_eq!(row.error_count, 3);
        assert!(err.source().is_none());
    }

    #[test]
    fn scan_summary_builds_by_code_and_stops_when_a_worst_file_is_present() {
        let summary = ScanSummary {
            by_code: vec![
                ByCodeRow {
                    code: SL001.to_owned(),
                    severity: "warning".to_owned(),
                    count: 1,
                    files: 1,
                },
                ByCodeRow {
                    code: SL001.to_owned(),
                    severity: "error".to_owned(),
                    count: 4,
                    files: 2,
                },
            ],
            worst_files: Vec::new(),
        };
        let dict = summary.to_dict().expect("no minimize call");
        assert_eq!(keys(&dict), ["by_code", "worst_files"]);
        let DictValue::List(rows) = entry(&dict, "by_code") else {
            panic!("by_code list");
        };
        assert_eq!(rows.len(), 2);
        let DictValue::Map(first) = &rows[0] else {
            panic!("row map");
        };
        assert_eq!(first[0].0, "code");
        assert_eq!(first[2].1, DictValue::Int(1));
        let DictValue::Map(second) = &rows[1] else {
            panic!("row map");
        };
        assert_eq!(second[1].1, DictValue::Int(4));
        assert_eq!(entry(&dict, "worst_files"), &DictValue::List(Vec::new()));

        let mut blocked = summary;
        blocked.worst_files.push(WorstFileRow {
            path: "C:/synthetic/session.jsonl".to_owned(),
            error_count: 1,
            warning_count: 0,
        });
        let err = blocked.to_dict().expect_err("worst file");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic"));
        assert_eq!(blocked.by_code.len(), 2);

        let empty = ScanSummary::default().to_dict().expect("empty");
        assert_eq!(entry(&empty, "by_code"), &DictValue::List(Vec::new()));
        assert_eq!(entry(&empty, "worst_files"), &DictValue::List(Vec::new()));
    }

    #[test]
    fn file_result_defaults_and_to_dict_do_not_format_findings() {
        let file = FileResult::new("C:/synthetic/session.jsonl", Verdict::Healthy);
        assert_eq!(file.error_count, 0);
        assert_eq!(file.warning_count, 0);
        assert!(!file.cache_hit);
        assert!(file.findings.is_empty());
        assert!(file.links.is_empty());
        assert_eq!(file.max_findings_per_code, 20);
        assert_eq!(file.skipped_reason, None);
        let err = file.to_dict().expect_err("minimize");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic"));

        let mut with_finding = file;
        with_finding.findings.push(synthetic_finding());
        with_finding.verdict = Verdict::Invalid;
        with_finding.error_count = 1;
        let err = with_finding.to_dict().expect_err("still minimize first");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains(SL001));
        assert_eq!(with_finding.findings[0].code(), SL001);
    }

    #[test]
    fn file_result_wire_preserves_the_path_and_bool_cache_flag() {
        let mut file = FileResult::new("C:/synthetic/session.jsonl", Verdict::Skipped);
        file.skipped_reason = Some("size-cap".to_owned());
        file.error_count = 2;
        file.warning_count = 0;
        file.cache_hit = true;
        file.session_id = Some("sess-1".to_owned());
        file.tip_id = Some("tip-1".to_owned());
        file.max_findings_per_code = 7;
        let mut link = SessionLink::new("session_ref", "sess-0");
        link.line = Some(8);
        file.links.push(link);
        file.findings.push(synthetic_finding());

        let wire = file.to_wire();
        assert_eq!(
            keys(&wire),
            [
                "path",
                "verdict",
                "skipped_reason",
                "error_count",
                "warning_count",
                "cache_hit",
                "links",
                "session_id",
                "tip_id",
                "detected_format",
                "max_findings_per_code",
                "findings",
            ]
        );
        assert_eq!(
            entry(&wire, "path"),
            &DictValue::Str("C:/synthetic/session.jsonl".to_owned())
        );
        assert_eq!(
            entry(&wire, "verdict"),
            &DictValue::Str("skipped".to_owned())
        );
        assert_eq!(entry(&wire, "error_count"), &DictValue::Int(2));
        assert_eq!(entry(&wire, "cache_hit"), &DictValue::Bool(true));
        assert_eq!(entry(&wire, "detected_format"), &DictValue::None);
        let DictValue::List(findings) = entry(&wire, "findings") else {
            panic!("findings");
        };
        let DictValue::Map(finding) = &findings[0] else {
            panic!("finding map");
        };
        assert_eq!(finding[0].0, "schema_version");
        assert_eq!(finding[1].1, DictValue::Str(SL001.to_owned()));

        let restored = FileResult::from_wire(&wire).expect("from wire");
        assert_eq!(restored, file);
    }

    #[test]
    fn file_result_from_wire_defaults_and_rejects_bool_ints() {
        let file = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
        ])
        .expect("defaults");
        assert_eq!(file, FileResult::new("a.jsonl", Verdict::Healthy));
        assert!(!file.cache_hit);

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            ("error_count", DictValue::Bool(true)),
        ])
        .expect_err("bool count");
        assert_eq!(err.to_string(), "FileResult.error_count bool is not an int");

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            ("warning_count", DictValue::Bool(false)),
        ])
        .expect_err("bool warning");
        assert_eq!(
            err.to_string(),
            "FileResult.warning_count bool is not an int"
        );

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            ("max_findings_per_code", DictValue::Bool(true)),
        ])
        .expect_err("bool cap");
        assert_eq!(
            err.to_string(),
            "FileResult.max_findings_per_code bool is not an int"
        );

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            ("cache_hit", DictValue::Int(1)),
        ])
        .expect_err("int flag");
        assert_eq!(err.to_string(), "FileResult.cache_hit int is not a bool");

        let file = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("invalid".to_owned())),
            ("cache_hit", DictValue::None),
        ])
        .expect("bool none");
        assert!(!file.cache_hit);
        assert_eq!(file.verdict, Verdict::Invalid);
    }

    #[test]
    fn file_result_from_wire_rejects_unknown_verdict_and_bad_lists() {
        let err = FileResult::from_wire(&[("verdict", DictValue::Str("healthy".to_owned()))])
            .expect_err("path");
        assert_eq!(err.to_string(), "'path'");

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("banana".to_owned())),
        ])
        .expect_err("verdict");
        assert_eq!(
            err.to_string(),
            "verdict must be healthy, invalid, unsupported, unreadable, or skipped"
        );
        assert!(err.source().is_some());

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            ("links", DictValue::None),
        ])
        .expect_err("links none");
        assert_eq!(err.to_string(), "FileResult.links must be a list or tuple");

        let err = FileResult::from_wire(&[
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("verdict", DictValue::Str("healthy".to_owned())),
            (
                "findings",
                DictValue::List(vec![DictValue::Map(Vec::new())]),
            ),
        ])
        .expect_err("empty finding");
        assert_eq!(
            err.to_string(),
            "Finding.from_dict requires a 'source' mapping"
        );
        let ScanDictError::Finding(finding) = err else {
            panic!("finding error");
        };
        assert_eq!(finding.code(), "FINDING");
    }

    #[test]
    fn file_result_from_wire_reads_a_tuple_of_links() {
        let link = SessionLink {
            kind: "head_ref".to_owned(),
            target: "tip-2".to_owned(),
            record_id: None,
            line: Some(0),
        };
        let file = FileResult::from_wire(&[
            ("verdict", DictValue::Str("unreadable".to_owned())),
            ("path", DictValue::Str("a.jsonl".to_owned())),
            ("path", DictValue::Str("b.jsonl".to_owned())),
            (
                "links",
                DictValue::Tuple(vec![super::as_map(link.to_dict())]),
            ),
            ("findings", DictValue::List(Vec::new())),
        ])
        .expect("tuple links");
        assert_eq!(file.path, "b.jsonl");
        assert_eq!(file.verdict, Verdict::Unreadable);
        assert_eq!(file.links, vec![link]);
        assert!(file.findings.is_empty());
        assert_eq!(file.max_findings_per_code, 20);
    }
}
