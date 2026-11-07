//! Scan summary types for one file and for aggregated rows (TASK-024, T-08).
//!
//! Port of `src/sesslint/scan.py` lines 1–436 and `_scan_single_source`
//! lines 439–749
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`scan_single_file`] stops before [`scan_single_source`]. This module does
//! not walk a directory, does not open sqlite, and does not link the report
//! crate.
//!
//! # Recorded gaps
//!
//! * A bool is not an int. `SessionLink.line`, `error_count`, `warning_count`,
//!   and `max_findings_per_code` reject `True` and `False`. They are not `1`
//!   and `0`. [`aggregate_scan`] takes `top` as `i64`. `true` is not `1` and
//!   `false` is not `0`.
//! * `cache_hit` rejects an int. `1` is not `True`. `0` is not `False`.
//!   A missing value and `None` follow `bool(...)` and are false.
//! * [`FileResult::to_dict`] and [`WorstFileRow::to_dict`] call
//!   `sesslint.report.minimize_path` before any later report helper. Display
//!   is [`MINIMIZE_PATH_UNAVAILABLE`]. The path is not rewritten and findings
//!   are not formatted. [`ScanReport::to_dict`] calls those methods. A
//!   non-empty `files` list, or a summary whose `worst_files` is non-empty,
//!   returns that same display and does not return a partial dictionary.
//! * [`ScanReport::to_json`] calls [`ScanReport::to_dict`] first. When that
//!   succeeds, display is `json.dumps is not available`. No JSON string is
//!   emitted.
//! * [`load_scan_schema`] uses [`get_scan_schema_path`]. A missing file uses
//!   the pin `FileNotFoundError` sentence. A file that exists stops with
//!   `json.loads is not available` and is not parsed.
//! * [`scan_single_file`] stops at [`MINIMIZE_PATH_UNAVAILABLE`] before
//!   [`scan_single_source`]. It does not call that function and it does not
//!   return a [`FileResult`].
//! * [`scan_single_source`] is `_scan_single_source`. `max_file_bytes` is
//!   `i64`. A bool is not that int. The file-too-large skip, an undetected
//!   file, a loaded size-limit skip, and `except FileTooLargeError` return
//!   [`FileResult`] without [`model::finding::make_finding`].
//! * An omitted fingerprint makes [`model::finding::make_finding`] return
//!   [`model::finding::FINGERPRINT_CODEC_UNAVAILABLE`]. That error is
//!   propagated. The finding is not appended, and a [`FileResult`] that
//!   required it is not returned.
//! * `sesslint.adapters.detect.resolve_format` and
//!   `sesslint.adapters.detect.resolve_format_bytes` are not in this crate,
//!   `model`, or `checks`. A clean probe stops at that call. An empty finding
//!   list is not returned in its place.
//! * `sesslint.adapters.load.profile_key_for_format`,
//!   `sesslint.adapters.load.load_events_for_format`, and
//!   `sesslint.baseline.filter_findings` stop the same way when the pin
//!   reaches them. [`checks::CheckContext::from_profile_and_adapter`] is
//!   called.
//! * When the pin would call `run_all_checks`, display is
//!   `sesslint.checks.runner.run_all_checks is not available`. Findings and
//!   events are not invented. The pin `except TypeError` retry is not taken.
//! * Bucket counts are `i64`. [`ScanTotals::total`] uses the mathematical sum.
//!   A sum outside `i64` is [`TotalOverflow`] and is not wrapped. Finding and
//!   skipped-reason counts that do not fit in `i64` are refused and are not
//!   wrapped.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use model::canonical::SessionEvent;
use model::codes::{Repairability, SL001, SL301, SL302};
use model::errors::FindingError;
use model::finding::{
    make_finding, DictValue, EvidenceLookup, Finding, MakeFindingInput, PyValue, Severity,
    SourceRef, SEVERITY_ORDER,
};

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

/// Python: `SCAN_SCHEMA_VERSION`.
pub const SCAN_SCHEMA_VERSION: &str = "sesslint.scan-report/v1";

/// `json.dumps` is not linked from this crate.
pub const JSON_DUMPS_UNAVAILABLE: &str = "json.dumps is not available";

/// `json.loads` is not linked from this crate.
pub const JSON_LOADS_UNAVAILABLE: &str = "json.loads is not available";

/// Schema file name passed to [`model::resources::schema_path`].
const SCAN_REPORT_SCHEMA_FILE: &str = "sesslint.scan-report.v1.json";

/// Top-level report containing per-file results and aggregate 5-bucket totals.
///
/// Construction stores the fields the caller already has. It does not scan
/// `root_path` and it does not read a schema file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub schema_version: String,
    pub root_path: String,
    pub totals: ScanTotals,
    pub files: Vec<FileResult>,
    pub summary: Option<ScanSummary>,
}

impl Default for ScanReport {
    /// Dataclass defaults: schema [`SCAN_SCHEMA_VERSION`], empty root, zero
    /// totals, no files, and no summary.
    fn default() -> Self {
        Self {
            schema_version: SCAN_SCHEMA_VERSION.to_owned(),
            root_path: String::new(),
            totals: ScanTotals::default(),
            files: Vec::new(),
            summary: None,
        }
    }
}

/// A skipped-reason count does not fit in `i64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasonCountOverflow;

impl fmt::Display for ReasonCountOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("skipped reason count exceeds i64")
    }
}

impl Error for ReasonCountOverflow {}

/// [`ScanReport::to_dict`] stopped before a dictionary was complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanReportDictError {
    /// [`ScanTotals::to_dict`] refused the bucket sum.
    Total(TotalOverflow),
    /// `sesslint.report.minimize_path` is not available.
    Minimize(MinimizePathUnavailable),
    /// A skipped-reason total does not fit in `i64`.
    Reason(ReasonCountOverflow),
}

impl fmt::Display for ScanReportDictError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Total(err) => write!(formatter, "{err}"),
            Self::Minimize(err) => write!(formatter, "{err}"),
            Self::Reason(err) => write!(formatter, "{err}"),
        }
    }
}

impl Error for ScanReportDictError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Total(err) => Some(err),
            Self::Minimize(err) => Some(err),
            Self::Reason(err) => Some(err),
        }
    }
}

/// [`ScanReport::to_json`] stopped. No JSON text was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanReportJsonError {
    /// [`ScanReport::to_dict`] failed. The display is that error.
    Dict(ScanReportDictError),
    /// `to_dict` succeeded and `json.dumps` is not available.
    Dumps,
}

impl fmt::Display for ScanReportJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dict(err) => write!(formatter, "{err}"),
            Self::Dumps => formatter.write_str(JSON_DUMPS_UNAVAILABLE),
        }
    }
}

impl Error for ScanReportJsonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dict(err) => Some(err),
            Self::Dumps => None,
        }
    }
}

/// Python `FileNotFoundError` or the `json.loads` stop for the scan schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadScanSchemaError {
    /// The pin sentence `Scan report schema not found at {path}`.
    NotFound(PathBuf),
    /// The schema file exists. Its bytes are not parsed.
    Loads,
}

impl fmt::Display for LoadScanSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(path) => {
                write!(
                    formatter,
                    "Scan report schema not found at {}",
                    path.display()
                )
            }
            Self::Loads => formatter.write_str(JSON_LOADS_UNAVAILABLE),
        }
    }
}

impl Error for LoadScanSchemaError {}

/// Python `ValueError` from [`aggregate_scan`], or a count that does not fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateScanError {
    /// `top must be >= 0, got {top}`.
    Top(i64),
    /// `group_by must be 'code' or 'none', got {group_by!r}`.
    GroupBy(String),
    /// A per-code finding count does not fit in `i64`.
    Count,
    /// [`SEVERITY_ORDER`] has no rank for this severity. No rank is invented.
    SeverityRank,
    /// The number of distinct paths for one code does not fit in `i64`.
    FileCount,
}

impl fmt::Display for AggregateScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top(top) => write!(formatter, "top must be >= 0, got {top}"),
            Self::GroupBy(group_by) => write!(
                formatter,
                "group_by must be 'code' or 'none', got {}",
                python_str_repr(group_by)
            ),
            Self::Count => formatter.write_str("finding count exceeds i64"),
            Self::SeverityRank => formatter.write_str("severity is not in SEVERITY_ORDER"),
            Self::FileCount => formatter.write_str("code file count exceeds i64"),
        }
    }
}

impl Error for AggregateScanError {}

impl ScanReport {
    /// Aggregate per-file `skipped_reason` counts into a sorted list.
    ///
    /// Only `skipped` files with a truthy reason are counted. An empty string
    /// is not counted. The pairs are sorted by reason, matching
    /// `dict(sorted(counts.items()))`.
    pub fn skipped_reason_totals(&self) -> Result<Vec<(String, i64)>, ReasonCountOverflow> {
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for file in &self.files {
            if file.verdict != Verdict::Skipped {
                continue;
            }
            let Some(reason) = file.skipped_reason.as_deref() else {
                continue;
            };
            if reason.is_empty() {
                continue;
            }
            match counts.get_mut(reason) {
                Some(count) => {
                    *count = count.checked_add(1).ok_or(ReasonCountOverflow)?;
                }
                None => {
                    counts.insert(reason.to_owned(), 1);
                }
            }
        }
        Ok(counts.into_iter().collect())
    }

    /// Python: `ScanReport.to_dict`.
    ///
    /// Totals are built first. Each file then calls [`FileResult::to_dict`].
    /// A non-empty `files` list stops at [`MINIMIZE_PATH_UNAVAILABLE`] and
    /// does not return a partial dictionary. Findings are not formatted.
    /// An empty `files` list can finish the totals dictionary. A summary is
    /// appended only after the files list. [`ScanSummary::to_dict`] then
    /// stops the same way when `worst_files` is non-empty.
    pub fn to_dict(&self) -> Result<ScanDict, ScanReportDictError> {
        let mut totals = self.totals.to_dict().map_err(ScanReportDictError::Total)?;
        let reasons = self
            .skipped_reason_totals()
            .map_err(ScanReportDictError::Reason)?;
        if !reasons.is_empty() {
            let skipped_reasons = DictValue::Map(
                reasons
                    .into_iter()
                    .map(|(reason, count)| (reason, DictValue::Int(count)))
                    .collect(),
            );
            totals.push(("skipped_reasons", skipped_reasons));
        }
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let dict = file.to_dict().map_err(ScanReportDictError::Minimize)?;
            files.push(as_map(dict));
        }
        let mut report = vec![
            ("files", DictValue::List(files)),
            ("root_path", DictValue::Str(self.root_path.clone())),
            (
                "schema_version",
                DictValue::Str(self.schema_version.clone()),
            ),
            ("totals", as_map(totals)),
        ];
        if let Some(summary) = &self.summary {
            let dict = summary.to_dict().map_err(ScanReportDictError::Minimize)?;
            report.push(("summary", as_map(dict)));
        }
        Ok(report)
    }

    /// Python: `ScanReport.to_json`.
    ///
    /// [`Self::to_dict`] runs first. Its error is propagated. When `to_dict`
    /// succeeds, this still returns [`JSON_DUMPS_UNAVAILABLE`] and does not
    /// emit a JSON string.
    pub fn to_json(&self) -> Result<String, ScanReportJsonError> {
        match self.to_dict() {
            Err(err) => Err(ScanReportJsonError::Dict(err)),
            Ok(_dict) => Err(ScanReportJsonError::Dumps),
        }
    }
}

/// Python: `get_scan_schema_path`.
///
/// Calls [`model::resources::schema_path`] with
/// [`SCAN_REPORT_SCHEMA_FILE`] and the repository file
/// `schemas/sesslint.scan-report.v1.json` derived from this crate's location.
/// The process current directory is not read. `sys._MEIPASS` and `sys.prefix`
/// are not invented.
#[must_use]
pub fn get_scan_schema_path() -> PathBuf {
    let development_path = scan_report_schema_development_path();
    model::resources::schema_path(SCAN_REPORT_SCHEMA_FILE, &development_path)
}

/// Python: `load_scan_schema`.
///
/// A missing file returns the pin `FileNotFoundError` sentence. A file that
/// exists stops with [`JSON_LOADS_UNAVAILABLE`]. The schema is not parsed and
/// a dictionary of schema contents is not returned.
pub fn load_scan_schema() -> Result<Infallible, LoadScanSchemaError> {
    refuse_scan_schema(&get_scan_schema_path())
}

/// Python: `aggregate_scan` (T-08).
///
/// Pure: no clock, no path rewrite, and no detector code or severity other
/// than those already stored on the findings. `top` is an `i64`. A bool is
/// not an int. Paths are stored verbatim. Rank comes from
/// [`SEVERITY_ORDER`].
///
/// `by_code` rows sort by severity rank, then count descending, then code.
/// `worst_files` sort by error count descending, then warning count
/// descending, then path. `top == 0` leaves `worst_files` empty.
/// `group_by == "none"` leaves `by_code` empty.
pub fn aggregate_scan(
    files: &[FileResult],
    top: i64,
    group_by: &str,
) -> Result<ScanSummary, AggregateScanError> {
    if top < 0 {
        return Err(AggregateScanError::Top(top));
    }
    if group_by != "code" && group_by != "none" {
        return Err(AggregateScanError::GroupBy(group_by.to_owned()));
    }

    let by_code = if group_by == "code" {
        aggregate_by_code(files)?
    } else {
        Vec::new()
    };
    let worst_files = if top > 0 {
        aggregate_worst_files(files, top)
    } else {
        Vec::new()
    };
    Ok(ScanSummary {
        by_code,
        worst_files,
    })
}

/// Python: `_scan_single_file`.
///
/// The pin calls `minimize_path` before `_scan_single_source`. That helper
/// lives in the report crate, which this crate does not depend on. Display is
/// [`MINIMIZE_PATH_UNAVAILABLE`]. No [`FileResult`] is returned.
/// [`scan_single_source`] is not called from this function. The pin default
/// for `max_file_bytes` is [`crate::io::DEFAULT_MAX_FILE_BYTES`]. A bool is
/// not that int.
pub fn scan_single_file(
    file_path: &Path,
    format: Option<&str>,
    effective_cfg: &checks::EffectiveConfig,
    skip_undetected: bool,
    resolved_profile: Option<&checks::Profile>,
    baseline: Option<&[String]>,
    max_file_bytes: i64,
) -> Result<FileResult, MinimizePathUnavailable> {
    let _bound = (
        file_path,
        format,
        effective_cfg,
        skip_undetected,
        resolved_profile,
        baseline,
        max_file_bytes,
    );
    Err(MinimizePathUnavailable)
}

/// Failure from [`scan_single_source`].
///
/// [`Display`](fmt::Display) for [`Self::Unavailable`] is `{name} is not available`.
/// [`Self::Finding`] forwards [`FindingError`]. [`Self::Checks`] forwards
/// [`checks::ChecksError`].
#[derive(Debug)]
pub enum ScanSourceError {
    /// [`model::finding::make_finding`] or [`SourceRef::try_new`] failed.
    Finding(FindingError),
    /// A pin call whose function is not in this crate, `model`, or `checks`.
    Unavailable(&'static str),
    /// [`checks::CheckContext::from_profile_and_adapter`] failed.
    Checks(checks::ChecksError),
    /// Python `except FileTooLargeError`.
    ///
    /// The arm returns the skipped [`FileResult`] and does not call
    /// [`make_finding`]. No ported callee raises this variant; loaders are
    /// unavailable before they could.
    FileTooLarge,
    /// Python `except (MaxRecordsExceededError, OSError)`.
    ///
    /// `type_name` is `type(err).__name__`. The handler calls [`make_finding`].
    LimitOrIo {
        /// Python exception class name.
        type_name: &'static str,
    },
    /// Python `except Exception` after the more specific handlers.
    ///
    /// `type_name` is `type(err).__name__`. The handler calls [`make_finding`].
    Unhandled {
        /// Python exception class name.
        type_name: String,
    },
    /// An `i64` finding count would wrap. It is not wrapped.
    CountOverflow,
    /// A link field cannot be stored without treating a bool as an int, or
    /// without stringifying a non-string `record_id`.
    Link(&'static str),
}

impl fmt::Display for ScanSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finding(err) => write!(formatter, "{err}"),
            Self::Unavailable(name) => write!(formatter, "{name} is not available"),
            Self::Checks(err) => write!(formatter, "{err}"),
            Self::FileTooLarge => formatter.write_str("FileTooLargeError"),
            Self::LimitOrIo { type_name } => formatter.write_str(type_name),
            Self::Unhandled { type_name } => formatter.write_str(type_name),
            Self::CountOverflow => formatter.write_str("finding count exceeds i64"),
            Self::Link(message) => formatter.write_str(message),
        }
    }
}

impl Error for ScanSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(err) => Some(err),
            Self::Checks(err) => Some(err),
            Self::Unavailable(_)
            | Self::FileTooLarge
            | Self::LimitOrIo { .. }
            | Self::Unhandled { .. }
            | Self::CountOverflow
            | Self::Link(_) => None,
        }
    }
}

/// Python: `_scan_single_source` (ux T-06).
///
/// `data: Some` is byte mode. `display_path` is stored verbatim and the
/// filesystem is not touched. `data: None` reads `file_path`.
///
/// `max_file_bytes` is an `i64`. A bool is not that int.
/// [`crate::io::probe_bytes_encoding`] and [`crate::io::probe_text_encoding`]
/// classify the bytes. A size skip, an undetected file, a loaded size-limit
/// skip, and [`ScanSourceError::FileTooLarge`] return [`FileResult`] without
/// [`make_finding`].
///
/// [`make_finding`] is called with an omitted fingerprint. That returns
/// [`model::finding::FINGERPRINT_CODEC_UNAVAILABLE`]. The error is propagated.
/// The finding is not appended, and a [`FileResult`] that required it is not
/// returned.
///
/// A clean probe calls `sesslint.adapters.detect.resolve_format` or
/// `resolve_format_bytes`. Those functions are not in this crate. Display is
/// `{name} is not available`. The call is not skipped and an empty finding
/// list is not invented.
///
/// The same stop is used for `sesslint.adapters.load.profile_key_for_format`,
/// `sesslint.adapters.load.load_events_for_format`, and
/// `sesslint.baseline.filter_findings` when the pin reaches them.
/// [`checks::CheckContext::from_profile_and_adapter`] is called.
/// When the pin would call `run_all_checks`, display is
/// `sesslint.checks.runner.run_all_checks is not available`. The `except
/// TypeError` retry is not taken: this error is not a `TypeError`. No
/// findings and no events are invented.
///
/// This function does not walk a directory, does not open sqlite, and does
/// not read a clock.
#[allow(clippy::too_many_arguments)]
pub fn scan_single_source(
    file_path: &Path,
    display_path: &str,
    data: Option<&[u8]>,
    format: Option<&str>,
    effective_cfg: &checks::EffectiveConfig,
    skip_undetected: bool,
    resolved_profile: Option<&checks::Profile>,
    baseline: Option<&[String]>,
    max_file_bytes: i64,
) -> Result<FileResult, ScanSourceError> {
    SourceRequest {
        file_path,
        display_path,
        data,
        format,
        effective_cfg,
        skip_undetected,
        resolved_profile,
        baseline,
        max_file_bytes,
    }
    .run()
}

struct SourceRequest<'a> {
    file_path: &'a Path,
    display_path: &'a str,
    data: Option<&'a [u8]>,
    format: Option<&'a str>,
    effective_cfg: &'a checks::EffectiveConfig,
    skip_undetected: bool,
    resolved_profile: Option<&'a checks::Profile>,
    baseline: Option<&'a [String]>,
    max_file_bytes: i64,
}

impl<'a> SourceRequest<'a> {
    fn run(&self) -> Result<FileResult, ScanSourceError> {
        if self.is_oversize() {
            return Ok(skipped_result(self.display_path, "file-too-large"));
        }
        match self.classify_probe() {
            ProbeClass::Io => {
                let finding = scan_finding(
                    SL001,
                    "Unreadable file or I/O error",
                    self.display_path,
                    evidence_pairs(&[("reason", "os_error"), ("detail", "io_error")]),
                )?;
                Ok(unreadable_with(self.display_path, finding))
            }
            ProbeClass::Nul => {
                let finding = scan_finding(
                    SL001,
                    "File contains forbidden NUL byte or binary data",
                    self.display_path,
                    PyValue::None,
                )?;
                Ok(unreadable_with(self.display_path, finding))
            }
            ProbeClass::Utf8 => {
                let finding = scan_finding(
                    SL001,
                    "File encoding error non-UTF-8",
                    self.display_path,
                    evidence_pairs(&[("reason", "encoding_error"), ("detail", "invalid_utf8")]),
                )?;
                Ok(unreadable_with(self.display_path, finding))
            }
            ProbeClass::Clean => finish_try(self.evaluate(), self.display_path),
        }
    }

    /// `len > max_file_bytes`. A negative max is greater than every size,
    /// including zero. A failed `stat` leaves the flag false (`except OSError: pass`).
    /// Directory metadata is one `stat`. Children are not listed.
    fn is_oversize(&self) -> bool {
        if let Some(data) = self.data {
            return exceeds_limit(
                u64::try_from(data.len()).unwrap_or(u64::MAX),
                self.max_file_bytes,
            );
        }
        match std::fs::metadata(self.file_path) {
            Ok(meta) => exceeds_limit(meta.len(), self.max_file_bytes),
            Err(_) => false,
        }
    }

    fn classify_probe(&self) -> ProbeClass {
        if let Some(data) = self.data {
            return match crate::io::probe_bytes_encoding(data) {
                None => ProbeClass::Clean,
                Some(crate::io::EncodingProbe::Nul) => ProbeClass::Nul,
                Some(crate::io::EncodingProbe::Utf8) => ProbeClass::Utf8,
            };
        }
        match crate::io::probe_text_encoding(self.file_path) {
            Ok(None) => ProbeClass::Clean,
            Ok(Some(crate::io::EncodingProbe::Nul)) => ProbeClass::Nul,
            Ok(Some(crate::io::EncodingProbe::Utf8)) => ProbeClass::Utf8,
            Err(_) => ProbeClass::Io,
        }
    }

    fn evaluate(&self) -> Result<FileResult, ScanSourceError> {
        match self.resolve_stage()? {
            ResolvedSource::File(file) => Ok(file),
            ResolvedSource::Open {
                resolved_fmt,
                findings,
            } => self.finish_open(resolved_fmt, findings),
        }
    }

    fn resolve_stage(&self) -> Result<ResolvedSource, ScanSourceError> {
        let resolution = self.resolve()?;
        let enabled = self.enabled_rules();
        let Some(resolved_fmt) = resolution.resolved_fmt else {
            let defects = detection_defects(resolution.findings, enabled);
            return Ok(ResolvedSource::File(undetected_file(
                self.display_path,
                defects,
                self.skip_undetected,
            )?));
        };
        let fmt_key = profile_key_for_format(&resolved_fmt)?;
        if adapter_rejected(
            fmt_key.as_deref(),
            &resolved_fmt,
            &self.effective_cfg.allowed_adapters,
        ) {
            let finding = scan_finding(
                SL302,
                "Format is not permitted by profile",
                self.display_path,
                evidence_pairs(&[
                    ("format", resolved_fmt.as_str()),
                    ("profile", self.effective_cfg.profile.as_str()),
                ]),
            )?;
            return Ok(ResolvedSource::File(invalid_with(
                self.display_path,
                finding,
            )));
        }
        Ok(ResolvedSource::Open {
            resolved_fmt,
            findings: resolution.findings,
        })
    }

    /// The pin binds `detection_res` and does not read it. It is not stored.
    fn resolve(&self) -> Result<FormatResolution, ScanSourceError> {
        let confidence_min = self.effective_cfg.confidence_min;
        let margin_min = self.effective_cfg.margin_min;
        if let Some(data) = self.data {
            resolve_format_bytes(
                self.format,
                data,
                "stdin.jsonl",
                self.display_path,
                confidence_min,
                margin_min,
            )
        } else {
            resolve_format(self.format, self.file_path, confidence_min, margin_min)
        }
    }

    fn finish_open(
        &self,
        resolved_fmt: String,
        mut adapter_findings: Vec<Finding>,
    ) -> Result<FileResult, ScanSourceError> {
        let limits = reader_limits(self.max_file_bytes)?;
        let load_source = match self.data {
            Some(bytes) => LoadSource::Bytes(bytes),
            None => LoadSource::Path(self.file_path),
        };
        let loaded = load_events_for_format(load_source, &resolved_fmt, &limits)?;
        let LoadedSource {
            events,
            findings: loaded_findings,
            source,
        } = loaded;
        if any_too_large(&loaded_findings)? {
            return Ok(skipped_result(self.display_path, "file-too-large"));
        }
        adapter_findings.extend(loaded_findings);
        if events.is_empty() && self.input_is_empty()? {
            adapter_findings.push(scan_finding(
                SL001,
                "Empty input: file contains no session records",
                self.display_path,
                evidence_pairs(&[("detail", "empty-or-whitespace-only input")]),
            )?);
        }
        let enabled = self.enabled_rules();
        adapter_findings.retain(|finding| rule_enabled(enabled, finding.code()));
        self.checks(resolved_fmt, adapter_findings, &events, source.as_deref())
    }

    fn input_is_empty(&self) -> Result<bool, ScanSourceError> {
        if let Some(data) = self.data {
            return Ok(bytes_are_whitespace(data));
        }
        path_is_whitespace_file(self.file_path)
    }

    fn enabled_rules(&self) -> &'a [String] {
        match self.resolved_profile {
            Some(profile) => profile.enabled_rules.as_slice(),
            None => self.effective_cfg.enabled_rules.as_slice(),
        }
    }

    fn check_profile(&self) -> CheckProfile<'a> {
        match self.resolved_profile {
            Some(profile) => CheckProfile::Profile(profile),
            None => CheckProfile::Name(self.effective_cfg.profile.as_str()),
        }
    }

    fn source_path_str(&self) -> String {
        match self.data {
            Some(_) => self.display_path.to_owned(),
            None => self.file_path.display().to_string(),
        }
    }

    fn checks(
        &self,
        resolved_fmt: String,
        mut all_findings: Vec<Finding>,
        events: &[SessionEvent],
        source: Option<&[(String, DictValue)]>,
    ) -> Result<FileResult, ScanSourceError> {
        let context = load_check_context(self.check_profile(), &resolved_fmt, source)?;
        let check_findings = run_all_checks(
            events,
            self.check_profile(),
            &self.source_path_str(),
            &context,
            &resolved_fmt,
        )?;
        all_findings.extend(check_findings);
        if let Some(baseline) = self.baseline {
            all_findings = filter_findings(all_findings, baseline)?;
        }
        let error_count = count_severity(&all_findings, SeverityCount::ErrorOrFatal)?;
        let warning_count = count_severity(&all_findings, SeverityCount::Warning)?;
        let verdict = classify_verdict(&all_findings, error_count);
        let (links, session_id) = links_and_session(source)?;
        let tip_id = events.last().map(|event| event.id.clone());
        let mut file = FileResult::new(self.display_path, verdict);
        file.findings = all_findings;
        file.error_count = error_count;
        file.warning_count = warning_count;
        file.links = links;
        file.session_id = session_id;
        file.tip_id = tip_id;
        file.detected_format = Some(resolved_fmt);
        Ok(file)
    }
}

enum ProbeClass {
    Clean,
    Nul,
    Utf8,
    Io,
}

enum ResolvedSource {
    File(FileResult),
    Open {
        resolved_fmt: String,
        findings: Vec<Finding>,
    },
}

enum CheckProfile<'a> {
    Profile(&'a checks::Profile),
    Name(&'a str),
}

enum LoadSource<'a> {
    Bytes(&'a [u8]),
    Path(&'a Path),
}

enum SeverityCount {
    ErrorOrFatal,
    Warning,
}

/// Success value of the format seam. The seam returns before this is built.
#[allow(dead_code)]
struct FormatResolution {
    resolved_fmt: Option<String>,
    findings: Vec<Finding>,
}

/// Success value of the loader seam. The seam returns before this is built.
#[allow(dead_code)]
struct LoadedSource {
    events: Vec<SessionEvent>,
    findings: Vec<Finding>,
    source: Option<Vec<(String, DictValue)>>,
}

fn exceeds_limit(size: u64, max_file_bytes: i64) -> bool {
    match u64::try_from(max_file_bytes) {
        Ok(limit) => size > limit,
        Err(_) => true,
    }
}

fn skipped_result(display_path: &str, reason: &str) -> FileResult {
    let mut file = FileResult::new(display_path, Verdict::Skipped);
    file.skipped_reason = Some(reason.to_owned());
    file
}

fn unreadable_with(display_path: &str, finding: Finding) -> FileResult {
    let mut file = FileResult::new(display_path, Verdict::Unreadable);
    file.findings = vec![finding];
    file.error_count = 1;
    file.warning_count = 0;
    file
}

fn invalid_with(display_path: &str, finding: Finding) -> FileResult {
    let mut file = FileResult::new(display_path, Verdict::Invalid);
    file.findings = vec![finding];
    file.error_count = 1;
    file.warning_count = 0;
    file
}

/// Python `try` / `except` around format resolution through the file result.
///
/// [`ScanSourceError::Unavailable`], [`ScanSourceError::Finding`],
/// [`ScanSourceError::Checks`], [`ScanSourceError::CountOverflow`], and
/// [`ScanSourceError::Link`] propagate. They are not turned into a finding.
fn finish_try(
    result: Result<FileResult, ScanSourceError>,
    display_path: &str,
) -> Result<FileResult, ScanSourceError> {
    match result {
        Ok(file) => Ok(file),
        Err(ScanSourceError::FileTooLarge) => Ok(skipped_result(display_path, "file-too-large")),
        Err(ScanSourceError::LimitOrIo { type_name }) => {
            let finding = scan_finding(
                SL001,
                "Unreadable file [detail: LIMIT_OR_IO]",
                display_path,
                evidence_pairs(&[("reason", "limit_or_io_error"), ("detail", type_name)]),
            )?;
            Ok(unreadable_with(display_path, finding))
        }
        Err(ScanSourceError::Unhandled { type_name }) => {
            let detail = type_name.as_str();
            let finding = scan_finding(
                SL001,
                "Failed to process file [detail: INTERNAL_ERROR]",
                display_path,
                evidence_pairs(&[("reason", "unhandled_exception"), ("detail", detail)]),
            )?;
            Ok(invalid_with(display_path, finding))
        }
        Err(other) => Err(other),
    }
}

fn scan_finding(
    code: &str,
    message_template: &str,
    display_path: &str,
    evidence: PyValue,
) -> Result<Finding, ScanSourceError> {
    let source = SourceRef::try_new(display_path, None, None).map_err(ScanSourceError::Finding)?;
    make_finding(&MakeFindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(message_template),
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
    })
    .map_err(ScanSourceError::Finding)
}

fn evidence_pairs(pairs: &[(&str, &str)]) -> PyValue {
    PyValue::map(
        pairs
            .iter()
            .map(|(key, value)| (PyValue::string(*key), PyValue::string(*value)))
            .collect(),
    )
}

fn detection_defects(findings: Vec<Finding>, enabled: &[String]) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| finding.code() != SL302 && rule_enabled(enabled, finding.code()))
        .collect()
}

fn undetected_file(
    display_path: &str,
    findings: Vec<Finding>,
    skip_undetected: bool,
) -> Result<FileResult, ScanSourceError> {
    if !findings.is_empty() {
        let error_count = count_severity(&findings, SeverityCount::ErrorOrFatal)?;
        let warning_count = count_severity(&findings, SeverityCount::Warning)?;
        let mut file = FileResult::new(display_path, Verdict::Invalid);
        file.findings = findings;
        file.error_count = error_count;
        file.warning_count = warning_count;
        return Ok(file);
    }
    if skip_undetected {
        return Ok(skipped_result(display_path, "format-undetected"));
    }
    let mut file = FileResult::new(display_path, Verdict::Unsupported);
    file.skipped_reason = Some("format-undetected".to_owned());
    Ok(file)
}

fn rule_enabled(rules: &[String], code: &str) -> bool {
    rules.iter().any(|rule| rule == code)
}

fn adapter_rejected(fmt_key: Option<&str>, resolved_fmt: &str, allowed: &[String]) -> bool {
    let key_absent = match fmt_key {
        Some(key) => !allowed.iter().any(|item| item == key),
        None => true,
    };
    let format_absent = !allowed.iter().any(|item| item == resolved_fmt);
    key_absent && format_absent
}

/// A severity match increments an `i64`. The match is not added as a bool.
fn count_severity(findings: &[Finding], kind: SeverityCount) -> Result<i64, ScanSourceError> {
    let mut count: i64 = 0;
    for finding in findings {
        let matched = match kind {
            SeverityCount::ErrorOrFatal => {
                matches!(finding.severity(), Severity::Error | Severity::Fatal)
            }
            SeverityCount::Warning => finding.severity() == Severity::Warning,
        };
        if matched {
            count = count.checked_add(1).ok_or(ScanSourceError::CountOverflow)?;
        }
    }
    Ok(count)
}

fn classify_verdict(findings: &[Finding], error_count: i64) -> Verdict {
    if findings.iter().any(|finding| finding.code() == SL301) {
        Verdict::Unsupported
    } else if error_count > 0 {
        Verdict::Invalid
    } else {
        Verdict::Healthy
    }
}

fn reader_limits(max_file_bytes: i64) -> Result<crate::io::ReaderLimits, ScanSourceError> {
    crate::io::ReaderLimits::try_new(
        crate::io::DEFAULT_MAX_LINE_BYTES,
        crate::io::DEFAULT_MAX_DEPTH,
        max_file_bytes,
        None,
    )
    .map_err(|_| ScanSourceError::Unhandled {
        type_name: "ValueError".to_owned(),
    })
}

/// Python `bytes.strip()` with no argument: ASCII whitespace only.
fn bytes_are_whitespace(data: &[u8]) -> bool {
    data.iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

fn path_is_whitespace_file(path: &Path) -> Result<bool, ScanSourceError> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            return Err(ScanSourceError::LimitOrIo {
                type_name: os_error_type_name(&err),
            });
        }
    };
    if meta.len() == 0 {
        return Ok(true);
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes_are_whitespace(&bytes)),
        Err(err) => Err(ScanSourceError::LimitOrIo {
            type_name: os_error_type_name(&err),
        }),
    }
}

fn os_error_type_name(err: &std::io::Error) -> &'static str {
    match err.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        std::io::ErrorKind::AlreadyExists => "FileExistsError",
        std::io::ErrorKind::IsADirectory => "IsADirectoryError",
        std::io::ErrorKind::NotADirectory => "NotADirectoryError",
        std::io::ErrorKind::Interrupted => "InterruptedError",
        std::io::ErrorKind::TimedOut => "TimeoutError",
        _ => "OSError",
    }
}

fn any_too_large(findings: &[Finding]) -> Result<bool, ScanSourceError> {
    for finding in findings {
        if signals_file_too_large(finding)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signals_file_too_large(finding: &Finding) -> Result<bool, ScanSourceError> {
    let Some(evidence) = finding.evidence() else {
        return Ok(false);
    };
    Ok(evidence_equals(evidence, "reason", "size_limit_exceeded")?
        || evidence_equals(evidence, "detail", "FileTooLargeError")?)
}

/// `map_string` returns an owned [`EvidenceLookup::Present`]. Compare here so
/// the string is not borrowed from that temporary.
fn evidence_equals(
    evidence: &model::finding::Evidence,
    key: &str,
    expected: &str,
) -> Result<bool, ScanSourceError> {
    match evidence.map_string(key) {
        EvidenceLookup::Present(value) => Ok(value.as_str() == Some(expected)),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(false),
        EvidenceLookup::Borrowed => Err(ScanSourceError::Unhandled {
            type_name: "RuntimeError".to_owned(),
        }),
    }
}

fn links_and_session(
    source: Option<&[(String, DictValue)]>,
) -> Result<(Vec<SessionLink>, Option<String>), ScanSourceError> {
    let Some(entries) = source else {
        return Ok((Vec::new(), None));
    };
    let links = match lookup(entries, "links") {
        Some(DictValue::List(items)) => links_from_list(items)?,
        _ => Vec::new(),
    };
    let session_id = match lookup(entries, "session_id") {
        Some(DictValue::Str(text)) => {
            let stripped = python_space_strip(text);
            if stripped.is_empty() {
                None
            } else {
                Some(stripped.to_owned())
            }
        }
        _ => None,
    };
    Ok((links, session_id))
}

fn links_from_list(items: &[DictValue]) -> Result<Vec<SessionLink>, ScanSourceError> {
    let mut links = Vec::new();
    for item in items {
        let DictValue::Map(entries) = item else {
            continue;
        };
        let Some(kind_value) = lookup(entries, "kind") else {
            continue;
        };
        let Some(target_value) = lookup(entries, "target") else {
            continue;
        };
        let kind = scalar_text(kind_value)?;
        let target = scalar_text(target_value)?;
        let mut link = SessionLink::new(kind, target);
        link.record_id = optional_link_record(lookup(entries, "record_id"))?;
        link.line = optional_link_line(lookup(entries, "line"))?;
        links.push(link);
    }
    Ok(links)
}

fn scalar_text(value: &DictValue) -> Result<String, ScanSourceError> {
    python_str_scalar(value).ok_or(ScanSourceError::Link(
        "SessionLink kind and target must be a str, int, bool, or None",
    ))
}

fn optional_link_record(value: Option<&DictValue>) -> Result<Option<String>, ScanSourceError> {
    match value {
        None | Some(DictValue::None) => Ok(None),
        Some(DictValue::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ScanSourceError::Link(
            "SessionLink.record_id must be a str or None",
        )),
    }
}

fn optional_link_line(value: Option<&DictValue>) -> Result<Option<i64>, ScanSourceError> {
    match value {
        None | Some(DictValue::None) => Ok(None),
        Some(DictValue::Int(number)) => Ok(Some(*number)),
        Some(DictValue::Bool(_)) => {
            Err(ScanSourceError::Link("SessionLink.line bool is not an int"))
        }
        Some(_) => Err(ScanSourceError::Link(
            "SessionLink.line must be an int or None",
        )),
    }
}

/// Python `str.strip` / `str.isspace` for a session id.
fn python_space_strip(text: &str) -> &str {
    text.trim_matches(python_str_isspace)
}

fn python_str_isspace(ch: char) -> bool {
    matches!(ch, '\u{001c}' | '\u{001d}' | '\u{001e}' | '\u{001f}') || ch.is_whitespace()
}

fn resolve_format(
    format: Option<&str>,
    file_path: &Path,
    confidence_min: f64,
    margin_min: f64,
) -> Result<FormatResolution, ScanSourceError> {
    let _bound = (format, file_path, confidence_min, margin_min);
    Err(ScanSourceError::Unavailable(
        "sesslint.adapters.detect.resolve_format",
    ))
}

fn resolve_format_bytes(
    format: Option<&str>,
    data: &[u8],
    filename: &str,
    display_path: &str,
    confidence_min: f64,
    margin_min: f64,
) -> Result<FormatResolution, ScanSourceError> {
    let _bound = (
        format,
        data.len(),
        filename,
        display_path,
        confidence_min,
        margin_min,
    );
    Err(ScanSourceError::Unavailable(
        "sesslint.adapters.detect.resolve_format_bytes",
    ))
}

fn profile_key_for_format(format: &str) -> Result<Option<String>, ScanSourceError> {
    let _bound = format;
    Err(ScanSourceError::Unavailable(
        "sesslint.adapters.load.profile_key_for_format",
    ))
}

fn load_events_for_format(
    source: LoadSource<'_>,
    format: &str,
    limits: &crate::io::ReaderLimits,
) -> Result<LoadedSource, ScanSourceError> {
    let source_len = match source {
        LoadSource::Bytes(bytes) => bytes.len(),
        LoadSource::Path(path) => path.as_os_str().len(),
    };
    let _bound = (source_len, format, limits.max_file_bytes());
    Err(ScanSourceError::Unavailable(
        "sesslint.adapters.load.load_events_for_format",
    ))
}

fn load_check_context(
    profile: CheckProfile<'_>,
    adapter: &str,
    source: Option<&[(String, DictValue)]>,
) -> Result<checks::CheckContext, ScanSourceError> {
    let _bound = (
        profile_label(profile),
        adapter,
        source.map(|entries| entries.len()),
    );
    checks::CheckContext::from_profile_and_adapter().map_err(ScanSourceError::Checks)
}

fn profile_label(profile: CheckProfile<'_>) -> &str {
    match profile {
        CheckProfile::Profile(profile) => profile.name.as_str(),
        CheckProfile::Name(name) => name,
    }
}

/// The pin retries with `profile=effective_cfg.profile` and `source_path` on
/// `TypeError`. This seam is not a `TypeError`, so that second call is not made.
fn run_all_checks(
    events: &[SessionEvent],
    profile: CheckProfile<'_>,
    source_path: &str,
    context: &checks::CheckContext,
    adapter: &str,
) -> Result<Vec<Finding>, ScanSourceError> {
    let _bound = (
        events.len(),
        profile_label(profile),
        source_path,
        context.adapter_id(),
        context.profile_id(),
        adapter,
    );
    Err(ScanSourceError::Unavailable(
        "sesslint.checks.runner.run_all_checks",
    ))
}

fn filter_findings(
    findings: Vec<Finding>,
    baseline: &[String],
) -> Result<Vec<Finding>, ScanSourceError> {
    let _bound = (findings.len(), baseline.len());
    Err(ScanSourceError::Unavailable(
        "sesslint.baseline.filter_findings",
    ))
}

fn scan_report_schema_development_path() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    match manifest
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
    {
        Some(root) => root.join("schemas").join(SCAN_REPORT_SCHEMA_FILE),
        None => manifest.join("schemas").join(SCAN_REPORT_SCHEMA_FILE),
    }
}

fn refuse_scan_schema(path: &Path) -> Result<Infallible, LoadScanSchemaError> {
    if !path.is_file() {
        return Err(LoadScanSchemaError::NotFound(path.to_path_buf()));
    }
    Err(LoadScanSchemaError::Loads)
}

struct CodeBucket {
    code: String,
    severity: Severity,
    count: i64,
    paths: BTreeSet<String>,
}

fn aggregate_by_code(files: &[FileResult]) -> Result<Vec<ByCodeRow>, AggregateScanError> {
    let mut buckets: Vec<CodeBucket> = Vec::new();
    for file in files {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for finding in &file.findings {
            let code = finding.code();
            let severity = finding.severity();
            let rank = severity_rank(severity)?;
            let position = buckets.iter().position(|bucket| bucket.code == code);
            if let Some(index) = position {
                let bucket = &mut buckets[index];
                bucket.count = bucket
                    .count
                    .checked_add(1)
                    .ok_or(AggregateScanError::Count)?;
                let current = severity_rank(bucket.severity)?;
                if rank < current {
                    bucket.severity = severity;
                }
                if seen.insert(code.to_owned()) {
                    bucket.paths.insert(file.path.clone());
                }
            } else {
                let mut paths = BTreeSet::new();
                paths.insert(file.path.clone());
                buckets.push(CodeBucket {
                    code: code.to_owned(),
                    severity,
                    count: 1,
                    paths,
                });
                seen.insert(code.to_owned());
            }
        }
    }

    let mut ranked = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        let rank = severity_rank(bucket.severity)?;
        let file_count =
            i64::try_from(bucket.paths.len()).map_err(|_| AggregateScanError::FileCount)?;
        ranked.push((rank, file_count, bucket));
    }
    ranked.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(right.2.count.cmp(&left.2.count))
            .then_with(|| left.2.code.cmp(&right.2.code))
    });
    Ok(ranked
        .into_iter()
        .map(|(_rank, file_count, bucket)| ByCodeRow {
            code: bucket.code,
            severity: bucket.severity.as_str().to_owned(),
            count: bucket.count,
            files: file_count,
        })
        .collect())
}

fn aggregate_worst_files(files: &[FileResult], top: i64) -> Vec<WorstFileRow> {
    let mut ranked: Vec<&FileResult> = files
        .iter()
        .filter(|file| file.error_count > 0 || file.warning_count > 0)
        .collect();
    ranked.sort_by(|left, right| {
        right
            .error_count
            .cmp(&left.error_count)
            .then(right.warning_count.cmp(&left.warning_count))
            .then_with(|| left.path.cmp(&right.path))
    });
    let limit = usize::try_from(top).unwrap_or(usize::MAX);
    ranked
        .into_iter()
        .take(limit)
        .map(|file| WorstFileRow {
            path: file.path.clone(),
            error_count: file.error_count,
            warning_count: file.warning_count,
        })
        .collect()
}

fn severity_rank(severity: Severity) -> Result<i64, AggregateScanError> {
    for (kind, rank) in SEVERITY_ORDER {
        if kind == severity {
            return Ok(rank);
        }
    }
    Err(AggregateScanError::SeverityRank)
}

/// Python `repr` for a `str`, preferring single quotes.
fn python_str_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        let code = u32::from(ch);
        if ch == '\\' {
            out.push_str("\\\\");
        } else if ch == quote {
            out.push('\\');
            out.push(quote);
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if code < 32 || code == 0x7F {
            out.push_str(&format!("\\x{code:02x}"));
        } else {
            out.push(ch);
        }
    }
    out.push(quote);
    out
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
        aggregate_scan, get_scan_schema_path, load_scan_schema, scan_single_file,
        scan_single_source, ByCodeRow, FileResult, MinimizePathUnavailable, ScanDictError,
        ScanReport, ScanSourceError, ScanSummary, ScanTotals, SessionLink, TotalOverflow,
        UnknownVerdict, Verdict, WorstFileRow, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES,
        JSON_DUMPS_UNAVAILABLE, JSON_LOADS_UNAVAILABLE, MINIMIZE_PATH_UNAVAILABLE,
        SCAN_SCHEMA_VERSION,
    };
    use model::codes::{Repairability, Severity, SL001, SL006, SL007, SL101, SL203, SL302};
    use model::finding::{
        DictValue, Finding, FindingInput, PyValue, SourceLine, SourceRef,
        FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };
    use std::error::Error;
    use std::path::{Path, PathBuf};

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

    fn finding(code: &str, severity: Severity) -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), None)
            .expect("synthetic source");
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(severity),
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

    fn file_with(
        path: &str,
        verdict: Verdict,
        findings: Vec<Finding>,
        error_count: i64,
        warning_count: i64,
    ) -> FileResult {
        let mut file = FileResult::new(path, verdict);
        file.findings = findings;
        file.error_count = error_count;
        file.warning_count = warning_count;
        file
    }

    fn sample_files() -> Vec<FileResult> {
        vec![
            file_with(
                "a.jsonl",
                Verdict::Invalid,
                vec![
                    finding(SL203, Severity::Error),
                    finding(SL203, Severity::Error),
                    finding(SL101, Severity::Warning),
                ],
                2,
                1,
            ),
            file_with(
                "b.jsonl",
                Verdict::Invalid,
                vec![
                    finding(SL302, Severity::Error),
                    finding(SL203, Severity::Error),
                ],
                3,
                0,
            ),
            FileResult::new("ok.jsonl", Verdict::Healthy),
        ]
    }

    fn effective_config() -> checks::EffectiveConfig {
        checks::EffectiveConfig {
            profile: "neutral".to_owned(),
            description: String::new(),
            allowed_adapters: Vec::new(),
            enabled_rules: Vec::new(),
            confidence_min: 0.5,
            margin_min: 0.1,
            checkpoint_sensitivity: "standard".to_owned(),
            format_override: None,
            thresholds_source: "profile".to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    #[test]
    fn scan_report_defaults_and_skipped_reason_totals_are_sorted() {
        let report = ScanReport::default();
        assert_eq!(report.schema_version, SCAN_SCHEMA_VERSION);
        assert_eq!(SCAN_SCHEMA_VERSION, "sesslint.scan-report/v1");
        assert_eq!(report.root_path, "");
        assert!(report.files.is_empty());
        assert!(report.summary.is_none());
        assert!(report.skipped_reason_totals().expect("reasons").is_empty());

        let mut skipped_empty = FileResult::new("empty.jsonl", Verdict::Skipped);
        skipped_empty.skipped_reason = Some(String::new());
        let mut healthy_with_reason = FileResult::new("healthy.jsonl", Verdict::Healthy);
        healthy_with_reason.skipped_reason = Some("nope".to_owned());
        let mut zero_reason = FileResult::new("zero.jsonl", Verdict::Skipped);
        zero_reason.skipped_reason = Some("0".to_owned());
        let mut a_reason = FileResult::new("c.jsonl", Verdict::Skipped);
        a_reason.skipped_reason = Some("a-reason".to_owned());
        let mut z_one = FileResult::new("b.jsonl", Verdict::Skipped);
        z_one.skipped_reason = Some("z-reason".to_owned());
        let mut z_two = FileResult::new("d.jsonl", Verdict::Skipped);
        z_two.skipped_reason = Some("z-reason".to_owned());
        let bare = FileResult::new("e.jsonl", Verdict::Skipped);
        let report = ScanReport {
            root_path: "/x".to_owned(),
            totals: ScanTotals {
                healthy: 1,
                skipped: 6,
                ..ScanTotals::default()
            },
            files: vec![
                FileResult::new("a.jsonl", Verdict::Healthy),
                z_one,
                a_reason,
                z_two,
                bare,
                skipped_empty,
                healthy_with_reason,
                zero_reason,
            ],
            ..ScanReport::default()
        };
        assert_eq!(
            report.skipped_reason_totals().expect("reasons"),
            vec![
                ("0".to_owned(), 1),
                ("a-reason".to_owned(), 1),
                ("z-reason".to_owned(), 2),
            ]
        );
    }

    #[test]
    fn scan_report_to_dict_builds_totals_only_when_files_are_empty() {
        let report = ScanReport {
            root_path: "C:/synthetic/root".to_owned(),
            totals: ScanTotals {
                healthy: 2,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
            },
            ..ScanReport::default()
        };
        let dict = report.to_dict().expect("empty files");
        assert_eq!(
            keys(&dict),
            ["files", "root_path", "schema_version", "totals"]
        );
        assert_eq!(entry(&dict, "files"), &DictValue::List(Vec::new()));
        assert_eq!(
            entry(&dict, "root_path"),
            &DictValue::Str("C:/synthetic/root".to_owned())
        );
        assert_eq!(
            entry(&dict, "schema_version"),
            &DictValue::Str(SCAN_SCHEMA_VERSION.to_owned())
        );
        let DictValue::Map(totals) = entry(&dict, "totals") else {
            panic!("totals map");
        };
        assert_eq!(
            totals
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            [
                "healthy",
                "invalid",
                "skipped",
                "total",
                "unreadable",
                "unsupported"
            ]
        );
        assert_eq!(totals[3].1, DictValue::Int(2));
        assert!(totals.iter().all(|(key, _)| key != "skipped_reasons"));

        let summary = ScanSummary {
            by_code: vec![ByCodeRow {
                code: SL001.to_owned(),
                severity: "error".to_owned(),
                count: 1,
                files: 1,
            }],
            worst_files: Vec::new(),
        };
        let with_summary = ScanReport {
            summary: Some(summary),
            ..report
        };
        let dict = with_summary.to_dict().expect("summary without worst files");
        assert_eq!(
            keys(&dict),
            ["files", "root_path", "schema_version", "totals", "summary"]
        );
        let DictValue::Map(summary_dict) = entry(&dict, "summary") else {
            panic!("summary map");
        };
        assert_eq!(summary_dict[0].0, "by_code");
        assert_eq!(summary_dict[1].0, "worst_files");
        assert_eq!(summary_dict[1].1, DictValue::List(Vec::new()));
    }

    #[test]
    fn scan_report_to_dict_propagates_minimize_path_without_a_partial_dict() {
        let mut file = FileResult::new("C:/synthetic/session.jsonl", Verdict::Invalid);
        file.findings.push(synthetic_finding());
        file.error_count = 1;
        let report = ScanReport {
            files: vec![file],
            summary: Some(ScanSummary {
                worst_files: vec![WorstFileRow {
                    path: "C:/synthetic/session.jsonl".to_owned(),
                    error_count: 1,
                    warning_count: 0,
                }],
                ..ScanSummary::default()
            }),
            ..ScanReport::default()
        };
        let err = report.to_dict().expect_err("files");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic"));
        assert!(!err.to_string().contains(SL001));
        assert!(err.source().is_some());

        let summary_only = ScanReport {
            files: Vec::new(),
            summary: Some(ScanSummary {
                by_code: vec![ByCodeRow {
                    code: SL001.to_owned(),
                    severity: "warning".to_owned(),
                    count: 1,
                    files: 1,
                }],
                worst_files: vec![WorstFileRow {
                    path: "C:/synthetic/worst.jsonl".to_owned(),
                    error_count: 2,
                    warning_count: 0,
                }],
            }),
            ..ScanReport::default()
        };
        let err = summary_only.to_dict().expect_err("worst file");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!err.to_string().contains("worst"));
        assert!(!err.to_string().contains(SL001));
    }

    #[test]
    fn scan_report_to_json_propagates_to_dict_then_stops_before_dumps() {
        let empty = ScanReport::default();
        assert!(empty.to_dict().is_ok());
        let err = empty.to_json().expect_err("dumps");
        assert_eq!(err.to_string(), JSON_DUMPS_UNAVAILABLE);
        assert_eq!(err.to_string(), "json.dumps is not available");
        assert!(err.source().is_none());

        let blocked = ScanReport {
            files: vec![FileResult::new(
                "C:/synthetic/session.jsonl",
                Verdict::Healthy,
            )],
            ..ScanReport::default()
        };
        let err = blocked.to_json().expect_err("minimize first");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert_ne!(err.to_string(), JSON_DUMPS_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic"));

        let overflow = ScanReport {
            totals: ScanTotals {
                healthy: i64::MAX,
                invalid: 1,
                ..ScanTotals::default()
            },
            files: vec![FileResult::new(
                "C:/synthetic/session.jsonl",
                Verdict::Healthy,
            )],
            ..ScanReport::default()
        };
        let err = overflow.to_json().expect_err("totals first");
        assert_eq!(err.to_string(), "scan total exceeds i64");
        assert_ne!(err.to_string(), JSON_DUMPS_UNAVAILABLE);
    }

    #[test]
    fn schema_path_comes_from_the_crate_and_load_stops() {
        let path = get_scan_schema_path();
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected = manifest
            .parent()
            .expect("crates")
            .parent()
            .expect("rust")
            .parent()
            .expect("repo")
            .join("schemas")
            .join("sesslint.scan-report.v1.json");
        assert_eq!(path, expected);
        assert!(path.is_absolute());
        assert!(path.is_file());
        let err = load_scan_schema().expect_err("loads");
        assert_eq!(err.to_string(), JSON_LOADS_UNAVAILABLE);
        assert_eq!(err.to_string(), "json.loads is not available");
        assert!(!err.to_string().contains("$schema"));
        assert!(!err.to_string().contains("sesslint.scan-report"));

        let missing = manifest
            .join("schemas")
            .join("sesslint.scan-report.missing.json");
        let err = super::refuse_scan_schema(&missing).expect_err("missing");
        assert_eq!(
            err.to_string(),
            format!("Scan report schema not found at {}", missing.display())
        );
        assert!(!missing.exists());

        let directory = expected.parent().expect("schemas dir");
        let err = super::refuse_scan_schema(directory).expect_err("directory");
        assert_eq!(
            err.to_string(),
            format!("Scan report schema not found at {}", directory.display())
        );
    }

    #[test]
    fn aggregate_scan_matches_the_pin_ranks_and_keeps_paths() {
        let files = sample_files();
        let summary = aggregate_scan(&files, 10, "code").expect("summary");
        let rows: Vec<_> = summary
            .by_code
            .iter()
            .map(|row| {
                (
                    row.code.as_str(),
                    row.severity.as_str(),
                    row.count,
                    row.files,
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (SL203, "error", 3, 2),
                (SL302, "error", 1, 1),
                (SL101, "warning", 1, 1),
            ]
        );
        assert_eq!(
            summary
                .worst_files
                .iter()
                .map(|row| (row.path.as_str(), row.error_count, row.warning_count))
                .collect::<Vec<_>>(),
            vec![("b.jsonl", 3, 0), ("a.jsonl", 2, 1)]
        );
        assert_eq!(aggregate_scan(&files, 10, "code").expect("again"), summary);

        let sorted = vec![file_with(
            "x.jsonl",
            Verdict::Invalid,
            vec![
                finding(SL007, Severity::Warning),
                finding(SL006, Severity::Warning),
                finding(SL006, Severity::Warning),
                finding(SL001, Severity::Error),
            ],
            1,
            3,
        )];
        let summary = aggregate_scan(&sorted, 10, "code").expect("sort");
        assert_eq!(
            summary
                .by_code
                .iter()
                .map(|row| row.code.as_str())
                .collect::<Vec<_>>(),
            vec![SL001, SL006, SL007]
        );

        let tied = vec![file_with(
            "x.jsonl",
            Verdict::Invalid,
            vec![
                finding(SL007, Severity::Warning),
                finding(SL006, Severity::Warning),
            ],
            0,
            2,
        )];
        let summary = aggregate_scan(&tied, 10, "code").expect("tie");
        assert_eq!(
            summary
                .by_code
                .iter()
                .map(|row| row.code.as_str())
                .collect::<Vec<_>>(),
            vec![SL006, SL007]
        );
    }

    #[test]
    fn aggregate_scan_keeps_the_stored_severity_and_verbatim_path() {
        let mut warning_then_error = file_with(
            "C:/synthetic/../kept.jsonl",
            Verdict::Invalid,
            vec![
                finding(SL001, Severity::Warning),
                finding(SL001, Severity::Error),
            ],
            1,
            1,
        );
        warning_then_error
            .findings
            .push(finding(SL001, Severity::Fatal));
        let duplicate = file_with(
            "C:/synthetic/../kept.jsonl",
            Verdict::Invalid,
            vec![finding(SL001, Severity::Info)],
            0,
            0,
        );
        let summary = aggregate_scan(&[warning_then_error, duplicate], 10, "code").expect("rank");
        assert_eq!(summary.by_code.len(), 1);
        assert_eq!(summary.by_code[0].code, SL001);
        assert_eq!(summary.by_code[0].severity, "fatal");
        assert_eq!(summary.by_code[0].count, 4);
        assert_eq!(summary.by_code[0].files, 1);
        assert_eq!(summary.worst_files.len(), 1);
        assert_eq!(summary.worst_files[0].path, "C:/synthetic/../kept.jsonl");
        assert_eq!(summary.worst_files[0].error_count, 1);
        assert_eq!(summary.worst_files[0].warning_count, 1);

        let info_heavy = file_with(
            "info.jsonl",
            Verdict::Invalid,
            vec![
                finding(SL001, Severity::Info),
                finding(SL001, Severity::Info),
                finding(SL006, Severity::Warning),
            ],
            0,
            1,
        );
        let summary = aggregate_scan(&[info_heavy], 10, "code").expect("order");
        assert_eq!(summary.by_code[0].code, SL006);
        assert_eq!(summary.by_code[0].severity, "warning");
        assert_eq!(summary.by_code[1].code, SL001);
        assert_eq!(summary.by_code[1].severity, "info");
        assert_eq!(summary.by_code[1].count, 2);
    }

    #[test]
    fn aggregate_scan_honors_top_and_group_by_and_rejects_the_pin_errors() {
        let files = sample_files();
        assert_eq!(
            aggregate_scan(&files, 1, "code")
                .expect("top 1")
                .worst_files
                .len(),
            1
        );
        assert!(aggregate_scan(&files, 0, "code")
            .expect("top 0")
            .worst_files
            .is_empty());
        let none = aggregate_scan(&files, 10, "none").expect("none");
        assert!(none.by_code.is_empty());
        assert_eq!(none.worst_files.len(), 2);

        let healthy = vec![
            FileResult::new("ok.jsonl", Verdict::Healthy),
            FileResult::new("also_ok.jsonl", Verdict::Healthy),
        ];
        let summary = aggregate_scan(&healthy, 10, "code").expect("healthy");
        assert!(summary.by_code.is_empty());
        assert!(summary.worst_files.is_empty());

        let err = aggregate_scan(&files, -1, "file").expect_err("top");
        assert_eq!(err.to_string(), "top must be >= 0, got -1");
        assert!(err.source().is_none());
        let err = aggregate_scan(&files, -1, "code").expect_err("negative");
        assert_eq!(err.to_string(), "top must be >= 0, got -1");

        let err = aggregate_scan(&files, 10, "file").expect_err("group");
        assert_eq!(
            err.to_string(),
            "group_by must be 'code' or 'none', got 'file'"
        );
        let err = aggregate_scan(&files, 10, "it's").expect_err("repr");
        assert_eq!(
            err.to_string(),
            "group_by must be 'code' or 'none', got \"it's\""
        );
        let err = aggregate_scan(&files, 0, "").expect_err("empty");
        assert_eq!(err.to_string(), "group_by must be 'code' or 'none', got ''");
    }

    #[test]
    fn scan_single_file_stops_before_minimize_path_without_a_file_result() {
        let path = Path::new("C:/synthetic/not-opened.jsonl");
        let config = effective_config();
        let baseline = vec!["SL001".to_owned()];
        let err = scan_single_file(
            path,
            Some("canonical"),
            &config,
            true,
            None,
            Some(baseline.as_slice()),
            crate::io::DEFAULT_MAX_FILE_BYTES,
        )
        .expect_err("seam");
        assert_eq!(err, MinimizePathUnavailable);
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert_eq!(
            err.to_string(),
            "sesslint.report.minimize_path is not available"
        );
        assert!(!err.to_string().contains("not-opened"));
        assert!(!err.to_string().contains(SL001));
        assert!(err.source().is_none());
        assert!(!path.exists());

        let err = scan_single_file(path, None, &config, false, None, None, -1).expect_err("still");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
    }

    fn source_config() -> checks::EffectiveConfig {
        effective_config()
    }

    fn scan_bytes(data: &[u8], max_file_bytes: i64) -> Result<FileResult, ScanSourceError> {
        scan_single_source(
            Path::new("not-opened.jsonl"),
            "session.jsonl",
            Some(data),
            None,
            &source_config(),
            false,
            None,
            None,
            max_file_bytes,
        )
    }

    fn assert_skipped(file: &FileResult, reason: &str) {
        assert_eq!(file.path, "session.jsonl");
        assert_eq!(file.verdict, Verdict::Skipped);
        assert_eq!(file.skipped_reason.as_deref(), Some(reason));
        assert!(file.findings.is_empty());
        assert_eq!(file.error_count, 0);
        assert_eq!(file.warning_count, 0);
        assert!(!file.cache_hit);
        assert!(file.links.is_empty());
        assert_eq!(file.detected_format, None);
    }

    #[test]
    fn oversize_bytes_return_a_skipped_file_result_without_a_finding() {
        let file = scan_bytes(b"abcd", 3).expect("skipped");
        assert_skipped(&file, "file-too-large");
        let file = scan_bytes(b"", -1).expect("negative max");
        assert_skipped(&file, "file-too-large");
        let file = scan_bytes(b" ", 0).expect("zero max");
        assert_skipped(&file, "file-too-large");
    }

    #[test]
    fn equal_size_and_empty_at_zero_stop_at_resolve_format_bytes() {
        let err = scan_bytes(b"abc", 3).expect_err("equal");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format_bytes is not available"
        );
        let err = scan_bytes(b"", 0).expect_err("empty at zero");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format_bytes is not available"
        );
        assert!(err.source().is_none());
    }

    #[test]
    fn byte_mode_does_not_open_the_path() {
        let missing = Path::new("C:/no/such/sesslint-scan-03-byte-mode.jsonl");
        assert!(!missing.exists());
        let baseline = [String::from("SL001")];
        let err = scan_single_source(
            missing,
            "session.jsonl",
            Some(b"{}\n"),
            Some("not-a-format"),
            &source_config(),
            true,
            None,
            Some(&baseline),
            crate::io::DEFAULT_MAX_FILE_BYTES,
        )
        .expect_err("bytes");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format_bytes is not available"
        );
        assert!(!err.to_string().contains("canonical_json"));
        assert!(!err.to_string().contains("SL001"));
        assert!(!missing.exists());
    }

    #[test]
    fn whitespace_bytes_stop_before_an_empty_input_finding() {
        let err = scan_bytes(b" \n\t", 100).expect_err("whitespace");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format_bytes is not available"
        );
        assert!(!err.to_string().contains("empty"));
    }

    #[test]
    fn nul_and_non_utf8_propagate_the_omitted_fingerprint_error() {
        for data in [b"\0".as_slice(), b"ab\0c".as_slice(), b"\xff".as_slice()] {
            let err = scan_bytes(data, 100).expect_err("probe");
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
            assert_eq!(
                err.to_string(),
                "sesslint.determinism.canonical_json_bytes is not available"
            );
            assert!(err.source().is_some());
            assert!(!err.to_string().contains("SL001"));
        }
    }

    #[test]
    fn a_missing_file_swallows_stat_then_stops_at_make_finding() {
        let missing =
            std::env::temp_dir().join(format!("sesslint-scan-03-missing-{}", std::process::id()));
        assert!(!missing.exists());
        let err = scan_single_source(
            &missing,
            "session.jsonl",
            None,
            None,
            &source_config(),
            false,
            None,
            None,
            crate::io::DEFAULT_MAX_FILE_BYTES,
        )
        .expect_err("missing");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("resolve_format"));
    }

    #[test]
    fn a_clean_file_stops_at_resolve_format_and_a_nul_file_does_not() {
        let scratch = Scratch::new("file");
        let clean = scratch.path().join("clean.jsonl");
        std::fs::write(&clean, b"{}\n").expect("write");
        let err = scan_single_source(
            &clean,
            "shown.jsonl",
            None,
            Some("canonical"),
            &source_config(),
            false,
            None,
            None,
            4,
        )
        .expect_err("clean");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format is not available"
        );
        assert!(!err.to_string().contains("shown"));

        let nul = scratch.path().join("nul.jsonl");
        std::fs::write(&nul, b"a\0b").expect("write");
        let err = scan_single_source(
            &nul,
            "shown.jsonl",
            None,
            None,
            &source_config(),
            false,
            None,
            None,
            100,
        )
        .expect_err("nul");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let over = scratch.path().join("over.jsonl");
        std::fs::write(&over, b"abcd").expect("write");
        let file = scan_single_source(
            &over,
            "shown.jsonl",
            None,
            None,
            &source_config(),
            false,
            None,
            None,
            3,
        )
        .expect("oversize");
        assert_eq!(file.path, "shown.jsonl");
        assert_eq!(file.verdict, Verdict::Skipped);
        assert_eq!(file.skipped_reason.as_deref(), Some("file-too-large"));
        assert!(file.findings.is_empty());
    }

    #[test]
    fn a_directory_is_not_listed() {
        let scratch = Scratch::new("dir");
        std::fs::write(scratch.path().join("child.jsonl"), b"child-marker").expect("child");
        let skipped = scan_single_source(
            scratch.path(),
            "shown",
            None,
            None,
            &source_config(),
            false,
            None,
            None,
            -1,
        )
        .expect("cap");
        assert_eq!(skipped.verdict, Verdict::Skipped);
        assert_eq!(skipped.skipped_reason.as_deref(), Some("file-too-large"));
        assert!(skipped.findings.is_empty());
        assert!(!skipped.path.contains("child"));

        let err = scan_single_source(
            scratch.path(),
            "shown",
            None,
            None,
            &source_config(),
            false,
            None,
            None,
            10_000_000,
        )
        .expect_err("open dir");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("child-marker"));
        assert!(!err.to_string().contains("child.jsonl"));
    }

    #[test]
    fn scan_single_file_does_not_call_scan_single_source() {
        let path = Path::new("C:/synthetic/not-opened.jsonl");
        let err = scan_single_file(path, None, &source_config(), false, None, None, -1)
            .expect_err("minimize");
        assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        let source_err = scan_bytes(b"", -1).expect("source skipped");
        assert_eq!(source_err.verdict, Verdict::Skipped);
    }

    #[test]
    fn file_too_large_exception_returns_a_file_result_without_make_finding() {
        let file = super::finish_try(Err(ScanSourceError::FileTooLarge), "session.jsonl")
            .expect("skipped");
        assert_skipped(&file, "file-too-large");
    }

    #[test]
    fn limit_or_io_and_unhandled_propagate_the_fingerprint_error() {
        let err = super::finish_try(
            Err(ScanSourceError::LimitOrIo {
                type_name: "OSError",
            }),
            "session.jsonl",
        )
        .expect_err("limit");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        let err = super::finish_try(
            Err(ScanSourceError::Unhandled {
                type_name: "ValueError".to_owned(),
            }),
            "session.jsonl",
        )
        .expect_err("unhandled");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("ValueError"));
    }

    #[test]
    fn an_unavailable_call_is_not_rewritten_as_a_file_result() {
        let err = super::finish_try(
            Err(ScanSourceError::Unavailable(
                "sesslint.adapters.detect.resolve_format",
            )),
            "session.jsonl",
        )
        .expect_err("seam");
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.detect.resolve_format is not available"
        );
    }

    #[test]
    fn run_all_checks_stop_does_not_invent_findings() {
        let context = checks::CheckContext::default();
        let err = super::run_all_checks(
            &[],
            super::CheckProfile::Name("neutral"),
            "session.jsonl",
            &context,
            "canonical",
        )
        .expect_err("checks");
        assert_eq!(
            err.to_string(),
            "sesslint.checks.runner.run_all_checks is not available"
        );
        assert!(err.source().is_none());
    }

    #[test]
    fn filter_findings_stop_does_not_return_an_empty_list() {
        let err =
            super::filter_findings(vec![synthetic_finding()], &["0123456789abcdef".to_owned()])
                .expect_err("baseline");
        assert_eq!(
            err.to_string(),
            "sesslint.baseline.filter_findings is not available"
        );
    }

    #[test]
    fn check_context_calls_the_ported_constructor() {
        let err =
            super::load_check_context(super::CheckProfile::Name("neutral"), "canonical", None)
                .expect_err("context");
        assert_eq!(err.to_string(), "checks error");
        assert!(err.source().is_some());
    }

    #[test]
    fn source_link_line_bool_is_not_an_int() {
        let err = super::optional_link_line(Some(&DictValue::Bool(true))).expect_err("true");
        assert_eq!(err.to_string(), "SessionLink.line bool is not an int");
        let err = super::optional_link_line(Some(&DictValue::Bool(false))).expect_err("false");
        assert_eq!(err.to_string(), "SessionLink.line bool is not an int");
        assert_eq!(
            super::optional_link_line(Some(&DictValue::Int(0))).expect("zero"),
            Some(0)
        );
        assert_eq!(
            super::optional_link_line(Some(&DictValue::Int(1))).expect("one"),
            Some(1)
        );
        assert_eq!(super::optional_link_line(None).expect("missing"), None);
        assert_eq!(
            super::optional_link_line(Some(&DictValue::None)).expect("none"),
            None
        );
        let err = super::optional_link_record(Some(&DictValue::Bool(true))).expect_err("record");
        assert_eq!(
            err.to_string(),
            "SessionLink.record_id must be a str or None"
        );
        let err = super::optional_link_record(Some(&DictValue::Int(1))).expect_err("int record");
        assert_eq!(
            err.to_string(),
            "SessionLink.record_id must be a str or None"
        );
        assert_eq!(
            super::scalar_text(&DictValue::Bool(true)).expect("true text"),
            "True"
        );
        assert_eq!(
            super::scalar_text(&DictValue::Bool(false)).expect("false text"),
            "False"
        );
        assert_eq!(
            super::scalar_text(&DictValue::Int(3)).expect("int text"),
            "3"
        );
        assert_eq!(
            super::scalar_text(&DictValue::None).expect("none text"),
            "None"
        );
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sesslint-scan-03-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Python: `_WORKER_KWARGS`.
///
/// Pool workers would store resolved kwargs here. This port does not store
/// them. The slot stays [`None`]. It is not a [`FileResult`].
pub const WORKER_KWARGS: Option<ScanDict> = None;

/// Python: `_init_scan_worker`.
///
/// Port of `src/sesslint/scan.py` lines 763–785
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The pin calls `apply_rule_selection` on the profile name before
/// `resolve_effective_config`. This calls
/// [`checks::profile::apply_rule_selection`] with
/// [`checks::profile::ProfileInput::Name`]. A name returns
/// [`checks::profile::ProfileError::BuiltinUnavailable`] before select and
/// ignore are applied. That error is propagated. Display is
/// `sesslint.profiles.builtin is not available`.
///
/// [`WORKER_KWARGS`] is not assigned. `resolve_effective_config` is not
/// called. A resolved profile is not returned as success. `timestamp_skew_ms`
/// and `max_file_bytes` are not read. A bool is not an int, and neither field
/// is coerced from a bool. Success is [`Infallible`].
///
/// # Errors
///
/// [`checks::profile::ProfileError`] from the name path. This function does
/// not panic.
pub fn init_scan_worker(
    profile: &str,
    select: Option<&[&str]>,
    ignore: Option<&[&str]>,
) -> Result<Infallible, checks::profile::ProfileError> {
    match checks::profile::apply_rule_selection(
        checks::profile::ProfileInput::Name(profile),
        select,
        ignore,
    ) {
        Err(error) => Err(error),
        Ok(_resolved) => Err(checks::profile::ProfileError::BuiltinUnavailable),
    }
}

/// Python: `_scan_file_worker`.
///
/// Port of `src/sesslint/scan.py` lines 788–807
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The pin calls `minimize_path` before the `try`. That helper is not in this
/// crate. Display is [`MINIMIZE_PATH_UNAVAILABLE`]. [`scan_single_file`] is
/// not called. [`make_finding`] is not called. No [`FileResult`] is built.
/// `to_wire` is not returned. The exception arm is not entered.
/// [`WORKER_KWARGS`] is not read and is not written.
///
/// # Errors
///
/// Always [`MinimizePathUnavailable`]. Success is [`Infallible`]. This
/// function does not panic.
pub fn scan_file_worker(path_str: &str) -> Result<Infallible, MinimizePathUnavailable> {
    let _ = path_str.len();
    Err(MinimizePathUnavailable)
}

#[cfg(test)]
mod worker_seam {
    use std::any::TypeId;
    use std::convert::Infallible;
    use std::error::Error;

    use super::{
        init_scan_worker, scan_file_worker, FileResult, MinimizePathUnavailable, ScanDict,
        MINIMIZE_PATH_UNAVAILABLE, WORKER_KWARGS,
    };

    fn assert_not_file_result<E: 'static>(result: Result<Infallible, E>) -> E {
        assert_ne!(TypeId::of::<Infallible>(), TypeId::of::<FileResult>());
        assert_ne!(
            TypeId::of::<Result<Infallible, E>>(),
            TypeId::of::<FileResult>()
        );
        match result {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    #[test]
    fn init_scan_worker_propagates_builtin_and_leaves_kwargs_unset() {
        assert!(WORKER_KWARGS.is_none());
        assert_ne!(TypeId::of::<Option<ScanDict>>(), TypeId::of::<FileResult>());
        let check = |select: Option<&[&str]>, ignore: Option<&[&str]>| {
            let error = assert_not_file_result(init_scan_worker("neutral", select, ignore));
            assert_eq!(error, checks::profile::ProfileError::BuiltinUnavailable);
            assert_eq!(
                error.to_string(),
                "sesslint.profiles.builtin is not available"
            );
            assert!(error.source().is_none());
            assert!(WORKER_KWARGS.is_none());
        };
        check(None, None);
        check(Some(&["SL001"]), None);
        check(None, Some(&["SL002"]));
        check(Some(&["SL001"]), Some(&["SL002"]));
        let error = assert_not_file_result(init_scan_worker("", Some(&[]), Some(&[])));
        assert_eq!(
            error.to_string(),
            "sesslint.profiles.builtin is not available"
        );
        assert!(WORKER_KWARGS.is_none());
    }

    #[test]
    fn scan_file_worker_stops_at_minimize_path_without_a_file_result() {
        assert!(WORKER_KWARGS.is_none());
        let path = "synthetic/session.jsonl";
        let error = assert_not_file_result(scan_file_worker(path));
        assert_eq!(error, MinimizePathUnavailable);
        assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.report.minimize_path is not available"
        );
        assert!(error.source().is_none());
        assert!(!error.to_string().contains(path));
        assert!(!error.to_string().contains("unreadable"));
        assert!(WORKER_KWARGS.is_none());
        let again = assert_not_file_result(init_scan_worker("neutral", None, None));
        assert_eq!(
            again.to_string(),
            "sesslint.profiles.builtin is not available"
        );
        let error = assert_not_file_result(scan_file_worker(path));
        assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(WORKER_KWARGS.is_none());
    }
}
