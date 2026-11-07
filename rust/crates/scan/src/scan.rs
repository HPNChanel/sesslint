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

/// `datetime.date.fromisoformat` is not available in this crate.
pub const DATE_FROMISOFORMAT_UNAVAILABLE: &str = "datetime.date.fromisoformat is not available";

/// Python `int` or `bool` for a [`scan_path`] limit.
///
/// [`ScanCount::Bool`] is not an int. `True` is not `1`. `False` is not `0`.
/// The shown text of a bool is `True` or `False`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCount {
    /// Python `int`. Not a bool.
    Int(i64),
    /// Python `bool`. Not an int.
    Bool(bool),
}

impl ScanCount {
    fn write_shown(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(number) => write!(formatter, "{number}"),
            Self::Bool(true) => formatter.write_str("True"),
            Self::Bool(false) => formatter.write_str("False"),
        }
    }
}

/// Failure from [`scan_path`].
///
/// The `ValueError` variants use the pin sentences. [`Self::DateFromisoformat`]
/// and [`Self::MinimizePath`] are the two seams. No [`ScanReport`] is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPathError {
    /// `max_files must be a positive integer (> 0), got {value}`.
    MaxFiles(ScanCount),
    /// `max_bytes must be a positive integer (> 0), got {value}`.
    MaxBytes(ScanCount),
    /// `jobs must be a positive integer (>= 1), got {value}`.
    Jobs(ScanCount),
    /// `max_file_bytes must be a positive integer`.
    MaxFileBytes,
    /// `max_findings_per_code must be a positive integer`.
    MaxFindingsPerCode,
    /// `newest must be a positive integer`.
    Newest,
    /// `vendor_layout must be claude or codex`.
    VendorLayout,
    /// [`DATE_FROMISOFORMAT_UNAVAILABLE`].
    DateFromisoformat,
    /// [`MINIMIZE_PATH_UNAVAILABLE`].
    MinimizePath,
}

impl fmt::Display for ScanPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxFiles(value) => {
                formatter.write_str("max_files must be a positive integer (> 0), got ")?;
                value.write_shown(formatter)
            }
            Self::MaxBytes(value) => {
                formatter.write_str("max_bytes must be a positive integer (> 0), got ")?;
                value.write_shown(formatter)
            }
            Self::Jobs(value) => {
                formatter.write_str("jobs must be a positive integer (>= 1), got ")?;
                value.write_shown(formatter)
            }
            Self::MaxFileBytes => formatter.write_str("max_file_bytes must be a positive integer"),
            Self::MaxFindingsPerCode => {
                formatter.write_str("max_findings_per_code must be a positive integer")
            }
            Self::Newest => formatter.write_str("newest must be a positive integer"),
            Self::VendorLayout => formatter.write_str("vendor_layout must be claude or codex"),
            Self::DateFromisoformat => formatter.write_str(DATE_FROMISOFORMAT_UNAVAILABLE),
            Self::MinimizePath => formatter.write_str(MINIMIZE_PATH_UNAVAILABLE),
        }
    }
}

impl Error for ScanPathError {}

/// `value <= 0` after a bool has already been rejected.
fn non_positive(number: i64) -> bool {
    number <= 0
}

/// `value < 1` after a bool has already been rejected.
fn below_one(number: i64) -> bool {
    number < 1
}

/// `isinstance(value, bool)` then `not isinstance(value, int)` then `rejected`.
fn require_shown(value: ScanCount, rejected: fn(i64) -> bool) -> Result<i64, ScanCount> {
    let number = match value {
        ScanCount::Bool(_) => return Err(value),
        ScanCount::Int(number) => number,
    };
    if rejected(number) {
        return Err(value);
    }
    Ok(number)
}

/// `type(value) is int`, then `rejected`. A bool is not that int.
fn require_type_int(
    value: ScanCount,
    rejected: fn(i64) -> bool,
    error: ScanPathError,
) -> Result<i64, ScanPathError> {
    let ScanCount::Int(number) = value else {
        return Err(error);
    };
    if rejected(number) {
        return Err(error);
    }
    Ok(number)
}

/// `newest is not None and (type(newest) is not int or newest < 1)`.
fn require_newest(newest: Option<ScanCount>) -> Result<(), ScanPathError> {
    let Some(value) = newest else {
        return Ok(());
    };
    let ScanCount::Int(number) = value else {
        return Err(ScanPathError::Newest);
    };
    if below_one(number) {
        return Err(ScanPathError::Newest);
    }
    Ok(())
}

/// `vendor_layout not in (None, "claude", "codex")`.
fn require_vendor_layout(vendor_layout: Option<&str>) -> Result<(), ScanPathError> {
    match vendor_layout {
        None | Some("claude") | Some("codex") => Ok(()),
        Some(_) => Err(ScanPathError::VendorLayout),
    }
}

/// Python `min(jobs, 61)` when `sys.platform == "win32"`.
#[cfg(windows)]
fn clamp_windows_jobs(jobs: i64) -> i64 {
    const WINDOWS_JOB_CAP: i64 = 61;
    jobs.min(WINDOWS_JOB_CAP)
}

/// Other platforms leave `jobs` unchanged.
#[cfg(not(windows))]
fn clamp_windows_jobs(jobs: i64) -> i64 {
    jobs
}

/// Python: `scan_path`.
///
/// Port of `src/sesslint/scan.py` lines 810–891
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The checks below run before `minimize_path`, in pin order. A bool is not
/// an int. `True` is not `1`. `False` is not `0`.
///
/// `max_files` and `max_bytes` reject a bool, then a non-positive int. `jobs`
/// rejects a bool, then a value below 1. Those three `ValueError` sentences
/// include the shown value. Bool text is `True` or `False`.
///
/// `max_file_bytes` uses `type is int`, so a bool is rejected, then `<= 0`.
/// `max_findings_per_code` uses `type is int` and requires `>= 1`. `newest`,
/// when present, does the same. `vendor_layout` must be `None`, `claude`, or
/// `codex`.
///
/// `since: Some` stops before a timestamp exists. Display is
/// [`DATE_FROMISOFORMAT_UNAVAILABLE`]. This function does not read a wall
/// clock and does not parse the string.
///
/// `since: None` on Windows sets `jobs` to `min(jobs, 61)`. The pin then
/// calls `minimize_path`. That helper is not in this crate. Display is
/// [`MINIMIZE_PATH_UNAVAILABLE`]. The path is not statted. A directory is not
/// walked. [`scan_single_file`], [`scan_file_worker`], and [`make_finding`]
/// are not called. sqlite is not opened. Lines 892–1505 are not executed,
/// including `Path.exists`, `validate_detection_thresholds`, and the
/// `timestamp_skew_ms` check. No [`ScanReport`] is returned. Success is
/// [`Infallible`].
///
/// Rust has no defaults. For the arguments this function reads, pass
/// `ScanCount::Int(DEFAULT_MAX_FILES)`, `ScanCount::Int(DEFAULT_MAX_BYTES)`,
/// `ScanCount::Int(1)`, `ScanCount::Int(crate::io::DEFAULT_MAX_FILE_BYTES)`,
/// `None`, `None`, `None`, and `ScanCount::Int(20)`. `recursive`,
/// `follow_symlinks`, `format`, `profile`, `confidence_min`, `margin_min`,
/// `progress_cb`, `cancel_token`, `skip_undetected`, `select`, `ignore`,
/// `baseline`, `exclude`, `ext`, `incremental`, `cache_dir`, and
/// `timestamp_skew_ms` are not read. `progress_cb` and `cancel_token` are not
/// parameters: `sesslint.progress` is not linked from this crate.
///
/// # Errors
///
/// A pin `ValueError`, [`ScanPathError::DateFromisoformat`], or
/// [`ScanPathError::MinimizePath`]. This function does not panic.
#[allow(
    clippy::too_many_arguments,
    reason = "pin arguments read before minimize_path, in signature order"
)]
pub fn scan_path(
    path: &Path,
    max_files: ScanCount,
    max_bytes: ScanCount,
    jobs: ScanCount,
    max_file_bytes: ScanCount,
    vendor_layout: Option<&str>,
    newest: Option<ScanCount>,
    since: Option<&str>,
    max_findings_per_code: ScanCount,
) -> Result<Infallible, ScanPathError> {
    let max_files = require_shown(max_files, non_positive).map_err(ScanPathError::MaxFiles)?;
    let max_bytes = require_shown(max_bytes, non_positive).map_err(ScanPathError::MaxBytes)?;
    let jobs = require_shown(jobs, below_one).map_err(ScanPathError::Jobs)?;
    let max_file_bytes =
        require_type_int(max_file_bytes, non_positive, ScanPathError::MaxFileBytes)?;
    let max_findings_per_code = require_type_int(
        max_findings_per_code,
        below_one,
        ScanPathError::MaxFindingsPerCode,
    )?;
    require_newest(newest)?;
    require_vendor_layout(vendor_layout)?;
    if since.is_some() {
        return Err(ScanPathError::DateFromisoformat);
    }
    // Pin: `if sys.platform == "win32": jobs = min(jobs, 61)`.
    let jobs = clamp_windows_jobs(jobs);
    // Pin: `root_str = minimize_path(target)`. The reference is not a stat.
    let _bound = (
        path,
        max_files,
        max_bytes,
        jobs,
        max_file_bytes,
        max_findings_per_code,
    );
    Err(ScanPathError::MinimizePath)
}

#[cfg(test)]
mod scan_path_seam {
    use std::any::TypeId;
    use std::convert::Infallible;
    use std::error::Error;
    use std::path::Path;

    use super::{
        scan_path, FileResult, ScanCount, ScanPathError, ScanReport,
        DATE_FROMISOFORMAT_UNAVAILABLE, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES,
        DEFAULT_MAX_FINDINGS_PER_CODE, MINIMIZE_PATH_UNAVAILABLE,
    };

    fn int(number: i64) -> ScanCount {
        ScanCount::Int(number)
    }

    fn flag(value: bool) -> ScanCount {
        ScanCount::Bool(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "same pin argument list as scan_path"
    )]
    fn call(
        path: &Path,
        max_files: ScanCount,
        max_bytes: ScanCount,
        jobs: ScanCount,
        max_file_bytes: ScanCount,
        vendor_layout: Option<&str>,
        newest: Option<ScanCount>,
        since: Option<&str>,
        max_findings_per_code: ScanCount,
    ) -> ScanPathError {
        assert_ne!(TypeId::of::<Infallible>(), TypeId::of::<ScanReport>());
        assert_ne!(TypeId::of::<Infallible>(), TypeId::of::<FileResult>());
        assert_ne!(
            TypeId::of::<Result<Infallible, ScanPathError>>(),
            TypeId::of::<ScanReport>()
        );
        match scan_path(
            path,
            max_files,
            max_bytes,
            jobs,
            max_file_bytes,
            vendor_layout,
            newest,
            since,
            max_findings_per_code,
        ) {
            Ok(never) => match never {},
            Err(error) => {
                assert!(error.source().is_none());
                let text = error.to_string();
                assert!(!text.contains("not-opened"));
                assert!(!text.contains("synthetic"));
                assert!(!text.contains("child.jsonl"));
                assert!(!text.contains("missing"));
                error
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "same pin argument list as scan_path"
    )]
    fn at(
        max_files: ScanCount,
        max_bytes: ScanCount,
        jobs: ScanCount,
        max_file_bytes: ScanCount,
        vendor_layout: Option<&str>,
        newest: Option<ScanCount>,
        since: Option<&str>,
        max_findings_per_code: ScanCount,
    ) -> ScanPathError {
        call(
            Path::new("synthetic/not-opened.jsonl"),
            max_files,
            max_bytes,
            jobs,
            max_file_bytes,
            vendor_layout,
            newest,
            since,
            max_findings_per_code,
        )
    }

    fn ready(
        jobs: ScanCount,
        vendor_layout: Option<&str>,
        newest: Option<ScanCount>,
        since: Option<&str>,
    ) -> ScanPathError {
        at(
            int(DEFAULT_MAX_FILES),
            int(DEFAULT_MAX_BYTES),
            jobs,
            int(crate::io::DEFAULT_MAX_FILE_BYTES),
            vendor_layout,
            newest,
            since,
            int(DEFAULT_MAX_FINDINGS_PER_CODE),
        )
    }

    fn expect(error: ScanPathError, sentence: &str) {
        assert_eq!(error.to_string(), sentence);
        assert!(error.source().is_none());
    }

    fn ready_findings(max_findings_per_code: ScanCount) -> ScanPathError {
        at(
            int(DEFAULT_MAX_FILES),
            int(DEFAULT_MAX_BYTES),
            int(1),
            int(crate::io::DEFAULT_MAX_FILE_BYTES),
            Some("codex"),
            Some(int(1)),
            None,
            max_findings_per_code,
        )
    }

    #[test]
    fn shown_limits_reject_bool_then_non_positive_int() {
        expect(
            at(
                flag(true),
                int(0),
                flag(true),
                flag(true),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                flag(true),
            ),
            "max_files must be a positive integer (> 0), got True",
        );
        assert_eq!(
            at(flag(true), int(1), int(1), int(1), None, None, None, int(1),),
            ScanPathError::MaxFiles(flag(true))
        );
        expect(
            at(
                flag(false),
                flag(true),
                int(0),
                int(0),
                Some("nope"),
                None,
                None,
                int(0),
            ),
            "max_files must be a positive integer (> 0), got False",
        );
        expect(
            at(
                int(0),
                flag(false),
                flag(false),
                flag(false),
                Some("nope"),
                Some(int(0)),
                Some("2020-01-01"),
                int(0),
            ),
            "max_files must be a positive integer (> 0), got 0",
        );
        expect(
            at(
                int(-4),
                int(0),
                int(-1),
                int(-1),
                Some("nope"),
                Some(int(-1)),
                None,
                int(-1),
            ),
            "max_files must be a positive integer (> 0), got -4",
        );
        expect(
            at(
                int(1),
                flag(true),
                flag(true),
                flag(true),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                flag(true),
            ),
            "max_bytes must be a positive integer (> 0), got True",
        );
        expect(
            at(
                int(1),
                flag(false),
                int(0),
                int(0),
                None,
                None,
                None,
                int(0),
            ),
            "max_bytes must be a positive integer (> 0), got False",
        );
        expect(
            at(
                int(1),
                int(0),
                flag(true),
                flag(true),
                Some("nope"),
                None,
                Some("2020-01-01"),
                int(0),
            ),
            "max_bytes must be a positive integer (> 0), got 0",
        );
        expect(
            at(
                int(1),
                int(-8),
                int(0),
                int(0),
                Some("nope"),
                None,
                None,
                int(0),
            ),
            "max_bytes must be a positive integer (> 0), got -8",
        );
        expect(
            at(
                int(1),
                int(1),
                flag(true),
                flag(true),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                flag(true),
            ),
            "jobs must be a positive integer (>= 1), got True",
        );
        expect(
            ready(
                flag(false),
                Some("nope"),
                Some(flag(false)),
                Some("2020-01-01"),
            ),
            "jobs must be a positive integer (>= 1), got False",
        );
        expect(
            ready(int(0), Some("claude"), None, Some("2020-01-01")),
            "jobs must be a positive integer (>= 1), got 0",
        );
        expect(
            ready(int(-1), None, Some(int(0)), None),
            "jobs must be a positive integer (>= 1), got -1",
        );
    }

    #[test]
    fn type_is_int_rejects_bool_without_the_shown_value() {
        let max_file_bytes = "max_file_bytes must be a positive integer";
        let findings = "max_findings_per_code must be a positive integer";
        expect(
            at(
                int(1),
                int(1),
                int(1),
                flag(true),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                flag(true),
            ),
            max_file_bytes,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                flag(false),
                None,
                None,
                None,
                int(0),
            ),
            max_file_bytes,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(0),
                Some("nope"),
                None,
                None,
                int(0),
            ),
            max_file_bytes,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(-3),
                None,
                Some(int(0)),
                Some("2020-01-01"),
                int(-1),
            ),
            max_file_bytes,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(1),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                flag(true),
            ),
            findings,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(1),
                Some("claude"),
                Some(flag(false)),
                None,
                flag(false),
            ),
            findings,
        );
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(1),
                None,
                Some(int(1)),
                Some("2020-01-01"),
                int(0),
            ),
            findings,
        );
        expect(ready_findings(int(-1)), findings);
    }

    #[test]
    fn newest_vendor_since_and_the_path_seam() {
        let newest = "newest must be a positive integer";
        let vendor = "vendor_layout must be claude or codex";
        expect(
            at(
                int(1),
                int(1),
                int(1),
                int(1),
                Some("nope"),
                Some(flag(true)),
                Some("2020-01-01"),
                int(1),
            ),
            newest,
        );
        expect(
            ready(int(1), Some("nope"), Some(flag(false)), Some("2020-01-01")),
            newest,
        );
        expect(ready(int(1), Some("claude"), Some(int(0)), None), newest);
        expect(
            ready(int(1), Some("codex"), Some(int(-5)), Some("2020-01-01")),
            newest,
        );
        expect(
            ready(int(1), Some("nope"), Some(int(1)), Some("2020-01-01")),
            vendor,
        );
        expect(
            ready(int(1), Some("Claude"), None, Some("2020-01-01")),
            vendor,
        );
        expect(ready(int(1), Some(""), None, None), vendor);
        expect(ready(int(1), Some("codex "), Some(int(2)), None), vendor);
        expect(ready(int(1), Some("none"), None, None), vendor);

        let since_error = ready(int(1), None, None, Some("2020-01-01"));
        assert_eq!(since_error, ScanPathError::DateFromisoformat);
        expect(since_error, "datetime.date.fromisoformat is not available");
        assert_eq!(since_error.to_string(), DATE_FROMISOFORMAT_UNAVAILABLE);
        assert!(!since_error.to_string().contains("2020"));
        assert!(!since_error
            .to_string()
            .chars()
            .any(|ch| ch.is_ascii_digit()));
        expect(
            ready(int(62), Some("claude"), Some(int(1)), Some("")),
            "datetime.date.fromisoformat is not available",
        );
        expect(
            ready(int(100), Some("codex"), None, Some("not-a-date")),
            "datetime.date.fromisoformat is not available",
        );

        let minimized = ready(int(1), None, None, None);
        assert_eq!(minimized, ScanPathError::MinimizePath);
        expect(minimized, "sesslint.report.minimize_path is not available");
        assert_eq!(minimized.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!minimized.to_string().chars().any(|ch| ch.is_ascii_digit()));
        expect(
            ready(int(61), Some("claude"), None, None),
            MINIMIZE_PATH_UNAVAILABLE,
        );
        expect(
            ready(int(62), Some("codex"), Some(int(1)), None),
            MINIMIZE_PATH_UNAVAILABLE,
        );
        expect(
            ready(int(100), None, Some(int(i64::MAX)), None),
            MINIMIZE_PATH_UNAVAILABLE,
        );
        expect(
            at(
                int(i64::MAX),
                int(i64::MAX),
                int(i64::MAX),
                int(i64::MAX),
                None,
                Some(int(i64::MAX)),
                None,
                int(i64::MAX),
            ),
            MINIMIZE_PATH_UNAVAILABLE,
        );
        expect(ready_findings(int(1)), MINIMIZE_PATH_UNAVAILABLE);

        let dot = call(
            Path::new("."),
            int(1),
            int(1),
            int(1),
            int(1),
            None,
            None,
            None,
            int(1),
        );
        assert_eq!(dot, ScanPathError::MinimizePath);
        let missing = call(
            Path::new("C:/synthetic/missing"),
            int(1),
            int(1),
            int(1),
            int(1),
            None,
            None,
            None,
            int(20),
        );
        assert_eq!(missing.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!missing.to_string().contains("C:"));
    }
}

/// Python default for `_walk_rollout_files(..., max_files=200_000)`.
///
/// Pass [`ScanCount::Int`]`(WALK_ROLLOUT_MAX_FILES)` when the caller omits
/// the argument. This is not [`DEFAULT_MAX_FILES`].
pub const WALK_ROLLOUT_MAX_FILES: i64 = 200_000;

/// `sesslint.adapters.safe_value.safe_discriminator` is not in this crate.
pub const SAFE_DISCRIMINATOR_UNAVAILABLE: &str =
    "sesslint.adapters.safe_value.safe_discriminator is not available";

const ROLLOUT_PREFIX: &str = "rollout-";
const CODEX_UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
const CODEX_UUID_LEN: usize = 36;

/// On-disk Codex rollout names and the minimized paths that would name them.
///
/// Python returns `(uuids, minimized_paths)`. Both sets stay empty unless a
/// later port can call `minimize_path`. This card does not invent those paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutWalk {
    pub uuids: BTreeSet<String>,
    pub paths: BTreeSet<String>,
}

/// `max_files` was a bool, or a rollout ledger reached `minimize_path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkRolloutFilesError {
    /// `max_files bool is not an int`. `True` is not `1`. `False` is not `0`.
    MaxFilesBool,
    /// [`MINIMIZE_PATH_UNAVAILABLE`].
    MinimizePath,
}

impl fmt::Display for WalkRolloutFilesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxFilesBool => formatter.write_str("max_files bool is not an int"),
            Self::MinimizePath => formatter.write_str(MINIMIZE_PATH_UNAVAILABLE),
        }
    }
}

impl Error for WalkRolloutFilesError {}

/// `sesslint.adapters.safe_value.safe_discriminator` is not in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeDiscriminatorUnavailable;

impl fmt::Display for SafeDiscriminatorUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SAFE_DISCRIMINATOR_UNAVAILABLE)
    }
}

impl Error for SafeDiscriminatorUnavailable {}

/// Python: `_rollout_uuid`.
///
/// Port of `src/sesslint/scan.py` lines 1508–1517
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The pattern is
/// `^rollout-.*-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`.
/// `.` does not match a newline. `$` also matches before one trailing newline.
/// The capture is ASCII-lowercased. This is not
/// [`crate::state_db::rollout_uuid_from_name`]: that function accepts the
/// first UUID anywhere and does not require this prefix or the end anchor.
#[must_use]
pub fn rollout_uuid(stem: &str) -> Option<String> {
    let stem = stem.strip_suffix('\n').unwrap_or(stem);
    if !stem.starts_with(ROLLOUT_PREFIX) {
        return None;
    }
    let chars: Vec<char> = stem.chars().collect();
    let uuid_at = chars.len().checked_sub(CODEX_UUID_LEN)?;
    let hyphen_at = uuid_at.checked_sub(1)?;
    if hyphen_at < ROLLOUT_PREFIX.len() {
        return None;
    }
    if chars.get(hyphen_at).copied() != Some('-') {
        return None;
    }
    let middle = chars.get(ROLLOUT_PREFIX.len()..hyphen_at)?;
    if middle.contains(&'\n') {
        return None;
    }
    let uuid = chars.get(uuid_at..)?;
    lowercase_uuid(uuid)
}

fn lowercase_uuid(chars: &[char]) -> Option<String> {
    if chars.len() != CODEX_UUID_LEN {
        return None;
    }
    let mut out = String::with_capacity(CODEX_UUID_LEN);
    let mut index = 0;
    for (group, &width) in CODEX_UUID_GROUPS.iter().enumerate() {
        if group > 0 {
            if chars.get(index).copied() != Some('-') {
                return None;
            }
            out.push('-');
            index += 1;
        }
        for _ in 0..width {
            let ch = chars.get(index).copied()?;
            if !ch.is_ascii_hexdigit() {
                return None;
            }
            out.push(ch.to_ascii_lowercase());
            index += 1;
        }
    }
    if index == CODEX_UUID_LEN {
        Some(out)
    } else {
        None
    }
}

/// Python: `_looks_pathy`.
///
/// Port of `src/sesslint/scan.py` lines 1555–1558
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// Backslashes are rewritten to `/` before the slash and suffix checks.
/// `.jsonl` does not count as `.json`. The suffix check is case-sensitive.
#[must_use]
pub fn looks_pathy(target: &str) -> bool {
    let normalized = target.replace('\\', "/");
    normalized.contains('/') || normalized.ends_with(".jsonl") || normalized.ends_with(".json")
}

/// Python: `_walk_rollout_files`.
///
/// Port of `src/sesslint/scan.py` lines 1520–1552
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The walk starts at `sessions_dir` and enters only real subdirectories of
/// that tree. It does not follow a directory symlink, does not open a parent,
/// and does not read file bytes. Names in one directory are visited in
/// ascending file-name order, top-down, so the cap does not depend on
/// `os.walk` order.
///
/// `sessions_dir` is a directory only when `Path.is_dir` would be true after
/// following a symlink. A missing path, a file, or a stat failure is not
/// provable and returns `Ok(None)`. A listing error also returns `Ok(None)`
/// and stops. The partial names already seen are not returned.
///
/// `max_files` is read only at `seen > max_files`, after a file has been
/// counted and before its name is classified. A bool is rejected there.
/// `True` is not `1`. `False` is not `0`. Zero and negative ints keep the
/// pin comparison. The omitted-argument value is [`WALK_ROLLOUT_MAX_FILES`].
///
/// A `rollout-*.jsonl` name at or under the cap runs [`rollout_uuid`] and
/// then stops. Display is [`MINIMIZE_PATH_UNAVAILABLE`]. No minimized path
/// and no UUID set is returned. [`ScanReport`] is not built.
///
/// # Errors
///
/// [`WalkRolloutFilesError::MaxFilesBool`] or
/// [`WalkRolloutFilesError::MinimizePath`]. This function does not panic.
pub fn walk_rollout_files(
    sessions_dir: &Path,
    max_files: ScanCount,
) -> Result<Option<RolloutWalk>, WalkRolloutFilesError> {
    if !metadata_is_dir(sessions_dir) {
        return Ok(None);
    }
    let mut stack = vec![sessions_dir.to_path_buf()];
    let mut seen: i64 = 0;
    while let Some(dir) = stack.pop() {
        let Some(listing) = list_rollout_dir(&dir) else {
            return Ok(None);
        };
        for name in listing.files {
            seen = match seen.checked_add(1) {
                Some(next) => next,
                None => return Ok(None),
            };
            if cap_reached(seen, max_files)? {
                return Ok(None);
            }
            if let Some(text) = name.to_str() {
                if is_rollout_ledger(text) {
                    return Err(stop_at_minimize_path(text, &dir));
                }
            }
        }
        for child in listing.directories.into_iter().rev() {
            stack.push(child);
        }
    }
    Ok(Some(empty_rollout_walk()))
}

fn metadata_is_dir(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_dir())
}

fn cap_reached(seen: i64, max_files: ScanCount) -> Result<bool, WalkRolloutFilesError> {
    match max_files {
        ScanCount::Bool(_) => Err(WalkRolloutFilesError::MaxFilesBool),
        ScanCount::Int(limit) => Ok(seen > limit),
    }
}

fn is_rollout_ledger(name: &str) -> bool {
    name.starts_with("rollout-") && name.ends_with(".jsonl")
}

fn stop_at_minimize_path(name: &str, dir: &Path) -> WalkRolloutFilesError {
    let stem = &name[..name.len() - ".jsonl".len()];
    let uuid = rollout_uuid(stem);
    let joined = dir.join(name);
    let _bound = (uuid.as_deref().map(str::len), joined.as_os_str().len());
    WalkRolloutFilesError::MinimizePath
}

fn empty_rollout_walk() -> RolloutWalk {
    RolloutWalk {
        uuids: BTreeSet::new(),
        paths: BTreeSet::new(),
    }
}

struct RolloutDirListing {
    files: Vec<std::ffi::OsString>,
    directories: Vec<PathBuf>,
}

enum RolloutEntry {
    File,
    Directory,
    Skipped,
}

fn list_rollout_dir(dir: &Path) -> Option<RolloutDirListing> {
    let read = std::fs::read_dir(dir).ok()?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for item in read {
        let entry = item.ok()?;
        match classify_entry(&entry) {
            RolloutEntry::File => files.push(entry.file_name()),
            RolloutEntry::Directory => directories.push(entry.path()),
            RolloutEntry::Skipped => {}
        }
    }
    files.sort();
    directories.sort();
    Some(RolloutDirListing { files, directories })
}

fn classify_entry(entry: &std::fs::DirEntry) -> RolloutEntry {
    match entry.file_type() {
        Ok(kind) if kind.is_symlink() => classify_symlink(entry),
        Ok(kind) if kind.is_dir() => RolloutEntry::Directory,
        Ok(_) | Err(_) => RolloutEntry::File,
    }
}

fn classify_symlink(entry: &std::fs::DirEntry) -> RolloutEntry {
    match std::fs::metadata(entry.path()) {
        Ok(meta) if meta.is_dir() => RolloutEntry::Skipped,
        _ => RolloutEntry::File,
    }
}

struct FileIndex {
    by_session: BTreeMap<String, BTreeSet<usize>>,
    by_stem: BTreeMap<String, BTreeSet<usize>>,
    by_tip: BTreeMap<String, BTreeSet<usize>>,
}

struct LinkDraft {
    resolution: &'static str,
    severity: Severity,
    message: &'static str,
    candidate_count: usize,
}

/// Python: `_resolve_cross_file_links`.
///
/// Port of `src/sesslint/scan.py` lines 1561–1671
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
/// Stops before `_reconcile_session_indexes`.
///
/// Session ids, filename stems, rollout UUIDs, and tip ids are indexed
/// before any link is resolved. An empty string is not indexed. A link with
/// one other candidate, or only its own file, is unchanged. `session_ref`
/// also matches a path-like target's stem. `head_ref` and every other kind
/// use tip ids only.
///
/// The pin imports `sesslint.adapters.safe_value.safe_discriminator` and
/// calls it only when a link would become an SL401 finding. That function
/// is not in this crate. Display is [`SAFE_DISCRIMINATOR_UNAVAILABLE`].
/// [`make_finding`] is not called. Baseline filtering runs after that call,
/// so a baseline does not turn the seam into success. No [`FileResult`] list
/// is returned when the call is required. No [`ScanReport`] is returned.
///
/// `None` is the pin's omitted baseline. Resolved input is cloned and returned.
///
/// # Errors
///
/// [`SafeDiscriminatorUnavailable`] when a link is ambiguous, missing, or
/// unresolved. This function does not panic.
pub fn resolve_cross_file_links(
    results: &[FileResult],
    baseline: Option<&BTreeSet<String>>,
) -> Result<Vec<FileResult>, SafeDiscriminatorUnavailable> {
    let index = index_file_results(results);
    for (idx, res) in results.iter().enumerate() {
        if res.links.is_empty() {
            continue;
        }
        for (link_index, link) in res.links.iter().enumerate() {
            let mut cand = if link.kind == "session_ref" {
                session_candidates(&index, &link.target)
            } else {
                tip_candidates(&index, &link.target)
            };
            let self_matched = cand.contains(&idx);
            cand.remove(&idx);
            if cand.len() == 1 || (self_matched && cand.is_empty()) {
                continue;
            }
            let draft = classify_link(&link.kind, &link.target, cand.len());
            return Err(stop_before_safe_discriminator(&draft, link_index, baseline));
        }
    }
    Ok(results.to_vec())
}

fn index_file_results(results: &[FileResult]) -> FileIndex {
    let mut index = FileIndex {
        by_session: BTreeMap::new(),
        by_stem: BTreeMap::new(),
        by_tip: BTreeMap::new(),
    };
    for (idx, res) in results.iter().enumerate() {
        if let Some(session_id) = present_text(res.session_id.as_deref()) {
            insert_id(&mut index.by_session, session_id, idx);
        }
        let stem = python_path_stem(&res.path);
        if !stem.is_empty() {
            insert_id(&mut index.by_stem, &stem, idx);
            if let Some(uuid) = rollout_uuid(&stem) {
                insert_id(&mut index.by_stem, &uuid, idx);
            }
        }
        if let Some(tip_id) = present_text(res.tip_id.as_deref()) {
            insert_id(&mut index.by_tip, tip_id, idx);
        }
    }
    index
}

fn present_text(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

fn insert_id(map: &mut BTreeMap<String, BTreeSet<usize>>, key: &str, idx: usize) {
    map.entry(key.to_owned()).or_default().insert(idx);
}

fn session_candidates(index: &FileIndex, target: &str) -> BTreeSet<usize> {
    let mut cand = BTreeSet::new();
    extend_ids(&mut cand, &index.by_session, target);
    extend_ids(&mut cand, &index.by_stem, target);
    if looks_pathy(target) {
        let stem = python_path_stem(target);
        extend_ids(&mut cand, &index.by_session, &stem);
        extend_ids(&mut cand, &index.by_stem, &stem);
    }
    cand
}

fn tip_candidates(index: &FileIndex, target: &str) -> BTreeSet<usize> {
    let mut cand = BTreeSet::new();
    extend_ids(&mut cand, &index.by_tip, target);
    cand
}

fn extend_ids(cand: &mut BTreeSet<usize>, map: &BTreeMap<String, BTreeSet<usize>>, key: &str) {
    if let Some(found) = map.get(key) {
        cand.extend(found.iter().copied());
    }
}

fn classify_link(kind: &str, target: &str, candidate_count: usize) -> LinkDraft {
    if candidate_count > 1 {
        LinkDraft {
            resolution: "ambiguous",
            severity: Severity::Warning,
            message: "Cross-file resume link is ambiguous: multiple scanned files match",
            candidate_count,
        }
    } else if kind == "head_ref" || looks_pathy(target) {
        LinkDraft {
            resolution: "unresolved",
            severity: Severity::Info,
            message: "Cross-file resume link target is outside the scanned set",
            candidate_count,
        }
    } else {
        LinkDraft {
            resolution: "missing",
            severity: Severity::Warning,
            message: "Cross-file resume link target is absent from the scanned set",
            candidate_count,
        }
    }
}

fn stop_before_safe_discriminator(
    draft: &LinkDraft,
    link_index: usize,
    baseline: Option<&BTreeSet<String>>,
) -> SafeDiscriminatorUnavailable {
    let _bound = (
        draft.resolution,
        draft.severity,
        draft.message,
        draft.candidate_count,
        link_index,
        baseline.map(BTreeSet::len),
    );
    SafeDiscriminatorUnavailable
}

fn python_path_stem(path: &str) -> String {
    stem_of_name(final_component(path))
}

fn final_component(path: &str) -> &str {
    let bytes = path.as_bytes();
    let mut last = "";
    let mut start = 0;
    let mut index = 0;
    while index <= bytes.len() {
        let at_end = index == bytes.len();
        let is_sep = !at_end && (bytes[index] == b'/' || bytes[index] == b'\\');
        if at_end || is_sep {
            let part = &path[start..index];
            if !part.is_empty() && part != "." {
                last = part;
            }
            start = index.saturating_add(1);
        }
        if at_end {
            break;
        }
        index += 1;
    }
    last
}

fn stem_of_name(name: &str) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 && dot + 1 < name.len() => name[..dot].to_owned(),
        _ => name.to_owned(),
    }
}

#[cfg(test)]
mod rollout_links {
    use std::any::TypeId;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        looks_pathy, resolve_cross_file_links, rollout_uuid, walk_rollout_files, FileResult,
        RolloutWalk, SafeDiscriminatorUnavailable, ScanCount, ScanReport, SessionLink, Verdict,
        WalkRolloutFilesError, MINIMIZE_PATH_UNAVAILABLE, SAFE_DISCRIMINATOR_UNAVAILABLE,
        WALK_ROLLOUT_MAX_FILES,
    };

    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const PARENT_UUID: &str = "019f8b5a-7c3e-4d2f-9a1b-000000000001";

    fn int(number: i64) -> ScanCount {
        ScanCount::Int(number)
    }

    fn flag(value: bool) -> ScanCount {
        ScanCount::Bool(value)
    }

    fn link(kind: &str, target: &str) -> SessionLink {
        SessionLink::new(kind, target)
    }

    fn file(path: &str, session_id: Option<&str>, tip_id: Option<&str>) -> FileResult {
        let mut result = FileResult::new(path, Verdict::Healthy);
        result.session_id = session_id.map(str::to_owned);
        result.tip_id = tip_id.map(str::to_owned);
        result
    }

    fn assert_resolved(results: &[FileResult], baseline: Option<&BTreeSet<String>>) {
        assert_ne!(
            TypeId::of::<Result<Vec<FileResult>, SafeDiscriminatorUnavailable>>(),
            TypeId::of::<ScanReport>()
        );
        let resolved = resolve_cross_file_links(results, baseline).expect("resolved links");
        assert_eq!(resolved, results);
    }

    fn assert_seam(results: &[FileResult], baseline: Option<&BTreeSet<String>>, hidden: &[&str]) {
        assert_ne!(
            TypeId::of::<Result<Vec<FileResult>, SafeDiscriminatorUnavailable>>(),
            TypeId::of::<ScanReport>()
        );
        assert_ne!(
            TypeId::of::<Vec<FileResult>>(),
            TypeId::of::<Result<Vec<FileResult>, SafeDiscriminatorUnavailable>>()
        );
        let error = resolve_cross_file_links(results, baseline).expect_err("discriminator seam");
        assert_eq!(error, SafeDiscriminatorUnavailable);
        assert_eq!(error.to_string(), SAFE_DISCRIMINATOR_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.adapters.safe_value.safe_discriminator is not available"
        );
        assert!(error.source().is_none());
        let text = error.to_string();
        for secret in hidden {
            assert!(!text.contains(secret), "{secret}");
        }
        assert!(!text.contains("ambiguous"));
        assert!(!text.contains("missing"));
        assert!(!text.contains("unresolved"));
    }

    #[test]
    fn rollout_uuid_is_anchored_and_not_the_state_db_search() {
        let stamped = format!("rollout-2026-01-01T00-00-00-{UUID}");
        assert_eq!(rollout_uuid(&stamped).as_deref(), Some(UUID));
        let upper = format!("rollout-2026-01-01T00-00-00-{}", UUID.to_ascii_uppercase());
        assert_eq!(rollout_uuid(&upper).as_deref(), Some(UUID));
        assert_eq!(
            rollout_uuid(&format!("rollout-x-{UUID}")).as_deref(),
            Some(UUID)
        );
        assert_eq!(
            rollout_uuid(&format!("rollout--{UUID}")).as_deref(),
            Some(UUID)
        );
        assert_eq!(
            rollout_uuid(&format!("rollout-x-{UUID}\n")).as_deref(),
            Some(UUID)
        );
        assert_eq!(
            rollout_uuid(&format!("rollout-\u{FF10}-{UUID}")).as_deref(),
            Some(UUID)
        );
        assert_eq!(rollout_uuid(&format!("rollout-{UUID}")), None);
        assert_eq!(
            crate::state_db::rollout_uuid_from_name(&format!("rollout-{UUID}")).as_deref(),
            Some(UUID)
        );
        assert_eq!(rollout_uuid(&format!("not-rollout-x-{UUID}")), None);
        assert_eq!(rollout_uuid(&format!("Rollout-x-{UUID}")), None);
        assert_eq!(rollout_uuid(&format!("rollout-x-{UUID}\n\n")), None);
        assert_eq!(rollout_uuid(&format!("rollout-x-{UUID} ")), None);
        assert_eq!(rollout_uuid(&format!("rollout-x-{UUID}-extra")), None);
        assert_eq!(rollout_uuid(&format!("prefix-rollout-x-{UUID}")), None);
        assert_eq!(rollout_uuid(&format!("rollout-\n-{UUID}")), None);
        assert_eq!(
            rollout_uuid("rollout-x-01234567-89ab-cdef-0123-456789abcdeg"),
            None
        );
        assert_eq!(
            rollout_uuid("rollout-x-\u{FF10}1234567-89ab-cdef-0123-456789abcdef"),
            None
        );
        assert_eq!(rollout_uuid(""), None);
        assert_eq!(rollout_uuid("rollout-"), None);
        assert_eq!(rollout_uuid(PARENT_UUID), None);
    }

    #[test]
    fn looks_pathy_normalizes_slashes_and_keeps_suffix_case() {
        assert!(!looks_pathy("sess-b"));
        assert!(!looks_pathy(""));
        assert!(!looks_pathy("foo.JSONL"));
        assert!(!looks_pathy("foo.JSON"));
        assert!(!looks_pathy("foo.jsonl.bak"));
        assert!(looks_pathy("foo.jsonl"));
        assert!(looks_pathy("foo.json"));
        assert!(looks_pathy(".jsonl"));
        assert!(looks_pathy(".json"));
        assert!(looks_pathy("a/b"));
        assert!(looks_pathy("a\\b"));
        assert!(looks_pathy("../elsewhere/sess-q.jsonl"));
        assert!(looks_pathy("..\\elsewhere\\sess-q.jsonl"));
    }

    #[test]
    fn path_stem_drops_dot_parts_and_both_separators() {
        let cases = [
            ("foo/./bar.jsonl", "bar"),
            ("foo/../bar.jsonl", "bar"),
            ("./bar.jsonl", "bar"),
            ("foo//bar.jsonl", "bar"),
            ("foo/bar/.", "bar"),
            ("/bar.jsonl", "bar"),
            ("foo/..", ".."),
            ("..", ".."),
            ("foo\\..\\bar.jsonl", "bar"),
            ("C:/foo/bar.jsonl", "bar"),
            ("sess-c.jsonl", "sess-c"),
            (".jsonl", ".jsonl"),
            ("foo.", "foo."),
            ("", ""),
            (".", ""),
            ("foo/bar/", "bar"),
            ("a\\b\\c.jsonl", "c"),
            ("dir\\foo.jsonl", "foo"),
            ("../elsewhere/sess-q.jsonl", "sess-q"),
            ("..\\elsewhere\\sess-q.jsonl", "sess-q"),
            ("foo.jsonl.bak", "foo.jsonl"),
            ("foo\\bar\\", "bar"),
            (
                "rollout-2026-01-01T00-00-00-019f8b5a-7c3e-4d2f-9a1b-000000000001.jsonl",
                "rollout-2026-01-01T00-00-00-019f8b5a-7c3e-4d2f-9a1b-000000000001",
            ),
        ];
        for (path, stem) in cases {
            assert_eq!(super::python_path_stem(path), stem, "{path}");
        }
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sesslint-scan-06-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("scratch");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(path, b"").expect("touch");
    }

    fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "symlink",
            ))
        }
    }

    fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "symlink",
            ))
        }
    }

    fn assert_empty(walk: Option<RolloutWalk>) {
        let walk = walk.expect("provable empty walk");
        assert!(walk.uuids.is_empty());
        assert!(walk.paths.is_empty());
    }

    fn assert_minimize(dir: &Path, max_files: ScanCount) {
        assert_ne!(
            TypeId::of::<Result<Option<RolloutWalk>, WalkRolloutFilesError>>(),
            TypeId::of::<ScanReport>()
        );
        let error = walk_rollout_files(dir, max_files).expect_err("minimize seam");
        assert_eq!(error, WalkRolloutFilesError::MinimizePath);
        assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.report.minimize_path is not available"
        );
        assert!(error.source().is_none());
        let text = error.to_string();
        assert!(!text.contains("rollout"));
        assert!(!text.contains("019f"));
        assert!(!text.contains("secret"));
        assert!(!text.chars().any(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn walk_default_cap_is_200000_and_stops_on_a_rollout_ledger() {
        assert_eq!(WALK_ROLLOUT_MAX_FILES, 200_000);
        assert_ne!(WALK_ROLLOUT_MAX_FILES, super::DEFAULT_MAX_FILES);
        let scratch = Scratch::new("cap");
        let sessions = scratch.path().join("sessions");
        touch(&sessions.join("note.txt"));
        touch(&sessions.join("nested").join("also.txt"));
        touch(&scratch.path().join("rollout-outside.jsonl"));
        let listed = walk_rollout_files(&sessions, int(WALK_ROLLOUT_MAX_FILES)).expect("walk");
        assert_empty(listed);
        assert_minimize(scratch.path(), int(WALK_ROLLOUT_MAX_FILES));
        assert!(walk_rollout_files(&sessions, int(1))
            .expect("two files hit the cap")
            .is_none());
        assert!(
            walk_rollout_files(&scratch.path().join("missing"), flag(false))
                .expect("absent")
                .is_none()
        );
        assert!(walk_rollout_files(&sessions.join("note.txt"), flag(true))
            .expect("file")
            .is_none());
        let empty = sessions.join("empty-child");
        fs::create_dir_all(&empty).expect("empty");
        assert_empty(walk_rollout_files(&empty, flag(true)).expect("bool is unused"));
        assert_empty(walk_rollout_files(&empty, flag(false)).expect("bool is unused"));
        let bool_error = walk_rollout_files(&sessions, flag(true)).expect_err("true is not 1");
        assert_eq!(bool_error, WalkRolloutFilesError::MaxFilesBool);
        assert_eq!(bool_error.to_string(), "max_files bool is not an int");
        assert!(!bool_error.to_string().contains("True"));
        assert!(!bool_error.to_string().contains('1'));
        let false_error = walk_rollout_files(&sessions, flag(false)).expect_err("false is not 0");
        assert_eq!(false_error.to_string(), "max_files bool is not an int");
        assert!(!false_error.to_string().contains("False"));
        assert!(!false_error.to_string().contains('0'));
        assert!(walk_rollout_files(&sessions, int(0))
            .expect("zero")
            .is_none());
        assert!(walk_rollout_files(&sessions, int(-4))
            .expect("negative")
            .is_none());
    }

    #[test]
    fn walk_counts_top_down_and_stops_before_minimize_path() {
        let scratch = Scratch::new("order");
        let sessions = scratch.path().join("sessions");
        touch(&sessions.join("z.txt"));
        touch(&sessions.join("sub").join("rollout-z.jsonl"));
        assert!(walk_rollout_files(&sessions, int(1))
            .expect("root file fills the cap")
            .is_none());
        assert_minimize(&sessions, int(2));
        assert_minimize(&sessions, int(WALK_ROLLOUT_MAX_FILES));
        let only = scratch.path().join("only");
        touch(&only.join("rollout-secret.jsonl"));
        assert_minimize(&only, int(1));
        assert!(walk_rollout_files(&only, int(0))
            .expect("cap before name")
            .is_none());
        let bool_first = walk_rollout_files(&only, flag(true)).expect_err("bool before seam");
        assert_eq!(bool_first, WalkRolloutFilesError::MaxFilesBool);
        touch(&sessions.join("a.txt"));
        assert!(walk_rollout_files(&sessions, int(1))
            .expect("sorted a.txt is first")
            .is_none());
    }

    #[test]
    fn walk_does_not_follow_directory_symlinks_or_leave_the_root() {
        let scratch = Scratch::new("links");
        let sessions = scratch.path().join("sessions");
        fs::create_dir_all(&sessions).expect("sessions");
        touch(&sessions.join("note.txt"));
        let elsewhere = scratch.path().join("elsewhere");
        touch(&elsewhere.join("rollout-linked.jsonl"));
        symlink_dir(&elsewhere, &sessions.join("linked")).expect("dir symlink");
        let listed = walk_rollout_files(&sessions, int(WALK_ROLLOUT_MAX_FILES)).expect("walk");
        assert_empty(listed);
        let outside = scratch.path().join("rollout-outside.jsonl");
        touch(&outside);
        symlink_file(&outside, &sessions.join("rollout-via-link.jsonl")).expect("file symlink");
        assert_minimize(&sessions, int(WALK_ROLLOUT_MAX_FILES));
        let child = sessions.join("nested-only");
        fs::create_dir_all(&child).expect("child");
        touch(&child.join("plain.txt"));
        let child_walk = walk_rollout_files(&child, int(WALK_ROLLOUT_MAX_FILES)).expect("child");
        assert_empty(child_walk);
    }

    #[test]
    fn resolved_links_stay_a_file_result_list() {
        assert_resolved(&[], None);
        let mut self_link = file("sess-s.jsonl", Some("sess-s"), Some("s2"));
        self_link.links.push(link("session_ref", "sess-s"));
        self_link.warning_count = 0;
        assert_resolved(std::slice::from_ref(&self_link), None);

        let parent = file("parent-file.jsonl", Some("opaque-id"), Some("p2"));
        let mut child = file("child.jsonl", Some("child-id"), Some("c2"));
        child.links.push(link("session_ref", "parent-file"));
        assert_resolved(&[parent, child.clone()], None);

        let mut head = file("sess-h.jsonl", Some("sess-h"), Some("a2"));
        head.links.push(link("head_ref", "a2"));
        let source = file("sess-a.jsonl", Some("sess-a"), Some("a2"));
        assert_resolved(&[source, head], None);

        let mut own_tip = file("sess-m.jsonl", Some("sess-m"), Some("m-tip"));
        own_tip.links.push(link("head_ref", "m-tip"));
        assert_resolved(std::slice::from_ref(&own_tip), None);

        let mut first = file("a.jsonl", Some("same"), None);
        let mut second = file("b.jsonl", Some("same"), None);
        second.links.push(link("session_ref", "same"));
        assert_resolved(&[first.clone(), second], None);
        first.links.push(link("session_ref", "same"));
        let third = file("c.jsonl", Some("same"), None);
        assert_resolved(&[first, third], None);

        let torn = file(
            "rollout-2026-01-01T00-00-00-019f8b5a-7c3e-4d2f-9a1b-000000000001.jsonl",
            None,
            None,
        );
        let mut spawned = file("rollout-child.jsonl", Some("thread-child"), Some("e1"));
        spawned.links.push(link("session_ref", PARENT_UUID));
        assert_resolved(&[torn, spawned], None);

        let upper_name = format!(
            "rollout-2026-01-01T00-00-00-{}.jsonl",
            PARENT_UUID.to_ascii_uppercase()
        );
        let upper = file(&upper_name, None, None);
        let mut lower_link = file("child.jsonl", Some("thread-child"), None);
        lower_link.links.push(link("session_ref", PARENT_UUID));
        assert_resolved(&[upper, lower_link], None);

        let nested = file("nested/parent-file.jsonl", Some("opaque-id"), None);
        let mut path_link = file("child.jsonl", Some("child-id"), None);
        path_link
            .links
            .push(link("session_ref", "dir/parent-file.jsonl"));
        assert_resolved(&[nested, path_link], None);

        let windows_stem = file("nested\\parent-file.jsonl", Some("opaque-id"), None);
        let mut bare = file("child.jsonl", Some("child-id"), None);
        bare.links.push(link("session_ref", "parent-file"));
        assert_resolved(&[windows_stem, bare], None);

        let mut spaced = file("space.jsonl", Some(" "), Some("tip"));
        let mut spacer = file("other.jsonl", Some("other"), None);
        spacer.links.push(link("session_ref", " "));
        assert_resolved(&[spaced.clone(), spacer], None);
        spaced.links.push(link("session_ref", "sess-s"));
        spaced.links.push(link("head_ref", "tip"));
        let known = file("sess-s.jsonl", Some("sess-s"), Some("tip"));
        let baseline = BTreeSet::from(["fp-synthetic".to_owned()]);
        assert_resolved(&[known, spaced], Some(&baseline));
    }

    #[test]
    fn unresolved_links_stop_at_safe_discriminator() {
        let mut missing = file("sess-c.jsonl", Some("sess-c"), Some("c2"));
        missing.links.push(link("session_ref", "sess-b"));
        missing.links.push(link("head_ref", "gone-tip"));
        assert_seam(&[missing], None, &["sess-b", "sess-c", "gone-tip"]);

        let mut outside = file("sess-x.jsonl", Some("sess-x"), None);
        outside
            .links
            .push(link("session_ref", "../elsewhere/sess-q.jsonl"));
        assert_seam(&[outside], None, &["elsewhere", "sess-q", "sess-x"]);

        let parent = file("sess-a.jsonl", Some("sess-a"), Some("a2"));
        let mut mid = file("sess-m.jsonl", Some("sess-m"), Some("m2"));
        mid.links.push(link("head_ref", "a1"));
        assert_seam(&[parent.clone(), mid], None, &["a1", "sess-a"]);

        let mut path_head = file("sess-p.jsonl", Some("sess-p"), Some("tip-a"));
        path_head.links.push(link("head_ref", "../x/tip-a"));
        assert_seam(&[path_head], None, &["tip-a"]);

        let mut not_session = file("sess-t.jsonl", Some("sess-a"), Some("other-tip"));
        not_session.links.push(link("head_ref", "sess-a"));
        assert_seam(&[parent, not_session], None, &["sess-a"]);

        let mut other_kind = file("sess-k.jsonl", Some("sess-k"), Some("k-tip"));
        other_kind.links.push(link("other", "sess-k"));
        assert_seam(std::slice::from_ref(&other_kind), None, &["sess-k"]);
        other_kind.links.clear();
        other_kind.links.push(link("other", "k-tip"));
        assert_resolved(std::slice::from_ref(&other_kind), None);

        let blank = file("blank.jsonl", Some(""), None);
        let mut blank_link = file("child.jsonl", Some("child"), None);
        blank_link.links.push(link("session_ref", ""));
        assert_seam(&[blank, blank_link], None, &["child", "blank"]);

        let left = file("a.jsonl", Some("same"), None);
        let right = file("b.jsonl", Some("same"), None);
        let mut ambiguous = file("c.jsonl", Some("child"), Some("c2"));
        ambiguous.links.push(link("session_ref", "known"));
        ambiguous.links.push(link("session_ref", "same"));
        assert_seam(&[left, right, ambiguous], None, &["same", "known", "child"]);

        let mut upper_target = file("child.jsonl", Some("thread-child"), None);
        upper_target
            .links
            .push(link("session_ref", &PARENT_UUID.to_ascii_uppercase()));
        let upper_name = format!(
            "rollout-2026-01-01T00-00-00-{}.jsonl",
            PARENT_UUID.to_ascii_uppercase()
        );
        let upper = file(&upper_name, None, None);
        assert_seam(
            &[upper, upper_target],
            None,
            &[PARENT_UUID, "019F8B5A", "thread-child"],
        );

        let mut one = file("only.jsonl", Some("only"), None);
        one.links.push(link("session_ref", "absent-id"));
        let baseline = BTreeSet::from(["fp-synthetic".to_owned()]);
        assert_seam(
            &[one],
            Some(&baseline),
            &["absent-id", "fp-synthetic", "only"],
        );

        let mut self_then_missing = file("sess-s.jsonl", Some("sess-s"), Some("s2"));
        self_then_missing.links.push(link("session_ref", "sess-s"));
        self_then_missing
            .links
            .push(link("session_ref", "sess-missing"));
        assert_seam(
            &[self_then_missing],
            Some(&baseline),
            &["sess-missing", "sess-s"],
        );
    }
}

#[allow(
    clippy::items_after_test_module,
    reason = "RX-P2.6-scan-scan-07 appends after the existing tests"
)]
mod session_indexes {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use super::{FileResult, MinimizePathUnavailable};

    /// Pin literal for `FORMAT_CLAUDE_CODE`. Data, not an adapters call.
    pub const FORMAT_CLAUDE_CODE: &str = "claude-code-jsonl";

    /// Pin literal for `FORMAT_CODEX_ROLLOUT`. Data, not an adapters call.
    pub const FORMAT_CODEX_ROLLOUT: &str = "codex-rollout";

    /// Pin `index_format_by_name`, in insertion order.
    const INDEX_FORMAT_BY_NAME: &[(&str, &str)] = &[
        ("sessions-index.json", FORMAT_CLAUDE_CODE),
        ("session_index.jsonl", FORMAT_CODEX_ROLLOUT),
    ];

    struct Parsed {
        drv: String,
        root: String,
        tail: Vec<String>,
    }

    struct SortedIndex<'a> {
        key: String,
        path: &'a Path,
    }

    /// Python: `_reconcile_session_indexes`.
    ///
    /// Port of `src/sesslint/scan.py` lines 1674–1915
    /// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
    /// Stops before `_reconcile_state_dbs`.
    ///
    /// [`FORMAT_CLAUDE_CODE`] is `claude-code-jsonl`. [`FORMAT_CODEX_ROLLOUT`]
    /// is `codex-rollout`. Those strings are data. This crate does not call
    /// `sesslint.adapters`. `sessions-index.json` maps to the Claude literal.
    /// `session_index.jsonl` maps to the Codex literal.
    ///
    /// Results are indexed by the stored `path` and by
    /// `PurePosixPath(path).parent.as_posix()` before the index-file loop.
    /// `PurePosixPath` does not treat `\` as a separator. A bool is not an
    /// int. `cache_hit` stays a bool. `warning_count` and `error_count` stay
    /// `i64`. This function does not coerce either kind.
    ///
    /// An empty `index_paths` returns the input rows. `minimize_path` is not
    /// called.
    ///
    /// A non-empty `index_paths` is sorted by Python `str(path)`, which is
    /// `pathlib.Path` on this platform, not `PurePosixPath`. The first path
    /// is where the pin calls `sesslint.report.minimize_path`, before
    /// `sesslint.indexes.read_index`. That helper is not in this crate.
    /// Display is `sesslint.report.minimize_path is not available`.
    /// `read_codex_state` and `make_finding` are not called. No [`FileResult`]
    /// list is returned. No SL402 finding is created. No
    /// [`super::ScanReport`] is returned.
    ///
    /// Rust has no defaults. Pass `&[]` when `state_db_files` is omitted and
    /// `None` when `baseline` is omitted.
    ///
    /// # Errors
    ///
    /// [`MinimizePathUnavailable`] when `index_paths` is non-empty, or when an
    /// index path has no Python `str`. This function does not panic.
    pub fn reconcile_session_indexes(
        results: &[FileResult],
        index_paths: &[&Path],
        state_db_files: &[&Path],
        baseline: Option<&BTreeSet<String>>,
    ) -> Result<Vec<FileResult>, MinimizePathUnavailable> {
        let formats = format_rows();
        let by_path = index_by_path(results);
        let out = results.to_vec();
        let by_parent = index_by_parent(results);
        let path_count = by_path.len();
        let parent_count = by_parent.len();
        if index_paths.is_empty() {
            let _indexed = (formats, path_count, parent_count);
            return Ok(out);
        }
        let sorted = sort_index_paths(index_paths)?;
        let Some(first) = sorted.first() else {
            return Err(MinimizePathUnavailable);
        };
        let _bound = (
            formats,
            path_count,
            parent_count,
            first.key.len(),
            first.path.as_os_str().is_empty(),
            state_db_files.len(),
            baseline.map(BTreeSet::len),
        );
        Err(MinimizePathUnavailable)
    }

    fn format_rows() -> usize {
        for (name, format) in INDEX_FORMAT_BY_NAME {
            let _row = (name.len(), format.len());
        }
        INDEX_FORMAT_BY_NAME.len()
    }

    fn index_by_path(results: &[FileResult]) -> BTreeMap<String, usize> {
        let mut by_path = BTreeMap::new();
        for (index, result) in results.iter().enumerate() {
            by_path.insert(result.path.clone(), index);
        }
        by_path
    }

    fn index_by_parent(results: &[FileResult]) -> BTreeMap<String, Vec<usize>> {
        let mut by_parent: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, result) in results.iter().enumerate() {
            by_parent
                .entry(pure_posix_parent(&result.path))
                .or_default()
                .push(index);
        }
        by_parent
    }

    fn sort_index_paths<'a>(
        index_paths: &'a [&Path],
    ) -> Result<Vec<SortedIndex<'a>>, MinimizePathUnavailable> {
        let mut keyed = Vec::with_capacity(index_paths.len());
        for path in index_paths {
            let Some(key) = python_path_str(path) else {
                return Err(MinimizePathUnavailable);
            };
            keyed.push(SortedIndex { key, path });
        }
        keyed.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(keyed)
    }

    fn python_path_str(path: &Path) -> Option<String> {
        path.to_str().map(python_path_text)
    }

    fn python_path_text(text: &str) -> String {
        format_parsed(&parse_platform(text), platform_sep())
    }

    #[cfg(windows)]
    fn parse_platform(text: &str) -> Parsed {
        parse_windows(text)
    }

    #[cfg(not(windows))]
    fn parse_platform(text: &str) -> Parsed {
        parse_posix(text)
    }

    #[cfg(windows)]
    fn platform_sep() -> &'static str {
        "\\"
    }

    #[cfg(not(windows))]
    fn platform_sep() -> &'static str {
        "/"
    }

    fn pure_posix_parent(text: &str) -> String {
        let mut parsed = parse_posix(text);
        if parsed.tail.is_empty() && !parsed.root.is_empty() {
            return format_parsed(&parsed, "/");
        }
        if !parsed.tail.is_empty() {
            parsed.tail.pop();
        }
        format_parsed(&parsed, "/")
    }

    fn parse_posix(text: &str) -> Parsed {
        let (root, rel) = if let Some(stripped) = text.strip_prefix('/') {
            let extra = stripped.chars().take_while(|ch| *ch == '/').count();
            let leading = extra + 1;
            let rest = stripped.trim_start_matches('/');
            if leading == 2 {
                ("//", rest)
            } else {
                ("/", rest)
            }
        } else {
            ("", text)
        };
        Parsed {
            drv: String::new(),
            root: root.to_owned(),
            tail: split_tail(rel, '/'),
        }
    }

    fn parse_windows(text: &str) -> Parsed {
        let (prefix, part) = prepare_windows(text);
        let (drv, root, rel) = splitroot_windows(&prefix, &part);
        Parsed {
            drv,
            root,
            tail: split_tail(&rel, '\\'),
        }
    }

    fn prepare_windows(text: &str) -> (String, String) {
        let normalized = text.replace('/', "\\");
        if let Some(rest) = normalized.strip_prefix("\\\\?\\") {
            if let Some(after) = rest.strip_prefix("UNC\\") {
                return ("\\\\?\\UNC".to_owned(), format!("\\\\{after}"));
            }
            return ("\\\\?\\".to_owned(), rest.to_owned());
        }
        (String::new(), normalized)
    }

    fn splitroot_windows(prefix: &str, part: &str) -> (String, String, String) {
        let bytes = part.as_bytes();
        let first = bytes.first().copied();
        let second = bytes.get(1).copied();
        let third = bytes.get(2).copied();
        if first == Some(b'\\') && second == Some(b'\\') && third != Some(b'\\') {
            if let Some((drv, rel)) = assemble_unc(prefix, part) {
                return (drv, "\\".to_owned(), rel);
            }
        }
        let (drv, mut rest, root_probe) = split_drive(part);
        let mut root = String::new();
        if root_probe == Some(b'\\') {
            root = "\\".to_owned();
            rest = rest.trim_start_matches('\\');
        }
        (format!("{prefix}{drv}"), root, rest.to_owned())
    }

    fn split_drive(part: &str) -> (&str, &str, Option<u8>) {
        let bytes = part.as_bytes();
        let first = bytes.first().copied();
        let second = bytes.get(1).copied();
        let third = bytes.get(2).copied();
        if second == Some(b':') && first.is_some_and(|byte| byte.is_ascii_alphabetic()) {
            if let (Some(drv), Some(rest)) = (part.get(..2), part.get(2..)) {
                return (drv, rest, third);
            }
        }
        ("", part, first)
    }

    fn assemble_unc(prefix: &str, part: &str) -> Option<(String, String)> {
        let index2 = unc_index2(part)?;
        if index2 < 1 || index2 > part.len() {
            return None;
        }
        let drv = if prefix.is_empty() {
            part.get(..index2)?.to_owned()
        } else {
            let middle = part.get(1..index2)?;
            format!("{prefix}{middle}")
        };
        let rel_at = index2.saturating_add(1);
        let rel = if rel_at > part.len() {
            String::new()
        } else {
            match part.get(rel_at..) {
                Some(text) => text.to_owned(),
                None => return None,
            }
        };
        Some((drv, rel))
    }

    fn unc_index2(part: &str) -> Option<usize> {
        let bytes = part.as_bytes();
        let found = bytes.iter().skip(2).position(|byte| *byte == b'\\')?;
        let index = found.checked_add(2)?;
        let skip_from = index.checked_add(1)?;
        let next = bytes
            .iter()
            .enumerate()
            .skip(skip_from)
            .find(|(_, byte)| **byte == b'\\');
        match next {
            Some((index2, _)) if index2 == skip_from => None,
            Some((index2, _)) => Some(index2),
            None => Some(bytes.len()),
        }
    }

    fn format_parsed(parsed: &Parsed, sep: &str) -> String {
        let body = if parsed.drv.is_empty() && parsed.root.is_empty() {
            parsed.tail.join(sep)
        } else {
            let mut out = String::new();
            out.push_str(&parsed.drv);
            out.push_str(&parsed.root);
            if !parsed.tail.is_empty() {
                out.push_str(&parsed.tail.join(sep));
            }
            out
        };
        if body.is_empty() {
            ".".to_owned()
        } else {
            body
        }
    }

    fn split_tail(rel: &str, sep: char) -> Vec<String> {
        if rel.is_empty() {
            return Vec::new();
        }
        rel.split(sep)
            .filter(|piece| !piece.is_empty() && *piece != ".")
            .map(str::to_owned)
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use std::any::TypeId;
        use std::collections::BTreeSet;
        use std::error::Error;
        use std::path::Path;

        use super::super::{
            FileResult, MinimizePathUnavailable, ScanReport, Verdict, MINIMIZE_PATH_UNAVAILABLE,
        };
        use super::{
            index_by_parent, index_by_path, pure_posix_parent, python_path_text,
            reconcile_session_indexes, sort_index_paths, FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT,
            INDEX_FORMAT_BY_NAME,
        };

        fn row(path: &str, verdict: Verdict) -> FileResult {
            FileResult::new(path, verdict)
        }

        #[test]
        fn format_literals_map_the_two_index_names() {
            assert_eq!(FORMAT_CLAUDE_CODE, "claude-code-jsonl");
            assert_eq!(FORMAT_CODEX_ROLLOUT, "codex-rollout");
            assert_ne!(FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT);
            assert_eq!(
                INDEX_FORMAT_BY_NAME,
                [
                    ("sessions-index.json", FORMAT_CLAUDE_CODE),
                    ("session_index.jsonl", FORMAT_CODEX_ROLLOUT),
                ]
                .as_slice()
            );
            assert_ne!(TypeId::of::<bool>(), TypeId::of::<i64>());
        }

        #[test]
        fn pure_posix_parent_keeps_dotdot_and_ignores_backslashes() {
            let cases = [
                ("", "."),
                (".", "."),
                ("..", "."),
                ("/", "/"),
                ("//", "//"),
                ("///", "/"),
                ("foo", "."),
                ("foo/", "."),
                ("foo/bar", "foo"),
                ("foo/bar/", "foo"),
                ("foo/./bar", "foo"),
                ("foo//bar", "foo"),
                ("foo/bar/..", "foo/bar"),
                ("foo/../bar", "foo/.."),
                ("foo/bar/../..", "foo/bar/.."),
                ("C:/foo", "C:"),
                ("C:/", "."),
                ("C:foo", "."),
                ("C:foo/bar", "C:foo"),
                ("/foo", "/"),
                ("/foo/bar", "/foo"),
                ("//server", "//"),
                ("//server/share", "//server"),
                ("//server/share/x", "//server/share"),
                ("///server/share/x", "/server/share"),
                ("///foo/bar", "/foo"),
                ("//foo//bar", "//foo"),
                ("//foo/bar/", "//foo"),
                ("a/b/c.jsonl", "a/b"),
                ("a/b/c/", "a/b"),
                ("sessions-index.json", "."),
                ("proj/sessions-index.json", "proj"),
                ("a/session_index.jsonl", "a"),
                ("../elsewhere/sess-q.jsonl", "../elsewhere"),
                ("../..", ".."),
                ("/..", "/"),
                ("/../foo", "/.."),
                ("foo/bar/.", "foo"),
                ("./foo", "."),
                ("foo/././bar", "foo"),
                (" ", "."),
                ("foo/ ", "foo"),
                ("...", "."),
                ("foo/.../bar", "foo/..."),
                ("a\\b\\c.jsonl", "."),
                ("a\\b", "."),
                ("foo\\bar/baz", "foo\\bar"),
                ("a\\b/c.jsonl", "a\\b"),
                ("foo\n/bar", "foo\n"),
                ("///a", "/"),
            ];
            for (path, parent) in cases {
                assert_eq!(pure_posix_parent(path), parent, "{path:?}");
            }
        }

        #[test]
        fn indexes_use_raw_paths_and_posix_parents() {
            let results = [
                row("same.jsonl", Verdict::Healthy),
                row("proj/b.jsonl", Verdict::Invalid),
                row("proj/a.jsonl", Verdict::Healthy),
                row("a\\b\\c.jsonl", Verdict::Skipped),
                row("same.jsonl", Verdict::Unreadable),
                row("", Verdict::Unsupported),
                row(".", Verdict::Healthy),
            ];
            let by_path = index_by_path(&results);
            assert_eq!(by_path.get("same.jsonl").copied(), Some(4));
            assert_eq!(by_path.get("proj/b.jsonl").copied(), Some(1));
            assert_eq!(by_path.get("").copied(), Some(5));
            assert_eq!(by_path.get(".").copied(), Some(6));
            assert_eq!(by_path.len(), 6);

            let by_parent = index_by_parent(&results);
            assert_eq!(
                by_parent.get("proj").map(Vec::as_slice),
                Some([1usize, 2].as_slice())
            );
            assert_eq!(
                by_parent.get(".").map(Vec::as_slice),
                Some([0usize, 3, 4, 5, 6].as_slice())
            );
            assert!(!by_parent.contains_key("a\\b"));
        }

        #[test]
        fn empty_index_paths_return_rows_and_keep_bools_distinct_from_ints() {
            let mut first = row("proj/a.jsonl", Verdict::Invalid);
            first.cache_hit = true;
            first.warning_count = 0;
            first.error_count = 3;
            first.max_findings_per_code = 4;
            first.detected_format = Some(FORMAT_CLAUDE_CODE.to_owned());
            first.session_id = Some("sess-secret".to_owned());
            first.tip_id = Some("tip-secret".to_owned());
            first.skipped_reason = Some("synthetic".to_owned());
            let mut second = row("same.jsonl", Verdict::Healthy);
            second.cache_hit = false;
            second.warning_count = 5;
            second.error_count = 0;
            second.detected_format = Some(FORMAT_CODEX_ROLLOUT.to_owned());
            let third = row("same.jsonl", Verdict::Unreadable);
            let results = [first, second, third];
            let baseline = BTreeSet::from(["fp-synthetic".to_owned()]);
            let state = Path::new("C:/synthetic/missing-state.sqlite");
            let returned = reconcile_session_indexes(&results, &[], &[state], Some(&baseline))
                .expect("empty index list");
            assert_eq!(returned, results);
            assert!(returned[0].cache_hit);
            assert_eq!(returned[0].warning_count, 0);
            assert_eq!(returned[0].error_count, 3);
            assert!(!returned[1].cache_hit);
            assert_eq!(returned[1].warning_count, 5);
            assert_eq!(returned.len(), 3);
            let absent = reconcile_session_indexes(&[], &[], &[], None).expect("both empty");
            assert!(absent.is_empty());
            let none_baseline =
                reconcile_session_indexes(&results, &[], &[], None).expect("omitted baseline");
            assert_eq!(none_baseline, results);
        }

        #[test]
        fn non_empty_index_paths_stop_at_minimize_path() {
            let mut kept = row("proj/a.jsonl", Verdict::Healthy);
            kept.cache_hit = true;
            kept.warning_count = 0;
            kept.session_id = Some("sess-secret".to_owned());
            kept.detected_format = Some("claude-code-jsonl".to_owned());
            let results = [kept];
            let baseline = BTreeSet::from(["fp-synthetic".to_owned()]);
            let state = Path::new("C:/synthetic/state.sqlite");
            let hidden = [
                "proj/a.jsonl",
                "sess-secret",
                "fp-synthetic",
                "state.sqlite",
                "sessions-index.json",
                "session_index.jsonl",
                "SL402",
                "index-truncated",
                "index-malformed",
                "file-not-in-index",
                "index-entry-no-file",
                "read_index",
                "read_codex_state",
                "make_finding",
                "claude-code-jsonl",
            ];
            let paths = [
                Path::new("b/session_index.jsonl"),
                Path::new("a/sessions-index.json"),
            ];
            assert_stopped(&results, &paths, &[state], Some(&baseline), &hidden);
            assert_stopped(&[], &paths, &[], None, &hidden);
            assert_stopped(
                &results,
                &[Path::new("sessions-index.json")],
                &[],
                None,
                &hidden,
            );
            let missing = Path::new("C:/synthetic/does-not-exist/sessions-index.json");
            assert_stopped(&results, &[missing], &[state], Some(&baseline), &hidden);
        }

        fn assert_stopped(
            results: &[FileResult],
            index_paths: &[&Path],
            state_db_files: &[&Path],
            baseline: Option<&BTreeSet<String>>,
            hidden: &[&str],
        ) {
            assert_ne!(
                TypeId::of::<Result<Vec<FileResult>, MinimizePathUnavailable>>(),
                TypeId::of::<ScanReport>()
            );
            assert_ne!(
                TypeId::of::<Vec<FileResult>>(),
                TypeId::of::<Result<Vec<FileResult>, MinimizePathUnavailable>>()
            );
            let error = reconcile_session_indexes(results, index_paths, state_db_files, baseline)
                .expect_err("minimize seam");
            assert_eq!(error, MinimizePathUnavailable);
            assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
            assert_eq!(
                error.to_string(),
                "sesslint.report.minimize_path is not available"
            );
            assert!(error.source().is_none());
            let text = error.to_string();
            assert!(!text.contains('/'));
            assert!(!text.contains('\\'));
            assert!(!text.chars().any(|ch| ch.is_ascii_digit()));
            for secret in hidden {
                assert!(!text.contains(secret), "{secret}");
            }
        }

        #[cfg(windows)]
        #[test]
        fn python_path_str_uses_windows_pathlib() {
            let cases = [
                ("", "."),
                (".", "."),
                ("..", ".."),
                ("/", "\\"),
                ("//", "\\"),
                ("///", "\\"),
                ("foo", "foo"),
                ("foo/", "foo"),
                ("foo/bar", "foo\\bar"),
                ("foo/bar/", "foo\\bar"),
                ("foo/./bar", "foo\\bar"),
                ("foo//bar", "foo\\bar"),
                ("foo/bar/..", "foo\\bar\\.."),
                ("foo/../bar", "foo\\..\\bar"),
                ("C:/foo", "C:\\foo"),
                ("C:/", "C:\\"),
                ("C:", "C:"),
                ("C:foo", "C:foo"),
                ("C:foo/bar", "C:foo\\bar"),
                ("/foo", "\\foo"),
                ("/foo/bar", "\\foo\\bar"),
                ("//server/share", "\\\\server\\share\\"),
                ("//server/share/x", "\\\\server\\share\\x"),
                ("///server/share/x", "\\server\\share\\x"),
                ("\\\\server\\share", "\\\\server\\share\\"),
                ("\\\\server\\share\\x", "\\\\server\\share\\x"),
                ("\\\\server", "\\server"),
                ("\\\\?\\C:\\foo", "\\\\?\\C:\\foo"),
                ("\\\\?\\C:\\foo\\bar", "\\\\?\\C:\\foo\\bar"),
                ("\\\\?\\UNC\\server\\share", "\\\\?\\UNC\\server\\share\\"),
                (
                    "\\\\?\\UNC\\server\\share\\x",
                    "\\\\?\\UNC\\server\\share\\x",
                ),
                ("\\\\.\\C:\\foo", "\\\\.\\C:\\foo"),
                ("//?/c:/a", "\\\\?\\c:\\a"),
                ("\\\\?\\c:/a", "\\\\?\\c:\\a"),
                ("a/b", "a\\b"),
                ("a\\b", "a\\b"),
                ("sessions-index.json", "sessions-index.json"),
                ("a/session_index.jsonl", "a\\session_index.jsonl"),
                ("../..", "..\\.."),
                ("/..", "\\.."),
                ("/../foo", "\\..\\foo"),
                ("foo/bar/.", "foo\\bar"),
                ("./foo", "foo"),
                (" ", " "),
                ("foo/ ", "foo\\ "),
                ("foo\n/bar", "foo\n\\bar"),
                ("//foo//bar", "\\foo\\bar"),
                ("//foo/bar/", "\\\\foo\\bar\\"),
                ("C:\\foo\\..\\bar", "C:\\foo\\..\\bar"),
                ("a/b/c/", "a\\b\\c"),
            ];
            for (path, shown) in cases {
                assert_eq!(python_path_text(path), shown, "{path:?}");
            }
        }

        #[cfg(not(windows))]
        #[test]
        fn python_path_str_uses_posix_pathlib() {
            let cases = [
                ("", "."),
                ("foo/bar", "foo/bar"),
                ("foo/./bar", "foo/bar"),
                ("foo//bar", "foo/bar"),
                ("foo/bar/..", "foo/bar/.."),
                ("//server/share", "//server/share"),
                ("//server/share/x", "//server/share/x"),
                ("///server/share/x", "/server/share/x"),
                ("//", "//"),
                ("///", "/"),
                ("a\\b", "a\\b"),
                ("C:/foo", "C:/foo"),
                ("C:/", "C:"),
                ("../..", "../.."),
                ("/foo/bar", "/foo/bar"),
                ("foo\n/bar", "foo\n/bar"),
                ("//foo//bar", "//foo/bar"),
                (" ", " "),
                ("foo/ ", "foo/ "),
                ("sessions-index.json", "sessions-index.json"),
                ("a/session_index.jsonl", "a/session_index.jsonl"),
                ("///foo", "/foo"),
            ];
            for (path, shown) in cases {
                assert_eq!(python_path_text(path), shown, "{path:?}");
            }
        }

        #[cfg(windows)]
        #[test]
        fn sort_is_windows_str_and_keeps_equal_keys_in_input_order() {
            let tie_second = Path::new("a/b");
            let tie_first = Path::new("a\\b");
            let early = Path::new("a/session_index.jsonl");
            let late = Path::new("z.jsonl");
            let paths = [tie_second, late, tie_first, early];
            let sorted = sort_index_paths(&paths).expect("keys");
            assert_eq!(sorted[0].key, "a\\b");
            assert_eq!(sorted[1].key, "a\\b");
            assert_eq!(sorted[2].key, "a\\session_index.jsonl");
            assert_eq!(sorted[3].key, "z.jsonl");
            assert_eq!(sorted[0].path.to_str(), Some("a/b"));
            assert_eq!(sorted[1].path.to_str(), Some("a\\b"));
            let unc = Path::new("//server/share/secret");
            let letter = Path::new("sessions-index.json");
            let unc_paths = [letter, unc];
            let ordered = sort_index_paths(&unc_paths).expect("unc");
            assert_eq!(ordered[0].key, "\\\\server\\share\\secret");
            assert_eq!(ordered[0].path.to_str(), Some("//server/share/secret"));
        }

        #[cfg(not(windows))]
        #[test]
        fn sort_is_posix_str() {
            let slash = Path::new("a/b");
            let back = Path::new("a\\b");
            let early = Path::new("a/session_index.jsonl");
            let late = Path::new("z.jsonl");
            let paths = [back, late, slash, early];
            let sorted = sort_index_paths(&paths).expect("keys");
            assert_eq!(sorted[0].key, "a/b");
            assert_eq!(sorted[1].key, "a/session_index.jsonl");
            assert_eq!(sorted[2].key, "a\\b");
            assert_eq!(sorted[3].key, "z.jsonl");
            assert_eq!(sorted[0].path.to_str(), Some("a/b"));
            assert_eq!(sorted[2].path.to_str(), Some("a\\b"));
        }

        #[cfg(windows)]
        #[test]
        fn undecodable_index_path_fails_closed() {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;

            let path = OsString::from_wide(&[0xD800, 0x20]);
            let index = Path::new(&path);
            assert!(super::python_path_str(index).is_none());
            let error =
                reconcile_session_indexes(&[], &[index], &[], None).expect_err("undecodable");
            assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
            assert!(!error.to_string().chars().any(|ch| ch.is_ascii_digit()));
        }

        #[cfg(unix)]
        #[test]
        fn undecodable_index_path_fails_closed() {
            use std::os::unix::ffi::OsStrExt;

            let index = Path::new(std::ffi::OsStr::from_bytes(&[0xff]));
            assert!(super::python_path_str(index).is_none());
            let error =
                reconcile_session_indexes(&[], &[index], &[], None).expect_err("undecodable");
            assert_eq!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        }
    }
}

pub use session_indexes::{reconcile_session_indexes, FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT};
