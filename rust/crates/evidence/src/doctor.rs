//! Environment diagnostics for `sesslint doctor` (ux-reporting T-04).
//!
//! Port of `src/sesslint/doctor.py` lines 1–258
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `b4bc93415d72096dcb62f0e57d668c879d0debfd`.
//!
//! `sesslint.report.minimize_path` and `sesslint.api.check_file` are not
//! ported. Calls that would reach them return a typed error. Classification
//! after a report exists is [`verdicts_from_outcomes`]; it does not call
//! `check_file`.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Python `DOCTOR_SCHEMA_VERSION`.
pub const DOCTOR_SCHEMA_VERSION: &str = "sesslint.doctor/v1";

/// Python `MAX_FILE_COUNT`. The walk reports capped when another entry is seen.
pub const MAX_FILE_COUNT: i64 = 10_000;

/// Python `MAX_QUICK_CHECKS`.
pub const MAX_QUICK_CHECKS: usize = 5;

/// Python `MAX_TOP_CODES`.
pub const MAX_TOP_CODES: usize = 5;

/// `sesslint.report.minimize_path` is not ported.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// `sesslint.api.check_file` is not ported.
pub const CHECK_FILE_UNAVAILABLE: &str = "sesslint.api.check_file is not available";

/// Python `ValueError` text for a NaN timestamp.
pub const TIMESTAMP_NAN: &str = "Invalid value NaN (not a number)";

/// Python `OverflowError` text when a timestamp does not fit.
pub const TIMESTAMP_TIME_T: &str = "timestamp out of range for platform time_t";

/// Python `OverflowError` text when the civil year is outside 1..=9999.
pub const TIMESTAMP_DATE: &str = "date value out of range";

/// Failure from the lines-1–258 port. Display text for a missing import is the
/// `module.function is not available` sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoctorError {
    /// `sesslint.report.minimize_path`.
    MinimizePathUnavailable,
    /// `sesslint.api.check_file`.
    CheckFileUnavailable,
    /// Python `KeyError` while reading an adapter row. Display is `repr(key)`.
    AdapterKey(String),
    /// Python timestamp exception text, without the type name.
    Timestamp(&'static str),
    /// `OSError` from a stat that Python would let escape `_quick_verdicts`.
    Io(String),
}

impl fmt::Display for DoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinimizePathUnavailable => formatter.write_str(MINIMIZE_PATH_UNAVAILABLE),
            Self::CheckFileUnavailable => formatter.write_str(CHECK_FILE_UNAVAILABLE),
            Self::AdapterKey(key) => formatter.write_str(&python_repr_str(key)),
            Self::Timestamp(text) => formatter.write_str(text),
            Self::Io(text) => formatter.write_str(text),
        }
    }
}

impl Error for DoctorError {}

/// JSON value used by `to_dict` / `to_json`.
///
/// Objects keep insertion order. `to_json` sorts keys to match
/// `json.dumps(..., sort_keys=True)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoctorJson {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<DoctorJson>),
    Object(Vec<(String, DoctorJson)>),
}

/// Python `IndexDiag`. `state` is stored as given; this slice does not validate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDiag {
    pub sessions_on_disk: i64,
    pub index_entries: Option<i64>,
    pub state: String,
}

impl IndexDiag {
    /// Python `IndexDiag.to_dict`. Key order is `index_entries`, `sessions_on_disk`, `state`.
    pub fn to_dict(&self) -> DoctorJson {
        let entries = match self.index_entries {
            Some(count) => DoctorJson::Int(count),
            None => DoctorJson::Null,
        };
        DoctorJson::Object(vec![
            ("index_entries".to_owned(), entries),
            (
                "sessions_on_disk".to_owned(),
                DoctorJson::Int(self.sessions_on_disk),
            ),
            ("state".to_owned(), DoctorJson::String(self.state.clone())),
        ])
    }
}

/// Python `RootDiag`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootDiag {
    pub agent: String,
    pub path: String,
    pub exists: bool,
    pub source: String,
    pub file_count: i64,
    pub file_count_capped: bool,
    pub newest_mtime: Option<String>,
    pub checked: i64,
    pub verdicts: Vec<(String, i64)>,
    pub top_codes: Vec<(String, i64)>,
    pub index: Option<IndexDiag>,
}

impl RootDiag {
    /// Python `RootDiag.to_dict`. Always asks `minimize_path` for `path`.
    pub fn to_dict(&self, home: Option<&Path>) -> Result<DoctorJson, DoctorError> {
        self.to_dict_with(home, show_minimized)
    }

    fn to_dict_with(
        &self,
        home: Option<&Path>,
        mut show: impl FnMut(&str, Option<&Path>) -> Result<String, DoctorError>,
    ) -> Result<DoctorJson, DoctorError> {
        let path = show(&self.path, home)?;
        Ok(root_dict(self, path))
    }
}

/// Python `DoctorReport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorReport {
    pub tool_version: String,
    pub adapters: Vec<Vec<(String, DoctorJson)>>,
    pub reader_limits: Vec<(String, Option<i64>)>,
    pub config_path: Option<String>,
    pub roots: Vec<RootDiag>,
}

impl DoctorReport {
    /// Python `DoctorReport.to_dict`.
    ///
    /// `minimize_path` runs for a config path and for every root. An empty
    /// report with `config_path is None` does not call it.
    pub fn to_dict(&self, home: Option<&Path>) -> Result<DoctorJson, DoctorError> {
        self.to_dict_with(home, show_minimized)
    }

    fn to_dict_with(
        &self,
        home: Option<&Path>,
        mut show: impl FnMut(&str, Option<&Path>) -> Result<String, DoctorError>,
    ) -> Result<DoctorJson, DoctorError> {
        let config_path = match &self.config_path {
            Some(path) => DoctorJson::String(show(path, home)?),
            None => DoctorJson::Null,
        };
        let mut roots = Vec::new();
        for root in &self.roots {
            roots.push(root.to_dict_with(home, &mut show)?);
        }
        Ok(DoctorJson::Object(vec![
            (
                "schema_version".to_owned(),
                DoctorJson::String(DOCTOR_SCHEMA_VERSION.to_owned()),
            ),
            (
                "tool_version".to_owned(),
                DoctorJson::String(self.tool_version.clone()),
            ),
            ("adapters".to_owned(), adapters_json(&self.adapters)),
            ("reader_limits".to_owned(), limits_json(&self.reader_limits)),
            ("config_path".to_owned(), config_path),
            ("roots".to_owned(), DoctorJson::Array(roots)),
        ]))
    }

    /// Python `DoctorReport.to_json`: `json.dumps(..., indent=2, sort_keys=True)`.
    pub fn to_json(&self, home: Option<&Path>) -> Result<String, DoctorError> {
        Ok(dumps_sorted(&self.to_dict(home)?))
    }

    /// Python `DoctorReport.render_human`.
    ///
    /// Adapter `KeyError` is raised before `minimize_path`. `versions_supported`
    /// is read before `name`.
    pub fn render_human(&self, home: Option<&Path>) -> Result<String, DoctorError> {
        self.render_human_with(home, show_minimized)
    }

    fn render_human_with(
        &self,
        home: Option<&Path>,
        mut show: impl FnMut(&str, Option<&Path>) -> Result<String, DoctorError>,
    ) -> Result<String, DoctorError> {
        let mut lines = vec![
            "SessLint doctor".to_owned(),
            format!("  tool version: {}", self.tool_version),
            "  adapters:".to_owned(),
        ];
        for row in &self.adapters {
            lines.push(render_adapter(row)?);
        }
        lines.push("  reader limits:".to_owned());
        for (key, value) in &self.reader_limits {
            let shown = match value {
                Some(number) => number.to_string(),
                None => "none".to_owned(),
            };
            lines.push(format!("    {key}: {shown}"));
        }
        let config = match &self.config_path {
            Some(path) => show(path, home)?,
            None => "none".to_owned(),
        };
        lines.push(format!("  config: {config}"));
        lines.push("  roots:".to_owned());
        for root in &self.roots {
            let shown = show(&root.path, home)?;
            push_root_lines(&mut lines, root, &shown);
        }
        Ok(lines.join("\n"))
    }
}

/// Result of Python `_count_files`: `(count, capped, candidates)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountedFiles {
    pub count: i64,
    pub capped: bool,
    pub candidates: Vec<PathBuf>,
}

/// Result of Python `_quick_verdicts`: `(checked, verdicts, top_codes)`.
///
/// `verdicts` keeps first-seen order. It is not a `HashMap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickVerdicts {
    pub checked: i64,
    pub verdicts: Vec<(String, i64)>,
    pub top_codes: Vec<(String, i64)>,
}

/// Fields `_quick_verdicts` reads after `check_file` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckView {
    pub limitation: String,
    pub by_severity: Vec<(String, i64)>,
    pub finding_codes: Vec<String>,
}

/// One file inside `_quick_verdicts`, including the `except Exception` arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Unreadable,
    Report(CheckView),
}

/// Python `_iso_utc`.
///
/// Fractional seconds round half-even to the microsecond, then `strftime`
/// drops them. The calendar is proleptic Gregorian UTC.
pub fn iso_utc(timestamp: f64) -> Result<String, DoctorError> {
    let micros = round_half_even_micros(timestamp)?;
    format_unix_seconds(micros.div_euclid(1_000_000))
}

/// Python `_count_files`.
///
/// Iterative walk. Directory names are sorted. `.git`, `.hg`, and `.svn` are
/// not entered. `sesslint.toml` and `.sesslint.toml` are not counted. Symlinks
/// are not followed. `OSError` skips that directory or entry.
pub fn count_files(root: &Path) -> CountedFiles {
    let mut count = 0i64;
    let mut candidates = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = BTreeSet::new();
    while let Some(current) = stack.pop() {
        let meta = match fs::metadata(&current) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !seen.insert(seen_key(&current, &meta)) {
            continue;
        }
        let read = match fs::read_dir(&current) {
            Ok(read) => read,
            Err(_) => continue,
        };
        let mut children = Vec::new();
        let mut failed = false;
        for entry in read {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    failed = true;
                    break;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            children.push(WalkChild {
                name: entry.file_name(),
                path: entry.path(),
                file_type,
            });
        }
        if failed {
            continue;
        }
        children.sort_by(|left, right| cmp_name(&left.name, &right.name));
        for child in children {
            if count >= MAX_FILE_COUNT {
                return CountedFiles {
                    count,
                    capped: true,
                    candidates,
                };
            }
            if child.file_type.is_symlink() {
                continue;
            }
            if child.file_type.is_dir() {
                if !is_vcs(child.name.to_str()) {
                    stack.push(child.path);
                }
                continue;
            }
            if !child.file_type.is_file() {
                continue;
            }
            let name = child.name.to_str();
            if is_skipped_file(name) {
                continue;
            }
            count += 1;
            if is_session_name(name) {
                candidates.push(child.path);
            }
        }
    }
    CountedFiles {
        count,
        capped: false,
        candidates,
    }
}

/// Python `_quick_verdicts`.
///
/// Files that are not regular files are ignored. The rest are ordered by
/// newest mtime, then path text, and cut to [`MAX_QUICK_CHECKS`]. A stat error
/// is returned in input order. A non-empty selection returns
/// [`DoctorError::CheckFileUnavailable`] because `check_file` is not ported.
pub fn quick_verdicts(files: &[PathBuf]) -> Result<QuickVerdicts, DoctorError> {
    let mut keyed = Vec::new();
    for path in files {
        if !path.is_file() {
            continue;
        }
        let mtime = sort_mtime(path)?;
        keyed.push((mtime, path.to_string_lossy().into_owned()));
    }
    keyed.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    keyed.truncate(MAX_QUICK_CHECKS);
    if keyed.is_empty() {
        return Ok(QuickVerdicts {
            checked: 0,
            verdicts: Vec::new(),
            top_codes: Vec::new(),
        });
    }
    let _selected = keyed;
    Err(DoctorError::CheckFileUnavailable)
}

/// Classify outcomes the way `_quick_verdicts` does after `check_file`.
///
/// `Unsupported:` wins, then `Skipped:`, then `error`+`fatal`, then `warning`.
/// A missing severity key is 0. Duplicate severity keys use the last value.
/// Top codes sort by descending count, then code, and stop at [`MAX_TOP_CODES`].
pub fn verdicts_from_outcomes(outcomes: &[CheckOutcome]) -> QuickVerdicts {
    let mut verdicts = Vec::new();
    let mut code_counts = Vec::new();
    for outcome in outcomes {
        match outcome {
            CheckOutcome::Unreadable => bump(&mut verdicts, "unreadable"),
            CheckOutcome::Report(view) => {
                bump(&mut verdicts, verdict_name(view));
                for code in &view.finding_codes {
                    bump(&mut code_counts, code);
                }
            }
        }
    }
    code_counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    code_counts.truncate(MAX_TOP_CODES);
    QuickVerdicts {
        checked: i64::try_from(outcomes.len()).unwrap_or(i64::MAX),
        verdicts,
        top_codes: code_counts,
    }
}

struct WalkChild {
    name: OsString,
    path: PathBuf,
    file_type: fs::FileType,
}

fn show_minimized(_path: &str, _home: Option<&Path>) -> Result<String, DoctorError> {
    Err(DoctorError::MinimizePathUnavailable)
}

fn root_dict(root: &RootDiag, path: String) -> DoctorJson {
    let newest = match &root.newest_mtime {
        Some(text) => DoctorJson::String(text.clone()),
        None => DoctorJson::Null,
    };
    let index = match &root.index {
        Some(index) => index.to_dict(),
        None => DoctorJson::Null,
    };
    DoctorJson::Object(vec![
        ("agent".to_owned(), DoctorJson::String(root.agent.clone())),
        ("path".to_owned(), DoctorJson::String(path)),
        ("exists".to_owned(), DoctorJson::Bool(root.exists)),
        ("source".to_owned(), DoctorJson::String(root.source.clone())),
        ("file_count".to_owned(), DoctorJson::Int(root.file_count)),
        (
            "file_count_capped".to_owned(),
            DoctorJson::Bool(root.file_count_capped),
        ),
        ("newest_mtime".to_owned(), newest),
        ("checked".to_owned(), DoctorJson::Int(root.checked)),
        ("verdicts".to_owned(), sorted_verdicts(&root.verdicts)),
        ("top_codes".to_owned(), top_codes_json(&root.top_codes)),
        ("index".to_owned(), index),
    ])
}

fn sorted_verdicts(items: &[(String, i64)]) -> DoctorJson {
    let mut sorted = items.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut pairs = Vec::new();
    for (key, value) in sorted {
        assign(&mut pairs, key, DoctorJson::Int(value));
    }
    DoctorJson::Object(pairs)
}

fn top_codes_json(items: &[(String, i64)]) -> DoctorJson {
    DoctorJson::Array(
        items
            .iter()
            .map(|(code, count)| {
                DoctorJson::Object(vec![
                    ("code".to_owned(), DoctorJson::String(code.clone())),
                    ("count".to_owned(), DoctorJson::Int(*count)),
                ])
            })
            .collect(),
    )
}

fn adapters_json(adapters: &[Vec<(String, DoctorJson)>]) -> DoctorJson {
    DoctorJson::Array(adapters.iter().map(|row| row_object(row)).collect())
}

fn row_object(row: &[(String, DoctorJson)]) -> DoctorJson {
    let mut pairs = Vec::new();
    for (key, value) in row {
        assign(&mut pairs, key.clone(), value.clone());
    }
    DoctorJson::Object(pairs)
}

fn limits_json(limits: &[(String, Option<i64>)]) -> DoctorJson {
    let mut pairs = Vec::new();
    for (key, value) in limits {
        let json = match value {
            Some(number) => DoctorJson::Int(*number),
            None => DoctorJson::Null,
        };
        assign(&mut pairs, key.clone(), json);
    }
    DoctorJson::Object(pairs)
}

fn assign(pairs: &mut Vec<(String, DoctorJson)>, key: String, value: DoctorJson) {
    if let Some((_, slot)) = pairs.iter_mut().find(|(name, _)| *name == key) {
        *slot = value;
    } else {
        pairs.push((key, value));
    }
}

fn render_adapter(row: &[(String, DoctorJson)]) -> Result<String, DoctorError> {
    let versions = lookup(row, "versions_supported")?;
    let name = python_str(lookup(row, "name")?);
    let vers = match versions {
        DoctorJson::Array(items) => items.iter().map(python_str).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    };
    Ok(format!("    {} {vers}", pad_end(&name, 24)))
}

fn lookup<'a>(row: &'a [(String, DoctorJson)], key: &str) -> Result<&'a DoctorJson, DoctorError> {
    row.iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .ok_or_else(|| DoctorError::AdapterKey(key.to_owned()))
}

fn push_root_lines(lines: &mut Vec<String>, root: &RootDiag, shown: &str) {
    if !root.exists {
        lines.push(format!("    {} absent ({shown})", pad_end(&root.agent, 10)));
        return;
    }
    let cap = if root.file_count_capped { "+" } else { "" };
    let mut line = format!(
        "    {} {shown}  files={}{cap}",
        pad_end(&root.agent, 10),
        root.file_count
    );
    if let Some(newest) = &root.newest_mtime {
        line.push_str(&format!("  newest={newest}"));
    }
    lines.push(line);
    if root.checked != 0 {
        let mut sorted = root.verdicts.clone();
        sorted.sort_by(|left, right| left.0.cmp(&right.0));
        let bits = sorted
            .iter()
            .filter(|(_, count)| *count != 0)
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>();
        let verdict_bits = if bits.is_empty() {
            "clean".to_owned()
        } else {
            bits.join(", ")
        };
        lines.push(format!(
            "{}checked={}  {verdict_bits}",
            " ".repeat(14),
            root.checked
        ));
        for (code, count) in &root.top_codes {
            lines.push(format!("{}{code} x{count}", " ".repeat(16)));
        }
    }
    if let Some(index) = &root.index {
        let entries = match index.index_entries {
            Some(count) => count.to_string(),
            None => "none".to_owned(),
        };
        lines.push(format!(
            "{}index={}  sessions={}  index_entries={entries}",
            " ".repeat(14),
            index.state,
            index.sessions_on_disk
        ));
    }
}

fn pad_end(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_owned();
    }
    let mut out = text.to_owned();
    out.extend(std::iter::repeat_n(' ', width - len));
    out
}

fn python_str(value: &DoctorJson) -> String {
    match value {
        DoctorJson::Null => "None".to_owned(),
        DoctorJson::Bool(true) => "True".to_owned(),
        DoctorJson::Bool(false) => "False".to_owned(),
        DoctorJson::Int(number) => number.to_string(),
        DoctorJson::String(text) => text.clone(),
        DoctorJson::Array(items) => {
            let rendered = items.iter().map(python_repr).collect::<Vec<_>>().join(", ");
            format!("[{rendered}]")
        }
        DoctorJson::Object(pairs) => {
            let rendered = pairs
                .iter()
                .map(|(key, item)| format!("{}: {}", python_repr_str(key), python_repr(item)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{rendered}}}")
        }
    }
}

fn python_repr(value: &DoctorJson) -> String {
    match value {
        DoctorJson::String(text) => python_repr_str(text),
        other => python_str(other),
    }
}

fn python_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut body = String::new();
    for ch in text.chars() {
        match ch {
            '\\' => body.push_str("\\\\"),
            '\n' => body.push_str("\\n"),
            '\r' => body.push_str("\\r"),
            '\t' => body.push_str("\\t"),
            '\'' if quote == '\'' => body.push_str("\\'"),
            '"' if quote == '"' => body.push_str("\\\""),
            other if (other as u32) < 0x20 || other == '\u{7f}' => {
                body.push_str(&format!("\\x{:02x}", other as u32));
            }
            other => body.push(other),
        }
    }
    format!("{quote}{body}{quote}")
}

fn verdict_name(view: &CheckView) -> &'static str {
    if view.limitation.starts_with("Unsupported:") {
        return "unsupported";
    }
    if view.limitation.starts_with("Skipped:") {
        return "skipped";
    }
    let errors = i128::from(severity(&view.by_severity, "error"))
        + i128::from(severity(&view.by_severity, "fatal"));
    if errors > 0 {
        return "invalid";
    }
    if severity(&view.by_severity, "warning") > 0 {
        return "warnings";
    }
    "healthy"
}

fn severity(pairs: &[(String, i64)], key: &str) -> i64 {
    pairs
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, count)| *count)
        .unwrap_or(0)
}

fn bump(counts: &mut Vec<(String, i64)>, key: &str) {
    if let Some((_, count)) = counts.iter_mut().find(|(name, _)| name == key) {
        *count = count.saturating_add(1);
    } else {
        counts.push((key.to_owned(), 1));
    }
}

fn sort_mtime(path: &Path) -> Result<SystemTime, DoctorError> {
    if !path.exists() {
        return Ok(UNIX_EPOCH);
    }
    match fs::metadata(path) {
        Ok(meta) => meta
            .modified()
            .map_err(|err| DoctorError::Io(err.to_string())),
        Err(err) => Err(DoctorError::Io(err.to_string())),
    }
}

/// Cycle key for one visited directory.
///
/// Unix uses `st_dev`/`st_ino`, matching Python. `MetadataExt::file_index`
/// is still unstable on Rust 1.91, so Windows keys the path that was opened.
/// A directory hard link with a different path is not collapsed there.
#[cfg(unix)]
type SeenKey = (u64, u64);
#[cfg(not(unix))]
type SeenKey = PathBuf;

fn seen_key(path: &Path, meta: &fs::Metadata) -> SeenKey {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        path.to_path_buf()
    }
}

fn cmp_name(left: &OsStr, right: &OsStr) -> Ordering {
    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => left.cmp(right),
        _ => left.cmp(right),
    }
}

fn is_vcs(name: Option<&str>) -> bool {
    matches!(name, Some(".git" | ".hg" | ".svn"))
}

fn is_skipped_file(name: Option<&str>) -> bool {
    matches!(name, Some("sesslint.toml" | ".sesslint.toml"))
}

fn is_session_name(name: Option<&str>) -> bool {
    match name {
        Some(name) => name.ends_with(".jsonl") || name.ends_with(".json"),
        None => false,
    }
}

fn round_half_even_micros(timestamp: f64) -> Result<i64, DoctorError> {
    if timestamp.is_nan() {
        return Err(DoctorError::Timestamp(TIMESTAMP_NAN));
    }
    if !timestamp.is_finite() {
        return Err(DoctorError::Timestamp(TIMESTAMP_TIME_T));
    }
    if timestamp == 0.0 {
        return Ok(0);
    }
    let negative = timestamp.is_sign_negative();
    let bits = timestamp.abs().to_bits();
    let exponent_bits = i32::try_from((bits >> 52) & 0x7ff).unwrap_or(0);
    let fraction = bits & ((1u64 << 52) - 1);
    let (significand, power) = if exponent_bits == 0 {
        (u128::from(fraction), -1074i32)
    } else {
        (
            u128::from(fraction | (1u64 << 52)),
            exponent_bits - 1023 - 52,
        )
    };
    let num = significand * 1_000_000;
    let rounded = if power >= 0 {
        let shift = u32::try_from(power).unwrap_or(u32::MAX);
        if shift >= 128 || num.leading_zeros() < shift {
            return Err(DoctorError::Timestamp(TIMESTAMP_TIME_T));
        }
        num << shift
    } else {
        let shift = -power;
        if shift >= 128 {
            0
        } else {
            let shift_u = u32::try_from(shift).unwrap_or(0);
            let quot = num >> shift_u;
            let rem = num & ((1u128 << shift_u) - 1);
            let half = 1u128 << (shift_u - 1);
            if rem > half || (rem == half && (quot & 1) == 1) {
                quot.checked_add(1)
                    .ok_or(DoctorError::Timestamp(TIMESTAMP_TIME_T))?
            } else {
                quot
            }
        }
    };
    magnitude_to_i64(rounded, negative)
}

fn magnitude_to_i64(magnitude: u128, negative: bool) -> Result<i64, DoctorError> {
    if negative && magnitude == (1u128 << 63) {
        return Ok(i64::MIN);
    }
    if magnitude > u128::from(i64::MAX as u64) {
        return Err(DoctorError::Timestamp(TIMESTAMP_TIME_T));
    }
    let value = magnitude as i64;
    if negative {
        Ok(-value)
    } else {
        Ok(value)
    }
}

fn format_unix_seconds(seconds: i64) -> Result<String, DoctorError> {
    let days = seconds.div_euclid(86_400);
    let sod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_unix_days(days)?;
    if !(1..=9999).contains(&year) {
        return Err(DoctorError::Timestamp(TIMESTAMP_DATE));
    }
    let hour = sod / 3_600;
    let minute = (sod % 3_600) / 60;
    let second = sod % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_unix_days(days: i64) -> Result<(i64, i64, i64), DoctorError> {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = z - era * 146_097;
    if doe < 0 {
        return Err(DoctorError::Timestamp(TIMESTAMP_DATE));
    }
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year_base = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year_base + 1 } else { year_base };
    Ok((year, month, day))
}

fn dumps_sorted(value: &DoctorJson) -> String {
    let mut out = String::new();
    write_json(&mut out, value, 0, true);
    out
}

fn write_json(out: &mut String, value: &DoctorJson, indent: usize, sort_keys: bool) {
    match value {
        DoctorJson::Null => out.push_str("null"),
        DoctorJson::Bool(true) => out.push_str("true"),
        DoctorJson::Bool(false) => out.push_str("false"),
        DoctorJson::Int(number) => out.push_str(&number.to_string()),
        DoctorJson::String(text) => push_json_string(out, text),
        DoctorJson::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            let inner = indent + 2;
            for (index, item) in items.iter().enumerate() {
                out.push('\n');
                push_spaces(out, inner);
                write_json(out, item, inner, sort_keys);
                if index + 1 != items.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_spaces(out, indent);
            out.push(']');
        }
        DoctorJson::Object(pairs) => {
            if pairs.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut order: Vec<usize> = (0..pairs.len()).collect();
            if sort_keys {
                order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
            }
            out.push('{');
            let inner = indent + 2;
            for (index, pair_index) in order.iter().enumerate() {
                let (key, nested) = &pairs[*pair_index];
                out.push('\n');
                push_spaces(out, inner);
                push_json_string(out, key);
                out.push_str(": ");
                write_json(out, nested, inner, sort_keys);
                if index + 1 != order.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_spaces(out, indent);
            out.push('}');
        }
    }
}

fn push_spaces(out: &mut String, count: usize) {
    out.extend(std::iter::repeat_n(' ', count));
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => {
                let code = other as u32;
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(other);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

#[cfg(test)]
mod tests {
    use super::{
        count_files, dumps_sorted, iso_utc, quick_verdicts, verdicts_from_outcomes, CheckOutcome,
        CheckView, DoctorError, DoctorJson, DoctorReport, IndexDiag, RootDiag,
        CHECK_FILE_UNAVAILABLE, MAX_FILE_COUNT, MINIMIZE_PATH_UNAVAILABLE, TIMESTAMP_NAN,
        TIMESTAMP_TIME_T,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const PRIMARY_HUMAN: &str = "SessLint doctor\n  tool version: 0.5.0\n  adapters:\n    synthetic                v1, v2\n    wide-name-exceeds-twenty-four \n  reader limits:\n    max_line_bytes: 8\n    max_depth: 3\n    max_file_bytes: 100\n    max_records: none\n  config: none\n  roots:";
    const PRIMARY_JSON: &str = "{\n  \"adapters\": [\n    {\n      \"default_profile\": \"neutral\",\n      \"description\": \"synthetic adapter row\",\n      \"name\": \"synthetic\",\n      \"versions_supported\": [\n        \"v1\",\n        \"v2\"\n      ]\n    },\n    {\n      \"name\": \"wide-name-exceeds-twenty-four\",\n      \"versions_supported\": []\n    }\n  ],\n  \"config_path\": null,\n  \"reader_limits\": {\n    \"max_depth\": 3,\n    \"max_file_bytes\": 100,\n    \"max_line_bytes\": 8,\n    \"max_records\": null\n  },\n  \"roots\": [],\n  \"schema_version\": \"sesslint.doctor/v1\",\n  \"tool_version\": \"0.5.0\"\n}";
    const NOTLIST_HUMAN: &str = "SessLint doctor\n  tool version: 0.5.0\n  adapters:\n    n                        \n  reader limits:\n    z: 1\n    a: none\n  config: none\n  roots:";
    const NOTLIST_JSON: &str = "{\n  \"adapters\": [\n    {\n      \"name\": \"n\",\n      \"versions_supported\": \"plain\"\n    }\n  ],\n  \"config_path\": null,\n  \"reader_limits\": {\n    \"a\": null,\n    \"z\": 1\n  },\n  \"roots\": [],\n  \"schema_version\": \"sesslint.doctor/v1\",\n  \"tool_version\": \"0.5.0\"\n}";
    const MIXED_HUMAN: &str = "SessLint doctor\n  tool version: t\n  adapters:\n    n                        a, 2, None, True, False\n  reader limits:\n    m: 0\n  config: none\n  roots:";
    const MIXED_JSON: &str = "{\n  \"adapters\": [\n    {\n      \"name\": \"n\",\n      \"versions_supported\": [\n        \"a\",\n        2,\n        null,\n        true,\n        false\n      ]\n    }\n  ],\n  \"config_path\": null,\n  \"reader_limits\": {\n    \"m\": 0\n  },\n  \"roots\": [],\n  \"schema_version\": \"sesslint.doctor/v1\",\n  \"tool_version\": \"t\"\n}";
    const UNI_HUMAN: &str = "SessLint doctor\n  tool version: t\n  adapters:\n    café                     ☃\n  reader limits:\n  config: none\n  roots:";
    const UNI_JSON: &str = "{\n  \"adapters\": [\n    {\n      \"name\": \"caf\\u00e9\",\n      \"versions_supported\": [\n        \"\\u2603\"\n      ]\n    }\n  ],\n  \"config_path\": null,\n  \"reader_limits\": {},\n  \"roots\": [],\n  \"schema_version\": \"sesslint.doctor/v1\",\n  \"tool_version\": \"t\"\n}";
    const ROOT_HUMAN: &str = "SessLint doctor\n  tool version: 0.5.0\n  adapters:\n  reader limits:\n    max_records: none\n  config: shown\n  roots:\n    claude     absent (shown)\n    codex      shown  files=3+  newest=2023-11-14T22:13:20Z\n              checked=2  invalid=1, warnings=1\n                SYN-B x2\n                SYN-A x1\n              index=absent  sessions=4  index_entries=none\n    other      shown  files=1\n              checked=1  healthy=1\n              index=ok  sessions=1  index_entries=1";
    const ROOT_JSON: &str = "{\n  \"adapters\": [],\n  \"config_path\": \"shown\",\n  \"reader_limits\": {\n    \"max_records\": null\n  },\n  \"roots\": [\n    {\n      \"agent\": \"claude\",\n      \"checked\": 0,\n      \"exists\": false,\n      \"file_count\": 0,\n      \"file_count_capped\": false,\n      \"index\": null,\n      \"newest_mtime\": null,\n      \"path\": \"shown\",\n      \"source\": \"default\",\n      \"top_codes\": [],\n      \"verdicts\": {}\n    },\n    {\n      \"agent\": \"codex\",\n      \"checked\": 2,\n      \"exists\": true,\n      \"file_count\": 3,\n      \"file_count_capped\": true,\n      \"index\": {\n        \"index_entries\": null,\n        \"sessions_on_disk\": 4,\n        \"state\": \"absent\"\n      },\n      \"newest_mtime\": \"2023-11-14T22:13:20Z\",\n      \"path\": \"shown\",\n      \"source\": \"env\",\n      \"top_codes\": [\n        {\n          \"code\": \"SYN-B\",\n          \"count\": 2\n        },\n        {\n          \"code\": \"SYN-A\",\n          \"count\": 1\n        }\n      ],\n      \"verdicts\": {\n        \"healthy\": 0,\n        \"invalid\": 1,\n        \"warnings\": 1\n      }\n    },\n    {\n      \"agent\": \"other\",\n      \"checked\": 1,\n      \"exists\": true,\n      \"file_count\": 1,\n      \"file_count_capped\": false,\n      \"index\": {\n        \"index_entries\": 1,\n        \"sessions_on_disk\": 1,\n        \"state\": \"ok\"\n      },\n      \"newest_mtime\": null,\n      \"path\": \"shown\",\n      \"source\": \"default\",\n      \"top_codes\": [],\n      \"verdicts\": {\n        \"healthy\": 1\n      }\n    }\n  ],\n  \"schema_version\": \"sesslint.doctor/v1\",\n  \"tool_version\": \"0.5.0\"\n}";

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sesslint-doctor-synthetic-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::File::create(path).unwrap();
    }

    fn string(text: &str) -> DoctorJson {
        DoctorJson::String(text.to_owned())
    }

    fn row(items: &[(&str, DoctorJson)]) -> Vec<(String, DoctorJson)> {
        items
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    fn limits(items: &[(&str, Option<i64>)]) -> Vec<(String, Option<i64>)> {
        items
            .iter()
            .map(|(key, value)| ((*key).to_owned(), *value))
            .collect()
    }

    fn object_keys(value: &DoctorJson) -> Vec<&str> {
        match value {
            DoctorJson::Object(pairs) => pairs.iter().map(|(key, _)| key.as_str()).collect(),
            _ => Vec::new(),
        }
    }

    fn primary_report() -> DoctorReport {
        DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![
                row(&[
                    ("name", string("synthetic")),
                    ("default_profile", string("neutral")),
                    ("description", string("synthetic adapter row")),
                    (
                        "versions_supported",
                        DoctorJson::Array(vec![string("v1"), string("v2")]),
                    ),
                ]),
                row(&[
                    ("name", string("wide-name-exceeds-twenty-four")),
                    ("versions_supported", DoctorJson::Array(Vec::new())),
                ]),
            ],
            reader_limits: limits(&[
                ("max_line_bytes", Some(8)),
                ("max_depth", Some(3)),
                ("max_file_bytes", Some(100)),
                ("max_records", None),
            ]),
            config_path: None,
            roots: Vec::new(),
        }
    }

    fn shown_root() -> DoctorReport {
        let absent = RootDiag {
            agent: "claude".to_owned(),
            path: "C:/synthetic/claude".to_owned(),
            exists: false,
            source: "default".to_owned(),
            file_count: 0,
            file_count_capped: false,
            newest_mtime: None,
            checked: 0,
            verdicts: Vec::new(),
            top_codes: Vec::new(),
            index: None,
        };
        let present = RootDiag {
            agent: "codex".to_owned(),
            path: "C:/synthetic/codex".to_owned(),
            exists: true,
            source: "env".to_owned(),
            file_count: 3,
            file_count_capped: true,
            newest_mtime: Some("2023-11-14T22:13:20Z".to_owned()),
            checked: 2,
            verdicts: vec![
                ("healthy".to_owned(), 0),
                ("warnings".to_owned(), 1),
                ("invalid".to_owned(), 1),
            ],
            top_codes: vec![("SYN-B".to_owned(), 2), ("SYN-A".to_owned(), 1)],
            index: Some(IndexDiag {
                sessions_on_disk: 4,
                index_entries: None,
                state: "absent".to_owned(),
            }),
        };
        let clean = RootDiag {
            agent: "other".to_owned(),
            path: "C:/synthetic/other".to_owned(),
            exists: true,
            source: "default".to_owned(),
            file_count: 1,
            file_count_capped: false,
            newest_mtime: None,
            checked: 1,
            verdicts: vec![("healthy".to_owned(), 1)],
            top_codes: Vec::new(),
            index: Some(IndexDiag {
                sessions_on_disk: 1,
                index_entries: Some(1),
                state: "ok".to_owned(),
            }),
        };
        DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: Vec::new(),
            reader_limits: limits(&[("max_records", None)]),
            config_path: Some("C:/synthetic/sesslint.toml".to_owned()),
            roots: vec![absent, present, clean],
        }
    }

    fn show_fixed(_path: &str, _home: Option<&Path>) -> Result<String, DoctorError> {
        Ok("shown".to_owned())
    }

    #[test]
    fn iso_utc_matches_python_samples() {
        let samples = [
            (0.0, "1970-01-01T00:00:00Z"),
            (1.0, "1970-01-01T00:00:01Z"),
            (1.9, "1970-01-01T00:00:01Z"),
            (1.1, "1970-01-01T00:00:01Z"),
            (-1.0, "1969-12-31T23:59:59Z"),
            (-1.1, "1969-12-31T23:59:58Z"),
            (-1.9, "1969-12-31T23:59:58Z"),
            (0.999_999_4, "1970-01-01T00:00:00Z"),
            (0.999_999_5, "1970-01-01T00:00:01Z"),
            (1.999_999_4, "1970-01-01T00:00:01Z"),
            (1.999_999_5, "1970-01-01T00:00:01Z"),
            (1_700_000_000.0, "2023-11-14T22:13:20Z"),
            (1_700_000_000.123_456, "2023-11-14T22:13:20Z"),
            (-43_200.0, "1969-12-31T12:00:00Z"),
            (951_782_400.0, "2000-02-29T00:00:00Z"),
            (1e-10, "1970-01-01T00:00:00Z"),
            (-0.0, "1970-01-01T00:00:00Z"),
        ];
        for (timestamp, expected) in samples {
            assert_eq!(iso_utc(timestamp).unwrap(), expected, "{timestamp}");
        }
    }

    #[test]
    fn iso_utc_rejects_non_finite_and_huge() {
        assert_eq!(iso_utc(f64::NAN).unwrap_err().to_string(), TIMESTAMP_NAN);
        assert_eq!(
            iso_utc(f64::INFINITY).unwrap_err(),
            DoctorError::Timestamp(TIMESTAMP_TIME_T)
        );
        assert_eq!(
            iso_utc(f64::NEG_INFINITY).unwrap_err().to_string(),
            TIMESTAMP_TIME_T
        );
        assert_eq!(iso_utc(1e20).unwrap_err().to_string(), TIMESTAMP_TIME_T);
    }

    #[test]
    fn index_to_dict_keeps_null_and_zero() {
        let absent = IndexDiag {
            sessions_on_disk: 2,
            index_entries: None,
            state: "absent".to_owned(),
        };
        assert_eq!(
            object_keys(&absent.to_dict()),
            ["index_entries", "sessions_on_disk", "state"]
        );
        assert_eq!(
            absent.to_dict(),
            DoctorJson::Object(vec![
                ("index_entries".to_owned(), DoctorJson::Null),
                ("sessions_on_disk".to_owned(), DoctorJson::Int(2)),
                ("state".to_owned(), string("absent")),
            ])
        );
        let zero = IndexDiag {
            sessions_on_disk: 0,
            index_entries: Some(0),
            state: "not-a-closed-state".to_owned(),
        };
        assert_eq!(
            zero.to_dict(),
            DoctorJson::Object(vec![
                ("index_entries".to_owned(), DoctorJson::Int(0)),
                ("sessions_on_disk".to_owned(), DoctorJson::Int(0)),
                ("state".to_owned(), string("not-a-closed-state")),
            ])
        );
    }

    #[test]
    fn empty_report_matches_python_text() {
        let report = primary_report();
        assert_eq!(report.render_human(None).unwrap(), PRIMARY_HUMAN);
        assert_eq!(report.to_json(None).unwrap(), PRIMARY_JSON);
        assert_eq!(
            object_keys(&report.to_dict(None).unwrap()),
            [
                "schema_version",
                "tool_version",
                "adapters",
                "reader_limits",
                "config_path",
                "roots"
            ]
        );
    }

    #[test]
    fn render_versions_type_and_unicode_match_python() {
        let not_list = DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![row(&[
                ("name", string("n")),
                ("versions_supported", string("plain")),
            ])],
            reader_limits: limits(&[("z", Some(1)), ("a", None)]),
            config_path: None,
            roots: Vec::new(),
        };
        assert_eq!(not_list.render_human(None).unwrap(), NOTLIST_HUMAN);
        assert_eq!(not_list.to_json(None).unwrap(), NOTLIST_JSON);

        let mixed = DoctorReport {
            tool_version: "t".to_owned(),
            adapters: vec![row(&[
                ("name", string("n")),
                (
                    "versions_supported",
                    DoctorJson::Array(vec![
                        string("a"),
                        DoctorJson::Int(2),
                        DoctorJson::Null,
                        DoctorJson::Bool(true),
                        DoctorJson::Bool(false),
                    ]),
                ),
            ])],
            reader_limits: limits(&[("m", Some(0))]),
            config_path: None,
            roots: Vec::new(),
        };
        assert_eq!(mixed.render_human(None).unwrap(), MIXED_HUMAN);
        assert_eq!(mixed.to_json(None).unwrap(), MIXED_JSON);

        let uni = DoctorReport {
            tool_version: "t".to_owned(),
            adapters: vec![row(&[
                ("name", string("café")),
                ("versions_supported", DoctorJson::Array(vec![string("☃")])),
            ])],
            reader_limits: Vec::new(),
            config_path: None,
            roots: Vec::new(),
        };
        assert_eq!(uni.render_human(None).unwrap(), UNI_HUMAN);
        assert_eq!(uni.to_json(None).unwrap(), UNI_JSON);
    }

    #[test]
    fn render_key_error_precedes_minimize() {
        let missing_versions = DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![row(&[("name", string("only-name"))])],
            reader_limits: Vec::new(),
            config_path: Some("C:/synthetic/sesslint.toml".to_owned()),
            roots: Vec::new(),
        };
        let error = missing_versions.render_human(None).unwrap_err();
        assert_eq!(error.to_string(), "'versions_supported'");

        let missing_name = DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![row(&[(
                "versions_supported",
                DoctorJson::Array(vec![string("x")]),
            )])],
            reader_limits: Vec::new(),
            config_path: None,
            roots: Vec::new(),
        };
        assert_eq!(
            missing_name.render_human(None).unwrap_err().to_string(),
            "'name'"
        );
    }

    #[test]
    fn minimize_path_is_a_typed_seam() {
        let configured = DoctorReport {
            tool_version: "t".to_owned(),
            adapters: Vec::new(),
            reader_limits: Vec::new(),
            config_path: Some("C:/synthetic/sesslint.toml".to_owned()),
            roots: Vec::new(),
        };
        let home = Path::new("C:/synthetic-home-missing");
        assert_eq!(
            configured.to_dict(Some(home)).unwrap_err().to_string(),
            MINIMIZE_PATH_UNAVAILABLE
        );
        assert_eq!(
            configured.to_json(None).unwrap_err(),
            DoctorError::MinimizePathUnavailable
        );
        assert_eq!(
            configured.render_human(None).unwrap_err().to_string(),
            MINIMIZE_PATH_UNAVAILABLE
        );

        let rooted = DoctorReport {
            tool_version: "t".to_owned(),
            adapters: Vec::new(),
            reader_limits: Vec::new(),
            config_path: None,
            roots: vec![RootDiag {
                agent: "claude".to_owned(),
                path: "C:/synthetic/claude".to_owned(),
                exists: false,
                source: "default".to_owned(),
                file_count: 0,
                file_count_capped: false,
                newest_mtime: None,
                checked: 0,
                verdicts: Vec::new(),
                top_codes: Vec::new(),
                index: None,
            }],
        };
        assert_eq!(
            rooted.to_dict(None).unwrap_err(),
            DoctorError::MinimizePathUnavailable
        );
        assert_eq!(
            rooted.render_human(None).unwrap_err().to_string(),
            MINIMIZE_PATH_UNAVAILABLE
        );
    }

    #[test]
    fn rendered_roots_match_python_when_path_is_already_shown() {
        let report = shown_root();
        let human = report.render_human_with(None, show_fixed).unwrap();
        assert_eq!(human, ROOT_HUMAN);
        let json = dumps_sorted(&report.to_dict_with(None, show_fixed).unwrap());
        assert_eq!(json, ROOT_JSON);
        let root = report.roots[1].to_dict_with(None, show_fixed).unwrap();
        assert_eq!(
            object_keys(&root),
            [
                "agent",
                "path",
                "exists",
                "source",
                "file_count",
                "file_count_capped",
                "newest_mtime",
                "checked",
                "verdicts",
                "top_codes",
                "index"
            ]
        );
    }

    #[test]
    fn count_files_walks_sorted_and_skips_vendor_dirs() {
        let scratch = Scratch::new();
        let root = scratch.path();
        for name in [
            "b.json",
            "a.txt",
            "sesslint.toml",
            ".sesslint.toml",
            "c.jsonl",
            "A.JSON",
            "keep.JSONL",
        ] {
            touch(&root.join(name));
        }
        touch(&root.join("m").join("d.json"));
        touch(&root.join(".git").join("hidden.json"));
        touch(&root.join(".hg").join("hidden.json"));
        touch(&root.join(".svn").join("hidden.json"));
        touch(&root.join("z").join("inner").join("e.json"));

        let counted = count_files(root);
        assert!(!counted.capped);
        assert_eq!(counted.count, 7);
        let rels = counted
            .candidates
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|component| component.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect::<Vec<_>>();
        assert_eq!(rels, ["b.json", "c.jsonl", "z/inner/e.json", "m/d.json"]);
    }

    #[test]
    fn count_files_missing_and_file_root_are_empty() {
        let scratch = Scratch::new();
        let missing = count_files(&scratch.path().join("no-such-dir"));
        assert_eq!(missing.count, 0);
        assert!(!missing.capped);
        assert!(missing.candidates.is_empty());
        let file = scratch.path().join("a.txt");
        touch(&file);
        let counted = count_files(&file);
        assert_eq!(counted.count, 0);
        assert!(!counted.capped);
        assert!(counted.candidates.is_empty());
    }

    #[test]
    fn count_files_caps_on_the_next_entry() {
        let scratch = Scratch::new();
        let root = scratch.path();
        let extra = MAX_FILE_COUNT + 1;
        for index in 0..extra {
            touch(&root.join(format!("n{index:05}.txt")));
        }
        let counted = count_files(root);
        assert!(counted.capped);
        assert_eq!(counted.count, MAX_FILE_COUNT);
        assert!(counted.candidates.is_empty());
    }

    #[test]
    fn count_files_does_not_follow_symlink() {
        let scratch = Scratch::new();
        let target = scratch.path().join("real.json");
        touch(&target);
        let link = scratch.path().join("link.jsonl");
        if symlink_file(&target, &link).is_err() {
            return;
        }
        let counted = count_files(scratch.path());
        assert_eq!(counted.count, 1);
        assert_eq!(counted.candidates.len(), 1);
        assert_eq!(counted.candidates[0].file_name().unwrap(), "real.json");
    }

    #[test]
    fn quick_verdicts_empty_and_check_file_seam() {
        let empty = quick_verdicts(&[]).unwrap();
        assert_eq!(empty.checked, 0);
        assert!(empty.verdicts.is_empty());
        assert!(empty.top_codes.is_empty());

        let scratch = Scratch::new();
        let directory = scratch.path().join("sub");
        fs::create_dir(&directory).unwrap();
        let missing = scratch.path().join("nope.json");
        let ignored = quick_verdicts(&[directory, missing]).unwrap();
        assert_eq!(ignored.checked, 0);

        let file = scratch.path().join("note.json");
        touch(&file);
        let error = quick_verdicts(&[file]).unwrap_err();
        assert_eq!(error.to_string(), CHECK_FILE_UNAVAILABLE);
    }

    #[test]
    fn verdict_rules_match_python_order() {
        let unsupported = CheckView {
            limitation: "Unsupported: synthetic".to_owned(),
            by_severity: vec![("fatal".to_owned(), 4), ("error".to_owned(), 1)],
            finding_codes: vec!["SYN-Z".to_owned()],
        };
        let skipped = CheckView {
            limitation: "Skipped: synthetic".to_owned(),
            by_severity: vec![("warning".to_owned(), 9)],
            finding_codes: Vec::new(),
        };
        let invalid = CheckView {
            limitation: String::new(),
            by_severity: vec![
                ("error".to_owned(), 0),
                ("error".to_owned(), 1),
                ("warning".to_owned(), 3),
            ],
            finding_codes: vec!["SYN-B".to_owned(), "SYN-A".to_owned()],
        };
        let warnings = CheckView {
            limitation: "warning-not-a-prefix".to_owned(),
            by_severity: vec![("warning".to_owned(), 1), ("fatal".to_owned(), 0)],
            finding_codes: vec!["SYN-A".to_owned()],
        };
        let healthy = CheckView {
            limitation: String::new(),
            by_severity: Vec::new(),
            finding_codes: vec!["SYN-C".to_owned()],
        };
        let outcome = verdicts_from_outcomes(&[
            CheckOutcome::Report(unsupported),
            CheckOutcome::Unreadable,
            CheckOutcome::Report(skipped),
            CheckOutcome::Report(invalid),
            CheckOutcome::Report(warnings),
            CheckOutcome::Report(healthy),
        ]);
        assert_eq!(outcome.checked, 6);
        assert_eq!(
            outcome.verdicts,
            vec![
                ("unsupported".to_owned(), 1),
                ("unreadable".to_owned(), 1),
                ("skipped".to_owned(), 1),
                ("invalid".to_owned(), 1),
                ("warnings".to_owned(), 1),
                ("healthy".to_owned(), 1),
            ]
        );
        assert_eq!(
            outcome.top_codes,
            vec![
                ("SYN-A".to_owned(), 2),
                ("SYN-B".to_owned(), 1),
                ("SYN-C".to_owned(), 1),
                ("SYN-Z".to_owned(), 1),
            ]
        );

        let mut crowded = Vec::new();
        for (code, times) in [
            ("SYN-B", 3),
            ("SYN-A", 3),
            ("SYN-D", 2),
            ("SYN-C", 2),
            ("SYN-F", 1),
            ("SYN-E", 1),
        ] {
            for _ in 0..times {
                crowded.push(CheckOutcome::Report(CheckView {
                    limitation: String::new(),
                    by_severity: Vec::new(),
                    finding_codes: vec![code.to_owned()],
                }));
            }
        }
        let top = verdicts_from_outcomes(&crowded);
        assert_eq!(
            top.top_codes,
            vec![
                ("SYN-A".to_owned(), 3),
                ("SYN-B".to_owned(), 3),
                ("SYN-C".to_owned(), 2),
                ("SYN-D".to_owned(), 2),
                ("SYN-E".to_owned(), 1),
            ]
        );
    }

    fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "symlinks are not available",
            ))
        }
    }
}
