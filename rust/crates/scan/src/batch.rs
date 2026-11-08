//! Batch repair report rows for one audited pass.
//!
//! Port of `src/sesslint/batch.py` lines 1-213
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! `sesslint.progress`, `sesslint.repair.RepairPlan`, and
//! `sesslint.stats._iter_files` are imported by the pin and are not called in
//! this slice. This module does not link those crates and does not fail to
//! load because they are absent.
//!
//! # Recorded gaps
//!
//! * [`BatchRepairReport::to_json`] calls [`BatchRepairReport::to_dict`] and
//!   then stops. `model` and `checks` do not expose
//!   `json.dumps(..., indent=2, sort_keys=True)`. Display is
//!   [`JSON_DUMPS_UNAVAILABLE`]. No JSON bytes are emitted.
//! * [`_plan_detail`] and [`_compute_plan`] stop at
//!   `from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format`.
//!   Display is [`FORMAT_CANONICAL_UNAVAILABLE`]. The source file is not
//!   read, `detect_format` is not called, and a repair plan is not returned.
//! * [`resolve_scan_report_files`] reads the file first. A missing file uses
//!   the pin `FileNotFoundError` sentence. After a successful UTF-8 read,
//!   display is [`JSON_LOADS_UNAVAILABLE`]. `home` is accepted and unused.
//!   `Path.home` is not called and resolved paths are not invented.
//! * [`BatchRepairReport::render_human`] appends ` - {reason}` when `reason`
//!   is `Some`, including an empty string.

use std::convert::Infallible;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Python: `BATCH_REPORT_VERSION`.
pub const BATCH_REPORT_VERSION: &str = "sesslint.batch-repair/v1";

/// `json.dumps` is not linked from this crate.
pub const JSON_DUMPS_UNAVAILABLE: &str = "json.dumps is not available";

/// `json.loads` is not linked from this crate.
pub const JSON_LOADS_UNAVAILABLE: &str = "json.loads is not available";

/// `sesslint.adapters.detect.FORMAT_CANONICAL` is not linked from this crate.
pub const FORMAT_CANONICAL_UNAVAILABLE: &str =
    "sesslint.adapters.detect.FORMAT_CANONICAL is not available";

const REPAIRED_MARK: &str = ".repaired";
const DEFAULT_SUFFIX: &str = ".jsonl";

/// Insertion-ordered dictionary. This is not `serde_json` and not a `BTreeMap`.
pub type BatchDict = Vec<(String, BatchValue)>;

/// One JSON-like value in a batch row or report dictionary.
///
/// Map and list entries keep insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchValue {
    /// A row count. This is the number of matching rows, not a wrapped integer.
    Count(usize),
    /// A string field.
    Text(String),
    /// Sorted detector or recipe codes.
    Texts(Vec<String>),
    /// An insertion-ordered object.
    Map(BatchDict),
    /// An insertion-ordered list.
    List(Vec<BatchValue>),
}

/// One file's batch outcome (content-free: paths minimized, codes only).
///
/// Python: `BatchRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRow {
    pub path: String,
    pub outcome: String,
    pub codes: Vec<String>,
    pub reason: Option<String>,
    pub output: Option<String>,
    pub manifest: Option<String>,
}

impl BatchRow {
    /// Dataclass construction: `path` and `outcome` are required.
    ///
    /// `codes` starts empty. `reason`, `output`, and `manifest` start as `None`.
    #[must_use]
    pub fn new(path: impl Into<String>, outcome: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            outcome: outcome.into(),
            codes: Vec::new(),
            reason: None,
            output: None,
            manifest: None,
        }
    }

    /// Python: `BatchRow.to_dict`.
    ///
    /// Keys start with `outcome`, then `path`. Empty `codes` are omitted.
    /// `reason`, `output`, and `manifest` are omitted when `None`. Present
    /// codes are stored sorted. The stored `codes` vector is not reordered.
    #[must_use]
    pub fn to_dict(&self) -> BatchDict {
        let mut dict = vec![
            ("outcome".to_owned(), BatchValue::Text(self.outcome.clone())),
            ("path".to_owned(), BatchValue::Text(self.path.clone())),
        ];
        if !self.codes.is_empty() {
            let mut codes = self.codes.clone();
            codes.sort();
            dict.push(("codes".to_owned(), BatchValue::Texts(codes)));
        }
        if let Some(reason) = &self.reason {
            dict.push(("reason".to_owned(), BatchValue::Text(reason.clone())));
        }
        if let Some(output) = &self.output {
            dict.push(("output".to_owned(), BatchValue::Text(output.clone())));
        }
        if let Some(manifest) = &self.manifest {
            dict.push(("manifest".to_owned(), BatchValue::Text(manifest.clone())));
        }
        dict
    }
}

/// Deterministic batch summary: counts plus per-file rows, no payloads.
///
/// Python: `BatchRepairReport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRepairReport {
    pub rows: Vec<BatchRow>,
    pub version: String,
}

impl BatchRepairReport {
    /// `rows` are stored in the caller's order. `version` is [`BATCH_REPORT_VERSION`].
    #[must_use]
    pub fn new(rows: Vec<BatchRow>) -> Self {
        Self {
            rows,
            version: BATCH_REPORT_VERSION.to_owned(),
        }
    }

    /// Rows whose outcome is `repaired`, `refused`, or `eligible`.
    #[must_use]
    pub fn attempted(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| {
                row.outcome == "repaired" || row.outcome == "refused" || row.outcome == "eligible"
            })
            .count()
    }

    /// Rows whose outcome is exactly `repaired`.
    #[must_use]
    pub fn repaired(&self) -> usize {
        count_outcome(&self.rows, "repaired")
    }

    /// Rows whose outcome is exactly `refused`.
    #[must_use]
    pub fn refused(&self) -> usize {
        count_outcome(&self.rows, "refused")
    }

    /// Rows whose outcome is exactly `skipped`.
    #[must_use]
    pub fn skipped(&self) -> usize {
        count_outcome(&self.rows, "skipped")
    }

    /// Python: `BatchRepairReport.to_dict`.
    ///
    /// Keys are `counts`, `rows`, `version`. Count keys are `attempted`,
    /// `refused`, `repaired`, `skipped`. `home` is accepted and unused.
    #[must_use]
    pub fn to_dict(&self, home: Option<&Path>) -> BatchDict {
        let _ = home;
        let counts = vec![
            ("attempted".to_owned(), BatchValue::Count(self.attempted())),
            ("refused".to_owned(), BatchValue::Count(self.refused())),
            ("repaired".to_owned(), BatchValue::Count(self.repaired())),
            ("skipped".to_owned(), BatchValue::Count(self.skipped())),
        ];
        let rows = self
            .rows
            .iter()
            .map(|row| BatchValue::Map(row.to_dict()))
            .collect();
        vec![
            ("counts".to_owned(), BatchValue::Map(counts)),
            ("rows".to_owned(), BatchValue::List(rows)),
            ("version".to_owned(), BatchValue::Text(self.version.clone())),
        ]
    }

    /// Python: `BatchRepairReport.to_json`.
    ///
    /// [`Self::to_dict`] runs first. `json.dumps(..., indent=2, sort_keys=True)`
    /// is not available. No JSON text is returned.
    pub fn to_json(&self, home: Option<&Path>) -> Result<Infallible, JsonDumpsUnavailable> {
        let _dict = self.to_dict(home);
        Err(JsonDumpsUnavailable)
    }

    /// Python: `BatchRepairReport.render_human`.
    ///
    /// Lines are joined with `\n`. There is no trailing newline. `home` is
    /// accepted and unused. An empty reason is omitted, matching `if r.reason`.
    #[must_use]
    pub fn render_human(&self, home: Option<&Path>) -> String {
        let _ = home;
        let mut lines = Vec::with_capacity(self.rows.len().saturating_add(1));
        lines.push(format!(
            "Batch repair: {} repaired, {} refused, {} skipped ({} attempted)",
            self.repaired(),
            self.refused(),
            self.skipped(),
            self.attempted()
        ));
        for row in &self.rows {
            lines.push(render_row(row));
        }
        lines.join("\n")
    }
}

/// `json.dumps` is not available in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonDumpsUnavailable;

impl fmt::Display for JsonDumpsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(JSON_DUMPS_UNAVAILABLE)
    }
}

impl Error for JsonDumpsUnavailable {}

/// `sesslint.adapters.detect.FORMAT_CANONICAL` is not available in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatCanonicalUnavailable;

impl fmt::Display for FormatCanonicalUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(FORMAT_CANONICAL_UNAVAILABLE)
    }
}

impl Error for FormatCanonicalUnavailable {}

/// [`resolve_scan_report_files`] stopped. No path list is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveScanReportError {
    /// Python `FileNotFoundError`, `PermissionError`, `UnicodeDecodeError`, or
    /// another read failure. Display is that exception's message.
    Read(String),
    /// The file was read as UTF-8. `json.loads` is not available.
    Loads,
}

impl fmt::Display for ResolveScanReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message) => formatter.write_str(message),
            Self::Loads => formatter.write_str(JSON_LOADS_UNAVAILABLE),
        }
    }
}

impl Error for ResolveScanReportError {}

/// [`_output_for`] could not build a path without inventing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputForError {
    /// A path component is not Unicode. No repaired name is invented.
    NotUnicode,
    /// Python `RuntimeError` from a symlink loop inside `Path.resolve`.
    ///
    /// The string is the Python `%r` of the path that looped.
    SymlinkLoop(String),
}

impl fmt::Display for OutputForError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode => formatter.write_str("path is not valid Unicode"),
            Self::SymlinkLoop(text) => write!(formatter, "Symlink loop from {text}"),
        }
    }
}

impl Error for OutputForError {}

/// Python: `_output_for`.
///
/// The file name is `stem + ".repaired" + suffix`, or `stem + ".repaired.jsonl"`
/// when the suffix is empty. When `root` is set, `resolve` and `relative_to`
/// mirror the parent directories under `out_dir`. `ValueError` and `OSError`
/// from that pair fall back to `out_dir / name`.
pub fn _output_for(
    src: &Path,
    root: Option<&Path>,
    out_dir: &Path,
) -> Result<PathBuf, OutputForError> {
    let name = repaired_name(src)?;
    if let Some(root) = root {
        match mirrored_parent(src, root) {
            Ok(parent) => return Ok(join_out(out_dir, &parent, &name)),
            Err(PathFail::GiveUp) => {}
            Err(PathFail::NotUnicode) => return Err(OutputForError::NotUnicode),
            Err(PathFail::SymlinkLoop(text)) => return Err(OutputForError::SymlinkLoop(text)),
        }
    }
    Ok(join_out(out_dir, &[], &name))
}

/// Python: `_plan_detail`.
///
/// Stops at `from sesslint.adapters.detect import FORMAT_CANONICAL, detect_format`.
/// `src` is not read.
pub fn _plan_detail(
    src: &Path,
    format: Option<&str>,
    policy: &str,
    profile: &str,
    acknowledge_side_effects: bool,
) -> Result<Infallible, FormatCanonicalUnavailable> {
    let _unused = (src, format, policy, profile, acknowledge_side_effects);
    Err(FormatCanonicalUnavailable)
}

/// Python: `_compute_plan`.
///
/// Calls [`_plan_detail`] and does not return a repair plan.
pub fn _compute_plan(
    src: &Path,
    format: Option<&str>,
    policy: &str,
    profile: &str,
    acknowledge_side_effects: bool,
) -> Result<Infallible, FormatCanonicalUnavailable> {
    _plan_detail(src, format, policy, profile, acknowledge_side_effects)
}

/// Python: `resolve_scan_report_files`.
///
/// Reads `report_path` as UTF-8 before any parse. `home` is accepted and unused.
/// A successful read stops with [`JSON_LOADS_UNAVAILABLE`].
pub fn resolve_scan_report_files(
    report_path: impl AsRef<Path>,
    home: Option<&Path>,
) -> Result<Infallible, ResolveScanReportError> {
    let text = read_report_text(report_path.as_ref())?;
    let _unused = (text, home);
    Err(ResolveScanReportError::Loads)
}

fn count_outcome(rows: &[BatchRow], outcome: &str) -> usize {
    rows.iter().filter(|row| row.outcome == outcome).count()
}

fn render_row(row: &BatchRow) -> String {
    let tail = codes_tail(&row.codes);
    let reason = match row.reason.as_deref() {
        Some(reason) if !reason.is_empty() => format!(" - {reason}"),
        _ => String::new(),
    };
    format!("  {}: {}{tail}{reason}", row.outcome, row.path)
}

fn codes_tail(codes: &[String]) -> String {
    if codes.is_empty() {
        return String::new();
    }
    let mut sorted = codes.to_vec();
    sorted.sort();
    format!(" [{}]", sorted.join(", "))
}

fn repaired_name(src: &Path) -> Result<String, OutputForError> {
    let name = final_name(src)?;
    let suffix = python_suffix(&name);
    let stem = python_stem(&name);
    let extension = if suffix.is_empty() {
        DEFAULT_SUFFIX
    } else {
        suffix
    };
    Ok(format!("{stem}{REPAIRED_MARK}{extension}"))
}

fn final_name(path: &Path) -> Result<String, OutputForError> {
    let mut last = String::new();
    let mut saw = false;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                last = os_owned(part).map_err(|_| OutputForError::NotUnicode)?;
                saw = true;
            }
            Component::ParentDir => {
                last = "..".to_owned();
                saw = true;
            }
            Component::CurDir | Component::RootDir => {}
            #[cfg(windows)]
            Component::Prefix(_) => {}
        }
    }
    if saw {
        Ok(last)
    } else {
        Ok(String::new())
    }
}

fn python_stem(name: &str) -> &str {
    match split_suffix(name) {
        Some((stem, _)) => stem,
        None => name,
    }
}

fn python_suffix(name: &str) -> &str {
    match split_suffix(name) {
        Some((_, suffix)) => suffix,
        None => "",
    }
}

fn split_suffix(name: &str) -> Option<(&str, &str)> {
    let dot = name.rfind('.')?;
    if dot == 0 || dot.saturating_add(1) >= name.len() {
        return None;
    }
    Some((name.get(..dot)?, name.get(dot..)?))
}

fn join_out(out_dir: &Path, parent: &[String], name: &str) -> PathBuf {
    let mut out = out_dir.to_path_buf();
    for part in parent {
        out.push(part);
    }
    out.push(name);
    out
}

enum PathFail {
    NotUnicode,
    SymlinkLoop(String),
    GiveUp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbsPath {
    anchor: String,
    parts: Vec<String>,
}

fn mirrored_parent(src: &Path, root: &Path) -> Result<Vec<String>, PathFail> {
    let src_abs = resolve_nonstrict(src)?;
    let root_abs = resolve_nonstrict(root)?;
    let relative = relative_parts(&src_abs, &root_abs).ok_or(PathFail::GiveUp)?;
    Ok(parent_parts(&relative))
}

fn parent_parts(relative: &[String]) -> Vec<String> {
    match relative.split_last() {
        Some((_, parent)) => parent.to_vec(),
        None => Vec::new(),
    }
}

fn relative_parts(src: &AbsPath, root: &AbsPath) -> Option<Vec<String>> {
    if !same_part(&src.anchor, &root.anchor) {
        return None;
    }
    if root.parts.len() > src.parts.len() {
        return None;
    }
    for (src_part, root_part) in src.parts.iter().zip(root.parts.iter()) {
        if !same_part(src_part, root_part) {
            return None;
        }
    }
    src.parts.get(root.parts.len()..).map(<[String]>::to_vec)
}

fn same_part(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    if cfg!(windows) {
        left.to_lowercase() == right.to_lowercase()
    } else {
        false
    }
}

fn resolve_nonstrict(path: &Path) -> Result<AbsPath, PathFail> {
    if drive_relative(path) {
        return Err(PathFail::GiveUp);
    }
    let absolute = std::path::absolute(path).map_err(|_| PathFail::GiveUp)?;
    let lexical = normalize_absolute(&absolute)?;
    with_existing_prefix(lexical)
}

fn drive_relative(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut saw_prefix = false;
        let mut saw_root = false;
        for component in path.components() {
            match component {
                Component::Prefix(_) => saw_prefix = true,
                Component::RootDir => saw_root = true,
                _ => {}
            }
        }
        saw_prefix && !saw_root
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

fn normalize_absolute(path: &Path) -> Result<AbsPath, PathFail> {
    if !path.is_absolute() {
        return Err(PathFail::GiveUp);
    }
    let mut anchor = String::new();
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => {
                anchor = prefix_anchor(prefix.kind())?;
            }
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                let _above_root = parts.pop();
            }
            Component::Normal(part) => parts.push(os_owned(part)?),
        }
    }
    Ok(AbsPath { anchor, parts })
}

fn with_existing_prefix(lexical: AbsPath) -> Result<AbsPath, PathFail> {
    let mut len = lexical.parts.len();
    loop {
        let candidate = render_abs(&lexical, len);
        match std::fs::canonicalize(&candidate) {
            Ok(canon) => {
                let base = normalize_absolute(&canon)?;
                let mut merged = base;
                if let Some(tail) = lexical.parts.get(len..) {
                    merged.parts.extend(tail.iter().cloned());
                }
                return Ok(merged);
            }
            Err(err) if is_soft(&err) => {
                if len == 0 {
                    return Ok(lexical);
                }
                len -= 1;
            }
            Err(err) if is_loop(&err) => {
                let shown = match python_path_str(&candidate) {
                    Ok(text) => python_repr(&text),
                    Err(_) => "''".to_owned(),
                };
                return Err(PathFail::SymlinkLoop(shown));
            }
            Err(_) => return Err(PathFail::GiveUp),
        }
    }
}

fn is_soft(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn is_loop(err: &io::Error) -> bool {
    // `ErrorKind::FilesystemLoop` is unstable (`io_error_more`) on this toolchain.
    let Some(code) = err.raw_os_error() else {
        return false;
    };
    eloop_code(code)
}

fn eloop_code(code: i32) -> bool {
    #[cfg(windows)]
    {
        // ERROR_CANT_RESOLVE_FILENAME. Python raises RuntimeError for this.
        code == 1921
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // ELOOP
        code == 40
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        // ELOOP
        code == 62
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )))]
    {
        let _ = code;
        false
    }
}

fn render_abs(path: &AbsPath, len: usize) -> PathBuf {
    let sep = std::path::MAIN_SEPARATOR;
    let mut rendered = String::new();
    if cfg!(windows) {
        rendered.push_str(&path.anchor);
        if !rendered.ends_with(sep) {
            rendered.push(sep);
        }
    } else {
        rendered.push(sep);
    }
    for (index, part) in path.parts.iter().take(len).enumerate() {
        if index > 0 {
            rendered.push(sep);
        }
        rendered.push_str(part);
    }
    PathBuf::from(rendered)
}

#[cfg(windows)]
fn prefix_anchor(prefix: std::path::Prefix<'_>) -> Result<String, PathFail> {
    match prefix {
        std::path::Prefix::Disk(disk) | std::path::Prefix::VerbatimDisk(disk) => {
            Ok(format!("{}:", char::from(disk)))
        }
        std::path::Prefix::UNC(server, share) | std::path::Prefix::VerbatimUNC(server, share) => {
            let server = os_owned(server)?;
            let share = os_owned(share)?;
            Ok(format!("\\\\{server}\\{share}"))
        }
        std::path::Prefix::DeviceNS(device) => {
            let device = os_owned(device)?;
            Ok(format!("\\\\.\\{device}"))
        }
        std::path::Prefix::Verbatim(text) => os_owned(text),
    }
}

fn os_owned(part: &OsStr) -> Result<String, PathFail> {
    match part.to_str() {
        Some(text) => Ok(text.to_owned()),
        None => Err(PathFail::NotUnicode),
    }
}

fn read_report_text(path: &Path) -> Result<String, ResolveScanReportError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => return Err(ResolveScanReportError::Read(io_message(&err, path))),
    };
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => Err(ResolveScanReportError::Read(utf8_message(&bytes))),
    }
}

fn io_message(err: &io::Error, path: &Path) -> String {
    let shown = match python_path_str(path) {
        Ok(text) => python_repr(&text),
        Err(_) => return "path is not valid Unicode".to_owned(),
    };
    match err.kind() {
        io::ErrorKind::NotFound => {
            format!("[Errno 2] No such file or directory: {shown}")
        }
        io::ErrorKind::PermissionDenied => format!("[Errno 13] Permission denied: {shown}"),
        #[cfg(windows)]
        io::ErrorKind::IsADirectory => format!("[Errno 13] Permission denied: {shown}"),
        #[cfg(not(windows))]
        io::ErrorKind::IsADirectory => format!("[Errno 21] Is a directory: {shown}"),
        _ => match err.raw_os_error() {
            Some(code) => format!("[os error {code}]: {shown}"),
            None => format!("[os error]: {shown}"),
        },
    }
}

fn python_path_str(path: &Path) -> Result<String, PathFail> {
    let mut anchor = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => {
                anchor = prefix_anchor(prefix.kind())?;
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(part) => parts.push(os_owned(part)?),
        }
    }
    Ok(render_parsed(&anchor, rooted, &parts))
}

fn render_parsed(anchor: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if parts.is_empty() {
        if anchor.is_empty() && !rooted {
            return ".".to_owned();
        }
        if rooted {
            let mut out = anchor.to_owned();
            if !out.ends_with(sep) {
                out.push(sep);
            }
            return out;
        }
        return anchor.to_owned();
    }
    if rooted {
        let mut out = anchor.to_owned();
        if !out.ends_with(sep) {
            out.push(sep);
        }
        out.push_str(&join_sep(parts, sep));
        return out;
    }
    if anchor.is_empty() {
        return join_sep(parts, sep);
    }
    let mut out = anchor.to_owned();
    if let Some(first) = parts.first() {
        out.push_str(first);
    }
    if let Some(rest) = parts.get(1..) {
        if !rest.is_empty() {
            out.push(sep);
            out.push_str(&join_sep(rest, sep));
        }
    }
    out
}

fn join_sep(parts: &[String], sep: char) -> String {
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(sep);
        }
        out.push_str(part);
    }
    out
}

fn python_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(quote);
            }
            ch if python_repr_literal(ch) => out.push(ch),
            ch if u32::from(ch) < 0x100 => push_hex(&mut out, "\\x", u32::from(ch), 2),
            ch if u32::from(ch) < 0x10000 => push_hex(&mut out, "\\u", u32::from(ch), 4),
            ch => push_hex(&mut out, "\\U", u32::from(ch), 8),
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
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = (value >> (shift.saturating_mul(4))) & 0x0f;
        out.push(hex_digit(nibble));
    }
}

fn hex_digit(nibble: u32) -> char {
    match nibble {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

fn utf8_message(bytes: &[u8]) -> String {
    match utf8_fault(bytes) {
        Some((start, end, reason)) => format_utf8(bytes, start, end, reason),
        None => "invalid utf-8".to_owned(),
    }
}

fn format_utf8(bytes: &[u8], start: usize, end: usize, reason: &str) -> String {
    if end == start.saturating_add(1) {
        match bytes.get(start) {
            Some(byte) => {
                format!(
                    "'utf-8' codec can't decode byte 0x{byte:02x} in position {start}: {reason}"
                )
            }
            None => {
                format!("'utf-8' codec can't decode bytes in position {start}-{end}: {reason}")
            }
        }
    } else {
        let last = end.saturating_sub(1);
        format!("'utf-8' codec can't decode bytes in position {start}-{last}: {reason}")
    }
}

fn utf8_fault(bytes: &[u8]) -> Option<(usize, usize, &'static str)> {
    let mut index = 0_usize;
    while index < bytes.len() {
        let first = match bytes.get(index) {
            Some(byte) => *byte,
            None => return Some((index, index, "unexpected end of data")),
        };
        if first < 0x80 {
            index = index.saturating_add(1);
            continue;
        }
        if !(0xC2..=0xF4).contains(&first) {
            return Some((index, index.saturating_add(1), "invalid start byte"));
        }
        let (need, low, high) = utf8_span(first);
        for step in 1..need {
            let Some(at) = index.checked_add(step) else {
                return Some((index, index, "unexpected end of data"));
            };
            if at >= bytes.len() {
                return Some((index, at, "unexpected end of data"));
            }
            let Some(byte) = bytes.get(at).copied() else {
                return Some((index, at, "unexpected end of data"));
            };
            let continuation = (byte & 0xC0) == 0x80;
            if step == 1 {
                if !continuation || !(low..=high).contains(&byte) {
                    return Some((index, index.saturating_add(1), "invalid continuation byte"));
                }
            } else if !continuation {
                return Some((index, at, "invalid continuation byte"));
            }
        }
        index = match index.checked_add(need) {
            Some(next) => next,
            None => return Some((index, index, "unexpected end of data")),
        };
    }
    None
}

fn utf8_span(first: u8) -> (usize, u8, u8) {
    if first <= 0xDF {
        (2, 0x80, 0xBF)
    } else if first <= 0xEF {
        let (low, high) = if first == 0xE0 {
            (0xA0, 0xBF)
        } else if first == 0xED {
            (0x80, 0x9F)
        } else {
            (0x80, 0xBF)
        };
        (3, low, high)
    } else {
        let (low, high) = if first == 0xF0 {
            (0x90, 0xBF)
        } else if first == 0xF4 {
            (0x80, 0x8F)
        } else {
            (0x80, 0xBF)
        };
        (4, low, high)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        _compute_plan, _output_for, _plan_detail, python_repr, resolve_scan_report_files,
        utf8_message, BatchRepairReport, BatchRow, BatchValue, FormatCanonicalUnavailable,
        ResolveScanReportError, BATCH_REPORT_VERSION, FORMAT_CANONICAL_UNAVAILABLE,
        JSON_DUMPS_UNAVAILABLE, JSON_LOADS_UNAVAILABLE,
    };

    fn keys(dict: &super::BatchDict) -> Vec<&str> {
        dict.iter().map(|(key, _)| key.as_str()).collect()
    }

    fn scratch_dir(name: &str) -> Scratch {
        let path = PathBuf::from(name);
        fs::create_dir_all(&path).expect("create synthetic dir");
        Scratch { path }
    }

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn assert_output(src: &str, root: Option<&str>, expected: &[&str]) {
        let root_buf = root.map(PathBuf::from);
        let actual = _output_for(Path::new(src), root_buf.as_deref(), Path::new("out"))
            .expect("output path");
        let mut expected_path = PathBuf::from("out");
        for part in expected {
            expected_path.push(part);
        }
        assert!(actual.is_relative());
        assert_eq!(actual, expected_path);
    }

    #[test]
    fn version_constant_matches_the_pin() {
        assert_eq!(BATCH_REPORT_VERSION, "sesslint.batch-repair/v1");
    }

    #[test]
    fn counts_use_exact_outcome_strings() {
        let report = BatchRepairReport::new(vec![
            BatchRow::new("synthetic/a.jsonl", "repaired"),
            BatchRow::new("synthetic/b.jsonl", "refused"),
            BatchRow::new("synthetic/c.jsonl", "eligible"),
            BatchRow::new("synthetic/d.jsonl", "skipped"),
            BatchRow::new("synthetic/e.jsonl", "Eligible"),
            BatchRow::new("synthetic/f.jsonl", "repaired "),
            BatchRow::new("synthetic/g.jsonl", "other"),
        ]);
        assert_eq!(report.attempted(), 3);
        assert_eq!(report.repaired(), 1);
        assert_eq!(report.refused(), 1);
        assert_eq!(report.skipped(), 1);
    }

    #[test]
    fn empty_report_counts_are_zero() {
        let report = BatchRepairReport::new(Vec::new());
        assert_eq!(report.attempted(), 0);
        assert_eq!(report.repaired(), 0);
        assert_eq!(report.refused(), 0);
        assert_eq!(report.skipped(), 0);
        assert_eq!(report.version, BATCH_REPORT_VERSION);
    }

    #[test]
    fn to_dict_keeps_insertion_order_and_omits_empty_optionals() {
        let mut row = BatchRow::new("synthetic/a.jsonl", "skipped");
        row.codes = vec!["SL002".to_owned(), "SL001".to_owned(), "SL001".to_owned()];
        row.reason = Some("blocked".to_owned());
        row.output = Some("synthetic/a.repaired.jsonl".to_owned());
        row.manifest = Some("synthetic/a.manifest.json".to_owned());
        let mut bare = BatchRow::new("synthetic/b.jsonl", "repaired");
        bare.reason = Some(String::new());
        let mut report = BatchRepairReport::new(vec![row.clone(), bare]);
        report.version = "synthetic-version".to_owned();

        let with_home = report.to_dict(Some(Path::new("synthetic-unused-home")));
        let without_home = report.to_dict(None);
        assert_eq!(with_home, without_home);
        assert_eq!(keys(&with_home), vec!["counts", "rows", "version"]);

        let BatchValue::Map(counts) = &with_home[0].1 else {
            panic!("counts must be a map");
        };
        assert_eq!(
            keys(counts),
            vec!["attempted", "refused", "repaired", "skipped"]
        );
        assert_eq!(
            counts,
            &vec![
                ("attempted".to_owned(), BatchValue::Count(1)),
                ("refused".to_owned(), BatchValue::Count(0)),
                ("repaired".to_owned(), BatchValue::Count(1)),
                ("skipped".to_owned(), BatchValue::Count(1)),
            ]
        );

        let BatchValue::List(rows) = &with_home[1].1 else {
            panic!("rows must be a list");
        };
        let BatchValue::Map(first) = &rows[0] else {
            panic!("row must be a map");
        };
        assert_eq!(
            keys(first),
            vec!["outcome", "path", "codes", "reason", "output", "manifest"]
        );
        assert_eq!(
            first[2],
            (
                "codes".to_owned(),
                BatchValue::Texts(vec![
                    "SL001".to_owned(),
                    "SL001".to_owned(),
                    "SL002".to_owned()
                ])
            )
        );
        assert_eq!(
            row.codes,
            vec!["SL002".to_owned(), "SL001".to_owned(), "SL001".to_owned()]
        );

        let BatchValue::Map(second) = &rows[1] else {
            panic!("row must be a map");
        };
        assert_eq!(keys(second), vec!["outcome", "path", "reason"]);
        assert_eq!(second[2].1, BatchValue::Text(String::new()));
        assert_eq!(
            with_home[2].1,
            BatchValue::Text("synthetic-version".to_owned())
        );

        let omitted = BatchRow::new("synthetic/c.jsonl", "eligible").to_dict();
        assert_eq!(keys(&omitted), vec!["outcome", "path"]);
    }

    #[test]
    fn render_human_matches_the_card_sentences() {
        let mut skipped = BatchRow::new("synthetic/a.jsonl", "skipped");
        skipped.codes = vec!["SL203".to_owned(), "SL001".to_owned()];
        skipped.reason = Some("blocked".to_owned());
        let repaired = BatchRow::new("synthetic/b.jsonl", "repaired");
        let report = BatchRepairReport::new(vec![skipped, repaired]);
        let text = report.render_human(Some(Path::new("synthetic-unused-home")));
        assert_eq!(
            text,
            "Batch repair: 1 repaired, 0 refused, 1 skipped (1 attempted)\n  \
             skipped: synthetic/a.jsonl [SL001, SL203] - blocked\n  \
             repaired: synthetic/b.jsonl"
        );
        assert!(!text.ends_with('\n'));
        assert!(!text.contains('\r'));
        assert_eq!(report.render_human(None), text);
    }

    #[test]
    fn render_human_empty_rows_have_no_newline() {
        let text = BatchRepairReport::new(Vec::new()).render_human(None);
        assert_eq!(
            text,
            "Batch repair: 0 repaired, 0 refused, 0 skipped (0 attempted)"
        );
        assert!(!text.contains('\n'));
    }

    #[test]
    fn render_human_omits_empty_reason_and_none() {
        let mut empty = BatchRow::new("synthetic/a.jsonl", "skipped");
        empty.reason = Some(String::new());
        empty.codes = vec![String::new()];
        let report =
            BatchRepairReport::new(vec![empty, BatchRow::new("synthetic/b.jsonl", "eligible")]);
        let text = report.render_human(None);
        assert_eq!(
            text,
            "Batch repair: 0 repaired, 0 refused, 1 skipped (1 attempted)\n  \
             skipped: synthetic/a.jsonl []\n  \
             eligible: synthetic/b.jsonl"
        );
    }

    #[test]
    fn to_json_stops_before_dumps() {
        let report = BatchRepairReport::new(vec![BatchRow::new("synthetic/a.jsonl", "eligible")]);
        let err = report
            .to_json(Some(Path::new("synthetic-unused-home")))
            .expect_err("json");
        assert_eq!(err.to_string(), JSON_DUMPS_UNAVAILABLE);
        assert_eq!(err.to_string(), "json.dumps is not available");
        let as_error: &dyn Error = &err;
        assert!(as_error.source().is_none());
        let again = report.to_json(None).expect_err("json");
        assert_eq!(again, err);
    }

    #[test]
    fn output_for_names_and_relative_mirror() {
        assert_output("session.jsonl", None, &["session.repaired.jsonl"]);
        assert_output("session", None, &["session.repaired.jsonl"]);
        assert_output(".jsonl", None, &[".jsonl.repaired.jsonl"]);
        assert_output("file.", None, &["file..repaired.jsonl"]);
        assert_output("foo.bar.jsonl", None, &["foo.bar.repaired.jsonl"]);
        assert_output("a.tar.gz", None, &["a.tar.repaired.gz"]);
        assert_output(
            "synthetic/nested/session.jsonl",
            Some("synthetic"),
            &["nested", "session.repaired.jsonl"],
        );
        assert_output(
            "synthetic/../synthetic/session.jsonl",
            Some("synthetic"),
            &["session.repaired.jsonl"],
        );
        assert_output(
            "synthetic/./nested/session.jsonl",
            Some("synthetic"),
            &["nested", "session.repaired.jsonl"],
        );
        assert_output("a/file.jsonl", Some("b"), &["file.repaired.jsonl"]);
        assert_output("Dir/File.JSONL", Some("dir"), &["File.repaired.JSONL"]);
        assert_output("file", Some("synthetic"), &["file.repaired.jsonl"]);
    }

    #[cfg(windows)]
    #[test]
    fn output_for_windows_casefold_root() {
        assert_output(
            "Synthetic/Nested/Session.jsonl",
            Some("synthetic"),
            &["Nested", "Session.repaired.jsonl"],
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn output_for_unix_case_sensitive_root_falls_back() {
        assert_output(
            "Synthetic/Nested/Session.jsonl",
            Some("synthetic"),
            &["Session.repaired.jsonl"],
        );
    }

    #[test]
    fn python_repr_escapes_backslash_and_quote() {
        assert_eq!(python_repr("a\\b"), "'a\\\\b'");
        assert_eq!(python_repr("it's"), "\"it's\"");
    }

    #[test]
    fn plan_detail_does_not_read_or_return_a_plan() {
        let missing = Path::new("synthetic-batch-missing-source.jsonl");
        assert!(!missing.exists());
        let detail = _plan_detail(missing, Some("auto"), "conservative", "neutral", false)
            .expect_err("plan");
        assert_eq!(detail, FormatCanonicalUnavailable);
        assert_eq!(detail.to_string(), FORMAT_CANONICAL_UNAVAILABLE);
        assert_eq!(
            detail.to_string(),
            "sesslint.adapters.detect.FORMAT_CANONICAL is not available"
        );
        let computed = _compute_plan(missing, None, "salvage", "neutral", true).expect_err("plan");
        assert_eq!(computed.to_string(), FORMAT_CANONICAL_UNAVAILABLE);
        assert!(!missing.exists());
        let as_error: &dyn Error = &detail;
        assert!(as_error.source().is_none());
    }

    #[test]
    fn missing_report_is_python_file_not_found() {
        let path = Path::new("synthetic-batch-missing-report.json");
        let err = resolve_scan_report_files(path, Some(Path::new("synthetic-unused-home")))
            .expect_err("missing");
        assert_eq!(
            err.to_string(),
            "[Errno 2] No such file or directory: 'synthetic-batch-missing-report.json'"
        );
        let nested = Path::new("synthetic-batch-missing").join("report.json");
        let nested_err = resolve_scan_report_files(&nested, None).expect_err("missing nested");
        let expected = if cfg!(windows) {
            "[Errno 2] No such file or directory: 'synthetic-batch-missing\\\\report.json'"
        } else {
            "[Errno 2] No such file or directory: 'synthetic-batch-missing/report.json'"
        };
        assert_eq!(nested_err.to_string(), expected);
    }

    #[test]
    fn directory_report_is_python_io_error() {
        let scratch = scratch_dir("synthetic-batch-dir");
        let err = resolve_scan_report_files(&scratch.path, None).expect_err("directory");
        let expected = if cfg!(windows) {
            "[Errno 13] Permission denied: 'synthetic-batch-dir'"
        } else {
            "[Errno 21] Is a directory: 'synthetic-batch-dir'"
        };
        assert_eq!(err.to_string(), expected);
        assert!(matches!(err, ResolveScanReportError::Read(_)));
    }

    #[test]
    fn successful_read_stops_at_json_loads() {
        let scratch = scratch_dir("synthetic-batch-report");
        let path = scratch.child("report.json");
        fs::write(&path, b"not json").expect("write synthetic");
        let err = resolve_scan_report_files(&path, Some(Path::new("synthetic-unused-home")))
            .expect_err("loads");
        assert_eq!(err.to_string(), JSON_LOADS_UNAVAILABLE);
        assert_eq!(err.to_string(), "json.loads is not available");
        assert!(matches!(err, ResolveScanReportError::Loads));
        fs::write(&path, b"").expect("write empty");
        let empty = resolve_scan_report_files(&path, None).expect_err("loads");
        assert_eq!(empty.to_string(), JSON_LOADS_UNAVAILABLE);
        fs::write(&path, b"\xef\xbb\xbf{}").expect("write bom");
        let bom = resolve_scan_report_files(path, None).expect_err("loads");
        assert_eq!(bom.to_string(), JSON_LOADS_UNAVAILABLE);
    }

    #[test]
    fn invalid_utf8_is_python_unicode_decode_error() {
        let samples: &[(&[u8], &str)] = &[
            (
                &[0xff],
                "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
            ),
            (
                &[0x80],
                "'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte",
            ),
            (
                &[0xc3],
                "'utf-8' codec can't decode byte 0xc3 in position 0: unexpected end of data",
            ),
            (
                &[0xc3, 0x20],
                "'utf-8' codec can't decode byte 0xc3 in position 0: invalid continuation byte",
            ),
            (
                &[0xe2, 0x82],
                "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data",
            ),
            (
                &[0xed, 0xa0, 0x80],
                "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
            ),
            (
                &[0xf0, 0x80, 0x80, 0x80],
                "'utf-8' codec can't decode byte 0xf0 in position 0: invalid continuation byte",
            ),
            (
                b"ab\xff",
                "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte",
            ),
        ];
        for (bytes, expected) in samples {
            assert_eq!(utf8_message(bytes), *expected);
        }
        let scratch = scratch_dir("synthetic-batch-bad-utf8");
        let path = scratch.child("bad.bin");
        fs::write(&path, [0xff]).expect("write synthetic");
        let err = resolve_scan_report_files(&path, None).expect_err("utf8");
        assert_eq!(
            err.to_string(),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        assert!(matches!(err, ResolveScanReportError::Read(_)));
    }
}
