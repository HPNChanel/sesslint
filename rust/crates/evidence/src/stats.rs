//! Content-free aggregate statistics over session files (ux-reporting T-03).
//!
//! Port of `src/sesslint/stats.py` lines 1–365
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Lines 1–231 are the counters, the bounded directory walk, and the hashed
//! tool-name fold. `to_dict`, `render_human`, and `to_json` stop on
//! `sesslint.report.minimize_path`. This crate does not link `report`, so
//! those three methods return [`MinimizePathUnavailable`] and do not build a
//! dictionary, human text, or JSON.
//!
//! Lines 234–365 append [`stats_paths`], [`get_stats_schema_path`], and
//! [`load_stats_schema`]. A missing limit stops on
//! `sesslint.scan.DEFAULT_MAX_FILES` and builds no [`SessionStats`]. When
//! both limits are provided, every root is checked before the load import.
//! After candidates are built, [`stats_paths`] stops on
//! `sesslint.adapters.load.load_events_for_format`. The schema helpers stop
//! on `sesslint._resources.schema_path`.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirEntry};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Python `STATS_SCHEMA_VERSION`.
pub const STATS_SCHEMA_VERSION: &str = "sesslint.stats/v1";

/// Python `_EXCLUDED_DIRS`. VCS internals are not session artifacts.
const EXCLUDED_DIRS: [&str; 3] = [".git", ".hg", ".svn"];

/// Python `_EXCLUDED_NAMES`. SessLint's own config is not a session file.
const EXCLUDED_FILE_NAMES: [&str; 2] = ["sesslint.toml", ".sesslint.toml"];

/// Python `MAX_TOOL_ROWS`. Top-N bound for a later tool-hash breakdown.
pub const MAX_TOOL_ROWS: usize = 100;

/// Display text when `sesslint.report.minimize_path` cannot be imported.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// `sesslint.report.minimize_path` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimizePathUnavailable;

impl fmt::Display for MinimizePathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MINIMIZE_PATH_UNAVAILABLE)
    }
}

impl Error for MinimizePathUnavailable {}

/// Display text when `sesslint.scan.DEFAULT_MAX_FILES` cannot be imported.
pub const SCAN_DEFAULT_MAX_FILES_UNAVAILABLE: &str =
    "sesslint.scan.DEFAULT_MAX_FILES is not available";

/// Display text when `sesslint.adapters.load.load_events_for_format` cannot be imported.
pub const LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE: &str =
    "sesslint.adapters.load.load_events_for_format is not available";

/// Display text when `sesslint._resources.schema_path` cannot be imported.
pub const SCHEMA_PATH_UNAVAILABLE: &str = "sesslint._resources.schema_path is not available";

/// Failure from [`stats_paths`] or the stats schema helpers.
///
/// Missing-import display text is the `module.attr is not available` sentence.
/// Path failures use the pin's `FileNotFoundError` and `ValueError` sentences,
/// without the Python exception type name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatsError {
    /// `from sesslint.scan import DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES` failed.
    ScanDefaultMaxFilesUnavailable,
    /// Python `FileNotFoundError`: `Path not found: {path}`.
    PathNotFound(String),
    /// Python `ValueError` when `Path.is_dir()` is true and `recursive` is false.
    ///
    /// `is_dir` follows a symlink, so a link to a directory uses this error too.
    DirectoryRequiresRecursive(String),
    /// `sesslint.adapters.load.load_events_for_format` failed to import.
    LoadEventsForFormatUnavailable,
    /// `sesslint._resources.schema_path` failed to import.
    SchemaPathUnavailable,
    /// `symlink_metadata` failed for a reason other than a missing path.
    Io(String),
}

impl fmt::Display for StatsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScanDefaultMaxFilesUnavailable => {
                formatter.write_str(SCAN_DEFAULT_MAX_FILES_UNAVAILABLE)
            }
            Self::PathNotFound(path) => write!(formatter, "Path not found: {path}"),
            Self::DirectoryRequiresRecursive(path) => {
                write!(
                    formatter,
                    "Path {path} is a directory. Use recursive=True to scan."
                )
            }
            Self::LoadEventsForFormatUnavailable => {
                formatter.write_str(LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE)
            }
            Self::SchemaPathUnavailable => formatter.write_str(SCHEMA_PATH_UNAVAILABLE),
            Self::Io(text) => formatter.write_str(text),
        }
    }
}

impl Error for StatsError {}

/// One payload value for [`StatsEvent`].
///
/// Truthiness matches Python: `None`, `""`, and `False` are falsy. [`Self::Other`]
/// carries `bool(value)` for every remaining non-string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadValue {
    /// Python `None`.
    None,
    /// Python `bool`.
    Bool(bool),
    /// Python `str`.
    Str(String),
    /// Non-string value other than `None` or `bool`.
    Other {
        /// Python `bool(value)`.
        truthy: bool,
    },
}

/// Local stand-in for the event fields `_count_events` reads.
///
/// `kind`, `actor`, and a string-keyed payload. Canonical events are not imported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatsEvent {
    pub kind: String,
    pub actor: String,
    pub payload: BTreeMap<String, PayloadValue>,
}

/// Mutable counters `_count_events` updates in place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsCounters {
    pub events_total: i64,
    pub by_kind: BTreeMap<String, i64>,
    pub by_actor: BTreeMap<String, i64>,
    pub tool_calls_total: i64,
    pub by_tool_hash: BTreeMap<String, i64>,
    pub compaction_boundaries: i64,
    pub checkpoints: i64,
}

/// Fixed percentile summary from [`_dist`].
///
/// Keys are `max`, `p50` at 0.50, `p95` at 0.95, and `total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dist {
    pub max: i64,
    pub p50: i64,
    pub p95: i64,
    pub total: i64,
}

/// Python `SessionStats` fields. `files_total` is computed, not stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStats {
    pub root_path: String,
    pub tool_version: String,
    pub files_processed: i64,
    pub files_undetected: i64,
    pub files_unreadable: i64,
    pub by_adapter: BTreeMap<String, i64>,
    pub events_total: i64,
    pub by_kind: BTreeMap<String, i64>,
    pub by_actor: BTreeMap<String, i64>,
    pub tool_calls_total: i64,
    pub by_tool_hash: BTreeMap<String, i64>,
    pub compaction_boundaries: i64,
    pub checkpoints: i64,
    pub file_bytes: BTreeMap<String, i64>,
    pub events_per_file: BTreeMap<String, i64>,
}

impl SessionStats {
    /// Python `files_total`. Sum of the three file counters.
    ///
    /// Does not call `minimize_path`.
    pub fn files_total(&self) -> i64 {
        self.files_processed + self.files_undetected + self.files_unreadable
    }

    /// Python `SessionStats.to_dict`.
    ///
    /// The body imports `sesslint.report.minimize_path` before any other work.
    /// That import is unavailable. No dictionary is built.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn to_dict(&self, _home: Option<&Path>) -> Result<Infallible, MinimizePathUnavailable> {
        Err(MinimizePathUnavailable)
    }

    /// Python `SessionStats.to_json`.
    ///
    /// Stops on the same `minimize_path` import as [`Self::to_dict`], before
    /// `json.dumps`. No JSON is built.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn to_json(&self, _home: Option<&Path>) -> Result<Infallible, MinimizePathUnavailable> {
        Err(MinimizePathUnavailable)
    }

    /// Python `SessionStats.render_human`.
    ///
    /// Imports `sesslint.report.minimize_path` before any other work. No human
    /// text is built.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn render_human(
        &self,
        _home: Option<&Path>,
    ) -> Result<Infallible, MinimizePathUnavailable> {
        Err(MinimizePathUnavailable)
    }
}

/// Python `_percentile`.
///
/// `sorted_vals` is already ordered. This does not sort it. An empty slice
/// returns 0. Otherwise the index is CPython `int(q * len)` (truncation toward
/// zero), then clamped to the last index. A negative index uses Python wrap.
pub fn _percentile(sorted_vals: &[i64], q: f64) -> i64 {
    if sorted_vals.is_empty() {
        return 0;
    }
    let len = sorted_vals.len();
    let len_i = i64::try_from(len).map_or(i64::MAX, |len| len);
    let mut idx = cpython_int(q, len);
    if idx >= len_i {
        idx = len_i - 1;
    }
    if idx < 0 {
        idx = idx.saturating_add(len_i);
        if idx < 0 {
            return 0;
        }
    }
    match usize::try_from(idx) {
        Ok(position) if position < len => sorted_vals[position],
        _ => 0,
    }
}

/// Python `_dist`.
///
/// Sorts a copy. Does not mutate `values`. Empty input is all zeros.
pub fn _dist(values: &[i64]) -> Dist {
    let mut sorted_vals = values.to_vec();
    sorted_vals.sort_unstable();
    let max = match sorted_vals.last() {
        Some(max) => *max,
        None => 0,
    };
    Dist {
        max,
        p50: _percentile(&sorted_vals, 0.50),
        p95: _percentile(&sorted_vals, 0.95),
        total: sorted_vals.iter().sum(),
    }
}

/// Python `_tool_hash`.
///
/// Lowercase sha256 hex of the UTF-8 name, first 16 characters. Never the raw name.
pub fn _tool_hash(name: &str) -> String {
    let digest = Sha256::digest(name.as_bytes());
    hex_prefix(digest.as_slice(), 16)
}

/// Python `_iter_files`.
///
/// Returns `(files, skipped)`. `skipped` is always empty; excluded names and
/// unfollowed symlinks are omitted, not collected.
///
/// A root that is a symlink, missing, or not a directory is appended as itself.
/// That append is not gated by `max_files` (the file-root hole). A real
/// directory is walked with a LIFO stack. `read_dir` entries are sorted by
/// name only, so the next pop is the last sorted sibling directory. The walk
/// returns immediately once `files.len() >= max_files`.
pub fn _iter_files(roots: &[PathBuf], max_files: i64) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut files = Vec::new();
    for root in roots {
        if is_unwalked_root(root) {
            files.push(root.clone());
            continue;
        }
        let mut stack = vec![root.clone()];
        while let Some(current) = stack.pop() {
            let Some(entries) = list_sorted(&current) else {
                continue;
            };
            for listed in entries {
                if reached_max_files(files.len(), max_files) {
                    return (files, Vec::new());
                }
                let file_type = match listed.entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                // `follow_symlinks=False`: a link is neither a directory nor a file.
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    if !name_in(&listed.name, &EXCLUDED_DIRS) {
                        stack.push(listed.entry.path());
                    }
                } else if file_type.is_file() && !name_in(&listed.name, &EXCLUDED_FILE_NAMES) {
                    files.push(listed.entry.path());
                }
            }
        }
    }
    (files, Vec::new())
}

/// Python `_count_events`.
///
/// Pure over `events`: no canonical import, no filesystem. Increments
/// `events_total` by `events.len()`, then counts every kind and actor. A
/// `tool_call` increments `tool_calls_total` before the name is resolved.
/// The name is payload `tool_name`, else `name`, else empty, using Python
/// truthiness. Only a non-empty string is hashed. Counters are mutated in place.
pub fn _count_events(events: &[StatsEvent], counters: &mut StatsCounters) {
    counters.events_total += i64::try_from(events.len()).map_or(i64::MAX, |len| len);
    for event in events {
        bump(&mut counters.by_kind, &event.kind);
        bump(&mut counters.by_actor, &event.actor);
        if event.kind == "tool_call" {
            counters.tool_calls_total += 1;
            if let Some(name) = tool_name_to_hash(&event.payload) {
                let hash = _tool_hash(name);
                bump(&mut counters.by_tool_hash, &hash);
            }
        } else if event.kind == "compaction_boundary" {
            counters.compaction_boundaries += 1;
        } else if event.kind == "checkpoint" {
            counters.checkpoints += 1;
        }
    }
}

fn cpython_int(q: f64, len: usize) -> i64 {
    let product = q * (len as f64);
    if product.is_nan() {
        return 0;
    }
    if !product.is_finite() {
        return if product.is_sign_positive() {
            i64::MAX
        } else {
            i64::MIN
        };
    }
    product.trunc() as i64
}

fn hex_prefix(bytes: &[u8], hex_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(hex_len);
    for &byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if out.len() == hex_len {
                return out;
            }
            out.push(char::from(HEX[usize::from(nibble)]));
        }
    }
    out
}

fn is_unwalked_root(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let kind = meta.file_type();
            kind.is_symlink() || !kind.is_dir()
        }
        Err(_) => true,
    }
}

struct ListedEntry {
    name: OsString,
    entry: DirEntry,
}

fn list_sorted(current: &Path) -> Option<Vec<ListedEntry>> {
    let read = match fs::read_dir(current) {
        Ok(read) => read,
        Err(_) => return None,
    };
    let mut listed = Vec::new();
    for item in read {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => return None,
        };
        let name = entry.file_name();
        listed.push(ListedEntry { name, entry });
    }
    listed.sort_by(|left, right| left.name.cmp(&right.name));
    Some(listed)
}

fn name_in(name: &OsStr, names: &[&str]) -> bool {
    match name.to_str() {
        Some(name) => names.contains(&name),
        None => false,
    }
}

fn reached_max_files(found: usize, max_files: i64) -> bool {
    match i64::try_from(found) {
        Ok(found) => found >= max_files,
        Err(_) => true,
    }
}

fn python_truthy(value: Option<&PayloadValue>) -> bool {
    match value {
        None | Some(PayloadValue::None) => false,
        Some(PayloadValue::Bool(flag)) => *flag,
        Some(PayloadValue::Str(text)) => !text.is_empty(),
        Some(PayloadValue::Other { truthy }) => *truthy,
    }
}

fn first_truthy<'a>(
    payload: &'a BTreeMap<String, PayloadValue>,
    key: &str,
) -> Option<&'a PayloadValue> {
    let value = payload.get(key);
    if python_truthy(value) {
        value
    } else {
        None
    }
}

fn tool_name_to_hash(payload: &BTreeMap<String, PayloadValue>) -> Option<&str> {
    let selected = first_truthy(payload, "tool_name").or_else(|| first_truthy(payload, "name"));
    match selected {
        Some(PayloadValue::Str(name)) if !name.is_empty() => Some(name.as_str()),
        _ => None,
    }
}

fn bump(counts: &mut BTreeMap<String, i64>, key: &str) {
    let count = counts.entry(key.to_owned()).or_insert(0);
    *count += 1;
}

/// Python `stats_paths`.
///
/// `recursive` is Python's default `False` when the caller omitted it.
/// `format` is accepted and not read on this slice. Either missing limit is
/// the `sesslint.scan` import. This crate cannot call `DEFAULT_MAX_FILES` or
/// `DEFAULT_MAX_BYTES`, so that import returns
/// [`StatsError::ScanDefaultMaxFilesUnavailable`] and no [`SessionStats`].
///
/// When both limits are provided, every root is checked before the load
/// import. A path that does not exist and is not a symlink is
/// `FileNotFoundError`. `Path.is_dir` follows symlinks: a real directory, or a
/// symlink to a directory, is `ValueError` unless `recursive` is true. After
/// that check, a symlink is an explicit entry. Only a real directory is walked.
///
/// Explicit entries stay in front of the walked tail. [`_iter_files`] walks
/// only non-symlink directories and receives `max_files`. The slice applies
/// to walked paths that are not already explicit, so explicit files stay.
///
/// After that list is built, the pin imports
/// `sesslint.adapters.load.load_events_for_format` and
/// `sesslint.io.probe_text_encoding`. Neither is linked. No events are
/// counted, `cwd` is not called, and `tool_version` is not filled.
///
/// # Errors
///
/// [`StatsError::ScanDefaultMaxFilesUnavailable`], [`StatsError::PathNotFound`],
/// [`StatsError::DirectoryRequiresRecursive`], [`StatsError::Io`], or
/// [`StatsError::LoadEventsForFormatUnavailable`].
pub fn stats_paths<P: AsRef<Path>>(
    paths: &[P],
    recursive: bool,
    format: Option<&str>,
    max_files: Option<i64>,
    max_bytes: Option<i64>,
) -> Result<SessionStats, StatsError> {
    let (Some(max_files), Some(_max_bytes)) = (max_files, max_bytes) else {
        return Err(StatsError::ScanDefaultMaxFilesUnavailable);
    };

    let mut explicit = Vec::new();
    let mut dirs = Vec::new();
    for path in paths {
        let path = path.as_ref();
        match classify_root(path, recursive)? {
            RootKind::Directory => dirs.push(path.to_path_buf()),
            RootKind::Explicit => explicit.push(path.to_path_buf()),
        }
    }

    let candidates = candidate_paths(explicit, &dirs, max_files);
    let _ = (candidates, format);
    Err(StatsError::LoadEventsForFormatUnavailable)
}

/// Python `get_stats_schema_path`.
///
/// The first statement imports `sesslint._resources.schema_path`. That
/// function is not linked. This does not build a `schemas/` path and does
/// not read a schema file.
///
/// # Errors
///
/// Always [`StatsError::SchemaPathUnavailable`].
pub fn get_stats_schema_path() -> Result<PathBuf, StatsError> {
    Err(StatsError::SchemaPathUnavailable)
}

/// Python `load_stats_schema`.
///
/// Calls [`get_stats_schema_path`] before any file check. The resource import
/// fails there, so this returns that same error. This does not read a schema
/// file and does not parse JSON.
///
/// # Errors
///
/// Always [`StatsError::SchemaPathUnavailable`]. Success is [`Infallible`].
pub fn load_stats_schema() -> Result<Infallible, StatsError> {
    let _schema_path = get_stats_schema_path()?;
    Err(StatsError::SchemaPathUnavailable)
}

enum RootKind {
    Explicit,
    Directory,
}

fn classify_root(path: &Path, recursive: bool) -> Result<RootKind, StatsError> {
    let unfollowed = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if is_missing_path(&error) => {
            return Err(StatsError::PathNotFound(path_text(path)));
        }
        Err(error) => return Err(StatsError::Io(error.to_string())),
    };
    let symlink = unfollowed.file_type().is_symlink();
    // `Path.is_dir` follows links. A broken symlink is not a directory.
    let followed_dir = if symlink {
        fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
    } else {
        unfollowed.is_dir()
    };
    if followed_dir && !recursive {
        return Err(StatsError::DirectoryRequiresRecursive(path_text(path)));
    }
    if followed_dir && !symlink {
        Ok(RootKind::Directory)
    } else {
        Ok(RootKind::Explicit)
    }
}

fn is_missing_path(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn candidate_paths(explicit: Vec<PathBuf>, dirs: &[PathBuf], max_files: i64) -> Vec<PathBuf> {
    let (walked, _skipped) = _iter_files(dirs, max_files);
    let mut tail = Vec::new();
    for walked_path in walked {
        if !explicit.contains(&walked_path) {
            tail.push(walked_path);
        }
    }
    let mut candidates = explicit;
    candidates.extend(prefix_slice(tail, max_files));
    candidates
}

fn prefix_slice(mut items: Vec<PathBuf>, max_files: i64) -> Vec<PathBuf> {
    if max_files < 0 {
        let Ok(drop_count) = usize::try_from(max_files.unsigned_abs()) else {
            return Vec::new();
        };
        if drop_count >= items.len() {
            return Vec::new();
        }
        items.truncate(items.len() - drop_count);
        return items;
    }
    let Ok(limit) = usize::try_from(max_files) else {
        return items;
    };
    if limit < items.len() {
        items.truncate(limit);
    }
    items
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};

    use super::{
        candidate_paths, get_stats_schema_path, load_stats_schema, path_text, stats_paths, Dist,
        MinimizePathUnavailable, PayloadValue, SessionStats, StatsCounters, StatsError, StatsEvent,
        _count_events, _dist, _iter_files, _percentile, _tool_hash,
        LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE, MAX_TOOL_ROWS, MINIMIZE_PATH_UNAVAILABLE,
        SCAN_DEFAULT_MAX_FILES_UNAVAILABLE, SCHEMA_PATH_UNAVAILABLE, STATS_SCHEMA_VERSION,
    };

    #[test]
    fn constants_match_the_pinned_slice() {
        assert_eq!(STATS_SCHEMA_VERSION, "sesslint.stats/v1");
        assert_eq!(MAX_TOOL_ROWS, 100);
        assert_eq!(
            MINIMIZE_PATH_UNAVAILABLE,
            "sesslint.report.minimize_path is not available"
        );
    }

    #[test]
    fn percentile_empty_and_ranked() {
        assert_eq!(_percentile(&[], 0.50), 0);
        assert_eq!(_percentile(&[], 0.95), 0);

        let sorted = [10, 20, 30, 40, 50];
        assert_eq!(_percentile(&sorted, 0.50), 30);
        assert_eq!(_percentile(&sorted, 0.95), 50);
        assert_eq!(_percentile(&sorted, 1.0), 50);
        assert_eq!(_percentile(&[9, 1, 8], 0.0), 9);
    }

    #[test]
    fn dist_sorts_a_copy() {
        assert_eq!(
            _dist(&[]),
            Dist {
                max: 0,
                p50: 0,
                p95: 0,
                total: 0,
            }
        );

        let values = vec![4, 1, 3, 2];
        assert_eq!(
            _dist(&values),
            Dist {
                max: 4,
                p50: 3,
                p95: 4,
                total: 10,
            }
        );
        assert_eq!(values, vec![4, 1, 3, 2]);
    }

    #[test]
    fn tool_hash_is_sha256_prefix() {
        let name = "tool";
        let digest = Sha256::digest(name.as_bytes());
        let hex = format!("{digest:x}");
        let hashed = _tool_hash(name);
        assert_eq!(hashed, hex[..16]);
        assert_eq!(hashed.len(), 16);
        assert_ne!(hashed, name);
        assert!(hashed
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn files_total_sums_the_three_file_counters() {
        let stats = sample_stats();
        assert_eq!(stats.files_processed, 2);
        assert_eq!(stats.files_undetected, 3);
        assert_eq!(stats.files_unreadable, 4);
        assert_eq!(stats.files_total(), 9);
    }

    #[test]
    fn report_output_stops_at_minimize_path() {
        let stats = sample_stats();
        assert_minimize(stats.to_dict(None));
        assert_minimize(stats.render_human(None));
        assert_minimize(stats.to_json(None));
    }

    #[test]
    fn file_root_max_files_hole() {
        let tree = TempTree::new("hole");
        let file = tree.path.join("root.jsonl");
        fs::write(&file, []).unwrap();
        let missing = tree.path.join("absent.jsonl");
        let (files, skipped) = _iter_files(&[file.clone(), missing.clone()], 0);
        assert!(skipped.is_empty());
        assert_eq!(files, vec![file, missing]);

        let left = TempTree::new("hole-left");
        fs::write(left.path.join("a.txt"), []).unwrap();
        fs::write(left.path.join("b.txt"), []).unwrap();
        let (files, skipped) = _iter_files(std::slice::from_ref(&left.path), 0);
        assert!(skipped.is_empty());
        assert!(files.is_empty());

        let right = TempTree::new("hole-right");
        fs::write(right.path.join("c.txt"), []).unwrap();
        let (files, skipped) = _iter_files(&[left.path.clone(), right.path.clone()], 1);
        assert!(skipped.is_empty());
        assert_eq!(files, vec![left.path.join("a.txt")]);
    }

    #[test]
    fn walk_skips_excluded_directories() {
        let tree = TempTree::new("excl");
        fs::create_dir(tree.path.join(".git")).unwrap();
        fs::write(tree.path.join(".git").join("hidden.txt"), []).unwrap();
        fs::create_dir(tree.path.join(".hg")).unwrap();
        fs::write(tree.path.join(".hg").join("hidden.txt"), []).unwrap();
        fs::create_dir(tree.path.join(".svn")).unwrap();
        fs::write(tree.path.join(".svn").join("hidden.txt"), []).unwrap();
        fs::write(tree.path.join(".sesslint.toml"), []).unwrap();
        fs::write(tree.path.join("sesslint.toml"), []).unwrap();
        fs::write(tree.path.join("a.txt"), []).unwrap();
        fs::write(tree.path.join("z.txt"), []).unwrap();
        fs::create_dir(tree.path.join("d1")).unwrap();
        fs::write(tree.path.join("d1").join("z.txt"), []).unwrap();
        fs::create_dir(tree.path.join("d2")).unwrap();
        fs::write(tree.path.join("d2").join("z.txt"), []).unwrap();

        let (files, skipped) = _iter_files(std::slice::from_ref(&tree.path), 100);
        assert!(skipped.is_empty());
        assert_eq!(
            files,
            vec![
                tree.path.join("a.txt"),
                tree.path.join("z.txt"),
                tree.path.join("d2").join("z.txt"),
                tree.path.join("d1").join("z.txt"),
            ]
        );
    }

    #[test]
    fn count_events_folds_tool_call_and_non_string_name() {
        let mut counters = StatsCounters::default();
        let events = vec![
            tool_event(payload(&[(
                "tool_name",
                PayloadValue::Str("tool".to_owned()),
            )])),
            StatsEvent {
                kind: "compaction_boundary".to_owned(),
                actor: "system".to_owned(),
                payload: BTreeMap::new(),
            },
            StatsEvent {
                kind: "checkpoint".to_owned(),
                actor: "user".to_owned(),
                payload: BTreeMap::new(),
            },
        ];
        _count_events(&events, &mut counters);
        assert_eq!(counters.events_total, 3);
        assert_eq!(counters.by_kind.values().sum::<i64>(), 3);
        assert_eq!(counters.tool_calls_total, 1);
        assert_eq!(counters.compaction_boundaries, 1);
        assert_eq!(counters.checkpoints, 1);
        assert_eq!(counters.by_kind.get("tool_call"), Some(&1));
        assert_eq!(counters.by_kind.get("compaction_boundary"), Some(&1));
        assert_eq!(counters.by_kind.get("checkpoint"), Some(&1));
        assert_eq!(counters.by_actor.get("assistant"), Some(&1));
        assert_eq!(counters.by_actor.get("system"), Some(&1));
        assert_eq!(counters.by_actor.get("user"), Some(&1));
        assert_eq!(counters.by_tool_hash.get(&_tool_hash("tool")), Some(&1));
        assert!(!counters.by_tool_hash.contains_key("tool"));

        _count_events(&events, &mut counters);
        assert_eq!(counters.events_total, 6);
        assert_eq!(counters.tool_calls_total, 2);

        let mut non_string = StatsCounters::default();
        let event = tool_event(payload(&[
            ("tool_name", PayloadValue::Other { truthy: true }),
            ("name", PayloadValue::Str("alt".to_owned())),
        ]));
        _count_events(std::slice::from_ref(&event), &mut non_string);
        assert_eq!(non_string.events_total, 1);
        assert_eq!(non_string.tool_calls_total, 1);
        assert_eq!(non_string.by_kind.get("tool_call"), Some(&1));
        assert!(non_string.by_tool_hash.is_empty());

        for falsy in [
            PayloadValue::None,
            PayloadValue::Str(String::new()),
            PayloadValue::Bool(false),
        ] {
            let mut fallen = StatsCounters::default();
            let event = tool_event(payload(&[
                ("tool_name", falsy),
                ("name", PayloadValue::Str("alt".to_owned())),
            ]));
            _count_events(std::slice::from_ref(&event), &mut fallen);
            assert_eq!(fallen.tool_calls_total, 1);
            assert_eq!(fallen.by_tool_hash.get(&_tool_hash("alt")), Some(&1));
            assert!(!fallen.by_tool_hash.contains_key("alt"));
        }
    }

    fn assert_minimize(result: Result<Infallible, MinimizePathUnavailable>) {
        let error = match result {
            Ok(never) => match never {},
            Err(error) => error,
        };
        let displayed = error.to_string();
        assert_eq!(displayed, "sesslint.report.minimize_path is not available");
        let as_error: &dyn Error = &error;
        assert_eq!(as_error.to_string(), displayed);
    }

    fn sample_stats() -> SessionStats {
        SessionStats {
            root_path: "corpus".to_owned(),
            tool_version: "0.0.0".to_owned(),
            files_processed: 2,
            files_undetected: 3,
            files_unreadable: 4,
            by_adapter: BTreeMap::new(),
            events_total: 0,
            by_kind: BTreeMap::new(),
            by_actor: BTreeMap::new(),
            tool_calls_total: 0,
            by_tool_hash: BTreeMap::new(),
            compaction_boundaries: 0,
            checkpoints: 0,
            file_bytes: BTreeMap::new(),
            events_per_file: BTreeMap::new(),
        }
    }

    fn payload(pairs: &[(&str, PayloadValue)]) -> BTreeMap<String, PayloadValue> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    fn tool_event(payload: BTreeMap<String, PayloadValue>) -> StatsEvent {
        StatsEvent {
            kind: "tool_call".to_owned(),
            actor: "assistant".to_owned(),
            payload,
        }
    }

    struct TempTree {
        path: PathBuf,
    }

    fn symlink_dir(original: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(original, link)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link)
        }
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sesslint-stats-{name}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn assert_no_session_stats(result: Result<SessionStats, StatsError>, display: &str) {
        match result {
            Ok(_stats) => panic!("stats_paths yielded SessionStats"),
            Err(error) => {
                assert_eq!(error.to_string(), display);
                let as_error: &dyn Error = &error;
                assert_eq!(as_error.to_string(), display);
                assert!(as_error.source().is_none());
            }
        }
    }

    #[test]
    fn missing_limit_stops_at_the_scan_constant() {
        let tree = TempTree::new("rx-limit");
        let cases: [(Option<i64>, Option<i64>); 3] =
            [(None, Some(8)), (Some(8), None), (None, None)];
        for (max_files, max_bytes) in cases {
            let error = stats_paths(
                std::slice::from_ref(&tree.path),
                false,
                None,
                max_files,
                max_bytes,
            )
            .unwrap_err();
            assert_eq!(error, StatsError::ScanDefaultMaxFilesUnavailable);
            assert_eq!(error.to_string(), SCAN_DEFAULT_MAX_FILES_UNAVAILABLE);
            assert_eq!(
                error.to_string(),
                "sesslint.scan.DEFAULT_MAX_FILES is not available"
            );
            assert!(!matches!(
                error,
                StatsError::DirectoryRequiresRecursive(_) | StatsError::PathNotFound(_)
            ));
            assert_ne!(error, StatsError::LoadEventsForFormatUnavailable);
            let as_error: &dyn Error = &error;
            assert_eq!(as_error.to_string(), SCAN_DEFAULT_MAX_FILES_UNAVAILABLE);
            assert!(as_error.source().is_none());
        }
    }

    #[test]
    fn missing_path_and_directory_raise_before_load() {
        let tree = TempTree::new("rx-roots");
        let missing = tree.path.join("synthetic-absent-session.jsonl");
        let missing_error = stats_paths(
            std::slice::from_ref(&missing),
            false,
            None,
            Some(4),
            Some(32),
        )
        .unwrap_err();
        let missing_text = path_text(&missing);
        assert_eq!(
            missing_error,
            StatsError::PathNotFound(missing_text.clone())
        );
        assert_eq!(
            missing_error.to_string(),
            format!("Path not found: {missing_text}")
        );
        assert_ne!(missing_error, StatsError::LoadEventsForFormatUnavailable);
        assert_ne!(
            missing_error.to_string(),
            LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE
        );

        let directory = tree.path.join("synthetic-dir");
        fs::create_dir(&directory).unwrap();
        let directory_error = stats_paths(
            std::slice::from_ref(&directory),
            false,
            Some("synthetic"),
            Some(4),
            Some(32),
        )
        .unwrap_err();
        let directory_text = path_text(&directory);
        assert_eq!(
            directory_error,
            StatsError::DirectoryRequiresRecursive(directory_text.clone())
        );
        assert_eq!(
            directory_error.to_string(),
            format!("Path {directory_text} is a directory. Use recursive=True to scan.")
        );
        assert_ne!(directory_error, StatsError::LoadEventsForFormatUnavailable);
        assert!(!directory_error
            .to_string()
            .contains("load_events_for_format"));

        let link = tree.path.join("synthetic-link-dir");
        let created = symlink_dir(&directory, &link);
        if created.is_ok() {
            let link_error =
                stats_paths(std::slice::from_ref(&link), false, None, Some(4), Some(32))
                    .unwrap_err();
            let link_text = path_text(&link);
            assert_eq!(
                link_error,
                StatsError::DirectoryRequiresRecursive(link_text.clone())
            );
            assert_eq!(
                link_error.to_string(),
                format!("Path {link_text} is a directory. Use recursive=True to scan.")
            );
            assert_no_session_stats(
                stats_paths(std::slice::from_ref(&link), true, None, Some(4), Some(32)),
                LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE,
            );
        }
    }

    #[test]
    fn real_file_stops_at_load_events_for_format() {
        let tree = TempTree::new("rx-file");
        let file = tree.path.join("synthetic-session.jsonl");
        fs::write(&file, b"synthetic\n").unwrap();
        assert_no_session_stats(
            stats_paths(&[file], false, Some("synthetic"), Some(4), Some(32)),
            "sesslint.adapters.load.load_events_for_format is not available",
        );

        assert_no_session_stats(
            stats_paths(
                std::slice::from_ref(&tree.path),
                true,
                None,
                Some(4),
                Some(32),
            ),
            LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE,
        );

        assert_no_session_stats(
            stats_paths(&[] as &[PathBuf], false, None, Some(1), Some(1)),
            LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE,
        );
    }

    #[test]
    fn explicit_files_are_not_dropped_by_the_max_files_slice() {
        let tree = TempTree::new("rx-cand");
        let first = tree.path.join("explicit-a.jsonl");
        let second = tree.path.join("explicit-b.jsonl");
        fs::write(&first, b"synthetic\n").unwrap();
        fs::write(&second, b"synthetic\n").unwrap();
        let dir = tree.path.join("synthetic-dir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("m.jsonl"), b"synthetic\n").unwrap();
        fs::write(dir.join("z.jsonl"), b"synthetic\n").unwrap();

        let kept = candidate_paths(
            vec![first.clone(), second.clone()],
            std::slice::from_ref(&dir),
            0,
        );
        assert_eq!(kept, vec![first.clone(), second.clone()]);

        let capped = candidate_paths(
            vec![first.clone(), second.clone()],
            std::slice::from_ref(&dir),
            1,
        );
        assert_eq!(capped, vec![first, second, dir.join("m.jsonl")]);
    }

    #[test]
    fn schema_functions_stop_at_schema_path() {
        let path_error = get_stats_schema_path().unwrap_err();
        assert_eq!(path_error, StatsError::SchemaPathUnavailable);
        assert_eq!(path_error.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert_eq!(
            path_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(!path_error.to_string().contains("schemas"));
        assert!(!path_error.to_string().contains(".json"));
        let as_error: &dyn Error = &path_error;
        assert!(as_error.source().is_none());

        let load_error = match load_stats_schema() {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(load_error, path_error);
        assert_eq!(
            load_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(std::error::Error::source(&load_error).is_none());
    }
}
