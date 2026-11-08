//! Content-free aggregate statistics over session files (ux-reporting T-03).
//!
//! Port of `src/sesslint/stats.py` lines 1–231
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! This slice is the counters, the bounded directory walk, and the hashed
//! tool-name fold. `stats_paths` is a later card. `to_dict`, `render_human`,
//! and `to_json` stop on `sesslint.report.minimize_path`. This crate does not
//! link `report`, so those three methods return [`MinimizePathUnavailable`]
//! and do not build a dictionary, human text, or JSON.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirEntry};
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};

    use super::{
        Dist, MinimizePathUnavailable, PayloadValue, SessionStats, StatsCounters, StatsEvent,
        _count_events, _dist, _iter_files, _percentile, _tool_hash, MAX_TOOL_ROWS,
        MINIMIZE_PATH_UNAVAILABLE, STATS_SCHEMA_VERSION,
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
}
