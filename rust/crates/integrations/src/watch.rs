//! Poll-based session directory monitor (ux-reporting T-05).
//!
//! Port of `src/sesslint/watch.py` lines 1–277
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `82c8f7c04a9c87ea9840021f11aa3a906af758e6`.
//!
//! The monitor snapshots `(mtime_ns, size)` and walks with `read_dir`.
//! It never writes a file, never installs a hook, and never holds a file
//! open: each directory iterator is dropped before the next directory, and
//! `metadata` returns before a check runs.
//!
//! `sesslint.api.check_file` is not linked. [`watch`] checks the interval,
//! then returns [`WatchError::CheckFileUnavailable`] when no check callback
//! is supplied. It does not walk, sleep, or read `format` on that path.
//! Injected checks run the poll loop. [`CheckError::Cancelled`] propagates;
//! any other check failure becomes `unreadable`.
//!
//! `sesslint.report.minimize_path` is not linked. [`WatchTransition::to_dict`]
//! and [`format_transition`] return [`WatchError::MinimizePathUnavailable`]
//! at that import, before a line or object is built.
//!
//! `sesslint.progress` is not linked and is not reimplemented. Cancellation is
//! the caller-supplied `throw_if_cancelled` probe. `Err` from that probe is
//! `operation cancelled`.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

/// Python `WATCH_EVENT_SCHEMA`.
pub const WATCH_EVENT_SCHEMA: &str = "sesslint.watch-event/v1";

/// Python `DEFAULT_INTERVAL`.
pub const DEFAULT_INTERVAL: f64 = 2.0;

/// Python `MIN_INTERVAL`.
pub const MIN_INTERVAL: f64 = 0.05;

/// Python `MAX_TRACKED_FILES`.
pub const MAX_TRACKED_FILES: usize = 4096;

/// Python `_EXCLUDED_DIRS`.
pub const _EXCLUDED_DIRS: &[&str] = &[".git", ".hg", ".svn"];

/// Python `_EXCLUDED_NAMES`.
pub const _EXCLUDED_NAMES: &[&str] = &["sesslint.toml", ".sesslint.toml"];

/// Python `__all__`, in source order.
pub const ALL: &[&str] = &[
    "DEFAULT_INTERVAL",
    "MAX_TRACKED_FILES",
    "MIN_INTERVAL",
    "WATCH_EVENT_SCHEMA",
    "CheckFn",
    "WatchTransition",
    "format_transition",
    "watch",
];

/// `sesslint.api.check_file` is not ported.
pub const CHECK_FILE_UNAVAILABLE: &str = "sesslint.api.check_file is not available";

/// `sesslint.report.minimize_path` is not ported.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// Python `OperationCancelled("operation cancelled")`.
const CANCELLED_MESSAGE: &str = "operation cancelled";

/// Python `time.sleep(nan)`.
const SLEEP_NAN: &str = "Invalid value NaN (not a number)";

/// Python `time.sleep` on a negative finite duration.
const SLEEP_NEGATIVE: &str = "sleep length must be non-negative";

/// Python `time.sleep` when the duration does not fit `_PyTime_t`.
const SLEEP_OVERFLOW: &str = "timestamp out of range for platform time_t";

/// Python `warnings.warn` message for an active set above the history cap.
const ACTIVE_FILE_WARNING: &str = "watch active-file count exceeds the history cap; \
retaining active files for complete checking";

/// Failure from [`watch`], [`WatchTransition::to_dict`], or [`format_transition`].
///
/// A missing import displays `module.function is not available`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchError {
    /// Python `ValueError` for an interval below [`MIN_INTERVAL`].
    Interval(String),
    /// Python exception text from the default `time.sleep`.
    Sleep(String),
    /// `sesslint.api.check_file`.
    CheckFileUnavailable,
    /// `sesslint.report.minimize_path`.
    MinimizePathUnavailable,
    /// The cancel probe raised `OperationCancelled`.
    Cancelled,
}

impl fmt::Display for WatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interval(message) | Self::Sleep(message) => formatter.write_str(message),
            Self::CheckFileUnavailable => formatter.write_str(CHECK_FILE_UNAVAILABLE),
            Self::MinimizePathUnavailable => formatter.write_str(MINIMIZE_PATH_UNAVAILABLE),
            Self::Cancelled => formatter.write_str(CANCELLED_MESSAGE),
        }
    }
}

impl Error for WatchError {}

/// Python `CheckFn`. `call` is `__call__(path)`.
///
/// `Ok` is the report `_verdict_of` reads. [`CheckError::Cancelled`] is
/// `OperationCancelled`. [`CheckError::Failed`] is any other exception.
pub trait CheckFn {
    /// Check one already-snapshotted path.
    fn call(&mut self, path: &Path) -> Result<WatchReport, CheckError>;
}

impl<F> CheckFn for F
where
    F: FnMut(&Path) -> Result<WatchReport, CheckError>,
{
    fn call(&mut self, path: &Path) -> Result<WatchReport, CheckError> {
        self(path)
    }
}

/// Result of an injected check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// Python `except OperationCancelled: raise`.
    Cancelled,
    /// Python `except Exception`: the verdict becomes `unreadable`.
    Failed,
}

/// Fields `_verdict_of` reads.
///
/// `limitation` uses `""` when the attribute is absent. `by_severity` uses
/// `0` for a missing key. `findings` are the finding codes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchReport {
    pub limitation: String,
    pub by_severity: BTreeMap<String, i64>,
    pub findings: Vec<String>,
}

/// One verdict transition on a watched file (content-free).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchTransition {
    pub path: String,
    pub from_state: String,
    pub to_state: String,
    pub codes: Vec<String>,
}

impl WatchTransition {
    /// Python `WatchTransition.to_dict`.
    ///
    /// The body imports `sesslint.report.minimize_path` before it builds the
    /// object. That function is not linked, so this returns
    /// [`WatchError::MinimizePathUnavailable`] and does not read `home`.
    pub fn to_dict(&self, home: Option<&Path>) -> Result<(), WatchError> {
        let _ = (self, home);
        Err(WatchError::MinimizePathUnavailable)
    }
}

/// Python `_FileState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct _FileState {
    pub mtime_ns: i128,
    pub size: u64,
    pub stable_polls: u64,
    pub verdict: Option<String>,
}

/// Keyword arguments of [`watch`].
///
/// `format` is forwarded only to `check_file`. A missing check returns before
/// that import reads `format`. An injected check does not read `format`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WatchSettings<'a> {
    pub interval: f64,
    pub max_polls: Option<i64>,
    pub format: Option<&'a str>,
}

impl WatchSettings<'static> {
    /// Python defaults: interval [`DEFAULT_INTERVAL`], no poll cap, no format.
    pub fn new() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            max_polls: None,
            format: None,
        }
    }
}

impl Default for WatchSettings<'static> {
    fn default() -> Self {
        Self::new()
    }
}

/// Injected callbacks. `None` selects the Python default where this crate can
/// implement it.
///
/// `sleep`: `None` is `time.sleep`. `throw_if_cancelled`: `None` never
/// cancels. `Err` from the probe is `operation cancelled`. `on_warning`
/// receives the active-file `RuntimeWarning` text. There is no `filename:lineno`
/// prefix, because that would embed this source path.
pub struct WatchCallbacks<'a> {
    pub check: Option<&'a mut dyn CheckFn>,
    pub sleep: Option<&'a mut dyn FnMut(f64)>,
    pub on_transition: Option<&'a mut dyn FnMut(&WatchTransition)>,
    pub throw_if_cancelled: Option<&'a mut dyn FnMut() -> Result<(), ()>>,
    pub on_warning: Option<&'a mut dyn FnMut(&str)>,
}

impl WatchCallbacks<'static> {
    /// No callbacks. [`watch`] then stops at `check_file` after the interval check.
    pub fn empty() -> Self {
        Self {
            check: None,
            sleep: None,
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        }
    }
}

/// Python `watch`.
///
/// Returns the number of transitions emitted. An interval below
/// [`MIN_INTERVAL`] is `ValueError` text in [`WatchError::Interval`], before
/// roots are read. A missing `check` is [`WatchError::CheckFileUnavailable`]
/// before the walk. `max_polls` bounds the loop; `None` runs until the cancel
/// probe fails.
pub fn watch<P: AsRef<Path>>(
    roots: &[P],
    settings: &WatchSettings<'_>,
    callbacks: &mut WatchCallbacks<'_>,
) -> Result<u64, WatchError> {
    watch_with_cap(roots, settings, callbacks, MAX_TRACKED_FILES)
}

fn watch_with_cap<P: AsRef<Path>>(
    roots: &[P],
    settings: &WatchSettings<'_>,
    callbacks: &mut WatchCallbacks<'_>,
    cap: usize,
) -> Result<u64, WatchError> {
    if settings.interval < MIN_INTERVAL {
        return Err(WatchError::Interval(interval_message(settings.interval)));
    }
    if callbacks.check.is_none() {
        return Err(WatchError::CheckFileUnavailable);
    }
    let root_paths: Vec<PathBuf> = roots
        .iter()
        .map(|root| normalized_path(root.as_ref()))
        .collect();
    let mut tracked = Tracked::default();
    let mut pending = PathList::default();
    let mut overflow_warned = false;
    let mut emitted = 0u64;
    let mut polls = 0u64;
    loop {
        if let Some(probe) = callbacks.throw_if_cancelled.as_mut() {
            if probe().is_err() {
                return Err(WatchError::Cancelled);
            }
        }
        if max_polls_reached(polls, settings.max_polls) {
            return Ok(emitted);
        }
        polls = polls.saturating_add(1);
        let mut seen = PathList::default();
        for root in &root_paths {
            for file in list_root(root) {
                observe(&mut tracked, &mut pending, &mut seen, &file);
            }
        }
        pending.retain_seen(&seen);
        emitted = emitted.saturating_add(dispatch(&mut tracked, &mut pending, callbacks)?);
        evict_absent(&mut tracked, &seen, cap);
        if seen.len() > cap {
            if !overflow_warned {
                emit_warning(callbacks, ACTIVE_FILE_WARNING);
                overflow_warned = true;
            }
        } else {
            overflow_warned = false;
        }
        if max_polls_reached(polls, settings.max_polls) {
            return Ok(emitted);
        }
        pause(callbacks, settings.interval)?;
    }
}

/// Python `format_transition`.
///
/// The first statement imports `minimize_path`. That import is not linked, so
/// the codes are not joined and `home` is not read.
pub fn format_transition(
    transition: &WatchTransition,
    home: Option<&Path>,
) -> Result<String, WatchError> {
    let _ = (transition, home);
    Err(WatchError::MinimizePathUnavailable)
}

/// Python `_snapshot_file`. `stat` follows symlinks. `OSError` is `None`.
///
/// The metadata handle is not kept.
pub fn _snapshot_file(path: &Path) -> Option<(i128, u64)> {
    let meta = fs::metadata(path).ok()?;
    let mtime_ns = mtime_ns(&meta)?;
    Some((mtime_ns, meta.len()))
}

/// Python `_walk_files`. Iterative, name-sorted, symlink-free.
///
/// `.git`, `.hg`, and `.svn` are not entered. `sesslint.toml` and
/// `.sesslint.toml` are not listed. A directory listing error skips that
/// directory. An error on one entry skips that entry. The directory iterator
/// is dropped before the next directory is opened.
pub fn _walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![normalized_path(root)];
    while let Some(current) = stack.pop() {
        let Some(mut children) = read_children(&current) else {
            continue;
        };
        children.sort_by(|left, right| cmp_name(&left.name, &right.name));
        for child in children {
            if child.file_type.is_symlink() {
                continue;
            }
            if child.file_type.is_dir() {
                if !excluded(&child.name, _EXCLUDED_DIRS) {
                    stack.push(child.path);
                }
                continue;
            }
            if child.file_type.is_file() && !excluded(&child.name, _EXCLUDED_NAMES) {
                out.push(normalized_path(&child.path));
            }
        }
    }
    out
}

/// Python `_verdict_of`.
///
/// `Unsupported:` wins over `Skipped:`. Both return an empty code list.
/// Otherwise codes are the sorted unique finding codes. `error + fatal > 0`
/// is `invalid`. A warning count, or any finding, is `warnings`. A missing
/// severity is `0`.
pub fn _verdict_of(report: &WatchReport) -> (&'static str, Vec<String>) {
    if report.limitation.starts_with("Unsupported:") {
        return ("unsupported", Vec::new());
    }
    if report.limitation.starts_with("Skipped:") {
        return ("skipped", Vec::new());
    }
    let mut codes = report.findings.clone();
    codes.sort();
    codes.dedup();
    let errors = severity(&report.by_severity, "error")
        .saturating_add(severity(&report.by_severity, "fatal"));
    if errors > 0 {
        return ("invalid", codes);
    }
    if severity(&report.by_severity, "warning") > 0 || !report.findings.is_empty() {
        return ("warnings", codes);
    }
    ("healthy", codes)
}

fn split_exponent(text: &str) -> Option<(&str, &str)> {
    let index = text.find(['e', 'E'].as_slice())?;
    Some((&text[..index], &text[index + 1..]))
}

fn interval_message(interval: f64) -> String {
    format!(
        "interval must be >= {}s, got {}",
        python_float_str(MIN_INTERVAL),
        python_float_str(interval)
    )
}

fn python_float_str(value: f64) -> String {
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
    let debug = format!("{value:?}");
    let Some((mantissa, exponent)) = split_exponent(&debug) else {
        return debug;
    };
    let (sign, digits) = if let Some(rest) = exponent.strip_prefix('+') {
        ('+', rest)
    } else if let Some(rest) = exponent.strip_prefix('-') {
        ('-', rest)
    } else {
        ('+', exponent)
    };
    if digits.len() >= 2 {
        format!("{mantissa}e{sign}{digits}")
    } else {
        format!("{mantissa}e{sign}0{digits}")
    }
}

fn time_sleep(seconds: f64) -> Result<(), WatchError> {
    if seconds.is_nan() {
        return Err(WatchError::Sleep(SLEEP_NAN.to_owned()));
    }
    match signed_nanos(seconds) {
        None => Err(WatchError::Sleep(SLEEP_OVERFLOW.to_owned())),
        Some(nanos) if nanos < 0 => Err(WatchError::Sleep(SLEEP_NEGATIVE.to_owned())),
        Some(nanos) => match u64::try_from(nanos) {
            Ok(nanoseconds) => {
                thread::sleep(Duration::from_nanos(nanoseconds));
                Ok(())
            }
            Err(_) => Err(WatchError::Sleep(SLEEP_OVERFLOW.to_owned())),
        },
    }
}

fn signed_nanos(seconds: f64) -> Option<i64> {
    if !seconds.is_finite() {
        return None;
    }
    let nanos = seconds * 1_000_000_000.0;
    if !nanos.is_finite() {
        return None;
    }
    let rounded = nanos.round();
    if !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&rounded) {
        return None;
    }
    Some(rounded as i64)
}

fn mtime_ns(meta: &fs::Metadata) -> Option<i128> {
    let modified = meta.modified().ok()?;
    match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok(),
        Err(error) => i128::try_from(error.duration().as_nanos())
            .ok()
            .map(|nanos| -nanos),
    }
}

fn list_root(root: &Path) -> Vec<PathBuf> {
    if listed_as_file(root) {
        vec![normalized_path(root)]
    } else {
        _walk_files(root)
    }
}

fn listed_as_file(root: &Path) -> bool {
    match fs::symlink_metadata(root) {
        Ok(meta) => meta.file_type().is_symlink() || !meta.is_dir(),
        Err(_) => true,
    }
}

struct WalkChild {
    name: OsString,
    path: PathBuf,
    file_type: fs::FileType,
}

fn read_children(current: &Path) -> Option<Vec<WalkChild>> {
    let read = fs::read_dir(current).ok()?;
    let mut children = Vec::new();
    for entry in read {
        let entry = entry.ok()?;
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
    Some(children)
}

fn cmp_name(left: &OsStr, right: &OsStr) -> Ordering {
    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => left.cmp(right),
        _ => left.cmp(right),
    }
}

fn excluded(name: &OsStr, table: &[&str]) -> bool {
    table.iter().any(|item| OsStr::new(item) == name)
}

fn normalized_path(path: &Path) -> PathBuf {
    if path.as_os_str().is_empty() {
        return PathBuf::from(".");
    }
    let mut components: Vec<Component<'_>> = path.components().collect();
    if components.len() > 1 && matches!(components.first(), Some(Component::CurDir)) {
        components.remove(0);
    }
    if components.is_empty() {
        PathBuf::from(".")
    } else {
        components.into_iter().collect()
    }
}

fn path_text(path: &Path) -> String {
    let text = normalized_path(path).to_string_lossy().into_owned();
    if text.is_empty() {
        ".".to_owned()
    } else {
        text
    }
}

fn identity_key(path: &Path) -> String {
    let text = path_text(path);
    #[cfg(windows)]
    {
        text.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        text
    }
}

fn severity(counts: &BTreeMap<String, i64>, key: &str) -> i64 {
    match counts.get(key) {
        Some(value) => *value,
        None => 0,
    }
}

fn from_label(previous: Option<&str>) -> &str {
    match previous {
        Some(text) if !text.is_empty() => text,
        _ => "new",
    }
}

fn max_polls_reached(polls: u64, max_polls: Option<i64>) -> bool {
    match max_polls {
        None => false,
        Some(limit) if limit <= 0 => true,
        Some(limit) => match u64::try_from(limit) {
            Ok(limit) => polls >= limit,
            Err(_) => false,
        },
    }
}

enum Observe {
    New,
    Changed,
    Stable,
}

fn observe(tracked: &mut Tracked, pending: &mut PathList, seen: &mut PathList, path: &Path) {
    let path = normalized_path(path);
    seen.insert(path.clone());
    let Some((mtime_ns, size)) = _snapshot_file(&path) else {
        return;
    };
    match classify(tracked, &path, mtime_ns, size) {
        Observe::New => {
            tracked.insert_new(
                path.clone(),
                _FileState {
                    mtime_ns,
                    size,
                    stable_polls: 0,
                    verdict: None,
                },
            );
            pending.insert(path.clone());
        }
        Observe::Changed => pending.insert(path.clone()),
        Observe::Stable => {}
    }
    tracked.move_to_end(&path);
}

fn classify(tracked: &mut Tracked, path: &Path, mtime_ns: i128, size: u64) -> Observe {
    let Some(state) = tracked.get_mut(path) else {
        return Observe::New;
    };
    if state.mtime_ns != mtime_ns || state.size != size {
        state.mtime_ns = mtime_ns;
        state.size = size;
        state.stable_polls = 0;
        Observe::Changed
    } else {
        state.stable_polls = state.stable_polls.saturating_add(1);
        Observe::Stable
    }
}

fn dispatch(
    tracked: &mut Tracked,
    pending: &mut PathList,
    callbacks: &mut WatchCallbacks<'_>,
) -> Result<u64, WatchError> {
    let mut ordered = pending.paths();
    ordered.sort_by_key(|path| path_text(path));
    let mut emitted = 0u64;
    for path in ordered {
        let stable = match tracked.get_mut(&path) {
            Some(state) => state.stable_polls,
            None => continue,
        };
        if stable < 1 {
            continue;
        }
        pending.remove(&path);
        let checked = match callbacks.check.as_mut() {
            Some(check) => check.call(&path),
            None => return Err(WatchError::CheckFileUnavailable),
        };
        let (verdict, codes) = match checked {
            Ok(report) => _verdict_of(&report),
            Err(CheckError::Cancelled) => return Err(WatchError::Cancelled),
            Err(CheckError::Failed) => ("unreadable", Vec::new()),
        };
        let previous = {
            let Some(state) = tracked.get_mut(&path) else {
                continue;
            };
            let previous = state.verdict.clone();
            state.verdict = Some(verdict.to_owned());
            previous
        };
        if verdict == "healthy" && previous.is_none() {
            continue;
        }
        if previous.as_deref() == Some(verdict) {
            continue;
        }
        let transition = WatchTransition {
            path: path_text(&path),
            from_state: from_label(previous.as_deref()).to_owned(),
            to_state: verdict.to_owned(),
            codes,
        };
        if let Some(on_transition) = callbacks.on_transition.as_mut() {
            on_transition(&transition);
        }
        emitted = emitted.saturating_add(1);
    }
    Ok(emitted)
}

fn evict_absent(tracked: &mut Tracked, seen: &PathList, cap: usize) {
    for old in tracked.paths() {
        if tracked.len() <= cap {
            break;
        }
        if !seen.contains(&old) {
            tracked.remove(&old);
        }
    }
}

fn emit_warning(callbacks: &mut WatchCallbacks<'_>, message: &str) {
    if let Some(callback) = callbacks.on_warning.as_mut() {
        callback(message);
    }
}

fn pause(callbacks: &mut WatchCallbacks<'_>, interval: f64) -> Result<(), WatchError> {
    if let Some(sleep) = callbacks.sleep.as_mut() {
        sleep(interval);
        Ok(())
    } else {
        time_sleep(interval)
    }
}

#[derive(Default)]
struct PathList {
    paths: Vec<PathBuf>,
}

impl PathList {
    fn len(&self) -> usize {
        self.paths.len()
    }

    fn paths(&self) -> Vec<PathBuf> {
        self.paths.clone()
    }

    fn contains(&self, path: &Path) -> bool {
        let key = identity_key(path);
        self.paths.iter().any(|item| identity_key(item) == key)
    }

    fn insert(&mut self, path: PathBuf) {
        let path = normalized_path(&path);
        if !self.contains(&path) {
            self.paths.push(path);
        }
    }

    fn remove(&mut self, path: &Path) {
        let key = identity_key(path);
        self.paths.retain(|item| identity_key(item) != key);
    }

    fn retain_seen(&mut self, seen: &PathList) {
        self.paths.retain(|item| seen.contains(item));
    }
}

#[derive(Default)]
struct Tracked {
    order: Vec<PathBuf>,
    states: Vec<_FileState>,
}

impl Tracked {
    fn len(&self) -> usize {
        self.order.len()
    }

    fn paths(&self) -> Vec<PathBuf> {
        self.order.clone()
    }

    fn index_of(&self, path: &Path) -> Option<usize> {
        let key = identity_key(path);
        self.order.iter().position(|item| identity_key(item) == key)
    }

    fn get_mut(&mut self, path: &Path) -> Option<&mut _FileState> {
        let index = self.index_of(path)?;
        self.states.get_mut(index)
    }

    fn insert_new(&mut self, path: PathBuf, state: _FileState) {
        self.order.push(normalized_path(&path));
        self.states.push(state);
    }

    fn move_to_end(&mut self, path: &Path) {
        let Some(index) = self.index_of(path) else {
            return;
        };
        if index + 1 == self.order.len() || index >= self.states.len() {
            return;
        }
        let path = self.order.remove(index);
        let state = self.states.remove(index);
        self.order.push(path);
        self.states.push(state);
    }

    fn remove(&mut self, path: &Path) {
        let Some(index) = self.index_of(path) else {
            return;
        };
        if index >= self.order.len() || index >= self.states.len() {
            return;
        }
        self.order.remove(index);
        self.states.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        format_transition, path_text, python_float_str, time_sleep, watch, watch_with_cap,
        CheckError, WatchCallbacks, WatchError, WatchReport, WatchSettings, WatchTransition,
        _FileState, _snapshot_file, _verdict_of, _walk_files, ACTIVE_FILE_WARNING, ALL,
        CHECK_FILE_UNAVAILABLE, DEFAULT_INTERVAL, MAX_TRACKED_FILES, MINIMIZE_PATH_UNAVAILABLE,
        MIN_INTERVAL, WATCH_EVENT_SCHEMA, _EXCLUDED_DIRS, _EXCLUDED_NAMES,
    };

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sesslint-rx-watch-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct HitPath<'a> {
        path: &'a Path,
        hits: &'a AtomicUsize,
    }

    impl AsRef<Path> for HitPath<'_> {
        fn as_ref(&self) -> &Path {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.path
        }
    }

    fn settings(interval: f64, max_polls: Option<i64>) -> WatchSettings<'static> {
        WatchSettings {
            interval,
            max_polls,
            format: None,
        }
    }

    fn touch(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    fn report(limitation: &str, findings: &[&str], severity: &[(&str, i64)]) -> WatchReport {
        WatchReport {
            limitation: limitation.to_owned(),
            findings: findings.iter().map(|code| (*code).to_owned()).collect(),
            by_severity: severity
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
        }
    }

    fn healthy(_: &Path) -> Result<WatchReport, CheckError> {
        Ok(WatchReport::default())
    }

    #[test]
    fn constants_match_the_module() {
        assert_eq!(WATCH_EVENT_SCHEMA, "sesslint.watch-event/v1");
        assert_eq!(DEFAULT_INTERVAL, 2.0);
        assert_eq!(MIN_INTERVAL, 0.05);
        assert_eq!(MAX_TRACKED_FILES, 4096);
        assert_eq!(_EXCLUDED_DIRS, [".git", ".hg", ".svn"].as_slice());
        assert_eq!(
            _EXCLUDED_NAMES,
            ["sesslint.toml", ".sesslint.toml"].as_slice()
        );
        assert_eq!(
            ALL,
            [
                "DEFAULT_INTERVAL",
                "MAX_TRACKED_FILES",
                "MIN_INTERVAL",
                "WATCH_EVENT_SCHEMA",
                "CheckFn",
                "WatchTransition",
                "format_transition",
                "watch",
            ]
            .as_slice()
        );
        assert_eq!(WatchSettings::new().interval, DEFAULT_INTERVAL);
        assert_eq!(
            CHECK_FILE_UNAVAILABLE,
            "sesslint.api.check_file is not available"
        );
        assert_eq!(
            MINIMIZE_PATH_UNAVAILABLE,
            "sesslint.report.minimize_path is not available"
        );
        let state = _FileState {
            mtime_ns: 0,
            size: 0,
            stable_polls: 0,
            verdict: None,
        };
        assert!(state.verdict.is_none());
    }

    #[test]
    fn python_float_text_matches_str() {
        let samples = [
            (0.05, "0.05"),
            (0.001, "0.001"),
            (2.0, "2.0"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (-1.0, "-1.0"),
            (1e-5, "1e-05"),
            (1e-10, "1e-10"),
            (1e16, "1e+16"),
            (1.23e20, "1.23e+20"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
        ];
        for (value, expected) in samples {
            assert_eq!(python_float_str(value), expected, "{value:?}");
        }
    }

    #[test]
    fn path_text_matches_python_str() {
        assert_eq!(path_text(Path::new("")), ".");
        assert_eq!(path_text(Path::new(".")), ".");
        assert_eq!(path_text(Path::new("./foo")), "foo");
        assert_eq!(
            path_text(Path::new("./../foo")),
            format!("..{}foo", std::path::MAIN_SEPARATOR)
        );
        assert_eq!(
            path_text(Path::new("foo/../bar")),
            format!(
                "foo{}..{}bar",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            )
        );
        assert_eq!(
            path_text(Path::new("foo/./bar")),
            format!("foo{}bar", std::path::MAIN_SEPARATOR)
        );
    }

    #[test]
    fn interval_is_checked_before_roots_and_check_file() {
        let hits = AtomicUsize::new(0);
        let scratch = Scratch::new("interval");
        let roots = [HitPath {
            path: &scratch.path,
            hits: &hits,
        }];
        let mut callbacks = WatchCallbacks::empty();
        let error = watch(&roots, &settings(0.001, Some(0)), &mut callbacks).unwrap_err();
        assert_eq!(error.to_string(), "interval must be >= 0.05s, got 0.001");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert!(matches!(error, WatchError::Interval(_)));

        let mut callbacks = WatchCallbacks::empty();
        let tiny = watch(&roots, &settings(1e-5, None), &mut callbacks).unwrap_err();
        assert_eq!(tiny.to_string(), "interval must be >= 0.05s, got 1e-05");
        let mut callbacks = WatchCallbacks::empty();
        let negative = watch(&roots, &settings(-0.0, None), &mut callbacks).unwrap_err();
        assert_eq!(negative.to_string(), "interval must be >= 0.05s, got -0.0");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_check_stops_at_check_file_after_a_valid_interval() {
        let hits = AtomicUsize::new(0);
        let scratch = Scratch::new("missing-check");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let roots = [HitPath {
            path: file.as_path(),
            hits: &hits,
        }];
        let mut cancel = || Err(());
        let mut callbacks = WatchCallbacks {
            check: None,
            sleep: None,
            on_transition: None,
            throw_if_cancelled: Some(&mut cancel),
            on_warning: None,
        };
        let mut settings = settings(MIN_INTERVAL, Some(0));
        settings.format = Some("canonical");
        let error = watch(&roots, &settings, &mut callbacks).unwrap_err();
        assert_eq!(error, WatchError::CheckFileUnavailable);
        assert_eq!(error.to_string(), CHECK_FILE_UNAVAILABLE);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&file).unwrap(), b"synthetic\n");
    }

    #[test]
    fn nan_interval_is_allowed_and_default_sleep_does_not_hang() {
        let mut check = healthy;
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: None,
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch::<PathBuf>(&[], &settings(f64::NAN, Some(0)), &mut callbacks).unwrap();
        assert_eq!(emitted, 0);

        let mut check = healthy;
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: None,
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let error =
            watch::<PathBuf>(&[], &settings(f64::INFINITY, Some(2)), &mut callbacks).unwrap_err();
        assert_eq!(
            error.to_string(),
            "timestamp out of range for platform time_t"
        );

        let mut check = healthy;
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: None,
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let huge = watch::<PathBuf>(&[], &settings(1e20, Some(2)), &mut callbacks).unwrap_err();
        assert_eq!(
            huge.to_string(),
            "timestamp out of range for platform time_t"
        );
    }

    #[test]
    fn default_sleep_messages_match_python() {
        assert!(time_sleep(0.0).is_ok());
        assert!(time_sleep(-0.0).is_ok());
        assert_eq!(
            time_sleep(f64::NAN).unwrap_err().to_string(),
            "Invalid value NaN (not a number)"
        );
        assert_eq!(
            time_sleep(-1.0).unwrap_err().to_string(),
            "sleep length must be non-negative"
        );
        for value in [f64::INFINITY, f64::NEG_INFINITY, 1e20, -1e20] {
            assert_eq!(
                time_sleep(value).unwrap_err().to_string(),
                "timestamp out of range for platform time_t",
                "{value:?}"
            );
        }
    }

    #[test]
    fn cancel_is_checked_before_max_polls() {
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(WatchReport::default())
        };
        let mut sleeps = 0u32;
        let mut sleep = |_interval: f64| sleeps += 1;
        let mut cancel = || Err(());
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: Some(&mut cancel),
            on_warning: None,
        };
        let error =
            watch::<PathBuf>(&[], &settings(MIN_INTERVAL, Some(0)), &mut callbacks).unwrap_err();
        assert_eq!(error, WatchError::Cancelled);
        assert_eq!(error.to_string(), "operation cancelled");
        assert_eq!(checks, 0);
        assert_eq!(sleeps, 0);
    }

    #[test]
    fn max_polls_zero_and_negative_do_not_poll() {
        let checks = Cell::new(0u32);
        let mut check = |_path: &Path| {
            checks.set(checks.get() + 1);
            Ok(WatchReport::default())
        };
        let sleeps = Cell::new(0u32);
        let mut sleep = |_interval: f64| sleeps.set(sleeps.get() + 1);
        let scratch = Scratch::new("max-polls");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        for cap in [Some(0), Some(-3)] {
            checks.set(0);
            sleeps.set(0);
            let mut callbacks = WatchCallbacks {
                check: Some(&mut check),
                sleep: Some(&mut sleep),
                on_transition: None,
                throw_if_cancelled: None,
                on_warning: None,
            };
            let emitted = watch(
                std::slice::from_ref(&file),
                &settings(MIN_INTERVAL, cap),
                &mut callbacks,
            )
            .unwrap();
            assert_eq!(emitted, 0);
            assert_eq!(checks.get(), 0);
            assert_eq!(sleeps.get(), 0);
        }
    }

    #[test]
    fn first_healthy_is_quiet_and_checked_once() {
        let scratch = Scratch::new("quiet");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let mut checks = Vec::new();
        let mut check = |path: &Path| {
            checks.push(path_text(path));
            Ok(WatchReport::default())
        };
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut sleeps = Vec::new();
        let mut sleep = |interval: f64| sleeps.push(interval);
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let before = fs::read(&file).unwrap();
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(4)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(emitted, 0);
        assert!(transitions.is_empty());
        assert_eq!(checks, vec![path_text(&file)]);
        assert_eq!(sleeps, vec![MIN_INTERVAL, MIN_INTERVAL, MIN_INTERVAL]);
        assert_eq!(fs::read(&file).unwrap(), before);
    }

    #[test]
    fn healthy_to_invalid_emits_one_sorted_transition() {
        let scratch = Scratch::new("invalid");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let armed = Cell::new(false);
        let mut check = |_path: &Path| {
            if armed.get() {
                Ok(report("", &["CODE-B", "CODE-A", "CODE-A"], &[("error", 2)]))
            } else {
                Ok(WatchReport::default())
            }
        };
        let polls = Cell::new(0u32);
        let mut sleep = |_interval: f64| {
            polls.set(polls.get() + 1);
            if polls.get() == 3 {
                touch(&file, b"synthetic\nchanged\n");
                armed.set(true);
            }
        };
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(8)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(emitted, 1);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from_state, "healthy");
        assert_eq!(transitions[0].to_state, "invalid");
        assert_eq!(
            transitions[0].codes,
            vec!["CODE-A".to_owned(), "CODE-B".to_owned()]
        );
        assert_eq!(transitions[0].path, path_text(&file));
        assert!(!transitions[0].path.contains("synthetic"));
    }

    #[test]
    fn debounce_skips_a_file_that_changes_every_poll() {
        let scratch = Scratch::new("debounce");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(WatchReport::default())
        };
        let mut polls = 0u32;
        let mut sleep = |_interval: f64| {
            polls += 1;
            let mut bytes = fs::read(&file).unwrap();
            bytes.extend(format!("synthetic-{polls}\n").into_bytes());
            fs::write(&file, bytes).unwrap();
        };
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(5)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(emitted, 0);
        assert_eq!(checks, 0);
    }

    #[test]
    fn unreadable_and_cancelled_checks() {
        let scratch = Scratch::new("unreadable");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let mut check = |_path: &Path| Err(CheckError::Failed);
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(4)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(emitted, 1);
        assert_eq!(transitions[0].from_state, "new");
        assert_eq!(transitions[0].to_state, "unreadable");
        assert!(transitions[0].codes.is_empty());
        assert!(!transitions[0].path.contains("synthetic"));

        touch(&file, b"synthetic\n");
        let mut check = |_path: &Path| Err(CheckError::Cancelled);
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut sleeps = 0u32;
        let mut sleep = |_interval: f64| sleeps += 1;
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let error = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(4)),
            &mut callbacks,
        )
        .unwrap_err();
        assert_eq!(error, WatchError::Cancelled);
        assert!(transitions.is_empty());
        assert_eq!(sleeps, 1);
    }

    #[test]
    fn cancellation_during_sleep_stops_the_next_poll() {
        let scratch = Scratch::new("cancel");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let flag = Cell::new(false);
        let mut sleep = |_interval: f64| flag.set(true);
        let mut cancel = || {
            if flag.get() {
                Err(())
            } else {
                Ok(())
            }
        };
        let mut check = healthy;
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: Some(&mut cancel),
            on_warning: None,
        };
        let error = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, None),
            &mut callbacks,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "operation cancelled");
    }

    #[test]
    fn verdict_rules_follow_watch_order() {
        let cases = [
            (
                report("Unsupported: synthetic", &["CODE-Z"], &[("fatal", 4)]),
                "unsupported",
                Vec::<String>::new(),
            ),
            (
                report("Skipped: synthetic", &["CODE-Z"], &[("warning", 9)]),
                "skipped",
                Vec::new(),
            ),
            (
                report("", &["CODE-B", "CODE-A"], &[("error", 1), ("warning", 3)]),
                "invalid",
                vec!["CODE-A".to_owned(), "CODE-B".to_owned()],
            ),
            (
                report("", &["CODE-A"], &[("fatal", 1), ("error", 0)]),
                "invalid",
                vec!["CODE-A".to_owned()],
            ),
            (report("", &[], &[("warning", 1)]), "warnings", Vec::new()),
            (
                report("", &["CODE-B", "CODE-A"], &[("warning", 0)]),
                "warnings",
                vec!["CODE-A".to_owned(), "CODE-B".to_owned()],
            ),
            (
                report("", &[], &[("error", -1), ("info", 5)]),
                "healthy",
                Vec::new(),
            ),
            (
                report("unsupported-not-a-prefix", &[], &[]),
                "healthy",
                Vec::new(),
            ),
        ];
        for (view, verdict, codes) in cases {
            assert_eq!(_verdict_of(&view), (verdict, codes));
        }
    }

    #[test]
    fn same_verdict_does_not_emit_again() {
        let scratch = Scratch::new("repeat");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let mut polls = 0u32;
        let mut sleep = |_interval: f64| {
            polls += 1;
            if polls == 3 {
                touch(&file, b"synthetic\nmore\n");
            }
        };
        let mut check = |_path: &Path| Ok(report("", &["CODE-A"], &[("warning", 1)]));
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(6)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(emitted, 1);
        assert_eq!(transitions[0].from_state, "new");
        assert_eq!(transitions[0].to_state, "warnings");
        assert_eq!(transitions[0].codes, vec!["CODE-A".to_owned()]);
    }

    #[test]
    fn minimize_path_is_not_called() {
        let scratch = Scratch::new("minimize");
        let home = scratch.child("home");
        fs::create_dir(&home).unwrap();
        touch(&home.join("marker.txt"), b"synthetic-marker\n");
        let transition = WatchTransition {
            path: path_text(&scratch.child("note.txt")),
            from_state: "healthy".to_owned(),
            to_state: "invalid".to_owned(),
            codes: vec!["CODE-A".to_owned(), "CODE-B".to_owned()],
        };
        let dict = transition.to_dict(Some(&home)).unwrap_err();
        let line = format_transition(&transition, Some(&home)).unwrap_err();
        assert_eq!(dict, WatchError::MinimizePathUnavailable);
        assert_eq!(line.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert!(!line.to_string().contains("CODE-A"));
        assert!(!line.to_string().contains("note.txt"));
        assert!(!dict.to_string().contains(&path_text(&home)));
        assert_eq!(
            fs::read(home.join("marker.txt")).unwrap(),
            b"synthetic-marker\n"
        );
        assert_eq!(WATCH_EVENT_SCHEMA, "sesslint.watch-event/v1");
    }

    #[test]
    fn exclusion_match_is_case_sensitive() {
        assert!(super::excluded(
            OsStr::new("sesslint.toml"),
            _EXCLUDED_NAMES
        ));
        assert!(super::excluded(
            OsStr::new(".sesslint.toml"),
            _EXCLUDED_NAMES
        ));
        assert!(!super::excluded(
            OsStr::new("Sesslint.toml"),
            _EXCLUDED_NAMES
        ));
        assert!(super::excluded(OsStr::new(".git"), _EXCLUDED_DIRS));
        assert!(!super::excluded(OsStr::new(".Git"), _EXCLUDED_DIRS));
    }

    #[test]
    fn walk_order_exclusions_and_symlinks() {
        let scratch = Scratch::new("walk");
        let root = scratch.child("root");
        touch(&root.join("a.txt"), b"synthetic\n");
        touch(&root.join("B.txt"), b"synthetic\n");
        touch(&root.join("m").join("z.txt"), b"synthetic\n");
        touch(&root.join("d1").join("a.txt"), b"synthetic\n");
        touch(&root.join("d2").join("b.txt"), b"synthetic\n");
        touch(&root.join(".git").join("hidden.txt"), b"synthetic\n");
        touch(&root.join("sesslint.toml"), b"synthetic\n");
        touch(&root.join(".sesslint.toml"), b"synthetic\n");
        touch(
            &root.join("sesslint.toml.dir").join("inside.txt"),
            b"synthetic\n",
        );
        let outside = scratch.child("outside");
        touch(&outside.join("target.txt"), b"synthetic\n");
        touch(&outside.join("dir").join("nested.txt"), b"synthetic\n");
        symlink_file(&outside.join("target.txt"), &root.join("link.txt"));
        symlink_dir(&outside.join("dir"), &root.join("sub_link"));
        symlink_file(&outside.join("missing.txt"), &root.join("broken.txt"));

        let names = |paths: Vec<PathBuf>| -> Vec<String> {
            paths
                .into_iter()
                .map(|path| {
                    path.strip_prefix(&root)
                        .unwrap()
                        .components()
                        .map(|component| component.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .collect()
        };
        assert_eq!(
            names(_walk_files(&root)),
            vec![
                "B.txt",
                "a.txt",
                "sesslint.toml.dir/inside.txt",
                "m/z.txt",
                "d2/b.txt",
                "d1/a.txt",
            ]
        );
        assert!(_walk_files(&root.join("a.txt")).is_empty());
        assert!(_snapshot_file(&root.join("missing.txt")).is_none());
        let snap = _snapshot_file(&root.join("a.txt")).unwrap();
        assert_eq!(snap.1, b"synthetic\n".len() as u64);
        assert_eq!(_snapshot_file(&root.join("a.txt")).unwrap(), snap);
        touch(&root.join("a.txt"), b"synthetic\nmore\n");
        assert_ne!(_snapshot_file(&root.join("a.txt")).unwrap(), snap);
    }

    #[test]
    fn file_root_missing_root_and_symlink_root() {
        let scratch = Scratch::new("roots");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let dotted = scratch.path.join(".").join("note.txt");
        let mut checks = Vec::new();
        let mut check = |path: &Path| {
            checks.push(path_text(path));
            Ok(report("", &["CODE-A"], &[("error", 1)]))
        };
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(&[dotted], &settings(MIN_INTERVAL, Some(2)), &mut callbacks).unwrap();
        assert_eq!(emitted, 1);
        assert_eq!(checks, vec![path_text(&file)]);
        assert_eq!(transitions[0].from_state, "new");
        assert_eq!(transitions[0].to_state, "invalid");
        assert!(!checks[0].contains(&format!(
            "{}..{}",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        )));

        let missing = scratch.child("absent.txt");
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(WatchReport::default())
        };
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(&[missing], &settings(MIN_INTERVAL, Some(2)), &mut callbacks).unwrap();
        assert_eq!(emitted, 0);
        assert_eq!(checks, 0);

        let target = scratch.child("target.txt");
        touch(&target, b"synthetic\n");
        let link = scratch.child("link.txt");
        symlink_file(&target, &link);
        let mut checks = Vec::new();
        let mut check = |path: &Path| {
            checks.push(path_text(path));
            let removed = fs::remove_file(path).is_ok();
            assert!(removed);
            Ok(WatchReport::default())
        };
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let _ = watch(
            std::slice::from_ref(&link),
            &settings(MIN_INTERVAL, Some(2)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(checks, vec![path_text(&link)]);
        assert!(target.is_file());
    }

    #[test]
    fn disappeared_file_is_not_unreadable_and_reappearance_checks() {
        let scratch = Scratch::new("vanish");
        let file = scratch.child("note.txt");
        touch(&file, b"synthetic\n");
        let mut polls = 0u32;
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(report("", &["CODE-A"], &[("warning", 1)]))
        };
        let mut sleep = |_interval: f64| {
            polls += 1;
            if polls == 1 {
                fs::remove_file(&file).unwrap();
            }
            if polls == 2 {
                touch(&file, b"synthetic\nback\n");
            }
        };
        let mut transitions = Vec::new();
        let mut on_transition = |transition: &WatchTransition| transitions.push(transition.clone());
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: Some(&mut on_transition),
            throw_if_cancelled: None,
            on_warning: None,
        };
        let emitted = watch(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(4)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(checks, 1);
        assert_eq!(emitted, 1);
        assert_eq!(transitions[0].from_state, "new");
        assert_eq!(transitions[0].to_state, "warnings");
    }

    #[test]
    fn active_files_stay_checked_when_history_overflows() {
        let scratch = Scratch::new("overflow");
        let mut files = Vec::new();
        for name in ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"] {
            let file = scratch.child(name);
            touch(&file, b"synthetic\n");
            files.push(file);
        }
        let mut checked = Vec::new();
        let mut check = |path: &Path| {
            checked.push(path_text(path));
            Ok(WatchReport::default())
        };
        let mut warnings = Vec::new();
        let mut on_warning = |message: &str| warnings.push(message.to_owned());
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: Some(&mut on_warning),
        };
        let emitted = watch_with_cap(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(3)),
            &mut callbacks,
            3,
        )
        .unwrap();
        assert_eq!(emitted, 0);
        let mut expected: Vec<String> = files.iter().map(|path| path_text(path)).collect();
        expected.sort();
        let mut got = checked.clone();
        got.sort();
        assert_eq!(got, expected);
        assert_eq!(warnings, vec![ACTIVE_FILE_WARNING.to_owned()]);
    }

    #[test]
    fn historical_files_are_evicted_and_warning_resets() {
        let scratch = Scratch::new("evict");
        let old_a = scratch.child("old-a.txt");
        let old_b = scratch.child("old-b.txt");
        touch(&old_a, b"synthetic\n");
        touch(&old_b, b"synthetic\n");
        let mut polls = 0u32;
        let mut checked = Vec::new();
        let mut check = |path: &Path| {
            checked.push(path_text(path));
            Ok(WatchReport::default())
        };
        let mut warnings = Vec::new();
        let mut on_warning = |message: &str| warnings.push(message.to_owned());
        let mut sleep = |_interval: f64| {
            polls += 1;
            if polls == 1 {
                fs::remove_file(&old_a).unwrap();
                fs::remove_file(&old_b).unwrap();
                for name in ["a.txt", "b.txt", "c.txt"] {
                    touch(&scratch.child(name), b"synthetic\n");
                }
            }
        };
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: Some(&mut on_warning),
        };
        let _ = watch_with_cap(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(3)),
            &mut callbacks,
            2,
        )
        .unwrap();
        let mut got = checked;
        got.sort();
        let mut expected = vec![
            path_text(&scratch.child("a.txt")),
            path_text(&scratch.child("b.txt")),
            path_text(&scratch.child("c.txt")),
        ];
        expected.sort();
        assert_eq!(got, expected);
        assert_eq!(warnings.len(), 1);

        let scratch = Scratch::new("warn-reset");
        touch(&scratch.child("a.txt"), b"synthetic\n");
        touch(&scratch.child("b.txt"), b"synthetic\n");
        let mut polls = 0u32;
        let mut check = healthy;
        let mut warnings = Vec::new();
        let mut on_warning = |message: &str| warnings.push(message.to_owned());
        let mut sleep = |_interval: f64| {
            polls += 1;
            if polls == 1 {
                fs::remove_file(scratch.child("b.txt")).unwrap();
            }
            if polls == 2 {
                touch(&scratch.child("b.txt"), b"synthetic\n");
            }
        };
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: Some(&mut on_warning),
        };
        let _ = watch_with_cap(
            std::slice::from_ref(&scratch.path),
            &settings(MIN_INTERVAL, Some(3)),
            &mut callbacks,
            1,
        )
        .unwrap();
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn missing_roots_count_toward_the_active_cap() {
        let scratch = Scratch::new("missing-cap");
        let left = scratch.child("left.txt");
        let right = scratch.child("right.txt");
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(WatchReport::default())
        };
        let mut warnings = Vec::new();
        let mut on_warning = |message: &str| warnings.push(message.to_owned());
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: Some(&mut on_warning),
        };
        let _ = watch_with_cap(
            &[left, right],
            &settings(MIN_INTERVAL, Some(1)),
            &mut callbacks,
            1,
        )
        .unwrap();
        assert_eq!(checks, 0);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn monitor_does_not_rewrite_the_tree() {
        let scratch = Scratch::new("rewrite");
        let root = scratch.child("root");
        touch(&root.join("note.txt"), b"synthetic\n");
        touch(&root.join("sub").join("more.txt"), b"synthetic\n");
        let before = tree_bytes(&root);
        let mut check = healthy;
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let _ = watch(
            std::slice::from_ref(&root),
            &settings(MIN_INTERVAL, Some(2)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(tree_bytes(&root), before);
    }

    #[test]
    fn checks_are_sorted_by_path_text_across_roots() {
        let scratch = Scratch::new("sort");
        let first = scratch.child("b");
        let second = scratch.child("a");
        touch(&first.join("a.txt"), b"synthetic\n");
        touch(&second.join("z.txt"), b"synthetic\n");
        let mut checks = Vec::new();
        let mut check = |path: &Path| {
            checks.push(path_text(path));
            Err(CheckError::Failed)
        };
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let _ = watch(
            &[first.clone(), second.clone()],
            &settings(MIN_INTERVAL, Some(2)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(
            checks,
            vec![
                path_text(&second.join("z.txt")),
                path_text(&first.join("a.txt")),
            ]
        );
    }

    fn tree_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files = _walk_files(root);
        files.sort_by_key(|path| path_text(path));
        files
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path_text(&path), bytes)
            })
            .collect()
    }

    fn symlink_file(source: &Path, link: &Path) {
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(source, link).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(source, link).unwrap();
    }

    fn symlink_dir(source: &Path, link: &Path) {
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(source, link).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(source, link).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_and_separators_are_one_file() {
        let scratch = Scratch::new("case");
        let file = scratch.child("A.txt");
        touch(&file, b"synthetic\n");
        let other_case = scratch.path.join("a.txt");
        let forward = PathBuf::from(file.to_string_lossy().replace('\\', "/"));
        let mut checks = 0u32;
        let mut check = |_path: &Path| {
            checks += 1;
            Ok(WatchReport::default())
        };
        let mut sleep = |_interval: f64| {};
        let mut callbacks = WatchCallbacks {
            check: Some(&mut check),
            sleep: Some(&mut sleep),
            on_transition: None,
            throw_if_cancelled: None,
            on_warning: None,
        };
        let _ = watch(
            &[scratch.path.clone(), other_case, forward],
            &settings(MIN_INTERVAL, Some(1)),
            &mut callbacks,
        )
        .unwrap();
        assert_eq!(checks, 1);
    }
}
