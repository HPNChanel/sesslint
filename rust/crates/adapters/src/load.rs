//! Format-dispatch loaders for vendor session artifacts.
//!
//! Port of `src/sesslint/adapters/load.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–166.
//!
//! [`load_events_for_format`] tries canonical, then a vendor id.
//! [`load_vendor_events`] tries claude, then openai, then codex.
//! Anything else is `ValueError`, and [`Display`](std::fmt::Display) is the
//! Python message, including `repr`.
//!
//! [`crate::claude_code::load_claude_code`] and
//! [`crate::canonical::load_canonical`] return [`std::convert::Infallible`]
//! on success. Those arms do not build events. [`load_openai_agents`] and
//! [`load_codex_rollout`] return their own [`EventList`] and findings. An
//! error from those functions is returned as that error.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `sesslint.io.ReaderLimits` is not in this crate. This crate does not
//!   depend on `scan`. [`LoadLimits`] carries the four integer fields.
//!   `None` is passed through as `None`. [`load_claude_code`] accepts only
//!   `max_file_bytes`. [`load_openai_agents`] accepts [`MaxFileBytes`]; a
//!   supplied cap is [`MaxFileBytes::Int`] because `ReaderLimits` does not
//!   store a bool. [`load_codex_rollout`] receives all four fields.
//!   [`load_canonical`] accepts [`SuppliedReaderLimits`], which has no
//!   fields: `Some` when limits were supplied, `None` when they were not.
//! - [`load_codex_rollout`] takes a secret tracker. `load.py` does not pass
//!   one. This module passes `None`.
//! - [`CanonicalSource::Stream`] has no reader. The stream name is passed.
//!   The reader is not an argument of that type.
//! - `str(Path)` matches the other adapter ports. A non-UTF-8 component is
//!   lossy. The file cap is `i64`. [`DEFAULT_MAX_FILE_BYTES`] is the
//!   `sesslint.io` literal `100 * 1024 * 1024`.

use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Cursor, Read};
use std::path::{Component, Path, PathBuf, PrefixComponent};

use model::finding::Finding;

use crate::canonical::{load_canonical, CanonicalSource, LoadCanonicalError};
use crate::claude_code::{
    load_claude_code, ClaudeFileLimit, ClaudeLoadSource, LoadClaudeCodeError,
};
use crate::codex_rollout::{
    load_codex_rollout, CodexLoadLimits, CodexLoadSource, LoadCodexRolloutError,
};
use crate::detect::{
    FORMAT_CANONICAL, FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT, FORMAT_OPENAI_AGENTS,
};
use crate::openai_agents::{
    load_openai_agents, EventList, LoadOpenAiAgentsError, MaxFileBytes, OpenAiAgentsSource,
};
use crate::source::SuppliedReaderLimits;

/// `sesslint.io.DEFAULT_MAX_FILE_BYTES` at the pin.
///
/// `100 * 1024 * 1024`. Copied here. This crate does not import `scan`.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// Python: `FORMAT_PROFILE_KEYS`.
///
/// Insertion order is the pin literal: claude, openai, codex, canonical.
/// This is not sorted. The ids are the [`crate::detect`] format constants.
pub const FORMAT_PROFILE_KEYS: [(&str, &str); 4] = [
    (FORMAT_CLAUDE_CODE, "claude"),
    (FORMAT_OPENAI_AGENTS, "openai"),
    (FORMAT_CODEX_ROLLOUT, "codex"),
    (FORMAT_CANONICAL, "canonical"),
];

/// Python `__all__`, in that order.
pub const ALL: [&str; 6] = [
    "FORMAT_PROFILE_KEYS",
    "is_vendor_format",
    "load_events_for_format",
    "load_vendor_events",
    "profile_key_for_format",
    "reload_vendor_bytes",
];

/// `ReaderLimits` fields this dispatcher can forward.
///
/// `None` at the call site means the loader's own default. A bool is not an
/// int, so these fields are `i64`. `max_records: None` means no record cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLimits {
    /// Python: `ReaderLimits.max_line_bytes`.
    pub max_line_bytes: i64,
    /// Python: `ReaderLimits.max_depth`.
    pub max_depth: i64,
    /// Python: `ReaderLimits.max_file_bytes`.
    pub max_file_bytes: i64,
    /// Python: `ReaderLimits.max_records`.
    pub max_records: Option<i64>,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 8 * 1024 * 1024,
            max_depth: 100,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_records: None,
        }
    }
}

/// `str | Path | io.BytesIO` as `load.py` passes it to a loader.
///
/// Each arm is converted to that loader's source enum. Raw `bytes` are not
/// an input of `load.py`. [`reload_vendor_bytes`] wraps them in a stream.
pub enum LoadSource<'a> {
    /// Python `str`.
    Str(&'a str),
    /// Python `pathlib.Path`.
    Path(&'a Path),
    /// Python `io.BytesIO` or another binary stream.
    ///
    /// `name` is `getattr(stream, "name", None)` when that value is text.
    /// `None` means the attribute is missing. [`SourceSnapshot`] always has
    /// a name. A bare `BytesIO` does not.
    Stream {
        /// Byte source. This is not closed.
        reader: &'a mut dyn Read,
        /// Stream `name`, when the attribute is text.
        name: Option<&'a str>,
    },
}

/// In-memory snapshot of a session file, labelled with its on-disk path.
///
/// Python: `SourceSnapshot`, a `BytesIO` whose `name` is `str(Path(path))`.
#[derive(Debug)]
pub struct SourceSnapshot {
    data: Cursor<Vec<u8>>,
    name: String,
}

impl SourceSnapshot {
    /// Buffer `data` and name it `str(Path(path))`.
    #[must_use]
    pub fn new(data: Vec<u8>, path: &Path) -> Self {
        Self {
            data: Cursor::new(data),
            name: python_path_text(path),
        }
    }

    /// Python attribute `name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Bytes stored in the buffer, independent of the read position.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.data.get_ref()
    }

    /// This snapshot as a named stream.
    pub fn as_source(&mut self) -> LoadSource<'_> {
        let Self { data, name } = self;
        LoadSource::Stream {
            reader: data,
            name: Some(name.as_str()),
        }
    }
}

impl Read for SourceSnapshot {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.data.read(buf)
    }
}

/// [`snapshot_input`] result: a path, or a named in-memory snapshot.
#[derive(Debug)]
pub enum SnapshotInput {
    /// `Path(path)`. Used when `data` is missing or longer than the cap.
    Path(PathBuf),
    /// [`SourceSnapshot`].
    Snapshot(SourceSnapshot),
}

impl SnapshotInput {
    /// Borrow this value as a [`LoadSource`].
    pub fn as_source(&mut self) -> LoadSource<'_> {
        match self {
            Self::Path(path) => LoadSource::Path(path.as_path()),
            Self::Snapshot(snapshot) => snapshot.as_source(),
        }
    }
}

/// `ValueError` from [`load_vendor_events`], or a vendor loader error.
#[derive(Debug)]
pub enum LoadVendorEventsError {
    /// `ValueError`: `Not a vendor format: {format!r}`.
    NotVendor(String),
    /// [`load_claude_code`] failed. Success does not produce events.
    Claude(LoadClaudeCodeError),
    /// [`load_openai_agents`] failed.
    OpenAi(LoadOpenAiAgentsError),
    /// [`load_codex_rollout`] failed.
    Codex(LoadCodexRolloutError),
}

impl fmt::Display for LoadVendorEventsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotVendor(message) => formatter.write_str(message),
            Self::Claude(error) => fmt::Display::fmt(error, formatter),
            Self::OpenAi(error) => fmt::Display::fmt(error, formatter),
            Self::Codex(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for LoadVendorEventsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NotVendor(_) => None,
            Self::Claude(error) => Some(error),
            Self::OpenAi(error) => Some(error),
            Self::Codex(error) => Some(error),
        }
    }
}

/// `ValueError` from [`load_events_for_format`], or a loader error.
#[derive(Debug)]
pub enum LoadEventsError {
    /// [`load_canonical`] stopped. Success does not produce events.
    Canonical(LoadCanonicalError),
    /// [`load_vendor_events`] failed.
    Vendor(LoadVendorEventsError),
    /// `ValueError`: `Unsupported format: {format!r}`.
    Unsupported(String),
}

impl fmt::Display for LoadEventsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => fmt::Display::fmt(error, formatter),
            Self::Vendor(error) => fmt::Display::fmt(error, formatter),
            Self::Unsupported(message) => formatter.write_str(message),
        }
    }
}

impl Error for LoadEventsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Vendor(error) => Some(error),
            Self::Unsupported(_) => None,
        }
    }
}

/// Return the profile `allowed_adapters` key for a resolved format id.
///
/// `None` stays `None`. A known id maps. An unknown id is returned unchanged.
#[must_use]
pub fn profile_key_for_format(format: Option<&str>) -> Option<&str> {
    let format = format?;
    for (id, key) in FORMAT_PROFILE_KEYS {
        if id == format {
            return Some(key);
        }
    }
    Some(format)
}

/// Return whether `format` names a vendor adapter.
///
/// True only for claude-code-jsonl, openai-agents, and codex-rollout.
#[must_use]
pub fn is_vendor_format(format: Option<&str>) -> bool {
    matches!(
        format,
        Some(FORMAT_CLAUDE_CODE) | Some(FORMAT_OPENAI_AGENTS) | Some(FORMAT_CODEX_ROLLOUT)
    )
}

/// Read a session file once so parse and hash can share the bytes.
///
/// Returns `None` for a non-file, a file larger than
/// [`DEFAULT_MAX_FILE_BYTES`], or an `OSError` from the later stat, open, or
/// read. A file at the cap is read. The read asks for at most cap + 1 bytes
/// and returns `None` when that read is longer than the cap.
#[must_use]
pub fn read_source_snapshot(path: &Path) -> Option<Vec<u8>> {
    read_source_snapshot_capped(path, DEFAULT_MAX_FILE_BYTES)
}

/// Loader input for `path`: a fresh stream over `data`, or the path.
///
/// `data` of `None`, or longer than [`DEFAULT_MAX_FILE_BYTES`], is the path.
/// A snapshot is named with `str(Path(path))`.
#[must_use]
pub fn snapshot_input(path: &Path, data: Option<&[u8]>) -> SnapshotInput {
    snapshot_input_capped(path, data, DEFAULT_MAX_FILE_BYTES)
}

/// Load events and findings for a vendor format id.
///
/// # Errors
///
/// `ValueError` when `format` is not a vendor id. Otherwise the error from
/// [`load_claude_code`], [`load_openai_agents`], or [`load_codex_rollout`].
/// Claude success is [`Infallible`](std::convert::Infallible), so that arm
/// does not return events.
pub fn load_vendor_events(
    source: LoadSource<'_>,
    format: Option<&str>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadVendorEventsError> {
    if format == Some(FORMAT_CLAUDE_CODE) {
        return load_claude(source, limits);
    }
    if format == Some(FORMAT_OPENAI_AGENTS) {
        return load_openai(source, limits);
    }
    if format == Some(FORMAT_CODEX_ROLLOUT) {
        return load_codex(source, limits);
    }
    Err(not_vendor(format))
}

/// Load events and findings for a supported format id.
///
/// Canonical is first. A vendor id goes to [`load_vendor_events`].
///
/// # Errors
///
/// The canonical or vendor loader error, or `ValueError` for an unsupported
/// id. Canonical success is [`Infallible`](std::convert::Infallible).
pub fn load_events_for_format(
    source: LoadSource<'_>,
    format: Option<&str>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadEventsError> {
    if format == Some(FORMAT_CANONICAL) {
        return load_canonical_source(source, limits);
    }
    if is_vendor_format(format) {
        return load_vendor_events(source, format, limits).map_err(LoadEventsError::Vendor);
    }
    Err(unsupported(format))
}

/// Re-load emitted vendor bytes through that adapter.
///
/// The bytes are an in-memory stream, not a path. Limits stay `None`.
///
/// # Errors
///
/// The [`load_vendor_events`] error for `format`.
pub fn reload_vendor_bytes(
    format: &str,
    data: &[u8],
) -> Result<(EventList, Vec<Finding>), LoadVendorEventsError> {
    let mut stream = Cursor::new(data);
    load_vendor_events(
        LoadSource::Stream {
            reader: &mut stream,
            name: None,
        },
        Some(format),
        None,
    )
}

fn read_source_snapshot_capped(path: &Path, max_file_bytes: i64) -> Option<Vec<u8>> {
    if !path.is_file() {
        return None;
    }
    let len = match retry_interrupted(|| fs::metadata(path)) {
        Ok(meta) => meta.len(),
        Err(_) => return None,
    };
    if u64_exceeds(len, max_file_bytes) {
        return None;
    }
    let mut file = match retry_interrupted(|| File::open(path)) {
        Ok(file) => file,
        Err(_) => return None,
    };
    read_bounded(&mut file, max_file_bytes).ok().flatten()
}

fn snapshot_input_capped(path: &Path, data: Option<&[u8]>, max_file_bytes: i64) -> SnapshotInput {
    match data {
        Some(bytes) if !usize_exceeds(bytes.len(), max_file_bytes) => {
            SnapshotInput::Snapshot(SourceSnapshot::new(bytes.to_vec(), path))
        }
        Some(_) | None => SnapshotInput::Path(path.to_path_buf()),
    }
}

fn load_claude(
    source: LoadSource<'_>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadVendorEventsError> {
    let limits = claude_limits(limits);
    let result = match source {
        LoadSource::Str(text) => load_claude_code(ClaudeLoadSource::Str(text), limits),
        LoadSource::Path(path) => {
            let text = python_path_text(path);
            load_claude_code(ClaudeLoadSource::PathLike(&text), limits)
        }
        LoadSource::Stream { reader, name } => {
            load_claude_code(ClaudeLoadSource::Stream { reader, name }, limits)
        }
    };
    without_events(result).map_err(LoadVendorEventsError::Claude)
}

fn load_openai(
    source: LoadSource<'_>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadVendorEventsError> {
    let limits = openai_limits(limits);
    let result = match source {
        LoadSource::Str(text) => {
            load_openai_agents(OpenAiAgentsSource::Path(Path::new(text)), limits)
        }
        LoadSource::Path(path) => load_openai_agents(OpenAiAgentsSource::Path(path), limits),
        LoadSource::Stream { reader, name } => {
            load_openai_agents(OpenAiAgentsSource::Stream { reader, name }, limits)
        }
    };
    result.map_err(LoadVendorEventsError::OpenAi)
}

fn load_codex(
    source: LoadSource<'_>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadVendorEventsError> {
    let limits = codex_limits(limits);
    let result = match source {
        LoadSource::Str(text) => load_codex_rollout(CodexLoadSource::Str(text), limits, None),
        LoadSource::Path(path) => load_codex_rollout(CodexLoadSource::Path(path), limits, None),
        LoadSource::Stream { reader, name } => {
            load_codex_rollout(CodexLoadSource::Stream { reader, name }, limits, None)
        }
    };
    result.map_err(LoadVendorEventsError::Codex)
}

fn load_canonical_source(
    source: LoadSource<'_>,
    limits: Option<LoadLimits>,
) -> Result<(EventList, Vec<Finding>), LoadEventsError> {
    let limits = canonical_limits(limits);
    let result = match source {
        LoadSource::Str(text) => load_canonical(CanonicalSource::Str(text), limits),
        LoadSource::Path(path) => {
            let text = python_path_text(path);
            load_canonical(CanonicalSource::PathLike(&text), limits)
        }
        LoadSource::Stream { reader: _, name } => {
            load_canonical(CanonicalSource::Stream { name }, limits)
        }
    };
    without_events(result).map_err(LoadEventsError::Canonical)
}

/// Success cannot carry events. The `Err` value is unchanged.
fn without_events<T, E>(result: Result<std::convert::Infallible, E>) -> Result<T, E> {
    match result {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}

fn claude_limits(limits: Option<LoadLimits>) -> Option<ClaudeFileLimit> {
    limits.map(|limits| ClaudeFileLimit {
        max_file_bytes: limits.max_file_bytes,
    })
}

fn openai_limits(limits: Option<LoadLimits>) -> Option<MaxFileBytes> {
    limits.map(|limits| MaxFileBytes::Int(limits.max_file_bytes))
}

fn codex_limits(limits: Option<LoadLimits>) -> Option<CodexLoadLimits> {
    limits.map(|limits| CodexLoadLimits {
        max_line_bytes: limits.max_line_bytes,
        max_depth: limits.max_depth,
        max_file_bytes: limits.max_file_bytes,
        max_records: limits.max_records,
    })
}

fn canonical_limits(limits: Option<LoadLimits>) -> Option<SuppliedReaderLimits> {
    limits.map(|_| SuppliedReaderLimits)
}

fn not_vendor(format: Option<&str>) -> LoadVendorEventsError {
    let rendered = python_format_repr(format);
    LoadVendorEventsError::NotVendor(format!("Not a vendor format: {rendered}"))
}

fn unsupported(format: Option<&str>) -> LoadEventsError {
    let rendered = python_format_repr(format);
    LoadEventsError::Unsupported(format!("Unsupported format: {rendered}"))
}

fn python_format_repr(format: Option<&str>) -> String {
    match format {
        None => String::from("None"),
        Some(text) => python_str_repr(text),
    }
}

fn u64_exceeds(len: u64, max_file_bytes: i64) -> bool {
    match u64::try_from(max_file_bytes) {
        Ok(max) => len > max,
        Err(_) => true,
    }
}

fn usize_exceeds(len: usize, max_file_bytes: i64) -> bool {
    u64_exceeds(u64::try_from(len).unwrap_or(u64::MAX), max_file_bytes)
}

fn bytes_to_read(max_file_bytes: i64) -> u64 {
    match max_file_bytes.checked_add(1) {
        Some(count) if count > 0 => u64::try_from(count).unwrap_or(u64::MAX),
        Some(_) => 0,
        None => u64::try_from(i64::MAX).map_or(u64::MAX, |value| value.saturating_add(1)),
    }
}

fn read_bounded(reader: &mut impl Read, max_file_bytes: i64) -> io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    reader
        .take(bytes_to_read(max_file_bytes))
        .read_to_end(&mut data)?;
    if usize_exceeds(data.len(), max_file_bytes) {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
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

/// `str(Path)`. Host separators stay. `.` and empty parts are dropped.
fn python_path_text(path: &Path) -> String {
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
    join_python_path(&prefix, rooted, &parts)
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

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{self, Cursor, Read};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        is_vendor_format, load_events_for_format, load_vendor_events, profile_key_for_format,
        python_path_text, read_bounded, read_source_snapshot, read_source_snapshot_capped,
        reload_vendor_bytes, snapshot_input, snapshot_input_capped, LoadEventsError, LoadLimits,
        LoadSource, LoadVendorEventsError, SnapshotInput, SourceSnapshot, ALL,
        DEFAULT_MAX_FILE_BYTES, FORMAT_PROFILE_KEYS,
    };
    use crate::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE as CANONICAL_TRACKER;
    use crate::claude_code::{
        LoadClaudeCodeError, OPEN_BYTE_SOURCE_UNAVAILABLE, SECRET_SCAN_TRACKER_UNAVAILABLE,
    };
    use crate::codex_rollout::{CodexTailCall, LoadCodexRolloutError};
    use crate::detect::{
        FORMAT_AUTO, FORMAT_CANONICAL, FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT,
        FORMAT_OPENAI_AGENTS,
    };
    use crate::openai_agents::{
        AgentsDocumentKind, FindingGate, LoadOpenAiAgentsError, SQLITE_MAGIC,
    };

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("sesslint-load-01-{label}-{n}"));
            fs::create_dir_all(&path).expect("scratch");
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

    struct Probe<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for Probe<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - self.pos);
            let Some(chunk) = self.data.get(self.pos..self.pos + n) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "probe range"));
            };
            let Some(dest) = buf.get_mut(..n) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "probe buffer"));
            };
            dest.copy_from_slice(chunk);
            self.pos += n;
            Ok(n)
        }
    }

    struct Boom;

    impl Read for Boom {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        }
    }

    fn limits(max_file_bytes: i64) -> LoadLimits {
        LoadLimits {
            max_file_bytes,
            ..LoadLimits::default()
        }
    }

    fn expect_snapshot(input: SnapshotInput) -> SourceSnapshot {
        match input {
            SnapshotInput::Snapshot(snapshot) => snapshot,
            SnapshotInput::Path(path) => panic!("snapshot, got {}", path.display()),
        }
    }

    fn expect_path(input: SnapshotInput) -> PathBuf {
        match input {
            SnapshotInput::Path(path) => path,
            SnapshotInput::Snapshot(_) => panic!("path, got snapshot"),
        }
    }

    #[test]
    fn format_profile_keys_keep_pin_order() {
        assert_eq!(
            FORMAT_PROFILE_KEYS,
            [
                (FORMAT_CLAUDE_CODE, "claude"),
                (FORMAT_OPENAI_AGENTS, "openai"),
                (FORMAT_CODEX_ROLLOUT, "codex"),
                (FORMAT_CANONICAL, "canonical"),
            ]
        );
        assert_eq!(FORMAT_PROFILE_KEYS[0].0, "claude-code-jsonl");
        assert_eq!(FORMAT_PROFILE_KEYS[1].0, "openai-agents");
        assert_eq!(FORMAT_PROFILE_KEYS[2].0, "codex-rollout");
        assert_eq!(FORMAT_PROFILE_KEYS[3].0, "canonical");
        assert!(FORMAT_PROFILE_KEYS[0].0 > FORMAT_PROFILE_KEYS[3].0);
        assert_eq!(
            ALL,
            [
                "FORMAT_PROFILE_KEYS",
                "is_vendor_format",
                "load_events_for_format",
                "load_vendor_events",
                "profile_key_for_format",
                "reload_vendor_bytes",
            ]
        );
    }

    #[test]
    fn profile_key_maps_known_ids_and_returns_unknown_unchanged() {
        assert_eq!(profile_key_for_format(None), None);
        assert_eq!(
            profile_key_for_format(Some(FORMAT_CLAUDE_CODE)),
            Some("claude")
        );
        assert_eq!(
            profile_key_for_format(Some(FORMAT_OPENAI_AGENTS)),
            Some("openai")
        );
        assert_eq!(
            profile_key_for_format(Some(FORMAT_CODEX_ROLLOUT)),
            Some("codex")
        );
        assert_eq!(
            profile_key_for_format(Some(FORMAT_CANONICAL)),
            Some("canonical")
        );
        let unknown = "unknown-fmt";
        let got = profile_key_for_format(Some(unknown)).expect("unknown");
        assert!(std::ptr::eq(got, unknown));
        assert_eq!(profile_key_for_format(Some(FORMAT_AUTO)), Some(FORMAT_AUTO));
    }

    #[test]
    fn is_vendor_format_is_only_the_three_vendors() {
        assert!(is_vendor_format(Some(FORMAT_CLAUDE_CODE)));
        assert!(is_vendor_format(Some(FORMAT_OPENAI_AGENTS)));
        assert!(is_vendor_format(Some(FORMAT_CODEX_ROLLOUT)));
        assert!(!is_vendor_format(Some(FORMAT_CANONICAL)));
        assert!(!is_vendor_format(None));
        assert!(!is_vendor_format(Some("unknown-fmt")));
        assert!(!is_vendor_format(Some(FORMAT_AUTO)));
    }

    #[test]
    fn default_file_limit_is_the_io_literal() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 104_857_600);
        assert_eq!(LoadLimits::default().max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(LoadLimits::default().max_line_bytes, 8 * 1024 * 1024);
        assert_eq!(LoadLimits::default().max_depth, 100);
        assert_eq!(LoadLimits::default().max_records, None);
    }

    #[test]
    fn read_source_snapshot_returns_the_file_bytes() {
        let scratch = Scratch::new("bytes");
        let path = scratch.child("session.bin");
        let body = b"a\xffb";
        fs::write(&path, body).expect("write");
        assert_eq!(read_source_snapshot(&path).expect("bytes"), body);
        let empty = scratch.child("empty.bin");
        fs::write(&empty, b"").expect("empty");
        assert_eq!(read_source_snapshot(&empty).expect("empty"), b"");
    }

    #[test]
    fn read_source_snapshot_is_none_for_a_non_file() {
        assert!(read_source_snapshot(Path::new("sesslint-load-01-missing")).is_none());
        let scratch = Scratch::new("dir");
        let directory = scratch.child("folder");
        fs::create_dir(&directory).expect("dir");
        assert!(read_source_snapshot(&directory).is_none());
        assert!(read_source_snapshot(Path::new("")).is_none());
    }

    #[test]
    fn read_source_snapshot_stat_gate_uses_the_cap() {
        let scratch = Scratch::new("cap");
        let path = scratch.child("sized.bin");
        fs::write(&path, b"abcde").expect("write");
        assert!(read_source_snapshot_capped(&path, 4).is_none());
        assert_eq!(
            read_source_snapshot_capped(&path, 5).expect("exact"),
            b"abcde"
        );
        assert_eq!(read_source_snapshot(&path).expect("default cap"), b"abcde");
    }

    #[test]
    fn read_bounded_stops_at_limit_plus_one() {
        let mut over = Probe {
            data: &[0_u8; 50],
            pos: 0,
        };
        assert!(read_bounded(&mut over, 4).expect("io").is_none());
        assert_eq!(over.pos, 5);
        let mut exact = Probe {
            data: &[1_u8; 4],
            pos: 0,
        };
        assert_eq!(
            read_bounded(&mut exact, 4).expect("io").expect("kept"),
            [1_u8; 4]
        );
        assert_eq!(exact.pos, 4);
        let mut five = Probe {
            data: &[2_u8; 5],
            pos: 0,
        };
        assert!(read_bounded(&mut five, 4).expect("io").is_none());
        assert_eq!(five.pos, 5);
    }

    #[test]
    fn read_bounded_oserror_stays_an_error() {
        let error = read_bounded(&mut Boom, 10).expect_err("oserror");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(windows)]
    #[test]
    fn exclusively_locked_file_returns_none() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let scratch = Scratch::new("lock");
        let path = scratch.child("locked.bin");
        fs::write(&path, b"abc").expect("write");
        let mut options = OpenOptions::new();
        options.read(true).share_mode(0);
        let _held = options.open(&path).expect("lock");
        assert!(path.is_file(), "stat still sees the file");
        assert!(File::open(&path).is_err(), "shared open fails");
        assert!(read_source_snapshot(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_returns_none() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("mode");
        let path = scratch.child("hidden.bin");
        fs::write(&path, b"abc").expect("write");
        let mut perms = fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&path, perms.clone()).expect("chmod");
        let opened = File::open(&path);
        let snapshot = read_source_snapshot(&path);
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).expect("restore");
        if opened.is_err() {
            assert!(snapshot.is_none());
        }
    }

    #[test]
    fn snapshot_input_returns_path_or_a_named_snapshot() {
        let path = Path::new("dir/file.jsonl");
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(expect_path(snapshot_input(path, None)), path);
        assert_eq!(
            expect_path(snapshot_input_capped(path, Some(b"abcd"), 3)),
            path
        );
        let kept = expect_snapshot(snapshot_input_capped(path, Some(b"abc"), 3));
        assert_eq!(kept.as_bytes(), b"abc");
        assert_eq!(kept.name(), format!("dir{sep}file.jsonl"));
        let empty = expect_snapshot(snapshot_input(Path::new("n"), Some(b"")));
        assert!(empty.as_bytes().is_empty());
        assert_eq!(empty.name(), "n");
        let dotted = expect_snapshot(snapshot_input(Path::new(""), Some(b"z")));
        assert_eq!(dotted.name(), ".");
        assert_eq!(python_path_text(Path::new("")), ".");
        assert_eq!(python_path_text(Path::new("./dir")), "dir");
        assert_eq!(
            python_path_text(Path::new("foo/../bar")),
            format!("foo{sep}..{sep}bar")
        );
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_name_uses_windows_path_text() {
        let snap = expect_snapshot(snapshot_input(Path::new("C:/nope/x"), Some(b"ab")));
        assert_eq!(snap.name(), r"C:\nope\x");
        assert_eq!(snap.as_bytes(), b"ab");
        assert_eq!(python_path_text(Path::new(r"C:foo")), "C:foo");
    }

    #[test]
    fn source_snapshot_reads_like_bytesio() {
        let mut snap = SourceSnapshot::new(b"xyz".to_vec(), Path::new("n"));
        let mut got = Vec::new();
        snap.read_to_end(&mut got).expect("read");
        assert_eq!(got, b"xyz");
        assert_eq!(snap.as_bytes(), b"xyz");
        assert_eq!(snap.name(), "n");
    }

    #[test]
    fn load_vendor_events_rejects_non_vendor_formats() {
        let none = load_vendor_events(LoadSource::Str("sesslint-load-01-missing"), None, None)
            .expect_err("none");
        assert_eq!(none.to_string(), "Not a vendor format: None");
        assert!(matches!(none, LoadVendorEventsError::NotVendor(_)));
        assert!(std::error::Error::source(&none).is_none());
        let canonical = load_vendor_events(
            LoadSource::Str("sesslint-load-01-missing"),
            Some(FORMAT_CANONICAL),
            None,
        )
        .expect_err("canonical");
        assert_eq!(canonical.to_string(), "Not a vendor format: 'canonical'");
        assert!(!canonical.to_string().contains("Session file not found"));
        let unknown = load_vendor_events(
            LoadSource::Str("sesslint-load-01-missing"),
            Some("nope"),
            None,
        )
        .expect_err("unknown");
        assert_eq!(unknown.to_string(), "Not a vendor format: 'nope'");
        let quoted = load_vendor_events(
            LoadSource::Str("sesslint-load-01-missing"),
            Some("it's"),
            None,
        )
        .expect_err("quoted");
        assert_eq!(quoted.to_string(), "Not a vendor format: \"it's\"");
    }

    #[test]
    fn load_events_for_format_rejects_unsupported_formats() {
        let none = load_events_for_format(LoadSource::Str("x"), None, None).expect_err("none");
        assert_eq!(none.to_string(), "Unsupported format: None");
        assert!(matches!(none, LoadEventsError::Unsupported(_)));
        assert!(std::error::Error::source(&none).is_none());
        let unknown =
            load_events_for_format(LoadSource::Str("x"), Some("nope"), None).expect_err("unknown");
        assert_eq!(unknown.to_string(), "Unsupported format: 'nope'");
        let auto = load_events_for_format(LoadSource::Str("x"), Some(FORMAT_AUTO), None)
            .expect_err("auto");
        assert_eq!(auto.to_string(), "Unsupported format: 'auto'");
        let quoted =
            load_events_for_format(LoadSource::Str("x"), Some("it's"), None).expect_err("quoted");
        assert_eq!(quoted.to_string(), "Unsupported format: \"it's\"");
    }

    #[test]
    fn canonical_stops_at_the_secret_scan_tracker() {
        let err = load_events_for_format(LoadSource::Str("x"), Some(FORMAT_CANONICAL), None)
            .expect_err("canonical");
        assert!(matches!(err, LoadEventsError::Canonical(_)));
        assert_eq!(err.to_string(), CANONICAL_TRACKER);
        assert!(!err.to_string().contains("Not a vendor format"));
        let with_limits = load_events_for_format(
            LoadSource::Str("x"),
            Some(FORMAT_CANONICAL),
            Some(limits(1)),
        )
        .expect_err("limits");
        assert_eq!(with_limits.to_string(), err.to_string());
        let source = std::error::Error::source(&err).expect("source");
        assert_eq!(source.to_string(), CANONICAL_TRACKER);
    }

    #[test]
    fn claude_seam_propagates_and_does_not_return_events() {
        let missing = load_vendor_events(
            LoadSource::Str("sesslint-load-01-missing"),
            Some(FORMAT_CLAUDE_CODE),
            None,
        )
        .expect_err("missing");
        assert!(matches!(
            missing,
            LoadVendorEventsError::Claude(LoadClaudeCodeError::NotFound(_))
        ));
        assert_eq!(
            missing.to_string(),
            "Session file not found: sesslint-load-01-missing"
        );
        let mut cursor = Cursor::new(b"missing/nope.json");
        let stream = load_vendor_events(
            LoadSource::Stream {
                reader: &mut cursor,
                name: None,
            },
            Some(FORMAT_CLAUDE_CODE),
            None,
        )
        .expect_err("stream");
        assert!(matches!(
            stream,
            LoadVendorEventsError::Claude(LoadClaudeCodeError::SecretScanTracker)
        ));
        assert_eq!(stream.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        let via = load_events_for_format(
            LoadSource::Str("sesslint-load-01-missing"),
            Some(FORMAT_CLAUDE_CODE),
            None,
        )
        .expect_err("via");
        assert!(matches!(
            via,
            LoadEventsError::Vendor(LoadVendorEventsError::Claude(
                LoadClaudeCodeError::NotFound(_)
            ))
        ));
        assert_eq!(via.to_string(), missing.to_string());
    }

    #[test]
    fn openai_error_and_empty_ok_are_the_loader_result() {
        let missing = load_vendor_events(
            LoadSource::Path(Path::new("sesslint-load-01-missing")),
            Some(FORMAT_OPENAI_AGENTS),
            None,
        )
        .expect_err("missing");
        assert!(matches!(
            missing,
            LoadVendorEventsError::OpenAi(LoadOpenAiAgentsError::NotFound(_))
        ));
        assert!(missing.to_string().starts_with("Session file not found:"));
        let mut cursor = Cursor::new(b"{");
        let tracked = load_vendor_events(
            LoadSource::Stream {
                reader: &mut cursor,
                name: None,
            },
            Some(FORMAT_OPENAI_AGENTS),
            None,
        )
        .expect_err("tracker");
        assert!(matches!(
            tracked,
            LoadVendorEventsError::OpenAi(LoadOpenAiAgentsError::SecretScanTracker(
                AgentsDocumentKind::Json
            ))
        ));
        let (events, findings) = reload_vendor_bytes(FORMAT_OPENAI_AGENTS, b"").expect("empty ok");
        assert!(events.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn codex_error_propagates() {
        let missing = load_vendor_events(
            LoadSource::Str("sesslint-load-01-missing"),
            Some(FORMAT_CODEX_ROLLOUT),
            None,
        )
        .expect_err("missing");
        assert!(matches!(
            missing,
            LoadVendorEventsError::Codex(LoadCodexRolloutError::NotFound(_))
        ));
        assert_eq!(
            missing.to_string(),
            "Session file not found: sesslint-load-01-missing"
        );
        let empty = reload_vendor_bytes(FORMAT_CODEX_ROLLOUT, b"").expect_err("empty");
        assert!(matches!(
            empty,
            LoadVendorEventsError::Codex(LoadCodexRolloutError::Tail(CodexTailCall::Finalize))
        ));
        assert_eq!(
            empty.to_string(),
            "sesslint.io.MalformedTailTracker.finalize is not available"
        );
        assert!(!empty.to_string().contains("Session file not found"));
        assert!(!matches!(
            empty,
            LoadVendorEventsError::Codex(LoadCodexRolloutError::SecretScanTracker)
        ));
    }

    #[test]
    fn reload_vendor_bytes_uses_a_stream_of_the_bytes() {
        let claude =
            reload_vendor_bytes(FORMAT_CLAUDE_CODE, b"missing/nope.json").expect_err("claude");
        assert!(matches!(
            claude,
            LoadVendorEventsError::Claude(LoadClaudeCodeError::SecretScanTracker)
        ));
        assert_eq!(claude.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        let openai = reload_vendor_bytes(FORMAT_OPENAI_AGENTS, SQLITE_MAGIC).expect_err("openai");
        let LoadVendorEventsError::OpenAi(error) = openai else {
            panic!("openai stream");
        };
        assert_eq!(error.finding_gate(), Some(FindingGate::Sqlite));
        assert_eq!(error.source_path(), Some("<stream>"));
        let rejected = reload_vendor_bytes(FORMAT_CANONICAL, b"{}").expect_err("canonical");
        assert_eq!(rejected.to_string(), "Not a vendor format: 'canonical'");
    }

    #[test]
    fn limits_reach_each_loader() {
        let scratch = Scratch::new("limits");
        let path = scratch.child("four.bin");
        fs::write(&path, b"abcd").expect("write");
        let too_big = load_vendor_events(
            LoadSource::Path(&path),
            Some(FORMAT_CLAUDE_CODE),
            Some(limits(1)),
        )
        .expect_err("too big");
        assert!(matches!(
            too_big,
            LoadVendorEventsError::Claude(LoadClaudeCodeError::FileTooLarge(_))
        ));
        assert_eq!(
            too_big.to_string(),
            "File size 4 bytes exceeds maximum limit (1 bytes)"
        );
        let under = load_vendor_events(LoadSource::Path(&path), Some(FORMAT_CLAUDE_CODE), None)
            .expect_err("under");
        assert!(matches!(
            under,
            LoadVendorEventsError::Claude(LoadClaudeCodeError::OpenByteSource)
        ));
        assert_eq!(under.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE);

        let mut cursor = Cursor::new(b"{}");
        let sized = load_vendor_events(
            LoadSource::Stream {
                reader: &mut cursor,
                name: None,
            },
            Some(FORMAT_OPENAI_AGENTS),
            Some(limits(1)),
        )
        .expect_err("openai size");
        let LoadVendorEventsError::OpenAi(error) = sized else {
            panic!("openai size gate");
        };
        assert_eq!(error.finding_gate(), Some(FindingGate::Size));
        assert!(error.document_kind().is_none());

        let mut codex_cursor = Cursor::new(b"x\n");
        let records = load_vendor_events(
            LoadSource::Stream {
                reader: &mut codex_cursor,
                name: None,
            },
            Some(FORMAT_CODEX_ROLLOUT),
            Some(LoadLimits {
                max_records: Some(0),
                ..LoadLimits::default()
            }),
        )
        .expect_err("max records");
        assert!(matches!(
            records,
            LoadVendorEventsError::Codex(LoadCodexRolloutError::MaxRecords(_))
        ));
        assert_eq!(records.to_string(), "Record count 1 exceeds limit of 0");
    }

    #[test]
    fn snapshot_stream_keeps_the_path_name() {
        let mut input = snapshot_input(Path::new(r"a\b"), Some(SQLITE_MAGIC));
        let err = load_vendor_events(input.as_source(), Some(FORMAT_OPENAI_AGENTS), None)
            .expect_err("named");
        let LoadVendorEventsError::OpenAi(error) = err else {
            panic!("named stream");
        };
        assert_eq!(error.finding_gate(), Some(FindingGate::Sqlite));
        assert_eq!(error.source_path(), Some("a/b"));
        assert_ne!(error.source_path(), Some("<bytes>"));
        assert_ne!(error.source_path(), Some("<stream>"));
    }
}
