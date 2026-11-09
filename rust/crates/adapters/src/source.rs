//! Source fingerprinting, immutability guarding, and concurrent-modification detection.
//!
//! Port of `src/sesslint/source.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–175.
//!
//! [`fingerprint_file`] and [`fingerprint_bytes`] are SHA-256 over raw bytes.
//! [`guard`] records the real path, size, mtime, and digest. [`verify`] checks
//! that snapshot. [`guarded`] runs a body and verifies on success.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `chunk_size` is `i64`. Python `int` is unbounded. A size that cannot be
//!   reserved is read in 64 KiB blocks. The digest does not depend on the
//!   block size. Rust `i64` has no `bool`, so `True` is not `1`.
//! - A Rust path has no lone surrogate. Non-Unicode paths are shown with
//!   `to_string_lossy`.
//! - mtime is the platform file timestamp: Unix `mtime` plus `mtime_nsec`,
//!   Windows FILETIME converted the way CPython builds `st_mtime_ns`. This
//!   module does not read `SystemTime`.
//! - `sesslint.io.ReaderLimits` and `sesslint.io.iter_events` are not in this
//!   crate. [`guarded_iter_events`] returns that fact. It does not invent
//!   `sesslint.io`.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use model::errors::SourceChangedError;
use sha2::{Digest, Sha256};

/// Python default for `fingerprint_file(..., chunk_size=65536)`.
const DEFAULT_CHUNK_SIZE: i64 = 65_536;

const DEFAULT_CHUNK_BYTES: usize = 65_536;

/// Stop a symlink cycle. Python's non-strict `realpath` also stops.
const REALPATH_SEEN_LIMIT: usize = 64;

/// `sesslint.io.ReaderLimits` is not ported into this crate.
pub const READER_LIMITS_UNAVAILABLE: &str = "sesslint.io.ReaderLimits is not available";

/// `sesslint.io.iter_events` is not ported into this crate.
pub const ITER_EVENTS_UNAVAILABLE: &str = "sesslint.io.iter_events is not available";

/// Witness that the caller already holds a `sesslint.io.ReaderLimits`.
///
/// This crate cannot name that type. The witness has no fields: nothing in
/// this module reads them before `iter_events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppliedReaderLimits;

/// Snapshot of a source file's identity and state.
///
/// Field order matches the Python dataclass: `path`, `sha256`, `size`,
/// `mtime_ns`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceGuard {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub mtime_ns: i128,
}

/// Failure from fingerprinting, guarding, or an unported `sesslint.io` name.
#[derive(Debug)]
pub enum SourceError {
    /// Python `ValueError`: `chunk_size` is not positive.
    InvalidChunkSize { chunk_size: i64 },
    /// Python `IsADirectoryError`: `Expected file, got directory`.
    IsADirectory { path: String },
    /// Python `FileNotFoundError` or `OSError` from open or stat.
    Io(IoPathError),
    /// Python `SourceChangedError`.
    Changed(SourceChangedError),
    /// A `sesslint.io` name this crate does not port.
    Unavailable(&'static str),
}

/// OSError text for a path, plus the underlying [`io::Error`].
#[derive(Debug)]
pub struct IoPathError {
    message: String,
    source: io::Error,
}

impl IoPathError {
    fn open(path: &Path, source: io::Error) -> Self {
        Self {
            message: format_open_error(path, &source),
            source,
        }
    }

    fn stat(path: &Path, source: io::Error) -> Self {
        Self {
            message: format_stat_error(path, &source),
            source,
        }
    }

    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: io::Error::new(io::ErrorKind::Unsupported, "st_mtime_ns"),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IoPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for IoPathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChunkSize { chunk_size } => {
                write!(formatter, "chunk_size must be positive, got {chunk_size}")
            }
            Self::IsADirectory { path } => {
                write!(formatter, "Expected file, got directory: {path}")
            }
            Self::Io(error) => formatter.write_str(&error.message),
            Self::Changed(error) => fmt::Display::fmt(error, formatter),
            Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl Error for SourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Changed(error) => Some(error),
            Self::InvalidChunkSize { .. } | Self::IsADirectory { .. } | Self::Unavailable(_) => {
                None
            }
        }
    }
}

/// Outcome of [`guarded`].
///
/// Python's context manager skips `verify` when the block raises.
/// [`GuardExit::Body`] is that path. [`GuardExit::Source`] is `guard` or
/// `verify`.
#[derive(Debug)]
pub enum GuardExit<E> {
    Source(SourceError),
    Body(E),
}

impl<E: fmt::Display> fmt::Display for GuardExit<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => fmt::Display::fmt(error, formatter),
            Self::Body(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl<E: Error + 'static> Error for GuardExit<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Body(error) => Some(error),
        }
    }
}

/// SHA-256 hex digest of a file, read in `chunk_size` blocks.
///
/// Python: `fingerprint_file(path, *, chunk_size=65536)`.
/// Pass [`DEFAULT_CHUNK_SIZE`] by using `65_536` for that default.
///
/// # Errors
///
/// `chunk_size <= 0` is `chunk_size must be positive, got {chunk_size}`.
/// A directory is `Expected file, got directory: {path}` using the path
/// argument, not its real path. A missing file or a read failure is the
/// Python `open()` OSError text.
pub fn fingerprint_file(path: &Path, chunk_size: i64) -> Result<String, SourceError> {
    if chunk_size <= 0 {
        return Err(SourceError::InvalidChunkSize { chunk_size });
    }
    if path.is_dir() {
        return Err(directory(path));
    }
    let mut file = File::open(path).map_err(|err| SourceError::Io(IoPathError::open(path, err)))?;
    let mut hasher = Sha256::new();
    let mut buf = chunk_buffer(chunk_size);
    loop {
        let read = read_chunk(&mut file, &mut buf)
            .map_err(|err| SourceError::Io(IoPathError::open(path, err)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex_lower(hasher.finalize().as_slice()))
}

/// SHA-256 hex digest of an in-memory buffer.
///
/// Python: `fingerprint_bytes`. The same bytes produce the same digest as
/// [`fingerprint_file`].
pub fn fingerprint_bytes(data: &[u8]) -> String {
    hex_lower(Sha256::digest(data).as_slice())
}

/// Snapshot `path` before processing.
///
/// Python: `guard`. The stored path is `os.path.realpath` (symlinks followed,
/// `\\?\` stripped when Python would strip it). The directory check uses that
/// real path. The error text keeps the original argument.
///
/// # Errors
///
/// A directory is `IsADirectory`. A missing path or a stat failure is the
/// Python `Path.stat` OSError. [`fingerprint_file`] errors propagate unchanged.
pub fn guard(path: &Path) -> Result<SourceGuard, SourceError> {
    let real_path = python_realpath(path);
    if real_path.is_dir() {
        return Err(directory(path));
    }
    let meta = fs::metadata(&real_path)
        .map_err(|err| SourceError::Io(IoPathError::stat(&real_path, err)))?;
    let digest = fingerprint_file(&real_path, DEFAULT_CHUNK_SIZE)?;
    let Some(mtime_ns) = file_mtime_ns(&meta) else {
        return Err(SourceError::Io(IoPathError::plain(
            "st_mtime_ns is not available on this platform",
        )));
    };
    Ok(SourceGuard {
        path: real_path,
        sha256: digest,
        size: meta.len(),
        mtime_ns,
    })
}

/// Check that `snapshot` still names the same bytes and metadata.
///
/// Python: `verify`. Stat failures become `SourceChangedError`. A later
/// [`fingerprint_file`] failure is returned as itself: Python only wraps the
/// `stat()` OSError.
///
/// # Errors
///
/// See the three `SourceChangedError` sentences in the Python source, or the
/// [`fingerprint_file`] errors when the hash read fails after a successful stat.
pub fn verify(snapshot: &SourceGuard) -> Result<(), SourceError> {
    let meta = match fs::metadata(&snapshot.path) {
        Ok(meta) => meta,
        Err(err) => return Err(changed_inaccessible(&snapshot.path, &err)),
    };
    let Some(mtime_ns) = file_mtime_ns(&meta) else {
        return Err(SourceError::Io(IoPathError::plain(
            "st_mtime_ns is not available on this platform",
        )));
    };
    if meta.len() != snapshot.size || mtime_ns != snapshot.mtime_ns {
        return Err(changed_metadata(snapshot, meta.len(), mtime_ns));
    }
    let current = fingerprint_file(&snapshot.path, DEFAULT_CHUNK_SIZE)?;
    if current != snapshot.sha256 {
        return Err(changed_digest(snapshot, &current));
    }
    Ok(())
}

/// Run `body`, then [`verify`], matching `@contextmanager` `guarded`.
///
/// `Ok` from `body` is verified. `Err` from `body` skips `verify`.
///
/// # Errors
///
/// [`GuardExit::Source`] is a [`guard`] or [`verify`] error.
/// [`GuardExit::Body`] is the body's error.
pub fn guarded<T, E>(
    path: &Path,
    body: impl FnOnce(&SourceGuard) -> Result<T, E>,
) -> Result<T, GuardExit<E>> {
    let snapshot = match guard(path) {
        Ok(snapshot) => snapshot,
        Err(error) => return Err(GuardExit::Source(error)),
    };
    let value = match body(&snapshot) {
        Ok(value) => value,
        Err(error) => return Err(GuardExit::Body(error)),
    };
    match verify(&snapshot) {
        Ok(()) => Ok(value),
        Err(error) => Err(GuardExit::Source(error)),
    }
}

/// Stream events from `path`, then verify the guard.
///
/// Python: `guarded_iter_events`. `limits == None` constructs `ReaderLimits()`
/// before [`guard`]. That class is not available, so this returns
/// [`READER_LIMITS_UNAVAILABLE`] and does not touch `path`.
///
/// `Some(SuppliedReaderLimits)` means the caller already built limits. This
/// runs [`guard`] (directory and missing-file errors included) and then
/// returns [`ITER_EVENTS_UNAVAILABLE`]. [`verify`] does not run: Python
/// verifies only after `iter_events` is exhausted, and that call does not start.
///
/// # Errors
///
/// [`READER_LIMITS_UNAVAILABLE`], [`ITER_EVENTS_UNAVAILABLE`], or a [`guard`]
/// error. This never yields `SessionEvent` or `Finding`.
pub fn guarded_iter_events(
    path: &Path,
    limits: Option<SuppliedReaderLimits>,
) -> Result<(), SourceError> {
    if limits.is_none() {
        return Err(SourceError::Unavailable(READER_LIMITS_UNAVAILABLE));
    }
    let snapshot = guard(path)?;
    let _snapshot = snapshot;
    Err(SourceError::Unavailable(ITER_EVENTS_UNAVAILABLE))
}

fn directory(path: &Path) -> SourceError {
    SourceError::IsADirectory {
        path: path_text(path),
    }
}

fn changed_inaccessible(path: &Path, err: &io::Error) -> SourceError {
    let text = path_text(path);
    let os_err = format_stat_error(path, err);
    SourceError::Changed(SourceChangedError::new(format!(
        "Source file inaccessible or removed during processing: {text} ({os_err})"
    )))
}

fn changed_metadata(snapshot: &SourceGuard, size: u64, mtime_ns: i128) -> SourceError {
    let text = path_text(&snapshot.path);
    SourceError::Changed(SourceChangedError::new(format!(
        "Source file metadata changed concurrently: {text} (expected size {}B mtime {}ns, got size {size}B mtime {mtime_ns}ns)",
        snapshot.size, snapshot.mtime_ns
    )))
}

fn changed_digest(snapshot: &SourceGuard, current: &str) -> SourceError {
    let text = path_text(&snapshot.path);
    SourceError::Changed(SourceChangedError::new(format!(
        "Source file content SHA-256 modified concurrently: {text} (expected {}, got {current})",
        snapshot.sha256
    )))
}

fn chunk_buffer(chunk_size: i64) -> Vec<u8> {
    let requested = usize::try_from(chunk_size).unwrap_or(DEFAULT_CHUNK_BYTES);
    let mut buf = Vec::new();
    if requested > 0 && buf.try_reserve_exact(requested).is_ok() {
        buf.resize(requested, 0);
        return buf;
    }
    vec![0_u8; DEFAULT_CHUNK_BYTES]
}

fn read_chunk(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn file_mtime_ns(meta: &fs::Metadata) -> Option<i128> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let secs = i128::from(meta.mtime());
        let nanos = i128::from(meta.mtime_nsec());
        Some(secs * 1_000_000_000 + nanos)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Some(filetime_to_unix_ns(meta.last_write_time()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        None
    }
}

#[cfg(windows)]
fn filetime_to_unix_ns(ticks: u64) -> i128 {
    /// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
    const WINDOWS_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    (i128::from(ticks) - WINDOWS_EPOCH_100NS) * 100
}

fn python_realpath(path: &Path) -> PathBuf {
    let mut seen = Vec::new();
    python_realpath_inner(path, &mut seen)
}

fn python_realpath_inner(path: &Path, seen: &mut Vec<PathBuf>) -> PathBuf {
    if let Some(device) = windows_nul(path) {
        return device;
    }
    let absolute = normalized_absolute(path);
    if let Some(canon) = existing_canonical(&absolute) {
        return canon;
    }
    if seen.len() >= REALPATH_SEEN_LIMIT || seen.iter().any(|item| same_path(item, &absolute)) {
        return absolute;
    }
    if let Some(target) = symlink_target(&absolute) {
        seen.push(absolute);
        return python_realpath_inner(&target, seen);
    }
    existing_ancestor(&absolute)
}

fn normalized_absolute(path: &Path) -> PathBuf {
    match std::path::absolute(path) {
        Ok(value) => lexical_normalize(&value),
        Err(_) => lexical_normalize(path),
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn existing_canonical(path: &Path) -> Option<PathBuf> {
    let canon = fs::canonicalize(path).ok()?;
    Some(prefer_non_verbatim(path, &canon))
}

fn prefer_non_verbatim(original: &Path, canon: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let original_text = original.to_string_lossy();
        if original_text.starts_with(r"\\?\") {
            return canon.to_path_buf();
        }
        let stripped = strip_verbatim_text(&canon.to_string_lossy());
        if let Ok(again) = fs::canonicalize(Path::new(&stripped)) {
            if again.as_path() == canon {
                return PathBuf::from(&stripped);
            }
        }
        canon.to_path_buf()
    }
    #[cfg(not(windows))]
    {
        let _ = original;
        canon.to_path_buf()
    }
}

#[cfg(windows)]
fn strip_verbatim_text(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return rest.to_owned();
    }
    text.to_owned()
}

fn existing_ancestor(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Some(mut canon) = existing_canonical(&current) {
            for name in tail.iter().rev() {
                canon.push(name);
            }
            return canon;
        }
        let Some(name) = current.file_name().map(OsString::from) else {
            return path.to_path_buf();
        };
        tail.push(name);
        if !current.pop() {
            return path.to_path_buf();
        }
    }
}

fn symlink_target(path: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    let target = fs::read_link(path).ok()?;
    if target.is_absolute() {
        Some(target)
    } else {
        let parent = path.parent().unwrap_or(Path::new(""));
        Some(parent.join(target))
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn windows_nul(path: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let normalized = lexical_normalize(path);
        if normalized.to_string_lossy().eq_ignore_ascii_case("nul") {
            return Some(PathBuf::from(r"\\.\NUL"));
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

fn format_open_error(path: &Path, err: &io::Error) -> String {
    let shown = python_str_repr(&path_text(path));
    let (code, message) = open_errno(err);
    format!("[Errno {code}] {message}: {shown}")
}

fn open_errno(err: &io::Error) -> (i32, String) {
    match err.kind() {
        io::ErrorKind::NotFound => (2, "No such file or directory".to_owned()),
        io::ErrorKind::PermissionDenied => (13, "Permission denied".to_owned()),
        io::ErrorKind::AlreadyExists => (17, "File exists".to_owned()),
        io::ErrorKind::InvalidInput => (22, "Invalid argument".to_owned()),
        io::ErrorKind::IsADirectory => (21, "Is a directory".to_owned()),
        _ => (err.raw_os_error().unwrap_or(0), os_strerror(err)),
    }
}

fn format_stat_error(path: &Path, err: &io::Error) -> String {
    let shown = python_str_repr(&path_text(path));
    #[cfg(windows)]
    {
        let code = err.raw_os_error().unwrap_or(0);
        let message = os_strerror(err);
        format!("[WinError {code}] {message}: {shown}")
    }
    #[cfg(not(windows))]
    {
        let code = err.raw_os_error().unwrap_or(0);
        let message = os_strerror(err);
        format!("[Errno {code}] {message}: {shown}")
    }
}

fn os_strerror(err: &io::Error) -> String {
    let mut text = err.to_string();
    if let Some(code) = err.raw_os_error() {
        let suffix = format!(" (os error {code})");
        if let Some(stripped) = text.strip_suffix(&suffix) {
            text = stripped.to_owned();
        }
    }
    if let Some(stripped) = text.strip_suffix('.') {
        text = stripped.to_owned();
    }
    text
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

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
            c if c == quote => {
                out.push('\\');
                out.push(quote);
            }
            c if python_repr_literal(c) => out.push(c),
            c if u32::from(c) < 0x100 => push_hex(&mut out, "\\x", u32::from(c), 2),
            c if u32::from(c) < 0x10000 => push_hex(&mut out, "\\u", u32::from(c), 4),
            c => push_hex(&mut out, "\\U", u32::from(c), 8),
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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = (value >> (shift * 4)) & 0x0f;
        let index = usize::try_from(nibble).unwrap_or(0);
        out.push(char::from(HEX[index]));
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        file_mtime_ns, fingerprint_bytes, fingerprint_file, guard, guarded, guarded_iter_events,
        path_text, python_realpath, python_str_repr, verify, GuardExit, SourceError, SourceGuard,
        SuppliedReaderLimits, ITER_EVENTS_UNAVAILABLE, READER_LIMITS_UNAVAILABLE,
    };

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SYNTHETIC: &[u8] = b"synthetic-source-01\n";

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("sesslint-source-{n}"));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_bytes(path: &Path, bytes: &[u8]) {
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    #[cfg(windows)]
    fn expect_stat_missing_file(path: &Path) -> String {
        format!(
            "[WinError 2] The system cannot find the file specified: {}",
            python_str_repr(&path_text(path))
        )
    }

    #[cfg(not(windows))]
    fn expect_stat_missing_file(path: &Path) -> String {
        format!(
            "[Errno 2] No such file or directory: {}",
            python_str_repr(&path_text(path))
        )
    }

    fn expect_open_missing(path: &Path) -> String {
        format!(
            "[Errno 2] No such file or directory: {}",
            python_str_repr(&path_text(path))
        )
    }

    #[test]
    fn fingerprint_bytes_matches_known_digests() {
        assert_eq!(fingerprint_bytes(b""), EMPTY_SHA);
        assert_eq!(fingerprint_bytes(b"abc"), ABC_SHA);
        assert_eq!(fingerprint_bytes(SYNTHETIC).len(), 64);
    }

    #[test]
    fn fingerprint_file_empty_and_stable() {
        let dir = TempDir::new();
        let file = dir.child("empty.bin");
        write_bytes(&file, b"");
        let first = fingerprint_file(&file, 65_536).unwrap();
        let second = fingerprint_file(&file, 65_536).unwrap();
        assert_eq!(first, EMPTY_SHA);
        assert_eq!(second, first);
    }

    #[test]
    fn fingerprint_file_matches_bytes_across_chunk_sizes() {
        let dir = TempDir::new();
        let file = dir.child("chunks.bin");
        let mut payload = vec![b'A'; 150_000];
        payload.extend(std::iter::repeat_n(b'B', 50_000));
        write_bytes(&file, &payload);
        let expected = fingerprint_bytes(&payload);
        assert_eq!(fingerprint_file(&file, 4096).unwrap(), expected);
        assert_eq!(fingerprint_file(&file, 65_536).unwrap(), expected);
        assert_eq!(fingerprint_file(&file, 1).unwrap(), expected);
    }

    #[test]
    fn fingerprint_file_rejects_non_positive_chunk_before_io() {
        let missing = Path::new("synthetic-missing-chunk.jsonl");
        let zero = fingerprint_file(missing, 0).unwrap_err();
        let negative = fingerprint_file(missing, -100).unwrap_err();
        assert_eq!(zero.to_string(), "chunk_size must be positive, got 0");
        assert_eq!(
            negative.to_string(),
            "chunk_size must be positive, got -100"
        );
        assert!(matches!(
            zero,
            SourceError::InvalidChunkSize { chunk_size: 0 }
        ));
    }

    #[test]
    fn fingerprint_file_directory_uses_the_given_path() {
        let err = fingerprint_file(Path::new("."), 65_536).unwrap_err();
        assert_eq!(err.to_string(), "Expected file, got directory: .");
    }

    #[test]
    fn fingerprint_file_missing_matches_open_oserror() {
        let dir = TempDir::new();
        let missing = dir.child("missing.jsonl");
        let weird = dir.child("sub").join("..").join("missing.jsonl");
        let err = fingerprint_file(&missing, 65_536).unwrap_err();
        assert_eq!(err.to_string(), expect_open_missing(&missing));
        let weird_err = fingerprint_file(&weird, 65_536).unwrap_err();
        assert_eq!(weird_err.to_string(), expect_open_missing(&weird));
        assert!(weird_err.to_string().contains(".."));
    }

    #[test]
    fn python_str_repr_escapes_backslashes_and_picks_quotes() {
        assert_eq!(python_str_repr(r"C:\a\b"), r"'C:\\a\\b'");
        assert_eq!(python_str_repr("it's"), "\"it's\"");
        assert_eq!(python_str_repr("a\nb"), "'a\\nb'");
    }

    #[test]
    fn guard_and_verify_clean_file() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, SYNTHETIC);
        let snapshot = guard(&file).unwrap();
        assert_eq!(snapshot.path, python_realpath(&file));
        assert!(snapshot.path.is_absolute());
        let canon = fs::canonicalize(&file).unwrap();
        let canon_text = path_text(&canon);
        #[cfg(windows)]
        let expected_path = canon_text
            .strip_prefix(r"\\?\")
            .unwrap_or(canon_text.as_str());
        #[cfg(not(windows))]
        let expected_path = canon_text.as_str();
        assert_eq!(path_text(&snapshot.path), expected_path);
        assert_eq!(snapshot.sha256, fingerprint_bytes(SYNTHETIC));
        assert_eq!(snapshot.size, SYNTHETIC.len() as u64);
        let meta = fs::metadata(&snapshot.path).unwrap();
        assert_eq!(snapshot.mtime_ns, file_mtime_ns(&meta).unwrap());
        assert!(snapshot.mtime_ns > 0);
        verify(&snapshot).unwrap();
        verify(&snapshot).unwrap();
    }

    #[test]
    fn guard_collapses_dotdot_to_the_existing_file() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, SYNTHETIC);
        let via = dir.child("sub").join("..").join("sample.bin");
        let snapshot = guard(&via).unwrap();
        assert_eq!(snapshot.path, guard(&file).unwrap().path);
        assert!(!path_text(&snapshot.path).contains(".."));
    }

    #[test]
    fn guard_directory_reports_the_original_path() {
        let err = guard(Path::new(".")).unwrap_err();
        assert_eq!(err.to_string(), "Expected file, got directory: .");
    }

    #[test]
    fn guard_missing_matches_stat_oserror() {
        let dir = TempDir::new();
        let missing = dir.child("missing.jsonl");
        let err = guard(&missing).unwrap_err();
        let resolved = python_realpath(&missing);
        assert_eq!(err.to_string(), expect_stat_missing_file(&resolved));
    }

    #[test]
    fn guard_missing_parent_uses_path_not_found_on_windows() {
        let dir = TempDir::new();
        let missing = dir.child("no-parent").join("missing.jsonl");
        let err = guard(&missing).unwrap_err().to_string();
        #[cfg(windows)]
        assert!(
            err.contains("[WinError 3] The system cannot find the path specified:"),
            "{err}"
        );
        #[cfg(not(windows))]
        assert!(
            err.contains("[Errno 2] No such file or directory:"),
            "{err}"
        );
    }

    #[test]
    fn verify_reports_metadata_when_bytes_are_appended() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"initial content\n");
        let snapshot = guard(&file).unwrap();
        write_bytes(&file, b"initial content\nappended line\n");
        let meta = fs::metadata(&snapshot.path).unwrap();
        let err = verify(&snapshot).unwrap_err();
        let expected = format!(
            "Source file metadata changed concurrently: {} (expected size {}B mtime {}ns, got size {}B mtime {}ns)",
            path_text(&snapshot.path),
            snapshot.size,
            snapshot.mtime_ns,
            meta.len(),
            file_mtime_ns(&meta).unwrap()
        );
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn verify_reports_digest_when_metadata_is_unchanged() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"ABCDEFGHIJ");
        let snapshot = guard(&file).unwrap();
        let forged = SourceGuard {
            sha256: "0".repeat(64),
            ..snapshot
        };
        let err = verify(&forged).unwrap_err();
        let expected = format!(
            "Source file content SHA-256 modified concurrently: {} (expected {}, got {})",
            path_text(&forged.path),
            forged.sha256,
            fingerprint_bytes(b"ABCDEFGHIJ")
        );
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn verify_same_length_rewrite_is_source_changed() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"ABCDEFGHIJ");
        let snapshot = guard(&file).unwrap();
        write_bytes(&file, b"KLMNOPQRST");
        let err = verify(&snapshot).unwrap_err().to_string();
        assert!(
            err.contains("Source file metadata changed concurrently")
                || err.contains("Source file content SHA-256 modified concurrently"),
            "{err}"
        );
    }

    #[test]
    fn verify_reports_removal() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"temp");
        let snapshot = guard(&file).unwrap();
        fs::remove_file(&file).unwrap();
        let err = verify(&snapshot).unwrap_err();
        let expected = format!(
            "Source file inaccessible or removed during processing: {} ({})",
            path_text(&snapshot.path),
            expect_stat_missing_file(&snapshot.path)
        );
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn guarded_verifies_when_the_body_succeeds() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"unmodified line\n");
        let size = guarded(&file, |snapshot| Ok::<_, &str>(snapshot.size)).unwrap();
        assert_eq!(size, fs::metadata(&file).unwrap().len());
    }

    #[test]
    fn guarded_verifies_a_mutation_made_by_the_body() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"original\n");
        let err = guarded(&file, |_| {
            write_bytes(&file, b"modified\n");
            Ok::<(), &str>(())
        })
        .unwrap_err();
        assert!(matches!(err, GuardExit::Source(_)));
        assert!(err.to_string().contains("Source file"));
    }

    #[test]
    fn guarded_skips_verify_when_the_body_fails() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, b"original\n");
        let snapshot = guard(&file).unwrap();
        let err = guarded(&file, |_| {
            write_bytes(&file, b"modified-body\n");
            Err::<(), &str>("body-failed")
        })
        .unwrap_err();
        assert!(matches!(err, GuardExit::Body("body-failed")));
        assert_eq!(err.to_string(), "body-failed");
        assert!(verify(&snapshot).is_err());
    }

    #[test]
    fn guarded_iter_events_omitted_limits_stop_before_guard() {
        let missing = Path::new("synthetic-limits-missing.jsonl");
        let err = guarded_iter_events(missing, None).unwrap_err();
        assert_eq!(err.to_string(), READER_LIMITS_UNAVAILABLE);
        assert!(matches!(
            err,
            SourceError::Unavailable(READER_LIMITS_UNAVAILABLE)
        ));
        let directory = guarded_iter_events(Path::new("."), None).unwrap_err();
        assert_eq!(directory.to_string(), READER_LIMITS_UNAVAILABLE);
    }

    #[test]
    fn guarded_iter_events_supplied_limits_guard_then_stop() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        write_bytes(&file, SYNTHETIC);
        let err = guarded_iter_events(&file, Some(SuppliedReaderLimits)).unwrap_err();
        assert_eq!(err.to_string(), ITER_EVENTS_UNAVAILABLE);

        let directory = guarded_iter_events(dir.path(), Some(SuppliedReaderLimits)).unwrap_err();
        assert_eq!(
            directory.to_string(),
            format!("Expected file, got directory: {}", path_text(dir.path()))
        );

        let missing = dir.child("missing.jsonl");
        let missing_err = guarded_iter_events(&missing, Some(SuppliedReaderLimits)).unwrap_err();
        let resolved = python_realpath(&missing);
        assert_eq!(missing_err.to_string(), expect_stat_missing_file(&resolved));
    }

    #[test]
    fn symlink_to_file_guards_the_target() {
        let dir = TempDir::new();
        let file = dir.child("sample.bin");
        let link = dir.child("alias.bin");
        write_bytes(&file, SYNTHETIC);
        if let Err(err) = symlink_file(&file, &link) {
            assert!(
                err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1314),
                "{err}"
            );
            return;
        }
        let via_link = guard(&link).unwrap();
        let direct = guard(&file).unwrap();
        assert_eq!(via_link.path, direct.path);
        assert_eq!(via_link.sha256, direct.sha256);
        assert_eq!(via_link.size, direct.size);
    }

    #[cfg(windows)]
    fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(unix)]
    fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(not(any(unix, windows)))]
    fn symlink_file(_target: &Path, _link: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink",
        ))
    }
}
