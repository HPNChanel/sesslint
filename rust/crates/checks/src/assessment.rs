//! One bounded source snapshot for checking and repair previews.
//!
//! Port of `src/sesslint/assessment.py` lines 1–119
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`assess_source`] validates the byte cap, rejects a non-regular file, and
//! may stat and read a regular file. It then stops. `sesslint.api._check_impl`
//! is not in this crate. Display is [`CHECK_IMPL_UNAVAILABLE`].
//!
//! [`SourceAssessment::unchanged`] rehashes a snapshot the caller already
//! holds. Metadata alone is not proof. The digest is SHA-256.
//!
//! # Recorded gaps
//!
//! * A bool is not an int. [`MaxFileBytes::Bool`] is a `ValueError` before
//!   any `stat`. `True` is not `1`. `False` is not `0`.
//! * Python `int` is unbounded. The cap is `i64`. [`DEFAULT_MAX_FILE_BYTES`]
//!   fits. A larger integer is not representable here.
//! * Windows `MetadataExt::file_index` and `volume_serial_number` are
//!   unstable on Rust 1.91, and this crate forbids `unsafe`. `st_dev` and
//!   `st_ino` are `0` on non-Unix. `st_size` and `st_mtime_ns` still compare.
//! * `sesslint.report.Report` and `SessionEvent` are not constructed.
//!   [`assess_source`] does not return [`SourceAssessment`].
//! * A missing path keeps Rust's [`std::io::Error`]. The non-regular file
//!   uses the pin sentence [`TRIAGE_REQUIRES_REGULAR_FILE`].

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Python `sesslint.io.DEFAULT_MAX_FILE_BYTES` (`100 * 1024 * 1024`, 100 MB).
///
/// Copied from the pin blob `src/sesslint/io.py`. This crate does not depend
/// on an io crate.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// `sesslint.api._check_impl` is not available in this crate.
pub const CHECK_IMPL_UNAVAILABLE: &str = "sesslint.api._check_impl is not available";

/// Python `ValueError` for a non-positive or non-int cap.
pub const MAX_FILE_BYTES_POSITIVE: &str = "max_file_bytes must be a positive integer";

/// Python `OSError` when `stat.S_ISREG` is false.
pub const TRIAGE_REQUIRES_REGULAR_FILE: &str = "Triage requires a regular file";

/// Python `stream.read(min(65536, remaining))` in `unchanged`.
const READ_CHUNK: usize = 65_536;

/// Python `max_file_bytes`.
///
/// [`MaxFileBytes::Bool`] is not an int and is not used as `0` or `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxFileBytes {
    /// Python `int`. Not a bool.
    Int(i64),
    /// Python `bool`. Not an int.
    Bool(bool),
}

/// `(st_dev, st_ino, st_size, st_mtime_ns)` from Python `_identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// `st_dev`. `0` when the platform cannot report it without unstable APIs.
    pub dev: u64,
    /// `st_ino`. `0` when the platform cannot report it without unstable APIs.
    pub ino: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_mtime_ns`.
    pub mtime_ns: i128,
}

/// Fields of Python `SourceAssessment` that do not require `Report` or events.
///
/// `source_fingerprint` is `report.source_fingerprint`. This crate does not
/// build a `Report` and does not store events. [`assess_source`] does not
/// return this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAssessment {
    /// Path that was assessed.
    pub path: PathBuf,
    /// `Report.source_fingerprint`. Hex text, compared exactly.
    pub source_fingerprint: String,
    /// Adapter name captured with the events. No events are stored here.
    pub format: Option<String>,
    /// Profile name passed to the check pipeline.
    pub profile: String,
    /// `(st_dev, st_ino, st_size, st_mtime_ns)` at the open.
    pub identity: FileIdentity,
    /// Python `readable_snapshot`. `false` skips the rehash.
    pub readable_snapshot: bool,
}

impl SourceAssessment {
    /// Bounded rehash. Metadata alone cannot prove the bytes are unchanged.
    ///
    /// Python `SourceAssessment.unchanged`. A snapshot that was not readable
    /// returns `false` and does not open the path. Any `OSError` returns
    /// `false`. The digest is lowercase SHA-256 of exactly `identity.size`
    /// bytes, compared to [`Self::source_fingerprint`].
    #[must_use]
    pub fn unchanged(&self) -> bool {
        if !self.readable_snapshot {
            return false;
        }
        self.prove_unchanged().unwrap_or(false)
    }

    fn prove_unchanged(&self) -> io::Result<bool> {
        if identity_from_meta(&fs::metadata(&self.path)?)? != self.identity {
            return Ok(false);
        }
        let mut file = File::open(&self.path)?;
        if identity_from_meta(&file.metadata()?)? != self.identity {
            return Ok(false);
        }
        let Some(digest) = hash_exact(&mut file, self.identity.size)? else {
            return Ok(false);
        };
        if identity_from_meta(&file.metadata()?)? != self.identity {
            return Ok(false);
        }
        let again = identity_from_meta(&fs::metadata(&self.path)?)?;
        Ok(again == self.identity && digest == self.source_fingerprint)
    }
}

/// Failure from [`assess_source`].
///
/// [`Self::MaxFileBytes`] is Python `ValueError`. [`Self::NotRegular`] and
/// [`Self::Io`] are Python `OSError`. [`Self::CheckImpl`] is the missing
/// pipeline.
#[derive(Debug)]
pub enum AssessmentError {
    /// `max_file_bytes must be a positive integer`.
    MaxFileBytes,
    /// `Triage requires a regular file`.
    NotRegular,
    /// `stat`, `open`, or `read` failed.
    Io(io::Error),
    /// `sesslint.api._check_impl` is not available.
    CheckImpl,
}

impl fmt::Display for AssessmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxFileBytes => formatter.write_str(MAX_FILE_BYTES_POSITIVE),
            Self::NotRegular => formatter.write_str(TRIAGE_REQUIRES_REGULAR_FILE),
            Self::Io(source) => fmt::Display::fmt(source, formatter),
            Self::CheckImpl => formatter.write_str(CHECK_IMPL_UNAVAILABLE),
        }
    }
}

impl Error for AssessmentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::MaxFileBytes | Self::NotRegular | Self::CheckImpl => None,
        }
    }
}

impl From<io::Error> for AssessmentError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Read a regular file once, then stop before `sesslint.api._check_impl`.
///
/// Python `assess_source`. `format` and `profile` are the keyword-only
/// arguments. Rust has no defaults: pass `None`, `"neutral"`, and
/// `MaxFileBytes::Int(DEFAULT_MAX_FILE_BYTES)` for the Python defaults.
///
/// A bool or a non-positive cap is [`AssessmentError::MaxFileBytes`] and does
/// not stat. A path that is not a regular file is
/// [`AssessmentError::NotRegular`] before the pipeline. A regular file is
/// opened. When `st_size` is within the cap, at most `max_file_bytes + 1`
/// bytes are read. Oversized paths are not read. Either way this then returns
/// [`AssessmentError::CheckImpl`] and does not build a [`SourceAssessment`],
/// a `Report`, or events.
///
/// # Errors
///
/// [`AssessmentError::MaxFileBytes`], [`AssessmentError::NotRegular`],
/// [`AssessmentError::Io`], or [`AssessmentError::CheckImpl`]. Success is
/// [`Infallible`].
pub fn assess_source(
    path: impl AsRef<Path>,
    format: Option<&str>,
    profile: &str,
    max_file_bytes: MaxFileBytes,
) -> Result<Infallible, AssessmentError> {
    let limit = positive_limit(max_file_bytes)?;
    let target = path.as_ref();
    let meta = fs::metadata(target)?;
    if !meta.is_file() {
        return Err(AssessmentError::NotRegular);
    }
    let mut file = File::open(target)?;
    let before = identity_from_meta(&file.metadata()?)?;
    let data = if exceeds(before.size, limit) {
        None
    } else {
        Some(read_at_most(&mut file, read_cap(limit))?)
    };
    let after = identity_from_meta(&file.metadata()?)?;
    // Arguments of `_check_impl`, including the bounded read. That call is
    // not available. Nothing here becomes a `Report` or a list of events.
    let _for_check_impl = (format, profile, limit, before, after, data);
    Err(AssessmentError::CheckImpl)
}

fn positive_limit(max_file_bytes: MaxFileBytes) -> Result<i64, AssessmentError> {
    match max_file_bytes {
        MaxFileBytes::Int(value) if value > 0 => Ok(value),
        MaxFileBytes::Int(_) | MaxFileBytes::Bool(_) => Err(AssessmentError::MaxFileBytes),
    }
}

fn identity_from_meta(meta: &fs::Metadata) -> io::Result<FileIdentity> {
    let mtime_ns = file_mtime_ns(meta).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "st_mtime_ns is not available on this platform",
        )
    })?;
    let (dev, ino) = dev_ino(meta);
    Ok(FileIdentity {
        dev,
        ino,
        size: meta.len(),
        mtime_ns,
    })
}

fn dev_ino(meta: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        (0, 0)
    }
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

fn exceeds(size: u64, limit: i64) -> bool {
    let Ok(limit) = u64::try_from(limit) else {
        return true;
    };
    size > limit
}

fn read_cap(limit: i64) -> u64 {
    let Ok(limit) = u64::try_from(limit) else {
        return 1;
    };
    limit.saturating_add(1)
}

fn read_at_most(file: &mut File, cap: u64) -> io::Result<Vec<u8>> {
    let mut limited = file.take(cap);
    let mut data = Vec::new();
    limited.read_to_end(&mut data)?;
    Ok(data)
}

fn hash_exact(file: &mut File, size: u64) -> io::Result<Option<String>> {
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buf = [0_u8; READ_CHUNK];
    while remaining > 0 {
        let want = chunk_want(remaining, buf.len());
        let read = read_chunk(file, &mut buf[..want])?;
        if read == 0 {
            return Ok(None);
        }
        hasher.update(&buf[..read]);
        let read_len = u64_from_usize(read);
        if read_len > remaining {
            return Ok(None);
        }
        remaining -= read_len;
    }
    if read_chunk(file, &mut buf[..1])? != 0 {
        return Ok(None);
    }
    Ok(Some(hex_encode(hasher.finalize().as_slice())))
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

fn chunk_want(remaining: u64, buf_len: usize) -> usize {
    let cap = remaining.min(u64_from_usize(buf_len));
    usize::try_from(cap).unwrap_or(buf_len)
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        out.push(char::from(HEX[high]));
        out.push(char::from(HEX[low]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest, Sha256};

    use super::{
        assess_source, hex_encode, identity_from_meta, AssessmentError, FileIdentity, MaxFileBytes,
        SourceAssessment, CHECK_IMPL_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES, MAX_FILE_BYTES_POSITIVE,
        TRIAGE_REQUIRES_REGULAR_FILE,
    };

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sesslint-assess-{}-{n}", std::process::id()));
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

    fn write_bytes(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
    }

    fn assert_value_error(err: &AssessmentError) {
        assert!(matches!(err, AssessmentError::MaxFileBytes));
        assert_eq!(err.to_string(), "max_file_bytes must be a positive integer");
        assert_eq!(err.to_string(), MAX_FILE_BYTES_POSITIVE);
        assert!(Error::source(err).is_none());
    }

    fn assert_check_impl(err: &AssessmentError) {
        assert!(matches!(err, AssessmentError::CheckImpl));
        assert_eq!(err.to_string(), "sesslint.api._check_impl is not available");
        assert_eq!(err.to_string(), CHECK_IMPL_UNAVAILABLE);
        assert!(Error::source(err).is_none());
    }

    fn stop(path: &Path, format: Option<&str>, limit: MaxFileBytes) -> AssessmentError {
        match assess_source(path, format, "neutral", limit) {
            Ok(never) => match never {},
            Err(err) => err,
        }
    }

    fn sealed(path: &Path, fingerprint: &str, readable: bool) -> SourceAssessment {
        let identity = if path.is_file() {
            identity_from_meta(&fs::metadata(path).unwrap()).unwrap()
        } else {
            FileIdentity {
                dev: 0,
                ino: 0,
                size: 0,
                mtime_ns: 0,
            }
        };
        SourceAssessment {
            path: path.to_path_buf(),
            source_fingerprint: fingerprint.to_owned(),
            format: None,
            profile: "neutral".to_owned(),
            identity,
            readable_snapshot: readable,
        }
    }

    #[test]
    fn default_max_file_bytes_matches_the_pin() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 104_857_600);
    }

    #[test]
    fn bool_true_is_not_an_int_and_does_not_stat() {
        let scratch = Scratch::new();
        let err = stop(&scratch.path, None, MaxFileBytes::Bool(true));
        assert_value_error(&err);
    }

    #[test]
    fn bool_false_on_a_missing_path_does_not_stat() {
        let scratch = Scratch::new();
        let err = stop(&scratch.child("missing"), None, MaxFileBytes::Bool(false));
        assert_value_error(&err);
    }

    #[test]
    fn non_positive_limit_is_value_error_before_stat() {
        let scratch = Scratch::new();
        let missing = scratch.child("missing");
        assert_value_error(&stop(&missing, None, MaxFileBytes::Int(0)));
        assert_value_error(&stop(&missing, None, MaxFileBytes::Int(-1)));
        assert_value_error(&stop(&scratch.path, None, MaxFileBytes::Int(i64::MIN)));
    }

    #[test]
    fn directory_is_the_pin_oserror_before_check_impl() {
        let scratch = Scratch::new();
        let err = stop(
            &scratch.path,
            None,
            MaxFileBytes::Int(DEFAULT_MAX_FILE_BYTES),
        );
        assert!(matches!(err, AssessmentError::NotRegular));
        assert_eq!(err.to_string(), "Triage requires a regular file");
        assert_eq!(err.to_string(), TRIAGE_REQUIRES_REGULAR_FILE);
        assert!(Error::source(&err).is_none());
        assert!(!err.to_string().contains("is not available"));
    }

    #[test]
    fn missing_file_is_an_os_error() {
        let scratch = Scratch::new();
        let missing = scratch.child("missing");
        let err = stop(&missing, None, MaxFileBytes::Int(DEFAULT_MAX_FILE_BYTES));
        match &err {
            AssessmentError::Io(source) => assert_eq!(source.kind(), ErrorKind::NotFound),
            other => panic!("expected io error, got {other:?}"),
        }
        assert_ne!(err.to_string(), TRIAGE_REQUIRES_REGULAR_FILE);
        assert_ne!(err.to_string(), CHECK_IMPL_UNAVAILABLE);
        assert!(Error::source(&err).is_some());
    }

    #[test]
    fn regular_file_stops_at_check_impl_without_a_source_assessment() {
        let scratch = Scratch::new();
        let path = scratch.child("short");
        write_bytes(&path, b"abcd");
        let err = stop(&path, None, MaxFileBytes::Int(4));
        assert_check_impl(&err);
        let text = path.to_str().unwrap();
        let err = match assess_source(text, Some("canonical"), "neutral", MaxFileBytes::Int(8)) {
            Ok(never) => match never {},
            Err(err) => err,
        };
        assert_check_impl(&err);
    }

    #[test]
    fn unknown_format_and_oversized_file_still_stop() {
        let scratch = Scratch::new();
        let path = scratch.child("wide");
        write_bytes(&path, b"xy");
        let err = stop(&path, Some("not-a-format"), MaxFileBytes::Int(1));
        assert_check_impl(&err);
        let err = stop(&path, None, MaxFileBytes::Int(i64::MAX));
        assert_check_impl(&err);
        let empty = scratch.child("empty");
        write_bytes(&empty, b"");
        assert_check_impl(&stop(&empty, None, MaxFileBytes::Int(1)));
    }

    #[test]
    fn unchanged_skips_io_when_the_snapshot_was_not_readable() {
        let scratch = Scratch::new();
        let missing = scratch.child("missing");
        let item = sealed(&missing, EMPTY_SHA, false);
        assert!(!item.unchanged());
    }

    #[test]
    fn unchanged_hashes_empty_and_abc_with_sha256() {
        let scratch = Scratch::new();
        let empty = scratch.child("empty");
        write_bytes(&empty, b"");
        assert!(sealed(&empty, EMPTY_SHA, true).unchanged());
        let upper = EMPTY_SHA.to_ascii_uppercase();
        assert!(!sealed(&empty, &upper, true).unchanged());

        let abc = scratch.child("abc");
        write_bytes(&abc, b"abc");
        assert!(sealed(&abc, ABC_SHA, true).unchanged());
        assert!(!sealed(&abc, EMPTY_SHA, true).unchanged());
    }

    #[test]
    fn unchanged_is_false_when_the_file_changes_or_disappears() {
        let scratch = Scratch::new();
        let path = scratch.child("body");
        write_bytes(&path, b"abc");
        let item = sealed(&path, ABC_SHA, true);
        assert!(item.unchanged());
        write_bytes(&path, b"abcd");
        assert!(!item.unchanged());
        fs::remove_file(&path).unwrap();
        assert!(!item.unchanged());
    }

    #[test]
    fn unchanged_hashes_across_the_64kib_chunk() {
        let scratch = Scratch::new();
        for len in [65_536_usize, 65_537_usize] {
            let path = scratch.child(&format!("chunk-{len}"));
            let bytes = vec![b'a'; len];
            write_bytes(&path, &bytes);
            let fingerprint = hex_encode(Sha256::digest(&bytes).as_slice());
            assert_eq!(fingerprint.len(), 64);
            assert!(sealed(&path, &fingerprint, true).unchanged());
            assert!(!sealed(&path, ABC_SHA, true).unchanged());
        }
    }
}
