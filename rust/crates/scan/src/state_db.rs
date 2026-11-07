//! Codex `state_*.sqlite` registry reader — bounded, read-only (T-05).
//!
//! Port of `src/sesslint/state_db.py` lines 1–223
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! `rollout_uuid_from_name` and `is_state_db_name` follow the pinned functions.
//! `read_codex_state` runs the symlink, file, and size checks, then stops before
//! `sqlite3.connect`. This crate does not open a database and does not link the
//! report crate. The migration-skip path that would call `short_hash` stops
//! with [`ShortHashUnavailable`].

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// Python: `MAX_STATE_DB_BYTES = 256 * 1024 * 1024`.
pub const MAX_STATE_DB_BYTES: u64 = 256 * 1024 * 1024;

/// Python: `MAX_STATE_ROWS = 1_000_000`.
pub const MAX_STATE_ROWS: i64 = 1_000_000;

/// Python: `MAX_STATE_QUERY_STEPS = 50_000_000`.
pub const MAX_STATE_QUERY_STEPS: i64 = 50_000_000;

/// Python: `STATE_DB_GLOB = "state_*.sqlite"`.
pub const STATE_DB_GLOB: &str = "state_*.sqlite";

/// Python keyword default for `read_codex_state(..., *, immutable=False)`.
pub const DEFAULT_IMMUTABLE: bool = false;

/// Columns the reader may touch on `threads`.
///
/// Python: `_THREADS_COLS`. Title, name, preview, and other content columns
/// are outside this allowlist.
pub const THREADS_COLS: [&str; 4] = ["id", "rollout_path", "thread_source", "archived"];

/// Python: `_SPAWN_COLS`.
pub const SPAWN_COLS: [&str; 2] = ["parent_thread_id", "child_thread_id"];

/// Python: `_SKIP_COLS`.
pub const SKIP_COLS: [&str; 1] = ["skip_reason"];

const UUID_WIDTH: usize = 36;
const UUID_GROUP_WIDTHS: [usize; 5] = [8, 4, 4, 4, 12];

/// `sqlite3.connect` is not in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteConnectUnavailable;

impl fmt::Display for SqliteConnectUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sqlite3.connect is not available")
    }
}

impl Error for SqliteConnectUnavailable {}

/// `sesslint.report.short_hash` is not in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortHashUnavailable;

impl fmt::Display for ShortHashUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sesslint.report.short_hash is not available")
    }
}

impl Error for ShortHashUnavailable {}

/// Failure from [`read_codex_state`] after the pure path checks, or from
/// building the read-only URI those checks lead to.
#[derive(Debug)]
pub enum ReadCodexStateError {
    /// Python reached `sqlite3.connect`. The connection is not opened.
    SqliteConnect,
    /// `Path.absolute()` could not read the working directory.
    WorkingDirectory(io::Error),
    /// Python `ValueError` from `Path.as_uri` on a relative path.
    RelativePath,
    /// The path is not Unicode, so it cannot be quoted as a file URI.
    UndecodablePath,
}

impl fmt::Display for ReadCodexStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqliteConnect => formatter.write_str("sqlite3.connect is not available"),
            Self::WorkingDirectory(err) => write!(formatter, "{err}"),
            Self::RelativePath => {
                formatter.write_str("relative path can't be expressed as a file URI")
            }
            Self::UndecodablePath => formatter.write_str("path is not valid Unicode"),
        }
    }
}

impl Error for ReadCodexStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WorkingDirectory(err) => Some(err),
            Self::SqliteConnect | Self::RelativePath | Self::UndecodablePath => None,
        }
    }
}

impl From<SqliteConnectUnavailable> for ReadCodexStateError {
    fn from(_err: SqliteConnectUnavailable) -> Self {
        Self::SqliteConnect
    }
}

/// Structural membership snapshot of one `state_*.sqlite` registry.
///
/// `parse_ok` is false when the file cannot be interpreted as a Codex
/// registry. `schema_note` records why claims are not provable.
/// Membership is complete only when `parse_ok` is true and `schema_note` is
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexStateSnapshot {
    pub parse_ok: bool,
    pub schema_note: Option<String>,
    pub thread_ids: BTreeSet<String>,
    pub rollout_uuids: BTreeSet<String>,
    pub thread_rows: i64,
    pub spawn_edge_orphans: i64,
    pub migration_skips: i64,
    pub migration_skip_reason_hashes: Vec<String>,
    pub thread_rollout_pairs: BTreeSet<(String, String)>,
}

impl CodexStateSnapshot {
    /// Python: `parse_ok and schema_note is None`.
    #[must_use]
    pub fn membership_complete(&self) -> bool {
        self.parse_ok && self.schema_note.is_none()
    }
}

/// Extract the thread UUID from a `rollout-<ts>-<uuid>.jsonl` name.
///
/// The body searches for the first ASCII UUID. It does not require the
/// `rollout-` prefix. Hex digits are `0-9`, `a-f`, and `A-F` only. A
/// non-ASCII decimal digit is not a hex digit. The captured text is
/// lowercased.
#[must_use]
pub fn rollout_uuid_from_name(name: &str) -> Option<String> {
    let chars: Vec<char> = name.chars().collect();
    let last_start = chars.len().checked_sub(UUID_WIDTH)?;
    for start in 0..=last_start {
        if let Some(found) = match_uuid(&chars[start..start + UUID_WIDTH]) {
            return Some(found);
        }
    }
    None
}

/// True for Codex registry files (`state_*.sqlite`).
///
/// Python: `name.startswith("state_") and name.endswith(".sqlite")`.
/// The check is case-sensitive and does not treat `*` as a glob.
#[must_use]
pub fn is_state_db_name(name: &str) -> bool {
    name.starts_with("state_") && name.ends_with(".sqlite")
}

/// Read one Codex `state_*.sqlite` into a [`CodexStateSnapshot`].
///
/// Check order follows the pin: symlink, then regular file, then size,
/// then the read-only URI. Symlink and stat failures before the size read
/// match `Path.is_symlink` and `Path.is_file`, which swallow `OSError`.
/// The size `stat` maps `OSError` to `io-error`. A file that passes those
/// checks does not yield an empty snapshot: [`ReadCodexStateError`] displays
/// `sqlite3.connect is not available` and no database is opened.
///
/// `immutable` matches the Python keyword. Pass [`DEFAULT_IMMUTABLE`] when
/// the caller would omit it. The flag is part of the URI and is not read
/// when an earlier check returns a snapshot.
pub fn read_codex_state(
    path: &Path,
    immutable: bool,
) -> Result<CodexStateSnapshot, ReadCodexStateError> {
    if let Some(snapshot) = pure_path_snapshot(path) {
        return Ok(snapshot);
    }
    let uri = sqlite_uri(path, immutable)?;
    Err(sqlite3_connect(&uri).into())
}

/// Columns reported by `PRAGMA table_info`.
///
/// Python executes that pragma on an open connection. No connection is
/// opened here, so this returns the same sqlite stop as [`read_codex_state`].
pub fn table_columns(table: &str) -> Result<BTreeSet<String>, ReadCodexStateError> {
    let _known = match table {
        "threads" => Some(&THREADS_COLS[..]),
        "thread_spawn_edges" => Some(&SPAWN_COLS[..]),
        "rollout_migration_skipped_rollouts" => Some(&SKIP_COLS[..]),
        _ => None,
    };
    Err(SqliteConnectUnavailable.into())
}

/// Hash one `rollout_migration_skipped_rollouts.skip_reason` cell.
///
/// Python calls `short_hash(reason if isinstance(reason, str) else "")`.
/// `None` is the non-`str` cell and would be hashed as `""`. The report
/// helper is not in this crate. The reason text is not copied into the error.
pub fn migration_skip_reason_hash(reason: Option<&str>) -> Result<String, ShortHashUnavailable> {
    let text = reason.unwrap_or_default();
    Err(reject_short_hash(text))
}

fn reject_short_hash(text: &str) -> ShortHashUnavailable {
    let _ = text;
    ShortHashUnavailable
}

fn empty_snapshot(parse_ok: bool, note: Option<&str>) -> CodexStateSnapshot {
    CodexStateSnapshot {
        parse_ok,
        schema_note: note.map(str::to_owned),
        thread_ids: BTreeSet::new(),
        rollout_uuids: BTreeSet::new(),
        thread_rows: 0,
        spawn_edge_orphans: 0,
        migration_skips: 0,
        migration_skip_reason_hashes: Vec::new(),
        thread_rollout_pairs: BTreeSet::new(),
    }
}

fn pure_path_snapshot(path: &Path) -> Option<CodexStateSnapshot> {
    if is_symlink(path) {
        return Some(empty_snapshot(false, Some("symlink")));
    }
    if !is_regular_file(path) {
        return Some(empty_snapshot(true, Some("absent")));
    }
    size_refusal(fs::metadata(path).map(|meta| meta.len()))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

fn is_regular_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

fn size_refusal(size: io::Result<u64>) -> Option<CodexStateSnapshot> {
    match size {
        Err(_) => Some(empty_snapshot(false, Some("io-error"))),
        Ok(size) if size > MAX_STATE_DB_BYTES => Some(empty_snapshot(false, Some("oversized"))),
        Ok(_) => None,
    }
}

fn sqlite_uri(path: &Path, immutable: bool) -> Result<String, ReadCodexStateError> {
    let absolute = std::path::absolute(path).map_err(ReadCodexStateError::WorkingDirectory)?;
    let mut uri = make_uri(&absolute)?;
    uri.push_str("?mode=ro");
    if immutable {
        uri.push_str("&immutable=1");
    }
    Ok(uri)
}

fn sqlite3_connect(uri: &str) -> SqliteConnectUnavailable {
    let _ = uri;
    SqliteConnectUnavailable
}

fn make_uri(path: &Path) -> Result<String, ReadCodexStateError> {
    if !path.is_absolute() {
        return Err(ReadCodexStateError::RelativePath);
    }
    #[cfg(windows)]
    {
        windows_make_uri(path)
    }
    #[cfg(not(windows))]
    {
        posix_make_uri(path)
    }
}

#[cfg(windows)]
fn windows_make_uri(path: &Path) -> Result<String, ReadCodexStateError> {
    let posix = as_posix(path)?;
    if let Some(std::path::Component::Prefix(prefix)) = path.components().next() {
        if let std::path::Prefix::Disk(disk) | std::path::Prefix::VerbatimDisk(disk) = prefix.kind()
        {
            return windows_disk_uri(&posix, disk);
        }
    }
    Ok(format!("file:{}", quote_from_bytes(posix.as_bytes())))
}

#[cfg(windows)]
fn windows_disk_uri(posix: &str, disk: u8) -> Result<String, ReadCodexStateError> {
    let drive = format!("{}:", char::from(disk));
    let Some(rest) = posix.strip_prefix(&drive) else {
        return Err(ReadCodexStateError::RelativePath);
    };
    let rest = rest.trim_start_matches('/');
    Ok(format!(
        "file:///{drive}/{}",
        quote_from_bytes(rest.as_bytes())
    ))
}

#[cfg(not(windows))]
fn posix_make_uri(path: &Path) -> Result<String, ReadCodexStateError> {
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    Ok(format!("file://{}", quote_from_bytes(bytes)))
}

#[cfg(windows)]
fn as_posix(path: &Path) -> Result<String, ReadCodexStateError> {
    let text = path.to_str().ok_or(ReadCodexStateError::UndecodablePath)?;
    Ok(text.replace('\\', "/"))
}

fn quote_from_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if is_uri_safe(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

fn is_uri_safe(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/'
    )
}

fn hex_digit(value: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(value)])
}

fn match_uuid(window: &[char]) -> Option<String> {
    if window.len() != UUID_WIDTH {
        return None;
    }
    let mut out = String::with_capacity(UUID_WIDTH);
    let mut index = 0;
    for (group_index, &width) in UUID_GROUP_WIDTHS.iter().enumerate() {
        if group_index > 0 {
            if window.get(index).copied() != Some('-') {
                return None;
            }
            out.push('-');
            index += 1;
        }
        for _ in 0..width {
            let ch = window.get(index).copied()?;
            if !is_ascii_hex_char(ch) {
                return None;
            }
            out.push(ch.to_ascii_lowercase());
            index += 1;
        }
    }
    if index != UUID_WIDTH {
        return None;
    }
    Some(out)
}

/// ASCII `0-9a-fA-F` only. Unicode decimal digits fail this check.
fn is_ascii_hex_char(ch: char) -> bool {
    ch.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::{
        is_state_db_name, make_uri, migration_skip_reason_hash, read_codex_state,
        rollout_uuid_from_name, size_refusal, sqlite_uri, table_columns, CodexStateSnapshot,
        ReadCodexStateError, ShortHashUnavailable, SqliteConnectUnavailable, DEFAULT_IMMUTABLE,
        MAX_STATE_DB_BYTES, MAX_STATE_QUERY_STEPS, MAX_STATE_ROWS, SKIP_COLS, SPAWN_COLS,
        STATE_DB_GLOB, THREADS_COLS,
    };
    use std::collections::BTreeSet;
    use std::fs::{self, File};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "sesslint-state-db-synthetic-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("scratch dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn immutable_default() -> bool {
        DEFAULT_IMMUTABLE
    }

    fn assert_stopped(snapshot: &CodexStateSnapshot, parse_ok: bool, note: &str) {
        assert_eq!(snapshot.parse_ok, parse_ok);
        assert_eq!(snapshot.schema_note.as_deref(), Some(note));
        assert!(!snapshot.membership_complete());
        assert!(snapshot.thread_ids.is_empty());
        assert!(snapshot.rollout_uuids.is_empty());
        assert_eq!(snapshot.thread_rows, 0);
        assert_eq!(snapshot.spawn_edge_orphans, 0);
        assert_eq!(snapshot.migration_skips, 0);
        assert!(snapshot.migration_skip_reason_hashes.is_empty());
        assert!(snapshot.thread_rollout_pairs.is_empty());
    }

    fn assert_sqlite_stop(result: Result<CodexStateSnapshot, ReadCodexStateError>) {
        let error = result.expect_err("sqlite stop must not be a snapshot");
        assert!(matches!(error, ReadCodexStateError::SqliteConnect));
        assert_eq!(error.to_string(), SqliteConnectUnavailable.to_string());
        assert_eq!(error.to_string(), "sqlite3.connect is not available");
    }

    fn link_file(target: &Path, link: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "symlink is unavailable",
            ))
        }
    }

    fn dir_names(scratch: &Scratch) -> Vec<String> {
        let mut names = fs::read_dir(&scratch.path)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(MAX_STATE_DB_BYTES, 268_435_456);
        assert_eq!(MAX_STATE_ROWS, 1_000_000);
        assert_eq!(MAX_STATE_QUERY_STEPS, 50_000_000);
        assert_eq!(STATE_DB_GLOB, "state_*.sqlite");
        assert!(!immutable_default());
        assert_eq!(
            THREADS_COLS,
            ["id", "rollout_path", "thread_source", "archived"]
        );
        assert_eq!(SPAWN_COLS, ["parent_thread_id", "child_thread_id"]);
        assert_eq!(SKIP_COLS, ["skip_reason"]);
    }

    #[test]
    fn column_allowlist_excludes_content() {
        for banned in [
            "title",
            "name",
            "preview",
            "first_user_message",
            "objective",
            "raw_memory",
        ] {
            assert!(!THREADS_COLS.contains(&banned));
            assert!(!SPAWN_COLS.contains(&banned));
            assert!(!SKIP_COLS.contains(&banned));
        }
    }

    #[test]
    fn rollout_uuid_from_name_matches_the_pin() {
        let cases = [
            ("", None),
            (
                "01a0c4d8-a9f7-7973-8155-dba14d25a377",
                Some("01a0c4d8-a9f7-7973-8155-dba14d25a377"),
            ),
            (
                "01A0C4D8-A9F7-7973-8155-DBA14D25A377",
                Some("01a0c4d8-a9f7-7973-8155-dba14d25a377"),
            ),
            (
                "rollout-2026-09-20T00-00-00-01a0c4d8-a9f7-7973-8155-dba14d25a377.jsonl",
                Some("01a0c4d8-a9f7-7973-8155-dba14d25a377"),
            ),
            (
                "rollout-2026-09-20T00-00-00-01A0C4D8-A9F7-7973-8155-DBA14D25A377.jsonl",
                Some("01a0c4d8-a9f7-7973-8155-dba14d25a377"),
            ),
            (
                "prefix-01234567-89ab-cdef-0123-456789abcdef-suffix",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
            (
                "01234567-89AB-CDEF-0123-456789ABCDEF",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
            ("01234567-89ab-cdef-0123-456789abcdeg", None),
            (
                "012345678-9abc-def0-1234-567890abcdef",
                Some("12345678-9abc-def0-1234-567890abcdef"),
            ),
            (
                "01234567-89ab-cdef-0123-456789abcdefEXTRA",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
            (
                "{01234567-89ab-cdef-0123-456789abcdef}",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
            (
                "01234567-89ab-cdef-0123-456789abcdef-01234567-89ab-cdef-0123-456789abcdee",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
            ("not-a-uuid", None),
            ("01234567-89ab-cdef-0123-456789abcde", None),
            ("g1234567-89ab-cdef-0123-456789abcdef", None),
            (
                "01234567-89ab-cdef-0123-456789abcdef\n",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
            ),
        ];
        for (name, expected) in cases {
            assert_eq!(rollout_uuid_from_name(name), expected.map(str::to_owned));
        }
    }

    #[test]
    fn non_ascii_decimal_digit_is_not_a_hex_digit() {
        assert!(!'\u{FF10}'.is_ascii_hexdigit());
        assert!(!'\u{0660}'.is_ascii_hexdigit());
        assert!(!'\u{FF21}'.is_ascii_hexdigit());
        assert_eq!(
            rollout_uuid_from_name("\u{FF10}1234567-89ab-cdef-0123-456789abcdef"),
            None
        );
        assert_eq!(
            rollout_uuid_from_name(
                "\u{FF10}\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}-\u{FF18}\u{FF19}ab-cdef-0123-456789abcdef"
            ),
            None
        );
        assert_eq!(
            rollout_uuid_from_name("0\u{FF11}234567-89ab-cdef-0123-456789abcdef"),
            None
        );
        assert_eq!(
            rollout_uuid_from_name("\u{0660}1234567-89ab-cdef-0123-456789abcdef"),
            None
        );
        assert_eq!(
            rollout_uuid_from_name("\u{FF10}-01234567-89ab-cdef-0123-456789abcdef"),
            Some("01234567-89ab-cdef-0123-456789abcdef".to_owned())
        );
        assert_eq!(
            rollout_uuid_from_name("aa\u{00E9}01234567-89ab-cdef-0123-456789abcdef"),
            Some("01234567-89ab-cdef-0123-456789abcdef".to_owned())
        );
        let en_dash = "01234567\u{2013}89ab-cdef-0123-456789abcdef";
        assert_eq!(rollout_uuid_from_name(en_dash), None);
    }

    #[test]
    fn is_state_db_name_matches_the_pin() {
        let cases = [
            ("", false),
            ("state_1.sqlite", true),
            ("state_.sqlite", true),
            ("state_1.SQLITE", false),
            ("State_1.sqlite", false),
            ("state_1.sqlite.bak", false),
            ("xstate_1.sqlite", false),
            ("state_1.sqlite ", false),
            ("state_", false),
            (".sqlite", false),
            ("state_1.sqlite.sqlite", true),
            ("state_*.sqlite", true),
            ("state_\u{FF10}.sqlite", true),
            ("state_1.sqlite\n", false),
            ("state_sqlite", false),
            ("state_.sqliteextra", false),
            ("STATE_1.sqlite", false),
            ("state_1.Sqlite", false),
        ];
        for (name, expected) in cases {
            assert_eq!(is_state_db_name(name), expected, "{name:?}");
        }
    }

    #[test]
    fn membership_complete_requires_parse_ok_and_no_note() {
        let mut snapshot = CodexStateSnapshot {
            parse_ok: true,
            schema_note: None,
            thread_ids: BTreeSet::new(),
            rollout_uuids: BTreeSet::new(),
            thread_rows: 0,
            spawn_edge_orphans: 0,
            migration_skips: 0,
            migration_skip_reason_hashes: Vec::new(),
            thread_rollout_pairs: BTreeSet::new(),
        };
        assert!(snapshot.membership_complete());
        snapshot.schema_note = Some(String::new());
        assert!(!snapshot.membership_complete());
        snapshot.schema_note = None;
        snapshot.parse_ok = false;
        assert!(!snapshot.membership_complete());
    }

    #[test]
    fn missing_path_is_absent() {
        let scratch = Scratch::new();
        let missing = scratch.join("state_1.sqlite");
        let snapshot = read_codex_state(&missing, DEFAULT_IMMUTABLE).expect("absent snapshot");
        assert_stopped(&snapshot, true, "absent");
        let again = read_codex_state(&missing, true).expect("absent ignores immutable");
        assert_stopped(&again, true, "absent");
    }

    #[test]
    fn directory_is_absent() {
        let scratch = Scratch::new();
        let folder = scratch.join("state_dir.sqlite");
        fs::create_dir(&folder).expect("dir");
        let snapshot = read_codex_state(&folder, false).expect("directory snapshot");
        assert_stopped(&snapshot, true, "absent");
    }

    #[test]
    fn symlink_is_not_followed() {
        let scratch = Scratch::new();
        let target = scratch.join("real.sqlite");
        fs::write(&target, b"target-bytes").expect("target");
        let link = scratch.join("state_link.sqlite");
        link_file(&target, &link).expect("symlink");
        let snapshot = read_codex_state(&link, false).expect("symlink snapshot");
        assert_stopped(&snapshot, false, "symlink");
        assert_eq!(fs::read(&target).expect("target bytes"), b"target-bytes");
    }

    #[test]
    fn dangling_symlink_is_symlink() {
        let scratch = Scratch::new();
        let link = scratch.join("state_dangling.sqlite");
        link_file(&scratch.join("missing-target.sqlite"), &link).expect("dangling symlink");
        let snapshot = read_codex_state(&link, true).expect("dangling snapshot");
        assert_stopped(&snapshot, false, "symlink");
    }

    #[test]
    fn small_files_stop_at_sqlite_without_sidecars() {
        let scratch = Scratch::new();
        let empty = scratch.join("state_empty.sqlite");
        fs::write(&empty, b"").expect("empty");
        assert_sqlite_stop(read_codex_state(&empty, false));

        let garbage = scratch.join("state_garbage.sqlite");
        let payload = b"not a sqlite file at all";
        fs::write(&garbage, payload).expect("garbage");
        assert_sqlite_stop(read_codex_state(&garbage, true));
        assert_eq!(fs::read(&garbage).expect("bytes"), payload);
        assert_eq!(
            dir_names(&scratch),
            vec![
                "state_empty.sqlite".to_owned(),
                "state_garbage.sqlite".to_owned(),
            ]
        );
    }

    #[test]
    fn size_boundary_uses_strict_greater_than() {
        let scratch = Scratch::new();
        let exact = scratch.join("state_exact.sqlite");
        let file = File::create(&exact).expect("exact");
        file.set_len(MAX_STATE_DB_BYTES).expect("exact len");
        drop(file);
        assert_eq!(
            fs::metadata(&exact).expect("exact meta").len(),
            MAX_STATE_DB_BYTES
        );
        assert_sqlite_stop(read_codex_state(&exact, false));
        fs::remove_file(&exact).expect("remove exact");

        let big = scratch.join("state_big.sqlite");
        let file = File::create(&big).expect("big");
        file.set_len(MAX_STATE_DB_BYTES + 1).expect("big len");
        drop(file);
        let snapshot = read_codex_state(&big, true).expect("oversized snapshot");
        assert_stopped(&snapshot, false, "oversized");
        assert_eq!(dir_names(&scratch), vec!["state_big.sqlite".to_owned()]);
    }

    #[test]
    fn reader_does_not_require_the_state_db_name() {
        let scratch = Scratch::new();
        let notes = scratch.join("notes.txt");
        fs::write(&notes, b"synthetic").expect("notes");
        assert_sqlite_stop(read_codex_state(&notes, DEFAULT_IMMUTABLE));
    }

    #[test]
    fn size_refusal_maps_io_error_and_the_boundary() {
        let denied = io::Error::new(io::ErrorKind::PermissionDenied, "synthetic io");
        let snapshot = size_refusal(Err(denied)).expect("io-error");
        assert_stopped(&snapshot, false, "io-error");
        assert!(size_refusal(Ok(0)).is_none());
        assert!(size_refusal(Ok(MAX_STATE_DB_BYTES)).is_none());
        let oversized = size_refusal(Ok(MAX_STATE_DB_BYTES + 1)).expect("oversized");
        assert_stopped(&oversized, false, "oversized");
    }

    #[test]
    fn sqlite_uri_matches_the_pin() {
        let cases = [
            (
                Path::new(r"C:\synthetic\state dir\state_1.sqlite"),
                "file:///C:/synthetic/state%20dir/state_1.sqlite?mode=ro",
            ),
            (
                Path::new(r"C:\synthetic\a b\c?.sqlite"),
                "file:///C:/synthetic/a%20b/c%3F.sqlite?mode=ro",
            ),
            (
                Path::new(r"C:\synthetic\hash#\q&u.sqlite"),
                "file:///C:/synthetic/hash%23/q%26u.sqlite?mode=ro",
            ),
            (
                Path::new("C:/synthetic/already.sqlite"),
                "file:///C:/synthetic/already.sqlite?mode=ro",
            ),
            (
                Path::new(r"\\server\share\state_1.sqlite"),
                "file://server/share/state_1.sqlite?mode=ro",
            ),
            (
                Path::new("D:/synthetic/state_\u{00FC}.sqlite"),
                "file:///D:/synthetic/state_%C3%BC.sqlite?mode=ro",
            ),
            (
                Path::new(r"C:\synthetic\a~b_c-d.sqlite"),
                "file:///C:/synthetic/a~b_c-d.sqlite?mode=ro",
            ),
        ];
        for (path, expected) in cases {
            let plain = sqlite_uri(path, false).expect("uri");
            assert_eq!(plain, expected);
            let frozen = sqlite_uri(path, true).expect("immutable uri");
            assert_eq!(frozen, format!("{expected}&immutable=1"));
        }
    }

    #[test]
    fn relative_uri_only_appends_the_immutable_flag() {
        let path = Path::new("state_1.sqlite");
        let plain = sqlite_uri(path, false).expect("relative uri");
        let frozen = sqlite_uri(path, true).expect("relative immutable uri");
        assert!(plain.ends_with("state_1.sqlite?mode=ro"));
        assert_eq!(frozen, format!("{plain}&immutable=1"));
    }

    #[test]
    fn relative_make_uri_matches_python_value_error() {
        let error = make_uri(Path::new("state_1.sqlite")).expect_err("relative");
        assert!(matches!(error, ReadCodexStateError::RelativePath));
        assert_eq!(
            error.to_string(),
            "relative path can't be expressed as a file URI"
        );
    }

    #[test]
    fn migration_skip_reason_does_not_call_short_hash() {
        for reason in [Some("schema-too-new"), Some(""), None] {
            let error = migration_skip_reason_hash(reason).expect_err("short_hash stop");
            assert_eq!(error, ShortHashUnavailable);
            assert_eq!(
                error.to_string(),
                "sesslint.report.short_hash is not available"
            );
            assert!(!error.to_string().contains("schema-too-new"));
        }
    }

    #[test]
    fn table_columns_stops_without_opening_a_database() {
        let scratch = Scratch::new();
        let before = dir_names(&scratch);
        for table in ["threads", "thread_spawn_edges", "other", ""] {
            let error = table_columns(table).expect_err("pragma is not executed");
            assert!(matches!(error, ReadCodexStateError::SqliteConnect));
            assert_eq!(error.to_string(), "sqlite3.connect is not available");
        }
        assert_eq!(dir_names(&scratch), before);
    }
}
