//! Tamper-evident hash-chain ledger for SessLint verdicts (evidence-assurance T-01).
//!
//! Port of `src/sesslint/seal.py` lines 1–465
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `b25074ea2dbebe8bcf3359ec288bf08b80b0b9ed`.
//!
//! Lines 1–315 are the hash, verify, and [`ledger_lock`] behavior. Lines
//! 318–465 are [`append_seal`], the locked append, directory sync, and the
//! schema loaders. `__all__` is the public items already exported here.
//!
//! [`append_seal`] calls [`ledger_lock`] before it opens a ledger. The lock
//! helper closes the sidecar and returns [`SealError::LockingUnavailable`].
//! That error is propagated. On that path the ledger is not opened for append
//! and no ledger bytes are written. The locked body runs only after the lock
//! returns `Ok`.
//!
//! [`build_entry`] and [`append_seal`] require the caller to pass the instant.
//! This module does not read the wall clock. The formatted instant is the pin's
//! `datetime.isoformat(timespec="seconds").replace("+00:00", "Z")` and is
//! inside the hashed entry.
//!
//! The hash helper calls [`codec::canonical_codec::canonical_json_bytes`] with
//! `newline` false, which is the `_canonical_codec` default. The appended line
//! uses `newline` true. Canonical JSON is not reimplemented here.
//!
//! [`ledger_lock`] opens the lock file before the missing `msvcrt` / `fcntl`
//! import. It then closes the descriptor and returns [`SealError::LockingUnavailable`].
//! It does not hold the file open, append ledger bytes, or link `libc`.
//! `O_NOFOLLOW` is not applied: this crate does not depend on `libc`. The
//! symlink check still runs before the open, as in the pin.
//!
//! [`get_seal_schema_path`] checks the pure relative development path, then
//! returns [`SealError::ResourcesUnavailable`]. `sesslint._resources` is not
//! ported and is not invented. [`load_seal_schema`] stops at that error.
//! Neither function reads `schemas/`.
//!
//! # Recorded gaps
//!
//! * `_SEALED_AT` uses Python `\d`, which matches Unicode category Nd. This
//!   port checks the ASCII shape `YYYY-MM-DDTHH:MM:SSZ`. A non-ASCII decimal
//!   digit fails the shape check.
//! * A lone UTF-16 surrogate in a JSON `\u` escape cannot be stored in a Rust
//!   string. The line is not valid JSON. Python `json.loads` keeps the
//!   surrogate code point.
//! * Python `int` is unbounded. Integers that fit in the codec's public
//!   constructors are hashed. A wider integer that must be hashed returns an
//!   error and is not reported as an intact chain. A wider `seq` still
//!   produces `seq-gap` when it is not the expected counter, without hashing.
//! * `sha256_file` returns [`std::io::Error`]. Its Display is the Rust I/O
//!   text. Python lets `OSError` propagate from `open`.
//! * JSON container nesting follows CPython 3.11.9's default `json.loads`:
//!   995 nested arrays or objects parse, and 996 raises `RecursionError`,
//!   which [`verify_lines`] reports as a malformed line.
//! * Directory sync is a no-op on Windows, matching `os.name == "nt"`.
//!   Closing the ledger file ignores a close error.
//! * Pure-path text drops `.` components. Python `str(Path)` keeps them.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use codec::canonical_codec::{canonical_json_bytes, ObjectKey, Value};
use sha2::{Digest, Sha256};

/// Python `SEAL_SCHEMA_ID`.
pub const SEAL_SCHEMA_ID: &str = "sesslint.seal-ledger/v1";

/// Schema file name under `schemas/`, checked before the missing import.
const SEAL_SCHEMA_FILE: &str = "sesslint.seal-ledger.v1.json";

/// `sesslint._resources` is not ported.
pub const RESOURCES_UNAVAILABLE: &str = "sesslint._resources is not available";

/// Python `GENESIS`.
pub const GENESIS: &str = "GENESIS";

/// Python `SEAL_TOOLS`, in source-literal order.
///
/// The `build_entry` error lists them sorted: `check`, `repair`, `verify`.
pub const SEAL_TOOLS: [&str; 3] = ["check", "verify", "repair"];

/// Python `DIVERGENCE_KINDS`, in source-literal order.
pub const DIVERGENCE_KINDS: [&str; 5] = [
    "malformed-line",
    "bad-schema",
    "seq-gap",
    "chain-break",
    "hash-mismatch",
];

const SORTED_TOOLS: &str = "['check', 'repair', 'verify']";

/// Python `_CHUNK`. Streaming read size for [`sha256_file`].
const CHUNK: usize = 1024 * 1024;

/// CPython 3.11.9 `json.loads` accepts this many nested containers and raises
/// `RecursionError` on the next one.
const MAX_JSON_DEPTH: usize = 995;

const DAY_MICROS: i128 = 86_400_000_000;

/// Python `SealError`, plus the typed lock-import and resources failures.
///
/// [`Display`](fmt::Display) is the Python message, the lock sentence, or
/// [`RESOURCES_UNAVAILABLE`]. It does not include a Rust type name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Python exception text (`SealError`, `ValueError`, `SchemaError`, or an OS message).
    Message(String),
    /// `msvcrt.locking` or `fcntl.flock` is not available. The lock file was closed.
    LockingUnavailable,
    /// `sesslint._resources` is not ported. Schema bytes were not read.
    ResourcesUnavailable,
}

impl SealError {
    fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(text) => formatter.write_str(text),
            Self::LockingUnavailable => {
                if cfg!(windows) {
                    formatter.write_str("msvcrt.locking is not available")
                } else {
                    formatter.write_str("fcntl.flock is not available")
                }
            }
            Self::ResourcesUnavailable => formatter.write_str(RESOURCES_UNAVAILABLE),
        }
    }
}

impl Error for SealError {}

/// Instant supplied to [`build_entry`] and [`append_seal`].
///
/// `offset_micros_east == None` is a naive datetime. `Some(0)` is UTC.
/// The value is not read from the wall clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealInstant {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    microsecond: u32,
    offset_micros_east: Option<i128>,
}

impl SealInstant {
    /// Validate fields the way `datetime` and `timezone` do, then store them.
    #[allow(clippy::too_many_arguments)] // one parameter per `datetime` field, plus the offset
    pub fn try_new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsecond: u32,
        offset_micros_east: Option<i128>,
    ) -> Result<Self, SealError> {
        if !(1..=9999).contains(&year) {
            return Err(SealError::message(format!("year {year} is out of range")));
        }
        if month == 0 || month > 12 {
            return Err(SealError::message("month must be in 1..12"));
        }
        if day == 0 || day > days_in_month(year, month) {
            return Err(SealError::message("day is out of range for month"));
        }
        if hour > 23 {
            return Err(SealError::message("hour must be in 0..23"));
        }
        if minute > 59 {
            return Err(SealError::message("minute must be in 0..59"));
        }
        if second > 59 {
            return Err(SealError::message("second must be in 0..59"));
        }
        if microsecond > 999_999 {
            return Err(SealError::message("microsecond must be in 0..999999"));
        }
        if let Some(offset) = offset_micros_east {
            if offset <= -DAY_MICROS || offset >= DAY_MICROS {
                return Err(SealError::message(offset_error(offset)));
            }
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            offset_micros_east,
        })
    }

    /// UTC instant with microsecond 0. `Some(0)` formats as `Z` after the pin's replace.
    pub fn utc(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, SealError> {
        Self::try_new(year, month, day, hour, minute, second, 0, Some(0))
    }

    /// Naive instant. The formatted text has no offset suffix.
    pub fn naive(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, SealError> {
        Self::try_new(year, month, day, hour, minute, second, 0, None)
    }

    /// Python `(now).isoformat(timespec="seconds").replace("+00:00", "Z")`.
    fn sealed_text(self) -> String {
        let mut text = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if let Some(offset) = self.offset_micros_east {
            text.push_str(&format_offset(offset));
            text = text.replace("+00:00", "Z");
        }
        text
    }
}

/// One ledger line returned by [`build_entry`].
///
/// `codes` keeps the first-seen key order. Canonical JSON sorts keys, so the
/// hash does not depend on that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealEntry {
    pub schema: &'static str,
    pub seq: i64,
    pub prev_sha256: String,
    pub file_sha256: String,
    pub path: Option<String>,
    pub tool: String,
    pub verdict: String,
    pub codes: Vec<(String, i64)>,
    pub report_sha256: String,
    pub genesis_of: Option<String>,
    pub sealed_at: String,
    pub entry_sha256: String,
}

/// Keyword-only arguments of Python `build_entry`. `now` is required.
#[derive(Clone, Copy, Debug)]
pub struct EntryInput<'a> {
    pub seq: i64,
    pub prev_sha256: &'a str,
    pub file_sha256: &'a str,
    pub path: Option<&'a str>,
    pub tool: &'a str,
    pub verdict: &'a str,
    pub codes: &'a [(&'a str, i64)],
    pub report_sha256: &'a str,
    pub genesis_of: Option<&'a str>,
    pub now: &'a SealInstant,
}

/// First divergence from [`verify_lines`].
///
/// `seq` is the decimal spelling of the Python int. It is present for
/// `seq-gap`, `chain-break`, and `hash-mismatch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    pub kind: &'static str,
    pub line: i64,
    pub seq: Option<String>,
    pub detail: String,
}

/// SHA-256 hex digest of in-memory bytes.
///
/// Python `sha256_bytes`. Lowercase hex, matching `hashlib.sha256.hexdigest`.
pub fn sha256_bytes(data: &[u8]) -> String {
    hex_lower(Sha256::digest(data).as_slice())
}

/// Streaming SHA-256 hex digest of a file's bytes (1 MiB chunks).
///
/// Python `sha256_file`. `OSError` from `open` / `read` is [`io::Error`].
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let read = read_retry(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex_lower(hasher.finalize().as_slice()))
}

/// Build one ledger line, including `entry_sha256`, after validating fields.
///
/// Python `build_entry`. `now` is required; the wall clock is not consulted.
pub fn build_entry(input: EntryInput<'_>) -> Result<SealEntry, SealError> {
    if input.seq < 1 {
        return Err(SealError::message(format!(
            "seq must be a positive integer, got {}",
            input.seq
        )));
    }
    if input.prev_sha256 != GENESIS && !is_hex64(input.prev_sha256) {
        return Err(SealError::message(
            "prev_sha256 must be 'GENESIS' or a sha256 hex digest",
        ));
    }
    if !is_hex64(input.file_sha256) {
        return Err(SealError::message(
            "file_sha256 must be a sha256 hex digest",
        ));
    }
    if !SEAL_TOOLS.contains(&input.tool) {
        return Err(SealError::message(format!(
            "tool must be one of {SORTED_TOOLS}, got {}",
            python_repr(input.tool)
        )));
    }
    if input.verdict.is_empty() {
        return Err(SealError::message("verdict must be a non-empty string"));
    }
    let mut codes = Vec::new();
    for (code, count) in input.codes {
        if *count < 0 {
            return Err(SealError::message(format!(
                "codes must map code strings to non-negative ints: {}",
                python_repr(code)
            )));
        }
        if let Some(slot) = codes.iter_mut().find(|(name, _)| name == code) {
            slot.1 = *count;
        } else {
            codes.push(((*code).to_owned(), *count));
        }
    }
    if !is_hex64(input.report_sha256) {
        return Err(SealError::message(
            "report_sha256 must be a sha256 hex digest",
        ));
    }
    if let Some(genesis) = input.genesis_of {
        if !is_hex64(genesis) {
            return Err(SealError::message("genesis_of must be a sha256 hex digest"));
        }
    }
    let sealed_at = input.now.sealed_text();
    let digest = hash_built(&input, &codes, &sealed_at)?;
    Ok(SealEntry {
        schema: SEAL_SCHEMA_ID,
        seq: input.seq,
        prev_sha256: input.prev_sha256.to_owned(),
        file_sha256: input.file_sha256.to_owned(),
        path: input.path.map(str::to_owned),
        tool: input.tool.to_owned(),
        verdict: input.verdict.to_owned(),
        codes,
        report_sha256: input.report_sha256.to_owned(),
        genesis_of: input.genesis_of.map(str::to_owned),
        sealed_at,
        entry_sha256: digest,
    })
}

/// Walk parsed ledger lines. `Ok(None)` means the chain is intact.
///
/// Python `verify_lines`. A JSON integer wider than the codec can hash
/// returns [`Err`] instead of an intact chain.
pub fn verify_lines(lines: &[(i64, &str)]) -> Result<Option<Divergence>, SealError> {
    let mut prev_hash = GENESIS.to_owned();
    let mut expected_seq: i64 = 1;
    for (line_no, raw) in lines {
        let entry = match parse_json(raw) {
            Ok(value) => value,
            Err(()) => {
                return Ok(Some(plain_divergence(
                    "malformed-line",
                    *line_no,
                    "line is not valid JSON (edit or truncation)",
                )));
            }
        };
        if let Some(kind) = validate_entry_shape(&entry) {
            let detail = if kind == "bad-schema" {
                "document is not a sesslint.seal-ledger/v1 entry"
            } else {
                "entry fields are malformed or missing"
            };
            return Ok(Some(plain_divergence(kind, *line_no, detail)));
        }
        let Json::Object(entries) = &entry else {
            return Ok(Some(plain_divergence(
                "malformed-line",
                *line_no,
                "entry fields are malformed or missing",
            )));
        };
        let Some(Json::Int(seq)) = object_get(entries, "seq") else {
            return Ok(Some(plain_divergence(
                "malformed-line",
                *line_no,
                "entry fields are malformed or missing",
            )));
        };
        if !seq.eq_i64(expected_seq) {
            let found = seq.decimal();
            return Ok(Some(Divergence {
                kind: "seq-gap",
                line: *line_no,
                seq: Some(found.clone()),
                detail: format!(
                    "expected seq {expected_seq}, found {found} (line drop or reorder)"
                ),
            }));
        }
        let Some(Json::String(prev)) = object_get(entries, "prev_sha256") else {
            return Ok(Some(plain_divergence(
                "malformed-line",
                *line_no,
                "entry fields are malformed or missing",
            )));
        };
        if prev != &prev_hash {
            return Ok(Some(Divergence {
                kind: "chain-break",
                line: *line_no,
                seq: Some(seq.decimal()),
                detail: "prev_sha256 does not bind to the previous entry hash".to_owned(),
            }));
        }
        let Some(Json::String(actual)) = object_get(entries, "entry_sha256") else {
            return Ok(Some(plain_divergence(
                "malformed-line",
                *line_no,
                "entry fields are malformed or missing",
            )));
        };
        let actual = actual.clone();
        let hashed = hash_object(entries)?;
        if actual != hashed {
            return Ok(Some(Divergence {
                kind: "hash-mismatch",
                line: *line_no,
                seq: Some(seq.decimal()),
                detail: "entry_sha256 does not match the entry contents (line edited)".to_owned(),
            }));
        }
        prev_hash = actual;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| SealError::message("seal sequence is outside the supported range"))?;
    }
    Ok(None)
}

/// Verify a ledger file end to end.
///
/// Python `verify_ledger`. Returns `(entries_verified, divergence)`.
/// [`SealError`] means the file is missing or unreadable.
pub fn verify_ledger(path: &Path) -> Result<(i64, Option<Divergence>), SealError> {
    if !path.is_file() {
        return Err(SealError::message(format!(
            "ledger not found: {}",
            path_text(path)
        )));
    }
    let lines = iter_lines(path)?;
    let borrowed: Vec<(i64, &str)> = lines
        .iter()
        .map(|(number, text)| (*number, text.as_str()))
        .collect();
    let divergence = verify_lines(&borrowed)?;
    if let Some(found) = &divergence {
        let verified = lines
            .iter()
            .filter(|(number, _)| *number < found.line)
            .count();
        let verified = i64::try_from(verified)
            .map_err(|_| SealError::message("ledger line number is outside the supported range"))?;
        return Ok((verified, divergence));
    }
    let count = i64::try_from(lines.len())
        .map_err(|_| SealError::message("ledger line number is outside the supported range"))?;
    Ok((count, None))
}

/// Open the lock sidecar, close it, and report that the lock primitive is missing.
///
/// Python `_ledger_lock` through the `os.close` on line 315. The import of
/// `msvcrt` or `fcntl` is not available, so this never yields a held lock and
/// never appends ledger bytes.
pub fn ledger_lock(path: &Path) -> Result<(), SealError> {
    let lock_path = lock_sidecar(path)?;
    if is_symlink(&lock_path) {
        return Err(SealError::message("ledger lock must not be a symlink"));
    }
    let file = match open_lock(&lock_path) {
        Ok(file) => file,
        Err(_) => return Err(SealError::message("cannot open ledger lock")),
    };
    drop(file);
    Err(SealError::LockingUnavailable)
}

/// Keyword-only arguments of Python `append_seal`. `now` is required.
///
/// The instant is supplied by the caller. This module does not read the wall clock.
#[derive(Clone, Copy, Debug)]
pub struct AppendInput<'a> {
    pub ledger: &'a Path,
    pub tool: &'a str,
    pub file_sha256: &'a str,
    pub path: Option<&'a str>,
    pub verdict: &'a str,
    pub codes: &'a [(&'a str, i64)],
    pub report_sha256: &'a str,
    pub genesis_of: Option<&'a str>,
    pub now: &'a SealInstant,
}

/// Append one sealed line after re-verifying the chain.
///
/// Python `append_seal`. [`ledger_lock`] runs before the ledger is opened.
/// The lock closes its sidecar and returns [`SealError::LockingUnavailable`].
/// This propagates that error. The ledger is not opened for append and no
/// ledger bytes are written on that path.
pub fn append_seal(input: AppendInput<'_>) -> Result<SealEntry, SealError> {
    ledger_lock(input.ledger)?;
    append_seal_locked(input)
}

/// Python `_append_seal_locked`. Runs only after [`ledger_lock`] returns `Ok`.
fn append_seal_locked(input: AppendInput<'_>) -> Result<SealEntry, SealError> {
    let path = input.ledger;
    let (seq, prev) = if path.exists() {
        let lines = iter_lines(path)?;
        let borrowed: Vec<(i64, &str)> = lines
            .iter()
            .map(|(number, text)| (*number, text.as_str()))
            .collect();
        if let Some(found) = verify_lines(&borrowed)? {
            return Err(SealError::message(format!(
                "ledger {} is divergent at line {} ({}: {}) — refusing to extend",
                path_text(path),
                found.line,
                found.kind,
                found.detail
            )));
        }
        next_link(&lines)?
    } else {
        (1, GENESIS.to_owned())
    };
    if input.genesis_of.is_some() && seq != 1 {
        return Err(SealError::message(
            "genesis_of binds only a ledger's first line (seq 1)",
        ));
    }
    let entry = build_entry(EntryInput {
        seq,
        prev_sha256: &prev,
        file_sha256: input.file_sha256,
        path: input.path,
        tool: input.tool,
        verdict: input.verdict,
        codes: input.codes,
        report_sha256: input.report_sha256,
        genesis_of: input.genesis_of,
        now: input.now,
    })?;
    let line = entry_line_bytes(&entry)?;
    append_line(path, line)?;
    Ok(entry)
}

fn next_link(lines: &[(i64, String)]) -> Result<(i64, String), SealError> {
    let Some((_, raw)) = lines.last() else {
        return Ok((1, GENESIS.to_owned()));
    };
    let Ok(parsed) = parse_json(raw) else {
        return Err(SealError::message(
            "line is not valid JSON (edit or truncation)",
        ));
    };
    let Json::Object(entries) = parsed else {
        return Err(SealError::message("entry fields are malformed or missing"));
    };
    let next = {
        let Some(Json::Int(seq)) = object_get(&entries, "seq") else {
            return Err(SealError::message("entry fields are malformed or missing"));
        };
        let Some(value) = seq.to_i128() else {
            return Err(SealError::message(
                "canonical integer is outside the supported range",
            ));
        };
        let seq = i64::try_from(value)
            .map_err(|_| SealError::message("seal sequence is outside the supported range"))?;
        seq.checked_add(1)
            .ok_or_else(|| SealError::message("seal sequence is outside the supported range"))?
    };
    let Some(Json::String(prev)) = object_get(&entries, "entry_sha256") else {
        return Err(SealError::message("entry fields are malformed or missing"));
    };
    Ok((next, prev.clone()))
}

fn entry_line_bytes(entry: &SealEntry) -> Result<Vec<u8>, SealError> {
    let mut codes = Vec::with_capacity(entry.codes.len());
    for (code, count) in &entry.codes {
        codes.push((ObjectKey::string(code.clone()), Value::int(*count)));
    }
    let mut fields = vec![
        (ObjectKey::string("schema"), Value::string(entry.schema)),
        (ObjectKey::string("seq"), Value::int(entry.seq)),
        (
            ObjectKey::string("prev_sha256"),
            Value::string(&entry.prev_sha256),
        ),
        (
            ObjectKey::string("file_sha256"),
            Value::string(&entry.file_sha256),
        ),
        (ObjectKey::string("tool"), Value::string(&entry.tool)),
        (ObjectKey::string("verdict"), Value::string(&entry.verdict)),
        (ObjectKey::string("codes"), Value::object(codes)),
        (
            ObjectKey::string("report_sha256"),
            Value::string(&entry.report_sha256),
        ),
        (
            ObjectKey::string("sealed_at"),
            Value::string(&entry.sealed_at),
        ),
        (
            ObjectKey::string("entry_sha256"),
            Value::string(&entry.entry_sha256),
        ),
    ];
    if let Some(path) = &entry.path {
        fields.push((ObjectKey::string("path"), Value::string(path)));
    }
    if let Some(genesis) = &entry.genesis_of {
        fields.push((ObjectKey::string("genesis_of"), Value::string(genesis)));
    }
    canonical_json_bytes(&Value::object(fields), true)
        .map_err(|err| SealError::message(err.to_string()))
}

fn append_line(path: &Path, line: Vec<u8>) -> Result<(), SealError> {
    let parent = ledger_parent(path);
    if !parent.exists() {
        return Err(SealError::message(format!(
            "ledger directory does not exist: {}",
            path_text(&parent)
        )));
    }
    if let Err(err) = write_ledger_line(path, line) {
        return Err(SealError::message(format!(
            "cannot append to ledger {}: {}",
            path_text(path),
            os_error_text(&err, path)
        )));
    }
    sync_dir(&parent);
    Ok(())
}

fn write_ledger_line(path: &Path, mut line: Vec<u8>) -> io::Result<()> {
    let mut file = open_append(path)?;
    let len = file.metadata()?.len();
    if len > 0 {
        file.seek(SeekFrom::Start(len - 1))?;
        let mut last = [0_u8; 1];
        let read = read_retry(&mut file, &mut last)?;
        if read != 1 || last[0] != b'\n' {
            let mut joined = Vec::with_capacity(line.len().saturating_add(1));
            joined.push(b'\n');
            joined.append(&mut line);
            line = joined;
        }
    }
    file.write_all(&line)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
}

/// Python `_sync_dir`. Best-effort parent directory fsync. No-op on Windows.
fn sync_dir(path: &Path) {
    #[cfg(windows)]
    {
        let _ = path;
    }
    #[cfg(not(windows))]
    {
        if let Ok(file) = File::open(path) {
            let _ = file.sync_all();
        }
    }
}

fn ledger_parent(path: &Path) -> PathBuf {
    let mut pure = pure_path(path);
    if pure.parts.is_empty() {
        if pure.rooted {
            return PathBuf::from(pure.native());
        }
        return PathBuf::from(".");
    }
    pure.parts.pop();
    if pure.parts.is_empty() && !pure.rooted && pure.anchor.is_empty() {
        return PathBuf::from(".");
    }
    PathBuf::from(pure.native())
}

/// Python `get_seal_schema_path`.
///
/// Checks the pure relative development path, then stops because
/// `sesslint._resources` is not ported. This does not call `schema_path`,
/// does not resolve `__file__`, and does not read `schemas/`.
pub fn get_seal_schema_path() -> Result<PathBuf, SealError> {
    let _path = seal_schema_development_path()?;
    Err(SealError::ResourcesUnavailable)
}

fn seal_schema_development_path() -> Result<PathBuf, SealError> {
    let path = PathBuf::from("schemas").join(SEAL_SCHEMA_FILE);
    let pure = pure_path(&path);
    if !pure.rooted
        && pure.anchor.is_empty()
        && pure.parts.len() == 2
        && pure.parts.first().map(String::as_str) == Some("schemas")
        && pure.parts.get(1).map(String::as_str) == Some(SEAL_SCHEMA_FILE)
    {
        return Ok(PathBuf::from(pure.native()));
    }
    Err(SealError::message(format!(
        "Invalid name {}",
        python_repr(SEAL_SCHEMA_FILE)
    )))
}

/// Python `load_seal_schema`.
///
/// Uses [`get_seal_schema_path`] and returns that failure. This does not test
/// `Path.is_file`, parse JSON, or read `schemas/`.
pub fn load_seal_schema() -> Result<Value, SealError> {
    get_seal_schema_path()?;
    Err(SealError::ResourcesUnavailable)
}

fn hash_built(
    input: &EntryInput<'_>,
    codes: &[(String, i64)],
    sealed_at: &str,
) -> Result<String, SealError> {
    let mut code_fields = Vec::with_capacity(codes.len());
    for (code, count) in codes {
        code_fields.push((ObjectKey::string(code.clone()), Value::int(*count)));
    }
    let mut fields = vec![
        (ObjectKey::string("schema"), Value::string(SEAL_SCHEMA_ID)),
        (ObjectKey::string("seq"), Value::int(input.seq)),
        (
            ObjectKey::string("prev_sha256"),
            Value::string(input.prev_sha256),
        ),
        (
            ObjectKey::string("file_sha256"),
            Value::string(input.file_sha256),
        ),
        (ObjectKey::string("tool"), Value::string(input.tool)),
        (ObjectKey::string("verdict"), Value::string(input.verdict)),
        (ObjectKey::string("codes"), Value::object(code_fields)),
        (
            ObjectKey::string("report_sha256"),
            Value::string(input.report_sha256),
        ),
        (ObjectKey::string("sealed_at"), Value::string(sealed_at)),
    ];
    if let Some(path) = input.path {
        fields.push((ObjectKey::string("path"), Value::string(path)));
    }
    if let Some(genesis) = input.genesis_of {
        fields.push((ObjectKey::string("genesis_of"), Value::string(genesis)));
    }
    digest_value(&Value::object(fields))
}

fn digest_value(value: &Value) -> Result<String, SealError> {
    let bytes =
        canonical_json_bytes(value, false).map_err(|err| SealError::message(err.to_string()))?;
    Ok(sha256_bytes(&bytes))
}

/// Python `_entry_hash`: SHA-256 of canonical JSON with `entry_sha256` removed.
fn hash_object(entries: &[(String, Json)]) -> Result<String, SealError> {
    let mut kept = Vec::new();
    for (key, value) in entries {
        if key != "entry_sha256" {
            kept.push((key.clone(), value.clone()));
        }
    }
    digest_value(&json_to_value(&Json::Object(kept))?)
}

fn iter_lines(path: &Path) -> Result<Vec<(i64, String)>, SealError> {
    let text = read_ledger_text(path)?;
    let mut lines = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        if python_blank(line) {
            continue;
        }
        let line_no = i64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                SealError::message("ledger line number is outside the supported range")
            })?;
        lines.push((line_no, line.to_owned()));
    }
    Ok(lines)
}

fn read_ledger_text(path: &Path) -> Result<String, SealError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(SealError::message(format!(
                "cannot read ledger {}: {}",
                path_text(path),
                os_error_text(&err, path)
            )));
        }
    };
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(err) => Err(SealError::message(format!(
            "ledger {} is not UTF-8: {}",
            path_text(path),
            utf8_message(err.as_bytes())
        ))),
    }
}

fn validate_entry_shape(entry: &Json) -> Option<&'static str> {
    let Json::Object(entries) = entry else {
        return Some("malformed-line");
    };
    match object_get(entries, "schema") {
        Some(Json::String(schema)) if schema == SEAL_SCHEMA_ID => {}
        _ => return Some("bad-schema"),
    }
    match object_get(entries, "seq") {
        Some(Json::Int(seq)) if seq.is_positive() => {}
        _ => return Some("malformed-line"),
    }
    match object_get(entries, "prev_sha256") {
        Some(Json::String(prev)) if prev == GENESIS || is_hex64(prev) => {}
        _ => return Some("malformed-line"),
    }
    for key in ["file_sha256", "report_sha256", "entry_sha256"] {
        match object_get(entries, key) {
            Some(Json::String(value)) if is_hex64(value) => {}
            _ => return Some("malformed-line"),
        }
    }
    match object_get(entries, "tool") {
        Some(Json::String(tool)) if SEAL_TOOLS.contains(&tool.as_str()) => {}
        _ => return Some("malformed-line"),
    }
    match object_get(entries, "verdict") {
        Some(Json::String(verdict)) if !verdict.is_empty() => {}
        _ => return Some("malformed-line"),
    }
    match object_get(entries, "codes") {
        Some(Json::Object(codes)) if codes.iter().all(|(_, value)| code_count_ok(value)) => {}
        _ => return Some("malformed-line"),
    }
    match object_get(entries, "sealed_at") {
        Some(Json::String(text)) if sealed_at_matches(text) => {}
        _ => return Some("malformed-line"),
    }
    if let Some(path) = object_get(entries, "path") {
        if !matches!(path, Json::String(_)) {
            return Some("malformed-line");
        }
    }
    if let Some(genesis) = object_get(entries, "genesis_of") {
        match genesis {
            Json::String(text) if is_hex64(text) => {}
            _ => return Some("malformed-line"),
        }
    }
    None
}

fn code_count_ok(value: &Json) -> bool {
    match value {
        Json::Bool(_) => true,
        Json::Int(number) => number.is_non_negative(),
        _ => false,
    }
}

fn object_get<'a>(entries: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn plain_divergence(kind: &'static str, line: i64, detail: &str) -> Divergence {
    Divergence {
        kind,
        line,
        seq: None,
        detail: detail.to_owned(),
    }
}

fn is_hex64(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn sealed_at_matches(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

fn json_to_value(json: &Json) -> Result<Value, SealError> {
    match json {
        Json::Null => Ok(Value::null()),
        Json::Bool(value) => Ok(Value::bool(*value)),
        Json::Int(number) => {
            let Some(value) = number.to_i128() else {
                return Err(SealError::message(
                    "canonical integer is outside the supported range",
                ));
            };
            Ok(Value::int_i128(value))
        }
        Json::Float(value) => Ok(Value::float(*value)),
        Json::String(text) => Ok(Value::string(text.clone())),
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_value(item)?);
            }
            Ok(Value::array(out))
        }
        Json::Object(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                out.push((ObjectKey::string(key.clone()), json_to_value(value)?));
            }
            Ok(Value::object(out))
        }
    }
}

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Int(JsonInt),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

#[derive(Clone, Debug)]
struct JsonInt {
    negative: bool,
    digits: String,
}

impl JsonInt {
    fn from_token(token: &str) -> Result<Self, ()> {
        let (negative, digits) = match token.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        if digits.len() > 1 && digits.as_bytes().first() == Some(&b'0') {
            return Err(());
        }
        if digits == "0" {
            return Ok(Self {
                negative: false,
                digits: "0".to_owned(),
            });
        }
        Ok(Self {
            negative,
            digits: digits.to_owned(),
        })
    }

    fn is_positive(&self) -> bool {
        !self.negative && self.digits != "0"
    }

    fn is_non_negative(&self) -> bool {
        !self.negative || self.digits == "0"
    }

    fn decimal(&self) -> String {
        if self.negative && self.digits != "0" {
            format!("-{}", self.digits)
        } else {
            self.digits.clone()
        }
    }

    fn eq_i64(&self, expected: i64) -> bool {
        if expected < 0 {
            return self.decimal() == expected.to_string();
        }
        !self.negative && self.digits == expected.to_string()
    }

    fn to_i128(&self) -> Option<i128> {
        if self.digits == "0" {
            return Some(0);
        }
        if self.negative && self.digits == "170141183460469231731687303715884105728" {
            return Some(i128::MIN);
        }
        if self.digits.len() > 39 {
            return None;
        }
        let mut value: i128 = 0;
        for byte in self.digits.bytes() {
            let digit = i128::from(byte - b'0');
            value = value.checked_mul(10)?.checked_add(digit)?;
        }
        if self.negative {
            value.checked_neg()
        } else {
            Some(value)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Value,
    ValueOrEnd,
    Key,
    KeyOrEnd,
    Colon,
    AfterValue,
}

enum Frame {
    Array {
        items: Vec<Json>,
        slot: Slot,
    },
    Object {
        entries: Vec<(String, Json)>,
        key: Option<String>,
        slot: Slot,
    },
}

fn frame_slot(frame: &Frame) -> Slot {
    match frame {
        Frame::Array { slot, .. } | Frame::Object { slot, .. } => *slot,
    }
}

struct Parser<'a> {
    source: &'a str,
    index: usize,
}

fn parse_json(source: &str) -> Result<Json, ()> {
    let mut parser = Parser { source, index: 0 };
    parser.skip_ws()?;
    if parser.index == parser.source.len() {
        return Err(());
    }
    let value = parser.parse_container()?;
    parser.skip_ws()?;
    if parser.index != parser.source.len() {
        return Err(());
    }
    Ok(value)
}

impl<'a> Parser<'a> {
    fn parse_container(&mut self) -> Result<Json, ()> {
        let mut frames: Vec<Frame> = Vec::new();
        loop {
            self.skip_ws()?;
            let slot = frames.last().map(frame_slot).unwrap_or(Slot::Value);
            match slot {
                Slot::Value | Slot::ValueOrEnd => {
                    if slot == Slot::ValueOrEnd && self.peek_char()? == Some(']') {
                        self.bump_char()?;
                        let value = finish_frame(&mut frames)?;
                        if let Some(done) = deliver(&mut frames, value)? {
                            return Ok(done);
                        }
                        continue;
                    }
                    match self.peek_char()? {
                        Some('[' | '{') => self.push_container(&mut frames)?,
                        Some(_) => {
                            let value = self.parse_scalar()?;
                            if let Some(done) = deliver(&mut frames, value)? {
                                return Ok(done);
                            }
                        }
                        None => return Err(()),
                    }
                }
                Slot::Key | Slot::KeyOrEnd => {
                    if slot == Slot::KeyOrEnd && self.peek_char()? == Some('}') {
                        self.bump_char()?;
                        let value = finish_frame(&mut frames)?;
                        if let Some(done) = deliver(&mut frames, value)? {
                            return Ok(done);
                        }
                        continue;
                    }
                    let key = self.parse_string()?;
                    set_key(&mut frames, key)?;
                }
                Slot::Colon => {
                    if self.peek_char()? != Some(':') {
                        return Err(());
                    }
                    self.bump_char()?;
                    set_top_slot(&mut frames, Slot::Value)?;
                }
                Slot::AfterValue => {
                    let end = container_end(&frames)?;
                    match self.peek_char()? {
                        Some(',') => {
                            self.bump_char()?;
                            let next = if top_is_array(&frames)? {
                                Slot::Value
                            } else {
                                Slot::Key
                            };
                            set_top_slot(&mut frames, next)?;
                        }
                        Some(ch) if ch == end => {
                            self.bump_char()?;
                            let value = finish_frame(&mut frames)?;
                            if let Some(done) = deliver(&mut frames, value)? {
                                return Ok(done);
                            }
                        }
                        _ => return Err(()),
                    }
                }
            }
        }
    }

    fn push_container(&mut self, frames: &mut Vec<Frame>) -> Result<(), ()> {
        if frames.len() == MAX_JSON_DEPTH {
            return Err(());
        }
        match self.peek_char()? {
            Some('[') => {
                self.bump_char()?;
                frames.push(Frame::Array {
                    items: Vec::new(),
                    slot: Slot::ValueOrEnd,
                });
                Ok(())
            }
            Some('{') => {
                self.bump_char()?;
                frames.push(Frame::Object {
                    entries: Vec::new(),
                    key: None,
                    slot: Slot::KeyOrEnd,
                });
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn parse_scalar(&mut self) -> Result<Json, ()> {
        match self.peek_char()? {
            Some('"') => Ok(Json::String(self.parse_string()?)),
            Some('t') => {
                self.eat("true")?;
                Ok(Json::Bool(true))
            }
            Some('f') => {
                self.eat("false")?;
                Ok(Json::Bool(false))
            }
            Some('n') => {
                self.eat("null")?;
                Ok(Json::Null)
            }
            Some('N') => {
                self.eat("NaN")?;
                Ok(Json::Float(f64::NAN))
            }
            Some('I') => {
                self.eat("Infinity")?;
                Ok(Json::Float(f64::INFINITY))
            }
            Some('-') if self.starts_with("-Infinity")? => {
                self.eat("-Infinity")?;
                Ok(Json::Float(f64::NEG_INFINITY))
            }
            Some('-' | '0'..='9') => self.parse_number(),
            _ => Err(()),
        }
    }

    fn parse_number(&mut self) -> Result<Json, ()> {
        let start = self.index;
        if self.peek_char()? == Some('-') {
            self.bump_char()?;
        }
        match self.peek_char()? {
            Some('0') => {
                self.bump_char()?;
                if matches!(self.peek_char()?, Some('0'..='9')) {
                    return Err(());
                }
            }
            Some('1'..='9') => {
                while matches!(self.peek_char()?, Some('0'..='9')) {
                    self.bump_char()?;
                }
            }
            _ => return Err(()),
        }
        let mut is_float = false;
        if self.peek_char()? == Some('.') {
            is_float = true;
            self.bump_char()?;
            if !self.consume_digits()? {
                return Err(());
            }
        }
        if matches!(self.peek_char()?, Some('e' | 'E')) {
            is_float = true;
            self.bump_char()?;
            if matches!(self.peek_char()?, Some('+' | '-')) {
                self.bump_char()?;
            }
            if !self.consume_digits()? {
                return Err(());
            }
        }
        let token = self.source.get(start..self.index).ok_or(())?;
        if is_float {
            let value = token.parse::<f64>().map_err(|_| ())?;
            Ok(Json::Float(value))
        } else {
            Ok(Json::Int(JsonInt::from_token(token)?))
        }
    }

    fn consume_digits(&mut self) -> Result<bool, ()> {
        let start = self.index;
        while matches!(self.peek_char()?, Some('0'..='9')) {
            self.bump_char()?;
        }
        Ok(self.index > start)
    }

    fn parse_string(&mut self) -> Result<String, ()> {
        if self.peek_char()? != Some('"') {
            return Err(());
        }
        self.bump_char()?;
        let mut out = String::new();
        loop {
            match self.peek_char()? {
                None => return Err(()),
                Some('"') => {
                    self.bump_char()?;
                    return Ok(out);
                }
                Some('\\') => {
                    self.bump_char()?;
                    self.parse_escape(&mut out)?;
                }
                Some(ch) if u32::from(ch) < 0x20 => return Err(()),
                Some(ch) => {
                    out.push(ch);
                    self.bump_char()?;
                }
            }
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), ()> {
        match self.peek_char()? {
            Some(ch @ ('"' | '\\' | '/')) => {
                self.bump_char()?;
                out.push(ch);
                Ok(())
            }
            Some('b') => {
                self.bump_char()?;
                out.push('\u{0008}');
                Ok(())
            }
            Some('f') => {
                self.bump_char()?;
                out.push('\u{000c}');
                Ok(())
            }
            Some('n') => {
                self.bump_char()?;
                out.push('\n');
                Ok(())
            }
            Some('r') => {
                self.bump_char()?;
                out.push('\r');
                Ok(())
            }
            Some('t') => {
                self.bump_char()?;
                out.push('\t');
                Ok(())
            }
            Some('u') => {
                self.bump_char()?;
                self.push_unicode(out)
            }
            _ => Err(()),
        }
    }

    fn push_unicode(&mut self, out: &mut String) -> Result<(), ()> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if !self.starts_with("\\u")? {
                return Err(());
            }
            self.bump_char()?;
            self.bump_char()?;
            let low = self.read_hex4()?;
            let Some(ch) = paired_surrogate(code, low) else {
                return Err(());
            };
            out.push(ch);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(());
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(());
        };
        out.push(ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, ()> {
        let end = self.index.checked_add(4).ok_or(())?;
        let chunk = self.source.get(self.index..end).ok_or(())?;
        if chunk.len() != 4 {
            return Err(());
        }
        let mut value = 0_u32;
        for byte in chunk.bytes() {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return Err(()),
            };
            value = (value << 4) | digit;
        }
        self.index = end;
        Ok(value)
    }

    fn eat(&mut self, literal: &str) -> Result<(), ()> {
        if !self.starts_with(literal)? {
            return Err(());
        }
        self.index = self.index.checked_add(literal.len()).ok_or(())?;
        Ok(())
    }

    fn starts_with(&self, literal: &str) -> Result<bool, ()> {
        let rest = self.source.get(self.index..).ok_or(())?;
        Ok(rest.starts_with(literal))
    }

    fn skip_ws(&mut self) -> Result<(), ()> {
        while matches!(self.peek_char()?, Some(' ' | '\t' | '\n' | '\r')) {
            self.bump_char()?;
        }
        Ok(())
    }

    fn peek_char(&self) -> Result<Option<char>, ()> {
        let rest = self.source.get(self.index..).ok_or(())?;
        Ok(rest.chars().next())
    }

    fn bump_char(&mut self) -> Result<(), ()> {
        let Some(ch) = self.peek_char()? else {
            return Err(());
        };
        self.index = self.index.checked_add(ch.len_utf8()).ok_or(())?;
        Ok(())
    }
}

fn finish_frame(frames: &mut Vec<Frame>) -> Result<Json, ()> {
    match frames.pop() {
        Some(Frame::Array { items, .. }) => Ok(Json::Array(items)),
        Some(Frame::Object { entries, .. }) => Ok(Json::Object(entries)),
        None => Err(()),
    }
}

fn deliver(frames: &mut [Frame], value: Json) -> Result<Option<Json>, ()> {
    if frames.is_empty() {
        return Ok(Some(value));
    }
    match frames.last_mut() {
        Some(Frame::Array { items, slot }) => {
            items.push(value);
            *slot = Slot::AfterValue;
            Ok(None)
        }
        Some(Frame::Object { entries, key, slot }) => {
            let Some(name) = key.take() else {
                return Err(());
            };
            if let Some(found) = entries.iter_mut().find(|(existing, _)| existing == &name) {
                found.1 = value;
            } else {
                entries.push((name, value));
            }
            *slot = Slot::AfterValue;
            Ok(None)
        }
        None => Ok(Some(value)),
    }
}

fn set_key(frames: &mut [Frame], key: String) -> Result<(), ()> {
    match frames.last_mut() {
        Some(Frame::Object {
            key: slot,
            slot: state,
            ..
        }) => {
            *slot = Some(key);
            *state = Slot::Colon;
            Ok(())
        }
        _ => Err(()),
    }
}

fn set_top_slot(frames: &mut [Frame], slot: Slot) -> Result<(), ()> {
    match frames.last_mut() {
        Some(Frame::Array { slot: current, .. } | Frame::Object { slot: current, .. }) => {
            *current = slot;
            Ok(())
        }
        None => Err(()),
    }
}

fn container_end(frames: &[Frame]) -> Result<char, ()> {
    match frames.last() {
        Some(Frame::Array { .. }) => Ok(']'),
        Some(Frame::Object { .. }) => Ok('}'),
        None => Err(()),
    }
}

fn top_is_array(frames: &[Frame]) -> Result<bool, ()> {
    match frames.last() {
        Some(Frame::Array { .. }) => Ok(true),
        Some(Frame::Object { .. }) => Ok(false),
        None => Err(()),
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let point = 0x1_0000 + (((high - 0xD800) << 10) | (low - 0xDC00));
    char::from_u32(point)
}

fn lock_sidecar(path: &Path) -> Result<PathBuf, SealError> {
    let pure = pure_path(path);
    let name = pure.name();
    if name.is_empty() {
        return Err(SealError::message(format!(
            "{} has an empty name",
            path_repr(path)
        )));
    }
    let new_name = format!("{name}.lock");
    if new_name == "." || new_name == ".." || new_name.contains(['/', '\\']) {
        return Err(SealError::message(format!(
            "Invalid name {}",
            python_repr(&new_name)
        )));
    }
    Ok(PathBuf::from(pure.with_last(&new_name).native()))
}

fn open_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn is_symlink(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

struct PurePath {
    anchor: String,
    rooted: bool,
    parts: Vec<String>,
}

impl PurePath {
    fn name(&self) -> &str {
        match self.parts.last() {
            Some(part) => part.as_str(),
            None => "",
        }
    }

    fn with_last(&self, name: &str) -> Self {
        let mut parts = self.parts.clone();
        if let Some(last) = parts.last_mut() {
            *last = name.to_owned();
        }
        Self {
            anchor: self.anchor.clone(),
            rooted: self.rooted,
            parts,
        }
    }

    fn native(&self) -> String {
        let sep = native_sep();
        if self.parts.is_empty() {
            if self.anchor.is_empty() {
                return ".".to_owned();
            }
            return self.anchor.clone();
        }
        if self.rooted {
            let mut out = self.anchor.clone();
            out.push_str(&join_sep(&self.parts, sep));
            return out;
        }
        if self.anchor.is_empty() {
            return join_sep(&self.parts, sep);
        }
        let mut out = self.anchor.clone();
        out.push_str(&self.parts[0]);
        if self.parts.len() > 1 {
            out.push(sep);
            out.push_str(&join_sep(&self.parts[1..], sep));
        }
        out
    }

    fn posix(&self) -> String {
        self.native().replace('\\', "/")
    }
}

fn pure_path(path: &Path) -> PurePath {
    let mut anchor = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => {
                anchor.push_str(&prefix.as_os_str().to_string_lossy());
            }
            Component::RootDir => {
                rooted = true;
                anchor.push(native_sep());
            }
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
        }
    }
    PurePath {
        anchor,
        rooted,
        parts,
    }
}

fn path_text(path: &Path) -> String {
    pure_path(path).native()
}

fn path_repr(path: &Path) -> String {
    let class = if cfg!(windows) {
        "WindowsPath"
    } else {
        "PosixPath"
    };
    format!("{class}({})", python_repr(&pure_path(path).posix()))
}

fn native_sep() -> char {
    if cfg!(windows) {
        '\\'
    } else {
        '/'
    }
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

fn python_blank(text: &str) -> bool {
    text.chars().all(is_python_space)
}

fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000a}'
            | '\u{000b}'
            | '\u{000c}'
            | '\u{000d}'
            | '\u{001c}'
            | '\u{001d}'
            | '\u{001e}'
            | '\u{001f}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

fn os_error_text(err: &io::Error, path: &Path) -> String {
    let quoted = python_repr(&path_text(path));
    match err.kind() {
        io::ErrorKind::NotFound => format!("[Errno 2] No such file or directory: {quoted}"),
        io::ErrorKind::PermissionDenied => format!("[Errno 13] Permission denied: {quoted}"),
        io::ErrorKind::AlreadyExists => format!("[Errno 17] File exists: {quoted}"),
        io::ErrorKind::IsADirectory => format!("[Errno 21] Is a directory: {quoted}"),
        _ => {
            if let Some(code) = err.raw_os_error() {
                format!("[os error {code}]: {quoted}")
            } else {
                format!("[os error]: {quoted}")
            }
        }
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
        let byte = match bytes.get(start) {
            Some(byte) => *byte,
            None => 0,
        };
        format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {start}: {reason}")
    } else {
        let last = end.saturating_sub(1);
        format!("'utf-8' codec can't decode bytes in position {start}-{last}: {reason}")
    }
}

fn utf8_fault(bytes: &[u8]) -> Option<(usize, usize, &'static str)> {
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        if first < 0x80 {
            index += 1;
            continue;
        }
        if !(0xC2..=0xF4).contains(&first) {
            return Some((index, index + 1, "invalid start byte"));
        }
        let (need, low, high) = if first <= 0xDF {
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
        };
        for step in 1..need {
            if index + step >= bytes.len() {
                return Some((index, index + step, "unexpected end of data"));
            }
            let byte = bytes[index + step];
            let continuation = (byte & 0xC0) == 0x80;
            if step == 1 {
                if !continuation || !(low..=high).contains(&byte) {
                    return Some((index, index + 1, "invalid continuation byte"));
                }
            } else if !continuation {
                return Some((index, index + step, "invalid continuation byte"));
            }
        }
        index += need;
    }
    None
}

fn python_repr(text: &str) -> String {
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
            other if u32::from(other) < 0x20 || other == '\u{7f}' => {
                body.push_str(&format!("\\x{:02x}", u32::from(other)));
            }
            other => body.push(other),
        }
    }
    format!("{quote}{body}{quote}")
}

fn read_retry(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(buf) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn format_offset(micros_east: i128) -> String {
    let negative = micros_east < 0;
    let abs = micros_east.unsigned_abs();
    let sign = if negative { '-' } else { '+' };
    let hours = abs / 3_600_000_000;
    let mut rem = abs % 3_600_000_000;
    let mins = rem / 60_000_000;
    rem %= 60_000_000;
    let secs = rem / 1_000_000;
    let micros = rem % 1_000_000;
    let mut out = format!("{sign}{hours:02}:{mins:02}");
    if secs != 0 || micros != 0 {
        out.push_str(&format!(":{secs:02}"));
        if micros != 0 {
            out.push_str(&format!(".{micros:06}"));
        }
    }
    out
}

fn offset_error(micros: i128) -> String {
    format!(
        "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not {}.",
        timedelta_repr(micros)
    )
}

fn timedelta_repr(total: i128) -> String {
    const DAY: u128 = 86_400_000_000;
    if total >= 0 {
        let abs = total.unsigned_abs();
        let days = match i128::try_from(abs / DAY) {
            Ok(days) => days,
            Err(_) => i128::MAX,
        };
        let rem = abs % DAY;
        return format_parts(days, rem / 1_000_000, rem % 1_000_000);
    }
    let abs = total.unsigned_abs();
    let days = abs / DAY;
    let rem = abs % DAY;
    if rem == 0 {
        return format!("datetime.timedelta(days=-{days})");
    }
    let borrowed = DAY.saturating_sub(rem);
    let neg_days = days.saturating_add(1);
    format_parts(
        match i128::try_from(neg_days) {
            Ok(days) => -days,
            Err(_) => i128::MIN,
        },
        borrowed / 1_000_000,
        borrowed % 1_000_000,
    )
}

fn format_parts(days: i128, seconds: u128, micros: u128) -> String {
    let mut args = Vec::new();
    if days != 0 {
        args.push(format!("days={days}"));
    }
    if seconds != 0 {
        args.push(format!("seconds={seconds}"));
    }
    if micros != 0 {
        args.push(format!("microseconds={micros}"));
    }
    if args.is_empty() {
        return "datetime.timedelta(0)".to_owned();
    }
    format!("datetime.timedelta({})", args.join(", "))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const GOLDEN_HASH: &str = "8deebdaa4d34b446334a5f9802448e67271a9aa2d3dba8579f73063d5b97f15e";
    const BOOL_HASH: &str = "9862fd74d2d5255990dd174c5e4737bf5eaf6330257ca4f14dbf6698b5d409f4";
    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sesslint-seal-synthetic-{id}-{}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
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

    fn fixed() -> SealInstant {
        SealInstant::utc(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample_entry(path: Option<&str>) -> SealEntry {
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let now = fixed();
        let codes = [("SL101", 2_i64)];
        build_entry(EntryInput {
            seq: 1,
            prev_sha256: GENESIS,
            file_sha256: &file,
            path,
            tool: "check",
            verdict: "healthy",
            codes: &codes,
            report_sha256: &report,
            genesis_of: None,
            now: &now,
        })
        .unwrap()
    }

    fn canonical_line(entry: &SealEntry) -> String {
        let mut codes = Vec::new();
        for (code, count) in &entry.codes {
            codes.push((ObjectKey::string(code.clone()), Value::int(*count)));
        }
        let mut fields = vec![
            (ObjectKey::string("schema"), Value::string(entry.schema)),
            (ObjectKey::string("seq"), Value::int(entry.seq)),
            (
                ObjectKey::string("prev_sha256"),
                Value::string(&entry.prev_sha256),
            ),
            (
                ObjectKey::string("file_sha256"),
                Value::string(&entry.file_sha256),
            ),
            (ObjectKey::string("tool"), Value::string(&entry.tool)),
            (ObjectKey::string("verdict"), Value::string(&entry.verdict)),
            (ObjectKey::string("codes"), Value::object(codes)),
            (
                ObjectKey::string("report_sha256"),
                Value::string(&entry.report_sha256),
            ),
            (
                ObjectKey::string("sealed_at"),
                Value::string(&entry.sealed_at),
            ),
            (
                ObjectKey::string("entry_sha256"),
                Value::string(&entry.entry_sha256),
            ),
        ];
        if let Some(path) = &entry.path {
            fields.push((ObjectKey::string("path"), Value::string(path)));
        }
        if let Some(genesis) = &entry.genesis_of {
            fields.push((ObjectKey::string("genesis_of"), Value::string(genesis)));
        }
        let bytes = canonical_json_bytes(&Value::object(fields), false).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn linked(seq: i64, prev: &str, file_byte: u8, now: &SealInstant) -> SealEntry {
        let file = format!("{file_byte:02x}").repeat(32);
        let report = "b".repeat(64);
        build_entry(EntryInput {
            seq,
            prev_sha256: prev,
            file_sha256: &file,
            path: None,
            tool: "check",
            verdict: "healthy",
            codes: &[],
            report_sha256: &report,
            genesis_of: None,
            now,
        })
        .unwrap()
    }

    fn locking_text() -> &'static str {
        if cfg!(windows) {
            "msvcrt.locking is not available"
        } else {
            "fcntl.flock is not available"
        }
    }

    #[test]
    fn sha256_bytes_matches_hashlib() {
        assert_eq!(sha256_bytes(b""), EMPTY_HASH);
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_file_streams_chunks() {
        let scratch = Scratch::new();
        let path = scratch.join("bytes.bin");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::write(&path, b"").unwrap();
        assert_eq!(sha256_file(&path).unwrap(), EMPTY_HASH);
        let mut bulky = vec![b'a'; CHUNK + 3];
        bulky[0] = b'q';
        bulky[CHUNK] = b'z';
        fs::write(&path, &bulky).unwrap();
        assert_eq!(sha256_file(&path).unwrap(), sha256_bytes(&bulky));
    }

    #[test]
    fn build_entry_matches_pin_hash_for_fixed_instant() {
        let entry = sample_entry(Some("sess.jsonl"));
        assert_eq!(entry.schema, SEAL_SCHEMA_ID);
        assert_eq!(entry.sealed_at, "2026-01-01T00:00:00Z");
        assert_eq!(entry.entry_sha256, GOLDEN_HASH);
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let expected = format!(
            "{{\"codes\":{{\"SL101\":2}},\"file_sha256\":\"{file}\",\"path\":\"sess.jsonl\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"tool\":\"check\",\"verdict\":\"healthy\"}}"
        );
        assert_eq!(sha256_bytes(expected.as_bytes()), GOLDEN_HASH);
        let again = sample_entry(Some("sess.jsonl"));
        assert_eq!(entry, again);
    }

    #[test]
    fn build_entry_rejects_closed_vocabulary() {
        let now = fixed();
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let codes = [("SL101", 2_i64)];
        let bad_codes = [("SL001", -1_i64)];
        let build =
            |seq, prev: &str, file_sha: &str, tool: &str, verdict: &str, codes: &[(&str, i64)]| {
                build_entry(EntryInput {
                    seq,
                    prev_sha256: prev,
                    file_sha256: file_sha,
                    path: None,
                    tool,
                    verdict,
                    codes,
                    report_sha256: &report,
                    genesis_of: None,
                    now: &now,
                })
            };
        assert_eq!(
            build(0, GENESIS, &file, "check", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "seq must be a positive integer, got 0"
        );
        assert_eq!(
            build(-1, GENESIS, &file, "check", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "seq must be a positive integer, got -1"
        );
        assert_eq!(
            build(1, &"z".repeat(64), &file, "check", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "prev_sha256 must be 'GENESIS' or a sha256 hex digest"
        );
        assert_eq!(
            build(1, GENESIS, "not-hex", "check", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "file_sha256 must be a sha256 hex digest"
        );
        assert_eq!(
            build(1, GENESIS, &"A".repeat(64), "check", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "file_sha256 must be a sha256 hex digest"
        );
        assert_eq!(
            build(1, GENESIS, &file, "scan", "healthy", &codes)
                .unwrap_err()
                .to_string(),
            "tool must be one of ['check', 'repair', 'verify'], got 'scan'"
        );
        assert_eq!(
            build(1, GENESIS, &file, "check", "", &codes)
                .unwrap_err()
                .to_string(),
            "verdict must be a non-empty string"
        );
        assert_eq!(
            build(1, GENESIS, &file, "check", "healthy", &bad_codes)
                .unwrap_err()
                .to_string(),
            "codes must map code strings to non-negative ints: 'SL001'"
        );
    }

    #[test]
    fn sealed_at_follows_pin_replace() {
        let utc = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 999_999, Some(0)).unwrap();
        assert_eq!(utc.sealed_text(), "2026-01-01T00:00:00Z");
        let plus = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(7 * 3_600_000_000)).unwrap();
        assert_eq!(plus.sealed_text(), "2026-01-01T00:00:00+07:00");
        let minus = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(-19_800_000_000)).unwrap();
        assert_eq!(minus.sealed_text(), "2026-01-01T00:00:00-05:30");
        let naive = SealInstant::naive(2026, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(naive.sealed_text(), "2026-01-01T00:00:00");
        let year_one = SealInstant::utc(1, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(year_one.sealed_text(), "0001-01-01T00:00:00Z");
        let one_second = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(1_000_000)).unwrap();
        assert_eq!(one_second.sealed_text(), "2026-01-01T00:00:00Z:01");
        let minus_second = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(-1_000_000)).unwrap();
        assert_eq!(minus_second.sealed_text(), "2026-01-01T00:00:00-00:00:01");
        let one_micro = SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(1)).unwrap();
        assert_eq!(one_micro.sealed_text(), "2026-01-01T00:00:00Z:00.000001");
        let almost = SealInstant::try_new(
            2026,
            1,
            1,
            0,
            0,
            0,
            0,
            Some(23 * 3_600_000_000 + 59 * 60_000_000),
        )
        .unwrap();
        assert_eq!(almost.sealed_text(), "2026-01-01T00:00:00+23:59");
    }

    #[test]
    fn instant_validation_matches_datetime_text() {
        assert_eq!(
            SealInstant::utc(0, 1, 1, 0, 0, 0).unwrap_err().to_string(),
            "year 0 is out of range"
        );
        assert_eq!(
            SealInstant::utc(10_000, 1, 1, 0, 0, 0)
                .unwrap_err()
                .to_string(),
            "year 10000 is out of range"
        );
        assert_eq!(
            SealInstant::utc(2026, 13, 1, 0, 0, 0)
                .unwrap_err()
                .to_string(),
            "month must be in 1..12"
        );
        assert_eq!(
            SealInstant::utc(2026, 2, 29, 0, 0, 0)
                .unwrap_err()
                .to_string(),
            "day is out of range for month"
        );
        assert!(SealInstant::utc(2024, 2, 29, 0, 0, 0).is_ok());
        assert!(SealInstant::utc(2000, 2, 29, 0, 0, 0).is_ok());
        assert!(SealInstant::utc(1900, 2, 29, 0, 0, 0).is_err());
        assert_eq!(
            SealInstant::try_new(2026, 1, 1, 24, 0, 0, 0, Some(0))
                .unwrap_err()
                .to_string(),
            "hour must be in 0..23"
        );
        assert_eq!(
            SealInstant::try_new(2026, 1, 1, 0, 0, 0, 1_000_000, Some(0))
                .unwrap_err()
                .to_string(),
            "microsecond must be in 0..999999"
        );
        assert_eq!(
            SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(DAY_MICROS))
                .unwrap_err()
                .to_string(),
            "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not datetime.timedelta(days=1)."
        );
        assert_eq!(
            SealInstant::try_new(2026, 1, 1, 0, 0, 0, 0, Some(-DAY_MICROS))
                .unwrap_err()
                .to_string(),
            "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not datetime.timedelta(days=-1)."
        );
    }

    #[test]
    fn verify_lines_accepts_bool_code_and_rejects_shape() {
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let raw = format!(
            "{{\"codes\":{{\"SL101\":true}},\"entry_sha256\":\"{BOOL_HASH}\",\"file_sha256\":\"{file}\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"tool\":\"check\",\"verdict\":\"healthy\"}}"
        );
        assert!(verify_lines(&[(1, raw.as_str())]).unwrap().is_none());

        let upper = raw.replace(&file, &"A".repeat(64));
        let div = verify_lines(&[(4, upper.as_str())]).unwrap().unwrap();
        assert_eq!(div.kind, "malformed-line");
        assert_eq!(div.detail, "entry fields are malformed or missing");
        assert!(div.seq.is_none());

        let div = verify_lines(&[(2, "{}")]).unwrap().unwrap();
        assert_eq!(div.kind, "bad-schema");
        assert_eq!(
            div.detail,
            "document is not a sesslint.seal-ledger/v1 entry"
        );
        let div = verify_lines(&[(3, "[]")]).unwrap().unwrap();
        assert_eq!(div.kind, "malformed-line");
        assert_eq!(div.detail, "entry fields are malformed or missing");
        let div = verify_lines(&[(1, "01")]).unwrap().unwrap();
        assert_eq!(div.detail, "line is not valid JSON (edit or truncation)");
        let div = verify_lines(&[(1, "{")]).unwrap().unwrap();
        assert_eq!(div.detail, "line is not valid JSON (edit or truncation)");
    }

    #[test]
    fn verify_lines_reports_chain_faults_and_wide_integers() {
        let now = fixed();
        let first = linked(1, GENESIS, 0, &now);
        let second = linked(2, &first.entry_sha256, 1, &now);
        let third = linked(3, &second.entry_sha256, 2, &now);
        let lines = [
            canonical_line(&first),
            canonical_line(&second),
            canonical_line(&third),
        ];
        let borrowed: Vec<(i64, &str)> = lines
            .iter()
            .enumerate()
            .map(|(index, line)| (i64::try_from(index).unwrap() + 1, line.as_str()))
            .collect();
        assert!(verify_lines(&borrowed).unwrap().is_none());

        let mut edited = lines.clone();
        edited[1] = edited[1].replace("healthy", "invalid");
        let borrowed: Vec<(i64, &str)> = edited
            .iter()
            .enumerate()
            .map(|(index, line)| (i64::try_from(index).unwrap() + 1, line.as_str()))
            .collect();
        let div = verify_lines(&borrowed).unwrap().unwrap();
        assert_eq!(div.kind, "hash-mismatch");
        assert_eq!(div.line, 2);
        assert_eq!(div.seq.as_deref(), Some("2"));
        assert_eq!(
            div.detail,
            "entry_sha256 does not match the entry contents (line edited)"
        );

        let skipped = [lines[0].as_str(), lines[2].as_str()];
        let borrowed = [(1_i64, skipped[0]), (2, skipped[1])];
        let div = verify_lines(&borrowed).unwrap().unwrap();
        assert_eq!(div.kind, "seq-gap");
        assert_eq!(div.detail, "expected seq 2, found 3 (line drop or reorder)");

        let line = canonical_line(&second).replace(
            &format!("\"prev_sha256\":\"{}\"", first.entry_sha256),
            "\"prev_sha256\":\"GENESIS\"",
        );
        let borrowed = [(1_i64, lines[0].as_str()), (2, line.as_str())];
        let div = verify_lines(&borrowed).unwrap().unwrap();
        assert_eq!(div.kind, "chain-break");
        assert_eq!(
            div.detail,
            "prev_sha256 does not bind to the previous entry hash"
        );

        let digits = format!("1{}", "0".repeat(40));
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let hash = "c".repeat(64);
        let wide_seq = format!(
            "{{\"codes\":{{}},\"entry_sha256\":\"{hash}\",\"file_sha256\":\"{file}\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":{digits},\"tool\":\"check\",\"verdict\":\"healthy\"}}"
        );
        let div = verify_lines(&[(1, wide_seq.as_str())]).unwrap().unwrap();
        assert_eq!(div.kind, "seq-gap");
        assert_eq!(div.seq.as_deref(), Some(digits.as_str()));

        let wide_extra = format!(
            "{{\"codes\":{{}},\"entry_sha256\":\"{hash}\",\"extra\":{digits},\"file_sha256\":\"{file}\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"tool\":\"check\",\"verdict\":\"healthy\"}}"
        );
        assert_eq!(
            verify_lines(&[(1, wide_extra.as_str())])
                .unwrap_err()
                .to_string(),
            "canonical integer is outside the supported range"
        );

        let nan = format!(
            "{{\"codes\":{{}},\"entry_sha256\":\"{hash}\",\"extra\":NaN,\"file_sha256\":\"{file}\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"tool\":\"check\",\"verdict\":\"healthy\"}}"
        );
        assert_eq!(
            verify_lines(&[(1, nan.as_str())]).unwrap_err().to_string(),
            "Float value nan is not valid in SessLint canonical JSON"
        );
    }

    #[test]
    fn json_nesting_matches_cpython_ceiling() {
        let ok = format!("{}{}", "[".repeat(995), "]".repeat(995));
        let div = verify_lines(&[(1, ok.as_str())]).unwrap().unwrap();
        assert_eq!(div.kind, "malformed-line");
        assert_eq!(div.detail, "entry fields are malformed or missing");
        let bad = format!("{}{}", "[".repeat(996), "]".repeat(996));
        let div = verify_lines(&[(1, bad.as_str())]).unwrap().unwrap();
        assert_eq!(div.detail, "line is not valid JSON (edit or truncation)");
    }

    #[test]
    fn verify_ledger_counts_blank_lines_and_io_errors() {
        let scratch = Scratch::new();
        let missing = scratch.join("absent.jsonl");
        assert_eq!(
            verify_ledger(&missing).unwrap_err().to_string(),
            format!("ledger not found: {}", path_text(&missing))
        );
        assert_eq!(
            verify_ledger(&scratch.path).unwrap_err().to_string(),
            format!("ledger not found: {}", path_text(&scratch.path))
        );
        let ledger = scratch.join("empty.jsonl");
        fs::write(&ledger, b"").unwrap();
        assert_eq!(verify_ledger(&ledger).unwrap(), (0, None));

        let now = fixed();
        let first = linked(1, GENESIS, 0, &now);
        let second = linked(2, &first.entry_sha256, 1, &now);
        let text = format!(
            "\n{}\n\n{}\n",
            canonical_line(&first),
            canonical_line(&second)
        );
        fs::write(&ledger, text.as_bytes()).unwrap();
        assert_eq!(verify_ledger(&ledger).unwrap().0, 2);
        assert!(verify_ledger(&ledger).unwrap().1.is_none());

        let bad = scratch.join("bad.jsonl");
        fs::write(&bad, [0xff]).unwrap();
        let err = iter_lines(&bad).unwrap_err().to_string();
        assert_eq!(
            err,
            format!(
                "ledger {} is not UTF-8: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
                path_text(&bad)
            )
        );
        let gone = scratch.join("missing-read.jsonl");
        let err = iter_lines(&gone).unwrap_err().to_string();
        assert_eq!(
            err,
            format!(
                "cannot read ledger {}: [Errno 2] No such file or directory: {}",
                path_text(&gone),
                python_repr(&path_text(&gone))
            )
        );
        let err = iter_lines(&scratch.path).unwrap_err().to_string();
        assert!(err.contains("cannot read ledger"), "{err}");
    }

    #[test]
    fn ledger_lock_closes_without_appending() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let err = ledger_lock(&ledger).unwrap_err();
        assert_eq!(err.to_string(), locking_text());
        assert!(!ledger.exists());
        let lock = scratch.join("ledger.jsonl.lock");
        assert!(lock.is_file());
        assert_eq!(fs::read(&lock).unwrap(), b"");
        fs::remove_file(&lock).unwrap();
        fs::write(&lock, b"synthetic").unwrap();
        let err = ledger_lock(&ledger).unwrap_err();
        assert_eq!(err.to_string(), locking_text());
        assert_eq!(fs::read(&lock).unwrap(), b"synthetic");
        assert!(!ledger.exists());

        let missing = scratch.join("no-such-dir").join("ledger.jsonl");
        assert_eq!(
            ledger_lock(&missing).unwrap_err().to_string(),
            "cannot open ledger lock"
        );
        assert_eq!(
            lock_sidecar(Path::new(".")).unwrap_err().to_string(),
            if cfg!(windows) {
                "WindowsPath('.') has an empty name"
            } else {
                "PosixPath('.') has an empty name"
            }
        );
        assert_eq!(
            lock_sidecar(Path::new("..")).unwrap(),
            PathBuf::from("...lock")
        );
    }

    #[test]
    fn path_text_matches_pure_path() {
        let expected = if cfg!(windows) { "a\\b" } else { "a/b" };
        assert_eq!(path_text(Path::new("a/./b")), expected);
        let parent = if cfg!(windows) { "a\\..\\b" } else { "a/../b" };
        assert_eq!(path_text(Path::new("a/../b")), parent);
        assert_eq!(path_text(Path::new(".")), ".");
        assert_eq!(path_text(Path::new("")), ".");
        assert_eq!(path_text(Path::new("ledger.jsonl")), "ledger.jsonl");
    }

    #[test]
    fn utf8_faults_match_cpython_messages() {
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
                &[0xc3, 0x28],
                "'utf-8' codec can't decode byte 0xc3 in position 0: invalid continuation byte",
            ),
            (
                &[0xe2, 0x82],
                "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data",
            ),
            (
                &[0xe2, 0x82, 0x28],
                "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte",
            ),
            (
                &[0xed, 0xa0, 0x80],
                "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
            ),
            (
                &[0xc0, 0x80],
                "'utf-8' codec can't decode byte 0xc0 in position 0: invalid start byte",
            ),
            (
                &[0xf4, 0x90, 0x80, 0x80],
                "'utf-8' codec can't decode byte 0xf4 in position 0: invalid continuation byte",
            ),
        ];
        for (bytes, message) in samples {
            assert_eq!(utf8_message(bytes), *message, "{bytes:?}");
            assert!(std::str::from_utf8(bytes).is_err());
        }
        assert!(utf8_fault(b"ok").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn ledger_lock_refuses_symlink_when_the_os_allows_one() {
        let scratch = Scratch::new();
        let target = scratch.join("target.bin");
        fs::write(&target, b"synthetic-lock-target").unwrap();
        let ledger = scratch.join("ledger.jsonl");
        let link = scratch.join("ledger.jsonl.lock");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            return;
        }
        let err = ledger_lock(&ledger).unwrap_err();
        assert_eq!(err.to_string(), "ledger lock must not be a symlink");
        assert_eq!(fs::read(&target).unwrap(), b"synthetic-lock-target");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!ledger.exists());
    }

    fn check_input<'a>(
        ledger: &'a Path,
        file_sha256: &'a str,
        report_sha256: &'a str,
        path: Option<&'a str>,
        codes: &'a [(&'a str, i64)],
        genesis_of: Option<&'a str>,
        now: &'a SealInstant,
    ) -> AppendInput<'a> {
        AppendInput {
            ledger,
            tool: "check",
            file_sha256,
            path,
            verdict: "healthy",
            codes,
            report_sha256,
            genesis_of,
            now,
        }
    }

    #[test]
    fn append_seal_propagates_lock_and_does_not_write() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let now = fixed();
        let report = "b".repeat(64);
        let file = "a".repeat(64);
        let err =
            append_seal(check_input(&ledger, &file, &report, None, &[], None, &now)).unwrap_err();
        assert_eq!(err.to_string(), locking_text());
        assert!(!ledger.exists());
        let lock = scratch.join("ledger.jsonl.lock");
        assert!(lock.is_file());
        assert_eq!(fs::read(&lock).unwrap(), b"");

        fs::write(&ledger, b"synthetic-ledger-bytes").unwrap();
        let err =
            append_seal(check_input(&ledger, &file, &report, None, &[], None, &now)).unwrap_err();
        assert_eq!(err.to_string(), locking_text());
        assert_eq!(fs::read(&ledger).unwrap(), b"synthetic-ledger-bytes");

        let missing = scratch.join("no-such-dir").join("ledger.jsonl");
        let err =
            append_seal(check_input(&missing, &file, &report, None, &[], None, &now)).unwrap_err();
        assert_eq!(err.to_string(), "cannot open ledger lock");
        assert!(!missing.exists());
        assert!(!scratch.join("no-such-dir").exists());
    }

    #[test]
    fn append_seal_locked_writes_canonical_line_for_fixed_instant() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let now = fixed();
        let file = "a".repeat(64);
        let report = "b".repeat(64);
        let codes = [("SL101", 2_i64)];
        let entry = append_seal_locked(check_input(
            &ledger,
            &file,
            &report,
            Some("sess.jsonl"),
            &codes,
            None,
            &now,
        ))
        .unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.prev_sha256, GENESIS);
        assert_eq!(entry.sealed_at, "2026-01-01T00:00:00Z");
        assert_eq!(entry.entry_sha256, GOLDEN_HASH);
        let expected = format!(
            "{{\"codes\":{{\"SL101\":2}},\"entry_sha256\":\"{GOLDEN_HASH}\",\"file_sha256\":\"{file}\",\"path\":\"sess.jsonl\",\"prev_sha256\":\"GENESIS\",\"report_sha256\":\"{report}\",\"schema\":\"sesslint.seal-ledger/v1\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"tool\":\"check\",\"verdict\":\"healthy\"}}\n"
        );
        let bytes = fs::read(&ledger).unwrap();
        assert_eq!(bytes, expected.as_bytes());
        assert!(!bytes.contains(&b'\r'));
        let again = append_seal_locked(check_input(
            &scratch.join("other.jsonl"),
            &file,
            &report,
            Some("sess.jsonl"),
            &codes,
            None,
            &now,
        ))
        .unwrap();
        assert_eq!(again, entry);
    }

    #[test]
    fn append_seal_locked_chains_and_refuses_divergence() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let now = fixed();
        let report = "b".repeat(64);
        let mut prev = GENESIS.to_owned();
        for seq in 1..=3 {
            let index = seq - 1;
            let file = format!("{index:064x}");
            let entry =
                append_seal_locked(check_input(&ledger, &file, &report, None, &[], None, &now))
                    .unwrap();
            assert_eq!(entry.seq, seq);
            assert_eq!(entry.prev_sha256, prev);
            assert_eq!(entry.sealed_at, "2026-01-01T00:00:00Z");
            prev = entry.entry_sha256;
        }
        let (count, divergence) = verify_ledger(&ledger).unwrap();
        assert_eq!(count, 3);
        assert!(divergence.is_none());
        let bytes = fs::read(&ledger).unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert!(!bytes.contains(&b'\r'));
        assert!(!bytes.windows(2).any(|pair| pair == b"\n\n"));

        let mut parts: Vec<String> = String::from_utf8(bytes.clone())
            .unwrap()
            .split('\n')
            .map(str::to_owned)
            .collect();
        assert!(parts.len() > 2, "{}", parts.len());
        parts[1] = parts[1].replace("healthy", "invalid");
        let tampered = parts.join("\n");
        fs::write(&ledger, tampered.as_bytes()).unwrap();
        let before = fs::read(&ledger).unwrap();
        let file = "c".repeat(64);
        let err = append_seal_locked(check_input(&ledger, &file, &report, None, &[], None, &now))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "ledger {} is divergent at line 2 (hash-mismatch: entry_sha256 does not match the entry contents (line edited)) — refusing to extend",
                path_text(&ledger)
            )
        );
        assert_eq!(fs::read(&ledger).unwrap(), before);

        let err =
            append_seal(check_input(&ledger, &file, &report, None, &[], None, &now)).unwrap_err();
        assert_eq!(err.to_string(), locking_text());
        assert_eq!(fs::read(&ledger).unwrap(), before);
    }

    #[test]
    fn append_seal_locked_genesis_and_missing_directory() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let now = fixed();
        let report = "b".repeat(64);
        let file = "a".repeat(64);
        let genesis = "f".repeat(64);
        fs::write(&ledger, b"").unwrap();
        let entry = append_seal_locked(check_input(
            &ledger,
            &file,
            &report,
            None,
            &[],
            Some(&genesis),
            &now,
        ))
        .unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.genesis_of.as_deref(), Some(genesis.as_str()));
        let err = append_seal_locked(check_input(
            &ledger,
            &file,
            &report,
            None,
            &[],
            Some(&genesis),
            &now,
        ))
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "genesis_of binds only a ledger's first line (seq 1)"
        );
        let kept = fs::read(&ledger).unwrap();
        let bad = "z".repeat(64);
        let err = append_seal_locked(check_input(&ledger, &bad, &report, None, &[], None, &now))
            .unwrap_err();
        assert_eq!(err.to_string(), "file_sha256 must be a sha256 hex digest");
        assert_eq!(fs::read(&ledger).unwrap(), kept);

        let missing = scratch.join("missing").join("ledger.jsonl");
        let err = append_seal_locked(check_input(&missing, &file, &report, None, &[], None, &now))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "ledger directory does not exist: {}",
                path_text(&ledger_parent(&missing))
            )
        );
        assert!(!missing.exists());
        assert!(!scratch.join("missing").exists());
    }

    #[test]
    fn append_seal_locked_repairs_a_missing_trailing_newline() {
        let scratch = Scratch::new();
        let ledger = scratch.join("ledger.jsonl");
        let now = fixed();
        let report = "b".repeat(64);
        let first_file = format!("{:064x}", 0);
        let first = append_seal_locked(check_input(
            &ledger,
            &first_file,
            &report,
            None,
            &[],
            None,
            &now,
        ))
        .unwrap();
        let raw = fs::read(&ledger).unwrap();
        assert!(raw.ends_with(b"\n"));
        let stripped = raw[..raw.len() - 1].to_vec();
        fs::write(&ledger, &stripped).unwrap();
        let second_file = format!("{:064x}", 1);
        let second = append_seal_locked(check_input(
            &ledger,
            &second_file,
            &report,
            None,
            &[],
            None,
            &now,
        ))
        .unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_sha256, first.entry_sha256);
        let mut expected = stripped;
        expected.push(b'\n');
        expected.extend(entry_line_bytes(&second).unwrap());
        assert_eq!(fs::read(&ledger).unwrap(), expected);
        assert!(!expected.contains(&b'\r'));
    }

    #[test]
    fn schema_loaders_stop_after_the_pure_path() {
        let path = seal_schema_development_path().unwrap();
        let expected = if cfg!(windows) {
            "schemas\\sesslint.seal-ledger.v1.json"
        } else {
            "schemas/sesslint.seal-ledger.v1.json"
        };
        assert_eq!(path_text(&path), expected);
        assert_eq!(
            get_seal_schema_path().unwrap_err(),
            SealError::ResourcesUnavailable
        );
        assert_eq!(
            get_seal_schema_path().unwrap_err().to_string(),
            "sesslint._resources is not available"
        );
        assert_eq!(
            load_seal_schema().unwrap_err(),
            SealError::ResourcesUnavailable
        );
        assert_eq!(
            load_seal_schema().unwrap_err().to_string(),
            "sesslint._resources is not available"
        );
    }

    #[test]
    fn ledger_parent_and_sync_dir_follow_the_pin() {
        assert_eq!(ledger_parent(Path::new("ledger.jsonl")), PathBuf::from("."));
        assert_eq!(ledger_parent(Path::new(".")), PathBuf::from("."));
        assert_eq!(ledger_parent(Path::new("")), PathBuf::from("."));
        assert_eq!(ledger_parent(Path::new("..")), PathBuf::from("."));
        let nested = if cfg!(windows) { "dir\\sub" } else { "dir/sub" };
        assert_eq!(
            ledger_parent(Path::new("dir/sub/ledger.jsonl")),
            PathBuf::from(nested)
        );
        #[cfg(windows)]
        {
            assert_eq!(
                ledger_parent(Path::new("C:/ledger.jsonl")),
                PathBuf::from("C:\\")
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(
                ledger_parent(Path::new("/ledger.jsonl")),
                PathBuf::from("/")
            );
        }
        let scratch = Scratch::new();
        sync_dir(&scratch.path);
        sync_dir(&scratch.join("missing-dir"));
        assert!(scratch.path.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn append_seal_refuses_lock_symlink_without_writing() {
        let scratch = Scratch::new();
        let target = scratch.join("target.bin");
        fs::write(&target, b"synthetic-lock-target").unwrap();
        let ledger = scratch.join("ledger.jsonl");
        let link = scratch.join("ledger.jsonl.lock");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            return;
        }
        let now = fixed();
        let report = "b".repeat(64);
        let file = "a".repeat(64);
        let err =
            append_seal(check_input(&ledger, &file, &report, None, &[], None, &now)).unwrap_err();
        assert_eq!(err.to_string(), "ledger lock must not be a symlink");
        assert!(!ledger.exists());
        assert_eq!(fs::read(&target).unwrap(), b"synthetic-lock-target");
    }
}
