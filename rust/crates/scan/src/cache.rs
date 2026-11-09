//! Optional SQLite scan-result cache (perf-scale T-02).
//!
//! Port of `src/sesslint/cache.py` at
//! `02694d537104659df66cdd084354739f3cccc440` (RX-P2.6-scan-cache-01).
//! No cache error changes a scan verdict: storage failures disable this instance,
//! while malformed row JSON is a miss and leaves the connection healthy.
//!
//! Payloads use Rust's finite, scalar-Unicode JSON value domain. Integers outside
//! i64/u64, non-finite numbers, unpaired surrogates and nesting beyond 128 levels
//! are unsupported cache hits, never rounded or silently rewritten. This is a
//! recorded boundary versus Python's broader `dict[str, Any]`, not full dynamic
//! Python-value parity. `put` does not filter `unreadable`: the caller owns that
//! policy in the pinned source. SQLite file bytes are not a parity surface.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Write};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codec::canonical_codec::{CanonicalCodec, CanonicalError, PurePythonCanonicalCodec, Value};
use model::{codes::ALL_CODES, version};
use rusqlite::{params, types::Value as SqlValue, Connection, OpenFlags, OptionalExtension};
use serde_json::{value::RawValue, Map, Value as JsonValue};
use sha2::{Digest, Sha256};

pub const SCHEMA_TABLE: &str = "cache_v1";
const JSON_DEPTH_LIMIT: usize = 128;

/// Typed cache wire payload. Session content must not be supplied by callers.
pub type CachePayload = Map<String, JsonValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeUnavailable;

impl fmt::Display for HomeUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Could not determine home directory.")
    }
}
impl Error for HomeUnavailable {}

/// Python `Path.home()` resolution for the current platform, only when needed.
fn user_home() -> Result<PathBuf, HomeUnavailable> {
    #[cfg(windows)]
    {
        if let Some(profile) = env::var_os("USERPROFILE") {
            return Ok(PathBuf::from(profile));
        }
        let mut home = env::var_os("HOMEDRIVE").unwrap_or_default();
        home.push(env::var_os("HOMEPATH").ok_or(HomeUnavailable)?);
        Ok(PathBuf::from(home))
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = env::var_os("HOME") {
            return Ok(PathBuf::from(home));
        }
        env::home_dir().ok_or(HomeUnavailable)
    }
}

/// The explicit cache override wins; empty overrides fall through like Python.
pub fn default_cache_dir() -> Result<PathBuf, HomeUnavailable> {
    cache_dir_from(cfg!(windows), |key| env::var_os(key), user_home)
}

fn cache_dir_from(
    windows: bool,
    getenv: impl Fn(&str) -> Option<OsString>,
    home: impl FnOnce() -> Result<PathBuf, HomeUnavailable>,
) -> Result<PathBuf, HomeUnavailable> {
    let nonempty = |key| getenv(key).filter(|value| !value.is_empty());
    if let Some(override_path) = nonempty("SESSLINT_CACHE_DIR") {
        return Ok(PathBuf::from(override_path));
    }
    if windows {
        if let Some(base) = nonempty("LOCALAPPDATA") {
            return Ok(PathBuf::from(base).join("sesslint"));
        }
        return Ok(home()?.join("AppData").join("Local").join("sesslint"));
    }
    if let Some(base) = nonempty("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(base).join("sesslint"));
    }
    Ok(home()?.join(".cache").join("sesslint"))
}

/// All keyword inputs to the pinned analysis fingerprint. Empty lists are null;
/// ordering is ignored but duplicate list elements are retained.
#[derive(Debug, Clone)]
pub struct AnalysisInputs<'a> {
    pub format: Option<&'a str>,
    pub profile: &'a str,
    pub select: Option<&'a [String]>,
    pub ignore: Option<&'a [String]>,
    pub confidence_min: Option<f64>,
    pub margin_min: Option<f64>,
    pub skip_undetected: bool,
    pub baseline: Option<&'a [String]>,
}

/// Hash Python's sorted, compact, ASCII-escaped JSON, including NaN/Infinity
/// threshold spellings. No environment, wall clock or active codec override.
pub fn analysis_fingerprint(input: &AnalysisInputs<'_>) -> Result<String, CanonicalError> {
    let versions = |pairs: &[(&str, &str)]| -> Result<String, CanonicalError> {
        let fields: BTreeMap<_, _> = pairs.iter().copied().collect();
        let mut encoded = Vec::new();
        for (key, value) in fields {
            encoded.push(format!("{}:{}", ascii_string(key)?, ascii_string(value)?));
        }
        Ok(format!("{{{}}}", encoded.join(",")))
    };
    let sorted_list = |items: Option<&[String]>| -> Result<String, CanonicalError> {
        let Some(items) = items.filter(|items| !items.is_empty()) else {
            return Ok("null".to_string());
        };
        let mut items = items.to_vec();
        items.sort();
        let encoded = items
            .iter()
            .map(|item| ascii_string(item))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(format!("[{}]", encoded.join(",")))
    };
    let threshold = |value: Option<f64>| match value {
        Some(value) => python_float(value),
        None => Ok("null".to_string()),
    };
    let mut fields = BTreeMap::new();
    fields.insert("adapter_versions", versions(version::ADAPTER_VERSIONS)?);
    fields.insert("baseline", sorted_list(input.baseline)?);
    fields.insert("confidence_min", threshold(input.confidence_min)?);
    fields.insert("engine", ascii_string(version::VERSION)?);
    fields.insert(
        "format",
        ascii_string(
            input
                .format
                .filter(|value| !value.is_empty())
                .unwrap_or("auto"),
        )?,
    );
    fields.insert("ignore", sorted_list(input.ignore)?);
    fields.insert("margin_min", threshold(input.margin_min)?);
    fields.insert("profile", ascii_string(input.profile)?);
    fields.insert("profile_versions", versions(version::PROFILE_VERSIONS)?);
    let rules: Vec<String> = ALL_CODES.iter().map(|code| (*code).to_string()).collect();
    fields.insert("rules", sorted_list(Some(&rules))?);
    fields.insert("select", sorted_list(input.select)?);
    fields.insert("skip_undetected", input.skip_undetected.to_string());
    let mut encoded = Vec::new();
    for (key, value) in fields {
        encoded.push(format!("{}:{value}", ascii_string(key)?));
    }
    let blob = format!("{{{}}}", encoded.join(","));
    Ok(format!("{:x}", Sha256::digest(blob.as_bytes())))
}

fn ascii_string(value: &str) -> Result<String, CanonicalError> {
    let bytes = PurePythonCanonicalCodec.canonical_json_bytes(&Value::string(value), false)?;
    // The codec emits UTF-8. Iterate scalar characters so non-BMP characters
    // become the same UTF-16 escape pair emitted by ensure_ascii=True.
    let mut result = String::new();
    for ch in String::from_utf8_lossy(&bytes).chars() {
        if ch >= '\u{7f}' {
            let mut units = [0_u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                let _ = write!(result, "\\u{unit:04x}");
            }
        } else {
            result.push(ch);
        }
    }
    Ok(result)
}

fn python_float(value: f64) -> Result<String, CanonicalError> {
    if value.is_nan() {
        return Ok("NaN".to_string());
    }
    if value == f64::INFINITY {
        return Ok("Infinity".to_string());
    }
    if value == f64::NEG_INFINITY {
        return Ok("-Infinity".to_string());
    }
    let bytes = PurePythonCanonicalCodec.canonical_json_bytes(&Value::float(value), false)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Stateful soft-failing cache. The connection is never exposed to callers.
pub struct ScanCache {
    db: Option<Connection>,
    ok: bool,
}

impl ScanCache {
    #[must_use]
    pub fn new(db_path: &Path) -> Self {
        if db_path.to_str().is_none() {
            return Self {
                db: None,
                ok: false,
            };
        }
        let db_path = if db_path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            db_path
        };
        let parent = db_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let opened = (|| -> Result<Connection, ()> {
            fs::create_dir_all(parent).map_err(|_| ())?;
            // Python sqlite3.connect(uri=False): a file: path is a literal name.
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            let db = Connection::open_with_flags(db_path, flags).map_err(|_| ())?;
            db.busy_timeout(Duration::from_secs(5)).map_err(|_| ())?;
            db.execute_batch("CREATE TABLE IF NOT EXISTS cache_v1 (path TEXT NOT NULL, analysis_fp TEXT NOT NULL, file_sha256 TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY (path, analysis_fp))").map_err(|_| ())?;
            Ok(db)
        })();
        match opened {
            Ok(db) => Self {
                db: Some(db),
                ok: true,
            },
            Err(()) => Self {
                db: None,
                ok: false,
            },
        }
    }

    #[must_use]
    pub fn healthy(&self) -> bool {
        self.ok
    }

    pub fn get(
        &mut self,
        path: &str,
        analysis_fp: &str,
        file_sha256: &str,
    ) -> Option<CachePayload> {
        if !self.ok {
            return None;
        }
        let db = self.db.as_ref()?;
        let row = db
            .query_row(
                "SELECT file_sha256, result FROM cache_v1 WHERE path=? AND analysis_fp=?",
                params![path, analysis_fp],
                |row| Ok((row.get::<_, SqlValue>(0)?, row.get::<_, SqlValue>(1)?)),
            )
            .optional();
        let (stored_hash, payload) = match row {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(_) => {
                self.ok = false;
                return None;
            }
        };
        if stored_hash != SqlValue::Text(file_sha256.to_string()) {
            return None;
        }
        let text = match payload {
            SqlValue::Text(text) => text,
            SqlValue::Blob(bytes) => decode_json_bytes(&bytes)?,
            _ => return None,
        };
        let value = parse_lossless_json(&text, 0)?;
        match value {
            JsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn put(&mut self, path: &str, analysis_fp: &str, file_sha256: &str, result: &CachePayload) {
        if !self.ok {
            return;
        }
        let Some(db) = self.db.as_ref() else {
            return;
        };
        let encoded = match encode_object(result, 0) {
            Some(encoded) => encoded,
            None => {
                self.ok = false;
                return;
            }
        };
        // Python's legacy isolation mode starts a DEFERRED transaction before
        // INSERT, then commits. A failed operation leaves cleanup to close().
        let stored = (|| -> rusqlite::Result<()> {
            db.execute_batch("BEGIN DEFERRED")?;
            db.execute("INSERT OR REPLACE INTO cache_v1 (path, analysis_fp, file_sha256, result) VALUES (?,?,?,?)", params![path, analysis_fp, file_sha256, encoded])?;
            db.execute_batch("COMMIT")
        })();
        if stored.is_err() {
            self.ok = false;
        }
    }

    pub fn close(&mut self) {
        if let Some(db) = self.db.take() {
            let _ = db.close();
        }
        self.ok = false;
    }
}

/// Python json.dumps(result, sort_keys=True): default spaces and ASCII escaping.
fn encode_json(value: &JsonValue, depth: usize) -> Option<String> {
    if depth > JSON_DEPTH_LIMIT {
        return None;
    }
    match value {
        JsonValue::Null => Some("null".to_string()),
        JsonValue::Bool(value) => Some(value.to_string()),
        JsonValue::String(value) => ascii_string(value).ok(),
        JsonValue::Number(value) => {
            if value.is_i64() || value.is_u64() {
                Some(value.to_string())
            } else {
                python_float(value.as_f64()?).ok()
            }
        }
        JsonValue::Array(values) => {
            let values = values
                .iter()
                .map(|v| encode_json(v, depth + 1))
                .collect::<Option<Vec<_>>>()?;
            Some(format!("[{}]", values.join(", ")))
        }
        JsonValue::Object(values) => encode_object(values, depth),
    }
}

fn encode_object(values: &CachePayload, depth: usize) -> Option<String> {
    if depth > JSON_DEPTH_LIMIT {
        return None;
    }
    let sorted: BTreeMap<_, _> = values.iter().collect();
    let values = sorted
        .into_iter()
        .map(|(key, value)| {
            Some(format!(
                "{}: {}",
                ascii_string(key).ok()?,
                encode_json(value, depth + 1)?
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(format!("{{{}}}", values.join(", ")))
}

/// Keep integers outside the typed domain as misses, never serde's lossy f64.
fn parse_lossless_json(text: &str, depth: usize) -> Option<JsonValue> {
    if depth > JSON_DEPTH_LIMIT {
        return None;
    }
    let raw: &RawValue = serde_json::from_str(text).ok()?;
    let text = raw.get();
    match text.as_bytes().first()? {
        b'{' => {
            let values: BTreeMap<String, Box<RawValue>> = serde_json::from_str(text).ok()?;
            let mut output = Map::new();
            for (key, value) in values {
                output.insert(key, parse_lossless_json(value.get(), depth + 1)?);
            }
            Some(JsonValue::Object(output))
        }
        b'[' => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(text).ok()?;
            let values = values
                .iter()
                .map(|value| parse_lossless_json(value.get(), depth + 1))
                .collect::<Option<Vec<_>>>()?;
            Some(JsonValue::Array(values))
        }
        b'-' | b'0'..=b'9' if !text.contains(['.', 'e', 'E']) => {
            if let Ok(value) = text.parse::<i64>() {
                Some(JsonValue::from(value))
            } else {
                text.parse::<u64>().ok().map(JsonValue::from)
            }
        }
        _ => serde_json::from_str(text).ok(),
    }
}

/// json.loads accepts UTF-8/16/32 bytes with BOM or detectable zero patterns.
fn decode_json_bytes(bytes: &[u8]) -> Option<String> {
    let (width, little, skip) = if bytes.starts_with(&[0, 0, 0xfe, 0xff]) {
        (4, false, 4)
    } else if bytes.starts_with(&[0xff, 0xfe, 0, 0]) {
        (4, true, 4)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (2, false, 2)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (2, true, 2)
    } else if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        (1, false, 3)
    } else if bytes.len() >= 4 && bytes[0..3] == [0, 0, 0] {
        (4, false, 0)
    } else if bytes.len() >= 4 && bytes[1..4] == [0, 0, 0] {
        (4, true, 0)
    } else if bytes.len() >= 2 && bytes[0] == 0 {
        (2, false, 0)
    } else if bytes.len() >= 2 && bytes[1] == 0 {
        (2, true, 0)
    } else {
        (1, false, 0)
    };
    let bytes = &bytes[skip..];
    if width == 1 {
        return String::from_utf8(bytes.to_vec()).ok();
    }
    if !bytes.len().is_multiple_of(width) {
        return None;
    }
    if width == 2 {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b| {
                if little {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect();
        return String::from_utf16(&units).ok();
    }
    bytes
        .chunks_exact(4)
        .map(|b| {
            char::from_u32(if little {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let root = env::temp_dir().join(format!(
                "sesslint-cache-unit-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            // create_dir never adopts an existing directory belonging to others.
            fs::create_dir(&root).expect("create owned synthetic scratch directory");
            Self(root)
        }
        fn database(&self) -> PathBuf {
            self.0.join("cache.sqlite")
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            assert_eq!(self.0.parent(), Some(env::temp_dir().as_path()));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn payload() -> CachePayload {
        serde_json::json!({"path":"a/b.jsonl","verdict":"healthy","findings":[]})
            .as_object()
            .expect("synthetic object")
            .clone()
    }

    fn raw_row(cache: &ScanCache, value: SqlValue) {
        cache.db.as_ref().expect("test database").execute(
            "INSERT OR REPLACE INTO cache_v1 (path, analysis_fp, file_sha256, result) VALUES ('p','fp','sha',?)",
            params![value],
        ).expect("insert synthetic row");
    }

    fn inputs() -> AnalysisInputs<'static> {
        AnalysisInputs {
            format: None,
            profile: "neutral",
            select: None,
            ignore: None,
            confidence_min: None,
            margin_min: None,
            skip_undetected: false,
            baseline: None,
        }
    }

    #[test]
    fn real_sqlite_roundtrip_persists_after_close_and_reopen() {
        let scratch = Scratch::new();
        let path = scratch.0.join("nested").join("cache.sqlite");
        let mut first = ScanCache::new(&path);
        assert!(first.healthy());
        first.put("p", "fp", "sha", &payload());
        first.close();
        assert!(!first.healthy());
        let mut second = ScanCache::new(&path);
        assert_eq!(second.get("p", "fp", "sha"), Some(payload()));
        assert_eq!(second.get("p", "fp", "new-sha"), None);
        assert_eq!(second.get("p", "new-fp", "sha"), None);
        assert_eq!(second.get("other", "fp", "sha"), None);
        assert!(second.healthy());
    }

    #[test]
    fn changed_hash_replaces_same_path_and_analysis_only() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let other = serde_json::json!({"v":2})
            .as_object()
            .expect("object")
            .clone();
        cache.put("p", "fp", "sha1", &payload());
        cache.put("p", "second-fp", "sha1", &payload());
        cache.put("p", "fp", "sha2", &other);
        assert!(cache.get("p", "fp", "sha1").is_none());
        assert_eq!(cache.get("p", "fp", "sha2"), Some(other));
        assert_eq!(cache.get("p", "second-fp", "sha1"), Some(payload()));
    }

    #[test]
    fn directory_and_corrupt_file_fail_soft() {
        let scratch = Scratch::new();
        assert!(!ScanCache::new(&scratch.0).healthy());
        fs::write(scratch.database(), b"synthetic invalid sqlite bytes").expect("write fixture");
        assert!(!ScanCache::new(&scratch.database()).healthy());
        assert!(!ScanCache::new(&scratch.database().join("child.sqlite")).healthy());
        assert!(!ScanCache::new(Path::new("")).healthy());
    }

    #[test]
    fn close_is_idempotent_and_closed_calls_are_noops() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        cache.close();
        cache.close();
        cache.put("p", "fp", "sha", &payload());
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(!cache.healthy());
        let mut reopened = ScanCache::new(&scratch.database());
        assert!(reopened.get("p", "fp", "sha").is_none());
    }

    #[test]
    fn malformed_or_non_object_json_misses_without_poisoning() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        for value in [
            "[",
            "null",
            "[]",
            "true",
            "123",
            "{\"n\":18446744073709551616}",
            "{\"n\":NaN}",
            "{\"n\":Infinity}",
            "{\"s\":\"\\ud800\"}",
        ] {
            raw_row(&cache, SqlValue::Text(value.to_string()));
            assert!(cache.get("p", "fp", "sha").is_none(), "case {value}");
            assert!(cache.healthy(), "case {value}");
        }
        raw_row(&cache, SqlValue::Integer(5));
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(cache.healthy());
        raw_row(&cache, SqlValue::Text("{".repeat(2000)));
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(cache.healthy());
        cache.put("p", "fp", "sha", &payload());
        assert_eq!(cache.get("p", "fp", "sha"), Some(payload()));
    }

    #[test]
    fn sql_read_error_disables_instance_until_closed() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        cache
            .db
            .as_ref()
            .expect("db")
            .execute_batch("DROP TABLE cache_v1")
            .expect("drop test table");
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(!cache.healthy());
        cache.put("p", "fp", "sha", &payload());
        cache.close();
    }

    #[test]
    fn write_error_disables_and_close_releases_transaction() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        cache
            .db
            .as_ref()
            .expect("db")
            .execute_batch("PRAGMA query_only=ON")
            .expect("read only");
        cache.put("p", "fp", "sha", &payload());
        assert!(!cache.healthy());
        cache.close();
        let mut replacement = ScanCache::new(&scratch.database());
        replacement.put("p", "fp", "sha", &payload());
        assert_eq!(replacement.get("p", "fp", "sha"), Some(payload()));
    }

    #[test]
    fn locked_database_fails_soft_and_default_timeout_matches_python() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let db = cache.db.as_ref().expect("db");
        let timeout: i64 = db
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("timeout");
        assert_eq!(timeout, 5000);
        // Exercise SQLITE_BUSY without spending five seconds in a unit test.
        db.busy_timeout(Duration::ZERO).expect("test timeout");
        let blocker = Connection::open(scratch.database()).expect("second real connection");
        blocker.execute_batch("BEGIN EXCLUSIVE").expect("hold lock");
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(!cache.healthy());
        blocker.execute_batch("ROLLBACK").expect("release lock");
        assert!(!cache.healthy());
    }

    #[test]
    fn bound_parameters_preserve_sql_and_embedded_nuls() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let path = "p'); DROP TABLE cache_v1; --\0tail";
        cache.put(path, "fp\0x", "sha\0x", &payload());
        assert_eq!(cache.get(path, "fp\0x", "sha\0x"), Some(payload()));
        assert!(cache.healthy());
    }

    #[test]
    fn unreadable_filter_belongs_to_scan_caller_not_cache() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let value = serde_json::json!({"verdict":"unreadable"})
            .as_object()
            .expect("object")
            .clone();
        cache.put("p", "fp", "sha", &value);
        assert_eq!(cache.get("p", "fp", "sha"), Some(value));
    }

    #[test]
    fn stored_text_matches_python_sorted_ascii_json() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let value = serde_json::json!({"z":-0.0,"á":"😀\u{7f}","a":[true,null,1e20]})
            .as_object()
            .expect("object")
            .clone();
        cache.put("p", "fp", "sha", &value);
        let actual: String = cache
            .db
            .as_ref()
            .expect("db")
            .query_row("SELECT result FROM cache_v1", [], |row| row.get(0))
            .expect("stored JSON");
        assert_eq!(
            actual,
            "{\"a\": [true, null, 1e+20], \"z\": -0.0, \"\\u00e1\": \"\\ud83d\\ude00\\u007f\"}"
        );
        assert_eq!(cache.get("p", "fp", "sha"), Some(value));
    }

    #[test]
    fn blob_json_encodings_and_text_bom_follow_python_boundary() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let text = "{\"v\":\"á😀\"}";
        let expected = serde_json::json!({"v":"á😀"})
            .as_object()
            .expect("object")
            .clone();
        let mut variants = vec![
            text.as_bytes().to_vec(),
            [b"\xef\xbb\xbf".as_slice(), text.as_bytes()].concat(),
        ];
        for little in [true, false] {
            let utf16: Vec<u8> = text
                .encode_utf16()
                .flat_map(|u| {
                    if little {
                        u.to_le_bytes()
                    } else {
                        u.to_be_bytes()
                    }
                })
                .collect();
            let utf32: Vec<u8> = text
                .chars()
                .flat_map(|ch| {
                    if little {
                        (ch as u32).to_le_bytes()
                    } else {
                        (ch as u32).to_be_bytes()
                    }
                })
                .collect();
            let bom16 = if little {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            let bom32 = if little {
                vec![0xff, 0xfe, 0, 0]
            } else {
                vec![0, 0, 0xfe, 0xff]
            };
            variants.extend([
                utf16.clone(),
                [bom16, utf16].concat(),
                utf32.clone(),
                [bom32, utf32].concat(),
            ]);
        }
        for bytes in variants {
            raw_row(&cache, SqlValue::Blob(bytes));
            assert_eq!(cache.get("p", "fp", "sha"), Some(expected.clone()));
            assert!(cache.healthy());
        }
        raw_row(&cache, SqlValue::Text(format!("\u{feff}{text}")));
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(cache.healthy());
        raw_row(&cache, SqlValue::Blob(vec![0xff, 0xfe, 0x7b]));
        assert!(cache.get("p", "fp", "sha").is_none());
        assert!(cache.healthy());
    }

    #[test]
    fn integer_edges_and_duplicate_fields_do_not_round() {
        let text = "{\"max\":18446744073709551615,\"min\":-9223372036854775808,\"x\":1,\"x\":2}";
        let parsed = parse_lossless_json(text, 0).expect("bounded integers");
        assert_eq!(parsed["max"].as_u64(), Some(u64::MAX));
        assert_eq!(parsed["min"].as_i64(), Some(i64::MIN));
        assert_eq!(parsed["x"], 2);
        for text in [
            "{\"n\":18446744073709551616}",
            "{\"n\":-9223372036854775809}",
        ] {
            assert!(parse_lossless_json(text, 0).is_none());
        }
    }

    #[test]
    fn deeply_nested_put_fails_without_cloning_unbounded_tree() {
        let scratch = Scratch::new();
        let mut cache = ScanCache::new(&scratch.database());
        let mut value = JsonValue::Null;
        for _ in 0..512 {
            value = JsonValue::Array(vec![value]);
        }
        let mut payload = Map::new();
        payload.insert("nested".to_string(), value);
        cache.put("p", "fp", "sha", &payload);
        assert!(!cache.healthy());
        assert!(cache.get("p", "fp", "sha").is_none());
        cache.close();
        let mut reopened = ScanCache::new(&scratch.database());
        assert!(reopened.get("p", "fp", "sha").is_none());
    }

    #[test]
    fn cache_directory_precedence_is_lazy() {
        let resolve = |windows, items: &[(&str, &str)]| {
            cache_dir_from(
                windows,
                |key| {
                    items
                        .iter()
                        .find(|(k, _)| *k == key)
                        .map(|(_, v)| OsString::from(v))
                },
                || Ok(PathBuf::from("synthetic-home")),
            )
        };
        assert_eq!(
            resolve(
                true,
                &[
                    ("SESSLINT_CACHE_DIR", "override"),
                    ("LOCALAPPDATA", "local")
                ]
            ),
            Ok(PathBuf::from("override"))
        );
        assert_eq!(
            resolve(
                true,
                &[("SESSLINT_CACHE_DIR", ""), ("LOCALAPPDATA", "local")]
            ),
            Ok(PathBuf::from("local").join("sesslint"))
        );
        assert_eq!(
            resolve(true, &[]),
            Ok(PathBuf::from("synthetic-home")
                .join("AppData")
                .join("Local")
                .join("sesslint"))
        );
        assert_eq!(
            resolve(false, &[("XDG_CACHE_HOME", "xdg")]),
            Ok(PathBuf::from("xdg").join("sesslint"))
        );
        assert_eq!(
            resolve(false, &[]),
            Ok(PathBuf::from("synthetic-home")
                .join(".cache")
                .join("sesslint"))
        );
        assert_eq!(
            cache_dir_from(false, |_| None, || Err(HomeUnavailable)),
            Err(HomeUnavailable)
        );
        assert_eq!(
            cache_dir_from(
                false,
                |key| (key == "SESSLINT_CACHE_DIR").then(|| OsString::from("override")),
                || panic!("home must not be consulted")
            ),
            Ok(PathBuf::from("override"))
        );
    }

    #[test]
    fn fingerprint_matches_pinned_python_float_goldens() {
        // Generated by the original module at 02694d537104..., not a Rust model.
        let cases = [
            (
                None,
                None,
                "e8098d6612c4a5dfdb4f97000df0b63fe8de051faabde51e45dae0976e217495",
            ),
            (
                Some(0.0),
                None,
                "8e9eebf68a738462c4eedcee3defaea66999348703b79431b5fd0215bdbb5d36",
            ),
            (
                Some(-0.0),
                None,
                "2e7e1512dd545b2c04615d9300818c3d30f40e9248fb0dfe9b74e22ac0a60827",
            ),
            (
                Some(0.1),
                Some(0.2),
                "72c690ddfe29d78b1d49ac8e385713bb830929c14eda32c401e753f30549f9e9",
            ),
            (
                Some(1e-7),
                Some(1e20),
                "e4a09ced4cc2ce4aef396e7be20ecef3c3595fd65f6811b08bd0f15a3990675d",
            ),
            (
                Some(f64::from_bits(1)),
                Some(f64::MAX),
                "e3e13ca7754237a1c187997775d6cfed662279444dcf8717d0846fdd4da81ac3",
            ),
            (
                Some(f64::NAN),
                None,
                "957d0d448701f026c29782ca1e2824a74a1280b3c2a623d8195023865823111c",
            ),
            (
                Some(f64::INFINITY),
                Some(f64::NEG_INFINITY),
                "6a986633652993e738fe56dc7079b48f1d0df35194bbc7a74857e17a98fcb404",
            ),
        ];
        for (confidence_min, margin_min, expected) in cases {
            let mut input = inputs();
            input.confidence_min = confidence_min;
            input.margin_min = margin_min;
            assert_eq!(analysis_fingerprint(&input).expect("fingerprint"), expected);
        }
    }

    #[test]
    fn fingerprint_matches_pinned_python_unicode_and_list_goldens() {
        let select = vec![
            "SL101".to_string(),
            "SL001".to_string(),
            "SL101".to_string(),
        ];
        let ignore = vec!["SL002".to_string(), "SL001".to_string()];
        let baseline = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        let mut input = inputs();
        input.select = Some(&select);
        input.ignore = Some(&ignore);
        input.baseline = Some(&baseline);
        assert_eq!(
            analysis_fingerprint(&input).expect("fp"),
            "ae02f13c37c72bd8e326bfb3879c5f8246b782c90de9b3b611fc73318d82aaf0"
        );
        let unicode = vec!["z".to_string(), "á".to_string(), "😀".to_string()];
        let mut input = inputs();
        input.format = Some("tự động😀\u{7f}");
        input.profile = "hồ sơ";
        input.baseline = Some(&unicode);
        assert_eq!(
            analysis_fingerprint(&input).expect("fp"),
            "2aeaa428773cc95329580ffefb2c54ae80a817e86db986888822e84171c34edb"
        );
        let mut input = inputs();
        input.format = Some("");
        input.select = Some(&[]);
        input.ignore = Some(&[]);
        input.baseline = Some(&[]);
        assert_eq!(
            analysis_fingerprint(&input).expect("fp"),
            "e8098d6612c4a5dfdb4f97000df0b63fe8de051faabde51e45dae0976e217495"
        );
        input.skip_undetected = true;
        assert_eq!(
            analysis_fingerprint(&input).expect("fp"),
            "6a442661276fd7a5b55fc13c3811777997c4e1962d4e85f6f541855e777c27a4"
        );
    }
}
