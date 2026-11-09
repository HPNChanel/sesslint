//! User configuration loading.
//!
//! Port of `src/sesslint/config.py` lines 1–261
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Card pin `02694d5` is overridden by that commit.
//!
//! [`allowed_profiles`] calls [`list_profiles`]. That function still returns
//! [`BUILTIN_UNAVAILABLE`]. This module does not copy profile names.
//!
//! # Recorded gaps
//!
//! * ADR-0009 has no TOML crate. [`read_pyproject`] and [`load_config`] do
//!   not parse. A path that would call `tomllib.loads` or `tomllib.load`
//!   returns [`TOMLLIB_UNAVAILABLE`] and does not invent keys. A readable
//!   explicit file, or a discovered `sesslint.toml` / `.sesslint.toml`, is
//!   that error. Invalid TOML is not reported as `Invalid TOML`. An empty
//!   document is not returned as an empty map. `No [tool.sesslint] section`
//!   is not produced, because that check runs only after a successful parse.
//! * A `pyproject.toml` whose bytes contain the literal marker
//!   `[tool.sesslint` fails discovery with [`TOMLLIB_UNAVAILABLE`] and does
//!   not fall through, including a file Python would have parsed. A
//!   `pyproject.toml` without that marker is skipped without parsing, so
//!   the walk can still use a parent `sesslint.toml`.
//! * [`str::trim`] does not drop U+001C through U+001F. Python `str.strip`
//!   does. A string or list item that is empty only after those characters
//!   are removed stays non-empty here. No Unicode crate is added.
//! * Python `int` is unbounded. A value that does not fit `i64` is
//!   [`ConfigValue::UnboundedInt`] and [`PYTHON_INT_UNBOUNDED`], not a wrap
//!   and not a panic. An in-range int stored as a float uses `i64 as f64`,
//!   which is not exact past `2^53`.
//! * OS errors use [`std::io::Error`] display text, not CPython `OSError`.
//! * [`load_config`] uses the process current directory only when both
//!   `start` and `explicit` are absent, matching Python. Tests pass `start`.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::profile::{list_profiles, OrderedMap, ProfileError, BUILTIN_UNAVAILABLE, VALID_FORMATS};

/// `tomllib.loads` / `tomllib.load` are not available. No keys are invented.
pub const TOMLLIB_UNAVAILABLE: &str = "tomllib is not available";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

const CONFIG_FILENAMES: [&str; 3] = ["sesslint.toml", ".sesslint.toml", "pyproject.toml"];

/// Literal bytes, not a parsed table.
const PYPROJECT_MARKER: &[u8] = b"[tool.sesslint";

const ALLOWED_KEYS: [&str; 17] = [
    "profile",
    "adapter",
    "policy",
    "fail_on",
    "select",
    "ignore",
    "skip_undetected",
    "confidence_min",
    "margin_min",
    "max_files",
    "max_bytes",
    "max_file_bytes",
    "max_findings_per_code",
    "timestamp_skew_ms",
    "fail_on_unsupported",
    "exclude",
    "ext",
];

const STR_KEYS: [&str; 4] = ["profile", "adapter", "policy", "fail_on"];
const BOOL_KEYS: [&str; 2] = ["skip_undetected", "fail_on_unsupported"];
const FLOAT_KEYS: [&str; 2] = ["confidence_min", "margin_min"];
const INT_KEYS: [&str; 5] = [
    "max_files",
    "max_bytes",
    "max_file_bytes",
    "max_findings_per_code",
    "timestamp_skew_ms",
];
const LIST_KEYS: [&str; 4] = ["select", "ignore", "exclude", "ext"];

/// One config value.
///
/// Maps use [`OrderedMap`]. Key order is insertion order, not a `BTreeMap`.
/// [`ConfigValue::UnboundedInt`] is a Python `int` that does not fit `i64`.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigValue {
    Str(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    List(Vec<ConfigValue>),
    Map(OrderedMap<ConfigValue>),
    UnboundedInt,
}

/// Raised when a sesslint config file is unreadable or invalid.
///
/// [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Message(String),
    BuiltinUnavailable,
    PythonIntUnbounded,
    TomllibUnavailable,
}

impl ConfigError {
    pub fn message(&self) -> &str {
        match self {
            Self::Message(text) => text,
            Self::BuiltinUnavailable => BUILTIN_UNAVAILABLE,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::TomllibUnavailable => TOMLLIB_UNAVAILABLE,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ConfigError {}

/// Return registered profile names.
///
/// Calls [`list_profiles`]. That call returns [`BUILTIN_UNAVAILABLE`] and
/// does not produce a membership list.
pub fn allowed_profiles() -> Result<Vec<String>, ConfigError> {
    match list_profiles() {
        Ok(names) => Ok(names),
        Err(ProfileError::BuiltinUnavailable) => Err(ConfigError::BuiltinUnavailable),
        Err(error) => Err(ConfigError::Message(error.to_string())),
    }
}

/// Return the sesslint table, or the whole mapping for any other filename.
///
/// A `pyproject.toml` walks `tool` then `sesslint`. A missing key or a
/// non-mapping node is [`None`]. Any other filename returns `raw` unchanged.
pub fn extract_section(
    path: &Path,
    raw: &OrderedMap<ConfigValue>,
) -> Option<OrderedMap<ConfigValue>> {
    if path.file_name() != Some(OsStr::new("pyproject.toml")) {
        return Some(raw.clone());
    }
    let tool = match raw.get("tool") {
        Some(ConfigValue::Map(map)) => map,
        _ => return None,
    };
    match tool.get("sesslint") {
        Some(ConfigValue::Map(map)) => Some(map.clone()),
        _ => None,
    }
}

/// Inspect a `pyproject.toml` candidate during discovery.
///
/// An unreadable file is [`None`]. Bytes without the marker `[tool.sesslint`
/// are [`None`]. Bytes that contain the marker would be passed to
/// `tomllib.loads`, which returns [`TOMLLIB_UNAVAILABLE`] and does not
/// invent a table. [`Some`] would be a parsed document; this function does
/// not produce one.
///
/// # Errors
///
/// [`TOMLLIB_UNAVAILABLE`] when the marker is present.
pub fn read_pyproject(candidate: &Path) -> Result<Option<OrderedMap<ConfigValue>>, ConfigError> {
    let blob = match fs::read(candidate) {
        Ok(blob) => blob,
        Err(_) => return Ok(None),
    };
    if contains_marker(&blob) {
        return Err(ConfigError::TomllibUnavailable);
    }
    Ok(None)
}

/// Walk upward from `start` and return the nearest config file.
///
/// A file `start` uses its parent. The walk includes that directory, then
/// its parents, and stops at the root. Within one directory the names are
/// `sesslint.toml`, `.sesslint.toml`, then `pyproject.toml`.
///
/// `sesslint.toml` and `.sesslint.toml` are returned when they are files,
/// without reading them. An unreadable `pyproject.toml`, or one without
/// the marker `[tool.sesslint`, is skipped. A `pyproject.toml` with the marker
/// returns [`TOMLLIB_UNAVAILABLE`] and does not continue.
///
/// # Errors
///
/// [`TOMLLIB_UNAVAILABLE`] when a discovered `pyproject.toml` contains the marker.
pub fn find_config_file(start: &Path) -> Result<Option<PathBuf>, ConfigError> {
    let directory = discovery_directory(start);
    for current in directory.ancestors() {
        for name in CONFIG_FILENAMES {
            let candidate = current.join(name);
            if !candidate.is_file() {
                continue;
            }
            if name == "pyproject.toml" {
                match read_pyproject(&candidate)? {
                    Some(_) => return Ok(Some(candidate)),
                    None => continue,
                }
            }
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Validate keys. Output key order is the input order.
///
/// `format` is the rename error. Unknown keys are sorted in the message.
/// `select` and `ignore` are mutually exclusive when both are present,
/// including empty lists. Strings are trimmed with [`str::trim`].
///
/// # Errors
///
/// A renamed key, an unknown key, both `select` and `ignore`, a bad type,
/// an enum miss, [`BUILTIN_UNAVAILABLE`] for a non-empty `profile`, or
/// [`PYTHON_INT_UNBOUNDED`] for [`ConfigValue::UnboundedInt`] used as a
/// number.
pub fn validate_keys(
    cfg: &OrderedMap<ConfigValue>,
    source: &Path,
) -> Result<OrderedMap<ConfigValue>, ConfigError> {
    if cfg.get("format").is_some() {
        return Err(ConfigError::Message(format!(
            "Config key 'format' was renamed to 'adapter' in 0.5.0; rename the key in {}",
            source.display()
        )));
    }
    let mut unknown = Vec::new();
    for (key, _) in cfg.entries() {
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            unknown.push(key.as_str());
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(unknown_key_message(&unknown, source));
    }
    if cfg.get("select").is_some() && cfg.get("ignore").is_some() {
        return Err(ConfigError::Message(format!(
            "Config keys 'select' and 'ignore' are mutually exclusive in {}",
            source.display()
        )));
    }
    let mut out = OrderedMap::new();
    for (key, value) in cfg.entries() {
        let stored = validate_one(key, value, source)?;
        out.insert(key.clone(), stored);
    }
    Ok(out)
}

/// Load and validate sesslint configuration.
///
/// `explicit` disables discovery. A directory, a missing file, and an
/// unreadable file fail closed. A readable explicit file is read and then
/// `tomllib.load` returns [`TOMLLIB_UNAVAILABLE`]. Discovery that finds
/// nothing returns an empty map and does not call the parser. A discovered
/// `sesslint.toml` or `.sesslint.toml` is the same parser error.
///
/// Pass `start` in tests. The process current directory is used only when
/// both arguments are [`None`].
///
/// # Errors
///
/// A directory explicit path, a missing explicit file, an unreadable file,
/// [`TOMLLIB_UNAVAILABLE`], or a discovery error from [`find_config_file`].
pub fn load_config(
    start: Option<&Path>,
    explicit: Option<&Path>,
) -> Result<OrderedMap<ConfigValue>, ConfigError> {
    let config_path = if let Some(explicit) = explicit {
        if explicit.is_dir() {
            return Err(ConfigError::Message(format!(
                "Config path is a directory, not a file: {} (pass a sesslint.toml / .sesslint.toml / pyproject.toml path)",
                explicit.display()
            )));
        }
        if !explicit.is_file() {
            return Err(ConfigError::Message(format!(
                "Config file not found: {}",
                explicit.display()
            )));
        }
        explicit.to_path_buf()
    } else {
        let base = match start {
            Some(start) => start.to_path_buf(),
            None => fs_current_dir()?,
        };
        match find_config_file(&base)? {
            Some(path) => path,
            None => return Ok(OrderedMap::new()),
        }
    };
    match fs::read(&config_path) {
        // `tomllib.load` would parse `_blob`. Nothing is decoded.
        Ok(_blob) => Err(ConfigError::TomllibUnavailable),
        Err(error) => Err(ConfigError::Message(format!(
            "Cannot read config file {}: {error}",
            config_path.display()
        ))),
    }
}

fn fs_current_dir() -> Result<PathBuf, ConfigError> {
    std::env::current_dir().map_err(|error| {
        ConfigError::Message(format!("Cannot determine current directory: {error}"))
    })
}

fn discovery_directory(start: &Path) -> PathBuf {
    if start.is_dir() {
        return start.to_path_buf();
    }
    match start.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        Some(_) | None => PathBuf::from("."),
    }
}

fn contains_marker(blob: &[u8]) -> bool {
    blob.windows(PYPROJECT_MARKER.len())
        .any(|window| window == PYPROJECT_MARKER)
}

fn sorted_allowed_keys() -> [&'static str; 17] {
    let mut keys = ALLOWED_KEYS;
    keys.sort_unstable();
    keys
}

fn sorted_valid_formats() -> Vec<&'static str> {
    let mut names = VALID_FORMATS.to_vec();
    names.sort_unstable();
    names
}

fn unknown_key_message(unknown: &[&str], source: &Path) -> ConfigError {
    ConfigError::Message(format!(
        "Unknown sesslint config key(s) {} in {}. Allowed keys: {}",
        python_list(unknown.iter().copied()),
        source.display(),
        python_list(sorted_allowed_keys()),
    ))
}

fn expect(key: &str, expected: &str, source: &Path) -> ConfigError {
    ConfigError::Message(format!(
        "Config key {} must be {expected} in {}",
        python_repr(key),
        source.display()
    ))
}

fn ensure_member(
    key: &str,
    allowed: &[&str],
    value: &str,
    source: &Path,
) -> Result<(), ConfigError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::Message(format!(
            "Config key {} must be one of {} in {}, got {}",
            python_repr(key),
            python_list(allowed.iter().copied()),
            source.display(),
            python_repr(value),
        )))
    }
}

fn validate_one(key: &str, value: &ConfigValue, source: &Path) -> Result<ConfigValue, ConfigError> {
    if STR_KEYS.contains(&key) {
        validate_string(key, value, source)
    } else if BOOL_KEYS.contains(&key) {
        validate_bool(key, value, source)
    } else if FLOAT_KEYS.contains(&key) {
        validate_float(key, value, source)
    } else if INT_KEYS.contains(&key) {
        validate_int(key, value, source)
    } else if LIST_KEYS.contains(&key) {
        validate_list(key, value, source)
    } else {
        Err(unknown_key_message(&[key], source))
    }
}

fn validate_string(
    key: &str,
    value: &ConfigValue,
    source: &Path,
) -> Result<ConfigValue, ConfigError> {
    let ConfigValue::Str(text) = value else {
        return Err(expect(key, "a non-empty string", source));
    };
    let stripped = text.trim();
    if stripped.is_empty() {
        return Err(expect(key, "a non-empty string", source));
    }
    match key {
        "profile" => {
            let names = allowed_profiles()?;
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            ensure_member(key, &refs, stripped, source)?;
        }
        "fail_on" => ensure_member(key, &["error", "warning"], stripped, source)?,
        "policy" => ensure_member(key, &["conservative", "salvage"], stripped, source)?,
        "adapter" => {
            let allowed = sorted_valid_formats();
            ensure_member(key, &allowed, stripped, source)?;
        }
        _ => {}
    }
    Ok(ConfigValue::Str(stripped.to_owned()))
}

fn validate_bool(
    key: &str,
    value: &ConfigValue,
    source: &Path,
) -> Result<ConfigValue, ConfigError> {
    match value {
        ConfigValue::Bool(flag) => Ok(ConfigValue::Bool(*flag)),
        _ => Err(expect(key, "a boolean", source)),
    }
}

fn validate_float(
    key: &str,
    value: &ConfigValue,
    source: &Path,
) -> Result<ConfigValue, ConfigError> {
    match value {
        ConfigValue::Bool(_) => Err(expect(key, "a number", source)),
        ConfigValue::Int(integer) => Ok(ConfigValue::Float(*integer as f64)),
        ConfigValue::Float(number) => Ok(ConfigValue::Float(*number)),
        ConfigValue::UnboundedInt => Err(ConfigError::PythonIntUnbounded),
        ConfigValue::Str(_) | ConfigValue::List(_) | ConfigValue::Map(_) => {
            Err(expect(key, "a number", source))
        }
    }
}

fn validate_int(key: &str, value: &ConfigValue, source: &Path) -> Result<ConfigValue, ConfigError> {
    let minimum = if key == "timestamp_skew_ms" { 0 } else { 1 };
    match value {
        ConfigValue::UnboundedInt => Err(ConfigError::PythonIntUnbounded),
        ConfigValue::Int(integer) if *integer >= minimum => Ok(ConfigValue::Int(*integer)),
        ConfigValue::Bool(_)
        | ConfigValue::Int(_)
        | ConfigValue::Float(_)
        | ConfigValue::Str(_)
        | ConfigValue::List(_)
        | ConfigValue::Map(_) => Err(expect(key, "a positive integer", source)),
    }
}

fn validate_list(
    key: &str,
    value: &ConfigValue,
    source: &Path,
) -> Result<ConfigValue, ConfigError> {
    let ConfigValue::List(items) = value else {
        return Err(expect(key, "a list of non-empty strings", source));
    };
    let mut stripped = Vec::with_capacity(items.len());
    for item in items {
        let ConfigValue::Str(text) = item else {
            return Err(expect(key, "a list of non-empty strings", source));
        };
        let cleaned = text.trim();
        if cleaned.is_empty() {
            return Err(expect(key, "a list of non-empty strings", source));
        }
        stripped.push(ConfigValue::Str(cleaned.to_owned()));
    }
    Ok(ConfigValue::List(stripped))
}

fn python_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            other if (u32::from(other)) < 32 || other == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

fn python_list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let mut out = String::from("[");
    for (index, item) in items.into_iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_repr(item));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const ALLOWED_REPR: &str = "['adapter', 'confidence_min', 'exclude', 'ext', 'fail_on', 'fail_on_unsupported', 'ignore', 'margin_min', 'max_bytes', 'max_file_bytes', 'max_files', 'max_findings_per_code', 'policy', 'profile', 'select', 'skip_undetected', 'timestamp_skew_ms']";

    fn source() -> &'static Path {
        Path::new("synthetic/sesslint.toml")
    }

    fn entry_keys(map: &OrderedMap<ConfigValue>) -> Vec<&str> {
        map.entries().iter().map(|(key, _)| key.as_str()).collect()
    }

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sesslint-config-{id}-{}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn every_allowed_key_has_one_type_class() {
        assert_eq!(ALLOWED_KEYS.len(), 17);
        for key in ALLOWED_KEYS {
            let classes = [
                STR_KEYS.contains(&key),
                BOOL_KEYS.contains(&key),
                FLOAT_KEYS.contains(&key),
                INT_KEYS.contains(&key),
                LIST_KEYS.contains(&key),
            ]
            .into_iter()
            .filter(|hit| *hit)
            .count();
            assert_eq!(classes, 1, "{key}");
        }
        assert_eq!(python_list(sorted_allowed_keys()), ALLOWED_REPR);
        assert_eq!(
            CONFIG_FILENAMES,
            ["sesslint.toml", ".sesslint.toml", "pyproject.toml"]
        );
    }

    #[test]
    fn format_key_was_renamed_to_adapter() {
        let mut cfg = OrderedMap::new();
        cfg.insert("format", ConfigValue::Str("canonical".into()));
        cfg.insert("bogus", ConfigValue::Bool(true));
        let err = validate_keys(&cfg, source()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Config key 'format' was renamed to 'adapter' in 0.5.0; rename the key in {}",
                source().display()
            )
        );
    }

    #[test]
    fn unknown_key_lists_sorted_allowed_keys() {
        let mut cfg = OrderedMap::new();
        cfg.insert("bogus", ConfigValue::Bool(true));
        let err = validate_keys(&cfg, source()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Unknown sesslint config key(s) ['bogus'] in {}. Allowed keys: {ALLOWED_REPR}",
                source().display()
            )
        );

        let mut many = OrderedMap::new();
        many.insert("zebra", ConfigValue::Int(1));
        many.insert("alpha", ConfigValue::Int(1));
        many.insert("select", ConfigValue::List(vec![]));
        many.insert("ignore", ConfigValue::List(vec![]));
        let err = validate_keys(&many, source()).unwrap_err().to_string();
        assert!(err.starts_with("Unknown sesslint config key(s) ['alpha', 'zebra'] in "));
        assert!(err.contains(ALLOWED_REPR));
        assert!(!err.contains("mutually exclusive"));
    }

    #[test]
    fn select_and_ignore_reject_even_when_empty() {
        let mut cfg = OrderedMap::new();
        cfg.insert("ignore", ConfigValue::List(vec![]));
        cfg.insert("select", ConfigValue::List(vec![]));
        assert_eq!(
            validate_keys(&cfg, source()).unwrap_err().to_string(),
            format!(
                "Config keys 'select' and 'ignore' are mutually exclusive in {}",
                source().display()
            )
        );

        let mut wrong_types = OrderedMap::new();
        wrong_types.insert("select", ConfigValue::Int(0));
        wrong_types.insert("ignore", ConfigValue::Bool(false));
        let err = validate_keys(&wrong_types, source())
            .unwrap_err()
            .to_string();
        assert!(err.contains("mutually exclusive"));
        assert!(!err.contains("positive integer"));

        let mut only_select = OrderedMap::new();
        only_select.insert("select", ConfigValue::List(vec![]));
        let out = validate_keys(&only_select, source()).unwrap();
        assert_eq!(out.get("select"), Some(&ConfigValue::List(vec![])));
    }

    #[test]
    fn empty_string_is_rejected() {
        for key in ["profile", "adapter", "policy", "fail_on"] {
            for value in ["", " ", "\n\t", "  \r\n"] {
                let mut cfg = OrderedMap::new();
                cfg.insert(key, ConfigValue::Str(value.into()));
                let err = validate_keys(&cfg, source()).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    format!(
                        "Config key {} must be a non-empty string in {}",
                        python_repr(key),
                        source().display()
                    ),
                    "{key} {value:?}"
                );
                assert!(!err.to_string().contains("not available"));
            }
            let mut cfg = OrderedMap::new();
            cfg.insert(key, ConfigValue::Bool(true));
            let err = validate_keys(&cfg, source()).unwrap_err().to_string();
            assert!(err.contains("non-empty string"), "{key} {err}");
            assert!(!err.contains("must be one of"), "{key} {err}");
        }
    }

    #[test]
    fn fail_on_and_adapter_enums() {
        for value in ["error", "warning", " error ", "\twarning\n"] {
            let mut cfg = OrderedMap::new();
            cfg.insert("fail_on", ConfigValue::Str(value.into()));
            let out = validate_keys(&cfg, source()).unwrap();
            assert_eq!(
                out.get("fail_on"),
                Some(&ConfigValue::Str(value.trim().to_owned()))
            );
        }
        let mut fatal = OrderedMap::new();
        fatal.insert("fail_on", ConfigValue::Str("fatal".into()));
        assert_eq!(
            validate_keys(&fatal, source()).unwrap_err().to_string(),
            format!(
                "Config key 'fail_on' must be one of ['error', 'warning'] in {}, got 'fatal'",
                source().display()
            )
        );

        for value in ["conservative", "salvage", " salvage "] {
            let mut cfg = OrderedMap::new();
            cfg.insert("policy", ConfigValue::Str(value.into()));
            let out = validate_keys(&cfg, source()).unwrap();
            assert_eq!(
                out.get("policy"),
                Some(&ConfigValue::Str(value.trim().to_owned()))
            );
        }
        let mut strict = OrderedMap::new();
        strict.insert("policy", ConfigValue::Str("strict".into()));
        assert_eq!(
            validate_keys(&strict, source()).unwrap_err().to_string(),
            format!(
                "Config key 'policy' must be one of ['conservative', 'salvage'] in {}, got 'strict'",
                source().display()
            )
        );

        let mut sorted = VALID_FORMATS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            [
                "auto",
                "canonical",
                "claude",
                "claude-code-jsonl",
                "codex",
                "codex-rollout",
                "openai",
                "openai-agents",
            ]
        );
        for name in &sorted {
            let mut cfg = OrderedMap::new();
            cfg.insert("adapter", ConfigValue::Str(format!("  {name}\n")));
            let out = validate_keys(&cfg, source()).unwrap();
            assert_eq!(
                out.get("adapter"),
                Some(&ConfigValue::Str((*name).to_owned()))
            );
        }
        let mut nope = OrderedMap::new();
        nope.insert("adapter", ConfigValue::Str("nope".into()));
        let err = validate_keys(&nope, source()).unwrap_err().to_string();
        let allowed = python_list(sorted.iter().copied());
        assert_eq!(
            err,
            format!(
                "Config key 'adapter' must be one of {allowed} in {}, got 'nope'",
                source().display()
            )
        );
        let claude_code = err.find("claude-code-jsonl").expect("sorted adapter");
        let codex = err.find("'codex'").expect("sorted adapter");
        assert!(claude_code < codex, "{err}");
    }

    #[test]
    fn profile_string_returns_builtin_error() {
        assert_eq!(
            allowed_profiles().unwrap_err().to_string(),
            "sesslint.profiles.builtin is not available"
        );
        let mut cfg = OrderedMap::new();
        cfg.insert("profile", ConfigValue::Str("  synthetic-profile  ".into()));
        let err = validate_keys(&cfg, source()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "sesslint.profiles.builtin is not available"
        );
        assert!(!err.to_string().contains("must be one of"));

        let mut empty = OrderedMap::new();
        empty.insert("profile", ConfigValue::Str("".into()));
        let err = validate_keys(&empty, source()).unwrap_err().to_string();
        assert!(err.contains("non-empty string"));
        assert!(!err.contains("not available"));
    }

    #[test]
    fn bool_is_not_a_number_or_an_integer() {
        let mut confidence = OrderedMap::new();
        confidence.insert("confidence_min", ConfigValue::Bool(true));
        assert_eq!(
            validate_keys(&confidence, source())
                .unwrap_err()
                .to_string(),
            format!(
                "Config key 'confidence_min' must be a number in {}",
                source().display()
            )
        );
        let mut margin = OrderedMap::new();
        margin.insert("margin_min", ConfigValue::Bool(false));
        assert!(validate_keys(&margin, source())
            .unwrap_err()
            .to_string()
            .contains("must be a number"));

        let mut files = OrderedMap::new();
        files.insert("max_files", ConfigValue::Bool(true));
        assert_eq!(
            validate_keys(&files, source()).unwrap_err().to_string(),
            format!(
                "Config key 'max_files' must be a positive integer in {}",
                source().display()
            )
        );
        let mut skew = OrderedMap::new();
        skew.insert("timestamp_skew_ms", ConfigValue::Bool(false));
        assert!(validate_keys(&skew, source())
            .unwrap_err()
            .to_string()
            .contains("positive integer"));

        let mut as_float = OrderedMap::new();
        as_float.insert("confidence_min", ConfigValue::Int(2));
        let out = validate_keys(&as_float, source()).unwrap();
        assert!(matches!(
            out.get("confidence_min"),
            Some(ConfigValue::Float(number)) if number.to_bits() == 2.0_f64.to_bits()
        ));

        let mut flag = OrderedMap::new();
        flag.insert("fail_on_unsupported", ConfigValue::Int(1));
        assert!(validate_keys(&flag, source())
            .unwrap_err()
            .to_string()
            .contains("must be a boolean"));
        let mut flag_ok = OrderedMap::new();
        flag_ok.insert("skip_undetected", ConfigValue::Bool(true));
        let out = validate_keys(&flag_ok, source()).unwrap();
        assert_eq!(out.get("skip_undetected"), Some(&ConfigValue::Bool(true)));
    }

    #[test]
    fn timestamp_zero_is_accepted() {
        let mut cfg = OrderedMap::new();
        cfg.insert("timestamp_skew_ms", ConfigValue::Int(0));
        let out = validate_keys(&cfg, source()).unwrap();
        assert_eq!(out.get("timestamp_skew_ms"), Some(&ConfigValue::Int(0)));
    }

    #[test]
    fn timestamp_negative_is_rejected() {
        let mut cfg = OrderedMap::new();
        cfg.insert("timestamp_skew_ms", ConfigValue::Int(-1));
        assert_eq!(
            validate_keys(&cfg, source()).unwrap_err().to_string(),
            format!(
                "Config key 'timestamp_skew_ms' must be a positive integer in {}",
                source().display()
            )
        );
        let mut files = OrderedMap::new();
        files.insert("max_files", ConfigValue::Int(0));
        assert_eq!(
            validate_keys(&files, source()).unwrap_err().to_string(),
            format!(
                "Config key 'max_files' must be a positive integer in {}",
                source().display()
            )
        );
        let mut bytes = OrderedMap::new();
        bytes.insert("max_file_bytes", ConfigValue::Int(1));
        let out = validate_keys(&bytes, source()).unwrap();
        assert_eq!(out.get("max_file_bytes"), Some(&ConfigValue::Int(1)));
    }

    #[test]
    fn list_items_are_stripped() {
        let mut cfg = OrderedMap::new();
        cfg.insert(
            "ext",
            ConfigValue::List(vec![
                ConfigValue::Str("  .jsonl  ".into()),
                ConfigValue::Str("\t.toml\n".into()),
            ]),
        );
        let out = validate_keys(&cfg, source()).unwrap();
        assert_eq!(
            out.get("ext"),
            Some(&ConfigValue::List(vec![
                ConfigValue::Str(".jsonl".into()),
                ConfigValue::Str(".toml".into()),
            ]))
        );

        let mut blank = OrderedMap::new();
        blank.insert(
            "ignore",
            ConfigValue::List(vec![ConfigValue::Str("  ".into())]),
        );
        assert!(validate_keys(&blank, source())
            .unwrap_err()
            .to_string()
            .contains("list of non-empty strings"));

        let mut bad = OrderedMap::new();
        bad.insert("select", ConfigValue::List(vec![ConfigValue::Int(1)]));
        assert!(validate_keys(&bad, source())
            .unwrap_err()
            .to_string()
            .contains("list of non-empty strings"));

        let mut not_list = OrderedMap::new();
        not_list.insert("exclude", ConfigValue::Str("nope".into()));
        assert!(validate_keys(&not_list, source())
            .unwrap_err()
            .to_string()
            .contains("list of non-empty strings"));
    }

    #[test]
    fn key_order_is_preserved() {
        let mut cfg = OrderedMap::new();
        cfg.insert(
            "exclude",
            ConfigValue::List(vec![ConfigValue::Str("  z  ".into())]),
        );
        cfg.insert("fail_on", ConfigValue::Str(" warning ".into()));
        cfg.insert("max_files", ConfigValue::Int(2));
        cfg.insert("confidence_min", ConfigValue::Int(1));
        cfg.insert("skip_undetected", ConfigValue::Bool(false));
        let out = validate_keys(&cfg, source()).unwrap();
        assert_eq!(
            entry_keys(&out),
            [
                "exclude",
                "fail_on",
                "max_files",
                "confidence_min",
                "skip_undetected",
            ]
        );
        assert_eq!(
            out.get("exclude"),
            Some(&ConfigValue::List(vec![ConfigValue::Str("z".into())]))
        );
        assert_eq!(
            out.get("fail_on"),
            Some(&ConfigValue::Str("warning".into()))
        );
        assert_eq!(out.get("max_files"), Some(&ConfigValue::Int(2)));
        assert!(matches!(
            out.get("confidence_min"),
            Some(ConfigValue::Float(number)) if number.to_bits() == 1.0_f64.to_bits()
        ));
        assert_eq!(out.get("skip_undetected"), Some(&ConfigValue::Bool(false)));
    }

    #[test]
    fn unbounded_integer_is_a_typed_error() {
        assert_eq!(
            PYTHON_INT_UNBOUNDED,
            "Python ints are unbounded; an i64 overflow is not a wrap and not a panic"
        );
        for key in [
            "max_files",
            "max_bytes",
            "timestamp_skew_ms",
            "confidence_min",
            "margin_min",
        ] {
            let mut cfg = OrderedMap::new();
            cfg.insert(key, ConfigValue::UnboundedInt);
            assert_eq!(
                validate_keys(&cfg, source()).unwrap_err().to_string(),
                PYTHON_INT_UNBOUNDED,
                "{key}"
            );
        }
    }

    #[test]
    fn file_separator_is_not_trimmed() {
        for code in ['\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}'] {
            let mut cfg = OrderedMap::new();
            cfg.insert("fail_on", ConfigValue::Str(format!("{code}error")));
            let err = validate_keys(&cfg, source()).unwrap_err().to_string();
            assert!(err.contains("must be one of"), "{code:?} {err}");
            assert!(!err.contains("non-empty string"), "{code:?} {err}");

            let mut items = OrderedMap::new();
            items.insert(
                "ext",
                ConfigValue::List(vec![ConfigValue::Str(code.to_string())]),
            );
            let out = validate_keys(&items, source()).unwrap();
            assert_eq!(
                out.get("ext"),
                Some(&ConfigValue::List(vec![ConfigValue::Str(code.to_string())]))
            );
        }
    }

    #[test]
    fn extract_section_walks_tool_then_sesslint() {
        let mut section = OrderedMap::new();
        section.insert("fail_on", ConfigValue::Str("error".into()));
        section.insert("max_files", ConfigValue::Int(4));
        let mut tool = OrderedMap::new();
        tool.insert("other", ConfigValue::Str("synthetic".into()));
        tool.insert("sesslint", ConfigValue::Map(section.clone()));
        let mut raw = OrderedMap::new();
        raw.insert("project", ConfigValue::Str("synthetic".into()));
        raw.insert("tool", ConfigValue::Map(tool));

        let extracted = extract_section(Path::new("nested/pyproject.toml"), &raw).expect("section");
        assert_eq!(entry_keys(&extracted), ["fail_on", "max_files"]);
        assert_eq!(extracted, section);

        assert!(extract_section(Path::new("pyproject.toml"), &OrderedMap::new()).is_none());
        let mut tool_string = OrderedMap::new();
        tool_string.insert("tool", ConfigValue::Str("synthetic".into()));
        assert!(extract_section(Path::new("pyproject.toml"), &tool_string).is_none());

        let mut tool_only = OrderedMap::new();
        let mut inner = OrderedMap::new();
        inner.insert("name", ConfigValue::Str("synthetic".into()));
        tool_only.insert("tool", ConfigValue::Map(inner));
        assert!(extract_section(Path::new("pyproject.toml"), &tool_only).is_none());

        let mut sesslint_list = OrderedMap::new();
        let mut listed = OrderedMap::new();
        listed.insert("sesslint", ConfigValue::List(vec![]));
        sesslint_list.insert("tool", ConfigValue::Map(listed));
        assert!(extract_section(Path::new("pyproject.toml"), &sesslint_list).is_none());

        let kept = extract_section(Path::new("dir/sesslint.toml"), &raw).expect("raw");
        assert_eq!(kept, raw);
        let other = extract_section(Path::new("Pyproject.TOML"), &raw).expect("raw");
        assert_eq!(other, raw);
    }

    #[test]
    fn nearest_sesslint_toml_wins() {
        let scratch = Scratch::new();
        let root = scratch.path.clone();
        let nested = root.join("a").join("b");
        write_file(&root.join("sesslint.toml"), b"fail_on = \"error\"\n");
        write_file(&nested.join("sesslint.toml"), b"fail_on = \"warning\"\n");
        assert_eq!(
            find_config_file(&nested).unwrap().as_deref(),
            Some(nested.join("sesslint.toml").as_path())
        );
        assert_eq!(
            find_config_file(&root.join("a")).unwrap().as_deref(),
            Some(root.join("sesslint.toml").as_path())
        );
        let leaf = nested.join("leaf.txt");
        write_file(&leaf, b"synthetic\n");
        assert_eq!(
            find_config_file(&leaf).unwrap().as_deref(),
            Some(nested.join("sesslint.toml").as_path())
        );
    }

    #[test]
    fn sesslint_toml_before_dotfile() {
        let scratch = Scratch::new();
        let dir = scratch.path.join("nested");
        write_file(&dir.join(".sesslint.toml"), b"adapter = \"auto\"\n");
        write_file(&dir.join("sesslint.toml"), b"fail_on = \"error\"\n");
        write_file(&dir.join("pyproject.toml"), b"[tool.sesslint]\n");
        assert_eq!(
            find_config_file(&dir).unwrap().as_deref(),
            Some(dir.join("sesslint.toml").as_path())
        );
        std::fs::remove_file(dir.join("sesslint.toml")).unwrap();
        assert_eq!(
            find_config_file(&dir).unwrap().as_deref(),
            Some(dir.join(".sesslint.toml").as_path())
        );
    }

    #[test]
    fn pyproject_without_marker_falls_through() {
        let scratch = Scratch::new();
        let root = scratch.path.clone();
        let nested = root.join("sub");
        write_file(&root.join("sesslint.toml"), b"fail_on = \"warning\"\n");
        write_file(&nested.join("pyproject.toml"), b"not = [valid\n");
        assert_eq!(
            find_config_file(&nested).unwrap().as_deref(),
            Some(root.join("sesslint.toml").as_path())
        );
        assert!(read_pyproject(&nested.join("pyproject.toml"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn pyproject_with_marker_does_not_use_parent() {
        let scratch = Scratch::new();
        let root = scratch.path.clone();
        let nested = root.join("sub");
        write_file(&root.join("sesslint.toml"), b"fail_on = \"warning\"\n");
        write_file(
            &nested.join("pyproject.toml"),
            b"[tool.sesslint]\nfail_on = \"error\"\n",
        );
        assert_eq!(
            find_config_file(&nested).unwrap_err().to_string(),
            TOMLLIB_UNAVAILABLE
        );
        assert_eq!(
            load_config(Some(&nested), None).unwrap_err().to_string(),
            TOMLLIB_UNAVAILABLE
        );
        assert_eq!(TOMLLIB_UNAVAILABLE, "tomllib is not available");
    }

    #[test]
    fn read_pyproject_skips_unreadable_and_unmarked() {
        let scratch = Scratch::new();
        let missing = scratch.path.join("pyproject.toml");
        assert!(read_pyproject(&missing).unwrap().is_none());
        assert!(read_pyproject(&scratch.path).unwrap().is_none());
        let unmarked = scratch.path.join("sub").join("pyproject.toml");
        write_file(&unmarked, b"[project]\nname = \"synthetic\"\n");
        assert!(read_pyproject(&unmarked).unwrap().is_none());
        let marked = scratch.path.join("marked.toml");
        write_file(&marked, b"prefix [tool.sesslint suffix");
        assert_eq!(
            read_pyproject(&marked).unwrap_err().to_string(),
            TOMLLIB_UNAVAILABLE
        );
    }

    #[test]
    fn explicit_directory_is_rejected() {
        let scratch = Scratch::new();
        let dir = scratch.path.clone();
        let err = load_config(Some(&dir), Some(&dir)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Config path is a directory, not a file: {} (pass a sesslint.toml / .sesslint.toml / pyproject.toml path)",
                dir.display()
            )
        );
    }

    #[test]
    fn missing_explicit_file_is_rejected() {
        let scratch = Scratch::new();
        write_file(
            &scratch.path.join("sesslint.toml"),
            b"fail_on = \"error\"\n",
        );
        let missing = scratch.path.join("missing.toml");
        let err = load_config(Some(&scratch.path), Some(&missing)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("Config file not found: {}", missing.display())
        );
    }

    #[test]
    fn no_config_returns_an_empty_map() {
        let scratch = Scratch::new();
        let nested = scratch.path.join("empty").join("leaf");
        std::fs::create_dir_all(&nested).unwrap();
        let loaded = load_config(Some(&nested), None).unwrap();
        assert!(loaded.is_empty());
        assert!(find_config_file(&nested).unwrap().is_none());
    }

    #[test]
    fn readable_file_returns_parser_error_without_keys() {
        let scratch = Scratch::new();
        let file = scratch.path.join("sesslint.toml");
        write_file(&file, b"fail_on = \"warning\"\n");
        assert_eq!(
            load_config(Some(&scratch.path), Some(&file))
                .unwrap_err()
                .to_string(),
            TOMLLIB_UNAVAILABLE
        );
        assert_eq!(
            load_config(Some(&scratch.path), None)
                .unwrap_err()
                .to_string(),
            TOMLLIB_UNAVAILABLE
        );
        let project = scratch.path.join("other").join("pyproject.toml");
        write_file(&project, b"[project]\nname = \"synthetic\"\n");
        assert_eq!(
            load_config(None, Some(&project)).unwrap_err().to_string(),
            TOMLLIB_UNAVAILABLE
        );
        let dot = scratch.path.join("dot").join(".sesslint.toml");
        write_file(&dot, b"adapter = \"auto\"\n");
        assert_eq!(
            find_config_file(&scratch.path.join("dot"))
                .unwrap()
                .as_deref(),
            Some(dot.as_path())
        );
        assert_eq!(
            load_config(Some(&scratch.path.join("dot")), None)
                .unwrap_err()
                .to_string(),
            TOMLLIB_UNAVAILABLE
        );
    }
}
