//! Snapshot parity for `sesslint.indexes` against pinned Python vectors.

use checks::indexes::{read_index, IndexSnapshot, ALL};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VECTORS_REL: &str = "../../parity/vectors/indexes/vectors.json";
const FIXTURES_REL: &str = "../../parity/vectors/indexes/fixtures";

#[derive(Debug, Clone, PartialEq, Eq)]
struct VectorCase {
    id: String,
    construct: Construct,
    expected: Expected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Construct {
    ReadIndexFixture { fixture: String, target: String },
    ReadIndexSetup { setup: String },
    ModuleAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    Snapshot(SnapshotExpected),
    All(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotExpected {
    format: String,
    entry_ids: Vec<String>,
    entry_paths: Vec<String>,
    normalized_ids: Vec<String>,
    entry_count: usize,
    parse_ok: bool,
    truncated: bool,
    schema_note: Option<String>,
    membership_complete: bool,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_REL)
}

fn snapshot_from_rust(snap: &IndexSnapshot) -> SnapshotExpected {
    SnapshotExpected {
        format: snap.format.clone(),
        entry_ids: snap.entry_ids().into_iter().collect(),
        entry_paths: snap.entry_paths().into_iter().collect(),
        normalized_ids: snap.normalized_ids().into_iter().collect(),
        entry_count: snap.entry_count(),
        parse_ok: snap.parse_ok,
        truncated: snap.truncated,
        schema_note: snap.schema_note.clone(),
        membership_complete: snap.membership_complete(),
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sesslint-indexes-parity-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create temp dir for parity setup");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn setup_oversized_claude(root: &Path) -> PathBuf {
    let path = root.join("sessions-index.json");
    let mut body = b"{\"entries\": [".to_vec();
    body.extend(std::iter::repeat_n(b' ', 17 * 1024 * 1024));
    fs::write(&path, body).expect("write oversized index");
    path
}

fn write_claude_index(dirpath: &Path, session_id: &str) -> PathBuf {
    let doc = format!(
        r#"{{"version":1,"originalPath":"synthetic/proj","entries":[{{"sessionId":"{session_id}","fullPath":"synthetic/{session_id}.jsonl"}}]}}"#
    );
    let path = dirpath.join("sessions-index.json");
    fs::write(&path, doc).expect("write claude index");
    path
}

fn setup_symlink_claude(root: &Path) -> PathBuf {
    let real_dir = root.join("real");
    fs::create_dir_all(&real_dir).expect("mkdir real");
    let real = write_claude_index(&real_dir, "sym-aaa");
    let link = root.join("sessions-index.json");
    create_file_symlink(&real, &link).expect("symlink required for parity vector");
    link
}

fn create_file_symlink(real: &Path, link: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(real, link).map_err(|err| err.to_string())
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(real, link).map_err(|err| err.to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (real, link);
        Err("symlinks unsupported on this platform".into())
    }
}

fn run_construct(construct: &Construct) -> Result<EitherSnapshot, String> {
    match construct {
        Construct::ReadIndexFixture { fixture, target } => {
            let path = fixtures_root().join(fixture).join(target);
            Ok(EitherSnapshot::Index(read_index(&path)))
        }
        Construct::ReadIndexSetup { setup } => {
            let tmp = TempDir::new(setup);
            let path = match setup.as_str() {
                "oversized_claude" => setup_oversized_claude(tmp.path()),
                "symlink_claude" => setup_symlink_claude(tmp.path()),
                other => return Err(format!("unknown setup {other}")),
            };
            Ok(EitherSnapshot::Index(read_index(&path)))
        }
        Construct::ModuleAll => Ok(EitherSnapshot::All(
            ALL.iter().map(|name| (*name).to_owned()).collect(),
        )),
    }
}

enum EitherSnapshot {
    Index(IndexSnapshot),
    All(Vec<String>),
}

fn assert_case(case: &VectorCase) {
    let actual = run_construct(&case.construct)
        .unwrap_or_else(|err| panic!("vector {} setup: {err}", case.id));
    match (&case.expected, actual) {
        (Expected::Snapshot(expected), EitherSnapshot::Index(snap)) => {
            let got = snapshot_from_rust(&snap);
            assert_eq!(got, *expected, "vector {}", case.id);
        }
        (Expected::All(expected), EitherSnapshot::All(got)) => {
            assert_eq!(got, *expected, "vector {}", case.id);
        }
        _ => panic!("vector {} construct/expected kind mismatch", case.id),
    }
}

#[test]
fn indexes_module_parity_vectors() {
    let path = vectors_path();
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(cases.len(), 7, "unexpected vector count");
    for case in &cases {
        assert_case(case);
    }
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    items.iter().map(parse_vector_case).collect()
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = parse_construct(object_field(obj, "construct")?)?;
    let expected = parse_expected(object_field(obj, "expected")?, &construct)?;
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn parse_construct(obj: &[(String, JsonValue)]) -> Result<Construct, ParseError> {
    let kind = string_field(obj, "type")?;
    match kind.as_str() {
        "read_index" => {
            if let Some(fixture) = optional_string_field(obj, "fixture")? {
                let target = string_field(obj, "target")?;
                return Ok(Construct::ReadIndexFixture { fixture, target });
            }
            let setup = string_field(obj, "setup")?;
            Ok(Construct::ReadIndexSetup { setup })
        }
        "module_all" => Ok(Construct::ModuleAll),
        other => Err(ParseError {
            message: format!("unknown construct type {other}"),
        }),
    }
}

fn parse_expected(
    obj: &[(String, JsonValue)],
    construct: &Construct,
) -> Result<Expected, ParseError> {
    match construct {
        Construct::ModuleAll => {
            let all = string_array_field(obj, "all")?;
            Ok(Expected::All(all))
        }
        _ => Ok(Expected::Snapshot(SnapshotExpected {
            format: string_field(obj, "format")?,
            entry_ids: string_array_field(obj, "entry_ids")?,
            entry_paths: string_array_field(obj, "entry_paths")?,
            normalized_ids: string_array_field(obj, "normalized_ids")?,
            entry_count: usize_field(obj, "entry_count")?,
            parse_ok: bool_field(obj, "parse_ok")?,
            truncated: bool_field(obj, "truncated")?,
            schema_note: nullable_string_field(obj, "schema_note")?,
            membership_complete: bool_field(obj, "membership_complete")?,
        })),
    }
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => s.parse().map_err(|_| ParseError {
            message: format!("{key} must be usize string"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
        }),
    }
}

fn nullable_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    let JsonValue::Array(items) = &value.1 else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        c if c.is_ascii_digit() || c == b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0usize;
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_digit() {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let digits = &input[..end];
    Ok((JsonValue::Str(digits.to_owned()), &input[end..]))
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if input.starts_with(word) {
        Ok((value, &input[word.len()..]))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if rest.starts_with(']') {
        return Ok((JsonValue::Array(items), &rest[1..]));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if rest.starts_with(']') {
            return Ok((JsonValue::Array(items), &rest[1..]));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if rest.starts_with('}') {
        return Ok((JsonValue::Object(items), &rest[1..]));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if rest.starts_with('}') {
            return Ok((JsonValue::Object(items), &rest[1..]));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
