//! Byte-exact parity for `sesslint.atomic` against pinned Python vectors.

use model::errors::AtomicWriteError;
use scan::atomic::{atomic_write_bytes, atomic_write_text, AtomicWriteOptions};
use std::cell::RefCell;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

const VECTORS_REL: &str = "../../parity/vectors/atomic/vectors.json";

type PreWriteHookBox = Box<dyn Fn() -> Result<(), String>>;
type PreRenameHookBox = Box<dyn Fn(&Path) -> Result<(), String>>;

#[cfg(windows)]
const EXPECTED_VECTOR_COUNT: usize = 15;
#[cfg(not(windows))]
const EXPECTED_VECTOR_COUNT: usize = 14;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sesslint-atomic-parity-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create sandbox");
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn apply_setup(name: &str, root: &Path) {
    match name {
        "empty" => {}
        "seed_keep_me" => {
            fs::write(root.join("out.bin"), b"keep-me").expect("seed keep-me");
        }
        "seed_hook_dest" => {
            fs::write(root.join("out.bin"), b"pre-existing untouched").expect("seed hook dest");
        }
        "parent_is_file" => {
            fs::write(root.join("file.txt"), b"not a directory").expect("parent file");
        }
        "hardlink_alias" => {
            let source = root.join("source.bin");
            fs::write(&source, b"initial source").expect("write source");
            fs::hard_link(&source, root.join("alias.bin")).expect("hard link");
        }
        "case_alias" => {
            fs::write(root.join("Case.TXT"), b"abc").expect("case source");
        }
        "other_refuse" => {
            fs::write(root.join("other.bin"), b"other-content-bytes").expect("other file");
        }
        "seed_overwrite" => {
            fs::write(root.join("out.bin"), b"old version").expect("seed overwrite");
        }
        other => panic!("unknown setup {other}"),
    }
}

fn temp_count(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".sesslint_tmp_")
        })
        .count()
}

fn decode_b64(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let val = if ch == b'=' {
            break;
        } else if let Some(index) = TABLE.iter().position(|&b| b == ch) {
            u32::try_from(index).unwrap_or(0)
        } else if ch.is_ascii_whitespace() {
            continue;
        } else {
            panic!("invalid base64");
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn string_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(Vec::new()),
        Some((_, JsonValue::Array(items))) => items
            .iter()
            .map(|item| match item {
                JsonValue::Str(s) => Ok(s.clone()),
                _ => Err(ParseError {
                    message: format!("{key} entries must be strings"),
                }),
            })
            .collect(),
        _ => Err(ParseError {
            message: format!("{key} must be array when present"),
        }),
    }
}

fn optional_string(obj: &[(String, JsonValue)], key: &str) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
        }),
    }
}

fn optional_bool(obj: &[(String, JsonValue)], key: &str) -> Result<Option<bool>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Bool(b))) => Ok(Some(*b)),
        _ => Err(ParseError {
            message: format!("{key} must be bool when present"),
        }),
    }
}

fn should_run(case: &VectorCase) -> bool {
    if let Ok(Some(platform)) = optional_string(&case.construct, "requires_platform") {
        if platform == "windows" {
            #[cfg(not(windows))]
            return false;
        }
    }
    true
}

fn assert_case(case: &VectorCase) {
    let setup = string_field(&case.construct, "setup").expect("setup");
    let dest_rel = string_field(&case.construct, "dest").expect("dest");
    let sandbox = Sandbox::new(&case.id);
    apply_setup(&setup, sandbox.path());
    let dest = sandbox.path().join(&dest_rel);

    let refuse_names = string_list(&case.construct, "refuse_paths").expect("refuse_paths");
    let refuse_paths: Vec<PathBuf> = refuse_names
        .iter()
        .map(|name| sandbox.path().join(name))
        .collect();
    let refuse_storage = refuse_paths.clone();

    let hook_kind = optional_string(&case.construct, "hook")
        .expect("hook")
        .unwrap_or_default();
    let hook_events = Rc::new(RefCell::new(Vec::<String>::new()));
    let pre_write_slot: Option<PreWriteHookBox> = match hook_kind.as_str() {
        "lifecycle" => {
            let events = Rc::clone(&hook_events);
            Some(Box::new(move || {
                events.borrow_mut().push("pre_write".into());
                Ok(())
            }))
        }
        "" | "pre_rename_fail" => None,
        other => panic!("unknown hook {other} in {}", case.id),
    };
    let pre_rename_slot: Option<PreRenameHookBox> = match hook_kind.as_str() {
        "lifecycle" => {
            let events = Rc::clone(&hook_events);
            Some(Box::new(move |temp: &Path| {
                events.borrow_mut().push("pre_rename".into());
                assert!(temp
                    .file_name()
                    .expect("temp name")
                    .to_string_lossy()
                    .starts_with(".sesslint_tmp_"));
                assert_eq!(fs::read(temp).expect("temp bytes"), b"payload");
                Ok(())
            }))
        }
        "pre_rename_fail" => Some(Box::new(|_temp: &Path| {
            Err("Fault injection before rename".into())
        })),
        "" => None,
        other => panic!("unknown hook {other} in {}", case.id),
    };

    let refuse_refs: Vec<&Path> = refuse_storage.iter().map(|path| path.as_path()).collect();
    let encoding_owned = optional_string(&case.construct, "encoding").expect("encoding");
    let mut options = AtomicWriteOptions::new();
    if let Some(sync_dir) = optional_bool(&case.construct, "sync_dir").expect("sync_dir") {
        options.sync_dir = sync_dir;
    }
    if let Some(overwrite) = optional_bool(&case.construct, "overwrite").expect("overwrite") {
        options.overwrite = overwrite;
    }
    options.encoding = encoding_owned.as_deref().unwrap_or("utf-8");
    options.refuse_paths = &refuse_refs;
    options.pre_write_hook = pre_write_slot.as_deref();
    options.pre_rename_hook = pre_rename_slot.as_deref();

    let construct_type = string_field(&case.construct, "type").expect("type");
    let outcome = string_field(&case.expected, "result").expect("result");

    let run_result: Result<String, AtomicWriteError> = match construct_type.as_str() {
        "atomic_write_bytes" => {
            let data_b64 = string_field(&case.construct, "data_b64").expect("data_b64");
            let data = decode_b64(&data_b64);
            atomic_write_bytes(&dest, &data, &options)
        }
        "atomic_write_text" => {
            let text = string_field(&case.construct, "text").expect("text");
            atomic_write_text(&dest, &text, &options)
        }
        other => panic!("unsupported construct {other} in {}", case.id),
    };

    if outcome == "ok" {
        let digest =
            run_result.unwrap_or_else(|err| panic!("unexpected error for {}: {err}", case.id));
        if let Ok(want_sha) = string_field(&case.expected, "sha256") {
            assert_eq!(digest, want_sha, "sha256 mismatch for {}", case.id);
        }
        if let Ok(want_b64) = string_field(&case.expected, "dest_b64") {
            assert_eq!(
                fs::read(&dest).expect("dest read"),
                decode_b64(&want_b64),
                "dest bytes for {}",
                case.id
            );
        }
        if let Ok(events_want) = string_list(&case.expected, "hook_events") {
            assert_eq!(
                hook_events.borrow().as_slice(),
                events_want.as_slice(),
                "hook order for {}",
                case.id
            );
        }
        if let Some(other_b64) =
            optional_string(&case.expected, "other_unchanged_b64").expect("other b64")
        {
            assert_eq!(
                fs::read(sandbox.path().join("other.bin")).expect("other"),
                decode_b64(&other_b64),
                "other unchanged for {}",
                case.id
            );
        }
        let want_temps = usize_field(&case.expected, "temp_count").expect("temp_count");
        assert_eq!(
            temp_count(sandbox.path()),
            want_temps,
            "temps for {}",
            case.id
        );
        return;
    }

    let err = run_result.expect_err(&format!("expected error for {}", case.id));
    assert_eq!(err.code(), "ATOMIC_WRITE_ERROR", "code for {}", case.id);

    if let Some(exact) = optional_string(&case.expected, "exact_message").expect("exact_message") {
        assert_eq!(err.to_string(), exact, "message for {}", case.id);
    } else {
        let kind = string_field(&case.expected, "error_kind").expect("error_kind");
        match kind.as_str() {
            "missing_parent" => {
                let parent = dest.parent().expect("parent");
                assert_eq!(
                    err.to_string(),
                    format!("Destination directory does not exist: {}", parent.display()),
                    "{}",
                    case.id
                );
            }
            "parent_not_dir" => {
                let parent_rel = string_field(&case.expected, "parent_rel").expect("parent_rel");
                let parent = sandbox.path().join(&parent_rel);
                assert_eq!(
                    err.to_string(),
                    format!(
                        "Destination parent path is not a directory: {}",
                        parent.display()
                    ),
                    "{}",
                    case.id
                );
            }
            "refuse_protected" => {
                let dest_rel = string_field(&case.expected, "dest_rel").expect("dest_rel");
                let prohibited_rel =
                    string_field(&case.expected, "prohibited_rel").expect("prohibited_rel");
                let dest_path = sandbox.path().join(&dest_rel);
                let prohibited = sandbox.path().join(&prohibited_rel);
                assert_eq!(
                    err.to_string(),
                    format!(
                        "Refusing to write to protected path: {} (matches prohibited path {})",
                        dest_path.display(),
                        prohibited.display()
                    ),
                    "{}",
                    case.id
                );
                if let Some(source_b64) =
                    optional_string(&case.expected, "source_unchanged_b64").expect("source b64")
                {
                    let source_path = sandbox.path().join(&prohibited_rel);
                    assert_eq!(
                        fs::read(&source_path).expect("source read"),
                        decode_b64(&source_b64),
                        "source unchanged for {}",
                        case.id
                    );
                }
            }
            "write_failed_exclusive" => {
                let prefix = format!("Atomic write to '{}' failed: ", dest.display());
                let message = err.to_string();
                assert!(
                    message.starts_with(&prefix),
                    "prefix for {}: {message}",
                    case.id
                );
                #[cfg(windows)]
                assert!(
                    message.contains(
                        "[WinError 183] Cannot create a file when that file already exists"
                    ),
                    "WinError 183 for {}: {message}",
                    case.id
                );
                #[cfg(not(windows))]
                assert!(
                    message.contains("[Errno 17] File exists:"),
                    "errno 17 for {}: {message}",
                    case.id
                );
                if let Some(dest_b64) =
                    optional_string(&case.expected, "dest_unchanged_b64").expect("dest b64")
                {
                    assert_eq!(
                        fs::read(&dest).expect("dest"),
                        decode_b64(&dest_b64),
                        "dest unchanged for {}",
                        case.id
                    );
                }
            }
            "write_failed_hook" => {
                assert_eq!(
                    err.to_string(),
                    format!(
                        "Atomic write to '{}' failed: Fault injection before rename",
                        dest.display()
                    ),
                    "{}",
                    case.id
                );
                if let Some(dest_b64) =
                    optional_string(&case.expected, "dest_unchanged_b64").expect("dest b64")
                {
                    assert_eq!(
                        fs::read(&dest).expect("dest"),
                        decode_b64(&dest_b64),
                        "dest unchanged for {}",
                        case.id
                    );
                }
            }
            other => panic!("unsupported error_kind {other} in {}", case.id),
        }
    }

    if optional_bool(&case.expected, "dest_exists").expect("dest_exists") == Some(false) {
        assert!(!dest.exists(), "dest must not exist for {}", case.id);
    }

    let want_temps = usize_field(&case.expected, "temp_count").expect("temp_count");
    assert_eq!(
        temp_count(sandbox.path()),
        want_temps,
        "temps for {}",
        case.id
    );
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(num))) => num.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be non-negative integer"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

#[test]
fn atomic_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    let runnable: Vec<_> = cases.iter().filter(|case| should_run(case)).collect();
    assert_eq!(
        runnable.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected runnable vector count"
    );
    for case in runnable {
        assert_case(case);
    }
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
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
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
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
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
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
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
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
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
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
