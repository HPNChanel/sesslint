//! Schema check for `sesslint.baseline/v2`.
//!
//! Rules come from pinned `schemas/sesslint.baseline.v2.json` at
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The checker refuses a document
//! that breaks a required field, the version const, an entry enum, a pattern,
//! `minLength`, or `additionalProperties: false`. It does not build canonical
//! JSON. Emitter bytes stay in [`crate::baseline`].

use std::error::Error;
use std::fmt;

/// `$id` of the pinned baseline v2 schema.
pub const SCHEMA_ID: &str = "https://sesslint.dev/schemas/sesslint.baseline/v2";

/// `schema_version` const from the pinned schema.
pub const SCHEMA_VERSION: &str = "sesslint.baseline/v2";

/// `entries[].key` pattern from the pinned schema.
pub const KEY_PATTERN: &str = "^[0-9a-f]{16}$";

/// `entries[].code` pattern from the pinned schema.
pub const CODE_PATTERN: &str = "^SL[0-9]{3}$";

/// `entries[].file_role` `minLength` from the pinned schema.
pub const FILE_ROLE_MIN_LENGTH: usize = 1;

/// First `migrated` enum value from the pinned schema.
pub const MIGRATED_VERIFIED: &str = "verified";

/// Second `migrated` enum value from the pinned schema.
pub const MIGRATED_UNVERIFIED: &str = "unverified";

const ROOT_REQUIRED: &[&str] = &["entries", "schema_version"];
const ROOT_ALLOWED: &[&str] = &["entries", "schema_version"];
const ENTRY_REQUIRED: &[&str] = &["key"];
const ENTRY_ALLOWED: &[&str] = &["key", "code", "file_role", "created_by", "migrated"];

const MAX_INPUT: usize = 1_048_576;
const MAX_DEPTH: u32 = 32;
const MAX_STRING: usize = 65_536;
const MAX_KEY: usize = 256;
const MAX_ITEMS: usize = 10_000;

/// One refused baseline document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineSchemaError {
    keyword: &'static str,
    pointer: String,
    detail: String,
}

impl BaselineSchemaError {
    fn new(keyword: &'static str, pointer: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            keyword,
            pointer: pointer.into(),
            detail: detail.into(),
        }
    }

    /// Schema keyword that failed. Parse failures use `parse`.
    pub fn keyword(&self) -> &str {
        self.keyword
    }

    /// JSON pointer of the failing value. The root pointer is empty.
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Expected constraint. Document values are not copied here.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for BaselineSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {}",
            self.keyword, self.pointer, self.detail
        )
    }
}

impl Error for BaselineSchemaError {}

/// Refuse a baseline document that breaks the pinned v2 schema.
pub fn validate_baseline_v2(text: &str) -> Result<(), BaselineSchemaError> {
    let value = parse_json(text)?;
    validate_root(&value)
}

fn validate_root(value: &Value) -> Result<(), BaselineSchemaError> {
    let items = expect_object(value, "")?;
    reject_additional(items, "", ROOT_ALLOWED)?;
    require_all(items, "", ROOT_REQUIRED)?;
    let version = require_string(items, "", "schema_version")?;
    if version != SCHEMA_VERSION {
        return Err(BaselineSchemaError::new(
            "const",
            "/schema_version",
            SCHEMA_VERSION,
        ));
    }
    let entries = lookup(items, "entries")
        .ok_or_else(|| BaselineSchemaError::new("required", "", "entries"))?;
    let entries = expect_array(entries, "/entries")?;
    for (index, entry) in entries.iter().enumerate() {
        validate_entry(entry, &format!("/entries/{index}"))?;
    }
    Ok(())
}

fn validate_entry(value: &Value, pointer: &str) -> Result<(), BaselineSchemaError> {
    let items = expect_object(value, pointer)?;
    reject_additional(items, pointer, ENTRY_ALLOWED)?;
    require_all(items, pointer, ENTRY_REQUIRED)?;
    let key = require_string(items, pointer, "key")?;
    if !is_key(key) {
        return Err(BaselineSchemaError::new(
            "pattern",
            format!("{pointer}/key"),
            KEY_PATTERN,
        ));
    }
    if let Some(code) = optional_string(items, pointer, "code")? {
        if !is_code(code) {
            return Err(BaselineSchemaError::new(
                "pattern",
                format!("{pointer}/code"),
                CODE_PATTERN,
            ));
        }
    }
    if let Some(role) = optional_string(items, pointer, "file_role")? {
        if role.chars().count() < FILE_ROLE_MIN_LENGTH {
            return Err(BaselineSchemaError::new(
                "minLength",
                format!("{pointer}/file_role"),
                FILE_ROLE_MIN_LENGTH.to_string(),
            ));
        }
    }
    let _created = optional_string(items, pointer, "created_by")?;
    if let Some(migrated) = optional_string(items, pointer, "migrated")? {
        if migrated != MIGRATED_VERIFIED && migrated != MIGRATED_UNVERIFIED {
            return Err(BaselineSchemaError::new(
                "enum",
                format!("{pointer}/migrated"),
                format!("{MIGRATED_VERIFIED}|{MIGRATED_UNVERIFIED}"),
            ));
        }
    }
    Ok(())
}

fn is_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 16
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_code(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 5
        && bytes[0] == b'S'
        && bytes[1] == b'L'
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn expect_object<'a>(
    value: &'a Value,
    pointer: &str,
) -> Result<&'a [(String, Value)], BaselineSchemaError> {
    match value {
        Value::Object(items) => Ok(items),
        _ => Err(BaselineSchemaError::new("type", pointer, "object")),
    }
}

fn expect_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value], BaselineSchemaError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(BaselineSchemaError::new("type", pointer, "array")),
    }
}

fn require_all(
    items: &[(String, Value)],
    pointer: &str,
    keys: &[&str],
) -> Result<(), BaselineSchemaError> {
    for key in keys {
        if lookup(items, key).is_none() {
            return Err(BaselineSchemaError::new("required", pointer, *key));
        }
    }
    Ok(())
}

fn reject_additional(
    items: &[(String, Value)],
    pointer: &str,
    allowed: &[&str],
) -> Result<(), BaselineSchemaError> {
    let mut extra: Vec<&str> = items
        .iter()
        .map(|(key, _)| key.as_str())
        .filter(|key| !allowed.contains(key))
        .collect();
    extra.sort_unstable();
    if let Some(name) = extra.first() {
        return Err(BaselineSchemaError::new(
            "additionalProperties",
            pointer,
            *name,
        ));
    }
    Ok(())
}

fn require_string<'a>(
    items: &'a [(String, Value)],
    pointer: &str,
    key: &str,
) -> Result<&'a str, BaselineSchemaError> {
    match optional_string(items, pointer, key)? {
        Some(text) => Ok(text),
        None => Err(BaselineSchemaError::new("required", pointer, key)),
    }
}

fn optional_string<'a>(
    items: &'a [(String, Value)],
    pointer: &str,
    key: &str,
) -> Result<Option<&'a str>, BaselineSchemaError> {
    let Some(value) = lookup(items, key) else {
        return Ok(None);
    };
    match value {
        Value::String(text) => Ok(Some(text)),
        _ => Err(BaselineSchemaError::new(
            "type",
            format!("{pointer}/{key}"),
            "string",
        )),
    }
}

fn lookup<'a>(items: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    items
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn parse_err(detail: &'static str) -> BaselineSchemaError {
    BaselineSchemaError::new("parse", "", detail)
}

enum Value {
    Null,
    /// The bool is read by the parity test. Validation only needs the type.
    Bool(#[cfg_attr(not(test), allow(dead_code))] bool),
    /// The integer is read by the parity test. Validation only needs the type.
    Integer(#[cfg_attr(not(test), allow(dead_code))] i64),
    Number,
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
    depth: u32,
}

fn parse_json(text: &str) -> Result<Value, BaselineSchemaError> {
    if text.len() > MAX_INPUT {
        return Err(parse_err("limit"));
    }
    if text.starts_with('\u{feff}') {
        return Err(parse_err("syntax"));
    }
    let mut parser = Parser {
        text,
        index: 0,
        depth: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.text.len() {
        return Err(parse_err("trailing"));
    }
    Ok(value)
}

impl Parser<'_> {
    fn peek_byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.index).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn expect_byte(&mut self, byte: u8) -> Result<(), BaselineSchemaError> {
        if self.peek_byte() == Some(byte) {
            self.index += 1;
            Ok(())
        } else {
            Err(parse_err("syntax"))
        }
    }

    fn parse_value(&mut self) -> Result<Value, BaselineSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => self.parse_literal("true", Value::Bool(true)),
            Some(b'f') => self.parse_literal("false", Value::Bool(false)),
            Some(b'n') => self.parse_literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(parse_err("syntax")),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Value) -> Result<Value, BaselineSchemaError> {
        if self.text[self.index..].starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(parse_err("syntax"))
        }
    }

    fn parse_object(&mut self) -> Result<Value, BaselineSchemaError> {
        self.expect_byte(b'{')?;
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek_byte() == Some(b'}') {
            self.index += 1;
            self.depth -= 1;
            return Ok(Value::Object(items));
        }
        loop {
            self.skip_ws();
            if self.peek_byte() != Some(b'"') {
                return Err(parse_err("syntax"));
            }
            let key = self.parse_string()?;
            if key.len() > MAX_KEY {
                return Err(parse_err("limit"));
            }
            if items.iter().any(|(existing, _)| existing == &key) {
                return Err(parse_err("duplicate"));
            }
            self.skip_ws();
            self.expect_byte(b':')?;
            let value = self.parse_value()?;
            items.push((key, value));
            if items.len() > MAX_ITEMS {
                return Err(parse_err("limit"));
            }
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(items));
                }
                _ => return Err(parse_err("syntax")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, BaselineSchemaError> {
        self.expect_byte(b'[')?;
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek_byte() == Some(b']') {
            self.index += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            if items.len() > MAX_ITEMS {
                return Err(parse_err("limit"));
            }
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(parse_err("syntax")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, BaselineSchemaError> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek_byte() else {
                return Err(parse_err("syntax"));
            };
            if byte == b'"' {
                self.index += 1;
                return Ok(out);
            }
            if byte == b'\\' {
                self.index += 1;
                out.push(self.parse_escape()?);
            } else if byte < 0x20 {
                return Err(parse_err("syntax"));
            } else {
                let rest = &self.text[self.index..];
                let ch = rest.chars().next().ok_or_else(|| parse_err("syntax"))?;
                self.index += ch.len_utf8();
                out.push(ch);
            }
            if out.len() > MAX_STRING {
                return Err(parse_err("limit"));
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, BaselineSchemaError> {
        let Some(byte) = self.peek_byte() else {
            return Err(parse_err("escape"));
        };
        self.index += 1;
        match byte {
            b'"' | b'\\' | b'/' => Ok(char::from(byte)),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode(),
            _ => Err(parse_err("escape")),
        }
    }

    fn parse_unicode(&mut self) -> Result<char, BaselineSchemaError> {
        let unit = self.parse_hex4()?;
        let code = if (0xD800..=0xDBFF).contains(&unit) {
            self.expect_byte(b'\\')?;
            self.expect_byte(b'u')?;
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(parse_err("escape"));
            }
            0x1_0000 + (((unit - 0xD800) << 10) | (low - 0xDC00))
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(parse_err("escape"));
        } else {
            unit
        };
        char::from_u32(code).ok_or_else(|| parse_err("escape"))
    }

    fn parse_hex4(&mut self) -> Result<u32, BaselineSchemaError> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let Some(byte) = self.peek_byte() else {
                return Err(parse_err("escape"));
            };
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return Err(parse_err("escape")),
            };
            self.index += 1;
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, BaselineSchemaError> {
        let start = self.index;
        if self.peek_byte() == Some(b'-') {
            self.index += 1;
        }
        match self.peek_byte() {
            Some(b'0') => {
                self.index += 1;
                if matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    return Err(parse_err("syntax"));
                }
            }
            Some(b'1'..=b'9') => {
                self.index += 1;
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return Err(parse_err("syntax")),
        }
        let mut integer = true;
        if self.peek_byte() == Some(b'.') {
            integer = false;
            self.index += 1;
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(parse_err("syntax"));
            }
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            integer = false;
            self.index += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(parse_err("syntax"));
            }
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        if !integer {
            return Ok(Value::Number);
        }
        let text = &self.text[start..self.index];
        if text == "-0" {
            return Ok(Value::Integer(0));
        }
        let number = text.parse::<i64>().map_err(|_| parse_err("limit"))?;
        Ok(Value::Integer(number))
    }

    fn enter(&mut self) -> Result<(), BaselineSchemaError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(parse_err("limit"))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod parity {
    use super::{
        validate_baseline_v2, Value, CODE_PATTERN, ENTRY_ALLOWED, ENTRY_REQUIRED,
        FILE_ROLE_MIN_LENGTH, KEY_PATTERN, MIGRATED_UNVERIFIED, MIGRATED_VERIFIED, ROOT_ALLOWED,
        ROOT_REQUIRED, SCHEMA_ID, SCHEMA_VERSION,
    };
    use crate::baseline::{dump_baseline, load_baseline, upgrade_baseline, DEFAULT_CREATED_BY};
    use model::finding::Finding;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const EXPECTED_VECTOR_COUNT: usize = 25;
    const EXPECTED_COVERED: usize = 3;
    const EXPECTED_NOT_APPLICABLE: usize = 19;
    const EXPECTED_VECTORS_SHA256: &str =
        "9e2dc91e68e60bb53c7f947861a94ed7cefa7de63d6368e3ec1a8afc2ed050a7";
    const EXPECTED_SCHEMA_SHA256: &str =
        "d2b1e0a160b0289db257f353df01f4b7e1620804ee748236f5eeecff6b9802dd";
    const EXPECTED_BASELINE_PY_SHA256: &str =
        "7d641bb31d495783f7f14b0d99e8a29ef3c80f85924ed616013ba883892d0851";
    const MALFORMED_V2: &str =
        "{\"schema_version\":\"sesslint.baseline/v2\",\"entries\":[{\"key\":\"nothex\"}]}";
    const V1_UNVERIFIED: &str = "{\"fingerprints\": [\"5d4465190d6abf3f\", \"aabbccddeeff0011\"], \"schema_version\": \"sesslint.baseline/v1\"}";
    const V1_DETERMINISTIC: &str = "{\"fingerprints\": [\"aabbccddeeff0011\", \"5d4465190d6abf3f\"], \"schema_version\": \"sesslint.baseline/v1\"}";
    const VECTOR_IDS: [&str; 25] = [
        "upgrade_unverified_without_source",
        "upgrade_deterministic",
        "dump_empty",
        "upgrade_verified_synthetic",
        "validate_key_only",
        "validate_empty_created_by",
        "validate_file_role_one",
        "load_malformed_v2",
        "missing_entries",
        "missing_schema_version",
        "missing_key",
        "root_additional",
        "entry_additional",
        "wrong_const",
        "bad_enum",
        "bad_code_pattern",
        "empty_file_role",
        "entries_not_array",
        "entry_not_object",
        "root_not_object",
        "created_by_not_string",
        "key_not_string",
        "schema_version_not_string",
        "uppercase_key",
        "trailing_comma",
    ];

    struct TempFile(PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _unused = fs::remove_file(&self.0);
        }
    }

    struct Case {
        id: String,
        kind: String,
        entire_test: bool,
        function: String,
        mode: String,
        emitter: bool,
        document: Option<String>,
        v1_text: Option<String>,
        created_by: Option<String>,
        calls: Option<i64>,
        findings: Option<String>,
        fingerprints: Vec<String>,
        schema_ok: bool,
        expected_document: Option<String>,
        verified: Option<i64>,
        unverified: Option<i64>,
        keyword: Option<String>,
        pointer: Option<String>,
        detail: Option<String>,
        message_contains: Vec<String>,
    }

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.baseline.v2")
    }

    fn read_clean(path: &Path) -> String {
        let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        assert!(!bytes.contains(&b'\r'), "{} contains CR", path.display());
        let text = String::from_utf8(bytes).unwrap_or_else(|err| panic!("utf-8 {}", err));
        assert!(!text.contains("FOR_WORK"), "{}", path.display());
        assert!(!text.contains("sesslint-wt-"), "{}", path.display());
        assert!(!text.contains("02694d5"), "{}", path.display());
        assert!(!contains_sbp(&text), "{}", path.display());
        text
    }

    fn contains_sbp(text: &str) -> bool {
        let bytes = text.as_bytes();
        let mut start = 0;
        while let Some(rel) = text[start..].find("sbp_") {
            let at = start + rel + 4;
            if bytes.len() >= at + 40
                && bytes[at..at + 40]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return true;
            }
            start = at;
        }
        false
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            out.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            out.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
        out
    }

    fn object(value: &Value) -> &[(String, Value)] {
        match value {
            Value::Object(items) => items,
            _ => panic!("expected object"),
        }
    }

    fn get<'a>(items: &'a [(String, Value)], key: &str) -> &'a Value {
        let pair = items
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("missing {key}"));
        &pair.1
    }

    fn as_str(value: &Value) -> &str {
        match value {
            Value::String(text) => text,
            _ => panic!("expected string"),
        }
    }

    fn as_bool(value: &Value) -> bool {
        match value {
            Value::Bool(flag) => *flag,
            _ => panic!("expected bool"),
        }
    }

    fn as_i64(value: &Value) -> i64 {
        match value {
            Value::Integer(number) => *number,
            _ => panic!("expected integer"),
        }
    }

    fn as_array(value: &Value) -> &[Value] {
        match value {
            Value::Array(items) => items,
            _ => panic!("expected array"),
        }
    }

    fn opt_string(items: &[(String, Value)], key: &str) -> Option<String> {
        match items.iter().find(|(name, _)| name == key) {
            None | Some((_, Value::Null)) => None,
            Some((_, Value::String(text))) => Some(text.clone()),
            Some(_) => panic!("{key} is not a string"),
        }
    }

    fn opt_i64(items: &[(String, Value)], key: &str) -> Option<i64> {
        match items.iter().find(|(name, _)| name == key) {
            None | Some((_, Value::Null)) => None,
            Some((_, Value::Integer(number))) => Some(*number),
            Some(_) => panic!("{key} is not an integer"),
        }
    }

    fn string_list(value: &Value) -> Vec<String> {
        as_array(value)
            .iter()
            .map(as_str)
            .map(ToOwned::to_owned)
            .collect()
    }

    fn assert_string_list(value: &Value, expected: &[&str]) {
        let got = string_list(value);
        let want: Vec<String> = expected.iter().map(|item| (*item).to_owned()).collect();
        assert_eq!(got, want);
    }

    fn parse_case(value: &Value) -> Case {
        let items = object(value);
        let construct = object(get(items, "construct"));
        let expected = object(get(items, "expected"));
        let fingerprints = match construct.iter().find(|(name, _)| name == "fingerprints") {
            None => Vec::new(),
            Some((_, value)) => string_list(value),
        };
        let message_contains = match expected.iter().find(|(name, _)| name == "message_contains") {
            None => Vec::new(),
            Some((_, value)) => string_list(value),
        };
        Case {
            id: as_str(get(items, "id")).to_owned(),
            kind: as_str(get(construct, "type")).to_owned(),
            entire_test: as_bool(get(construct, "entire_test")),
            function: as_str(get(construct, "function")).to_owned(),
            mode: as_str(get(construct, "mode")).to_owned(),
            emitter: as_bool(get(construct, "emitter")),
            document: opt_string(construct, "document"),
            v1_text: opt_string(construct, "v1_text"),
            created_by: opt_string(construct, "created_by"),
            calls: opt_i64(construct, "calls"),
            findings: opt_string(construct, "findings"),
            fingerprints,
            schema_ok: as_bool(get(expected, "schema_ok")),
            expected_document: opt_string(expected, "document"),
            verified: opt_i64(expected, "verified"),
            unverified: opt_i64(expected, "unverified"),
            keyword: opt_string(expected, "keyword"),
            pointer: opt_string(expected, "pointer"),
            detail: opt_string(expected, "detail"),
            message_contains,
        }
    }

    fn assert_schema(text: &str, case: &Case) {
        let result = validate_baseline_v2(text);
        if case.schema_ok {
            result.unwrap_or_else(|err| panic!("{} should pass: {err}", case.id));
            return;
        }
        let err = result.unwrap_err();
        assert_eq!(
            err.keyword(),
            case.keyword.as_deref().unwrap(),
            "{}",
            case.id
        );
        assert_eq!(
            err.pointer(),
            case.pointer.as_deref().unwrap(),
            "{}",
            case.id
        );
        assert_eq!(err.detail(), case.detail.as_deref().unwrap(), "{}", case.id);
    }

    fn write_temp(name: &str, text: &str) -> TempFile {
        let path = std::env::temp_dir().join(name);
        fs::write(&path, text.as_bytes()).unwrap_or_else(|err| panic!("write temp: {err}"));
        TempFile(path)
    }

    fn assert_upgrade(case: &Case) {
        assert!(case.entire_test, "{}", case.id);
        assert_eq!(case.function, "upgrade_baseline");
        assert_eq!(case.mode, "success");
        assert!(case.emitter, "{}", case.id);
        assert_eq!(case.findings.as_deref(), Some("none"));
        assert_eq!(case.created_by.as_deref(), Some(DEFAULT_CREATED_BY));
        let v1 = case.v1_text.as_deref().unwrap();
        let expected = case.expected_document.as_deref().unwrap();
        let calls = usize::try_from(case.calls.unwrap()).unwrap();
        assert!(calls == 1 || calls == 2, "{}", case.id);
        for _ in 0..calls {
            let file = write_temp(&format!("sl-baseline-schema-{}.json", case.id), v1);
            let none: Option<std::iter::Empty<&Finding>> = None;
            let (document, verified, unverified) =
                upgrade_baseline(&file.0, none, DEFAULT_CREATED_BY)
                    .unwrap_or_else(|err| panic!("{} upgrade: {err}", case.id));
            assert_eq!(document, expected, "{}", case.id);
            assert_eq!(i64::try_from(verified).unwrap(), case.verified.unwrap());
            assert_eq!(i64::try_from(unverified).unwrap(), case.unverified.unwrap());
            assert_schema(&document, case);
        }
    }

    fn assert_dump_empty(case: &Case) {
        assert!(!case.entire_test, "{}", case.id);
        assert_eq!(case.function, "dump_baseline");
        assert_eq!(case.mode, "success");
        assert!(case.emitter);
        let expected = case.expected_document.as_deref().unwrap();
        let document = dump_baseline(std::iter::empty::<&Finding>(), DEFAULT_CREATED_BY)
            .unwrap_or_else(|err| panic!("dump: {err}"));
        assert_eq!(document, expected);
        assert_schema(&document, case);
    }

    fn assert_load(case: &Case) {
        assert!(case.entire_test, "{}", case.id);
        assert_eq!(case.function, "load_baseline");
        assert_eq!(case.mode, "failure");
        assert!(!case.emitter);
        let document = case.document.as_deref().unwrap();
        assert_eq!(document, MALFORMED_V2);
        let file = write_temp("sl-baseline-schema-load-malformed.json", document);
        let err = load_baseline(&file.0).unwrap_err();
        let message = err.to_string();
        assert!(!case.message_contains.is_empty());
        for needle in &case.message_contains {
            assert!(message.contains(needle), "{needle} missing from loader");
        }
        assert_schema(document, case);
    }

    fn assert_validate(case: &Case) {
        assert_eq!(case.function, "validate_baseline_v2");
        assert!(!case.entire_test, "{}", case.id);
        let document = case.document.as_deref().unwrap();
        assert_schema(document, case);
    }

    fn assert_case(case: &Case) {
        match case.id.as_str() {
            "upgrade_unverified_without_source" => {
                assert_eq!(case.kind, "upgrade_baseline");
                assert_eq!(case.fingerprints, ["5d4465190d6abf3f", "aabbccddeeff0011"]);
                assert_eq!(case.v1_text.as_deref(), Some(V1_UNVERIFIED));
                assert_eq!(case.calls, Some(1));
                assert_upgrade(case);
            }
            "upgrade_deterministic" => {
                assert_eq!(case.kind, "upgrade_baseline");
                assert_eq!(case.fingerprints, ["aabbccddeeff0011", "5d4465190d6abf3f"]);
                assert_eq!(case.v1_text.as_deref(), Some(V1_DETERMINISTIC));
                assert_eq!(case.calls, Some(2));
                assert_upgrade(case);
            }
            "dump_empty" => {
                assert_eq!(case.kind, "dump_baseline");
                assert_dump_empty(case);
            }
            "load_malformed_v2" => {
                assert_eq!(case.kind, "load_baseline");
                assert_load(case);
            }
            "upgrade_verified_synthetic"
            | "validate_key_only"
            | "validate_empty_created_by"
            | "validate_file_role_one"
            | "missing_entries"
            | "missing_schema_version"
            | "missing_key"
            | "root_additional"
            | "entry_additional"
            | "wrong_const"
            | "bad_enum"
            | "bad_code_pattern"
            | "empty_file_role"
            | "entries_not_array"
            | "entry_not_object"
            | "root_not_object"
            | "created_by_not_string"
            | "key_not_string"
            | "schema_version_not_string"
            | "uppercase_key"
            | "trailing_comma" => {
                assert_eq!(case.kind, "validate");
                assert_validate(case);
            }
            other => panic!("unexpected vector {other}"),
        }
    }

    fn assert_constraints(root: &Value) {
        let constraints = object(get(object(root), "constraints"));
        assert_string_list(get(constraints, "root_required"), ROOT_REQUIRED);
        assert_string_list(
            get(constraints, "root_properties"),
            &["schema_version", "entries"],
        );
        assert!(!as_bool(get(constraints, "root_additional")));
        assert_eq!(
            as_str(get(constraints, "schema_version_const")),
            SCHEMA_VERSION
        );
        assert_string_list(get(constraints, "entry_required"), ENTRY_REQUIRED);
        assert_string_list(get(constraints, "entry_properties"), ENTRY_ALLOWED);
        assert!(!as_bool(get(constraints, "entry_additional")));
        assert_eq!(as_str(get(constraints, "key_pattern")), KEY_PATTERN);
        assert_eq!(as_str(get(constraints, "code_pattern")), CODE_PATTERN);
        assert_eq!(
            as_i64(get(constraints, "file_role_min_length")),
            i64::try_from(FILE_ROLE_MIN_LENGTH).unwrap()
        );
        assert_string_list(
            get(constraints, "migrated_enum"),
            &[MIGRATED_VERIFIED, MIGRATED_UNVERIFIED],
        );
        let mut pin_allowed = string_list(get(constraints, "root_properties"));
        pin_allowed.sort();
        let mut rust_allowed: Vec<String> =
            ROOT_ALLOWED.iter().map(|item| (*item).to_owned()).collect();
        rust_allowed.sort();
        assert_eq!(pin_allowed, rust_allowed);
    }

    fn assert_coverage(text: &str, cases: &[Case]) {
        let root = super::parse_json(text).unwrap();
        let items = object(&root);
        assert_eq!(as_str(get(items, "python_commit")), PIN);
        assert_eq!(as_str(get(items, "schema_id")), SCHEMA_ID);
        assert_eq!(as_str(get(items, "test_file")), "tests/test_baseline.py");
        assert_eq!(
            as_i64(get(items, "covered_count")),
            i64::try_from(EXPECTED_COVERED).unwrap()
        );
        assert_eq!(
            as_i64(get(items, "not_applicable_count")),
            i64::try_from(EXPECTED_NOT_APPLICABLE).unwrap()
        );
        let rows = as_array(get(items, "rows"));
        assert_eq!(rows.len(), EXPECTED_COVERED + EXPECTED_NOT_APPLICABLE);
        let mut covered = 0_usize;
        let mut not_applicable = 0_usize;
        for row in rows {
            let fields = object(row);
            let status = as_str(get(fields, "status"));
            let test_name = as_str(get(fields, "test"));
            assert_eq!(as_str(get(fields, "column")), "column_0");
            assert!(test_name.starts_with("tests/test_baseline.py::test_"));
            match status {
                "covered" => {
                    covered += 1;
                    let vector_id = as_str(get(fields, "vector_id"));
                    let case = cases.iter().find(|case| case.id == vector_id).unwrap();
                    assert!(case.entire_test, "{test_name}");
                    assert_eq!(case.function, expected_function(test_name));
                    assert_eq!(vector_id, expected_vector(test_name));
                }
                "not_applicable" => {
                    not_applicable += 1;
                    assert!(matches!(get(fields, "vector_id"), Value::Null));
                    let note = as_str(get(fields, "note"));
                    assert!(!note.is_empty(), "{test_name}");
                }
                other => panic!("status {other}"),
            }
        }
        assert_eq!(covered, EXPECTED_COVERED);
        assert_eq!(not_applicable, EXPECTED_NOT_APPLICABLE);
    }

    fn expected_function(test_name: &str) -> &'static str {
        match test_name {
            "tests/test_baseline.py::test_load_malformed_v2_fails" => "load_baseline",
            "tests/test_baseline.py::test_upgrade_unverified_without_source"
            | "tests/test_baseline.py::test_upgrade_deterministic" => "upgrade_baseline",
            _ => panic!("not a covered test {test_name}"),
        }
    }

    fn expected_vector(test_name: &str) -> &'static str {
        match test_name {
            "tests/test_baseline.py::test_load_malformed_v2_fails" => "load_malformed_v2",
            "tests/test_baseline.py::test_upgrade_unverified_without_source" => {
                "upgrade_unverified_without_source"
            }
            "tests/test_baseline.py::test_upgrade_deterministic" => "upgrade_deterministic",
            _ => panic!("not a covered test {test_name}"),
        }
    }

    #[test]
    fn duplicate_key_is_refused() {
        let err = validate_baseline_v2(r#"{"entries":[],"entries":[]}"#).unwrap_err();
        assert_eq!(err.keyword(), "parse");
        assert_eq!(err.detail(), "duplicate");
        assert_eq!(err.pointer(), "");
    }

    #[test]
    fn baseline_v2_schema_matches_pin() {
        let dir = parity_dir();
        let vectors_text = read_clean(&dir.join("vectors.json"));
        assert_eq!(sha256_hex(vectors_text.as_bytes()), EXPECTED_VECTORS_SHA256);
        let root = super::parse_json(&vectors_text).unwrap();
        let items = object(&root);
        assert_eq!(
            as_str(get(items, "schema")),
            "sesslint.parity-schema-vectors/v1"
        );
        assert_eq!(as_str(get(items, "module")), "sesslint.baseline");
        assert_eq!(as_str(get(items, "schema_id")), SCHEMA_ID);
        assert_eq!(as_str(get(items, "python_commit")), PIN);
        assert_eq!(as_str(get(items, "schema_sha256")), EXPECTED_SCHEMA_SHA256);
        assert_eq!(
            as_str(get(items, "baseline_py_sha256")),
            EXPECTED_BASELINE_PY_SHA256
        );
        assert_constraints(&root);
        let values = as_array(get(items, "vectors"));
        assert_eq!(values.len(), EXPECTED_VECTOR_COUNT);
        let cases: Vec<Case> = values.iter().map(parse_case).collect();
        for (case, ident) in cases.iter().zip(VECTOR_IDS) {
            assert_eq!(case.id, ident);
            assert_case(case);
        }
        let entire = cases.iter().filter(|case| case.entire_test).count();
        assert_eq!(entire, EXPECTED_COVERED);

        let manifest_text = read_clean(&dir.join("manifest.json"));
        let manifest = super::parse_json(&manifest_text).unwrap();
        let manifest_items = object(&manifest);
        assert_eq!(as_str(get(manifest_items, "python_commit")), PIN);
        assert_eq!(as_str(get(manifest_items, "schema_id")), SCHEMA_ID);
        assert_eq!(
            as_str(get(manifest_items, "vectors_sha256")),
            EXPECTED_VECTORS_SHA256
        );
        assert_eq!(
            as_i64(get(manifest_items, "vector_count")),
            i64::try_from(EXPECTED_VECTOR_COUNT).unwrap()
        );
        assert_eq!(
            as_i64(get(manifest_items, "covered_count")),
            i64::try_from(EXPECTED_COVERED).unwrap()
        );
        assert_eq!(
            as_i64(get(manifest_items, "not_applicable_count")),
            i64::try_from(EXPECTED_NOT_APPLICABLE).unwrap()
        );
        assert_eq!(
            as_str(get(manifest_items, "schema_sha256")),
            EXPECTED_SCHEMA_SHA256
        );

        let coverage_text = read_clean(&dir.join("coverage.json"));
        assert_coverage(&coverage_text, &cases);

        let provenance_text = read_clean(&dir.join("PROVENANCE.json"));
        let provenance = super::parse_json(&provenance_text).unwrap();
        let provenance_items = object(&provenance);
        assert!(!as_bool(get(provenance_items, "contains_real_data")));
        assert_eq!(as_str(get(provenance_items, "origin")), "synthetic");
        assert_eq!(as_str(get(provenance_items, "python_commit")), PIN);
    }
}
