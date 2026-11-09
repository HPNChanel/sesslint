//! JSON Schema `sesslint.seal-ledger/v1`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! `schemas/sesslint.seal-ledger.v1.json`.
//!
//! [`validate_json`] enforces that document: required names, the `schema`
//! const, the `tool` enum, `additionalProperties: false`, and the type, bound,
//! length, and pattern constraints written beside them. A value this module
//! cannot prove is rejected. Duplicate object keys are rejected. A JSON number
//! with a fraction, an exponent, or a magnitude outside `i64` is rejected.
//!
//! [`emit_entry`] builds one ledger object in the pin's `build_entry` field
//! order. Bytes come from [`codec::canonical_codec::canonical_json_bytes`].
//! `entry_sha256` is SHA-256 of those bytes with `newline` false, over every
//! field except `entry_sha256`. This module does not encode JSON itself. A
//! codec error is copied unchanged, including
//! `sesslint._canonical_codec.canonical_json_bytes is not available`.
//!
//! `sealed_at` is an argument. The wall clock is not read. Session payload
//! text is not stored.

use std::error::Error;
use std::fmt;

use codec::canonical_codec::{canonical_json_bytes, CanonicalError, ObjectKey, Value};

/// Draft URI on the pinned schema.
pub const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// `$id` of the pinned schema.
pub const SCHEMA_DOCUMENT_ID: &str = "https://sesslint.dev/schemas/sesslint.seal-ledger/v1";

/// `properties.schema.const` and the pin's `SEAL_SCHEMA_ID`.
pub const SCHEMA_CONST: &str = "sesslint.seal-ledger/v1";

/// Pin `GENESIS`.
pub const GENESIS: &str = "GENESIS";

/// Pinned `required`, in document order.
pub const REQUIRED: [&str; 10] = [
    "schema",
    "seq",
    "prev_sha256",
    "file_sha256",
    "tool",
    "verdict",
    "codes",
    "report_sha256",
    "sealed_at",
    "entry_sha256",
];

/// Pinned `properties`, in document order.
pub const PROPERTIES: [&str; 12] = [
    "schema",
    "seq",
    "prev_sha256",
    "file_sha256",
    "path",
    "tool",
    "verdict",
    "codes",
    "report_sha256",
    "sealed_at",
    "genesis_of",
    "entry_sha256",
];

/// Fields `build_entry` inserts, including optional names.
pub const EMIT_FIELD_ORDER: [&str; 12] = [
    "schema",
    "seq",
    "prev_sha256",
    "file_sha256",
    "tool",
    "verdict",
    "codes",
    "report_sha256",
    "sealed_at",
    "path",
    "genesis_of",
    "entry_sha256",
];

/// Pinned `tool.enum`, in document order.
pub const TOOLS: [&str; 3] = ["check", "verify", "repair"];

/// Pinned `seq.minimum`.
pub const SEQ_MINIMUM: i64 = 1;

/// Pinned code-count minimum.
pub const CODE_MINIMUM: i64 = 0;

/// Pinned `path.minLength` and `verdict.minLength`.
pub const TEXT_MIN_LENGTH: usize = 1;

/// Pinned `prev_sha256.pattern`.
pub const PREV_SHA256_PATTERN: &str = "^(GENESIS|[0-9a-f]{64})$";

/// Pinned 64-digit hex pattern.
pub const HEX64_PATTERN: &str = "^[0-9a-f]{64}$";

/// Pinned `sealed_at.pattern`.
pub const SEALED_AT_PATTERN: &str = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$";

/// Pinned code-name pattern.
pub const CODE_NAME_PATTERN: &str = "^SL[0-9]{3}$";

const MAX_DEPTH: usize = 32;

/// Failure from [`validate_json`] or [`emit_entry`].
///
/// [`Display`] is the reason only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSchemaError {
    message: String,
}

impl LedgerSchemaError {
    /// Stable reason text. Field names from the schema are included.
    /// Arbitrary document values are not.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LedgerSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for LedgerSchemaError {}

/// Inputs for [`emit_entry`]. `sealed_at` is already formatted.
#[derive(Clone, Copy, Debug)]
pub struct EmitInput<'a> {
    /// Pinned `seq`.
    pub seq: i64,
    /// Pinned `prev_sha256`.
    pub prev_sha256: &'a str,
    /// Pinned `file_sha256`.
    pub file_sha256: &'a str,
    /// Omitted when `None`, matching `build_entry`.
    pub path: Option<&'a str>,
    /// Pinned `tool`.
    pub tool: &'a str,
    /// Pinned `verdict`.
    pub verdict: &'a str,
    /// Code counts in caller order. Names must be unique.
    pub codes: &'a [(&'a str, i64)],
    /// Pinned `report_sha256`.
    pub report_sha256: &'a str,
    /// Omitted when `None`.
    pub genesis_of: Option<&'a str>,
    /// Pinned `sealed_at` text.
    pub sealed_at: &'a str,
}

/// Canonical ledger object and the one-LF line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emitted {
    /// SHA-256 hex of the canonical preimage.
    pub entry_sha256: String,
    /// Canonical object with `newline` false.
    pub object_bytes: Vec<u8>,
    /// Canonical object with `newline` true.
    pub line_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Validate one JSON document against the pinned seal-ledger schema.
///
/// # Errors
///
/// Returns a schema reason, a JSON syntax reason, or an unproven-number
/// reason. The document text is not copied into the error.
pub fn validate_json(document: &str) -> Result<(), LedgerSchemaError> {
    validate_root(&parse_json(document)?)
}

/// Emit one ledger entry and its canonical bytes.
///
/// Invalid inputs are refused before the codec runs. After the codec returns,
/// the object is validated again and dropped if that check fails.
///
/// # Errors
///
/// Schema reasons use the same text as [`validate_json`]. A codec failure
/// keeps [`CanonicalError::message`] exactly.
pub fn emit_entry(input: EmitInput<'_>) -> Result<Emitted, LedgerSchemaError> {
    reject_emit(input)?;
    let preimage = entry_value(input, None);
    let hashed = canonical_bytes(&preimage, false)?;
    let entry_sha256 = crate::seal::sha256_bytes(&hashed);
    let full = entry_value(input, Some(entry_sha256.as_str()));
    let object_bytes = canonical_bytes(&full, false)?;
    let line_bytes = canonical_bytes(&full, true)?;
    let text = match std::str::from_utf8(&object_bytes) {
        Ok(text) => text,
        Err(_) => return fail("json_invalid"),
    };
    validate_json(text)?;
    Ok(Emitted {
        entry_sha256,
        object_bytes,
        line_bytes,
    })
}

fn failure(message: impl Into<String>) -> LedgerSchemaError {
    LedgerSchemaError {
        message: message.into(),
    }
}

fn fail<T>(message: impl Into<String>) -> Result<T, LedgerSchemaError> {
    Err(failure(message))
}

fn codec_failure(err: CanonicalError) -> LedgerSchemaError {
    let message = err.message().to_owned();
    failure(message)
}

fn canonical_bytes(value: &Value, newline: bool) -> Result<Vec<u8>, LedgerSchemaError> {
    match canonical_json_bytes(value, newline) {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(codec_failure(err)),
    }
}

fn reject_emit(input: EmitInput<'_>) -> Result<(), LedgerSchemaError> {
    if input.seq < SEQ_MINIMUM {
        return fail("minimum:seq");
    }
    if input.prev_sha256 != GENESIS && !is_hex64(input.prev_sha256) {
        return fail("pattern:prev_sha256");
    }
    if !is_hex64(input.file_sha256) {
        return fail("pattern:file_sha256");
    }
    if let Some(path) = input.path {
        if path.chars().count() < TEXT_MIN_LENGTH {
            return fail("min_length:path");
        }
    }
    if !TOOLS.contains(&input.tool) {
        return fail("enum_mismatch:tool");
    }
    if input.verdict.chars().count() < TEXT_MIN_LENGTH {
        return fail("min_length:verdict");
    }
    if duplicate_code(input.codes) {
        return fail("duplicate_key");
    }
    let mut names: Vec<&str> = input.codes.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    for name in &names {
        if !is_code_name(name) {
            return fail("pattern:codes");
        }
    }
    if input.codes.iter().any(|(_, count)| *count < CODE_MINIMUM) {
        return fail("minimum:codes");
    }
    if !is_hex64(input.report_sha256) {
        return fail("pattern:report_sha256");
    }
    if !is_sealed_at(input.sealed_at) {
        return fail("pattern:sealed_at");
    }
    if let Some(genesis) = input.genesis_of {
        if !is_hex64(genesis) {
            return fail("pattern:genesis_of");
        }
    }
    Ok(())
}

fn duplicate_code(codes: &[(&str, i64)]) -> bool {
    codes
        .iter()
        .enumerate()
        .any(|(index, (name, _))| codes[..index].iter().any(|(earlier, _)| earlier == name))
}

fn entry_value(input: EmitInput<'_>, entry_sha256: Option<&str>) -> Value {
    let codes = input
        .codes
        .iter()
        .map(|(name, count)| (ObjectKey::string((*name).to_owned()), Value::int(*count)))
        .collect();
    let mut fields = vec![
        (ObjectKey::string("schema"), Value::string(SCHEMA_CONST)),
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
        (ObjectKey::string("codes"), Value::object(codes)),
        (
            ObjectKey::string("report_sha256"),
            Value::string(input.report_sha256),
        ),
        (
            ObjectKey::string("sealed_at"),
            Value::string(input.sealed_at),
        ),
    ];
    if let Some(path) = input.path {
        fields.push((ObjectKey::string("path"), Value::string(path)));
    }
    if let Some(genesis) = input.genesis_of {
        fields.push((ObjectKey::string("genesis_of"), Value::string(genesis)));
    }
    if let Some(hash) = entry_sha256 {
        fields.push((ObjectKey::string("entry_sha256"), Value::string(hash)));
    }
    Value::object(fields)
}

fn validate_root(value: &Json) -> Result<(), LedgerSchemaError> {
    let Json::Object(items) = value else {
        return fail("type_mismatch:$");
    };
    for field in REQUIRED {
        if object_get(items, field).is_none() {
            return fail(format!("missing_required:{field}"));
        }
    }
    if items.iter().any(|(key, _)| !is_known_property(key)) {
        return fail("additional_property");
    }
    validate_const(present(items, "schema")?, SCHEMA_CONST, "schema")?;
    validate_seq(present(items, "seq")?)?;
    validate_prev(present(items, "prev_sha256")?)?;
    validate_hex(present(items, "file_sha256")?, "file_sha256")?;
    if let Some(path) = object_get(items, "path") {
        validate_min_string(path, "path")?;
    }
    validate_tool(present(items, "tool")?)?;
    validate_min_string(present(items, "verdict")?, "verdict")?;
    validate_codes(present(items, "codes")?)?;
    validate_hex(present(items, "report_sha256")?, "report_sha256")?;
    validate_sealed(present(items, "sealed_at")?)?;
    if let Some(genesis) = object_get(items, "genesis_of") {
        validate_hex(genesis, "genesis_of")?;
    }
    validate_hex(present(items, "entry_sha256")?, "entry_sha256")?;
    Ok(())
}

fn present<'a>(items: &'a [(String, Json)], key: &str) -> Result<&'a Json, LedgerSchemaError> {
    match object_get(items, key) {
        Some(value) => Ok(value),
        None => fail(format!("missing_required:{key}")),
    }
}

fn object_get<'a>(items: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    items
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn is_known_property(key: &str) -> bool {
    PROPERTIES.contains(&key)
}

fn validate_const(value: &Json, expected: &str, path: &str) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if text == expected => Ok(()),
        _ => fail(format!("const_mismatch:{path}")),
    }
}

fn validate_seq(value: &Json) -> Result<(), LedgerSchemaError> {
    match value {
        Json::Int(number) if *number >= SEQ_MINIMUM => Ok(()),
        Json::Int(_) => fail("minimum:seq"),
        _ => fail("type_mismatch:seq"),
    }
}

fn validate_prev(value: &Json) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if text == GENESIS || is_hex64(text) => Ok(()),
        Json::String(_) => fail("pattern:prev_sha256"),
        _ => fail("type_mismatch:prev_sha256"),
    }
}

fn validate_hex(value: &Json, path: &str) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if is_hex64(text) => Ok(()),
        Json::String(_) => fail(format!("pattern:{path}")),
        _ => fail(format!("type_mismatch:{path}")),
    }
}

fn validate_min_string(value: &Json, path: &str) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if text.chars().count() >= TEXT_MIN_LENGTH => Ok(()),
        Json::String(_) => fail(format!("min_length:{path}")),
        _ => fail(format!("type_mismatch:{path}")),
    }
}

fn validate_tool(value: &Json) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if TOOLS.contains(&text.as_str()) => Ok(()),
        Json::String(_) => fail("enum_mismatch:tool"),
        _ => fail("type_mismatch:tool"),
    }
}

fn validate_sealed(value: &Json) -> Result<(), LedgerSchemaError> {
    match value {
        Json::String(text) if is_sealed_at(text) => Ok(()),
        Json::String(_) => fail("pattern:sealed_at"),
        _ => fail("type_mismatch:sealed_at"),
    }
}

fn validate_codes(value: &Json) -> Result<(), LedgerSchemaError> {
    let Json::Object(items) = value else {
        return fail("type_mismatch:codes");
    };
    let mut names: Vec<&str> = items.iter().map(|(key, _)| key.as_str()).collect();
    names.sort_unstable();
    for name in &names {
        if !is_code_name(name) {
            return fail("pattern:codes");
        }
    }
    for name in &names {
        let Some(item) = object_get(items, name) else {
            return fail("type_mismatch:codes");
        };
        match item {
            Json::Int(count) if *count >= CODE_MINIMUM => {}
            Json::Int(_) => return fail("minimum:codes"),
            _ => return fail("type_mismatch:codes"),
        }
    }
    Ok(())
}

fn is_hex64(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_code_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 5
        && bytes[0] == b'S'
        && bytes[1] == b'L'
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4].is_ascii_digit()
}

fn is_sealed_at(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 20
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .into_iter()
            .all(|index| bytes[index].is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
}

fn parse_json(document: &str) -> Result<Json, LedgerSchemaError> {
    let mut parser = Parser {
        text: document,
        index: 0,
        depth: 0,
    };
    parser.skip();
    if parser.index >= parser.text.len() {
        return fail("json_invalid");
    }
    let value = parser.parse_value()?;
    parser.skip();
    if parser.index != parser.text.len() {
        return fail("json_invalid");
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn parse_value(&mut self) -> Result<Json, LedgerSchemaError> {
        self.skip();
        match self.peek_byte() {
            Some(b'n') => self.consume_literal("null", Json::Null),
            Some(b't') => self.consume_literal("true", Json::Bool(true)),
            Some(b'f') => self.consume_literal("false", Json::Bool(false)),
            Some(b'"') => self.parse_string().map(Json::String),
            Some(b'{') => self.parse_object().map(Json::Object),
            Some(b'[') => self.parse_array().map(Json::Array),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => fail("json_invalid"),
        }
    }

    fn parse_object(&mut self) -> Result<Vec<(String, Json)>, LedgerSchemaError> {
        self.enter()?;
        self.expect(b'{')?;
        self.skip();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.index += 1;
            self.depth -= 1;
            return Ok(items);
        }
        loop {
            self.skip();
            let key = self.parse_string()?;
            if items.iter().any(|(name, _)| name == &key) {
                return fail("duplicate_key");
            }
            self.skip();
            self.expect(b':')?;
            let value = self.parse_value()?;
            items.push((key, value));
            self.skip();
            match self.peek_byte() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    break;
                }
                _ => return fail("json_invalid"),
            }
        }
        self.depth -= 1;
        Ok(items)
    }

    fn parse_array(&mut self) -> Result<Vec<Json>, LedgerSchemaError> {
        self.enter()?;
        self.expect(b'[')?;
        self.skip();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.index += 1;
            self.depth -= 1;
            return Ok(items);
        }
        loop {
            items.push(self.parse_value()?);
            self.skip();
            match self.peek_byte() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    break;
                }
                _ => return fail("json_invalid"),
            }
        }
        self.depth -= 1;
        Ok(items)
    }

    fn parse_string(&mut self) -> Result<String, LedgerSchemaError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(ch) = self.bump_char() else {
                return fail("json_invalid");
            };
            match ch {
                '"' => return Ok(out),
                '\\' => out.push(self.parse_escape()?),
                other if (other as u32) < 0x20 => return fail("json_invalid"),
                other => out.push(other),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, LedgerSchemaError> {
        let Some(ch) = self.bump_char() else {
            return fail("json_invalid");
        };
        match ch {
            '"' => Ok('"'),
            '\\' => Ok('\\'),
            '/' => Ok('/'),
            'b' => Ok('\u{0008}'),
            'f' => Ok('\u{000c}'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            'u' => self.parse_unicode(),
            _ => fail("json_invalid"),
        }
    }

    fn parse_unicode(&mut self) -> Result<char, LedgerSchemaError> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let Some(ch) = self.bump_char() else {
                return fail("json_invalid");
            };
            let digit = match ch {
                '0'..='9' => u32::from(ch as u8 - b'0'),
                'a'..='f' => u32::from(ch as u8 - b'a' + 10),
                'A'..='F' => u32::from(ch as u8 - b'A' + 10),
                _ => return fail("json_invalid"),
            };
            value = (value << 4) | digit;
        }
        if (0xD800..=0xDFFF).contains(&value) {
            return fail("unproven_escape");
        }
        char::from_u32(value).ok_or_else(|| failure("unproven_escape"))
    }

    fn parse_number(&mut self) -> Result<Json, LedgerSchemaError> {
        let negative = if self.peek_byte() == Some(b'-') {
            self.index += 1;
            true
        } else {
            false
        };
        let digits_at = self.index;
        let Some(first) = self.peek_byte() else {
            return fail("json_invalid");
        };
        if !first.is_ascii_digit() {
            return fail("json_invalid");
        }
        if first == b'0' {
            self.index += 1;
        } else {
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        if matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            return fail("json_invalid");
        }
        if matches!(self.peek_byte(), Some(b'.' | b'e' | b'E')) {
            return fail("unproven_number");
        }
        let digits = &self.text[digits_at..self.index];
        match i64_digits(digits, negative) {
            Ok(value) => Ok(Json::Int(value)),
            Err(()) => fail("unproven_integer"),
        }
    }

    fn consume_literal(&mut self, word: &str, value: Json) -> Result<Json, LedgerSchemaError> {
        if !self.text[self.index..].starts_with(word) {
            return fail("json_invalid");
        }
        self.index += word.len();
        if matches!(
            self.peek_byte(),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
        ) {
            return fail("json_invalid");
        }
        Ok(value)
    }

    fn enter(&mut self) -> Result<(), LedgerSchemaError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return fail("unproven_depth");
        }
        Ok(())
    }

    fn expect(&mut self, byte: u8) -> Result<(), LedgerSchemaError> {
        if self.peek_byte() == Some(byte) {
            self.index += 1;
            Ok(())
        } else {
            fail("json_invalid")
        }
    }

    fn skip(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.index).copied()
    }

    fn bump_char(&mut self) -> Option<char> {
        let ch = self.text[self.index..].chars().next()?;
        self.index += ch.len_utf8();
        Some(ch)
    }
}

fn i64_digits(digits: &str, negative: bool) -> Result<i64, ()> {
    if digits.len() > 19 {
        return Err(());
    }
    let mut value: i128 = 0;
    for byte in digits.bytes() {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(i128::from(byte - b'0')))
            .ok_or(())?;
    }
    if negative {
        value = value.checked_neg().ok_or(())?;
    }
    i64::try_from(value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TEST: &str = "tests/test_seal.py::test_seal_schema_self_consistent";
    const VECTOR_IDS: [&str; 18] = [
        "schema_facts",
        "emit_path_omitted",
        "emit_path_and_genesis",
        "validate_emit_path_omitted",
        "validate_emit_path_and_genesis",
        "validate_missing_seq",
        "validate_additional_property",
        "validate_bad_const",
        "validate_bad_enum",
        "validate_tool_integer",
        "validate_bad_file_sha256",
        "validate_seq_zero",
        "validate_empty_verdict",
        "validate_bad_code_name",
        "validate_negative_code",
        "validate_empty_path",
        "validate_bool_seq",
        "validate_bad_prev",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("parity")
            .join("schemas")
            .join("sesslint.seal-ledger.v1")
    }

    fn read_text(name: &str) -> String {
        let bytes = fs::read(parity_dir().join(name)).unwrap_or_else(|err| panic!("{name}: {err}"));
        let text = std::str::from_utf8(&bytes).unwrap_or_else(|_| panic!("{name} is not utf-8"));
        assert_clean(text);
        assert!(text.ends_with('\n'), "{name} must end with LF");
        text.to_owned()
    }

    fn assert_clean(text: &str) {
        assert!(!text.contains('\r'), "CR");
        assert!(!text.contains("FOR_WORK"));
        assert!(!text.contains("sesslint-wt-"));
        let bytes = text.as_bytes();
        let mut offset = 0;
        while let Some(found) = text[offset..].find("sbp_") {
            let start = offset + found + 4;
            let hex = bytes[start..]
                .iter()
                .take_while(|byte| byte.is_ascii_hexdigit())
                .count();
            assert!(hex < 40, "contiguous sbp_ hash");
            offset = start;
        }
    }

    fn object(value: &Json) -> &[(String, Json)] {
        match value {
            Json::Object(items) => items,
            _ => panic!("not an object"),
        }
    }

    fn array(value: &Json) -> &[Json] {
        match value {
            Json::Array(items) => items,
            _ => panic!("not an array"),
        }
    }

    fn get<'a>(obj: &'a [(String, Json)], key: &str) -> &'a Json {
        object_get(obj, key).unwrap_or_else(|| panic!("missing {key}"))
    }

    fn string<'a>(obj: &'a [(String, Json)], key: &str) -> &'a str {
        match get(obj, key) {
            Json::String(text) => text.as_str(),
            _ => panic!("{key} is not a string"),
        }
    }

    fn int_value(value: &Json) -> i64 {
        match value {
            Json::Int(number) => *number,
            _ => panic!("not an int"),
        }
    }

    fn bool_value(obj: &[(String, Json)], key: &str) -> bool {
        match get(obj, key) {
            Json::Bool(value) => *value,
            _ => panic!("{key} is not a bool"),
        }
    }

    fn opt_string(value: &Json) -> Option<&str> {
        match value {
            Json::Null => None,
            Json::String(text) => Some(text.as_str()),
            _ => panic!("not a string or null"),
        }
    }

    fn string_list(value: &Json) -> Vec<&str> {
        array(value)
            .iter()
            .map(|item| match item {
                Json::String(text) => text.as_str(),
                _ => panic!("list item is not a string"),
            })
            .collect()
    }

    fn code_pairs(value: &Json) -> Vec<(&str, i64)> {
        array(value)
            .iter()
            .map(|item| {
                let parts = array(item);
                assert_eq!(parts.len(), 2);
                let name = match &parts[0] {
                    Json::String(text) => text.as_str(),
                    _ => panic!("code name"),
                };
                (name, int_value(&parts[1]))
            })
            .collect()
    }

    fn present_fields(path: bool, genesis: bool) -> Vec<&'static str> {
        EMIT_FIELD_ORDER
            .into_iter()
            .filter(|name| match *name {
                "path" => path,
                "genesis_of" => genesis,
                _ => true,
            })
            .collect()
    }

    #[test]
    fn empty_object_misses_schema() {
        let err = validate_json("{}").unwrap_err();
        assert_eq!(err.message(), "missing_required:schema");
    }

    #[test]
    fn parser_rejects_unproven_forms() {
        assert_eq!(validate_json("").unwrap_err().message(), "json_invalid");
        assert_eq!(validate_json("{").unwrap_err().message(), "json_invalid");
        assert_eq!(validate_json("01").unwrap_err().message(), "json_invalid");
        assert_eq!(
            validate_json("1.5").unwrap_err().message(),
            "unproven_number"
        );
        assert_eq!(
            validate_json("1e2").unwrap_err().message(),
            "unproven_number"
        );
        assert_eq!(
            validate_json("9223372036854775808").unwrap_err().message(),
            "unproven_integer"
        );
        assert_eq!(
            validate_json("-9223372036854775809").unwrap_err().message(),
            "unproven_integer"
        );
        assert_eq!(
            validate_json("9223372036854775807").unwrap_err().message(),
            "type_mismatch:$"
        );
        assert_eq!(
            validate_json("{\"a\":1,\"a\":2}").unwrap_err().message(),
            "duplicate_key"
        );
        assert_eq!(
            parse_json("\"\\uD800\"").unwrap_err().message(),
            "unproven_escape"
        );
        let parsed = parse_json("\"\\u0041\\n\"").unwrap();
        assert_eq!(parsed, Json::String("A\n".to_owned()));
    }

    #[test]
    fn deep_object_is_refused() {
        let mut text = String::new();
        for _ in 0..33 {
            text.push_str("{\"a\":");
        }
        text.push('1');
        for _ in 0..33 {
            text.push('}');
        }
        assert_eq!(
            validate_json(&text).unwrap_err().message(),
            "unproven_depth"
        );
    }

    #[test]
    fn codec_seam_sentence_is_kept() {
        let err = CanonicalError::Unsupported(
            "sesslint._canonical_codec.canonical_json_bytes is not available",
        );
        assert_eq!(
            codec_failure(err).message(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
    }

    #[test]
    fn emit_refuses_unknown_tool_before_bytes() {
        let err = emit_entry(EmitInput {
            seq: 1,
            prev_sha256: GENESIS,
            file_sha256: &"a".repeat(64),
            path: None,
            tool: "scan",
            verdict: "healthy",
            codes: &[],
            report_sha256: &"b".repeat(64),
            genesis_of: None,
            sealed_at: "2026-01-01T00:00:00Z",
        })
        .unwrap_err();
        assert_eq!(err.message(), "enum_mismatch:tool");
    }

    #[test]
    fn pinned_vectors_match_schema_and_bytes() {
        let vector_text = read_text("vectors.json");
        let vector_bytes = vector_text.as_bytes();
        let manifest_text = read_text("manifest.json");
        let manifest_json = parse_json(&manifest_text).unwrap();
        let manifest = object(&manifest_json);
        assert_eq!(string(manifest, "python_commit"), PIN);
        assert_eq!(string(manifest, "module"), "sesslint.seal");
        assert_eq!(
            string(manifest, "vectors_sha256"),
            crate::seal::sha256_bytes(vector_bytes)
        );
        assert_eq!(
            int_value(get(manifest, "vector_count")),
            i64::try_from(VECTOR_IDS.len()).unwrap()
        );

        let vector_json = parse_json(&vector_text).unwrap();
        let root = object(&vector_json);
        assert_eq!(string(root, "python_commit"), PIN);
        assert_eq!(
            string(root, "schema_sha256"),
            string(manifest, "schema_sha256")
        );
        let vectors = array(get(root, "vectors"));
        assert_eq!(vectors.len(), VECTOR_IDS.len());
        for (item, id) in vectors.iter().zip(VECTOR_IDS) {
            let row = object(item);
            assert_eq!(string(row, "id"), id);
            let construct = object(get(row, "construct"));
            let expected = object(get(row, "expected"));
            match string(construct, "type") {
                "schema_facts" => check_facts(expected),
                "emit" => check_emit(construct, expected),
                "validate" => check_validate(construct, expected),
                other => panic!("unknown vector type {other}"),
            }
        }
    }

    fn check_facts(expected: &[(String, Json)]) {
        assert_eq!(string(expected, "draft"), DRAFT);
        assert_eq!(string(expected, "id"), SCHEMA_DOCUMENT_ID);
        assert_eq!(string(expected, "root_type"), "object");
        assert!(!bool_value(expected, "additional_properties"));
        assert_eq!(string_list(get(expected, "required")), REQUIRED);
        assert_eq!(string_list(get(expected, "properties")), PROPERTIES);
        assert_eq!(string(expected, "schema_const"), SCHEMA_CONST);
        assert_eq!(string(expected, "seal_schema_id"), SCHEMA_CONST);
        assert_eq!(string(expected, "genesis"), GENESIS);
        assert_eq!(string_list(get(expected, "tool_enum")), TOOLS);
        assert_eq!(int_value(get(expected, "seq_minimum")), SEQ_MINIMUM);
        assert_eq!(string(expected, "seq_type"), "integer");
        assert_eq!(string(expected, "code_name_pattern"), CODE_NAME_PATTERN);
        assert_eq!(int_value(get(expected, "code_minimum")), CODE_MINIMUM);
        assert_eq!(string(expected, "code_value_type"), "integer");
        assert_eq!(
            int_value(get(expected, "path_min_length")),
            i64::try_from(TEXT_MIN_LENGTH).unwrap()
        );
        assert_eq!(
            int_value(get(expected, "verdict_min_length")),
            i64::try_from(TEXT_MIN_LENGTH).unwrap()
        );
        let patterns = object(get(expected, "patterns"));
        assert_eq!(string(patterns, "prev_sha256"), PREV_SHA256_PATTERN);
        assert_eq!(string(patterns, "file_sha256"), HEX64_PATTERN);
        assert_eq!(string(patterns, "report_sha256"), HEX64_PATTERN);
        assert_eq!(string(patterns, "sealed_at"), SEALED_AT_PATTERN);
        assert_eq!(string(patterns, "genesis_of"), HEX64_PATTERN);
        assert_eq!(string(patterns, "entry_sha256"), HEX64_PATTERN);
        assert!(REQUIRED.iter().all(|name| PROPERTIES.contains(name)));
    }

    fn check_emit(construct: &[(String, Json)], expected: &[(String, Json)]) {
        let codes = code_pairs(get(construct, "codes"));
        let path = opt_string(get(construct, "path"));
        let genesis = opt_string(get(construct, "genesis_of"));
        let emitted = emit_entry(EmitInput {
            seq: int_value(get(construct, "seq")),
            prev_sha256: string(construct, "prev_sha256"),
            file_sha256: string(construct, "file_sha256"),
            path,
            tool: string(construct, "tool"),
            verdict: string(construct, "verdict"),
            codes: &codes,
            report_sha256: string(construct, "report_sha256"),
            genesis_of: genesis,
            sealed_at: string(construct, "sealed_at"),
        })
        .unwrap_or_else(|err| panic!("{}", err.message()));
        assert_eq!(string(expected, "mode"), "ok");
        assert_eq!(emitted.entry_sha256, string(expected, "entry_sha256"));
        assert_eq!(
            emitted.object_bytes,
            string(expected, "object_utf8").as_bytes()
        );
        assert_eq!(emitted.line_bytes, string(expected, "line_utf8").as_bytes());
        assert_eq!(
            string_list(get(expected, "keys")),
            present_fields(path.is_some(), genesis.is_some())
        );
        assert!(bool_value(expected, "required_subset_of_entry"));
        assert!(bool_value(expected, "entry_subset_of_properties"));
        let text = std::str::from_utf8(&emitted.object_bytes).unwrap();
        validate_json(text).unwrap();
    }

    fn check_validate(construct: &[(String, Json)], expected: &[(String, Json)]) {
        let result = validate_json(string(construct, "document"));
        match get(expected, "reason") {
            Json::Null => {
                assert_eq!(string(expected, "mode"), "ok");
                assert_eq!(string(construct, "mode"), "ok");
                result.unwrap();
            }
            Json::String(text) => {
                assert_eq!(string(expected, "mode"), "reject");
                assert_eq!(string(construct, "mode"), "reject");
                assert_eq!(result.unwrap_err().message(), text);
            }
            _ => panic!("reason is not null or string"),
        }
    }

    #[test]
    fn schema_test_is_not_claimed_covered() {
        let coverage_text = read_text("coverage.json");
        let coverage_json = parse_json(&coverage_text).unwrap();
        let coverage = object(&coverage_json);
        assert_eq!(string(coverage, "python_commit"), PIN);
        assert_eq!(int_value(get(coverage, "covered_count")), 0);
        assert_eq!(int_value(get(coverage, "not_applicable_count")), 1);
        let rows = array(get(coverage, "rows"));
        assert_eq!(rows.len(), 1);
        let row = object(&rows[0]);
        assert_eq!(string(row, "test"), SCHEMA_TEST);
        assert_eq!(string(row, "status"), "not_applicable");
        assert!(matches!(get(row, "vector_id"), Json::Null));
        assert!(!string(row, "note").is_empty());
        let vector_text = read_text("vectors.json");
        let vector_json = parse_json(&vector_text).unwrap();
        let vectors = array(get(object(&vector_json), "vectors"));
        for item in vectors {
            let construct = object(get(object(item), "construct"));
            let function = string(construct, "fn");
            assert_ne!(
                (function, string(construct, "mode")),
                ("load_seal_schema", "ok"),
                "a load_seal_schema success vector would not be the whole test"
            );
        }
    }

    #[test]
    fn provenance_is_synthetic() {
        let provenance_text = read_text("PROVENANCE.json");
        let provenance_json = parse_json(&provenance_text).unwrap();
        let provenance = object(&provenance_json);
        assert!(!bool_value(provenance, "contains_real_data"));
        assert_eq!(string(provenance, "origin"), "synthetic");
        assert_eq!(string(provenance, "python_commit"), PIN);
        let gaps = array(get(provenance, "known_parity_gaps"));
        assert_eq!(gaps.len(), 4);
    }
}
