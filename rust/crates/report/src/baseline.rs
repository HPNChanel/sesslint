//! Baseline fingerprint store (FR-046).
//!
//! Port of `src/sesslint/baseline.py` at
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! v1 files list raw finding fingerprints. v2 files list path-normalized keys.
//! Loading returns one set; a finding is suppressed when its v1 fingerprint or
//! its unambiguous v2 key is in that set. `--write-baseline` emits v2.
//! `upgrade_baseline` rewrites v1: fingerprints reproduced by the supplied
//! findings become verified v2 keys, and the rest stay `migrated: "unverified"`
//! so they still match on the v1 leg.
//!
//! Missing, unreadable, and malformed baselines fail closed. A v2 key shared by
//! two distinct findings matches neither. Canonical evidence that cannot be
//! serialized the way `canonical_json_bytes` would is refused, not guessed.
//!
//! The on-disk document is `json.dumps(..., indent=2, sort_keys=True)` plus a
//! trailing newline. The reader is `json.loads`. Both are hand-written. The v2
//! preimage uses the compact canonical codec (`sort_keys`, separators `( ",",
//! ":" )`, `ensure_ascii=False`, no trailing newline) and SHA-256.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use model::finding::{
    canonical_evidence_for_fingerprint, DictValue, Evidence, EvidenceLookup, Finding,
};
use sha2::{Digest, Sha256};

/// Python: `BASELINE_SCHEMA_VERSION`.
pub const BASELINE_SCHEMA_VERSION: &str = "sesslint.baseline/v1";

/// Python: `BASELINE_SCHEMA_VERSION_V2`.
pub const BASELINE_SCHEMA_VERSION_V2: &str = "sesslint.baseline/v2";

/// Python default for `created_by` on `dump_baseline`, `write_baseline`, and
/// `upgrade_baseline`. Rust has no default arguments; pass this to match.
pub const DEFAULT_CREATED_BY: &str = "sesslint";

const CANON_FAILED: &str = "canonical serialization of baseline evidence failed";

/// `evidence_to_dict` replaces anything past this depth with `None`. Hashing
/// that stand-in would not match Python, so the key is refused.
const MAX_CANON_DEPTH: usize = 32;

/// Recursive JSON reader limit. Baseline documents are a few levels deep.
/// Deeper input fails closed instead of growing the stack.
const MAX_JSON_DEPTH: u32 = 64;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Raised when a baseline file is missing, unreadable, or malformed, or when
/// a v2 key or an atomic write cannot be completed safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineError {
    message: String,
}

impl BaselineError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The error text. This is the Python exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for BaselineError {}

fn canon_failed() -> BaselineError {
    BaselineError::new(CANON_FAILED)
}

/// Portable file identity for v2 keys: `parent-basename/basename`.
///
/// Virtual `<...>` paths are returned unchanged. Absolute spellings (a leading
/// `/`, or a `:` in the second character) are not joined to the working
/// directory. Anything else is joined lexically to the current directory, with
/// no filesystem access. `.` and `..` collapse lexically. The result is the
/// immediate parent basename plus the basename.
///
/// Returns [`BaselineError`] when a relative path needs the working directory
/// and that directory cannot be read as Unicode.
pub fn file_role(path_str: &str) -> Result<String, BaselineError> {
    if path_str.starts_with('<') {
        return Ok(path_str.to_owned());
    }
    let mut norm = path_str.replace('\\', "/");
    if !is_rooted(&norm) {
        let cwd = working_directory()?;
        norm = format!("{cwd}/{norm}");
    }
    let mut collapsed: Vec<&str> = Vec::new();
    for segment in norm.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            if !collapsed.is_empty() {
                collapsed.pop();
            }
            continue;
        }
        collapsed.push(segment);
    }
    if collapsed.is_empty() {
        return Ok(norm.trim_end_matches('/').to_owned());
    }
    let basename = collapsed[collapsed.len() - 1];
    if collapsed.len() >= 2 {
        let parent = collapsed[collapsed.len() - 2];
        Ok(format!("{parent}/{basename}"))
    } else {
        Ok(basename.to_owned())
    }
}

fn is_rooted(norm: &str) -> bool {
    let mut chars = norm.chars();
    match chars.next() {
        Some('/') => true,
        Some(_) => chars.next() == Some(':'),
        None => false,
    }
}

fn working_directory() -> Result<String, BaselineError> {
    let cwd = std::env::current_dir().map_err(|err| {
        BaselineError::new(format!(
            "Cannot resolve the working directory for a relative file role: {err}"
        ))
    })?;
    match cwd.to_str() {
        Some(text) => Ok(text.replace('\\', "/")),
        None => Err(BaselineError::new(
            "Cannot resolve the working directory for a relative file role: path is not Unicode",
        )),
    }
}

/// Path-normalized baseline key (`sesslint.baseline/v2`).
///
/// Preimage, in order: code, file role, line, non-negative `record_ordinal`
/// (absent when missing, boolean, or negative), record id, and the allowlisted
/// evidence subset from [`canonical_evidence_for_fingerprint`]. Adapter and
/// profile ids are not included. The bytes are canonical JSON without a
/// trailing newline. The key is the first 16 lowercase hex digits of SHA-256.
pub fn compute_v2_key(finding: &Finding) -> Result<String, BaselineError> {
    let encoded = v2_preimage(finding)?;
    Ok(sha256_prefix16(&encoded))
}

fn v2_preimage(finding: &Finding) -> Result<Vec<u8>, BaselineError> {
    let role = file_role(finding.source().path())?;
    let ordinal = fingerprint_ordinal(finding.evidence());
    let subset = canonical_evidence_for_fingerprint(finding.evidence());
    let projected = projected_evidence(finding);
    let mut fields = Vec::with_capacity(subset.len());
    for (key, evidence) in subset {
        let Some(value) = last_projected(&projected, &key) else {
            return Err(canon_failed());
        };
        fields.push((key, encode_evidence(&evidence, value, 0)?));
    }
    let preimage = Canon::Arr(vec![
        Canon::Str(finding.code().to_owned()),
        Canon::Str(role),
        match finding.source().line() {
            Some(line) => Canon::Int(line),
            None => Canon::Null,
        },
        match ordinal {
            Some(value) => Canon::Int(value),
            None => Canon::Null,
        },
        match finding.source().record_id() {
            Some(record_id) => Canon::Str(record_id.to_owned()),
            None => Canon::Null,
        },
        Canon::Obj(fields),
    ]);
    let mut out = Vec::new();
    emit(&mut out, preimage);
    Ok(out)
}

fn fingerprint_ordinal(evidence: Option<&Evidence>) -> Option<i64> {
    let evidence = evidence?;
    match evidence.map_string("record_ordinal") {
        EvidenceLookup::Present(value) => value.as_int().filter(|ordinal| *ordinal >= 0),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap | EvidenceLookup::Borrowed => None,
    }
}

fn projected_evidence(finding: &Finding) -> Vec<(String, DictValue)> {
    for (key, value) in finding.to_dict() {
        if key == "evidence" {
            if let DictValue::Map(entries) = value {
                return entries;
            }
        }
    }
    Vec::new()
}

fn last_projected<'a>(entries: &'a [(String, DictValue)], key: &str) -> Option<&'a DictValue> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn encode_evidence(
    value: &Evidence,
    projected: &DictValue,
    depth: usize,
) -> Result<Canon, BaselineError> {
    if depth > MAX_CANON_DEPTH {
        return Err(canon_failed());
    }
    if let Some(text) = value.as_str() {
        return match projected {
            DictValue::Str(got) if got == text => Ok(Canon::Str(text.to_owned())),
            _ => Err(canon_failed()),
        };
    }
    if let Some(number) = value.as_int() {
        return match projected {
            DictValue::Int(got) if *got == number => Ok(Canon::Int(number)),
            _ => Err(canon_failed()),
        };
    }
    if let Some(flag) = value.as_bool() {
        return match projected {
            DictValue::Bool(got) if *got == flag => Ok(Canon::Bool(flag)),
            _ => Err(canon_failed()),
        };
    }
    if value.is_map() {
        return encode_map(value, projected, depth);
    }
    if value == &Evidence::none_value() {
        return match projected {
            DictValue::None => Ok(Canon::Null),
            _ => Err(canon_failed()),
        };
    }
    if value == &Evidence::ignored() {
        return Err(canon_failed());
    }
    match projected {
        DictValue::List(items) | DictValue::Tuple(items) => encode_seq(items, depth),
        DictValue::Set(_)
        | DictValue::FrozenSet(_)
        | DictValue::Bytes(_)
        | DictValue::Map(_)
        | DictValue::Str(_)
        | DictValue::Int(_)
        | DictValue::Bool(_)
        | DictValue::None => Err(canon_failed()),
    }
}

fn encode_map(
    value: &Evidence,
    projected: &DictValue,
    depth: usize,
) -> Result<Canon, BaselineError> {
    let DictValue::Map(entries) = projected else {
        return Err(canon_failed());
    };
    let mut folded: BTreeMap<&str, &DictValue> = BTreeMap::new();
    for (key, child) in entries {
        folded.insert(key.as_str(), child);
    }
    let mut fields = Vec::with_capacity(folded.len());
    for (key, child) in folded {
        let child_evidence = match value.map_string(key) {
            EvidenceLookup::Present(found) => found,
            EvidenceLookup::Absent | EvidenceLookup::NotAMap | EvidenceLookup::Borrowed => {
                return Err(canon_failed());
            }
        };
        fields.push((
            key.to_owned(),
            encode_evidence(&child_evidence, child, depth + 1)?,
        ));
    }
    Ok(Canon::Obj(fields))
}

fn encode_seq(items: &[DictValue], depth: usize) -> Result<Canon, BaselineError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(encode_projected(item, depth + 1)?);
    }
    Ok(Canon::Arr(out))
}

fn encode_projected(value: &DictValue, depth: usize) -> Result<Canon, BaselineError> {
    if depth > MAX_CANON_DEPTH {
        return Err(canon_failed());
    }
    match value {
        DictValue::Str(text) => Ok(Canon::Str(text.clone())),
        DictValue::Int(number) => Ok(Canon::Int(*number)),
        DictValue::Bool(flag) => Ok(Canon::Bool(*flag)),
        DictValue::None => Ok(Canon::Null),
        DictValue::List(items) | DictValue::Tuple(items) => encode_seq(items, depth),
        DictValue::Map(entries) => encode_projected_map(entries, depth),
        DictValue::Set(_) | DictValue::FrozenSet(_) | DictValue::Bytes(_) => Err(canon_failed()),
    }
}

fn encode_projected_map(
    entries: &[(String, DictValue)],
    depth: usize,
) -> Result<Canon, BaselineError> {
    let mut folded: BTreeMap<&str, &DictValue> = BTreeMap::new();
    for (key, child) in entries {
        folded.insert(key.as_str(), child);
    }
    let mut fields = Vec::with_capacity(folded.len());
    for (key, child) in folded {
        fields.push((key.to_owned(), encode_projected(child, depth + 1)?));
    }
    Ok(Canon::Obj(fields))
}

enum Canon {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Canon>),
    Obj(Vec<(String, Canon)>),
}

fn emit(out: &mut Vec<u8>, value: Canon) {
    match value {
        Canon::Null => out.extend_from_slice(b"null"),
        Canon::Bool(true) => out.extend_from_slice(b"true"),
        Canon::Bool(false) => out.extend_from_slice(b"false"),
        Canon::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Canon::Str(text) => push_canonical_string(out, &text),
        Canon::Arr(items) => {
            out.push(b'[');
            for (index, item) in items.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                emit(out, item);
            }
            out.push(b']');
        }
        Canon::Obj(mut fields) => {
            fields.sort_by(|left, right| left.0.cmp(&right.0));
            out.push(b'{');
            for (index, (key, child)) in fields.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                push_canonical_string(out, &key);
                out.push(b':');
                emit(out, child);
            }
            out.push(b'}');
        }
    }
}

/// `json.dumps(..., ensure_ascii=False)` string escapes, then raw UTF-8.
fn push_canonical_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{000c}' => out.extend_from_slice(br#"\f"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            other if (other as u32) < 0x20 => push_canonical_control(out, other as u8),
            other => {
                let mut buffer = [0u8; 4];
                let encoded = other.encode_utf8(&mut buffer);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn push_canonical_control(out: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(b"\\u00");
    out.push(HEX[usize::from(byte >> 4)]);
    out.push(HEX[usize::from(byte & 0x0f)]);
}

fn sha256_prefix16(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// 16 lowercase hex digits. The check walks the raw bytes.
fn is_fingerprint(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 16 {
        return false;
    }
    for byte in bytes {
        match byte {
            b'0'..=b'9' | b'a'..=b'f' => {}
            _ => return false,
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonText {
    Owned(String),
    /// Lone surrogates, which Python `str` can hold and Rust `String` cannot.
    Units(Vec<u32>),
}

impl JsonText {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Owned(text) => Some(text.as_str()),
            Self::Units(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Big(String),
    Float(String),
    String(JsonText),
    Array(Vec<Json>),
    Object(Vec<(JsonText, Json)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JsonError {
    message: String,
}

impl JsonError {
    fn at(text: &str, byte_index: usize, message: &str) -> Self {
        let (line, column, char_index) = line_column(text, byte_index);
        Self {
            message: format!("{message}: line {line} column {column} (char {char_index})"),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for JsonError {}

fn line_column(text: &str, byte_index: usize) -> (usize, usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let mut chars = 0usize;
    let mut seen = 0usize;
    for ch in text.chars() {
        if seen >= byte_index {
            break;
        }
        seen += ch.len_utf8();
        chars += 1;
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column, chars)
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
    depth: u32,
}

fn parse_json(text: &str) -> Result<Json, JsonError> {
    if text.starts_with('\u{feff}') {
        return Err(JsonError::at(
            text,
            0,
            "Unexpected UTF-8 BOM (decode using utf-8-sig)",
        ));
    }
    let mut parser = Parser {
        text,
        index: 0,
        depth: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.text.len() {
        return Err(parser.error_here("Extra data"));
    }
    Ok(value)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.text[self.index..].chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.index += ch.len_utf8();
        }
    }

    fn error_here(&self, message: &str) -> JsonError {
        JsonError::at(self.text, self.index, message)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump();
        }
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_JSON_DEPTH {
            return Err(self.error_here("JSON nesting depth exceeded"));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, JsonError> {
        self.skip_ws();
        match self.peek() {
            None => Err(self.error_here("Expecting value")),
            Some('n') => self.parse_literal("null", Json::Null),
            Some('t') => self.parse_literal("true", Json::Bool(true)),
            Some('f') => self.parse_literal("false", Json::Bool(false)),
            Some('"') => Ok(Json::String(self.parse_string()?)),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-' | '0'..='9') => self.parse_number(),
            Some(_) => Err(self.error_here("Expecting value")),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, JsonError> {
        if self.text[self.index..].starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.error_here("Expecting value"))
        }
    }

    fn parse_array(&mut self) -> Result<Json, JsonError> {
        self.bump();
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.bump();
            self.leave();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(']') => {
                    self.bump();
                    self.leave();
                    return Ok(Json::Array(items));
                }
                Some(',') => self.bump(),
                _ => return Err(self.error_here("Expecting ',' delimiter")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, JsonError> {
        self.bump();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some('}') {
            self.bump();
            self.leave();
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(self.error_here("Expecting property name enclosed in double quotes"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(':') {
                return Err(self.error_here("Expecting ':' delimiter"));
            }
            self.bump();
            let value = self.parse_value()?;
            if let Some((_, stored)) = entries
                .iter_mut()
                .find(|(existing, _)| texts_equal(existing, &key))
            {
                *stored = value;
            } else {
                entries.push((key, value));
            }
            self.skip_ws();
            match self.peek() {
                Some('}') => {
                    self.bump();
                    self.leave();
                    return Ok(Json::Object(entries));
                }
                Some(',') => self.bump(),
                _ => return Err(self.error_here("Expecting ',' delimiter")),
            }
        }
    }

    fn parse_number(&mut self) -> Result<Json, JsonError> {
        let start = self.index;
        let bytes = self.text.as_bytes();
        if bytes.get(self.index) == Some(&b'-') {
            self.index += 1;
        }
        if self.index >= bytes.len() || !bytes[self.index].is_ascii_digit() {
            return Err(JsonError::at(self.text, start, "Expecting value"));
        }
        if bytes[self.index] == b'0' {
            self.index += 1;
        } else {
            while self.index < bytes.len() && bytes[self.index].is_ascii_digit() {
                self.index += 1;
            }
        }
        let mut is_float = false;
        if self.index < bytes.len() && bytes[self.index] == b'.' {
            let next = self.index + 1;
            if next < bytes.len() && bytes[next].is_ascii_digit() {
                is_float = true;
                self.index = next + 1;
                while self.index < bytes.len() && bytes[self.index].is_ascii_digit() {
                    self.index += 1;
                }
            }
        }
        if self.index < bytes.len() && matches!(bytes[self.index], b'e' | b'E') {
            let mut probe = self.index + 1;
            if probe < bytes.len() && matches!(bytes[probe], b'+' | b'-') {
                probe += 1;
            }
            if probe < bytes.len() && bytes[probe].is_ascii_digit() {
                is_float = true;
                probe += 1;
                while probe < bytes.len() && bytes[probe].is_ascii_digit() {
                    probe += 1;
                }
                self.index = probe;
            }
        }
        let token = &self.text[start..self.index];
        if is_float {
            let value = match token.parse::<f64>() {
                Ok(value) => value,
                Err(_) => return Err(JsonError::at(self.text, start, "Expecting value")),
            };
            return Ok(Json::Float(float_repr(value)));
        }
        Ok(classify_int(token))
    }

    fn parse_string(&mut self) -> Result<JsonText, JsonError> {
        let start = self.index;
        self.bump();
        let mut units = Vec::new();
        let mut pending: Option<u32> = None;
        loop {
            let Some(ch) = self.peek() else {
                return Err(JsonError::at(
                    self.text,
                    start,
                    "Unterminated string starting at",
                ));
            };
            if ch == '"' {
                flush_pending(&mut units, &mut pending);
                self.bump();
                return Ok(finish_text(units));
            }
            if ch == '\\' {
                let slash = self.index;
                self.bump();
                let Some(esc) = self.peek() else {
                    return Err(JsonError::at(
                        self.text,
                        start,
                        "Unterminated string starting at",
                    ));
                };
                match esc {
                    '"' | '\\' | '/' => {
                        flush_pending(&mut units, &mut pending);
                        units.push(u32::from(esc));
                        self.bump();
                    }
                    'b' => push_unit(&mut units, &mut pending, 0x08, self),
                    'f' => push_unit(&mut units, &mut pending, 0x0c, self),
                    'n' => push_unit(&mut units, &mut pending, 0x0a, self),
                    'r' => push_unit(&mut units, &mut pending, 0x0d, self),
                    't' => push_unit(&mut units, &mut pending, 0x09, self),
                    'u' => {
                        let u_index = self.index;
                        self.bump();
                        let Some(code) = self.read_hex4() else {
                            return Err(JsonError::at(
                                self.text,
                                u_index,
                                "Invalid \\uXXXX escape",
                            ));
                        };
                        push_unicode(&mut units, &mut pending, code);
                    }
                    _ => {
                        return Err(JsonError::at(self.text, slash, "Invalid \\escape"));
                    }
                };
                continue;
            }
            if (ch as u32) < 0x20 {
                return Err(JsonError::at(
                    self.text,
                    self.index,
                    "Invalid control character at",
                ));
            }
            flush_pending(&mut units, &mut pending);
            units.push(u32::from(ch));
            self.bump();
        }
    }

    fn read_hex4(&mut self) -> Option<u32> {
        let bytes = self.text.as_bytes();
        if self.index + 4 > bytes.len() {
            return None;
        }
        let mut code = 0u32;
        for offset in 0..4 {
            let digit = match bytes[self.index + offset] {
                byte @ b'0'..=b'9' => u32::from(byte - b'0'),
                byte @ b'a'..=b'f' => u32::from(byte - b'a') + 10,
                byte @ b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return None,
            };
            code = (code << 4) | digit;
        }
        self.index += 4;
        Some(code)
    }
}

fn push_unit(units: &mut Vec<u32>, pending: &mut Option<u32>, code: u32, parser: &mut Parser<'_>) {
    flush_pending(units, pending);
    units.push(code);
    parser.bump();
}

fn flush_pending(units: &mut Vec<u32>, pending: &mut Option<u32>) {
    if let Some(high) = pending.take() {
        units.push(high);
    }
}

fn push_unicode(units: &mut Vec<u32>, pending: &mut Option<u32>, code: u32) {
    if (0xDC00..=0xDFFF).contains(&code) {
        if let Some(high) = pending.take() {
            let combined = 0x1_0000 + (((high - 0xD800) << 10) | (code - 0xDC00));
            units.push(combined);
            return;
        }
        units.push(code);
        return;
    }
    if let Some(high) = pending.take() {
        units.push(high);
    }
    if (0xD800..=0xDBFF).contains(&code) {
        *pending = Some(code);
    } else {
        units.push(code);
    }
}

fn finish_text(units: Vec<u32>) -> JsonText {
    let mut owned = String::new();
    for unit in &units {
        match char::from_u32(*unit) {
            Some(ch) => owned.push(ch),
            None => return JsonText::Units(units),
        }
    }
    JsonText::Owned(owned)
}

fn texts_equal(left: &JsonText, right: &JsonText) -> bool {
    match (left, right) {
        (JsonText::Owned(left), JsonText::Owned(right)) => left == right,
        (JsonText::Units(left), JsonText::Units(right)) => left == right,
        _ => false,
    }
}

fn classify_int(token: &str) -> Json {
    let digits = token.strip_prefix('-').unwrap_or(token);
    if !digits.is_empty() && digits.bytes().all(|byte| byte == b'0') {
        return Json::Int(0);
    }
    match parse_i64_token(token) {
        Some(value) => Json::Int(value),
        None => Json::Big(token.to_owned()),
    }
}

fn parse_i64_token(token: &str) -> Option<i64> {
    let (negative, digits) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let digit = i64::from(byte - b'0');
        value = if negative {
            value.checked_mul(10)?.checked_sub(digit)?
        } else {
            value.checked_mul(10)?.checked_add(digit)?
        };
    }
    Some(value)
}

fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_owned()
        } else {
            "0.0".to_owned()
        };
    }
    let text = value.to_string();
    if text.contains('.') || text.contains('e') || text.contains('E') {
        text.replace('E', "e")
    } else {
        format!("{text}.0")
    }
}

fn python_repr(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(number) => number.to_string(),
        Json::Big(token) | Json::Float(token) => token.clone(),
        Json::String(text) => python_text_repr(text),
        Json::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&python_repr(item));
            }
            out.push(']');
            out
        }
        Json::Object(entries) => {
            let mut out = String::from("{");
            for (index, (key, child)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&python_text_repr(key));
                out.push_str(": ");
                out.push_str(&python_repr(child));
            }
            out.push('}');
            out
        }
    }
}

fn python_text_repr(text: &JsonText) -> String {
    match text {
        JsonText::Owned(value) => python_str_repr(value),
        JsonText::Units(units) => python_units_repr(units),
    }
}

fn python_str_repr(text: &str) -> String {
    let has_single = text.contains('\'');
    let has_double = text.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        push_python_char(&mut out, ch, quote);
    }
    out.push(quote);
    out
}

fn python_units_repr(units: &[u32]) -> String {
    let mut has_single = false;
    let mut has_double = false;
    for unit in units {
        if let Some(ch) = char::from_u32(*unit) {
            if ch == '\'' {
                has_single = true;
            } else if ch == '"' {
                has_double = true;
            }
        }
    }
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for unit in units {
        match char::from_u32(*unit) {
            Some(ch) => push_python_char(&mut out, ch, quote),
            None => {
                out.push_str("\\u");
                push_hex4(&mut out, *unit);
            }
        }
    }
    out.push(quote);
    out
}

fn push_python_char(out: &mut String, ch: char, quote: char) {
    match ch {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        other if other == quote => {
            out.push('\\');
            out.push(quote);
        }
        other if (other as u32) < 0x20 || other == '\u{7f}' => {
            out.push_str(&format!("\\x{:02x}", other as u32));
        }
        other => out.push(other),
    }
}

fn push_hex4(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for shift in [12, 8, 4, 0] {
        let nibble = ((code >> shift) & 0xF) as usize;
        out.push(char::from(HEX[nibble]));
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn read_baseline_json(path: &Path) -> Result<Json, BaselineError> {
    if !path.is_file() {
        return Err(BaselineError::new(format!(
            "Baseline file not found: {}",
            path_text(path)
        )));
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(BaselineError::new(format!(
                "Cannot read baseline file {}: {err}",
                path_text(path)
            )));
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(err) => {
            return Err(BaselineError::new(format!(
                "Cannot read baseline file {}: {}",
                path_text(path),
                utf8_message(&bytes, &err)
            )));
        }
    };
    match parse_json(text) {
        Ok(value) => Ok(value),
        Err(err) => Err(BaselineError::new(format!(
            "Cannot read baseline file {}: {err}",
            path_text(path)
        ))),
    }
}

fn utf8_message(bytes: &[u8], err: &std::str::Utf8Error) -> String {
    let pos = err.valid_up_to();
    let byte = bytes.get(pos).copied().unwrap_or(0);
    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {pos}: invalid start byte")
}

fn expect_object<'a>(
    path: &Path,
    value: &'a Json,
) -> Result<&'a [(JsonText, Json)], BaselineError> {
    match value {
        Json::Object(entries) => Ok(entries),
        _ => Err(BaselineError::new(format!(
            "Baseline file {} must contain a JSON object",
            path_text(path)
        ))),
    }
}

fn lookup<'a>(entries: &'a [(JsonText, Json)], key: &str) -> Option<&'a Json> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn _load_v1(path: &Path, raw: &[(JsonText, Json)]) -> Result<BTreeSet<String>, BaselineError> {
    let fingerprints = match lookup(raw, "fingerprints") {
        Some(Json::Array(items)) => items,
        _ => {
            return Err(BaselineError::new(format!(
                "Baseline file {} must contain a 'fingerprints' list",
                path_text(path)
            )));
        }
    };
    let mut keys = BTreeSet::new();
    for (idx, item) in fingerprints.iter().enumerate() {
        match item {
            Json::String(text) if text.as_str().is_some_and(is_fingerprint) => {
                if let Some(fp) = text.as_str() {
                    keys.insert(fp.to_owned());
                }
            }
            _ => {
                return Err(BaselineError::new(format!(
                    "Baseline file {} fingerprints[{idx}] must be a 16-hex string, got {}",
                    path_text(path),
                    python_repr(item)
                )));
            }
        }
    }
    Ok(keys)
}

fn _load_v2(path: &Path, raw: &[(JsonText, Json)]) -> Result<BTreeSet<String>, BaselineError> {
    let entries = match lookup(raw, "entries") {
        Some(Json::Array(items)) => items,
        _ => {
            return Err(BaselineError::new(format!(
                "Baseline file {} must contain an 'entries' list",
                path_text(path)
            )));
        }
    };
    let mut keys = BTreeSet::new();
    for (idx, entry) in entries.iter().enumerate() {
        let Json::Object(fields) = entry else {
            return Err(BaselineError::new(format!(
                "Baseline file {} entries[{idx}] must be an object, got {}",
                path_text(path),
                python_repr(entry)
            )));
        };
        let key = lookup(fields, "key");
        match key {
            Some(Json::String(text)) if text.as_str().is_some_and(is_fingerprint) => {
                if let Some(fp) = text.as_str() {
                    keys.insert(fp.to_owned());
                }
            }
            Some(other) => {
                return Err(BaselineError::new(format!(
                    "Baseline file {} entries[{idx}].key must be a 16-hex string, got {}",
                    path_text(path),
                    python_repr(other)
                )));
            }
            None => {
                return Err(BaselineError::new(format!(
                    "Baseline file {} entries[{idx}].key must be a 16-hex string, got None",
                    path_text(path)
                )));
            }
        }
    }
    Ok(keys)
}

/// Load a v1 or v2 baseline file into a validated key set.
///
/// The set is the union of v1 fingerprints and v2 keys. Matching tries each
/// finding's v1 fingerprint and v2 key against it.
pub fn load_baseline(path: &Path) -> Result<BTreeSet<String>, BaselineError> {
    let value = read_baseline_json(path)?;
    let raw = expect_object(path, &value)?;
    match lookup(raw, "schema_version") {
        Some(Json::String(text)) if text.as_str() == Some(BASELINE_SCHEMA_VERSION) => {
            _load_v1(path, raw)
        }
        Some(Json::String(text)) if text.as_str() == Some(BASELINE_SCHEMA_VERSION_V2) => {
            _load_v2(path, raw)
        }
        _ => Err(BaselineError::new(format!(
            "Baseline file {} must declare schema_version '{BASELINE_SCHEMA_VERSION}' or '{BASELINE_SCHEMA_VERSION_V2}'",
            path_text(path)
        ))),
    }
}

enum Doc {
    String(String),
    Array(Vec<Doc>),
    Object(Vec<(String, Doc)>),
}

struct V2Entry {
    key: String,
    doc: Doc,
}

fn _v2_entry(finding: &Finding, created_by: &str) -> Result<V2Entry, BaselineError> {
    let key = compute_v2_key(finding)?;
    let role = file_role(finding.source().path())?;
    let doc = Doc::Object(vec![
        ("code".to_owned(), Doc::String(finding.code().to_owned())),
        ("created_by".to_owned(), Doc::String(created_by.to_owned())),
        ("file_role".to_owned(), Doc::String(role)),
        ("key".to_owned(), Doc::String(key.clone())),
    ]);
    Ok(V2Entry { key, doc })
}

/// Serialize findings as a deterministic v2 baseline document.
///
/// `created_by` has no default. Pass [`DEFAULT_CREATED_BY`] to match Python.
/// The first finding wins when two findings share a v2 key. Entries are sorted
/// by that key. The text ends with one LF.
pub fn dump_baseline<'a, I>(findings: I, created_by: &str) -> Result<String, BaselineError>
where
    I: IntoIterator<Item = &'a Finding>,
{
    let mut by_key: BTreeMap<String, Doc> = BTreeMap::new();
    for finding in findings {
        let entry = _v2_entry(finding, created_by)?;
        by_key.entry(entry.key).or_insert(entry.doc);
    }
    let entries: Vec<Doc> = by_key.into_values().collect();
    let doc = Doc::Object(vec![
        ("entries".to_owned(), Doc::Array(entries)),
        (
            "schema_version".to_owned(),
            Doc::String(BASELINE_SCHEMA_VERSION_V2.to_owned()),
        ),
    ]);
    Ok(format!("{}\n", dumps_indent2(&doc)))
}

/// Write findings as a v2 baseline file. Returns how many times `"key"` occurs
/// in the document, matching Python `str.count`.
pub fn write_baseline<'a, I>(
    path: &Path,
    findings: I,
    created_by: &str,
) -> Result<usize, BaselineError>
where
    I: IntoIterator<Item = &'a Finding>,
{
    let doc = dump_baseline(findings, created_by)?;
    atomic_write_text(path, &doc)?;
    Ok(doc.matches("\"key\"").count())
}

/// Return findings suppressed neither by v1 fingerprint nor by an unambiguous
/// v2 key.
///
/// A v2 key shared by two or more distinct findings (different v1 fingerprints)
/// is ambiguous and matches neither. Input order is preserved.
pub fn filter_findings<'a, I>(
    findings: I,
    baseline: &BTreeSet<String>,
) -> Result<Vec<&'a Finding>, BaselineError>
where
    I: IntoIterator<Item = &'a Finding>,
{
    let items: Vec<&Finding> = findings.into_iter().collect();
    let mut keys = Vec::with_capacity(items.len());
    for finding in &items {
        keys.push(compute_v2_key(finding)?);
    }
    let mut owners: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (key, finding) in keys.iter().zip(&items) {
        owners
            .entry(key.as_str())
            .or_default()
            .insert(finding.fingerprint());
    }
    let ambiguous: BTreeSet<&str> = owners
        .iter()
        .filter(|(_, fingerprints)| fingerprints.len() > 1)
        .map(|(key, _)| *key)
        .collect();
    let mut kept = Vec::new();
    for (key, finding) in keys.iter().zip(items) {
        let fingerprint_hit = baseline.contains(finding.fingerprint());
        let key_hit = baseline.contains(key);
        let key_ambiguous = ambiguous.contains(key.as_str());
        if !fingerprint_hit && (!key_hit || key_ambiguous) {
            kept.push(finding);
        }
    }
    Ok(kept)
}

/// Rewrite a v1 baseline as a v2 document.
///
/// `findings` reproduces a re-check of the source. An empty iterator matches
/// Python `None`: every fingerprint is `migrated: "unverified"`. A fingerprint
/// that reappears becomes a verified v2 key. Returns the document, the verified
/// count, and the unverified count.
///
/// The input must be `sesslint.baseline/v1`.
pub fn upgrade_baseline<'a, I>(
    baseline_path: &Path,
    findings: Option<I>,
    created_by: &str,
) -> Result<(String, usize, usize), BaselineError>
where
    I: IntoIterator<Item = &'a Finding>,
{
    let value = read_baseline_json(baseline_path)?;
    let raw = expect_object(baseline_path, &value)?;
    match lookup(raw, "schema_version") {
        Some(Json::String(text)) if text.as_str() == Some(BASELINE_SCHEMA_VERSION) => {}
        _ => {
            return Err(BaselineError::new(format!(
                "--upgrade requires a '{BASELINE_SCHEMA_VERSION}' baseline, got {}",
                path_text(baseline_path)
            )));
        }
    }
    let v1_fps = _load_v1(baseline_path, raw)?;
    let mut by_v1: BTreeMap<String, &Finding> = BTreeMap::new();
    if let Some(findings) = findings {
        for finding in findings {
            by_v1.insert(finding.fingerprint().to_owned(), finding);
        }
    }
    let mut entries = Vec::new();
    let mut verified = 0usize;
    for fingerprint in &v1_fps {
        if let Some(finding) = by_v1.get(fingerprint) {
            let mut entry = _v2_entry(finding, created_by)?;
            push_migrated(&mut entry.doc, "verified")?;
            entries.push(entry.doc);
            verified += 1;
        } else {
            entries.push(Doc::Object(vec![
                ("key".to_owned(), Doc::String(fingerprint.clone())),
                ("migrated".to_owned(), Doc::String("unverified".to_owned())),
            ]));
        }
    }
    let unverified = entries.len() - verified;
    let doc = Doc::Object(vec![
        ("entries".to_owned(), Doc::Array(entries)),
        (
            "schema_version".to_owned(),
            Doc::String(BASELINE_SCHEMA_VERSION_V2.to_owned()),
        ),
    ]);
    Ok((format!("{}\n", dumps_indent2(&doc)), verified, unverified))
}

fn push_migrated(doc: &mut Doc, state: &str) -> Result<(), BaselineError> {
    let Doc::Object(fields) = doc else {
        return Err(canon_failed());
    };
    fields.push(("migrated".to_owned(), Doc::String(state.to_owned())));
    Ok(())
}

/// `json.dumps(value, indent=2, sort_keys=True)` with default `ensure_ascii=True`.
fn dumps_indent2(value: &Doc) -> String {
    let mut out = String::new();
    write_doc(&mut out, value, 0);
    out
}

fn write_doc(out: &mut String, value: &Doc, indent: usize) {
    match value {
        Doc::String(text) => push_json_string(out, text),
        Doc::Array(items) => write_array(out, items, indent),
        Doc::Object(pairs) => write_object(out, pairs, indent),
    }
}

fn write_array(out: &mut String, items: &[Doc], indent: usize) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    let inner = indent.saturating_add(2);
    for (index, item) in items.iter().enumerate() {
        out.push('\n');
        push_spaces(out, inner);
        write_doc(out, item, inner);
        if index + 1 != items.len() {
            out.push(',');
        }
    }
    out.push('\n');
    push_spaces(out, indent);
    out.push(']');
}

fn write_object(out: &mut String, pairs: &[(String, Doc)], indent: usize) {
    if pairs.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    out.push('{');
    let inner = indent.saturating_add(2);
    for (index, pair_index) in order.iter().enumerate() {
        let (key, nested) = &pairs[*pair_index];
        out.push('\n');
        push_spaces(out, inner);
        push_json_string(out, key);
        out.push_str(": ");
        write_doc(out, nested, inner);
        if index + 1 != order.len() {
            out.push(',');
        }
    }
    out.push('\n');
    push_spaces(out, indent);
    out.push('}');
}

fn push_spaces(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push(' ');
    }
}

/// `json.dumps` string with `ensure_ascii=True`.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => {
                let code = u32::from(other);
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(other);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    out.push_str("\\u");
    push_hex4(out, code);
}

fn atomic_write_text(dest: &Path, text: &str) -> Result<(), BaselineError> {
    let parent = parent_dir(dest);
    ensure_directory(&parent)?;
    let (mut file, temp) = match create_temp(&parent) {
        Ok(opened) => opened,
        Err(err) => return Err(wrap_atomic(dest, err)),
    };
    if let Err(err) = file.write_all(text.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(wrap_atomic(dest, err));
    }
    if let Err(err) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(wrap_atomic(dest, err));
    }
    drop(file);
    if let Err(err) = fs::rename(&temp, dest) {
        let _ = fs::remove_file(&temp);
        return Err(wrap_atomic(dest, err));
    }
    Ok(())
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn ensure_directory(path: &Path) -> Result<(), BaselineError> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(BaselineError::new(format!(
            "Destination parent path is not a directory: {}",
            path_text(path)
        ))),
        Err(_) => Err(BaselineError::new(format!(
            "Destination directory does not exist: {}",
            path_text(path)
        ))),
    }
}

fn create_temp(parent: &Path) -> io::Result<(File, PathBuf)> {
    let pid = std::process::id();
    for _ in 0..10_000 {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".sesslint_tmp_{pid}_{seq}"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "exhausted temporary names",
    ))
}

fn wrap_atomic(dest: &Path, err: io::Error) -> BaselineError {
    BaselineError::new(format!(
        "Atomic write to '{}' failed: {err}",
        path_text(dest)
    ))
}

#[cfg(test)]
mod tests {
    use super::compute_v2_key;
    use super::{
        dump_baseline, file_role, filter_findings, load_baseline, parse_json, python_repr,
        upgrade_baseline, write_baseline, BASELINE_SCHEMA_VERSION, BASELINE_SCHEMA_VERSION_V2,
        CANON_FAILED, DEFAULT_CREATED_BY,
    };
    use model::codes::{Repairability, Severity};
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("sesslint-baseline-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source(path: &str, line: Option<i64>, record_id: Option<&str>) -> SourceRef {
        SourceRef::try_new(path, line.map(SourceLine::Int), record_id).unwrap()
    }

    fn finding(
        path: &str,
        line: Option<i64>,
        record_id: Option<&str>,
        fingerprint: &str,
        evidence: PyValue,
    ) -> Finding {
        Finding::try_new(FindingInput {
            code: PyValue::string("SL001"),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source(path, line, record_id)),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }

    fn plain(path: &str, fingerprint: &str) -> Finding {
        finding(path, None, None, fingerprint, PyValue::None)
    }

    #[test]
    fn file_role_normalizes_spelling() {
        assert_eq!(
            file_role(r"C:\work\proj\sess\run.jsonl").unwrap(),
            "sess/run.jsonl"
        );
        assert_eq!(file_role("sess/run.jsonl").unwrap(), "sess/run.jsonl");
        assert_eq!(file_role("./sess/run.jsonl").unwrap(), "sess/run.jsonl");
        assert_eq!(
            file_role("/abs/anywhere/sess/run.jsonl").unwrap(),
            "sess/run.jsonl"
        );
        assert_eq!(file_role("<stdin>").unwrap(), "<stdin>");
        assert_eq!(file_role("<stdin>/extra").unwrap(), "<stdin>/extra");
        assert_eq!(
            file_role("//server/share/run.jsonl").unwrap(),
            "share/run.jsonl"
        );
        assert_eq!(file_role("/").unwrap(), "");
        assert_eq!(file_role("/..").unwrap(), "/..");
        assert_eq!(file_role("C:/foo").unwrap(), "C:/foo");
        assert_eq!(file_role("C:run.jsonl").unwrap(), "C:run.jsonl");
    }

    #[test]
    fn file_role_bare_name_uses_cwd() {
        let cwd = std::env::current_dir().unwrap();
        let cwd_text = cwd.to_str().unwrap().replace('\\', "/");
        let mut collapsed = Vec::new();
        for segment in format!("{cwd_text}/run.jsonl").split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".." {
                if !collapsed.is_empty() {
                    collapsed.pop();
                }
                continue;
            }
            collapsed.push(segment.to_owned());
        }
        let expected = format!(
            "{}/{}",
            collapsed[collapsed.len() - 2],
            collapsed[collapsed.len() - 1]
        );
        assert_eq!(file_role("run.jsonl").unwrap(), expected);
        assert_eq!(file_role("../sess/run.jsonl").unwrap(), "sess/run.jsonl");
    }

    #[test]
    fn v2_key_matches_python_goldens() {
        let plain = plain("C:/deep/checkout/sess/run.jsonl", "0123456789abcdef");
        assert_eq!(compute_v2_key(&plain).unwrap(), "a035df28f53dcf3f");
        assert_eq!(
            compute_v2_key(&plain).unwrap(),
            compute_v2_key(&finding(
                "sess/run.jsonl",
                None,
                None,
                "fedcba9876543210",
                PyValue::None
            ))
            .unwrap()
        );

        let rich = finding(
            "sess/run.jsonl",
            Some(3),
            Some("rec-1"),
            "0123456789abcdef",
            PyValue::map(vec![
                (PyValue::string("record_ordinal"), PyValue::int(4)),
                (
                    PyValue::string("event_ids"),
                    PyValue::list(vec![PyValue::string("e-b"), PyValue::string("e-a")]),
                ),
                (PyValue::string("count"), PyValue::int(2)),
                (PyValue::string("note"), PyValue::string("skip")),
            ]),
        );
        assert_eq!(compute_v2_key(&rich).unwrap(), "f2010f0dc440ac90");

        let unicode = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "fedcba9876543210",
            PyValue::map(vec![
                (PyValue::string("reason"), PyValue::string("caf\u{00e9}")),
                (PyValue::string("variant"), PyValue::string("a\"b\\c")),
            ]),
        );
        assert_eq!(compute_v2_key(&unicode).unwrap(), "cd708af3284c3635");

        let nested = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(
                PyValue::string("differing_fields"),
                PyValue::map(vec![
                    (PyValue::string("z"), PyValue::int(1)),
                    (PyValue::string("a"), PyValue::string("q")),
                ]),
            )]),
        );
        assert_eq!(compute_v2_key(&nested).unwrap(), "b9df0b810ca17654");
    }

    #[test]
    fn ordinal_slot_follows_python_int_rules() {
        let bool_ord = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(
                PyValue::string("record_ordinal"),
                PyValue::bool_value(true),
            )]),
        );
        assert_eq!(compute_v2_key(&bool_ord).unwrap(), "5cd6c34109480bf0");
        let false_ord = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(
                PyValue::string("record_ordinal"),
                PyValue::bool_value(false),
            )]),
        );
        assert_eq!(compute_v2_key(&false_ord).unwrap(), "3d244b1cd3251a7b");
        let negative = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(PyValue::string("record_ordinal"), PyValue::int(-1))]),
        );
        assert_eq!(compute_v2_key(&negative).unwrap(), "46df75197e1b6d4b");
        let zero = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(PyValue::string("record_ordinal"), PyValue::int(0))]),
        );
        assert_eq!(compute_v2_key(&zero).unwrap(), "f3c8cc5dca22259a");
        let last_wins = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![
                (PyValue::string("record_ordinal"), PyValue::int(1)),
                (PyValue::string("record_ordinal"), PyValue::int(2)),
            ]),
        );
        assert_eq!(compute_v2_key(&last_wins).unwrap(), "d8ead83bc7de036b");
    }

    #[test]
    fn parent_rename_changes_the_v2_key() {
        let left = plain("dirA/run.jsonl", "0123456789abcdef");
        let right = plain("dirB/run.jsonl", "0123456789abcdef");
        assert_ne!(
            compute_v2_key(&left).unwrap(),
            compute_v2_key(&right).unwrap()
        );
    }

    #[test]
    fn non_json_evidence_fails_closed() {
        let set_value = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(
                PyValue::string("event_ids"),
                PyValue::set(vec![PyValue::string("a")]),
            )]),
        );
        assert_eq!(
            compute_v2_key(&set_value).unwrap_err().to_string(),
            CANON_FAILED
        );
        let ignored = finding(
            "C:/deep/checkout/sess/run.jsonl",
            None,
            None,
            "0123456789abcdef",
            PyValue::map(vec![(
                PyValue::string("variant"),
                PyValue::severity(Severity::Error),
            )]),
        );
        assert_eq!(
            compute_v2_key(&ignored).unwrap_err().to_string(),
            CANON_FAILED
        );
    }

    #[test]
    fn dump_matches_python_bytes_and_sorts_keys() {
        let rich = finding(
            "sess/run.jsonl",
            Some(3),
            Some("rec-1"),
            "0123456789abcdef",
            PyValue::map(vec![
                (PyValue::string("record_ordinal"), PyValue::int(4)),
                (
                    PyValue::string("event_ids"),
                    PyValue::list(vec![PyValue::string("e-b"), PyValue::string("e-a")]),
                ),
                (PyValue::string("count"), PyValue::int(2)),
                (PyValue::string("note"), PyValue::string("skip")),
            ]),
        );
        let plain_finding = plain("C:/deep/checkout/sess/run.jsonl", "fedcba9876543210");
        let doc = dump_baseline([&rich, &plain_finding], DEFAULT_CREATED_BY).unwrap();
        assert_eq!(
            doc,
            "{\n  \"entries\": [\n    {\n      \"code\": \"SL001\",\n      \"created_by\": \"sesslint\",\n      \"file_role\": \"sess/run.jsonl\",\n      \"key\": \"a035df28f53dcf3f\"\n    },\n    {\n      \"code\": \"SL001\",\n      \"created_by\": \"sesslint\",\n      \"file_role\": \"sess/run.jsonl\",\n      \"key\": \"f2010f0dc440ac90\"\n    }\n  ],\n  \"schema_version\": \"sesslint.baseline/v2\"\n}\n"
        );
        assert!(!doc.contains('\r'));
        assert_eq!(doc.matches("\"key\"").count(), 2);

        let again = plain("sess/run.jsonl", "0011223344556677");
        let deduped = dump_baseline([&plain_finding, &again], DEFAULT_CREATED_BY).unwrap();
        assert_eq!(deduped.matches("\"key\"").count(), 1);

        let escaped = dump_baseline([&plain_finding], "caf\u{00e9}").unwrap();
        assert!(escaped.contains("\\u00e9"));
        assert!(!escaped.contains('\u{00e9}'));
    }

    #[test]
    fn write_round_trip_replaces_and_leaves_no_temp() {
        let scratch = Scratch::new("write");
        let path = scratch.join("base.json");
        let finding = plain("C:/deep/checkout/sess/run.jsonl", "0123456789abcdef");
        let count = write_baseline(&path, [&finding], DEFAULT_CREATED_BY).unwrap();
        assert_eq!(count, 1);
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.contains(&b'\r'));
        let keys = load_baseline(&path).unwrap();
        assert_eq!(keys, BTreeSet::from(["a035df28f53dcf3f".to_owned()]));
        let other = plain("dirB/run.jsonl", "fedcba9876543210");
        write_baseline(&path, [&other], DEFAULT_CREATED_BY).unwrap();
        let loaded = load_baseline(&path).unwrap();
        assert!(!loaded.contains("a035df28f53dcf3f"));
        assert_eq!(loaded.len(), 1);
        let leftovers: Vec<_> = fs::read_dir(scratch.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".sesslint_tmp_"))
            .collect();
        assert!(leftovers.is_empty());

        let missing = scratch.join("missing").join("base.json");
        let err = write_baseline(&missing, [&finding], DEFAULT_CREATED_BY).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn load_accepts_v1_and_v2_and_fails_closed() {
        let scratch = Scratch::new("load");
        let v1 = scratch.join("v1.json");
        fs::write(
            &v1,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[\"5d4465190d6abf3f\",\"aabbccddeeff0011\"]}",
        )
        .unwrap();
        assert_eq!(
            load_baseline(&v1).unwrap(),
            BTreeSet::from(["5d4465190d6abf3f".to_owned(), "aabbccddeeff0011".to_owned()])
        );

        let dup = scratch.join("dup.json");
        fs::write(
            &dup,
            "{\"schema_version\":\"nope\",\"fingerprints\":[],\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[\"0123456789abcdef\",\"0123456789abcdef\"]}",
        )
        .unwrap();
        assert_eq!(
            load_baseline(&dup).unwrap(),
            BTreeSet::from(["0123456789abcdef".to_owned()])
        );

        let missing = scratch.join("nope.json");
        let err = load_baseline(&missing).unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("nope.json"));

        let bad = scratch.join("bad.json");
        fs::write(
            &bad,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[\"nope\"]}",
        )
        .unwrap();
        let err = load_baseline(&bad).unwrap_err().to_string();
        assert!(err.contains("fingerprints[0] must be a 16-hex string, got 'nope'"));

        let upper = scratch.join("upper.json");
        fs::write(
            &upper,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[\"0123456789ABCDEF\"]}",
        )
        .unwrap();
        assert!(load_baseline(&upper)
            .unwrap_err()
            .to_string()
            .contains("got '0123456789ABCDEF'"));

        let types = scratch.join("types.json");
        fs::write(
            &types,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[true,-0,1e309]}",
        )
        .unwrap();
        let err = load_baseline(&types).unwrap_err().to_string();
        assert!(err.contains("got True"));

        let inf = scratch.join("inf.json");
        fs::write(
            &inf,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[1e309]}",
        )
        .unwrap();
        assert!(load_baseline(&inf)
            .unwrap_err()
            .to_string()
            .contains("got inf"));

        let zero = scratch.join("zero.json");
        fs::write(
            &zero,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[-0]}",
        )
        .unwrap();
        assert!(load_baseline(&zero)
            .unwrap_err()
            .to_string()
            .contains("got 0"));

        let not_list = scratch.join("obj.json");
        fs::write(
            &not_list,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":{}}",
        )
        .unwrap();
        assert!(load_baseline(&not_list)
            .unwrap_err()
            .to_string()
            .contains("must contain a 'fingerprints' list"));

        let v2 = scratch.join("v2.json");
        fs::write(
            &v2,
            "{\"schema_version\":\"sesslint.baseline/v2\",\"entries\":[{\"key\":\"nothex\"}]}",
        )
        .unwrap();
        assert!(load_baseline(&v2)
            .unwrap_err()
            .to_string()
            .contains("16-hex"));

        let entry = scratch.join("entry.json");
        fs::write(
            &entry,
            "{\"schema_version\":\"sesslint.baseline/v2\",\"entries\":[[]]}",
        )
        .unwrap();
        assert!(load_baseline(&entry)
            .unwrap_err()
            .to_string()
            .contains("entries[0] must be an object, got []"));

        let no_key = scratch.join("nokey.json");
        fs::write(
            &no_key,
            "{\"schema_version\":\"sesslint.baseline/v2\",\"entries\":[{}]}",
        )
        .unwrap();
        assert!(load_baseline(&no_key)
            .unwrap_err()
            .to_string()
            .contains("entries[0].key must be a 16-hex string, got None"));

        let schema = scratch.join("schema.json");
        fs::write(
            &schema,
            "{\"schema_version\":\"other/v9\",\"fingerprints\":[]}",
        )
        .unwrap();
        let err = load_baseline(&schema).unwrap_err().to_string();
        assert!(err.contains("'sesslint.baseline/v1'"));
        assert!(err.contains("'sesslint.baseline/v2'"));

        let array = scratch.join("array.json");
        fs::write(&array, "[]").unwrap();
        assert!(load_baseline(&array)
            .unwrap_err()
            .to_string()
            .contains("must contain a JSON object"));

        let broken = scratch.join("broken.json");
        fs::write(&broken, "{").unwrap();
        let err = load_baseline(&broken).unwrap_err().to_string();
        assert!(err.contains("Cannot read baseline file"));
        assert!(err.contains(
            "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"
        ));

        let bom = scratch.join("bom.json");
        fs::write(&bom, b"\xef\xbb\xbf{}").unwrap();
        assert!(load_baseline(&bom)
            .unwrap_err()
            .to_string()
            .contains("Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)"));

        let binary = scratch.join("bin.json");
        fs::write(&binary, [0xff]).unwrap();
        assert!(load_baseline(&binary)
            .unwrap_err()
            .to_string()
            .contains("0xff"));
        let _ = BASELINE_SCHEMA_VERSION;
        let _ = BASELINE_SCHEMA_VERSION_V2;
    }

    #[test]
    fn json_loads_messages_match_cpython() {
        assert_eq!(
            parse_json("").unwrap_err().to_string(),
            "Expecting value: line 1 column 1 (char 0)"
        );
        assert_eq!(
            parse_json("  \n  ").unwrap_err().to_string(),
            "Expecting value: line 2 column 3 (char 5)"
        );
        assert_eq!(
            parse_json("01").unwrap_err().to_string(),
            "Extra data: line 1 column 2 (char 1)"
        );
        assert_eq!(
            parse_json("\"a\\q\"").unwrap_err().to_string(),
            "Invalid \\escape: line 1 column 3 (char 2)"
        );
        assert_eq!(
            parse_json("\"\\u12\"").unwrap_err().to_string(),
            "Invalid \\uXXXX escape: line 1 column 3 (char 2)"
        );
        assert_eq!(
            parse_json("\"").unwrap_err().to_string(),
            "Unterminated string starting at: line 1 column 1 (char 0)"
        );
        assert_eq!(
            parse_json("\"\n\"").unwrap_err().to_string(),
            "Invalid control character at: line 1 column 2 (char 1)"
        );
        assert_eq!(
            parse_json("{\"a\" 1}").unwrap_err().to_string(),
            "Expecting ':' delimiter: line 1 column 6 (char 5)"
        );
        assert_eq!(
            parse_json("[1 2]").unwrap_err().to_string(),
            "Expecting ',' delimiter: line 1 column 4 (char 3)"
        );
        assert_eq!(
            parse_json("nul").unwrap_err().to_string(),
            "Expecting value: line 1 column 1 (char 0)"
        );
        assert_eq!(
            parse_json("truee").unwrap_err().to_string(),
            "Extra data: line 1 column 5 (char 4)"
        );
        assert_eq!(python_repr(&parse_json("1e2").unwrap()), "100.0");
        assert_eq!(python_repr(&parse_json("1e309").unwrap()), "inf");
        assert_eq!(python_repr(&parse_json("-0").unwrap()), "0");
        assert_eq!(
            python_repr(&parse_json("{\"a\":1,\"b\":2,\"a\":3}").unwrap()),
            "{'a': 3, 'b': 2}"
        );
        assert_eq!(
            python_repr(&parse_json("{\"ok\":true}").unwrap()),
            "{'ok': True}"
        );
        assert_eq!(
            python_repr(&parse_json("{\"ok\":null}").unwrap()),
            "{'ok': None}"
        );
        let deep = format!("{}null{}", "[".repeat(65), "]".repeat(65));
        assert!(parse_json(&deep)
            .unwrap_err()
            .to_string()
            .contains("JSON nesting depth exceeded"));
    }

    #[test]
    fn filter_suppresses_v1_and_unambiguous_v2_only() {
        let first = plain("sess/run.jsonl", "0123456789abcdef");
        let second = plain("sess/run.jsonl", "fedcba9876543210");
        let shared = compute_v2_key(&first).unwrap();
        assert_eq!(shared, compute_v2_key(&second).unwrap());
        let baseline = BTreeSet::from([shared.clone()]);
        let kept = filter_findings([&first, &second], &baseline).unwrap();
        assert_eq!(kept, vec![&first, &second]);
        assert!(filter_findings([&first], &baseline).unwrap().is_empty());

        let mut mixed = BTreeSet::from([shared]);
        mixed.insert(first.fingerprint().to_owned());
        let kept = filter_findings([&first, &second], &mixed).unwrap();
        assert_eq!(kept, vec![&second]);

        let other = plain("dirB/run.jsonl", "0011223344556677");
        let only_fp = BTreeSet::from([other.fingerprint().to_owned()]);
        let kept = filter_findings([&first, &other], &only_fp).unwrap();
        assert_eq!(kept, vec![&first]);

        let set_value = finding(
            "dirC/run.jsonl",
            None,
            None,
            "abcdef0123456789",
            PyValue::map(vec![(
                PyValue::string("event_ids"),
                PyValue::set(vec![PyValue::string("a")]),
            )]),
        );
        assert!(filter_findings([&first, &set_value], &BTreeSet::new()).is_err());
    }

    #[test]
    fn upgrade_matches_python_documents() {
        let scratch = Scratch::new("upgrade");
        let v1 = scratch.join("v1.json");
        fs::write(
            &v1,
            "{\"fingerprints\":[\"aabbccddeeff0011\",\"0123456789abcdef\"],\"schema_version\":\"sesslint.baseline/v1\"}",
        )
        .unwrap();
        let (text, verified, unverified) =
            upgrade_baseline(&v1, None::<[&Finding; 0]>, DEFAULT_CREATED_BY).unwrap();
        assert_eq!(verified, 0);
        assert_eq!(unverified, 2);
        assert_eq!(
            text,
            "{\n  \"entries\": [\n    {\n      \"key\": \"0123456789abcdef\",\n      \"migrated\": \"unverified\"\n    },\n    {\n      \"key\": \"aabbccddeeff0011\",\n      \"migrated\": \"unverified\"\n    }\n  ],\n  \"schema_version\": \"sesslint.baseline/v2\"\n}\n"
        );
        assert_eq!(
            upgrade_baseline(&v1, None::<[&Finding; 0]>, DEFAULT_CREATED_BY)
                .unwrap()
                .0,
            text
        );
        assert!(!text.contains('\r'));

        let reproduced = plain("C:/deep/checkout/sess/run.jsonl", "0123456789abcdef");
        let (verified_doc, verified, unverified) =
            upgrade_baseline(&v1, Some([&reproduced]), DEFAULT_CREATED_BY).unwrap();
        assert_eq!(verified, 1);
        assert_eq!(unverified, 1);
        assert_eq!(
            verified_doc,
            "{\n  \"entries\": [\n    {\n      \"code\": \"SL001\",\n      \"created_by\": \"sesslint\",\n      \"file_role\": \"sess/run.jsonl\",\n      \"key\": \"a035df28f53dcf3f\",\n      \"migrated\": \"verified\"\n    },\n    {\n      \"key\": \"aabbccddeeff0011\",\n      \"migrated\": \"unverified\"\n    }\n  ],\n  \"schema_version\": \"sesslint.baseline/v2\"\n}\n"
        );

        let empty = scratch.join("empty.json");
        fs::write(
            &empty,
            "{\"schema_version\":\"sesslint.baseline/v1\",\"fingerprints\":[]}",
        )
        .unwrap();
        let (empty_doc, verified, unverified) =
            upgrade_baseline(&empty, None::<[&Finding; 0]>, DEFAULT_CREATED_BY).unwrap();
        assert_eq!((verified, unverified), (0, 0));
        assert_eq!(
            empty_doc,
            "{\n  \"entries\": [],\n  \"schema_version\": \"sesslint.baseline/v2\"\n}\n"
        );

        let v2 = scratch.join("v2.json");
        write_baseline(&v2, [&reproduced], DEFAULT_CREATED_BY).unwrap();
        let err = upgrade_baseline(&v2, None::<[&Finding; 0]>, DEFAULT_CREATED_BY).unwrap_err();
        assert!(err.to_string().contains("requires"));
        assert!(err.to_string().contains("'sesslint.baseline/v1'"));

        let missing = scratch.join("missing.json");
        assert!(
            upgrade_baseline(&missing, None::<[&Finding; 0]>, DEFAULT_CREATED_BY)
                .unwrap_err()
                .to_string()
                .contains("not found")
        );
    }
}
