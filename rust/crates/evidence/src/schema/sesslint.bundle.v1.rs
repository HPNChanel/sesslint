//! JSON Schema `sesslint.bundle/v1`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! `schemas/sesslint.bundle.v1.json`.
//!
//! [`validate_json`] enforces that document: required names, `const`, `enum`,
//! `additionalProperties: false`, and the other assertions in the pin (`type`,
//! `minimum`, `pattern`, `minLength`, `maxLength`, `properties`, `items`,
//! `uniqueItems`, and `additionalProperties` subschemas). A keyword or comparison
//! this module cannot prove is rejected. Duplicate object keys are rejected.
//! JSON numbers are integers only when the token is a proven `i128`.
//!
//! This module does not emit canonical JSON and does not store session payload.
//! [`CANONICAL_JSON_SEAM`] is kept intact. Those bytes are not invented here.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.bundle.v1.json` bytes, including the trailing newline.
pub const BUNDLE_SCHEMA_JSON: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.bundle/v1",
  "title": "SessLint Support Bundle Format v1",
  "description": "Privacy-safe diagnostic bundle emitted by sesslint bundle: content-free report, detection confidences, and a synthetic fixture skeleton. Nested evidence objects are intentionally permissive; no raw session content is permitted anywhere (DW-T-09).",
  "type": "object",
  "required": [
    "bundle_version",
    "created_by",
    "detection",
    "fixture_skeleton",
    "report",
    "source"
  ],
  "properties": {
    "bundle_version": {
      "const": "sesslint.bundle/v1"
    },
    "created_by": {
      "type": "object",
      "required": [
        "adapters",
        "cli",
        "profiles",
        "schema_manifest",
        "schema_report",
        "schema_session",
        "tool",
        "version",
        "versions"
      ],
      "properties": {
        "tool": {
          "const": "sesslint"
        },
        "version": {
          "type": "string"
        },
        "cli": {
          "type": "string"
        },
        "schema_session": {
          "type": "string"
        },
        "schema_report": {
          "type": "string"
        },
        "schema_manifest": {
          "type": "string"
        },
        "adapters": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "profiles": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "versions": {
          "type": "object"
        }
      },
      "additionalProperties": false
    },
    "source": {
      "type": "object",
      "required": [
        "path",
        "sha256",
        "size"
      ],
      "properties": {
        "path": {
          "type": "string"
        },
        "sha256": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$"
        },
        "size": {
          "type": "integer",
          "minimum": 0
        }
      },
      "additionalProperties": false
    },
    "detection": {
      "type": "object",
      "required": [
        "confidences",
        "reason",
        "requested",
        "resolved"
      ],
      "properties": {
        "requested": {
          "type": "string"
        },
        "resolved": {
          "type": ["string", "null"]
        },
        "reason": {
          "type": "string"
        },
        "confidences": {
          "type": "object",
          "additionalProperties": {
            "type": "number"
          }
        }
      },
      "additionalProperties": false
    },
    "report": {
      "type": "object",
      "required": [
        "assurance",
        "counts",
        "coverage",
        "findings",
        "limitation",
        "schema_version",
        "session_id",
        "source_fingerprint",
        "tool_version"
      ],
      "properties": {
        "schema_version": {
          "type": "string"
        },
        "tool_version": {
          "type": "string"
        },
        "session_id": {
          "type": "string"
        },
        "source_fingerprint": {
          "type": "string"
        },
        "assurance": {
          "type": "string"
        },
        "limitation": {
          "type": "string"
        },
        "counts": {
          "type": "object",
          "required": [
            "by_code",
            "by_severity",
            "total"
          ],
          "properties": {
            "total": {
              "type": "integer",
              "minimum": 0
            },
            "by_code": {
              "type": "object",
              "additionalProperties": {
                "type": "integer",
                "minimum": 0
              }
            },
            "by_severity": {
              "type": "object",
              "additionalProperties": {
                "type": "integer",
                "minimum": 0
              }
            }
          },
          "additionalProperties": false
        },
        "coverage": {
          "type": "object"
        },
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "required": [
              "code",
              "fingerprint",
              "repairability",
              "severity",
              "span"
            ],
            "properties": {
              "code": {
                "type": "string"
              },
              "severity": {
                "type": "string"
              },
              "repairability": {
                "type": "string"
              },
              "fingerprint": {
                "type": "string"
              },
              "remediation": {
                "type": "string"
              },
              "message": {
                "type": "string"
              },
              "evidence": {
                "type": "object"
              },
              "span": {
                "type": "object",
                "required": [
                  "path"
                ],
                "properties": {
                  "path": {
                    "type": "string"
                  },
                  "line": {
                    "type": ["integer", "null"]
                  },
                  "byte": {
                    "type": ["integer", "null"]
                  }
                },
                "additionalProperties": false
              }
            },
            "additionalProperties": false
          }
        }
      },
      "additionalProperties": false
    },
    "fixture_skeleton": {
      "type": "object",
      "required": [
        "codes",
        "kinds",
        "record_count",
        "template"
      ],
      "properties": {
        "codes": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "kinds": {
          "type": "object",
          "additionalProperties": {
            "type": "integer",
            "minimum": 0
          }
        },
        "record_count": {
          "type": "integer",
          "minimum": 0
        },
        "template": {
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "share_advisory": {
      "type": "object",
      "description": "Optional pre-share advisory emitted when the bundled source produced SL009 findings (transcript-hygiene T-03). Content-free: family labels and counts only, never matched values. Absent (not null) when the source is clean.",
      "required": [
        "families",
        "finding_count",
        "kind",
        "note"
      ],
      "properties": {
        "kind": {
          "const": "secret-material-present"
        },
        "finding_count": {
          "type": "integer",
          "minimum": 1
        },
        "families": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "uniqueItems": true
        },
        "note": {
          "type": "string"
        }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
"#;

/// Codec seam. Canonical bundle bytes are not produced by this module.
pub const CANONICAL_JSON_SEAM: &str =
    "sesslint._canonical_codec.canonical_json_bytes is not available";

/// The only pattern the pin publishes. Any other pattern is unproven.
const HEX64_PATTERN: &str = "^[0-9a-f]{64}$";

const MAX_DEPTH: usize = 64;

/// Failure to parse JSON or to prove an instance against the pinned bundle schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax {
        /// Byte offset of the rejected token.
        byte: usize,
    },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        /// Schema keyword, or `unsupported` when the keyword cannot be proven.
        keyword: &'static str,
        /// JSON pointer of the instance node. Empty at the root.
        path: String,
        /// Required name or additional property name. Empty when the value is omitted.
        detail: String,
    },
}

impl fmt::Display for BundleSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(formatter, "bundle schema json syntax at byte {byte}")
            }
            Self::Reject {
                keyword,
                path,
                detail,
            } => {
                let at = if path.is_empty() {
                    "<root>"
                } else {
                    path.as_str()
                };
                if detail.is_empty() {
                    write!(formatter, "bundle schema {keyword} at {at}")
                } else {
                    write!(formatter, "bundle schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for BundleSchemaError {}

/// Structural JSON value. `PartialEq` compares parser structure, not JSON Schema equality.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    NonInteger,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Parse one JSON document and validate it against the pinned bundle schema.
///
/// # Errors
///
/// Returns a syntax failure or a schema rejection. Document text is not copied
/// into the error. Field names from the schema or the instance key may appear.
pub fn validate_json(input: &str) -> Result<(), BundleSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), BundleSchemaError> {
    let schema = match parse_json(BUNDLE_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, value, "")
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> BundleSchemaError {
    BundleSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, BundleSchemaError> {
    let mut parser = Parser {
        source: input,
        index: 0,
        depth: 0,
    };
    parser.skip_ws();
    if parser.done() {
        return Err(parser.syntax());
    }
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.done() {
        return Err(parser.syntax());
    }
    Ok(value)
}

struct Parser<'a> {
    source: &'a str,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn done(&self) -> bool {
        self.index >= self.source.len()
    }

    fn syntax(&self) -> BundleSchemaError {
        BundleSchemaError::Syntax { byte: self.index }
    }

    fn rest(&self) -> &'a str {
        self.source.get(self.index..).unwrap_or("")
    }

    fn peek_byte(&self) -> Option<u8> {
        self.rest().as_bytes().first().copied()
    }

    fn peek_char(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump_byte(&mut self) {
        if self.peek_byte().is_some() {
            self.index += 1;
        }
    }

    fn bump_char(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.index += ch.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump_byte();
        }
    }

    fn enter(&mut self) -> Result<(), BundleSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, BundleSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.syntax()),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, BundleSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, BundleSchemaError> {
        let start = self.index;
        if self.peek_byte() == Some(b'-') {
            self.bump_byte();
        }
        match self.peek_byte() {
            Some(b'0') => self.bump_byte(),
            Some(b'1'..=b'9') => {
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.bump_byte();
                }
            }
            _ => return Err(self.syntax()),
        }
        if self.peek_byte() == Some(b'.') {
            self.bump_byte();
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.bump_byte();
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.bump_byte();
            }
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        let Some(token) = self.source.get(start..self.index) else {
            return Err(self.syntax());
        };
        Ok(classify_number(token))
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.bump_byte();
        }
        self.index > start
    }

    fn parse_array(&mut self) -> Result<Json, BundleSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.bump_byte();
            self.exit();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b']') {
                        return Err(self.syntax());
                    }
                }
                Some(b']') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, BundleSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.bump_byte();
            self.exit();
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek_byte() != Some(b'"') {
                return Err(self.syntax());
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(name, _)| name == &key) {
                return Err(self.syntax());
            }
            self.skip_ws();
            if self.peek_byte() != Some(b':') {
                return Err(self.syntax());
            }
            self.bump_byte();
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b'}') {
                        return Err(self.syntax());
                    }
                }
                Some(b'}') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Object(entries));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, BundleSchemaError> {
        if self.peek_byte() != Some(b'"') {
            return Err(self.syntax());
        }
        self.bump_byte();
        let mut out = String::new();
        let mut pending_high: Option<u32> = None;
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax());
            };
            if ch == '"' {
                if pending_high.is_some() {
                    return Err(self.syntax());
                }
                self.bump_char();
                return Ok(out);
            }
            if ch == '\\' {
                self.push_escape(&mut out, &mut pending_high)?;
                continue;
            }
            if pending_high.is_some() || (ch as u32) < 0x20 {
                return Err(self.syntax());
            }
            self.bump_char();
            out.push(ch);
        }
    }

    fn push_escape(
        &mut self,
        out: &mut String,
        pending_high: &mut Option<u32>,
    ) -> Result<(), BundleSchemaError> {
        self.bump_char();
        let Some(esc) = self.peek_char() else {
            return Err(self.syntax());
        };
        self.bump_char();
        if esc == 'u' {
            let code = self.read_hex4()?;
            return self.push_unicode(out, pending_high, code);
        }
        if pending_high.is_some() {
            return Err(self.syntax());
        }
        let decoded = match esc {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{0008}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return Err(self.syntax()),
        };
        out.push(decoded);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, BundleSchemaError> {
        let mut code = 0_u32;
        for _ in 0..4 {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax());
            };
            let Some(digit) = ch.to_digit(16) else {
                return Err(self.syntax());
            };
            self.bump_char();
            code = (code << 4) | digit;
        }
        Ok(code)
    }

    fn push_unicode(
        &self,
        out: &mut String,
        pending_high: &mut Option<u32>,
        code: u32,
    ) -> Result<(), BundleSchemaError> {
        if let Some(high) = pending_high.take() {
            let Some(ch) = paired_surrogate(high, code) else {
                return Err(self.syntax());
            };
            out.push(ch);
            return Ok(());
        }
        if (0xD800..=0xDBFF).contains(&code) {
            *pending_high = Some(code);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(self.syntax());
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(self.syntax());
        };
        out.push(ch);
        Ok(())
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let point = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(point)
}

fn classify_number(token: &str) -> Json {
    match exact_i128(token) {
        Some(value) => Json::Int(value),
        None => Json::NonInteger,
    }
}

fn exact_i128(token: &str) -> Option<i128> {
    let (negative, body) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if body.is_empty() {
        return None;
    }
    let (mantissa, exponent) = split_exponent(body)?;
    let (whole, frac) = match mantissa.split_once('.') {
        Some((whole, frac)) => {
            if whole.is_empty() || frac.is_empty() {
                return None;
            }
            (whole, frac)
        }
        None => (mantissa, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let frac_len = i32::try_from(frac.len()).ok()?;
    let scale = exponent.checked_sub(frac_len)?;
    let magnitude = parse_i128_digits(whole, frac)?;
    let shifted = shift10(magnitude, scale)?;
    if negative {
        shifted.checked_neg()
    } else {
        Some(shifted)
    }
}

fn split_exponent(body: &str) -> Option<(&str, i32)> {
    let Some(index) = body.find(['e', 'E']) else {
        return Some((body, 0));
    };
    let mantissa = &body[..index];
    let mut exp = &body[index + 1..];
    if exp.is_empty() {
        return None;
    }
    let negative = if let Some(rest) = exp.strip_prefix('-') {
        exp = rest;
        true
    } else if let Some(rest) = exp.strip_prefix('+') {
        exp = rest;
        false
    } else {
        false
    };
    if exp.is_empty() || !exp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value: i32 = 0;
    for byte in exp.bytes() {
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    if negative {
        value = value.checked_neg()?;
    }
    Some((mantissa, value))
}

fn parse_i128_digits(whole: &str, frac: &str) -> Option<i128> {
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    let mut value: i128 = 0;
    for byte in whole.bytes().chain(frac.bytes()) {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(i128::from(byte - b'0'))?;
    }
    Some(value)
}

fn shift10(magnitude: i128, scale: i32) -> Option<i128> {
    if scale >= 0 {
        let mut value = magnitude;
        let steps = u32::try_from(scale).ok()?;
        for _ in 0..steps {
            value = value.checked_mul(10)?;
        }
        return Some(value);
    }
    let steps = u32::try_from(scale.checked_neg()?).ok()?;
    let mut divisor: i128 = 1;
    for _ in 0..steps {
        divisor = divisor.checked_mul(10)?;
    }
    if magnitude % divisor != 0 {
        return None;
    }
    Some(magnitude / divisor)
}

fn object_get<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    let Json::Object(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, item)| item)
}

fn is_annotation(key: &str) -> bool {
    matches!(
        key,
        "$schema"
            | "$id"
            | "$comment"
            | "title"
            | "description"
            | "default"
            | "examples"
            | "deprecated"
    )
}

fn is_known_keyword(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "const"
            | "enum"
            | "minLength"
            | "maxLength"
            | "pattern"
            | "minimum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "uniqueItems"
    )
}

fn check(schema: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Json::Object(entries) = schema else {
        return Err(reject("unsupported", path, "schema"));
    };
    for (key, _) in entries {
        if !is_annotation(key) && !is_known_keyword(key) {
            return Err(reject("unsupported", path, key));
        }
    }
    if let Some(spec) = object_get(schema, "type") {
        if !type_matches(spec, value, path)? {
            return Err(reject("type", path, ""));
        }
    }
    if let Some(expected) = object_get(schema, "const") {
        match json_equal(value, expected) {
            Some(true) => {}
            Some(false) => return Err(reject("const", path, "")),
            None => return Err(reject("unsupported", path, "const")),
        }
    }
    if let Some(choices) = object_get(schema, "enum") {
        check_enum(choices, value, path)?;
    }
    check_string(schema, value, path)?;
    check_minimum(schema, value, path)?;
    check_object(schema, value, path)?;
    check_array(schema, value, path)?;
    Ok(())
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, BundleSchemaError> {
    match spec {
        Json::String(name) => type_name_matches(name, value, path),
        Json::Array(items) => {
            for item in items {
                if type_matches(item, value, path)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(reject("unsupported", path, "type")),
    }
}

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, BundleSchemaError> {
    let matched = match name {
        "object" => matches!(value, Json::Object(_)),
        "array" => matches!(value, Json::Array(_)),
        "string" => matches!(value, Json::String(_)),
        "boolean" => matches!(value, Json::Bool(_)),
        "null" => matches!(value, Json::Null),
        "integer" => matches!(value, Json::Int(_)),
        "number" => matches!(value, Json::Int(_) | Json::NonInteger),
        _ => return Err(reject("unsupported", path, "type")),
    };
    Ok(matched)
}

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Json::Array(choices) = choices else {
        return Err(reject("unsupported", path, "enum"));
    };
    for choice in choices {
        match json_equal(value, choice) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => return Err(reject("unsupported", path, "enum")),
        }
    }
    Err(reject("enum", path, ""))
}

fn check_string(schema: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Json::String(text) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() < limit {
            return Err(reject("minLength", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() > limit {
            return Err(reject("maxLength", path, ""));
        }
    }
    if let Some(pattern) = object_get(schema, "pattern") {
        let Json::String(pattern) = pattern else {
            return Err(reject("unsupported", path, "pattern"));
        };
        match pattern_match(pattern) {
            Ok(engine) => {
                if !engine(text) {
                    return Err(reject("pattern", path, ""));
                }
            }
            Err(()) => return Err(reject("unsupported", path, "pattern")),
        }
    }
    Ok(())
}

fn pattern_match(pattern: &str) -> Result<fn(&str) -> bool, ()> {
    if pattern == HEX64_PATTERN {
        Ok(is_hex64)
    } else {
        Err(())
    }
}

fn is_hex64(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn length_bound(bound: &Json, path: &str) -> Result<usize, BundleSchemaError> {
    let Json::Int(value) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    if *value < 0 {
        return Err(reject("unsupported", path, "length"));
    }
    usize::try_from(*value).map_err(|_| reject("unsupported", path, "length"))
}

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Some(bound) = object_get(schema, "minimum") else {
        return Ok(());
    };
    match value {
        Json::Int(number) => {
            let Json::Int(limit) = bound else {
                return Err(reject("unsupported", path, "minimum"));
            };
            if number < limit {
                return Err(reject("minimum", path, ""));
            }
            Ok(())
        }
        Json::NonInteger => Err(reject("unsupported", path, "minimum")),
        _ => Ok(()),
    }
}

fn check_object(schema: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Json::Object(entries) = value else {
        return Ok(());
    };
    if let Some(required) = object_get(schema, "required") {
        let Json::Array(names) = required else {
            return Err(reject("unsupported", path, "required"));
        };
        for name in names {
            let Json::String(name) = name else {
                return Err(reject("unsupported", path, "required"));
            };
            if object_get(value, name).is_none() {
                return Err(reject("required", path, name));
            }
        }
    }
    if let Some(flag) = object_get(schema, "additionalProperties") {
        let allowed = property_names(schema, path)?;
        let unknown = unknown_keys(entries, &allowed);
        match flag {
            Json::Bool(false) => {
                if let Some(key) = unknown.first() {
                    return Err(reject("additionalProperties", path, key));
                }
            }
            Json::Bool(true) => {}
            Json::Object(_) => {
                for key in unknown {
                    let Some(child) = object_get(value, key) else {
                        return Err(reject("unsupported", path, "additionalProperties"));
                    };
                    check(flag, child, &pointer(path, key))?;
                }
            }
            _ => return Err(reject("unsupported", path, "additionalProperties")),
        }
    }
    if let Some(properties) = object_get(schema, "properties") {
        let Json::Object(properties) = properties else {
            return Err(reject("unsupported", path, "properties"));
        };
        for (name, sub) in properties {
            if let Some(child) = object_get(value, name) {
                check(sub, child, &pointer(path, name))?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, BundleSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn unknown_keys<'a>(entries: &'a [(String, Json)], allowed: &[&str]) -> Vec<&'a str> {
    let mut unknown: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str())
        .filter(|key| !allowed.iter().any(|name| name == key))
        .collect();
    unknown.sort_unstable();
    unknown
}

fn check_array(schema: &Json, value: &Json, path: &str) -> Result<(), BundleSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            check(item_schema, item, &pointer_index(path, index))?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(Json::Bool(false)) => Ok(()),
        Some(Json::Bool(true)) => unique_items(items, path),
        Some(_) => Err(reject("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[Json], path: &str) -> Result<(), BundleSchemaError> {
    for right in 1..items.len() {
        for left in 0..right {
            match json_equal(&items[left], &items[right]) {
                Some(true) => return Err(reject("uniqueItems", path, "")),
                Some(false) => {}
                None => return Err(reject("unsupported", path, "uniqueItems")),
            }
        }
    }
    Ok(())
}

fn json_equal(left: &Json, right: &Json) -> Option<bool> {
    match (left, right) {
        (Json::Null, Json::Null) => Some(true),
        (Json::Null, _) | (_, Json::Null) => Some(false),
        (Json::Bool(left), Json::Bool(right)) => Some(left == right),
        (Json::Bool(_), _) | (_, Json::Bool(_)) => Some(false),
        (Json::NonInteger, Json::NonInteger | Json::Int(_)) | (Json::Int(_), Json::NonInteger) => {
            None
        }
        (Json::NonInteger, _) | (_, Json::NonInteger) => Some(false),
        (Json::Int(left), Json::Int(right)) => Some(left == right),
        (Json::Int(_), _) | (_, Json::Int(_)) => Some(false),
        (Json::String(left), Json::String(right)) => Some(left == right),
        (Json::String(_), _) | (_, Json::String(_)) => Some(false),
        (Json::Array(left), Json::Array(right)) => array_equal(left, right),
        (Json::Array(_), _) | (_, Json::Array(_)) => Some(false),
        (Json::Object(left), Json::Object(right)) => object_equal(left, right),
    }
}

fn array_equal(left: &[Json], right: &[Json]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (left_item, right_item) in left.iter().zip(right.iter()) {
        if !json_equal(left_item, right_item)? {
            return Some(false);
        }
    }
    Some(true)
}

fn object_equal(left: &[(String, Json)], right: &[(String, Json)]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (key, value) in left {
        let Some((_, other)) = right.iter().find(|(name, _)| name == key) else {
            return Some(false);
        };
        if !json_equal(value, other)? {
            return Some(false);
        }
    }
    Some(true)
}

fn pointer(parent: &str, key: &str) -> String {
    let mut out = String::from(parent);
    out.push('/');
    for ch in key.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
    out
}

fn pointer_index(parent: &str, index: usize) -> String {
    format!("{parent}/{index}")
}

#[cfg(test)]
mod tests {
    use super::{
        check, classify_number, is_annotation, is_known_keyword, object_get, parse_json,
        pattern_match, validate_json, BundleSchemaError, Json, BUNDLE_SCHEMA_JSON,
        CANONICAL_JSON_SEAM, HEX64_PATTERN,
    };
    use codec::canonical_codec::CanonicalError;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: [&str; 6] = [
        "tests/test_plan_bundle_schemas.py::test_bundle_schema_loads_and_self_consistent",
        "tests/test_plan_bundle_schemas.py::test_bundle_dict_validates",
        "tests/test_plan_bundle_schemas.py::test_detection_failed_bundle_dict_validates",
        "tests/test_plan_bundle_schemas.py::test_bundle_json_round_trip_validates",
        "tests/test_plan_bundle_schemas.py::test_bundle_missing_section_fails_validation",
        "tests/test_plan_bundle_schemas.py::test_bundle_wrong_version_fails_validation",
    ];
    const FACT_KEYS: [&str; 33] = [
        "adapter_value_type",
        "additional_properties",
        "bundle_version_const",
        "by_code_minimum",
        "confidence_type",
        "counts_required",
        "created_by_required",
        "detection_required",
        "draft",
        "emitter_bundle_version",
        "emitter_keys",
        "families_unique_items",
        "finding_count_minimum",
        "finding_required",
        "id",
        "kind_count_minimum",
        "properties",
        "record_count_minimum",
        "report_required",
        "required",
        "resolved_type",
        "root_type",
        "sha256_pattern",
        "share_kind_const",
        "share_required",
        "size_minimum",
        "skeleton_required",
        "source_required",
        "span_byte_type",
        "span_line_type",
        "span_required",
        "tool_const",
        "total_minimum",
    ];
    const KNOWN_TYPES: [&str; 7] = [
        "array", "boolean", "integer", "null", "number", "object", "string",
    ];
    const NOT_WHOLE_TEST: [&str; 6] = [
        "load_bundle_schema",
        "get_bundle_schema_path",
        "build_bundle",
        "_validate_bundle_dict",
        "to_dict",
        "to_json",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("parity")
            .join("schemas")
            .join("sesslint.bundle.v1")
    }

    fn read_bytes(name: &str) -> Vec<u8> {
        fs::read(parity_dir().join(name)).unwrap_or_else(|err| panic!("{name}: {err}"))
    }

    fn read_text(name: &str) -> String {
        let bytes = read_bytes(name);
        let text = std::str::from_utf8(&bytes).unwrap_or_else(|_| panic!("{name} is not utf-8"));
        assert_clean(text, name);
        assert!(text.ends_with('\n'), "{name} must end with LF");
        text.to_owned()
    }

    fn assert_clean(text: &str, name: &str) {
        assert!(!text.contains('\r'), "{name} CR");
        assert!(!text.contains("FOR_WORK"), "{name}");
        assert!(!text.contains("sesslint-wt-"), "{name}");
        assert!(!text.contains("02694d5"), "{name}");
        let bytes = text.as_bytes();
        let mut offset = 0;
        while let Some(found) = text[offset..].find("sbp_") {
            let start = offset + found + 4;
            let hex = bytes
                .get(start..)
                .unwrap_or(&[])
                .iter()
                .take_while(|byte| byte.is_ascii_hexdigit())
                .count();
            assert!(hex < 40, "{name} contiguous sbp_ hash");
            offset = start;
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
        object_get(value, key).unwrap_or_else(|| panic!("missing {key}"))
    }

    fn as_str(value: &Json) -> &str {
        match value {
            Json::String(text) => text.as_str(),
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_bool(value: &Json) -> bool {
        match value {
            Json::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_int(value: &Json) -> i128 {
        match value {
            Json::Int(number) => *number,
            other => panic!("expected int, got {other:?}"),
        }
    }

    fn as_array(value: &Json) -> &[Json] {
        match value {
            Json::Array(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    fn string_list(value: &Json) -> Vec<String> {
        as_array(value)
            .iter()
            .map(|item| as_str(item).to_owned())
            .collect()
    }

    fn object_keys(value: &Json) -> Vec<String> {
        match value {
            Json::Object(entries) => entries.iter().map(|(key, _)| key.clone()).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }

    fn properties(schema: &Json) -> &Json {
        field(schema, "properties")
    }

    fn child<'a>(schema: &'a Json, name: &str) -> &'a Json {
        field(properties(schema), name)
    }

    #[test]
    fn empty_object_misses_bundle_version() {
        let err = validate_json("{}").unwrap_err();
        match err {
            BundleSchemaError::Reject {
                keyword,
                path,
                detail,
            } => {
                assert_eq!(keyword, "required");
                assert_eq!(path, "");
                assert_eq!(detail, "bundle_version");
            }
            other => panic!("expected required, got {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_unproven_forms() {
        assert!(parse_json("").is_err());
        assert!(parse_json("{").is_err());
        assert!(parse_json("01").is_err());
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("1e2"), Json::Int(100));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
        let mut text = String::new();
        for _ in 0..80 {
            text.push_str("{\"a\":");
        }
        text.push('1');
        for _ in 0..80 {
            text.push('}');
        }
        assert!(parse_json(&text).is_err());
    }

    #[test]
    fn keywords_fail_closed() {
        let format_schema = parse_json(r#"{"format":"date"}"#).unwrap();
        let err = check(&format_schema, &parse_json(r#""m""#).unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "format");
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
        let enum_schema = parse_json(r#"{"enum":["check","verify"]}"#).unwrap();
        check(&enum_schema, &parse_json(r#""check""#).unwrap(), "").unwrap();
        let err = check(&enum_schema, &parse_json(r#""scan""#).unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject { keyword, .. } => assert_eq!(keyword, "enum"),
            other => panic!("expected enum, got {other:?}"),
        }
        let const_schema = parse_json(r#"{"const":"sesslint"}"#).unwrap();
        let err = check(&const_schema, &parse_json("1").unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject { keyword, .. } => assert_eq!(keyword, "const"),
            other => panic!("expected const, got {other:?}"),
        }
        let err = check(&const_schema, &parse_json("1.5").unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject { keyword, .. } => assert_eq!(keyword, "const"),
            other => panic!("expected const, got {other:?}"),
        }
        let number_const = parse_json(r#"{"const":1}"#).unwrap();
        let err = check(&number_const, &parse_json("1.5").unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "const");
            }
            other => panic!("expected unproven const, got {other:?}"),
        }
        let unique = parse_json(r#"{"uniqueItems":true}"#).unwrap();
        let err = check(&unique, &parse_json("[1.5,1.5]").unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "uniqueItems");
            }
            other => panic!("expected unproven uniqueItems, got {other:?}"),
        }
        let map_schema = parse_json(
            r#"{"type":"object","additionalProperties":{"type":"integer","minimum":0}}"#,
        )
        .unwrap();
        check(&map_schema, &parse_json(r#"{"a":0,"b":2}"#).unwrap(), "").unwrap();
        let err = check(&map_schema, &parse_json(r#"{"a":-1}"#).unwrap(), "").unwrap_err();
        match err {
            BundleSchemaError::Reject {
                keyword,
                path,
                detail,
            } => {
                assert_eq!(keyword, "minimum");
                assert_eq!(path, "/a");
                assert_eq!(detail, "");
            }
            other => panic!("expected minimum, got {other:?}"),
        }
        assert!(pattern_match(HEX64_PATTERN).unwrap()(&"a".repeat(64)));
        assert!(!pattern_match(HEX64_PATTERN).unwrap()(&"A".repeat(64)));
        assert!(!pattern_match(HEX64_PATTERN).unwrap()(&"a".repeat(63)));
        assert!(pattern_match("^$").is_err());
    }

    #[test]
    fn canonical_json_seam_is_kept() {
        let err = CanonicalError::Unsupported(CANONICAL_JSON_SEAM);
        assert_eq!(err.message(), CANONICAL_JSON_SEAM);
        assert_eq!(
            CANONICAL_JSON_SEAM,
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
    }

    #[test]
    fn pinned_vectors_match_schema() {
        let vector_bytes = read_bytes("vectors.json");
        let vector_text = read_text("vectors.json");
        let manifest_text = read_text("manifest.json");
        let manifest = parse_json(&manifest_text).unwrap();
        assert_eq!(as_str(field(&manifest, "python_commit")), PIN);
        assert_eq!(as_str(field(&manifest, "module")), "sesslint.bundle");
        assert_eq!(
            as_str(field(&manifest, "schema_file")),
            "schemas/sesslint.bundle.v1.json"
        );
        assert_eq!(
            as_str(field(&manifest, "schema_sha256")),
            sha256_hex(BUNDLE_SCHEMA_JSON.as_bytes())
        );
        assert_eq!(
            as_str(field(&manifest, "vectors_sha256")),
            sha256_hex(&vector_bytes)
        );
        assert!(!BUNDLE_SCHEMA_JSON.contains('\r'));
        assert!(BUNDLE_SCHEMA_JSON.ends_with('\n'));
        assert!(BUNDLE_SCHEMA_JSON.starts_with('{'));

        let root = parse_json(&vector_text).unwrap();
        assert_eq!(as_str(field(&root, "python_commit")), PIN);
        assert_eq!(
            as_str(field(&root, "schema_sha256")),
            as_str(field(&manifest, "schema_sha256"))
        );
        let gaps = as_array(field(&root, "known_parity_gaps"));
        assert!(gaps
            .iter()
            .any(|item| as_str(item).contains(CANONICAL_JSON_SEAM)));
        let vectors = as_array(field(&root, "vectors"));
        assert_eq!(
            as_int(field(&manifest, "vector_count")),
            i128::try_from(vectors.len()).unwrap()
        );
        let mut ids = BTreeSet::new();
        for item in vectors {
            let id = as_str(field(item, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let construct = field(item, "construct");
            let expected = field(item, "expected");
            match as_str(field(construct, "type")) {
                "schema_facts" => {
                    assert_eq!(as_str(field(construct, "fn")), "schema_document");
                    assert_eq!(as_str(field(construct, "mode")), "pin");
                    check_facts(expected);
                }
                "validate" => {
                    assert_eq!(as_str(field(construct, "fn")), "validate_json");
                    assert!(!NOT_WHOLE_TEST.contains(&as_str(field(construct, "fn"))));
                    check_validate(id, construct, expected);
                }
                other => panic!("unknown vector type {other}"),
            }
        }
        for id in [
            "schema_facts",
            "validate_minimal",
            "validate_share_advisory",
            "validate_empty_object",
            "validate_bad_const",
            "validate_sha256_pattern",
            "validate_confidence_fraction",
            "validate_families_duplicate",
        ] {
            assert!(ids.contains(id), "missing {id}");
        }
    }

    fn check_facts(expected: &Json) {
        let schema = parse_json(BUNDLE_SCHEMA_JSON).unwrap();
        assert_proven(&schema);
        let mut keys = object_keys(expected);
        keys.sort_unstable();
        assert_eq!(keys, FACT_KEYS.map(str::to_owned).to_vec());
        assert_eq!(
            as_str(field(&schema, "$schema")),
            as_str(field(expected, "draft"))
        );
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(expected, "id")));
        assert_eq!(
            as_str(field(&schema, "type")),
            as_str(field(expected, "root_type"))
        );
        assert!(!as_bool(field(&schema, "additionalProperties")));
        assert!(!as_bool(field(expected, "additional_properties")));
        let required = string_list(field(&schema, "required"));
        let props = object_keys(properties(&schema));
        assert_eq!(required, string_list(field(expected, "required")));
        assert_eq!(props, string_list(field(expected, "properties")));
        assert!(required.iter().all(|name| props.contains(name)));
        assert_eq!(
            as_str(field(child(&schema, "bundle_version"), "const")),
            as_str(field(expected, "bundle_version_const"))
        );
        assert_eq!(
            as_str(field(expected, "emitter_bundle_version")),
            as_str(field(expected, "bundle_version_const"))
        );
        let mut emitter = string_list(field(expected, "emitter_keys"));
        let mut prop_names = props.clone();
        emitter.sort_unstable();
        prop_names.sort_unstable();
        assert_eq!(emitter, prop_names);
        let source = child(&schema, "source");
        assert_eq!(
            string_list(field(source, "required")),
            string_list(field(expected, "source_required"))
        );
        assert_eq!(
            as_str(field(child(source, "sha256"), "pattern")),
            HEX64_PATTERN
        );
        assert_eq!(as_str(field(expected, "sha256_pattern")), HEX64_PATTERN);
        assert_eq!(
            as_int(field(child(source, "size"), "minimum")),
            as_int(field(expected, "size_minimum"))
        );
        let created = child(&schema, "created_by");
        assert_eq!(
            string_list(field(created, "required")),
            string_list(field(expected, "created_by_required"))
        );
        assert_eq!(
            as_str(field(child(created, "tool"), "const")),
            as_str(field(expected, "tool_const"))
        );
        assert_eq!(
            as_str(field(
                field(child(created, "adapters"), "additionalProperties"),
                "type"
            )),
            as_str(field(expected, "adapter_value_type"))
        );
        let detection = child(&schema, "detection");
        assert_eq!(
            string_list(field(detection, "required")),
            string_list(field(expected, "detection_required"))
        );
        assert_eq!(
            string_list(field(child(detection, "resolved"), "type")),
            string_list(field(expected, "resolved_type"))
        );
        assert_eq!(
            as_str(field(
                field(child(detection, "confidences"), "additionalProperties"),
                "type"
            )),
            as_str(field(expected, "confidence_type"))
        );
        let report = child(&schema, "report");
        assert_eq!(
            string_list(field(report, "required")),
            string_list(field(expected, "report_required"))
        );
        let counts = child(report, "counts");
        assert_eq!(
            string_list(field(counts, "required")),
            string_list(field(expected, "counts_required"))
        );
        assert_eq!(
            as_int(field(child(counts, "total"), "minimum")),
            as_int(field(expected, "total_minimum"))
        );
        assert_eq!(
            as_int(field(
                field(child(counts, "by_code"), "additionalProperties"),
                "minimum"
            )),
            as_int(field(expected, "by_code_minimum"))
        );
        let finding = field(child(report, "findings"), "items");
        assert_eq!(
            string_list(field(finding, "required")),
            string_list(field(expected, "finding_required"))
        );
        let span = child(finding, "span");
        assert_eq!(
            string_list(field(span, "required")),
            string_list(field(expected, "span_required"))
        );
        assert_eq!(
            string_list(field(child(span, "line"), "type")),
            string_list(field(expected, "span_line_type"))
        );
        assert_eq!(
            string_list(field(child(span, "byte"), "type")),
            string_list(field(expected, "span_byte_type"))
        );
        let skeleton = child(&schema, "fixture_skeleton");
        assert_eq!(
            string_list(field(skeleton, "required")),
            string_list(field(expected, "skeleton_required"))
        );
        assert_eq!(
            as_int(field(child(skeleton, "record_count"), "minimum")),
            as_int(field(expected, "record_count_minimum"))
        );
        assert_eq!(
            as_int(field(
                field(child(skeleton, "kinds"), "additionalProperties"),
                "minimum"
            )),
            as_int(field(expected, "kind_count_minimum"))
        );
        let share = child(&schema, "share_advisory");
        assert_eq!(
            string_list(field(share, "required")),
            string_list(field(expected, "share_required"))
        );
        assert_eq!(
            as_str(field(child(share, "kind"), "const")),
            as_str(field(expected, "share_kind_const"))
        );
        assert_eq!(
            as_int(field(child(share, "finding_count"), "minimum")),
            as_int(field(expected, "finding_count_minimum"))
        );
        assert_eq!(
            as_bool(field(child(share, "families"), "uniqueItems")),
            as_bool(field(expected, "families_unique_items"))
        );
    }

    fn assert_proven(schema: &Json) {
        let Json::Object(entries) = schema else {
            panic!("schema node is not an object");
        };
        for (key, value) in entries {
            if is_annotation(key) {
                continue;
            }
            assert!(is_known_keyword(key), "unproven keyword {key}");
            match key.as_str() {
                "pattern" => assert_eq!(as_str(value), HEX64_PATTERN),
                "minimum" | "minLength" | "maxLength" => {
                    assert!(matches!(value, Json::Int(number) if *number >= 0));
                }
                "additionalProperties" => match value {
                    Json::Bool(_) => {}
                    Json::Object(_) => assert_proven(value),
                    other => panic!("additionalProperties {other:?}"),
                },
                "items" => assert_proven(value),
                "properties" => {
                    let Json::Object(props) = value else {
                        panic!("properties");
                    };
                    for (_, sub) in props {
                        assert_proven(sub);
                    }
                }
                "required" => {
                    for name in as_array(value) {
                        assert!(matches!(name, Json::String(_)));
                    }
                }
                "type" => assert_type_name(value),
                "const" => assert!(matches!(value, Json::String(_))),
                "enum" => {
                    for choice in as_array(value) {
                        assert!(matches!(choice, Json::String(_)));
                    }
                }
                "uniqueItems" => assert!(matches!(value, Json::Bool(_))),
                _ => {}
            }
        }
    }

    fn assert_type_name(value: &Json) {
        match value {
            Json::String(name) => assert!(KNOWN_TYPES.contains(&name.as_str()), "{name}"),
            Json::Array(items) => {
                for item in items {
                    let Json::String(name) = item else {
                        panic!("type union");
                    };
                    assert!(KNOWN_TYPES.contains(&name.as_str()), "{name}");
                }
            }
            other => panic!("type {other:?}"),
        }
    }

    fn check_validate(id: &str, construct: &Json, expected: &Json) {
        let document = as_str(field(construct, "document"));
        let result = validate_json(document);
        let mode = as_str(field(expected, "mode"));
        assert_eq!(as_str(field(construct, "mode")), mode, "{id}");
        if mode == "ok" {
            assert_eq!(as_str(field(expected, "keyword")), "", "{id}");
            assert_eq!(as_str(field(expected, "path")), "", "{id}");
            assert_eq!(as_str(field(expected, "detail")), "", "{id}");
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        assert_eq!(mode, "reject", "{id}");
        let err = result.unwrap_err();
        let BundleSchemaError::Reject {
            keyword,
            ref path,
            ref detail,
        } = err
        else {
            panic!("{id} expected a schema reject");
        };
        assert_eq!(keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(path.as_str(), as_str(field(expected, "path")), "{id}");
        assert_eq!(detail.as_str(), as_str(field(expected, "detail")), "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains("aaaaaaaaaaaaaaaa"), "{id}");
        assert!(!rendered.contains("FOR_WORK"), "{id}");
    }

    #[test]
    fn schema_tests_are_not_claimed_covered() {
        let coverage = parse_json(&read_text("coverage.json")).unwrap();
        assert_eq!(as_str(field(&coverage, "python_commit")), PIN);
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), SCHEMA_TESTS.len());
        let mut covered = 0_usize;
        let mut not_applicable = 0_usize;
        for (row, expected_name) in rows.iter().zip(SCHEMA_TESTS.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            assert_eq!(as_str(field(row, "column")), "column_0");
            match as_str(field(row, "status")) {
                "covered" => covered += 1,
                "not_applicable" => not_applicable += 1,
                other => panic!("unknown status {other}"),
            }
            assert!(matches!(field(row, "vector_id"), Json::Null));
            assert!(!as_str(field(row, "note")).is_empty());
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert!(!read_text("coverage.json").contains("\"status\": \"covered\""));
    }

    #[test]
    fn provenance_is_synthetic() {
        let provenance = parse_json(&read_text("PROVENANCE.json")).unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert_eq!(as_str(field(&provenance, "python_commit")), PIN);
        let gaps = as_array(field(&provenance, "known_parity_gaps"));
        assert_eq!(gaps.len(), 5);
        assert!(gaps
            .iter()
            .any(|item| as_str(item).contains(CANONICAL_JSON_SEAM)));
    }
}
