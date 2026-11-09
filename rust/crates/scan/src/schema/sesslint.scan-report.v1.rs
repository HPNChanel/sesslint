//! Fail-closed checker for pinned `schemas/sesslint.scan-report.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`validate_scan_report_json`] accepts one JSON value. The pinned document
//! states `type`, `const`, `enum`, `required`, `properties`, `additionalProperties`,
//! `items`, `minLength`, and `minimum`. `additionalProperties` is either `false`
//! or a nested schema. `pattern`, `uniqueItems`, and any other keyword fail closed.
//! A JSON number is an integer only when the token is a proven `i128`.
//! The result is accept or reject. Errors name a keyword and a path.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.scan-report.v1.json` bytes, including the trailing newline.
pub const SCAN_REPORT_SCHEMA_JSON: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.scan-report/v1",
  "title": "SessLint Scan Report Format v1",
  "description": "Directory scan report with 5-bucket totals for SessLint.",
  "type": "object",
  "required": [
    "files",
    "root_path",
    "schema_version",
    "totals"
  ],
  "properties": {
    "schema_version": {
      "const": "sesslint.scan-report/v1"
    },
    "root_path": {
      "type": "string"
    },
    "totals": {
      "type": "object",
      "required": [
        "healthy",
        "invalid",
        "skipped",
        "total",
        "unreadable",
        "unsupported"
      ],
      "properties": {
        "healthy": {
          "type": "integer",
          "minimum": 0
        },
        "invalid": {
          "type": "integer",
          "minimum": 0
        },
        "skipped": {
          "type": "integer",
          "minimum": 0
        },
        "total": {
          "type": "integer",
          "minimum": 0
        },
        "unreadable": {
          "type": "integer",
          "minimum": 0
        },
        "unsupported": {
          "type": "integer",
          "minimum": 0
        },
        "skipped_reasons": {
          "type": "object",
          "description": "Aggregate counts of skipped_reason values across skipped files.",
          "additionalProperties": {
            "type": "integer",
            "minimum": 1
          }
        }
      },
      "additionalProperties": false
    },
    "files": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "error_count",
          "path",
          "verdict",
          "warning_count"
        ],
        "properties": {
          "error_count": {
            "type": "integer",
            "minimum": 0
          },
          "path": {
            "type": "string",
            "minLength": 1
          },
          "verdict": {
            "type": "string",
            "enum": [
              "healthy",
              "invalid",
              "unsupported",
              "unreadable",
              "skipped"
            ]
          },
          "warning_count": {
            "type": "integer",
            "minimum": 0
          },
          "skipped_reason": {
            "type": "string",
            "minLength": 1
          },
          "findings": {
            "type": "array",
            "items": {
              "type": "object",
              "required": [
                "code",
                "fingerprint",
                "remediation",
                "repairability",
                "severity",
                "span"
              ],
              "properties": {
                "code": {
                  "type": "string",
                  "enum": [
                    "SL001",
                    "SL002",
                    "SL003",
                    "SL004",
                    "SL005",
                    "SL006",
                    "SL007",
                    "SL008",
                    "SL009",
                    "SL010",
                    "SL011",
                    "SL101",
                    "SL102",
                    "SL103",
                    "SL104",
                    "SL105",
                    "SL106",
                    "SL107",
                    "SL108",
                    "SL201",
                    "SL202",
                    "SL203",
                    "SL204",
                    "SL205",
                    "SL206",
                    "SL207",
                    "SL208",
                    "SL301",
                    "SL302",
                    "SL303",
                    "SL304",
                    "SL305",
                    "SL306",
                    "SL401",
                    "SL402"
                  ]
                },
                "fingerprint": {
                  "type": "string",
                  "minLength": 1
                },
                "remediation": {
                  "type": "string"
                },
                "repairability": {
                  "type": "string"
                },
                "severity": {
                  "type": "string"
                },
                "span": {
                  "type": "object",
                  "required": [
                    "path"
                  ],
                  "properties": {
                    "path": {
                      "type": "string",
                      "minLength": 1
                    },
                    "line": {
                      "type": [
                        "integer",
                        "null"
                      ]
                    },
                    "byte": {
                      "type": [
                        "integer",
                        "null"
                      ]
                    }
                  }
                },
                "evidence": {
                  "type": [
                    "object",
                    "null"
                  ]
                }
              }
            }
          },
          "finding_groups": {
            "type": "array",
            "items": {
              "type": "object",
              "required": [
                "code",
                "kind",
                "count",
                "sample_fingerprints"
              ],
              "properties": {
                "code": {
                  "type": "string"
                },
                "kind": {
                  "type": "string"
                },
                "count": {
                  "type": "integer",
                  "minimum": 1
                },
                "sample_fingerprints": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "additionalProperties": false
            }
          }
        }
      }
    }
  }
}
"#;

const MAX_DEPTH: usize = 64;

/// Failure to parse one JSON value or to prove it against the pinned scan-report schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanReportSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax { byte: usize },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        keyword: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for ScanReportSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(formatter, "scan report schema json syntax at byte {byte}")
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
                    write!(formatter, "scan report schema {keyword} at {at}")
                } else {
                    write!(formatter, "scan report schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for ScanReportSchemaError {}

/// Structural JSON value. `PartialEq` compares parser structure, not JSON Schema equality.
#[derive(Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    NonInteger,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Parse one JSON document and validate it against the pinned scan-report schema.
pub fn validate_scan_report_json(input: &str) -> Result<(), ScanReportSchemaError> {
    let value = parse_json(input)?;
    validate_scan_report_value(&value)
}

fn validate_scan_report_value(value: &Json) -> Result<(), ScanReportSchemaError> {
    let schema = match parse_json(SCAN_REPORT_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, value, "")
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> ScanReportSchemaError {
    ScanReportSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, ScanReportSchemaError> {
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

    fn syntax(&self) -> ScanReportSchemaError {
        ScanReportSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), ScanReportSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, ScanReportSchemaError> {
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

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, ScanReportSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, ScanReportSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, ScanReportSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, ScanReportSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, ScanReportSchemaError> {
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
    ) -> Result<(), ScanReportSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, ScanReportSchemaError> {
        let mut code = 0u32;
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
    ) -> Result<(), ScanReportSchemaError> {
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
            | "minimum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
    )
}

fn check(schema: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
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
    check_array(schema, value, path)
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, ScanReportSchemaError> {
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

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, ScanReportSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
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

fn check_string(schema: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
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
    Ok(())
}

fn length_bound(bound: &Json, path: &str) -> Result<usize, ScanReportSchemaError> {
    let Json::Int(value) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    usize::try_from(*value).map_err(|_| reject("unsupported", path, "length"))
}

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
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

fn check_object(schema: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
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
        match flag {
            Json::Bool(false) => {
                for (key, _) in entries {
                    if !allowed.iter().any(|name| name == key) {
                        return Err(reject("additionalProperties", path, key));
                    }
                }
            }
            Json::Bool(true) => {}
            Json::Object(_) => {
                for (key, child) in entries {
                    if !allowed.iter().any(|name| name == key) {
                        let child_path = pointer(path, key);
                        check(flag, child, &child_path)?;
                    }
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
                let child_path = pointer(path, name);
                check(sub, child, &child_path)?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, ScanReportSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn check_array(schema: &Json, value: &Json, path: &str) -> Result<(), ScanReportSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = pointer_index(path, index);
            check(item_schema, item, &child_path)?;
        }
    }
    Ok(())
}

fn json_equal(left: &Json, right: &Json) -> Option<bool> {
    match (left, right) {
        (Json::NonInteger, _) | (_, Json::NonInteger) => None,
        (Json::Null, Json::Null) => Some(true),
        (Json::Null, _) | (_, Json::Null) => Some(false),
        (Json::Bool(left), Json::Bool(right)) => Some(left == right),
        (Json::Bool(_), _) | (_, Json::Bool(_)) => Some(false),
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
        check, classify_number, object_get, parse_json, validate_scan_report_json,
        validate_scan_report_value, Json, ScanReportSchemaError, SCAN_REPORT_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/test_scan_schema.py::test_scan_schema_loads_and_self_consistent",
        "tests/test_scan_schema.py::test_scan_report_dict_validates",
        "tests/test_scan_schema.py::test_scan_report_json_round_trip_validates",
        "tests/test_scan_schema.py::test_scan_report_skipped_reasons_aggregated",
        "tests/test_scan_schema.py::test_scan_report_skipped_reasons_omitted_when_empty",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "maxLength",
        "minLength",
        "minimum",
        "required",
        "type",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../parity/schemas/sesslint.scan-report.v1")
    }

    fn read_text(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    fn contains_banned(text: &str) -> bool {
        if text.contains('\r')
            || text.contains("FOR_WORK")
            || text.contains("sesslint-wt-")
            || text.contains("02694d5")
        {
            return true;
        }
        let bytes = text.as_bytes();
        if bytes.len() < 44 {
            return false;
        }
        (0..=bytes.len() - 44).any(|index| {
            &bytes[index..index + 4] == b"sbp_"
                && bytes[index + 4..index + 44]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
        })
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

    fn string_list(value: &Json) -> Vec<&str> {
        as_array(value).iter().map(as_str).collect()
    }

    fn object_keys(value: &Json) -> Vec<&str> {
        match value {
            Json::Object(entries) => entries.iter().map(|(key, _)| key.as_str()).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }

    fn collect_keywords(schema: &Json, found: &mut BTreeSet<String>) {
        let Json::Object(entries) = schema else {
            return;
        };
        for (key, value) in entries {
            if super::is_annotation(key) {
                continue;
            }
            found.insert(key.clone());
            if key == "properties" {
                if let Json::Object(properties) = value {
                    for (_, sub) in properties {
                        collect_keywords(sub, found);
                    }
                }
            } else if key == "additionalProperties" {
                if let Json::Object(_) = value {
                    collect_keywords(value, found);
                }
            } else if key == "items" {
                match value {
                    Json::Object(_) => collect_keywords(value, found),
                    Json::Array(items) => {
                        for item in items {
                            collect_keywords(item, found);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn proven_integer_tokens_and_closed_failures() {
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("1e1"), Json::Int(10));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("0.0"), Json::Int(0));
        assert_eq!(classify_number("2.5e1"), Json::Int(25));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
        assert!(parse_json("01").is_err());
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_json("[1,]").is_err());
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        assert!(parse_json("").is_err());
        assert!(parse_json("{}{}").is_err());
        let mut nested = String::new();
        for _ in 0..70 {
            nested.push('[');
        }
        nested.push('1');
        for _ in 0..70 {
            nested.push(']');
        }
        assert!(parse_json(&nested).is_err());
        assert_closed("{\"pattern\":\"^a$\"}", "\"a\"", "pattern");
        assert_closed("{\"uniqueItems\":true}", "[\"a\",\"a\"]", "uniqueItems");
        assert_closed("{\"format\":\"date\"}", "\"m\"", "format");
    }

    fn assert_closed(schema_text: &str, value_text: &str, detail: &str) {
        let schema = parse_json(schema_text).unwrap();
        let value = parse_json(value_text).unwrap();
        let err = check(&schema, &value, "").unwrap_err();
        match err {
            ScanReportSchemaError::Reject {
                keyword,
                detail: got,
                ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(got, detail);
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn length_error_does_not_echo_the_string() {
        let schema = parse_json("{\"type\":\"string\",\"maxLength\":2}").unwrap();
        let value = parse_json(&format!("\"{}\"", "p".repeat(20))).unwrap();
        let err = check(&schema, &value, "/message").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maxLength"));
        assert!(!rendered.contains(&"p".repeat(4)));
        let document = format!(
            "{{\"files\":[{{\"error_count\":0,\"path\":\"{}\",\"verdict\":\"healthy\",\"warning_count\":0}}],\"root_path\":\"r\",\"schema_version\":\"sesslint.scan-report/v1\",\"totals\":{{\"healthy\":0,\"invalid\":0,\"skipped\":0,\"total\":0,\"unreadable\":0,\"unsupported\":0}}}}",
            "p".repeat(8)
        );
        assert!(validate_scan_report_json(&document).is_ok());
        let err = validate_scan_report_json("{}").unwrap_err();
        match err {
            ScanReportSchemaError::Reject {
                keyword,
                path,
                detail,
            } => {
                assert_eq!(keyword, "required");
                assert_eq!(path, "");
                assert_eq!(detail, "files");
            }
            other => panic!("expected required, got {other:?}"),
        }
    }

    #[test]
    fn parity_files_are_synthetic_and_match_the_pin() {
        let dir = parity_dir();
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
        ] {
            let text = read_text(&dir.join(name));
            assert!(!contains_banned(&text), "{name} contains banned text");
            let doc = parse_json(&text).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(as_str(field(&doc, "python_commit")), PIN, "{name}");
        }
        let provenance = parse_json(&read_text(&dir.join("PROVENANCE.json"))).unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert!(!as_array(field(&provenance, "known_parity_gaps")).is_empty());
        let manifest = parse_json(&read_text(&dir.join("manifest.json"))).unwrap();
        let vectors = parse_json(&read_text(&dir.join("vectors.json"))).unwrap();
        assert_eq!(
            as_int(field(&manifest, "vector_count")) as usize,
            as_array(field(&vectors, "vectors")).len()
        );
        assert!(!SCAN_REPORT_SCHEMA_JSON.contains('\r'));
        assert!(SCAN_REPORT_SCHEMA_JSON.starts_with('{'));
        assert!(SCAN_REPORT_SCHEMA_JSON.ends_with("}\n"));
        assert!(!SCAN_REPORT_SCHEMA_JSON.contains("___PIN_SCHEMA___"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(SCAN_REPORT_SCHEMA_JSON).unwrap();
        assert_eq!(
            as_str(field(&schema, "$schema")),
            as_str(field(facts, "dialect"))
        );
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
        assert_eq!(
            string_list(field(&schema, "required")),
            string_list(field(facts, "required"))
        );
        assert_eq!(
            object_keys(field(&schema, "properties")),
            string_list(field(facts, "property_names"))
        );
        assert!(object_get(&schema, "additionalProperties").is_none());
        assert!(matches!(
            field(facts, "root_additional_properties"),
            Json::Null
        ));
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "schema_version"), "const")),
            as_str(field(facts, "schema_version_const"))
        );
        let totals = field(properties, "totals");
        assert_eq!(
            string_list(field(totals, "required")),
            string_list(field(facts, "totals_required"))
        );
        assert_eq!(
            object_keys(field(totals, "properties")),
            string_list(field(facts, "totals_property_names"))
        );
        assert_eq!(
            as_bool(field(totals, "additionalProperties")),
            as_bool(field(facts, "totals_additional_properties"))
        );
        let total_properties = field(totals, "properties");
        assert_eq!(
            as_int(field(field(total_properties, "healthy"), "minimum")),
            as_int(field(facts, "counter_minimum"))
        );
        let reasons = field(total_properties, "skipped_reasons");
        let reason_values = field(reasons, "additionalProperties");
        assert_eq!(
            as_str(field(reason_values, "type")),
            as_str(field(facts, "skipped_reasons_value_type"))
        );
        assert_eq!(
            as_int(field(reason_values, "minimum")),
            as_int(field(facts, "skipped_reasons_minimum"))
        );
        let file_item = field(field(properties, "files"), "items");
        assert_eq!(
            string_list(field(file_item, "required")),
            string_list(field(facts, "file_required"))
        );
        assert_eq!(
            object_keys(field(file_item, "properties")),
            string_list(field(facts, "file_property_names"))
        );
        assert!(object_get(file_item, "additionalProperties").is_none());
        let file_properties = field(file_item, "properties");
        assert_eq!(
            string_list(field(field(file_properties, "verdict"), "enum")),
            string_list(field(facts, "verdict_enum"))
        );
        assert_eq!(
            as_int(field(field(file_properties, "path"), "minLength")),
            as_int(field(facts, "path_min_length"))
        );
        assert_eq!(
            as_int(field(field(file_properties, "skipped_reason"), "minLength")),
            as_int(field(facts, "skipped_reason_min_length"))
        );
        let finding = field(field(file_properties, "findings"), "items");
        assert_eq!(
            string_list(field(finding, "required")),
            string_list(field(facts, "finding_required"))
        );
        assert_eq!(
            object_keys(field(finding, "properties")),
            string_list(field(facts, "finding_property_names"))
        );
        assert!(object_get(finding, "additionalProperties").is_none());
        let finding_properties = field(finding, "properties");
        assert_eq!(
            string_list(field(field(finding_properties, "code"), "enum")),
            string_list(field(facts, "code_enum"))
        );
        assert_eq!(
            as_int(field(field(finding_properties, "fingerprint"), "minLength")),
            as_int(field(facts, "fingerprint_min_length"))
        );
        assert_eq!(
            string_list(field(field(finding_properties, "evidence"), "type")),
            string_list(field(facts, "evidence_type"))
        );
        let span = field(finding_properties, "span");
        assert!(object_get(span, "additionalProperties").is_none());
        assert_eq!(
            string_list(field(span, "required")),
            string_list(field(facts, "span_required"))
        );
        assert_eq!(
            object_keys(field(span, "properties")),
            string_list(field(facts, "span_property_names"))
        );
        assert_eq!(
            string_list(field(field(field(span, "properties"), "line"), "type")),
            string_list(field(facts, "line_type"))
        );
        let group = field(field(file_properties, "finding_groups"), "items");
        assert_eq!(
            as_bool(field(group, "additionalProperties")),
            as_bool(field(facts, "group_additional_properties"))
        );
        assert_eq!(
            string_list(field(group, "required")),
            string_list(field(facts, "group_required"))
        );
        assert_eq!(
            object_keys(field(group, "properties")),
            string_list(field(facts, "group_property_names"))
        );
        assert_eq!(
            as_int(field(field(field(group, "properties"), "count"), "minimum")),
            as_int(field(facts, "group_count_minimum"))
        );
        let mut found = BTreeSet::new();
        collect_keywords(&schema, &mut found);
        let actual: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(actual, string_list(field(facts, "keywords")));
        assert!(!actual.contains(&"pattern"));
        assert!(!actual.contains(&"uniqueItems"));
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        assert!(cases.len() > 1);
        let mut ids = BTreeSet::new();
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let expected = field(case, "expected");
            let result = if object_get(case, "raw").is_some() {
                assert!(object_get(case, "instance").is_none(), "{id}");
                validate_scan_report_json(as_str(field(case, "raw")))
            } else {
                validate_scan_report_value(field(case, "instance"))
            };
            assert_result(id, result, expected);
        }
    }

    fn assert_result(id: &str, result: Result<(), ScanReportSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let ScanReportSchemaError::Reject {
            keyword,
            ref path,
            ref detail,
        } = err
        else {
            panic!("{id} expected a schema reject");
        };
        assert!(
            FAILURE_KEYWORDS.contains(&keyword),
            "{id} keyword {keyword}"
        );
        assert_eq!(keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(path, as_str(field(expected, "path")), "{id}");
        assert_eq!(detail, as_str(field(expected, "detail")), "{id}");
        assert!(detail.len() < 80, "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains("0123456789abcdef"), "{id}");
    }

    #[test]
    fn coverage_does_not_claim_a_partial_test() {
        let coverage = parse_json(&read_text(&parity_dir().join("coverage.json"))).unwrap();
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), SCHEMA_TESTS.len());
        let mut covered = 0usize;
        let mut not_applicable = 0usize;
        for (row, expected_name) in rows.iter().zip(SCHEMA_TESTS.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            let status = as_str(field(row, "status"));
            match status {
                "covered" => covered += 1,
                "not_applicable" => not_applicable += 1,
                other => panic!("unknown status {other}"),
            }
            assert!(
                matches!(field(row, "vector_id"), Json::Null),
                "{expected_name}"
            );
            assert!(!as_str(field(row, "note")).is_empty(), "{expected_name}");
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert!(!read_text(&parity_dir().join("coverage.json")).contains("\"status\": \"covered\""));
    }
}
